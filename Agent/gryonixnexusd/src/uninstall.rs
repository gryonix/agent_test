//! Removing ONE service, through the deployment's own uninstall wrapper.
//!
//! Deliberately narrower than the wrapper it drives. `/opt/gryonixnexus-uninstall.sh`
//! also takes `--all`, and that erase stops this agent, deletes its binary, its
//! socket and its state directory — so a stream reporting the erase is killed
//! BY the erase, and the client cannot tell "the server was wiped as asked"
//! from "the agent died halfway". Erase therefore stays on the SSH route, which
//! outlives its own subject. This module must never grow an `--all` path; the
//! reason is a property of the operation, not a gap to close later.
//!
//! Everything else is the backup route's shape: no shell, no sudo, the service
//! id used as a GATE against the `discover` table with its `&'static str`
//! reaching argv, and the wrapper left to own what removal means (its default
//! keeps data and backups; the two purge flags are independent).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use hyper::StatusCode;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::util::strip_ansi;
use crate::state::Store;
use crate::{discover, pb};

pub const WRAPPER_PATH: &str = "/opt/gryonixnexus-uninstall.sh";

/// Printed by the wrapper as its very last line, after every case arm.
/// Streaming carries no exit status the client can trust on its own (the same
/// lesson every other wrapper in this product already paid for), so success is
/// this literal marker — never the child's exit code, which a `set -euo
/// pipefail` script can happen to return 0 for reasons that are not "it did the
/// thing this call asked for".
const DONE_MARKER: &str = "GRYONIXNEXUS_UNINSTALL_DONE";

/// The wrapper's two independent purge flags. Absent means absent — the
/// wrapper's own default keeps both data and backups, and this module must
/// never invent a default of its own.
const PURGE_DATA_FLAG: &str = "--purge-data";
const PURGE_BACKUPS_FLAG: &str = "--purge-backups";

/// Deadline for one removal. Same number as the backup route's `RUN_TIMEOUT_SECS`
/// (600s) and the SSH path's `long` timeout class: `docker compose down
/// --rmi local` on a mail stack is not instant, and a route that waited longer
/// would make "this server cannot remove a service in ten minutes" true only
/// over the agent and not over SSH.
const RUN_TIMEOUT_SECS: u64 = 600;

/// Client strings are echoed back so a mistyped id is diagnosable, but only a
/// bounded prefix: the message travels into logs and UI.
const ECHO_LIMIT: usize = 64;

/// Why a removal was refused BEFORE anything on the host was touched.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Not a service in the agent's catalog — the same gate management and
    /// backups use. `--all` falls in here too: it is grammar the WRAPPER
    /// accepts, but it is not, and must never become, a catalog service id.
    UnknownService(String),
    /// This host has no uninstall wrapper at all: an adopted server, or one set
    /// up before the wrapper existed. Not a defect of this route — the SSH
    /// route calls the same missing file — so it says what to do about it.
    NoWrapper,
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::UnknownService(id) => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                format!("unknown service '{}'", truncate(id)),
            ),
            // failed_precondition, not not_found: the request is well formed
            // and the service may well be installed — what is missing is the
            // host's uninstall wrapper, and re-running setup installs it.
            Rejection::NoWrapper => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "this server has no uninstall wrapper ({WRAPPER_PATH}) — re-run the setup script to install it"
                ),
            ),
        }
    }

    fn response(&self) -> Resp {
        let (status, code, message) = self.parts();
        connect_error(status, code, &message)
    }
}

fn truncate(value: &str) -> String {
    value.chars().take(ECHO_LIMIT).collect()
}

fn wrapper_path() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_UNINSTALL_WRAPPER").unwrap_or_else(|_| WRAPPER_PATH.to_string()))
}

/// `systemd-run`, overridable for tests.
///
/// **Its own variable rather than `install::packages`'s.** Both name the same
/// binary, but tests SET and REMOVE these, and the rule two separate incidents
/// already bought (GOTCHAS.md, `util::STATE_DIR_ENV_LOCK`) is that a variable
/// with more than one reader needs ONE lock shared by all of them. Keeping one
/// variable per reader makes that count verifiable instead of assumed.
fn systemd_run_bin() -> String {
    std::env::var("GRYONIXNEXUSD_UNINSTALL_SYSTEMD_RUN_BIN").unwrap_or_else(|_| "systemd-run".to_string())
}

/// Is that binary usable? A bare name is a `PATH` question; an absolute path
/// (only a test ever sets one) is a filesystem question, and answering the
/// second one by walking `PATH` would work only by accident.
fn systemd_run_available(bin: &str) -> bool {
    let path = Path::new(bin);
    if path.is_absolute() {
        path.is_file()
    } else {
        crate::install::packages::have_binary(bin)
    }
}

/// The command that runs the wrapper: `systemd-run` when this host has it, the
/// wrapper itself otherwise.
///
/// **Why the wrapper must escape the agent's sandbox.** A child inherits the
/// mount namespace, so a wrapper the agent spawns is confined exactly as the
/// agent is — and `ProtectSystem=full` keeps `/etc` read-only. Every `/etc` path
/// inside the wrapper has therefore needed its own `ReadWritePaths=` grant, and
/// each one was found ONE INCIDENT LATE (`/etc/wireguard`, `/etc/sysctl.d`); the
/// rule in GOTCHAS.md says as much, naming "a new path inside a wrapper the
/// agent runs" as a reason to re-read the list. This ends that class: the
/// wrapper no longer runs in this namespace at all, so the next path added to it
/// needs no grant and no incident.
///
/// **Measured, including which part of the old story was wrong.** The gap
/// recorded in `tests/unit_sandbox.rs` was `/etc/nftables.conf.bak.*` — a file
/// directly in `/etc`, which no grant short of undoing the hardening could
/// cover. Reading a real wrapper on a live host showed that glob sits ONLY in
/// the `--all` branch, and `--all` never reaches the agent (it would kill the
/// agent mid-stream, so `ServiceRemovalRouting` sends it over SSH), so that
/// particular file was never the agent's to lose. What the live A/B on
/// `lab-bare` 2026-08-13 did prove is the mechanism, both ways: with the direct
/// spawn a stand-in wrapper reported `/etc` read-only and the file survived;
/// through `systemd-run` the same wrapper unlinked it.
///
/// `systemd-run` is not a fork — it asks PID 1 for a transient unit, which gets
/// its OWN namespace with no `ProtectSystem` at all, and the exit status
/// propagates back through `--wait --pipe` (measured on the same host). The
/// hardening on the agent is untouched.
///
/// **This is not a privilege gain.** The wrapper is root-owned, generated by
/// this project, already runs as root, and its argv is a `&'static str` from the
/// agent's own catalog table plus fixed flags — no byte of the request reaches
/// it. What changes is only which mount namespace it deletes in.
///
/// A host with no `systemd-run` (a container, a non-systemd box) keeps the old
/// direct spawn: the removal still works, and only the `/etc`-level backup
/// copies stay behind, exactly as before.
fn wrapper_command(args: &[&str]) -> (PathBuf, Vec<String>) {
    let wrapper = wrapper_path();
    if !systemd_run_available(&systemd_run_bin()) {
        return (wrapper, args.iter().map(|a| a.to_string()).collect());
    }
    let mut argv: Vec<String> = ["--quiet", "--collect", "--wait", "--pipe", "--service-type=oneshot"]
        .iter()
        .map(|flag| flag.to_string())
        .collect();
    argv.push(wrapper.to_string_lossy().to_string());
    argv.extend(args.iter().map(|a| a.to_string()));
    (PathBuf::from(systemd_run_bin()), argv)
}

/// Resolve a client id to the wrapper's own label, or say exactly why not.
/// Nothing has been touched on the host when this returns an error.
///
/// The gate is `discover::known_service_id`, which hands back a `&'static str`
/// from the agent's OWN table — never the caller's bytes. `--all` is not a
/// member of that table, so this function is the whole reason the module-level
/// promise above holds: nothing downstream of `resolve` can ever see it.
pub fn resolve(service_id: &str) -> Result<&'static str, Rejection> {
    let label =
        discover::known_service_id(service_id).ok_or_else(|| Rejection::UnknownService(service_id.to_string()))?;
    if !wrapper_path().exists() {
        return Err(Rejection::NoWrapper);
    }
    Ok(label)
}

/// The wrapper's argument vector for one removal: `<label> [--purge-data]
/// [--purge-backups]`, in the order `UninstallSections` documents. Every
/// element is the agent's own constant or a `&'static str` out of `resolve` —
/// nothing here is built from a client-supplied string.
fn build_args(label: &'static str, purge_data: bool, purge_backups: bool) -> Vec<&'static str> {
    let mut args = vec![label];
    if purge_data {
        args.push(PURGE_DATA_FLAG);
    }
    if purge_backups {
        args.push(PURGE_BACKUPS_FLAG);
    }
    args
}

/// The freshly re-read status of one service, built from the same two calls
/// `control::service_status` uses (`discover::known_service` +
/// `discover::service_snapshot`) — so the answer this route gives after a
/// removal and the answer the ordinary `ServiceStatus` RPC gives cannot
/// disagree about what "installed" means for the same host. `control.rs` has
/// no re-usable function that returns the bare struct (only one that encodes a
/// whole `Resp`), so the two branches are mirrored here rather than decoding a
/// response this module never needed to build.
async fn read_status(service_id: &str) -> Result<pb::ServiceStatusResponse, String> {
    let display = discover::known_service(service_id).unwrap_or(service_id);
    match discover::service_snapshot(service_id).await {
        Ok(Some(service)) => Ok(pb::ServiceStatusResponse {
            service: Some(service),
            installed: true,
        }),
        // Gone — which for a removal that worked is the expected answer, not a
        // fallback.
        Ok(None) => Ok(pb::ServiceStatusResponse {
            service: Some(pb::Service {
                    // Filled by `Store::snapshot` from the column this very
                    // action raises; nothing here has a claim to make.
                    installed_outside: false,
                id: service_id.to_string(),
                display_name: display.to_string(),
                status: pb::ServiceStatus::Unspecified as i32,
                version: String::new(),
                containers: Vec::new(),
            }),
            installed: false,
        }),
        Err(err) => Err(err.to_string()),
    }
}

/// Remove one service through the host's own root-owned wrapper, streaming its
/// output.
///
/// Errors travel on two channels, exactly as they do for `ControlService` and
/// backups:
/// * a refusal BEFORE anything ran (unknown id, no wrapper on this host) is a
///   plain Connect error — nothing was touched, so no stream opens;
/// * a failure DURING the run ends the stream with an error trailer, but only
///   after a COMPLETED event carrying the freshly re-read status. After a
///   half-finished removal the only useful question is what the host reports
///   about that service NOW, and an error alone does not answer it.
pub async fn remove_service(codec: Codec, req: pb::RemoveServiceRequest,
                            store: Arc<Mutex<Store>>) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("service", &req.service_id) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let label = match resolve(&req.service_id) {
        Ok(label) => label,
        Err(rejection) => return rejection.response(),
    };
    let args = build_args(label, req.purge_data, req.purge_backups);

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let service_id = req.service_id.clone();

    tokio::spawn(async move {
        let _claim = claim;
        // The client hanging up drops the receiver and every send fails, but
        // the wrapper already running is NOT cancelled: a half-removed service
        // is worse than one nobody watched finish.
        run(&service_id, &args, codec, tx, store).await;
    });

    stream_response(json, rx)
}

/// The production entry point for one run: reads the post-removal status from
/// the real host AND writes it into the agent's own store. Split out from
/// `run_with` so tests can supply a stand-in status reader and prove this
/// module's own logic — event ordering, marker detection, argv assembly —
/// without a live docker daemon, which plenty of build machines (this one
/// included) do not have.
///
/// **The write sits beside the read, and it is a REMOVAL that has to reach the
/// store** (2026-09-04): until now nothing but `Discover` and the start/stop
/// buttons wrote there, so a service taken off the host stayed in `GetState`
/// until the next scan — offering a phone that had not rescanned actions on
/// something that is gone. `installed: false` is the expected answer here, not
/// a fallback, and it deletes the row; `true` means the wrapper did not remove
/// it, and what is still running is recorded instead. A read that FAILED
/// reaches neither branch — `run_with` reports it, and the store is left alone
/// rather than made to guess.
async fn run(service_id: &str, args: &[&str], codec: Codec, tx: Sender<Bytes>,
             store: Arc<Mutex<Store>>) {
    run_with(service_id, args, codec, tx, move |id| async move {
        let status = read_status(&id).await;
        if let Ok(status) = &status {
            let service = if status.installed { status.service.as_ref() } else { None };
            // Best effort, as everywhere else this store is written from a
            // stream: a failed write must not turn a successful removal into a
            // reported failure.
            if let Ok(store) = store.lock() {
                if let Err(err) = store.record_action(&id, service) {
                    tracing::warn!(?err, service_id = %id, "could not persist post-removal status");
                }
            }
        }
        status
    })
    .await;
}

async fn run_with<F, Fut>(service_id: &str, args: &[&str], codec: Codec, tx: Sender<Bytes>, status_reader: F)
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<pb::ServiceStatusResponse, String>>,
{
    let sink = EventSink {
        tx,
        codec,
        service_id: service_id.to_string(),
        journal: crate::jobs::Journal::open(pb::JobKind::Uninstall, service_id),
    };
    let _ = sink.started().await;

    let outcome = run_wrapper_streaming(args, RUN_TIMEOUT_SECS, &sink).await;

    let mut failure = outcome.err();
    let status = match status_reader(service_id.to_string()).await {
        Ok(status) => Some(status),
        Err(err) => {
            // Losing the re-read is worth reporting, but only after the
            // COMPLETED event has gone out with whatever else is known — the
            // same rule the backup route follows for its own re-read.
            failure.get_or_insert_with(|| format!("could not re-read status after removal: {err}"));
            None
        }
    };
    let _ = sink.completed(status).await;
    if let Some(why) = failure {
        let _ = sink.fail(&why).await;
    }
    // On success the body simply ends — the same clean end the other streams use.
}

/// Run the wrapper, streaming every line as PROGRESS. `Ok` only when the
/// process exited 0 AND printed the marker: an exit code alone is not proof,
/// because a script under `set -euo pipefail` can still return 0 for reasons
/// that have nothing to do with "it removed the thing this call asked for" —
/// the marker is the one thing on this path that means that, on purpose.
async fn run_wrapper_streaming(args: &[&str], timeout_secs: u64, sink: &EventSink) -> Result<(), String> {
    let (program, argv) = wrapper_command(args);
    let mut child = tokio::process::Command::new(program)
        .args(&argv)
        // Nothing is written to the wrapper: no shell, and no secret this
        // route needs to keep out of argv (unlike backups' passphrase). Stdin
        // is closed rather than inherited so the child can never block on it.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run the uninstall wrapper: {err}"))?;

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut stdout = String::new();
    let mut stderr = String::new();

    // ONE deadline for the whole run rather than a per-line one: a removal is
    // silent for long stretches (`docker compose down` on a big stack says
    // nothing for a while), and a quiet minute is not a hung command.
    let outcome = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => {
                            let text = strip_ansi(&text);
                            stdout.push_str(&text);
                            stdout.push('\n');
                            let _ = sink.progress("stdout", text).await;
                        }
                        _ => out = None, // EOF or read error on this pipe
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        // The wrapper narrates on stderr too (docker, awk), so
                        // an stderr line is progress — the exit status and the
                        // marker are what decide success.
                        Ok(Some(text)) => {
                            let text = strip_ansi(&text);
                            stderr.push_str(&text);
                            stderr.push('\n');
                            let _ = sink.progress("stderr", text).await;
                        }
                        _ => err = None,
                    }
                }
                else => break,
            }
        }
        child.wait().await
    })
    .await;

    match outcome {
        Err(_) => Err(format!("the uninstall wrapper timed out after {timeout_secs}s")),
        Ok(Err(io)) => Err(format!("the uninstall wrapper did not finish: {io}")),
        Ok(Ok(status)) if status.success() && stdout.contains(DONE_MARKER) => Ok(()),
        // Exit 0 but no marker: something short-circuited before the wrapper's
        // last line, and calling that success would be trusting an exit code
        // this route explicitly does not trust.
        Ok(Ok(status)) if status.success() => {
            Err("the uninstall wrapper exited without printing the completion marker".to_string())
        }
        Ok(Ok(status)) => Err(describe_failure(status.code(), &stderr)),
    }
}

fn describe_failure(code: Option<i32>, stderr: &str) -> String {
    let detail = stderr.trim();
    let detail: String = detail.chars().rev().take(400).collect::<Vec<_>>().into_iter().rev().collect();
    match (code, detail.is_empty()) {
        (_, false) => detail,
        (Some(code), true) => format!("the uninstall wrapper exited {code}"),
        (None, true) => "the uninstall wrapper was killed by a signal".to_string(),
    }
}

/// Frames and pushes one run's events. A failing send means the client is
/// gone; callers treat that as "stop talking", never as an error to report.
struct EventSink {
    tx: Sender<Bytes>,
    codec: Codec,
    service_id: String,
    /// The record this run leaves behind, so a client that closed can ask how
    /// it went — see `crate::jobs`. `None` when the host could not open one,
    /// which costs the reattach and nothing else.
    journal: Option<crate::jobs::Journal>,
}

impl EventSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::UninstallEvent {
        pb::UninstallEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            service_id: self.service_id.clone(),
            text: String::new(),
            stream: String::new(),
            status: None,
        }
    }

    async fn send(&self, event: pb::UninstallEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self) -> Result<(), ()> {
        self.send(self.event(pb::ServiceOperationPhase::Started)).await
    }

    async fn progress(&self, stream: &str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(&self, status: Option<pb::ServiceStatusResponse>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.status = status;
        self.send(event).await
    }

    /// End the stream with a Connect error trailer — what makes the client
    /// throw. Always sent AFTER `completed`, never instead of it.
    async fn fail(&self, message: &str) -> Result<(), ()> {
        // **The failure is the run's ending, and the record needs it in the
        // same words the trailer carries.** Without this the journal would be
        // closed by the drop below with "outcome not reported", which is true
        // of an early return and a lie about a failure that was named.
        crate::jobs::finish(&self.journal, Some(message));
        self.tx.send(error_trailer("internal", message)).await.map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::END_OF_STREAM_FLAG;
    use prost::Message;

    /// The wrapper location is overridden through the environment, which is
    /// process-wide, and cargo runs tests in parallel threads — without this
    /// the tests would flip each other's override and fail at random. Same
    /// technique as `backup.rs`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn write_stub(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let script = dir.join(name);
        std::fs::write(&script, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        script
    }

    fn decode_data_frame(bytes: &Bytes) -> pb::UninstallEvent {
        assert_eq!(bytes[0], 0x00, "expected a data frame, got flags {:#x}", bytes[0]);
        pb::UninstallEvent::decode(&bytes[5..]).expect("valid UninstallEvent frame")
    }

    fn is_trailer(bytes: &Bytes) -> bool {
        bytes[0] == END_OF_STREAM_FLAG
    }

    async fn drain(rx: &mut tokio::sync::mpsc::Receiver<Bytes>) -> Vec<Bytes> {
        let mut frames = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            frames.push(frame);
        }
        frames
    }

    // ─────────────────────────── resolve / gate ───────────────────────────

    /// **The wrapper runs OUTSIDE the agent's sandbox when the host can do it.**
    ///
    /// A child inherits the mount namespace, so the wrapper used to delete under
    /// `ProtectSystem=full` — fine for `/etc/wireguard/wg0.conf.bak.*` (its
    /// directory has a grant), impossible for `/etc/nftables.conf.bak.*`, a file
    /// sitting directly in a read-only `/etc`. That was the recorded gap in
    /// `tests/unit_sandbox.rs`, and this is the fix: a transient unit gets its
    /// own namespace with no `ProtectSystem` at all.
    ///
    /// Both branches are pinned, because the fallback is the whole reason this
    /// is safe to do: a host with no `systemd-run` must still remove services.
    #[test]
    fn the_wrapper_escapes_the_sandbox_through_a_transient_unit_when_the_host_has_one() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-uninstall-run-{}", std::process::id()));
        let wrapper = write_stub(&dir, "uninstall.sh", "#!/bin/sh\necho done\n");
        let systemd_run = write_stub(&dir, "systemd-run", "#!/bin/sh\nexit 0\n");
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", &wrapper);

        // No systemd-run on this host: the wrapper is spawned directly, exactly
        // as it always was.
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_SYSTEMD_RUN_BIN", dir.join("no-such-systemd-run"));
        let (program, argv) = wrapper_command(&["nextcloud", "--purge-data"]);
        assert_eq!(program, wrapper);
        assert_eq!(argv, vec!["nextcloud".to_string(), "--purge-data".to_string()]);

        // With systemd-run: PID 1 is asked for a oneshot unit that runs the
        // wrapper, and `--wait --pipe` is what keeps the output streaming and
        // the exit status propagating (measured live 2026-08-13).
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_SYSTEMD_RUN_BIN", &systemd_run);
        let (program, argv) = wrapper_command(&["nextcloud", "--purge-data"]);
        assert_eq!(program, systemd_run);
        assert_eq!(
            argv,
            vec![
                "--quiet".to_string(),
                "--collect".to_string(),
                "--wait".to_string(),
                "--pipe".to_string(),
                "--service-type=oneshot".to_string(),
                wrapper.to_string_lossy().to_string(),
                "nextcloud".to_string(),
                "--purge-data".to_string(),
            ],
            "the wrapper and its arguments must stay LAST and in order — systemd-run \
             treats the first non-flag word as the command"
        );

        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_SYSTEMD_RUN_BIN");
        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_service_id_is_refused_before_anything_runs() {
        assert_eq!(resolve("nope"), Err(Rejection::UnknownService("nope".into())));
        assert!(matches!(
            resolve("nextcloud; rm -rf /"),
            Err(Rejection::UnknownService(_))
        ));
    }

    #[test]
    fn the_target_all_is_never_a_catalog_service_and_cannot_reach_resolve() {
        // `--all` is grammar the WRAPPER accepts (see `UninstallSections
        // .allTarget`), but it is not a catalog id, and `resolve` is the only
        // gate between a request and this module's argv — so refusing it here,
        // unconditionally and before the wrapper's presence is even checked,
        // is what makes the whole module's "never `--all`" promise hold.
        assert_eq!(resolve("--all"), Err(Rejection::UnknownService("--all".into())));
        assert_eq!(resolve("vpn --all"), Err(Rejection::UnknownService("vpn --all".into())));
    }

    #[test]
    fn the_label_that_reaches_argv_is_the_agents_own_string_not_the_requests() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-uninstall-ptr-{}", std::process::id()));
        let script = write_stub(&dir, "uninstall.sh", "#!/bin/sh\necho done\n");
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", &script);

        // The gate is not "the id looked acceptable" — what continues into a
        // privileged argument vector is a pointer into the agent's OWN table.
        // A lookup that validated the input and handed the caller's bytes
        // onwards would pass every equality check and still carry
        // client-controlled memory into the wrapper's argv.
        let from_the_wire = String::from("nextcloud");
        let label = resolve(&from_the_wire).expect("a catalog id resolves");
        assert_eq!(label, "nextcloud");
        assert!(
            !std::ptr::eq(label.as_ptr(), from_the_wire.as_ptr()),
            "the wrapper label must come from the agent's table, not from the request"
        );

        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_host_with_no_wrapper_is_told_what_to_do_and_the_unknown_id_check_comes_first() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", "/nonexistent/gryonixnexus-uninstall.sh");
        assert_eq!(resolve("nextcloud"), Err(Rejection::NoWrapper));
        // An unrecognized id refuses regardless of the host at all — it never
        // gets far enough to notice the wrapper is missing.
        assert_eq!(resolve("nope"), Err(Rejection::UnknownService("nope".into())));
        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
    }

    #[test]
    fn missing_wrapper_response_is_failed_precondition_naming_the_path() {
        let (status, code, message) = Rejection::NoWrapper.parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains(WRAPPER_PATH));
        assert!(message.to_lowercase().contains("re-run"));
    }

    // ─────────────────────────── argv assembly ───────────────────────────

    #[test]
    fn purge_flags_are_independent_and_absent_by_default() {
        assert_eq!(build_args("nextcloud", false, false), vec!["nextcloud"]);
        assert_eq!(
            build_args("nextcloud", true, false),
            vec!["nextcloud", "--purge-data"]
        );
        assert_eq!(
            build_args("nextcloud", false, true),
            vec!["nextcloud", "--purge-backups"]
        );
        assert_eq!(
            build_args("nextcloud", true, true),
            vec!["nextcloud", "--purge-data", "--purge-backups"]
        );
        // The case that would be unrecoverable if it slipped: a plain removal
        // request (both flags false) must put NEITHER flag in argv — the
        // wrapper's own default (keep data, keep backups) is the only thing
        // that decides, and this is the one test that would catch a removal
        // silently purging data nobody asked to lose.
        assert_eq!(build_args("vaultwarden", false, false).len(), 1);
    }

    #[test]
    fn the_literal_all_flag_never_appears_in_constructed_argv() {
        // Every catalog id this table knows, crossed with every purge
        // combination: none of it can ever produce the string "--all", because
        // the only inputs `build_args` accepts are `resolve`'s own output (never
        // a member of the catalog) and the two fixed purge-flag constants.
        //
        // The ids come from the catalog ITSELF, not from a list written here:
        // the hand-copied version of this list never grew a Psono or a Passbolt
        // row, so the two newest services were the only ones this assertion did
        // not actually make.
        for id in discover::all_service_ids() {
            let label = discover::known_service_id(id).expect("catalog id");
            for purge_data in [false, true] {
                for purge_backups in [false, true] {
                    let args = build_args(label, purge_data, purge_backups);
                    assert!(
                        !args.contains(&"--all"),
                        "build_args({label}, {purge_data}, {purge_backups}) produced --all: {args:?}"
                    );
                }
            }
        }
    }

    // ─────────────────────────── wrapper plumbing ───────────────────────────

    #[tokio::test]
    async fn a_clean_removal_prints_the_marker_and_completes_with_installed_false() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-uninstall-clean-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "uninstall.sh",
            "#!/bin/sh\necho 'stopping containers'\necho 'GRYONIXNEXUS_UNINSTALL_DONE'\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        run_with(
            "nextcloud",
            &["nextcloud"],
            Codec::Proto,
            tx,
            |_id| async { Ok(pb::ServiceStatusResponse { service: None, installed: false }) },
        )
        .await;

        let frames = drain(&mut rx).await;
        assert!(!frames.is_empty());
        // Success ends the stream cleanly — no error trailer at all.
        assert!(frames.iter().all(|f| !is_trailer(f)), "a clean removal must not send a trailer");

        let events: Vec<_> = frames.iter().map(decode_data_frame).collect();
        assert_eq!(events.first().unwrap().phase, pb::ServiceOperationPhase::Started as i32);
        let progressed_marker = events
            .iter()
            .any(|e| e.phase == pb::ServiceOperationPhase::Progress as i32 && e.text.contains(DONE_MARKER));
        assert!(progressed_marker, "the marker line must have been streamed as progress");

        let completed = events.last().unwrap();
        assert_eq!(completed.phase, pb::ServiceOperationPhase::Completed as i32);
        let status = completed.status.as_ref().expect("completed carries a status");
        assert!(!status.installed, "a removed service must report installed = false");

        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_failing_wrapper_completes_first_and_then_sends_an_error_trailer() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-uninstall-fail-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "uninstall.sh",
            "#!/bin/sh\necho 'compose down failed' >&2\nexit 7\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        run_with(
            "nextcloud",
            &["nextcloud"],
            Codec::Proto,
            tx,
            // A service that is still there — the honest answer to "what is
            // the host reporting NOW" after a half-finished removal.
            |_id| async {
                Ok(pb::ServiceStatusResponse {
                    service: Some(pb::Service {
                    // Filled by `Store::snapshot` from the column this very
                    // action raises; nothing here has a claim to make.
                    installed_outside: false,
                        id: "nextcloud".to_string(),
                        display_name: "Nextcloud".to_string(),
                        status: pb::ServiceStatus::Running as i32,
                        version: String::new(),
                        containers: Vec::new(),
                    }),
                    installed: true,
                })
            },
        )
        .await;

        let frames = drain(&mut rx).await;
        assert!(frames.len() >= 2, "expected at least a COMPLETED event and a trailer");
        // The order the whole design hinges on: the re-read status arrives
        // BEFORE the failure that makes the client throw, never instead of it.
        let (last, rest) = frames.split_last().unwrap();
        assert!(is_trailer(last), "the LAST frame must be the error trailer");
        let completed = rest
            .iter()
            .map(decode_data_frame)
            .find(|e| e.phase == pb::ServiceOperationPhase::Completed as i32)
            .expect("a COMPLETED event must precede the trailer");
        let status = completed.status.as_ref().expect("COMPLETED carries a status even on failure");
        assert!(status.installed, "the service the wrapper failed to remove is still installed");

        let payload = String::from_utf8(last[5..].to_vec()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["error"]["code"], "internal");
        assert!(parsed["error"]["message"].as_str().unwrap().contains("compose down failed"));

        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn exit_zero_without_the_marker_is_still_a_failure() {
        // The rule this test exists to pin: success is the MARKER, never the
        // exit code. A script that returns 0 without ever reaching its last
        // line (e.g. a case arm nobody expected to be reachable) must not read
        // as "done".
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-uninstall-nomark-{}", std::process::id()));
        let script = write_stub(&dir, "uninstall.sh", "#!/bin/sh\necho 'nothing to do'\nexit 0\n");
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", &script);

        let outcome = run_wrapper_streaming(
            &["nextcloud"],
            30,
            &EventSink {
                tx: tokio::sync::mpsc::channel(64).0,
                codec: Codec::Proto,
                service_id: "nextcloud".to_string(),
                journal: None,
            },
        )
        .await;
        assert!(outcome.is_err(), "exit 0 without the marker must not count as success");
        assert!(outcome.unwrap_err().contains("marker"));

        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn describe_failure_prefers_the_wrappers_own_words() {
        assert_eq!(
            describe_failure(Some(2), "compose down failed\n"),
            "compose down failed"
        );
        assert_eq!(describe_failure(Some(2), "   "), "the uninstall wrapper exited 2");
        assert_eq!(describe_failure(None, ""), "the uninstall wrapper was killed by a signal");
    }
}
