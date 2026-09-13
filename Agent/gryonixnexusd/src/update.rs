//! Updates, driven through the deployment's own root-owned wrapper.
//!
//! Sibling of [`crate::backup`] in every structural decision, and for the same
//! reason: the wrapper `/opt/gryonixnexus-update-ctl.sh` already decides what an
//! update IS — back up, remember the running image id, pull, wait for health,
//! roll back by putting the tag back — and a second opinion here would be a
//! second source of truth about a destructive operation. The agent carries its
//! answers and nothing else.
//!
//! What must not be weakened, all of it inherited from the backup route:
//!  * **No shell and no sudo on the path.** The wrapper is executed directly,
//!    every argument its own argv element, so quoting does not exist as a class
//!    of problem here.
//!  * **The service id is a GATE, not an input.** It selects among the ids the
//!    `discover` table knows and what reaches argv is that table's
//!    `&'static str`, never bytes from the request.
//!  * **The children get a writable HOME.** A run calls the BACKUP wrapper
//!    first, which reaches `gpg`, and the unit is `ProtectHome=true`: without
//!    the agent's own home every encrypted service would fail to update, which
//!    is every service that holds a secret.
//!
//! The wrapper path is pinned by a literal on three sides (the generator, the
//! app's `CommandCatalog`, and here) because the modules deliberately do not
//! depend on each other.
//!
//! **`resolve` deliberately does NOT parse the wrapper's own `KNOWN`/
//! `SELF_MANAGED` tables.** It could — they sit in the generated script as
//! plainly as the backup directories `backup.rs` parses — but doing so would
//! be a second implementation of "does this id ship its own updater", and the
//! proto schema (`RunUpdate`'s doc comment) says outright that this project
//! chose NOT to pay for that: the wrapper alone answers the question, by
//! being run. `resolve` only gates against the general catalog
//! (`discover::known_service_id`) and checks the wrapper exists — exactly
//! `uninstall.rs`'s shape. Whether the resolved id is something the wrapper
//! actually updates is discovered by calling it, which is why `RunUpdate` can
//! end in an error trailer with NO preceding `COMPLETED` event: that refusal
//! happens AFTER the stream has already opened.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use hyper::StatusCode;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::util::strip_ansi;
use crate::{discover, pb};

/// Same shape as the backup wrapper's constant, and the same reason for it: a
/// test points this at a stub through the environment, a server never does.
pub const WRAPPER_PATH: &str = "/opt/gryonixnexus-update-ctl.sh";

/// The schedule config, world-readable by design (`chmod 644` — "it holds no
/// secrets and the app reads it without sudo"), so it is read directly rather
/// than through the wrapper: there is no `status`-style subcommand that prints
/// it, because the app's SSH route already reads this same file with a bare
/// `cat`. Must stay byte-identical to `UpdateControlSections.configPath`.
const CONFIG_PATH: &str = "/etc/gryonixnexus/autoupdate.conf";
/// What the last run(s) left behind — also world-readable (`chmod 644`), also
/// read directly. Must stay byte-identical to `UpdateControlSections.statusPath`.
const STATUS_PATH: &str = "/var/lib/gryonixnexus/autoupdate-status.txt";

/// One line per image that moved: `<marker> <service> <image>`.
const AVAILABLE_MARKER: &str = "GRYONIXNEXUS_UPDATE_AVAILABLE";
/// Only when every image of the service answered and none moved.
const CURRENT_MARKER: &str = "GRYONIXNEXUS_UPDATE_CURRENT";
/// `<marker> <service> <reason>` — the check could not be completed.
const UNKNOWN_MARKER: &str = "GRYONIXNEXUS_UPDATE_UNKNOWN";
/// `<marker> <service>` — a successful update.
const DONE_MARKER: &str = "GRYONIXNEXUS_UPDATE_DONE";
/// `<marker> <service> <reason>` — reason can be several words
/// ("a container is restarting"), so it is never split further than the
/// service field.
const ROLLED_BACK_MARKER: &str = "GRYONIXNEXUS_UPDATE_ROLLED_BACK";
/// `<marker> <service> <reason>` — same multi-word rule as rolled-back.
const FAILED_MARKER: &str = "GRYONIXNEXUS_UPDATE_FAILED";

const ALL_TARGET: &str = "--all";

/// The exit code the update wrapper reserves for REFUSING — an invalid label,
/// a service its plan never included, a service that ships its own updater.
/// It is the wrapper's whole vocabulary for "this was never going to run":
/// every other non-zero ending it has means something actually went wrong (1
/// for a scheduled sweep with failures, 75 for a lock another run holds).
/// Named here because the trailer's code is derived from it — see `run_with`.
const REFUSAL_EXIT_CODE: i32 = 2;

/// Deadline for `run`: a backup, a pull and a health wait. Same number as the
/// backup route's own `RUN_TIMEOUT_SECS` and the SSH path's `long` timeout
/// class, for the same reason — a route that waited longer would make "this
/// server cannot finish an update in ten minutes" true only over the agent.
const RUN_TIMEOUT_SECS: u64 = 600;
/// Deadline for `set-schedule`, which only writes a file and (dis)arms a
/// timer.
const QUICK_TIMEOUT_SECS: u64 = 120;
/// Deadline for `check`: one registry request per image, sequential, each
/// bounded by the wrapper's own `HTTP_TIMEOUT` (20s default). A host with many
/// slow or unreachable registries can take minutes, not seconds — generous on
/// purpose so a real answer is not mistaken for a hang.
const CHECK_TIMEOUT_SECS: u64 = 300;

/// Client strings are echoed back so a mistake is diagnosable, but only a
/// bounded prefix.
const ECHO_LIMIT: usize = 96;

/// Why an update request was refused BEFORE anything on the host was touched.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Not a service in the agent's catalog — the same gate management and
    /// backups use.
    UnknownService(String),
    /// This host has no update wrapper at all: an adopted server, or one set
    /// up before scheduled updates existed. Not a defect of this route — the
    /// SSH route calls the same missing file.
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
            Rejection::NoWrapper => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "this server has no update wrapper ({WRAPPER_PATH}) — re-run the setup script to install it"
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
    PathBuf::from(std::env::var("GRYONIXNEXUSD_UPDATE_WRAPPER").unwrap_or_else(|_| WRAPPER_PATH.to_string()))
}

fn config_path() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_UPDATE_CONFIG").unwrap_or_else(|_| CONFIG_PATH.to_string()))
}

fn status_path() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_UPDATE_STATUS").unwrap_or_else(|_| STATUS_PATH.to_string()))
}

/// Resolve a client id to the wrapper's own label, or say exactly why not.
/// Nothing has been touched on the host when this returns an error.
///
/// Deliberately the SAME two rejections `uninstall::resolve` checks and
/// nothing more — see the module doc for why this does not also ask "does the
/// wrapper actually manage this id".
pub fn resolve(service_id: &str) -> Result<&'static str, Rejection> {
    let label =
        discover::known_service_id(service_id).ok_or_else(|| Rejection::UnknownService(service_id.to_string()))?;
    if !wrapper_path().exists() {
        return Err(Rejection::NoWrapper);
    }
    Ok(label)
}

// ─────────────────────────── Marker parsing ───────────────────────────

/// `<marker> <service>[ <rest of line>]`. The service is the first
/// whitespace-delimited token after the marker; everything after THAT is
/// taken whole (trimmed), because a reason like "a container is restarting"
/// must survive as one string, not just its first word.
fn parse_after_marker<'a>(line: &'a str, marker: &str) -> Option<(&'a str, &'a str)> {
    let rest = line.strip_prefix(marker)?;
    let rest = rest.strip_prefix(' ')?;
    match rest.split_once(' ') {
        Some((service, tail)) => Some((service, tail.trim())),
        None => Some((rest.trim(), "")),
    }
}

/// Every service `check` answered about, in first-seen order. A self-managed
/// service prints a prose note that matches none of these markers, so it
/// contributes no row at all — exactly what the proto's missing
/// `SELF_MANAGED` variant documents.
fn parse_check_output(output: &str) -> Vec<pb::ServiceUpdateStatus> {
    let mut order: Vec<String> = Vec::new();
    let mut availability: HashMap<String, pb::UpdateAvailability> = HashMap::new();
    let mut moved_images: HashMap<String, Vec<String>> = HashMap::new();
    let mut reasons: HashMap<String, String> = HashMap::new();

    let note_first_seen = |service: &str, order: &mut Vec<String>| {
        if !order.iter().any(|seen| seen == service) {
            order.push(service.to_string());
        }
    };

    for raw in output.lines() {
        let line = raw.trim_start();
        if let Some((service, image)) = parse_after_marker(line, AVAILABLE_MARKER) {
            note_first_seen(service, &mut order);
            availability
                .entry(service.to_string())
                .or_insert(pb::UpdateAvailability::Available);
            moved_images.entry(service.to_string()).or_default().push(image.to_string());
        } else if let Some((service, _)) = parse_after_marker(line, CURRENT_MARKER) {
            note_first_seen(service, &mut order);
            availability
                .entry(service.to_string())
                .or_insert(pb::UpdateAvailability::Current);
        } else if let Some((service, reason)) = parse_after_marker(line, UNKNOWN_MARKER) {
            note_first_seen(service, &mut order);
            // An unanswered image outranks everything else the wrapper
            // printed for this service (its own ordering rule: "an unanswered
            // image outranks nothing moved"), so this always wins, even over
            // an AVAILABLE line seen earlier for the same service.
            availability.insert(service.to_string(), pb::UpdateAvailability::Unknown);
            reasons.insert(service.to_string(), reason.to_string());
        }
    }

    order
        .into_iter()
        .map(|service| {
            let availability = availability
                .get(&service)
                .copied()
                .unwrap_or(pb::UpdateAvailability::Unspecified);
            let moved_images = moved_images.remove(&service).unwrap_or_default();
            let reason = reasons.remove(&service).unwrap_or_default();
            pb::ServiceUpdateStatus {
                service_id: service,
                availability: availability as i32,
                moved_images,
                reason,
            }
        })
        .collect()
}

/// The outcome `run` recorded, if any marker was printed at all. `None` is
/// the case the proto documents specially: nothing was touched, so there is
/// nothing to report as a status — see `run_with`.
fn parse_run_outcome(output: &str) -> Option<(pb::UpdateOutcome, String)> {
    for raw in output.lines() {
        let line = raw.trim_start();
        if parse_after_marker(line, DONE_MARKER).is_some() {
            return Some((pb::UpdateOutcome::Updated, String::new()));
        }
        if let Some((_, reason)) = parse_after_marker(line, ROLLED_BACK_MARKER) {
            return Some((pb::UpdateOutcome::RolledBack, reason.to_string()));
        }
        if let Some((_, reason)) = parse_after_marker(line, FAILED_MARKER) {
            return Some((pb::UpdateOutcome::Failed, reason.to_string()));
        }
    }
    None
}

// ─────────────────────────── Schedule + status files ───────────────────────────

/// `SCHEDULE=<grammar>` / `SERVICES='<space separated>'`, exactly the shape
/// `do_set_schedule` writes. Missing file (never configured) reads as the
/// wrapper's own defaults: `off`, no services — not an error.
fn read_schedule_config() -> (String, Vec<String>) {
    let text = std::fs::read_to_string(config_path()).unwrap_or_default();
    let mut schedule = "off".to_string();
    let mut services = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("SCHEDULE=") {
            let rest = rest.trim();
            if !rest.is_empty() {
                schedule = rest.to_string();
            }
        } else if let Some(rest) = line.strip_prefix("SERVICES=") {
            let rest = rest.trim();
            let unquoted = rest.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')).unwrap_or(rest);
            services = unquoted.split_whitespace().map(str::to_string).collect();
        }
    }
    (schedule, services)
}

/// The status file's own records, plus the timestamp of the most recent
/// `last-run` header — written only by a `--scheduled` run, which is why a
/// manual run's entries can appear with no header of their own (0 stays the
/// answer for "never scheduled", matching the proto's documented default).
/// Missing file (never run) is empty, not an error.
fn read_status_file() -> (Vec<pb::UpdateRunRecord>, i64) {
    let text = std::fs::read_to_string(status_path()).unwrap_or_default();
    let mut last_run_at = 0i64;
    let mut records = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("last-run ") {
            if let Some(millis) = parse_iso8601_utc_millis(rest.trim()) {
                last_run_at = millis;
            }
            continue;
        }
        if let Some((service, _)) = parse_after_marker(line, DONE_MARKER) {
            records.push(pb::UpdateRunRecord {
                service_id: service.to_string(),
                outcome: pb::UpdateOutcome::Updated as i32,
                reason: String::new(),
            });
        } else if let Some((service, reason)) = parse_after_marker(line, ROLLED_BACK_MARKER) {
            records.push(pb::UpdateRunRecord {
                service_id: service.to_string(),
                outcome: pb::UpdateOutcome::RolledBack as i32,
                reason: reason.to_string(),
            });
        } else if let Some((service, reason)) = parse_after_marker(line, FAILED_MARKER) {
            records.push(pb::UpdateRunRecord {
                service_id: service.to_string(),
                outcome: pb::UpdateOutcome::Failed as i32,
                reason: reason.to_string(),
            });
        }
    }
    (records, last_run_at)
}

/// `YYYY-MM-DDTHH:MM:SSZ` (`date -u +%Y-%m-%dT%H:%M:%SZ`, always this exact
/// shape) → Unix milliseconds. No date-library dependency: the agent already
/// avoids one (see `LogLine.at`'s own comment), and the format is fixed by
/// the wrapper, not user input.
fn parse_iso8601_utc_millis(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 20 {
        return None;
    }
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':' || bytes[19] != b'Z'
    {
        return None;
    }
    let year: i64 = text.get(0..4)?.parse().ok()?;
    let month: i64 = text.get(5..7)?.parse().ok()?;
    let day: i64 = text.get(8..10)?.parse().ok()?;
    let hour: i64 = text.get(11..13)?.parse().ok()?;
    let minute: i64 = text.get(14..16)?.parse().ok()?;
    let second: i64 = text.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    Some(seconds * 1000)
}

/// Howard Hinnant's `days_from_civil`: days since the Unix epoch for a
/// proleptic-Gregorian civil date. Standard, well-tested algorithm — chosen
/// over a date-library dependency for one fixed, wrapper-controlled format.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

fn read_policy() -> pb::UpdatePolicy {
    let (schedule, services) = read_schedule_config();
    let (last_run, last_run_at) = read_status_file();
    pb::UpdatePolicy {
        schedule,
        services,
        last_run,
        last_run_at,
    }
}

// ─────────────────────────── RPCs ───────────────────────────

/// What each service's images resolve to right now. Unary: bounded (one
/// metadata request per image), and it changes nothing on the host.
///
/// Refusals mirror `uninstall::remove_service`'s shape (unknown catalog id,
/// missing wrapper) — a single unsupported-to-THIS-wrapper id (a
/// self-managed service asked about by itself is fine, see below; something
/// the wrapper's plan never included, like a built-on-server VPN protocol, is
/// not) surfaces as the wrapper's own words via `wrapper_failed`, the same
/// path every other "the wrapper said no" case in this crate takes.
pub async fn check_updates(codec: Codec, req: pb::CheckUpdatesRequest) -> Resp {
    let label = if req.service_id.is_empty() {
        None
    } else {
        match discover::known_service_id(&req.service_id) {
            Some(label) => Some(label),
            None => return Rejection::UnknownService(req.service_id.clone()).response(),
        }
    };
    if !wrapper_path().exists() {
        return Rejection::NoWrapper.response();
    }
    let target = label.unwrap_or(ALL_TARGET);
    match run_wrapper(&["check", target], CHECK_TIMEOUT_SECS).await {
        Ok(output) => encode(
            codec,
            &pb::UpdateCheckResult {
                services: parse_check_output(&output.stdout),
            },
        ),
        Err(why) => wrapper_failed(&why),
    }
}

/// The schedule and the last run's record, in one answer — see the proto's
/// own reasoning for why splitting them is how a server failing every night
/// reads as healthy. Read straight off disk (see the two constants above):
/// there is no wrapper subcommand for the schedule half, and the status half
/// is world-readable for exactly this reason.
pub async fn get_update_policy(codec: Codec, _req: pb::GetUpdatePolicyRequest) -> Resp {
    if !wrapper_path().exists() {
        return Rejection::NoWrapper.response();
    }
    encode(codec, &read_policy())
}

/// Set the schedule; answer with the policy RE-READ from the server. The
/// wrapper strips services it does not manage, so echoing the request back
/// would show the owner a switch that does not match what will actually run.
pub async fn set_update_schedule(codec: Codec, req: pb::SetUpdateScheduleRequest) -> Resp {
    if !wrapper_path().exists() {
        return Rejection::NoWrapper.response();
    }
    let mut args: Vec<&str> = vec!["set-schedule", req.schedule.as_str()];
    for service in &req.services {
        args.push(service.as_str());
    }
    if let Err(why) = run_wrapper(&args, QUICK_TIMEOUT_SECS).await {
        return wrapper_failed(&why);
    }
    encode(codec, &read_policy())
}

/// Apply one service's update, streaming the wrapper's output.
///
/// Errors travel on two channels — but with the one documented exception the
/// proto calls out: whether `run <label>` even applies to this id (self
/// managed, or simply not part of the wrapper's plan) is discovered by
/// running it, so that refusal happens AFTER the stream opens, and it ends
/// with an error trailer carrying NO `COMPLETED` event at all — the absence
/// of a post-action status IS the message "nothing happened". Every other
/// outcome (updated, rolled back, failed) sends `COMPLETED` with the re-read
/// status before anything else, exactly like `backup::run_backup` and
/// `uninstall::remove_service`.
pub async fn run_update(codec: Codec, req: pb::RunUpdateRequest) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("service", &req.service_id) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let label = match resolve(&req.service_id) {
        Ok(label) => label,
        Err(rejection) => return rejection.response(),
    };

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let service_id = req.service_id.clone();

    tokio::spawn(async move {
        let _claim = claim;
        run(&service_id, label, codec, tx).await;
    });

    stream_response(json, rx)
}

/// The production entry point: reads the post-update status from the real
/// host. Split out from `run_with` so tests can supply a stand-in status
/// reader, the same split `uninstall.rs` uses and for the same reason — no
/// live docker daemon is required to prove event ordering and marker
/// detection.
async fn run(service_id: &str, label: &'static str, codec: Codec, tx: Sender<Bytes>) {
    run_with(service_id, label, codec, tx, |id| async move { read_service_status(&id).await }).await;
}

async fn run_with<F, Fut>(service_id: &str, label: &'static str, codec: Codec, tx: Sender<Bytes>, status_reader: F)
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<pb::ServiceStatusResponse, String>>,
{
    let sink = EventSink {
        tx,
        codec,
        service_id: service_id.to_string(),
        journal: crate::jobs::Journal::open(pb::JobKind::Update, service_id),
    };
    let _ = sink.started().await;

    let run = run_wrapper_streaming(&["run", label], RUN_TIMEOUT_SECS, &sink).await;

    match parse_run_outcome(&run.stdout) {
        Some((outcome, reason)) => {
            // UPDATED needs no trailer at all; ROLLED_BACK and FAILED are
            // both a recorded failure of the run, so the stream still ends in
            // an error — but only after COMPLETED, the same two-channel rule
            // every other streamed operation in this crate follows.
            let mut failure: Option<String> = if outcome == pb::UpdateOutcome::Updated {
                None
            } else if reason.is_empty() {
                Some(format!("the update ended as {outcome:?}"))
            } else {
                Some(reason.clone())
            };
            let status = match status_reader(service_id.to_string()).await {
                Ok(status) => Some(status),
                Err(err) => {
                    failure.get_or_insert_with(|| format!("could not re-read status after the update: {err}"));
                    None
                }
            };
            let _ = sink.completed(outcome, &reason, status).await;
            if let Some(why) = failure {
                // `internal` on purpose: the run really ran, and what it did
                // is in the COMPLETED event that just went out.
                let _ = sink.fail("internal", &why).await;
            }
        }
        // No marker at all: the wrapper touched nothing (self-managed, or an
        // id its plan never included). No COMPLETED event — see the doc
        // comment on `run_update`.
        None => {
            // Exit 2 is the wrapper's REFUSAL code and only that: an invalid
            // label, a service its plan never included, a service that ships
            // its own updater. Nothing broke and nothing was touched, so the
            // trailer says `failed_precondition` — the same answer the
            // install gate gives to a real id it cannot serve. Every other
            // ending here is genuinely unexpected (the wrapper would not
            // spawn, or it exited 0 without saying what it did) and stays
            // `internal`. Measured on a live host 2026-08-16: this branch is
            // the ONLY thing a self-managed service ever reaches, so a client
            // that reads codes could not otherwise tell "this was never going
            // to run" from "the agent broke".
            let (code, why) = match &run.status {
                Err(spawn_err) => ("internal", spawn_err.clone()),
                Ok(status) if status.success() => (
                    "internal",
                    "the update wrapper exited without printing an outcome marker".to_string(),
                ),
                Ok(status) => {
                    let code = if status.code() == Some(REFUSAL_EXIT_CODE) {
                        "failed_precondition"
                    } else {
                        "internal"
                    };
                    (code, describe_failure(status.code(), &run.stderr))
                }
            };
            let _ = sink.fail(code, &why).await;
        }
    }
}

/// The freshly re-read status of one service — identical shape to
/// `uninstall.rs`'s own `read_status`, duplicated rather than shared because
/// the two modules deliberately do not depend on each other (see the crate's
/// running rule about wrapper-path literals).
async fn read_service_status(service_id: &str) -> Result<pb::ServiceStatusResponse, String> {
    let display = discover::known_service(service_id).unwrap_or(service_id);
    match discover::service_snapshot(service_id).await {
        Ok(Some(service)) => Ok(pb::ServiceStatusResponse {
            service: Some(service),
            installed: true,
        }),
        Ok(None) => Ok(pb::ServiceStatusResponse {
            service: Some(pb::Service {
                // Filled by `Store::snapshot` from the column the install
                // raises; an update has no claim of its own to make.
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

// ─────────────────────────── Wrapper plumbing ───────────────────────────

struct QuickOutput {
    stdout: String,
}

/// Spawn the wrapper, wait for it to finish, return its stdout. No shell, no
/// stdin (`check`, `set-schedule` and `status` never read one) — stdin is
/// closed rather than inherited so the child can never block on it.
async fn run_wrapper(args: &[&str], timeout_secs: u64) -> Result<QuickOutput, String> {
    let child = tokio::process::Command::new(wrapper_path())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run the update wrapper: {err}"))?;

    let output = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
        .await
        .map_err(|_| format!("the update wrapper timed out after {timeout_secs}s"))?
        .map_err(|err| format!("the update wrapper did not finish: {err}"))?;

    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    if output.status.success() {
        return Ok(QuickOutput { stdout });
    }
    let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr));
    Err(describe_failure(output.status.code(), &stderr))
}

/// What one `run` invocation produced, regardless of how it ended — the
/// caller (`run_with`) decides success/failure from the MARKERS in `stdout`,
/// never from `status` alone (mirrors every other wrapper in this crate).
struct WrapperRun {
    stdout: String,
    stderr: String,
    /// `Err` only when the process itself could not be run to completion
    /// (spawn failure, timeout, wait failure) — a machinery fault distinct
    /// from the wrapper's own exit code.
    status: Result<std::process::ExitStatus, String>,
}

/// Same spawn as `run_wrapper`, but every output line is streamed as a
/// PROGRESS event while the run is under way, and the child gets a writable
/// HOME/GNUPGHOME: `run` calls the BACKUP wrapper internally, which reaches
/// `gpg` for every encrypted service, and the unit's `ProtectHome=true`
/// leaves the inherited `$HOME` read-only. Reuses `backup::wrapper_home`
/// rather than a second implementation of that fix.
async fn run_wrapper_streaming(args: &[&str], timeout_secs: u64, sink: &EventSink) -> WrapperRun {
    let home = crate::backup::wrapper_home();
    let spawned = tokio::process::Command::new(wrapper_path())
        .args(args)
        .env("HOME", &home)
        .env("GNUPGHOME", home.join(".gnupg"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();

    let mut child = match spawned {
        Ok(child) => child,
        Err(err) => {
            return WrapperRun {
                stdout: String::new(),
                stderr: String::new(),
                status: Err(format!("could not run the update wrapper: {err}")),
            };
        }
    };

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut stdout = String::new();
    let mut stderr = String::new();

    // ONE deadline for the whole run rather than a per-line one: an update is
    // silent for long stretches (health waits, a slow pull), and a quiet
    // minute is not a hung command.
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
        Err(_) => WrapperRun {
            stdout,
            stderr,
            status: Err(format!("the update wrapper timed out after {timeout_secs}s")),
        },
        Ok(Err(io)) => WrapperRun {
            stdout,
            stderr,
            status: Err(format!("the update wrapper did not finish: {io}")),
        },
        Ok(Ok(status)) => WrapperRun { stdout, stderr, status: Ok(status) },
    }
}

fn describe_failure(code: Option<i32>, stderr: &str) -> String {
    let detail = stderr.trim();
    let detail: String = detail.chars().rev().take(400).collect::<Vec<_>>().into_iter().rev().collect();
    match (code, detail.is_empty()) {
        (_, false) => detail,
        (Some(code), true) => format!("the update wrapper exited {code}"),
        (None, true) => "the update wrapper was killed by a signal".to_string(),
    }
}

fn wrapper_failed(detail: &str) -> Resp {
    connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", detail)
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec
        .encode(message)
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
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
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::UpdateEvent {
        pb::UpdateEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            service_id: self.service_id.clone(),
            text: String::new(),
            stream: String::new(),
            outcome: pb::UpdateOutcome::Unspecified as i32,
            reason: String::new(),
            status: None,
        }
    }

    async fn send(&self, event: pb::UpdateEvent) -> Result<(), ()> {
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

    async fn completed(
        &self,
        outcome: pb::UpdateOutcome,
        reason: &str,
        status: Option<pb::ServiceStatusResponse>,
    ) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.outcome = outcome as i32;
        event.reason = reason.to_string();
        event.status = status;
        self.send(event).await
    }

    /// End the stream with a Connect error trailer. Always sent AFTER
    /// `completed` when both are sent — never instead of it, except for the
    /// one documented case (`run_with`'s `None` arm) where there is no
    /// completed status to send at all.
    ///
    /// The code is the caller's to choose and not this helper's to assume: a
    /// refusal that touched nothing and a run that broke halfway are the two
    /// things this stream exists to tell apart, and answering both `internal`
    /// spends that distinction on the one client that cannot recover it.
    async fn fail(&self, code: &str, message: &str) -> Result<(), ()> {
        // **The failure is the run's ending, and the record needs it in the
        // same words the trailer carries.** Without this the journal would be
        // closed by the drop below with "outcome not reported", which is true
        // of an early return and a lie about a failure that was named.
        crate::jobs::finish(&self.journal, Some(message));
        self.tx.send(error_trailer(code, message)).await.map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::END_OF_STREAM_FLAG;
    use prost::Message;

    /// The wrapper/config/status locations are overridden through the
    /// environment, which is process-wide, and cargo runs tests in parallel
    /// threads — without this the tests would flip each other's override and
    /// fail at random. Same technique as `backup.rs`/`uninstall.rs`.
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

    fn decode_data_frame(bytes: &Bytes) -> pb::UpdateEvent {
        assert_eq!(bytes[0], 0x00, "expected a data frame, got flags {:#x}", bytes[0]);
        pb::UpdateEvent::decode(&bytes[5..]).expect("valid UpdateEvent frame")
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

    // ─────────────────────────── marker parsing ───────────────────────────

    #[test]
    fn parse_after_marker_splits_service_from_a_multi_word_reason() {
        assert_eq!(
            parse_after_marker("GRYONIXNEXUS_UPDATE_ROLLED_BACK nextcloud a container is restarting", ROLLED_BACK_MARKER),
            Some(("nextcloud", "a container is restarting"))
        );
        assert_eq!(
            parse_after_marker("GRYONIXNEXUS_UPDATE_FAILED nextcloud the backup failed", FAILED_MARKER),
            Some(("nextcloud", "the backup failed"))
        );
        // Two-field markers: no reason at all.
        assert_eq!(
            parse_after_marker("GRYONIXNEXUS_UPDATE_DONE nextcloud", DONE_MARKER),
            Some(("nextcloud", ""))
        );
        assert_eq!(
            parse_after_marker("GRYONIXNEXUS_UPDATE_CURRENT vaultwarden", CURRENT_MARKER),
            Some(("vaultwarden", ""))
        );
        // A different marker, or no marker at all, matches nothing.
        assert_eq!(parse_after_marker("GRYONIXNEXUS_UPDATE_DONE nextcloud", ROLLED_BACK_MARKER), None);
        assert_eq!(parse_after_marker("nextcloud: updated by its own updater", DONE_MARKER), None);
    }

    // ─────────────────────────── check parsing ───────────────────────────

    #[test]
    fn check_output_groups_moved_images_and_orders_services_by_first_appearance() {
        let output = "\
GRYONIXNEXUS_UPDATE_AVAILABLE nextcloud nextcloud:apache
GRYONIXNEXUS_UPDATE_AVAILABLE nextcloud mariadb:11
GRYONIXNEXUS_UPDATE_CURRENT vaultwarden
GRYONIXNEXUS_UPDATE_UNKNOWN immich registry_unreachable
gitlab: updated by its own updater, not by this wrapper
GRYONIXNEXUS_UPDATE_CTL_DONE
";
        let services = parse_check_output(output);
        let ids: Vec<_> = services.iter().map(|s| s.service_id.as_str()).collect();
        // First-seen order, and the self-managed prose line and the trailing
        // CTL_DONE marker produced NO row at all.
        assert_eq!(ids, ["nextcloud", "vaultwarden", "immich"]);

        let nextcloud = &services[0];
        assert_eq!(nextcloud.availability, pb::UpdateAvailability::Available as i32);
        assert_eq!(nextcloud.moved_images, vec!["nextcloud:apache", "mariadb:11"]);
        assert_eq!(nextcloud.reason, "");

        let vaultwarden = &services[1];
        assert_eq!(vaultwarden.availability, pb::UpdateAvailability::Current as i32);
        assert!(vaultwarden.moved_images.is_empty());

        let immich = &services[2];
        assert_eq!(immich.availability, pb::UpdateAvailability::Unknown as i32);
        assert_eq!(immich.reason, "registry_unreachable");
    }

    #[test]
    fn an_unanswered_image_outranks_current_even_when_another_image_of_the_same_service_moved() {
        // The wrapper's own ordering rule ("an unanswered image outranks
        // 'nothing moved'"): AVAILABLE for one image, then UNKNOWN because a
        // second image could not be checked. The service must read UNKNOWN,
        // never CURRENT, and the moved image is still reported.
        let output = "\
GRYONIXNEXUS_UPDATE_AVAILABLE nextcloud nextcloud:apache
GRYONIXNEXUS_UPDATE_UNKNOWN nextcloud not_pulled
";
        let services = parse_check_output(output);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].availability, pb::UpdateAvailability::Unknown as i32);
        assert_eq!(services[0].reason, "not_pulled");
        assert_eq!(services[0].moved_images, vec!["nextcloud:apache"]);
    }

    #[test]
    fn docker_unavailable_marks_every_known_service_unknown() {
        let output = "\
GRYONIXNEXUS_UPDATE_UNKNOWN nextcloud docker_unavailable
GRYONIXNEXUS_UPDATE_UNKNOWN vaultwarden docker_unavailable
";
        let services = parse_check_output(output);
        assert_eq!(services.len(), 2);
        assert!(services.iter().all(|s| s.availability == pb::UpdateAvailability::Unknown as i32));
        assert!(services.iter().all(|s| s.reason == "docker_unavailable"));
    }

    #[test]
    fn a_self_managed_only_output_produces_zero_rows() {
        // No `SELF_MANAGED` variant exists in the schema on purpose — a
        // self-managed service must produce NO row, not an Unspecified one.
        assert!(parse_check_output("gitlab: updated by its own updater, not by this wrapper\nGRYONIXNEXUS_UPDATE_CTL_DONE\n").is_empty());
        assert!(parse_check_output("").is_empty());
    }

    // ─────────────────────────── run outcome parsing ───────────────────────────

    #[test]
    fn run_outcome_reads_each_marker_with_its_reason() {
        assert_eq!(
            parse_run_outcome("backing up nextcloud before updating it\nGRYONIXNEXUS_UPDATE_DONE nextcloud\nGRYONIXNEXUS_UPDATE_CTL_DONE\n"),
            Some((pb::UpdateOutcome::Updated, String::new()))
        );
        assert_eq!(
            parse_run_outcome("waiting for nextcloud: a container is restarting\nGRYONIXNEXUS_UPDATE_ROLLED_BACK nextcloud a container is restarting\n"),
            Some((pb::UpdateOutcome::RolledBack, "a container is restarting".to_string()))
        );
        assert_eq!(
            parse_run_outcome("the backup of nextcloud failed, so the update was not applied\nGRYONIXNEXUS_UPDATE_FAILED nextcloud the backup failed\n"),
            Some((pb::UpdateOutcome::Failed, "the backup failed".to_string()))
        );
        // Self-managed / not part of the plan: no marker anywhere.
        assert_eq!(
            parse_run_outcome("gitlab ships its own updater, so this wrapper does not swap its images\n"),
            None
        );
        assert_eq!(parse_run_outcome(""), None);
    }

    // ─────────────────────────── schedule config parsing ───────────────────────────

    #[test]
    fn schedule_config_reads_the_two_fields_the_wrapper_writes() {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("autoupdate.conf");
        std::fs::write(&config, "SCHEDULE=every:1d@04:00\nSERVICES='nextcloud immich'\n").unwrap();

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_UPDATE_CONFIG", &config);
        let (schedule, services) = read_schedule_config();
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_CONFIG");

        assert_eq!(schedule, "every:1d@04:00");
        assert_eq!(services, vec!["nextcloud", "immich"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_config_reads_as_the_wrappers_own_defaults() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_UPDATE_CONFIG", "/nonexistent/autoupdate.conf");
        let (schedule, services) = read_schedule_config();
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_CONFIG");
        assert_eq!(schedule, "off");
        assert!(services.is_empty());
    }

    #[test]
    fn empty_services_quotes_read_as_no_services() {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-config-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("autoupdate.conf");
        std::fs::write(&config, "SCHEDULE=off\nSERVICES=''\n").unwrap();

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_UPDATE_CONFIG", &config);
        let (schedule, services) = read_schedule_config();
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_CONFIG");

        assert_eq!(schedule, "off");
        assert!(services.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────── status file parsing ───────────────────────────

    #[test]
    fn status_file_reads_the_last_run_header_and_every_record() {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let status = dir.join("autoupdate-status.txt");
        std::fs::write(
            &status,
            "last-run 2026-08-08T04:00:03Z\nGRYONIXNEXUS_UPDATE_DONE nextcloud\nGRYONIXNEXUS_UPDATE_FAILED immich the backup failed\n",
        )
        .unwrap();

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_UPDATE_STATUS", &status);
        let (records, last_run_at) = read_status_file();
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_STATUS");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].service_id, "nextcloud");
        assert_eq!(records[0].outcome, pb::UpdateOutcome::Updated as i32);
        assert_eq!(records[1].service_id, "immich");
        assert_eq!(records[1].outcome, pb::UpdateOutcome::Failed as i32);
        assert_eq!(records[1].reason, "the backup failed");
        assert!(last_run_at > 0, "the last-run header must produce a non-zero timestamp");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_status_file_is_empty_history_not_an_error() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_UPDATE_STATUS", "/nonexistent/autoupdate-status.txt");
        let (records, last_run_at) = read_status_file();
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_STATUS");
        assert!(records.is_empty());
        // Only a SCHEDULED run writes the header; a host that has never run
        // one (or only ran manually) must read as 0, never a guessed time.
        assert_eq!(last_run_at, 0);
    }

    #[test]
    fn a_manual_runs_record_with_no_header_leaves_last_run_at_zero() {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-status-manual-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let status = dir.join("autoupdate-status.txt");
        std::fs::write(&status, "GRYONIXNEXUS_UPDATE_DONE nextcloud\n").unwrap();

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_UPDATE_STATUS", &status);
        let (records, last_run_at) = read_status_file();
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_STATUS");

        assert_eq!(records.len(), 1);
        assert_eq!(last_run_at, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────── ISO8601 parsing ───────────────────────────

    #[test]
    fn iso8601_parses_known_instants() {
        // date -u -d @0 → 1970-01-01T00:00:00Z
        assert_eq!(parse_iso8601_utc_millis("1970-01-01T00:00:00Z"), Some(0));
        // A round, well-known instant.
        assert_eq!(parse_iso8601_utc_millis("2000-01-01T00:00:00Z"), Some(946_684_800_000));
        // The exact stamp `gd_record`'s header would carry on this project's
        // "today".
        assert_eq!(parse_iso8601_utc_millis("2026-08-08T04:00:03Z"), Some(1_786_161_603_000));
    }

    #[test]
    fn iso8601_rejects_malformed_input_instead_of_guessing() {
        for bad in ["", "not a date", "2026-08-08 04:00:03Z", "2026-13-01T00:00:00Z", "2026-08-08T04:00:03"] {
            assert_eq!(parse_iso8601_utc_millis(bad), None, "{bad} must not parse");
        }
    }

    // ─────────────────────────── resolve / gate ───────────────────────────

    #[test]
    fn unknown_service_id_is_refused_before_anything_runs() {
        assert_eq!(resolve("nope"), Err(Rejection::UnknownService("nope".into())));
        assert!(matches!(resolve("nextcloud; rm -rf /"), Err(Rejection::UnknownService(_))));
    }

    #[test]
    fn a_host_with_no_wrapper_is_told_what_to_do_and_the_unknown_id_check_comes_first() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", "/nonexistent/gryonixnexus-update-ctl.sh");
        assert_eq!(resolve("nextcloud"), Err(Rejection::NoWrapper));
        assert_eq!(resolve("nope"), Err(Rejection::UnknownService("nope".into())));
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
    }

    #[test]
    fn missing_wrapper_response_is_failed_precondition_naming_the_path() {
        let (status, code, message) = Rejection::NoWrapper.parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains(WRAPPER_PATH));
        assert!(message.to_lowercase().contains("re-run"));
    }

    #[test]
    fn the_label_that_reaches_argv_is_the_agents_own_string_not_the_requests() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-ptr-{}", std::process::id()));
        let script = write_stub(&dir, "update-ctl.sh", "#!/bin/sh\necho done\n");
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", &script);

        let from_the_wire = String::from("nextcloud");
        let label = resolve(&from_the_wire).expect("a catalog id resolves");
        assert_eq!(label, "nextcloud");
        assert!(
            !std::ptr::eq(label.as_ptr(), from_the_wire.as_ptr()),
            "the wrapper label must come from the agent's table, not from the request"
        );

        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn describe_failure_prefers_the_wrappers_own_words() {
        assert_eq!(describe_failure(Some(2), "unsupported service: vpn\n"), "unsupported service: vpn");
        assert_eq!(describe_failure(Some(2), "   "), "the update wrapper exited 2");
        assert_eq!(describe_failure(None, ""), "the update wrapper was killed by a signal");
    }

    // ─────────────────────────── check_updates, against a real stub ───────────────────────────

    #[tokio::test]
    async fn check_updates_all_parses_a_realistic_wrapper_run() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-check-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "update-ctl.sh",
            "#!/bin/sh\n\
             echo 'GRYONIXNEXUS_UPDATE_AVAILABLE nextcloud nextcloud:apache'\n\
             echo 'GRYONIXNEXUS_UPDATE_CURRENT vaultwarden'\n\
             echo 'GRYONIXNEXUS_UPDATE_UNKNOWN immich registry_unreachable'\n\
             echo 'gitlab: updated by its own updater, not by this wrapper'\n\
             echo 'GRYONIXNEXUS_UPDATE_CTL_DONE'\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", &script);

        let resp = check_updates(Codec::Proto, pb::CheckUpdatesRequest { service_id: String::new() }).await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let result = pb::UpdateCheckResult::decode(body).expect("valid UpdateCheckResult");
        let ids: Vec<_> = result.services.iter().map(|s| s.service_id.as_str()).collect();
        assert_eq!(ids, ["nextcloud", "vaultwarden", "immich"]);

        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn check_updates_reports_no_wrapper_when_the_host_has_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", "/nonexistent/gryonixnexus-update-ctl.sh");
        let resp = check_updates(Codec::Proto, pb::CheckUpdatesRequest { service_id: String::new() }).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
    }

    #[tokio::test]
    async fn check_updates_refuses_an_unknown_service_before_touching_the_host() {
        let resp = check_updates(
            Codec::Proto,
            pb::CheckUpdatesRequest {
                service_id: "nope".to_string(),
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ─────────────────────────── run_update, against a real stub ───────────────────────────

    fn no_status_reader(_id: String) -> impl std::future::Future<Output = Result<pb::ServiceStatusResponse, String>> {
        async {
            Ok(pb::ServiceStatusResponse {
                service: Some(pb::Service {
                    installed_outside: false,
                    id: "nextcloud".to_string(),
                    display_name: "Nextcloud".to_string(),
                    status: pb::ServiceStatus::Running as i32,
                    version: "30.0.1".to_string(),
                    containers: Vec::new(),
                }),
                installed: true,
            })
        }
    }

    /// This reads the CHANNEL, not the wire: the success trailer is appended by
    /// `ChannelBody` when the sender drops, so the absence checked here is the
    /// absence of an ERROR trailer — a run that went well says so by staying
    /// quiet, and the terminal envelope is added one layer down. Renamed from
    /// "…with_no_trailer_at_all", which stopped being true of the wire the day
    /// the terminal envelope was added and would have gone on passing anyway.
    #[tokio::test]
    async fn a_successful_update_puts_no_error_trailer_on_the_channel() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-done-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "update-ctl.sh",
            "#!/bin/sh\necho 'backing up nextcloud before updating it'\necho 'GRYONIXNEXUS_UPDATE_DONE nextcloud'\necho 'GRYONIXNEXUS_UPDATE_CTL_DONE'\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        run_with("nextcloud", "nextcloud", Codec::Proto, tx, no_status_reader).await;

        let frames = drain(&mut rx).await;
        assert!(frames.iter().all(|f| !is_trailer(f)), "a successful update must not send an error trailer");
        let events: Vec<_> = frames.iter().map(decode_data_frame).collect();
        assert_eq!(events.first().unwrap().phase, pb::ServiceOperationPhase::Started as i32);
        let completed = events.last().unwrap();
        assert_eq!(completed.phase, pb::ServiceOperationPhase::Completed as i32);
        assert_eq!(completed.outcome, pb::UpdateOutcome::Updated as i32);
        assert!(completed.status.as_ref().unwrap().installed);

        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_rolled_back_update_completes_then_sends_a_trailer_carrying_the_reason() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-rollback-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "update-ctl.sh",
            "#!/bin/sh\necho 'waiting for nextcloud: a container is restarting' >&2\necho 'GRYONIXNEXUS_UPDATE_ROLLED_BACK nextcloud a container is restarting'\nexit 1\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        run_with("nextcloud", "nextcloud", Codec::Proto, tx, no_status_reader).await;

        let frames = drain(&mut rx).await;
        let (last, rest) = frames.split_last().unwrap();
        assert!(is_trailer(last), "the LAST frame must be the error trailer");
        let completed = rest
            .iter()
            .map(decode_data_frame)
            .find(|e| e.phase == pb::ServiceOperationPhase::Completed as i32)
            .expect("a COMPLETED event must precede the trailer");
        assert_eq!(completed.outcome, pb::UpdateOutcome::RolledBack as i32);
        assert_eq!(completed.reason, "a container is restarting");
        assert!(completed.status.is_some(), "the re-read status must still be sent on a rollback");

        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_failed_update_completes_then_sends_a_trailer_carrying_the_reason() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-failed-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "update-ctl.sh",
            "#!/bin/sh\necho 'the backup of nextcloud failed, so the update was not applied' >&2\necho 'GRYONIXNEXUS_UPDATE_FAILED nextcloud the backup failed'\nexit 1\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        run_with("nextcloud", "nextcloud", Codec::Proto, tx, no_status_reader).await;

        let frames = drain(&mut rx).await;
        let (last, rest) = frames.split_last().unwrap();
        assert!(is_trailer(last));
        let completed = rest
            .iter()
            .map(decode_data_frame)
            .find(|e| e.phase == pb::ServiceOperationPhase::Completed as i32)
            .unwrap();
        assert_eq!(completed.outcome, pb::UpdateOutcome::Failed as i32);
        assert_eq!(completed.reason, "the backup failed");

        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_service_the_wrapper_does_not_touch_ends_with_a_trailer_and_no_completed_event_at_all() {
        // The one documented exception: self-managed (or simply not part of
        // the wrapper's plan) is discovered by running it, so the stream
        // already opened (STARTED went out) before the refusal — and unlike
        // every other failure path in this crate, there is NO COMPLETED
        // event before the trailer, because nothing was touched to report on.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-selfmanaged-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "update-ctl.sh",
            "#!/bin/sh\necho 'gitlab ships its own updater, so this wrapper does not swap its images' >&2\nexit 2\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        run_with("gitlab", "gitlab", Codec::Proto, tx, no_status_reader).await;

        let frames = drain(&mut rx).await;
        let events: Vec<_> = frames.iter().filter(|f| !is_trailer(f)).map(decode_data_frame).collect();
        // STARTED, plus the stderr sentence streamed as ordinary PROGRESS
        // (the client is entitled to see it arrive) — what must be absent is
        // specifically a COMPLETED event.
        assert_eq!(events[0].phase, pb::ServiceOperationPhase::Started as i32);
        assert!(
            !events.iter().any(|e| e.phase == pb::ServiceOperationPhase::Completed as i32),
            "a run that touched nothing must not send a COMPLETED event"
        );

        let last = frames.last().unwrap();
        assert!(is_trailer(last), "the stream must still end in an error trailer");
        let payload = String::from_utf8(last[5..].to_vec()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ships its own updater"));
        // The CODE, not just the sentence: this client reads the message, but
        // the conformant one the wire format exists for reads the code, and
        // for it a refusal that touched nothing must not look like a crash.
        assert_eq!(parsed["error"]["code"], "failed_precondition");

        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_wrapper_that_actually_broke_still_ends_in_an_internal_trailer() {
        // The other half of the rule above, and the reason it keys on the
        // wrapper's exit code rather than on the absence of a marker: a
        // wrapper that dies for any other reason has NOT refused, and calling
        // that a precondition would tell a client to stop asking about a
        // server that merely needs looking at. Exit 1 is what a scheduled
        // sweep uses when services in it failed.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-broken-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "update-ctl.sh",
            "#!/bin/sh\necho 'the update failed for: nextcloud' >&2\nexit 1\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        run_with("nextcloud", "nextcloud", Codec::Proto, tx, no_status_reader).await;

        let frames = drain(&mut rx).await;
        let last = frames.last().unwrap();
        assert!(is_trailer(last), "the stream must end in an error trailer");
        let payload = String::from_utf8(last[5..].to_vec()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["error"]["code"], "internal");

        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_update_hands_the_wrapper_a_home_it_can_actually_write_to() {
        // Same live defect class `backup.rs` already fixed: `run` calls the
        // BACKUP wrapper internally, and the unit's ProtectHome leaves the
        // inherited $HOME read-only. Reusing `backup::wrapper_home` is what
        // is pinned here, not a second implementation of the fix.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Shared with the other modules that redirect this variable — see
        // `util::STATE_DIR_ENV_LOCK`.
        let _state_guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-home-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "update-ctl.sh",
            "#!/bin/sh\necho \"HOME: $HOME\"\necho \"GNUPGHOME: $GNUPGHOME\"\necho 'GRYONIXNEXUS_UPDATE_DONE nextcloud'\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", &script);
        let state = dir.join("state");
        std::env::set_var("GRYONIXNEXUSD_STATE_DIR", &state);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        run_with("nextcloud", "nextcloud", Codec::Proto, tx, no_status_reader).await;

        let frames = drain(&mut rx).await;
        let home = state.join("wrapper-home");
        let progressed_home = frames
            .iter()
            .filter(|f| !is_trailer(f))
            .map(decode_data_frame)
            .any(|e| e.phase == pb::ServiceOperationPhase::Progress as i32 && e.text.contains(&format!("HOME: {}", home.display())));
        assert!(progressed_home, "the child must see the agent's own wrapper-home as HOME");

        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_update_refuses_an_unknown_service_before_the_stream_opens() {
        let resp = run_update(
            Codec::Proto,
            pb::RunUpdateRequest {
                service_id: "nope".to_string(),
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ─────────────────────────── get/set schedule ───────────────────────────

    #[tokio::test]
    async fn get_update_policy_reads_schedule_and_history_off_disk() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let wrapper = write_stub(&dir, "update-ctl.sh", "#!/bin/sh\necho unused\n");
        let config = dir.join("autoupdate.conf");
        std::fs::write(&config, "SCHEDULE=every:1d@04:00\nSERVICES='nextcloud'\n").unwrap();
        let status = dir.join("autoupdate-status.txt");
        std::fs::write(&status, "last-run 2026-08-08T04:00:03Z\nGRYONIXNEXUS_UPDATE_DONE nextcloud\n").unwrap();

        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", &wrapper);
        std::env::set_var("GRYONIXNEXUSD_UPDATE_CONFIG", &config);
        std::env::set_var("GRYONIXNEXUSD_UPDATE_STATUS", &status);

        let resp = get_update_policy(Codec::Proto, pb::GetUpdatePolicyRequest {}).await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let policy = pb::UpdatePolicy::decode(body).unwrap();
        assert_eq!(policy.schedule, "every:1d@04:00");
        assert_eq!(policy.services, vec!["nextcloud"]);
        assert_eq!(policy.last_run.len(), 1);
        assert!(policy.last_run_at > 0);

        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_CONFIG");
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_STATUS");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn get_update_policy_reports_no_wrapper_when_the_host_has_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", "/nonexistent/gryonixnexus-update-ctl.sh");
        let resp = get_update_policy(Codec::Proto, pb::GetUpdatePolicyRequest {}).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
    }

    #[tokio::test]
    async fn set_update_schedule_answers_with_the_policy_re_read_from_disk_not_the_request() {
        // The wrapper drops services it does not manage; the request here
        // asks for "gitlab" too, but the CONFIG file this stub leaves behind
        // (as the REAL wrapper would after filtering) omits it. The answer
        // must reflect the file, proving it is not an echo of the request.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-setsched-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("autoupdate.conf");
        // Pre-seeded as if a PRIOR real wrapper run already filtered gitlab
        // out — the stub below does not touch this file at all, so any
        // agreement between the response and this file proves the read path,
        // not a lucky echo.
        std::fs::write(&config, "SCHEDULE=every:1d@04:00\nSERVICES='nextcloud'\n").unwrap();
        let wrapper = write_stub(&dir, "update-ctl.sh", "#!/bin/sh\necho \"ARGV: $*\" > \"$(dirname \"$0\")/argv.txt\"\n");

        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", &wrapper);
        std::env::set_var("GRYONIXNEXUSD_UPDATE_CONFIG", &config);
        std::env::set_var("GRYONIXNEXUSD_UPDATE_STATUS", dir.join("autoupdate-status.txt"));

        let resp = set_update_schedule(
            Codec::Proto,
            pb::SetUpdateScheduleRequest {
                schedule: "every:1d@04:00".to_string(),
                services: vec!["nextcloud".to_string(), "gitlab".to_string()],
            },
        )
        .await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let policy = pb::UpdatePolicy::decode(body).unwrap();
        assert_eq!(policy.schedule, "every:1d@04:00");
        assert_eq!(policy.services, vec!["nextcloud"], "gitlab must not appear: the answer is read, not echoed");

        let argv = std::fs::read_to_string(dir.join("argv.txt")).unwrap();
        assert_eq!(argv.trim(), "ARGV: set-schedule every:1d@04:00 nextcloud gitlab");

        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_CONFIG");
        std::env::remove_var("GRYONIXNEXUSD_UPDATE_STATUS");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_update_schedule_surfaces_a_bad_grammar_refusal_in_the_wrappers_own_words() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-update-badsched-{}", std::process::id()));
        let wrapper = write_stub(
            &dir,
            "update-ctl.sh",
            "#!/bin/sh\necho 'unsupported schedule: bogus' >&2\nexit 2\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UPDATE_WRAPPER", &wrapper);

        let resp = set_update_schedule(
            Codec::Proto,
            pb::SetUpdateScheduleRequest {
                schedule: "bogus".to_string(),
                services: vec![],
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["message"].as_str().unwrap().contains("unsupported schedule"));

        std::env::remove_var("GRYONIXNEXUSD_UPDATE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
