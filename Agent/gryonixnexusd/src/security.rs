//! `Security/GetSecurityStatus` — a read-only window onto the host's own
//! intrusion defence (CrowdSec + the nftables firewall bouncer).
//!
//! **Nothing here installs, changes or removes anything.** CrowdSec is put on
//! the host and kept current by `install::crowdsec` from `ProvisionHost`,
//! beside the firewall and the admin guard — its module doc explains at length
//! why it is host protection and not a catalog service. This module exists for
//! one reason: a defence nobody can see is a defence nobody trusts, and the app
//! had no way to show the owner that it is running or what it has caught.
//!
//! Every number is read from a fast local `cscli` call at request time — the
//! agent stores none of it, so the card is always live. A host where CrowdSec
//! is missing or its postinst failed (`cscli` answers but `config.yaml` is not
//! there — the exact state measured on the first live install) comes back with
//! `present = false` and the rest zeroed, never an error: the card then says
//! the protection is not in place, which is the true and useful thing to show.
//!
//! No shell and no stdin: `cscli`/`systemctl` are spawned directly, every
//! argument its own argv element, stdin closed.
//!
//! ## The one thing here that DOES change the host
//!
//! `GetSshPasswordState` / `SetSshPasswordLogin` sit beside the CrowdSec read
//! because the owner asks them as one question — "is this machine's front door
//! safe" — and the app draws them on one card. They are the exception to the
//! paragraph above and say so loudly: the work is `install::ssh_password`'s,
//! which is where the drop-in, the numbering, the `sshd -t` rollback and the
//! key guard are documented and pinned. Nothing about that policy is decided
//! here; this module only carries a request to it and a state back.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use hyper::StatusCode;
use tokio::io::AsyncBufReadExt;
use serde_json::Value;

use crate::api::{connect_error, Codec, Resp};
use crate::install::packages::have_binary;
use crate::install::ssh_password;
use crate::pb;
use crate::util::strip_ansi;

/// The package's config file. Its presence — not the binary's — is what tells
/// an installed CrowdSec apart from one whose postinst died after dpkg
/// unpacked the binary but before it wrote any configuration. Same test
/// `install::crowdsec::engine_configured` uses, and for the same reason.
const CONFIG_PATH: &str = "/etc/crowdsec/config.yaml";
const ENGINE_UNIT: &str = "crowdsec";
const BOUNCER_UNIT: &str = "crowdsec-firewall-bouncer";
const CSCLI_BIN: &str = "cscli";

/// One call's deadline. `cscli` talks to a local API over a unix socket; this
/// is generous for that and has nothing in common with the ten-minute ceilings
/// the container-engine wrappers need.
const QUICK_TIMEOUT_SECS: u64 = 20;

/// How many entries the card shows. Small on purpose — the card is a summary,
/// not a log; the full picture is `cscli` on the box.
const TOP_SCENARIOS: usize = 5;
const RECENT_BANS: usize = 8;

fn cscli_bin() -> String {
    std::env::var("GRYONIXNEXUSD_CSCLI_BIN").unwrap_or_else(|_| CSCLI_BIN.to_string())
}

fn config_path() -> PathBuf {
    PathBuf::from(
        std::env::var("GRYONIXNEXUSD_CROWDSEC_CONFIG").unwrap_or_else(|_| CONFIG_PATH.to_string()),
    )
}

/// cscli is reachable AND the package's config exists — "configured", not
/// merely "unpacked".
fn present() -> bool {
    have_binary(&cscli_bin()) && config_path().exists()
}

/// `systemctl is-active <unit>` → true only on a literal `active`.
async fn unit_active(unit: &str) -> bool {
    let Ok(child) = tokio::process::Command::new("systemctl")
        .args(["is-active", unit])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    else {
        return false;
    };
    let Ok(Ok(output)) =
        tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output()).await
    else {
        return false;
    };
    String::from_utf8_lossy(&output.stdout).trim() == "active"
}

/// Run `cscli <args>` and return its stdout, or `None` on any failure — a
/// missing binary, a non-zero exit, a timeout. The caller treats `None` as
/// "this number is unavailable", never as an error.
async fn cscli(args: &[&str]) -> Option<String> {
    let child = tokio::process::Command::new(cscli_bin())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let output =
        tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output())
            .await
            .ok()?
            .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(strip_ansi(&String::from_utf8_lossy(&output.stdout)))
}

/// `cscli version` prints `version: v1.8.0-debian-pragmatic-amd64-<hash>` as
/// its first line. The card wants the version, not the build string, so this
/// stops at the first `-`.
fn parse_engine_version(output: &str) -> String {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("version:"))
        .map(str::trim)
        .map(|v| v.split('-').next().unwrap_or(v).to_string())
        .unwrap_or_default()
}

/// `cscli alerts list … -o json` is a JSON array; the count is its length.
/// A non-array (an error object, an empty body) counts as zero.
fn parse_alert_count(json: &str) -> u32 {
    serde_json::from_str::<Value>(json)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len() as u32))
        .unwrap_or(0)
}

/// The most recent alerts as ban rows for the "caught these" list. Reads only
/// the fields the card shows and skips a row missing an address — an alert
/// without a source IP is not one the owner can act on.
fn parse_recent_bans(json: &str, limit: usize) -> Vec<pb::SecurityBan> {
    let Ok(Value::Array(alerts)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    alerts
        .iter()
        .filter_map(|alert| {
            let source = alert.get("source")?;
            let ip = source.get("value").and_then(Value::as_str).unwrap_or_default();
            if ip.is_empty() {
                return None;
            }
            Some(pb::SecurityBan {
                ip: ip.to_string(),
                country: source
                    .get("cn")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                scenario: alert
                    .get("scenario")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                at: alert
                    .get("created_at")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .take(limit)
        .collect()
}

/// `cscli metrics -o json` carries an `alerts` object of `{scenario: count}`,
/// all-time. The card shows the busiest few, most first.
fn parse_top_scenarios(metrics: &Value, limit: usize) -> Vec<pb::SecurityScenario> {
    let Some(alerts) = metrics.get("alerts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut rows: Vec<pb::SecurityScenario> = alerts
        .iter()
        .filter_map(|(name, count)| {
            Some(pb::SecurityScenario {
                name: name.clone(),
                count: count.as_u64()? as u32,
            })
        })
        .collect();
    // Count descending, then name so equal counts do not reshuffle between
    // reads off an unordered map.
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    rows.truncate(limit);
    rows
}

/// The community blocklist the bouncer is enforcing — addresses reported by
/// other CrowdSec installations, summed across every bouncer's `CAPI`
/// active-decision count in `cscli metrics -o json`.
fn parse_community_blocklist_ips(metrics: &Value) -> u32 {
    walk_bouncers(metrics)
        .filter(|(origin, _)| *origin == "CAPI")
        .filter_map(|(_, body)| {
            body.get("active_decisions")
                .and_then(|d| d.get("ip"))
                .and_then(Value::as_u64)
        })
        .sum::<u64>() as u32
}

/// Packets the bouncer has dropped since it started, across every source
/// (`CAPI`, local `crowdsec`, `cscli`), summed over every bouncer.
fn parse_packets_dropped(metrics: &Value) -> u64 {
    walk_bouncers(metrics)
        .filter_map(|(_, body)| {
            body.get("dropped")
                .and_then(|d| d.get("packet"))
                .and_then(Value::as_u64)
        })
        .sum()
}

/// Yields `(origin, body)` for every `bouncers.<name>.<origin>` object in the
/// metrics — the shape `cscli metrics -o json` uses for per-bouncer counters.
fn walk_bouncers(metrics: &Value) -> impl Iterator<Item = (&str, &Value)> {
    metrics
        .get("bouncers")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|bouncers| bouncers.values())
        .filter_map(Value::as_object)
        .flat_map(|by_origin| by_origin.iter())
        .map(|(origin, body)| (origin.as_str(), body))
}

/// Assemble the status from the host. Never fails: a host without CrowdSec
/// answers `present = false`, and any single `cscli` call that does not come
/// back just leaves its own field at zero.
pub async fn get_security_status(codec: Codec, _req: pb::GetSecurityStatusRequest) -> Resp {
    let mut status = pb::SecurityStatus::default();

    if !present() {
        return encode(codec, &status);
    }
    status.present = true;
    status.engine_running = unit_active(ENGINE_UNIT).await;
    status.bouncer_running = unit_active(BOUNCER_UNIT).await;

    if let Some(version) = cscli(&["version"]).await {
        status.engine_version = parse_engine_version(&version);
    }
    // `--limit 0` on both counting calls, and it is not decoration: without it
    // cscli applies its own default page size — 50 for alerts, 100 for
    // decisions — and `parse_alert_count` returns the length of what came
    // back, so the card would stop counting there and never move again.
    // Measured on `vps-middle` 2026-09-02: the same window answered 50 without
    // the flag and 53 with it. The third call below passes `--limit 16`
    // deliberately, which is why the flag was known and these two still missed
    // it; the fixtures have 4 and 0 rows, so nothing under test could reach the
    // cap.
    if let Some(json) = cscli(&["alerts", "list", "--since", "24h", "--limit", "0", "-o", "json"]).await {
        status.alerts_24h = parse_alert_count(&json);
    }
    if let Some(json) = cscli(&["decisions", "list", "--limit", "0", "-o", "json"]).await {
        status.local_bans = parse_alert_count(&json);
    }
    if let Some(json) = cscli(&["alerts", "list", "--limit", "16", "-o", "json"]).await {
        status.recent_bans = parse_recent_bans(&json, RECENT_BANS);
    }
    if let Some(text) = cscli(&["metrics", "-o", "json"]).await {
        if let Ok(metrics) = serde_json::from_str::<Value>(&text) {
            status.top_scenarios = parse_top_scenarios(&metrics, TOP_SCENARIOS);
            status.community_blocklist_ips = parse_community_blocklist_ips(&metrics);
            status.packets_dropped = parse_packets_dropped(&metrics);
        }
    }

    encode(codec, &status)
}

// ─────────────────────── SSH password login ────────────────────────────

/// What the host's SSH accepts right now, and whether the app's key is on the
/// account it signs in with.
///
/// **Never an error for a host that simply could not be asked.** A build with
/// no `systemd-run`, an account with no home directory, an sshd that would not
/// print its merged configuration — each of those is a state the card has to
/// DRAW, and the drawing is "we could not tell, so nothing is offered". An
/// error would put a banner over a screen whose honest answer is a sentence.
pub async fn get_ssh_password_state(codec: Codec, req: pb::GetSshPasswordStateRequest) -> Resp {
    let state = match ssh_password::read_state(&req.login_user, &req.app_public_key).await {
        Ok(state) => state,
        Err(why) => return encode(codec, &unknown_state(&req.login_user, &why)),
    };
    encode(codec, &into_pb(state, String::new()))
}

/// Close SSH password login, or take this product's drop-in back off.
///
/// The answer is the state RE-READ from the host, with the verdict's own
/// sentence attached — never the request echoed back. A close that the guard
/// refuses comes back with `password_login_open` still true and a `detail` that
/// says why, which is the only shape in which the app can tell the owner the
/// truth about a host it did not change.
pub async fn set_ssh_password_login(codec: Codec, req: pb::SetSshPasswordLoginRequest) -> Resp {
    let verdict = if req.allow_passwords {
        ssh_password::open_password_login_now().await
    } else {
        ssh_password::close_password_login_now(&req.login_user, &req.app_public_key).await
    };
    let detail = match verdict {
        Ok(verdict) => ssh_password::verdict_sentence(&verdict, &req.login_user),
        // The work could not be attempted at all — a host with no
        // `systemd-run`, a key that is not one line, an account nobody named.
        // Reported as an error rather than as a state, because unlike the read
        // above there IS something the owner asked for that did not happen.
        Err(why) => {
            return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "failed_precondition", &why)
        }
    };
    // Re-read AFTER acting, and the failure of the re-read is not the failure
    // of the action: the drop-in may well be written and reloaded on a host
    // whose second `systemd-run` did not come back. The verdict is what
    // happened; the state is what is true now, and the card shows both.
    match ssh_password::read_state(&req.login_user, &req.app_public_key).await {
        Ok(state) => encode(codec, &into_pb(state, detail)),
        Err(why) => encode(codec, &unknown_state(&req.login_user, &format!("{detail}; {why}"))),
    }
}

fn into_pb(state: ssh_password::State, detail: String) -> pb::SshPasswordState {
    pb::SshPasswordState {
        // `unwrap_or(false)` is safe only because `known` travels with it: a
        // client that reads the flag without the qualifier is reading "closed"
        // off a host nobody could ask, which is why the schema puts them side
        // by side and the card refuses to draw the switch without both.
        password_login_open: state.password_open.unwrap_or(false),
        known: state.password_open.is_some(),
        app_key_present: state.app_key_present,
        drop_in_present: state.drop_in_present,
        sshd_present: state.sshd_present,
        login_user: state.login_user,
        detail,
    }
}

fn unknown_state(login_user: &str, detail: &str) -> pb::SshPasswordState {
    pb::SshPasswordState {
        password_login_open: false,
        known: false,
        app_key_present: false,
        drop_in_present: false,
        sshd_present: false,
        login_user: login_user.to_string(),
        detail: detail.to_string(),
    }
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}


// ─────────────────────── ControlSecurity ───────────────────────────

/// Run the host's intrusion defence: start, stop, restart, update, install or
/// remove it.
///
/// **The one verb on this service that changes CrowdSec itself, and the reason
/// it exists** (owner, 2026-09-12: "пользователь полностью контролирует
/// сервер"). Everything else about this host is startable, stoppable and
/// removable from the app; the protection this product installs by default was
/// the exception, and software the owner of a machine cannot stop is not
/// theirs.
///
/// **Not `ControlService`.** That verb is keyed by catalog id and talks to
/// compose projects. This is two systemd units and two apt packages, with no
/// container, no site and no domain — keying it into the catalog to borrow a
/// stream would be a lie every later reader of the schema has to carry.
///
/// Streams like every other operation: STARTED, the command's own output line
/// by line, then COMPLETED carrying the status as RE-READ from the host. A stop
/// the host refused therefore comes back running, which is the only shape in
/// which the card can be honest.
pub async fn control_security(codec: Codec, req: pb::ControlSecurityRequest) -> Resp {
    let action = match pb::SecurityAction::try_from(req.action) {
        Ok(pb::SecurityAction::Unspecified) | Err(_) => {
            return connect_error(
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "no action was named, so nothing was done",
            )
        }
        Ok(action) => action,
    };

    // The same admission `ControlService` takes, under a key of its own: two
    // apt runs against the same packages at once is how a host ends up with a
    // half-configured dpkg state, and that state breaks EVERY later install on
    // the machine (see `install::crowdsec`'s header).
    let claim = match crate::jobs::OperationClaim::acquire("security", "crowdsec") {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    // Refused before the stream opens, exactly like `ControlService` refuses an
    // uninstalled service: there is nothing to start, stop or upgrade, and an
    // empty stream would report success for work nobody did. INSTALL is the one
    // action whose whole point is that it is not there yet.
    if action != pb::SecurityAction::Install && !present() {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "failed_precondition",
            "this host has no intrusion defence installed, so there is nothing to run.              Install it first — nothing was changed",
        );
    }

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);

    tokio::spawn(async move {
        let _claim = claim;
        let sink = SecuritySink {
            tx,
            codec,
            action,
            journal: crate::jobs::Journal::open(pb::JobKind::SecurityControl, "crowdsec"),
        };
        let _ = sink.started().await;

        let failure = match action {
            pb::SecurityAction::Install => install(&sink).await,
            _ => run_script(&script_for(action), &sink).await.err(),
        };

        // Re-read whatever happened, and send it even when the action failed:
        // "what state is it in now" is the next question either way, and an
        // error alone does not answer it.
        let status = read_status().await;
        let _ = sink.completed(status).await;

        if let Some(why) = failure {
            let _ = sink.fail(&why).await;
        }
    });

    crate::api::stream_response(json, rx)
}

/// The shell one action runs, outside the agent's own mount namespace.
///
/// **Written as a script rather than as argv** because every one of these is
/// several commands that have to happen in order on the host, and the route out
/// of this crate's sandbox (`packages::run_outside_sandbox`) takes a shell line.
/// Nothing here interpolates anything a caller sent: the action is an enum and
/// the unit and package names are constants of this crate.
fn script_for(action: pb::SecurityAction) -> String {
    use crate::install::crowdsec::{BOUNCER_PACKAGE, BOUNCER_UNIT, ENGINE_PACKAGE, ENGINE_UNIT};
    let apt = crate::install::packages::APT_LOCK_WAIT;
    match action {
        // `enable --now`, not `start`: a defence that does not come back after
        // a reboot is worse than none, because the host still looks defended.
        pb::SecurityAction::Start => format!(
            "systemctl enable --now {ENGINE_UNIT}\n\
             systemctl enable --now {BOUNCER_UNIT} || true\n"
        ),
        // Stopped, not disabled: "stop" is a thing the owner does to look at
        // something, and a stop that also survived a reboot would be a removal
        // wearing a smaller word.
        pb::SecurityAction::Stop => format!(
            "systemctl stop {BOUNCER_UNIT} || true\n\
             systemctl stop {ENGINE_UNIT}\n"
        ),
        // The bouncer after the engine, both times: it talks to the engine's
        // local API and comes up shouting "access forbidden" if that API is not
        // there yet.
        pb::SecurityAction::Restart => format!(
            "systemctl restart {ENGINE_UNIT}\n\
             systemctl try-restart {BOUNCER_UNIT} || true\n"
        ),
        // **The hub is half of what this software IS.** Upgrading the packages
        // and leaving the scenarios where they were gives a host watching for
        // last year's attacks with this year's binary, which is the kind of
        // up-to-date that is worse than none.
        pb::SecurityAction::Update => format!(
            "set -e\n\
             export DEBIAN_FRONTEND=noninteractive\n\
             apt-get {apt} update\n\
             apt-get {apt} install -y --only-upgrade {ENGINE_PACKAGE} {BOUNCER_PACKAGE}\n\
             cscli hub update --error || true\n\
             cscli hub upgrade --error || true\n\
             systemctl restart {ENGINE_UNIT}\n\
             systemctl try-restart {BOUNCER_UNIT} || true\n"
        ),
        // **Purge, and the configuration with it.** A half-removed CrowdSec is
        // the state that makes every later `apt-get install` on this host exit
        // 100 (see `install::crowdsec`'s header for the measured chain), so
        // "remove" has to mean gone. The bans go too — the app says so before
        // it asks.
        pb::SecurityAction::Remove => format!(
            "export DEBIAN_FRONTEND=noninteractive\n\
             systemctl disable --now {BOUNCER_UNIT} >/dev/null 2>&1 || true\n\
             systemctl disable --now {ENGINE_UNIT} >/dev/null 2>&1 || true\n\
             apt-get {apt} purge -y {BOUNCER_PACKAGE} {ENGINE_PACKAGE}\n\
             apt-get {apt} autoremove -y || true\n\
             rm -rf /etc/crowdsec\n"
        ),
        // Handled by `install` above; never reached.
        pb::SecurityAction::Install | pb::SecurityAction::Unspecified => String::new(),
    }
}

/// Put CrowdSec back on a host that has none.
///
/// **Delegates to the provision path rather than re-spelling it.**
/// `install::crowdsec::ensure_present` is where the repository, the two
/// packages in the right order, the journald acquisition, the local-API port
/// pin and the bouncer's key registration are decided, each with the live
/// failure that taught it. A second copy of those steps here would be a second
/// answer to the same question, and this crate has already paid for that twice.
///
/// The cost is named: that function narrates into an install-shaped sink, so
/// its lines do not reach this stream. What the client gets instead is the
/// bracketing narration below and, at the end, the status as re-read — which is
/// the fact the card draws. A minutes-long apt run with no line-by-line output
/// is a worse watch than an install, and it is the honest trade against two
/// divergent installers.
async fn install(sink: &SecuritySink) -> Option<String> {
    let _ = sink
        .progress("agent", "installing the host's intrusion defence — this takes a few minutes".into())
        .await;
    crate::install::crowdsec::ensure_present(true, &crate::install::execute::EventSink::detached()).await;
    if crate::install::crowdsec::engine_configured() {
        let _ = sink.progress("agent", "CrowdSec is installed".into()).await;
        None
    } else {
        Some("CrowdSec did not finish installing; the host is unchanged apart from any packages apt left behind".into())
    }
}

/// Run one action's script outside the agent's own mount namespace, forwarding
/// every line it prints.
///
/// **`systemd-run --wait --pipe`, the same route `packages::run_outside_sandbox`
/// takes** — this process runs under `ProtectSystem=full`, so apt and systemctl
/// have to be handed to PID 1 or they cannot write what they own. `--collect`
/// removes the transient unit afterwards even when it failed, so a host does
/// not accumulate units nobody will read.
///
/// **Its own reader rather than `execute::run_child_streaming`**, and the
/// reason is the event type: that function narrates into an install-shaped
/// sink, and these events are `SecurityOperationEvent`s. What is NOT copied is
/// the mistake that function's own doc records — a `select!` over stdout,
/// stderr and `wait()` starves the reaping branch and leaves a finished child
/// `<defunct>` with the caller waiting for ever. Here the pipes are drained by
/// two tasks of their own and `wait()` is the only thing this function awaits,
/// so there is no branch to starve.
async fn run_script(script: &str, sink: &SecuritySink) -> Result<(), String> {
    let mut child = tokio::process::Command::new(systemd_run_bin())
        .args([
            "--quiet",
            "--collect",
            "--wait",
            "--pipe",
            "--service-type=oneshot",
            "/bin/sh",
            "-c",
            script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run systemd-run: {err}"))?;

    // A channel rather than the sink directly, because a sink is not `Sync` to
    // hand to two tasks: the readers push text, this function frames it.
    let (lines_tx, mut lines_rx) = tokio::sync::mpsc::channel::<(&'static str, String)>(64);
    if let Some(pipe) = child.stdout.take() {
        let tx = lines_tx.clone();
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(pipe).lines();
            while let Ok(Some(text)) = lines.next_line().await {
                if tx.send(("stdout", strip_ansi(&text))).await.is_err() {
                    return;
                }
            }
        });
    }
    // apt narrates on stderr and so does systemctl; a line there is progress,
    // not proof of failure. The exit status is.
    if let Some(pipe) = child.stderr.take() {
        let tx = lines_tx.clone();
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(pipe).lines();
            while let Ok(Some(text)) = lines.next_line().await {
                if tx.send(("stderr", strip_ansi(&text))).await.is_err() {
                    return;
                }
            }
        });
    }
    drop(lines_tx);

    let forwarding = async {
        while let Some((stream, text)) = lines_rx.recv().await {
            let _ = sink.progress(stream, text).await;
        }
    };
    // One deadline for the whole run, not per line: `apt-get install` is silent
    // for long stretches and a quiet minute is not a hung command. Dropping the
    // future on timeout drops the child, and `kill_on_drop` reaps it.
    let outcome = tokio::time::timeout(
        Duration::from_secs(ACTION_TIMEOUT_SECS),
        async {
            let (_, status) = tokio::join!(forwarding, child.wait());
            status
        },
    )
    .await;

    match outcome {
        Err(_) => Err(format!("timed out after {ACTION_TIMEOUT_SECS}s")),
        Ok(Err(io)) => Err(format!("the command did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(match status.code() {
            Some(code) => format!("the command exited {code}"),
            None => "the command was killed by a signal".to_string(),
        }),
    }
}

/// How long one action may take. Generous because `UPDATE` and `INSTALL` are
/// apt runs on somebody's small VPS, and nothing here is interactive.
const ACTION_TIMEOUT_SECS: u64 = 900;

/// Overridable for tests, the same technique the install module uses: a stub
/// records argv and exits how the test wants. A server never sets it.
fn systemd_run_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN").unwrap_or_else(|_| "systemd-run".to_string())
}

/// The whole status, re-read after an action. Never fails: a host that no
/// longer has CrowdSec answers `present = false`, which is exactly what the
/// card has to draw after a removal.
async fn read_status() -> pb::SecurityStatus {
    let mut status = pb::SecurityStatus::default();
    if !present() {
        return status;
    }
    status.present = true;
    status.engine_running = unit_active(ENGINE_UNIT).await;
    status.bouncer_running = unit_active(BOUNCER_UNIT).await;
    if let Some(version) = cscli(&["version"]).await {
        status.engine_version = parse_engine_version(&version);
    }
    status
}

/// Frames and pushes one operation's events — the same shape `control.rs`'s own
/// sink has, carrying `SecurityOperationEvent` instead.
pub(crate) struct SecuritySink {
    tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
    codec: Codec,
    action: pb::SecurityAction,
    journal: Option<crate::jobs::Journal>,
}

impl SecuritySink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::SecurityOperationEvent {
        pb::SecurityOperationEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            action: self.action as i32,
            text: String::new(),
            stream: String::new(),
            status: None,
        }
    }

    async fn send(&self, event: pb::SecurityOperationEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(crate::api::envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self) -> Result<(), ()> {
        self.send(self.event(pb::ServiceOperationPhase::Started)).await
    }

    pub(crate) async fn progress(&self, stream: &str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(&self, status: pb::SecurityStatus) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.status = Some(status);
        self.send(event).await
    }

    /// End the stream with an error trailer — without it a failed stop would
    /// look exactly like a successful one, since a stream carries no exit
    /// status of its own.
    async fn fail(&self, message: &str) -> Result<(), ()> {
        crate::jobs::finish(&self.journal, Some(message));
        self.tx
            .send(crate::api::error_trailer("internal", message))
            .await
            .map_err(|_| ())
    }
}

// ─────────────────── Decisions and the allowlist ───────────────────

/// The allowlist this product owns. One per host, created on first use, named
/// after the product so a person reading `cscli allowlists list` on the box can
/// tell who wrote it. Other allowlists are left alone and never reported: they
/// are somebody else's policy, and an app that quietly edited them would be
/// changing a security decision it did not make.
const ALLOWLIST_NAME: &str = "gryonixnexus";

/// The most decisions the agent will hand over. Far past what a phone lists,
/// far short of the community blocklist — which is counted, never fetched.
const DECISIONS_LIMIT: usize = 200;

/// What a ban says when the app asked for it and the person typed no reason.
/// A decision with no reason is one nobody can audit a week later.
const MANUAL_REASON: &str = "gryonixnexus: added by hand";

/// Run `cscli` and keep the failure. The reading path uses `cscli()` above and
/// treats every failure as "this number is unavailable"; a verb that CHANGES
/// the host cannot do that — "the ban was not lifted" and "the ban is gone"
/// must not look alike — so this one returns the error text, stderr included,
/// for the app to show.
async fn cscli_checked(args: &[&str]) -> Result<String, String> {
    let child = tokio::process::Command::new(cscli_bin())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("cscli could not be started: {err}"))?;
    let output =
        tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output())
            .await
            .map_err(|_| "cscli did not answer in time".to_string())?
            .map_err(|err| format!("cscli failed: {err}"))?;
    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    if output.status.success() {
        return Ok(stdout);
    }
    let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr));
    let detail = [stderr.trim(), stdout.trim()]
        .into_iter()
        .find(|text| !text.is_empty())
        .unwrap_or("cscli refused the request")
        .to_string();
    Err(detail)
}

/// An IPv4/IPv6 address or a CIDR range, and nothing else.
///
/// **Checked here rather than trusted from the client**, and not because the
/// argument could become a shell injection — nothing here goes through a shell
/// — but because `cscli decisions add --ip "'; drop"` succeeds: CrowdSec stores
/// the value it was given. A typo therefore becomes a permanent row in the
/// host's decision list that matches no traffic and that nobody later can
/// explain. The narrow answer is the honest one: an address, or a refusal
/// naming what was wrong.
fn valid_target(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let Ok(address) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    match prefix {
        None => true,
        Some(prefix) => {
            let ceiling = if address.is_ipv4() { 32 } else { 128 };
            // Digits only, and no leading zero: `1.2.3.4/007` parses as 7 and
            // would be STORED as typed, so the host's list would carry a range
            // spelled one way and matched another.
            if prefix.is_empty()
                || prefix.len() > 3
                || !prefix.chars().all(|c| c.is_ascii_digit())
                || (prefix.len() > 1 && prefix.starts_with('0'))
            {
                return false;
            }
            matches!(prefix.parse::<u32>(), Ok(bits) if bits <= ceiling)
        }
    }
}

/// Seconds as a Go duration, which is what every `cscli` flag takes. 0 means
/// "say nothing and let CrowdSec use its own default" — four hours for a ban,
/// forever for an allowlist entry.
fn duration_arg(seconds: u64) -> Option<String> {
    (seconds > 0).then(|| format!("{seconds}s"))
}

/// `cscli decisions list -o json` answers an array of ALERTS, each carrying the
/// decisions it produced — usually one — plus the enrichment (country, AS) that
/// lives on the alert's source rather than on the decision.
///
/// Flattened here into one row per decision, because that is what the list
/// shows and what "lift this one" acts on. Measured against a real host
/// (2026-09-12) rather than written from the documentation: the id is a NUMBER
/// in the JSON and a string in the table, `origin` is what the table calls
/// Source, and `scenario` is what it calls Reason.
fn parse_decisions(json: &str, limit: usize) -> Vec<pb::SecurityDecision> {
    let Ok(Value::Array(alerts)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for alert in &alerts {
        let source = alert.get("source");
        let country = source
            .and_then(|s| s.get("cn"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let as_name = source
            .and_then(|s| s.get("as_name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let events = alert
            .get("events_count")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        let Some(Value::Array(decisions)) = alert.get("decisions") else {
            continue;
        };
        for decision in decisions {
            let value = decision
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if value.is_empty() {
                continue;
            }
            rows.push(pb::SecurityDecision {
                // A number in JSON, a string here: the id is an opaque handle
                // to pass back, and every client already has string fields.
                id: decision
                    .get("id")
                    .and_then(Value::as_u64)
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                scope: decision.get("scope").and_then(Value::as_str).unwrap_or_default().to_string(),
                value: value.to_string(),
                action: decision.get("type").and_then(Value::as_str).unwrap_or_default().to_string(),
                reason: decision
                    .get("scenario")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                country: country.clone(),
                as_name: as_name.clone(),
                source: decision.get("origin").and_then(Value::as_str).unwrap_or_default().to_string(),
                expires_in: decision
                    .get("duration")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                events,
            });
            if rows.len() >= limit {
                return rows;
            }
        }
    }
    rows
}

/// The addresses with an SSH session open on this host right now.
///
/// **The only way the agent can tell the app what the app looks like from
/// outside.** Every RPC arrives through an SSH tunnel to a unix socket, so the
/// peer address the agent could read is always the loopback; and a phone behind
/// NAT cannot know its own public address either. `ss` knows, because sshd's
/// sockets are the connections in question.
///
/// Reported as a list, never resolved to "this one is you": several sessions
/// are normal (a person in a terminal while the app polls), and an agent that
/// guessed would sooner or later hand the app somebody else's address to put
/// beyond banning.
async fn ssh_client_ips() -> Vec<String> {
    let Some(text) = run_capture(
        "ss",
        &["-H", "-t", "-n", "state", "established", "sport", "=", ":22"],
    )
    .await
    else {
        return Vec::new();
    };
    parse_ss_peers(&text)
}

/// The peer address out of each `ss` row.
///
/// **Counted from the END of the line, not from its start**, and that is the
/// whole of what this function gets right. `ss` prints a State column — and
/// DROPS it when the query already filters on state, which this one does. A
/// parser that took the fifth field therefore read every row of a real host as
/// unparseable and answered "nobody is connected" while two people were
/// (measured on `vps-lab`, 2026-09-12: `0 228 31.70.137.80:22
/// 207.89.80.9:58830` — four fields, not five). The peer is the last address on
/// the row under either shape.
///
/// IPv6 arrives bracketed (`[2001:db8::1]:54321`), so the brackets come off
/// before the address is parsed — and parsing it is what keeps a header line or
/// a `users:(("sshd",pid=…))` tail out of the answer.
fn parse_ss_peers(text: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for line in text.lines() {
        let peer = line
            .split_whitespace()
            .rev()
            .find_map(|field| {
                let (address, _port) = field.rsplit_once(':')?;
                let address = address.trim_start_matches('[').trim_end_matches(']');
                address.parse::<std::net::IpAddr>().ok().map(|_| address.to_string())
            });
        let Some(address) = peer else { continue };
        if !seen.iter().any(|known| known == &address) {
            seen.push(address);
        }
    }
    seen
}

/// Run a binary and return its stdout, or `None` on any failure. Same contract
/// as `cscli()` and separate from it only because the binary differs.
async fn run_capture(bin: &str, args: &[&str]) -> Option<String> {
    let child = tokio::process::Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let output =
        tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output())
            .await
            .ok()?
            .ok()?;
    output
        .status
        .success()
        .then(|| strip_ansi(&String::from_utf8_lossy(&output.stdout)))
}

/// The decision list as the host has it now.
async fn read_decisions() -> pb::SecurityDecisions {
    let mut answer = pb::SecurityDecisions::default();
    if !present() {
        return answer;
    }
    answer.present = true;
    // `--limit 0` — everything the host decided itself, then capped here. The
    // flag matters for the same measured reason `get_security_status` carries
    // it: without it cscli pages at 100 and the list silently stops there.
    if let Some(json) = cscli(&["decisions", "list", "--limit", "0", "-o", "json"]).await {
        answer.decisions = parse_decisions(&json, DECISIONS_LIMIT);
    }
    if let Some(text) = cscli(&["metrics", "-o", "json"]).await {
        if let Ok(metrics) = serde_json::from_str::<Value>(&text) {
            answer.community_count = parse_community_blocklist_ips(&metrics);
        }
    }
    answer.ssh_client_ips = ssh_client_ips().await;
    answer
}

pub async fn get_security_decisions(codec: Codec, _req: pb::GetSecurityDecisionsRequest) -> Resp {
    let answer = read_decisions().await;
    encode(codec, &answer)
}

/// Ban an address by hand, or lift a ban.
///
/// **Lifting by id and lifting by address are different requests and both
/// exist.** "Take this row off" is by id; "let me back in" is by address and
/// has to clear every decision on it, because a client that tripped two
/// scenarios has two rows and clearing one leaves the wall up.
pub async fn set_security_decision(codec: Codec, req: pb::SetSecurityDecisionRequest) -> Resp {
    if !present() {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "failed_precondition",
            "this host has no CrowdSec installed",
        );
    }
    let value = req.value.trim().to_string();
    let id = req.id.trim().to_string();
    let by_id = !id.is_empty() && !req.banned;
    if !by_id && !valid_target(&value) {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "an address or a CIDR range is required, for example 203.0.113.9 or 203.0.113.0/24",
        );
    }
    if by_id && !id.chars().all(|c| c.is_ascii_digit()) {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "a decision id is a number",
        );
    }

    let range = value.contains('/');
    let duration = duration_arg(req.duration_seconds);
    let reason = {
        let typed = req.reason.trim();
        if typed.is_empty() { MANUAL_REASON.to_string() } else { typed.to_string() }
    };

    let mut args: Vec<&str> = vec!["decisions"];
    if req.banned {
        args.push("add");
        args.push(if range { "--range" } else { "--ip" });
        args.push(&value);
        args.push("--reason");
        args.push(&reason);
        if let Some(duration) = duration.as_deref() {
            args.push("--duration");
            args.push(duration);
        }
    } else {
        args.push("delete");
        if by_id {
            args.push("--id");
            args.push(&id);
        } else {
            args.push(if range { "--range" } else { "--ip" });
            args.push(&value);
        }
    }

    if let Err(detail) = cscli_checked(&args).await {
        return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &detail);
    }
    // Re-read, never echo: a ban CrowdSec refused because the address is on the
    // allowlist exits zero and changes nothing, and only the list says so.
    let answer = read_decisions().await;
    encode(codec, &answer)
}

/// `cscli allowlists inspect <name> -o json` answers one object with an
/// `items` array of `{value, description, expiration}` — measured on a live
/// host, 2026-09-12. An entry that never expires carries no `expiration`.
fn parse_allowlist_items(json: &str) -> Vec<pb::SecurityAllowlistEntry> {
    let Ok(list) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    // `inspect` answers the object; `list` answers an array of them. Accept
    // both, so one parser serves both calls.
    let object = match &list {
        Value::Array(lists) => lists
            .iter()
            .find(|entry| entry.get("name").and_then(Value::as_str) == Some(ALLOWLIST_NAME)),
        Value::Object(_) => Some(&list),
        _ => None,
    };
    let Some(Some(Value::Array(items))) = object.map(|o| o.get("items")) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let value = item.get("value").and_then(Value::as_str)?;
            Some(pb::SecurityAllowlistEntry {
                value: value.to_string(),
                comment: item
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                // **A never-expiring entry does not come back empty, it comes
                // back as the ZERO timestamp** (`0001-01-01T00:00:00.000Z`) —
                // measured on a live host, 2026-09-12. Passed through, that is
                // a date from the year one drawn beside an address, so it is
                // read here as what it means: no expiry.
                expires_in: item
                    .get("expiration")
                    .and_then(Value::as_str)
                    .filter(|at| !at.starts_with("0001-01-01"))
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .collect()
}

/// Whether this CrowdSec knows `cscli allowlists` at all, and what is on ours.
///
/// The support question is answered by ASKING — `allowlists list` on a version
/// without the command exits non-zero with "unknown command" — rather than by
/// comparing version numbers, which would have to be kept in step with
/// CrowdSec's releases forever and would be wrong on the first backport.
async fn read_allowlist() -> pb::SecurityAllowlist {
    let mut answer = pb::SecurityAllowlist {
        name: ALLOWLIST_NAME.to_string(),
        ..Default::default()
    };
    if !present() {
        return answer;
    }
    answer.present = true;
    let Ok(listed) = cscli_checked(&["allowlists", "list", "-o", "json"]).await else {
        return answer;
    };
    answer.supported = true;
    answer.entries = parse_allowlist_items(&listed);
    answer.ssh_client_ips = ssh_client_ips().await;
    answer
}

pub async fn get_security_allowlist(codec: Codec, _req: pb::GetSecurityAllowlistRequest) -> Resp {
    let answer = read_allowlist().await;
    encode(codec, &answer)
}

/// Put an address beyond banning, or stop protecting it.
///
/// **This is the one of the three verbs that works from the banned side of the
/// wall, and it works only because it is set BEFORE the ban.** Once CrowdSec
/// drops an address, the app's own SSH tunnel to this agent is dropped with it;
/// nothing here can be reached to undo it. So the app offers this on the
/// security card, with the host's own view of who is connected
/// (`ssh_client_ips`) to fill in, and the person chooses.
pub async fn set_security_allowlist(codec: Codec, req: pb::SetSecurityAllowlistRequest) -> Resp {
    if !present() {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "failed_precondition",
            "this host has no CrowdSec installed",
        );
    }
    let value = req.value.trim().to_string();
    if !valid_target(&value) {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "an address or a CIDR range is required, for example 203.0.113.9 or 203.0.113.0/24",
        );
    }

    if req.allowed {
        // Created on demand and only then: a host where nobody ever allowed an
        // address should not carry an empty list of ours. `create` on an
        // existing list exits non-zero, and that is not a failure of this
        // request — the list existing is what the next line needs.
        let _ = cscli_checked(&[
            "allowlists",
            "create",
            ALLOWLIST_NAME,
            "-d",
            "Addresses gryonixNexus was told never to ban",
        ])
        .await;
        let comment = {
            let typed = req.comment.trim();
            if typed.is_empty() { "added from gryonixNexus".to_string() } else { typed.to_string() }
        };
        let duration = duration_arg(req.duration_seconds);
        let mut args: Vec<&str> = vec!["allowlists", "add", ALLOWLIST_NAME, &value, "-d", &comment];
        if let Some(duration) = duration.as_deref() {
            args.push("-e");
            args.push(duration);
        }
        if let Err(detail) = cscli_checked(&args).await {
            return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &detail);
        }
        // **Allowlisting does not lift a ban that is already in place** —
        // measured on a live host, 2026-09-12: an address added to a list while
        // a decision on it existed stayed blocked until the decision went. The
        // owner asking not to be banned means both, so both happen, and a
        // failure here is not fatal: the protection they asked for is already
        // on.
        let _ = cscli_checked(&["decisions", "delete", "--ip", &value]).await;
    } else if let Err(detail) =
        cscli_checked(&["allowlists", "remove", ALLOWLIST_NAME, &value]).await
    {
        return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &detail);
    }

    let answer = read_allowlist().await;
    encode(codec, &answer)
}

#[cfg(test)]
mod tests {

    // ─────────────── ControlSecurity ───────────────

    /// Every action is several commands in one order, and the order is the
    /// whole of what these scripts get right: the bouncer talks to the
    /// engine's local API, so it goes up after the engine and down before it.
    #[test]
    fn the_bouncer_follows_the_engine_up_and_leads_it_down() {
        let start = script_for(pb::SecurityAction::Start);
        let engine = start.find("enable --now crowdsec\n").expect("the engine is started");
        let bouncer = start.find("crowdsec-firewall-bouncer").expect("the bouncer is started");
        assert!(engine < bouncer, "the bouncer must not start before the engine:\n{start}");

        let stop = script_for(pb::SecurityAction::Stop);
        let stop_bouncer = stop.find("crowdsec-firewall-bouncer").expect("the bouncer is stopped");
        let stop_engine = stop.rfind("stop crowdsec\n").expect("the engine is stopped");
        assert!(stop_bouncer < stop_engine, "the engine must not stop first:\n{stop}");
    }

    /// `enable --now`, never a bare `start`: a defence that does not come back
    /// after a reboot is worse than none, because the host still looks
    /// defended.
    #[test]
    fn starting_survives_a_reboot() {
        let start = script_for(pb::SecurityAction::Start);
        assert!(start.contains("enable --now"), "{start}");
        assert!(!start.contains("systemctl start "), "a bare start does not survive a reboot: {start}");
    }

    /// Stop is a pause, not a quiet removal — so it must not disable the
    /// units, or "stop" would outlive the next reboot under a smaller word.
    #[test]
    fn stopping_does_not_disable() {
        assert!(!script_for(pb::SecurityAction::Stop).contains("disable"));
    }

    /// Upgrading the packages and leaving the scenarios where they were is a
    /// host watching for last year's attacks with this year's binary.
    #[test]
    fn updating_moves_the_hub_as_well_as_the_packages() {
        let update = script_for(pb::SecurityAction::Update);
        assert!(update.contains("--only-upgrade"), "{update}");
        assert!(update.contains("cscli hub update"), "{update}");
        assert!(update.contains("cscli hub upgrade"), "{update}");
        // An upgraded engine still running the old binary has upgraded nothing.
        assert!(update.contains("systemctl restart crowdsec"), "{update}");
    }

    /// **Purge, not remove.** A half-removed CrowdSec makes every later
    /// `apt-get install` on the host exit 100 — the measured chain in
    /// `install::crowdsec`'s header — so the weaker verb would leave the
    /// machine worse off than before it was asked.
    #[test]
    fn removing_purges_the_packages_and_the_configuration() {
        let remove = script_for(pb::SecurityAction::Remove);
        assert!(remove.contains("purge -y"), "{remove}");
        assert!(!remove.contains(" remove -y"), "remove is not enough: {remove}");
        assert!(remove.contains("rm -rf /etc/crowdsec"), "{remove}");
        assert!(remove.contains("disable --now"), "the units must not come back on reboot: {remove}");
    }

    /// Nothing a caller sends reaches the shell: the action is an enum and
    /// every name in these scripts is a constant of this crate.
    #[test]
    fn the_scripts_interpolate_nothing_a_caller_controls() {
        for action in [
            pb::SecurityAction::Start,
            pb::SecurityAction::Stop,
            pb::SecurityAction::Restart,
            pb::SecurityAction::Update,
            pb::SecurityAction::Remove,
        ] {
            let script = script_for(action);
            assert!(!script.is_empty(), "{action:?} has no script");
            for name in script.split_whitespace().filter(|word| word.starts_with("crowdsec")) {
                assert!(
                    name.starts_with("crowdsec"),
                    "{action:?} names something other than the two units/packages: {script}"
                );
            }
        }
        // INSTALL is handled by the provision path, not by a script here.
        assert!(script_for(pb::SecurityAction::Install).is_empty());
    }

    /// An unnamed action is refused before anything runs — an empty stream
    /// would report success for work nobody did.
    #[tokio::test]
    async fn an_action_nobody_named_is_refused() {
        let response = control_security(
            Codec::Json,
            pb::ControlSecurityRequest { action: pb::SecurityAction::Unspecified as i32 },
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/security")
                .join(name),
        )
        .unwrap_or_else(|err| panic!("read fixture {name}: {err}"))
    }

    #[test]
    fn engine_version_is_the_version_not_the_build_string() {
        assert_eq!(parse_engine_version(&fixture("version.txt")), "v1.8.0");
        assert_eq!(parse_engine_version(""), "");
        assert_eq!(parse_engine_version("Codename: alphaga\nversion: v2.0.0-x"), "v2.0.0");
    }

    #[test]
    fn alert_count_is_the_array_length() {
        assert_eq!(parse_alert_count(&fixture("alerts-24h.json")), 4);
        assert_eq!(parse_alert_count(&fixture("decisions.json")), 0);
        assert_eq!(parse_alert_count("not json"), 0);
        assert_eq!(parse_alert_count("{\"error\":\"nope\"}"), 0);
    }

    #[test]
    fn recent_bans_carry_ip_country_and_scenario_and_honour_the_limit() {
        let bans = parse_recent_bans(&fixture("alerts-recent.json"), 3);
        assert_eq!(bans.len(), 3);
        assert_eq!(bans[0].ip, "193.233.199.37");
        assert_eq!(bans[0].country, "RU");
        assert_eq!(bans[0].scenario, "crowdsecurity/ssh-slow-bf");
        assert_eq!(bans[0].at, "2026-09-01T16:25:37Z");
    }

    #[test]
    fn a_row_without_a_source_address_is_dropped_not_blanked() {
        let json = r#"[
            {"scenario":"x","created_at":"t","source":{"value":"1.2.3.4","cn":"US"}},
            {"scenario":"y","created_at":"t","source":{"scope":"Country"}},
            {"scenario":"z","created_at":"t"}
        ]"#;
        let bans = parse_recent_bans(json, 8);
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, "1.2.3.4");
    }

    #[test]
    fn top_scenarios_are_count_descending_and_capped() {
        let metrics: Value = serde_json::from_str(&fixture("metrics.json")).unwrap();
        let top = parse_top_scenarios(&metrics, 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].name, "crowdsecurity/ssh-bf");
        assert_eq!(top[0].count, 37);
        assert_eq!(top[1].name, "crowdsecurity/ssh-slow-bf");
        assert_eq!(top[1].count, 11);
    }

    #[test]
    fn top_scenarios_break_a_tie_by_name_so_the_list_is_stable() {
        let metrics = serde_json::json!({ "alerts": { "b/two": 5, "a/one": 5, "c/three": 9 } });
        let top = parse_top_scenarios(&metrics, 3);
        assert_eq!(
            top.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["c/three", "a/one", "b/two"]
        );
    }

    #[test]
    fn community_blocklist_is_the_capi_active_decision_count() {
        let metrics: Value = serde_json::from_str(&fixture("metrics.json")).unwrap();
        assert_eq!(parse_community_blocklist_ips(&metrics), 15737);
    }

    #[test]
    fn packets_dropped_sum_every_origin_of_every_bouncer() {
        let metrics: Value = serde_json::from_str(&fixture("metrics.json")).unwrap();
        // CAPI 1620 + crowdsec 19409 + cscli 0.
        assert_eq!(parse_packets_dropped(&metrics), 21029);
    }

    /// One lock for every reader of the two env knobs this module has, the
    /// rule the crate already follows: a test that both sets and clears an
    /// environment variable races every other test that reads it.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A cscli that records the argv it was called with and answers `[]`.
    ///
    /// **The arguments are the only place this defect could ever be seen.**
    /// `parse_alert_count` returns the length of the array it is given, so a
    /// fixture proves the count is read correctly and says nothing about how
    /// many rows cscli was asked for — which is exactly how the missing
    /// `--limit` survived: the fixtures have 4 and 0 rows and the cap is 50.
    fn stub_cscli(dir: &std::path::Path) -> std::path::PathBuf {
        let log = dir.join("argv.log");
        let bin = dir.join("cscli");
        std::fs::write(
            &bin,
            format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf '[]'\n", log.display()),
        )
        .expect("write the stub");
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("make the stub executable");
        bin
    }

    /// **Both counting calls ask for every row, not for cscli's first page.**
    ///
    /// Measured on `vps-middle` 2026-09-02, which is what turned this from a
    /// reading into a defect: `cscli alerts list --since 72h` answered 50 rows
    /// and the same call with `--limit 0` answered 53. A host under a real
    /// password-guessing run passes 50 alerts in a day easily, and the card
    /// would then have shown the same number for ever.
    #[tokio::test]
    async fn the_counting_calls_ask_for_every_row() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-cscli-argv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let bin = stub_cscli(&dir);
        let config = dir.join("config.yaml");
        std::fs::write(&config, "# present\n").expect("write the config");
        std::env::set_var("GRYONIXNEXUSD_CSCLI_BIN", &bin);
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_CONFIG", &config);

        let _ = get_security_status(Codec::Json, pb::GetSecurityStatusRequest::default()).await;

        std::env::remove_var("GRYONIXNEXUSD_CSCLI_BIN");
        std::env::remove_var("GRYONIXNEXUSD_CROWDSEC_CONFIG");

        let argv = std::fs::read_to_string(dir.join("argv.log")).expect("the stub ran");
        let alerts = argv
            .lines()
            .find(|line| line.starts_with("alerts list --since 24h"))
            .expect("the 24h alert count is asked for");
        assert!(alerts.contains("--limit 0"), "alerts asked without a limit: {alerts}");
        let decisions = argv
            .lines()
            .find(|line| line.starts_with("decisions list"))
            .expect("the local ban count is asked for");
        assert!(decisions.contains("--limit 0"), "decisions asked without a limit: {decisions}");
        // The recent-ban list is a DIFFERENT question — the newest sixteen —
        // and asserting it here keeps a future "just add --limit 0 everywhere"
        // from turning a short list into every alert the host has ever seen.
        let recent = argv
            .lines()
            .find(|line| line.starts_with("alerts list --limit 16"))
            .expect("the recent bans are asked for");
        assert!(!recent.contains("--limit 0"), "the recent list must stay short: {recent}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────── Decisions and the allowlist ───────────────

    /// The shape is not invented: this is `cscli decisions list -o json` from a
    /// live host (v1.8.1, 2026-09-12), trimmed to the fields the list draws.
    /// The whole point of pinning it is that CrowdSec answers ALERTS carrying
    /// decisions, not decisions — a parser written from the table's columns
    /// would find nothing.
    const DECISIONS_JSON: &str = r#"[
     {
      "created_at": "2026-09-12T16:57:17Z",
      "decisions": [
       {
        "duration": "4m58s",
        "id": 270038,
        "origin": "cscli",
        "scenario": "gryonixnexus shape probe",
        "scope": "Ip",
        "simulated": false,
        "type": "ban",
        "value": "198.51.100.7"
       }
      ],
      "events_count": 1,
      "id": 70,
      "source": { "ip": "198.51.100.7", "scope": "Ip", "value": "198.51.100.7",
                  "cn": "DE", "as_name": "58243 TELE AG" }
     }
    ]"#;

    #[test]
    fn a_decision_carries_what_the_row_shows() {
        let rows = parse_decisions(DECISIONS_JSON, 200);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.value, "198.51.100.7");
        // The id is a number in the JSON and a handle everywhere else.
        assert_eq!(row.id, "270038");
        assert_eq!(row.action, "ban");
        assert_eq!(row.source, "cscli");
        assert_eq!(row.reason, "gryonixnexus shape probe");
        assert_eq!(row.expires_in, "4m58s");
        // Country and AS live on the ALERT's source, not on the decision, and
        // a parser that looked for them beside `value` would always find "".
        assert_eq!(row.country, "DE");
        assert_eq!(row.as_name, "58243 TELE AG");
        assert_eq!(row.events, 1);
    }

    #[test]
    fn the_decision_parser_survives_shapes_it_does_not_recognise() {
        assert!(parse_decisions("[]", 200).is_empty());
        assert!(parse_decisions("not json", 200).is_empty());
        assert!(parse_decisions(r#"[{"decisions": null}]"#, 200).is_empty());
        // A decision with no address is not one the owner can act on.
        assert!(parse_decisions(r#"[{"decisions":[{"id":1,"value":""}]}]"#, 200).is_empty());
    }

    /// The cap is on DECISIONS, not on alerts: one alert can carry several, and
    /// a limit applied to the outer array would hand back more rows than asked.
    #[test]
    fn the_cap_counts_decisions_and_not_alerts() {
        let json = r#"[{"events_count":1,"decisions":[
            {"id":1,"value":"203.0.113.1","type":"ban"},
            {"id":2,"value":"203.0.113.2","type":"ban"},
            {"id":3,"value":"203.0.113.3","type":"ban"}]}]"#;
        assert_eq!(parse_decisions(json, 2).len(), 2);
    }

    /// `cscli allowlists inspect -o json` answers one object; `list` answers an
    /// array of them. One parser reads both, and it picks OUR list by name —
    /// another product's allowlist on the same host is not ours to report.
    #[test]
    fn the_allowlist_parser_reads_both_shapes_and_only_our_list() {
        let inspect = r#"{"name":"gryonixnexus","items":[
            {"value":"203.0.113.9","description":"office","expiration":"2026-09-12T17:02:00.925Z"}]}"#;
        let from_inspect = parse_allowlist_items(inspect);
        assert_eq!(from_inspect.len(), 1);
        assert_eq!(from_inspect[0].value, "203.0.113.9");
        assert_eq!(from_inspect[0].comment, "office");
        assert!(!from_inspect[0].expires_in.is_empty());

        // **CrowdSec spells "never" as the year one**, not as an absent field
        // (live host, 2026-09-12), and a date from the year one drawn beside an
        // address is worse than nothing.
        let forever = r#"{"name":"gryonixnexus","items":[
            {"value":"203.0.113.5","description":"office","expiration":"0001-01-01T00:00:00.000Z"}]}"#;
        assert!(parse_allowlist_items(forever)[0].expires_in.is_empty());

        let listed = r#"[{"name":"somebody-else","items":[{"value":"198.51.100.1"}]},
                         {"name":"gryonixnexus","items":[{"value":"203.0.113.9"}]}]"#;
        let from_list = parse_allowlist_items(listed);
        assert_eq!(from_list.len(), 1, "another product's list must not be reported");
        assert_eq!(from_list[0].value, "203.0.113.9");
        // An entry that never expires carries no expiration at all.
        assert!(from_list[0].expires_in.is_empty());
    }

    /// **`ss` drops its State column when the query filters on state**, and
    /// this is the row shape a real host answered with (`vps-lab`,
    /// 2026-09-12). A parser counting fields from the left read it as nothing
    /// at all — and "nobody is connected" is indistinguishable from a correct
    /// answer on an idle host, which is why it needs a test rather than a look.
    #[test]
    fn the_ssh_peers_are_read_from_either_shape_of_ss_output() {
        let filtered = "0      228    31.70.137.80:22  207.89.80.9:58830\n                        0      0      31.70.137.80:22 187.40.41.85:31294";
        assert_eq!(parse_ss_peers(filtered), vec!["207.89.80.9", "187.40.41.85"]);

        // With the State column, and with IPv6 bracketed the way ss prints it.
        let with_state = "ESTAB 0 0 [2001:db8::1]:22 [2001:db8::9]:54321";
        assert_eq!(parse_ss_peers(with_state), vec!["2001:db8::9"]);

        // A header line, and a row whose tail carries process info, are not
        // addresses and must not become rows.
        let noisy = "Recv-Q Send-Q Local Address:Port Peer Address:Port\n                     0 0 10.0.0.1:22 203.0.113.9:2222 users:((\"sshd\",pid=1,fd=4))";
        assert_eq!(parse_ss_peers(noisy), vec!["203.0.113.9"]);

        // One address with two sessions is one address.
        let twice = "0 0 10.0.0.1:22 203.0.113.9:1\n0 0 10.0.0.1:22 203.0.113.9:2";
        assert_eq!(parse_ss_peers(twice), vec!["203.0.113.9"]);
    }

    /// **`cscli` stores whatever value it is given**, so a typo would become a
    /// permanent row matching no traffic that nobody can later explain. The
    /// guard is the agent's, not the client's: three clients would otherwise
    /// have to agree on it.
    #[test]
    fn only_an_address_or_a_range_may_be_banned() {
        for good in ["203.0.113.9", "203.0.113.0/24", "2001:db8::1", "2001:db8::/32", " 203.0.113.9 "] {
            assert!(valid_target(good), "{good} is an address");
        }
        for bad in ["", "  ", "example.com", "203.0.113.9; rm -rf /", "203.0.113.9/33",
                    "2001:db8::/129", "203.0.113.9/", "203.0.113.9/007", "203.0.113",
                    "-i", "--ip"] {
            assert!(!valid_target(bad), "{bad} is not an address");
        }
    }

    /// 0 means "say nothing", because CrowdSec's own default differs per verb —
    /// four hours for a ban, forever for an allowlist entry — and an agent that
    /// invented one number for both would be making policy.
    #[test]
    fn a_zero_duration_passes_no_flag_at_all() {
        assert_eq!(duration_arg(0), None);
        assert_eq!(duration_arg(3600).as_deref(), Some("3600s"));
    }

    #[test]
    fn metrics_parsers_survive_a_shape_they_do_not_recognise() {
        let empty = serde_json::json!({});
        assert_eq!(parse_top_scenarios(&empty, 5).len(), 0);
        assert_eq!(parse_community_blocklist_ips(&empty), 0);
        assert_eq!(parse_packets_dropped(&empty), 0);
        let odd = serde_json::json!({ "bouncers": { "b": { "CAPI": "not an object" } } });
        assert_eq!(parse_community_blocklist_ips(&odd), 0);
    }
}
