//! The admin-guard toggle, driven through the deployment's own wrapper
//! (`/opt/gryonixnexus-admin-lockdown.sh`).
//!
//! Deployment-scoped, not per-service — the same shape as [`crate::update`]'s
//! `GetUpdatePolicy`/`SetUpdateSchedule`, and for the same reason: the wrapper
//! answers for the whole server's Caddy site in one call, so there is nothing
//! here to key by a catalog id the way `Backup`/`Uninstall` are.
//!
//! **The agent CALLS the wrapper; it does not touch nftables or Caddy
//! itself.** That script already IS the engine — it flips the guard's host
//! matcher and reloads Caddy — and it is the same script the SSH route
//! already drives (`StatusOperations.adminLockdownStatus`/`setAdminLockdown`).
//! A second implementation here would be a second opinion about what
//! "guarded" means for the same server, exactly the drift every other
//! wrapper-calling module in this crate was written to avoid.
//!
//! Both RPCs are unary: `status`/`on`/`off`/`only` are fast, local operations
//! (an nftables/Caddy reload, not a container engine call, and no `gpg` on
//! the path either — unlike backups and restores this wrapper needs neither a
//! writable `HOME` nor a passphrase on stdin), so there is no partial state
//! worth streaming.
//!
//! No shell and no stdin: the wrapper is spawned directly, every argument its
//! own argv element, and stdin is closed rather than inherited so the child
//! can never block on it — it never reads one.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::util::strip_ansi;
use crate::pb;

/// Must stay byte-identical to `CommandCatalog.AdminLockdown`'s three command
/// strings (Swift) — the modules deliberately do not depend on each other.
pub const WRAPPER_PATH: &str = "/opt/gryonixnexus-admin-lockdown.sh";

/// Deadline for one call. Generous for a local nftables/Caddy reload — this is
/// not a container engine call and has nothing in common with the ten-minute
/// ceilings backups/updates/restores need for a stack that can take that long.
const QUICK_TIMEOUT_SECS: u64 = 60;

/// Client strings are echoed back in error messages so a mistake is
/// diagnosable, but only a bounded prefix.
const ECHO_LIMIT: usize = 200;

fn truncate(value: &str) -> String {
    value.chars().take(ECHO_LIMIT).collect()
}

fn wrapper_path() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER").unwrap_or_else(|_| WRAPPER_PATH.to_string()))
}

/// Why a lockdown request was refused before anything on the host was
/// touched. There is no per-service `UnknownService` case here — this route
/// is not keyed by a catalog id at all.
#[derive(Debug, PartialEq, Eq)]
enum Rejection {
    /// This host has no lockdown wrapper at all: an adopted server, or one set
    /// up before the wrapper existed. Not a defect of this route — the SSH
    /// route calls the same missing file.
    NoWrapper,
    /// The mode field was left at its zero value. Refused rather than
    /// defaulted: a client that failed to set it must not silently flip a
    /// live server's guard.
    UnspecifiedMode,
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::NoWrapper => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "this server has no lockdown wrapper ({WRAPPER_PATH}) — re-run the setup script to install it"
                ),
            ),
            Rejection::UnspecifiedMode => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "mode is required (off, all or only)".to_string(),
            ),
        }
    }

    fn response(&self) -> Resp {
        let (status, code, message) = self.parts();
        connect_error(status, code, &message)
    }
}

/// Client-side mirror of the wrapper's own host validation — the exact
/// charset `CommandCatalog.AdminLockdown.isValidHost` (Swift) checks: a
/// non-empty string of ASCII letters, digits, `.` and `-`.
fn is_valid_host(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Port of `StatusOperations.parseLockdownAnswer` (Swift), kept
/// behaviour-for-behaviour identical on purpose: the wrapper's last non-empty
/// output line is the ONLY thing that decides the guard state, on both
/// routes, and a parser that drifted from its sibling would show two
/// different lockdown states for the same server depending on which client
/// asked.
///
/// Bare `"on"` → ALL. A line starting with `"only "` → ONLY, with the
/// space-separated hosts filtered through [`is_valid_host`]; if every host
/// fails that filter the answer collapses to OFF, exactly as the Swift
/// parser's `hosts.isEmpty ? .off : .only(...)` does. Anything else
/// (including no output at all) → OFF, the wrapper's own default.
fn parse_lockdown_answer(output: &str) -> pb::LockdownState {
    // Swift's `split(separator:)` omits empty subsequences by default, so
    // "the last non-empty line, trimmed" is the faithful port of "the last
    // line after splitting on \n".
    let last = output
        .split('\n')
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .last()
        .unwrap_or("");

    if last == "on" {
        return pb::LockdownState { mode: pb::LockdownMode::All as i32, hosts: Vec::new() };
    }
    if let Some(rest) = last.strip_prefix("only ") {
        let hosts: Vec<String> =
            rest.split(' ').filter(|h| !h.is_empty()).filter(|h| is_valid_host(h)).map(str::to_string).collect();
        return if hosts.is_empty() {
            pb::LockdownState { mode: pb::LockdownMode::Off as i32, hosts: Vec::new() }
        } else {
            pb::LockdownState { mode: pb::LockdownMode::Only as i32, hosts }
        };
    }
    pb::LockdownState { mode: pb::LockdownMode::Off as i32, hosts: Vec::new() }
}

/// The wrapper's argv for one `SetLockdown` call, or the refusal to build one
/// at all. Every element is a fixed literal or a host that already passed
/// [`is_valid_host`] — defense in depth: the wrapper validates hosts again,
/// but a bad one must never even reach argv, the same rule every module in
/// this crate follows for client-supplied strings that reach a spawned
/// process.
///
/// `ONLY` with an empty (or entirely filtered-out) host list becomes `off`,
/// mirroring the Swift rule in `StatusOperations.setAdminLockdown(hosts:on:)`:
/// "an empty list means off".
fn build_set_args(mode: pb::LockdownMode, hosts: &[String]) -> Result<Vec<String>, Rejection> {
    match mode {
        pb::LockdownMode::Unspecified => Err(Rejection::UnspecifiedMode),
        pb::LockdownMode::Off => Ok(vec!["off".to_string()]),
        pb::LockdownMode::All => Ok(vec!["on".to_string()]),
        pb::LockdownMode::Only => {
            let valid: Vec<String> = hosts.iter().filter(|h| is_valid_host(h)).cloned().collect();
            if valid.is_empty() {
                Ok(vec!["off".to_string()])
            } else {
                let mut args = vec!["only".to_string()];
                args.extend(valid);
                Ok(args)
            }
        }
    }
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

/// Spawn the wrapper, wait for it to finish, return its stdout. No shell, no
/// stdin — none of the four subcommands ever reads one, so stdin is closed
/// rather than inherited and the child can never block on it.
async fn run_wrapper(args: &[&str]) -> Result<String, String> {
    let child = tokio::process::Command::new(wrapper_path())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run the lockdown wrapper: {err}"))?;

    let output = tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output())
        .await
        .map_err(|_| format!("the lockdown wrapper timed out after {QUICK_TIMEOUT_SECS}s"))?
        .map_err(|err| format!("the lockdown wrapper did not finish: {err}"))?;

    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    if output.status.success() {
        return Ok(stdout);
    }
    let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr));
    Err(describe_failure(output.status.code(), &stderr))
}

fn describe_failure(code: Option<i32>, stderr: &str) -> String {
    let detail = truncate(stderr.trim());
    match (code, detail.is_empty()) {
        (_, false) => detail,
        (Some(code), true) => format!("the lockdown wrapper exited {code}"),
        (None, true) => "the lockdown wrapper was killed by a signal".to_string(),
    }
}

fn wrapper_failed(detail: &str) -> Resp {
    connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", detail)
}

/// The current guard state, as the wrapper's own last output line encodes it.
pub async fn get_lockdown(codec: Codec, _req: pb::GetLockdownRequest) -> Resp {
    if !wrapper_path().exists() {
        return Rejection::NoWrapper.response();
    }
    match run_wrapper(&["status"]).await {
        Ok(stdout) => encode(codec, &parse_lockdown_answer(&stdout)),
        Err(why) => wrapper_failed(&why),
    }
}

/// Change the guard state. The answer is the state the WRAPPER reports
/// afterwards — never the request echoed back, see the module's proto-side
/// doc comment for why that matters specifically for a filtered ONLY.
pub async fn set_lockdown(codec: Codec, req: pb::SetLockdownRequest) -> Resp {
    let mode = pb::LockdownMode::try_from(req.mode).unwrap_or(pb::LockdownMode::Unspecified);
    let args = match build_set_args(mode, &req.hosts) {
        Ok(args) => args,
        Err(rejection) => return rejection.response(),
    };
    if !wrapper_path().exists() {
        return Rejection::NoWrapper.response();
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match run_wrapper(&args).await {
        Ok(stdout) => encode(codec, &parse_lockdown_answer(&stdout)),
        Err(why) => wrapper_failed(&why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wrapper location is overridden through the environment, which is
    /// process-wide, and cargo runs tests in parallel threads — without this
    /// the tests would flip each other's override and fail at random. Same
    /// technique every other module in this crate uses.
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

    // ─────────────────────────── parse_lockdown_answer ───────────────────────────

    #[test]
    fn bare_on_is_all() {
        let state = parse_lockdown_answer("on\n");
        assert_eq!(state.mode, pb::LockdownMode::All as i32);
        assert!(state.hosts.is_empty());
    }

    #[test]
    fn bare_off_is_off() {
        let state = parse_lockdown_answer("off\n");
        assert_eq!(state.mode, pb::LockdownMode::Off as i32);
        assert!(state.hosts.is_empty());
    }

    #[test]
    fn only_line_lists_the_hosts() {
        let state = parse_lockdown_answer("only a.example.com b.example.com\n");
        assert_eq!(state.mode, pb::LockdownMode::Only as i32);
        assert_eq!(state.hosts, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn an_only_line_where_a_host_fails_the_charset_check_drops_just_that_host() {
        // A hostile or malformed token in the wrapper's own output must not
        // reach the client verbatim — the same charset gate the Swift parser
        // applies.
        let state = parse_lockdown_answer("only a.example.com evil;host b.example.com\n");
        assert_eq!(state.mode, pb::LockdownMode::Only as i32);
        assert_eq!(state.hosts, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn an_only_line_where_every_host_fails_collapses_to_off() {
        let state = parse_lockdown_answer("only evil;host another$one\n");
        assert_eq!(state.mode, pb::LockdownMode::Off as i32);
        assert!(state.hosts.is_empty());
    }

    #[test]
    fn empty_or_garbage_output_is_off() {
        assert_eq!(parse_lockdown_answer("").mode, pb::LockdownMode::Off as i32);
        assert_eq!(parse_lockdown_answer("\n\n").mode, pb::LockdownMode::Off as i32);
        assert_eq!(parse_lockdown_answer("some unrelated line\n").mode, pb::LockdownMode::Off as i32);
    }

    #[test]
    fn only_the_last_non_empty_line_is_read() {
        // A wrapper that logs progress before its final answer must not have
        // an earlier line mistaken for the result.
        let state = parse_lockdown_answer("reloading caddy\n\non\n");
        assert_eq!(state.mode, pb::LockdownMode::All as i32);
    }

    // ─────────────────────────── build_set_args ───────────────────────────

    #[test]
    fn unspecified_mode_is_refused_before_anything_runs() {
        assert_eq!(build_set_args(pb::LockdownMode::Unspecified, &[]), Err(Rejection::UnspecifiedMode));
    }

    #[test]
    fn off_and_all_build_their_bare_subcommand() {
        assert_eq!(build_set_args(pb::LockdownMode::Off, &[]), Ok(vec!["off".to_string()]));
        assert_eq!(build_set_args(pb::LockdownMode::All, &[]), Ok(vec!["on".to_string()]));
        // Hosts are ignored outside ONLY.
        assert_eq!(
            build_set_args(pb::LockdownMode::Off, &["a.example.com".to_string()]),
            Ok(vec!["off".to_string()])
        );
    }

    #[test]
    fn only_builds_the_subcommand_plus_every_valid_host() {
        let hosts = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        assert_eq!(
            build_set_args(pb::LockdownMode::Only, &hosts),
            Ok(vec!["only".to_string(), "a.example.com".to_string(), "b.example.com".to_string()])
        );
    }

    #[test]
    fn only_filters_out_a_host_with_a_shell_metacharacter_or_a_space_before_it_ever_reaches_argv() {
        let hosts = vec![
            "a.example.com".to_string(),
            "evil;rm -rf /".to_string(),
            "has space.example.com".to_string(),
            "$(whoami).example.com".to_string(),
        ];
        assert_eq!(build_set_args(pb::LockdownMode::Only, &hosts), Ok(vec!["only".to_string(), "a.example.com".to_string()]));
    }

    #[test]
    fn only_with_an_empty_host_list_becomes_off() {
        assert_eq!(build_set_args(pb::LockdownMode::Only, &[]), Ok(vec!["off".to_string()]));
    }

    #[test]
    fn only_where_every_host_fails_the_charset_check_also_becomes_off() {
        let hosts = vec!["evil;rm -rf /".to_string(), "has space".to_string()];
        assert_eq!(build_set_args(pb::LockdownMode::Only, &hosts), Ok(vec!["off".to_string()]));
    }

    // ─────────────────────────── get_lockdown, against a real stub ───────────────────────────

    #[tokio::test]
    async fn get_lockdown_reports_no_wrapper_when_the_host_has_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", "/nonexistent/gryonixnexus-admin-lockdown.sh");
        let resp = get_lockdown(Codec::Proto, pb::GetLockdownRequest {}).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
    }

    #[tokio::test]
    async fn get_lockdown_parses_each_of_the_three_wrapper_answers() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-lockdown-get-{}", std::process::id()));

        for (script_body, expected_mode) in [
            ("#!/bin/sh\necho on\n", pb::LockdownMode::All),
            ("#!/bin/sh\necho off\n", pb::LockdownMode::Off),
            ("#!/bin/sh\necho 'only a.example.com'\n", pb::LockdownMode::Only),
        ] {
            let script = write_stub(&dir, "admin-lockdown.sh", script_body);
            std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", &script);
            let resp = get_lockdown(Codec::Json, pb::GetLockdownRequest {}).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
            let state: pb::LockdownState = serde_json::from_slice(&body).unwrap();
            assert_eq!(state.mode, expected_mode as i32);
        }

        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────── set_lockdown, against a real stub ───────────────────────────

    #[tokio::test]
    async fn set_lockdown_reports_no_wrapper_when_the_host_has_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", "/nonexistent/gryonixnexus-admin-lockdown.sh");
        let resp = set_lockdown(Codec::Proto, pb::SetLockdownRequest { mode: pb::LockdownMode::All as i32, hosts: Vec::new() }).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
    }

    #[tokio::test]
    async fn set_lockdown_refuses_unspecified_mode_without_touching_the_host() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // No wrapper override at all: if this reached the wrapper it would try
        // the real /opt path and fail differently than invalid_argument.
        let resp = set_lockdown(Codec::Proto, pb::SetLockdownRequest { mode: 0, hosts: Vec::new() }).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn set_lockdown_passes_the_right_argv_and_reads_the_wrappers_own_answer_back() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-lockdown-set-{}", std::process::id()));
        // Echoes argv on stderr (so it does not become the parsed answer) and
        // always answers "on" — proving the RESPONSE comes from the wrapper's
        // own last line, not from what the client asked for.
        let script = write_stub(
            &dir,
            "admin-lockdown.sh",
            "#!/bin/sh\necho \"args: $*\" >&2\necho on\n",
        );
        std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", &script);

        let resp = set_lockdown(
            Codec::Json,
            pb::SetLockdownRequest { mode: pb::LockdownMode::Only as i32, hosts: vec!["a.example.com".to_string()] },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let state: pb::LockdownState = serde_json::from_slice(&body).unwrap();
        // The wrapper answered "on" regardless of what was asked — the answer
        // the client sees must be THAT, never an echo of the request.
        assert_eq!(state.mode, pb::LockdownMode::All as i32);

        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_lockdown_only_with_an_empty_host_list_runs_off_not_only() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-lockdown-set-empty-{}", std::process::id()));
        let script = write_stub(&dir, "admin-lockdown.sh", "#!/bin/sh\necho \"args: $*\" >&2\necho off\n");
        std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", &script);

        let resp = set_lockdown(Codec::Proto, pb::SetLockdownRequest { mode: pb::LockdownMode::Only as i32, hosts: Vec::new() }).await;
        assert_eq!(resp.status(), StatusCode::OK);

        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_lockdown_surfaces_the_wrappers_own_failure_text() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-lockdown-set-fail-{}", std::process::id()));
        let script = write_stub(&dir, "admin-lockdown.sh", "#!/bin/sh\necho 'no caddyfile found' >&2\nexit 1\n");
        std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", &script);

        let resp = set_lockdown(Codec::Proto, pb::SetLockdownRequest { mode: pb::LockdownMode::All as i32, hosts: Vec::new() }).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["message"].as_str().unwrap().contains("no caddyfile found"));

        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
