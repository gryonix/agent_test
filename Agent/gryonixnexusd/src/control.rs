//! Management behind the API (Phase 2): start / stop / restart one catalog
//! service, and read one service's live status.
//!
//! The deliberate shape here is TYPED verbs. There is no "run this command" RPC
//! and there must never be one: the agent is root and holds the docker socket,
//! so a generic exec would hand every paired device a root-equivalent primitive
//! and would put the engine back into the client — the opposite of why the
//! control plane moved to the server. A client sends a catalog id and an action;
//! everything else — which compose projects that id means, which verb runs, how
//! long to wait — is decided here.
//!
//! Nothing from the wire is ever interpolated into a shell. There is no shell on
//! this path at all: the id is checked against the agent's own catalog
//! (`discover::known_service`), and the strings that end up in argv are the
//! project names the HOST reported through `docker compose ls`.

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hyper::StatusCode;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::state::Store;
use crate::{discover, pb};

/// Deadline for ONE compose project. Ported from the app's `long` timeout class
/// (ten minutes), which is what the SSH path already allows a mail stack to take
/// on a Raspberry Pi. A blown deadline kills the child (`kill_on_drop`) and is
/// reported as a failure — never as a silent success.
const PROJECT_TIMEOUT_SECS: u64 = 600;

/// Client strings are echoed back in error messages so a mistyped id is
/// diagnosable, but only a bounded prefix of one: the message travels into logs
/// and UI, and a paired device must not be able to make either arbitrarily long.
const ECHO_LIMIT: usize = 64;

/// Why a management request was refused BEFORE anything on the host was touched.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Not a service in the agent's catalog — the validation gate.
    UnknownService(String),
    /// The action field was left at its zero value. Refused rather than
    /// defaulted: a client that forgot to set it must not perform some action
    /// on a live service by accident.
    UnspecifiedAction,
    /// A real catalog service, just not installed on this host.
    NotInstalled(String),
}

impl Rejection {
    /// Connect code + HTTP status. "Unknown id" and "not installed here" are
    /// deliberately different: the first is a client bug, the second is a state
    /// the user can fix, and the app phrases them differently.
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::UnknownService(id) => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                format!("unknown service '{}'", truncate(id)),
            ),
            Rejection::UnspecifiedAction => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "action is required (start, stop or restart)".to_string(),
            ),
            Rejection::NotInstalled(id) => (
                StatusCode::NOT_FOUND,
                "not_found",
                format!("service '{}' is not installed on this host", truncate(id)),
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

/// Check a request before any resolution or execution. Returns the action and
/// the service's display name.
pub fn validate(service_id: &str, action: i32) -> Result<(pb::ServiceAction, &'static str), Rejection> {
    let action = pb::ServiceAction::try_from(action).unwrap_or(pb::ServiceAction::Unspecified);
    if action == pb::ServiceAction::Unspecified {
        return Err(Rejection::UnspecifiedAction);
    }
    match discover::known_service(service_id) {
        Some(display) => Ok((action, display)),
        None => Err(Rejection::UnknownService(service_id.to_string())),
    }
}

/// The compose verb for an action, ported one-to-one from the Swift catalog's
/// `ServicePower`.
///
/// `stop` is `stop` and NEVER `down`: down REMOVES the containers, so `start`
/// could not bring the same ones back, and removing a service's containers is
/// uninstall — which lives behind its own root-owned wrapper with its own
/// confirmation. Getting this wrong would turn a "turn it off for a minute" tap
/// into a teardown.
fn verb(action: pb::ServiceAction) -> &'static str {
    match action {
        pb::ServiceAction::Start => "start",
        pb::ServiceAction::Stop => "stop",
        pb::ServiceAction::Restart => "restart",
        // Unreachable: `validate` rejects it before anything runs. Restarting is
        // the least destructive of the three if a future caller skips validation.
        pb::ServiceAction::Unspecified => "restart",
    }
}

/// The argument vector for one compose project. No shell, and the project name
/// is its own argv element: even a compose project with a hostile name is one
/// argument, never a second command.
///
/// No compose FILE and no `cd`: compose v2 finds a project's containers by
/// label, which is why `-p <project>` alone is enough — the same reason the SSH
/// path spells it this way.
pub fn docker_args(project: &str, action: pb::ServiceAction) -> Vec<String> {
    vec![
        "compose".to_string(),
        "-p".to_string(),
        project.to_string(),
        verb(action).to_string(),
    ]
}

// ─────────────────────────── ServiceStatus ───────────────────────────

/// One service's live status. Not installed is a RESULT, not an error: "gone"
/// and "never installed" are both states the user is entitled to see, and the
/// SSH path already renders a missing container as a warning row rather than a
/// failed probe.
pub async fn service_status(codec: Codec, req: pb::ServiceStatusRequest) -> Resp {
    let Some(display) = discover::known_service(&req.service_id) else {
        return Rejection::UnknownService(req.service_id.clone()).response();
    };
    match discover::service_snapshot(&req.service_id).await {
        Ok(Some(service)) => encode(
            codec,
            &pb::ServiceStatusResponse {
                service: Some(service),
                installed: true,
            },
        ),
        Ok(None) => encode(
            codec,
            &pb::ServiceStatusResponse {
                service: Some(pb::Service {
                    // Filled by `Store::snapshot` from the column this very
                    // action raises; nothing here has a claim to make.
                    installed_outside: false,
                    id: req.service_id.clone(),
                    display_name: display.to_string(),
                    status: pb::ServiceStatus::Unspecified as i32,
                    version: String::new(),
                    containers: Vec::new(),
                }),
                installed: false,
            },
        ),
        Err(err) => engine_unreachable(&err.to_string()),
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

/// The container engine itself could not be reached/queried. Its own text is
/// carried through: "docker: command not found" and "permission denied on the
/// socket" need opposite fixes, and hiding the difference is what made the SSH
/// path's silent failures so expensive.
fn engine_unreachable(detail: &str) -> Resp {
    connect_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        &format!("container engine unavailable: {detail}"),
    )
}

// ─────────────────────────── ControlService ───────────────────────────

/// Start / stop / restart one service, streaming progress.
///
/// Errors travel on two channels, on purpose:
/// * refusals that happen BEFORE anything is touched (unknown id, missing
///   action, service not installed, engine unreachable) come back as a plain
///   Connect error response — nothing ran, so there is no stream to open;
/// * a failure DURING the run ends the stream with an error trailer, but only
///   after the COMPLETED event has delivered the freshly re-read status. The
///   user's next question is always "what state is it in now", and answering it
///   is more useful than an error alone.
pub async fn control_service(
    codec: Codec,
    req: pb::ControlServiceRequest,
    store: Arc<Mutex<Store>>,
) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("service", &req.service_id) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let action = match validate(&req.service_id, req.action) {
        Ok((action, _display)) => action,
        Err(rejection) => return rejection.response(),
    };
    let projects = match discover::projects_of_service(&req.service_id).await {
        Ok(projects) => projects,
        Err(err) => return engine_unreachable(&err.to_string()),
    };
    if projects.is_empty() {
        return Rejection::NotInstalled(req.service_id.clone()).response();
    }

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let service_id = req.service_id.clone();

    tokio::spawn(async move {
        let _claim = claim;
        let sink = EventSink {
            tx,
            codec,
            service_id: service_id.clone(),
            action,
            journal: crate::jobs::Journal::open(pb::JobKind::ServiceControl, &service_id),
        };
        // The client hanging up at any point drops the receiver, every send
        // fails, and the task ends — but the docker command already running is
        // NOT cancelled halfway: a half-restarted stack is worse than one the
        // user stopped watching.
        let _ = sink.started(&projects).await;

        let mut failures = Vec::new();
        for project in &projects {
            // Every project is attempted even after one fails. A VPN service is
            // the panel plus each protocol as separate compose projects, and
            // stopping on the first error would leave the aggregate half
            // controlled with no way to tell which half.
            if let Err(why) = run_project(project, action, &sink).await {
                failures.push(format!("{project}: {why}"));
            }
        }

        match discover::service_snapshot(&service_id).await {
            Ok(Some(service)) => {
                // Best effort: a state write that fails must not turn a
                // successful restart into a reported failure. The snapshot the
                // client just received is the authority either way.
                if let Ok(store) = store.lock() {
                    if let Err(err) = store.put_service(&service) {
                        tracing::warn!(?err, "could not persist post-action status");
                    }
                }
                let _ = sink.completed(Some(service)).await;
            }
            Ok(None) => {
                let _ = sink.completed(None).await;
            }
            Err(err) => failures.push(format!("status re-read: {err}")),
        }

        if !failures.is_empty() {
            let _ = sink.fail(&failures.join("; ")).await;
        }
        // On success the body simply ends — the same clean end the other
        // streams use.
    });

    stream_response(json, rx)
}

/// Run one compose project's action, forwarding its output line by line.
/// `Err` carries a short reason; the process output has already been streamed.
async fn run_project(project: &str, action: pb::ServiceAction, sink: &EventSink) -> Result<(), String> {
    let args = docker_args(project, action);
    let mut child = tokio::process::Command::new("docker")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run docker: {err}"))?;

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());

    // The whole run is wrapped in ONE deadline rather than a per-line one:
    // `docker compose restart` on a twenty-container stack is silent for long
    // stretches, and a quiet minute is not a hung command. Dropping the future
    // on timeout drops the child, and `kill_on_drop` reaps it.
    let outcome = tokio::time::timeout(Duration::from_secs(PROJECT_TIMEOUT_SECS), async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.progress("stdout", text).await; }
                        _ => out = None, // EOF or read error on this pipe
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        // compose narrates on stderr ("Restarting 3/3"), so an
                        // stderr line is progress, not proof of failure — the
                        // exit status is.
                        Ok(Some(text)) => { let _ = sink.progress("stderr", text).await; }
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
        Err(_) => Err(format!("timed out after {PROJECT_TIMEOUT_SECS}s")),
        Ok(Err(io)) => Err(format!("docker did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(match status.code() {
            Some(code) => format!("docker exited {code}"),
            None => "docker was killed by a signal".to_string(),
        }),
    }
}

/// Frames and pushes the events of one operation. Every send failing means the
/// client is gone; callers treat that as "stop talking", never as an error to
/// report to anyone.
struct EventSink {
    tx: Sender<Bytes>,
    codec: Codec,
    service_id: String,
    action: pb::ServiceAction,
    /// The record this run leaves behind, so a client that closed can ask how
    /// it went — see `crate::jobs`. `None` when the host could not open one,
    /// which costs the reattach and nothing else.
    journal: Option<crate::jobs::Journal>,
}

impl EventSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::ServiceOperationEvent {
        pb::ServiceOperationEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            service_id: self.service_id.clone(),
            action: self.action as i32,
            text: String::new(),
            stream: String::new(),
            projects: Vec::new(),
            service: None,
        }
    }

    async fn send(&self, event: pb::ServiceOperationEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, projects: &[String]) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.projects = projects.to_vec();
        self.send(event).await
    }

    async fn progress(&self, stream: &str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(&self, service: Option<pb::Service>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.service = service;
        self.send(event).await
    }

    /// End the stream with a Connect error trailer. This is what makes the
    /// client throw: a streamed operation carries no exit status of its own, so
    /// without the trailer a failed restart would look exactly like a
    /// successful one — the same lesson the wrapper scripts learned with their
    /// completion markers.
    async fn fail(&self, message: &str) -> Result<(), ()> {
        // **The failure is the run's ending, and the record needs it in the
        // same words the trailer carries.** Without this the journal would be
        // closed by the drop below with "outcome not reported", which is true
        // of an early return and a lie about a failure that was named.
        crate::jobs::finish(&self.journal, Some(message));
        self.tx
            .send(error_trailer("internal", message))
            .await
            .map_err(|_| ())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::END_OF_STREAM_FLAG;

    #[test]
    fn unknown_service_is_refused_before_anything_runs() {
        // The gate: an id that is not in the catalog never reaches resolution,
        // let alone a command. `; rm -rf /` is here to show that a hostile
        // string is refused as an ID, not escaped — nothing on this path
        // builds a command line.
        assert_eq!(
            validate("nope", pb::ServiceAction::Restart as i32),
            Err(Rejection::UnknownService("nope".into()))
        );
        assert!(matches!(
            validate("vaultwarden; rm -rf /", pb::ServiceAction::Restart as i32),
            Err(Rejection::UnknownService(_))
        ));
    }

    #[test]
    fn unspecified_action_is_refused_not_defaulted() {
        assert_eq!(
            validate("vaultwarden", 0),
            Err(Rejection::UnspecifiedAction)
        );
        // An action outside the enum is the same failure, not a wild verb.
        assert_eq!(
            validate("vaultwarden", 99),
            Err(Rejection::UnspecifiedAction)
        );
    }

    #[test]
    fn known_services_validate_with_their_display_names() {
        assert_eq!(
            validate("vaultwarden", pb::ServiceAction::Stop as i32),
            Ok((pb::ServiceAction::Stop, "Vaultwarden"))
        );
        // The VPN aggregate: the panel and every protocol are one service here,
        // exactly as Discover and Logs report them.
        assert_eq!(
            validate("vpn", pb::ServiceAction::Start as i32),
            Ok((pb::ServiceAction::Start, "VPN"))
        );
    }

    #[test]
    fn stop_is_stop_and_never_down() {
        // Pinning the whole argv, not just the verb: `down` would REMOVE the
        // containers, which is uninstall, and `-p` alone (no compose file, no
        // cd) is what makes compose v2 find them by label.
        assert_eq!(
            docker_args("mailcowdockerized", pb::ServiceAction::Stop),
            ["compose", "-p", "mailcowdockerized", "stop"]
        );
        assert_eq!(
            docker_args("vaultwarden", pb::ServiceAction::Start),
            ["compose", "-p", "vaultwarden", "start"]
        );
        assert_eq!(
            docker_args("vpnpanel", pb::ServiceAction::Restart),
            ["compose", "-p", "vpnpanel", "restart"]
        );
        for action in [
            pb::ServiceAction::Start,
            pb::ServiceAction::Stop,
            pb::ServiceAction::Restart,
        ] {
            assert!(!docker_args("x", action).contains(&"down".to_string()));
            assert!(!docker_args("x", action).contains(&"rm".to_string()));
        }
    }

    #[test]
    fn a_project_name_stays_one_argument() {
        // The host's own compose project names reach argv; nothing splits them,
        // so a name with a space cannot become two arguments.
        let args = docker_args("weird name", pb::ServiceAction::Restart);
        assert_eq!(args.len(), 4);
        assert_eq!(args[2], "weird name");
    }

    #[test]
    fn rejections_carry_distinct_codes() {
        let (status, code, message) = Rejection::UnknownService("zzz".into()).parts();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "invalid_argument");
        assert!(message.contains("zzz"));

        let (status, code, message) = Rejection::NotInstalled("immich".into()).parts();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(code, "not_found");
        assert!(message.contains("immich"));
    }

    #[test]
    fn echoed_client_input_is_bounded() {
        let long = "a".repeat(5000);
        let (_, _, message) = Rejection::UnknownService(long).parts();
        assert!(message.len() < 200, "message was {} bytes", message.len());
    }

    #[test]
    fn error_trailer_is_an_end_of_stream_envelope() {
        let framed = error_trailer("internal", "vpnpanel: docker exited 1");
        assert_eq!(framed[0], END_OF_STREAM_FLAG);
        let payload = String::from_utf8(framed[5..].to_vec()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["error"]["code"], "internal");
        assert_eq!(parsed["error"]["message"], "vpnpanel: docker exited 1");
    }

    #[test]
    fn events_carry_their_service_and_action() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let sink = EventSink {
            tx,
            codec: Codec::Proto,
            service_id: "mailcow".into(),
            action: pb::ServiceAction::Restart,
            // No journal: this test is about what an event CARRIES, and a
            // record on disk would make it a test of two things.
            journal: None,
        };
        let event = sink.event(pb::ServiceOperationPhase::Progress);
        assert_eq!(event.service_id, "mailcow");
        assert_eq!(event.action, pb::ServiceAction::Restart as i32);
        assert_eq!(event.phase, pb::ServiceOperationPhase::Progress as i32);
    }
}
