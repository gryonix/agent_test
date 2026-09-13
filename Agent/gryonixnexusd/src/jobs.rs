//! What a long operation leaves behind, so the phone does not have to stay.
//!
//! **The install slice's lesson, once, for every kind** (owner, 2026-08-29:
//! "пользователь должен иметь возможность закрыть приложение, чтобы процедура
//! продолжилась"). `install::journal` says it best and says it first: the work
//! was never owned by the stream. Every long verb here spawns its run into the
//! daemon and narrates through a channel whose `send` is allowed to fail —
//! `let _ = sink.step(...)` — so a client hanging up has never stopped an
//! update, a backup, a restore or a container operation. What they lacked was
//! a NAME and a RECORD: nothing to ask about afterwards, so a returning client
//! could only guess from live state whether the thing had happened.
//!
//! This module is that record, generalised. One file format, one directory,
//! one pair of verbs (`WatchJob` / `ListJobs`) for all of them.
//!
//! **Why not one journal module per verb.** Because the client has to render
//! them in ONE list — "what is this host doing right now" is a question about
//! the host, not about a particular verb — and because a rule that exists in
//! nine copies is a rule that will differ in nine ways. GOTCHAS already
//! carries that lesson twice over from the health check that was fixed in the
//! agent and left broken in the generated wrapper.
//!
//! **The narration is stored; the typed payload is not.** These verbs end by
//! re-reading live state (`ServiceStatusResponse`, `BackupList`,
//! `ContainerGroup`) and freezing one of those into a file would hand a
//! returning client an answer that was true minutes ago. `install::journal`
//! made the same call about its `Service` snapshot, for the same reason.
//!
//! **`/var/lib/gryonixnexus/agent` needs no unit change.** The unit already
//! grants `StateDirectory=gryonixnexus/agent`, so a subdirectory of it is
//! writable by construction — and GOTCHAS' rule stands: a path added to
//! `ReadWritePaths` that does not exist on disk kills the agent outright.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hyper::StatusCode;
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::pb;

/// An atomic reservation, acquired before spawning and held by the task rather
/// than its HTTP stream. Journal IO is deliberately not the admission lock:
/// backups must remain exclusive even when a full disk prevents a journal.
pub struct OperationClaim(String);

fn claimed() -> &'static Mutex<std::collections::HashSet<String>> {
    static CLAIMED: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    CLAIMED.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

impl OperationClaim {
    pub fn acquire(namespace: &str, subject: &str) -> Result<Self, Resp> {
        let key = format!("{namespace}:{subject}");
        let mut held = claimed().lock().unwrap_or_else(|e| e.into_inner());
        if !held.insert(key.clone()) {
            return Err(connect_error(StatusCode::CONFLICT, "already_exists",
                "An operation is already running for this service or container group. Wait for it to finish."));
        }
        Ok(Self(key))
    }
}

impl Drop for OperationClaim {
    fn drop(&mut self) {
        claimed().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.0);
    }
}

/// Same seam `main.rs` reads, so a test can point the journals somewhere
/// harmless without a state directory or root.
const STATE_DIR_ENV: &str = "GRYONIXNEXUSD_STATE_DIR";
const STATE_DIR_FALLBACK: &str = "/var/lib/gryonixnexus/agent";

/// How many runs are kept across all kinds. A journal is a few hundred
/// kilobytes at worst; the client only ever asks about the last few, but a
/// host that backs up nightly for a year must not accumulate them for ever.
const KEEP_JOBS: usize = 80;

/// How often a follower looks for new lines while a run is still going. Steps
/// arrive seconds apart at best (docker pulls, health waits), so polling costs
/// nothing next to the work being narrated, and it needs no filesystem
/// notification for a file whose name we already know.
const FOLLOW_POLL: Duration = Duration::from_millis(250);

fn state_dir() -> PathBuf {
    PathBuf::from(std::env::var(STATE_DIR_ENV).unwrap_or_else(|_| STATE_DIR_FALLBACK.to_string()))
}

fn journal_dir() -> PathBuf {
    state_dir().join("jobs")
}

/// **The install slice wrote its journals here first, and hosts have them.**
/// Read-only as far as this module is concerned: `install::journal` still owns
/// that directory, and this one reads it so a returning client sees installs
/// in the same list as everything else rather than having to ask a second verb
/// which it would only know to ask on an older host.
fn legacy_install_dir() -> PathBuf {
    state_dir().join("installs")
}

fn path_for(job_id: &str) -> PathBuf {
    journal_dir().join(format!("{job_id}.jsonl"))
}

/// Is this shaped like something `mint_job_id` could have minted — here or in
/// `install::journal`, which uses the identical `{hex}-{hex}-{hex}` scheme?
///
/// **`run_watch_job`/`run_cancel_job` check this before their first lookup,
/// not `locate()`.** `locate()` (via `parse()`) is also how `list()` reads
/// back ids it globbed off disk itself (`ids_in`) — trusted by construction,
/// including on hosts old enough to have legacy install ids that predate this
/// scheme. Only a `job_id` that arrived from an RPC request is untrusted: an
/// unvalidated one (`..`, `/`) would let `WatchJob`/`CancelJob` read any
/// `.jsonl` on the host as root, joined straight into `path_for`/
/// `legacy_install_dir`.
fn is_valid_job_id(job_id: &str) -> bool {
    let mut groups = job_id.split('-');
    let three_hex_groups =
        (0..3).all(|_| groups.next().is_some_and(|g| !g.is_empty() && g.bytes().all(|b| b.is_ascii_hexdigit())));
    three_hex_groups && groups.next().is_none()
}

/// Jobs this daemon process is running right now, job id → kind.
///
/// **The authority for RUNNING within one lifetime, and the reason ABANDONED
/// can be told apart from it.** A journal with no closing line means one of two
/// very different things — the work is still going, or the daemon died holding
/// it — and nothing in the file can distinguish them.
fn running() -> &'static Mutex<HashMap<String, i32>> {
    static RUNNING: OnceLock<Mutex<HashMap<String, i32>>> = OnceLock::new();
    RUNNING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// **Poisoning is not an error here.** A panic inside one spawned run would
/// poison this lock and every `lock().unwrap()` after it, so a single failed
/// backup would take out `ListJobs`, `WatchJob` and the next backup with it.
/// The map is a set of names, not an invariant that can be half-updated — the
/// honest recovery is to keep using it. Learned the expensive way in
/// `install::journal`, whose negative control failed seven tests for one
/// defect.
fn running_guard() -> std::sync::MutexGuard<'static, HashMap<String, i32>> {
    running().lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// An id unique on this host without pulling in a uuid crate: the start time
/// in seconds, the process id, and a counter that separates two runs started
/// in the same second by the same daemon.
fn mint_job_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}-{:x}", now_unix(), std::process::id(), n)
}

fn write_line(path: &PathBuf, line: &serde_json::Value) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")
}

/// The handle a running operation writes through.
///
/// Cloneable and cheap: the sinks that narrate these operations are moved into
/// spawned tasks and shared with the readers that stream a wrapper's stdout,
/// and a journal that could not be shared would have to be threaded by
/// reference through every one of those signatures.
#[derive(Clone)]
pub struct Journal(std::sync::Arc<Inner>);

struct Inner {
    job_id: String,
    kind: i32,
    subject: String,
    path: PathBuf,
    /// The next sequence number. Owned HERE rather than taken from the caller:
    /// the typed streams number their events differently, and some not at all,
    /// while `from_sequence` has to mean one thing.
    next: AtomicU64,
    /// Whether an ending has been written. Read by the drop below, which is
    /// the safety net for a run that returns without saying how it went.
    closed: std::sync::atomic::AtomicBool,
    /// Whether the run narrated a COMPLETED phase. That event is every verb's
    /// own word for "the work is done and here is what it produced", so a
    /// journal that has one and no failure ended in success — which is what
    /// lets the drop below tell a finished run from an abandoned one without
    /// nine call sites having to say so.
    completed: std::sync::atomic::AtomicBool,
}

impl Journal {
    /// Open a journal for a run about to start.
    ///
    /// **Failing to open one is not a reason to refuse the work.** The run is
    /// the product; the record is how you ask about it later. A `None` journal
    /// means only that this run cannot be reattached to — which is exactly
    /// what every one of these operations was before this module existed.
    pub fn open(kind: pb::JobKind, subject: &str) -> Option<Journal> {
        let dir = journal_dir();
        if let Err(err) = fs::create_dir_all(&dir) {
            tracing::warn!("job journal unavailable ({err}); this run cannot be reattached to");
            return None;
        }
        let job_id = mint_job_id();
        let path = path_for(&job_id);
        let meta = serde_json::json!({
            "kind": "meta",
            "job": job_id,
            "job_kind": kind as i32,
            "subject": subject,
            "started": now_unix(),
        });
        if let Err(err) = write_line(&path, &meta) {
            tracing::warn!("job journal unavailable ({err}); this run cannot be reattached to");
            return None;
        }
        running_guard().insert(job_id.clone(), kind as i32);
        prune(&dir);
        Some(Journal(std::sync::Arc::new(Inner {
            job_id,
            kind: kind as i32,
            subject: subject.to_string(),
            path,
            next: AtomicU64::new(0),
            closed: std::sync::atomic::AtomicBool::new(false),
            completed: std::sync::atomic::AtomicBool::new(false),
        })))
    }

    pub fn job_id(&self) -> &str {
        &self.0.job_id
    }

    /// Record one narrated line. Never fails loudly: a full disk must not turn
    /// a working backup into a failed one.
    pub fn append(&self, phase: pb::JobPhase, stream: &str, text: &str) {
        if phase == pb::JobPhase::Completed {
            self.0.completed.store(true, Ordering::SeqCst);
        }
        let sequence = self.0.next.fetch_add(1, Ordering::Relaxed);
        let line = serde_json::json!({
            "kind": "event",
            "seq": sequence,
            "phase": phase as i32,
            "stream": stream,
            "text": text,
        });
        if let Err(err) = write_line(&self.0.path, &line) {
            tracing::warn!("could not append to the job journal: {err}");
        }
    }

    /// Close the journal. After this the run reads back as SUCCEEDED or FAILED
    /// rather than RUNNING, which is what lets a returning client stop
    /// following.
    pub fn finish(&self, failure: Option<&str>) {
        self.0.close(failure, false);
    }

    /// Close it as STOPPED ON REQUEST.
    ///
    /// A third ending rather than a failure with a polite message: the person
    /// who pressed Cancel knows why the run ended, and a screen that renders
    /// it red sends them looking for a cause that does not exist. `note` is
    /// what the run left behind — the words go in the journal, not in the
    /// `failure` field a client colours by.
    pub fn cancelled(&self, note: &str) {
        self.append(pb::JobPhase::Completed, "agent", note);
        self.0.close(None, true);
    }
}

impl Inner {
    fn close(&self, failure: Option<&str>, cancelled: bool) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // A field rather than a sentinel in `failure`: a journal written by an
        // older agent has neither, reads back exactly as it did before, and a
        // reader that does not know the field still sees a run that ended.
        let line = serde_json::json!({
            "kind": "end",
            "finished": now_unix(),
            "failure": failure.unwrap_or(""),
            "cancelled": cancelled,
        });
        if let Err(err) = write_line(&self.path, &line) {
            tracing::warn!("could not close the job journal: {err}");
        }
        running_guard().remove(&self.job_id);
        let _ = (&self.kind, &self.subject);
    }
}

/// **A run that ends without saying how is still a run that ENDED.**
///
/// A failure closes the journal in the words of its own trailer; everything
/// else ends here, when the last handle goes — which is the end of the spawned
/// task, whichever way the control flow got there. Left open, the file would
/// read RUNNING for as long as the daemon lives and a client would follow it
/// for ever.
///
/// **Success is not assumed, it is READ.** A journal that narrated COMPLETED —
/// every verb's own word for "done, and here is what it produced" — closes as
/// a success; one that did not says so, because a run that returned early
/// without a word about how it went is exactly the case nobody should be told
/// went fine.
impl Drop for Inner {
    fn drop(&mut self) {
        if self.completed.load(Ordering::SeqCst) {
            // The verb said COMPLETED and never said it failed: that is a
            // success, and the drop is simply where the run ended.
            self.close(None, false);
            return;
        }
        self.close(
            Some("the run ended without reporting an outcome; what it left behind is not known"),
            false,
        );
    }
}

/// The id a caller puts on its typed events, journal or not. An empty string
/// is the honest answer when no journal could be opened: the client reads it
/// as "this run cannot be watched", which is true.
pub fn id_of(journal: &Option<Journal>) -> String {
    journal
        .as_ref()
        .map(|j| j.job_id().to_string())
        .unwrap_or_default()
}

/// **The nine verbs all narrate through the same four phases**, so the mapping
/// from their own enum to this module's lives here once rather than in each of
/// them. An unknown value from a future phase is PROGRESS: it is narration, and
/// dropping it would lose a line the operator was shown live.
pub fn phase_of(service_operation_phase: i32) -> pb::JobPhase {
    match service_operation_phase {
        x if x == pb::ServiceOperationPhase::Started as i32 => pb::JobPhase::Started,
        x if x == pb::ServiceOperationPhase::Completed as i32 => pb::JobPhase::Completed,
        _ => pb::JobPhase::Progress,
    }
}

/// Copy one narrated event into the run's record. Called from every sink's
/// `send`, which is the one place each verb's events are finished being built.
pub fn tee(journal: &Option<Journal>, phase: i32, stream: &str, text: &str) {
    if let Some(journal) = journal {
        journal.append(phase_of(phase), stream, text);
    }
}

/// Close a run's record, if it has one.
pub fn finish(journal: &Option<Journal>, failure: Option<&str>) {
    if let Some(journal) = journal {
        journal.finish(failure);
    }
}

/// Drop the oldest journals once there are more than [`KEEP_JOBS`]. Best
/// effort in every direction: an unreadable directory simply keeps what is
/// there.
fn prune(dir: &PathBuf) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    let mut files: Vec<(SystemTime, PathBuf)> = entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
        .filter_map(|e| {
            let modified = e.metadata().ok()?.modified().ok()?;
            Some((modified, e.path()))
        })
        .collect();
    if files.len() <= KEEP_JOBS {
        return;
    }
    files.sort_by_key(|(when, _)| *when);
    for (_, path) in files.iter().take(files.len() - KEEP_JOBS) {
        let _ = fs::remove_file(path);
    }
}

/// What one journal file says about itself.
struct Parsed {
    job_id: String,
    kind: i32,
    subject: String,
    started: i64,
    finished: i64,
    failure: String,
    closed: bool,
    cancelled: bool,
    events: Vec<pb::JobEvent>,
}

/// Parse one file. `default_kind` is what a file without a `job_kind` in its
/// meta line means — which is how the install slice's own journals, written
/// before kinds existed, read as installs rather than as nothing.
fn parse_file(path: &PathBuf, job_id: &str, default_kind: i32) -> Option<Parsed> {
    let file = File::open(path).ok()?;
    let mut parsed = Parsed {
        job_id: job_id.to_string(),
        kind: default_kind,
        subject: String::new(),
        started: 0,
        finished: 0,
        failure: String::new(),
        closed: false,
        cancelled: false,
        events: Vec::new(),
    };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            // A torn last line is what a journal looks like when the daemon
            // died mid-write. Everything before it is still true.
            continue;
        };
        match value.get("kind").and_then(|k| k.as_str()) {
            Some("meta") => {
                // "subject" here, "service" in the install slice's files: one
                // reader, two writers, and the older one named the field after
                // the only kind it had.
                parsed.subject = value
                    .get("subject")
                    .or_else(|| value.get("service"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                parsed.started = value.get("started").and_then(|v| v.as_i64()).unwrap_or(0);
                if let Some(kind) = value.get("job_kind").and_then(|v| v.as_i64()) {
                    parsed.kind = kind as i32;
                }
            }
            Some("event") => parsed.events.push(pb::JobEvent {
                job_id: job_id.to_string(),
                sequence: value.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
                kind: parsed.kind,
                phase: value.get("phase").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                text: value
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                stream: value
                    .get("stream")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                subject: parsed.subject.clone(),
            }),
            Some("end") => {
                parsed.closed = true;
                parsed.finished = value.get("finished").and_then(|v| v.as_i64()).unwrap_or(0);
                parsed.failure = value
                    .get("failure")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                parsed.cancelled = value
                    .get("cancelled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            }
            _ => {}
        }
    }
    if parsed.subject.is_empty() && parsed.events.is_empty() {
        return None;
    }
    Some(parsed)
}

/// Where a job id lives: this module's directory, or the install slice's.
fn locate(job_id: &str) -> Option<(PathBuf, i32)> {
    let own = path_for(job_id);
    if own.exists() {
        return Some((own, pb::JobKind::Unspecified as i32));
    }
    let legacy = legacy_install_dir().join(format!("{job_id}.jsonl"));
    if legacy.exists() {
        return Some((legacy, pb::JobKind::Install as i32));
    }
    None
}

fn parse(job_id: &str) -> Option<Parsed> {
    let (path, default_kind) = locate(job_id)?;
    parse_file(&path, job_id, default_kind)
}

fn outcome_of(parsed: &Parsed) -> pb::JobOutcome {
    if !parsed.closed {
        return if running_guard().contains_key(&parsed.job_id)
            || crate::install::journal::is_running(&parsed.job_id)
        {
            pb::JobOutcome::Running
        } else {
            pb::JobOutcome::Abandoned
        };
    }
    if parsed.cancelled {
        return pb::JobOutcome::Cancelled;
    }
    if parsed.failure.is_empty() {
        pb::JobOutcome::Succeeded
    } else {
        pb::JobOutcome::Failed
    }
}

fn ids_in(dir: PathBuf) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            if path.extension().is_some_and(|x| x == "jsonl") {
                path.file_stem()?.to_str().map(|s| s.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn job_of(parsed: &Parsed) -> pb::Job {
    pb::Job {
        job_id: parsed.job_id.clone(),
        kind: parsed.kind,
        subject: parsed.subject.clone(),
        started_unix: parsed.started,
        finished_unix: parsed.finished,
        outcome: outcome_of(parsed) as i32,
        failure: parsed.failure.clone(),
        events: parsed.events.len() as u64,
    }
}

/// Every run this host still has a record of, newest first — both this
/// module's journals and the install slice's.
pub fn list(kind: pb::JobKind, running_only: bool) -> Vec<pb::Job> {
    let mut jobs: Vec<pb::Job> = ids_in(journal_dir())
        .into_iter()
        .chain(ids_in(legacy_install_dir()))
        .filter_map(|id| parse(&id))
        .map(|parsed| job_of(&parsed))
        .filter(|job| kind == pb::JobKind::Unspecified || job.kind == kind as i32)
        .filter(|job| !running_only || job.outcome == pb::JobOutcome::Running as i32)
        .collect();
    jobs.sort_by(|a, b| b.started_unix.cmp(&a.started_unix));
    jobs
}

/// One job, or `None` when this host has no record of that id.
pub fn job(job_id: &str) -> Option<pb::Job> {
    parse(job_id).map(|parsed| job_of(&parsed))
}

/// The events of a job from `from_sequence` on, plus whether the run has ended
/// and with what.
pub fn events_after(job_id: &str, from_sequence: u64) -> Option<(Vec<pb::JobEvent>, bool, String)> {
    let parsed = parse(job_id)?;
    let closed = parsed.closed;
    let failure = parsed.failure.clone();
    let events = parsed
        .events
        .into_iter()
        .filter(|e| e.sequence >= from_sequence)
        .collect();
    Some((events, closed, failure))
}

pub fn is_running(job_id: &str) -> bool {
    running_guard().contains_key(job_id)
}

/// How long a follower should wait before looking for more.
pub fn follow_poll() -> Duration {
    FOLLOW_POLL
}

/// Called once at startup. Nothing this daemon did not start is running, so
/// every open journal on disk belongs to a previous life and is ABANDONED.
/// This exists to say so out loud, because a host that reboots mid-backup
/// otherwise looks like a host where a backup is still going.
pub fn sweep_abandoned() {
    let abandoned: Vec<String> = ids_in(journal_dir())
        .into_iter()
        .filter_map(|id| parse(&id))
        .filter(|parsed| !parsed.closed)
        .map(|parsed| format!("{} ({})", parsed.job_id, parsed.subject))
        .collect();
    if !abandoned.is_empty() {
        tracing::warn!(
            "runs left unfinished by a previous agent process: {}",
            abandoned.join(", ")
        );
    }
}

// ─────────────────────────── the two verbs ───────────────────────────

/// `Jobs/WatchJob` — attach to a run that is going, or read back one that has
/// ended.
///
/// **One verb for both, deliberately.** A client cannot know which it is
/// before it asks: between deciding and asking, a run it thought was live can
/// end. Making it choose would put it on the losing side of that race every
/// time; here a running job streams its journal and then follows it, and a
/// finished one streams the journal and stops.
pub async fn run_watch_job(codec: Codec, req: pb::WatchJobRequest) -> Resp {
    if !is_valid_job_id(&req.job_id) || job(&req.job_id).is_none() {
        return connect_error(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("this host has no record of job {}", req.job_id),
        );
    }
    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        follow(req.job_id, req.from_sequence, codec, tx).await;
    });
    stream_response(json, rx)
}

async fn follow(job_id: String, from_sequence: u64, codec: Codec, tx: Sender<Bytes>) {
    let mut next = from_sequence;
    loop {
        let Some((events, closed, failure)) = events_after(&job_id, next) else {
            // Pruned out from under the follower. Nothing left to say about it.
            return;
        };
        for event in events {
            next = event.sequence + 1;
            let payload = codec.encode_payload(&event);
            if tx.send(envelope(0x00, &payload)).await.is_err() {
                // The watcher hung up too. Same rule as the run itself: not a
                // reason for anything to stop, just a reason to stop talking.
                return;
            }
        }
        if closed {
            // The same two-channel discipline the live streams hold: the
            // failure rides the trailer, after everything that was narrated.
            if !failure.is_empty() {
                let _ = tx.send(error_trailer("internal", &failure)).await;
            }
            return;
        }
        if !is_running(&job_id) && !crate::install::journal::is_running(&job_id) {
            // An open journal nobody is writing to. Saying nothing would leave
            // the client following an empty file for ever — the exact shape of
            // "reads as a hung agent" GOTCHAS warns about.
            let _ = tx
                .send(error_trailer(
                    "aborted",
                    "the agent stopped while this run was going; nothing is known about what it \
                     left behind. What to do about that depends on the operation, so the client \
                     is told rather than guessed for",
                ))
                .await;
            return;
        }
        tokio::time::sleep(follow_poll()).await;
    }
}

/// `Jobs/ListJobs` — what this host has run lately, newest first.
///
/// For the client that has no job id to watch: a reinstalled app, a second
/// device, a deployment imported from a file. Unary because a listing does not
/// change while it is being read.
pub async fn run_list_jobs(codec: Codec, req: pb::ListJobsRequest) -> Resp {
    let kind = pb::JobKind::try_from(req.kind).unwrap_or(pb::JobKind::Unspecified);
    let list = pb::JobList {
        jobs: list(kind, req.running_only),
    };
    codec.encode(&list).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

// ───────────────────────────── Stopping one ─────────────────────────────

/// The switches of the runs that can be stopped, by job id.
///
/// **A run is cancellable only if it registered itself here, and most do not.**
/// Stopping is a promise about the state left behind: a model fetch writes into
/// a scratch file nothing else depends on, so dropping the connection and
/// deleting the partial blob puts the host back where it started. An install,
/// an update or a restore is a sequence of steps against a live machine, and
/// "stopped halfway" is not a state any of them can describe — those must not
/// offer a button that leaves a host nobody can name. The registry IS the
/// answer to "can this be stopped": no entry, no cancel.
fn switches() -> &'static Mutex<HashMap<String, tokio::sync::watch::Sender<bool>>> {
    static SWITCHES: OnceLock<Mutex<HashMap<String, tokio::sync::watch::Sender<bool>>>> =
        OnceLock::new();
    SWITCHES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn switches_guard() -> std::sync::MutexGuard<'static, HashMap<String, tokio::sync::watch::Sender<bool>>>
{
    switches().lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Held by a run that can be stopped; unregisters itself when the run ends.
///
/// The receiver is what the work selects on. Dropping the switch removes the
/// entry, so a finished run answers "cannot be stopped" rather than accepting a
/// cancel that reaches nothing.
pub struct CancelSwitch {
    job_id: String,
    rx: tokio::sync::watch::Receiver<bool>,
}

impl CancelSwitch {
    /// True once somebody has asked this run to stop.
    ///
    /// A polling read beside `wait()`'s `select!`-friendly future — nothing
    /// in production reaches for it today (every real caller has a future to
    /// select on instead, see `models.rs`'s pull loop), but the test below
    /// does, which is exactly the shape a dead-code warning cannot tell
    /// apart from a method nobody uses at all.
    #[allow(dead_code)]
    pub fn asked(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolves when somebody asks this run to stop, and never otherwise —
    /// the branch to put in a `select!` beside the work.
    pub async fn wait(&self) {
        let mut rx = self.rx.clone();
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                // The sender is gone, which happens only when this run is
                // already ending. Never resolve: the other branch is about to.
                std::future::pending::<()>().await;
            }
        }
    }
}

impl Drop for CancelSwitch {
    fn drop(&mut self) {
        switches_guard().remove(&self.job_id);
    }
}

/// Register a run as stoppable. `None` when it has no journal, because a run
/// nobody can name is a run nobody can cancel either.
pub fn cancellable(journal: &Option<Journal>) -> Option<CancelSwitch> {
    let job_id = journal.as_ref()?.job_id().to_string();
    let (tx, rx) = tokio::sync::watch::channel(false);
    switches_guard().insert(job_id.clone(), tx);
    Some(CancelSwitch { job_id, rx })
}

/// Ask a run to stop. False when nothing is listening — an unknown id, a run
/// that has ended, or a kind that does not offer cancellation.
pub fn ask_to_stop(job_id: &str) -> bool {
    match switches_guard().get(job_id) {
        Some(tx) => tx.send(true).is_ok(),
        None => false,
    }
}

/// `Jobs/CancelJob` — stop a run that is still going.
///
/// **Answers the job rather than an acknowledgement**, and waits a moment for
/// the run to actually end first: a client that asked to stop a fetch wants to
/// see it stopped, and a screen that has to poll for the difference between
/// "asked" and "stopped" is a screen that will show one as the other.
///
/// A run that finished while the request was in flight is not an error. The
/// person pressed a button on a screen that was a second out of date, and the
/// honest answer is the outcome the run actually reached.
pub async fn run_cancel_job(codec: Codec, req: pb::CancelJobRequest) -> Resp {
    if !is_valid_job_id(&req.job_id) {
        return connect_error(StatusCode::NOT_FOUND, "not_found", "no run with that id on this host");
    }
    let Some(current) = job(&req.job_id) else {
        return connect_error(StatusCode::NOT_FOUND, "not_found", "no run with that id on this host");
    };
    if current.outcome != pb::JobOutcome::Running as i32 {
        return codec.encode(&current).unwrap_or_else(|err| {
            connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
        });
    }
    if !ask_to_stop(&req.job_id) {
        return connect_error(
            StatusCode::FAILED_DEPENDENCY,
            "failed_precondition",
            "this run cannot be stopped once it has started",
        );
    }
    // Long enough for a fetch to notice between two lines of progress, short
    // enough that the request does not look hung. What comes back after it is
    // the truth either way — a run still closing reads RUNNING, and the client
    // is already watching it.
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !is_running(&req.job_id) {
            break;
        }
    }
    let answer = job(&req.job_id).unwrap_or(current);
    codec.encode(&answer).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **One lock for one env var, shared with every other reader of it.**
    /// `GRYONIXNEXUSD_STATE_DIR` is process-wide, and GOTCHAS carries the price
    /// of modules that each brought their own: internally consistent, mutually
    /// destructive. `util::STATE_DIR_ENV_LOCK` is the crate's one lock, and
    /// this module takes it rather than minting a tenth.
    fn with_dir<T>(name: &str, body: impl FnOnce() -> T) -> T {
        let _guard = crate::util::STATE_DIR_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-jobs-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var(STATE_DIR_ENV, &dir);
        running_guard().clear();
        let out = body();
        std::env::remove_var(STATE_DIR_ENV);
        let _ = fs::remove_dir_all(&dir);
        out
    }

    /// **Stopped on request is its own ending, not a failure.** A screen that
    /// colours the third state red sends the person who pressed Cancel looking
    /// for a cause that does not exist, and `failure` is the field they colour
    /// by — so it has to stay empty.
    #[test]
    fn a_stopped_run_reads_back_as_cancelled_and_not_as_a_failure() {
        with_dir("cancelled", || {
            let journal = Journal::open(pb::JobKind::ModelPull, "llama3.2:3b").unwrap();
            let id = journal.job_id().to_string();
            journal.append(pb::JobPhase::Progress, "agent", "pulling manifest");
            journal.cancelled("stopped; 12.0 GB of partly fetched layers removed");

            let job = super::job(&id).unwrap();
            assert_eq!(job.outcome, pb::JobOutcome::Cancelled as i32);
            assert!(job.failure.is_empty(), "a cancel is not a failure: {}", job.failure);
            let (events, closed, failure) = events_after(&id, 0).unwrap();
            assert!(closed);
            assert!(failure.is_empty());
            assert!(
                events.last().unwrap().text.contains("partly fetched layers removed"),
                "the run does not say what it left behind: {events:?}"
            );
        });
    }

    /// A journal written before this ending existed carries no `cancelled`
    /// field at all, and must read back exactly as it always did.
    #[test]
    fn an_older_journal_still_reads_as_it_did() {
        with_dir("older", || {
            let journal = Journal::open(pb::JobKind::Backup, "nextcloud").unwrap();
            let id = journal.job_id().to_string();
            journal.append(pb::JobPhase::Progress, "agent", "archiving");
            drop(journal);
            // The end line an older agent wrote: no `cancelled` key.
            let path = path_for(&id);
            let text = fs::read_to_string(&path).unwrap();
            let stripped: String = text
                .lines()
                .map(|line| line.replace(",\"cancelled\":false", "").replace(",\"cancelled\":true", ""))
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(&path, format!("{stripped}\n")).unwrap();

            let job = super::job(&id).unwrap();
            assert_ne!(job.outcome, pb::JobOutcome::Cancelled as i32);
        });
    }

    /// **The registry IS the answer to "can this be stopped".** A run that
    /// registered nothing must refuse rather than accept a cancel that reaches
    /// no work — an install answering "stopping…" and carrying on is worse
    /// than an install saying it cannot be stopped.
    #[test]
    fn only_a_run_that_registered_a_switch_can_be_stopped() {
        with_dir("switches", || {
            let journal = Some(Journal::open(pb::JobKind::ModelPull, "llama3.2:3b").unwrap());
            let id = crate::jobs::id_of(&journal);
            assert!(!ask_to_stop(&id), "a run with no switch accepted a cancel");

            let switch = cancellable(&journal).unwrap();
            assert!(!switch.asked());
            assert!(ask_to_stop(&id), "a registered run refused a cancel");
            assert!(switch.asked(), "the switch did not see the request");

            drop(switch);
            assert!(!ask_to_stop(&id), "a finished run still accepts a cancel");
        });
    }

    /// An install has no switch, so a cancel of one is a refusal and not a
    /// promise nothing keeps.
    #[test]
    fn a_run_of_a_kind_that_cannot_stop_is_refused() {
        with_dir("uncancellable", || {
            let journal = Journal::open(pb::JobKind::Install, "mailcow").unwrap();
            assert!(!ask_to_stop(journal.job_id()));
        });
    }

    /// The whole promise in one test: a run narrates, the client is gone, and
    /// what it said is still there afterwards — with the outcome.
    #[test]
    fn a_finished_run_reads_back_line_for_line() {
        with_dir("readback", || {
            let journal = Journal::open(pb::JobKind::Backup, "nextcloud").unwrap();
            let job = journal.job_id().to_string();
            for text in ["stopping", "archiving", "done"] {
                journal.append(pb::JobPhase::Progress, "agent", text);
            }
            journal.finish(None);

            let (events, closed, failure) = events_after(&job, 0).unwrap();
            assert_eq!(events.len(), 3);
            assert_eq!(events[1].text, "archiving");
            assert_eq!(events[1].sequence, 1, "sequences are dense and start at 0");
            assert_eq!(events[1].job_id, job);
            assert_eq!(events[1].kind, pb::JobKind::Backup as i32);
            assert_eq!(events[1].subject, "nextcloud");
            assert!(closed);
            assert!(failure.is_empty());
            let job = super::job(&job).unwrap();
            assert_eq!(job.outcome, pb::JobOutcome::Succeeded as i32);
            assert_eq!(job.kind, pb::JobKind::Backup as i32);
            assert_eq!(job.subject, "nextcloud");
        });
    }

    /// A client that kept the tail asks only for what it missed — the whole
    /// reason `from_sequence` exists rather than "send me everything".
    #[test]
    fn reattaching_asks_for_what_it_has_not_seen() {
        with_dir("resume", || {
            let journal = Journal::open(pb::JobKind::Update, "immich").unwrap();
            let job = journal.job_id().to_string();
            for text in ["a", "b", "c", "d"] {
                journal.append(pb::JobPhase::Progress, "agent", text);
            }
            let (events, closed, _) = events_after(&job, 2).unwrap();
            assert_eq!(events.iter().map(|e| e.text.as_str()).collect::<Vec<_>>(), ["c", "d"]);
            assert!(!closed, "an unfinished run is not closed");
            assert_eq!(super::job(&job).unwrap().outcome, pb::JobOutcome::Running as i32,
                       "a journal this process is holding is RUNNING, not abandoned");
        });
    }

    /// Failure is recorded as failure, with the words the stream's trailer
    /// carried — a returning client must not have to guess from the last line.
    #[test]
    fn a_failed_run_says_so_and_says_why() {
        with_dir("failed", || {
            let journal = Journal::open(pb::JobKind::ContainerUpdate, "immich-stack").unwrap();
            let job = journal.job_id().to_string();
            journal.append(pb::JobPhase::Progress, "stderr", "no space left on device");
            journal.finish(Some("the update failed and was rolled back"));

            let (_, closed, failure) = events_after(&job, 0).unwrap();
            assert!(closed);
            assert_eq!(failure, "the update failed and was rolled back");
            assert_eq!(super::job(&job).unwrap().outcome, pb::JobOutcome::Failed as i32);
        });
    }

    /// **A verb that said COMPLETED and then simply returned SUCCEEDED.**
    /// This is the ordinary path of all nine: none of them closes its journal
    /// on success, they just end — so if the drop guessed "outcome unknown"
    /// here, every successful backup on every host would read as a failure.
    #[test]
    fn a_run_that_completed_reads_back_as_a_success() {
        with_dir("completed", || {
            let job = {
                let journal = Journal::open(pb::JobKind::Backup, "nextcloud").unwrap();
                let id = journal.job_id().to_string();
                journal.append(pb::JobPhase::Progress, "agent", "archiving");
                journal.append(pb::JobPhase::Completed, "agent", "");
                id
            };
            let job = super::job(&job).unwrap();
            assert_eq!(job.outcome, pb::JobOutcome::Succeeded as i32);
            assert!(job.failure.is_empty());
        });
    }

    /// **A run that returns without saying how is still a run that ended.**
    /// Dropping the last handle closes the journal — otherwise an early return
    /// anywhere in nine verbs leaves a file that reads RUNNING for ever and a
    /// client that follows it for ever.
    #[test]
    fn dropping_the_handle_ends_the_run() {
        with_dir("dropped", || {
            let job = {
                let journal = Journal::open(pb::JobKind::Restore, "vaultwarden").unwrap();
                let id = journal.job_id().to_string();
                journal.append(pb::JobPhase::Progress, "agent", "unpacking");
                id
            };
            let job = super::job(&job).unwrap();
            assert_eq!(job.outcome, pb::JobOutcome::Failed as i32,
                       "an outcome nobody reported is not a success");
            assert!(!job.failure.is_empty(), "and it says that much out loud");
            assert!(!is_running(&job.job_id), "nor is it still running");
        });
    }

    /// The listing is the answer for a client with no id of its own: newest
    /// first, filterable by kind, and by "what is going right now".
    #[test]
    fn the_listing_answers_by_kind_and_by_what_is_still_going() {
        with_dir("listing", || {
            let done = Journal::open(pb::JobKind::Backup, "nextcloud").unwrap();
            done.append(pb::JobPhase::Progress, "agent", "x");
            done.finish(None);
            let going = Journal::open(pb::JobKind::Update, "immich").unwrap();
            going.append(pb::JobPhase::Progress, "agent", "y");

            let all = list(pb::JobKind::Unspecified, false);
            assert_eq!(all.len(), 2, "every kind, because a returning client does not know");
            let updates = list(pb::JobKind::Update, false);
            assert_eq!(updates.len(), 1);
            assert_eq!(updates[0].subject, "immich");
            let running = list(pb::JobKind::Unspecified, true);
            assert_eq!(running.len(), 1, "only the one nobody has closed");
            assert_eq!(running[0].job_id, going.job_id());
            // Both halves stated, so a filter that returned everything or
            // nothing could not pass either assertion.
            assert!(list(pb::JobKind::Backup, true).is_empty());
        });
    }

    /// **A `job_id` shaped like a path must never reach the filesystem at
    /// all**, not just fail to resolve — `WatchJob`/`CancelJob` are reachable
    /// unauthenticated under the default session policy (`api.rs::
    /// session_refusal` on `never`). Plants the file a `..` escape would read
    /// OUTSIDE the journal directory and confirms both RPCs answer NOT_FOUND
    /// without it, exactly as they do for an id that is merely unknown. See
    /// the 2026-09-13 security audit, finding F7.
    #[tokio::test]
    async fn a_path_shaped_job_id_is_rejected_before_it_reaches_the_filesystem() {
        let _guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-jobs-traversal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var(STATE_DIR_ENV, &dir);
        running_guard().clear();
        // The secret a `../` traversal would reach: a sibling of `dir`, one
        // level up from where `journal_dir()`/`legacy_install_dir()` look.
        let secret = dir.parent().unwrap().join("gryonixnexusd-jobs-traversal-secret.jsonl");
        fs::write(&secret, r#"{"kind":"meta","job":"secret","service":"root-only","started":1}"#).unwrap();
        let traversal_id = format!("../{}", secret.file_stem().unwrap().to_str().unwrap());

        let watch =
            run_watch_job(Codec::Json, pb::WatchJobRequest { job_id: traversal_id.clone(), from_sequence: 0 }).await;
        assert_eq!(watch.status(), StatusCode::NOT_FOUND);

        let cancel = run_cancel_job(Codec::Json, pb::CancelJobRequest { job_id: traversal_id }).await;
        assert_eq!(cancel.status(), StatusCode::NOT_FOUND);

        let _ = fs::remove_file(&secret);
        std::env::remove_var(STATE_DIR_ENV);
        let _ = fs::remove_dir_all(&dir);
    }

    /// **The install slice's own journals are in this listing too.** They live
    /// in another directory, were written before kinds existed, and name their
    /// subject `service` — a client that had to ask a second verb for them
    /// would only know to do that on hosts old enough to need it.
    #[test]
    fn installs_written_by_the_older_slice_are_listed_as_installs() {
        with_dir("legacy", || {
            let dir = legacy_install_dir();
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("legacy-job.jsonl");
            let mut file = fs::File::create(&path).unwrap();
            writeln!(file, r#"{{"kind":"meta","job":"legacy-job","service":"adguard","started":10}}"#).unwrap();
            writeln!(file, r#"{{"kind":"event","seq":0,"phase":2,"stream":"agent","text":"pulling"}}"#).unwrap();
            writeln!(file, r#"{{"kind":"end","finished":20,"failure":""}}"#).unwrap();

            let jobs = list(pb::JobKind::Unspecified, false);
            assert_eq!(jobs.len(), 1);
            assert_eq!(jobs[0].kind, pb::JobKind::Install as i32);
            assert_eq!(jobs[0].subject, "adguard");
            assert_eq!(jobs[0].outcome, pb::JobOutcome::Succeeded as i32);
            let (events, closed, _) = events_after("legacy-job", 0).unwrap();
            assert_eq!(events[0].text, "pulling");
            assert!(closed);
        });
    }

    /// **What this module lists, the install slice actually wrote.**
    ///
    /// Moved here 2026-09-04 with the listing itself. The two halves are worth
    /// keeping joined: the writer is `install::journal::Journal`, the reader is
    /// this module, and a fixture written by hand would only prove that this
    /// module can read what this module's test authored — the mistake GOTCHAS
    /// records about fixtures that repeat the product.
    #[test]
    fn runs_the_install_slice_wrote_are_listed_and_each_names_its_service() {
        with_dir("install-writer", || {
            let first = crate::install::journal::Journal::open("adguard").unwrap();
            first.append(0, 2, "agent", "one", "adguard");
            first.finish(None);
            let second = crate::install::journal::Journal::open("pihole").unwrap();
            second.append(0, 2, "agent", "two", "pihole");
            second.finish(None);

            let jobs = list(pb::JobKind::Unspecified, false);
            assert_eq!(jobs.len(), 2);
            // Both were opened in the same second, so what matters here is that
            // both are present and each names its own subject.
            let subjects: Vec<&str> = jobs.iter().map(|j| j.subject.as_str()).collect();
            assert!(subjects.contains(&"adguard"));
            assert!(subjects.contains(&"pihole"));
            assert!(jobs.iter().all(|j| j.events == 1));
            assert!(jobs.iter().all(|j| j.kind == pb::JobKind::Install as i32));
        });
    }

    /// **An install journal with no ending reads RUNNING while the install
    /// slice holds it and ABANDONED once it does not.**
    ///
    /// Moved here 2026-09-04 from `install::journal`, which used to answer this
    /// for its own verb and no longer has one. That makes this the only test of
    /// the second half of [`outcome_of`]'s running check — the one that asks
    /// the install slice rather than this module's own map — and without it a
    /// daemon restart mid-install would report the run as still going forever.
    #[test]
    fn an_unfinished_install_is_abandoned_once_nothing_is_holding_it() {
        with_dir("legacy-abandoned", || {
            let dir = legacy_install_dir();
            fs::create_dir_all(&dir).unwrap();
            let mut file = fs::File::create(dir.join("stuck.jsonl")).unwrap();
            writeln!(file, r#"{{"kind":"meta","job":"stuck","service":"forgejo","started":10}}"#).unwrap();
            writeln!(file, r#"{{"kind":"event","seq":0,"phase":1,"stream":"agent","text":"started"}}"#).unwrap();
            drop(file);

            crate::install::journal::hold_for_test("stuck", "forgejo");
            let held = list(pb::JobKind::Unspecified, false);
            assert_eq!(held.len(), 1);
            assert_eq!(held[0].outcome, pb::JobOutcome::Running as i32);

            // What a daemon restart looks like: the file still has no closing
            // line, and nothing is writing to it any more.
            crate::install::journal::release_all_for_test();
            let dropped = list(pb::JobKind::Unspecified, false);
            assert_eq!(
                dropped[0].outcome,
                pb::JobOutcome::Abandoned as i32,
                "an unfinished journal no process is writing to must not read as still running"
            );
        });
    }

    /// The four phases a client renders, mapped from the phase every one of
    /// these verbs already speaks. Both ends stated, and the unknown case
    /// pinned as PROGRESS: a line from a newer agent is still a line.
    #[test]
    fn phases_map_to_what_the_verbs_already_say() {
        assert_eq!(phase_of(pb::ServiceOperationPhase::Started as i32), pb::JobPhase::Started);
        assert_eq!(phase_of(pb::ServiceOperationPhase::Progress as i32), pb::JobPhase::Progress);
        assert_eq!(phase_of(pb::ServiceOperationPhase::Completed as i32), pb::JobPhase::Completed);
        assert_eq!(phase_of(99), pb::JobPhase::Progress);
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn same_subject_is_exclusive_and_release_allows_retry() {
        let first = OperationClaim::acquire("service", "admission-exclusive").ok().unwrap();
        assert!(OperationClaim::acquire("service", "admission-exclusive").is_err());
        assert!(OperationClaim::acquire("service", "admission-other").is_ok());
        drop(first);
        assert!(OperationClaim::acquire("service", "admission-exclusive").is_ok());
    }

    #[test]
    fn simultaneous_requests_admit_exactly_one() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8).map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let claim = OperationClaim::acquire("service", "admission-race");
                barrier.wait();
                claim.is_ok()
            })
        }).collect();
        assert_eq!(threads.into_iter().map(|t| t.join().unwrap() as usize).sum::<usize>(), 1);
    }

    #[tokio::test]
    async fn backup_refuses_before_starting_a_second_stream() {
        let _claim = OperationClaim::acquire("service", "admission-rpc").ok().unwrap();
        let response = crate::backup::run_backup(Codec::Json,
            pb::RunBackupRequest { service_id: "admission-rpc".into(), ..Default::default() }).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response = crate::update::run_update(Codec::Json,
            pb::RunUpdateRequest { service_id: "admission-rpc".into(), ..Default::default() }).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn aborting_task_releases_its_reservation() {
        let claim = OperationClaim::acquire("service", "admission-abort").ok().unwrap();
        let task = tokio::spawn(async move {
            let _claim = claim;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        assert!(OperationClaim::acquire("service", "admission-abort").is_ok());
    }
}
