//! The record an install leaves behind, so the phone does not have to stay.
//!
//! **The work was never owned by the stream.** `execute::run_install` decides
//! everything it can refuse BEFORE the response opens (id, licence, reverse
//! proxy, ports), then `tokio::spawn`s the run into the daemon and hands the
//! caller a receiver. Every one of the 219 places that narrate a step writes
//! `let _ = sink.step(...)` — a send that fails because nobody is listening has
//! never been a reason to stop. So an install has always survived the client
//! hanging up; what it could not survive was being ASKED ABOUT afterwards.
//! There was no name for the run and no trace of it, so a client that closed
//! had exactly two options: watch a screen for fifteen minutes, or find out by
//! guessing from `GetState` whether the thing appeared.
//!
//! This module is that missing half. Each run gets an id and an append-only
//! journal under the agent's own state directory; `WatchInstall` replays it and
//! then follows it, and `ListJobs` — which reads this slice's journals along
//! with every other verb's — says what this host has run. There was an
//! install-only listing here too; it went 2026-09-04, because `Job` carries
//! every field `InstallJob` carried.
//!
//! **`/var/lib/gryonixnexus/agent` needs no unit change, and that is the point.**
//! GOTCHAS.md's rule about `ReadWritePaths` is that a path listed there which
//! does not exist on disk kills the agent outright (226/NAMESPACE, and
//! `Restart=always` turns it into a start loop). The unit already gives us
//! `StateDirectory=gryonixnexus/agent` at 0700 — the directory `state.db` lives
//! in — so a subdirectory of it is writable by construction and adds no entry
//! to the accumulating exception list. Anything else under `/etc` or `/var`
//! would have been a new claim that a directory exists.
//!
//! **What is NOT stored: the `Service` snapshot.** The COMPLETED event carries
//! the service as re-read after the install, and serialising a prost message
//! into this file would freeze a status that is only interesting when fresh. A
//! watcher re-reads it live instead, which is the same "render what the server
//! reports, never what a stored value implies" rule the rest of the crate
//! holds.
//!
//! **Secrets never reach this file, for the same reason nothing else logs
//! them.** The journal holds exactly what the stream held — the agent's own
//! narration and child-process output — and the executors already keep
//! passwords out of both (stdin, never argv; see the docker-mailserver notes).
//! A journal that recorded MORE than the stream would be a new place for a
//! password to sit at 0600 for ever.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pb;

/// Same seam `main.rs` reads, so a test can point the journal somewhere
/// harmless without a state directory or root.
const STATE_DIR_ENV: &str = "GRYONIXNEXUSD_STATE_DIR";
const STATE_DIR_FALLBACK: &str = "/var/lib/gryonixnexus/agent";

/// How many runs are kept. An install journal is a few hundred kilobytes at
/// worst (mailcow narrates twenty image pulls), and the client only ever asks
/// about the last one or two — but a host that installs a service a week for a
/// year should not accumulate them for ever.
const KEEP_JOBS: usize = 40;

/// How often a follower looks for new lines while a run is still going. Steps
/// arrive seconds apart at best (docker pulls, container health waits), so
/// polling costs nothing next to the work being narrated, and it avoids a
/// filesystem-notification dependency for a file we already know the name of.
const FOLLOW_POLL: Duration = Duration::from_millis(250);

fn journal_dir() -> PathBuf {
    let base = std::env::var(STATE_DIR_ENV).unwrap_or_else(|_| STATE_DIR_FALLBACK.to_string());
    PathBuf::from(base).join("installs")
}

fn path_for(job_id: &str) -> PathBuf {
    journal_dir().join(format!("{job_id}.jsonl"))
}

/// Jobs this daemon process is running right now, job id → service id.
///
/// **The authority for RUNNING within one lifetime, and the reason ABANDONED
/// can be told apart from it.** A journal with no closing line means one of two
/// very different things: the work is still going, or the daemon died holding
/// it. Nothing in the file can distinguish them — so the answer comes from
/// here for this process, and from [`sweep_abandoned`] for everything older.
fn running() -> &'static Mutex<HashMap<String, String>> {
    static RUNNING: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    RUNNING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// **Poisoning is not an error here, and treating it as one costs more than
/// the thing it guards.** A panic inside a spawned install would poison this
/// lock, and every `lock().unwrap()` afterwards would panic too — so one failed
/// install would take out `ListJobs`, `WatchInstall` and the next
/// install with it. The map is a set of names, not an invariant that can be
/// half-updated, so the honest recovery is to keep using it. Found by this
/// module's own negative control: a single deliberate defect failed all seven
/// tests, six of them for this reason rather than their own.
fn running_guard() -> std::sync::MutexGuard<'static, HashMap<String, String>> {
    running().lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// An id that is unique on this host without pulling in a uuid crate: the
/// start time in seconds, the process id, and a counter that makes two runs
/// started in the same second by the same daemon distinct.
fn mint_job_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}-{:x}", now_unix(), std::process::id(), n)
}

/// One line of the file. `kind` discriminates so a reader never has to guess
/// what a line meant: "meta" opens the journal, "event" is one narrated line,
/// "end" closes it.
fn write_line(path: &PathBuf, line: &serde_json::Value) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")
}

/// The handle a running install writes through.
pub struct Journal {
    job_id: String,
    service_id: String,
    path: PathBuf,
}

impl Journal {
    /// Open a journal for a run that is about to start. Failing to create it is
    /// NOT fatal to the install: the run is the product, the record is how you
    /// ask about it later, and refusing to install because a log file could not
    /// be opened would trade the whole thing for the report of it. A `None`
    /// journal simply means this run cannot be reattached to.
    pub fn open(service_id: &str) -> Option<Journal> {
        let dir = journal_dir();
        if let Err(err) = fs::create_dir_all(&dir) {
            tracing::warn!("install journal unavailable ({err}); this run cannot be reattached to");
            return None;
        }
        let job_id = mint_job_id();
        let path = path_for(&job_id);
        let meta = serde_json::json!({
            "kind": "meta",
            "job": job_id,
            "service": service_id,
            "started": now_unix(),
        });
        if let Err(err) = write_line(&path, &meta) {
            tracing::warn!("install journal unavailable ({err}); this run cannot be reattached to");
            return None;
        }
        running_guard()
            .insert(job_id.clone(), service_id.to_string());
        prune(&dir);
        Some(Journal {
            job_id,
            service_id: service_id.to_string(),
            path,
        })
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Record one narrated line. Never fails loudly: a full disk must not turn
    /// a working install into a failed one.
    pub fn append(&self, sequence: u64, phase: i32, stream: &str, text: &str, project: &str) {
        let line = serde_json::json!({
            "kind": "event",
            "seq": sequence,
            "phase": phase,
            "stream": stream,
            "text": text,
            "project": project,
        });
        if let Err(err) = write_line(&self.path, &line) {
            tracing::warn!("could not append to the install journal: {err}");
        }
    }

    /// Close the journal. After this the run reads back as SUCCEEDED or FAILED
    /// rather than RUNNING, which is what lets a returning client stop
    /// following.
    pub fn finish(&self, failure: Option<&str>) {
        let line = serde_json::json!({
            "kind": "end",
            "finished": now_unix(),
            "failure": failure.unwrap_or(""),
        });
        if let Err(err) = write_line(&self.path, &line) {
            tracing::warn!("could not close the install journal: {err}");
        }
        running_guard().remove(&self.job_id);
        let _ = &self.service_id;
    }
}

/// Drop the oldest journals once there are more than [`KEEP_JOBS`], newest
/// kept. Best effort in every direction: an unreadable directory simply keeps
/// what is there.
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
    service_id: String,
    started: i64,
    finished: i64,
    failure: String,
    closed: bool,
    events: Vec<pb::InstallServiceEvent>,
}

fn parse(job_id: &str) -> Option<Parsed> {
    let file = File::open(path_for(job_id)).ok()?;
    let mut parsed = Parsed {
        job_id: job_id.to_string(),
        service_id: String::new(),
        started: 0,
        finished: 0,
        failure: String::new(),
        closed: false,
        events: Vec::new(),
    };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            // A torn last line is what a journal looks like when the daemon
            // died mid-write. Everything before it is still true, so the run is
            // reported from what parsed rather than thrown away.
            continue;
        };
        match value.get("kind").and_then(|k| k.as_str()) {
            Some("meta") => {
                parsed.service_id = value
                    .get("service")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                parsed.started = value.get("started").and_then(|v| v.as_i64()).unwrap_or(0);
            }
            Some("event") => parsed.events.push(pb::InstallServiceEvent {
                phase: value.get("phase").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                service_id: parsed.service_id.clone(),
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
                project: value
                    .get("project")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                service: None,
                job_id: job_id.to_string(),
                sequence: value.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
            }),
            Some("end") => {
                parsed.closed = true;
                parsed.finished = value.get("finished").and_then(|v| v.as_i64()).unwrap_or(0);
                parsed.failure = value
                    .get("failure")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
            }
            _ => {}
        }
    }
    if parsed.service_id.is_empty() && parsed.events.is_empty() {
        return None;
    }
    Some(parsed)
}

fn job_ids() -> Vec<String> {
    let Ok(entries) = fs::read_dir(journal_dir()) else {
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

/// Does this host have a record of that run at all?
///
/// **All that is left of this module's own listing.** It used to build
/// `InstallJob`s and rank them by outcome for an install-only verb; that verb
/// is gone (owner, 2026-09-04) and `crate::jobs` answers the same question for
/// every kind of run, reading THIS directory among its own. Two implementations
/// of "what did that run end as" was the drift, not the saving — so what stays
/// here is the one thing the follower actually needs: whether there is a file
/// to follow.
pub fn exists(job_id: &str) -> bool {
    parse(job_id).is_some()
}

/// The events of a job strictly after `from_sequence`, plus whether the run has
/// ended and with what.
pub fn events_after(job_id: &str, from_sequence: u64) -> Option<(Vec<pb::InstallServiceEvent>, bool, String)> {
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

/// Is a run of this service going right now, and under what id? The guard that
/// keeps a second tap on "Install" from starting a second install of the same
/// thing — which became possible to ask only once runs had names.
pub fn running_job_for(service_id: &str) -> Option<String> {
    running_guard()
        .iter()
        .find(|(_, service)| service.as_str() == service_id)
        .map(|(job, _)| job.clone())
}

pub fn is_running(job_id: &str) -> bool {
    running_guard().contains_key(job_id)
}

/// Pretend this process is holding a run — **for tests in OTHER modules.**
///
/// `crate::jobs` decides RUNNING against ABANDONED for install journals by
/// asking [`is_running`], and since that verb moved there its test has to be
/// able to set the answer. Test-only on purpose: production code takes a hold
/// by OPENING a journal, never by naming one, and a public setter would be a
/// second way to claim a run.
///
/// Safe to call from another module's test only because both take the crate's
/// `STATE_DIR_ENV_LOCK` around their bodies — this map is process-wide.
#[cfg(test)]
pub(crate) fn hold_for_test(job_id: &str, service_id: &str) {
    running_guard().insert(job_id.to_string(), service_id.to_string());
}

/// Drop every hold — the other half of [`hold_for_test`], and what a daemon
/// restart looks like from the outside.
#[cfg(test)]
pub(crate) fn release_all_for_test() {
    running_guard().clear();
}

/// How long a follower should wait before looking for more.
pub fn follow_poll() -> Duration {
    FOLLOW_POLL
}

/// Called once at startup. Nothing this daemon did not start is running, so
/// every open journal on disk belongs to a previous life and is ABANDONED —
/// which `crate::jobs` already concludes from an empty running set, by asking
/// [`is_running`]. This exists to say so out loud in the log, because a host
/// that reboots mid-install otherwise looks like a host where an install is
/// still going.
pub fn sweep_abandoned() {
    let abandoned: Vec<String> = job_ids()
        .iter()
        .filter_map(|id| parse(id))
        .filter(|parsed| !parsed.closed)
        .map(|parsed| format!("{} ({})", parsed.job_id, parsed.service_id))
        .collect();
    if !abandoned.is_empty() {
        tracing::warn!(
            "install runs left unfinished by a previous agent process: {}",
            abandoned.join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test in this module points the journal at its own directory, and
    /// the env var is process-wide — so they take one lock, the same
    /// discipline GOTCHAS.md's note about shared env vars demands.
    fn with_dir<T>(name: &str, body: impl FnOnce() -> T) -> T {
        // **The crate's lock, not this module's own.** `GRYONIXNEXUSD_STATE_DIR`
        // is process-wide and `jobs` now redirects it too; two modules each
        // holding their own lock are internally consistent and mutually
        // destructive, which is the exact failure GOTCHAS records about shared
        // env vars. Poison-tolerant for the same reason as `running_guard`: one
        // failing test must not fail the others for a reason that is not theirs.
        let _guard = crate::util::STATE_DIR_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-journal-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var(STATE_DIR_ENV, &dir);
        running_guard().clear();
        let out = body();
        std::env::remove_var(STATE_DIR_ENV);
        let _ = fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn a_finished_run_reads_back_line_for_line() {
        with_dir("readback", || {
            let journal = Journal::open("adguard").unwrap();
            let job = journal.job_id().to_string();
            for (i, text) in ["pulling", "starting", "up"].iter().enumerate() {
                journal.append(i as u64, 2, "agent", text, "adguard");
            }
            journal.finish(None);

            let (events, closed, failure) = events_after(&job, 0).unwrap();
            assert_eq!(events.len(), 3);
            assert_eq!(events[1].text, "starting");
            assert_eq!(events[1].sequence, 1);
            assert_eq!(events[1].job_id, job);
            assert!(closed);
            assert!(failure.is_empty());
            assert!(exists(&job));
            assert!(!exists("no-such-run"), "and a run this host never had is not one");
        });
    }

    #[test]
    fn reattaching_asks_for_what_it_has_not_seen() {
        with_dir("resume", || {
            let journal = Journal::open("nextcloud").unwrap();
            let job = journal.job_id().to_string();
            for i in 0..5u64 {
                journal.append(i, 2, "stdout", &format!("line {i}"), "nextcloud");
            }
            journal.finish(None);

            // A client that saw through sequence 2 asks for 3 onward, and gets
            // exactly the two it is missing — no gap, no repeat.
            let (events, _, _) = events_after(&job, 3).unwrap();
            assert_eq!(events.len(), 2);
            assert_eq!(events[0].text, "line 3");
            assert_eq!(events[1].text, "line 4");
        });
    }

    /// **Running against abandoned is asserted in `crate::jobs`**, which is
    /// the module that now answers it — for install journals along with every
    /// other kind. What is left here is the half only this module owns: the
    /// guard that says a run of this service is going right now.
    #[test]
    fn a_failed_run_carries_its_reason() {
        with_dir("failed", || {
            let journal = Journal::open("mailcow").unwrap();
            let job = journal.job_id().to_string();
            journal.append(0, 2, "stderr", "port 25 is taken", "mailcowdockerized");
            journal.finish(Some("port 25 is taken"));

            let (_, closed, failure) = events_after(&job, 0).unwrap();
            assert!(closed);
            assert_eq!(failure, "port 25 is taken");
        });
    }

    #[test]
    fn a_second_install_of_the_same_service_can_be_seen_coming() {
        with_dir("guard", || {
            let journal = Journal::open("jellyfin").unwrap();
            assert_eq!(
                running_job_for("jellyfin").as_deref(),
                Some(journal.job_id())
            );
            assert_eq!(running_job_for("adguard"), None);
            journal.finish(None);
            assert_eq!(
                running_job_for("jellyfin"),
                None,
                "a finished run must not keep refusing the next one"
            );
        });
    }

    #[test]
    fn a_torn_final_line_does_not_lose_the_run() {
        with_dir("torn", || {
            let journal = Journal::open("seafile").unwrap();
            let job = journal.job_id().to_string();
            journal.append(0, 2, "agent", "creating directories", "seafile");
            // What a killed daemon leaves: half a line, no newline, no ending.
            let mut file = OpenOptions::new().append(true).open(path_for(&job)).unwrap();
            file.write_all(b"{\"kind\":\"eve").unwrap();
            drop(file);

            let (events, closed, _) = events_after(&job, 0).unwrap();
            assert_eq!(events.len(), 1, "the intact lines before the tear still count");
            assert!(!closed);
        });
    }
}
