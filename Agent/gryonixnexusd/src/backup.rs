//! Backups behind the API: what exists, what a run would cost, running one,
//! deleting one.
//!
//! **This module CALLS the deployment's root-owned wrapper; it does not
//! reimplement backing up.** The wrapper (`/opt/gryonixnexus-backup-ctl.sh`) is
//! generated from each service's `BackupSpec`, and it is the very body the
//! systemd timer runs — one body, two callers, which is the drift this project
//! already paid to end once. Everything expensive lives in there: a tar of a
//! live database directory is a corrupt backup, so each database is dumped
//! through its own client from INSIDE its own container (the password is read
//! from the container's own environment, because `docker exec` argv is
//! world-readable through /proc); mailcow runs its own tool, which names and
//! rotates its archives itself; containers are started again on every exit path.
//! Rewriting that here would make a third implementation of the most expensive
//! logic in the product, and the copies would drift in silence.
//!
//! What the agent adds is the CONTRACT, not the engine:
//!
//! * the client sends a catalog id and a verb — never a command line, never a
//!   path it chose;
//! * the argument vector is built from the agent's own tables and the wrapper's
//!   own labels, and there is NO SHELL on this path at all (the wrapper is
//!   spawned directly), so quoting cannot go wrong in the first place;
//! * the passphrase goes to the wrapper's STDIN, never argv;
//! * the listing comes back as typed rows instead of `ls -lht` text the client
//!   has to parse — that parser already lost a file whose name contained two
//!   spaces;
//! * `sudo` is out of the picture, so the whole "sudoers on the server is older
//!   than the app" failure class does not exist on this route.
//!
//! The one thing the agent must learn from the host is WHERE a service's
//! archives live. It cannot be a constant here: the backup root is a
//! per-deployment setting (`/opt/backups` by default, but editable), so a
//! constant would be wrong for exactly the deployments that changed it. It must
//! not come from the client either: this code is root, so a client-supplied
//! directory is a "list any directory on the box" primitive. So it is read from
//! the wrapper the setup generated ON THIS HOST — the same rule the mailbox
//! slice follows when it takes docker-mailserver's config directory from the
//! container's bind mount rather than from a `ServiceContext` the agent does
//! not have.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hyper::StatusCode;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::util::strip_ansi;
use crate::{discover, pb};

/// The wrapper every backup goes through. Must stay byte-identical to
/// `BackupWrapperSpec.wrapperPath` (ServiceCatalog) and
/// `BackupControlSections.scriptPath` (MailRecipe) — the modules deliberately do
/// not depend on each other, so all sides pin the literal.
const WRAPPER_PATH: &str = "/opt/gryonixnexus-backup-ctl.sh";

/// Printed by a finished archive: `<marker> <bytes> <path>`. The wrapper prints
/// it because a STREAMED SSH command carries no exit status back, so the app had
/// to be told in-band. The agent has the real exit status of the child, so it
/// does not need the marker as proof — but it is still the only place the
/// archive's PATH is announced, which is what the UI offers to share.
const BACKUP_DONE_MARKER: &str = "GRYONIXNEXUS_BACKUP_DONE";

/// Printed by `estimate`: `<marker> <data bytes> <free bytes>`.
const ESTIMATE_MARKER: &str = "GRYONIXNEXUS_BACKUP_ESTIMATE";

/// Upload staging lives inside the backup directory; it is not a backup and must
/// not masquerade as one in a picker. Matches `CommandCatalog.Restore
/// .stagingDirectoryName`.
const STAGING_DIRECTORY: &str = "incoming";

/// The VPN protocols share one panel and one backup target. The agent's
/// aggregate id is `vpn`; the wrapper's label is the panel's catalog id, because
/// that is the service whose `BackupSpec` generated the arm.
const VPN_WRAPPER_TARGET: &str = "vpn-panel";

/// Deadline for one wrapper call that does real work. Deliberately the SAME
/// number as the app's `long` timeout class (600s), which is what the SSH route
/// already gives a backup: a route that waits longer would turn "this server
/// cannot finish a backup in ten minutes" into "it works over the agent and not
/// over SSH", and the truth would be neither.
const RUN_TIMEOUT_SECS: u64 = 600;

/// Deadline for the read-only/bookkeeping calls (estimate, delete). `estimate`
/// walks the data with `du`, so it is not instant on a photo library.
const QUICK_TIMEOUT_SECS: u64 = 120;

/// Client strings are echoed back so a mistake is diagnosable, but only a
/// bounded prefix: the message travels into logs and UI.
const ECHO_LIMIT: usize = 96;

/// Why a backup request was refused BEFORE anything on the host was touched.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Not a service in the agent's catalog — the same gate management uses.
    UnknownService(String),
    /// This host has no backup wrapper at all: an adopted server, or one set up
    /// before backups existed. NOT a defect of this route — the SSH route calls
    /// the same missing file — so it says what to do about it.
    NoWrapper,
    /// The wrapper exists but has no arm for this service. The wrapper is
    /// GENERATED from the services this deployment installed, so a service that
    /// was never part of it (or was removed) has no entry — and an entry cannot
    /// be invented, because inventing one means guessing a directory to list and
    /// to delete out of.
    NotBackedUp(String),
    /// A delete path that is not inside this service's own backup directory.
    PathOutsideBackupDirectory(String),
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::UnknownService(id) => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                format!("unknown service '{}'", truncate(id)),
            ),
            // failed_precondition, not not_found: the request is well formed and
            // the service may well be installed — what is missing is the host's
            // backup wrapper, and re-running setup installs it.
            Rejection::NoWrapper => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "this server has no backup wrapper ({WRAPPER_PATH}) — re-run the setup script to install it"
                ),
            ),
            Rejection::NotBackedUp(id) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "the backup wrapper on this server has no entry for '{}'",
                    truncate(id)
                ),
            ),
            Rejection::PathOutsideBackupDirectory(path) => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                format!("'{}' is not inside this service's backup directory", truncate(path)),
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
    PathBuf::from(std::env::var("GRYONIXNEXUSD_BACKUP_WRAPPER").unwrap_or_else(|_| WRAPPER_PATH.to_string()))
}

/// Where the wrapper's own schedule config lives — world-readable, no sudo
/// needed to read it, matching `AutoBackupOperations.readSchedule` (Swift)
/// and `update::config_path` (this crate's own precedent for the same shape).
const CONFIG_PATH: &str = "/etc/gryonixnexus/autobackup.conf";

fn config_path() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_BACKUP_CONFIG").unwrap_or_else(|_| CONFIG_PATH.to_string()))
}

/// A HOME the wrapper's children can actually write to, created on demand.
///
/// The unit hardens the agent with `ProtectHome=true`, which replaces `/root`
/// with an empty read-only mount inside the agent's namespace — while `HOME`
/// still says `/root`. Every child inherits that, and `gpg` is the one that
/// notices: `--symmetric` wants `$HOME/.gnupg` and dies with
///
///   gpg: Fatal: can't create directory '/root/.gnupg': Read-only file system
///
/// That is EVERY ENCRYPTED backup — the default for the password store, the mail
/// stack and the VPN panel — failing on the agent route, while the very same
/// wrapper succeeds over SSH because `sudo` hands it a real home. Found on the
/// first live run of this slice (2026-08-07); no test that stubs the wrapper can
/// reach it, because the sandbox belongs to the unit and not to the code.
///
/// The fix belongs here rather than in the unit (the hardening is deliberate and
/// unrelated to backups) or in the wrapper (it is GENERATED, so a fix there
/// reaches a server only when its setup is re-run — an agent fix ships with the
/// binary). What the agent owes the wrapper is the environment its other two
/// callers already give it: a writable home.
///
/// It lives under the agent's own state directory — root-only 0700, guaranteed
/// writable by `StateDirectory=`, and persistent, so gpg's `random_seed` is not
/// rebuilt on every run.
pub(crate) fn wrapper_home() -> PathBuf {
    let state = std::env::var("GRYONIXNEXUSD_STATE_DIR")
        .or_else(|_| std::env::var("STATE_DIRECTORY"))
        .unwrap_or_else(|_| AGENT_STATE_DIR.to_string());
    let home = PathBuf::from(state).join("wrapper-home");
    // Best effort: a home that cannot be made is no worse than the inherited
    // one, and the wrapper's own error stays the explanation either way.
    let _ = std::fs::create_dir_all(home.join(".gnupg"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // gpg refuses to use a home other accounts can read, and says so in a
        // warning that would otherwise appear in every backup log.
        let _ = std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(home.join(".gnupg"), std::fs::Permissions::from_mode(0o700));
    }
    home
}

/// Mirrors `main.rs`'s `STATE_DIR`. The two are deliberately separate literals:
/// this module is reached in tests without `main`'s constants, and the path is
/// part of the unit's contract, not of this module's logic.
const AGENT_STATE_DIR: &str = "/var/lib/gryonixnexus/agent";

/// The wrapper's service label for a catalog id, as a `&'static str`.
///
/// Static on purpose: this is what goes into the wrapper's argv, so a client can
/// only pick one of the agent's own constants. It is also the same table
/// `discover` uses, so "a service the scan can see" and "a service backups
/// accept" cannot drift apart.
pub fn wrapper_target(service_id: &str) -> Option<&'static str> {
    if service_id == "vpn" {
        return Some(VPN_WRAPPER_TARGET);
    }
    discover::known_service_id(service_id)
}

/// Where one service's archives live, according to the wrapper generated on THIS
/// host, plus the label to call it with.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub label: &'static str,
    pub directory: PathBuf,
}

/// Parse the wrapper's own service table.
///
/// The generated `do_estimate` carries one arm per backup-capable service:
///
/// ```sh
///     nextcloud) dir='/opt/backups/nextcloud'; paths=('/opt/nextcloud/data') ;;
/// ```
///
/// That is the only place on the host that states where a given service's
/// archives go, and it is machine-written by the generator, not typed by a
/// person. If the generator ever changes the shape, this returns nothing for the
/// service and the RPC fails LOUDLY with `NotBackedUp` — it never falls back to
/// guessing a path, because a guessed path here is a root-owned listing or a
/// delete pointed at the wrong directory. The shape is pinned from the Swift
/// side too (`BackupWrapperContractTests`), against a really generated wrapper.
fn parse_directories(script: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for line in script.lines() {
        let line = line.trim();
        let Some((label, rest)) = line.split_once(')') else { continue };
        // Only a plain service label: the neighbouring arms of the same `case`
        // are globs (`*..*)`, `*)`), and a label is what the client's id maps to.
        if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            continue;
        }
        let Some(after) = rest.split_once("dir='") else { continue };
        let Some((dir, _)) = after.1.split_once('\'') else { continue };
        if dir.starts_with('/') {
            found.push((label.to_string(), dir.to_string()));
        }
    }
    found
}

/// Resolve a client id to the wrapper label and directory, or say exactly why
/// not. Nothing has been touched on the host when this returns an error.
pub fn resolve(service_id: &str) -> Result<Target, Rejection> {
    let Some(label) = wrapper_target(service_id) else {
        return Err(Rejection::UnknownService(service_id.to_string()));
    };
    let script = std::fs::read_to_string(wrapper_path()).map_err(|_| Rejection::NoWrapper)?;
    parse_directories(&script)
        .into_iter()
        .find(|(candidate, _)| candidate == label)
        .map(|(_, dir)| Target {
            label,
            directory: PathBuf::from(dir),
        })
        .ok_or_else(|| Rejection::NotBackedUp(label.to_string()))
}

// ─────────────────────────── Listing ───────────────────────────

/// Read one backup directory. A directory that does not exist yet is an EMPTY
/// listing, not an error: the wrapper creates it on the first run, and a server
/// that has never been backed up must show the app's empty state rather than a
/// red banner (the same call the history buckets make about a missing file).
pub fn read_directory(dir: &Path) -> std::io::Result<Vec<pb::BackupArchive>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut archives = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // The upload staging directory lives inside the backup directory. It is
        // where a file from the user's device lands, not a backup.
        if name == STAGING_DIRECTORY {
            continue;
        }
        // Neither is anything hidden, and that is not tidiness: the wrapper
        // builds every archive in a `.work-XXXXXX` directory it creates INSIDE
        // the backup directory (`mktemp -d '<dir>/.work-XXXXXX'`), so a listing
        // taken while a run is under way shows it, and a run that was killed
        // (deadline, a restarted agent, a reboot) leaves it behind for ever.
        // Either way it would appear as a backup, with a delete button and a
        // place in the restore picker, and the archive inside it is half
        // written. The SSH route never showed them because `ls -lht <dir>` does
        // not list dotfiles — reading the directory directly is what made them
        // visible, so the agent has to skip them explicitly or the two routes
        // disagree about what a backup is.
        if name.starts_with('.') {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        archives.push(pb::BackupArchive {
            name,
            path: entry.path().to_string_lossy().to_string(),
            // For a directory this is the inode's own size, exactly what
            // `ls -lh` showed the SSH route. Summing a mailcow backup directory
            // would mean walking tens of gigabytes on every listing refresh.
            size_bytes: meta.len() as i64,
            modified_at: modified,
            directory: meta.is_dir(),
        });
    }
    // Newest first — the order `ls -lht` gave the SSH route, and the order the
    // picker's "the last backup" depends on.
    archives.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));
    Ok(archives)
}

fn listing(service_id: &str, target: &Target) -> Result<pb::BackupList, std::io::Error> {
    Ok(pb::BackupList {
        service_id: service_id.to_string(),
        directory: target.directory.to_string_lossy().to_string(),
        archives: read_directory(&target.directory)?,
    })
}

pub fn list_backups(codec: Codec, req: pb::ListBackupsRequest) -> Resp {
    let target = match resolve(&req.service_id) {
        Ok(target) => target,
        Err(rejection) => return rejection.response(),
    };
    match listing(&req.service_id, &target) {
        Ok(list) => encode(codec, &list),
        // The directory exists but cannot be read: a real fault on the host, and
        // hiding it as "no backups yet" is how a broken backup setup stays
        // invisible until the day it is needed.
        Err(err) => connect_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            &format!("could not read {}: {err}", target.directory.display()),
        ),
    }
}

// ─────────────────────────── Estimate ───────────────────────────

/// `GRYONIXNEXUS_BACKUP_ESTIMATE <data bytes> <free bytes>` → the two numbers.
/// `None` when the marker is absent, which is what an older wrapper (one from
/// before `estimate` existed) answers.
fn parse_estimate(output: &str) -> Option<pb::BackupEstimate> {
    let line = output.lines().find(|line| line.trim_start().starts_with(ESTIMATE_MARKER))?;
    let mut fields = line.split_whitespace();
    fields.next()?; // the marker
    Some(pb::BackupEstimate {
        data_bytes: fields.next()?.parse().ok()?,
        free_bytes: fields.next()?.parse().ok()?,
    })
}

pub async fn estimate_backup(codec: Codec, req: pb::EstimateBackupRequest) -> Resp {
    let target = match resolve(&req.service_id) {
        Ok(target) => target,
        Err(rejection) => return rejection.response(),
    };
    let outcome = run_wrapper(&["estimate", target.label], None, QUICK_TIMEOUT_SECS).await;
    match outcome {
        Err(why) => wrapper_failed(&why),
        Ok(output) => match parse_estimate(&output.stdout) {
            Some(estimate) => encode(codec, &estimate),
            // Exit 0 and no marker means the wrapper on this host predates the
            // estimate subcommand. Saying so is better than an invented zero,
            // which the app would render as "0 bytes, plenty of room".
            None => connect_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                "the backup wrapper on this server does not report estimates — re-run the setup script",
            ),
        },
    }
}

// ─────────────────────────── Delete ───────────────────────────

/// The client's path must sit inside the directory THIS service resolved to.
/// The wrapper checks again against the directories baked into it, so this is
/// not the only gate — but it is the one that keeps one service's screen from
/// deleting another service's archives, which the wrapper cannot tell apart.
fn validate_delete_path(path: &str, dir: &Path) -> Result<(), Rejection> {
    let outside = || Rejection::PathOutsideBackupDirectory(path.to_string());
    if path.contains("..") {
        return Err(outside());
    }
    let prefix = format!("{}/", dir.to_string_lossy());
    let Some(rest) = path.strip_prefix(&prefix) else {
        return Err(outside());
    };
    // One level down only: the archives sit directly in the directory, and the
    // staging area is not a backup.
    if rest.is_empty() || rest.contains('/') || rest == STAGING_DIRECTORY {
        return Err(outside());
    }
    Ok(())
}

pub async fn delete_backup(codec: Codec, req: pb::DeleteBackupRequest) -> Resp {
    let target = match resolve(&req.service_id) {
        Ok(target) => target,
        Err(rejection) => return rejection.response(),
    };
    if let Err(rejection) = validate_delete_path(&req.path, &target.directory) {
        return rejection.response();
    }
    if let Err(why) = run_wrapper(&["delete", &req.path], None, QUICK_TIMEOUT_SECS).await {
        return wrapper_failed(&why);
    }
    // The answer is the re-read listing, never "it worked": the same rule the
    // mailbox verbs follow.
    match listing(&req.service_id, &target) {
        Ok(list) => encode(codec, &list),
        Err(err) => connect_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            &format!("could not read {}: {err}", target.directory.display()),
        ),
    }
}

// ─────────────────────────── Schedule ───────────────────────────

/// Reads the wrapper's own config file — `SCHEDULE=`/`RETENTION=`/`SERVICES=`,
/// same shape `AutoBackupOperations.parse` (Swift) reads. Missing or
/// unparsable reads as "off", matching that side: a host predating this
/// feature, or one whose config the app cannot see yet, is not an error.
fn read_backup_schedule() -> pb::BackupSchedulePolicy {
    let text = std::fs::read_to_string(config_path()).unwrap_or_default();
    let mut schedule = "off".to_string();
    let mut retention = 7i32;
    let mut services = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("SCHEDULE=") {
            let rest = rest.trim();
            if !rest.is_empty() {
                schedule = rest.to_string();
            }
        } else if let Some(rest) = line.strip_prefix("RETENTION=") {
            if let Ok(value) = rest.trim().parse::<i32>() {
                if value >= 1 {
                    retention = value;
                }
            }
        } else if let Some(rest) = line.strip_prefix("SERVICES=") {
            let rest = rest.trim();
            let unquoted = rest.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')).unwrap_or(rest);
            services = unquoted.split_whitespace().map(str::to_string).collect();
        }
    }
    pb::BackupSchedulePolicy { schedule, retention, services }
}

/// Read-only, sudo-free: the config file is world-readable, same reason
/// `update::get_update_policy` needs no wrapper call either.
pub async fn get_backup_schedule(codec: Codec, _req: pb::GetBackupScheduleRequest) -> Resp {
    encode(codec, &read_backup_schedule())
}

/// Set the schedule; answer with the policy RE-READ from disk, never the
/// request echoed back — the wrapper can drop services it does not manage,
/// exactly as `update::set_update_schedule` documents for its own schedule.
///
/// The passphrase (if any) is stored FIRST, as its own wrapper call: it is a
/// second stdin-carried secret with its own subcommand
/// (`set-passphrase`), not an argument to `set-schedule`, and a schedule
/// that fails must not leave a stored passphrase for a run that was never
/// armed to attribute the error to.
pub async fn set_backup_schedule(codec: Codec, req: pb::SetBackupScheduleRequest) -> Resp {
    if !wrapper_path().exists() {
        return Rejection::NoWrapper.response();
    }
    if !req.passphrase.is_empty() {
        if let Err(why) = run_wrapper(&["set-passphrase"], Some(&req.passphrase), QUICK_TIMEOUT_SECS).await {
            return wrapper_failed(&why);
        }
    }
    let retention = req.retention.max(1).to_string();
    let mut args: Vec<&str> = vec!["set-schedule", req.schedule.as_str(), retention.as_str()];
    for service in &req.services {
        args.push(service.as_str());
    }
    if let Err(why) = run_wrapper(&args, None, QUICK_TIMEOUT_SECS).await {
        return wrapper_failed(&why);
    }
    encode(codec, &read_backup_schedule())
}

// ─────────────────────────── Run ───────────────────────────

/// The wrapper's flag for the requested encryption, or `None` for "let the
/// wrapper apply the service's own default". Passing neither flag is how the
/// default stays in ONE place: the wrapper knows that a password store encrypts
/// and a photo library does not, and the agent has no business having a second
/// opinion.
fn encryption_flag(encryption: pb::BackupEncryption) -> Option<&'static str> {
    match encryption {
        pb::BackupEncryption::Unspecified => None,
        pb::BackupEncryption::Enabled => Some("--encrypt"),
        pb::BackupEncryption::Disabled => Some("--no-encrypt"),
    }
}

/// `GRYONIXNEXUS_BACKUP_DONE <bytes> <path>` → the archive that landed. The LAST
/// such line wins (a run announces one, but a re-run in the same output would
/// make the newest the truth).
fn parse_archive(output: &str) -> Option<pb::BackupArchive> {
    let line = output
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with(BACKUP_DONE_MARKER))?;
    let rest = line.trim_start().strip_prefix(BACKUP_DONE_MARKER)?.trim_start();
    // The path may contain spaces in principle, so only the size is split off
    // and the remainder is taken whole.
    let (size, path) = rest.split_once(' ')?;
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    Some(pb::BackupArchive {
        name: path.rsplit('/').next().unwrap_or(path).to_string(),
        path: path.to_string(),
        size_bytes: size.parse().unwrap_or(0),
        modified_at: now_millis(),
        directory: false,
    })
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Run one backup, streaming the wrapper's output.
///
/// Errors travel on two channels, exactly as they do for `ControlService`:
/// * a refusal BEFORE anything ran (unknown id, no wrapper, no arm for this
///   service) is a plain Connect error — nothing was touched, so no stream opens;
/// * a failure DURING the run ends the stream with an error trailer, but only
///   after a COMPLETED event carrying the re-read listing. "Did an archive
///   land?" is the first question after a failed backup, and an error alone does
///   not answer it — a run can fail in `gd_rotate` with the archive already on
///   disk, or fail before writing anything at all.
pub async fn run_backup(codec: Codec, req: pb::RunBackupRequest) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("service", &req.service_id) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let target = match resolve(&req.service_id) {
        Ok(target) => target,
        Err(rejection) => return rejection.response(),
    };
    let encryption = pb::BackupEncryption::try_from(req.encryption).unwrap_or(pb::BackupEncryption::Unspecified);

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let service_id = req.service_id.clone();
    let passphrase = req.passphrase.clone();

    tokio::spawn(async move {
        let _claim = claim;
        let sink = EventSink {
            tx,
            codec,
            service_id: service_id.clone(),
            journal: crate::jobs::Journal::open(pb::JobKind::Backup, &service_id),
        };
        let _ = sink.started(target.label).await;

        let mut args = vec!["backup", target.label];
        if let Some(flag) = encryption_flag(encryption) {
            args.push(flag);
        }
        // The client hanging up drops the receiver and every send fails, but the
        // wrapper already running is NOT cancelled: a half-made backup with the
        // service's containers still stopped is worse than one nobody watched.
        let outcome = run_wrapper_streaming(&args, &passphrase, RUN_TIMEOUT_SECS, &sink).await;

        let mut failure = outcome.as_ref().err().cloned();
        let archive = outcome.ok().as_deref().and_then(parse_archive);
        let backups = match listing(&service_id, &target) {
            Ok(list) => Some(list),
            Err(err) => {
                // Losing the re-read is worth reporting, but only after the
                // event has gone out with whatever else is known.
                failure.get_or_insert_with(|| format!("could not re-read the backup directory: {err}"));
                None
            }
        };
        let _ = sink.completed(archive, backups).await;
        if let Some(why) = failure {
            let _ = sink.fail(&why).await;
        }
    });

    stream_response(json, rx)
}

// ─────────────────────────── Wrapper plumbing ───────────────────────────

struct WrapperOutput {
    stdout: String,
}

/// Spawn the wrapper and collect its output. No shell: the wrapper is executed
/// directly and every argument is its own argv element, so there is nothing to
/// quote and nothing to escape.
///
/// `passphrase` is written to STDIN. Stdin is ALWAYS a pipe that gets closed,
/// even when nothing is written: the wrapper reads it with `cat` whenever a run
/// encrypts, and `cat` on an open pipe waits for EOF for ever — the same trap
/// the mailbox path hit with `docker exec -i`.
async fn run_wrapper(args: &[&str], passphrase: Option<&str>, timeout_secs: u64) -> Result<WrapperOutput, String> {
    let home = wrapper_home();
    let mut child = tokio::process::Command::new(wrapper_path())
        .args(args)
        // See `wrapper_home`: the unit's ProtectHome makes the inherited HOME
        // read-only, and gpg dies on it.
        .env("HOME", &home)
        .env("GNUPGHOME", home.join(".gnupg"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run the backup wrapper: {err}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        if let Some(passphrase) = passphrase {
            let _ = stdin.write_all(passphrase.as_bytes()).await;
        }
        let _ = stdin.shutdown().await;
        drop(stdin);
    }

    let output = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
        .await
        .map_err(|_| format!("the backup wrapper timed out after {timeout_secs}s"))?
        .map_err(|err| format!("the backup wrapper did not finish: {err}"))?;

    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    if output.status.success() {
        return Ok(WrapperOutput { stdout });
    }
    // The wrapper's own words are the explanation — "no such backup", "an
    // encrypted backup needs a passphrase on stdin", "the nextcloud database
    // dump failed". Swallowing them is the mistake this project keeps paying
    // for (mailcow's `curl -f`, nextcloud's `occ >/dev/null`).
    let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr));
    Err(describe_failure(output.status.code(), &stderr))
}

fn describe_failure(code: Option<i32>, stderr: &str) -> String {
    let detail = stderr.trim();
    let detail: String = detail.chars().rev().take(400).collect::<Vec<_>>().into_iter().rev().collect();
    match (code, detail.is_empty()) {
        (_, false) => detail,
        (Some(code), true) => format!("the backup wrapper exited {code}"),
        (None, true) => "the backup wrapper was killed by a signal".to_string(),
    }
}

/// Same spawn, but every output line is streamed as a PROGRESS event while the
/// run is under way. Returns the accumulated stdout so the caller can read the
/// archive announcement out of it.
async fn run_wrapper_streaming(
    args: &[&str],
    passphrase: &str,
    timeout_secs: u64,
    sink: &EventSink,
) -> Result<String, String> {
    let home = wrapper_home();
    let mut child = tokio::process::Command::new(wrapper_path())
        .args(args)
        // See `wrapper_home`: without this every ENCRYPTED backup fails, because
        // gpg cannot create its home under the unit's ProtectHome.
        .env("HOME", &home)
        .env("GNUPGHOME", home.join(".gnupg"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run the backup wrapper: {err}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        // Written even when empty, then closed: the wrapper falls back to the
        // stored passphrase when it reads nothing, but it can only READ nothing
        // if the pipe is closed.
        if !passphrase.is_empty() {
            let _ = stdin.write_all(passphrase.as_bytes()).await;
        }
        let _ = stdin.shutdown().await;
        drop(stdin);
    }

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut stdout = String::new();
    let mut stderr = String::new();

    // ONE deadline for the whole run rather than a per-line one: a backup is
    // silent for long stretches (a `tar` of a photo library says nothing), and a
    // quiet minute is not a hung command.
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
                        // The wrapper narrates progress on stderr too (docker,
                        // gpg and tar all do), so an stderr line is progress —
                        // the exit status is what decides success.
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
        Err(_) => Err(format!("the backup timed out after {timeout_secs}s")),
        Ok(Err(io)) => Err(format!("the backup wrapper did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(stdout),
        Ok(Ok(status)) => Err(describe_failure(status.code(), &stderr)),
    }
}

fn wrapper_failed(detail: &str) -> Resp {
    connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", detail)
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

/// Frames and pushes one run's events. A failing send means the client is gone;
/// callers treat that as "stop talking", never as an error to report.
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
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::BackupEvent {
        pb::BackupEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            service_id: self.service_id.clone(),
            text: String::new(),
            stream: String::new(),
            archive: None,
            backups: None,
            target: String::new(),
        }
    }

    async fn send(&self, event: pb::BackupEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, target: &str) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.target = target.to_string();
        self.send(event).await
    }

    async fn progress(&self, stream: &str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(&self, archive: Option<pb::BackupArchive>, backups: Option<pb::BackupList>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.archive = archive;
        event.backups = backups;
        self.send(event).await
    }

    /// End the stream with a Connect error trailer — what makes the client
    /// throw. It is sent AFTER `completed`, never instead of it.
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

    /// The wrapper location is overridden through the environment, which is
    /// process-wide, and cargo runs tests in parallel threads — without this the
    /// tests would flip each other's override and fail at random.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A wrapper as the generator really writes it (the arms of `do_estimate`
    /// and `do_delete`, verbatim in shape), trimmed to what this module reads.
    const WRAPPER: &str = r#"#!/bin/bash
        set -euo pipefail
        do_delete() {
          local path="${1:-}"
          case "$path" in
            *..*) echo "invalid path: ${path}" >&2; exit 2 ;;
          esac
          case "$path" in
            "/opt/backups/nextcloud"/*|"/opt/backups/vpn-panel"/*) ;;
            *) echo "path outside the backup directories: ${path}" >&2; exit 2 ;;
          esac
        }
        do_estimate() {
          local svc="${1:-}" dir="" total=0 free="" sz=""
          case "$svc" in
            nextcloud) dir='/opt/backups/nextcloud'; paths=('/opt/nextcloud/data' '/opt/nextcloud/db') ;;
            vpn-panel) dir='/opt/backups/vpn-panel'; paths=('/opt/vpn-panel/data') ;;
            docker-mailserver) dir='/srv/backups/docker-mailserver'; paths=('/opt/docker-mailserver') ;;
            *) echo "unsupported service: ${svc}" >&2; exit 2 ;;
          esac
        }
"#;

    #[test]
    fn the_wrappers_own_table_is_where_a_backup_directory_comes_from() {
        let found = parse_directories(WRAPPER);
        assert_eq!(
            found,
            vec![
                ("nextcloud".to_string(), "/opt/backups/nextcloud".to_string()),
                ("vpn-panel".to_string(), "/opt/backups/vpn-panel".to_string()),
                // A deployment that moved its backup root: exactly the case a
                // constant in the agent would get wrong, and the reason the
                // directory is read from the host at all.
                ("docker-mailserver".to_string(), "/srv/backups/docker-mailserver".to_string()),
            ]
        );
    }

    #[test]
    fn the_case_arms_that_are_not_service_labels_are_ignored() {
        // `*..*)` and `*)` sit in the same `case` blocks; neither is a service.
        // The third one is the shape that would actually do damage: a catch-all
        // arm carrying a directory. Read as a service, it would become an entry
        // named `*` pointing at a directory no service owns — and this parser's
        // whole job is to answer "where does THIS service keep its archives".
        for line in [
            "    *..*) echo bad ;;",
            "    *) echo \"unsupported\" ;;",
            "    *) dir='/opt/backups/fallback'; paths=() ;;",
            "  ;;",
        ] {
            assert!(parse_directories(line).is_empty(), "{line} must not parse as a service");
        }
        // A relative directory is refused as well: everything downstream joins
        // and compares absolute paths.
        assert!(parse_directories("  nextcloud) dir='backups/nextcloud'; paths=() ;;").is_empty());
    }

    #[test]
    fn only_catalog_ids_resolve_to_a_wrapper_label() {
        // The gate: a client picks among the agent's own constants.
        assert_eq!(wrapper_target("nextcloud"), Some("nextcloud"));
        assert_eq!(wrapper_target("docker-mailserver"), Some("docker-mailserver"));
        assert_eq!(wrapper_target("jellyfin"), Some("jellyfin"));
        // Every VPN protocol shares the panel's backup, as they share the panel.
        assert_eq!(wrapper_target("vpn"), Some("vpn-panel"));
        for hostile in ["nope", "nextcloud; rm -rf /", "../../etc/shadow", "", "--encrypt"] {
            assert_eq!(wrapper_target(hostile), None, "{hostile} must not resolve");
        }
    }

    #[test]
    fn the_label_that_reaches_argv_is_the_agents_own_string_not_the_requests() {
        // The gate is not "the id looked acceptable". It is that what continues
        // into a privileged argument vector is a pointer into the agent's OWN
        // table — a lookup that validated the input and then handed the caller's
        // bytes onwards would satisfy every equality check above and still carry
        // client-controlled memory into the wrapper's argv.
        let from_the_wire = String::from("nextcloud");
        let label = wrapper_target(&from_the_wire).expect("a catalog id resolves");
        assert_eq!(label, "nextcloud");
        assert!(
            !std::ptr::eq(label.as_ptr(), from_the_wire.as_ptr()),
            "the wrapper label must come from the agent's table, not from the request"
        );
        // The other half of this rule — that EVERY catalog id resolves to a
        // label — is pinned beside the table itself, in `discover`, so a service
        // added there joins the check without anyone remembering to.
    }

    #[test]
    fn a_host_with_no_wrapper_is_told_what_to_do_not_shown_an_empty_list() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // An adopted server, or one installed before backups existed. Answering
        // "no backups" there would be a lie the user acts on.
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", "/nonexistent/gryonixnexus-backup-ctl.sh");
        assert_eq!(resolve("nextcloud"), Err(Rejection::NoWrapper));
        // …and the unknown-id refusal still comes FIRST: it does not depend on
        // the host at all.
        assert_eq!(resolve("nope"), Err(Rejection::UnknownService("nope".into())));
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
    }

    #[test]
    fn a_service_the_wrapper_has_no_arm_for_is_refused_before_anything_runs() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("backup-ctl.sh");
        std::fs::write(&script, WRAPPER).unwrap();
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &script);

        assert_eq!(
            resolve("nextcloud"),
            Ok(Target {
                label: "nextcloud",
                directory: PathBuf::from("/opt/backups/nextcloud")
            })
        );
        // The wrapper is generated from the services THIS deployment installed,
        // so a catalog service that is not part of it has no arm. Answering with
        // a guessed `/opt/backups/immich` would be a directory nothing writes —
        // an empty listing that reads as "no backups", and a delete pointed
        // somewhere nobody asked for.
        assert_eq!(resolve("immich"), Err(Rejection::NotBackedUp("immich".into())));

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_delete_path_must_be_inside_this_services_own_directory() {
        let dir = Path::new("/opt/backups/nextcloud");
        assert!(validate_delete_path("/opt/backups/nextcloud/nextcloud-20260806.tar.gz", dir).is_ok());
        // A name with spaces is fine — those come from files uploaded off the
        // device, and the old `ls` parser lost exactly this case.
        assert!(validate_delete_path("/opt/backups/nextcloud/my  backup.tar.gz", dir).is_ok());
        for hostile in [
            // Another service's archives: the wrapper would ACCEPT this one (it
            // is inside a directory the deployment owns), which is why this gate
            // exists at all.
            "/opt/backups/vaultwarden/vault.tar.gz.gpg",
            "/opt/backups/nextcloud/../../../etc/shadow",
            "/etc/shadow",
            "/opt/backups/nextcloud",
            "/opt/backups/nextcloud/",
            "/opt/backups/nextcloud/incoming",
            "/opt/backups/nextcloudx/archive.tar.gz",
            "",
        ] {
            assert!(
                validate_delete_path(hostile, dir).is_err(),
                "{hostile} must be refused"
            );
        }
    }

    #[test]
    fn the_estimate_marker_is_read_as_two_byte_counts() {
        let output = "making room\nGRYONIXNEXUS_BACKUP_ESTIMATE 1073741824 223338299392\nGRYONIXNEXUS_BACKUP_CTL_DONE\n";
        assert_eq!(
            parse_estimate(output),
            Some(pb::BackupEstimate {
                data_bytes: 1_073_741_824,
                free_bytes: 223_338_299_392
            })
        );
        // A wrapper from before `estimate` existed prints no marker. None means
        // "no estimate", which the app renders as such — never as zero bytes,
        // which reads as "it will fit".
        assert_eq!(parse_estimate("GRYONIXNEXUS_BACKUP_CTL_DONE\n"), None);
        assert_eq!(parse_estimate("GRYONIXNEXUS_BACKUP_ESTIMATE 12\n"), None);
    }

    #[test]
    fn the_archive_announcement_carries_size_and_path() {
        let output = "backing up\nGRYONIXNEXUS_BACKUP_DONE 4096 /opt/backups/nextcloud/nextcloud-2026.tar.gz.gpg\nGRYONIXNEXUS_BACKUP_CTL_DONE\n";
        let archive = parse_archive(output).unwrap();
        assert_eq!(archive.path, "/opt/backups/nextcloud/nextcloud-2026.tar.gz.gpg");
        assert_eq!(archive.name, "nextcloud-2026.tar.gz.gpg");
        assert_eq!(archive.size_bytes, 4096);
        // mailcow runs its own tool and announces nothing: no marker is a
        // successful run with no archive to name, not a failure.
        assert_eq!(parse_archive("GRYONIXNEXUS_BACKUP_CTL_DONE\n"), None);
        // A path with spaces survives whole.
        let spaced = parse_archive("GRYONIXNEXUS_BACKUP_DONE 10 /opt/backups/nc/my backup.tar.gz").unwrap();
        assert_eq!(spaced.path, "/opt/backups/nc/my backup.tar.gz");
    }

    #[test]
    fn encryption_unspecified_passes_no_flag_at_all() {
        // The per-service default (secrets yes, bulk media no) lives in the
        // wrapper. Passing a flag here would be the agent holding a second
        // opinion about it, and the two would drift.
        assert_eq!(encryption_flag(pb::BackupEncryption::Unspecified), None);
        assert_eq!(encryption_flag(pb::BackupEncryption::Enabled), Some("--encrypt"));
        assert_eq!(encryption_flag(pb::BackupEncryption::Disabled), Some("--no-encrypt"));
    }

    #[test]
    fn a_directory_that_does_not_exist_yet_is_an_empty_listing() {
        let missing = std::env::temp_dir().join("gryonixnexusd-backup-missing-dir");
        let _ = std::fs::remove_dir_all(&missing);
        assert!(read_directory(&missing).unwrap().is_empty());
    }

    #[test]
    fn listings_are_newest_first_and_skip_the_upload_staging_directory() {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(STAGING_DIRECTORY)).unwrap();
        // The wrapper's own scratch directory, in the shape it really makes it:
        // `mktemp -d '<backup dir>/.work-XXXXXX'`. It exists for the whole of
        // every run and survives a run that was killed, and the half-written
        // archive inside it is not a backup anybody may restore from.
        std::fs::create_dir_all(dir.join(".work-Ab3xQ1")).unwrap();
        std::fs::write(dir.join("old.tar.gz"), b"old").unwrap();
        // mailcow keeps each backup as a directory; those are listed too.
        std::fs::create_dir_all(dir.join("mailcow-2026-08-06")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(dir.join("new.tar.gz.gpg"), b"newer").unwrap();

        let archives = read_directory(&dir).unwrap();
        let names: Vec<_> = archives.iter().map(|a| a.name.as_str()).collect();
        assert!(!names.contains(&STAGING_DIRECTORY), "the upload staging dir is not a backup: {names:?}");
        assert!(
            !names.iter().any(|name| name.starts_with('.')),
            "the wrapper's in-flight work directory is not a backup: {names:?}"
        );
        assert_eq!(names.len(), 3);
        // Newest first — the order `ls -lht` gave the SSH route, and what "the
        // last backup" in the picker depends on.
        assert_eq!(names[0], "new.tar.gz.gpg", "newest first: {names:?}");
        let old = archives.iter().find(|a| a.name == "old.tar.gz").unwrap();
        assert_eq!(old.size_bytes, 3);
        assert!(!old.directory);
        assert!(archives.iter().find(|a| a.name == "mailcow-2026-08-06").unwrap().directory);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failing_wrapper_is_reported_in_its_own_words() {
        // "no such backup", "an encrypted backup needs a passphrase on stdin",
        // "the nextcloud database dump failed" — the wrapper's line IS the
        // explanation, and swallowing it is the mistake mailcow's `curl -f` and
        // nextcloud's `occ >/dev/null` already cost this project.
        assert_eq!(describe_failure(Some(2), "no such backup: /x\n"), "no such backup: /x");
        assert_eq!(describe_failure(Some(2), "   "), "the backup wrapper exited 2");
        assert_eq!(describe_failure(None, ""), "the backup wrapper was killed by a signal");
        // Bounded: the message travels into logs and UI.
        let long = "x".repeat(900);
        assert_eq!(describe_failure(Some(1), &long).chars().count(), 400);
    }

    #[tokio::test]
    async fn the_passphrase_never_appears_in_the_wrappers_arguments() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The whole reason it is a request FIELD and not an argument: argv is
        // world-readable through /proc to every account on the box. This runs a
        // stand-in wrapper that prints its own argv and whatever reached stdin.
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-stdin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("wrapper.sh");
        std::fs::write(&script, "#!/bin/sh\necho \"ARGV: $*\"\necho \"STDIN: $(cat)\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &script);

        let out = run_wrapper(&["backup", "nextcloud", "--encrypt"], Some("s3cret-phrase"), 30)
            .await
            .unwrap();
        assert!(out.stdout.contains("ARGV: backup nextcloud --encrypt"), "{}", out.stdout);
        assert!(!out.stdout.contains("ARGV: backup nextcloud --encrypt s3cret"), "{}", out.stdout);
        assert!(out.stdout.contains("STDIN: s3cret-phrase"), "{}", out.stdout);

        // And with no passphrase the pipe still CLOSES: the wrapper reads stdin
        // with `cat` whenever a run encrypts, and an open pipe would hang the
        // call until the deadline — the same trap `docker exec -i` set for the
        // mailbox path.
        let closed = tokio::time::timeout(
            Duration::from_secs(10),
            run_wrapper(&["backup", "nextcloud"], None, 30),
        )
        .await
        .expect("stdin must be closed, or the wrapper waits for EOF for ever")
        .unwrap();
        assert!(closed.stdout.contains("STDIN: \n") || closed.stdout.contains("STDIN: "), "{}", closed.stdout);

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_wrapper_is_handed_a_home_it_can_actually_write_to() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Shared with the other modules that redirect this variable — see
        // `util::STATE_DIR_ENV_LOCK`.
        let _state_guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Live defect, 2026-08-07: the unit hardens the agent with
        // `ProtectHome=true`, so the inherited HOME (/root) is an empty
        // read-only mount, and `gpg --symmetric` — which every ENCRYPTED backup
        // runs — died with "can't create directory '/root/.gnupg': Read-only
        // file system". The identical wrapper succeeded over SSH, where sudo
        // hands it a real home, so nothing but a run on a real unit could show
        // it. What is pinned here is the contract that made it possible: the
        // child gets a HOME and a GNUPGHOME, and both exist and are writable.
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-home-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("wrapper.sh");
        // The shape of the real failure: create something under $HOME, exactly
        // as gpg does before it can encrypt anything.
        std::fs::write(
            &script,
            "#!/bin/sh\nset -e\nmkdir -p \"$HOME/probe\"\n: > \"$HOME/probe/file\"\n\
             mkdir -p \"$GNUPGHOME\"\n: > \"$GNUPGHOME/random_seed\"\n\
             echo \"HOME: $HOME\"\necho \"GNUPGHOME: $GNUPGHOME\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &script);
        let state = dir.join("state");
        std::env::set_var("GRYONIXNEXUSD_STATE_DIR", &state);

        let out = run_wrapper(&["backup", "nextcloud", "--encrypt"], Some("phrase"), 30)
            .await
            .expect("the wrapper must be able to write under the HOME it is given");
        let home = state.join("wrapper-home");
        assert!(out.stdout.contains(&format!("HOME: {}", home.display())), "{}", out.stdout);
        assert!(home.join("probe/file").exists(), "the child could not write under HOME");
        assert!(home.join(".gnupg/random_seed").exists(), "the child could not write under GNUPGHOME");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // gpg warns loudly about a home other accounts can read, and that
            // warning would land in every backup log.
            let mode = std::fs::metadata(home.join(".gnupg")).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "GNUPGHOME must not be readable by anyone else: {mode:o}");
        }

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────── Schedule ───────────────────────────

    use prost::Message;

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

    #[tokio::test]
    async fn get_backup_schedule_reads_off_disk_with_no_wrapper_call() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-sched-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("autobackup.conf");
        std::fs::write(&config, "SCHEDULE=every:1d@03:30\nRETENTION=14\nSERVICES='nextcloud vaultwarden'\n").unwrap();
        std::env::set_var("GRYONIXNEXUSD_BACKUP_CONFIG", &config);

        let resp = get_backup_schedule(Codec::Proto, pb::GetBackupScheduleRequest {}).await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let policy = pb::BackupSchedulePolicy::decode(body).unwrap();
        assert_eq!(policy.schedule, "every:1d@03:30");
        assert_eq!(policy.retention, 14);
        assert_eq!(policy.services, vec!["nextcloud", "vaultwarden"]);

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn get_backup_schedule_reads_off_as_the_default_for_a_missing_or_empty_config() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_BACKUP_CONFIG", "/nonexistent/autobackup.conf");
        let resp = get_backup_schedule(Codec::Proto, pb::GetBackupScheduleRequest {}).await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let policy = pb::BackupSchedulePolicy::decode(body).unwrap();
        assert_eq!(policy.schedule, "off");
        assert_eq!(policy.retention, 7);
        assert!(policy.services.is_empty());
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_CONFIG");
    }

    #[tokio::test]
    async fn set_backup_schedule_answers_with_the_policy_re_read_from_disk_not_the_request() {
        // Same proof as update's own test: the wrapper drops a service it does
        // not manage (gitlab), the stub's pre-seeded config omits it, and the
        // answer must come from that file, not from echoing the request.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-setsched-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("autobackup.conf");
        std::fs::write(&config, "SCHEDULE=every:1d@03:30\nRETENTION=14\nSERVICES='nextcloud'\n").unwrap();
        let wrapper = write_stub(&dir, "backup-ctl.sh", "#!/bin/sh\necho \"ARGV: $*\" > \"$(dirname \"$0\")/argv.txt\"\n");

        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &wrapper);
        std::env::set_var("GRYONIXNEXUSD_BACKUP_CONFIG", &config);

        let resp = set_backup_schedule(
            Codec::Proto,
            pb::SetBackupScheduleRequest {
                schedule: "every:1d@03:30".to_string(),
                retention: 14,
                services: vec!["nextcloud".to_string(), "gitlab".to_string()],
                passphrase: String::new(),
            },
        )
        .await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let policy = pb::BackupSchedulePolicy::decode(body).unwrap();
        assert_eq!(policy.services, vec!["nextcloud"], "gitlab must not appear: the answer is read, not echoed");

        let argv = std::fs::read_to_string(dir.join("argv.txt")).unwrap();
        assert_eq!(argv.trim(), "ARGV: set-schedule every:1d@03:30 14 nextcloud gitlab");

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A non-empty passphrase is stored through its OWN wrapper call
    /// (`set-passphrase`, stdin-carried), before `set-schedule` — never as an
    /// argument on the schedule call, which is the argv-is-world-readable
    /// rule every other secret in this crate already follows.
    #[tokio::test]
    async fn set_backup_schedule_stores_a_passphrase_through_its_own_call_first() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-setpass-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("autobackup.conf");
        std::fs::write(&config, "SCHEDULE=off\n").unwrap();
        let wrapper = write_stub(
            &dir,
            "backup-ctl.sh",
            "#!/bin/sh\n\
             echo \"$1\" >> \"$(dirname \"$0\")/calls.txt\"\n\
             if [ \"$1\" = set-passphrase ]; then cat > \"$(dirname \"$0\")/passphrase.txt\"; fi\n",
        );
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &wrapper);
        std::env::set_var("GRYONIXNEXUSD_BACKUP_CONFIG", &config);

        let _ = set_backup_schedule(
            Codec::Proto,
            pb::SetBackupScheduleRequest {
                schedule: "every:1d@03:30".to_string(),
                retention: 7,
                services: vec!["vaultwarden".to_string()],
                passphrase: "correct horse battery staple".to_string(),
            },
        )
        .await;

        let calls = std::fs::read_to_string(dir.join("calls.txt")).unwrap();
        assert_eq!(calls.lines().collect::<Vec<_>>(), vec!["set-passphrase", "set-schedule"],
                  "set-passphrase must run, and run BEFORE set-schedule");
        let stored = std::fs::read_to_string(dir.join("passphrase.txt")).unwrap();
        assert_eq!(stored, "correct horse battery staple");

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_backup_schedule_surfaces_a_bad_grammar_refusal_in_the_wrappers_own_words() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-badsched-{}", std::process::id()));
        let wrapper = write_stub(
            &dir,
            "backup-ctl.sh",
            "#!/bin/sh\necho 'unsupported schedule: bogus' >&2\nexit 2\n",
        );
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &wrapper);

        let resp = set_backup_schedule(
            Codec::Proto,
            pb::SetBackupScheduleRequest {
                schedule: "bogus".to_string(),
                retention: 7,
                services: vec![],
                passphrase: String::new(),
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["message"].as_str().unwrap().contains("unsupported schedule"));

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_backup_schedule_reports_no_wrapper_when_the_host_has_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", "/nonexistent/gryonixnexus-backup-ctl.sh");
        let resp = set_backup_schedule(
            Codec::Proto,
            pb::SetBackupScheduleRequest {
                schedule: "off".to_string(),
                retention: 7,
                services: vec![],
                passphrase: String::new(),
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
    }
}
