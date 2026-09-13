//! Executing a stranger's backup plan.
//!
//! The plan itself is worked out in `container_backup`; this is what runs it.
//! Every decision here exists because of a failure the catalog's own backups
//! already paid for, and the two most expensive ones are restated in code
//! rather than left to be rediscovered:
//!
//! * **A database directory is never archived live.** `tar` over a running
//!   engine's files produces an archive that restores into a corrupt database,
//!   and it does so without a single error AT BACKUP TIME. The failure shows up
//!   at the restore, which is the worst moment there is. So a database that can
//!   be dumped is dumped and its data directory is subtracted from the tar; one
//!   that cannot forces the stack to stop for the duration.
//! * **The password is NAMED, never passed.** `docker exec` argv is readable
//!   through `/proc` by any account on the machine, so the plan carries the
//!   env var's NAME and the dump command dereferences it INSIDE the container.
//!
//! The archive lands beside the catalog's own so that one backups screen
//! answers for the whole host, but under its own `containers/` branch: these
//! are not catalog services, and a restore wrapper that found them there would
//! be a wrapper asked to restore something it has no spec for.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use tokio::sync::mpsc::Sender;

use hyper::StatusCode;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::container_ops::{capture, capture_to_file, first_lines, run_streaming};
use crate::containers::{self, GroupKind};
use crate::pb;

/// Where a stranger's archives live. A sibling of the catalog's root rather
/// than a child of it: `/opt/backups/<service>` is addressed BY CATALOG ID
/// throughout the restore wrapper, and a directory named after a compose
/// project sitting in that namespace would eventually be handed to it.
const CONTAINER_BACKUP_ROOT: &str = "/opt/backups/containers";

/// Long, because this is bounded by how much data the group holds rather than
/// by anything the agent controls. The catalog's own runs get the same order of
/// budget.
const BACKUP_TIMEOUT_SECS: u64 = 60 * 60 * 6;
/// A dump is a conversation with a live engine; if it has said nothing for this
/// long it is not going to.
const DUMP_TIMEOUT_SECS: u64 = 60 * 60;
const STOP_TIMEOUT_SECS: u64 = 300;

pub fn backup_root() -> PathBuf {
    PathBuf::from(
        std::env::var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT")
            .unwrap_or_else(|_| CONTAINER_BACKUP_ROOT.to_string()),
    )
}

/// What one group's backup directory holds, newest first.
///
/// **Read-only, and the only verb that could ever answer this.** The archives
/// have existed since container backups landed and nothing returned them, so
/// the app ran backups for a stranger's stack that it could then never show.
/// `Backup/ListBackups` cannot stand in: it resolves a CATALOG id through the
/// wrapper the installer generated, and a foreign group has neither an id nor a
/// wrapper.
///
/// **The path is RESOLVED, never accepted.** The caller names the group; the
/// directory comes from this module's own root joined with the key the host
/// reported. A request carrying a path would be a directory listing for
/// anything the agent can read.
///
/// A missing directory is an empty list, not a failure: a group that has never
/// been backed up is the ordinary case. A directory that exists and cannot be
/// READ is a fault on the host and is reported as one — hiding it as "no
/// backups yet" is how a broken backup setup stays invisible until the day it
/// is needed.
pub fn list(key: &str) -> Result<pb::ContainerBackupList, Resp> {
    let dir = backup_root().join(key);
    match crate::backup::read_directory(&dir) {
        Ok(archives) => Ok(pb::ContainerBackupList {
            key: key.to_string(),
            directory: dir.to_string_lossy().to_string(),
            archives,
        }),
        Err(err) => Err(connect_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            &format!("could not read {}: {err}", dir.display()),
        )),
    }
}

/// Run one group's plan, streaming progress.
///
/// Two error channels, as every destructive streamed verb in this crate has: a
/// refusal BEFORE anything is touched is a plain Connect error and no stream
/// opens; a failure DURING the run ends with an error trailer, but only AFTER a
/// COMPLETED event carrying the re-read group — because a backup that stopped a
/// stack and then failed leaves "is it running again?" as the first question.
pub async fn run(
    codec: Codec,
    req: pb::RunContainerGroupBackupRequest,
    names: Vec<(String, String)>,
    stored: Option<pb::ContainerBackupPlan>,
) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("container", &req.key) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let (group, details) = match containers::details_of_group(&req.key, &names).await {
        Ok(pair) => pair,
        Err(refusal) => return refusal.response(),
    };

    // From here the strings are the HOST's, never the caller's.
    let key = group.key.clone();
    let kind = containers::kind_of_group(&group);
    let container_names: Vec<String> = group.containers.iter().map(|c| c.name.clone()).collect();
    let plan = crate::container_backup::effective(&key, &details, stored);

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);

    tokio::spawn(async move {
        let _claim = claim;
        let sink = BackupSink {
            tx,
            codec,
            key: key.clone(),
            journal: crate::jobs::Journal::open(pb::JobKind::ContainerBackup, &key),
        };
        let _ = sink.started(plan.clone()).await;

        let outcome = execute(&key, kind, &plan, &details, &container_names, &sink.tx, &sink.encoder()).await;
        let (archive, failure) = match outcome {
            Ok(archive) => (Some(archive), None),
            Err(err) => (None, Some(err)),
        };

        let mut problems: Vec<String> = failure.into_iter().collect();
        match containers::inventory(&names).await {
            Ok(fresh) => {
                let _ = sink.completed(archive, containers::resolve(&fresh, &key).cloned()).await;
            }
            Err(err) => problems.push(format!("status re-read: {err}")),
        }
        if !problems.is_empty() {
            let _ = sink.fail(&problems.join("; ")).await;
        }
    });

    stream_response(json, rx)
}

/// The plan, in the one order it can safely run.
async fn execute(
    key: &str,
    kind: GroupKind,
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    container_names: &[String],
    tx: &Sender<Bytes>,
    encode: &(dyn Fn(&'static str, String) -> Bytes + Sync),
) -> Result<pb::BackupArchive, String> {
    let dir = backup_root().join(key);
    std::fs::create_dir_all(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    restrict(&dir);

    let stamp = timestamp();
    let staging = dir.join(format!(".incoming-{stamp}"));
    std::fs::create_dir_all(&staging)
        .map_err(|err| format!("could not create {}: {err}", staging.display()))?;
    restrict(&staging);

    // Whatever happens below, the staging directory does not outlive this run:
    // a half-written dump left beside finished archives is the kind of thing a
    // later listing shows as a backup.
    let result =
        fill_and_pack(key, kind, plan, details, container_names, &dir, &staging, &stamp, tx, encode).await;
    let _ = std::fs::remove_dir_all(&staging);
    result
}

#[allow(clippy::too_many_arguments)]
async fn fill_and_pack(
    key: &str,
    kind: GroupKind,
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    container_names: &[String],
    dir: &Path,
    staging: &Path,
    stamp: &str,
    tx: &Sender<Bytes>,
    encode: &(dyn Fn(&'static str, String) -> Bytes + Sync),
) -> Result<pb::BackupArchive, String> {
    // 1. Dumps FIRST, while the stack is still up: a dump needs a live engine,
    //    and the stop below (when there is one) is precisely for what cannot be
    //    dumped.
    for dump in &plan.databases {
        let engine = pb::ContainerDatabaseEngine::try_from(dump.engine)
            .unwrap_or(pb::ContainerDatabaseEngine::Unspecified);
        let file = staging.join(format!("{}.{}.dump", sanitise_component(&dump.container), suffix(engine)));
        let _ = tx.send(encode("agent", format!("dumping {} from {}", dump.database, dump.container))).await;
        let args = dump_args(dump, engine)?;
        let bytes = capture_to_file("docker", &args, &file, DUMP_TIMEOUT_SECS)
            .await
            .map_err(|err| format!("dumping {} failed: {err}", dump.container))?;
        // An engine that answers but writes nothing is not a backup. Caught
        // here rather than at the restore, which is the whole point of the
        // module's opening note.
        if bytes == 0 {
            return Err(format!("dumping {} produced an empty file", dump.container));
        }
        let _ = tx.send(encode("agent", format!("dumped {bytes} bytes from {}", dump.container))).await;
    }

    // 2. Stop, if the plan says the archive cannot be consistent otherwise.
    let stopped = if plan.stop_while_archiving {
        let _ = tx.send(encode("agent", "stopping the group so the archive is consistent".to_string())).await;
        let args = containers::docker_args(key, kind, pb::ServiceAction::Stop);
        run_streaming("docker", &args, STOP_TIMEOUT_SECS, tx, encode)
            .await
            .map_err(|err| format!("could not stop the group: {err}"))?;
        true
    } else {
        false
    };

    // 3. Archive. Even a failure here must not leave the group down, so the
    //    start below runs on EVERY path out — the same rule the catalog's
    //    wrapper follows with its containers.
    let packed = pack(plan, details, staging, dir, key, stamp, tx, encode).await;

    if stopped {
        let _ = tx.send(encode("agent", "starting the group again".to_string())).await;
        let args = containers::docker_args(key, kind, pb::ServiceAction::Start);
        if let Err(err) = run_streaming("docker", &args, STOP_TIMEOUT_SECS, tx, encode).await {
            // Said out loud and made part of the failure: a group left stopped
            // by its own backup is worse than a missing archive, and silence
            // here is what would hide it.
            let _ = tx.send(encode("agent", format!("WARNING: could not start the group again: {err}"))).await;
            return match packed {
                Ok(_) => Err(format!("the archive was written but the group did not start again: {err}")),
                Err(first) => Err(format!("{first}; and the group did not start again: {err}")),
            };
        }
    }
    let _ = container_names;
    packed
}

/// tar the plan's paths, volumes and dumps into one archive.
async fn pack(
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    staging: &Path,
    dir: &Path,
    key: &str,
    stamp: &str,
    tx: &Sender<Bytes>,
    encode: &(dyn Fn(&'static str, String) -> Bytes + Sync),
) -> Result<pb::BackupArchive, String> {
    let mut sources: Vec<String> = Vec::new();
    let excludes = dump_covered_dirs(plan, details);

    for path in &plan.paths {
        if !Path::new(path).exists() {
            let _ = tx.send(encode("agent", format!("skipping {path}: it is not on this host"))).await;
            continue;
        }
        sources.push(path.clone());
    }
    // A named volume is archived through its mountpoint on the host, which the
    // engine will name, rather than through a helper container: a helper needs
    // an IMAGE, and an image that has to be pulled is a backup that fails on a
    // host with no registry access — exactly the host most likely to be
    // holding the only copy of the data.
    for volume in &plan.volumes {
        match volume_mountpoint(volume).await {
            Ok(Some(path)) => sources.push(path),
            Ok(None) => {
                let _ = tx.send(encode("agent", format!("skipping volume {volume}: the engine reports no mountpoint"))).await;
            }
            Err(err) => {
                let _ = tx.send(encode("agent", format!("skipping volume {volume}: {err}"))).await;
            }
        }
    }
    let has_dumps = std::fs::read_dir(staging).map(|mut d| d.next().is_some()).unwrap_or(false);

    if sources.is_empty() && !has_dumps {
        return Err("this plan names nothing that exists on the host — nothing was archived".to_string());
    }

    let archive = dir.join(format!("{key}-{stamp}.tar.gz"));
    let mut args: Vec<String> = vec!["-czf".into(), archive.display().to_string()];
    for dir in &excludes {
        args.push(format!("--exclude={dir}"));
    }
    // Absolute paths keep tar's leading-slash warning; it is noise, not a
    // failure, and stripping it is what lets a restore land the files back
    // where they came from.
    args.push("-P".into());
    args.extend(sources.iter().cloned());
    // **The dumps go in under a STABLE name, never under the staging
    // directory's.** `-C` rebases what follows it, so they land as
    // `./<container>.<engine>.dump` instead of carrying
    // `.incoming-<epoch>/` into the archive — a path that changes every run is
    // a path a restore cannot be written against. Measured on a live host: the
    // first archive stored the dump as
    // `/opt/backups/containers/<key>/.incoming-1787428831/…`.
    if has_dumps {
        args.push("-C".into());
        args.push(staging.display().to_string());
        args.push(".".into());
    }

    let _ = tx.send(encode("agent", format!("archiving into {}", archive.display()))).await;
    run_streaming("tar", &args, BACKUP_TIMEOUT_SECS, tx, encode)
        .await
        .map_err(|err| {
            // A partial archive is worse than none: it lists as a backup.
            let _ = std::fs::remove_file(&archive);
            format!("archiving failed: {err}")
        })?;
    restrict_file(&archive);

    let size = std::fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
    Ok(pb::BackupArchive {
        name: archive.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        path: archive.display().to_string(),
        size_bytes: size as i64,
        modified_at: (stamp.parse::<i64>().unwrap_or(0)) * 1000,
        directory: false,
    })
}

/// The data directories the dumps already cover, so tar does not also take them
/// live. Without this the archive would contain BOTH a good dump and a torn
/// copy of the same database, and a restore would have to guess which is meant.
fn dump_covered_dirs(plan: &pb::ContainerBackupPlan, details: &[pb::ContainerDetail]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for dump in &plan.databases {
        let Some(detail) = details
            .iter()
            .find(|d| d.container.as_ref().is_some_and(|c| c.name == dump.container))
        else {
            continue;
        };
        for mount in &detail.mounts {
            if crate::container_backup::is_database_dir(&mount.destination) && !mount.source.is_empty() {
                if !out.iter().any(|existing| existing == &mount.source) {
                    out.push(mount.source.clone());
                }
            }
        }
    }
    out
}

/// The dump command for one engine.
///
/// The password NEVER appears in argv: what travels is the env var's NAME, and
/// the shell inside the container dereferences it. `docker exec` argv is
/// world-readable through `/proc`, which is why the plan carries a name in the
/// first place.
fn dump_args(dump: &pb::ContainerDatabaseDump, engine: pb::ContainerDatabaseEngine) -> Result<Vec<String>, String> {
    let container = &dump.container;
    let db = &dump.database;
    let user = if dump.user.is_empty() { "root" } else { &dump.user };
    let pw = &dump.password_env;
    let script = match engine {
        pb::ContainerDatabaseEngine::Postgres => {
            if pw.is_empty() {
                format!("pg_dump -U {} {}", shq(user), shq(db))
            } else {
                format!("PGPASSWORD=\"${pw}\" pg_dump -U {} {}", shq(user), shq(db))
            }
        }
        pb::ContainerDatabaseEngine::Mysql | pb::ContainerDatabaseEngine::Mariadb => {
            let auth = if pw.is_empty() { String::new() } else { format!(" -p\"${pw}\"") };
            format!("mysqldump --single-transaction -u {}{} {}", shq(user), auth, shq(db))
        }
        pb::ContainerDatabaseEngine::Mongo => {
            let auth = if pw.is_empty() { String::new() } else { format!(" -p \"${pw}\"") };
            format!("mongodump --archive -u {}{} --db {}", shq(user), auth, shq(db))
        }
        pb::ContainerDatabaseEngine::Unspecified => {
            return Err(format!("no dump command is known for {container}"))
        }
    };
    Ok(vec!["exec".into(), container.clone(), "sh".into(), "-c".into(), script])
}

/// Single-quote for the shell that runs INSIDE the container. Only the
/// database and user names go through it — both are host-reported — but a name
/// with a quote in it must not be able to end the string.
fn shq(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn suffix(engine: pb::ContainerDatabaseEngine) -> &'static str {
    match engine {
        pb::ContainerDatabaseEngine::Postgres => "pgsql",
        pb::ContainerDatabaseEngine::Mysql | pb::ContainerDatabaseEngine::Mariadb => "sql",
        pb::ContainerDatabaseEngine::Mongo => "mongo",
        pb::ContainerDatabaseEngine::Unspecified => "bin",
    }
}

/// A container name, made safe to use as ONE filename component. The name is
/// host-reported, but a filename is not a name, and `..` in one is a write
/// somewhere else.
fn sanitise_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();
    let trimmed = cleaned.trim_matches('.').to_string();
    if trimmed.is_empty() { "container".to_string() } else { trimmed }
}

async fn volume_mountpoint(volume: &str) -> Result<Option<String>, String> {
    let out = capture(
        "docker",
        &["volume".into(), "inspect".into(), volume.into(), "--format".into(), "{{.Mountpoint}}".into()],
        30,
    )
    .await?;
    if !out.success {
        return Err(first_lines(out.stderr.trim(), 1));
    }
    let path = out.stdout.trim().to_string();
    Ok(if path.is_empty() { None } else { Some(path) })
}

fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{now}")
}

fn restrict(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// An archive holds whatever the group held, which routinely includes a
/// database dump with credentials in it.
fn restrict_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// The same archive, driven by ANOTHER verb's stream.
///
/// The update chain has to back up before it pulls, and it must be the SAME
/// backup — a second implementation of "archive a stranger's group" beside this
/// one is exactly the drift the section's notes warn about. So the update hands
/// in its own encoder and the output arrives as update events.
pub(crate) async fn run_for_update(
    key: &str,
    kind: GroupKind,
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    tx: &Sender<Bytes>,
    encode: &(dyn Fn(&'static str, String) -> Bytes + Sync),
) -> Result<pb::BackupArchive, String> {
    let container_names: Vec<String> = details
        .iter()
        .filter_map(|d| d.container.as_ref().map(|c| c.name.clone()))
        .collect();
    execute(key, kind, plan, details, &container_names, tx, encode).await
}

struct BackupSink {
    tx: Sender<Bytes>,
    codec: Codec,
    key: String,
    /// The record this run leaves behind, so a client that closed can ask how
    /// it went — see `crate::jobs`. `None` when the host could not open one,
    /// which costs the reattach and nothing else.
    journal: Option<crate::jobs::Journal>,
}

impl BackupSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::ContainerBackupEvent {
        pb::ContainerBackupEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            key: self.key.clone(),
            text: String::new(),
            stream: String::new(),
            plan: None,
            archive: None,
            group: None,
        }
    }

    /// The encoder handed to `run_streaming`, so a child's output arrives as
    /// this verb's own event type.
    fn encoder(&self) -> impl Fn(&'static str, String) -> Bytes + Sync + '_ {
        move |stream: &'static str, text: String| {
            let mut event = self.event(pb::ServiceOperationPhase::Progress);
            event.stream = stream.to_string();
            event.text = text;
            envelope(0x00, &self.codec.encode_payload(&event))
        }
    }

    async fn send(&self, event: pb::ContainerBackupEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, plan: pb::ContainerBackupPlan) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.plan = Some(plan);
        self.send(event).await
    }

    async fn completed(
        &self,
        archive: Option<pb::BackupArchive>,
        group: Option<pb::ContainerGroup>,
    ) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.archive = archive;
        event.group = group;
        self.send(event).await
    }

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

    fn dump(container: &str, engine: pb::ContainerDatabaseEngine, pw: &str) -> pb::ContainerDatabaseDump {
        pb::ContainerDatabaseDump {
            container: container.to_string(),
            engine: engine as i32,
            database: "appdb".to_string(),
            user: "appuser".to_string(),
            password_env: pw.to_string(),
        }
    }

    /// **The password is NAMED, never passed.** `docker exec` argv is readable
    /// through `/proc` by any account on the machine, which is why the plan
    /// carries an env var's NAME and the shell inside the container
    /// dereferences it. This test asserts the shape that keeps that true.
    #[test]
    fn a_dump_command_carries_the_variable_name_and_never_its_value() {
        let args = dump_args(&dump("db", pb::ContainerDatabaseEngine::Postgres, "POSTGRES_PASSWORD"), pb::ContainerDatabaseEngine::Postgres).unwrap();
        let joined = args.join(" ");
        // The variable is DEREFERENCED inside the container...
        assert!(joined.contains("PGPASSWORD=\"$POSTGRES_PASSWORD\""), "{joined}");
        // ...and the first three arguments are the exec itself, so the script
        // is the only place a shell is involved at all.
        assert_eq!(args[0], "exec");
        assert_eq!(args[1], "db");
        assert_eq!(args[2], "sh");

        // MySQL and Mongo spell it differently and must still not carry a value.
        for engine in [pb::ContainerDatabaseEngine::Mysql, pb::ContainerDatabaseEngine::Mariadb] {
            let args = dump_args(&dump("db", engine, "MYSQL_PASSWORD"), engine).unwrap();
            assert!(args.join(" ").contains("$MYSQL_PASSWORD"), "{engine:?}");
        }
        let args = dump_args(&dump("db", pb::ContainerDatabaseEngine::Mongo, "MONGO_PW"), pb::ContainerDatabaseEngine::Mongo).unwrap();
        assert!(args.join(" ").contains("$MONGO_PW"));
    }

    /// An engine with no password variable is a real case (trust auth on a
    /// private network), and it must produce a command WITHOUT a dangling
    /// empty flag — `-p""` is not the same as no flag.
    #[test]
    fn a_dump_without_a_password_variable_omits_the_flag_entirely() {
        let args = dump_args(&dump("db", pb::ContainerDatabaseEngine::Postgres, ""), pb::ContainerDatabaseEngine::Postgres).unwrap();
        let joined = args.join(" ");
        assert!(!joined.contains("PGPASSWORD"), "{joined}");
        assert!(joined.contains("pg_dump -U 'appuser' 'appdb'"), "{joined}");

        let args = dump_args(&dump("db", pb::ContainerDatabaseEngine::Mysql, ""), pb::ContainerDatabaseEngine::Mysql).unwrap();
        assert!(!args.join(" ").contains("-p"), "{:?}", args);
    }

    /// The database and user names are host-reported, but a name with a quote
    /// in it must not be able to end the string it sits in.
    #[test]
    fn a_quote_in_a_name_cannot_end_the_quoted_string() {
        let mut d = dump("db", pb::ContainerDatabaseEngine::Postgres, "PW");
        d.database = "ap'p".to_string();
        let args = dump_args(&d, pb::ContainerDatabaseEngine::Postgres).unwrap();
        let script = args.last().unwrap();
        assert!(script.contains(r"'ap'\''p'"), "{script}");
    }

    /// An engine nobody has a client for is refused rather than turned into a
    /// command that would fail confusingly at run time.
    #[test]
    fn an_unknown_engine_is_refused() {
        let d = dump("db", pb::ContainerDatabaseEngine::Unspecified, "PW");
        assert!(dump_args(&d, pb::ContainerDatabaseEngine::Unspecified).is_err());
    }

    /// A container name becomes ONE filename component. It is host-reported,
    /// but a name is not a filename, and `..` in one is a write elsewhere.
    #[test]
    fn a_container_name_becomes_one_safe_filename_component() {
        assert_eq!(sanitise_component("stack-db-1"), "stack-db-1");
        assert_eq!(sanitise_component("../../etc/passwd"), "_.._etc_passwd");
        assert!(!sanitise_component("..").contains(".."));
        assert_eq!(sanitise_component(""), "container");
    }

    /// **The archives a foreign group's backups leave, which nothing could ask
    /// for until this verb existed.** Runs have been writing them since
    /// container backups landed; the app could start one and never show it.
    #[test]
    fn a_groups_archives_come_back_newest_first_from_a_derived_path() {
        let root = std::env::temp_dir()
            .join(format!("gryonixnexusd-cbl-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("acme-stack");
        std::fs::create_dir_all(&dir).unwrap();
        // Two archives and the two things that are NOT archives: the half-written
        // staging directory a run creates inside its own destination, and the
        // dotfile a killed run leaves behind for ever.
        // Ordered by writing them a second apart, the way `read_directory`'s
        // own test does: this crate carries no clock-setting dependency, and
        // adding one to order two files would be a dependency for a fixture.
        std::fs::write(dir.join("older.tar.gz"), b"x").unwrap();
        for name in [".incoming-20260904", ".work-abc"] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(dir.join("newer.tar.gz"), b"x").unwrap();

        std::env::set_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT", &root);
        let listed = list("acme-stack").expect("a readable directory is not a failure");
        std::env::remove_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT");

        assert_eq!(listed.key, "acme-stack");
        // The path is DERIVED from the key, never taken from the caller.
        assert_eq!(listed.directory, dir.to_string_lossy());
        assert_eq!(
            listed.archives.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            vec!["newer.tar.gz", "older.tar.gz"],
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **A directory that exists and cannot be READ is a fault, not "no backups
    /// yet".** Hiding it is how a broken backup setup stays invisible until the
    /// day it is needed — the same rule the catalog's own listing follows.
    ///
    /// The obstacle is BUILT rather than imagined: the group's directory is a
    /// FILE, so `read_dir` fails with something that is not `NotFound`. A test
    /// that only deleted the directory would be testing the empty case twice.
    #[test]
    fn a_directory_that_cannot_be_read_is_a_failure_rather_than_an_empty_list() {
        let root = std::env::temp_dir()
            .join(format!("gryonixnexusd-cbl-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // Where the group's directory should be, there is a file.
        std::fs::write(root.join("blocked"), b"not a directory").unwrap();

        std::env::set_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT", &root);
        let outcome = list("blocked");
        std::env::remove_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT");

        assert!(outcome.is_err(), "an unreadable directory was reported as no backups");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **A group that has never been backed up is an empty list, not an
    /// error.** That is the ordinary state of every stranger's stack until
    /// somebody runs one, and a failure there would make the screen say
    /// something is broken about a server that is fine.
    #[test]
    fn a_group_with_no_backups_yet_is_empty_rather_than_a_failure() {
        let root = std::env::temp_dir()
            .join(format!("gryonixnexusd-cbl-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&root);
        std::env::set_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT", &root);
        let listed = list("never-backed-up").expect("a missing directory is not a failure");
        std::env::remove_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT");
        assert!(listed.archives.is_empty());
        assert!(listed.directory.ends_with("never-backed-up"));
    }
}
