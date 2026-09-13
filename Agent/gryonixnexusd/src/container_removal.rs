//! Removing a group the configurator never installed.
//!
//! **Not through the uninstall wrapper, and that is structural rather than a
//! preference.** `/opt/gryonixnexus-uninstall.sh` is GENERATED from the catalog
//! set that was installed on this host: its targets are a `case` over catalog
//! ids, so a compose project it has never heard of gets "unsupported target".
//! Teaching it the stranger's list would mean regenerating the wrapper whenever
//! the host's containers change, which is the opposite of what a wrapper is
//! for. So the agent does this itself, with argv it builds from what the host
//! reported — the same gate as every other verb in this section.
//!
//! **What goes and what stays is the catalog's shape, not a new one.** The
//! default is "stop and remove the containers, keep everything they held";
//! data and backups are independent toggles and both default to keeping. A
//! removal that quietly took the data with it would be the one mistake here
//! that cannot be undone.
//!
//! The preview exists because a stranger's stack is one whose contents the
//! owner has NOT seen. Naming the directories on the screen that asks for
//! confirmation is the difference between an informed yes and a hopeful one.

use std::path::Path;

use bytes::Bytes;
use tokio::sync::mpsc::Sender;

use crate::api::{envelope, error_trailer, stream_response, Codec, Resp};
use crate::container_ops::run_streaming;
use crate::containers::{self, GroupKind, Refusal};
use crate::pb;

const REMOVE_TIMEOUT_SECS: u64 = 900;

/// Directories that are never deleted, whatever a mount claims.
///
/// A bind mount can name ANY host path — including `/`, `/etc` or a home
/// directory — because it is the stack author who chose it, not us. Removing
/// what a mount points at is therefore only safe for paths that look like they
/// belong to that stack, and the cheapest correct rule is a deny-list of the
/// places where deleting anything is catastrophic plus a depth rule below.
const NEVER_DELETED: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt", "/opt", "/proc", "/root",
    "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
];

/// Work out what removal would delete, without deleting anything.
pub async fn preview(
    codec: Codec,
    req: pb::PreviewContainerGroupRemovalRequest,
    names: &[(String, String)],
) -> Resp {
    match containers::details_of_group(&req.key, names).await {
        Err(refusal) => refusal.response(),
        Ok((group, details)) => {
            let plan = build_preview(&group, &details, req.purge_data, req.purge_backups);
            match codec.encode(&plan) {
                Ok(resp) => resp,
                Err(_) => Refusal::EngineUnavailable("could not encode the preview".to_string()).response(),
            }
        }
    }
}

/// Pure, so the whole decision is exercised on a machine with no engine.
pub fn build_preview(
    group: &pb::ContainerGroup,
    details: &[pb::ContainerDetail],
    purge_data: bool,
    purge_backups: bool,
) -> pb::ContainerRemovalPreview {
    let mut out = pb::ContainerRemovalPreview {
        key: group.key.clone(),
        containers: group.containers.iter().map(|c| c.name.clone()).collect(),
        volumes: Vec::new(),
        paths: Vec::new(),
        backup_paths: Vec::new(),
        notes: Vec::new(),
    };

    if purge_data {
        for detail in details {
            for mount in &detail.mounts {
                if mount.source.is_empty() {
                    continue;
                }
                match mount.kind.as_str() {
                    // A bind mount is a host path the stack's author chose, so
                    // it is the one that needs the gate below.
                    "bind" => match deletable(&mount.source) {
                        Ok(()) => push_unique(&mut out.paths, &mount.source),
                        Err(why) => {
                            let note = format!("{} is left alone: {why}", mount.source);
                            push_unique(&mut out.notes, &note);
                        }
                    },
                    // BY NAME — `docker volume rm` rejects the path, and the
                    // failure is a warning, so the volume would survive a
                    // removal the owner asked for.
                    "volume" => push_unique(&mut out.volumes, &crate::container_backup::volume_id(mount)),
                    // tmpfs and anything the engine grows later: nothing on
                    // disk to delete, and guessing would be the quiet kind of
                    // wrong this module exists to avoid.
                    _ => {}
                }
            }
        }
        if out.paths.is_empty() && out.volumes.is_empty() {
            out.notes.push("this group has no data of its own that the host can name".to_string());
        }
    }

    if purge_backups {
        let dir = crate::container_backup_run::backup_root().join(&group.key);
        if dir.exists() {
            out.backup_paths.push(dir.display().to_string());
        } else {
            out.notes.push("this group has no backups taken by this app".to_string());
        }
    }

    out
}

/// May this host path be deleted?
///
/// Two rules, and the second is what makes the first sufficient. A path in the
/// deny-list is refused outright; anything else must be at least two levels
/// deep, because `/anything` at the top level is a system directory whether or
/// not this list happens to name it. Both refusals are NAMED in `notes` — a
/// path silently dropped from a removal is a removal that half happened and
/// said it finished.
fn deletable(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err("it is not an absolute path".to_string());
    }
    if path.contains("..") {
        return Err("it contains ..".to_string());
    }
    let trimmed = path.trim_end_matches('/');
    let trimmed = if trimmed.is_empty() { "/" } else { trimmed };
    if NEVER_DELETED.iter().any(|deny| *deny == trimmed) {
        return Err("it is a system directory".to_string());
    }
    // `/opt/foo` is depth 2 and fine; `/opt` is depth 1 and is not.
    let depth = trimmed.split('/').filter(|part| !part.is_empty()).count();
    if depth < 2 {
        return Err("it sits at the top of the filesystem".to_string());
    }
    Ok(())
}

fn push_unique(into: &mut Vec<String>, value: &str) {
    if !into.iter().any(|existing| existing == value) {
        into.push(value.to_string());
    }
}

/// Remove one group, streaming progress.
pub async fn remove(codec: Codec, req: pb::RemoveContainerGroupRequest, names: Vec<(String, String)>) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("container", &req.key) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let (group, details) = match containers::details_of_group(&req.key, &names).await {
        Ok(pair) => pair,
        Err(refusal) => return refusal.response(),
    };

    let key = group.key.clone();
    let kind = containers::kind_of_group(&group);
    // The file the HOST named — `down` is given it for the same reason `pull`
    // and `up` are: the agent has no working directory, and a compose verb that
    // has to know WHAT the project is made of cannot find it by label alone.
    let compose_file = group.config_files.first().cloned();
    let plan = build_preview(&group, &details, req.purge_data, req.purge_backups);

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);

    tokio::spawn(async move {
        let _claim = claim;
        let sink = RemovalSink {
            tx,
            codec,
            key: key.clone(),
            journal: crate::jobs::Journal::open(pb::JobKind::ContainerRemoval, &key),
        };
        let _ = sink.started(plan.clone()).await;

        let failure = execute(&key, kind, &plan, compose_file.as_deref(), &sink).await.err();

        // Re-read whatever happened. A removal that half happened is exactly
        // what this field exists for: absent group means it is gone, present
        // means containers survived.
        let mut problems: Vec<String> = failure.into_iter().collect();
        match containers::inventory(&names).await {
            Ok(fresh) => {
                let _ = sink.completed(containers::resolve(&fresh, &key).cloned()).await;
            }
            Err(err) => problems.push(format!("status re-read: {err}")),
        }
        if !problems.is_empty() {
            let _ = sink.fail(&problems.join("; ")).await;
        }
    });

    stream_response(json, rx)
}

async fn execute(
    key: &str,
    kind: GroupKind,
    plan: &pb::ContainerRemovalPreview,
    compose_file: Option<&str>,
    sink: &RemovalSink,
) -> Result<(), String> {
    // 1. The containers. `down` for a project (which is what removal MEANS,
    //    and the one place it is correct — `stop` is stop everywhere else in
    //    this section); `rm -f` for a lone container.
    let args: Vec<String> = match kind {
        GroupKind::ComposeProject => {
            let mut args = vec!["compose".to_string(), "-p".to_string(), key.to_string()];
            if let Some(file) = compose_file {
                args.push("-f".to_string());
                args.push(file.to_string());
            }
            args.push("down".to_string());
            args.push("--remove-orphans".to_string());
            args
        }
        GroupKind::Standalone => vec!["rm".into(), "-f".into(), key.to_string()],
    };
    let _ = sink.progress("agent", format!("removing the containers of {key}")).await;
    run_streaming("docker", &args, REMOVE_TIMEOUT_SECS, &sink.tx, &sink.encoder())
        .await
        .map_err(|err| format!("could not remove the containers: {err}"))?;

    // 2. Named volumes, only when asked. After the containers, never before:
    //    the engine refuses to remove a volume still attached, and the refusal
    //    would read as a permissions problem.
    for volume in &plan.volumes {
        let _ = sink.progress("agent", format!("removing volume {volume}")).await;
        let args = vec!["volume".into(), "rm".into(), volume.clone()];
        if let Err(err) = run_streaming("docker", &args, 120, &sink.tx, &sink.encoder()).await {
            // Not fatal: a volume another stack also uses is a volume we must
            // not insist on, and the containers are already gone.
            let _ = sink.progress("agent", format!("WARNING: volume {volume} was left in place: {err}")).await;
        }
    }

    // 3. Host paths and backups, only when asked.
    for path in plan.paths.iter().chain(plan.backup_paths.iter()) {
        // Checked AGAIN here, not only in the preview: the preview is a
        // separate call, and a gate that only runs in the screen that asks is
        // a gate a different caller skips.
        if let Err(why) = deletable(path) {
            let _ = sink.progress("agent", format!("WARNING: {path} was left alone: {why}")).await;
            continue;
        }
        let _ = sink.progress("agent", format!("deleting {path}")).await;
        if let Err(err) = std::fs::remove_dir_all(path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                let _ = sink.progress("agent", format!("WARNING: could not delete {path}: {err}")).await;
            }
        }
    }

    Ok(())
}

struct RemovalSink {
    tx: Sender<Bytes>,
    codec: Codec,
    key: String,
    /// The record this run leaves behind, so a client that closed can ask how
    /// it went — see `crate::jobs`. `None` when the host could not open one,
    /// which costs the reattach and nothing else.
    journal: Option<crate::jobs::Journal>,
}

impl RemovalSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::ContainerRemovalEvent {
        pb::ContainerRemovalEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            key: self.key.clone(),
            text: String::new(),
            stream: String::new(),
            removing: None,
            group: None,
        }
    }

    fn encoder(&self) -> impl Fn(&'static str, String) -> Bytes + Sync + '_ {
        move |stream: &'static str, text: String| {
            let mut event = self.event(pb::ServiceOperationPhase::Progress);
            event.stream = stream.to_string();
            event.text = text;
            envelope(0x00, &self.codec.encode_payload(&event))
        }
    }

    async fn send(&self, event: pb::ContainerRemovalEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, plan: pb::ContainerRemovalPreview) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.removing = Some(plan);
        self.send(event).await
    }

    async fn progress(&self, stream: &'static str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(&self, group: Option<pb::ContainerGroup>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
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

    /// A volume gets a NAME and a PATH that differ, as a real host reports
    /// them: `docker volume rm` takes the name and rejects the path, so a
    /// fixture where both are one string proves nothing about which is used.
    fn mount(kind: &str, source: &str, destination: &str) -> pb::ContainerMount {
        pb::ContainerMount {
            name: if kind == "volume" { source.to_string() } else { String::new() },
            source: if kind == "volume" {
                format!("/var/lib/docker/volumes/{source}/_data")
            } else {
                source.to_string()
            },
            destination: destination.to_string(),
            mode: "rw".to_string(),
            kind: kind.to_string(),
        }
    }

    fn detail(name: &str, mounts: Vec<pb::ContainerMount>) -> pb::ContainerDetail {
        pb::ContainerDetail {
            container: Some(pb::Container {
                name: name.to_string(),
                ..Default::default()
            }),
            created_at: String::new(),
            restart_policy: String::new(),
            compose_project: "stack".to_string(),
            compose_service: name.to_string(),
            command: String::new(),
            env: Vec::new(),
            mounts,
        }
    }

    fn group(key: &str, containers: &[&str]) -> pb::ContainerGroup {
        pb::ContainerGroup {
            key: key.to_string(),
            containers: containers
                .iter()
                .map(|n| pb::Container { name: n.to_string(), ..Default::default() })
                .collect(),
            ..Default::default()
        }
    }

    /// **A bind mount can name ANY host path, because the stack's author chose
    /// it and not us.** So the removal's gate is the difference between
    /// deleting a stack's data directory and deleting `/etc`. Both refusals are
    /// NAMED rather than dropped: a path silently skipped is a removal that
    /// half happened and reported that it finished.
    #[test]
    fn a_system_directory_is_never_deleted_and_the_refusal_is_named() {
        for path in ["/", "/etc", "/home", "/usr", "/var", "/opt", "/root"] {
            assert!(deletable(path).is_err(), "{path} must not be deletable");
        }
        // Depth is what makes the deny-list sufficient: a top-level directory
        // is a system directory whether or not the list happens to name it.
        assert!(deletable("/data").is_err(), "a top-level directory is not deletable");
        assert!(deletable("/opt/mystack/data").is_ok());
        assert!(deletable("/var/lib/mystack").is_ok());
        // Traversal and relative paths are refused outright.
        assert!(deletable("/opt/stack/../../etc").is_err());
        assert!(deletable("relative/path").is_err());

        // And a refused path appears in the notes rather than vanishing.
        let details = vec![detail("app", vec![mount("bind", "/etc", "/host-etc")])];
        let preview = build_preview(&group("stack", &["app"]), &details, true, false);
        assert!(preview.paths.is_empty(), "no system path may be listed for deletion");
        assert!(
            preview.notes.iter().any(|n| n.contains("/etc") && n.contains("system directory")),
            "the refusal must be named: {:?}",
            preview.notes
        );
    }

    /// The toggles are independent, and BOTH default to keeping. A removal that
    /// quietly took the data is the one mistake here that cannot be undone.
    #[test]
    fn data_and_backups_are_separate_toggles_and_default_to_keeping() {
        let details = vec![detail(
            "app",
            vec![mount("bind", "/opt/mystack/data", "/data"), mount("volume", "mystack_db", "/var/lib/postgresql/data")],
        )];
        let g = group("mystack", &["app"]);

        // Neither toggle: the containers go, nothing else is even listed.
        let plain = build_preview(&g, &details, false, false);
        assert_eq!(plain.containers, vec!["app".to_string()]);
        assert!(plain.paths.is_empty() && plain.volumes.is_empty() && plain.backup_paths.is_empty());

        // Data only: paths and volumes, still no backups.
        let with_data = build_preview(&g, &details, true, false);
        assert_eq!(with_data.paths, vec!["/opt/mystack/data".to_string()]);
        assert_eq!(with_data.volumes, vec!["mystack_db".to_string()]);
        assert!(with_data.backup_paths.is_empty());
    }

    /// A tmpfs has nothing on disk, and guessing at it would be the quiet kind
    /// of wrong this whole section is built to avoid.
    #[test]
    fn a_mount_that_is_neither_bind_nor_volume_is_left_alone() {
        let details = vec![detail("app", vec![mount("tmpfs", "/tmp/scratch", "/scratch")])];
        let preview = build_preview(&group("stack", &["app"]), &details, true, false);
        assert!(preview.paths.is_empty() && preview.volumes.is_empty());
    }
}
