//! Updating a group the configurator never installed.
//!
//! The chain is the catalog update wrapper's chain, in the catalog update
//! wrapper's order, and the order is not rearrangeable:
//!
//!   back up → REMEMBER THE IMAGE IDS → pull → recreate → health-check → roll back
//!
//! **The ids are read BEFORE the pull, and that is the whole reason the step
//! exists where it does.** `docker pull` moves the TAG; once it has run, asking
//! "what was running here before" has nobody left to answer. A rollback is
//! `docker tag <old-id> <ref>`, so the id is the only thing that makes one
//! possible at all — and the wrapper learned this the expensive way.
//!
//! **The backup comes first and its failure stops the update.** The catalog's
//! rule, and it matters more here, not less: this is a stack the app did not
//! write, so there is no spec to reconstruct it from if the new image eats its
//! data. `skip_backup` exists because a group with nothing worth keeping should
//! not be forced through one, but it is REFUSED when the plan says a database
//! must be dumped — that is precisely the case where proceeding blind is the
//! expensive mistake.

use std::collections::BTreeMap;

use bytes::Bytes;
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::container_ops::{capture, first_lines, run_streaming};
use crate::containers::{self, GroupKind};
use crate::pb;
use hyper::StatusCode;

const PULL_TIMEOUT_SECS: u64 = 60 * 60;
const RECREATE_TIMEOUT_SECS: u64 = 900;
/// How long the group gets to come back up before the update calls it a failure
/// and rolls back. Long enough for a database to replay a log, short enough
/// that a crash-loop is not mistaken for a slow start.
const HEALTH_DEADLINE_SECS: u64 = 180;
const HEALTH_POLL_SECS: u64 = 5;
/// How many consecutive clean looks the group must give before an update is
/// called good. Three at five seconds apart is ten seconds of quiet — nothing
/// on the scale of an update, and more than any crash loop stays up for.
const HEALTH_SETTLE_SAMPLES: usize = 3;

/// **Nothing at all**, which is a different question from "nothing that
/// exists". This one is answered from the plan alone: a group whose containers
/// hold every byte they need inside their own images has no path, no volume and
/// no database to name. Whether the things a plan DOES name are still on the
/// host is a question for the host, and it is asked where the archive is
/// actually built.
fn plan_names_nothing(plan: &pb::ContainerBackupPlan) -> bool {
    plan.paths.is_empty() && plan.volumes.is_empty() && plan.databases.is_empty()
}

pub async fn run(
    codec: Codec,
    req: pb::UpdateContainerGroupRequest,
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
    let key = group.key.clone();
    let kind = containers::kind_of_group(&group);
    // **The file the HOST named, never one derived from the key.** `pull` and
    // `up` do not find a project by label the way `ps`, `stop` and `start` do —
    // without `-f` they answer "no configuration file provided", and the agent
    // has no working directory of its own (systemd starts it in `/`). Measured
    // on a live host 2026-08-22, which is the only way this shows up: a stubbed
    // docker writes argv and exits 0 either way.
    let compose_file = group.config_files.first().cloned();
    let plan = crate::container_backup::effective(&key, &details, stored);

    // Refused BEFORE the stream opens, like every other precondition here.
    if req.skip_backup && !plan.databases.is_empty() {
        return connect_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "failed_precondition",
            "this group has a database that would be dumped, so its update cannot skip the backup: \
             a new image that migrates a schema is exactly the case a backup is kept for, and this \
             stack has no install recipe to rebuild it from",
        );
    }
    // **An empty plan is refused BEFORE the pull, and the refusal is
    // recognisable** (owner, 2026-09-04). A group that keeps everything inside
    // its images produces a plan naming nothing, the backup then fails with
    // "this plan names nothing that exists on the host", and a failed backup
    // stops the update — correct, and unreadable: the update refuses and the
    // reason offers nothing to do about it.
    //
    // What is NOT done here is treating that as "nothing to archive" and
    // updating anyway. A plan that went empty BY MISTAKE — a volume renamed, a
    // directory gone, a container recreated differently — looks exactly the
    // same from inside the backup, and updating past it destroys data with no
    // copy. So the two cases are separated by WHERE they are answered: a plan
    // that names nothing at all is knowable here, without touching the disk,
    // and is refused with a marker the app turns into an offer; a plan that
    // names things which are not there is still the run-time refusal in
    // `container_backup_run`, and stays one.
    //
    // The marker leads the message, the same convention `session_refusal`
    // uses: both apps have to tell this refusal from every other
    // `failed_precondition` to know whether to offer "update without a
    // backup", and the Connect code alone cannot say which.
    if !req.skip_backup && plan_names_nothing(&plan) {
        return connect_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "failed_precondition",
            "nothing_to_archive: this group stores nothing outside its images — no volume, no              bind mount and no database — so a backup before the update would archive nothing.              Update it without one, or give it a backup plan first",
        );
    }
    // A lone `docker run` container has no compose file, so there is nothing to
    // recreate it FROM: pulling a newer image would leave the old container
    // running and report success. Said plainly rather than half-done.
    if kind == GroupKind::Standalone {
        return connect_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "failed_precondition",
            "this is a single container started outside compose, so the agent cannot recreate it \
             from anything: pulling a newer image would change nothing that is running. Recreate it \
             with whatever started it",
        );
    }

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);

    tokio::spawn(async move {
        let _claim = claim;
        let sink = UpdateSink {
            tx,
            codec,
            key: key.clone(),
            journal: crate::jobs::Journal::open(pb::JobKind::ContainerUpdate, &key),
        };

        // Read the ids FIRST — before the stream even says it started, so that
        // what STARTED reports is what a rollback could actually use.
        let previous = image_ids(&details).await;
        let _ = sink.started(previous.clone()).await;

        let outcome =
            execute(&key, kind, &previous, req.skip_backup, &plan, &details, compose_file.as_deref(), &sink).await;

        let (rolled_back, already_current, failure) = match outcome {
            Ok(Outcome::Updated) => (false, false, None),
            Ok(Outcome::AlreadyCurrent) => (false, true, None),
            Ok(Outcome::RolledBack(why)) => (true, false, Some(why)),
            Err(err) => (false, false, Some(err)),
        };

        let mut problems: Vec<String> = failure.into_iter().collect();
        match containers::inventory(&names).await {
            Ok(fresh) => {
                let group = containers::resolve(&fresh, &key).cloned();
                let _ = sink.completed(rolled_back, already_current, group).await;
            }
            Err(err) => problems.push(format!("status re-read: {err}")),
        }
        if !problems.is_empty() {
            let _ = sink.fail(&problems.join("; ")).await;
        }
    });

    stream_response(json, rx)
}

/// `docker compose -p <key> [-f <file>] <verb…>`.
///
/// The file is included when the host reported one. It is NOT derived from the
/// key: what travels is the string `docker compose ls` printed, the same rule
/// that keeps every other argument on this path host-reported.
fn compose_args(key: &str, compose_file: Option<&str>, verb: &[&str]) -> Vec<String> {
    let mut args = vec!["compose".to_string(), "-p".to_string(), key.to_string()];
    if let Some(file) = compose_file {
        args.push("-f".to_string());
        args.push(file.to_string());
    }
    args.extend(verb.iter().map(|v| v.to_string()));
    args
}

enum Outcome {
    Updated,
    AlreadyCurrent,
    RolledBack(String),
}

#[allow(clippy::too_many_arguments)]
async fn execute(
    key: &str,
    kind: GroupKind,
    previous: &BTreeMap<String, String>,
    skip_backup: bool,
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    compose_file: Option<&str>,
    sink: &UpdateSink,
) -> Result<Outcome, String> {
    if skip_backup {
        let _ = sink.progress("agent", "skipping the backup, as asked".to_string()).await;
    } else {
        // The backup is run through the SAME executor the backup verb uses.
        // A second implementation of "back up a stranger's group" beside it is
        // the drift this section's own notes warn about.
        let _ = sink.progress("agent", "backing up before the pull".to_string()).await;
        // Deliberately not fatal-by-panic: the message travels as the reason
        // the update stopped, which is what the wrapper does too.
        back_up_first(key, kind, plan, details, sink).await?;
    }

    let _ = sink.progress("agent", "pulling newer images".to_string()).await;
    let pull = compose_args(key, compose_file, &["pull"]);
    run_streaming("docker", &pull, PULL_TIMEOUT_SECS, &sink.tx, &sink.encoder())
        .await
        .map_err(|err| format!("pulling failed: {err}"))?;

    // Nothing moved? Then there is nothing to recreate, and saying so is more
    // useful than a restart that looks like an update.
    let after = pulled_ids(previous.keys()).await;
    if !previous.is_empty() && after == *previous {
        let _ = sink.progress("agent", "every image is already the newest published".to_string()).await;
        return Ok(Outcome::AlreadyCurrent);
    }

    let _ = sink.progress("agent", "recreating the containers".to_string()).await;
    let up = compose_args(key, compose_file, &["up", "-d"]);
    if let Err(err) = run_streaming("docker", &up, RECREATE_TIMEOUT_SECS, &sink.tx, &sink.encoder()).await {
        let why = format!("recreating failed: {err}");
        return rollback(key, kind, previous, compose_file, &why, sink).await;
    }

    let _ = sink.progress("agent", "waiting for the group to come back".to_string()).await;
    if let Err(err) = wait_healthy(key, sink).await {
        return rollback(key, kind, previous, compose_file, &err, sink).await;
    }

    Ok(Outcome::Updated)
}

async fn back_up_first(
    key: &str,
    kind: GroupKind,
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    sink: &UpdateSink,
) -> Result<(), String> {
    match crate::container_backup_run::run_for_update(key, kind, plan, details, &sink.tx, &sink.encoder()).await {
        Ok(archive) => {
            let _ = sink.progress("agent", format!("backed up to {}", archive.path)).await;
            Ok(())
        }
        // Fatal, and the wording says why rather than only what: the wrapper's
        // rule is that a failed backup stops the update, and the reason it is
        // worth more here is that this stack has no install recipe.
        Err(err) => Err(format!("the backup before this update failed, so nothing was pulled: {err}")),
    }
}

/// Put the previous images back under the references they had, and recreate.
async fn rollback(
    key: &str,
    _kind: GroupKind,
    previous: &BTreeMap<String, String>,
    compose_file: Option<&str>,
    why: &str,
    sink: &UpdateSink,
) -> Result<Outcome, String> {
    let _ = sink.progress("agent", format!("rolling back: {why}")).await;
    if previous.is_empty() {
        return Err(format!("{why}; and there was no previous image id to roll back to"));
    }
    for (reference, id) in previous {
        let args = vec!["tag".to_string(), id.clone(), reference.clone()];
        if let Err(err) = run_streaming("docker", &args, 120, &sink.tx, &sink.encoder()).await {
            let _ = sink.progress("agent", format!("WARNING: could not restore {reference}: {err}")).await;
        }
    }
    let up = compose_args(key, compose_file, &["up", "-d"]);
    match run_streaming("docker", &up, RECREATE_TIMEOUT_SECS, &sink.tx, &sink.encoder()).await {
        Ok(()) => Ok(Outcome::RolledBack(why.to_string())),
        Err(err) => Err(format!("{why}; and the rollback did not come up either: {err}")),
    }
}

/// image reference → image id, for the containers running right now.
async fn image_ids(details: &[pb::ContainerDetail]) -> BTreeMap<String, String> {
    let mut refs: Vec<String> = Vec::new();
    for detail in details {
        if let Some(container) = detail.container.as_ref() {
            if !container.image.is_empty() && !refs.contains(&container.image) {
                refs.push(container.image.clone());
            }
        }
    }
    pulled_ids(refs.iter()).await
}

async fn pulled_ids<'a>(refs: impl Iterator<Item = &'a String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for reference in refs {
        let args = vec![
            "image".to_string(),
            "inspect".to_string(),
            reference.clone(),
            "--format".to_string(),
            "{{.Id}}".to_string(),
        ];
        if let Ok(res) = capture("docker", &args, 60).await {
            if res.success {
                let id = res.stdout.trim().to_string();
                if !id.is_empty() {
                    out.insert(reference.clone(), id);
                }
            }
        }
    }
    out
}

/// Is every container of the group running, and has none of them fallen into a
/// restart loop?
///
/// **A container that is "up" is not a container that works, and a restart loop
/// is the shape a bad image actually takes** — it is up, then it is not, then
/// it is up again. So the check is not one look but a deadline, and a
/// `Restarting` state is a failure the moment it is seen rather than something
/// to wait out.
///
/// **ONE look is not enough, and that was measured rather than reasoned.** On
/// `vps-middle` (2026-08-25) a group was updated to an image whose entrypoint
/// exits immediately: `docker compose ps` reported it `running` for 1.5s after
/// `up -d` returned, and the check — which accepted its first clean sample —
/// called the update a success and left the host crash-looping on the new
/// image, with no rollback and no error. Worse, a group already in a steady
/// crash loop still answers `running` on roughly one sample in six, because
/// that is what a restart loop IS. Hence two rules, both needed:
///
/// * the group must look clean on `HEALTH_SETTLE_SAMPLES` consecutive looks,
///   which no crash loop survives for long; and
/// * its restart counters must not MOVE across those looks, which is what
///   catches a loop whose up-windows happen to line up with the polls.
async fn wait_healthy(key: &str, sink: &UpdateSink) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(HEALTH_DEADLINE_SECS);
    let mut last;
    let mut clean = 0usize;
    let mut counts_at_first_clean: BTreeMap<String, u64> = BTreeMap::new();
    loop {
        let args = vec![
            "compose".to_string(),
            "-p".to_string(),
            key.to_string(),
            "ps".to_string(),
            "--format".to_string(),
            "{{.Name}} {{.State}}".to_string(),
        ];
        let res = capture("docker", &args, 60).await?;
        if res.success {
            match verdict(&res.stdout) {
                Look::Restarting(who) => {
                    return Err(format!("{who} is restarting in a loop after the update"))
                }
                Look::Running(names) => {
                    // The counters are read on every clean look, because a
                    // loop that ticks between two of them is exactly what a
                    // sequence of "running" answers hides.
                    let counts = restart_counts(&names).await;
                    if clean == 0 {
                        counts_at_first_clean = counts;
                        clean = 1;
                    } else if counts != counts_at_first_clean {
                        let moved: Vec<&str> = counts
                            .iter()
                            .filter(|(name, count)| {
                                counts_at_first_clean.get(*name) != Some(*count)
                            })
                            .map(|(name, _)| name.as_str())
                            .collect();
                        return Err(format!(
                            "{} restarted while the update was watching it",
                            moved.join(", ")
                        ));
                    } else {
                        clean += 1;
                    }
                    if clean >= HEALTH_SETTLE_SAMPLES {
                        return Ok(());
                    }
                    last = String::new();
                }
                Look::Down(who) => {
                    clean = 0;
                    last = who;
                }
            }
        } else {
            clean = 0;
            last = first_lines(res.stderr.trim(), 1);
        }
        if std::time::Instant::now() >= deadline {
            let detail = if last.is_empty() { "the group did not report itself running".to_string() } else { last };
            return Err(format!("after {HEALTH_DEADLINE_SECS}s: {detail}"));
        }
        let _ = sink.progress("agent", "still waiting for the group".to_string()).await;
        tokio::time::sleep(std::time::Duration::from_secs(HEALTH_POLL_SECS)).await;
    }
}

/// What one look at `docker compose ps` says.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Look {
    /// Every container is running; carries their names, for the counters.
    Running(Vec<String>),
    /// At least one is restarting — a failure the moment it is seen.
    Restarting(String),
    /// Nothing is restarting, but something is not up yet; carries who.
    Down(String),
}

/// **Empty output is DOWN, not clean.** A group whose containers are all gone
/// prints nothing, and reading that as "everything is running" is how an update
/// that removed the stack reports success.
pub(crate) fn verdict(stdout: &str) -> Look {
    let mut running: Vec<String> = Vec::new();
    let mut restarting: Vec<&str> = Vec::new();
    let mut down: Vec<&str> = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(state)) = (parts.next(), parts.next()) else { continue };
        match state {
            "running" => running.push(name.to_string()),
            "restarting" => restarting.push(name),
            _ => down.push(name),
        }
    }
    if !restarting.is_empty() {
        return Look::Restarting(restarting.join(", "));
    }
    if !down.is_empty() {
        return Look::Down(down.join(", "));
    }
    if running.is_empty() {
        return Look::Down("the group reported no containers at all".to_string());
    }
    Look::Running(running)
}

/// `<name> <restart count>` for the containers named, as docker reports them.
pub(crate) async fn restart_counts(names: &[String]) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    if names.is_empty() {
        return out;
    }
    let mut args = vec!["inspect".to_string(), "--format".to_string(),
                        "{{.Name}} {{.RestartCount}}".to_string()];
    args.extend(names.iter().cloned());
    if let Ok(res) = capture("docker", &args, 60).await {
        if res.success {
            out = parse_restart_counts(&res.stdout);
        }
    }
    out
}

/// docker prints the name with a leading slash; the group's own strings do not
/// have one, and a map keyed both ways compares unequal for ever.
fn parse_restart_counts(stdout: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(count)) = (parts.next(), parts.next()) else { continue };
        if let Ok(count) = count.parse::<u64>() {
            out.insert(name.trim_start_matches('/').to_string(), count);
        }
    }
    out
}

struct UpdateSink {
    tx: Sender<Bytes>,
    codec: Codec,
    key: String,
    /// The record this run leaves behind, so a client that closed can ask how
    /// it went — see `crate::jobs`. `None` when the host could not open one,
    /// which costs the reattach and nothing else.
    journal: Option<crate::jobs::Journal>,
}

impl UpdateSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::ContainerUpdateEvent {
        pb::ContainerUpdateEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            key: self.key.clone(),
            text: String::new(),
            stream: String::new(),
            previous_images: std::collections::HashMap::new(),
            rolled_back: false,
            already_current: false,
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

    async fn send(&self, event: pb::ContainerUpdateEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, previous: BTreeMap<String, String>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.previous_images = previous.into_iter().collect();
        self.send(event).await
    }

    async fn progress(&self, stream: &'static str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(
        &self,
        rolled_back: bool,
        already_current: bool,
        group: Option<pb::ContainerGroup>,
    ) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.rolled_back = rolled_back;
        event.already_current = already_current;
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

    fn plan(paths: &[&str], volumes: &[&str], databases: usize) -> pb::ContainerBackupPlan {
        pb::ContainerBackupPlan {
            key: "shopdemo".to_string(),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            volumes: volumes.iter().map(|v| v.to_string()).collect(),
            databases: (0..databases)
                .map(|i| pb::ContainerDatabaseDump {
                    container: format!("db-{i}"),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    /// **"Nothing at all" is the only case answered from the plan**, because it
    /// is the only one that can be: a group with no path, no volume and no
    /// database keeps everything inside its images, and that is true before
    /// anybody looks at the disk.
    #[test]
    fn a_plan_naming_no_path_no_volume_and_no_database_names_nothing() {
        assert!(plan_names_nothing(&plan(&[], &[], 0)));
    }

    /// **Each of the three on its own is enough to make it a plan**, and all
    /// three are asserted rather than one: a condition that dropped a term
    /// would call a group with only volumes "nothing to archive" and offer to
    /// update it without a copy — which is the failure this whole refusal
    /// exists to prevent, delivered by the thing meant to prevent it.
    #[test]
    fn any_one_of_the_three_makes_it_a_plan() {
        assert!(!plan_names_nothing(&plan(&["/srv/data"], &[], 0)), "a bind mount was ignored");
        assert!(!plan_names_nothing(&plan(&[], &["shopdemo_db"], 0)), "a volume was ignored");
        assert!(!plan_names_nothing(&plan(&[], &[], 1)), "a database was ignored");
    }

    /// **A plan that names things which are gone is NOT this case.** The
    /// distinction is the owner's decision of 2026-09-04: a volume renamed or a
    /// directory deleted leaves a plan that still names them, and updating past
    /// that would destroy data with no copy. It stays a run-time refusal, from
    /// the host, where the archive is built — so this function must go on
    /// answering "there is a plan" for it.
    #[test]
    fn a_plan_whose_sources_have_vanished_is_still_a_plan() {
        assert!(!plan_names_nothing(&plan(&["/srv/gone"], &["renamed_away"], 0)));
    }

    /// **`pull` and `up` do NOT find a project by label — they need the file.**
    ///
    /// Measured on a live host: `docker compose -p shopdemo pull` run from `/`
    /// answers "no configuration file provided: not found", while `ps`, `stop`
    /// and `start` on the same project work fine. The agent is started in `/`
    /// by systemd, so this is its normal working directory, and a stubbed
    /// docker cannot show the difference — it writes argv and exits 0 whether
    /// or not `-f` is there. That is why this is asserted rather than assumed.
    #[test]
    fn a_compose_verb_that_needs_the_file_is_given_the_one_the_host_named() {
        let with = compose_args("shopdemo", Some("/opt/shopdemo/docker-compose.yml"), &["pull"]);
        assert_eq!(
            with,
            vec!["compose", "-p", "shopdemo", "-f", "/opt/shopdemo/docker-compose.yml", "pull"]
        );

        // Two verbs travel as two arguments, never as one joined string.
        let up = compose_args("shopdemo", Some("/opt/shopdemo/docker-compose.yml"), &["up", "-d"]);
        assert_eq!(up.last().map(String::as_str), Some("-d"));
        assert_eq!(up[up.len() - 2], "up");

        // A host that reported no file still gets a usable command rather than
        // an empty `-f`: some projects genuinely have none recorded, and an
        // argument with a missing value is worse than the older behaviour.
        let without = compose_args("shopdemo", None, &["pull"]);
        assert_eq!(without, vec!["compose", "-p", "shopdemo", "pull"]);
        assert!(!without.iter().any(|a| a == "-f"));
    }

    /// **The two strings a live host actually printed.** Taken from
    /// `vps-middle` on 2026-08-25, sampled every 200ms while a group was
    /// updated to an image that exits on start: `running` for the first 1.5s
    /// after `up -d` returned, `restarting` after that — and `running` again on
    /// roughly one sample in six for as long as the loop ran.
    #[test]
    fn one_look_at_a_crash_loop_can_say_running() {
        assert_eq!(
            verdict("probe-roll-app-1 running\n"),
            Look::Running(vec!["probe-roll-app-1".to_string()])
        );
        assert_eq!(
            verdict("probe-roll-app-1 restarting\n"),
            Look::Restarting("probe-roll-app-1".to_string())
        );
        // Mixed: one restarting container condemns the whole group, whatever
        // its neighbours are doing.
        assert_eq!(
            verdict("a running\nb restarting\n"),
            Look::Restarting("b".to_string())
        );
        assert_eq!(verdict("a running\nb exited\n"), Look::Down("b".to_string()));
        // **Nothing printed is DOWN.** An update that removed the stack must
        // not be able to report success, and "no lines" is what that looks
        // like.
        match verdict("") {
            Look::Down(_) => {}
            other => panic!("empty output read as {other:?}"),
        }
    }

    /// The counter is what catches the loop whose up-windows line up with the
    /// polls. docker prints the name with a leading slash and the group's own
    /// strings do not, so a map keyed straight off that output never compares
    /// equal to itself.
    #[test]
    fn restart_counters_are_read_by_the_name_the_group_uses() {
        let first = parse_restart_counts("/probe-roll-app-1 4\n");
        assert_eq!(first.get("probe-roll-app-1"), Some(&4));
        // A group at rest gives the same map twice — that is what "clean" means
        // and the update proceeds on it.
        assert_eq!(first, parse_restart_counts("/probe-roll-app-1 4\n"));
        // A crash loop does not.
        assert_ne!(first, parse_restart_counts("/probe-roll-app-1 5\n"));
        // Malformed lines are skipped rather than parsed into a zero, which
        // would read as "it stopped restarting".
        assert!(parse_restart_counts("/probe-roll-app-1 not-a-number\n").is_empty());
    }
}
