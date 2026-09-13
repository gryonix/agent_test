//! What a backup of a stranger's container group would actually take.
//!
//! A catalog service answers this from its `BackupSpec`: the app wrote the
//! stack, so it knows which directory holds the data and which client dumps the
//! database. A group the configurator never installed has no such record, and
//! the honest options are exactly two — work it out from what the host can be
//! asked, or ask the owner. The section does BOTH: detection proposes, the
//! owner corrects, and the sheet says which of the two produced each line.
//!
//! **The one thing detection must never do is guess quietly.** Tarring a live
//! database directory produces an archive that restores into a corrupt
//! database, and it does so without a single error at backup time — the failure
//! surfaces months later, at the restore, which is the worst moment there is.
//! So a database that is found and CAN be dumped becomes a dump; a database
//! that is found and cannot becomes `stop_while_archiving`; and either way the
//! reason is written into `notes`.

use crate::pb;

/// Mounts that are plumbing, never data. Archiving the docker socket is
/// archiving a root-equivalent handle; the timezone files are the host's, not
/// the container's.
const NEVER_ARCHIVED: &[&str] = &[
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/etc/localtime",
    "/etc/timezone",
    "/sys",
    "/proc",
    "/dev",
];

/// image substring → engine, and the env vars that engine states its database,
/// user and password in.
///
/// Matched on the image because that is the only self-description a container
/// reliably has: the compose SERVICE name is whatever the author typed (`db`,
/// `database`, `pg`, `store`), and a rule reading it would miss most stacks
/// and misread some.
struct EngineProfile {
    needles: &'static [&'static str],
    engine: pb::ContainerDatabaseEngine,
    database: &'static [&'static str],
    user: &'static [&'static str],
    password: &'static [&'static str],
    /// Where this engine keeps its files, so the tar can skip what the dump
    /// already covers.
    data_dirs: &'static [&'static str],
}

const PROFILES: &[EngineProfile] = &[
    EngineProfile {
        // `postgis` and `timescale` are Postgres with extensions — same client,
        // same variables. A rule matching only "postgres" would tar their data
        // directories live.
        needles: &["postgres", "postgis", "timescale", "pgvector"],
        engine: pb::ContainerDatabaseEngine::Postgres,
        database: &["POSTGRES_DB", "POSTGRESQL_DATABASE"],
        user: &["POSTGRES_USER", "POSTGRESQL_USERNAME"],
        password: &["POSTGRES_PASSWORD", "POSTGRESQL_PASSWORD"],
        data_dirs: &["/var/lib/postgresql/data", "/var/lib/postgresql"],
    },
    EngineProfile {
        needles: &["mariadb"],
        engine: pb::ContainerDatabaseEngine::Mariadb,
        // MariaDB's own image accepts both spellings and so does the catalog's
        // PhotoPrism step, which is why both are listed rather than the newer
        // one alone.
        database: &["MARIADB_DATABASE", "MYSQL_DATABASE"],
        user: &["MARIADB_USER", "MYSQL_USER"],
        password: &["MARIADB_PASSWORD", "MYSQL_PASSWORD", "MARIADB_ROOT_PASSWORD", "MYSQL_ROOT_PASSWORD"],
        data_dirs: &["/var/lib/mysql"],
    },
    EngineProfile {
        needles: &["mysql", "percona"],
        engine: pb::ContainerDatabaseEngine::Mysql,
        database: &["MYSQL_DATABASE"],
        user: &["MYSQL_USER"],
        password: &["MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD"],
        data_dirs: &["/var/lib/mysql"],
    },
    EngineProfile {
        needles: &["mongo"],
        engine: pb::ContainerDatabaseEngine::Mongo,
        database: &["MONGO_INITDB_DATABASE"],
        user: &["MONGO_INITDB_ROOT_USERNAME"],
        password: &["MONGO_INITDB_ROOT_PASSWORD"],
        data_dirs: &["/data/db"],
    },
];

/// Engines that live INSIDE the application's own container rather than beside
/// it. There is nothing to `docker exec` into separately, so the only
/// consistent archive is one taken with the stack stopped.
///
/// SQLite is the common case and it is invisible: it leaves no process, no
/// port and no environment variable — just a file inside a data directory. So
/// it is not detected at all, and that is stated in the notes rather than
/// pretended away.
const EMBEDDED_ENGINE_IMAGES: &[&str] = &["gitlab", "sameersbn/gitlab"];

/// Work out a plan from the group's containers.
///
/// Pure: everything it needs has already been read off the host, which is what
/// lets the whole decision be exercised on a machine with no container engine.
pub fn detect(key: &str, details: &[pb::ContainerDetail]) -> pb::ContainerBackupPlan {
    let mut plan = pb::ContainerBackupPlan {
        key: key.to_string(),
        detected: true,
        ..Default::default()
    };

    let mut covered_dirs: Vec<String> = Vec::new();

    for detail in details {
        let Some(container) = detail.container.as_ref() else { continue };
        let image = container.image.to_lowercase();

        if EMBEDDED_ENGINE_IMAGES.iter().any(|n| image.contains(n)) {
            plan.stop_while_archiving = true;
            plan.notes.push(format!(
                "{}: this image runs its database inside the application container, so the stack is stopped while the archive is taken",
                container.name
            ));
            continue;
        }

        let Some(profile) = PROFILES.iter().find(|p| p.needles.iter().any(|n| image.contains(n)))
        else {
            continue;
        };

        match first_present(&detail.env, profile.password) {
            Some(password_env) => {
                plan.databases.push(pb::ContainerDatabaseDump {
                    container: container.name.clone(),
                    engine: profile.engine as i32,
                    database: first_value(&detail.env, profile.database).unwrap_or_default(),
                    user: first_value(&detail.env, profile.user).unwrap_or_default(),
                    password_env,
                });
                // A dump covers this engine's files, so archiving them live
                // would add a corrupt copy of what the dump already holds.
                for dir in profile.data_dirs {
                    covered_dirs.push(dir.to_string());
                }
                plan.notes.push(format!(
                    "{}: dumped from inside the container; its data directory is left out of the archive",
                    container.name
                ));
            }
            None => {
                // Found an engine, cannot dump it. Stopping the stack is the
                // only consistent archive left — and saying so is the point:
                // a silent live tar here is the failure this module exists for.
                plan.stop_while_archiving = true;
                plan.notes.push(format!(
                    "{}: looks like a database but its password is not in the environment, so the stack is stopped while the archive is taken",
                    container.name
                ));
            }
        }
    }

    for detail in details {
        let Some(container) = detail.container.as_ref() else { continue };
        for mount in &detail.mounts {
            if is_plumbing(&mount.destination) || is_plumbing(&mount.source) {
                continue;
            }
            if covered_dirs.iter().any(|dir| under(&mount.destination, dir)) {
                continue;
            }
            match mount.kind.as_str() {
                "volume" if !volume_id(mount).is_empty() => push_unique(&mut plan.volumes, &volume_id(mount)),
                "bind" if mount.source.starts_with('/') => push_unique(&mut plan.paths, &mount.source),
                // An anonymous volume has no name to archive and no host path.
                // Naming it in the notes is the only useful thing to do: data
                // in one is data the owner is going to lose anyway.
                _ => plan.notes.push(format!(
                    "{}: {} is an anonymous volume and cannot be archived",
                    container.name, mount.destination
                )),
            }
        }
    }

    if plan.paths.is_empty() && plan.volumes.is_empty() && plan.databases.is_empty() {
        plan.notes.push(
            "nothing to archive was found: this group keeps no data outside its container images"
                .to_string(),
        );
    }
    plan
}

/// The plan the client sees: detection, replaced wholesale by the owner's
/// correction when there is one.
///
/// **Replaced, never merged.** A merge would mean the owner cannot REMOVE a
/// path detection proposes — and the reason someone opens this sheet is usually
/// that detection proposed something wrong.
pub fn effective(
    key: &str,
    details: &[pb::ContainerDetail],
    override_plan: Option<pb::ContainerBackupPlan>,
) -> pb::ContainerBackupPlan {
    match override_plan {
        Some(mut plan) => {
            plan.key = key.to_string();
            plan.detected = false;
            plan
        }
        None => detect(key, details),
    }
}

/// Is this container-side path one an engine keeps its files in?
///
/// Used by the RUN to subtract from the tar exactly what a dump already covers:
/// an archive holding both a good dump and a torn live copy of the same
/// database leaves the restore to guess which one is meant.
pub fn is_database_dir(destination: &str) -> bool {
    PROFILES
        .iter()
        .flat_map(|profile| profile.data_dirs.iter())
        .any(|dir| under(destination, dir))
}

fn is_plumbing(path: &str) -> bool {
    NEVER_ARCHIVED.iter().any(|p| path == *p || under(path, p))
}

/// Is `path` inside `dir`? Compared on segment boundaries, so `/var/lib/mysqldata`
/// is NOT inside `/var/lib/mysql` — a prefix match would silently drop a
/// directory that only shares a name.
fn under(path: &str, dir: &str) -> bool {
    path == dir || path.starts_with(&format!("{}/", dir.trim_end_matches('/')))
}

fn push_unique(into: &mut Vec<String>, value: &str) {
    if !into.iter().any(|existing| existing == value) {
        into.push(value.to_string());
    }
}

/// The NAME of the first of these vars the container actually sets. A var set
/// to an empty string counts as absent: an empty password is not a password the
/// dump can use, and treating it as one turns a detectable problem into a
/// failing backup at run time.
fn first_present(env: &[pb::ContainerEnvVar], keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        env.iter()
            .find(|var| var.key == *key && !var.value.is_empty())
            .map(|var| var.key.clone())
    })
}

fn first_value(env: &[pb::ContainerEnvVar], keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        env.iter()
            .find(|var| var.key == *key && !var.value.is_empty())
            .map(|var| var.value.clone())
    })
}

// ──────────────────────────── the owner's correction ─────────────────────────

/// Check an owner-supplied plan before it is stored.
///
/// **The paths in a plan are archived BY ROOT, so an unchecked plan is an
/// "archive any directory on this box" primitive** — the same thing the backup
/// module refuses to accept from a client for catalog services, and the reason
/// it reads the backup root out of the host's own wrapper instead.
///
/// The gate is not "looks like a path". It is a MEMBERSHIP test against what the
/// host itself reported for this group: the bind-mount sources of its
/// containers, its named volumes, and the directories holding its compose files.
/// Which means the correction sheet can do the thing people actually open it for
/// — drop an entry detection got wrong, keep the ones that matter — without ever
/// becoming a way to read somewhere else.
///
/// The compose file's own directory is allowed because it is genuinely worth
/// keeping (it holds `docker-compose.yml` and `.env`) and is often mounted
/// nowhere. It is host-reported, so it costs nothing to allow.
pub fn sanitise(
    mut plan: pb::ContainerBackupPlan,
    group: &pb::ContainerGroup,
    details: &[pb::ContainerDetail],
) -> Result<pb::ContainerBackupPlan, String> {
    let allowed_paths = allowed_paths(group, details);
    for path in &plan.paths {
        if !allowed_paths.iter().any(|allowed| allowed == path) {
            return Err(format!(
                "'{}' is not a path this host reports for that group",
                truncate(path)
            ));
        }
    }

    let allowed_volumes = allowed_volumes(details);
    for volume in &plan.volumes {
        if !allowed_volumes.iter().any(|allowed| allowed == volume) {
            return Err(format!(
                "'{}' is not a volume this host reports for that group",
                truncate(volume)
            ));
        }
    }

    for dump in &plan.databases {
        let Some(detail) = details
            .iter()
            .find(|d| d.container.as_ref().is_some_and(|c| c.name == dump.container))
        else {
            return Err(format!(
                "'{}' is not a container of that group",
                truncate(&dump.container)
            ));
        };
        if pb::ContainerDatabaseEngine::try_from(dump.engine)
            .unwrap_or(pb::ContainerDatabaseEngine::Unspecified)
            == pb::ContainerDatabaseEngine::Unspecified
        {
            return Err(format!("no database engine chosen for '{}'", truncate(&dump.container)));
        }
        // The password is named, never carried — so the name has to be one the
        // container really sets, or the dump would run with an empty password
        // and fail at the worst possible time.
        if !dump.password_env.is_empty()
            && !detail.env.iter().any(|var| var.key == dump.password_env)
        {
            return Err(format!(
                "'{}' does not set an environment variable called '{}'",
                truncate(&dump.container),
                truncate(&dump.password_env)
            ));
        }
    }

    // The notes describe DETECTION. Carrying a client's copy of them back would
    // let the sheet explain a plan by quoting text the client wrote itself.
    plan.notes.clear();
    plan.detected = false;
    plan.key = group.key.clone();
    Ok(plan)
}

/// Every host path this group legitimately has: its containers' bind sources,
/// plus the directories its compose files live in.
fn allowed_paths(group: &pb::ContainerGroup, details: &[pb::ContainerDetail]) -> Vec<String> {
    let mut allowed = Vec::new();
    for detail in details {
        for mount in &detail.mounts {
            if mount.kind == "bind" && mount.source.starts_with('/') && !is_plumbing(&mount.source) {
                push_unique(&mut allowed, &mount.source);
            }
        }
    }
    for file in &group.config_files {
        if let Some((dir, _)) = file.rsplit_once('/') {
            if dir.starts_with('/') {
                push_unique(&mut allowed, dir);
            }
        }
    }
    allowed
}

/// How a named volume is addressed: its NAME, falling back to the path for a
/// host old enough not to report one.
pub fn volume_id(mount: &pb::ContainerMount) -> String {
    if mount.name.is_empty() { mount.source.clone() } else { mount.name.clone() }
}

fn allowed_volumes(details: &[pb::ContainerDetail]) -> Vec<String> {
    let mut allowed = Vec::new();
    for detail in details {
        for mount in &detail.mounts {
            if mount.kind == "volume" {
                // BY NAME: that is what `docker volume inspect` takes when the
                // run resolves this to a path, and what the owner sees.
                let id = volume_id(mount);
                if !id.is_empty() {
                    push_unique(&mut allowed, &id);
                }
            }
        }
    }
    allowed
}

/// Client strings are echoed back so a mistake is diagnosable, but only a
/// bounded prefix: the message travels into logs and UI.
fn truncate(value: &str) -> String {
    value.chars().take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(name: &str, image: &str, env: &[(&str, &str)], mounts: &[(&str, &str, &str, bool)]) -> pb::ContainerDetail {
        pb::ContainerDetail {
            container: Some(pb::Container {
                name: name.to_string(),
                image: image.to_string(),
                state: "running".to_string(),
                ..Default::default()
            }),
            env: env
                .iter()
                .map(|(k, v)| pb::ContainerEnvVar {
                    key: k.to_string(),
                    value: v.to_string(),
                    sensitive: false,
                })
                .collect(),
            mounts: mounts
                .iter()
                .map(|(kind, source, destination, rw)| pb::ContainerMount {
                    kind: kind.to_string(),
                    // A volume fixture carries a NAME and a PATH that differ,
                    // exactly as a real host reports them — a fixture where
                    // both are the same string would pass whichever one the
                    // code picked.
                    name: if *kind == "volume" { source.to_string() } else { String::new() },
                    // An EMPTY source in a fixture means "anonymous" — no name
                    // and nothing to address it by — so it must stay empty on
                    // both fields. A named one gets the two different strings a
                    // real host reports.
                    source: if *kind == "volume" && !source.is_empty() {
                        format!("/var/lib/docker/volumes/{source}/_data")
                    } else {
                        source.to_string()
                    },
                    destination: destination.to_string(),
                    mode: if *rw { "rw".into() } else { "ro".into() },
                })
                .collect(),
            ..Default::default()
        }
    }

    /// The whole reason this module exists: a live tar of a database directory
    /// restores into a corrupt database, and it does so with no error at backup
    /// time. Detecting the engine means the dump replaces the directory, not
    /// joins it.
    #[test]
    fn a_database_becomes_a_dump_and_leaves_its_directory_out_of_the_archive() {
        let details = vec![
            detail(
                "stack-db-1",
                "postgres:16-alpine",
                &[("POSTGRES_DB", "app"), ("POSTGRES_USER", "app"), ("POSTGRES_PASSWORD", "s3cret")],
                &[("bind", "/srv/stack/pg", "/var/lib/postgresql/data", true)],
            ),
            detail(
                "stack-web-1",
                "nginx:1.27",
                &[],
                &[("bind", "/srv/stack/files", "/data", true)],
            ),
        ];
        let plan = detect("stack", &details);

        assert_eq!(plan.databases.len(), 1);
        assert_eq!(plan.databases[0].engine, pb::ContainerDatabaseEngine::Postgres as i32);
        assert_eq!(plan.databases[0].database, "app");
        // The NAME travels, never the value: `docker exec` argv is readable
        // through /proc by any account on the box.
        assert_eq!(plan.databases[0].password_env, "POSTGRES_PASSWORD");
        assert!(!plan.databases[0].password_env.contains("s3cret"));

        assert_eq!(plan.paths, vec!["/srv/stack/files".to_string()]);
        assert!(!plan.stop_while_archiving);
    }

    /// Postgres with extensions is still Postgres. A rule matching only the
    /// word "postgres" would tar these live.
    #[test]
    fn postgres_flavours_are_postgres() {
        for image in ["postgis/postgis:16-3.4", "timescale/timescaledb:latest-pg16", "pgvector/pgvector:pg16"] {
            let details = vec![detail("db", image, &[("POSTGRES_PASSWORD", "x")], &[])];
            let plan = detect("g", &details);
            assert_eq!(plan.databases.len(), 1, "{image}");
            assert_eq!(plan.databases[0].engine, pb::ContainerDatabaseEngine::Postgres as i32);
        }
    }

    /// An engine we can see but cannot dump is the dangerous case, and the
    /// answer is to stop the stack and SAY SO — never to tar it live and stay
    /// quiet, which is a backup that fails only at the restore.
    #[test]
    fn a_database_without_a_password_stops_the_stack_and_says_why() {
        let details = vec![detail(
            "db",
            "mariadb:11",
            &[("MARIADB_DATABASE", "app")],
            &[("bind", "/srv/x/mysql", "/var/lib/mysql", true)],
        )];
        let plan = detect("g", &details);

        assert!(plan.databases.is_empty());
        assert!(plan.stop_while_archiving);
        assert!(plan.notes.iter().any(|n| n.contains("password is not in the environment")));
        // Its directory is still archived — with the stack stopped that is the
        // consistent copy, and dropping it would back up nothing at all.
        assert_eq!(plan.paths, vec!["/srv/x/mysql".to_string()]);
    }

    /// An empty password is not a password the dump can use. Treating it as one
    /// turns something detectable now into a backup that fails at run time.
    #[test]
    fn an_empty_password_counts_as_absent() {
        let details = vec![detail("db", "postgres:16", &[("POSTGRES_PASSWORD", "")], &[])];
        let plan = detect("g", &details);
        assert!(plan.databases.is_empty());
        assert!(plan.stop_while_archiving);
    }

    /// Archiving the docker socket is archiving a root-equivalent handle.
    #[test]
    fn plumbing_mounts_are_never_archived() {
        let details = vec![detail(
            "watchtower",
            "containrrr/watchtower",
            &[],
            &[
                ("bind", "/var/run/docker.sock", "/var/run/docker.sock", true),
                ("bind", "/etc/localtime", "/etc/localtime", false),
                ("bind", "/srv/keep", "/keep", true),
            ],
        )];
        let plan = detect("g", &details);
        assert_eq!(plan.paths, vec!["/srv/keep".to_string()]);
    }

    /// `/var/lib/mysqldata` only SHARES A NAME with `/var/lib/mysql`. A prefix
    /// match would drop it from the archive silently.
    #[test]
    fn a_directory_that_merely_shares_a_name_is_not_inside_it() {
        assert!(under("/var/lib/mysql/x", "/var/lib/mysql"));
        assert!(under("/var/lib/mysql", "/var/lib/mysql"));
        assert!(!under("/var/lib/mysqldata", "/var/lib/mysql"));
    }

    #[test]
    fn a_named_volume_is_listed_as_a_volume_and_an_anonymous_one_is_named_in_the_notes() {
        let details = vec![detail(
            "app",
            "someapp:1",
            &[],
            &[
                ("volume", "appdata", "/data", true),
                ("volume", "", "/scratch", true),
            ],
        )];
        let plan = detect("g", &details);
        assert_eq!(plan.volumes, vec!["appdata".to_string()]);
        assert!(plan.notes.iter().any(|n| n.contains("anonymous volume")));
    }

    /// "Nothing was found" is a conclusion the sheet has to state. A blank plan
    /// with no note reads as a screen that failed to load.
    #[test]
    fn finding_nothing_is_said_out_loud() {
        let details = vec![detail("app", "someapp:1", &[], &[])];
        let plan = detect("g", &details);
        assert!(plan.paths.is_empty() && plan.volumes.is_empty() && plan.databases.is_empty());
        assert!(plan.notes.iter().any(|n| n.contains("nothing to archive")));
    }

    // ─────────────────────────────── the gate ───────────────────────────────

    fn group_with(key: &str, config_files: &[&str]) -> pb::ContainerGroup {
        pb::ContainerGroup {
            key: key.to_string(),
            config_files: config_files.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// A plan is archived BY ROOT, so an unchecked path is an "archive any
    /// directory on this box" primitive. Membership against what the host
    /// reported is the gate — not "looks like a path".
    #[test]
    fn a_path_the_host_never_reported_is_refused() {
        let group = group_with("stack", &["/srv/stack/docker-compose.yml"]);
        let details = vec![detail("web", "nginx", &[], &[("bind", "/srv/stack/files", "/data", true)])];

        let ok = pb::ContainerBackupPlan { paths: vec!["/srv/stack/files".into()], ..Default::default() };
        assert!(sanitise(ok, &group, &details).is_ok());

        for hostile in ["/etc", "/root/.ssh", "/", "/var/lib/gryonixnexus"] {
            let plan = pb::ContainerBackupPlan { paths: vec![hostile.into()], ..Default::default() };
            assert!(sanitise(plan, &group, &details).is_err(), "{hostile} must be refused");
        }
    }

    /// The compose file's directory holds `docker-compose.yml` and `.env` and is
    /// often mounted nowhere — worth keeping, and host-reported, so allowing it
    /// costs nothing.
    #[test]
    fn the_compose_directory_is_allowed_because_the_host_named_it() {
        let group = group_with("stack", &["/srv/stack/docker-compose.yml"]);
        let details = vec![detail("web", "nginx", &[], &[])];
        let plan = pb::ContainerBackupPlan { paths: vec!["/srv/stack".into()], ..Default::default() };
        assert!(sanitise(plan, &group, &details).is_ok());
    }

    #[test]
    fn a_dump_must_name_a_container_of_this_group_and_a_variable_it_sets() {
        let group = group_with("stack", &[]);
        let details = vec![detail("stack-db-1", "postgres:16", &[("POSTGRES_PASSWORD", "x")], &[])];
        let dump = |container: &str, env: &str| pb::ContainerBackupPlan {
            databases: vec![pb::ContainerDatabaseDump {
                container: container.into(),
                engine: pb::ContainerDatabaseEngine::Postgres as i32,
                password_env: env.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(sanitise(dump("stack-db-1", "POSTGRES_PASSWORD"), &group, &details).is_ok());
        assert!(sanitise(dump("someone-elses-db", "POSTGRES_PASSWORD"), &group, &details).is_err());
        assert!(sanitise(dump("stack-db-1", "NOT_SET_HERE"), &group, &details).is_err());
    }

    /// An engine left unchosen is refused rather than defaulted: a dump run with
    /// the wrong client produces an empty file and calls it a backup.
    #[test]
    fn an_unchosen_engine_is_refused() {
        let group = group_with("stack", &[]);
        let details = vec![detail("db", "postgres:16", &[], &[])];
        let plan = pb::ContainerBackupPlan {
            databases: vec![pb::ContainerDatabaseDump { container: "db".into(), ..Default::default() }],
            ..Default::default()
        };
        assert!(sanitise(plan, &group, &details).is_err());
    }

    /// A correction REPLACES detection rather than merging with it — otherwise
    /// the owner cannot remove a path detection proposed, which is the commonest
    /// reason to open the sheet at all.
    #[test]
    fn a_correction_replaces_detection_rather_than_merging() {
        let details = vec![detail("web", "nginx", &[], &[("bind", "/srv/a", "/a", true)])];
        let override_plan = pb::ContainerBackupPlan { paths: vec!["/srv/b".into()], ..Default::default() };

        let plan = effective("g", &details, Some(override_plan));
        assert_eq!(plan.paths, vec!["/srv/b".to_string()]);
        assert!(!plan.detected);

        let detected = effective("g", &details, None);
        assert_eq!(detected.paths, vec!["/srv/a".to_string()]);
        assert!(detected.detected);
    }

    /// "Back up nothing" is a real instruction, and it must survive the round
    /// trip as itself rather than turning back into detection.
    #[test]
    fn an_empty_correction_means_back_up_nothing_not_go_back_to_detecting() {
        let details = vec![detail("web", "nginx", &[], &[("bind", "/srv/a", "/a", true)])];
        let plan = effective("g", &details, Some(pb::ContainerBackupPlan::default()));
        assert!(plan.paths.is_empty());
        assert!(!plan.detected);
    }
}
