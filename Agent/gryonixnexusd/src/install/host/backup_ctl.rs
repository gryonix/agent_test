//! Port of `BackupControlSections` — `/opt/gryonixnexus-backup-ctl.sh`.
//!
//! One root-owned wrapper for everything that makes or manages a backup: the
//! per-service backup bodies, the schedule that drives them, deleting one
//! backup, and the size estimate the app shows before a long run. Same three
//! rules as every file in `install::host` (see that module's doc): byte
//! parity with the Swift generator, rebuilt from the WHOLE installed set on
//! every install (never just the service being installed), and nothing here
//! widens the sandbox silently.
//!
//! **One wrapper, not a sudoers line per service.** A backup needs `tar`,
//! `pg_dump`, `mysqldump` and container stop/start; whitelisting those with
//! free arguments hands the control account uid 0 (`tar
//! --use-compress-program` runs anything) — the mistake ARCHITECTURE.md
//! already records once for a single `/bin/tar` entry. This script validates
//! its own input instead.
//!
//! **One body per service, called by both callers.** The timer's `run` and
//! the app's `backup <service>` dispatch into the same generated function —
//! the per-service bodies used to exist twice (Swift history), which is the
//! drift this project keeps paying for.
//!
//! **Every dispatch to a service body is lock-guarded** (`super::lock`): the
//! timer and a manual `backup <id>` are two independent processes reaching
//! the SAME containers.
//!
//! **Catalog order, not request order.** `HostInput.services` is SORTED
//! (mod.rs's own doc), which is an equality/dedup convenience, not a
//! rendering order — the Swift generator always walks `ServiceRegistry.all`
//! (the mail engine first, then every other service in the catalog's fixed
//! order), and this port reorders into that same fixed order before building
//! `case` arms. Getting this wrong would still pass every fixture with only
//! ONE selected service and fail silently the moment two are combined in an
//! order the alphabetically-sorted input does not already happen to match.
//!
//! **The agent collapses five VPN pieces into one id `vpn`, but the wrapper's
//! own `case` label has always been `"vpn-panel"`.** The Swift generator
//! auto-injects `VPNPanelService` (not any protocol container — none of the
//! five protocols declare a `BackupSpec` of their own) the moment any VPN
//! protocol is selected, and that service's `wrapperTarget` is
//! `ServiceID.vpnPanel.rawValue == "vpn-panel"`. Emitting `"vpn"` instead
//! would silently disagree with `LockSections`' namespace
//! (`backup-vpn-panel`) and with every fixture, none of which ever say
//! `"vpn"`.
//!
//! **`OWNER` when there is no SSH control user is new territory, not a port.**
//! Swift only ever generates this wrapper when `DashboardAccessInput` exists
//! (`DashboardAccessSections.swift`'s call site), so `access.sshUser` is never
//! absent there. The agent writes this wrapper unconditionally (mod.rs rule:
//! "the agent is root ... no sudo appears anywhere"), so `HostInput.ssh_user`
//! can genuinely be `None` on an agent-only host. Falling back to `"root"` is
//! the only owner that is always correct — the agent itself runs as root and
//! created the file — and it changes nothing observable: the enclosing
//! directory's `0750` is what actually keeps other accounts out (the
//! `OWNER` field's own comment, ported verbatim below), `chown` here is a
//! convenience for the one caller (the app) that DOES have a control user.

use crate::install::host::{lock, HostInput};
// The compose project names come from the installers themselves rather than
// from literals here: `gd_compose_stop` has to name the project docker really
// created, and two spellings of it would be a backup that quiesces nothing.
use crate::install::{authelia, headscale, homepage, pihole};

/// Where the wrapper lives on disk.
pub const SCRIPT_PATH: &str = "/opt/gryonixnexus-backup-ctl.sh";
pub const DONE_MARKER: &str = "GRYONIXNEXUS_BACKUP_CTL_DONE";
/// Printed by a finished backup: `<marker> <bytes> <path>`. A streamed
/// command carries no exit status, so this is what tells the app the archive
/// exists.
pub const BACKUP_DONE_MARKER: &str = "GRYONIXNEXUS_BACKUP_DONE";
/// Printed by `estimate`: `<marker> <data bytes> <free bytes>`.
pub const ESTIMATE_MARKER: &str = "GRYONIXNEXUS_BACKUP_ESTIMATE";
pub const CONFIG_DIRECTORY: &str = "/etc/gryonixnexus";
pub const CONFIG_PATH: &str = "/etc/gryonixnexus/autobackup.conf";
pub const PASSPHRASE_PATH: &str = "/etc/gryonixnexus/autobackup.pass";
pub const TIMER_NAME: &str = "gryonixnexus-autobackup.timer";
pub const SERVICE_NAME: &str = "gryonixnexus-autobackup.service";

/// `DashboardAccessInput.backupRetention`'s default. `install::context::Input`
/// carries no override for it — no caller has ever threaded a non-default
/// retention through an agent request, the same "default lives on the Swift
/// struct, not reproduced as a knob here" call every other unconfigurable
/// setting in this crate makes.
const DEFAULT_RETENTION: u32 = 7;

/// `ArchiveBackupPlan.dumpDirectoryName` — fixed, so a restore of an archive
/// made by an older build still finds the dumps inside it.
const DUMP_DIRECTORY_NAME: &str = "gryonixnexus-db";

#[derive(Clone, Copy)]
enum Engine {
    Postgres,
    Mysql,
}

struct Database {
    engine: Engine,
    service: &'static str,
    file_name: &'static str,
    /// `BackupDatabase.databaseName` — spelled out only for a service that
    /// owns several databases in one engine (Seafile); `None` lets the dump
    /// helper fall back to the container's own `MYSQL_DATABASE`/`POSTGRES_DB`.
    database_name: Option<&'static str>,
}

/// One backup-capable service, resolved from the catalog id: its wrapper
/// label, where its archives go, whether a run encrypts unless told
/// otherwise, what the estimate measures, and the bash that performs one
/// backup — mirrors `BackupControlSections.AutoBackupTarget` field for field.
struct Target {
    /// The `case` label — `BackupWrapperSpec.wrapperTarget`. NOT always the
    /// agent's own catalog id (see the module doc: `"vpn"` renders as
    /// `"vpn-panel"`).
    id: String,
    backup_dir: String,
    encrypts_by_default: bool,
    size_paths: Vec<String>,
    body: String,
}

/// Bash function name for a service label (`vpn-panel` → `vpn_panel`).
fn function_name(id: &str) -> String {
    id.replace('-', "_")
}

/// Quotes a path for bash but keeps a glob `*` OUTSIDE the quotes so it still
/// expands — mirrors `BackupControlSections.quotedPath`. Splitting on `*`
/// keeps empty subsequences (mailcow's single trailing glob produces a
/// trailing empty segment that must contribute nothing).
fn quoted_path(path: &str) -> String {
    path.split('*')
        .map(|part| if part.is_empty() { String::new() } else { format!("'{part}'") })
        .collect::<Vec<_>>()
        .join("*")
}

/// Last path component, ignoring a trailing slash — used to build the
/// `--exclude` patterns for the services whose excludes are relative to a
/// configurable path (mirrors `<Service>.archiveSlot`).
fn last_component(path: &str) -> String {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or(path).to_string()
}

/// `ArchiveBackupPlan.dataParent`/`.dataSlot`: the directory `dataPath` sits
/// in (for `tar -C`) and its own last component (the archive member name).
fn split_data_path(data_path: &str) -> (String, String) {
    let trimmed = data_path.trim_end_matches('/');
    let parent = match trimmed.rfind('/') {
        Some(0) => "/".to_string(),
        Some(idx) => trimmed[..idx].to_string(),
        None => "/".to_string(),
    };
    let slot = trimmed.rsplit('/').next().unwrap_or(trimmed).to_string();
    (parent, slot)
}

/// The body of one generated `backup_<service>` function for the `.archive`
/// shape — mirrors `BackupControlSections.archiveBody` line for line. A
/// database is NEVER tarred: it is dumped through its own client, which is
/// why `databases` is separate from `data_path`.
fn archive_body(
    id: &str,
    backup_dir: &str,
    compose_project: &str,
    data_path: &str,
    databases: &[Database],
    quiesce: &[&str],
    excludes: &[String],
) -> String {
    let mut lines: Vec<String> = vec![
        "  local stamp work plain rc=0".to_string(),
        format!("  install -d -m 750 '{backup_dir}'"),
        "  stamp=\"$(date +%Y%m%d-%H%M%S)\"".to_string(),
        format!("  work=\"$(mktemp -d '{backup_dir}/.work-XXXXXX')\""),
        format!("  plain=\"$work/{id}-$stamp.tar.gz\""),
        format!("  install -d -m 700 \"$work/{DUMP_DIRECTORY_NAME}\""),
        format!("  if [ ! -d '{data_path}' ]; then"),
        "    rm -rf \"$work\"".to_string(),
        format!("    echo \"{id} has no data at {data_path}\" >&2"),
        "    return 1".to_string(),
        "  fi".to_string(),
    ];

    if !quiesce.is_empty() {
        let quoted = quiesce.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(" ");
        lines.push("  # Stopped for the archive only, and started again on EVERY path".to_string());
        lines.push("  # below — a backup that leaves the service down is an outage.".to_string());
        lines.push(format!("  gd_compose_stop '{compose_project}' {quoted}"));
    }

    for db in databases {
        let helper = match db.engine {
            Engine::Postgres => "gd_dump_postgres",
            Engine::Mysql => "gd_dump_mysql",
        };
        let named = db.database_name.map(|n| format!(" '{n}'")).unwrap_or_default();
        let service = db.service;
        let file_name = db.file_name;
        lines.push(format!(
            "  {helper} '{compose_project}' '{service}' \"$work/{DUMP_DIRECTORY_NAME}/{file_name}\"{named} || rc=1"
        ));
    }

    let excludes_str: String = excludes.iter().map(|e| format!(" --exclude '{e}'")).collect();
    let (data_parent, data_slot) = split_data_path(data_path);
    lines.push("  if [ \"$rc\" -eq 0 ]; then".to_string());
    lines.push(format!("    tar --numeric-owner -czf \"$plain\"{excludes_str} \\"));
    lines.push(format!("        -C '{data_parent}' '{data_slot}' \\"));
    lines.push(format!("        -C \"$work\" '{DUMP_DIRECTORY_NAME}' || rc=1"));
    lines.push("  fi".to_string());

    if !quiesce.is_empty() {
        let quoted = quiesce.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(" ");
        lines.push(format!("  gd_compose_start '{compose_project}' {quoted}"));
    }

    lines.push("  if [ \"$rc\" -ne 0 ]; then".to_string());
    lines.push("    rm -rf \"$work\"".to_string());
    lines.push(format!("    echo \"{id} backup failed\" >&2"));
    lines.push("    return 1".to_string());
    lines.push("  fi".to_string());
    lines.push(format!("  gd_finish '{id}' '{backup_dir}' \"$plain\" \"$work\""));

    lines.join("\n")
}

/// Vaultwarden's `.encryptedVolume` body — deliberately NOT the generated
/// archive shape (see `BackupControlSections`'s own comment: this is the
/// stop → tar → encrypt → start sequence that was live-verified, and the app
/// still drives its own interactive copy of it). Built with plain
/// concatenation rather than `format!`: the bash contains a literal
/// `{ ...; }` brace group, which `format!` would otherwise need escaped as
/// `{{`/`}}` throughout — a much easier place to introduce a byte-level
/// mistake than a few extra `push_str` calls.
fn vaultwarden_body(container: &str, data_path: &str, backup_dir: &str) -> String {
    let mut s = String::new();
    s.push_str("  local stamp plain\n");
    s.push_str("  stamp=\"$(date +%Y%m%d-%H%M%S)\"\n");
    s.push_str("  plain='");
    s.push_str(backup_dir);
    s.push_str("/vaultwarden-backup.tar.gz'\n");
    s.push_str("  docker stop '");
    s.push_str(container);
    s.push_str("' >/dev/null 2>&1 || true\n");
    s.push_str("  tar -czf \"$plain\" '");
    s.push_str(data_path);
    s.push_str("' 2>/dev/null || true\n");
    s.push_str("  # The container comes back up no matter what the archive did.\n");
    s.push_str("  docker start '");
    s.push_str(container);
    s.push_str("' >/dev/null 2>&1 || true\n");
    s.push_str("  [ -s \"$plain\" ] || { echo \"vaultwarden archive is empty\" >&2; return 1; }\n");
    s.push_str("  if ! printf '%s' \"$GD_PASS\" | gpg --batch --quiet --yes --symmetric \\\n");
    s.push_str("       --cipher-algo AES256 --passphrase-fd 0 --pinentry-mode loopback \\\n");
    s.push_str("       --output \"$plain.$stamp.gpg\" \"$plain\"; then\n");
    s.push_str("    rm -f \"$plain\"\n");
    s.push_str("    echo \"could not encrypt the vaultwarden backup\" >&2\n");
    s.push_str("    return 1\n");
    s.push_str("  fi\n");
    s.push_str("  # The plain archive never outlives the encrypted one.\n");
    s.push_str("  rm -f \"$plain\"\n");
    s.push_str("  chmod 600 \"$plain.$stamp.gpg\"\n");
    s.push_str("  chown \"$OWNER\" \"$plain.$stamp.gpg\" 2>/dev/null || true\n");
    s.push_str("  # Rotation: keep the newest RETENTION encrypted archives. The\n");
    s.push_str("  # pipeline is guarded — with fewer archives than RETENTION,\n");
    s.push_str("  # `ls` finds nothing to list and would fail the whole run\n");
    s.push_str("  # under pipefail (which is every first run).\n");
    s.push_str("  { ls -1t '");
    s.push_str(backup_dir);
    s.push_str("'/*.gpg 2>/dev/null || true; } \\\n");
    s.push_str("    | tail -n +$((RETENTION + 1)) | xargs -r rm -f\n");
    s.push_str("  printf '%s %s %s\\n' '");
    s.push_str(BACKUP_DONE_MARKER);
    s.push_str("' \\\n");
    s.push_str("    \"$(stat -c %s \"$plain.$stamp.gpg\" 2>/dev/null || echo 0)\" \"$plain.$stamp.gpg\"");
    s
}

/// Every backup-capable service actually on this host, mirroring
/// `BackupControlSections.targets` — one `if` per service instead of
/// iterating `ServiceRegistry.all`, because each service's plan is a
/// distinct shape in Swift too (three different `case`s of
/// `BackupPlan`/`.backup`). **The order these `if`s appear in below IS the
/// rendering order** (`ServiceRegistry.all`: the mail engines first, then
/// every other service in the catalog's fixed order — see the module doc's
/// "Catalog order, not request order"); the five VPN protocol containers are
/// absent because none of them declare a `BackupSpec` of their own, only the
/// panel does (the last `if`, keyed on the agent's collapsed `"vpn"` id).
/// Every catalog id whose service declares a backup, as the wrapper labels
/// them.
///
/// **Data, and duplicated on purpose.** The Swift generator does not have a
/// list like this: it walks the catalog and renders an arm for whatever
/// declares a `BackupSpec`, so a new service arrives on the SSH route by
/// declaring itself. This port is a chain of `if has(...)` blocks, which means
/// the same service arrives here only if somebody edits this file — and nothing
/// notices until a host set up by the agent is asked to back it up, which is
/// months later and on somebody's server. Four services lived in exactly that
/// gap (pihole, homepage, authelia, headscale).
///
/// So the list is stated once here and once in Swift
/// (`BackupWrapperContractTests`), the same two-sided pinning the
/// `GRYONIXNEXUS_*` markers use — a musl binary and a Swift package cannot share
/// a source of truth in either direction. Adding a service to the catalog now
/// fails on the Swift side (its set no longer matches) and adding an id here
/// without an arm fails on this one.
pub const BACKUP_CAPABLE_SERVICE_IDS: &[&str] = &[
    "mailcow",
    "mailu",
    "docker-mailserver",
    "vaultwarden",
    "psono",
    "passbolt",
    "nextcloud",
    "seafile",
    "immich",
    "photoprism",
    "forgejo",
    "gitlab",
    "jellyfin",
    "minecraft-java",
    "minecraft-bedrock",
    "crafty-controller",
    "adguard-home",
    "pihole",
    "homepage",
    "authelia",
    "headscale",
    // The panel, which the agent reaches through the collapsed `vpn` group —
    // see the module doc for why its label is `vpn-panel` and never `vpn`.
    "vpn-panel",
    // The chat and the gateway. `ollama` is deliberately NOT here: what lives
    // under its path is models — published files, identical on every machine
    // that fetches them — so an archive of it would be tens of gigabytes
    // duplicating something one command downloads again. The conversations
    // worth keeping are the chat's, and the gateway's routing table and master
    // key are the two files that cannot be worked out again.
    "open-webui",
    // The retrieval pair: the documents and their embeddings are the one thing
    // on this shelf that cannot be fetched again. Placed around the gateway
    // because this list follows `CATALOG_ORDER`, which a test asserts.
    "anythingllm",
    "litellm",
    "qdrant",
    // The assistant's paired sessions. `searxng` is deliberately NOT here, and
    // it is the same distinction `ollama` draws one line up: what lives under
    // its path is a settings file this crate writes and a cache it can fetch
    // again, so there is no state a restore could bring back.
    "openclaw",
    "n8n",
];

fn build_targets(input: &HostInput) -> Vec<Target> {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);
    let mut result = Vec::new();

    if has("mailcow") {
        let path = p.mailcow_path.clone();
        result.push(Target {
            id: "mailcow".to_string(),
            backup_dir: "/opt/backups/mailcow".to_string(),
            // externalScript is never encrypted by default — mailcow's own
            // bot-backup.sh owns that decision.
            encrypts_by_default: false,
            size_paths: vec![path.clone(), "/var/lib/docker/volumes/mailcowdockerized_*".to_string()],
            body: format!("  '{path}/bot-backup.sh'"),
        });
    }

    if has("mailu") {
        let path = p.mailu_path.clone();
        let backup_dir = "/opt/backups/mailu".to_string();
        let slot = last_component(&path);
        let quiesce = ["front", "admin", "imap", "smtp", "antispam", "webmail", "redis", "resolver"];
        let excludes = vec![format!("{slot}/filter"), format!("{slot}/mailqueue")];
        let body = archive_body("mailu", &backup_dir, "mailu", &path, &[], &quiesce, &excludes);
        result.push(Target {
            id: "mailu".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![format!("{path}/mail"), format!("{path}/data"), format!("{path}/webmail")],
            body,
        });
    }

    if has("docker-mailserver") {
        let path = p.docker_mailserver_path.clone();
        let backup_dir = "/opt/backups/docker-mailserver".to_string();
        let slot = last_component(&path);
        let quiesce = ["mailserver", "webmail"];
        let excludes = vec![format!("{slot}/mail-logs")];
        let body = archive_body("docker-mailserver", &backup_dir, "dockermailserver", &path, &[], &quiesce, &excludes);
        result.push(Target {
            id: "docker-mailserver".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![format!("{path}/mail-data"), format!("{path}/config")],
            body,
        });
    }

    if has("vaultwarden") {
        let container = p.vaultwarden_container.clone();
        let data_path = p.vaultwarden_data_path.clone();
        let backup_dir = "/opt/backups/vaultwarden".to_string();
        let body = vaultwarden_body(&container, &data_path, &backup_dir);
        result.push(Target {
            id: "vaultwarden".to_string(),
            backup_dir,
            // The password store: an unencrypted copy on disk would defeat
            // the service it came from.
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("psono") {
        let path = p.psono_path.clone();
        let backup_dir = "/opt/backups/psono".to_string();
        let data_path = format!("{path}/config");
        let databases =
            [Database { engine: Engine::Postgres, service: "db", file_name: "psono.sql", database_name: None }];
        let body = archive_body("psono", &backup_dir, "psono", &data_path, &databases, &[], &[]);
        result.push(Target {
            id: "psono".to_string(),
            backup_dir,
            // This is the password store's own asymmetric keypair.
            encrypts_by_default: true,
            size_paths: vec![data_path, format!("{path}/db")],
            body,
        });
    }

    if has("passbolt") {
        let path = p.passbolt_path.clone();
        let backup_dir = "/opt/backups/passbolt".to_string();
        let data_path = format!("{path}/secrets");
        let databases =
            [Database { engine: Engine::Mysql, service: "db", file_name: "passbolt.sql", database_name: None }];
        let body = archive_body("passbolt", &backup_dir, "passbolt", &data_path, &databases, &[], &[]);
        result.push(Target {
            id: "passbolt".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path, format!("{path}/db")],
            body,
        });
    }

    if has("nextcloud") {
        let path = p.nextcloud_path.clone();
        let backup_dir = "/opt/backups/nextcloud".to_string();
        let data_path = format!("{path}/data");
        let databases =
            [Database { engine: Engine::Mysql, service: "db", file_name: "nextcloud.sql", database_name: None }];
        let quiesce = ["app"];
        let body = archive_body("nextcloud", &backup_dir, "nextcloud", &data_path, &databases, &quiesce, &[]);
        result.push(Target {
            id: "nextcloud".to_string(),
            backup_dir,
            // Bulk user files; GPG over tens of gigabytes on a Raspberry Pi
            // costs hours of CPU, so the caller opts in per run.
            encrypts_by_default: false,
            size_paths: vec![data_path, format!("{path}/db")],
            body,
        });
    }

    if has("seafile") {
        let path = p.seafile_path.clone();
        let backup_dir = "/opt/backups/seafile".to_string();
        let data_path = format!("{path}/data");
        let databases = [
            Database { engine: Engine::Mysql, service: "db", file_name: "ccnet_db.sql", database_name: Some("ccnet_db") },
            Database {
                engine: Engine::Mysql,
                service: "db",
                file_name: "seafile_db.sql",
                database_name: Some("seafile_db"),
            },
            Database {
                engine: Engine::Mysql,
                service: "db",
                file_name: "seahub_db.sql",
                database_name: Some("seahub_db"),
            },
        ];
        let quiesce = ["seafile"];
        // Literal, not computed from `data_path`: Seafile's archive path is
        // always `<seafilePath>/data`, so its slot is always `data` — same
        // as `SeafileService`'s own hardcoded `excludes: ["data/logs"]`.
        let excludes = vec!["data/logs".to_string()];
        let body = archive_body("seafile", &backup_dir, "seafile", &data_path, &databases, &quiesce, &excludes);
        result.push(Target {
            id: "seafile".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path, format!("{path}/db")],
            body,
        });
    }

    if has("immich") {
        let path = p.immich_path.clone();
        let backup_dir = "/opt/backups/immich".to_string();
        let data_path = format!("{path}/library");
        let databases =
            [Database { engine: Engine::Postgres, service: "database", file_name: "immich.sql", database_name: None }];
        let body = archive_body("immich", &backup_dir, "immich", &data_path, &databases, &[], &[]);
        result.push(Target {
            id: "immich".to_string(),
            backup_dir,
            // Nothing is stopped, so the archive step can run for hours on a
            // real library — see `ImmichService`'s own comment.
            encrypts_by_default: false,
            size_paths: vec![data_path, format!("{path}/postgres")],
            body,
        });
    }

    if has("photoprism") {
        let path = p.photoprism_path.clone();
        let backup_dir = "/opt/backups/photoprism".to_string();
        let data_path = format!("{path}/originals");
        let databases = [Database {
            engine: Engine::Mysql,
            service: "mariadb",
            file_name: "photoprism.sql",
            database_name: None,
        }];
        let body = archive_body("photoprism", &backup_dir, "photoprism", &data_path, &databases, &[], &[]);
        result.push(Target {
            id: "photoprism".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path, format!("{path}/storage"), format!("{path}/db")],
            body,
        });
    }

    if has("forgejo") {
        let path = p.forgejo_path.clone();
        let backup_dir = "/opt/backups/forgejo".to_string();
        let data_path = format!("{path}/data");
        let databases =
            [Database { engine: Engine::Postgres, service: "db", file_name: "forgejo.sql", database_name: None }];
        let quiesce = ["server"];
        let body = archive_body("forgejo", &backup_dir, "forgejo", &data_path, &databases, &quiesce, &[]);
        result.push(Target {
            id: "forgejo".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path, format!("{path}/db")],
            body,
        });
    }

    if has("gitlab") {
        let path = p.gitlab_path.clone();
        let backup_dir = "/opt/backups/gitlab".to_string();
        let slot = last_component(&path);
        let quiesce = ["gitlab"];
        let excludes = vec![format!("{slot}/logs")];
        let body = archive_body("gitlab", &backup_dir, "gitlab", &path, &[], &quiesce, &excludes);
        result.push(Target {
            id: "gitlab".to_string(),
            backup_dir,
            // The archive carries gitlab-secrets.json; encryption is still
            // off by default (bulk repositories/CI artifacts dominate it),
            // the caller opts in per run when it matters more than the CPU.
            encrypts_by_default: false,
            size_paths: vec![format!("{path}/config"), format!("{path}/data")],
            body,
        });
    }

    if has("jellyfin") {
        let path = p.jellyfin_path.clone();
        let backup_dir = "/opt/backups/jellyfin".to_string();
        let data_path = format!("{path}/config");
        let quiesce = ["jellyfin"];
        let body = archive_body("jellyfin", &backup_dir, "jellyfin", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "jellyfin".to_string(),
            backup_dir,
            // The media library itself is deliberately NOT in the archive —
            // it is the user's own directory, mounted read-only.
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }

    // The worlds. Both engines are stopped for the archive rather than tarred
    // live: a running server holds its region files open and writes them
    // continuously, so a live archive restores into a corrupt world — and does
    // it without one error at backup time, which is the worst shape a failure
    // can take.
    if has("minecraft-java") {
        let path = p.minecraft_java_path.clone();
        let backup_dir = "/opt/backups/minecraft-java".to_string();
        let data_path = format!("{path}/data");
        let quiesce = ["minecraft-java"];
        let body = archive_body("minecraft-java", &backup_dir, "minecraft-java", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "minecraft-java".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("minecraft-bedrock") {
        let path = p.minecraft_bedrock_path.clone();
        let backup_dir = "/opt/backups/minecraft-bedrock".to_string();
        let data_path = format!("{path}/data");
        let quiesce = ["minecraft-bedrock"];
        let body =
            archive_body("minecraft-bedrock", &backup_dir, "minecraft-bedrock", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "minecraft-bedrock".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("crafty-controller") {
        let path = p.crafty_path.clone();
        let backup_dir = "/opt/backups/crafty-controller".to_string();
        let data_path = format!("{path}/config");
        let quiesce = ["crafty"];
        let body = archive_body("crafty-controller", &backup_dir, "crafty", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "crafty-controller".to_string(),
            backup_dir,
            // Its OWN `backups` directory is not archived: those are world
            // backups Crafty already made, and copying them in would store
            // every world twice.
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("adguard-home") {
        let path = p.adguard_path.clone();
        let backup_dir = "/opt/backups/adguard-home".to_string();
        let data_path = format!("{path}/conf");
        let body = archive_body("adguard-home", &backup_dir, "adguardhome", &data_path, &[], &[], &[]);
        result.push(Target {
            id: "adguard-home".to_string(),
            backup_dir,
            // Kilobytes, so encryption costs nothing measurable — and the
            // file carries the admin credential hash and filtering topology.
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    // The three services of 2026-08-18 and the mesh control server. **They
    // were missing here while the Swift generator emitted arms for all four**,
    // and the shape of that defect is worth keeping: this function is a list of
    // `if has(...)` blocks, while the Swift side WALKS THE CATALOG and renders
    // whatever declares a backup. So a service added to the catalog arrives on
    // the SSH route by declaring itself and on this one only if somebody
    // remembers this file — and nothing failed until a host set up by the agent
    // was asked to back one of them up, months later, with "the backup wrapper
    // on this server has no entry for 'homepage'" (owner, 2026-08-22).
    // `every_backup_capable_service_has_an_arm` below is the guard that makes
    // the next one fail here instead of on a server.
    if has("pihole") {
        let path = p.pihole_path.clone();
        let backup_dir = "/opt/backups/pihole".to_string();
        let data_path = format!("{path}/etc-pihole");
        let body = archive_body("pihole", &backup_dir, pihole::COMPOSE_PROJECT, &data_path, &[], &[], &[]);
        result.push(Target {
            id: "pihole".to_string(),
            backup_dir,
            // pihole.toml carries the admin password hash, gravity.db the
            // lists — kilobytes either way, so encrypting costs nothing.
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("headscale") {
        let path = p.headscale_path.clone();
        let backup_dir = "/opt/backups/headscale".to_string();
        let data_path = format!("{path}/data");
        let quiesce = ["headscale"];
        let body = archive_body("headscale", &backup_dir, headscale::COMPOSE_PROJECT, &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "headscale".to_string(),
            backup_dir,
            // The node keys and the pre-auth keys of every device on the mesh.
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("homepage") {
        let path = p.homepage_path.clone();
        let backup_dir = "/opt/backups/homepage".to_string();
        let data_path = format!("{path}/config");
        let body = archive_body("homepage", &backup_dir, homepage::COMPOSE_PROJECT, &data_path, &[], &[], &[]);
        result.push(Target {
            id: "homepage".to_string(),
            backup_dir,
            // A page of links: nothing secret, and the half this app writes is
            // regenerated from the catalog on every run anyway.
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("authelia") {
        let path = p.authelia_path.clone();
        let backup_dir = "/opt/backups/authelia".to_string();
        let data_path = format!("{path}/config");
        // Stopped for the archive: the SQLite file underneath holds live
        // sessions, and tar over a database being written is an archive that
        // restores into a broken one — silently, at backup time.
        let quiesce = ["authelia"];
        let body = archive_body("authelia", &backup_dir, authelia::COMPOSE_PROJECT, &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "authelia".to_string(),
            backup_dir,
            // The user database with its password hashes.
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    // The agent's single collapsed `vpn` id stands for the whole VPN slice,
    // but only the panel owns data worth backing up (see the module doc) —
    // the panel's own path is fixed (`VPNPanelService.path`), not one of the
    // per-protocol settings on `Input`.
    // Keyed on the VPN GROUP, not on the agent's collapsed `"vpn"` id: this
    // struct's `services` are catalog ids (see `HostInput.services`), and
    // keying on the aggregate meant a real host — whose set is built from what
    // `discover` found, expanded to catalog ids — silently lost the panel from
    // its backup list. Found live on nukki 2026-08-12.
    if super::has_vpn(&input.services) {
        let backup_dir = "/opt/backups/vpn-panel".to_string();
        let data_path = "/opt/gryonix-vpn-panel/data".to_string();
        let quiesce = ["vpnpanel"];
        let body = archive_body("vpn-panel", &backup_dir, "vpnpanel", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "vpn-panel".to_string(),
            backup_dir,
            // Key material and password hashes; small enough that GPG costs
            // nothing even on a Pi.
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("open-webui") {
        let path = p.open_webui_path.clone();
        let backup_dir = "/opt/backups/open-webui".to_string();
        let data_path = format!("{path}/data");
        // SQLite inside that directory, written continuously, so a live tar
        // can produce an archive that will not open. One container, seconds
        // to stop — the same trade Jellyfin makes for the same reason.
        let quiesce = ["open-webui"];
        let body = archive_body("open-webui", &backup_dir, "open-webui", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "open-webui".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("anythingllm") {
        let path = p.anythingllm_path.clone();
        let backup_dir = "/opt/backups/anythingllm".to_string();
        // The WHOLE service directory, not just `storage` — the settings file
        // beside it carries the keys this instance signs its sessions with and
        // whatever the owner configured in the UI. An archive of the documents
        // without it restores a service that has forgotten how it was set up.
        let data_path = path;
        // SQLite and a vector index, both written continuously.
        let quiesce = ["anythingllm"];
        let body = archive_body("anythingllm", &backup_dir, "anythingllm", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "anythingllm".to_string(),
            backup_dir,
            // Documents, their embeddings, and whichever provider keys were
            // typed into the UI.
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("litellm") {
        let path = p.litellm_path.clone();
        let backup_dir = "/opt/backups/litellm".to_string();
        // The routing table and the master key. NOT the provider keys: those
        // live in the agent's own store, which its own backup covers — copying
        // them here would put the most valuable secret on the host into a
        // second archive with a different retention.
        let data_path = path;
        let body = archive_body("litellm", &backup_dir, "litellm", &data_path, &[], &[], &[]);
        result.push(Target {
            id: "litellm".to_string(),
            backup_dir,
            // The master key is in there, so the archive is encrypted by
            // default the way the password stores' are.
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("qdrant") {
        let path = p.qdrant_path.clone();
        let backup_dir = "/opt/backups/qdrant".to_string();
        let data_path = format!("{path}/storage");
        // Qdrant writes its segments continuously and has no dump client to
        // take a consistent copy through, so the archive takes the files with
        // the service stopped.
        let quiesce = ["qdrant"];
        let body = archive_body("qdrant", &backup_dir, "qdrant", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "qdrant".to_string(),
            backup_dir,
            // Embeddings are the documents in a form that still answers
            // questions about them.
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("openclaw") {
        let path = p.openclaw_path.clone();
        let backup_dir = "/opt/backups/openclaw".to_string();
        // The paired sessions, the config and the workspace. A WhatsApp
        // pairing lost here is a QR code scanned again on somebody's phone,
        // which is the one thing on this shelf a re-install cannot redo.
        let data_path = format!("{path}/state");
        // Sessions are written continuously, so a live archive can hold a
        // half-written one. One container, seconds.
        let quiesce = ["openclaw"];
        let body = archive_body("openclaw", &backup_dir, "openclaw", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "openclaw".to_string(),
            backup_dir,
            // Messenger sessions are credentials: whoever holds this archive
            // can speak as the person in their own chats.
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("n8n") {
        let path = p.n8n_path.clone();
        let backup_dir = "/opt/backups/n8n".to_string();
        // The settings directory, which is where n8n keeps the key that
        // decrypts every stored credential. The workflows themselves are rows
        // in the database and travel in the dump; `<path>/postgres` is not
        // archived, for the reason every other service with a database skips
        // it — tarring a live PostgreSQL data directory produces an archive
        // that will not replay.
        let data_path = format!("{path}/data");
        let databases =
            [Database { engine: Engine::Postgres, service: "database", file_name: "n8n.sql", database_name: None }];
        // Seconds, and worth them: n8n writes execution rows continuously, and
        // a dump taken mid-run is a dump of a half-finished execution.
        let quiesce = ["n8n"];
        let body = archive_body("n8n", &backup_dir, "n8n", &data_path, &databases, &quiesce, &[]);
        result.push(Target {
            id: "n8n".to_string(),
            backup_dir,
            // The credentials of every service these workflows touch, plus the
            // key that decrypts them, in one file.
            encrypts_by_default: true,
            size_paths: vec![data_path, format!("{path}/postgres")],
            body,
        });
    }



    result
}

/// Every backup-capable service on this host, paired with the EXACT directory
/// its own `case` arm above writes archives into.
///
/// **The same formula `build_targets` computes, not a second one.** The setup
/// script's own directory-ownership step (`DashboardAccessSections.
/// serviceBackupDirs`) reads `.backup?.listDirectory` off each installed
/// `ManagedService` — this is that step's port, and it has to agree with the
/// wrapper it is handing out ownership FOR: a list built from
/// `uninstall::BackupPaths.for_id` independently would drift the moment a
/// service's directory stops being the plain `root/id` shape (mailcow's and
/// vaultwarden's both already are, by historical accident, which is exactly
/// the kind of coincidence this project has been burned by before — see
/// `install/host/mod.rs`'s "every wrapper recognises the vpn from the SAME
/// ids"). `provision.rs` calls this to `chown` each directory to the control
/// user right after install; `build_targets` itself stays private, since
/// every OTHER caller of this module only needs the rendered wrapper.
pub fn backup_dirs(input: &HostInput) -> Vec<(String, String)> {
    build_targets(input).into_iter().map(|t| (t.id, t.backup_dir)).collect()
}

/// Does anything on this host refuse to be backed up in the clear?
///
/// **The answer decides whether the host needs a stored backup passphrase at
/// all, and getting it wrong costs an update channel silently.** A secret
/// store (Vaultwarden, Psono, Passbolt) encrypts by default; the scheduled
/// backup has nobody to ask for a passphrase, so with none stored it refuses,
/// and `update-ctl` refuses to update a service whose backup failed. The
/// result is a service that never auto-updates, reported once a night into a
/// status file and otherwise invisible — measured on the production host
/// 2026-08-19, where Vaultwarden had been failing that way since it was
/// installed because NEITHER install route ever created a passphrase.
///
/// Read off the same table the wrapper is rendered from, so a new service that
/// declares `encrypts_by_default` is covered by declaring it.
pub fn needs_stored_passphrase(input: &HostInput) -> bool {
    build_targets(input).iter().any(|t| t.encrypts_by_default)
}

/// The wrapper's own body — everything between the heredoc delimiters the
/// executor writes to `SCRIPT_PATH`. Byte-identical to
/// `tests/fixtures/install/host/backup_ctl/*.txt`, which are heredoc bodies
/// lifted out of REAL generated setup scripts (see that directory's
/// `README.md`), not a transcription of `BackupControlSections.swift`.
pub fn script(input: &HostInput) -> String {
    let targets = build_targets(input);

    let owner = input.ssh_user.clone().unwrap_or_else(|| "root".to_string());

    let ids: Vec<&str> = targets.iter().map(|t| t.id.as_str()).collect();
    let all_ids = ids.join(" ");
    let forloop_ids = if ids.is_empty() { "''".to_string() } else { all_ids.clone() };

    let functions = if targets.is_empty() {
        ": # no backup-capable service is installed".to_string()
    } else {
        targets
            .iter()
            .map(|t| format!("backup_{}() {{\n{}\n}}", function_name(&t.id), t.body))
            .collect::<Vec<_>>()
            .join("\n\n")
    };

    let dispatch_arms = targets
        .iter()
        .map(|t| format!("    {}) gd_with_lock 'backup-{}' backup_{} ;;", t.id, t.id, function_name(&t.id)))
        .collect::<Vec<_>>()
        .join("\n");

    let encrypt_arms = targets
        .iter()
        .map(|t| format!("    {}) echo {} ;;", t.id, i32::from(t.encrypts_by_default)))
        .collect::<Vec<_>>()
        .join("\n");

    let estimate_arms = targets
        .iter()
        .map(|t| {
            let paths = t.size_paths.iter().map(|p| quoted_path(p)).collect::<Vec<_>>().join(" ");
            format!("    {}) dir='{}'; paths=({}) ;;", t.id, t.backup_dir, paths)
        })
        .collect::<Vec<_>>()
        .join("\n");

    let dir_cases = if targets.is_empty() {
        "\"\"".to_string()
    } else {
        targets.iter().map(|t| format!("\"{}\"/*", t.backup_dir)).collect::<Vec<_>>().join("|")
    };

    let template = r#####"#!/bin/bash
# Managed by gryonixNexus — backup housekeeping for the Server Dashboard.
# Usage: gryonixnexus-backup-ctl.sh delete <path>
#        gryonixnexus-backup-ctl.sh set-schedule <off|every:<n><h|d>@<HH:MM>> <retention> [services...]
#        gryonixnexus-backup-ctl.sh set-passphrase   (passphrase on stdin)
#        gryonixnexus-backup-ctl.sh run
#        gryonixnexus-backup-ctl.sh backup <service> [--encrypt|--no-encrypt]
#                                       (GPG passphrase on stdin when encrypting)
#        gryonixnexus-backup-ctl.sh estimate <service>
set -euo pipefail

ACTION="${1:-}"
CONFIG='/etc/gryonixnexus/autobackup.conf'
PASSFILE='/etc/gryonixnexus/autobackup.pass'
RETENTION=@@GD_RETENTION@@
SERVICES='@@GD_SERVICES@@'
SCHEDULE=off
# The control user. Finished archives are chowned to it: the app
# downloads and shares them, and what keeps other accounts away is the
# 0750 on the enclosing backup root, not the file's owner.
OWNER='@@GD_OWNER@@'
# Encryption state of the CURRENT run. The passphrase lives in a shell
# variable and reaches gpg down a pipe — never in argv, which is
# world-readable through /proc.
GD_ENCRYPT=0
GD_PASS=""

load_config() {
  # shellcheck disable=SC1090
  [ -f "$CONFIG" ] && . "$CONFIG"
  # A config from an older build may not set every value.
  : "${SCHEDULE:=off}" "${RETENTION:=@@GD_RETENTION@@}" "${SERVICES:=@@GD_SERVICES@@}"
}

# --- per-service locking (see LockSections) --------------------------

@@GD_LOCK_HELPER@@

# --- helpers shared by every generated service body -----------------

gd_compose_stop() {
  local project="$1"
  shift
  docker compose -p "$project" stop "$@" >/dev/null 2>&1 || true
}

gd_compose_start() {
  local project="$1"
  shift
  docker compose -p "$project" start "$@" >/dev/null 2>&1 || true
}

# Container id of one compose service; empty when it is not running.
gd_container() {
  docker compose -p "$1" ps -q "$2" 2>/dev/null | head -n 1
}

# A tar of a live database directory is a corrupt backup, so the
# database is dumped through its own client instead. The credentials
# come from the container's OWN environment — compose already put them
# there — because passing them from here would place the password in
# the argv of `docker exec`, readable by every account on the host.
gd_dump_postgres() {
  local cid
  cid="$(gd_container "$1" "$2")"
  if [ -z "$cid" ]; then
    echo "the $1 database container is not running" >&2
    return 1
  fi
  if ! docker exec "$cid" sh -c \
       'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_dump --clean --if-exists -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
       > "$3"; then
    echo "the $1 database dump failed" >&2
    return 1
  fi
  [ -s "$3" ] || { echo "the $1 database dump is empty" >&2; return 1; }
}

# --single-transaction is what makes a dump of a RUNNING InnoDB
# database trustworthy: one consistent snapshot, no instance-wide lock.
# mariadb-dump on current images, mysqldump on older ones.
#
# A fourth argument names the database explicitly, for a service that
# keeps several in one engine and whose container therefore sets no
# MYSQL_DATABASE at all; without it the container's own variable is
# used, as it always was. Only the NAME travels here — the password is
# still read inside the container, never put in the argv of docker exec
# where /proc hands it to every account on the host.
gd_dump_mysql() {
  local cid
  cid="$(gd_container "$1" "$2")"
  if [ -z "$cid" ]; then
    echo "the $1 database container is not running" >&2
    return 1
  fi
  if ! docker exec "$cid" sh -c \
       'if command -v mariadb-dump >/dev/null 2>&1; then D=mariadb-dump; else D=mysqldump; fi; MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec "$D" --single-transaction --quick -u root "${1:-$MYSQL_DATABASE}"' \
       sh "${4:-}" > "$3"; then
    echo "the $1 database dump failed" >&2
    return 1
  fi
  [ -s "$3" ] || { echo "the $1 database dump is empty" >&2; return 1; }
}

# Keeps the newest RETENTION archives of one service — encrypted and
# plain together, they are one series. The pipeline is guarded: with
# fewer archives than RETENTION `ls` finds nothing to list and would
# fail the whole run under pipefail, which is every first run.
gd_rotate() {
  { ls -1t "$1/$2"-*.tar.gz "$1/$2"-*.tar.gz.gpg 2>/dev/null || true; } \
    | tail -n +$((RETENTION + 1)) | xargs -r rm -f
}

# Encrypt (or not), put the archive in place, rotate, announce.
gd_finish() {
  local name="$1" dir="$2" plain="$3" work="$4" out=""
  if [ ! -s "$plain" ]; then
    rm -rf "$work"
    echo "the $name archive is empty" >&2
    return 1
  fi
  if [ "$GD_ENCRYPT" -eq 1 ]; then
    out="$dir/$(basename "$plain").gpg"
    if ! printf '%s' "$GD_PASS" | gpg --batch --quiet --yes --symmetric \
         --cipher-algo AES256 --passphrase-fd 0 --pinentry-mode loopback \
         --output "$out" "$plain"; then
      rm -rf "$work"
      echo "could not encrypt the $name backup" >&2
      return 1
    fi
  else
    out="$dir/$(basename "$plain")"
    mv "$plain" "$out"
  fi
  # The plain archive never outlives the encrypted one.
  rm -rf "$work"
  chmod 600 "$out"
  chown "$OWNER" "$out" 2>/dev/null || true
  gd_rotate "$dir" "$name"
  # A streamed command carries no exit status back to the app, so the
  # archive announces itself: marker, size in bytes, path.
  printf '%s %s %s\n' 'GRYONIXNEXUS_BACKUP_DONE' \
    "$(stat -c %s "$out" 2>/dev/null || echo 0)" "$out"
}

# --- per-service bodies (generated from each service's BackupSpec) ---

@@GD_FUNCTIONS@@

# The ONE dispatch both callers go through: the timer's `run` and the
# app's `backup`. Two copies of these bodies is exactly the drift this
# wrapper exists to prevent.
gd_run_service() {
  case "$1" in
@@GD_DISPATCH_ARMS@@
    *) echo "unsupported service: $1" >&2; return 2 ;;
  esac
}

# Whether a run of this service encrypts unless the caller says
# otherwise. Secret stores yes; bulk media no — GPG over a photo
# library costs hours of CPU on a Raspberry Pi.
gd_default_encrypt() {
  case "$1" in
@@GD_ENCRYPT_ARMS@@
    *) echo 0 ;;
  esac
}

do_delete() {
  local path="${1:-}"
  # The path must sit inside a backup directory this deployment owns.
  # Without the check a whitelisted wrapper would delete ANY file.
  case "$path" in
    *..*) echo "invalid path: ${path}" >&2; exit 2 ;;
  esac
  case "$path" in
    @@GD_DIR_CASES@@) ;;
    *) echo "path outside the backup directories: ${path}" >&2; exit 2 ;;
  esac
  [ -e "$path" ] || { echo "no such backup: ${path}" >&2; exit 2; }
  rm -rf "$path"
}

do_run() {
  load_config
  local failed=""
  for svc in $SERVICES; do
    # Each service runs in its own subshell, and the `||` keeps errexit
    # from firing on a failure: an unattended run must not let one
    # broken service cancel the backups of every service after it.
    (
      GD_ENCRYPT="$(gd_default_encrypt "$svc")"
      GD_PASS=""
      if [ "$GD_ENCRYPT" -eq 1 ]; then
        # Unattended, so there is nobody to ask: the stored passphrase
        # is the only source. Without it the service refuses rather
        # than quietly writing its secrets out in the clear.
        if [ ! -s "$PASSFILE" ]; then
          echo "no backup passphrase stored for $svc" >&2
          exit 1
        fi
        GD_PASS="$(cat "$PASSFILE")"
      fi
      gd_run_service "$svc"
    ) || failed="$failed $svc"
  done
  if [ -n "$failed" ]; then
    echo "backup failed for:$failed" >&2
    exit 1
  fi
}

# One service, on demand. Same bodies the timer runs; the only
# difference is where the passphrase comes from.
do_backup() {
  local svc="${1:-}"
  shift || true
  load_config
  GD_ENCRYPT="$(gd_default_encrypt "$svc")"
  for arg in "$@"; do
    case "$arg" in
      --encrypt) GD_ENCRYPT=1 ;;
      --no-encrypt) GD_ENCRYPT=0 ;;
      *) echo "unsupported option: ${arg}" >&2; exit 2 ;;
    esac
  done
  if [ "$GD_ENCRYPT" -eq 1 ]; then
    # On stdin, never argv. A terminal means nobody piped anything in,
    # and reading would hang forever.
    if [ ! -t 0 ]; then GD_PASS="$(cat)"; fi
    # No passphrase given: fall back to the stored one, so an
    # encrypted run is possible without re-typing it.
    if [ -z "$GD_PASS" ] && [ -s "$PASSFILE" ]; then GD_PASS="$(cat "$PASSFILE")"; fi
    if [ -z "$GD_PASS" ]; then
      echo "an encrypted backup needs a passphrase on stdin" >&2
      exit 2
    fi
  fi
  gd_run_service "$svc"
}

# What a backup of this service would cost, in bytes, and what the
# backup filesystem still has free. Read-only, and the only reason the
# app can warn BEFORE starting an hours-long run.
do_estimate() {
  local svc="${1:-}" dir="" total=0 free="" sz=""
  local -a paths=()
  case "$svc" in
@@GD_ESTIMATE_ARMS@@
    *) echo "unsupported service: ${svc}" >&2; exit 2 ;;
  esac
  install -d -m 750 "$dir"
  local p
  for p in "${paths[@]}"; do
    [ -e "$p" ] || continue
    sz="$(du -sb "$p" 2>/dev/null | cut -f1)" || sz=""
    total=$((total + ${sz:-0}))
  done
  free="$(df -B1 --output=avail "$dir" 2>/dev/null | tail -n 1 | tr -cd '0-9')"
  printf '%s %s %s\n' 'GRYONIXNEXUS_BACKUP_ESTIMATE' "$total" "${free:-0}"
}

do_set_schedule() {
  # <schedule> is `off` or `every:<n><unit>@<HH:MM>` — the interval and
  # the time of day the user picked. Parsed here rather than taking a
  # raw OnCalendar expression: the wrapper is whitelisted in sudoers,
  # so it must not accept arbitrary systemd input from the client.
  local schedule="${1:-off}" retention="${2:-@@GD_RETENTION@@}"
  shift 2 || true
  local services="$*"
  local oncal=""
  case "$schedule" in
    off) ;;
    every:*)
      local spec="${schedule#every:}"
      local every="${spec%@*}" at="${spec#*@}"
      local n="${every%[hd]}" unit="${every##*[0-9]}"
      case "$n" in
        ''|*[!0-9]*) echo "invalid interval: ${every}" >&2; exit 2 ;;
      esac
      [ "$n" -ge 1 ] || { echo "invalid interval: ${every}" >&2; exit 2; }
      case "$at" in
        [0-2][0-9]:[0-5][0-9]) ;;
        *) echo "invalid time: ${at}" >&2; exit 2 ;;
      esac
      [ "${at%%:*}" -le 23 ] || { echo "invalid time: ${at}" >&2; exit 2; }
      case "$unit" in
        h)
          # Every n hours, aligned to the chosen minute.
          if [ "$n" -ge 24 ]; then
            oncal="*-*-* ${at}:00"
          else
            oncal="*-*-* 00/${n}:${at#*:}:00"
          fi
          ;;
        d)
          # Every n days at the chosen time. systemd has no "every n
          # days" for n > 1, so those run daily-aligned on a day step.
          if [ "$n" -le 1 ]; then
            oncal="*-*-* ${at}:00"
          else
            oncal="*-*-01/${n} ${at}:00"
          fi
          ;;
        *) echo "invalid interval unit: ${every}" >&2; exit 2 ;;
      esac
      ;;
    *) echo "unsupported schedule: ${schedule}" >&2; exit 2 ;;
  esac
  case "$retention" in
    ''|*[!0-9]*) echo "invalid retention: ${retention}" >&2; exit 2 ;;
  esac
  [ "$retention" -ge 1 ] || { echo "invalid retention: ${retention}" >&2; exit 2; }
  # Only services this wrapper knows about may end up in the config.
  local checked=""
  for svc in $services; do
    for known in @@GD_FORLOOP_IDS@@; do
      if [ "$svc" = "$known" ]; then checked="$checked $svc"; fi
    done
  done
  install -d -m 755 "$(dirname "$CONFIG")"
  cat > "$CONFIG" <<EOF_CONF
SCHEDULE=$schedule
RETENTION=$retention
SERVICES='${checked# }'
EOF_CONF
  # World-readable on purpose: it holds no secrets (the passphrase is
  # a separate 0600 file) and the app reads it without sudo.
  chmod 644 "$CONFIG"
  if [ "$schedule" = "off" ]; then
    systemctl disable --now 'gryonixnexus-autobackup.timer' >/dev/null 2>&1 || true
  else
    mkdir -p /etc/systemd/system
    cat > /etc/systemd/system/gryonixnexus-autobackup.timer <<EOF_TIMER
[Unit]
Description=gryonixNexus scheduled backups
[Timer]
OnCalendar=$oncal
# Servers are not up 24/7 — a missed window must still run.
Persistent=true
# Small jitter only: the user picked a specific time, so the run must
# not wander an hour away from it.
RandomizedDelaySec=5m
[Install]
WantedBy=timers.target
EOF_TIMER
    systemctl daemon-reload
    # A bad OnCalendar would leave the timer permanently inactive —
    # catch it here, while the app is still listening. Only when the
    # tool is actually present: its ABSENCE must not reject a schedule
    # that is fine (minimal images ship without systemd-analyze).
    if command -v systemd-analyze >/dev/null 2>&1; then
      if ! systemd-analyze calendar "$oncal" >/dev/null 2>&1; then
        echo "invalid schedule expression: ${oncal}" >&2; exit 2
      fi
    fi
    systemctl enable --now 'gryonixnexus-autobackup.timer' >/dev/null 2>&1 || true
  fi
}

do_set_passphrase() {
  install -d -m 755 "$(dirname '/etc/gryonixnexus/autobackup.pass')"
  # From stdin, never argv: argv is world-readable in /proc.
  cat > '/etc/gryonixnexus/autobackup.pass'
  chmod 600 '/etc/gryonixnexus/autobackup.pass'
}

case "$ACTION" in
  delete) do_delete "${2:-}" ;;
  run) do_run ;;
  backup) shift; do_backup "$@" ;;
  estimate) do_estimate "${2:-}" ;;
  set-schedule) shift; do_set_schedule "$@" ;;
  set-passphrase) do_set_passphrase ;;
  *) echo "unsupported action: ${ACTION}" >&2; exit 2 ;;
esac
echo 'GRYONIXNEXUS_BACKUP_CTL_DONE'"#####;

    template
        .replace("@@GD_RETENTION@@", &DEFAULT_RETENTION.to_string())
        .replace("@@GD_SERVICES@@", &all_ids)
        .replace("@@GD_OWNER@@", &owner)
        .replace("@@GD_LOCK_HELPER@@", &lock::helper())
        .replace("@@GD_FUNCTIONS@@", &functions)
        .replace("@@GD_DISPATCH_ARMS@@", &dispatch_arms)
        .replace("@@GD_ENCRYPT_ARMS@@", &encrypt_arms)
        .replace("@@GD_DIR_CASES@@", &dir_cases)
        .replace("@@GD_ESTIMATE_ARMS@@", &estimate_arms)
        .replace("@@GD_FORLOOP_IDS@@", &forloop_ids)
}

/// The systemd unit `TIMER_NAME` runs — `ServiceName` in Swift's naming,
/// fully static (no scenario in the fixture set ever varies it, matching
/// `tests/fixtures/install/host/README.md`'s note that some wrappers
/// interpolate nothing).
pub fn unit() -> String {
    format!("[Unit]\nDescription=gryonixNexus scheduled backup run\nAfter=docker.service\n[Service]\nType=oneshot\nExecStart={SCRIPT_PATH} run")
}

/// Removal of everything this section installs, for the uninstall wrapper —
/// mirrors `BackupControlSections.uninstallLines`. Lives here rather than
/// being spelled out in `uninstall.rs` so the two can never drift: the timer
/// is armed by `set-schedule` long after install, so a wrapper that forgets
/// it leaves a root timer firing forever against services that no longer
/// exist, and `PASSPHRASE_PATH` is a real secret that must not outlive a
/// wipe.
#[allow(dead_code)]
pub fn uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# Scheduled backups: the timer is armed by set-schedule, not by"),
        format!("{indent}# setup, so it outlives the services unless it is stopped here."),
        format!("{indent}systemctl disable --now '{TIMER_NAME}' >/dev/null 2>&1 || true"),
        format!("{indent}rm -f /etc/systemd/system/{TIMER_NAME} /etc/systemd/system/{SERVICE_NAME}"),
        format!("{indent}rm -f '{SCRIPT_PATH}'"),
        format!("{indent}rm -rf '{CONFIG_DIRECTORY}'"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_records::Language;
    use crate::install::context::Input;
    use crate::install::host::HostRole;

    fn host_input(services: &[&str]) -> HostInput {
        let mut services: Vec<String> = services.iter().map(|s| s.to_string()).collect();
        services.sort();
        HostInput {
            services,
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        }
    }

    /// A host carrying a secret store needs a stored passphrase; one carrying
    /// only bulk data does not.
    ///
    /// **The consequence of getting this wrong is silent.** Without a stored
    /// passphrase the unattended backup of a secret store refuses, and
    /// `update-ctl` refuses to update a service whose backup failed — so the
    /// service simply never auto-updates, reported once a night into a file
    /// nobody opens. Measured on the production host 2026-08-19.
    #[test]
    fn only_a_host_with_a_secret_store_needs_a_stored_passphrase() {
        assert!(needs_stored_passphrase(&host_input(&["vaultwarden"])));
        assert!(needs_stored_passphrase(&host_input(&["psono"])));
        assert!(needs_stored_passphrase(&host_input(&["passbolt"])));
        assert!(
            needs_stored_passphrase(&host_input(&["jellyfin", "vaultwarden"])),
            "one service that encrypts is enough for the host to need one"
        );
        assert!(
            !needs_stored_passphrase(&host_input(&["jellyfin"])),
            "bulk media is not encrypted by default — GPG over a photo library costs hours"
        );
        assert!(!needs_stored_passphrase(&host_input(&[])));
    }

    /// Read off the wrapper's own table rather than a list kept here, so a
    /// service added with `encrypts_by_default` is covered by declaring it.
    /// This pins the two together: every target the wrapper renders as
    /// encrypting must make its host need a passphrase.
    #[test]
    fn every_encrypting_target_makes_its_host_need_a_passphrase() {
        for id in ["vaultwarden", "psono", "passbolt", "nextcloud", "jellyfin", "seafile"] {
            let input = host_input(&[id]);
            let encrypts = build_targets(&input).iter().any(|t| t.encrypts_by_default);
            assert_eq!(
                encrypts,
                needs_stored_passphrase(&input),
                "{id}: the wrapper's own table and the passphrase decision disagree"
            );
        }
    }

    #[test]
    fn quoted_path_keeps_a_glob_outside_the_quotes() {
        assert_eq!(quoted_path("/opt/mailcow-dockerized"), "'/opt/mailcow-dockerized'");
        assert_eq!(
            quoted_path("/var/lib/docker/volumes/mailcowdockerized_*"),
            "'/var/lib/docker/volumes/mailcowdockerized_'*"
        );
    }

    #[test]
    fn split_data_path_matches_archive_backup_plan() {
        assert_eq!(split_data_path("/opt/gitlab-ce"), ("/opt".to_string(), "gitlab-ce".to_string()));
        assert_eq!(split_data_path("/opt/nextcloud/data"), ("/opt/nextcloud".to_string(), "data".to_string()));
        assert_eq!(split_data_path("/opt"), ("/".to_string(), "opt".to_string()));
    }

    /// Structural coverage for the branch NO fixture exercises: every
    /// backup_ctl fixture comes from a scenario with at least one
    /// backup-capable service (see `tests/fixtures/install/host/README.md` —
    /// the 23 distinct bodies never include an empty `SERVICES=''`). Derived
    /// directly from `BackupControlSections.wrapper`'s ternaries, not from a
    /// lifted fixture — the one place in this file that is NOT byte-verified
    /// against a real generated script.
    #[test]
    fn an_empty_service_set_uses_the_documented_fallbacks() {
        let input = host_input(&[]);
        let rendered = script(&input);
        assert!(rendered.contains("SERVICES=''"));
        assert!(rendered.contains(": # no backup-capable service is installed"));
        assert!(rendered.contains("    \"\") ;;"));
        assert!(rendered.contains("for known in ''; do"));
    }

    #[test]
    fn falls_back_to_root_when_no_ssh_control_user_exists() {
        let mut input = host_input(&["adguard-home"]);
        input.ssh_user = None;
        assert!(script(&input).contains("OWNER='root'\n"));
    }

    #[test]
    fn unit_matches_the_real_generated_timer_service() {
        let path = format!(
            "{}/tests/fixtures/install/host/autobackup_unit/A-adguard-access-en.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        let expected = std::fs::read_to_string(&path).expect("fixture");
        assert_eq!(unit(), expected.trim_end_matches('\n'));
    }

    /// **`backup_dirs` has to name the exact directories `script` dispatches
    /// into** — the whole reason `provision.rs` calls it rather than
    /// recomputing the list from `uninstall::BackupPaths`. A non-backup id
    /// (a bare VPN protocol container, which declares no `BackupSpec` of its
    /// own) must not appear, and the panel's directory has to show up from
    /// the collapsed `wireguard-vpn` id the same way the wrapper's own
    /// `vpn-panel)` arm does.
    #[test]
    fn backup_dirs_names_exactly_the_directories_the_wrapper_dispatches_into() {
        let input = host_input(&["vaultwarden", "nextcloud", "wireguard-vpn", "vpn-panel"]);
        let dirs = backup_dirs(&input);
        assert_eq!(
            dirs,
            vec![
                ("vaultwarden".to_string(), "/opt/backups/vaultwarden".to_string()),
                ("nextcloud".to_string(), "/opt/backups/nextcloud".to_string()),
                ("vpn-panel".to_string(), "/opt/backups/vpn-panel".to_string()),
            ]
        );
        // A protocol container has no directory of its own — only the panel
        // backs anything up (see `build_targets`'s own comment on this).
        assert!(!dirs.iter().any(|(id, _)| id == "wireguard-vpn"));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — the same
/// discipline `lock::tests` and `dns_records::fixture_parity` follow (see
/// `install::host`'s module doc, rule 1). Fixtures are heredoc bodies lifted
/// out of a real generated `setup-mail-server.sh`
/// (`tests/fixtures/install/host/README.md`), not a transcription of
/// `BackupControlSections.swift`. If a fixture and this module's output ever
/// disagree, the working assumption is that the bug is in THIS PORT — the
/// variant-to-input mapping below is read off
/// `GeneratedScriptLintTests.makeVariants()`, the manifest, not re-derived
/// from the fixture file names (`README.md`'s own warning).
/// The guard that would have caught the four missing arms before a server did.
#[cfg(test)]
mod arm_coverage {
    use super::*;
    use crate::install::context::Input;
    use crate::install::host::HostRole;

    fn host(services: &[&str]) -> HostInput {
        HostInput {
            services: services.iter().map(|s| s.to_string()).collect(),
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: crate::dns_records::Language::En,
            ssh_user: Some("server-user".to_string()),
            role: HostRole::SingleHost,
        }
    }

    /// Every backup-capable service, one host at a time: the arm has to exist
    /// for the service ALONE, because that is how the refusal was met — a
    /// server carrying Homepage and nothing else that needed backing up.
    #[test]
    fn every_backup_capable_service_has_an_arm() {
        for id in BACKUP_CAPABLE_SERVICE_IDS {
            let targets = build_targets(&host(&[id]));
            assert!(
                targets.iter().any(|t| t.id == *id),
                "`{id}` declares a backup but this wrapper renders no arm for it — \
                 a host set up by the agent refuses to back it up"
            );
        }
    }

    /// And all of them together, which is the shape a full host has: an arm
    /// that only renders when its neighbour is absent is the same defect a
    /// dispatch table away.
    #[test]
    fn a_full_host_carries_every_arm() {
        let script = script(&host(BACKUP_CAPABLE_SERVICE_IDS));
        for id in BACKUP_CAPABLE_SERVICE_IDS {
            assert!(
                script.contains(&format!("    {id}) dir='")),
                "the rendered wrapper has no estimate arm for `{id}` — this is \
                 the exact line `backup::resolve` reads to answer at all"
            );
        }
    }
}

#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::install::context::Input;
    use crate::install::host::HostRole;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/host/backup_ctl/{name}.txt", env!("CARGO_MANIFEST_DIR"));
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"));
        raw.trim_end_matches('\n').to_string()
    }

    fn host_input(services: &[&str]) -> HostInput {
        let mut services: Vec<String> = services.iter().map(|s| s.to_string()).collect();
        services.sort();
        HostInput {
            services,
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: crate::dns_records::Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        }
    }

    fn assert_parity(services: &[&str], fixture_name: &str) {
        assert_eq!(script(&host_input(services)), fixture(fixture_name), "{fixture_name}");
    }

    /// The three services of 2026-08-18 and the mesh control server — the four
    /// the agent's wrapper had no arms for at all, so a host it set up refused
    /// to back them up with "no entry for 'homepage'" while the SSH route
    /// wrote them (owner, 2026-08-22).
    #[test]
    fn pihole() {
        assert_parity(&["pihole"], "A-pihole-access-en");
    }

    #[test]
    fn homepage() {
        assert_parity(&["homepage"], "A-homepage-access-en");
    }

    #[test]
    fn authelia() {
        assert_parity(&["authelia"], "A-authelia-access-en");
    }

    #[test]
    fn headscale() {
        // The mesh node rides along with the control server and carries no
        // backup of its own — it is here because the real service set has it.
        assert_parity(&["headscale", "tailscale-node"], "A-mesh-access-en");
    }

    #[test]
    fn adguard() {
        assert_parity(&["adguard-home"], "A-adguard-access-en");
    }

    #[test]
    fn adguard_full() {
        assert_parity(&["adguard-home", "vaultwarden", "nextcloud", "wireguard-vpn", "vpn-panel"], "A-adguard-full-access-en");
    }

    #[test]
    fn dms() {
        assert_parity(&["docker-mailserver"], "A-dms-access-en");
    }

    #[test]
    fn dms_full() {
        assert_parity(&["docker-mailserver", "vaultwarden", "forgejo", "wireguard-vpn", "vpn-panel"], "A-dms-full-access-en");
    }

    #[test]
    fn jellyfin() {
        assert_parity(&["jellyfin"], "A-jellyfin-access-en");
    }

    #[test]
    fn jellyfin_full() {
        assert_parity(&["jellyfin", "vaultwarden", "nextcloud", "wireguard-vpn", "vpn-panel"], "A-jellyfin-full-access-en");
    }

    #[test]
    fn mailcow() {
        assert_parity(&["mailcow"], "A-mailcow-access-en");
    }

    #[test]
    fn mailcow_awg() {
        // amneziaWG carries no backup of its own; it only pulls the panel in.
        assert_parity(&["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "wireguard-vpn", "vpn-panel"], "A-mailcow-awg-access-en");
    }

    #[test]
    fn mailcow_wg() {
        assert_parity(&["mailcow", "vaultwarden", "nextcloud", "immich", "wireguard-vpn", "vpn-panel"], "A-mailcow-wg-access-en");
    }

    #[test]
    fn mailcow_xray() {
        // xrayReality carries no backup of its own either; same as awg above.
        assert_parity(&["mailcow", "vaultwarden", "wireguard-vpn", "vpn-panel"], "A-mailcow-xray-access-en");
    }

    #[test]
    fn mailu() {
        assert_parity(&["mailu"], "A-mailu-access-en");
    }

    #[test]
    fn mailu_full() {
        assert_parity(&["mailu", "vaultwarden", "nextcloud", "immich", "forgejo", "wireguard-vpn", "vpn-panel"], "A-mailu-full-access-en");
    }

    #[test]
    fn multidomain() {
        // Multi-domain does not change this wrapper at all (it has no
        // hostnames in it) — the fixture exists because the SAME generated
        // script also carries every other wrapper, and this one just needs
        // to keep matching its slice of it.
        assert_parity(
            &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "gitlab", "wireguard-vpn", "vpn-panel"],
            "A-multidomain",
        );
    }

    #[test]
    fn nomail() {
        assert_parity(&["vaultwarden", "nextcloud", "immich", "forgejo", "gitlab"], "A-nomail-access-en");
    }

    #[test]
    fn nomail_ovpn() {
        // openVPN carries no backup of its own; only the panel does. Also
        // covers `nomail-ss` (shadowsocks), which the fixture set dropped as
        // a DUPLICATE of this body — see the directory's README.md.
        assert_parity(&["vaultwarden", "wireguard-vpn", "vpn-panel"], "A-nomail-ovpn-access-en");
    }

    #[test]
    fn passbolt() {
        assert_parity(&["passbolt"], "A-passbolt-access-en");
    }

    #[test]
    fn passwords_shelf() {
        assert_parity(&["passbolt", "psono", "vaultwarden"], "A-passwords-shelf-access-en");
    }

    #[test]
    fn photoprism() {
        assert_parity(&["photoprism"], "A-photoprism-access-en");
    }

    #[test]
    fn photoprism_immich() {
        assert_parity(&["photoprism", "immich", "vaultwarden"], "A-photoprism-immich-access-en");
    }

    #[test]
    fn psono() {
        assert_parity(&["psono"], "A-psono-access-en");
    }

    #[test]
    fn psono_vaultwarden() {
        assert_parity(&["psono", "vaultwarden"], "A-psono-vaultwarden-access-en");
    }

    #[test]
    fn seafile() {
        assert_parity(&["seafile"], "A-seafile-access-en");
    }

    #[test]
    fn seafile_nextcloud() {
        assert_parity(&["seafile", "nextcloud", "vaultwarden"], "A-seafile-nextcloud-access-en");
    }
}
