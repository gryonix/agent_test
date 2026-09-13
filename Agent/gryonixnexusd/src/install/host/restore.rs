//! Port of `DashboardAccessSections.restoreWrapper` — `/opt/gryonixnexus-restore.sh`.
//!
//! See `install/host/mod.rs` for the three rules that apply to everything in
//! this module. Like `uninstall.rs`, this file renders only the wrapper
//! BODY — the heredoc content the fixtures under
//! `tests/fixtures/install/host/restore/` hold, not the `log` line, the
//! `writeFile` framing, the `chmod 750` or the upload-staging-directory
//! section Swift's `restoreWrapper` appends after them (those belong to
//! `access.rs`, which owns the SSH-fallback / dashboard-access half of this
//! contract).
//!
//! **The one wrapper whose fixtures are language-dependent.** Every other
//! file in `install::host` renders byte-identical output for every language
//! (see `mod.rs`'s sibling docs) — this one does not, because two of its
//! lines call `L10nScripts` directly inside the wrapper BODY itself:
//! `restore_mailcow`'s "mailcow not found in …" message, and the closing
//! "Restore finished." line. Everything else in the body — every path,
//! every compose project, every generated function — is language-independent,
//! which is why only these two strings need a translation table here rather
//! than a full `dns_l10n`-style port.
//!
//! **Two hardcoded arms, always present, gated on nothing.** `restore_mailcow`
//! and `restore_vaultwarden` are written into EVERY wrapper this module
//! renders, whether or not mailcow/vaultwarden are actually selected — they
//! are literal Swift string constants, not derived from `ServiceRegistry`.
//! The 13 OTHER restorable services (everything with a `RestoreSpec` except
//! mailcow, whose backup is `.externalScript`, and vaultwarden, whose backup
//! is the legacy `.encryptedVolume` flavour the app drives over SSH, not this
//! wrapper) get a GENERATED `restore_<id>` arm only when actually selected —
//! see [`archive_plan_for`].

use crate::install::context::Input;
use crate::install::host::uninstall::BackupPaths;
use crate::install::host::HostInput;

// MARK: - Catalog order for the services this wrapper restores

/// Every catalog id whose `ServiceActions.restore` is non-nil, in
/// `ServiceRegistry.all` order — a port of the ids `RestoreSpec(...)`
/// appears on in the Swift `Services/*.swift` sources. The five raw VPN
/// protocols have no `RestoreSpec` (only `vpn-panel` does), so they are
/// absent here the same way they are absent from `uninstall::CATALOG_ORDER`'s
/// non-VPN half.
/// Where this wrapper lives. `restore.rs` (the RPC) runs it by an identical
/// literal of its own; `provision` writes it here, so the two agree by
/// construction rather than by having been typed the same way twice.
pub const SCRIPT_PATH: &str = "/opt/gryonixnexus-restore.sh";

const RESTORABLE_ORDER: &[&str] = &[
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
    // Forgejo before GitLab since 2026-08-19, mirroring `CATALOG_ORDER` and
    // `ServiceRegistry`. This list is a THIRD copy of that order and drifts
    // silently: nothing but a multi-service fixture notices.
    "forgejo",
    "gitlab",
    "jellyfin",
    "minecraft-java",
    "minecraft-bedrock",
    "crafty-controller",
    "adguard-home",
    // Pi-hole, Homepage and Authelia sit here for the same reason they were
    // added to `backup_ctl`: they declare a restore in the catalog, the Swift
    // generator emits their arms by walking it, and this list is the hand-kept
    // copy that did not have them. A backup nothing can restore is the worse
    // half of that pair — it fails at the moment the data is already gone.
    // Order mirrors `CATALOG_ORDER` (tailscale-node and cloudflared carry no
    // restore, so they are absent the way the raw VPN protocols are).
    "pihole",
    "headscale",
    "homepage",
    "authelia",
    "vpn-panel",
    // The chat. The engine beside it declares no restore, for the same reason
    // it declares no backup — see `backup_ctl`'s list.
    "open-webui",
    // The retrieval pair straddles the gateway here exactly as it does in
    // `CATALOG_ORDER` — this list is asserted against that one.
    "anythingllm",
    "litellm",
    "qdrant",
    "openclaw",
    "n8n",
];

const VPN_PROTOCOLS: &[&str] =
    &["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"];

/// Every restorable service actually selected, in catalog order, `vpn-panel`
/// auto-injected the instant any VPN protocol is present — the same
/// injection `MailContext.additionalServices` performs and `uninstall.rs`'s
/// `selected_vpn_services` already ports; duplicated here (not imported)
/// because it is three lines and pulling a whole sibling function across
/// files for three lines is the wrong trade — see this crate's own
/// duplication-over-shared-dependency rule (`dns_records`'s module doc).
fn restorable_services(input: &HostInput) -> Vec<&'static str> {
    let has_protocol = VPN_PROTOCOLS.iter().any(|p| input.services.iter().any(|s| s == p));
    RESTORABLE_ORDER
        .iter()
        .copied()
        .filter(|id| {
            let present = input.services.iter().any(|s| s == id);
            present || (*id == "vpn-panel" && has_protocol)
        })
        .collect()
}

// MARK: - ArchiveBackupPlan (the 13 non-mailcow, non-vaultwarden services)

enum Engine {
    Postgres,
    Mysql,
}

struct Database {
    engine: Engine,
    service: &'static str,
    file_name: &'static str,
    database_name: Option<&'static str>,
}

/// A port of `ArchiveBackupPlan` — only the fields the RESTORE side reads
/// (`encryptsByDefault`/`sizePaths`/`excludes` are backup-estimate/tar
/// concerns `backup_ctl.rs` owns, not this wrapper).
struct ArchivePlan {
    compose_project: &'static str,
    data_path: String,
    databases: Vec<Database>,
    quiesce_services: Vec<&'static str>,
}

impl ArchivePlan {
    /// A port of `ArchiveBackupPlan.dataSlot`: the archive member name.
    fn data_slot(&self) -> &str {
        self.data_path.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or(&self.data_path)
    }

    /// A port of `ArchiveBackupPlan.dataParent`: `tar -C`'s target, so the
    /// archive stores a relative member.
    fn data_parent(&self) -> String {
        let trimmed = self.data_path.strip_suffix('/').unwrap_or(&self.data_path);
        match trimmed.rfind('/') {
            Some(0) | None => "/".to_string(),
            Some(i) => trimmed[..i].to_string(),
        }
    }
}

/// A port of every non-mailcow, non-vaultwarden service's
/// `actions(_:).backup?.wrapper?.plan.archive`. `id` must be one of
/// [`RESTORABLE_ORDER`]'s entries other than `"mailcow"`/`"vaultwarden"` —
/// callers only ever reach this through [`render`], which filters those two
/// out first (they get the two hardcoded arms instead).
fn archive_plan_for(id: &str, input: &Input) -> ArchivePlan {
    use crate::install::mail::{dockermailserver as dms, mailu};
    match id {
        "adguard-home" => ArchivePlan {
            compose_project: crate::install::adguard::COMPOSE_PROJECT,
            data_path: format!("{}/conf", input.adguard_path),
            databases: Vec::new(),
            quiesce_services: Vec::new(),
        },
        "forgejo" => ArchivePlan {
            compose_project: crate::install::forgejo::COMPOSE_PROJECT,
            data_path: format!("{}/data", input.forgejo_path),
            databases: vec![Database {
                engine: Engine::Postgres,
                service: "db",
                file_name: "forgejo.sql",
                database_name: None,
            }],
            quiesce_services: vec!["server"],
        },
        "docker-mailserver" => ArchivePlan {
            compose_project: dms::COMPOSE_PROJECT,
            data_path: input.docker_mailserver_path.clone(),
            databases: Vec::new(),
            quiesce_services: vec!["mailserver", "webmail"],
        },
        "immich" => ArchivePlan {
            compose_project: crate::install::immich::COMPOSE_PROJECT,
            data_path: format!("{}/library", input.immich_path),
            databases: vec![Database {
                engine: Engine::Postgres,
                service: "database",
                file_name: "immich.sql",
                database_name: None,
            }],
            quiesce_services: Vec::new(),
        },
        "gitlab" => ArchivePlan {
            compose_project: crate::install::gitlab::COMPOSE_PROJECT,
            data_path: input.gitlab_path.clone(),
            databases: Vec::new(),
            // `GitLabService.containerName`: coincides with the compose
            // project's own name today, but it is a SEPARATE Swift constant
            // (a single-container stack), so it is spelled out rather than
            // reused from `compose_project` above.
            quiesce_services: vec!["gitlab"],
        },
        "jellyfin" => ArchivePlan {
            compose_project: crate::install::jellyfin::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.jellyfin_path),
            databases: Vec::new(),
            quiesce_services: vec!["jellyfin"],
        },
        "minecraft-java" => ArchivePlan {
            compose_project: crate::install::minecraft::JAVA_COMPOSE_PROJECT,
            data_path: format!("{}/data", input.minecraft_java_path),
            databases: Vec::new(),
            // Stopped while the world is written back, for the same reason it
            // is stopped while it is read.
            quiesce_services: vec!["minecraft-java"],
        },
        "minecraft-bedrock" => ArchivePlan {
            compose_project: crate::install::minecraft::BEDROCK_COMPOSE_PROJECT,
            data_path: format!("{}/data", input.minecraft_bedrock_path),
            databases: Vec::new(),
            quiesce_services: vec!["minecraft-bedrock"],
        },
        "litellm" => ArchivePlan {
            compose_project: crate::install::litellm::COMPOSE_PROJECT,
            data_path: input.litellm_path.clone(),
            databases: Vec::new(),
            // Nothing to quiesce: the two files under that path are written by
            // the install and never by the running container.
            quiesce_services: Vec::new(),
        },
        "anythingllm" => ArchivePlan {
            compose_project: crate::install::anythingllm::COMPOSE_PROJECT,
            // The whole directory — see `backup_ctl` for why the settings file
            // travels with the documents.
            data_path: input.anythingllm_path.clone(),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::anythingllm::CONTAINER],
        },
        "qdrant" => ArchivePlan {
            compose_project: crate::install::qdrant::COMPOSE_PROJECT,
            data_path: format!("{}/storage", input.qdrant_path),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::qdrant::CONTAINER],
        },
        "openclaw" => ArchivePlan {
            compose_project: crate::install::openclaw::COMPOSE_PROJECT,
            data_path: format!("{}/state", input.openclaw_path),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::openclaw::CONTAINER],
        },
        "n8n" => ArchivePlan {
            compose_project: crate::install::n8n::COMPOSE_PROJECT,
            // The settings directory, which carries the encryption key; the
            // workflows come back through the dump.
            data_path: format!("{}/data", input.n8n_path),
            databases: vec![Database {
                engine: Engine::Postgres,
                service: crate::install::n8n::DATABASE_SERVICE,
                file_name: "n8n.sql",
                database_name: None,
            }],
            quiesce_services: vec![crate::install::n8n::CONTAINER],
        },
        "open-webui" => ArchivePlan {
            compose_project: crate::install::open_webui::COMPOSE_PROJECT,
            data_path: format!("{}/data", input.open_webui_path),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::open_webui::CONTAINER],
        },
        "crafty-controller" => ArchivePlan {
            compose_project: crate::install::crafty::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.crafty_path),
            databases: Vec::new(),
            quiesce_services: vec!["crafty"],
        },
        "nextcloud" => ArchivePlan {
            compose_project: crate::install::nextcloud::COMPOSE_PROJECT,
            data_path: format!("{}/data", input.nextcloud_path),
            databases: vec![Database {
                engine: Engine::Mysql,
                service: "db",
                file_name: "nextcloud.sql",
                database_name: None,
            }],
            quiesce_services: vec!["app"],
        },
        "mailu" => ArchivePlan {
            compose_project: mailu::COMPOSE_PROJECT,
            data_path: input.mailu_path.clone(),
            databases: Vec::new(),
            quiesce_services: vec![
                "front", "admin", "imap", "smtp", "antispam", "webmail", "redis", "resolver",
            ],
        },
        "passbolt" => ArchivePlan {
            compose_project: crate::install::passbolt::COMPOSE_PROJECT,
            // A port of `PassboltService.secretsPath(_:)`: `<passboltPath>/secrets`.
            data_path: format!("{}/secrets", input.passbolt_path),
            databases: vec![Database {
                engine: Engine::Mysql,
                service: "db",
                file_name: "passbolt.sql",
                database_name: None,
            }],
            quiesce_services: Vec::new(),
        },
        "psono" => ArchivePlan {
            compose_project: crate::install::psono::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.psono_path),
            databases: vec![Database {
                engine: Engine::Postgres,
                service: "db",
                file_name: "psono.sql",
                database_name: None,
            }],
            quiesce_services: Vec::new(),
        },
        "photoprism" => ArchivePlan {
            compose_project: crate::install::photoprism::COMPOSE_PROJECT,
            data_path: format!("{}/originals", input.photoprism_path),
            databases: vec![Database {
                engine: Engine::Mysql,
                service: "mariadb",
                file_name: "photoprism.sql",
                database_name: None,
            }],
            quiesce_services: Vec::new(),
        },
        "seafile" => ArchivePlan {
            compose_project: crate::install::seafile::COMPOSE_PROJECT,
            // A port of `SeafileService.dataPath(_:)`: `<seafilePath>/data`.
            data_path: format!("{}/data", input.seafile_path),
            // All three, by name — the database container sets no
            // `MYSQL_DATABASE` of its own (see `ArchiveBackupPlan`'s own
            // doc), so a dump driven by it would silently carry none of them.
            databases: vec![
                Database {
                    engine: Engine::Mysql,
                    service: "db",
                    file_name: "ccnet_db.sql",
                    database_name: Some("ccnet_db"),
                },
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
            ],
            quiesce_services: vec!["seafile"],
        },
        "pihole" => ArchivePlan {
            compose_project: crate::install::pihole::COMPOSE_PROJECT,
            data_path: format!("{}/etc-pihole", input.pihole_path),
            databases: Vec::new(),
            // Not stopped: FTL keeps gravity.db open, but the restore replaces
            // the whole directory by rename and the container is restarted by
            // the wrapper's own tail — the same shape AdGuard uses.
            quiesce_services: Vec::new(),
        },
        "homepage" => ArchivePlan {
            compose_project: crate::install::homepage::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.homepage_path),
            databases: Vec::new(),
            quiesce_services: Vec::new(),
        },
        "authelia" => ArchivePlan {
            compose_project: crate::install::authelia::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.authelia_path),
            databases: Vec::new(),
            // Stopped, unlike the two above: the directory holds a live SQLite
            // file of sessions and the portal writes to it continuously.
            quiesce_services: vec![crate::install::authelia::CONTAINER],
        },
        "headscale" => ArchivePlan {
            compose_project: crate::install::headscale::COMPOSE_PROJECT,
            data_path: format!("{}/data", input.headscale_path),
            databases: Vec::new(),
            // Stopped for the archive: the data directory is a live SQLite
            // file, and a tar of one taken mid-write restores as a database
            // that only announces itself the next time a node logs in.
            quiesce_services: vec![crate::install::headscale::CONTAINER],
        },
        "vpn-panel" => ArchivePlan {
            compose_project: crate::install::vpn::panel::COMPOSE_PROJECT,
            data_path: format!("{}/data", crate::install::vpn::panel::PATH),
            databases: Vec::new(),
            quiesce_services: vec!["vpnpanel"],
        },
        other => unreachable!("archive_plan_for called with an id outside RESTORABLE_ORDER: {other}"),
    }
}

/// A port of `DashboardAccessSections.restoreArchiveFunction(target:plan:)`.
fn restore_archive_function(target: &str, plan: &ArchivePlan) -> String {
    let name = target.replace('-', "_");
    let project = plan.compose_project;
    let data = &plan.data_path;
    let slot = plan.data_slot();
    let parent = plan.data_parent();

    let mut lines: Vec<String> = vec![
        format!("restore_{name}() {{"),
        "  local plain=\"$ARCHIVE\" tmp=\"\" stage=\"\" previous=\"\" saved=0 rc=0".to_string(),
        "  case \"$ARCHIVE\" in".to_string(),
        "    *.gpg)".to_string(),
        "      tmp=\"$(mktemp -d \"$(dirname \"$ARCHIVE\")/.gpg-XXXXXX\")\"".to_string(),
        "      plain=\"$tmp/restore.tar.gz\"".to_string(),
        "      # --passphrase-fd 0: the secret arrives on stdin, never in argv.".to_string(),
        "      if ! gpg --batch --quiet --yes --decrypt --passphrase-fd 0 \\".to_string(),
        "           --pinentry-mode loopback --output \"$plain\" \"$ARCHIVE\"; then".to_string(),
        "        rm -rf \"$tmp\"".to_string(),
        "        echo \"could not decrypt the backup (wrong passphrase?)\" >&2".to_string(),
        "        exit 1".to_string(),
        "      fi".to_string(),
        "      ;;".to_string(),
        "  esac".to_string(),
        "  # Verified BEFORE anything is stopped: a truncated upload must not".to_string(),
        "  # cost the user the data they still have.".to_string(),
        "  if ! tar -tzf \"$plain\" >/dev/null 2>&1; then".to_string(),
        "    rm -rf \"$tmp\"".to_string(),
        "    echo \"the backup archive is not readable\" >&2".to_string(),
        "    exit 1".to_string(),
        "  fi".to_string(),
        "  # Staged on the SERVICE's own filesystem, so putting the data back".to_string(),
        "  # is a rename rather than a second copy of the whole directory.".to_string(),
        format!("  stage=\"$(mktemp -d '{parent}/.restore-XXXXXX')\""),
        "  # shellcheck disable=SC2064".to_string(),
        "  trap \"rm -rf '$stage' '$tmp'\" EXIT".to_string(),
        "  tar --numeric-owner -xzf \"$plain\" -C \"$stage\"".to_string(),
        format!("  if [ ! -d \"$stage/{slot}\" ]; then"),
        format!("    echo \"the archive carries no {target} data\" >&2"),
        "    exit 1".to_string(),
        "  fi".to_string(),
    ];
    if !plan.quiesce_services.is_empty() {
        let quiesce = plan.quiesce_services.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(" ");
        lines.push(format!("  gd_compose_stop '{project}' {quiesce}"));
    }
    lines.extend([
        "  # The old data is moved aside, never deleted: if the move back".to_string(),
        "  # fails it is the only way home.".to_string(),
        format!("  previous='{data}'\".pre-restore-$STAMP\""),
        format!("  if [ -d '{data}' ]; then mv '{data}' \"$previous\"; saved=1; fi"),
        format!("  if mv \"$stage/{slot}\" '{data}'; then"),
        "    if [ \"$saved\" -eq 1 ]; then echo \"previous data kept at ${previous}\"; fi".to_string(),
        "  else".to_string(),
        "    echo \"restore failed, rolling back to the previous data\" >&2".to_string(),
        format!("    rm -rf '{data}'"),
        "    if [ \"$saved\" -eq 1 ]; then mv \"$previous\" '".to_string() + data + "'; fi",
        format!("    gd_compose_start_all '{project}'"),
        "    exit 1".to_string(),
        "  fi".to_string(),
    ]);
    for db in &plan.databases {
        let helper = match db.engine {
            Engine::Postgres => "gd_load_postgres",
            Engine::Mysql => "gd_load_mysql",
        };
        let db_name_arg = db.database_name.map(|n| format!(" '{n}'")).unwrap_or_default();
        lines.extend([
            "  # The database container has to be up to take its dump back;".to_string(),
            "  # the rest of the project stays down until it is loaded.".to_string(),
            format!("  gd_compose_start '{project}' '{}'", db.service),
            format!(
                "  {helper} '{project}' '{}' \"$stage/gryonixnexus-db/{}\"{db_name_arg} || rc=1",
                db.service, db.file_name
            ),
        ]);
    }
    lines.extend([
        "  # Up again on every path, restored or not.".to_string(),
        format!("  gd_compose_start_all '{project}'"),
        "  if [ \"$rc\" -ne 0 ]; then".to_string(),
        format!("    echo \"the {target} database could not be restored\" >&2"),
        "    exit 1".to_string(),
        "  fi".to_string(),
        "}".to_string(),
    ]);
    lines.join("\n")
}

// MARK: - The two hardcoded arms

/// A port of the `restore_mailcow()` body — byte-identical across every
/// fixture except the localized "not found" message, substituted for
/// `__MAILCOW_NOT_FOUND__` below. A raw string, not a `format!` template:
/// the body is dense with literal `$…`/`${…}`/`$(…)` bash, and escaping
/// every brace for `format!` is where a byte-parity port goes to drift.
const RESTORE_MAILCOW_TEMPLATE: &str = r#"restore_mailcow() {
  [ -x "$MAILCOW_PATH/helper-scripts/backup_and_restore.sh" ] \
    || { echo "__MAILCOW_NOT_FOUND__" >&2; exit 1; }
  # mailcow's helper restores from a DIRECTORY inside its backup
  # location and picks it from a numbered menu. Stage the chosen backup
  # alone in a scratch location so that menu has exactly one entry.
  local stage="$MAILCOW_BACKUPS/.restore-$STAMP"
  mkdir -p "$stage"
  chmod 0777 "$stage"
  # shellcheck disable=SC2064
  trap "rm -rf '$stage'" EXIT
  if [ -d "$ARCHIVE" ]; then
    cp -a "$ARCHIVE" "$stage/"
  else
    tar -xzf "$ARCHIVE" -C "$stage"
  fi
  export MAILCOW_BACKUP_LOCATION="$stage"
  # Bounded input, never `yes` (SIGPIPE under pipefail kills the pipeline).
  # The helper asks exactly two questions and then restores ONCE:
  # "Select a restore point" -> 1, the only staged backup; "Select a
  # dataset to restore" -> 0, the "[ 0 ] - all" entry, which expands to
  # every dataset in the backup (restore() loops over its arguments).
  # Feeding component indices one after another instead — as this did —
  # restores a SINGLE component and discards the rest of the input when
  # the helper exits, and which component index 1 refers to is whatever
  # `ls -f` returns first, so the survivor varied per run while the
  # wrapper still reported success. Verified against mailcow 2026-07a.
  # The trailing "n" answers the vmail branch's "Force a resync now?";
  # extra input is harmless, a missing answer would depend on EOF.
  # Under `timeout` because an unrecognised prompt would otherwise wait
  # for a human that is never coming.
  printf '1\n0\nn\n' \
    | timeout 3600 "$MAILCOW_PATH/helper-scripts/backup_and_restore.sh" restore
}"#;

/// A port of the `restore_vaultwarden()` body — fully static, no
/// interpolation at all (it reads `$VW_CONTAINER`/`$VW_DATA`, both already
/// bash variables set earlier in the script).
const RESTORE_VAULTWARDEN_BODY: &str = r#"restore_vaultwarden() {
  local plain="$ARCHIVE"
  local tmp=""
  case "$ARCHIVE" in
    *.gpg)
      tmp="$(mktemp -d)"
      # shellcheck disable=SC2064
      trap "rm -rf '$tmp'" EXIT
      plain="$tmp/restore.tar.gz"
      # --passphrase-fd 0: the secret arrives on stdin, never in argv.
      gpg --batch --quiet --yes --decrypt --passphrase-fd 0 \
          --pinentry-mode loopback --output "$plain" "$ARCHIVE" \
        || { echo "could not decrypt the backup (wrong passphrase?)" >&2; exit 1; }
      ;;
  esac
  # Verify BEFORE touching live data: a truncated upload must not cost
  # the user the data they still have.
  tar -tzf "$plain" >/dev/null 2>&1 \
    || { echo "the backup archive is not readable" >&2; exit 1; }
  docker stop "$VW_CONTAINER" >/dev/null 2>&1 || true
  # The old data is moved aside, never deleted: if unpacking fails it is
  # the only way back, and the container must come up again either way.
  local previous="${VW_DATA}.pre-restore-$STAMP"
  local saved=0
  if [ -d "$VW_DATA" ]; then mv "$VW_DATA" "$previous"; saved=1; fi
  if tar -xzf "$plain" -C /; then
    if [ "$saved" -eq 1 ]; then echo "previous data kept at ${previous}"; fi
  else
    echo "restore failed, rolling back to the previous data" >&2
    rm -rf "$VW_DATA"
    # Plain `if`, not `[ ... ] && mv`: under `set -e` a false test makes
    # the whole list fail and would abort the function right here,
    # leaving the container stopped.
    if [ "$saved" -eq 1 ]; then mv "$previous" "$VW_DATA"; fi
    docker start "$VW_CONTAINER" >/dev/null 2>&1 || true
    exit 1
  fi
  docker start "$VW_CONTAINER" >/dev/null 2>&1 || true
}"#;

/// A port of `DashboardAccessSections.restoreHelpers` — the shared helpers
/// generated `restore_<id>` arms call, present only when at least one such
/// arm exists (mailcow/vaultwarden predate them and use neither).
const RESTORE_HELPERS: &str = r#"gd_compose_stop() {
  local project="$1"
  shift
  docker compose -p "$project" stop "$@" >/dev/null 2>&1 || true
}

gd_compose_start() {
  local project="$1"
  shift
  docker compose -p "$project" start "$@" >/dev/null 2>&1 || true
}

# Everything the project has, so the service is up again whatever the
# restore did — the same guarantee the vaultwarden arm gives.
gd_compose_start_all() {
  docker compose -p "$1" start >/dev/null 2>&1 || true
}

gd_container() {
  docker compose -p "$1" ps -q "$2" 2>/dev/null | head -n 1
}

# A container that has just been started reports "up" long before its
# engine accepts connections, and a dump loaded into it then fails with
# a connection error that reads exactly like a corrupt backup.
gd_db_wait() {
  local cid="$1" engine="$2" deadline
  deadline=$(( $(date +%s) + 180 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    case "$engine" in
      postgres)
        if docker exec "$cid" sh -c 'exec pg_isready -q -U "$POSTGRES_USER"' >/dev/null 2>&1; then
          return 0
        fi
        ;;
      mysql)
        if docker exec "$cid" sh -c 'if command -v mariadb-admin >/dev/null 2>&1; then A=mariadb-admin; else A=mysqladmin; fi; MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec "$A" ping -u root' >/dev/null 2>&1; then
          return 0
        fi
        ;;
    esac
    sleep 3
  done
  return 1
}

# The credentials come from the container's OWN environment (compose
# put them there), never from the argv of docker exec — that is
# world-readable through /proc on the host.
gd_load_postgres() {
  local cid
  cid="$(gd_container "$1" "$2")"
  if [ -z "$cid" ]; then echo "the $1 database container is not running" >&2; return 1; fi
  if ! gd_db_wait "$cid" postgres; then echo "the $1 database never became ready" >&2; return 1; fi
  if [ ! -s "$3" ]; then echo "the archive carries no $1 database dump" >&2; return 1; fi
  # ON_ERROR_STOP: without it psql replays half a dump and still exits
  # 0, i.e. reports a restore that did not happen.
  if ! docker exec -i "$cid" sh -c \
       'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -v ON_ERROR_STOP=1 -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
       < "$3"; then
    echo "the $1 database could not be loaded" >&2
    return 1
  fi
}

# The fourth argument mirrors gd_dump_mysql: a service that keeps
# several databases in one engine names each one, and the load has to
# put each dump back where it came from.
gd_load_mysql() {
  local cid
  cid="$(gd_container "$1" "$2")"
  if [ -z "$cid" ]; then echo "the $1 database container is not running" >&2; return 1; fi
  if ! gd_db_wait "$cid" mysql; then echo "the $1 database never became ready" >&2; return 1; fi
  if [ ! -s "$3" ]; then echo "the archive carries no $1 database dump" >&2; return 1; fi
  if ! docker exec -i "$cid" sh -c \
       'if command -v mariadb >/dev/null 2>&1; then C=mariadb; else C=mysql; fi; MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec "$C" -u root "${1:-$MYSQL_DATABASE}"' \
       sh "${4:-}" < "$3"; then
    echo "the $1 database could not be loaded" >&2
    return 1
  fi
}"#;

// MARK: - Localization (the only language-dependent lines in this wrapper)

/// A port of `L10nScripts.mailcowNotFound(_:path:)`.
fn mailcow_not_found(language: crate::dns_records::Language, path: &str) -> String {
    use crate::dns_records::Language::*;
    match language {
        En => format!("mailcow not found in {path}"),
        De => format!("mailcow nicht gefunden in {path}"),
        Fr => format!("mailcow introuvable dans {path}"),
        Es => format!("mailcow no encontrado en {path}"),
        Ru => format!("mailcow не найден в {path}"),
        Uk => format!("mailcow не знайдено в {path}"),
        It => format!("mailcow non trovato in {path}"),
        Ja => format!("{path} に mailcow が見つかりません"),
        Zh => format!("在 {path} 中未找到 mailcow"),
    }
}

/// A port of `L10nScripts.restoreDone(_:)`.
fn restore_done(language: crate::dns_records::Language) -> &'static str {
    use crate::dns_records::Language::*;
    match language {
        En => "Restore finished.",
        De => "Wiederherstellung abgeschlossen.",
        Fr => "Restauration terminée.",
        Es => "Restauración finalizada.",
        Ru => "Восстановление завершено.",
        Uk => "Відновлення завершено.",
        It => "Ripristino completato.",
        Ja => "復元が完了しました。",
        Zh => "恢复完成。",
    }
}

// MARK: - Assembly

/// A port of `DashboardAccessSections.restoreWrapper(_:context:language:)`,
/// the `script` local variable only (see this module's own doc for why the
/// framing around it is out of scope here).
///
/// Scenario B's relay never gets this wrapper at all (`vpsSection` never
/// calls `restoreWrapper` — the relay carries no services to restore), so
/// this function is meaningful only for `HostRole::SingleHost`/
/// `HostRole::HomeBackend`; unlike `uninstall`'s two wrappers, there is no
/// second shape to dispatch to by role, and the body itself does not vary
/// with `include_wire_guard` either (nothing here touches the tunnel), so
/// `render` takes no role parameter — a caller building a VPS-relay host's
/// files simply never calls it.
pub fn render(input: &HostInput, backups: &BackupPaths) -> String {
    let settings = &input.install;
    let restorable = restorable_services(input);
    let archive_ids: Vec<&str> =
        restorable.iter().copied().filter(|id| *id != "mailcow" && *id != "vaultwarden").collect();

    let usage_targets = restorable.join("|");

    let mut dir_patterns = vec!["\"$MAILCOW_BACKUPS\"/*".to_string(), "\"$VW_BACKUPS\"/*".to_string()];
    for id in &restorable {
        if *id == "mailcow" || *id == "vaultwarden" {
            continue;
        }
        dir_patterns.push(format!("\"{}\"/*", backups.for_id(id)));
    }
    let dir_patterns = dir_patterns.join("|");

    let generated_helpers =
        if archive_ids.is_empty() { String::new() } else { format!("\n{RESTORE_HELPERS}\n") };

    let generated_arms = archive_ids
        .iter()
        .map(|id| restore_archive_function(id, &archive_plan_for(id, settings)))
        .collect::<Vec<_>>()
        .join("\n\n");

    let generated_cases = archive_ids
        .iter()
        .map(|id| format!("  {id}) restore_{} ;;", id.replace('-', "_")))
        .collect::<Vec<_>>()
        .join("\n");

    let mailcow_body =
        RESTORE_MAILCOW_TEMPLATE.replace("__MAILCOW_NOT_FOUND__", &mailcow_not_found(input.language, &settings.mailcow_path));

    let mut out = String::new();
    out.push_str("#!/bin/bash\n");
    out.push_str("# Managed by gryonixNexus — restore a service from a backup.\n");
    out.push_str(&format!("# Usage: gryonixnexus-restore.sh <{usage_targets}> <archive>\n"));
    out.push_str("#        GPG passphrase (encrypted archives only) on stdin.\n");
    out.push_str("set -euo pipefail\n");
    out.push('\n');
    out.push_str("SERVICE=\"${1:-}\"\n");
    out.push_str("ARCHIVE=\"${2:-}\"\n");
    out.push('\n');
    out.push_str(&format!("MAILCOW_PATH='{}'\n", settings.mailcow_path));
    out.push_str(&format!("MAILCOW_BACKUPS='{}'\n", backups.mailcow));
    out.push_str(&format!("VW_CONTAINER='{}'\n", settings.vaultwarden_container));
    out.push_str(&format!("VW_DATA='{}'\n", settings.vaultwarden_data_path));
    out.push_str(&format!("VW_BACKUPS='{}'\n", backups.vaultwarden));
    out.push_str("STAMP=\"$(date +%Y%m%d-%H%M%S)\"\n");
    out.push('\n');
    out.push_str("# The archive must sit inside a backup directory this deployment owns.\n");
    out.push_str("# Without the check a whitelisted wrapper would happily unpack ANY\n");
    out.push_str("# root-readable file over a service's data directory.\n");
    out.push_str("case \"$ARCHIVE\" in\n");
    out.push_str("  *..*) echo \"invalid path: ${ARCHIVE}\" >&2; exit 2 ;;\n");
    out.push_str("esac\n");
    out.push_str("case \"$ARCHIVE\" in\n");
    out.push_str(&format!("  {dir_patterns}) ;;\n"));
    out.push_str("  *) echo \"path outside the backup directories: ${ARCHIVE}\" >&2; exit 2 ;;\n");
    out.push_str("esac\n");
    out.push_str("[ -e \"$ARCHIVE\" ] || { echo \"no such backup: ${ARCHIVE}\" >&2; exit 2; }\n");
    out.push_str(&generated_helpers);
    out.push('\n');
    out.push_str(&mailcow_body);
    out.push_str("\n\n");
    out.push_str(RESTORE_VAULTWARDEN_BODY);
    out.push_str("\n\n");
    out.push_str(&generated_arms);
    out.push_str("\n\n");
    out.push_str("case \"$SERVICE\" in\n");
    out.push_str("  mailcow) restore_mailcow ;;\n");
    out.push_str("  vaultwarden) restore_vaultwarden ;;\n");
    out.push_str(&generated_cases);
    out.push('\n');
    out.push_str("  *) echo \"unsupported service: ${SERVICE}\" >&2; exit 2 ;;\n");
    out.push_str("esac\n");
    out.push_str("# A streamed command carries no exit status back to the app, so success\n");
    out.push_str("# is announced with a fixed ASCII marker (never the localized line —\n");
    out.push_str("# the app must not have to know which language the script was made in).\n");
    out.push_str(&format!("echo \"{}\"\n", restore_done(input.language)));
    out.push_str("echo 'GRYONIXNEXUS_RESTORE_DONE'");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_records::Language;
    use crate::install::host::HostRole;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/host/restore/{name}.txt", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn base_input() -> Input {
        Input {
            domain: "example.com".to_string(),
            wireguard_vpn_port: 51821,
            xray_reality_port: 8443,
            ..Input::default()
        }
    }

    fn multidomain_input() -> Input {
        Input {
            domain: "example.com".to_string(),
            additional_domains: vec!["example.org".to_string(), "example.net".to_string()],
            wireguard_vpn_port: 51821,
            xray_reality_port: 8443,
            ..Input::default()
        }
    }

    fn host(services: &[&str], language: Language) -> HostInput {
        HostInput {
            services: services.iter().map(|s| s.to_string()).collect(),
            install: base_input(),
            language,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        }
    }

    /// Every fixture under `tests/fixtures/install/host/restore/`, matched
    /// against the `HostInput` its name corresponds to per
    /// `GeneratedScriptLintTests.makeVariants()`'s `serviceSets` — the same
    /// manifest `uninstall.rs`'s fixture test reads. `"bare"` and
    /// `"nomail-ss"` have no restore fixtures at all (unlike uninstall's 25,
    /// this wrapper only kept 45 of 97 dumped variants as DISTINCT bodies —
    /// see `tests/fixtures/install/host/README.md`), so this list has two
    /// fewer service-set rows than `uninstall::tests::fixture_parity`'s.
    #[test]
    fn fixture_parity() {
        let cases: &[(&str, &[&str])] = &[
            ("mailcow", &["mailcow"]),
            ("nomail", &["vaultwarden", "nextcloud", "immich", "forgejo", "gitlab"]),
            (
                "mailcow-wg",
                &["mailcow", "vaultwarden", "nextcloud", "immich", "wireguard-vpn"],
            ),
            (
                "mailcow-awg",
                &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "amnezia-wg"],
            ),
            ("mailcow-xray", &["mailcow", "vaultwarden", "xray-reality"]),
            ("nomail-ovpn", &["vaultwarden", "openvpn"]),
            ("mailu", &["mailu"]),
            ("dms", &["docker-mailserver"]),
            (
                "dms-full",
                &["docker-mailserver", "vaultwarden", "forgejo", "wireguard-vpn"],
            ),
            (
                "mailu-full",
                &["mailu", "vaultwarden", "nextcloud", "immich", "forgejo", "wireguard-vpn"],
            ),
            ("jellyfin", &["jellyfin"]),
            ("jellyfin-full", &["jellyfin", "vaultwarden", "nextcloud", "wireguard-vpn"]),
            ("adguard", &["adguard-home"]),
            // The three of 2026-08-18: they declare a restore in the catalog,
            // so the SSH route has always written their arms — this port had
            // none until a live server refused to back one of them up.
            ("pihole", &["pihole"]),
            ("homepage", &["homepage"]),
            ("authelia", &["authelia"]),
            ("adguard-full", &["adguard-home", "vaultwarden", "nextcloud", "wireguard-vpn"]),
            ("photoprism", &["photoprism"]),
            ("photoprism-immich", &["photoprism", "immich", "vaultwarden"]),
            ("seafile", &["seafile"]),
            ("seafile-nextcloud", &["seafile", "nextcloud", "vaultwarden"]),
            ("psono", &["psono"]),
            ("psono-vaultwarden", &["psono", "vaultwarden"]),
            ("passbolt", &["passbolt"]),
            ("passwords-shelf", &["passbolt", "psono", "vaultwarden"]),
        ];

        for (name, services) in cases {
            for (lang_suffix, language) in [("en", Language::En), ("ru", Language::Ru)] {
                let input = host(services, language);
                let backups = BackupPaths::default();
                let actual = render(&input, &backups);
                let fixture_name = format!("A-{name}-access-{lang_suffix}");
                let expected = fixture(&fixture_name);
                assert_eq!(actual, expected.trim_end_matches('\n'), "{fixture_name}");
            }
        }
    }

    /// The multidomain fixture — a different `Input`, still `Language::En`;
    /// nothing in this wrapper's body reads `domain`/`additional_domains` at
    /// all (no hostnames, no Caddy), so this case exists only because the
    /// service SET (`mailcow, vaultwarden, nextcloud, immich, forgejo,
    /// gitlab, amnezia-wg`) is otherwise uncovered, not because the domain
    /// matters here.
    #[test]
    fn fixture_parity_multidomain() {
        let input = HostInput {
            services: ["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "gitlab", "amnezia-wg"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            install: multidomain_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        };
        let backups = BackupPaths::default();
        let actual = render(&input, &backups);
        let expected = fixture("A-multidomain");
        assert_eq!(actual, expected.trim_end_matches('\n'));
    }

    /// `render` does not depend on `role` at all (see its own doc comment) —
    /// proven directly, since none of the 45 fixtures exercise
    /// `HostRole::HomeBackend`.
    #[test]
    fn render_is_the_same_regardless_of_host_role() {
        let mut input = host(&["adguard-home", "vaultwarden"], Language::En);
        let backups = BackupPaths::default();
        let single_host = render(&input, &backups);
        input.role = HostRole::HomeBackend;
        assert_eq!(render(&input, &backups), single_host);
    }

    /// No archive-backed service selected (only the two hardcoded arms): the
    /// shared `gd_*` helpers must not appear at all — they exist only to be
    /// called by a generated arm, and a wrapper that carries dead helper
    /// functions on every install is bytes nobody asked for.
    #[test]
    fn no_archive_services_omits_the_shared_helpers() {
        let input = host(&["mailcow"], Language::En);
        let backups = BackupPaths::default();
        let script = render(&input, &backups);
        assert!(!script.contains("gd_compose_stop()"));
        assert!(!script.contains("gd_load_mysql()"));
        assert!(script.contains("restore_mailcow() {"));
        assert!(script.contains("restore_vaultwarden() {"));
    }

    /// The two hardcoded arms are present even when NEITHER mailcow nor
    /// vaultwarden is selected — a port of Swift's own unconditional
    /// `restore_mailcow()`/`restore_vaultwarden()` in the template, not
    /// something derived from `restorable`.
    #[test]
    fn the_two_hardcoded_arms_are_always_present() {
        let input = host(&["adguard-home"], Language::En);
        let backups = BackupPaths::default();
        let script = render(&input, &backups);
        assert!(script.contains("restore_mailcow() {"));
        assert!(script.contains("restore_vaultwarden() {"));
        assert!(script.contains("  mailcow) restore_mailcow ;;"));
        assert!(script.contains("  vaultwarden) restore_vaultwarden ;;"));
    }

    /// Negative control's raw material: `data_slot`/`data_parent` are the
    /// two derived values most likely to silently drift (they are computed,
    /// not copied) — pinned directly against the one case that makes the
    /// distinction visible (a path with no subdirectory: gitlab_path itself).
    #[test]
    fn data_parent_and_slot_split_a_bare_opt_path_correctly() {
        let plan = ArchivePlan {
            compose_project: "gitlab",
            data_path: "/opt/gitlab-ce".to_string(),
            databases: Vec::new(),
            quiesce_services: vec!["gitlab"],
        };
        assert_eq!(plan.data_slot(), "gitlab-ce");
        assert_eq!(plan.data_parent(), "/opt");
    }
}
