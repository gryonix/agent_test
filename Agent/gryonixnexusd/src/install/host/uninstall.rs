//! Port of `UninstallSections` — `/opt/gryonixnexus-uninstall.sh`.
//!
//! See `install/host/mod.rs` for the three rules that apply to everything in
//! this module (byte parity against real generated scripts, "function of the
//! whole installed set, not one service", nothing widens the sandbox
//! silently). This file renders the wrapper BODY only — the heredoc content
//! between `cat > /opt/gryonixnexus-uninstall.sh <<'EOF_UNINSTALL'` and its
//! terminator, which is what every fixture under
//! `tests/fixtures/install/host/uninstall/` actually holds. The `log`
//! line, the `writeFile` framing and the trailing `chmod 750` that Swift's
//! `installSection` wraps around it are setup-script concerns this module
//! does not own.
//!
//! **Two parameters `HostInput` alone cannot supply, ported as their own
//! arguments — the same split Swift itself uses.** `UninstallSections`' own
//! functions take `access: DashboardAccessInput` and `context: MailContext`
//! separately; `HostInput` corresponds to `context`, but the wrapper BODY
//! also embeds `DashboardAccessInput.appPublicKey`/`.createUser` (the APP_KEY
//! strip block inside `uninstall_all`) and `ServiceSettings.backupRoot` /
//! `.mailcowBackupDir` / `.vaultwardenBackupDir` (every non-mail-engine
//! service's default backup directory) — none of which `HostInput` carries,
//! because they are backup-wrapper and SSH-fallback concerns, not install-time
//! settings `context::Input` was scoped to. [`DashboardAccess`] and
//! [`BackupPaths`] carry exactly those fields, with Swift's own defaults.
//!
//! **VPN granularity `HostInput.services` cannot supply today.** The agent's
//! own catalog (`discover::CATALOG`) collapses every VPN piece into one id,
//! `"vpn"` — correct for `GetState`/`InstallService`, where the app manages
//! the whole stack as one card, but the Swift wrapper this module ports
//! removes each protocol's OWN compose project individually
//! (`AmneziaWGVPNService`/`ShadowsocksService`/`XrayRealityService`/
//! `OpenVPNService` each have their own `docker compose -p`). This module
//! therefore reads the GRANULAR Swift catalog ids from `services` —
//! `"wireguard-vpn"`, `"amnezia-wg"`, `"shadowsocks"`, `"xray-reality"`,
//! `"openvpn"`, `"vpn-panel"` — exactly as `GeneratedScriptLintTests`'
//! `serviceSets` spell them, and auto-injects `"vpn-panel"` the moment any
//! protocol is present (a port of `MailContext.additionalServices`' `if
//! !ids.isDisjoint(with: vpnProtocols) { ids.insert(.vpnPanel) }` — the
//! fixtures never carry `vpnPanel` explicitly either). The bare aggregate
//! `"vpn"` id `discover` reports is not expanded by this module — whoever
//! wires a live `HostInput` from `discover`'s output has to translate it
//! into the granular ids this module (and the Swift generator it mirrors)
//! actually key on; today that is only ever `"vpn-panel"` +
//! `"wireguard-vpn"`, since those are the only two the agent's own installer
//! (`install::vpn`) can produce.

use crate::install::context::Input;
use crate::install::host::access::service_sudoers_lines;
use crate::install::host::{HostInput, HostRole};

// MARK: - Parameters `HostInput` does not carry

/// `DashboardAccessInput`'s fields the wrapper body itself reads (the APP_KEY
/// strip block in `uninstall_all`) — `HostInput.ssh_user` already carries the
/// account name, so only the other two ride along here.
#[derive(Debug, Clone, PartialEq)]
pub struct DashboardAccess {
    /// `DashboardAccessInput.createUser`. `false` (existing-user mode) makes
    /// the strip block a no-op `:` — the account was never handed a key by
    /// this deployment to take back.
    pub create_user: bool,
    pub app_public_key: String,
}

/// `ServiceSettings.backupRoot` / `.mailcowBackupDir` / `.vaultwardenBackupDir`
/// — every service's default backup directory bar the two with their own
/// historical paths, which `context.backupDirectory(for:)` special-cases.
#[derive(Debug, Clone, PartialEq)]
pub struct BackupPaths {
    pub root: String,
    pub mailcow: String,
    pub vaultwarden: String,
}

impl Default for BackupPaths {
    fn default() -> Self {
        Self {
            root: "/opt/backups".to_string(),
            mailcow: "/opt/backups/mailcow".to_string(),
            vaultwarden: "/opt/backups/vaultwarden".to_string(),
        }
    }
}

impl BackupPaths {
    /// A port of `ServiceContext.backupDirectory(for:)`'s `default` arm —
    /// mailcow and vaultwarden are NOT routed through this (they use `.mailcow`
    /// / `.vaultwarden` directly, matching `MailcowService`/`VaultwardenService`'s
    /// own `uninstallSpec`, which reads the dedicated fields rather than the
    /// generic formula).
    ///
    /// `pub`, not private: `restore.rs` needs the exact same formula for the
    /// backup-directory patterns its wrapper accepts an archive from
    /// (`RestoreSpec.backupDir` is the same `context.backupDirectory(for:)`
    /// call), and a second copy of "root/id" would be one of the two files
    /// this port owns drifting from the other silently.
    pub fn for_id(&self, id: &str) -> String {
        format!("{}/{id}", self.root)
    }
}

// MARK: - Catalog order

use super::CATALOG_ORDER;

/// `ServiceID.vpnProtocols` — everything that shares the panel's `vpn.<domain>`
/// site and is grouped into the single `vpn` uninstall target, `vpn-panel`
/// itself excluded (it is appended separately, always last, matching
/// `servicesHostWrapper`'s "panel last inside the group" comment).
const VPN_PROTOCOLS: &[&str] =
    &["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"];

const VPN_PANEL: &str = "vpn-panel";

fn is_vpn_member(id: &str) -> bool {
    VPN_PROTOCOLS.contains(&id) || id == VPN_PANEL
}

// MARK: - Per-service UninstallSpec

/// A port of `ServiceCatalog.UninstallSpec`.
struct Spec {
    compose_project: Option<&'static str>,
    config_directory: Option<String>,
    data_paths: Vec<String>,
    backup_dirs: Vec<String>,
    pre_steps: Vec<String>,
    post_steps: Vec<String>,
}

impl Spec {
    fn empty() -> Self {
        Self {
            compose_project: None,
            config_directory: None,
            data_paths: Vec::new(),
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }
    }

    /// The default `ManagedService.uninstallSpec(_:)` extension: just the
    /// compose project and the compose file's own directory, nothing else —
    /// what `AmneziaWGVPNService`, `ShadowsocksService`, `XrayRealityService`,
    /// `OpenVPNService` and `GitLabService` all fall back to (none of them
    /// override `uninstallSpec`).
    fn default_for(compose_project: &'static str, config_directory: impl Into<String>) -> Self {
        Self { compose_project: Some(compose_project), config_directory: Some(config_directory.into()), ..Self::empty() }
    }
}

/// A port of every catalog service's `uninstallSpec(_:)`, `id` a raw
/// `ServiceID` value from [`CATALOG_ORDER`]. Panics on an id outside that
/// list — callers only ever reach this through [`services_host_wrapper`]/
/// [`vps_wrapper`], which both filter against it first.
fn spec_for(id: &str, input: &Input, backups: &BackupPaths) -> Spec {
    use crate::install::mail::{dockermailserver as dms, mailcow, mailu};
    match id {
        "mailcow" => Spec {
            compose_project: Some(mailcow::COMPOSE_PROJECT),
            config_directory: Some(input.mailcow_path.clone()),
            data_paths: Vec::new(),
            backup_dirs: vec![backups.mailcow.clone()],
            pre_steps: Vec::new(),
            post_steps: vec![
                format!("systemctl disable --now {unit}.timer >/dev/null 2>&1 || true", unit = mailcow::CERT_SYNC_UNIT),
                format!(
                    "rm -f /etc/systemd/system/{unit}.service /etc/systemd/system/{unit}.timer {script}",
                    unit = mailcow::CERT_SYNC_UNIT,
                    script = mailcow::CERT_SYNC_SCRIPT_PATH
                ),
                "systemctl daemon-reload || true".to_string(),
                format!(
                    "rm -f '{path}/bot-backup.sh' '{path}'/bot-backup.sh.bak.* || true",
                    path = input.mailcow_path
                ),
                format!("rm -f {}", mailcow::DKIM_DUMP_SCRIPT_PATH),
            ],
        },
        "mailu" => Spec {
            compose_project: Some(mailu::COMPOSE_PROJECT),
            config_directory: None,
            data_paths: vec![input.mailu_path.clone()],
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: vec![
                format!("systemctl disable --now {unit}.timer >/dev/null 2>&1 || true", unit = mailu::CERT_SYNC_UNIT),
                format!(
                    "rm -f /etc/systemd/system/{unit}.service /etc/systemd/system/{unit}.timer '{cert}' '{dkim}'",
                    unit = mailu::CERT_SYNC_UNIT,
                    cert = mailu::CERT_SYNC_SCRIPT_PATH,
                    dkim = mailu::DKIM_DUMP_SCRIPT_PATH
                ),
                format!(
                    "rm -f '{cert}'.bak.* '{dkim}'.bak.*",
                    cert = mailu::CERT_SYNC_SCRIPT_PATH,
                    dkim = mailu::DKIM_DUMP_SCRIPT_PATH
                ),
                "systemctl daemon-reload || true".to_string(),
            ],
        },
        "docker-mailserver" => Spec {
            compose_project: Some(dms::COMPOSE_PROJECT),
            config_directory: None,
            data_paths: vec![input.docker_mailserver_path.clone()],
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: vec![
                format!("systemctl disable --now {unit}.timer >/dev/null 2>&1 || true", unit = dms::CERT_SYNC_UNIT),
                format!(
                    "rm -f /etc/systemd/system/{unit}.service /etc/systemd/system/{unit}.timer '{cert}' '{mailbox}' '{dkim}'",
                    unit = dms::CERT_SYNC_UNIT,
                    cert = dms::CERT_SYNC_SCRIPT_PATH,
                    mailbox = dms::MAILBOX_SCRIPT_PATH,
                    dkim = dms::DKIM_DUMP_SCRIPT_PATH
                ),
                format!(
                    "rm -f '{cert}'.bak.* '{mailbox}'.bak.* '{dkim}'.bak.*",
                    cert = dms::CERT_SYNC_SCRIPT_PATH,
                    mailbox = dms::MAILBOX_SCRIPT_PATH,
                    dkim = dms::DKIM_DUMP_SCRIPT_PATH
                ),
                "systemctl daemon-reload || true".to_string(),
            ],
        },
        "vaultwarden" => Spec {
            compose_project: Some(crate::install::vaultwarden::COMPOSE_PROJECT),
            config_directory: Some(crate::install::vaultwarden::COMPOSE_DIRECTORY.to_string()),
            data_paths: vec![
                input.vaultwarden_data_path.clone(),
                format!("{}.pre-restore-*", input.vaultwarden_data_path),
            ],
            backup_dirs: vec![backups.vaultwarden.clone()],
            pre_steps: Vec::new(),
            post_steps: vec!["rm -f /opt/vaultwarden-update.sh /opt/vaultwarden-update.sh.bak.* || true".to_string()],
        },
        "psono" => Spec {
            compose_project: Some(crate::install::psono::COMPOSE_PROJECT),
            config_directory: Some(input.psono_path.clone()),
            data_paths: vec![format!("{}/config.pre-restore-*", input.psono_path)],
            backup_dirs: vec![backups.for_id("psono")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "passbolt" => Spec {
            compose_project: Some(crate::install::passbolt::COMPOSE_PROJECT),
            config_directory: Some(input.passbolt_path.clone()),
            // A port of `PassboltService.secretsPath(_:)`: `<passboltPath>/secrets`.
            data_paths: vec![format!("{}/secrets.pre-restore-*", input.passbolt_path)],
            backup_dirs: vec![backups.for_id("passbolt")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "nextcloud" => Spec {
            compose_project: Some(crate::install::nextcloud::COMPOSE_PROJECT),
            config_directory: Some(input.nextcloud_path.clone()),
            data_paths: vec![format!("{}/data.pre-restore-*", input.nextcloud_path)],
            backup_dirs: vec![backups.for_id("nextcloud")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "seafile" => Spec {
            compose_project: Some(crate::install::seafile::COMPOSE_PROJECT),
            config_directory: Some(input.seafile_path.clone()),
            // A port of `SeafileService.dataPath(_:)`: `<seafilePath>/data`.
            data_paths: vec![format!("{}/data.pre-restore-*", input.seafile_path)],
            backup_dirs: vec![backups.for_id("seafile")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "immich" => Spec {
            compose_project: Some(crate::install::immich::COMPOSE_PROJECT),
            config_directory: Some(input.immich_path.clone()),
            data_paths: vec![format!("{}/library.pre-restore-*", input.immich_path)],
            backup_dirs: vec![backups.for_id("immich")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "photoprism" => Spec {
            compose_project: Some(crate::install::photoprism::COMPOSE_PROJECT),
            config_directory: Some(input.photoprism_path.clone()),
            data_paths: vec![format!("{}/originals.pre-restore-*", input.photoprism_path)],
            backup_dirs: vec![backups.for_id("photoprism")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "gitlab" => Spec::default_for(crate::install::gitlab::COMPOSE_PROJECT, input.gitlab_path.clone()),
        "forgejo" => Spec {
            compose_project: Some(crate::install::forgejo::COMPOSE_PROJECT),
            config_directory: Some(input.forgejo_path.clone()),
            data_paths: vec![format!("{}/data.pre-restore-*", input.forgejo_path)],
            backup_dirs: vec![backups.for_id("forgejo")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "jellyfin" => Spec {
            compose_project: Some(crate::install::jellyfin::COMPOSE_PROJECT),
            config_directory: Some(input.jellyfin_path.clone()),
            data_paths: vec![format!("{}/config.pre-restore-*", input.jellyfin_path)],
            backup_dirs: vec![backups.for_id("jellyfin")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "minecraft-java" => Spec {
            compose_project: Some(crate::install::minecraft::JAVA_COMPOSE_PROJECT),
            config_directory: Some(input.minecraft_java_path.clone()),
            // The world. Removed only under --purge-data, like every other
            // service's data — but worth naming: this is the thing people
            // would miss most.
            data_paths: vec![format!("{}/data", input.minecraft_java_path)],
            backup_dirs: vec![backups.for_id("minecraft-java")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "minecraft-bedrock" => Spec {
            compose_project: Some(crate::install::minecraft::BEDROCK_COMPOSE_PROJECT),
            config_directory: Some(input.minecraft_bedrock_path.clone()),
            data_paths: vec![format!("{}/data", input.minecraft_bedrock_path)],
            backup_dirs: vec![backups.for_id("minecraft-bedrock")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "crafty-controller" => Spec {
            compose_project: Some(crate::install::crafty::COMPOSE_PROJECT),
            config_directory: Some(input.crafty_path.clone()),
            data_paths: vec![
                format!("{}/config", input.crafty_path),
                format!("{}/servers", input.crafty_path),
            ],
            backup_dirs: vec![backups.for_id("crafty-controller")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "open-webui" => Spec {
            compose_project: Some(crate::install::open_webui::COMPOSE_PROJECT),
            config_directory: Some(input.open_webui_path.clone()),
            data_paths: vec![format!("{}/data.pre-restore-*", input.open_webui_path)],
            backup_dirs: vec![backups.for_id("open-webui")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        // No backup directory, because the service has no backup: what lives
        // under its path is MODELS — published files fetched by name — and an
        // archive of them would be tens of gigabytes duplicating something one
        // command downloads again. They still go under an explicit purge with
        // the config directory, which is the right level for a decision
        // somebody may well want to make the other way.
        "ollama" => Spec {
            compose_project: Some(crate::install::ollama::COMPOSE_PROJECT),
            config_directory: Some(input.ollama_path.clone()),
            data_paths: Vec::new(),
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "litellm" => Spec {
            compose_project: Some(crate::install::litellm::COMPOSE_PROJECT),
            config_directory: Some(input.litellm_path.clone()),
            // The two shared secrets, under purge only. An erase that left
            // them behind would leave the most valuable thing on the host on a
            // disk somebody asked to be wiped — and the gateway key is no use
            // to anything once the gateway is gone.
            data_paths: vec![
                crate::install::llm_keys::KEYS_ENV_PATH.to_string(),
                crate::install::litellm::GATEWAY_KEY_PATH.to_string(),
            ],
            backup_dirs: vec![backups.for_id("litellm")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "anythingllm" => Spec {
            compose_project: Some(crate::install::anythingllm::COMPOSE_PROJECT),
            config_directory: Some(input.anythingllm_path.clone()),
            data_paths: vec![format!("{}.pre-restore-*", input.anythingllm_path)],
            backup_dirs: vec![backups.for_id("anythingllm")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "qdrant" => Spec {
            compose_project: Some(crate::install::qdrant::COMPOSE_PROJECT),
            config_directory: Some(input.qdrant_path.clone()),
            // The shared key, under purge only: it is no use to anything once
            // the store is gone, and an erase that left it behind would leave
            // a secret on a disk somebody asked to be wiped. Same rule as the
            // gateway key beside it.
            data_paths: vec![
                crate::install::qdrant::API_KEY_PATH.to_string(),
                format!("{}/storage.pre-restore-*", input.qdrant_path),
            ],
            backup_dirs: vec![backups.for_id("qdrant")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "searxng" => Spec {
            compose_project: Some(crate::install::searxng::COMPOSE_PROJECT),
            config_directory: Some(input.searxng_path.clone()),
            // Nothing outside the config directory: the settings file and the
            // cache both live under it, and there is no shared secret here
            // because nothing else on the host reads one.
            data_paths: Vec::new(),
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "openclaw" => Spec {
            compose_project: Some(crate::install::openclaw::COMPOSE_PROJECT),
            config_directory: Some(input.openclaw_path.clone()),
            data_paths: vec![format!("{}/state.pre-restore-*", input.openclaw_path)],
            backup_dirs: vec![backups.for_id("openclaw")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "n8n" => Spec {
            compose_project: Some(crate::install::n8n::COMPOSE_PROJECT),
            config_directory: Some(input.n8n_path.clone()),
            // `<path>/postgres` is deliberately NOT listed, and Immich sets
            // the precedent: the database volume lives INSIDE the config
            // directory, which this same spec already removes. Naming it here
            // would be a second answer to a question the line above answers,
            // and this file is a port — a divergence from
            // `N8NService.uninstallSpec` is the defect, not the tidiness.
            data_paths: vec![format!("{}/data.pre-restore-*", input.n8n_path)],
            backup_dirs: vec![backups.for_id("n8n")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "adguard-home" => Spec {
            compose_project: Some(crate::install::adguard::COMPOSE_PROJECT),
            config_directory: Some(input.adguard_path.clone()),
            data_paths: vec![format!("{}/conf.pre-restore-*", input.adguard_path)],
            backup_dirs: vec![backups.for_id("adguard-home")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "pihole" => Spec {
            compose_project: Some(crate::install::pihole::COMPOSE_PROJECT),
            config_directory: Some(input.pihole_path.clone()),
            data_paths: vec![format!("{}/etc-pihole.pre-restore-*", input.pihole_path)],
            backup_dirs: vec![backups.for_id("pihole")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "authelia" => Spec {
            compose_project: Some(crate::install::authelia::COMPOSE_PROJECT),
            config_directory: Some(input.authelia_path.clone()),
            data_paths: vec![format!("{}/config.pre-restore-*", input.authelia_path)],
            backup_dirs: vec![backups.for_id("authelia")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "homepage" => Spec {
            compose_project: Some(crate::install::homepage::COMPOSE_PROJECT),
            config_directory: Some(input.homepage_path.clone()),
            data_paths: vec![format!("{}/config.pre-restore-*", input.homepage_path)],
            backup_dirs: vec![backups.for_id("homepage")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        "headscale" => Spec {
            compose_project: Some(crate::install::headscale::COMPOSE_PROJECT),
            config_directory: Some(input.headscale_path.clone()),
            data_paths: vec![format!("{}/data.pre-restore-*", input.headscale_path)],
            backup_dirs: vec![backups.for_id("headscale")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        // Its own project and directory, NOT a corner of headscale's: the two
        // have separate lifetimes, and removing the control server must not
        // silently take the node's identity with it (nor the other way round).
        "tailscale-node" => Spec {
            compose_project: Some(crate::install::tailscale::COMPOSE_PROJECT),
            config_directory: Some(input.tailscale_node_path.clone()),
            data_paths: Vec::new(),
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        // Nothing to keep: everything this service knows is a token that
        // lives in Cloudflare and can be reissued there.
        "cloudflared" => Spec {
            compose_project: Some(crate::install::cloudflared::COMPOSE_PROJECT),
            config_directory: Some(input.cloudflared_path.clone()),
            data_paths: Vec::new(),
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        },
        // WireGuardVPNService.uninstallSpec is a literal `UninstallSpec()` —
        // the panel IS the WireGuard server, so the marker service that
        // contributes the protocol to the catalog removes nothing of its own.
        "wireguard-vpn" => Spec::empty(),
        "amnezia-wg" => Spec::default_for("awgvpn", input.amnezia_wg_path.clone()),
        "shadowsocks" => Spec::default_for("shadowsocks", input.shadowsocks_path.clone()),
        "xray-reality" => Spec::default_for("xray", input.xray_reality_path.clone()),
        "openvpn" => Spec::default_for("openvpn", input.openvpn_path.clone()),
        "vpn-panel" => {
            let path = crate::install::vpn::panel::PATH;
            Spec {
                compose_project: Some(crate::install::vpn::panel::COMPOSE_PROJECT),
                config_directory: Some(path.to_string()),
                data_paths: vec![format!("{path}/data.pre-restore-*")],
                backup_dirs: vec![backups.for_id("vpn-panel")],
                pre_steps: vec!["ip link delete wgpanel 2>/dev/null || true".to_string()],
                post_steps: vec![
                    format!("rm -f {}", crate::install::vpn::panel::LOCKDOWN_SCRIPT_PATH),
                    format!(": > {} 2>/dev/null || true", crate::install::caddy::ADMIN_GUARD_PATH),
                    "systemctl reload caddy 2>/dev/null || true".to_string(),
                ],
            }
        }
        other => unreachable!("spec_for called with an id outside CATALOG_ORDER: {other}"),
    }
}

/// A port of each service's `hostname(_:)`, but only for the ones whose
/// `webIngress(_:)` is non-nil — every catalog service except the four raw
/// VPN protocols (`WireGuardVPNService` included: it has no Caddy site of its
/// own, the panel's is what gets removed). `None` here is what makes
/// `site_headers` skip `remove_caddy_site` for those four, matching Swift's
/// `guard let ingress = service.webIngress(...) else { return [] }`.
pub(crate) fn hostname_for(id: &str, input: &Input) -> Option<String> {
    use crate::install::mail::{dockermailserver as dms, mailcow, mailu};
    match id {
        "mailcow" => Some(mailcow::hostname(input)),
        "mailu" => Some(mailu::hostname(input)),
        "docker-mailserver" => Some(dms::hostname(input)),
        "vaultwarden" => Some(crate::install::vaultwarden::hostname(input)),
        "psono" => Some(crate::install::psono::hostname(input)),
        "passbolt" => Some(crate::install::passbolt::hostname(input)),
        "nextcloud" => Some(crate::install::nextcloud::hostname(input)),
        "seafile" => Some(crate::install::seafile::hostname(input)),
        "immich" => Some(crate::install::immich::hostname(input)),
        "photoprism" => Some(crate::install::photoprism::hostname(input)),
        "gitlab" => Some(crate::install::gitlab::hostname(input)),
        "forgejo" => Some(crate::install::forgejo::hostname(input)),
        "jellyfin" => Some(crate::install::jellyfin::hostname(input)),
        "crafty-controller" => Some(crate::install::crafty::hostname(input)),
        "open-webui" => Some(crate::install::open_webui::hostname(input)),
        "litellm" => Some(crate::install::litellm::hostname(input)),
        "n8n" => Some(crate::install::n8n::hostname(input)),
        "anythingllm" => Some(crate::install::anythingllm::hostname(input)),
        // Publishes nothing — see its module note.
        "qdrant" => None,
        // Nor this: the callers are the containers beside it.
        "searxng" => None,
        "openclaw" => Some(crate::install::openclaw::hostname(input)),
        // The engine publishes nothing: an unauthenticated model API has no
        // business on a hostname.
        "ollama" => None,
        "adguard-home" => Some(crate::install::adguard::hostname(input)),
        "pihole" => Some(crate::install::pihole::hostname(input)),
        "homepage" => Some(crate::install::homepage::hostname(input)),
        "authelia" => Some(crate::install::authelia::hostname(input)),
        "headscale" => Some(crate::install::headscale::hostname(input)),
        // It publishes no site of its own — the names live in Cloudflare.
        "cloudflared" => None,
        "vpn-panel" => Some(crate::install::vpn::panel::hostname(input)),
        "wireguard-vpn" | "amnezia-wg" | "shadowsocks" | "xray-reality" | "openvpn" => None,
        _ => None,
    }
}

/// A port of `UninstallSections.siteHeaders(_:context:)`: zero or one lines
/// (`<name>, <mirror>, <mirror>`), the exact first line of the Caddy site
/// block `caddy::merge_site` writes, minus the trailing ` {`.
fn site_headers(id: &str, input: &Input) -> Vec<String> {
    let Some(hostname) = hostname_for(id, input) else { return Vec::new() };
    let mut names = vec![hostname.clone()];
    names.extend(input.mirrored_hostnames(&hostname));
    vec![names.join(", ")]
}

/// A port of `UninstallSections.quotedPath(_:)`: `*` stays OUTSIDE quotes so
/// a baked-in glob (vaultwarden's `.pre-restore-*`) still expands, while
/// everything else is single-quoted.
fn quoted_path(path: &str) -> String {
    path.split('*')
        .map(|part| if part.is_empty() { String::new() } else { format!("'{part}'") })
        .collect::<Vec<_>>()
        .join("*")
}

/// A port of `UninstallSections.purgeBlock(_:indent:)`.
fn purge_block(spec: &Spec, indent: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut data_targets: Vec<String> = spec.config_directory.clone().into_iter().collect();
    data_targets.extend(spec.data_paths.iter().cloned());
    if !data_targets.is_empty() {
        lines.push(format!("{indent}if [ \"$PURGE_DATA\" -eq 1 ]; then"));
        for target in &data_targets {
            lines.push(format!("{indent}  rm -rf {}", quoted_path(target)));
        }
        lines.push(format!("{indent}fi"));
    }
    if !spec.backup_dirs.is_empty() {
        lines.push(format!("{indent}if [ \"$PURGE_BACKUPS\" -eq 1 ]; then"));
        for target in &spec.backup_dirs {
            lines.push(format!("{indent}  rm -rf {}", quoted_path(target)));
        }
        lines.push(format!("{indent}fi"));
    }
    lines
}

/// A port of `UninstallSections.sudoersOwners(_:context:)`: every selected
/// id's own sudoers lines, mapped to which ids contribute each one. Some
/// lines are NOT unique to one service — every container-based service's
/// `statusProbe` asks the identical `/usr/bin/docker ps -a` — so a removal can
/// only ever drop a line none of its SIBLINGS still need.
fn sudoers_owners(
    ids: &[&'static str],
    input: &Input,
    backups: &BackupPaths,
    user: &str,
) -> std::collections::HashMap<String, std::collections::HashSet<&'static str>> {
    let mut owners: std::collections::HashMap<String, std::collections::HashSet<&'static str>> =
        std::collections::HashMap::new();
    for id in ids {
        for line in service_sudoers_lines(id, input, backups, user) {
            owners.entry(line).or_default().insert(id);
        }
    }
    owners
}

/// A port of `UninstallSections.removableSudoersLines(for:owners:context:)`:
/// the lines a removal unit (one service, or the mesh/VPN group removed
/// together) may safely drop — its own lines, minus any still owned by an id
/// OUTSIDE the unit. A line shared only between members of the SAME unit is
/// safe (the whole unit goes at once); one shared with an id staying
/// installed is not, however identical the two services' requests look.
fn removable_sudoers_lines(
    unit: &[&'static str],
    input: &Input,
    backups: &BackupPaths,
    user: &str,
    owners: &std::collections::HashMap<String, std::collections::HashSet<&'static str>>,
) -> Vec<String> {
    let unit_ids: std::collections::HashSet<&'static str> = unit.iter().copied().collect();
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for id in unit {
        for line in service_sudoers_lines(id, input, backups, user) {
            if !seen.insert(line.clone()) {
                continue;
            }
            let Some(owning) = owners.get(&line) else { continue };
            if owning.iter().any(|owner| !unit_ids.contains(owner)) {
                continue;
            }
            result.push(line);
        }
    }
    result
}

/// A port of `UninstallSections.sudoersRemovalCall(_:)` — one argument per
/// line, single-quoted (a sudoers line never contains a single quote itself).
fn sudoers_removal_call(lines: &[String]) -> Vec<String> {
    if lines.is_empty() {
        return Vec::new();
    }
    let quoted: Vec<String> = lines.iter().map(|line| format!("'{line}'")).collect();
    vec!["  remove_sudoers_lines \\".to_string(), format!("    {}", quoted.join(" \\\n    "))]
}

/// A port of `UninstallSections.uninstallFunction(name:spec:siteHeaders:sudoersLines:)`.
fn uninstall_function(name: &str, spec: &Spec, headers: &[String], sudoers_lines: &[String]) -> String {
    let mut lines = vec![format!("uninstall_{name}() {{")];
    for step in &spec.pre_steps {
        lines.push(format!("  {step}"));
    }
    if let Some(project) = spec.compose_project {
        lines.push(format!("  compose_down '{project}'"));
    }
    for header in headers {
        lines.push(format!("  remove_caddy_site '{header}'"));
    }
    for step in &spec.post_steps {
        lines.push(format!("  {step}"));
    }
    lines.extend(purge_block(spec, "  "));
    lines.extend(sudoers_removal_call(sudoers_lines));
    lines.push("}".to_string());
    lines.join("\n")
}

fn function_name(id: &str) -> String {
    id.replace('-', "_")
}

// MARK: - Cross-cutting removal (shared by both host roles)

const AGENT_UNIT: &str = "gryonixnexusd.service";
const AGENT_BINARY_PATH: &str = "/usr/local/bin/gryonixnexusd";
const AGENT_SOCKET_PATH: &str = "/run/gryonixnexusd.sock";
const AGENT_STATE_DIRECTORY: &str = "/var/lib/gryonixnexus/agent";
const PREDECESSOR_UNIT: &str = "gryonixnexus.service";
const PREDECESSOR_BINARY_PATH: &str = "/usr/local/bin/gryonixd";
const PREDECESSOR_SOCKET_PATH: &str = "/run/gryonixd.sock";

/// A port of `UninstallSections.agentRemoval(indent:)`.
fn agent_removal(indent: &str) -> Vec<String> {
    fn unit_removal(indent: &str, unit: &str, binary: &str, socket: &str) -> Vec<String> {
        vec![
            format!("{indent}if [ -f /etc/systemd/system/{unit} ]; then"),
            format!("{indent}  systemctl disable --now '{unit}' >/dev/null 2>&1 || true"),
            format!("{indent}  rm -f '/etc/systemd/system/{unit}'"),
            format!("{indent}  systemctl daemon-reload || true"),
            format!("{indent}fi"),
            format!("{indent}rm -f '{binary}' '{socket}'"),
        ]
    }
    let mut lines = vec![
        format!("{indent}# Control-plane agent: installed by its own bootstrap, outside this"),
        format!("{indent}# setup, and therefore invisible to everything else here. Stopped"),
        format!("{indent}# before the state directory below is removed — the unit's"),
        format!("{indent}# StateDirectory= re-creates it on every start."),
    ];
    lines.extend(unit_removal(indent, AGENT_UNIT, AGENT_BINARY_PATH, AGENT_SOCKET_PATH));
    lines.push(format!("{indent}rm -rf '{AGENT_STATE_DIRECTORY}'"));
    lines.push(format!("{indent}# The daemon before the rename (gryonixd). install-agent.sh removes"));
    lines.push(format!("{indent}# it, but a host that never re-ran the bootstrap still has it, and"));
    lines.push(format!("{indent}# its unit is Restart=always too."));
    lines.extend(unit_removal(indent, PREDECESSOR_UNIT, PREDECESSOR_BINARY_PATH, PREDECESSOR_SOCKET_PATH));
    lines
}

const SHARED_BACKUP_COPY_GLOBS: &[&str] = &[
    "/etc/nftables.conf.bak.*",
    "/etc/wireguard/wg0.conf.bak.*",
    "/etc/systemd/system/gryonixnexus-*.service.bak.*",
];

fn home_backup_copy_globs() -> Vec<&'static str> {
    let mut globs = SHARED_BACKUP_COPY_GLOBS.to_vec();
    globs.extend([
        "/opt/gryonixnexus-*.bak.*",
        "/opt/vaultwarden-update.sh.bak.*",
        "/etc/caddy/Caddyfile.bak.*",
        "/etc/systemd/system/gryonixnexus-*.timer.bak.*",
        "/etc/sysctl.d/99-gryonixnexus-rpfilter.conf.bak.*",
    ]);
    globs
}

fn vps_backup_copy_globs() -> Vec<&'static str> {
    let mut globs = SHARED_BACKUP_COPY_GLOBS.to_vec();
    globs.extend(["/opt/gryonixnexus-*.bak.*", "/etc/sysctl.d/99-gryonixnexus-forwarding.conf.bak.*"]);
    globs
}

/// A port of `UninstallSections.backupCopyRemoval(indent:globs:)`.
fn backup_copy_removal(indent: &str, globs: &[&str]) -> String {
    format!(
        "{indent}# Backup copies the setup makes before overwriting a managed file.\n{indent}rm -f {} || true",
        globs.join(" ")
    )
}

/// A port of `UninstallSections.appKeyRemoval(_:)`.
///
/// Swift's `access` parameter is never optional (the whole wrapper is only
/// generated when dashboard access was requested), so `guard
/// access.createUser else { return "  :" }` is its only escape hatch. This
/// port adds a second one for a host `HostInput` describes as having no SSH
/// dashboard access at all (`ssh_user: None`, agent-only) — the same "nothing
/// to strip" outcome, spelled the same no-op line, since the wrapper is
/// written unconditionally now (rule 1 in `install/host/mod.rs`'s doc: an
/// agent-only host still needs `-uninstall.sh` on disk for the agent's own
/// `RemoveService` to call).
fn app_key_removal(ssh_user: Option<&str>, access: Option<&DashboardAccess>) -> String {
    let (Some(user), Some(access)) = (ssh_user, access) else { return "  :".to_string() };
    if !access.create_user {
        return "  :".to_string();
    }
    [
        format!("  APP_KEY='{}'", access.app_public_key),
        format!("  USER_HOME=\"$(getent passwd '{user}' | cut -d: -f6 || true)\""),
        "  if [ -n \"$USER_HOME\" ] && [ -f \"$USER_HOME/.ssh/authorized_keys\" ]; then".to_string(),
        "    grep -vxF \"$APP_KEY\" \"$USER_HOME/.ssh/authorized_keys\" > \"$USER_HOME/.ssh/authorized_keys.gryonixnexus\" || true".to_string(),
        "    mv \"$USER_HOME/.ssh/authorized_keys.gryonixnexus\" \"$USER_HOME/.ssh/authorized_keys\"".to_string(),
        "    chmod 600 \"$USER_HOME/.ssh/authorized_keys\"".to_string(),
        "    # Root wrote the replacement, and sshd reads authorized_keys as".to_string(),
        "    # the account: leaving it root-owned makes the file unreadable to".to_string(),
        "    # sshd and kills every OTHER key the account has. Same reason the".to_string(),
        "    # revoke step chowns; see revokeInstallKey.".to_string(),
        format!("    chown '{user}' \"$USER_HOME/.ssh/authorized_keys\""),
        "  fi".to_string(),
    ]
    .join("\n")
}

const CONTAINER_CONTROL_SCRIPT_PATH: &str = "/opt/gryonixnexus-container-ctl.sh";
const RESTORE_SCRIPT_PATH: &str = "/opt/gryonixnexus-restore.sh";
/// `pub` because `provision` writes this file, and `uninstall.rs` (the RPC,
/// not this module) runs it by the same literal.
pub const SCRIPT_PATH: &str = "/opt/gryonixnexus-uninstall.sh";
const DONE_MARKER: &str = "GRYONIXNEXUS_UNINSTALL_DONE";
const VPN_TARGET: &str = "vpn";
const ALL_TARGET: &str = "--all";
const PURGE_DATA_FLAG: &str = "--purge-data";
const PURGE_BACKUPS_FLAG: &str = "--purge-backups";

const WIREGUARD_INTERFACE: &str = "wg0";

/// A port of `DashboardAccessSections.passwordAuthCloseUninstallLines(indent:)`.
///
/// **Before the app-key strip below, and unconditional.** The erase takes this
/// product's key out of `authorized_keys`; doing that first on a host whose
/// password login is closed leaves a machine with neither way in for as long as
/// the rest of the wrapper takes. Unconditional because the wrapper on disk
/// outlives the mode that generated it — a host closed in create-user mode and
/// later re-provisioned without a known key would otherwise keep the drop-in
/// for ever.
fn password_auth_close_uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# SSH password login comes back BEFORE the app key is stripped below,"),
        format!("{indent}# so this machine is never left with neither way in."),
        format!("{indent}rm -f {}", crate::install::ssh_password::DROP_IN_PATH),
        format!("{indent}systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true"),
    ]
}

/// A port of `RelayRouteSyncSections.uninstallLines(indent:)` — constant
/// text, duplicated here rather than imported because the module it belongs
/// to (`install/host/access.rs`'s sibling on the Swift side has no Rust port
/// yet, and this wrapper needs the exact lines regardless of when one lands).
fn relay_route_sync_uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# Policy routing that sends relayed replies back through the"),
        format!("{indent}# tunnel — armed by install(), re-synced by its own timer."),
        format!("{indent}systemctl disable --now 'gryonixnexus-relay-route-sync.timer' 'gryonixnexus-relay-route-sync.service' >/dev/null 2>&1 || true"),
        format!("{indent}rm -f /etc/systemd/system/gryonixnexus-relay-route-sync.timer /etc/systemd/system/gryonixnexus-relay-route-sync.service"),
        format!("{indent}systemctl daemon-reload || true"),
        format!("{indent}rm -f '/opt/gryonixnexus-relay-route-sync.sh'"),
        format!("{indent}ip rule del fwmark '0x1' table '100' 2>/dev/null || true"),
        format!("{indent}ip route flush table '100' 2>/dev/null || true"),
    ]
}

/// A port of `UpdateControlSections.uninstallLines(indent:)` — constant text
/// (no service iterates here; the timer and script are shared infrastructure
/// removed unconditionally). Duplicated for the reason given on
/// `relay_route_sync_uninstall_lines`: `host/update_ctl.rs` is a sibling
/// module under active port by another agent, and this wrapper's fixtures
/// (all 25 of them) pin this exact text regardless of that module's state.
fn update_control_uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# Scheduled updates: the timer is armed by set-schedule, not by"),
        format!("{indent}# setup, so it outlives the services unless it is stopped here."),
        format!("{indent}systemctl disable --now 'gryonixnexus-autoupdate.timer' >/dev/null 2>&1 || true"),
        format!("{indent}rm -f /etc/systemd/system/gryonixnexus-autoupdate.timer /etc/systemd/system/gryonixnexus-autoupdate.service"),
        format!("{indent}rm -f '/etc/gryonixnexus/autoupdate.conf' '/var/lib/gryonixnexus/autoupdate-status.txt'"),
        format!("{indent}rm -f '/opt/gryonixnexus-update-ctl.sh'"),
    ]
}

/// A port of `UninstallSections.dynamicDNSUninstallLines(indent:)`.
///
/// Removed by BOTH routes even though only the agent ever writes these files:
/// a host set up by the script can be given dynamic DNS later and then erased
/// by the wrapper the script generated. See the Swift side for the measurement
/// that found this — a full erase left the updater and both units behind.
fn dynamic_dns_uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# Dynamic DNS: the timer is armed by the panel long after setup,"),
        format!("{indent}# so it outlives the services unless it is stopped here."),
        format!("{indent}systemctl disable --now 'gryonixnexus-ddns.timer' >/dev/null 2>&1 || true"),
        format!("{indent}rm -f /etc/systemd/system/gryonixnexus-ddns.timer /etc/systemd/system/gryonixnexus-ddns.service"),
        format!("{indent}rm -f '/etc/gryonixnexus/ddns.conf' '/var/lib/gryonixnexus/ddns-status.txt'"),
        format!("{indent}rm -f '/opt/gryonixnexus-ddns.sh'"),
    ]
}

/// A port of `BackupControlSections.uninstallLines(indent:)` — see the note
/// on `update_control_uninstall_lines`.
fn backup_control_uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# Scheduled backups: the timer is armed by set-schedule, not by"),
        format!("{indent}# setup, so it outlives the services unless it is stopped here."),
        format!("{indent}systemctl disable --now 'gryonixnexus-autobackup.timer' >/dev/null 2>&1 || true"),
        format!("{indent}rm -f /etc/systemd/system/gryonixnexus-autobackup.timer /etc/systemd/system/gryonixnexus-autobackup.service"),
        format!("{indent}rm -f '/opt/gryonixnexus-backup-ctl.sh'"),
        format!("{indent}rm -rf '/etc/gryonixnexus'"),
    ]
}

// MARK: - Assembly

/// Every non-VPN selected service, in catalog order, deduplicated (the input
/// may repeat — callers are not trusted to have already deduplicated).
fn selected_app_services(input: &HostInput) -> Vec<&'static str> {
    CATALOG_ORDER
        .iter()
        .copied()
        .filter(|id| !is_vpn_member(id) && !is_mesh_member(id) && input.services.iter().any(|s| s == id))
        .collect()
}

/// The mesh group: the control server and the node this host joined it as.
const MESH_TARGET: &str = "headscale";
const MESH_NODE: &str = "tailscale-node";

fn is_mesh_member(id: &str) -> bool {
    id == MESH_TARGET || id == MESH_NODE
}

/// One target, for the same reason the VPN pieces are one: the node was
/// installed by the control server's own call and points AT it, so removing
/// the server alone leaves a node running against a coordinator that is gone.
///
/// **Measured, not reasoned:** `RemoveService(headscale)` on a live host took
/// the server away and left `tailscale` running — and the re-read status still
/// answered `installed: true`, because a container of the service was up.
/// The node is injected whenever the server is present, mirroring how
/// `vpn-panel` follows a protocol.
fn selected_mesh_services(input: &HostInput) -> Vec<&'static str> {
    let has_server = input.services.iter().any(|s| s == MESH_TARGET);
    CATALOG_ORDER
        .iter()
        .copied()
        .filter(|id| {
            let present = input.services.iter().any(|s| s == id);
            is_mesh_member(id) && (present || (*id == MESH_NODE && has_server))
        })
        .collect()
}

/// Every VPN-group member that belongs in `uninstall_vpn`, in catalog order,
/// `vpn-panel` auto-injected the moment any protocol is present — a port of
/// `MailContext.additionalServices`' own injection (see this module's doc).
fn selected_vpn_services(input: &HostInput) -> Vec<&'static str> {
    let has_protocol = VPN_PROTOCOLS.iter().any(|p| input.services.iter().any(|s| s == p));
    CATALOG_ORDER
        .iter()
        .copied()
        .filter(|id| {
            let present = input.services.iter().any(|s| s == id);
            (is_vpn_member(id)) && (present || (*id == VPN_PANEL && has_protocol))
        })
        .collect()
}

/// A port of `UninstallSections.servicesHostWrapper(_:context:includeWireGuard:)`.
/// Used for both `HostRole::SingleHost` (`include_wire_guard: false`) and
/// `HostRole::HomeBackend` (`true`) — the two share everything but the tunnel
/// teardown, exactly as the Swift doc comment on `servicesHostSection` says.
pub fn services_host_wrapper(
    input: &HostInput,
    backups: &BackupPaths,
    access: Option<&DashboardAccess>,
    include_wire_guard: bool,
) -> String {
    // Names are chosen against the neighbours, so the wrapper removes the
    // site this host actually serves.
    let among = input.install_among_neighbours();
    let settings = &among;
    let app_services = selected_app_services(input);
    let vpn_services = selected_vpn_services(input);
    let mesh_services = selected_mesh_services(input);

    // `input.ssh_user: None` means no sudoers whitelist was ever written for
    // this host (access.rs's own doc) — so there is nothing for a removal to
    // drop, and `sudoers_owners` stays empty rather than fabricate a user.
    let all_ids: Vec<&'static str> =
        app_services.iter().copied().chain(mesh_services.iter().copied()).chain(vpn_services.iter().copied()).collect();
    let sudoers_owners_by_line = input
        .ssh_user
        .as_deref()
        .map(|user| sudoers_owners(&all_ids, settings, backups, user))
        .unwrap_or_default();

    let mut functions: Vec<String> = Vec::new();
    let mut case_arms: Vec<String> = Vec::new();
    let mut all_calls: Vec<String> = Vec::new();

    for id in &app_services {
        let name = function_name(id);
        let spec = spec_for(id, settings, backups);
        let headers = site_headers(id, settings);
        let sudoers_lines = input
            .ssh_user
            .as_deref()
            .map(|user| removable_sudoers_lines(&[id], settings, backups, user, &sudoers_owners_by_line))
            .unwrap_or_default();
        functions.push(uninstall_function(&name, &spec, &headers, &sudoers_lines));
        case_arms.push(format!("  {id}) uninstall_{name} ;;"));
        all_calls.push(format!("  uninstall_{name}"));
    }

    if !mesh_services.is_empty() {
        let mut mesh_lines = vec!["uninstall_headscale() {".to_string()];
        let mut seen_projects: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
        for id in &mesh_services {
            let spec = spec_for(id, settings, backups);
            for step in &spec.pre_steps {
                mesh_lines.push(format!("  {step}"));
            }
            if let Some(project) = spec.compose_project {
                if seen_projects.insert(project) {
                    mesh_lines.push(format!("  compose_down '{project}'"));
                }
            }
            for header in site_headers(id, settings) {
                mesh_lines.push(format!("  remove_caddy_site '{header}'"));
            }
            for step in &spec.post_steps {
                mesh_lines.push(format!("  {step}"));
            }
        }
        for id in &mesh_services {
            let spec = spec_for(id, settings, backups);
            mesh_lines.extend(purge_block(&spec, "  "));
        }
        if let Some(user) = input.ssh_user.as_deref() {
            mesh_lines.extend(sudoers_removal_call(&removable_sudoers_lines(
                &mesh_services,
                settings,
                backups,
                user,
                &sudoers_owners_by_line,
            )));
        }
        mesh_lines.push("}".to_string());
        functions.push(mesh_lines.join("\n"));
        // Removing the control server takes its client with it — the client
        // points AT it. The client alone is a separate, smaller removal, and a
        // deployment that joined Tailscale has only that one.
        if input.services.iter().any(|s| s == MESH_TARGET) {
            case_arms.push(format!("  {MESH_TARGET}) uninstall_headscale ;;"));
        }
        case_arms.push(format!("  {MESH_NODE}) uninstall_headscale ;;"));
        all_calls.push("  uninstall_headscale".to_string());
    }

    if !vpn_services.is_empty() {
        let mut vpn_lines = vec!["uninstall_vpn() {".to_string()];
        let mut seen_projects: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
        for id in &vpn_services {
            let spec = spec_for(id, settings, backups);
            for step in &spec.pre_steps {
                vpn_lines.push(format!("  {step}"));
            }
            if let Some(project) = spec.compose_project {
                if seen_projects.insert(project) {
                    vpn_lines.push(format!("  compose_down '{project}'"));
                }
            }
            for header in site_headers(id, settings) {
                vpn_lines.push(format!("  remove_caddy_site '{header}'"));
            }
            for step in &spec.post_steps {
                vpn_lines.push(format!("  {step}"));
            }
        }
        for id in &vpn_services {
            let spec = spec_for(id, settings, backups);
            vpn_lines.extend(purge_block(&spec, "  "));
        }
        if let Some(user) = input.ssh_user.as_deref() {
            vpn_lines.extend(sudoers_removal_call(&removable_sudoers_lines(
                &vpn_services,
                settings,
                backups,
                user,
                &sudoers_owners_by_line,
            )));
        }
        vpn_lines.push("}".to_string());
        functions.push(vpn_lines.join("\n"));
        case_arms.push(format!("  {VPN_TARGET}) uninstall_vpn ;;"));
        all_calls.push("  uninstall_vpn".to_string());
    }

    let tunnel_cleanup = if include_wire_guard {
        let mut lines = vec![
            format!("  systemctl disable --now wg-quick@{WIREGUARD_INTERFACE} >/dev/null 2>&1 || true"),
            format!("  rm -f '/etc/wireguard/{WIREGUARD_INTERFACE}.conf'"),
            "  rm -f /etc/ssh/sshd_config.d/60-gryonixnexus-tunnel.conf".to_string(),
            "  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true".to_string(),
        ];
        lines.extend(relay_route_sync_uninstall_lines("  "));
        lines.push("  rm -f /etc/sysctl.d/99-gryonixnexus-rpfilter.conf".to_string());
        lines.join("\n")
    } else {
        String::new()
    };

    let home_globs = home_backup_copy_globs();

    format!(
        "#!/bin/bash\n\
         # Managed by gryonixNexus — remove services or the whole gryonixNexus install.\n\
         # Usage: gryonixnexus-uninstall.sh <service|{VPN_TARGET}|{ALL_TARGET}> [{PURGE_DATA_FLAG}] [{PURGE_BACKUPS_FLAG}]\n\
         # Default keeps data and backups on disk; the flags delete them (independently).\n\
         set -euo pipefail\n\
         \n\
         TARGET=\"${{1:-}}\"\n\
         PURGE_DATA=0\n\
         PURGE_BACKUPS=0\n\
         shift || true\n\
         for arg in \"$@\"; do\n\
         \x20 case \"$arg\" in\n\
         \x20   {PURGE_DATA_FLAG}) PURGE_DATA=1 ;;\n\
         \x20   {PURGE_BACKUPS_FLAG}) PURGE_BACKUPS=1 ;;\n\
         \x20 esac\n\
         done\n\
         \n\
         compose_down() {{\n\
         \x20 if [ \"$PURGE_DATA\" -eq 1 ]; then\n\
         \x20   # --rmi local also reclaims the images, but only the ones THIS\n\
         \x20   # project's services use — the scoped replacement for the\n\
         \x20   # `docker system prune -af` that used to run once at the end and\n\
         \x20   # took every unused image and stopped container on the host with\n\
         \x20   # it, ours or not. Images still referenced elsewhere are skipped\n\
         \x20   # by docker itself.\n\
         \x20   docker compose -p \"$1\" down --remove-orphans --volumes --rmi local >/dev/null 2>&1 || true\n\
         \x20 else\n\
         \x20   docker compose -p \"$1\" down --remove-orphans >/dev/null 2>&1 || true\n\
         \x20 fi\n\
         }}\n\
         \n\
         # Removes one site block from the Caddyfile. The header is the exact\n\
         # first line of the block as writeCaddyfile emits it (top-level `{cb}` on\n\
         # its own line closes it) — wrapper and Caddyfile are regenerated\n\
         # together on every setup run, so the format cannot drift between them.\n\
         remove_caddy_site() {{\n\
         \x20 local f=/etc/caddy/Caddyfile\n\
         \x20 [ -f \"$f\" ] || return 0\n\
         \x20 awk -v start=\"$1 {{\" '\n\
         \x20   $0 == start {{skip=1; next}}\n\
         \x20   skip && $0 == \"{cb}\" {{skip=0; next}}\n\
         \x20   !skip {{print}}\n\
         \x20 ' \"$f\" > \"$f.gryonixnexus\" && mv \"$f.gryonixnexus\" \"$f\"\n\
         \x20 systemctl reload caddy 2>/dev/null || true\n\
         }}\n\
         \n\
         # Drops exactly the sudoers lines named — baked in by the generator\n\
         # from the SAME sudoersLines a service was whitelisted with, never\n\
         # rediscovered here. Staged and validated with visudo, the same way\n\
         # the whitelist is written: a set of lines that fails to parse (should\n\
         # never happen — they are asked in the format already on disk) leaves\n\
         # the whitelist untouched rather than risk one sudo cannot read.\n\
         remove_sudoers_lines() {{\n\
         \x20 local f=/etc/sudoers.d/gryonixnexus-control\n\
         \x20 [ -f \"$f\" ] || return 0\n\
         \x20 local tmp=\"$f.gryonixnexus\"\n\
         \x20 printf '%s\\n' \"$@\" | grep -vFxf - \"$f\" > \"$tmp\" || true\n\
         \x20 if [ -s \"$tmp\" ] && visudo -cf \"$tmp\" >/dev/null 2>&1; then\n\
         \x20   mv \"$tmp\" \"$f\"\n\
         \x20 else\n\
         \x20   rm -f \"$tmp\"\n\
         \x20 fi\n\
         }}\n\
         \n\
         {functions}\n\
         \n\
         uninstall_all() {{\n\
         {all_calls}\n\
         {update_lines}\n\
         {backup_lines}\n\
         {ddns_lines}\n\
         {agent_lines}\n\
         \x20 # Host metrics collector + its history\n\
         \x20 systemctl disable --now gryonixnexus-metrics >/dev/null 2>&1 || true\n\
         \x20 rm -f /etc/systemd/system/gryonixnexus-metrics.service /opt/gryonixnexus-metrics-collector.sh\n\
         \x20 systemctl daemon-reload || true\n\
         \x20 rm -rf /var/lib/gryonixnexus\n\
         \x20 # The Caddy ingress is entirely ours\n\
         \x20 systemctl disable --now caddy >/dev/null 2>&1 || true\n\
         \x20 rm -f /etc/caddy/Caddyfile '{admin_guard}'\n\
         {tunnel_cleanup}\n\
         \x20 # No host-wide `docker system prune` here: image reclamation is done\n\
         \x20 # per compose project by compose_down --rmi local, which cannot\n\
         \x20 # reach Docker state this deployment did not create.\n\
         \x20 # Dashboard wrappers, then our own whitelist last — after this line\n\
         \x20 # the app's sudo access is gone, which is the point.\n\
         \x20 rm -f '{container_ctl}' '{restore}'\n\
         \x20 # The agent bootstrap wrapper and whatever sources it unpacked. A\n\
         \x20 # root-owned script the erase leaves behind is the DDNS lesson: the\n\
         \x20 # erased machine still carrying something only root can remove.\n\
         \x20 rm -f '{agent_bootstrap}'\n\
         \x20 rm -rf '{agent_unpack}'\n\
         {backup_copy}\n\
         {password_auth}\n\
         {app_key}\n\
         \x20 rm -f /etc/sudoers.d/gryonixnexus-control\n\
         \x20 rm -f '{SCRIPT_PATH}'\n\
         }}\n\
         \n\
         case \"$TARGET\" in\n\
         {case_arms}\n\
         \x20 {ALL_TARGET}) uninstall_all ;;\n\
         \x20 *) echo \"unsupported target: ${{TARGET}}\" >&2; exit 2 ;;\n\
         esac\n\
         echo '{DONE_MARKER}'",
        cb = "}",
        functions = functions.join("\n\n"),
        all_calls = all_calls.join("\n"),
        update_lines = update_control_uninstall_lines("  ").join("\n"),
        backup_lines = backup_control_uninstall_lines("  ").join("\n"),
        ddns_lines = dynamic_dns_uninstall_lines("  ").join("\n"),
        agent_lines = agent_removal("  ").join("\n"),
        admin_guard = crate::install::caddy::ADMIN_GUARD_PATH,
        tunnel_cleanup = tunnel_cleanup,
        container_ctl = CONTAINER_CONTROL_SCRIPT_PATH,
        agent_bootstrap = crate::install::host::access::AGENT_BOOTSTRAP_SCRIPT_PATH,
        agent_unpack = crate::install::host::agent_bootstrap::UNPACK_ROOT,
        restore = RESTORE_SCRIPT_PATH,
        backup_copy = backup_copy_removal("  ", &home_globs),
        password_auth = password_auth_close_uninstall_lines("  ").join("\n"),
        app_key = app_key_removal(input.ssh_user.as_deref(), access),
        case_arms = case_arms.join("\n"),
    )
}

/// A port of `UninstallSections.vpsWrapper(_:language:)` — scenario B's relay
/// half. No fixtures cover this today (every dumped scenario in
/// `GeneratedScriptLintTests.makeVariants()` that the extraction script
/// pulled from is scenario A — see `tests/fixtures/install/host/README.md`
/// and this crate's own `MailRecipe.swift` doc: scenario B writes
/// `setup-vps.sh`/`setup-home-server.sh`, and the extraction command only
/// ever targeted `__setup-mail-server.sh`), so this is ported by reading, not
/// verified byte-for-byte against a real artifact — flagged in this port's
/// final report rather than left silent.
pub fn vps_wrapper(input: &HostInput, access: Option<&DashboardAccess>) -> String {
    let globs = vps_backup_copy_globs();
    format!(
        "#!/bin/bash\n\
         # Managed by gryonixNexus — remove the gryonixNexus install from this relay.\n\
         # Usage: gryonixnexus-uninstall.sh {ALL_TARGET}\n\
         set -euo pipefail\n\
         \n\
         TARGET=\"${{1:-}}\"\n\
         if [ \"$TARGET\" != \"{ALL_TARGET}\" ]; then\n\
         \x20 echo \"unsupported target: ${{TARGET}}\" >&2; exit 2\n\
         fi\n\
         \n\
         systemctl disable --now wg-quick@{WIREGUARD_INTERFACE} >/dev/null 2>&1 || true\n\
         rm -f '/etc/wireguard/{WIREGUARD_INTERFACE}.conf'\n\
         rm -f /etc/sysctl.d/99-gryonixnexus-forwarding.conf\n\
         {agent_lines}\n\
         systemctl disable --now gryonixnexus-metrics >/dev/null 2>&1 || true\n\
         rm -f /etc/systemd/system/gryonixnexus-metrics.service /opt/gryonixnexus-metrics-collector.sh\n\
         systemctl daemon-reload || true\n\
         rm -rf /var/lib/gryonixnexus\n\
         {update_lines}\n\
         {backup_lines}\n\
         {ddns_lines}\n\
         {backup_copy}\n\
         {password_auth}\n\
         {app_key}\n\
         rm -f /etc/sudoers.d/gryonixnexus-control\n\
         rm -f '{SCRIPT_PATH}'\n\
         echo '{DONE_MARKER}'",
        agent_lines = agent_removal("").join("\n"),
        update_lines = update_control_uninstall_lines("").join("\n"),
        backup_lines = backup_control_uninstall_lines("").join("\n"),
        ddns_lines = dynamic_dns_uninstall_lines("").join("\n"),
        backup_copy = backup_copy_removal("", &globs),
        password_auth = password_auth_close_uninstall_lines("").join("\n"),
        app_key = app_key_removal(input.ssh_user.as_deref(), access),
    )
}

/// Dispatches on `input.role` — the one entry point the rest of the agent
/// should call; `services_host_wrapper`/`vps_wrapper` stay `pub` for the
/// fixture tests, which need to call both host roles independently of what a
/// real deployment's `HostInput` would set.
pub fn render(input: &HostInput, backups: &BackupPaths, access: Option<&DashboardAccess>) -> String {
    match input.role {
        HostRole::SingleHost => services_host_wrapper(input, backups, access, false),
        HostRole::HomeBackend => services_host_wrapper(input, backups, access, true),
        HostRole::VpsRelay => vps_wrapper(input, access),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_records::Language;
    use crate::install::context::Input;

    fn fixture(name: &str) -> String {
        let path = format!(
            "{}/tests/fixtures/install/host/uninstall/{name}.txt",
            env!("CARGO_MANIFEST_DIR")
        );
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

    fn host(services: &[&str]) -> HostInput {
        HostInput {
            services: services.iter().map(|s| s.to_string()).collect(),
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        }
    }

    fn access() -> DashboardAccess {
        DashboardAccess {
            create_user: true,
            app_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake gryonixnexus-app".to_string(),
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

    /// Every fixture under `tests/fixtures/install/host/uninstall/`, matched
    /// against the exact `HostInput` its name (per `GeneratedScriptLintTests.
    /// makeVariants()`'s `serviceSets`) corresponds to — the manifest this
    /// module's doc points at, not re-derived from the file name.
    #[test]
    fn fixture_parity() {
        let cases: &[(&str, &[&str])] = &[
            ("A-bare-access-en", &[]),
            ("A-mailcow-access-en", &["mailcow"]),
            ("A-nomail-access-en", &["vaultwarden", "nextcloud", "immich", "forgejo", "gitlab"]),
            (
                "A-mailcow-wg-access-en",
                &["mailcow", "vaultwarden", "nextcloud", "immich", "wireguard-vpn"],
            ),
            (
                "A-mailcow-awg-access-en",
                &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "amnezia-wg"],
            ),
            ("A-nomail-ss-access-en", &["vaultwarden", "shadowsocks"]),
            ("A-mailcow-xray-access-en", &["mailcow", "vaultwarden", "xray-reality"]),
            ("A-nomail-ovpn-access-en", &["vaultwarden", "openvpn"]),
            ("A-mailu-access-en", &["mailu"]),
            ("A-dms-access-en", &["docker-mailserver"]),
            (
                "A-dms-full-access-en",
                &["docker-mailserver", "vaultwarden", "forgejo", "wireguard-vpn"],
            ),
            (
                "A-mailu-full-access-en",
                &["mailu", "vaultwarden", "nextcloud", "immich", "forgejo", "wireguard-vpn"],
            ),
            ("A-jellyfin-access-en", &["jellyfin"]),
            (
                "A-jellyfin-full-access-en",
                &["jellyfin", "vaultwarden", "nextcloud", "wireguard-vpn"],
            ),
            ("A-adguard-access-en", &["adguard-home"]),
            (
                "A-adguard-full-access-en",
                &["adguard-home", "vaultwarden", "nextcloud", "wireguard-vpn"],
            ),
            ("A-photoprism-access-en", &["photoprism"]),
            ("A-photoprism-immich-access-en", &["photoprism", "immich", "vaultwarden"]),
            ("A-seafile-access-en", &["seafile"]),
            ("A-seafile-nextcloud-access-en", &["seafile", "nextcloud", "vaultwarden"]),
            ("A-psono-access-en", &["psono"]),
            ("A-psono-vaultwarden-access-en", &["psono", "vaultwarden"]),
            ("A-passbolt-access-en", &["passbolt"]),
            ("A-passwords-shelf-access-en", &["passbolt", "psono", "vaultwarden"]),
        ];

        for (fixture_name, services) in cases {
            let input = host(services);
            let backups = BackupPaths::default();
            let acc = access();
            let actual = services_host_wrapper(&input, &backups, Some(&acc), false);
            let expected = fixture(fixture_name);
            assert_eq!(actual, expected.trim_end_matches('\n'), "{fixture_name}");
        }
    }

    /// Every root-owned file this crate names has to come off again.
    ///
    /// **Found live, 2026-08-15.** A full erase on a real host left
    /// `/opt/gryonixnexus-ddns.sh` and both of its systemd units behind. Dynamic
    /// DNS had shipped hours earlier and its removal lines had simply never
    /// been written; with the timer still armed, an "erased" host would have
    /// kept a root-owned job firing every five minutes against a configuration
    /// the erase had just deleted.
    ///
    /// This is the rule ARCHITECTURE.md already states twice over — everything
    /// the install puts down must come off here, INCLUDING what appears later
    /// than the install (the autobackup timer, the `.bak.<epoch>` copies).
    /// Each time it was written down, and each time the NEXT new file broke it,
    /// because nothing checked.
    ///
    /// **It cannot tell which files we create** — they are string literals — so
    /// it does not guess: every `/opt/gryonixnexus-*.sh` and
    /// `/etc/systemd/system/gryonixnexus-*` path the crate names in CODE must be
    /// named by one of the two wrappers. Comments are stripped first, because a
    /// path can legitimately appear in prose saying we deliberately do NOT use
    /// it (`mailcow.rs` names one exactly that way).
    #[test]
    fn every_managed_path_the_crate_names_is_removed_by_some_wrapper() {
        // Both wrappers, each with every service, because a removal that only
        // runs under one arm still counts — and the relay's wrapper is a
        // different function with no fixture of its own.
        let everything: Vec<String> = CATALOG_ORDER.iter().map(|id| id.to_string()).collect();
        let acc = access();
        let backups = BackupPaths::default();
        // EVERY role, not just the single host: scenario B's home half is the
        // only one that removes the relay's route-sync timer, so a test that
        // rendered one role would call that removal missing. Roles differ in
        // what they clean up, which is exactly why the union is the question.
        let mut wrappers = String::new();
        for role in [HostRole::SingleHost, HostRole::HomeBackend, HostRole::VpsRelay] {
            let input = HostInput {
                services: everything.clone(),
                install: base_input(),
                language: Language::En,
                ssh_user: Some("admin".to_string()),
                role,
            };
            wrappers.push_str(&render(&input, &backups, Some(&acc)));
            wrappers.push('\n');
            wrappers.push_str(&vps_wrapper(&input, Some(&acc)));
            wrappers.push('\n');
        }

        let mut unremoved = Vec::new();
        for path in managed_paths_named_in_code() {
            if !wrappers.contains(&path) {
                unremoved.push(path);
            }
        }
        assert!(
            unremoved.is_empty(),
            "these root-owned paths are written by this crate and removed by neither wrapper — \
             an erased host would keep them:\n  {}",
            unremoved.join("\n  ")
        );
    }

    /// Managed paths named anywhere in the crate's CODE, comments excluded.
    fn managed_paths_named_in_code() -> std::collections::BTreeSet<String> {
        fn sources(dir: &std::path::Path, into: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("a source directory reads").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    sources(&path, into);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    into.push(path);
                }
            }
        }

        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        sources(&root, &mut files);

        let mut found = std::collections::BTreeSet::new();
        for file in files {
            let text = std::fs::read_to_string(&file).expect("a source file reads");
            for line in text.lines() {
                let code = line.trim_start();
                // A path in prose is not a path we write — `mailcow.rs` names
                // one precisely to say it is NOT used.
                if code.starts_with("//") {
                    continue;
                }
                for prefix in [
                    "/opt/gryonixnexus-",
                    "/etc/systemd/system/gryonixnexus-",
                    // The third prefix, added with the sshd password close.
                    // A drop-in this product leaves behind is worse than a
                    // stray wrapper: it does not sit inert, it keeps deciding
                    // how the machine can be logged into, on a host the owner
                    // believes is erased.
                    "/etc/ssh/sshd_config.d/",
                ] {
                    let mut rest = line;
                    while let Some(at) = rest.find(prefix) {
                        let tail = &rest[at..];
                        let end = tail
                            .find(|c: char| !(c.is_ascii_alphanumeric() || "/-_.".contains(c)))
                            .unwrap_or(tail.len());
                        let path = &tail[..end];
                        if path.ends_with(".sh")
                            || path.ends_with(".service")
                            || path.ends_with(".timer")
                            || path.ends_with(".conf")
                        {
                            found.insert(path.to_string());
                        }
                        rest = &tail[end.max(1)..];
                    }
                }
            }
        }
        found
    }

    /// The multidomain fixture: a different `Input` (two additional domains),
    /// still `services_host_wrapper` with `include_wire_guard: false`.
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
        let acc = access();
        let actual = services_host_wrapper(&input, &backups, Some(&acc), false);
        let expected = fixture("A-multidomain");
        assert_eq!(actual, expected.trim_end_matches('\n'));
    }

    /// `render` dispatches on `role` rather than requiring callers to pick
    /// the right function themselves — proven against the same fixture two
    /// ways, not just that it compiles.
    #[test]
    fn render_dispatches_single_host_to_the_services_wrapper() {
        let input = host(&["adguard-home"]);
        let backups = BackupPaths::default();
        let acc = access();
        assert_eq!(
            render(&input, &backups, Some(&acc)),
            services_host_wrapper(&input, &backups, Some(&acc), false)
        );
    }

    /// **Every id the agent can INSTALL must have an arm here.** The suite was
    /// green while a freshly added service could be installed and then not
    /// removed: `RemoveService` answered "unsupported target", and only a live
    /// run said so — the wrapper is generated from a table, and a service
    /// missing from it produces a script that simply has no case for it.
    #[test]
    fn every_installable_service_can_also_be_removed() {
        let ids = crate::install::execute::implemented_service_ids();
        // The installer takes ONE aggregate id for the whole VPN; the host it
        // produces carries the individual protocols, and the wrapper groups
        // them back under a single `vpn` target. Expanding it here is that
        // documented mapping, not a way around the check.
        let mut on_host: Vec<&str> = Vec::new();
        for id in &ids {
            if *id == "vpn" {
                on_host.extend(VPN_PROTOCOLS.iter().copied());
                on_host.push(VPN_PANEL);
            } else {
                on_host.push(id);
            }
        }
        let input = host(&on_host);
        let script = services_host_wrapper(&input, &BackupPaths::default(), None, false);
        for id in ids {
            assert!(
                script.contains(&format!("{id}) uninstall_")),
                "the uninstall wrapper has no arm for `{id}` — installing it would leave a service \
                 the agent cannot remove"
            );
        }
    }

    /// No SSH dashboard access at all (agent-only host): the wrapper still
    /// renders — an agent-installed host needs `-uninstall.sh` on disk for
    /// the agent's OWN `RemoveService` to call, which has nothing to do with
    /// whether the app's SSH fallback was ever provisioned — and the APP_KEY
    /// block collapses to the same no-op `:` line Swift's `createUser: false`
    /// takes, not a missing line (the case arms and function bodies of the
    /// rest of the script are unaffected — the difference is contained to
    /// the one line inside `uninstall_all`).
    #[test]
    fn no_dashboard_access_collapses_the_app_key_block_to_a_no_op() {
        let input = HostInput { ssh_user: None, ..host(&["adguard-home"]) };
        let backups = BackupPaths::default();
        let script = services_host_wrapper(&input, &backups, None, false);
        assert!(script.contains("\n  :\n"), "expected a bare no-op line inside uninstall_all:\n{script}");
        assert!(!script.contains("APP_KEY="));
        // Everything else about the script is untouched by the access
        // question — same case arm, same function.
        assert!(script.contains("adguard-home) uninstall_adguard_home ;;"));
    }

    /// `create_user: false` (existing-user mode) takes the same no-op path as
    /// no access at all — this is the branch Swift's `guard access.createUser
    /// else { return "  :" }` exists for, and no fixture exercises it
    /// (`GeneratedScriptLintTests` only ever constructs `DashboardAccessInput`
    /// with its default `createUser: true`).
    #[test]
    fn existing_user_mode_also_collapses_to_a_no_op() {
        let input = host(&["adguard-home"]);
        let backups = BackupPaths::default();
        let acc = DashboardAccess { create_user: false, app_public_key: "irrelevant".to_string() };
        let script = services_host_wrapper(&input, &backups, Some(&acc), false);
        assert!(script.contains("\n  :\n"));
        assert!(!script.contains("APP_KEY="));
    }

    /// `quoted_path` keeps `*` outside quotes so a baked-in glob still
    /// expands — proven directly rather than only through the fixtures,
    /// where it is easy to lose in the noise of a much larger diff.
    #[test]
    fn quoted_path_keeps_the_glob_star_unquoted() {
        assert_eq!(quoted_path("/opt/adguardhome/conf.pre-restore-*"), "'/opt/adguardhome/conf.pre-restore-'*");
        assert_eq!(quoted_path("/opt/adguardhome"), "'/opt/adguardhome'");
    }

    /// Negative control for the whole harness: this repository has been
    /// burned five times by a checker that was green on nothing (GOTCHAS.md's
    /// "Общее правило проверок"). One deliberate one-byte corruption of a
    /// well-known, widely-shared line has to fail MORE than one test — this
    /// isn't checked in, it is exercised by hand per the task's negative
    /// control requirement and then reverted; see the porting report for the
    /// counts.
    #[test]
    fn every_case_arm_uses_the_hyphenated_catalog_id_not_the_function_name() {
        let input = host(&["adguard-home", "docker-mailserver"]);
        let backups = BackupPaths::default();
        let acc = access();
        let script = services_host_wrapper(&input, &backups, Some(&acc), false);
        assert!(script.contains("  adguard-home) uninstall_adguard_home ;;"));
        assert!(script.contains("  docker-mailserver) uninstall_docker_mailserver ;;"));
        assert!(!script.contains("  adguard_home)"));
    }

    /// `vps_wrapper` — no fixture (see its own doc comment), so this is a
    /// structural check against a hand-read Swift source rather than a byte
    /// comparison: the relay's `--all`-only case, the tunnel + forwarding
    /// sysctl teardown, and the agent removal block all present, and NONE of
    /// the services-host-only content (Caddy, container-ctl, restore wrapper
    /// paths, per-service functions) leaks in — the same invariant
    /// `testVPSHasNoHomeOnlyProvisioning` pins on the Swift side.
    #[test]
    fn vps_wrapper_has_no_home_only_provisioning() {
        let input = HostInput {
            services: Vec::new(),
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::VpsRelay,
        };
        let acc = access();
        let script = vps_wrapper(&input, Some(&acc));
        assert!(script.contains("Usage: gryonixnexus-uninstall.sh --all"));
        assert!(script.contains("if [ \"$TARGET\" != \"--all\" ]; then"));
        assert!(script.contains("wg-quick@wg0"));
        assert!(script.contains("/etc/sysctl.d/99-gryonixnexus-forwarding.conf"));
        assert!(script.contains(AGENT_UNIT));
        assert!(script.ends_with("echo 'GRYONIXNEXUS_UNINSTALL_DONE'"));
        assert!(!script.contains("/etc/caddy/Caddyfile"));
        assert!(!script.contains(CONTAINER_CONTROL_SCRIPT_PATH));
        assert!(!script.contains("compose_down"));
    }

    /// `render` sends `HostRole::VpsRelay` to `vps_wrapper`, not the
    /// services-host wrapper — the two produce very different scripts, so a
    /// misrouted role would be obvious in a real deployment, but only if
    /// something actually asserts the dispatch.
    /// **One target takes the whole mesh down.** The node points at the
    /// control server; leaving it running against a coordinator that is gone
    /// is not a smaller removal, it is a broken one — measured live
    /// 2026-08-14, where the server went and `tailscale` stayed up and the
    /// re-read status still said the service was installed.
    #[test]
    fn removing_the_control_server_takes_its_node_with_it() {
        // Both ids, because that is what a real request carries: the app
        // sends the deployment's whole service set and Swift injects the node
        // beside the server. A fixture naming only the server would pass even
        // with the grouping removed — checked, and it did.
        let input = HostInput {
            services: vec!["headscale".to_string(), "tailscale-node".to_string()],
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        };
        let script = services_host_wrapper(&input, &BackupPaths::default(), None, false);

        // Both projects, in one function, reachable from the one arm the app
        // asks for.
        assert!(script.contains("uninstall_headscale() {"), "{script}");
        assert!(script.contains("compose_down 'headscale'"), "{script}");
        assert!(script.contains("compose_down 'tailscale'"), "{script}");
        assert!(script.contains("  headscale) uninstall_headscale ;;"), "{script}");
        // The node has an arm of its own as well, and it is not a duplicate:
        // a deployment that joined Tailscale has no control server at all, so
        // that is the only name its removal can be asked for. Both arms reach
        // the same function — removing either takes the pair, which is right,
        // because a client pointed at a server that is gone is not a smaller
        // installation, it is a broken one.
        assert!(script.contains("  tailscale-node) uninstall_headscale ;;"), "{script}");
    }

    #[test]
    fn render_dispatches_vps_relay_to_the_vps_wrapper() {
        let input = HostInput {
            services: Vec::new(),
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::VpsRelay,
        };
        let acc = access();
        assert_eq!(render(&input, &BackupPaths::default(), Some(&acc)), vps_wrapper(&input, Some(&acc)));
    }
}
