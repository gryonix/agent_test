//! The HOST half of install — everything the setup script provisions that is
//! not one service's compose project.
//!
//! **Why this exists.** Слайсы 4.2–4.10 ported the services: an agent can
//! create `/opt/<service>`, write its compose file and secrets, run docker and
//! merge its Caddy site. What it could NOT do is leave behind the root-owned
//! surface every LATER operation stands on. On a host installed only through
//! the agent there is today no `/opt/gryonixnexus-backup-ctl.sh`, no
//! `-update-ctl.sh`, no `-uninstall.sh`, no `-restore.sh`, no metrics
//! collector and no install report — so `Backup`, `Update`, `Restore` and
//! `RemoveService`, all of which were live-verified in Ф2, answer "wrapper not
//! installed" on exactly the hosts Ф4 is supposed to be able to build alone.
//! Ф2 owns the CONTRACT with those wrappers (`backup.rs`/`update.rs`/
//! `restore.rs`/`removal.rs` run them by absolute path); this module is what
//! puts them on disk.
//!
//! **The agent is root, so sudoers is not what makes these reachable.** The
//! unit runs as root and executes the wrappers directly — no `sudo` appears
//! anywhere in `backup.rs`/`update.rs`/`restore.rs`. The sudoers file and the
//! control user matter for the OTHER caller: the app's SSH path, which
//! `ServiceRemovalRouting` and friends still fall back to. That is why
//! `access` is in this module but is not what the rest of it depends on.
//!
//! ## Three decisions that apply to every file here
//!
//! **1. Byte parity with the generator, not "equivalent behaviour".** Each
//! wrapper is emitted by the Swift generator today, and both routes must put
//! the SAME bytes on disk: the app parses these wrappers' output (markers like
//! `GRYONIXNEXUS_BACKUP_ESTIMATE`, the `ls` listing `BackupListParser` reads),
//! and a host that was set up by the script and later managed by the agent
//! must not drift from one that was not. Fixtures are extracted from REAL
//! generated setup scripts (heredoc bodies — the exact bytes `cat` writes) and
//! diffed byte-for-byte, the same discipline every service slice used.
//!
//! **2. The wrapper is a function of the INSTALLED SET, not of one service.**
//! The setup script writes each wrapper once, for the whole deployment, with a
//! `case` arm per service. The agent installs one service at a time — so every
//! install REGENERATES these files from the union of what `discover` reports
//! plus the service being installed. A wrapper rewritten from the single
//! service in the current request would silently delete the arms for every
//! service already on the host, which is the same class of defect as
//! `caddy::merge_site`'s (a file that belongs to the host being overwritten by
//! one service's view of it). Rewriting in full is idempotent and is what the
//! service slices already do for compose files.
//!
//! **3. Nothing here may widen the sandbox silently.** `ProtectSystem=full`
//! keeps `/etc` read-only and the exception list is CUMULATIVE — `/etc/caddy`,
//! `/etc/gryonixnexus` and `/etc/systemd/system` each cost a live failure and a
//! version bump before they were found. Anything in this module that writes
//! under `/etc` (sudoers, timers) must have its path in the unit's
//! `ReadWritePaths` BEFORE it is live-tested, and the crate version bumped, or
//! the fix lands on disk while the broken namespace keeps running in memory.

use crate::dns_records::Language;
use crate::install::context::Input;

/// What every file in this module renders from.
///
/// One struct rather than one per wrapper, for the same reason
/// `context::Input` is one struct for every service: the wrappers are all
/// functions of the SAME thing — which services this host carries, where they
/// live, and who may call them.
#[derive(Debug, Clone, PartialEq)]
pub struct HostInput {
    /// Every service on this host, as catalog ids, SORTED — the union of what
    /// `discover` reports and the one being installed, never just the request's
    /// service (see rule 2 in this module's doc: a wrapper rewritten from one
    /// service deletes the arms of every other).
    pub services: Vec<String>,
    /// The same install-time input the service modules render from: paths,
    /// domain, settings. The wrappers need it for per-service directories.
    pub install: Input,
    /// The language the wrapper's own human-readable messages are written in.
    pub language: Language,
    /// The control user the sudoers whitelist is written for. `None` on a host
    /// where nothing but the agent will ever call these — the agent is root and
    /// runs them directly, so sudoers is for the app's SSH fallback only.
    pub ssh_user: Option<String>,
    /// Scenario B is not scenario A with an extra host: the relay carries no
    /// dashboard wrappers and no Caddy, and uninstall runs home BEFORE the VPS.
    pub role: HostRole,
}

impl HostInput {
    /// The install input with THIS HOST'S service list written into it.
    ///
    /// **Because a default hostname is a function of the neighbours**
    /// (`install::hostnames`): one forge on a host is `git.<domain>`, two make
    /// each say which it is. `install` is the per-service request, which knows
    /// only the service it came for; `services` is the union this struct
    /// exists to carry. Every host-level renderer that prints or scripts a
    /// service ADDRESS has to ask with the union, or the report names a site
    /// the Caddyfile does not have.
    pub fn install_among_neighbours(&self) -> Input {
        Input { installed_services: self.services.clone(), ..self.install.clone() }
    }
}

/// Which half of the deployment this host is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRole {
    /// Scenario A, and the services host of a local-only deployment.
    SingleHost,
    /// Scenario B's public half — relays traffic, provisions no dashboard
    /// wrappers of its own.
    VpsRelay,
    /// Scenario B's private half — carries the services.
    HomeBackend,
}

/// `ServiceRegistry.all`'s order, as the raw `ServiceID` values.
///
/// NOT alphabetical and not incidental: it is a product-decision order (the
/// Swift file's own comment on GitLab leading Forgejo, because switching a
/// category on installs its FIRST member), and `ServiceRegistry.services(_:)`
/// FILTERS this list rather than sorting by id. Every file here that emits
/// per-service arms — the wrappers' `case` bodies, the report's credential
/// blocks — has to walk the SAME sequence or its multi-service fixtures drift.
/// Shared rather than copied per module for the reason `lock` is shared: a
/// leaf nobody owns is how two ports end up disagreeing.
pub const CATALOG_ORDER: &[&str] = &[
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
    // Forgejo leads `code` since 2026-08-19 (owner's decision, reversing the
    // earlier one — GitLab's 8 GB floor made it a default nobody's machine
    // could run). Order is not cosmetic here: the report and every wrapper
    // walk this sequence, so a list that disagrees with `ServiceRegistry`
    // shows up as drifted multi-service fixtures and nowhere else.
    "forgejo",
    "gitlab",
    "jellyfin",
    // The games shelf, mirroring `ServiceRegistry`: the engines, then the
    // panel that operates them.
    "minecraft-java",
    "minecraft-bedrock",
    "crafty-controller",
    "adguard-home",
    // Mirrors `ServiceRegistry`: AdGuard leads the DNS shelf, Pi-hole follows.
    "pihole",
    "headscale",
    // Right after the control server, mirroring `ServiceRegistry`: the node is
    // installed by the server's own call and has nothing to join before it.
    "tailscale-node",
    "cloudflared",
    // Last in `ServiceRegistry` too: the page is built FROM the others.
    "homepage",
    // In FRONT of the services above it, so it is provisioned after them.
    "authelia",
    "wireguard-vpn",
    "amnezia-wg",
    "shadowsocks",
    "xray-reality",
    "openvpn",
    "vpn-panel",
    // The AI shelf, last in `ServiceRegistry` too. The chat leads the engine
    // there, and this list mirrors it: the order is what the report and every
    // wrapper walk, so a sequence that disagrees shows up as drifted
    // multi-service fixtures and nowhere else.
    "open-webui",
    "ollama",
    // The retrieval chat, between the engine it usually talks to and the
    // gateway — the shelf order `ServiceRegistry` fixes.
    "anythingllm",
    "litellm",
    // Last on the shelf, and installed after the service that reads from it.
    "qdrant",
    // The two the shelf ends with: the engine the others call, then the
    // assistant whose report names whatever backend the host provides.
    "searxng",
    "openclaw",
    // The automation shelf, after the AI one for the reason its category is
    // ordered after it: a workflow that calls a model wants the model
    // installed first.
    "n8n",
];

/// The VPN's catalog ids — the panel plus the five protocols.
///
/// `HostInput.services` carries `ServiceRegistry` ids, never the agent's
/// collapsed `"vpn"`. That is stated on the field, and `backup_ctl` still got
/// it wrong: it keyed the panel's backup target on `"vpn"`, its own fixture
/// tests passed `"vpn"` too, and so the disagreement was invisible until a
/// live host produced a wrapper whose backup list had silently lost the VPN
/// panel (nukki, 2026-08-12). Every module that asks "is there a VPN here"
/// asks THIS now.
pub const VPN_IDS: &[&str] = &[
    "wireguard-vpn",
    "amnezia-wg",
    "shadowsocks",
    "xray-reality",
    "openvpn",
    "vpn-panel",
];

/// Does this host carry any VPN piece?
pub fn has_vpn(services: &[String]) -> bool {
    services.iter().any(|id| VPN_IDS.contains(&id.as_str()))
}

/// Shared by the two wrappers that run both unattended and on demand.
/// Ported ahead of them deliberately: it is the one piece `backup_ctl` and
/// `update_ctl` both emit, and a shared leaf nobody owns is how two parallel
/// ports end up disagreeing about a lock's namespace.
pub mod agent_bootstrap;
pub mod lock;

/// The sudoers whitelist and `/opt/gryonixnexus-container-ctl.sh` (the single
/// whitelisted entry point for container start/stop/restart).
///
/// `DashboardAccessSections`' three REMAINING pieces — creating the control
/// user, installing the app's SSH key, revoking the install key — are NOT
/// ported, and now deliberately never will be here. Owner's decision
/// 2026-08-12: **the agent updates the whitelist, it never grants access.**
/// The reasoning is worth keeping, because the intuition runs the other way:
/// the agent is already root (it writes `/opt`, drives docker), so sudoers
/// does not bound what a compromised agent can do — but creating ACCOUNTS and
/// installing KEYS would genuinely widen it, handing a compromised agent the
/// ability to grant SSH access to the host. What sudoers does bound is the
/// app's SSH control user, and keeping that whitelist current is the whole
/// point: after an agent install, the newly installed service had no lines in
/// it, so the dashboard's buttons for that service did not work.
/// `provision::control_user` therefore reads the user's name out of the
/// EXISTING whitelist; no file means no control user and no sudoers at all.
pub mod access;

/// `/opt/gryonixnexus-backup-ctl.sh` — `BackupControlSections`.
pub mod backup_ctl;

/// `/opt/gryonixnexus-update-ctl.sh` — `UpdateControlSections`.
pub mod update_ctl;

/// `/opt/gryonixnexus-uninstall.sh` — `UninstallSections`.
pub mod uninstall;

/// `/opt/gryonixnexus-restore.sh` — `DashboardAccessSections.restoreWrapper`.
pub mod restore;

/// `/opt/gryonixnexus-admin-lockdown.sh` — the VPN-only admin guard control.
pub mod lockdown;

/// `/opt/gryonixnexus-metrics-collector.sh` and its unit — the CSV bucket daemon
/// `ServerMetricsStore` reads.
pub mod metrics;

/// `install-report.txt` — the one place generated credentials are written
/// down, and today the one thing an agent install produces nothing of.
pub mod report;

/// Which of the above an install actually leaves on disk, and the one rule
/// that decides whether a sudoers file is written at all.
/// Dynamic DNS — agent-only, unlike the rest of this directory. See the
/// module's own doc for why a generated setup script must not write it.
pub mod ddns;

pub mod provision;
