//! Port of `DashboardAccessSections` — but only the slice named for this
//! porting agent: the sudoers whitelist (`sudoers`/`vpsSudoersLines`/
//! `servicesHostSudoersLines`) and `/opt/gryonixnexus-container-ctl.sh`.
//!
//! See `install/host/mod.rs` for the three rules that apply to everything in
//! this module. Like `uninstall.rs`/`restore.rs`, this renders only wrapper
//! BODIES — the heredoc content between `cat > … <<'EOF_SUDOERS'`/
//! `<<'EOF_CONTAINER_CTL'` and their terminators — not the `log` line, the
//! `chmod`/`visudo` framing Swift's `sudoers(lines:language:)` wraps around
//! the whitelist, or the `writeFile` framing around the wrapper.
//!
//! **What this file deliberately does NOT port.** `DashboardAccessSections`
//! also has `controlUser`/`authorizedKey`/`revokeInstallKey` — the bash lines
//! that create the control user, install the app's SSH key and later strip
//! the install key. None of those are ported here: they render no bytes any
//! fixture captures (`tests/fixtures/install/host/README.md` lists only
//! `access_sudoers` and `access_container_ctl` for this Swift source), their
//! own text is entirely `L10nScripts`-localized prose with no Rust
//! localization table behind it yet, and — the more basic reason — the
//! porting task for this slice named exactly two artifacts: the sudoers file
//! and the container wrapper. Porting the rest with no fixture to check
//! against would be exactly the failure mode rule 1 exists to prevent
//! (`install/host/mod.rs`): a port "verified" only by reading the generator.
//!
//! **`HostInput.ssh_user: None` means neither artifact is written at all —
//! not "write them for a fallback user that doesn't exist".** Both artifacts
//! exist SOLELY to support the app's SSH-fallback path: the agent itself
//! calls `backup_ctl`/`update_ctl`/`uninstall`/`restore`/`lockdown` directly
//! as root, no `sudo` and no container-ctl wrapper anywhere in that path
//! (`install/host/mod.rs`'s own doc says so explicitly). Swift agrees at the
//! call-site level, not just in spirit: `servicesHostSection`/`vpsSection`
//! are the ONLY callers of `sudoers(...)`/`containerControlWrapper(...)`, and
//! both take a mandatory (non-optional) `DashboardAccessInput` — the
//! generator has no code path that renders a sudoers file with nobody to
//! grant it to. Falling back to `"root"` the way `backup_ctl.rs`'s `OWNER`
//! does would be actively wrong here, not merely redundant: `root` sudoing to
//! root is a no-op nobody would ever invoke, and shipping a live, unwhitelisted
//! `chmod 750` container-control wrapper onto an agent-only host for a
//! sudoers line that will never exist is bytes on disk with no caller and no
//! test could ever prove wrong (rule 3 — nothing here may widen the sandbox
//! silently, and an unreferenced privileged wrapper is the least visible way
//! to do that). `render` therefore returns `None` for `ssh_user: None`, and a
//! caller that still needs `/opt/gryonixnexus-container-ctl.sh`'s constant body
//! for some OTHER reason has `container_control_script()` as an unconditional
//! escape hatch (used by this module's own argument-level test).
//!
//! **The sudoers whitelist is a function of the SELECTED SERVICES, not a
//! transcription of one scenario.** `servicesHostSudoersLines` walks
//! `context.allSelectedServices` and asks each one for
//! `ManagedService.sudoersLines(_:)` — which is itself derived from
//! `ServiceActions` (`statusProbe`/`restart`/`start`/`stop`/`update`/
//! `backup`/`restore`) plus `extraSudoers`, in that fixed order, with a LOCAL
//! dedup (a repeated `PrivilegedCommand` inside one service's own list
//! collapses to one line — this is how vaultwarden's `EncryptedVolumeCommands`
//! sharing its `stop`/`start` with the `stop`/`start` action fields never
//! double-prints them) and then a GLOBAL dedup by exact rendered line
//! (`!lines.contains(line)`) as each service's lines are appended to the
//! deployment-wide list — this is how `wireguard-vpn` contributing
//! `docker restart vpnpanel` first (it sits earlier in catalog order) makes
//! `vpn-panel`'s own identical line a no-op, while `vpn-panel`'s
//! `start`/`stop` lines still land because nothing else claimed them. This
//! port reproduces BOTH dedup layers explicitly — reproducing only the global
//! one would still pass every SINGLE-service fixture and only disagree the
//! moment two services that share a `PrivilegedCommand` (vaultwarden;
//! `wireguard-vpn`+`vpn-panel`) are combined, exactly the trap
//! `backup_ctl.rs`'s own doc calls out for catalog order.
//!
//! **Catalog order, not request order**, for the same reason `backup_ctl.rs`
//! and `uninstall.rs` reorder `HostInput.services` before rendering:
//! `HostInput.services` is SORTED (`mod.rs`'s doc — a dedup convenience, not
//! a rendering order), while the Swift generator always walks
//! `ServiceRegistry.all`'s fixed array. `vpn-panel` is auto-injected the
//! instant any of the five protocol ids is present, mirroring
//! `MailContext.additionalServices`' own injection — the same rule
//! `uninstall.rs`'s `selected_vpn_services` and `restore.rs`'s
//! `restorable_services` already encode. Unlike those two modules, this one
//! does not need to SPLIT services into an app half and a VPN half: sudoers
//! lines are per-service regardless of group, so one ordered pass over the
//! whole catalog (VPN protocols included as themselves, never collapsed into
//! a `"vpn"` bucket) is enough.
//!
//! **Duplicated literals, not shared code, across the three already-done
//! sibling files.** `BackupPaths` is imported from `uninstall.rs` (already
//! `pub`, and that module is finished — not one of the two files under
//! concurrent edit for this slice). Every OTHER path this file needs
//! (`/opt/gryonixnexus-uninstall.sh`, `/opt/gryonixnexus-backup-ctl.sh`,
//! `/opt/gryonixnexus-update-ctl.sh`, `/opt/gryonixnexus-restore.sh`, `wg0`) is
//! redefined as a local constant instead of imported from `uninstall.rs`/
//! `backup_ctl.rs`/`update_ctl.rs`, the same choice `uninstall.rs` itself
//! documents on `relay_route_sync_uninstall_lines`/
//! `update_control_uninstall_lines`: a handful of literal bytes is a smaller
//! and safer surface than a cross-module dependency on a sibling this port
//! does not own, whether or not that sibling happens to be mid-edit right now.
//!
//! **Whether the update-ctl.sh line is whitelisted is reproduced from the
//! Swift catalog directly, not imported from `update_ctl.rs`.** Swift's
//! `UpdateControlSections.isUsed` is true iff at least one selected service
//! has `updateSpec.flavour == .composePull` with non-empty `images` — which,
//! read against every `Services/*.swift` file, is every catalog id except
//! `mailcow`/`gitlab` (both `.ownUpdater`) and `wireguard-vpn`/`openvpn`/
//! `vpn-panel` (all `.builtOnServer`). `UPDATE_CTL_EXCLUDED_IDS` below is
//! exactly that five-id exclusion list, checked against every `Services/*`
//! source file in this port's own verification pass, not guessed from
//! `update_ctl.rs`'s already-built `is_used` (a working sibling function is
//! not evidence this port's OWN understanding of the Swift catalog is right
//! — only reading the catalog is).

use crate::install::context::Input;
use crate::install::host::uninstall::BackupPaths;
use crate::install::host::{HostInput, HostRole};

use super::CATALOG_ORDER;

// MARK: - Cross-module literals, duplicated rather than imported (see module doc)

/// `pub` because `provision` writes this file: the path and the sudoers line
/// that authorises it must be one literal, not two.
pub const CONTAINER_CONTROL_SCRIPT_PATH: &str = "/opt/gryonixnexus-container-ctl.sh";
const UNINSTALL_SCRIPT_PATH: &str = "/opt/gryonixnexus-uninstall.sh";
/// The agent bootstrap the APP calls to install or update the agent.
/// `pub` for the same reason as the container wrapper above: the path and the
/// line that authorises it must be one literal, or a host ends up with a grant
/// for a script it does not have — or a script nobody may run.
pub const AGENT_BOOTSTRAP_SCRIPT_PATH: &str = "/opt/gryonixnexus-agent-bootstrap.sh";
/// The sudo target that lets the app reach the agent AT ALL: every RPC rides
/// `gryonixnexusd bridge`, spliced onto the root-owned socket, and the app
/// connects as the control user. A whitelist without this line means every
/// agent call dies in `sudo` — which reads, from the app, as "installed but
/// not answering". Argument pinned, because sudo compares argv verbatim.
/// Mirrors `AgentBootstrapSections.bridgeSudoersTarget`.
pub const AGENT_BRIDGE_SUDOERS_TARGET: &str = "/usr/local/bin/gryonixnexusd bridge";
/// Minting a pairing code — the OTHER command the app runs on the binary, and
/// the one that was left out when the bridge got its line. Enrolling a device
/// then failed with `sudo: a terminal is required to read the password` on
/// exactly the hosts the bridge grant was written for. The code writes into
/// the root-owned state database, so there is no non-sudo way to mint one.
/// Argument pinned; mirrors `AgentBootstrapSections.pairCodeSudoersTarget`.
pub const AGENT_PAIR_CODE_SUDOERS_TARGET: &str = "/usr/local/bin/gryonixnexusd pair-code";
const BACKUP_CTL_SCRIPT_PATH: &str = "/opt/gryonixnexus-backup-ctl.sh";
const UPDATE_CTL_SCRIPT_PATH: &str = "/opt/gryonixnexus-update-ctl.sh";
const RESTORE_SCRIPT_PATH: &str = "/opt/gryonixnexus-restore.sh";
const WIREGUARD_INTERFACE: &str = "wg0";

// MARK: - Catalog order (individual VPN ids, never collapsed into "vpn")

/// `mod.rs`'s shared `CATALOG_ORDER` — this port never groups the five VPN
/// protocols under a single `"vpn"` bucket the way `uninstall.rs`'s
/// `uninstall_vpn()` does: sudoers lines are per-`ManagedService`, so one
/// ordered pass over the whole catalog (VPN protocols included as
/// themselves) is enough, and the shared constant is walked directly rather
/// than re-filtered into an app/VPN split first.
const VPN_PROTOCOLS: &[&str] =
    &["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"];
const VPN_PANEL: &str = "vpn-panel";

/// Catalog ids with no `BackupSpec` at all — the four VPN protocol containers
/// besides `wireguard-vpn` (itself backup-less: the panel IS the WireGuard
/// server) declare neither `backup` nor `restore` in `actions(_:)`. Every
/// OTHER catalog id, `vpn-panel` included, declares `.wrapperScript` or (only
/// vaultwarden) `.encryptedVolume`.
const NO_BACKUP_IDS: &[&str] = VPN_PROTOCOLS;

/// Catalog ids `UpdateControlSections.plan` excludes from its `targets` list
/// — `mailcow`/`gitlab` (`.ownUpdater`, own updater drives itself) and
/// `wireguard-vpn`/`openvpn`/`vpn-panel` (`.builtOnServer`, no registry to
/// ask). See this module's own doc for how this was checked against the
/// catalog rather than borrowed from `update_ctl.rs`.
const UPDATE_CTL_EXCLUDED_IDS: &[&str] = &["mailcow", "gitlab", "wireguard-vpn", "openvpn", "vpn-panel"];

/// Every selected service in catalog order, `vpn-panel` auto-injected the
/// instant any protocol is present — mirrors `MailContext.additionalServices`'
/// injection, the same one `uninstall.rs`/`restore.rs` already encode for
/// their own purposes.
fn selected_services_in_order(input: &HostInput) -> Vec<&'static str> {
    let has_protocol = VPN_PROTOCOLS.iter().any(|p| input.services.iter().any(|s| s == p));
    CATALOG_ORDER
        .iter()
        .copied()
        .filter(|id| {
            let present = input.services.iter().any(|s| s == id);
            present || (*id == VPN_PANEL && has_protocol)
        })
        .collect()
}

// MARK: - Per-service sudoers targets

/// `docker compose -p <project> {ps,restart,start,stop}` — the `ps`/`restart`/
/// `start`/`stop` `ServiceActions` fields every compose-based service shares,
/// in the fixed order `sudoersLines` reads them (`statusProbe`, `restart`,
/// `start`, `stop`).
fn compose_power(project: &str) -> Vec<String> {
    vec![
        format!("/usr/bin/docker compose -p {project} ps"),
        format!("/usr/bin/docker compose -p {project} restart"),
        format!("/usr/bin/docker compose -p {project} start"),
        format!("/usr/bin/docker compose -p {project} stop"),
    ]
}

/// `docker ps -a` (the fixed `StatusProbe.container` list command — the
/// container NAME is metadata Swift's own type carries for the app's client
/// side; the sudoers TARGET never mentions it) plus
/// `docker {restart,start,stop} <name>`.
fn container_power(name: &str) -> Vec<String> {
    vec![
        "/usr/bin/docker ps -a".to_string(),
        format!("/usr/bin/docker restart {name}"),
        format!("/usr/bin/docker start {name}"),
        format!("/usr/bin/docker stop {name}"),
    ]
}

/// `docker compose -p <project> logs …` — the compose flavour of
/// [`container_logs`], same position rule.
fn compose_logs(project: &str) -> String {
    format!("/usr/bin/docker compose -p {project} logs --tail 500 --timestamps")
}

/// `docker logs --tail 500 --timestamps <name>` — the `logs` action row, for
/// the SSH route that has no `Logs` RPC to stream through.
///
/// **Separate from [`container_power`] because POSITION is part of the
/// contract**: `sudoersLines` reads the action fields in a fixed order and
/// `logs` comes AFTER `backup`/`restore`, not next to `stop`. Emitting it
/// inline would have produced a whitelist that grants the same set in a
/// different order — sudo would not care, and the fixture comparison would
/// have been the only thing that noticed, which is exactly what it did.
///
/// The argv is FIXED. A whitelisted `sudo docker` with free arguments is
/// root, a price this project has already paid once (`/bin/tar`, see the
/// sudoers note in ARCHITECTURE.md).
fn container_logs(name: &str) -> String {
    format!("/usr/bin/docker logs --tail 500 --timestamps {name}")
}

/// The common shape: compose power + the two shared wrappers (backup-ctl,
/// restore) — psono, passbolt, nextcloud, seafile, immich, photoprism, gitlab
/// and forgejo all take exactly this.
///
/// **The per-service `<path>/gryonixnexus-update.sh` line is gone**, with the
/// script itself: the dashboard has updated through `/opt/gryonixnexus-update-
/// ctl.sh` since Ф2 slice 4, so what the entry granted was permission to run
/// something nothing ran. Removed on both sides at once — a whitelist that
/// disagreed with the generator would be either a missing capability or a
/// standing grant, and only one of those is visible from the host.
fn compose_generic(project: &str, path: &str) -> Vec<String> {
    let _ = path;
    let mut lines = compose_power(project);
    lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
    lines.push(RESTORE_SCRIPT_PATH.to_string());
    lines.push(compose_logs(project));
    lines
}

/// The container-based mirror of [`compose_generic`] — jellyfin and
/// adguard-home.
fn container_generic(name: &str, path: &str) -> Vec<String> {
    let _ = path;
    let mut lines = container_power(name);
    lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
    lines.push(RESTORE_SCRIPT_PATH.to_string());
    lines.push(container_logs(name));
    lines
}

/// The four raw VPN protocol containers besides `wireguard-vpn`: container
/// power and nothing else — no backup/restore (see `NO_BACKUP_IDS`), and no
/// updater since the per-service scripts went away.
fn container_power_only(name: &str, path: &str) -> Vec<String> {
    let _ = path;
    let mut lines = container_power(name);
    lines.push(container_logs(name));
    lines
}

/// A port of `ManagedService.sudoersLines(_:)` for one catalog id, ALREADY
/// locally deduped (the one collision that would otherwise occur —
/// vaultwarden's backup `stop`/`start` repeating its own `stop`/`start`
/// action fields — is resolved by simply never emitting the backup flavour's
/// copies, since they are provably identical PrivilegedCommands to the ones
/// [`container_power`] already contributes; see the module doc). `user` is
/// needed only by vaultwarden's `chown` line. Panics on an id outside
/// [`CATALOG_ORDER`] — callers only ever reach this through
/// [`selected_services_in_order`], which filters against it first.
fn service_sudoers_targets(id: &str, input: &Input, backups: &BackupPaths, user: &str) -> Vec<String> {
    match id {
        "mailcow" => {
            let mut lines = compose_power("mailcowdockerized");
            lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
            lines.push(RESTORE_SCRIPT_PATH.to_string());
            lines.push(compose_logs("mailcowdockerized"));
            // extraSudoers: the read-only DKIM dump, not tied to an action row.
            lines.push("/opt/gryonixnexus-dkim.sh".to_string());
            lines
        }
        "mailu" => {
            let mut lines = compose_power("mailu");
            lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
            lines.push(RESTORE_SCRIPT_PATH.to_string());
            lines.push(compose_logs("mailu"));
            lines.push("/opt/gryonixnexus-mailu-dkim.sh".to_string());
            lines
        }
        "docker-mailserver" => {
            let mut lines = compose_power("dockermailserver");
            lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
            lines.push(RESTORE_SCRIPT_PATH.to_string());
            lines.push(compose_logs("dockermailserver"));
            // extraSudoers, in Swift's own order: mailbox management first,
            // then the DKIM dump.
            lines.push("/opt/gryonixnexus-dms-mailbox.sh".to_string());
            lines.push("/opt/gryonixnexus-dms-dkim.sh".to_string());
            lines
        }
        "vaultwarden" => {
            let mut lines = container_power(&input.vaultwarden_container);
            // BackupSpec.encryptedVolume: stop/start are the SAME
            // PrivilegedCommands container_power already emitted above (both
            // read "docker {stop,start} <container>"), so Swift's own local
            // dedup drops them here — only tar and chown are new.
            let staging =
                format!("{}/{}-backup.tar.gz", backups.vaultwarden, input.vaultwarden_container);
            let relative = input.vaultwarden_data_path.trim_start_matches('/');
            lines.push(format!("/bin/tar czf {staging} -C / {relative}"));
            lines.push(format!("/bin/chown {user} {staging}"));
            lines.push(RESTORE_SCRIPT_PATH.to_string());
            lines.push(container_logs(&input.vaultwarden_container));
            lines
        }
        "psono" => compose_generic("psono", &input.psono_path),
        "passbolt" => compose_generic("passbolt", &input.passbolt_path),
        "nextcloud" => compose_generic("nextcloud", &input.nextcloud_path),
        "seafile" => compose_generic("seafile", &input.seafile_path),
        "immich" => compose_generic("immich", &input.immich_path),
        "photoprism" => compose_generic("photoprism", &input.photoprism_path),
        "gitlab" => compose_generic("gitlab", &input.gitlab_path),
        "forgejo" => compose_generic("forgejo", &input.forgejo_path),
        "jellyfin" => container_generic("jellyfin", &input.jellyfin_path),
        "minecraft-java" => container_generic("minecraft-java", &input.minecraft_java_path),
        "minecraft-bedrock" => container_generic("minecraft-bedrock", &input.minecraft_bedrock_path),
        "crafty-controller" => container_generic("crafty", &input.crafty_path),
        "open-webui" => container_generic("open-webui", &input.open_webui_path),
        "litellm" => container_generic("litellm", &input.litellm_path),
        // Compose rather than container, because the project is two of them:
        // the engine and its Postgres. `N8NService.actions` probes and powers
        // the PROJECT for the same reason.
        "n8n" => compose_generic("n8n", &input.n8n_path),
        "anythingllm" => container_generic("anythingllm", &input.anythingllm_path),
        "qdrant" => container_generic("qdrant", &input.qdrant_path),
        // Power only, the way the engine below is: nothing under its path is
        // state a backup could return.
        "searxng" => container_power_only("searxng", &input.searxng_path),
        "openclaw" => container_generic("openclaw", &input.openclaw_path),
        // Power only, the way the connector is: no backup or restore of its
        // own — what lives under its path is models, not state.
        "ollama" => container_power_only("ollama", &input.ollama_path),
        "adguard-home" => container_generic("adguardhome", &input.adguard_path),
        "pihole" => container_generic("pihole", &input.pihole_path),
        "homepage" => container_generic("homepage", &input.homepage_path),
        "authelia" => container_generic("authelia", &input.authelia_path),
        "headscale" => container_generic("headscale", &input.headscale_path),
        // Power only: no backup or restore of its own — see its uninstall spec.
        "cloudflared" => container_power_only("cloudflared", &input.cloudflared_path),
        // The panel IS the WireGuard server (WireGuardVPNService.actions'
        // own comment): status + restart target the PANEL's container, no
        // start/stop/update/backup/restore of its own at all.
        // The logs row is still here, and it is the panel's: `logs` is DERIVED
        // from the status probe, and this service's probe names the panel's
        // container. When both are installed the line is emitted here and the
        // panel's own copy is dropped by the global dedup — which is why the
        // two arms disagree about where it sits, and the fixtures are what
        // says so.
        "wireguard-vpn" => vec![
            "/usr/bin/docker ps -a".to_string(),
            "/usr/bin/docker restart vpnpanel".to_string(),
            container_logs("vpnpanel"),
        ],
        "amnezia-wg" => container_power_only("awgvpn", &input.amnezia_wg_path),
        "shadowsocks" => container_power_only("shadowsocks", &input.shadowsocks_path),
        "xray-reality" => container_power_only("xray", &input.xray_reality_path),
        "openvpn" => container_power_only("openvpn", &input.openvpn_path),
        // Power and the log read only: it takes no backup, because all it
        // holds is one node identity and re-joining is a key and ten seconds.
        // Power and the log read only: it takes no backup, because all it
        // holds is one node identity and re-joining is a key and ten seconds.
        "tailscale-node" => container_power_only(
            crate::install::tailscale::CONTAINER,
            &input.tailscale_node_path,
        ),
        "vpn-panel" => {
            let mut lines = container_power("vpnpanel");
            // update: nil — the panel is built on the server, not pulled.
            lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
            lines.push(RESTORE_SCRIPT_PATH.to_string());
            lines.push(container_logs("vpnpanel"));
            // extraSudoers: the VPN-only admin lockdown switch. Empty
            // arguments, admissible because the wrapper validates its own
            // `only <hosts>` input (ARCHITECTURE.md's sudoers rule).
            lines.push("/opt/gryonixnexus-admin-lockdown.sh".to_string());
            lines
        }
        other => unreachable!("service_sudoers_targets called with an id outside CATALOG_ORDER: {other}"),
    }
}

// MARK: - Assembly

fn sudoers_line(user: &str, target: &str) -> String {
    format!("{user} ALL=(ALL) NOPASSWD: {target}")
}

/// The full sudoers LINES for one service — `service_sudoers_targets` plus
/// the user prefix. `pub(crate)`: `uninstall.rs` needs exactly this (which
/// lines a removed service's own arm may drop) and nothing else this module
/// keeps private, a port of `ManagedService.sudoersLines(_:)` used the same
/// way on the Swift side.
pub(crate) fn service_sudoers_lines(id: &str, input: &Input, backups: &BackupPaths, user: &str) -> Vec<String> {
    service_sudoers_targets(id, input, backups, user).iter().map(|target| sudoers_line(user, target)).collect()
}

/// A port of `DashboardAccessSections.servicesHostSudoersLines`.
/// `include_wire_guard: false` is scenario A / local-only; `true` is scenario
/// B's home backend.
fn services_host_sudoers_lines(input: &HostInput, backups: &BackupPaths, user: &str, include_wire_guard: bool) -> Vec<String> {
    let selected = selected_services_in_order(input);

    let mut lines =
        vec![sudoers_line(user, "/usr/bin/systemctl restart sshd"), sudoers_line(user, "/usr/bin/systemctl reboot")];
    if include_wire_guard {
        lines.insert(0, sudoers_line(user, &format!("/usr/bin/systemctl restart wg-quick@{WIREGUARD_INTERFACE}")));
        // Raspberry Pi OS home server: sysctl at /usr/sbin, not the VPS's /sbin.
        lines.push(sudoers_line(user, "/usr/sbin/sysctl net.ipv4.ip_forward"));
        lines.push(sudoers_line(user, "/usr/bin/wg show"));
    }
    // Every catalog service is docker-based, so "any docker service" reduces
    // to "any service at all" — there is no non-docker `ManagedService` in
    // this catalog to make the two questions diverge.
    if !selected.is_empty() {
        lines.push(sudoers_line(user, "/usr/bin/docker ps"));
        lines.push(sudoers_line(user, CONTAINER_CONTROL_SCRIPT_PATH));
    }
    // Service removal / full cleanup — unconditional, matching Swift.
    lines.push(sudoers_line(user, UNINSTALL_SCRIPT_PATH));
    lines.push(sudoers_line(user, AGENT_BOOTSTRAP_SCRIPT_PATH));
    lines.push(sudoers_line(user, AGENT_BRIDGE_SUDOERS_TARGET));
    lines.push(sudoers_line(user, AGENT_PAIR_CODE_SUDOERS_TARGET));
    if selected.iter().any(|id| !NO_BACKUP_IDS.contains(id)) {
        lines.push(sudoers_line(user, BACKUP_CTL_SCRIPT_PATH));
    }
    if selected.iter().any(|id| !UPDATE_CTL_EXCLUDED_IDS.contains(id)) {
        lines.push(sudoers_line(user, UPDATE_CTL_SCRIPT_PATH));
    }
    for id in &selected {
        for target in service_sudoers_targets(id, &input.install, backups, user) {
            let line = sudoers_line(user, &target);
            // Global dedup by exact rendered line, mirroring Swift's
            // `!lines.contains(line)` — see the module doc for why this has
            // to be a SECOND dedup layer on top of the per-service one.
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
    }
    lines
}

/// A port of `DashboardAccessSections.vpsSudoersLines`. Fixed seven lines,
/// independent of `HostInput.services` — scenario B's relay carries no
/// dashboard wrappers of its own (`mod.rs`'s doc on `HostRole::VpsRelay`).
/// Note `/sbin/sysctl`, not `/usr/sbin/sysctl`: Debian/Ubuntu VPS vs the home
/// backend's Raspberry Pi OS, a real difference the Swift source states
/// explicitly on this function's own doc comment.
fn vps_sudoers_lines(user: &str) -> Vec<String> {
    vec![
        sudoers_line(user, &format!("/usr/bin/systemctl restart wg-quick@{WIREGUARD_INTERFACE}")),
        sudoers_line(user, "/usr/bin/systemctl restart sshd"),
        sudoers_line(user, "/usr/bin/systemctl reboot"),
        sudoers_line(user, "/sbin/sysctl net.ipv4.ip_forward"),
        sudoers_line(user, "/usr/bin/wg show"),
        // Full cleanup of the relay — the wrapper validates its own target.
        sudoers_line(user, UNINSTALL_SCRIPT_PATH),
        // The relay's agent is reached over the same bridge, and it is the one
        // host the app can ONLY talk to that way (`ProvisionHost`).
        //
        // The bootstrap wrapper is deliberately absent: `provision.rs` returns
        // the relay's file list early and never writes that script, so granting
        // it was a grant on a file that does not exist. Swift never emitted it
        // here, and nothing caught the difference because no relay sudoers
        // fixture existed — there is one now.
        sudoers_line(user, AGENT_BRIDGE_SUDOERS_TARGET),
        sudoers_line(user, AGENT_PAIR_CODE_SUDOERS_TARGET),
    ]
}

/// The heredoc BODY of `/etc/sudoers.d/gryonixnexus-control` — a port of
/// `DashboardAccessSections.sudoers(lines:language:)`'s own heredoc content
/// (the `log`/`cat`/`chmod`/`visudo`/`mv` framing around it is a setup-script
/// concern this module does not own, matching `uninstall.rs`/`restore.rs`'s
/// own scoping).
fn sudoers_body(lines: &[String]) -> String {
    let mut body = String::from(
        "# Managed by gryonixNexus — Server Dashboard command whitelist.\n\
         # sudo matches these commands verbatim; do not add flags client-side.\n",
    );
    body.push_str(&lines.join("\n"));
    body
}

/// `/opt/gryonixnexus-container-ctl.sh`'s entire body — byte-identical across
/// every one of the 97 dumped scenarios (`tests/fixtures/install/host/
/// README.md`: `access_container_ctl` keeps exactly 1 distinct body). It
/// interpolates nothing: the wrapper validates its OWN arguments at runtime,
/// which is what makes the empty-arguments sudoers line for it admissible in
/// the first place (ARCHITECTURE.md's sudoers rule).
/// A RAW literal on purpose, not the `"…\n\` continuation style used elsewhere
/// in this crate: a `\` before a newline eats the newline AND the next line's
/// leading whitespace, which silently flattened the two-space `case`-arm
/// indentation the real script has. Bash does not care; byte parity does, and
/// this file's whole claim is byte parity. The fixture caught it — which is
/// the only reason it is not still here.
const CONTAINER_CTL_BODY: &str = r#"#!/bin/bash
# Managed by gryonixNexus — per-container control for the Server Dashboard.
# Usage: gryonixnexus-container-ctl.sh <start|stop|restart> <container>
# Whitelisted once in sudoers; validates its arguments before docker.
set -euo pipefail
ACTION="${1:-}"
NAME="${2:-}"
case "$ACTION" in
  start|stop|restart) ;;
  *) echo "unsupported action: ${ACTION}" >&2; exit 2 ;;
esac
case "$NAME" in
  [A-Za-z0-9]*) ;;
  *) echo "invalid container name: ${NAME}" >&2; exit 2 ;;
esac
case "$NAME" in
  *[!A-Za-z0-9_.-]*) echo "invalid container name: ${NAME}" >&2; exit 2 ;;
esac
exec docker "$ACTION" "$NAME""#;

/// Unconditional accessor for [`CONTAINER_CTL_BODY`] — the wrapper's bytes do
/// not depend on `HostInput` at all (no path, no user, no language), so
/// nothing about it needs the `ssh_user`/role gate [`render`] applies to the
/// SUDOERS half. Exists so the argument-level test (this file's negative
/// control target — see the module doc and `tests/fixtures/install/host/
/// README.md` on why a constant fixture needs coverage from elsewhere) can
/// reach the body without constructing a whole `HostInput`.
pub fn container_control_script() -> &'static str {
    CONTAINER_CTL_BODY
}

/// What [`render`] produces when there is a control user to provision access
/// for.
#[derive(Debug, Clone, PartialEq)]
pub struct Access {
    pub sudoers_body: String,
    /// `None` for `HostRole::VpsRelay` — Swift's `vpsSection` never calls
    /// `containerControlWrapper` at all (only `servicesHostSection` does);
    /// the relay carries no containers of its own to control this way.
    pub container_ctl_body: Option<String>,
}

/// A port of the `DashboardAccessSections` surface this module owns —
/// `None` when `HostInput.ssh_user` is `None` (see the module doc: neither
/// artifact has a caller on an agent-only host, and the generator itself
/// never renders either without a control user to provision).
pub fn render(input: &HostInput, backups: &BackupPaths) -> Option<Access> {
    let user = input.ssh_user.as_deref()?;
    let lines = match input.role {
        HostRole::VpsRelay => vps_sudoers_lines(user),
        HostRole::SingleHost => services_host_sudoers_lines(input, backups, user, false),
        HostRole::HomeBackend => services_host_sudoers_lines(input, backups, user, true),
    };
    let container_ctl_body = match input.role {
        HostRole::VpsRelay => None,
        HostRole::SingleHost | HostRole::HomeBackend => Some(CONTAINER_CTL_BODY.to_string()),
    };
    Some(Access { sudoers_body: sudoers_body(&lines), container_ctl_body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_records::Language;

    fn fixture(dir: &str, name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/host/{dir}/{name}.txt", env!("CARGO_MANIFEST_DIR"));
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

    fn multidomain_input() -> Input {
        Input {
            domain: "example.com".to_string(),
            additional_domains: vec!["example.org".to_string(), "example.net".to_string()],
            wireguard_vpn_port: 51821,
            xray_reality_port: 8443,
            ..Input::default()
        }
    }

    /// Every fixture under `tests/fixtures/install/host/access_sudoers/`,
    /// matched against the exact `HostInput` its name corresponds to per
    /// `GeneratedScriptLintTests.makeVariants()`'s `serviceSets` — the same
    /// manifest `uninstall.rs`'s and `restore.rs`'s own `fixture_parity`
    /// tests read, and (not a coincidence: both wrappers keep all 25 dumped
    /// variants as distinct bodies) the identical case list `uninstall.rs`
    /// uses, reused here rather than re-derived.
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
            let access = render(&input, &backups).expect("ssh_user is Some in every case row");
            let expected = fixture("access_sudoers", fixture_name);
            assert_eq!(access.sudoers_body, expected.trim_end_matches('\n'), "{fixture_name}");
        }
    }

    /// The multidomain fixture: a different `Input` (two additional
    /// domains), still `HostRole::SingleHost` — sudoers carries no hostnames
    /// at all, so this exists only because the SAME generated script also
    /// carries this wrapper's slice and it has to keep matching, exactly the
    /// reasoning `backup_ctl.rs`'s own multidomain test states.
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
        let access = render(&input, &backups).unwrap();
        let expected = fixture("access_sudoers", "A-multidomain");
        assert_eq!(access.sudoers_body, expected.trim_end_matches('\n'));
    }

    /// The one `access_container_ctl` fixture — constant across all 97
    /// dumped variants (`README.md`), so this proves the body matches a REAL
    /// generated script at least once; the argument-level test below is what
    /// actually exercises the validation the constant body performs (a port
    /// with the values hardcoded would pass this alone, per the README's own
    /// warning).
    #[test]
    fn container_ctl_fixture_parity() {
        let expected = fixture("access_container_ctl", "A-adguard-access-en");
        assert_eq!(container_control_script(), expected.trim_end_matches('\n'));
    }

    /// No SSH dashboard access at all (agent-only host): neither artifact is
    /// produced — see the module doc for why this is not "fall back to
    /// root" the way `backup_ctl.rs`'s `OWNER` does.
    #[test]
    fn no_ssh_user_renders_nothing() {
        let input = HostInput { ssh_user: None, ..host(&["adguard-home"]) };
        let backups = BackupPaths::default();
        assert!(render(&input, &backups).is_none());
    }

    /// `render` dispatches `HostRole::VpsRelay` to the fixed line set,
    /// independent of `HostInput.services`, and the body matches the bytes a
    /// REAL generated relay script writes.
    ///
    /// **This used to compare `vps_sudoers_lines` against itself**, because no
    /// relay fixture existed: the extraction only ever targeted scenario A's
    /// `__setup-mail-server.sh`. A test shaped like that agrees with any
    /// change made to the function it is checking, which is how this arm came
    /// to grant `/opt/gryonixnexus-agent-bootstrap.sh` — a script `provision.rs`
    /// deliberately never writes on a relay — while Swift granted no such
    /// thing. The fixture now comes out of `B-*__setup-vps.sh`, so the two
    /// routes are compared against the same bytes as every other wrapper.
    /// Also proves `container_ctl_body` is `None` for this role.
    #[test]
    fn render_dispatches_vps_relay_to_the_fixed_line_set() {
        let input = HostInput {
            services: vec!["mailcow".to_string(), "vaultwarden".to_string()],
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::VpsRelay,
        };
        let backups = BackupPaths::default();
        let access = render(&input, &backups).unwrap();
        let expected = fixture("access_sudoers", "B-relay-access-en");
        assert_eq!(access.sudoers_body, expected.trim_end_matches('\n'));
        assert!(access.container_ctl_body.is_none());
        // The grant without which no RPC reaches this host's agent — and
        // `ProvisionHost` is the ONLY way the app can manage a relay.
        assert!(access.sudoers_body.contains(AGENT_BRIDGE_SUDOERS_TARGET));
        // ...and not the bootstrap wrapper, which this role is never given.
        assert!(!access.sudoers_body.contains(AGENT_BOOTSTRAP_SCRIPT_PATH));
        // The relay's own service selection must not leak in — `vpsSection`
        // never calls `servicesHostSudoersLines` at all.
        assert!(!access.sudoers_body.contains("mailcowdockerized"));
        assert!(!access.sudoers_body.contains(CONTAINER_CONTROL_SCRIPT_PATH));
        assert!(access.sudoers_body.contains("/sbin/sysctl net.ipv4.ip_forward"));
        assert!(!access.sudoers_body.contains("/usr/sbin/sysctl"));
    }

    /// `HostRole::HomeBackend` (scenario B's home half) inserts the WireGuard
    /// restart line first and appends the Pi-flavoured sysctl + `wg show` —
    /// no fixture covers this role either (same gap as above), so this pins
    /// the shape against the Swift source directly.
    #[test]
    fn home_backend_adds_the_tunnel_lines() {
        let input = HostInput {
            services: vec!["adguard-home".to_string()],
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::HomeBackend,
        };
        let backups = BackupPaths::default();
        let access = render(&input, &backups).unwrap();
        let lines: Vec<&str> = access.sudoers_body.lines().collect();
        assert_eq!(lines[2], "admin ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart wg-quick@wg0");
        assert!(access.sudoers_body.contains("/usr/sbin/sysctl net.ipv4.ip_forward"));
        assert!(access.sudoers_body.contains("/usr/bin/wg show"));
    }

    /// Negative control's raw material, proven directly rather than only
    /// through the fixtures (easy to lose in a much larger diff): the SAME
    /// `PrivilegedCommand` contributed twice — once by `wireguard-vpn`'s own
    /// `restart` and once by `vpn-panel`'s `restart` for the identical
    /// `vpnpanel` container — collapses to ONE line, while `vpn-panel`'s
    /// `start`/`stop`, which nothing else claims, both still land.
    #[test]
    fn identical_privileged_commands_across_two_services_collapse_to_one_line() {
        let input = host(&["wireguard-vpn"]);
        let backups = BackupPaths::default();
        let access = render(&input, &backups).unwrap();
        let restart_count =
            access.sudoers_body.matches("admin ALL=(ALL) NOPASSWD: /usr/bin/docker restart vpnpanel").count();
        assert_eq!(restart_count, 1, "{}", access.sudoers_body);
        assert!(access.sudoers_body.contains("/usr/bin/docker start vpnpanel"));
        assert!(access.sudoers_body.contains("/usr/bin/docker stop vpnpanel"));
    }

    /// Vaultwarden alone: the `docker ps -a`/`restart`/`start`/`stop` lines
    /// appear exactly once each even though BOTH the `ServiceActions` power
    /// fields AND the `encryptedVolume` backup flavour name the same
    /// commands — the per-service local dedup this module's doc describes.
    #[test]
    fn vaultwarden_backup_does_not_repeat_its_own_stop_start_lines() {
        let input = host(&["vaultwarden"]);
        let backups = BackupPaths::default();
        let access = render(&input, &backups).unwrap();
        assert_eq!(access.sudoers_body.matches("docker stop vaultwarden").count(), 1);
        assert_eq!(access.sudoers_body.matches("docker start vaultwarden").count(), 1);
        assert!(access.sudoers_body.contains("/bin/tar czf /opt/backups/vaultwarden/vaultwarden-backup.tar.gz -C / opt/vaultwarden/data"));
        assert!(access.sudoers_body.contains("/bin/chown admin /opt/backups/vaultwarden/vaultwarden-backup.tar.gz"));
    }

    /// Argument-level coverage for the CONSTANT `access_container_ctl`
    /// fixture (README's own warning: a port with the values hardcoded would
    /// pass the single fixture regardless of whether the validation logic
    /// inside it actually works) — the wrapper is run for real under `bash`
    /// against a stub `docker` on `PATH`, never the real binary, so this is a
    /// live behavioural check of the SAME bytes [`container_ctl_fixture_parity`]
    /// only diffs textually.
    #[test]
    fn container_ctl_validates_its_arguments_for_real() {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-access-argtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script_path = dir.join("gryonixnexus-container-ctl.sh");
        std::fs::write(&script_path, container_control_script()).unwrap();

        let bin_dir = dir.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let stub_docker = bin_dir.join("docker");
        // Echoes exactly what it was called with, so a test can tell "the
        // wrapper reached docker" from "the wrapper rejected the input"
        // without touching a real daemon.
        std::fs::write(&stub_docker, "#!/bin/sh\necho \"STUB_DOCKER_ARGS:$*\"\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub_docker, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let real_path = std::env::var("PATH").unwrap_or_default();
        let run = |args: &[&str]| -> (i32, String, String) {
            let output = std::process::Command::new("bash")
                .arg(&script_path)
                .args(args)
                .env("PATH", format!("{}:{real_path}", bin_dir.display()))
                .output()
                .expect("bash must be on PATH for this test");
            (
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout).to_string(),
                String::from_utf8_lossy(&output.stderr).to_string(),
            )
        };

        // Valid action, valid name: reaches the stub docker with the exact argv.
        let (code, stdout, _) = run(&["start", "nextcloud-app1"]);
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), "STUB_DOCKER_ARGS:start nextcloud-app1");

        let (code, stdout, _) = run(&["restart", "adguardhome"]);
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), "STUB_DOCKER_ARGS:restart adguardhome");

        let (code, stdout, _) = run(&["stop", "vaultwarden"]);
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), "STUB_DOCKER_ARGS:stop vaultwarden");

        // Unsupported action: rejected before docker is ever reached.
        let (code, stdout, stderr) = run(&["frobnicate", "vaultwarden"]);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("unsupported action: frobnicate"));

        // Name starting with a non-alphanumeric character: rejected — this
        // is the leading-dash-as-a-flag guard.
        let (code, _, stderr) = run(&["start", "-rf"]);
        assert_eq!(code, 2);
        assert!(stderr.contains("invalid container name: -rf"));

        // Name containing a disallowed character after a valid start: the
        // SECOND `case` guard, not the first.
        let (code, _, stderr) = run(&["start", "abc;rm"]);
        assert_eq!(code, 2);
        assert!(stderr.contains("invalid container name: abc;rm"));

        // A dot/underscore/hyphen after the first character is legal —
        // docker's own naming charset.
        let (code, stdout, _) = run(&["start", "a.b_c-1"]);
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), "STUB_DOCKER_ARGS:start a.b_c-1");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
