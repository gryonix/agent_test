//! Port of `UpdateControlSections` — `/opt/gryonixnexus-update-ctl.sh`.
//!
//! The reasoning behind the wrapper's shape lives in the Swift original
//! (`Packages/gryonixNexus/Sources/MailRecipe/Scripts/UpdateControlSections.swift`)
//! and is not repeated here except where it changes what this port has to get
//! right on its own:
//!
//! - **The image id is read ONLY before `docker pull`.** `docker pull` moves
//!   a tag, never deletes the image it replaced, so rollback is `docker tag
//!   <old-id> <ref>` — and after the pull there is nobody left to ask what
//!   the old id was.
//! - **`GRYONIXNEXUS_UPDATE_CURRENT` prints in exactly one place.**
//! - **Every failure path records `GRYONIXNEXUS_UPDATE_FAILED <service>
//!   <reason>`** — a scheduled run is unattended, and `autoupdate-status.txt`
//!   is the only channel an owner ever reads it back from.
//! - **`exec {fd}>` needs bash 4.1** — see `lock.rs`'s own doc for why this
//!   is deliberate and must never become `exec 9>`.
//!
//! ## What had to be reverse-engineered, not just transcribed
//!
//! `UpdateControlSections.wrapper` takes `[any ManagedService]`, not a set of
//! ids — its ORDER decides the exact bytes of `KNOWN`/`SELF_MANAGED` and the
//! `case` arms of `gd_load_service`, so byte parity needs that order
//! reproduced, not just the membership. That order comes from
//! `MailContext.allSelectedServices`: the mail engine (if any) is moved to
//! the FRONT, then every other service follows `ServiceRegistry.all`'s fixed
//! catalog array — which is NOT alphabetical (`gitlab` sits before `forgejo`,
//! `wireguard-vpn` before `amnezia-wg`). This is a different ordering from
//! `HostInput.services`' own "SORTED" contract (`host/mod.rs`'s doc): that
//! sort is about deduplicating what `discover` reports, not about matching
//! the generator's catalog order, so `plan` below re-derives the Swift order
//! from scratch rather than trusting the order `services` arrives in.
//!
//! **Every `composePull` target's backup wrapper target is its own catalog
//! id.** Checked service by service against the Swift catalog: every
//! `ManagedService` that reaches this wrapper's `Target` either declares no
//! `BackupSpec` at all (the three VPN protocols below — `BACKUP_TARGET=''`)
//! or declares one whose `wrapperTarget`/`id.rawValue` is byte-identical to
//! its own `ServiceID.rawValue`. That collapses the Swift `switch` over
//! `BackupSpec` flavours into one fact this port leans on instead of
//! reproducing the switch.
//!
//! **Three catalog ids have no Rust module of their own yet** — AmneziaWG,
//! Shadowsocks and Xray Reality (ROADMAP leaves all four remaining VPN
//! protocols to a later slice; none has landed). Their project name, image and
//! settings path are duplicated here as literals straight from
//! `AmneziaWGVPNService`/`ShadowsocksService`/`XrayRealityService` (Swift)
//! rather than imported, because there is nothing to import from yet. When
//! their own `install::` module lands, these three arms should switch to its
//! constants instead of the local ones below.
//!
//! **mailcow and GitLab are `ownUpdater`** (their own updater/omnibus
//! reconfigure) and never reach `Target` at all — they only ever add a name
//! to `SELF_MANAGED`. **`wireguard-vpn`, `openvpn` and `vpn-panel` are
//! `builtOnServer`** (`:local` images, no registry to ask) and contribute
//! NOTHING to this wrapper — not a target, not a self-managed entry — which
//! is why `classify` answers `None` for all three: a host running only the
//! VPN panel plus plain WireGuard has no update wrapper installed at all,
//! same as Swift's `isUsed` gate (`is_used` below).
//!
//! ## Verification
//!
//! `fixture_parity` builds the `HostInput` every one of the 23 distinct
//! fixture bodies corresponds to (per `GeneratedScriptLintTests.makeVariants`'s
//! `serviceSets`, the manifest — service sets only, since topology/access/
//! language provably do not change this wrapper's bytes: no fixture name
//! carries a `B-` prefix because the home-backend half of every scenario-B
//! variant renders identically to its scenario-A counterpart, and the
//! VPS-relay half carries no services here to update at all) and diffs this
//! module's rendered output against the REAL heredoc body byte for byte.

use std::collections::HashSet;

use crate::install::context::Input;
use crate::install::mail::{dockermailserver, mailu};
use crate::install::{
    adguard, authelia, cloudflared, forgejo, headscale, homepage, immich, jellyfin, nextcloud,
    passbolt, photoprism, pihole, psono, seafile, tailscale, vaultwarden,
};

use super::HostInput;

pub const SCRIPT_PATH: &str = "/opt/gryonixnexus-update-ctl.sh";
pub const DONE_MARKER: &str = "GRYONIXNEXUS_UPDATE_CTL_DONE";
/// `<marker> <service> <image>` — one line per image that moved.
pub const AVAILABLE_MARKER: &str = "GRYONIXNEXUS_UPDATE_AVAILABLE";
/// Only when EVERY image of the service answered and none of them moved.
pub const CURRENT_MARKER: &str = "GRYONIXNEXUS_UPDATE_CURRENT";
/// `<marker> <service> <reason>` — the check could not be completed.
pub const UNKNOWN_MARKER: &str = "GRYONIXNEXUS_UPDATE_UNKNOWN";
/// `<marker> <service>` after a successful update.
pub const UPDATED_MARKER: &str = "GRYONIXNEXUS_UPDATE_DONE";
/// `<marker> <service> <reason>` — applied, unhealthy, rolled back.
pub const ROLLED_BACK_MARKER: &str = "GRYONIXNEXUS_UPDATE_ROLLED_BACK";
/// `<marker> <service> <reason>` — the run stopped before any image was
/// swapped. Recorded like the other two: a status file that only ever names
/// successes describes a server that never failed.
pub const FAILED_MARKER: &str = "GRYONIXNEXUS_UPDATE_FAILED";

/// Shared with the backup wrapper on the Swift side
/// (`BackupControlSections.configDirectory`), but NOT imported from
/// `backup_ctl` here: both are fixed literals, not derived values, and
/// `backup_ctl` is a sibling port under construction in parallel — depending
/// on its symbols would coupled two files that are safe to write independently
/// precisely because the value itself never varies.
pub const CONFIG_DIRECTORY: &str = "/etc/gryonixnexus";
pub const CONFIG_PATH: &str = "/etc/gryonixnexus/autoupdate.conf";
/// Kept OUTSIDE `CONFIG_DIRECTORY`, in the product's own state tree: `--all`
/// removes it along with everything else the product owns, while the schedule
/// config survives (it holds no secret, unlike the backup wrapper's
/// passphrase file next to it).
pub const STATUS_PATH: &str = "/var/lib/gryonixnexus/autoupdate-status.txt";
pub const TIMER_NAME: &str = "gryonixnexus-autoupdate.timer";
pub const SERVICE_NAME: &str = "gryonixnexus-autoupdate.service";
/// The argument the timer passes — not a subcommand of its own, so the timer
/// and the app's button reach the exact same per-service body.
pub const SCHEDULED_FLAG: &str = "--scheduled";

/// `BackupControlSections.scriptPath`, duplicated as a literal for the same
/// reason `CONFIG_DIRECTORY` above is: a fixed path, not a derived value, and
/// `backup_ctl` is a sibling port under construction in parallel.
const BACKUP_CTL_SCRIPT_PATH: &str = "/opt/gryonixnexus-backup-ctl.sh";

/// AmneziaWG — no `install::` module of this catalog id exists yet (see the
/// module doc). `AmneziaWGVPNService.composeProject`/`.image`, verbatim.
const AMNEZIA_WG_PROJECT: &str = "awgvpn";
const AMNEZIA_WG_IMAGE: &str = "ghcr.io/deckersu/amnezia-wg-easy:14";
/// Shadowsocks — `ShadowsocksService.composeProject`/`.image`, verbatim.
const SHADOWSOCKS_PROJECT: &str = "shadowsocks";
const SHADOWSOCKS_IMAGE: &str = "ghcr.io/shadowsocks/ssserver-rust:v1.24.0";
/// Xray Reality — `XrayRealityService.composeProject`/`.image`, verbatim.
const XRAY_REALITY_PROJECT: &str = "xray";
const XRAY_REALITY_IMAGE: &str = "ghcr.io/xtls/xray-core:26.7.11";

use super::CATALOG_ORDER;

/// The three mutually exclusive mail engines, in `CATALOG_ORDER`'s own
/// relative order (mailcow, mailu, docker-mailserver) — at most one is ever
/// selected (`ManagedService.conflicts`), so `find` is enough to pick it.
const MAIL_ENGINES: &[&str] = &["mailcow", "mailu", "docker-mailserver"];

/// One `docker compose pull` target — everything `gd_load_service`'s
/// matching `case` arm bakes in at generation time.
struct Target {
    id: &'static str,
    project: String,
    directory: String,
    /// Empty for a service that declares no `BackupSpec` at all (the three
    /// VPN protocols) — see the module doc on why every OTHER target's
    /// backup id is simply its own catalog id.
    backup_target: &'static str,
    images: Vec<String>,
}

/// What one selected catalog id turns into, mirroring
/// `UpdateControlSections.plan`'s per-service `switch spec.flavour`.
enum Entry {
    /// `.composePull` with a non-empty image list and a runtime/compose file
    /// — gets a `case` arm and a slot in `KNOWN`.
    Target(Target),
    /// `.ownUpdater` — gets a slot in `SELF_MANAGED`, no `case` arm.
    SelfManaged,
}

/// `MailuService.updateSpec`'s image list: the cache image, then one per
/// `Component.allCases` in enum-declaration order — nginx, unbound, admin,
/// dovecot, postfix, rspamd, webmail.
fn mailu_images() -> Vec<String> {
    let mut images = vec![mailu::CACHE_IMAGE.to_string()];
    for component in ["nginx", "unbound", "admin", "dovecot", "postfix", "rspamd", "webmail"] {
        images.push(format!("ghcr.io/mailu/{component}:{}", mailu::IMAGE_TAG));
    }
    images
}

/// A port of `UpdateControlSections.plan`'s per-service branch, one catalog
/// id at a time. `None` covers both "not in this catalog" and `.builtOnServer`
/// (`wireguard-vpn`/`openvpn`/`vpn-panel`) — Swift's `plan` does not
/// distinguish them either (both just `continue`).
fn classify(id: &str, input: &Input) -> Option<Entry> {
    match id {
        "mailcow" | "gitlab" => Some(Entry::SelfManaged),
        "mailu" => Some(Entry::Target(Target {
            id: "mailu",
            project: mailu::COMPOSE_PROJECT.to_string(),
            directory: input.mailu_path.clone(),
            backup_target: "mailu",
            images: mailu_images(),
        })),
        "docker-mailserver" => Some(Entry::Target(Target {
            id: "docker-mailserver",
            project: dockermailserver::COMPOSE_PROJECT.to_string(),
            directory: input.docker_mailserver_path.clone(),
            backup_target: "docker-mailserver",
            images: vec![dockermailserver::IMAGE.to_string(), dockermailserver::WEBMAIL_IMAGE.to_string()],
        })),
        // The compose DIRECTORY is fixed, unlike the data path — mirrors
        // `VaultwardenService.composeFile`'s own `Self.composeDirectory`,
        // not `context.settings.vaultwardenDataPath`.
        "vaultwarden" => Some(Entry::Target(Target {
            id: "vaultwarden",
            project: vaultwarden::COMPOSE_PROJECT.to_string(),
            directory: vaultwarden::COMPOSE_DIRECTORY.to_string(),
            backup_target: "vaultwarden",
            images: vec![vaultwarden::IMAGE.to_string()],
        })),
        "psono" => Some(Entry::Target(Target {
            id: "psono",
            project: psono::COMPOSE_PROJECT.to_string(),
            directory: input.psono_path.clone(),
            backup_target: "psono",
            images: vec![psono::IMAGE.to_string(), psono::DATABASE_IMAGE.to_string()],
        })),
        "passbolt" => Some(Entry::Target(Target {
            id: "passbolt",
            project: passbolt::COMPOSE_PROJECT.to_string(),
            directory: input.passbolt_path.clone(),
            backup_target: "passbolt",
            images: vec![passbolt::IMAGE.to_string(), passbolt::DATABASE_IMAGE.to_string()],
        })),
        "nextcloud" => Some(Entry::Target(Target {
            id: "nextcloud",
            project: nextcloud::COMPOSE_PROJECT.to_string(),
            directory: input.nextcloud_path.clone(),
            backup_target: "nextcloud",
            images: vec![nextcloud::IMAGE.to_string(), nextcloud::DATABASE_IMAGE.to_string(), nextcloud::CACHE_IMAGE.to_string()],
        })),
        "seafile" => Some(Entry::Target(Target {
            id: "seafile",
            project: seafile::COMPOSE_PROJECT.to_string(),
            directory: input.seafile_path.clone(),
            backup_target: "seafile",
            images: vec![seafile::IMAGE.to_string(), seafile::DATABASE_IMAGE.to_string(), seafile::CACHE_IMAGE.to_string()],
        })),
        "immich" => Some(Entry::Target(Target {
            id: "immich",
            project: immich::COMPOSE_PROJECT.to_string(),
            directory: input.immich_path.clone(),
            backup_target: "immich",
            images: vec![
                immich::IMAGE.to_string(),
                immich::MACHINE_LEARNING_IMAGE.to_string(),
                immich::CACHE_IMAGE.to_string(),
                immich::DATABASE_IMAGE.to_string(),
            ],
        })),
        "photoprism" => Some(Entry::Target(Target {
            id: "photoprism",
            project: photoprism::COMPOSE_PROJECT.to_string(),
            directory: input.photoprism_path.clone(),
            backup_target: "photoprism",
            images: vec![photoprism::IMAGE.to_string(), photoprism::DATABASE_IMAGE.to_string()],
        })),
        "forgejo" => Some(Entry::Target(Target {
            id: "forgejo",
            project: forgejo::COMPOSE_PROJECT.to_string(),
            directory: input.forgejo_path.clone(),
            backup_target: "forgejo",
            images: vec![forgejo::IMAGE.to_string(), forgejo::DATABASE_IMAGE.to_string()],
        })),
        "jellyfin" => Some(Entry::Target(Target {
            id: "jellyfin",
            project: jellyfin::COMPOSE_PROJECT.to_string(),
            directory: input.jellyfin_path.clone(),
            backup_target: "jellyfin",
            images: vec![jellyfin::IMAGE.to_string()],
        })),
        "minecraft-java" => Some(Entry::Target(Target {
            id: "minecraft-java",
            project: crate::install::minecraft::JAVA_COMPOSE_PROJECT.to_string(),
            directory: input.minecraft_java_path.clone(),
            backup_target: "minecraft-java",
            images: vec![crate::install::minecraft::JAVA_IMAGE.to_string()],
        })),
        "minecraft-bedrock" => Some(Entry::Target(Target {
            id: "minecraft-bedrock",
            project: crate::install::minecraft::BEDROCK_COMPOSE_PROJECT.to_string(),
            directory: input.minecraft_bedrock_path.clone(),
            backup_target: "minecraft-bedrock",
            images: vec![crate::install::minecraft::BEDROCK_IMAGE.to_string()],
        })),
        "crafty-controller" => Some(Entry::Target(Target {
            id: "crafty-controller",
            project: crate::install::crafty::COMPOSE_PROJECT.to_string(),
            directory: input.crafty_path.clone(),
            backup_target: "crafty-controller",
            images: vec![crate::install::crafty::IMAGE.to_string()],
        })),
        "anythingllm" => Some(Entry::Target(Target {
            id: "anythingllm",
            project: crate::install::anythingllm::COMPOSE_PROJECT.to_string(),
            directory: input.anythingllm_path.clone(),
            backup_target: "anythingllm",
            images: vec![crate::install::anythingllm::IMAGE.to_string()],
        })),
        "qdrant" => Some(Entry::Target(Target {
            id: "qdrant",
            project: crate::install::qdrant::COMPOSE_PROJECT.to_string(),
            directory: input.qdrant_path.clone(),
            backup_target: "qdrant",
            images: vec![crate::install::qdrant::IMAGE.to_string()],
        })),
        "searxng" => Some(Entry::Target(Target {
            id: "searxng",
            project: crate::install::searxng::COMPOSE_PROJECT.to_string(),
            directory: input.searxng_path.clone(),
            // **Empty, like `ollama` above, and for the same reason the backup
            // wrapper gives on its own line: everything this service holds is
            // the settings file the install writes and a cache it can fetch
            // again.** It declares no backup on the Swift side either, and a
            // non-empty id here asks the backup wrapper for an arm it does not
            // have — which does not degrade the update, it FAILS it: the
            // wrapper takes a backup first and stops when it cannot. Measured
            // on a live host, 2026-09-08: `RunUpdate(searxng)` came back
            // "the backup failed" every time, on an update that had nothing
            // wrong with it.
            backup_target: "",
            images: vec![crate::install::searxng::IMAGE.to_string()],
        })),
        "openclaw" => Some(Entry::Target(Target {
            id: "openclaw",
            project: crate::install::openclaw::COMPOSE_PROJECT.to_string(),
            directory: input.openclaw_path.clone(),
            backup_target: "openclaw",
            images: vec![crate::install::openclaw::IMAGE.to_string()],
        })),
        "n8n" => Some(Entry::Target(Target {
            id: "n8n",
            project: crate::install::n8n::COMPOSE_PROJECT.to_string(),
            directory: input.n8n_path.clone(),
            backup_target: "n8n",
            // Both images: the engine and the database beside it. A stack
            // whose Postgres is never pulled is one that stays on the tag it
            // was installed with for as long as the host lives.
            images: vec![
                crate::install::n8n::IMAGE.to_string(),
                crate::install::n8n::DATABASE_IMAGE.to_string(),
            ],
        })),
        "litellm" => Some(Entry::Target(Target {
            id: "litellm",
            project: crate::install::litellm::COMPOSE_PROJECT.to_string(),
            directory: input.litellm_path.clone(),
            backup_target: "litellm",
            images: vec![crate::install::litellm::IMAGE.to_string()],
        })),
        "open-webui" => Some(Entry::Target(Target {
            id: "open-webui",
            project: crate::install::open_webui::COMPOSE_PROJECT.to_string(),
            directory: input.open_webui_path.clone(),
            backup_target: "open-webui",
            images: vec![crate::install::open_webui::IMAGE.to_string()],
        })),
        // No `backup_target`, the way the connector and the mesh node have
        // none: there is no archive to take before swapping this image,
        // because the directory under it holds models rather than state.
        "ollama" => Some(Entry::Target(Target {
            id: "ollama",
            project: crate::install::ollama::COMPOSE_PROJECT.to_string(),
            directory: input.ollama_path.clone(),
            backup_target: "",
            images: vec![crate::install::ollama::IMAGE.to_string()],
        })),
        "adguard-home" => Some(Entry::Target(Target {
            id: "adguard-home",
            project: adguard::COMPOSE_PROJECT.to_string(),
            directory: input.adguard_path.clone(),
            backup_target: "adguard-home",
            images: vec![adguard::IMAGE.to_string()],
        })),
        // Six arms this port never had, while the Swift generator emitted
        // them from the catalog — the same gap `backup_ctl` and `restore` were
        // in, and the same cost: the app offers Update on these services (they
        // declare `.composePull`), the wrapper on an agent-built host has no
        // case for them, and the answer is a refusal naming the service
        // (owner, 2026-08-22).
        "pihole" => Some(Entry::Target(Target {
            id: "pihole",
            project: pihole::COMPOSE_PROJECT.to_string(),
            directory: input.pihole_path.clone(),
            backup_target: "pihole",
            images: vec![pihole::IMAGE.to_string()],
        })),
        "headscale" => Some(Entry::Target(Target {
            id: "headscale",
            project: headscale::COMPOSE_PROJECT.to_string(),
            directory: input.headscale_path.clone(),
            backup_target: "headscale",
            images: vec![headscale::IMAGE.to_string()],
        })),
        // The mesh node has no backup of its own: it holds a machine key it
        // can be issued again, not data. An empty `backup_target` is what the
        // generator emits for exactly that case, and the wrapper reads it as
        // "update without taking one first".
        "tailscale-node" => Some(Entry::Target(Target {
            id: "tailscale-node",
            project: tailscale::COMPOSE_PROJECT.to_string(),
            directory: input.tailscale_node_path.clone(),
            backup_target: "",
            images: vec![tailscale::IMAGE.to_string()],
        })),
        "cloudflared" => Some(Entry::Target(Target {
            id: "cloudflared",
            project: cloudflared::COMPOSE_PROJECT.to_string(),
            directory: input.cloudflared_path.clone(),
            backup_target: "",
            images: vec![cloudflared::IMAGE.to_string()],
        })),
        "homepage" => Some(Entry::Target(Target {
            id: "homepage",
            project: homepage::COMPOSE_PROJECT.to_string(),
            directory: input.homepage_path.clone(),
            backup_target: "homepage",
            images: vec![homepage::IMAGE.to_string()],
        })),
        "authelia" => Some(Entry::Target(Target {
            id: "authelia",
            project: authelia::COMPOSE_PROJECT.to_string(),
            directory: input.authelia_path.clone(),
            backup_target: "authelia",
            images: vec![authelia::IMAGE.to_string()],
        })),
        "amnezia-wg" => Some(Entry::Target(Target {
            id: "amnezia-wg",
            project: AMNEZIA_WG_PROJECT.to_string(),
            directory: input.amnezia_wg_path.clone(),
            backup_target: "",
            images: vec![AMNEZIA_WG_IMAGE.to_string()],
        })),
        "shadowsocks" => Some(Entry::Target(Target {
            id: "shadowsocks",
            project: SHADOWSOCKS_PROJECT.to_string(),
            directory: input.shadowsocks_path.clone(),
            backup_target: "",
            images: vec![SHADOWSOCKS_IMAGE.to_string()],
        })),
        "xray-reality" => Some(Entry::Target(Target {
            id: "xray-reality",
            project: XRAY_REALITY_PROJECT.to_string(),
            directory: input.xray_reality_path.clone(),
            backup_target: "",
            images: vec![XRAY_REALITY_IMAGE.to_string()],
        })),
        // `.builtOnServer` (wireguard-vpn's images are empty too, which
        // would fail Swift's `!spec.images.isEmpty` guard even without the
        // flavour check) or not a catalog id this wrapper ever sees.
        _ => None,
    }
}

/// Every catalog id whose service takes a `composePull` update — the set this
/// wrapper must have an arm for.
///
/// **Stated as data, and duplicated in Swift on purpose**, exactly like
/// `backup_ctl::BACKUP_CAPABLE_SERVICE_IDS`: the generator DERIVES this set by
/// walking the catalog, this port is a `match` somebody has to remember to
/// extend, and six services (Pi-hole, Homepage, Authelia, Headscale, the mesh
/// node and the tunnel) sat outside it while the app showed an Update button
/// for every one of them.
///
/// Absent on purpose: `mailcow` and `gitlab` ship their own updater, and
/// `openvpn`, `vpn-panel` and `wireguard-vpn` are built on the server — none
/// of the five is a thing this wrapper may pull an image for.
pub const UPDATE_CAPABLE_SERVICE_IDS: &[&str] = &[
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
    "jellyfin",
    "minecraft-java",
    "minecraft-bedrock",
    "crafty-controller",
    "adguard-home",
    "pihole",
    "headscale",
    "tailscale-node",
    "cloudflared",
    "homepage",
    "authelia",
    "amnezia-wg",
    "shadowsocks",
    "xray-reality",
    // The AI shelf. BOTH members, unlike the backup and restore lists: an
    // engine has no data worth archiving and an out-of-date one is still an
    // out-of-date container, so "can be updated" and "can be backed up" are
    // genuinely different questions about it.
    "open-webui",
    "ollama",
    "litellm",
    "n8n",
    "anythingllm",
    "qdrant",
    "searxng",
    "openclaw",
];

/// A port of `MailContext.allSelectedServices`' ordering, reduced to the ids
/// this wrapper cares about: the mail engine (if any of the three is
/// present) FIRST, then every other selected id in `CATALOG_ORDER`. This is
/// NOT `HostInput.services`' own order (that Vec is kept SORTED for a
/// different reason — see `host/mod.rs`), so it is rebuilt from the set of
/// what is present rather than trusted from the input.
fn ordered_services(input: &HostInput) -> Vec<&'static str> {
    let present: HashSet<&str> = input.services.iter().map(String::as_str).collect();
    let mail_engine = MAIL_ENGINES.iter().copied().find(|id| present.contains(id));
    let mut order = Vec::new();
    if let Some(engine) = mail_engine {
        order.push(engine);
    }
    for id in CATALOG_ORDER {
        if Some(*id) == mail_engine {
            continue;
        }
        if present.contains(id) {
            order.push(*id);
        }
    }
    order
}

/// A port of `UpdateControlSections.plan`: the ordered `Target` list
/// (`KNOWN`, the `case` arms) and the ordered self-managed id list
/// (`SELF_MANAGED`).
fn plan(input: &HostInput) -> (Vec<Target>, Vec<&'static str>) {
    let mut targets = Vec::new();
    let mut self_managed = Vec::new();
    for id in ordered_services(input) {
        match classify(id, &input.install) {
            Some(Entry::Target(target)) => targets.push(target),
            Some(Entry::SelfManaged) => self_managed.push(id),
            None => {}
        }
    }
    (targets, self_managed)
}

/// A port of `UpdateControlSections.isUsed`: whether this wrapper (and its
/// sudoers line, on the SSH path) is installed at all. Self-managed services
/// alone do NOT make it used — mailcow-only and GitLab-only hosts print no
/// `case` arm and get no update wrapper, exactly like Swift's `targets.isEmpty`
/// check (which does not look at `selfManaged`).
pub fn is_used(input: &HostInput) -> bool {
    !plan(input).0.is_empty()
}

fn render_arm(target: &Target) -> String {
    format!(
        "    {id}) PROJECT='{project}'; DIR='{directory}'; BACKUP_TARGET='{backup_target}'; IMAGES='{images}' ;;",
        id = target.id,
        project = target.project,
        directory = target.directory,
        backup_target = target.backup_target,
        images = target.images.join(" ")
    )
}

/// The `gd_load_service` case-block body. Empty targets fall back to a
/// single `__none__` arm — unreachable through `is_used`-gated callers (the
/// wrapper is not installed at all when nothing updates through a pull), but
/// ported anyway because `wrapper` itself does not enforce that gate, exactly
/// as `UpdateControlSections.wrapper` does not either.
fn render_service_arms(targets: &[Target]) -> String {
    if targets.is_empty() {
        "    __none__) ;; # nothing here updates through a pull".to_string()
    } else {
        targets.iter().map(render_arm).collect::<Vec<_>>().join("
")
    }
}

/// The wrapper body, byte-identical to `UpdateControlSections.wrapper`'s
/// `script` value (i.e. BEFORE `BashSections.writeFile` wraps it in a
/// heredoc — the extracted fixtures carry the heredoc's own trailing
/// newline, which is why the fixture tests below trim one before comparing,
/// the same convention `lock.rs`'s own test uses).
///
/// Everything in this script is a fixed literal EXCEPT three spots, replaced
/// by `wrapper` below: `@@KNOWN@@` (`KNOWN='...'`), `@@SELF_MANAGED@@`
/// (`SELF_MANAGED='...'`) and `@@ARMS@@` (the `gd_load_service` case-block
/// body). No other value in this template varies across any scenario this
/// crate can generate — not the config/status paths, not the backup
/// wrapper's path, not the markers: all of them are plain Swift literals on
/// the source side too, never settings-derived.
const TEMPLATE: &str = r#"#!/bin/bash
# Managed by gryonixNexus — update housekeeping for the Server Dashboard.
# Usage: gryonixnexus-update-ctl.sh check <service|--all>
#        gryonixnexus-update-ctl.sh run <service|--scheduled>
#        gryonixnexus-update-ctl.sh set-schedule <off|every:<n><h|d>@<HH:MM>> [services...]
#        gryonixnexus-update-ctl.sh status
set -euo pipefail

ACTION="${1:-}"
CONFIG='/etc/gryonixnexus/autoupdate.conf'
STATUS_FILE='/var/lib/gryonixnexus/autoupdate-status.txt'
# The one thing that makes a backup on this host. An update takes one
# BEFORE it changes anything, and it calls this rather than carrying its
# own copy of tar/pg_dump/gpg — the whole reason that wrapper exists.
BACKUP_CTL='/opt/gryonixnexus-backup-ctl.sh'
# Every service this wrapper can update. Baked in; the config below may
# only ever be a subset of it.
KNOWN='@@KNOWN@@'
# Services that ship their own updater (mailcow's update.sh, GitLab's
# omnibus, which migrates and reconfigures itself on start). Named so
# the refusal can say WHY instead of "unsupported service" — swapping
# their images on a schedule breaks an installation rather than
# updating it, and their own updater is the app's per-service Update
# button.
SELF_MANAGED='@@SELF_MANAGED@@'
# What the schedule covers. Empty until set-schedule writes the config:
# a run that found no configuration must update NOTHING, never
# everything.
SERVICES=''
SCHEDULE=off

# How long a service gets to come back up after its images changed
# before the update is called failed and rolled back. Overridable only
# from the environment of a root caller — sudo resets the environment,
# so this is not a way for the app to widen anything; it exists so the
# test harness does not have to wait five minutes.
HEALTH_TIMEOUT="${GRYONIXNEXUS_UPDATE_HEALTH_TIMEOUT:-300}"
# Per-request budget for a registry. A slow registry is a normal
# condition, not a fault: it ends as UNKNOWN, never as a failed run.
HTTP_TIMEOUT="${GRYONIXNEXUS_UPDATE_HTTP_TIMEOUT:-20}"
# Both list and single-manifest media types, in both the OCI and the
# Docker spelling: a multi-arch tag resolves to an INDEX, and asking
# without these gets either a 404 or the digest of one architecture —
# which would read as "moved" on every check.
ACCEPT_HEADER='Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

# Filled by gd_load_service from the table below, never from an argument.
PROJECT=''
DIR=''
BACKUP_TARGET=''
IMAGES=''

load_config() {
  # shellcheck disable=SC1090
  [ -f "$CONFIG" ] && . "$CONFIG"
  # A config from an older build may not set every value.
  : "${SCHEDULE:=off}" "${SERVICES:=}"
}

# --- per-service locking (see LockSections) --------------------------

GD_LOCK_BUSY=75

gd_with_lock() {
  local id="$1"
  shift
  install -d -m 700 '/var/lib/gryonixnexus/locks'
  local fd
  exec {fd}>"/var/lib/gryonixnexus/locks/$id.lock"
  if ! flock -n "$fd"; then
    echo "$id: another backup or update for this service is already running, skipping" >&2
    return "$GD_LOCK_BUSY"
  fi
  "$@"
}

# --- arguments -------------------------------------------------------

# A service label and nothing else. This script is whitelisted in
# sudoers with no arguments pinned, which is only acceptable because it
# validates its own input: an unchecked argument that reaches docker
# here is an argument that reached root.
gd_valid_label() {
  case "${1:-}" in
    ''|*[!a-z0-9-]*) echo "invalid service: ${1:-}" >&2; return 2 ;;
  esac
  return 0
}

# The table. Everything an update needs comes from HERE — the caller's
# bytes only choose an arm, they are never spliced into a command.
gd_load_service() {
  case "$1" in
@@ARMS@@
    *) echo "unsupported service: ${1}" >&2; return 2 ;;
  esac
}

gd_is_self_managed() {
  local known
  for known in $SELF_MANAGED; do
    if [ "$1" = "$known" ]; then return 0; fi
  done
  return 1
}

# Deliberately NOT a marker: what these run is decided by their own
# updater at run time, so this wrapper has no standing to call them
# current, available or unknown. A line of prose is what a person
# reading the log gets; the app's parser ignores it.
gd_self_managed_note() {
  printf '%s: updated by its own updater, not by this wrapper\n' "$1"
}

# --- the registry ----------------------------------------------------

# The digest `docker pull` recorded for THIS reference — not the image
# id, which is a local content address with no counterpart in a
# registry. Empty when the host has never pulled it.
gd_local_digest() {
  local ref="$1" name="${1%:*}"
  # Guarded as a whole: `head` closes the pipe early, and a SIGPIPE'd
  # `docker` would fail the run under pipefail.
  { docker image inspect "$ref" --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null \
      | grep -F "$name@" | head -n 1 | sed 's/.*@//'; } || true
}

# One HEAD against a registry. Never `curl -f`: it throws the body and
# the status away, and here the RESPONSE is the answer — a 401 carries
# the challenge that names the token endpoint. Never fatal either.
gd_registry_head() {
  if [ -n "$2" ]; then
    curl -sS -I --max-time "$HTTP_TIMEOUT" -D - -o /dev/null \
      -H "$ACCEPT_HEADER" -H "Authorization: Bearer $2" "$1" 2>/dev/null || true
  else
    curl -sS -I --max-time "$HTTP_TIMEOUT" -D - -o /dev/null \
      -H "$ACCEPT_HEADER" "$1" 2>/dev/null || true
  fi
}

# `key="value"` out of a WWW-Authenticate challenge.
gd_challenge_field() {
  printf '%s' "$1" | sed -n "s/.*$2=\"\([^\"]*\)\".*/\1/p" | head -n 1
}

gd_status_code() {
  printf '%s\n' "$1" | awk 'toupper($1) ~ /^HTTP/ {c=$2} END {print c}'
}

# An anonymous pull token. Parsed with sed rather than jq: jq is not a
# dependency of this script, and its absence would turn every check on
# the host into UNKNOWN. The pattern also matches "access_token", which
# is the same value wherever both are sent.
gd_registry_token() {
  local body=""
  body="$(curl -sS --max-time "$HTTP_TIMEOUT" --get \
            --data-urlencode "service=$2" --data-urlencode "scope=$3" "$1" 2>/dev/null)" || true
  printf '%s' "$body" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p' | head -n 1
}

# What the tag resolves to in its own registry, right now. Empty when
# the question could not be answered — the caller turns that into
# UNKNOWN, never into "up to date".
gd_remote_digest() {
  local ref="$1" host repo tag url response code challenge realm service scope token digest
  # A reference pinned by digest cannot move: it already IS what it
  # resolves to, and there is nothing to ask anyone.
  case "$ref" in
    *@sha256:*) printf '%s' "${ref##*@}"; return 0 ;;
  esac
  case "$ref" in
    */*)
      host="${ref%%/*}"
      case "$host" in
        # A first component with a dot or a port is a registry host;
        # anything else is a Docker Hub namespace (`adguard/…`).
        *.*|*:*|localhost) repo="${ref#*/}" ;;
        *) host='registry-1.docker.io'; repo="$ref" ;;
      esac
      ;;
    *) host='registry-1.docker.io'; repo="library/$ref" ;;
  esac
  case "$host" in
    docker.io|index.docker.io) host='registry-1.docker.io' ;;
  esac
  case "$repo" in
    *:*) tag="${repo##*:}"; repo="${repo%:*}" ;;
    *) tag='latest' ;;
  esac
  url="https://$host/v2/$repo/manifests/$tag"
  response="$(gd_registry_head "$url" '')"
  code="$(gd_status_code "$response")"
  if [ "$code" = "401" ]; then
    challenge="$({ printf '%s\n' "$response" | grep -i '^www-authenticate:' | head -n 1 | tr -d '\r'; } || true)"
    realm="$(gd_challenge_field "$challenge" realm)"
    service="$(gd_challenge_field "$challenge" service)"
    scope="$(gd_challenge_field "$challenge" scope)"
    [ -n "$scope" ] || scope="repository:$repo:pull"
    [ -n "$realm" ] || return 1
    token="$(gd_registry_token "$realm" "$service" "$scope")"
    [ -n "$token" ] || return 1
    response="$(gd_registry_head "$url" "$token")"
    code="$(gd_status_code "$response")"
  fi
  [ "$code" = "200" ] || return 1
  digest="$({ printf '%s\n' "$response" | grep -i '^docker-content-digest:' \
                | head -n 1 | tr -d '\r' | awk '{print $2}'; } || true)"
  [ -n "$digest" ] || return 1
  printf '%s' "$digest"
}

# --- the check -------------------------------------------------------

gd_check_service() {
  local svc="$1" moved=0 unknown='' img local_digest remote_digest
  gd_load_service "$svc" || return 2
  for img in $IMAGES; do
    local_digest="$(gd_local_digest "$img")"
    if [ -z "$local_digest" ]; then
      # The host is not running this image at all, so there is nothing
      # to compare. Saying "up to date" here would be a guess.
      unknown=not_pulled
      continue
    fi
    remote_digest="$(gd_remote_digest "$img")" || remote_digest=''
    if [ -z "$remote_digest" ]; then
      unknown=registry_unreachable
      continue
    fi
    if [ "$local_digest" != "$remote_digest" ]; then
      printf '%s %s %s\n' 'GRYONIXNEXUS_UPDATE_AVAILABLE' "$svc" "$img"
      moved=1
    fi
  done
  # Order matters: an unanswered image outranks "nothing moved", so a
  # partial answer can never be printed as CURRENT. An image that DID
  # move is reported either way — the app already prefers it.
  if [ -n "$unknown" ]; then
    printf '%s %s %s\n' 'GRYONIXNEXUS_UPDATE_UNKNOWN' "$svc" "$unknown"
  elif [ "$moved" -eq 0 ]; then
    printf '%s %s\n' 'GRYONIXNEXUS_UPDATE_CURRENT' "$svc"
  fi
}

do_check() {
  local target="${1:---all}" svc
  if ! command -v docker >/dev/null 2>&1; then
    # No docker means no local digests, i.e. no answer for anything.
    for svc in $KNOWN; do
      printf '%s %s %s\n' 'GRYONIXNEXUS_UPDATE_UNKNOWN' "$svc" 'docker_unavailable'
    done
    return 0
  fi
  if [ "$target" = "--all" ]; then
    for svc in $KNOWN; do gd_check_service "$svc"; done
    for svc in $SELF_MANAGED; do gd_self_managed_note "$svc"; done
    return 0
  fi
  gd_valid_label "$target" || exit 2
  if gd_is_self_managed "$target"; then gd_self_managed_note "$target"; return 0; fi
  gd_check_service "$target" || exit 2
}

# --- applying one ----------------------------------------------------

gd_image_id() {
  { docker image inspect "$1" --format '{{.Id}}' 2>/dev/null | head -n 1; } || true
}

# Puts every tag back on the image it pointed at before the pull.
# `docker pull` does not delete what it replaced — it only moves the
# tag — so this needs no registry and works with the network down,
# which is exactly the state a failed update can leave a host in.
gd_restore_images() {
  local img old now
  while read -r img old; do
    if [ -z "$old" ]; then
      echo "no previous image to put back for $img" >&2
      continue
    fi
    now="$(gd_image_id "$img")"
    if [ "$now" = "$old" ]; then continue; fi
    docker tag "$old" "$img" >/dev/null 2>&1 || echo "could not put $img back" >&2
  done < "$1"
}

# Waits for every container of the project to be up, and prints WHY it
# is not when the deadline passes. Progress goes to stderr so the
# reason stays the only thing on stdout.
# **One clean look is not health.** The container slice measured this on
# a live host: a container whose entrypoint exits is reported `running`
# for a second and a half after `up -d` returns, and a stack already in
# a steady crash loop still answers `running` on roughly one sample in
# six — because that is what a restart loop IS. A wait that accepted its
# first clean look therefore called a broken update good and never rolled
# back. That was fixed for container GROUPS in the agent and did not
# reach here, which is the cost of one rule living in two places.
#
# So: clean on 3 looks in a row, AND the restart
# counters unchanged across them — the second catches a loop whose
# up-windows happen to line up with the polls.
gd_wait_healthy() {
  local project="$1" deadline now beat ids cid state status restarting exitcode health bad
  local clean=0 counters="" counters_now=""
  now="$(date +%s)"
  deadline=$((now + $2))
  beat=$((now + 30))
  while : ; do
    bad=''
    ids="$(docker compose -p "$project" ps -q 2>/dev/null || true)"
    if [ -z "$ids" ]; then
      bad='no container is running'
    else
      for cid in $ids; do
        state="$(docker inspect -f '{{.State.Status}} {{.State.Restarting}} {{.State.ExitCode}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || true)"
        if [ -z "$state" ]; then bad='a container disappeared'; continue; fi
        read -r status restarting exitcode health <<< "$state"
        if [ "$restarting" = "true" ]; then bad='a container is restarting'; continue; fi
        case "$status" in
          running)
            case "$health" in
              unhealthy) bad='a container reports unhealthy' ;;
              starting) bad='a container is still starting' ;;
            esac
            ;;
          # A one-shot container that finished cleanly is not a fault:
          # several stacks here run an init container that exits 0.
          exited)
            if [ "$exitcode" != "0" ]; then bad="a container exited with $exitcode"; fi
            ;;
          *) bad="a container is $status" ;;
        esac
      done
    fi
    if [ -z "$bad" ]; then
      # shellcheck disable=SC2086
      counters_now="$(docker inspect -f '{{.Name}} {{.RestartCount}}' $ids 2>/dev/null || true)"
      if [ "$clean" -eq 0 ] || [ "$counters_now" != "$counters" ]; then
        clean=1
        counters="$counters_now"
      else
        clean=$((clean + 1))
      fi
      if [ "$clean" -ge 3 ]; then return 0; fi
      bad='waiting for the containers to hold still'
    else
      clean=0
    fi
    now="$(date +%s)"
    if [ "$now" -ge "$deadline" ]; then printf '%s\n' "$bad"; return 1; fi
    if [ "$now" -ge "$beat" ]; then
      # The app streams this; minutes of silence read as a hung run.
      echo "waiting for $project: $bad" >&2
      beat=$((now + 30))
    fi
    sleep 5
  done
}

# The entry point both callers go through: the timer's scheduled run
# and the app's button. Validates and refuses BEFORE taking the lock
# (an unknown or self-managed id was never going to run at all, so
# there is nothing to serialise against), then hands off to the
# locked body below. `gd_with_lock` calls it as a plain function in
# THIS shell, not a subshell or a fork, so the globals `gd_load_service`
# just filled (PROJECT/DIR/BACKUP_TARGET/IMAGES) stay visible to it.
gd_update_service() {
  local svc="$1"
  # Neither refusal below is recorded: both answer a question that was
  # never a run. A scheduled run cannot reach them at all — set-schedule
  # keeps self-managed and unknown ids out of SERVICES — so a record
  # here could only ever describe a button press whose answer the person
  # who pressed it is already reading.
  if gd_is_self_managed "$svc"; then
    echo "$svc ships its own updater, so this wrapper does not swap its images" >&2
    return 2
  fi
  gd_load_service "$svc" || return 2

  local rc=0
  gd_with_lock "update-$svc" gd_update_service_locked "$svc" || rc=$?
  if [ "$rc" -eq "$GD_LOCK_BUSY" ]; then
    # UNLIKE the refusals above, this IS recorded: the service was
    # eligible to run and did not, which is exactly the failure mode
    # `autoupdate-status.txt` exists to catch — a scheduled run that
    # skips silently reads as "nothing happened" to whoever checks
    # back later (see LockSections).
    gd_record "$(printf '%s %s %s' 'GRYONIXNEXUS_UPDATE_FAILED' "$svc" \
      'another update for this service was already running')"
  fi
  return "$rc"
}

# The ONE body both callers go through, once the lock is held. Two
# copies of this is the drift the backup wrapper already exists to
# prevent.
gd_update_service_locked() {
  local svc="$1" img old work='' reason='' health=''

  # 1. A backup FIRST, through the wrapper that owns backups. A failed
  # backup stops the update: the point of taking one is that the update
  # is the risky part.
  if [ -n "$BACKUP_TARGET" ]; then
    if [ ! -x "$BACKUP_CTL" ]; then
      echo "the backup helper is missing, so $svc was not updated" >&2
      gd_record "$(printf '%s %s %s' 'GRYONIXNEXUS_UPDATE_FAILED' "$svc" 'the backup helper is missing')"
      return 1
    fi
    echo "backing up $svc before updating it"
    # stdin is /dev/null on purpose. The backup wrapper reads a
    # passphrase from stdin when it encrypts, and an open pipe with
    # nobody writing would park it forever; closed, it falls back to the
    # stored passphrase and refuses if there is none — which is the
    # right answer for an unattended run over a secret store.
    if ! "$BACKUP_CTL" backup "$BACKUP_TARGET" < /dev/null; then
      echo "the backup of $svc failed, so the update was not applied" >&2
      gd_record "$(printf '%s %s %s' 'GRYONIXNEXUS_UPDATE_FAILED' "$svc" 'the backup failed')"
      return 1
    fi
  else
    echo "$svc declares no backup, so none was taken before this update"
  fi

  # 2. What a rollback would return to. Readable only now: after the
  # pull the tag points somewhere else.
  work="$(mktemp -d)"
  : > "$work/before"
  for img in $IMAGES; do
    old="$(gd_image_id "$img")"
    printf '%s %s\n' "$img" "$old" >> "$work/before"
  done

  # 3. Pull, then restart. `cd` because pull and up need the compose
  # FILE (ps finds the project by label, these do not).
  if ! ( cd "$DIR" && docker compose -p "$PROJECT" pull ); then
    # Nothing was restarted, so the service is still the one that was
    # running — but a partial pull may have moved a tag, and the next
    # `up` anywhere would then apply it silently.
    gd_restore_images "$work/before"
    rm -rf "$work"
    echo "could not pull the new images for $svc" >&2
    gd_record "$(printf '%s %s %s' 'GRYONIXNEXUS_UPDATE_FAILED' "$svc" 'could not pull the new images')"
    return 1
  fi
  if ! ( cd "$DIR" && docker compose -p "$PROJECT" up -d ); then
    reason=did_not_start
  else
    if ! health="$(gd_wait_healthy "$PROJECT" "$HEALTH_TIMEOUT")"; then
      reason="${health:-unhealthy}"
    fi
  fi

  # 4. Roll back to the images the host was already running.
  if [ -n "$reason" ]; then
    gd_restore_images "$work/before"
    ( cd "$DIR" && docker compose -p "$PROJECT" up -d ) || true
    rm -rf "$work"
    gd_record "$(printf '%s %s %s' 'GRYONIXNEXUS_UPDATE_ROLLED_BACK' "$svc" "$reason")"
    return 1
  fi
  rm -rf "$work"
  gd_record "$(printf '%s %s' 'GRYONIXNEXUS_UPDATE_DONE' "$svc")"
}

# --- the record ------------------------------------------------------

# Printed AND kept. The print is for the app streaming this run; the
# copy is for the app that was closed when the timer fired.
gd_record() {
  printf '%s\n' "$1"
  install -d -m 755 "$(dirname "$STATUS_FILE")" 2>/dev/null || true
  printf '%s\n' "$1" >> "$STATUS_FILE" 2>/dev/null || true
  # Bounded: manual runs append here too and nothing else prunes it.
  { tail -n 200 "$STATUS_FILE" > "$STATUS_FILE.tmp" && mv "$STATUS_FILE.tmp" "$STATUS_FILE"; } 2>/dev/null || true
  chmod 644 "$STATUS_FILE" 2>/dev/null || true
}

do_status() {
  # Read-only, and missing is not an error: a server that has never run
  # an update has nothing to report, which is not the same as broken.
  { cat "$STATUS_FILE" 2>/dev/null; } || true
}

do_run() {
  local target="${1:-}" svc failed=''
  if [ "$target" = '--scheduled' ]; then
    load_config
    install -d -m 755 "$(dirname "$STATUS_FILE")" 2>/dev/null || true
    printf 'last-run %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATUS_FILE" 2>/dev/null || true
    for svc in $SERVICES; do
      # Each service in its own subshell, and the `||` keeps errexit
      # from firing: an unattended run must not let one broken service
      # cancel the updates of every service after it.
      ( gd_update_service "$svc" ) || failed="$failed $svc"
    done
    if [ -n "$failed" ]; then
      echo "the update failed for:$failed" >&2
      exit 1
    fi
    return 0
  fi
  gd_valid_label "$target" || exit 2
  gd_update_service "$target"
}

do_set_schedule() {
  # <schedule> is `off` or `every:<n><unit>@<HH:MM>` — the interval and
  # the time of day the user picked. Parsed here rather than taking a
  # raw OnCalendar expression: the wrapper is whitelisted in sudoers,
  # so it must not accept arbitrary systemd input from the client.
  local schedule="${1:-off}"
  shift || true
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
  # Only services this wrapper can actually update may end up in the
  # config — a self-managed one ticked in the app is dropped HERE rather
  # than accepted and skipped later, because the app reads this file
  # back and the switch has to show what the server will really do.
  local checked=""
  for svc in $services; do
    # Membership tested against the baked-in list itself, so the set of
    # updatable services exists ONCE in this script and cannot disagree
    # with itself. The quotes inside the pattern are what make the
    # comparison literal: a caller sending `*` matches nothing.
    case " $KNOWN " in
      *" $svc "*) checked="$checked $svc" ;;
    esac
  done
  install -d -m 755 "$(dirname "$CONFIG")"
  cat > "$CONFIG" <<EOF_UP_CONF
SCHEDULE=$schedule
SERVICES='${checked# }'
EOF_UP_CONF
  # World-readable on purpose: it holds no secrets and the app reads it
  # without sudo.
  chmod 644 "$CONFIG"
  if [ "$schedule" = "off" ]; then
    systemctl disable --now 'gryonixnexus-autoupdate.timer' >/dev/null 2>&1 || true
  else
    mkdir -p /etc/systemd/system
    cat > /etc/systemd/system/gryonixnexus-autoupdate.timer <<EOF_UP_TIMER
[Unit]
Description=gryonixNexus scheduled updates
[Timer]
OnCalendar=$oncal
# Servers are not up 24/7 — a missed window must still run.
Persistent=true
# Small jitter only: the user picked a specific time, so the run must
# not wander an hour away from it.
RandomizedDelaySec=5m
[Install]
WantedBy=timers.target
EOF_UP_TIMER
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
    systemctl enable --now 'gryonixnexus-autoupdate.timer' >/dev/null 2>&1 || true
  fi
}

case "$ACTION" in
  check) shift; do_check "$@" ;;
  run) shift; do_run "$@" ;;
  set-schedule) shift; do_set_schedule "$@" ;;
  status) do_status ;;
  *) echo "unsupported action: ${ACTION}" >&2; exit 2 ;;
esac
echo 'GRYONIXNEXUS_UPDATE_CTL_DONE'"#;

/// A port of `UpdateControlSections.wrapper`.
pub fn wrapper(input: &HostInput) -> String {
    let (targets, self_managed) = plan(input);
    let known = targets.iter().map(|target| target.id).collect::<Vec<_>>().join(" ");
    let self_managed_ids = self_managed.join(" ");
    let arms = render_service_arms(&targets);
    TEMPLATE.replace("@@KNOWN@@", &known).replace("@@SELF_MANAGED@@", &self_managed_ids).replace("@@ARMS@@", &arms)
}

/// A port of the `unit` value inside `UpdateControlSections.wrapper` — the
/// `gryonixnexus-autoupdate.service` unit the timer activates. Every field is a
/// fixed literal; nothing here is settings-derived, so this takes no input.
pub fn autoupdate_unit() -> String {
    format!(
        "[Unit]\nDescription=gryonixNexus scheduled update run\nAfter=docker.service\n[Service]\nType=oneshot\nExecStart={SCRIPT_PATH} run {SCHEDULED_FLAG}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::host::HostRole;

    fn base_input(services: &[&str]) -> HostInput {
        HostInput {
            services: services.iter().map(|s| s.to_string()).collect(),
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: crate::dns_records::Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        }
    }

    /// **An update target's backup id has to be an arm the BACKUP wrapper
    /// actually has.** The update takes a backup first and stops when it
    /// cannot — so a service given a backup id it does not own does not
    /// degrade, it becomes unupdatable. SearXNG was: it declares no backup on
    /// either side (its whole state is the settings file the install writes
    /// and a cache it can fetch again), and this table still asked for one.
    /// Measured on a live host, 2026-09-08: `RunUpdate(searxng)` answered "the
    /// backup failed" on an update with nothing wrong with it.
    ///
    /// Checked against the backup wrapper's own generated text rather than
    /// against a second list: two lists are what disagreed in the first place.
    #[test]
    fn every_update_targets_backup_id_is_an_arm_the_backup_wrapper_has() {
        let ids: Vec<&str> = UPDATE_CAPABLE_SERVICE_IDS.to_vec();
        let input = base_input(&ids);
        let backup_wrapper = crate::install::host::backup_ctl::script(&input);
        for id in &ids {
            let Some(Entry::Target(target)) = classify(id, &input.install) else { continue };
            if target.backup_target.is_empty() {
                continue;
            }
            assert!(
                backup_wrapper.contains(&format!("{})", target.backup_target)),
                "{} is updated with a backup id ({}) the backup wrapper has no arm for",
                target.id, target.backup_target
            );
        }
    }

    /// The mail engine, if any, is moved to the FRONT — the rest keep
    /// `CATALOG_ORDER`'s own relative order. `gitlab` sits BEFORE `forgejo`
    /// in that order even though it is not the mail engine here, which is
    /// what this test actually exercises (a naive alphabetical sort would
    /// put `forgejo` first).
    #[test]
    fn mail_engine_moves_to_the_front_of_catalog_order() {
        let input = base_input(&["docker-mailserver", "forgejo", "gitlab", "vaultwarden"]);
        assert_eq!(ordered_services(&input), vec!["docker-mailserver", "vaultwarden", "forgejo", "gitlab"]);
    }

    /// mailcow and GitLab never reach a `Target` — only `SELF_MANAGED`.
    #[test]
    fn self_managed_services_produce_no_target() {
        let input = base_input(&["mailcow", "gitlab", "vaultwarden"]);
        let (targets, self_managed) = plan(&input);
        assert_eq!(targets.iter().map(|t| t.id).collect::<Vec<_>>(), vec!["vaultwarden"]);
        assert_eq!(self_managed, vec!["mailcow", "gitlab"]);
    }

    /// `builtOnServer` services (the panel, plain WireGuard, OpenVPN) are
    /// invisible to this wrapper entirely — not a target, not self-managed.
    /// The guard that would have caught the six missing arms here.
    #[test]
    fn every_update_capable_service_has_an_arm() {
        for id in UPDATE_CAPABLE_SERVICE_IDS {
            let input = HostInput {
                services: vec![id.to_string()],
                install: Input { domain: "example.com".to_string(), ..Input::default() },
                language: crate::dns_records::Language::En,
                ssh_user: Some("server-user".to_string()),
                role: HostRole::SingleHost,
            };
            assert!(
                wrapper(&input).contains(&format!("    {id}) PROJECT=")),
                "`{id}` takes a composePull update but this wrapper renders no arm for it — \
                 the app offers Update and the host answers that it has no entry"
            );
        }
    }

    #[test]
    fn built_on_server_services_are_entirely_excluded() {
        let input = base_input(&["wireguard-vpn", "vpn-panel", "openvpn"]);
        let (targets, self_managed) = plan(&input);
        assert!(targets.is_empty());
        assert!(self_managed.is_empty());
        assert!(!is_used(&input));
    }

    /// The three VPN protocols with a Rust module of their own still declare
    /// no backup, unlike every other composePull target.
    #[test]
    fn vpn_protocol_targets_have_no_backup_target() {
        let input = base_input(&["amnezia-wg", "shadowsocks", "xray-reality"]);
        let (targets, _) = plan(&input);
        assert!(targets.iter().all(|t| t.backup_target.is_empty()));
    }

    /// A host with only a composePull service is used; a host with only
    /// self-managed services is NOT (mirrors Swift's `isUsed`, which checks
    /// `targets.isEmpty`, never `selfManaged`).
    #[test]
    fn is_used_ignores_self_managed_only_hosts() {
        assert!(is_used(&base_input(&["vaultwarden"])));
        assert!(!is_used(&base_input(&["mailcow"])));
        assert!(!is_used(&base_input(&[])));
    }

    #[test]
    fn autoupdate_unit_names_the_scheduled_flag() {
        assert!(autoupdate_unit().contains("ExecStart=/opt/gryonixnexus-update-ctl.sh run --scheduled"));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — the same
/// discipline `lock.rs`'s own test module explains at length. Ground truth
/// is `UpdateControlSections.wrapper`'s actual output, not a re-reading of
/// its source; fixtures live under `tests/fixtures/install/host/update_ctl/`
/// and `.../autoupdate_unit/`. If a fixture and this module ever disagree,
/// the working assumption is that the bug is in this port.
#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::install::host::HostRole;

    fn fixture(dir: &str, name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/host/{dir}/{name}.txt", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn input_for(services: &[&str]) -> HostInput {
        HostInput {
            services: services.iter().map(|s| s.to_string()).collect(),
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: crate::dns_records::Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        }
    }

    /// One assertion per fixture, both diffed byte for byte after trimming
    /// the extraction tool's own trailing newline (see `TEMPLATE`'s doc).
    fn assert_parity(services: &[&str], variant: &str) {
        let input = input_for(services);
        assert_eq!(
            wrapper(&input),
            fixture("update_ctl", variant).trim_end_matches('\n'),
            "{variant}: update-ctl.sh body"
        );
    }

    // Every scenario below is a DISTINCT fixture body — 23 of the 97 script
    // variants `GeneratedScriptLintTests.makeVariants()` builds produce a
    // body different from every other (README.md in the fixtures directory).
    // Service sets are copied from that function's `serviceSets` array
    // verbatim (the manifest); topology/dashboard-access/language are
    // deliberately NOT varied here — this wrapper does not read any of them
    // (no `B-` fixture exists at all: the home-backend half of scenario B
    // renders identically to scenario A for the same service set, and the
    // relay half carries no services to update).

    #[test]
    fn jellyfin() {
        assert_parity(&["jellyfin"], "A-jellyfin-access-en");
    }

    #[test]
    fn psono() {
        assert_parity(&["psono"], "A-psono-access-en");
    }

    #[test]
    fn nomail_ovpn() {
        assert_parity(&["vaultwarden", "openvpn"], "A-nomail-ovpn-access-en");
    }

    #[test]
    fn passbolt() {
        assert_parity(&["passbolt"], "A-passbolt-access-en");
    }

    #[test]
    fn adguard() {
        assert_parity(&["adguard-home"], "A-adguard-access-en");
    }

    /// The six services this port had no arms for at all, so an agent-built
    /// host answered "no entry" to the Update button the app was showing.
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
    fn mesh() {
        // The node rides along with the control server, and it has an arm of
        // its own here (unlike in the backup wrapper) because it has an image.
        assert_parity(&["headscale", "tailscale-node"], "A-mesh-access-en");
    }

    #[test]
    fn tunnel() {
        assert_parity(&["cloudflared"], "A-tunnel-access-en");
    }

    #[test]
    fn photoprism() {
        assert_parity(&["photoprism"], "A-photoprism-access-en");
    }

    #[test]
    fn seafile() {
        assert_parity(&["seafile"], "A-seafile-access-en");
    }

    #[test]
    fn dms() {
        assert_parity(&["docker-mailserver"], "A-dms-access-en");
    }

    #[test]
    fn mailcow_xray() {
        assert_parity(&["mailcow", "vaultwarden", "xray-reality"], "A-mailcow-xray-access-en");
    }

    #[test]
    fn psono_vaultwarden() {
        assert_parity(&["psono", "vaultwarden"], "A-psono-vaultwarden-access-en");
    }

    #[test]
    fn nomail_ss() {
        assert_parity(&["vaultwarden", "shadowsocks"], "A-nomail-ss-access-en");
    }

    #[test]
    fn mailu() {
        assert_parity(&["mailu"], "A-mailu-access-en");
    }

    #[test]
    fn jellyfin_full() {
        assert_parity(&["jellyfin", "vaultwarden", "nextcloud", "wireguard-vpn"], "A-jellyfin-full-access-en");
    }

    #[test]
    fn passwords_shelf() {
        assert_parity(&["passbolt", "psono", "vaultwarden"], "A-passwords-shelf-access-en");
    }

    #[test]
    fn adguard_full() {
        assert_parity(&["adguard-home", "vaultwarden", "nextcloud", "wireguard-vpn"], "A-adguard-full-access-en");
    }

    #[test]
    fn seafile_nextcloud() {
        assert_parity(&["seafile", "nextcloud", "vaultwarden"], "A-seafile-nextcloud-access-en");
    }

    #[test]
    fn dms_full() {
        assert_parity(&["docker-mailserver", "vaultwarden", "forgejo", "wireguard-vpn"], "A-dms-full-access-en");
    }

    #[test]
    fn photoprism_immich() {
        assert_parity(&["photoprism", "immich", "vaultwarden"], "A-photoprism-immich-access-en");
    }

    #[test]
    fn mailcow_wg() {
        assert_parity(&["mailcow", "vaultwarden", "nextcloud", "immich", "wireguard-vpn"], "A-mailcow-wg-access-en");
    }

    #[test]
    fn nomail() {
        assert_parity(&["vaultwarden", "nextcloud", "immich", "forgejo", "gitlab"], "A-nomail-access-en");
    }

    #[test]
    fn mailcow_awg() {
        assert_parity(
            &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "amnezia-wg"],
            "A-mailcow-awg-access-en",
        );
    }

    #[test]
    fn multidomain() {
        assert_parity(
            &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "gitlab", "amnezia-wg"],
            "A-multidomain",
        );
    }

    #[test]
    fn mailu_full() {
        assert_parity(
            &["mailu", "vaultwarden", "nextcloud", "immich", "forgejo", "wireguard-vpn"],
            "A-mailu-full-access-en",
        );
    }

    /// The systemd unit the timer activates — constant across every
    /// scenario (measured: only one distinct body exists in the fixtures
    /// directory), so one comparison is enough.
    #[test]
    fn autoupdate_unit_matches_the_real_generated_script() {
        assert_eq!(autoupdate_unit(), fixture("autoupdate_unit", "A-adguard-access-en").trim_end_matches('\n'));
    }
}
