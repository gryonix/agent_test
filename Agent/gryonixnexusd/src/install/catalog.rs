//! The catalog's SHELVES, as the start page needs them.
//!
//! **A second copy of `ServiceCategory` + `ServiceRegistry`, and deliberately
//! so** — the same reasoning every other port in this crate carries: the agent
//! is a self-contained musl binary, the Swift package cannot be linked into
//! it, and `ServiceCatalog` knows nothing about Rust. There is nowhere for a
//! shared dependency to live in either direction, so the duplication is caught
//! by tests on both sides instead of prevented by structure.
//!
//! Only `homepage` reads this today. It is separate from `host::CATALOG_ORDER`
//! (which is a flat sequence for the wrappers) because the page needs the
//! GROUPING and the human-readable names, which that list does not carry.

use super::caddy::WebIngress;
use super::context::Input;

/// Title and one-line summary of a shelf, plus its members as
/// `(catalog id, display name)` — mirroring `ServiceCategory` and the order
/// `ServiceRegistry.all` puts the members in.
///
/// The titles and summaries are the Swift ones VERBATIM: they are written into
/// `services.yaml` on the server, so a paraphrase here would be a different
/// file, and the fixtures compare files.
type Shelf = (&'static str, &'static str, &'static [(&'static str, &'static str)]);

const MAIL: &[(&str, &str)] =
    &[("mailcow", "Mailcow"), ("mailu", "Mailu"), ("docker-mailserver", "Docker Mailserver")];
const PASSWORDS: &[(&str, &str)] =
    &[("vaultwarden", "Vaultwarden"), ("psono", "Psono"), ("passbolt", "Passbolt")];
const FILES: &[(&str, &str)] = &[("nextcloud", "Nextcloud"), ("seafile", "Seafile")];
const PHOTOS: &[(&str, &str)] = &[("immich", "Immich"), ("photoprism", "PhotoPrism")];
const MEDIA: &[(&str, &str)] = &[("jellyfin", "Jellyfin")];
const CODE: &[(&str, &str)] = &[("gitlab", "GitLab"), ("forgejo", "Forgejo")];
const NETWORK: &[(&str, &str)] = &[("adguard-home", "AdGuard Home"), ("pihole", "Pi-hole")];
const VPN: &[(&str, &str)] = &[
    ("wireguard-vpn", "WireGuard"),
    ("amnezia-wg", "AmneziaWG"),
    ("shadowsocks", "Shadowsocks"),
    ("xray-reality", "VLESS / Reality"),
    ("openvpn", "OpenVPN"),
    // An `implicit` service on the Swift side — nobody picks it, a protocol
    // brings it along — so it is on no shelf a form renders. On the PAGE it
    // belongs under VPN anyway: the five protocols have no web face, so
    // without it this group would be empty on every server that has a VPN,
    // and the panel is the one address somebody actually opens.
    ("vpn-panel", "VPN Panel"),
];
const MESH: &[(&str, &str)] = &[("headscale", "Headscale"), ("tailscale-node", "Tailscale")];
const REMOTE_ACCESS: &[(&str, &str)] = &[("cloudflared", "Cloudflare Tunnel")];
const DASHBOARD: &[(&str, &str)] = &[("homepage", "Homepage")];
const SSO: &[(&str, &str)] = &[("authelia", "Authelia")];
/// Mirrors `ServiceRegistry`: the chat leads, because switching the shelf on
/// installs the FIRST member and an engine with nothing in front of it is a
/// loopback port nobody can open. The engine has no web face at all, so on the
/// PAGE it would otherwise be invisible — the same reason the VPN panel and
/// Crafty appear on shelves they are implicit members of.
const AI: &[(&str, &str)] = &[
    ("open-webui", "Open WebUI"),
    ("ollama", "Ollama"),
    ("anythingllm", "AnythingLLM"),
    ("litellm", "LiteLLM"),
    ("qdrant", "Qdrant"),
    ("searxng", "SearXNG"),
    ("openclaw", "OpenClaw"),
];
/// Its own shelf on the Swift side, by the rule every shelf follows: a shelf
/// is a NEED, and "when this happens, do that" is not "talk to a model".
const AUTOMATION: &[(&str, &str)] = &[("n8n", "n8n")];
const GAMES: &[(&str, &str)] = &[
    ("minecraft-java", "Minecraft (Java)"),
    ("minecraft-bedrock", "Minecraft (Bedrock)"),
    // Implicit on the Swift side, exactly like the VPN panel above and for
    // the same reason: the engines have no web face at all, so without this
    // the group would be empty on every host that runs a game.
    ("crafty-controller", "Crafty Controller"),
];

/// In `ServiceCategory.selectable` order — what `ServiceRegistry.categories`
/// yields on the Swift side, minus the shelves with no members here.
pub fn categories() -> Vec<Shelf> {
    vec![
        ("Mail", "A mail server on your own domain: mailboxes, webmail, spam filtering.", MAIL),
        ("Passwords", "A password vault for people, with apps and browser extensions.", PASSWORDS),
        ("Files", "File sync and sharing across your devices — your own drive, on your own server.", FILES),
        ("Photos", "A photo and video library: automatic phone backup, albums, search.", PHOTOS),
        ("Media", "Streams films, series and music you already own to any device.", MEDIA),
        ("Git hosting", "Your own Git server: repositories, issues, pull requests.", CODE),
        (
            "Ad & tracker blocking",
            "A DNS server for your devices that drops ads, trackers and malware domains before they load.",
            NETWORK,
        ),
        (
            "VPN",
            "An encrypted tunnel into this server from anywhere, with a panel that hands out client profiles.",
            VPN,
        ),
        (
            "Private network for your devices",
            "Links your own phones, laptops and servers straight to each other, wherever they are. Nothing is published to the internet.",
            MESH,
        ),
        (
            "Game servers",
            "A Minecraft server on your own machine, with a web panel for the console, players and backups.",
            GAMES,
        ),
        (
            "Access without opening ports",
            "The server dials out and keeps the connection open, so its sites work from the internet even behind a router with no public IP.",
            REMOTE_ACCESS,
        ),
        (
            "Start page",
            "One page linking to everything installed on this server, built from the services you picked.",
            DASHBOARD,
        ),
        (
            "Single sign-on",
            "One login in front of the admin panels, on top of the password each of them already has.",
            SSO,
        ),
        (
            "AI",
            "A model that runs on your own machine, and a chat in front of it: nothing you type, and none of the documents you feed it, leaves the server.",
            AI,
        ),
        (
            "Automation",
            "Connects your services to each other: an event, then a step, then a step. Zapier, running on your own server.",
            AUTOMATION,
        ),
    ]
}

/// A service's Caddy ingress, or `None` when it publishes no site.
///
/// **The one place that knows how to render ANY service's site**, which is
/// what makes single sign-on possible at all: turning SSO on has to rewrite
/// the sites it guards, and those were written by their own installers with
/// no idea a portal would arrive later. Without this, the portal listed rules
/// for sites Caddy never asked it about — installed, and guarding nothing.
pub fn web_ingress_for(id: &str, input: &Input) -> Option<WebIngress> {
    use super::mail::{dockermailserver as dms, mailcow, mailu};
    match id {
        "mailcow" => Some(mailcow::web_ingress(input)),
        "mailu" => Some(mailu::web_ingress(input)),
        "docker-mailserver" => Some(dms::web_ingress(input)),
        "vaultwarden" => Some(super::vaultwarden::web_ingress(input)),
        "psono" => Some(super::psono::web_ingress(input)),
        "passbolt" => Some(super::passbolt::web_ingress(input)),
        "nextcloud" => Some(super::nextcloud::web_ingress(input)),
        "seafile" => Some(super::seafile::web_ingress(input)),
        "immich" => Some(super::immich::web_ingress(input)),
        "photoprism" => Some(super::photoprism::web_ingress(input)),
        "gitlab" => Some(super::gitlab::web_ingress(input)),
        "forgejo" => Some(super::forgejo::web_ingress(input)),
        "jellyfin" => Some(super::jellyfin::web_ingress(input)),
        "crafty-controller" => Some(super::crafty::web_ingress(input)),
        "adguard-home" => Some(super::adguard::web_ingress(input)),
        "pihole" => Some(super::pihole::web_ingress(input)),
        "homepage" => Some(super::homepage::web_ingress(input)),
        "headscale" => Some(super::headscale::web_ingress(input)),
        "authelia" => Some(super::authelia::web_ingress(input)),
        "vpn-panel" => Some(super::vpn::panel::web_ingress(input)),
        "open-webui" => Some(super::open_webui::web_ingress(input)),
        // Published where the engine is not, and the difference is
        // authentication rather than taste — see the module's own note.
        "litellm" => Some(super::litellm::web_ingress(input)),
        // The only ingress here that carries public paths — see `n8n`'s own
        // module note. `site_for` passes them through, so the generic route
        // renders the split without knowing which service asked for it.
        "n8n" => Some(super::n8n::web_ingress(input)),
        "anythingllm" => Some(super::anythingllm::web_ingress(input)),
        // The page behind it pairs messengers and holds their sessions, so it
        // is published and it is guarded.
        "openclaw" => Some(super::openclaw::web_ingress(input)),
        // `searxng` is deliberately absent, a third time and for a third
        // reason: nobody asked for another search page in a browser, and the
        // callers are the containers beside it.
        // `qdrant` is deliberately absent, exactly as `ollama` is: an API
        // holding the owner's documents has no business on a hostname.
        // `ollama` is deliberately absent: an unauthenticated model API has no
        // business on a hostname, so it falls through to `None` below with the
        // VPN protocols and the connector.
        // No site of its own: the connector publishes its names in
        // Cloudflare, and the raw VPN protocols speak the panel's.
        _ => None,
    }
}

/// Every name that service's site answers on — the hostname plus its mirrors.
pub fn site_names_for(id: &str, input: &Input) -> Vec<String> {
    let Some(ingress) = web_ingress_for(id, input) else { return Vec::new() };
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// That service's whole Caddy block, with or without the sign-on check.
pub fn site_for(id: &str, input: &Input, sso: bool) -> Option<(Vec<String>, String)> {
    let ingress = web_ingress_for(id, input)?;
    let names = site_names_for(id, input);
    let text = super::caddy::site_with_public_paths(
        // The catalog id itself: this is the generic route, and the id it was
        // asked about is exactly the owner the block should carry.
        id,
        &names.join(", "),
        ingress.upstream_port,
        ingress.admin_guard,
        ingress.upstream_https,
        input.local_only,
        sso,
        // Empty for everything but n8n, and empty renders the bytes this call
        // always rendered — so this stays the ONE generic route rather than
        // growing a special case for the one service that answers.
        &ingress.public_paths,
            false,
);
    Some((names, text))
}

/// The hostname a service's web face answers on, or `None` when it has none.
///
/// Delegates to the one table that already answers this
/// (`host::uninstall::hostname_for`) rather than writing a second: two answers
/// to "where does this service live" is how a Caddy site and its removal end
/// up disagreeing.
pub fn web_hostname(id: &str, input: &Input) -> Option<String> {
    super::host::uninstall::hostname_for(id, input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every id named here has to be one the rest of the crate knows, or the
    /// start page links to a service that does not exist.
    #[test]
    fn every_member_is_an_id_the_wrapper_catalog_also_carries() {
        for (_, _, members) in categories() {
            for (id, _) in members {
                assert!(
                    super::super::host::CATALOG_ORDER.contains(id),
                    "{id} is on a shelf here but not in CATALOG_ORDER"
                );
            }
        }
    }

    /// And the other way round: a service the wrappers manage but no shelf
    /// names would silently never appear on the page.
    #[test]
    fn every_catalog_id_sits_on_exactly_one_shelf() {
        for id in super::super::host::CATALOG_ORDER {
            let shelves: Vec<&str> = categories()
                .into_iter()
                .filter(|(_, _, members)| members.iter().any(|(m, _)| m == id))
                .map(|(title, _, _)| title)
                .collect();
            assert_eq!(shelves.len(), 1, "{id} sits on {shelves:?}");
        }
    }
}
