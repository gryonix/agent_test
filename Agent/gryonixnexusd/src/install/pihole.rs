//! Pi-hole's declarative install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/PiholeService.swift`,
//! the declarative half only (compose file, env template, hostname, DNS
//! hostnames, Caddy ingress, firewall ports). The imperative half — creating
//! the directory, writing the files, waiting for the resolver to answer a
//! query — lives in `execute.rs` beside every other service's, for the reason
//! `install::mod`'s doc gives.
//!
//! **Second engine on the DNS shelf, and the difference from AdGuard Home is
//! the point of having two.** AdGuard speaks DNS-over-HTTPS itself, so its
//! filter is reachable from anywhere through Caddy on an ordinary HTTPS name.
//! Pi-hole has no DoH server at all: it answers plain DNS on 53 and nothing
//! else, which makes it the household resolver a router is pointed at. The
//! app says so where the choice is made.

use super::caddy::{self, WebIngress};
use super::context::Input;
use super::firewall;

/// Exact pinned tag. arm64 verified by the ELF header inside the layer, not
/// by the index's promise: `usr/bin/pihole-FTL` in the linux/arm64 manifest
/// is a real AArch64 binary (e_machine 0xB7) — "multi-arch" tags in this
/// catalog have been fictitious before.
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "pihole";

pub const IMAGE: &str = "pihole/pihole:2026.07.2";
pub const COMPOSE_PROJECT: &str = "pihole";
pub const CONTAINER: &str = "pihole";
/// Loopback port Caddy proxies to — distinct from every other service's
/// upstream (8087 AdGuard, 8091 headscale, 8096 Jellyfin, …).
pub const WEB_UI_PORT: u16 = 8092;
/// Port the admin interface binds INSIDE the container. Left at Pi-hole's own
/// default rather than moved: FTL's web server and its API share it, and
/// every path in the UI is built from it.
pub const CONTAINER_WEB_PORT: u16 = 80;

/// A port of `PiholeService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.pihole_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.pihole_hostname.clone()
    }
}

/// A port of `PiholeService.composeFile(_:).composeContents`.
///
/// **Plain DNS is published on the LOOPBACK unless it is asked for.** A
/// recursive resolver reachable from the internet is found by scanners within
/// days and used for amplification. "Do not open 53 in nftables" does NOT
/// prevent it: docker publishes a port through its own DNAT, which the filter
/// chain never sees, so the BIND ADDRESS is the only control — which is why
/// the prefix below is the one line the safety of this service rests on.
///
/// `FTLCONF_dns_listeningMode: all` is not a widening of that: FTL's default
/// (`local`) answers only the subnets of its own interfaces, and inside a
/// container that is the docker bridge alone, so every forwarded query would
/// be refused. What is reachable is decided by the published address.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.pihole_path;
    let upstreams = &input.pihole_upstreams;
    let bind = if input.pihole_serves_network { "" } else { "127.0.0.1:" };
    format!(
        "services:\n  pihole:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      # Read by FTL itself: every `FTLCONF_<section>_<key>` maps to\n      # the matching key of pihole.toml. Verified in the pinned\n      # image's own `bash_functions.sh`, not assumed.\n      FTLCONF_webserver_api_password: ${{PIHOLE_ADMIN_PASSWORD}}\n      # `local` — FTL's default — answers only the subnets of its\n      # own interfaces, and inside a container that is the docker\n      # bridge alone: every forwarded query would be refused, which\n      # reads as \"the filter does not work\" rather than as a bind\n      # setting. What is actually reachable is decided by the\n      # published address below.\n      FTLCONF_dns_listeningMode: all\n      FTLCONF_dns_upstreams: {upstreams}\n    volumes:\n      - {path}/etc-pihole:/etc/pihole\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_WEB_PORT}/tcp\"\n      # See the type comment: a published port is reachable\n      # regardless of our nftables ruleset, so an open resolver is\n      # prevented by the bind address or nowhere.\n      - \"{bind}53:53/tcp\"\n      - \"{bind}53:53/udp\""
    )
}

/// A port of `PiholeService.composeFile(_:).envTemplate`. Generated on the
/// server; Pi-hole reads it once and stores a hash in pihole.toml, and the
/// plaintext stays in this 0600 file so the report can name it. This module
/// never sees the real secret, only the `__RANDOM__` template the substitution
/// replaces.
pub fn env_template() -> String {
    "PIHOLE_ADMIN_PASSWORD=__RANDOM__".to_string()
}

/// A port of `PiholeService.firewallPorts(_:)`.
///
/// Empty unless the resolver is meant to serve the network, and even then this
/// is a formality: a docker-published port bypasses the input chain entirely
/// (measured 2026-08-13). The entry exists so the ruleset describes the host
/// truthfully, and so scenario B's relay forwards the port when the resolver
/// lives on the home half.
pub fn firewall_ports(input: &Input) -> Vec<firewall::Port> {
    if input.pihole_serves_network {
        vec![firewall::Port::tcp(53), firewall::Port::udp(53)]
    } else {
        vec![]
    }
}

/// A port of `PiholeService.dnsHostnames(_:)`. Not read by `execute.rs` yet —
/// install-time DNS record generation is still open wiring — so this stays
/// fixture-tested but unreached in the binary until that RPC exists.
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `PiholeService.webIngress(_:)`: `admin_guard` true and
/// `upstream_https` false are `WebIngress`'s own Swift defaults, not something
/// this service sets.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
}

/// The Caddy site NAMES this ingress publishes — the hostname plus every
/// domain it mirrors onto. Exposed separately from `caddy_site` so a caller
/// folding this block into a shared Caddyfile does not recompute the list a
/// second way.
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    /// The one line the safety of this service rests on, in both directions.
    /// A negative control that flips the flag and expects the same string
    /// would pass on a compose file that ignored the setting entirely.
    #[test]
    fn plain_dns_is_loopback_only_until_the_network_is_asked_for() {
        let quiet = compose_contents(&input());
        assert!(quiet.contains("\"127.0.0.1:53:53/tcp\""), "{quiet}");
        assert!(quiet.contains("\"127.0.0.1:53:53/udp\""), "{quiet}");
        assert!(!quiet.contains("\"53:53/tcp\""), "an open resolver must not be the default: {quiet}");

        let mut wide = input();
        wide.pihole_serves_network = true;
        let served = compose_contents(&wide);
        assert!(served.contains("\"53:53/tcp\""), "{served}");
        assert!(served.contains("\"53:53/udp\""), "{served}");
        assert!(!served.contains("127.0.0.1:53:53"), "{served}");
    }

    /// The firewall drop-in follows the same switch. Nothing is opened for a
    /// resolver nobody outside this machine can reach.
    #[test]
    fn firewall_ports_follow_the_same_switch() {
        assert!(firewall_ports(&input()).is_empty());
        let mut wide = input();
        wide.pihole_serves_network = true;
        assert_eq!(firewall_ports(&wide), vec![firewall::Port::tcp(53), firewall::Port::udp(53)]);
    }

    /// It may take `dns.<domain>` — the name AdGuard Home uses — because the
    /// shelf is exclusive and the two can never be installed together. That is
    /// the mail engines' rule (all three pin `mail.<domain>`), not the
    /// second-engine rule that keeps Seafile off `cloud.`.
    #[test]
    fn the_default_hostname_is_the_shelf_name() {
        assert_eq!(hostname(&input()), "dns.example.com");
        let mut custom = input();
        custom.pihole_hostname = "filter.example.net".to_string();
        assert_eq!(hostname(&custom), "filter.example.net");
    }

    #[test]
    fn the_admin_password_is_a_generated_template_not_a_literal() {
        assert_eq!(env_template(), "PIHOLE_ADMIN_PASSWORD=__RANDOM__");
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — the same
/// discipline every other port in this module follows. Ground truth is the
/// Swift side's actual output for `PiholeService`'s declarative methods, not a
/// re-reading of `PiholeService.swift`; fixtures live under
/// `tests/fixtures/install/` and were dumped by a separate one-off pass
/// (`scratchpad/dump-pihole-install-fixtures.swift.txt`), not generated by
/// this crate. If a fixture and this module ever disagree, the working
/// assumption is that the BUG IS IN THIS PORT.
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    fn ingress_text(ingress: &WebIngress) -> String {
        format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}",
            ingress.hostname, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https
        )
    }

    fn ports_text(ports: &[firewall::Port]) -> String {
        ports
            .iter()
            .map(|p| format!("{}/{}", p.proto, p.port))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn assert_parity(input: &Input, scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(env_template(), fixture(&format!("{scenario}__env.template")), "{scenario}: env.template");
        assert_eq!(hostname(input), fixture(&format!("{scenario}__hostname.txt")), "{scenario}: hostname.txt");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames.txt"
        );
        assert_eq!(caddy_site(input), fixture(&format!("{scenario}__caddy-site.txt")), "{scenario}: caddy-site.txt");
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("{scenario}__ingress.txt")),
            "{scenario}: ingress.txt"
        );
        assert_eq!(
            ports_text(&firewall_ports(input)),
            fixture(&format!("{scenario}__firewall-ports.txt")),
            "{scenario}: firewall-ports.txt"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base("example.com"), "pihole-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "pihole-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "pihole-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.pihole_hostname = "filter.example.com".to_string();
        assert_parity(&input, "pihole-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.pihole_path = "/srv/pihole".to_string();
        assert_parity(&input, "pihole-custompath-public-en");
    }

    /// THE scenario of this service. Every other case here would pass on a
    /// port that ignored the switch and always wrote the loopback bind — this
    /// is the one that says the two halves agree about the line deciding
    /// whether the resolver is open to the internet.
    #[test]
    fn servesnetwork_public_en() {
        let mut input = base("example.com");
        input.pihole_serves_network = true;
        assert_parity(&input, "pihole-servesnetwork-public-en");
    }

    #[test]
    fn upstreams_public_en() {
        let mut input = base("example.com");
        input.pihole_upstreams = "9.9.9.9;149.112.112.112".to_string();
        assert_parity(&input, "pihole-upstreams-public-en");
    }

    /// The mirroring GUARD, not the mirroring: a service pointed at a hostname
    /// of its own must NOT be mirrored onto this deployment's other domains —
    /// Caddy would request a certificate for a name nobody owns.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.pihole_hostname = "dns.other-company.net".to_string();
        assert_parity(&input, "pihole-foreignhost-mirrored-public-en");
    }
}
