//! AdGuard Home's declarative install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/AdGuardHomeService.swift`,
//! ONLY the declarative half (compose file, env template, hostname, DNS
//! hostnames, Caddy ingress). `setupSteps` — the imperative shell that waits
//! for AdGuard's own installation API, POSTs the generated admin password,
//! and flips a DoH-insecure flag that moved key names between AdGuard
//! versions — is deliberately NOT ported; see `install::mod`'s doc for why.

use super::caddy::{self, WebIngress};
use super::context::Input;

/// Exact pinned tag. arm64 verified by ELF header inside the layer, not by
/// the index's promise (Swift type's own doc:
/// `opt/adguardhome/AdGuardHome` in the linux/arm64 manifest is a real
/// AArch64 binary, 34 MB — "multi-arch" tags in this catalog have been
/// fictitious before).
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "adguard-home";

pub const IMAGE: &str = "adguard/adguardhome:v0.107.78";
pub const COMPOSE_PROJECT: &str = "adguardhome";
pub const CONTAINER: &str = "adguardhome";
/// Loopback port Caddy proxies to — distinct from every other service's
/// upstream (8080 mailcow, 8086 docker-mailserver, 8096 Jellyfin, …).
pub const WEB_UI_PORT: u16 = 8087;
/// Port the web UI binds INSIDE the container — also what the (unported)
/// initial-configuration call has to name, or AdGuard moves its own
/// listener and the published port stops answering.
pub const CONTAINER_WEB_PORT: u16 = 3000;

/// A port of `AdGuardHomeService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.adguard_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.adguard_hostname.clone()
    }
}

/// A port of `AdGuardHomeService.composeFile(_:).composeContents`.
///
/// **Plain DNS is published on the LOOPBACK only.** A recursive resolver
/// reachable from the internet is found by scanners within days and used
/// for amplification — the traffic bill and the blocklisting land on the
/// owner. "Do not open 53 in nftables" is NOT enough to prevent that:
/// Docker publishes a port through its own DNAT and its own forward
/// accepts, which the filter chain never sees, so a `53:53` publish would
/// be public no matter what the firewall says. The BIND ADDRESS is the
/// control, which is why it is spelled `127.0.0.1:53:53`. Clients get the
/// filter over DNS-over-HTTPS through Caddy instead — TCP, TLS, no spoofed
/// sources, no amplification.
///
/// **systemd-resolved is left alone**, on purpose (not ported into this
/// function — nothing here disables it — but recorded because the Swift
/// type's doc treats it as load-bearing knowledge, not a footnote): its stub
/// listens on `127.0.0.53:53`, so `127.0.0.1:53` is free and there is
/// nothing to disable, and the host keeps resolving through it. Pointing the
/// host at the container instead is the tempting half-step, and it makes
/// apt, `docker pull` and ACME renewal depend on a filter container being
/// up — an outage that reads as "the server is broken", not as "the DNS
/// filter stopped".
pub fn compose_contents(input: &Input) -> String {
    let path = &input.adguard_path;
    format!(
        "services:\n  adguardhome:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    volumes:\n      - {path}/conf:/opt/adguardhome/conf\n      - {path}/work:/opt/adguardhome/work\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_WEB_PORT}\"\n      # Loopback ONLY — see the type comment. A published port is\n      # reachable from the internet regardless of our nftables\n      # ruleset, so an open resolver is prevented here or nowhere.\n      - \"127.0.0.1:53:53/tcp\"\n      - \"127.0.0.1:53:53/udp\""
    )
}

/// A port of `AdGuardHomeService.composeFile(_:).envTemplate`. Generated on
/// the server and printed in the report; the (unported) setup step hands it
/// to AdGuard's own installation API, which stores it as a bcrypt hash —
/// this module never sees the real secret, only the `__RANDOM__` template
/// `composeSetup`'s substitution loop replaces it with.
pub fn env_template() -> String {
    "ADGUARD_ADMIN_PASSWORD=__RANDOM__".to_string()
}

/// A port of `AdGuardHomeService.dnsHostnames(_:)`. Not read by `execute.rs`
/// yet — install-time DNS record generation is still the open wiring
/// question ROADMAP.md leaves for a later срез — so this stays fixture-
/// tested but unreached in the binary until that RPC exists.
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `AdGuardHomeService.webIngress(_:)`: `WebIngress(hostname:
/// upstreamPort:)` with everything else defaulted on the Swift side —
/// `admin_guard` true, `upstream_https` false, both `WebIngress`'s own
/// defaults, not something `AdGuardHomeService` sets explicitly.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
}

/// The Caddy site NAMES this service's ingress publishes — the hostname
/// itself plus every domain it mirrors onto. Exposed separately from
/// `caddy_site` so a caller that needs to IDENTIFY this service's own block
/// (folding it into a shared Caddyfile without touching any other service's
/// block — see `caddy::merge_site`) does not have to recompute the same
/// list a second way.
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// A port of the AdGuard-specific slice of `ServiceInfraSections.writeCaddyfile`:
/// mirror the ingress hostname onto every additional domain (one site,
/// several names — one certificate request covering all of them), then
/// render through `caddy::site`. `tls_internal` is `input.local_only`,
/// exactly as `writeCaddyfile` passes `context.isLocalOnly` for every
/// service, not something AdGuard decides on its own.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_defaults_to_dns_subdomain() {
        assert_eq!(hostname(&base("example.com")), "dns.example.com");
    }

    #[test]
    fn hostname_prefers_a_custom_value() {
        let mut input = base("example.com");
        input.adguard_hostname = "filter.example.com".to_string();
        assert_eq!(hostname(&input), "filter.example.com");
    }

    #[test]
    fn web_ingress_defaults_admin_guard_true_and_https_false() {
        let ingress = web_ingress(&base("example.com"));
        assert!(ingress.admin_guard);
        assert!(!ingress.upstream_https);
        assert_eq!(ingress.upstream_port, WEB_UI_PORT);
    }

    #[test]
    fn caddy_site_mirrors_the_hostname_onto_additional_domains() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert!(caddy_site(&input).starts_with("dns.example.com, dns.example.org {"));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — the same
/// discipline `dns_records::fixture_parity` follows (see that module's doc
/// for the full rationale and the GOTCHAS.md incidents it exists to avoid
/// repeating). Ground truth is the Swift side's actual output for
/// `AdGuardHomeService`'s declarative methods, not a re-reading of
/// `AdGuardHomeService.swift`; fixtures live under `tests/fixtures/install/`
/// and were dumped by a separate one-off pass, not generated by this crate.
/// If a fixture and this module's output ever disagree, the working
/// assumption is that the BUG IS IN THIS PORT.
#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::dns_records::Language;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    /// `<scenario>__ingress.txt`: four lines, `hostname=…`/`upstreamPort=…`/
    /// `adminGuard=…`/`upstreamHTTPS=…` — a plain-text render of `WebIngress`
    /// chosen for the fixture dump, not something either side's real code
    /// otherwise produces.
    fn ingress_text(ingress: &WebIngress) -> String {
        format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}",
            ingress.hostname, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https
        )
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
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base("example.com"), "default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.adguard_hostname = "filter.example.com".to_string();
        assert_parity(&input, "customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.adguard_path = "/srv/adguard".to_string();
        assert_parity(&input, "custompath-public-en");
    }

    #[test]
    fn mirrored_localonly_ru() {
        let mut input = base("home.local");
        input.local_only = true;
        input.additional_domains = vec!["home.lan".to_string()];
        input.language = Language::Ru;
        input.admin_username = "operator".to_string();
        assert_parity(&input, "mirrored-localonly-ru");
    }

    /// The mirroring GUARD rather than the mirroring itself, and the only
    /// scenario that can catch a port which mirrors blindly by prefix:
    /// `mirrored_hostnames` mirrors a name ONTO the deployment's other domains
    /// only when it actually sits under the primary one. A service pointed at
    /// a hostname of its own has nothing to do with these domains, and a
    /// mirror here would put a name nobody owns into the Caddy site — one
    /// certificate request that fails forever and burns the deployment's
    /// Let's Encrypt failure quota (see ARCHITECTURE.md on why site names are
    /// a contract with four parties). Every other scenario passes with the
    /// guard removed; this one does not.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.adguard_hostname = "dns.other-company.net".to_string();
        assert_parity(&input, "foreignhost-mirrored-public-en");
    }
}
