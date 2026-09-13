//! Crafty Controller's declarative install artifacts — a port of
//! `CraftyControllerService.swift`, declarative half only.
//!
//! The one piece of the games shelf that DOES have a web face, which is the
//! whole reason it exists: the servers themselves speak the game protocol and
//! nothing else, so without this there would be nothing to open.

use super::caddy::{self, WebIngress};
use super::context::Input;

/// Pinned release. Multi-arch verified against the GitLab registry's own
/// index: linux/arm64 and linux/amd64 are both present.
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "crafty-controller";

pub const IMAGE: &str = "registry.gitlab.com/crafty-controller/crafty-4:4.9.0";
pub const COMPOSE_PROJECT: &str = "crafty";
pub const CONTAINER: &str = "crafty";
/// Loopback port Caddy proxies to.
pub const WEB_UI_PORT: u16 = 8095;

/// A port of `CraftyControllerService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.crafty_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.crafty_hostname.clone()
    }
}

/// A port of `CraftyControllerService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.crafty_path;
    format!(
        "services:\n  crafty:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      TZ: \"Etc/UTC\"\n    volumes:\n      - {path}/backups:/crafty/backups\n      - {path}/logs:/crafty/logs\n      - {path}/servers:/crafty/servers\n      - {path}/config:/crafty/app/config\n      - {path}/import:/crafty/import\n    ports:\n      # Loopback only — Caddy publishes the name, and the panel is\n      # an admin surface like every other one in this catalog.\n      - \"127.0.0.1:{WEB_UI_PORT}:8443\""
    )
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `CraftyControllerService.webIngress(_:)`.
///
/// `upstream_https` is TRUE and it is load-bearing: Crafty serves HTTPS with
/// its own self-signed certificate and redirects plain HTTP to it, so proxying
/// over HTTP would be the infinite redirect loop mailcow's nginx already taught
/// this catalog about.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: true, public_paths: Vec::new() }
}

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

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_defaults_to_the_mc_subdomain() {
        assert_eq!(hostname(&base()), "mc.example.com");
    }

    /// The upstream is HTTPS, and getting this wrong is a redirect loop rather
    /// than a visible error.
    #[test]
    fn the_upstream_is_spoken_to_over_https() {
        assert!(web_ingress(&base()).upstream_https);
    }
}

/// Byte-for-byte parity against REAL Swift-generated output.
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

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
        assert_eq!(hostname(input), fixture(&format!("{scenario}__hostname.txt")), "{scenario}: hostname");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames"
        );
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("{scenario}__ingress.txt")),
            "{scenario}: ingress"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base(), "crafty-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base();
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "crafty-mirrored-public-en");
    }

    #[test]
    fn custom_public_en() {
        let mut input = base();
        input.crafty_hostname = "games.example.com".to_string();
        input.crafty_path = "/srv/crafty".to_string();
        assert_parity(&input, "crafty-custom-public-en");
    }
}
