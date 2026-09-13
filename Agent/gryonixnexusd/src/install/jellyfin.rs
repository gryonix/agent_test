//! Jellyfin's declarative install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/JellyfinService.swift`,
//! declarative half only. The imperative half (directories, pull/up) lives
//! in `execute.rs` next to the other services'.
//!
//! Jellyfin is the second-simplest thing in the catalog after AdGuard: one
//! container, no database service, no secret to generate — its compose file
//! has NO `.env` at all (`envTemplate` is nil on the Swift side), which is
//! why this module has no `env_template` and the executor skips that step
//! for it entirely.

use super::caddy::{self, WebIngress};
use super::context::Input;

/// Exact patch tag, arm64 verified against the manifest — half the servers
/// this catalog installs on are ARM.
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "jellyfin";

pub const IMAGE: &str = "jellyfin/jellyfin:10.11.11";
pub const COMPOSE_PROJECT: &str = "jellyfin";
pub const CONTAINER: &str = "jellyfin";
/// Loopback port Caddy proxies to. Same number the container listens on
/// inside, unlike AdGuard's — coincidence, not a rule.
pub const WEB_UI_PORT: u16 = 8096;

/// A port of `JellyfinService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.jellyfin_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.jellyfin_hostname.clone()
    }
}

/// A port of `JellyfinService.composeFile(_:).composeContents`, comments
/// included — they are part of the file the Swift generator writes, so a
/// port that dropped them would not be byte-identical to what the SSH path
/// puts on the same host.
///
/// **The library is mounted `:ro` and that is load-bearing**, not a
/// nicety: Jellyfin's web UI can delete files, and the library is the
/// user's own directory that predates the install. The same reasoning keeps
/// it out of backups and out of `--purge-data`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.jellyfin_path;
    let media = &input.jellyfin_media_path;
    let host = hostname(input);
    format!(
        "services:\n  jellyfin:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      # Jellyfin builds absolute URLs for clients from this.\n      JELLYFIN_PublishedServerUrl: \"https://{host}\"\n    volumes:\n      - {path}/config:/config\n      - {path}/cache:/cache\n      # Read-only: a media server has no business writing to the\n      # library, and a mistake in the UI would delete originals.\n      - {media}:/media:ro\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:8096\""
    )
}

/// A port of `JellyfinService.dnsHostnames(_:)`. Unreached in the binary for
/// the same reason AdGuard's is.
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `JellyfinService.webIngress(_:)`.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
}

/// The Caddy site NAMES this ingress publishes — see
/// `adguard::caddy_site_names`.
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// A port of the Jellyfin slice of `ServiceInfraSections.writeCaddyfile`.
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
    fn hostname_defaults_to_media_subdomain() {
        assert_eq!(hostname(&base("example.com")), "media.example.com");
    }

    /// The read-only flag is the one thing in this file that protects data
    /// the product does not own.
    #[test]
    fn the_library_mount_is_read_only() {
        let mut input = base("example.com");
        input.jellyfin_media_path = "/mnt/library".to_string();
        assert!(compose_contents(&input).contains("- /mnt/library:/media:ro"));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — same
/// discipline as `adguard::fixture_parity`.
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

    fn assert_parity(input: &Input, scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
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
        assert_parity(&base("example.com"), "jf-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "jf-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "jf-localonly-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.jellyfin_path = "/srv/jellyfin".to_string();
        input.jellyfin_media_path = "/mnt/library".to_string();
        assert_parity(&input, "jf-custompath-public-en");
    }

    /// The mirroring GUARD — see `adguard::fixture_parity`.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.jellyfin_hostname = "media.other-company.net".to_string();
        assert_parity(&input, "jf-foreignhost-mirrored-public-en");
    }
}
