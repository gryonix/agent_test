//! Immich's declarative install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/ImmichService.swift`,
//! declarative half only. The imperative half (directory, pull/up) lives in
//! `execute.rs` next to the other services'.
//!
//! **Four containers**: server, machine learning, valkey cache and postgres.
//! The widest stack in this port so far, and still nothing new for the
//! executor — the compose file declares it, `up -d` brings it up. One
//! generated secret, shared BY DESIGN between the server's `DB_PASSWORD` and
//! postgres's `POSTGRES_PASSWORD`: they are two ends of the same credential,
//! unlike PhotoPrism's three independent ones.
//!
//! **Immich cannot create an administrator from the environment** — the
//! first person to log in registers as one. That is a takeover window on a
//! public hostname, which is why the report says so in the loudest terms it
//! has; there is nothing this module can do about it, and inventing an API
//! call the product does not have would be worse than saying it plainly.

use super::caddy::{self, WebIngress};
use super::context::Input;

/// Immich rides `:release`, a floating tag: it moves under the same string,
/// which is why the update check asks the registry for a DIGEST instead of
/// comparing tags.
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "immich";

pub const IMAGE: &str = "ghcr.io/immich-app/immich-server:release";
/// Face and object recognition — version-locked to the server upstream.
pub const MACHINE_LEARNING_IMAGE: &str = "ghcr.io/immich-app/immich-machine-learning:release";
pub const CACHE_IMAGE: &str = "docker.io/valkey/valkey:8-bookworm";
/// NOT stock postgres: Immich needs the vector extension this image bundles,
/// so the tag cannot be swapped for `postgres:16`.
pub const DATABASE_IMAGE: &str = "ghcr.io/immich-app/postgres:16-vectorchord0.4.3";
pub const COMPOSE_PROJECT: &str = "immich";
pub const WEB_UI_PORT: u16 = 2283;

/// A port of `ImmichService.hostname(_:)`. Immich owns `photos.<domain>` on
/// the `photos` shelf; PhotoPrism deliberately defaults elsewhere.
pub fn hostname(input: &Input) -> String {
    if input.immich_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.immich_hostname.clone()
    }
}

/// A port of `ImmichService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.immich_path;
    let host = hostname(input);
    format!(
        "services:\n  immich-server:\n    image: {IMAGE}\n    restart: unless-stopped\n    depends_on:\n      - redis\n      - database\n    environment:\n      DB_HOSTNAME: database\n      DB_USERNAME: postgres\n      DB_PASSWORD: ${{DB_PASSWORD}}\n      DB_DATABASE_NAME: immich\n      REDIS_HOSTNAME: redis\n      IMMICH_SERVER_URL: https://{host}\n    volumes:\n      - {path}/library:/usr/src/app/upload\n      - /etc/localtime:/etc/localtime:ro\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:2283\"\n  immich-machine-learning:\n    image: {MACHINE_LEARNING_IMAGE}\n    restart: unless-stopped\n    volumes:\n      - {path}/ml-cache:/cache\n  redis:\n    image: {CACHE_IMAGE}\n    restart: unless-stopped\n  database:\n    image: {DATABASE_IMAGE}\n    restart: unless-stopped\n    environment:\n      POSTGRES_PASSWORD: ${{DB_PASSWORD}}\n      POSTGRES_USER: postgres\n      POSTGRES_DB: immich\n    volumes:\n      - {path}/postgres:/var/lib/postgresql/data"
    )
}

/// A port of `ImmichService.composeFile(_:).envTemplate`: ONE secret, read
/// by both the server and postgres — see the module doc.
pub fn env_template() -> String {
    "DB_PASSWORD=__RANDOM__".to_string()
}

/// A port of `ImmichService.dnsHostnames(_:)`. Unreached in the binary for
/// the same reason AdGuard's is.
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `ImmichService.webIngress(_:)`.
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

/// A port of the Immich slice of `ServiceInfraSections.writeCaddyfile`.
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
    fn hostname_defaults_to_the_photos_subdomain_immich_owns() {
        assert_eq!(hostname(&base("example.com")), "photos.example.com");
    }

    /// One credential with two ends: if these ever stopped being the same
    /// placeholder, the server would authenticate against a postgres that
    /// was initialised with a different password — and only on a FRESH
    /// database, which is the worst time to find out.
    #[test]
    fn the_server_and_postgres_read_the_same_generated_secret() {
        let compose = compose_contents(&base("example.com"));
        assert!(compose.contains("DB_PASSWORD: ${DB_PASSWORD}"));
        assert!(compose.contains("POSTGRES_PASSWORD: ${DB_PASSWORD}"));
        assert_eq!(env_template().lines().count(), 1);
    }

    /// The postgres image is not interchangeable with stock postgres — it
    /// carries the vector extension Immich requires.
    #[test]
    fn the_database_image_is_immichs_own_vector_build() {
        assert!(compose_contents(&base("example.com")).contains(DATABASE_IMAGE));
        assert!(DATABASE_IMAGE.contains("vectorchord"));
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
        assert_parity(&base("example.com"), "im-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "im-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "im-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.immich_hostname = "gallery.example.com".to_string();
        assert_parity(&input, "im-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.immich_path = "/srv/immich".to_string();
        assert_parity(&input, "im-custompath-public-en");
    }

    /// The mirroring GUARD — see `adguard::fixture_parity`.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.immich_hostname = "photos.other-company.net".to_string();
        assert_parity(&input, "im-foreignhost-mirrored-public-en");
    }
}
