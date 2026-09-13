//! Nextcloud's declarative install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/NextcloudService.swift`,
//! declarative half only. The imperative half (directory, pull/up, and the
//! `occ` re-application every run needs) lives in `execute.rs`.
//!
//! **Three containers** — app, MariaDB, Redis — and three independent
//! generated secrets, like PhotoPrism.
//!
//! **The trusted-domain list is the Caddy-site contract in another place.**
//! `NEXTCLOUD_TRUSTED_DOMAINS` carries EVERY name the site serves (the
//! hostname plus its mirror on each additional domain), because Caddy holds
//! one certificate covering all of them and Nextcloud answers any name not
//! on this list with "Access through untrusted domain" — see ARCHITECTURE.md
//! on site names being a contract with four parties. `OVERWRITEHOST` and
//! `overwrite.cli.url` stay SINGULAR on purpose: they are what Nextcloud
//! builds absolute links out of, and a list there would be meaningless.

use super::caddy::{self, WebIngress};
use super::context::Input;

/// A floating tag — `:apache` is the LINE, not a version, and it moves under
/// the same string. That is why the update check asks the registry what it
/// resolves to instead of comparing tag text.
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "nextcloud";

pub const IMAGE: &str = "nextcloud:apache";
pub const DATABASE_IMAGE: &str = "mariadb:11";
pub const CACHE_IMAGE: &str = "redis:7-alpine";
pub const COMPOSE_PROJECT: &str = "nextcloud";
/// The compose SERVICE name of the app container — what
/// `docker compose ps -q app` resolves, and what the `occ` step needs to
/// find the container to exec into. Not a container_name: this stack does
/// not pin one.
pub const APP_SERVICE: &str = "app";
pub const WEB_UI_PORT: u16 = 8081;

/// A port of `NextcloudService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.nextcloud_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.nextcloud_hostname.clone()
    }
}

/// Every name this site serves — hostname plus mirrors. Both the compose
/// file (trusted domains) and the `occ` step (one `trusted_domains` slot per
/// name) read THIS function, so the two cannot disagree about the list.
pub fn served_hostnames(input: &Input) -> Vec<String> {
    input.served_hostnames(&hostname(input))
}

/// A port of `NextcloudService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.nextcloud_path;
    let admin = &input.admin_username;
    let host = hostname(input);
    let trusted = served_hostnames(input).join(" ");
    format!(
        "services:\n  db:\n    image: {DATABASE_IMAGE}\n    restart: unless-stopped\n    command: --transaction-isolation=READ-COMMITTED --log-bin=binlog --binlog-format=ROW\n    environment:\n      MYSQL_ROOT_PASSWORD: ${{MYSQL_ROOT_PASSWORD}}\n      MYSQL_PASSWORD: ${{MYSQL_PASSWORD}}\n      MYSQL_DATABASE: nextcloud\n      MYSQL_USER: nextcloud\n    volumes:\n      - {path}/db:/var/lib/mysql\n  redis:\n    image: {CACHE_IMAGE}\n    restart: unless-stopped\n  app:\n    image: {IMAGE}\n    restart: unless-stopped\n    depends_on:\n      - db\n      - redis\n    environment:\n      MYSQL_HOST: db\n      MYSQL_PASSWORD: ${{MYSQL_PASSWORD}}\n      MYSQL_DATABASE: nextcloud\n      MYSQL_USER: nextcloud\n      REDIS_HOST: redis\n      NEXTCLOUD_ADMIN_USER: {admin}\n      NEXTCLOUD_ADMIN_PASSWORD: ${{NEXTCLOUD_ADMIN_PASSWORD}}\n      NEXTCLOUD_TRUSTED_DOMAINS: {trusted}\n      OVERWRITEHOST: {host}\n      OVERWRITEPROTOCOL: https\n    volumes:\n      - {path}/data:/var/www/html\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:80\""
    )
}

/// A port of `NextcloudService.composeFile(_:).envTemplate`: both database
/// secrets and the administrator password, all generated on the server.
pub fn env_template() -> String {
    "MYSQL_ROOT_PASSWORD=__RANDOM__\nMYSQL_PASSWORD=__RANDOM__\nNEXTCLOUD_ADMIN_PASSWORD=__RANDOM__".to_string()
}

/// A port of `NextcloudService.dnsHostnames(_:)`. Unreached in the binary for
/// the same reason AdGuard's is.
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `NextcloudService.webIngress(_:)`.
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

/// A port of the Nextcloud slice of `ServiceInfraSections.writeCaddyfile`.
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
    fn hostname_defaults_to_the_plain_files_name_when_it_is_alone() {
        assert_eq!(hostname(&base("example.com")), "files.example.com");
        let mut both = base("example.com");
        both.installed_services = vec![SERVICE_ID.to_string(), "seafile".to_string()];
        assert_eq!(hostname(&both), "nextcloud.example.com");
    }

    /// The trusted list must carry the aliases; the overwrite values must
    /// not. A mirrored name missing from the list is a site Caddy serves and
    /// Nextcloud rejects — and a list in OVERWRITEHOST is a link nobody can
    /// follow.
    #[test]
    fn trusted_domains_carry_the_mirrors_but_overwritehost_stays_singular() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        let compose = compose_contents(&input);
        assert!(compose.contains("NEXTCLOUD_TRUSTED_DOMAINS: files.example.com files.example.org"));
        assert!(compose.contains("OVERWRITEHOST: files.example.com\n"));
    }

    #[test]
    fn the_shared_admin_username_reaches_the_environment() {
        let mut input = base("example.com");
        input.admin_username = "operator".to_string();
        assert!(compose_contents(&input).contains("NEXTCLOUD_ADMIN_USER: operator"));
    }

    #[test]
    fn the_env_template_asks_for_three_separate_secrets() {
        assert_eq!(env_template().lines().filter(|l| l.ends_with("=__RANDOM__")).count(), 3);
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
        assert_parity(&base("example.com"), "nc-default-public-en");
    }

    /// The scenario that exercises the trusted-domain list: three names on
    /// one site, and every one of them has to reach the environment.
    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "nc-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "nc-localonly-en");
    }

    /// Custom hostname only — the scenario ALSO set Swift's
    /// `nextcloudAdminUser`, and the fixture proves that field reaches
    /// nothing: the compose file still says `NEXTCLOUD_ADMIN_USER: admin`,
    /// because every service reads the SHARED `adminUsername`. The port
    /// mirrors that (there is no `nextcloud_admin_user` field here) rather
    /// than inventing a knob the product does not honour.
    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.nextcloud_hostname = "files2.example.com".to_string();
        assert_parity(&input, "nc-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.nextcloud_path = "/srv/nextcloud".to_string();
        assert_parity(&input, "nc-custompath-public-en");
    }

    /// The mirroring GUARD — see `adguard::fixture_parity`.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.nextcloud_hostname = "cloud.other-company.net".to_string();
        assert_parity(&input, "nc-foreignhost-mirrored-public-en");
    }
}
