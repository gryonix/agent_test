//! n8n's declarative install artifacts — a port of `N8NService.swift`,
//! declarative half only.
//!
//! **The one service in the catalog whose site is not one block.** Half of
//! what n8n is for is a URL somebody else's server calls, and the shared
//! "admin panels only over VPN" switch would answer those calls with the same
//! 403 it answers a stranger's browser with — a failure that surfaces on the
//! CALLER's side, as a workflow that silently never fires. So the ingress
//! carries `public_paths` and `caddy::site_with_public_paths` splits the site
//! by path: the editor stays as guarded as every other panel, the webhook
//! prefixes answer the internet. See that function for why the split has to be
//! `handle` blocks.

use super::caddy::{self, WebIngress};
use super::context::Input;

pub const SERVICE_ID: &str = "n8n";

/// Pinned release — the one the `stable`/`latest` channel pointed at when this
/// was written (2026-09-07), rather than the newest tag on the registry.
/// Upstream tags a release the moment it builds and promotes it days later;
/// pinning the newest number would put this on a release the vendor has not
/// finished watching.
pub const IMAGE: &str = "n8nio/n8n:2.37.10";
/// Stock PostgreSQL, the same tag the other services that need one use.
pub const DATABASE_IMAGE: &str = "postgres:16-alpine";
pub const COMPOSE_PROJECT: &str = "n8n";
pub const CONTAINER: &str = "n8n";
/// The database container's compose service name. Named rather than inlined
/// because the backup step addresses it by this name — it is a contract with
/// the dump, not a label.
pub const DATABASE_SERVICE: &str = "database";
/// The database, its user, and what the two containers agree to call it.
pub const DATABASE_NAME: &str = "n8n";
/// Loopback port Caddy proxies to.
pub const WEB_UI_PORT: u16 = 8099;
/// The port inside the container.
pub const CONTAINER_PORT: u16 = 5678;

/// A port of `N8NService.webhookPaths`.
///
/// Both prefixes, not just the first: `/webhook-test/` is the URL the editor
/// shows while a workflow is being BUILT, and it is the one somebody pastes
/// into the other service to check the wiring. Exempting only the production
/// prefix would mean every workflow tests as broken and works after
/// activation, which is the worst order to learn it in.
pub const WEBHOOK_PATHS: [&str; 2] = ["/webhook/*", "/webhook-test/*"];

/// A port of `N8NService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.n8n_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.n8n_hostname.clone()
    }
}

/// A port of `N8NService.baseURL(_:)` — what n8n prints into every webhook URL
/// and every editor link. It has to be told: behind Caddy the only host and
/// scheme it can see are the proxy's own.
pub fn base_url(input: &Input) -> String {
    format!("https://{}/", hostname(input))
}

/// A port of `N8NService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.n8n_path;
    let host = hostname(input);
    let base = base_url(input);
    format!(
        "services:\n  n8n:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    depends_on:\n      - {DATABASE_SERVICE}\n    environment:\n      DB_TYPE: postgresdb\n      DB_POSTGRESDB_HOST: {DATABASE_SERVICE}\n      DB_POSTGRESDB_DATABASE: {DATABASE_NAME}\n      DB_POSTGRESDB_USER: {DATABASE_NAME}\n      DB_POSTGRESDB_PASSWORD: ${{DB_PASSWORD}}\n      # Both halves of \"which address is this?\": the first is what\n      # n8n checks incoming requests against, the second is what it\n      # PRINTS into every webhook URL and every editor link.\n      N8N_HOST: {host}\n      WEBHOOK_URL: \"{base}\"\n      N8N_EDITOR_BASE_URL: \"{base}\"\n      N8N_PROTOCOL: https\n      N8N_PORT: {CONTAINER_PORT}\n      # Caddy is the one hop in front. Without this n8n reads the\n      # proxy's own address as the client's, which turns every\n      # rate limit and every log line into a statement about\n      # 127.0.0.1.\n      N8N_PROXY_HOPS: 1\n      # Workflow code runs in the task runner rather than in the\n      # main process — the supported arrangement from 2.x, and the\n      # one that keeps a runaway Code node from taking the editor\n      # down with it.\n      N8N_RUNNERS_ENABLED: \"true\"\n      # Nothing about this deployment is reported anywhere. The\n      # whole point of the catalog is a server that is the owner's.\n      N8N_DIAGNOSTICS_ENABLED: \"false\"\n      N8N_HIRING_BANNER_ENABLED: \"false\"\n      # Schedule triggers (\"every day at 9\") are read in this zone.\n      # UTC rather than the server's, which on a rented VPS is\n      # whatever the provider set: a fixed, stated zone is one the\n      # owner can convert from, and it is changed in the workflow.\n      GENERIC_TIMEZONE: UTC\n    volumes:\n      - {path}/data:/home/node/.n8n\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_PORT}\"\n  {DATABASE_SERVICE}:\n    image: {DATABASE_IMAGE}\n    restart: unless-stopped\n    environment:\n      POSTGRES_DB: {DATABASE_NAME}\n      POSTGRES_USER: {DATABASE_NAME}\n      POSTGRES_PASSWORD: ${{DB_PASSWORD}}\n    volumes:\n      - {path}/postgres:/var/lib/postgresql/data"
    )
}

/// A port of `N8NService.composeFile(_:).envTemplate`.
///
/// The encryption key is NOT here, and that is a backup decision. n8n encrypts
/// every stored credential with one key; the archive plan takes `<path>/data`
/// and a dump of the database and does NOT take the compose directory, so a
/// key kept beside the compose file would be the one thing missing from every
/// backup. Left to n8n, it is written into `<path>/data/config` — inside what
/// the archive takes.
pub fn env_template() -> String {
    // No trailing newline: the Swift multiline literal it is a port of ends
    // without one, and the fixtures are compared byte for byte.
    "DB_PASSWORD=__RANDOM__".to_string()
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `N8NService.webIngress(_:)`. Guarded like every other panel, and
/// the only ingress in the catalog that carries public paths.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress {
        hostname: hostname(input),
        upstream_port: WEB_UI_PORT,
        admin_guard: true,
        upstream_https: false,
        public_paths: WEBHOOK_PATHS.iter().map(|p| p.to_string()).collect(),
    }
}

pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

pub fn caddy_site(input: &Input) -> String {
    caddy_site_with_sso(input, false)
}

/// The same site with the sign-on check. Its own entry point because n8n is
/// where the two interact: the portal has to land inside the same branch the
/// guard did, or the webhook is asked to log in.
pub fn caddy_site_with_sso(input: &Input, sso: bool) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site_with_public_paths(
        SERVICE_ID,
        &joined,
        ingress.upstream_port,
        ingress.admin_guard,
        ingress.upstream_https,
        input.local_only,
        sso,
        &ingress.public_paths,
            false,
)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_defaults_to_the_flows_subdomain() {
        assert_eq!(hostname(&base()), "flows.example.com");
    }

    /// Behind a proxy n8n cannot work out its own address, and a webhook URL
    /// pointing at `localhost:5678` is one no outside caller can reach — a
    /// service that looks installed and is not usable.
    #[test]
    fn the_public_address_is_told_to_it_three_times() {
        let text = compose_contents(&base());
        assert!(text.contains("N8N_HOST: flows.example.com"));
        assert!(text.contains("WEBHOOK_URL: \"https://flows.example.com/\""));
        assert!(text.contains("N8N_EDITOR_BASE_URL: \"https://flows.example.com/\""));
    }

    /// The key that decrypts every stored credential must travel with the data
    /// it decrypts. `.env` is not in the archive; the data directory is.
    #[test]
    fn the_encryption_key_is_not_in_the_env_file() {
        assert!(!env_template().contains("ENCRYPTION"));
        assert_eq!(env_template().trim(), "DB_PASSWORD=__RANDOM__");
    }

    /// The whole reason this slice touched the ingress model.
    #[test]
    fn the_webhook_prefixes_are_public_and_the_editor_is_not() {
        let site = caddy_site(&base());
        assert!(site.contains("@gryonixnexus_open path /webhook/* /webhook-test/*"));
        // The guard is inside the SECOND handle, never at the top of the site:
        // at the top it sorts ahead of the path matcher and refuses the
        // webhook. `caddy::site_with_public_paths` carries the measurement.
        let guard_at = site.find("import").expect("the editor is guarded");
        let split_at = site.find("handle @gryonixnexus_open").expect("the split exists");
        assert!(split_at < guard_at, "the guard must not precede the public branch");
    }

    /// Nothing about this deployment is reported to anybody.
    #[test]
    fn telemetry_is_off() {
        let text = compose_contents(&base());
        assert!(text.contains("N8N_DIAGNOSTICS_ENABLED: \"false\""));
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
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}\npublicPaths={}",
            ingress.hostname,
            ingress.upstream_port,
            ingress.admin_guard,
            ingress.upstream_https,
            ingress.public_paths.join(" ")
        )
    }

    fn assert_parity(input: &Input, scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(env_template(), fixture(&format!("{scenario}__env.template")), "{scenario}: env");
        assert_eq!(hostname(input), fixture(&format!("{scenario}__hostname.txt")), "{scenario}: hostname");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames"
        );
        assert_eq!(
            caddy_site(input),
            fixture(&format!("{scenario}__caddy-site.txt")),
            "{scenario}: caddy-site"
        );
        // The sign-on shape is its own artifact rather than a reading: n8n is
        // the one service where the portal and the guard share a branch.
        assert_eq!(
            caddy_site_with_sso(input, true),
            fixture(&format!("{scenario}__caddy-site-sso.txt")),
            "{scenario}: caddy-site with sso"
        );
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("{scenario}__ingress.txt")),
            "{scenario}: ingress"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base(), "n8n-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base();
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "n8n-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base();
        input.domain = "home.local".to_string();
        input.local_only = true;
        assert_parity(&input, "n8n-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base();
        input.n8n_hostname = "automation.example.com".to_string();
        input.n8n_path = "/srv/n8n".to_string();
        assert_parity(&input, "n8n-customhost-public-en");
    }
}
