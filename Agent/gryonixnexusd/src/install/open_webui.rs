//! Open WebUI's declarative install artifacts — a port of
//! `OpenWebUIService.swift`, declarative half only.
//!
//! **Its compose file is a function of the NEIGHBOURS as well as the input**,
//! which in this crate only Homepage was before it, and for the same reason:
//! which model backend the chat talks to is derived from what else the host
//! runs rather than typed by somebody. So `compose_contents` takes the service
//! list the same way `homepage::services_yaml` does — on the Swift side that
//! list is `ServiceContext.installedServices`, here it is `host_service_ids`
//! (discovery plus what is being installed), and nothing but the rendered file
//! is compared.

use super::caddy::{self, WebIngress};
use super::context::Input;
use super::litellm;
use super::ollama;
use super::searxng;

pub const SERVICE_ID: &str = "open-webui";

/// Pinned release. Upstream also publishes `:main`, `:cuda` and `:ollama` —
/// the last bundles an engine INSIDE this container, which would make "the
/// models run on another machine" impossible to offer.
pub const IMAGE: &str = "ghcr.io/open-webui/open-webui:v0.11.3";
pub const COMPOSE_PROJECT: &str = "open-webui";
pub const CONTAINER: &str = "open-webui";
/// Loopback port Caddy proxies to.
pub const WEB_UI_PORT: u16 = 8097;
/// The port inside the container. Not the same number as the published one,
/// so the two are not interchangeable in the mapping.
pub const CONTAINER_WEB_PORT: u16 = 8080;

/// A port of `OpenWebUIService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.open_webui_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.open_webui_hostname.clone()
    }
}

/// A port of `OpenWebUIService.engineURL(_:)` — the engine this chat is
/// configured with, or `None` when the host runs none.
///
/// The URL crosses the HOST's loopback rather than a shared docker network:
/// the two are separate compose projects with separate lifetimes, and a
/// network that only exists while both are installed would make removing one
/// break the other.
pub fn engine_url(services: &[String]) -> Option<String> {
    services
        .iter()
        .any(|id| id == ollama::SERVICE_ID)
        .then(|| format!("http://host.docker.internal:{}", ollama::API_PORT))
}

/// A port of `OpenWebUIService.gatewayURL(_:)` — the gateway this chat is also
/// configured with, when the host runs one.
///
/// **This branch was missing until phase 5, and its absence was silent.** The
/// agent already minted the shared key and wrote it into this service's own
/// `.env` (see `install_open_webui_steps`), but the compose file it generated
/// never read that key — so a host installed through the agent got a chat that
/// could see the local models and not one of the paid ones, while the same
/// deployment installed over SSH got both. No fixture covered a host with the
/// gateway on it, which is how the two halves stayed apart.
pub fn gateway_url(services: &[String]) -> Option<String> {
    services
        .iter()
        .any(|id| id == litellm::SERVICE_ID)
        .then(|| format!("http://host.docker.internal:{}/v1", litellm::WEB_UI_PORT))
}

/// A port of `OpenWebUIService.searchURL(_:)` — the search engine's query URL,
/// when this deployment installs one. `<query>` is Open WebUI's own
/// placeholder, so the string travels whole.
pub fn search_url(services: &[String]) -> Option<String> {
    services
        .iter()
        .any(|id| id == searxng::SERVICE_ID)
        .then(searxng::query_url)
}

/// A port of `OpenWebUIService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input, services: &[String]) -> String {
    let path = &input.open_webui_path;
    let host = hostname(input);
    let signups = if input.open_webui_allow_signups { "true" } else { "false" };
    let engine = engine_url(services)
        .map(|url| format!("\n      OLLAMA_BASE_URL: \"{url}\""))
        .unwrap_or_default();
    // LiteLLM speaks the OpenAI API, so the gateway arrives as an OpenAI
    // endpoint rather than as a provider of its own. The key is the shared
    // gateway secret, read out of this service's `.env`.
    let gateway = gateway_url(services)
        .map(|url| format!("\n      OPENAI_API_BASE_URL: \"{url}\"\n      OPENAI_API_KEY: ${{LLM_GATEWAY_KEY}}"))
        .unwrap_or_default();
    let search = search_url(services)
        .map(|url| format!("\n      ENABLE_WEB_SEARCH: \"true\"\n      WEB_SEARCH_ENGINE: \"searxng\"\n      SEARXNG_QUERY_URL: \"{url}\""))
        .unwrap_or_default();
    format!(
        "services:\n  open-webui:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    # Reaching the engine on the host's own loopback needs this\n    # name resolved; docker does not add it on Linux by itself.\n    extra_hosts:\n      - \"host.docker.internal:host-gateway\"\n    environment:\n      WEBUI_URL: \"https://{host}\"\n      # Session signing key. Generated on the server — regenerating\n      # it on every start would sign every existing session out.\n      WEBUI_SECRET_KEY: ${{WEBUI_SECRET_KEY}}\n      ENABLE_SIGNUP: \"{signups}\"{engine}{gateway}{search}\n    volumes:\n      - {path}/data:/app/backend/data\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_WEB_PORT}\""
    )
}

/// A port of `OpenWebUIService.composeFile(_:).envTemplate`.
pub fn env_template() -> String {
    // No trailing newline: the Swift multiline literal it is a port of ends
    // without one, and the fixtures are compared byte for byte.
    "WEBUI_SECRET_KEY=__RANDOM__".to_string()
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `OpenWebUIService.webIngress(_:)`. Guarded, and not by default in
/// the weak sense: this page holds every conversation and every uploaded
/// document on the host.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress {
        hostname: hostname(input),
        upstream_port: WEB_UI_PORT,
        admin_guard: true,
        upstream_https: false,
        public_paths: Vec::new(),
    }
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
    caddy::site(
        SERVICE_ID,
        &joined,
        ingress.upstream_port,
        ingress.admin_guard,
        ingress.upstream_https,
        input.local_only,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_defaults_to_the_plain_ai_name_when_it_is_alone() {
        // The engine, the store and the search engine are published under no
        // name at all, so a chat standing beside them is still alone here.
        let mut quiet = base();
        quiet.installed_services =
            vec![SERVICE_ID.to_string(), "ollama".to_string(), "qdrant".to_string()];
        assert_eq!(hostname(&quiet), "ai.example.com");
        let mut crowded = base();
        crowded.installed_services = vec![SERVICE_ID.to_string(), "openclaw".to_string()];
        assert_eq!(hostname(&crowded), "openwebui.example.com");
    }

    /// Derived from the neighbours, never typed. A URL pointing at a container
    /// that is not there is worse than no URL: the chat then fails on every
    /// request instead of asking for a provider.
    #[test]
    fn the_engine_is_configured_only_when_it_is_installed() {
        let input = base();
        let wired = compose_contents(&input, &["open-webui".to_string(), "ollama".to_string()]);
        assert!(wired.contains("OLLAMA_BASE_URL"));
        assert!(wired.contains(&ollama::API_PORT.to_string()));

        let alone = compose_contents(&input, &["open-webui".to_string()]);
        assert!(!alone.contains("OLLAMA_BASE_URL"));
    }

    /// The first account created becomes the administrator, so a compose file
    /// that closed registration would install a service nobody can enter.
    #[test]
    fn registration_is_open_by_default_and_closable() {
        let mut input = base();
        assert!(compose_contents(&input, &[]).contains("ENABLE_SIGNUP: \"true\""));
        input.open_webui_allow_signups = false;
        assert!(compose_contents(&input, &[]).contains("ENABLE_SIGNUP: \"false\""));
    }

    /// The session key signs every login: invented on each start, it would
    /// sign everybody out on each start.
    #[test]
    fn the_session_key_is_server_generated() {
        assert_eq!(env_template().trim(), "WEBUI_SECRET_KEY=__RANDOM__");
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

    fn assert_parity(input: &Input, services: &[String], scenario: &str) {
        assert_eq!(
            compose_contents(input, services),
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
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("{scenario}__ingress.txt")),
            "{scenario}: ingress"
        );
    }

    fn with_engine() -> Vec<String> {
        vec!["open-webui".to_string(), "ollama".to_string()]
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base(), &with_engine(), "owui-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base();
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, &with_engine(), "owui-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base();
        input.domain = "home.local".to_string();
        input.local_only = true;
        assert_parity(&input, &with_engine(), "owui-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base();
        input.open_webui_hostname = "ai.example.com".to_string();
        input.open_webui_path = "/srv/open-webui".to_string();
        assert_parity(&input, &with_engine(), "owui-customhost-public-en");
    }

    /// The one scenario the others cannot cover: no engine on the host, so the
    /// compose file has to come out WITHOUT the line the others all carry.
    #[test]
    fn no_engine_public_en() {
        assert_parity(&base(), &["open-webui".to_string()], "owui-noengine-public-en");
    }

    /// **The branch that was silently missing until phase 5.** The agent minted
    /// the gateway key and wrote it into this service's `.env`, and the compose
    /// file it generated never read it — no fixture covered a host with the
    /// gateway on it, which is how the two halves stayed apart for two phases.
    #[test]
    fn gateway_public_en() {
        let services = vec![
            "open-webui".to_string(),
            "ollama".to_string(),
            "litellm".to_string(),
        ];
        assert_parity(&base(), &services, "owui-gateway-public-en");
    }

    /// The search engine beside it, which is a third derived value in the same
    /// block and therefore a third way for the two ports to disagree.
    #[test]
    fn search_public_en() {
        let services = vec![
            "open-webui".to_string(),
            "ollama".to_string(),
            "searxng".to_string(),
        ];
        assert_parity(&base(), &services, "owui-search-public-en");
    }

    /// Registration closed — the branch that decides whether anybody can ever
    /// log in.
    #[test]
    fn signups_closed_public_en() {
        let mut input = base();
        input.open_webui_allow_signups = false;
        assert_parity(&input, &with_engine(), "owui-nosignup-public-en");
    }
}
