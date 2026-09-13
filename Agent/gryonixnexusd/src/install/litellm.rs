//! LiteLLM's declarative install artifacts — a port of `LiteLLMService.swift`,
//! declarative half only.
//!
//! The routing table is a function of the neighbours the way the chat's
//! compose file is: the local engine gets a route when it is installed, so one
//! address answers for the model on this disk and the model somebody else runs.
//!
//! **What it is FOR is the keys**, and those are not in this module: they live
//! in the agent's own encrypted store and are rendered by `llm_keys` into a
//! fixed root-only file this compose file names.

use super::caddy::{self, WebIngress};
use super::context::Input;
use super::llm_keys;
use super::ollama;

pub const SERVICE_ID: &str = "litellm";

/// Exact pinned tag; the index carries linux/amd64 and linux/arm64.
pub const IMAGE: &str = "ghcr.io/berriai/litellm:v1.100.0";
pub const COMPOSE_PROJECT: &str = "litellm";
pub const CONTAINER: &str = "litellm";
/// Loopback port Caddy proxies to.
pub const WEB_UI_PORT: u16 = 8098;
/// The port inside the container.
pub const CONTAINER_PORT: u16 = 4000;

/// The shared secret the gateway checks and the chat presents. One file
/// because the two ends have to agree and neither is reliably installed
/// first — see the Swift type's own comment.
pub const GATEWAY_KEY_PATH: &str = "/etc/gryonixnexus/llm-gateway.key";

/// A port of `LiteLLMService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.litellm_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.litellm_hostname.clone()
    }
}

/// A port of `LiteLLMService.configYAML(_:)`.
///
/// Wildcards rather than a list of model names: a list would be wrong the week
/// after it was written, and `openai/*` routes anything under that prefix with
/// that provider's key — which is what somebody typing a model name actually
/// wants.
pub fn config_yaml(services: &[String]) -> String {
    let mut lines = vec!["model_list:".to_string()];
    for provider in llm_keys::PROVIDERS {
        lines.push(format!(
            "  - model_name: \"{id}/*\"\n    litellm_params:\n      model: \"{id}/*\"\n      api_key: os.environ/{env}",
            id = provider.id,
            env = provider.environment_key
        ));
    }
    if services.iter().any(|id| id == ollama::SERVICE_ID) {
        lines.push(format!(
            "  - model_name: \"ollama/*\"\n    litellm_params:\n      model: \"ollama/*\"\n      api_base: http://host.docker.internal:{}",
            ollama::API_PORT
        ));
    }
    lines.push("general_settings:\n  master_key: os.environ/LITELLM_MASTER_KEY".to_string());
    lines.join("\n")
}

/// A port of `LiteLLMService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.litellm_path;
    let keys = llm_keys::KEYS_ENV_PATH;
    format!(
        "services:\n  litellm:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    # The local engine answers on the host's own loopback, and the\n    # gateway is a separate compose project — see the chat's own\n    # note for why this is not a shared docker network.\n    extra_hosts:\n      - \"host.docker.internal:host-gateway\"\n    command: [\"--config\", \"/app/config.yaml\", \"--port\", \"{CONTAINER_PORT}\"]\n    environment:\n      LITELLM_MASTER_KEY: ${{LITELLM_MASTER_KEY}}\n    # The provider keys, rendered by the agent from its own store.\n    # A separate file from .env because nothing on the device ever\n    # writes it and nothing here ever reads it back.\n    env_file:\n      - {keys}\n    volumes:\n      - {path}/config.yaml:/app/config.yaml:ro\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_PORT}\""
    )
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `LiteLLMService.webIngress(_:)`. Published, unlike the engine
/// beside it, and the difference is authentication rather than taste: this one
/// checks a master key on every request.
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
        assert_eq!(hostname(&base()), "ai.example.com");
        let mut crowded = base();
        crowded.installed_services = vec![SERVICE_ID.to_string(), "open-webui".to_string()];
        assert_eq!(hostname(&crowded), "litellm.example.com");
    }

    /// Every provider the agent will accept a key for has a route, or the key
    /// would be written into a file nothing reads.
    #[test]
    fn every_provider_the_keys_file_can_carry_has_a_route() {
        let yaml = config_yaml(&[]);
        for provider in llm_keys::PROVIDERS {
            assert!(yaml.contains(&format!("model_name: \"{}/*\"", provider.id)), "{}", provider.id);
            assert!(yaml.contains(&format!("os.environ/{}", provider.environment_key)));
        }
    }

    /// The local engine is a route only when it is there — the same neighbour
    /// rule the chat follows, and for the same reason.
    #[test]
    fn the_local_engine_is_routed_only_when_it_is_installed() {
        assert!(!config_yaml(&[]).contains("ollama/*"));
        assert!(config_yaml(&["ollama".to_string()]).contains("ollama/*"));
    }

    /// The keys file is named at a FIXED path, never one derived from a
    /// setting: the agent writes it as root from values a client sent.
    #[test]
    fn the_keys_file_is_the_fixed_path_and_not_under_the_service_directory() {
        let mut input = base();
        input.litellm_path = "/srv/litellm".to_string();
        let text = compose_contents(&input);
        assert!(text.contains(llm_keys::KEYS_ENV_PATH));
        assert!(!text.contains("/srv/litellm/keys"));
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

    fn assert_parity(input: &Input, services: &[String], scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            config_yaml(services),
            fixture(&format!("{scenario}__config.yaml")),
            "{scenario}: config.yaml"
        );
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
        vec!["open-webui".to_string(), "ollama".to_string(), "litellm".to_string()]
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base(), &with_engine(), "litellm-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base();
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, &with_engine(), "litellm-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base();
        input.domain = "home.local".to_string();
        input.local_only = true;
        assert_parity(&input, &with_engine(), "litellm-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base();
        input.litellm_hostname = "gateway.example.com".to_string();
        input.litellm_path = "/srv/litellm".to_string();
        assert_parity(&input, &with_engine(), "litellm-customhost-public-en");
    }

    /// No local engine: the routing table comes out one entry shorter.
    #[test]
    fn no_engine_public_en() {
        assert_parity(&base(), &["litellm".to_string()], "litellm-noengine-public-en");
    }
}
