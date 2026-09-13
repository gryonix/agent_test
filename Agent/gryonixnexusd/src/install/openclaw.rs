//! OpenClaw's declarative install artifacts — a port of
//! `OpenClawService.swift`, declarative half only.
//!
//! **No messenger token is written here, and there is no field for one.** A
//! WhatsApp pairing is a QR code scanned once; Telegram and Discord are bot
//! tokens their owner issues. All three belong to the person, live inside the
//! container's own state, and never travel through an install request. What
//! this module produces is a gateway on a hostname and the token that guards
//! it.
//!
//! **The model provider is deliberately not seeded either.** The engine on
//! this host installs with no models at all and the gateway next door serves
//! whatever keys somebody put in it, so a provider written at install time
//! would name a model that does not exist yet. The report prints the address
//! of whichever backend the host DOES run — see `model_endpoint`.

use super::caddy::{self, WebIngress};
use super::context::Input;
use super::litellm;
use super::ollama;

pub const SERVICE_ID: &str = "openclaw";

/// Pinned release, matching the upstream GitHub release of the same name
/// (checked 2026-09-07). Upstream also publishes `-slim` and `-browser`
/// variants and a moving `main`.
pub const IMAGE: &str = "ghcr.io/openclaw/openclaw:2026.9.2";
pub const COMPOSE_PROJECT: &str = "openclaw";
pub const CONTAINER: &str = "openclaw";
/// Loopback port Caddy proxies to.
pub const WEB_UI_PORT: u16 = 8102;
/// The gateway's own port inside the container — upstream's default, and the
/// value their own compose passes on the command line.
pub const GATEWAY_PORT: u16 = 18789;

/// The whole configuration this product writes: the two keys the gateway
/// refuses to work without.
///
/// **Unconfigured, the gateway does not run at all** — it exits with "Missing
/// config. Run `openclaw setup` or set gateway.mode=local" and the container
/// restarts forever (seen on a live host, 2026-09-08). Its own
/// `--allow-unconfigured` flag says in its help that it "does not repair
/// config", so the file is what fixes this and the flag is not. Written
/// rather than copied, for the reason SearXNG's settings are: a file this
/// product ships has to be a file this product wrote.
///
/// **`trustedProxies` is the second key, and without it the site serves
/// nothing.** The gateway answers 403 `proxy_attribution` to every request it
/// cannot attribute to a client — behind Caddy that is all of them. What it
/// sees is the gateway address of the compose project's own docker bridge
/// (`172.24.0.1` on the host this was found on, and a different one on the
/// next, because docker allocates those subnets as it goes), so the value is
/// the range rather than the address: `172.16.0.0/12` is docker's own default
/// pool, and the only traffic that can reach this container comes through that
/// bridge, since the port is published on the loopback.
pub const SEEDED_CONFIG: &str =
    r#"{"gateway":{"mode":"local","trustedProxies":["127.0.0.1","::1","172.16.0.0/12"]}}"#;

/// A port of `OpenClawService.configPath(_:)`. Inside the state directory,
/// because that is the single mount and the container's
/// `OPENCLAW_CONFIG_PATH` points into it.
pub fn config_path(input: &Input) -> String {
    format!("{}/state/openclaw.json", input.openclaw_path)
}

/// A port of `OpenClawService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.openclaw_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.openclaw_hostname.clone()
    }
}

/// A port of `OpenClawService.modelEndpoint(_:)` — where the model this host
/// runs answers, or `None` when it runs none.
///
/// The gateway wins where both exist, for the reason it exists: it is the one
/// place the keys live.
pub fn model_endpoint(services: &[String]) -> Option<String> {
    if services.iter().any(|id| id == litellm::SERVICE_ID) {
        return Some(format!("http://host.docker.internal:{}/v1", litellm::WEB_UI_PORT));
    }
    if services.iter().any(|id| id == ollama::SERVICE_ID) {
        return Some(format!("http://host.docker.internal:{}", ollama::API_PORT));
    }
    None
}

/// A port of `OpenClawService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.openclaw_path;
    format!("services:\n  openclaw:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    # PID 1 that reaps: this process spawns browsers and helpers,\n    # and upstream's own compose asks for the same.\n    init: true\n    # The engine and the gateway are separate compose projects\n    # reached over the HOST's loopback, so this name has to\n    # resolve; docker does not add it on Linux.\n    extra_hosts:\n      - \"host.docker.internal:host-gateway\"\n    # Upstream's own posture, kept rather than trimmed: a service\n    # that talks to strangers' messengers has no use for raw\n    # sockets or for interface administration inside its namespace.\n    cap_drop:\n      - NET_RAW\n      - NET_ADMIN\n    security_opt:\n      - no-new-privileges:true\n    environment:\n      # Guards the gateway and its web UI. Generated on the server\n      # — see the report for where to read it.\n      OPENCLAW_GATEWAY_TOKEN: ${{OPENCLAW_GATEWAY_TOKEN}}\n      OPENCLAW_GATEWAY_PORT: \"{GATEWAY_PORT}\"\n      OPENCLAW_STATE_DIR: /home/node/.openclaw\n      OPENCLAW_CONFIG_DIR: /home/node/.openclaw\n      OPENCLAW_CONFIG_PATH: /home/node/.openclaw/openclaw.json\n      OPENCLAW_WORKSPACE_DIR: /home/node/.openclaw/workspace\n    volumes:\n      # One mount, because the workspace above lives inside the\n      # state directory: two mounts of nested paths would be two\n      # things to keep in step for no second lifetime.\n      - {path}/state:/home/node/.openclaw\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{GATEWAY_PORT}\"\n    command:\n      - node\n      - dist/index.js\n      - gateway\n      - --bind\n      - lan\n      - --port\n      - \"{GATEWAY_PORT}\"")
}

/// A port of `OpenClawService.composeFile(_:).envTemplate`.
pub fn env_template() -> String {
    // No trailing newline: the Swift multiline literal it is a port of ends
    // without one, and the fixtures are compared byte for byte.
    "OPENCLAW_GATEWAY_TOKEN=__RANDOM__".to_string()
}

pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress {
        hostname: hostname(input),
        upstream_port: WEB_UI_PORT,
        admin_guard: true,
        upstream_https: false,
        public_paths: Vec::new(),
    }
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// **Not `caddy::site`, and the difference is the whole service.** The gateway
/// attributes every request to a client and refuses the ones it cannot
/// attribute; behind a proxy whose address it does not trust, that refusal is
/// the entire site (403 `proxy_attribution`, measured live 2026-09-08). The
/// trust is the service's half, in `SEEDED_CONFIG`; overwriting the forwarded
/// header rather than appending to it is the proxy's half, and its own
/// documentation asks for exactly that — an appending proxy lets a client put
/// a forged address in front of the real one.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site_overwriting_forwarded_for(
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
    fn hostname_defaults_to_the_plain_ai_name_and_never_to_agent() {
        // `agent.<domain>` belongs to nobody (owner, 2026-09-12).
        assert_eq!(hostname(&base()), "ai.example.com");
        let mut crowded = base();
        crowded.installed_services = vec![SERVICE_ID.to_string(), "open-webui".to_string()];
        assert_eq!(hostname(&crowded), "openclaw.example.com");
    }

    /// The gateway wins over the engine, and neither is invented.
    #[test]
    fn the_model_endpoint_is_derived_and_the_gateway_leads() {
        let engine = vec!["openclaw".to_string(), "ollama".to_string()];
        assert!(model_endpoint(&engine).unwrap().ends_with(&ollama::API_PORT.to_string()));

        let both = vec!["openclaw".to_string(), "ollama".to_string(), "litellm".to_string()];
        assert!(model_endpoint(&both).unwrap().ends_with("/v1"));

        assert_eq!(model_endpoint(&["openclaw".to_string()]), None);
    }

    /// The page pairs messengers and holds their sessions, so it is never
    /// published outside the admin guard.
    #[test]
    fn the_gateway_stays_behind_the_admin_guard() {
        assert!(web_ingress(&base()).admin_guard);
    }

    /// Nothing in the compose file names a messenger: those secrets are made
    /// in the service's own UI and stay in its own state directory.
    #[test]
    fn no_messenger_token_is_written_here() {
        let text = compose_contents(&base());
        for token in ["TELEGRAM", "DISCORD", "WHATSAPP", "BOT_TOKEN"] {
            assert!(!text.contains(token), "{token} belongs to the person, in their own UI");
        }
        assert!(text.contains("OPENCLAW_GATEWAY_TOKEN"));
    }

    /// `--bind lan` is upstream's name for "listen on the container's
    /// interfaces". Their `loopback` means the container's own namespace and
    /// nothing else, which would publish a port that answers nobody.
    #[test]
    fn the_gateway_binds_where_the_published_port_can_reach_it() {
        let text = compose_contents(&base());
        assert!(text.contains("--bind\n      - lan"));
        assert!(text.contains(&format!("\"127.0.0.1:{WEB_UI_PORT}:{GATEWAY_PORT}\"")));
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

    fn check(name: &str, input: &Input) {
        assert_eq!(compose_contents(input), fixture(&format!("{name}__docker-compose.yml")));
        assert_eq!(hostname(input), fixture(&format!("{name}__hostname.txt")));
        assert_eq!(dns_hostnames(input).join("\n"), fixture(&format!("{name}__dns-hostnames.txt")));
        assert_eq!(caddy_site(input), fixture(&format!("{name}__caddy-site.txt")));
        let ingress = web_ingress(input);
        let rendered = format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}\npublicPaths={}",
            ingress.hostname,
            ingress.upstream_port,
            ingress.admin_guard,
            ingress.upstream_https,
            ingress.public_paths.join(" ")
        );
        assert_eq!(rendered, fixture(&format!("{name}__ingress.txt")));
        assert_eq!(env_template(), fixture(&format!("{name}__env.template")));
    }

    #[test]
    fn default_public_en() {
        check("openclaw-default-public-en", &Input { domain: "example.com".to_string(), ..Input::default() });
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        check("openclaw-mirrored-public-en", &input);
    }

    #[test]
    fn localonly_en() {
        let mut input = Input { domain: "home.local".to_string(), ..Input::default() };
        input.local_only = true;
        check("openclaw-localonly-en", &input);
    }

    #[test]
    fn customhost_public_en() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.openclaw_path = "/srv/openclaw".to_string();
        input.openclaw_hostname = "claw.example.com".to_string();
        check("openclaw-customhost-public-en", &input);
    }
}
