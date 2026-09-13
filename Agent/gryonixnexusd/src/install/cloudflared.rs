//! Cloudflare Tunnel's declarative install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/CloudflaredService.swift`.
//!
//! **The whole service is a connector and a token.** It publishes nothing, opens
//! nothing and terminates nothing: `cloudflared` holds an OUTBOUND connection
//! to Cloudflare, which then delivers requests to the Caddy this deployment
//! already runs. Measured 2026-08-14 on a host with no inbound port open at
//! all — a service on loopback answered HTTP 200 from a foreign network.
//!
//! **The token cannot be generated here.** It is issued by Cloudflare when the
//! owner creates the tunnel, and the routes are set in that same dashboard, so
//! this file writes an EMPTY `.env` and the install refuses to start a
//! connector that would only retry for ever.

use super::context::Input;

/// Exact pinned tag, the build verified on the lab.
pub const IMAGE: &str = "cloudflare/cloudflared:2026.8.2";
pub const COMPOSE_PROJECT: &str = "cloudflared";
pub const CONTAINER: &str = "cloudflared";

/// A port of `CloudflaredService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    format!(
        "services:\n  cloudflared:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    \
         restart: unless-stopped\n    \
         # The host's own network, so the tunnel can reach Caddy on\n    \
         # 127.0.0.1 exactly as the dashboard's routes name it. A\n    \
         # bridge would put the connector on a different loopback and\n    \
         # every route would have to name a container address instead.\n    \
         network_mode: host\n    command: tunnel --no-autoupdate run\n    environment:\n      \
         # Read from .env, which is 0600 and generated once. The token\n      \
         # IS the credential for the whole tunnel.\n      \
         TUNNEL_TOKEN: ${{TUNNEL_TOKEN}}",
    )
    .replace("PLACEHOLDER_PATH", &input.cloudflared_path)
}

/// A port of the Swift `envTemplate`. Deliberately NOT `__RANDOM__`: this one
/// cannot be generated, only pasted.
pub fn env_template() -> String {
    "TUNNEL_TOKEN=\n".to_string()
}

/// Whether the `.env` on disk carries a token worth starting for.
///
/// A connector without one does not fail — it retries, for ever, saying the
/// same thing each time. Naming that state once at install is the difference
/// between a service the owner knows is waiting for them and a container they
/// find in a loop days later.
pub fn has_token(env_contents: &str) -> bool {
    env_contents
        .lines()
        .filter_map(|line| line.strip_prefix("TUNNEL_TOKEN="))
        .any(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_connector_runs_on_the_hosts_own_network() {
        let compose = compose_contents(&Input::default());
        // Without this the routes in Cloudflare's dashboard would have to name
        // a container address instead of 127.0.0.1.
        assert!(compose.contains("network_mode: host"));
        assert!(compose.contains("TUNNEL_TOKEN: ${TUNNEL_TOKEN}"));
        assert!(compose.contains(IMAGE));
    }

    /// It opens nothing and publishes nothing — the property the whole service
    /// exists for, asserted rather than assumed.
    #[test]
    fn nothing_is_published() {
        let compose = compose_contents(&Input::default());
        assert!(!compose.contains("ports:"), "a tunnel that publishes a port is not a tunnel");
    }

    #[test]
    fn an_empty_token_is_not_a_token() {
        assert!(!has_token(&env_template()));
        assert!(!has_token("TUNNEL_TOKEN=   \n"));
        assert!(!has_token("OTHER=x\n"));
        assert!(has_token("TUNNEL_TOKEN=eyJhIjoi\n"));
    }
}
