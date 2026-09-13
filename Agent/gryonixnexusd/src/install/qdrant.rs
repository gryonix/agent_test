//! Qdrant's declarative install artifacts — a port of `QdrantService.swift`,
//! declarative half only.
//!
//! **No `web_ingress` function, and that is the whole shape of this module.**
//! The store answers an API on loopback and publishes nothing, so unlike every
//! other service with a compose file here it contributes no Caddy site, no
//! hostname and no DNS record — the same shape `ollama` has, for a sharper
//! reason: what this one holds is the owner's documents as embeddings.

use super::context::Input;

pub const SERVICE_ID: &str = "qdrant";

/// Pinned release — the one `latest` pointed at when this was written
/// (2026-09-07). Upstream also publishes `-gpu-nvidia` and `-gpu-amd`
/// variants; those are amd64-only and want drivers on the host, so the plain
/// tag is the one that runs on a rented server.
pub const IMAGE: &str = "qdrant/qdrant:v1.19.1";
pub const COMPOSE_PROJECT: &str = "qdrant";
pub const CONTAINER: &str = "qdrant";
/// The REST API and the dashboard, on loopback.
pub const API_PORT: u16 = 6333;

/// The API key this store and its reader share. A `SharedSecrets` file rather
/// than either service's own `.env`, because neither end of the pair is
/// reliably installed first — see `install::llm_keys::ensure_shared_secret`.
pub const API_KEY_PATH: &str = "/etc/gryonixnexus/qdrant.key";

/// A port of `QdrantService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.qdrant_path;
    format!("services:\n  qdrant:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      # Read from the shared key file by the setup step below. Set\n      # here rather than baked into a config file so that rotating\n      # it is one file and one restart.\n      QDRANT__SERVICE__API_KEY: ${{QDRANT_API_KEY}}\n    volumes:\n      - {path}/storage:/qdrant/storage\n    ports:\n      # Loopback, and only the REST port. The dashboard rides on\n      # the same port; whoever reaches it has the documents.\n      - \"127.0.0.1:{API_PORT}:6333\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    /// Loopback, and nothing else. A vector store on a public port is the
    /// documents on a public port.
    #[test]
    fn the_api_is_bound_to_loopback_only() {
        let text = compose_contents(&base());
        assert!(text.contains(&format!("\"127.0.0.1:{API_PORT}:6333\"")));
        assert!(!text.contains("0.0.0.0"));
    }

    /// It is a database, so it has a password — the thing that separates it
    /// from the model engine beside it, which holds public weights.
    #[test]
    fn the_store_takes_a_key() {
        assert!(compose_contents(&base()).contains("QDRANT__SERVICE__API_KEY"));
    }

    /// gRPC is not published: nothing in this catalog speaks it, and a bound
    /// port with no client is a port somebody has to explain.
    #[test]
    fn the_grpc_port_is_not_published() {
        assert!(!compose_contents(&base()).contains("6334"));
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

    #[test]
    fn default_public_en() {
        let input = Input { domain: "example.com".to_string(), ..Input::default() };
        assert_eq!(
            compose_contents(&input),
            fixture("qdrant-default-public-en__docker-compose.yml")
        );
    }

    #[test]
    fn custompath_public_en() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.qdrant_path = "/srv/qdrant".to_string();
        assert_eq!(
            compose_contents(&input),
            fixture("qdrant-custompath-public-en__docker-compose.yml")
        );
    }
}
