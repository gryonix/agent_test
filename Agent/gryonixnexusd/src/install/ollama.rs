//! Ollama's declarative install artifacts — a port of `OllamaService.swift`,
//! declarative half only.
//!
//! **The service in this crate with no `web_ingress` and no hostname**, which
//! is the whole shape of it: the API answers on loopback and has no
//! authentication of any kind, so whoever reaches the port owns the models.
//! The chat interface beside it is the thing with a name.
//!
//! The install fetches NO MODEL (owner's decision, 2026-09-07) — see the Swift
//! type's own comment for why. Nothing in this module downloads one, and the
//! executor's step list has no arm that could.

use super::context::Input;

/// The catalog id this module installs. No Caddy block carries it — the
/// service publishes no site — but the wrappers, the uninstall table and the
/// start page all address it by this string.
pub const SERVICE_ID: &str = "ollama";

/// Pinned release. Upstream also publishes `:latest` and a `-rocm` variant;
/// this is the plain image, which is the one that runs on a server with no
/// graphics card — which is most of them.
pub const IMAGE: &str = "ollama/ollama:0.33.3";
pub const COMPOSE_PROJECT: &str = "ollama";
pub const CONTAINER: &str = "ollama";
/// Loopback only, and that is the security model rather than a preference.
pub const API_PORT: u16 = 11434;

/// Where the weights live INSIDE the container. The host side of that mount is
/// a setting (`ollama_path`), so it is asked of docker at runtime rather than
/// assumed — see `models::engine_models_path`.
pub const MODELS_MOUNT: &str = "/root/.ollama";

/// NVIDIA's own apt repository for the container toolkit, in the same two
/// pieces Caddy's is declared in — a key and a source list, taken from their
/// install guide rather than paraphrased. Byte-identical to what
/// `OllamaService.swift` writes on the SSH path, on purpose: two ways of
/// enabling the same card that disagree about where the package comes from
/// would be two different products.
pub const GPU_KEY_URL: &str = "https://nvidia.github.io/libnvidia-container/gpgkey";
pub const GPU_SOURCE_LIST_URL: &str =
    "https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list";
pub const GPU_KEYRING_PATH: &str = "/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg";
pub const GPU_SOURCE_LIST_PATH: &str = "/etc/apt/sources.list.d/nvidia-container-toolkit.list";

/// The compose OVERRIDE the install writes when — and only when — a card
/// actually answered on this host.
///
/// **An override rather than a branch in `docker-compose.yml`, and the reason
/// is which side knows what.** The compose file is written from a request that
/// was composed before anything looked at this machine, so a GPU reservation
/// baked into it on a host with no driver produces a container that refuses to
/// start. Compose loads this file automatically on every command, so the
/// restart button, the update wrapper and the power controls pick it up with
/// nothing else in the crate needing to know it exists.
pub fn gpu_override_path(input: &Input) -> String {
    format!("{}/docker-compose.override.yml", input.ollama_path)
}

/// A port of `OllamaService.gpuOverrideContents`.
pub fn gpu_override_contents() -> String {
    "services:\n  ollama:\n    deploy:\n      resources:\n        reservations:\n          devices:\n            # Every card on the host. The engine loads one model at a time\n            # and picks the device itself; enumerating them here would be a\n            # list to keep in step with the hardware.\n            - driver: nvidia\n              count: all\n              capabilities: [gpu]".to_string()
}

/// A port of `OllamaService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.ollama_path;
    format!(
        "services:\n  ollama:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      # Answer requests from the other containers on this host, not\n      # only from inside its own. The port is still bound to\n      # loopback below, so this widens nothing the outside can see.\n      OLLAMA_HOST: \"0.0.0.0:{API_PORT}\"\n    volumes:\n      # Models. The one bind mount in this catalog that is expected\n      # to reach tens of gigabytes.\n      - {path}/models:/root/.ollama\n    ports:\n      - \"127.0.0.1:{API_PORT}:{API_PORT}\""
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    /// The engine is reachable from the host's other containers and from
    /// nowhere else. Both halves matter: dropping the environment line breaks
    /// the chat beside it, dropping the loopback address publishes an
    /// unauthenticated model API to the internet.
    #[test]
    fn the_api_listens_widely_inside_and_is_published_narrowly_outside() {
        let text = compose_contents(&base());
        assert!(text.contains(&format!("OLLAMA_HOST: \"0.0.0.0:{API_PORT}\"")));
        assert!(text.contains(&format!("- \"127.0.0.1:{API_PORT}:{API_PORT}\"")));
    }

    /// The one directory in this catalog expected to reach tens of gigabytes,
    /// and the reason it is its own setting rather than a corner of the
    /// compose directory.
    #[test]
    fn models_live_under_the_configured_path() {
        let mut input = base();
        input.ollama_path = "/srv/models".to_string();
        assert!(compose_contents(&input).contains("- /srv/models/models:/root/.ollama"));
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

    #[test]
    fn default_public_en() {
        assert_eq!(
            compose_contents(&base()),
            fixture("ollama-default-public-en__docker-compose.yml")
        );
    }

    #[test]
    fn custom_path_public_en() {
        let mut input = base();
        input.ollama_path = "/srv/ollama".to_string();
        assert_eq!(
            compose_contents(&input),
            fixture("ollama-custompath-public-en__docker-compose.yml")
        );
    }

    /// The override the card branch writes. Its own fixture because it is a
    /// FILE this crate writes rather than a section of the script the Swift
    /// side generates — nothing else would notice the two drifting apart.
    #[test]
    fn gpu_override_public_en() {
        assert_eq!(
            gpu_override_contents(),
            fixture("ollama-gpu-public-en__compose-override.yml")
        );
    }
}
