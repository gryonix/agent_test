//! Shadowsocks (shadowsocks-rust) — one TCP+UDP port, one config file, one
//! server-minted key.
//!
//! The simplest of the four protocols слайс 4.9 refused, and the one that
//! shows the shape all four share: a compose project of its own, a first-run
//! secret, and NO Caddy site (it is not HTTP — `webIngress` is nil on the
//! Swift side, so nothing here touches `caddy::merge_site`).
//!
//! **The config file is the secret.** `config.json` holds the pre-shared key
//! in cleartext, which is why both routes keep it at 0600 root-owned and why
//! the container runs as `0:0` (a non-root process in the image could not
//! read its own config). It is written ONCE — a re-run that re-minted the key
//! would silently disconnect every client that already imported the ss:// link
//! — and the executor therefore creates it with `O_CREAT|O_EXCL` rather than
//! the generator's `[ ! -f config.json ]` check-then-act, the same
//! substitution `execute::write_env_if_absent` already makes for every
//! service's `.env`.
//!
//! **The key is base64, not hex.** The 2022-blake3 ciphers take a 32-byte key
//! encoded with standard base64 (`openssl rand -base64 32`), which is also
//! why the ss:// link percent-encodes it: `+`, `/` and `=` are not safe in URL
//! userinfo. That link is built by the REPORT, not here.

use crate::install::context::Input;

/// `ShadowsocksService.composeProject` — the `-p` every compose verb needs.
pub const COMPOSE_PROJECT: &str = "shadowsocks";

/// `ShadowsocksService.containerName`, pinned on the Swift side because the
/// dashboard's restart literal (and its sudoers line) names it.
pub const CONTAINER: &str = "shadowsocks";

pub const IMAGE: &str = "ghcr.io/shadowsocks/ssserver-rust:v1.24.0";

/// Where the image reads its config INSIDE the container.
const CONTAINER_CONFIG_PATH: &str = "/etc/shadowsocks-rust/config.json";

/// `ShadowsocksService.method`. An AEAD-2022 cipher — the reason the key is a
/// base64-encoded 32 bytes rather than a passphrase.
pub const METHOD: &str = "2022-blake3-aes-256-gcm";

/// The host directory, from settings.
pub fn dir(input: &Input) -> &str {
    &input.shadowsocks_path
}

/// The config file's path on the HOST — mounted read-only into the container.
pub fn config_path(input: &Input) -> String {
    format!("{}/config.json", dir(input))
}

/// A port of `ShadowsocksService.composeFile`.
pub fn compose_contents(input: &Input) -> String {
    let path = dir(input);
    let port = input.shadowsocks_port;
    format!(
        "services:
  ssserver:
    image: {IMAGE}
    container_name: {CONTAINER}
    restart: unless-stopped
    # Explicit binary name: the image's entrypoint does not prepend
    # `ssserver` for a bare `-c …`, so `exec \"$@\"` chokes on the
    # leading option (\"exec: illegal option -c\"). Run as root (0:0):
    # config.json is chmod 600 root-owned (setup and the panel both
    # keep it 600), so a non-root process could not read it.
    command: ssserver -c {CONTAINER_CONFIG_PATH}
    user: \"0:0\"
    volumes:
      - {path}/config.json:{CONTAINER_CONFIG_PATH}:ro
    ports:
      - \"{port}:{port}/tcp\"
      - \"{port}:{port}/udp\""
    )
}

/// A port of the `EOF_SS_CONFIG` heredoc — the server's whole configuration.
///
/// `password` is the base64 key. It is a parameter rather than something this
/// function mints so that the value written to disk and the value the caller
/// keeps for the report are provably the same string, and so that the parity
/// test can pass the generator's own `${SS_PASSWORD}` placeholder and compare
/// the two templates byte for byte.
pub fn config_json(input: &Input, password: &str) -> String {
    let port = input.shadowsocks_port;
    format!(
        "{{
    \"server\": \"0.0.0.0\",
    \"server_port\": {port},
    \"password\": \"{password}\",
    \"method\": \"{METHOD}\",
    \"mode\": \"tcp_and_udp\",
    \"timeout\": 300
}}
"
    )
}

#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::install::vpn::protocols::tests_support::{fixture, heredoc_body, scenario_input};

    fn assert_parity(scenario: &str) {
        let input = scenario_input(scenario);
        assert_eq!(
            compose_contents(&input),
            fixture(&format!("ss-{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            dir(&input),
            fixture(&format!("ss-{scenario}__compose-directory.txt")),
            "{scenario}: compose directory"
        );
        // The generated script writes this body through a heredoc whose
        // expansion the SERVER performs, so the fixture still carries
        // `${SS_PASSWORD}`. Rendering with that exact token is what makes the
        // two comparable — and it also pins the fact that the port writes the
        // key in the same place the shell would have.
        assert_eq!(
            config_json(&input, "${SS_PASSWORD}"),
            heredoc_body(
                &fixture(&format!("ss-{scenario}__setup-steps.txt")),
                "EOF_SS_CONFIG"
            ),
            "{scenario}: config.json"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity("default-public-en");
    }

    /// Every path and every port moved at once.
    #[test]
    fn custompaths_public_en() {
        assert_parity("custompaths-public-en");
    }

    /// The endpoint hostname reaches the ss:// link, which the REPORT builds —
    /// nothing this module writes moves with it. Pinned so that stays true.
    #[test]
    fn customhost_public_en() {
        assert_parity("customhost-public-en");
    }

    /// Russian. The only language-dependent line in the whole step is the
    /// `log` narration, which the agent replaces with its own English step
    /// text by schema decision — so every artifact here must be identical to
    /// the English scenario's.
    #[test]
    fn default_public_ru() {
        assert_parity("default-public-ru");
        let en = scenario_input("default-public-en");
        let ru = scenario_input("default-public-ru");
        assert_eq!(compose_contents(&en), compose_contents(&ru), "compose is language-independent");
        assert_eq!(
            config_json(&en, "K"),
            config_json(&ru, "K"),
            "config.json is language-independent"
        );
    }
}
