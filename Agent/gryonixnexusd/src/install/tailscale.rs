//! The server's own mesh membership — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/TailscaleNodeService.swift`.
//!
//! **Implicit, like the VPN panel.** It is installed by the Headscale call
//! rather than by one of its own, because a control server that never joined
//! its own network has no mesh address — and the names the other devices look
//! up have to point at something. That was measured before any of this was
//! written (ROADMAP, "как узел достаёт сервисы").
//!
//! **The join key never leaves the host.** The imperative half mints a
//! pre-auth key through the control server's own CLI, in this same machine's
//! container, and writes it into a 0600 `.env`. Nothing about it crosses the
//! network, and nothing about it reaches the app.

use super::context::Input;

/// Exact pinned tag. arm64 verified by the ELF header of the binary inside the
/// linux/arm64 manifest — a statically linked AArch64 Go binary — rather than
/// by the index's promise, which this catalog has seen lie before.
pub const IMAGE: &str = "tailscale/tailscale:v1.102.2";
pub const COMPOSE_PROJECT: &str = "tailscale";
pub const CONTAINER: &str = "tailscale";
/// The mesh user its key is minted under: one name for the deployment's own
/// machines, so the owner's laptops stay visibly separate in the node list.
pub const MESH_USER: &str = "gryonixnexus";

/// A port of `TailscaleNodeService.nodeName(_:)`.
pub fn node_name(input: &Input) -> String {
    if !input.tailscale_node_name.is_empty() {
        return input.tailscale_node_name.clone();
    }
    input
        .domain
        .split('.')
        .next()
        .filter(|label| !label.is_empty())
        .unwrap_or("server")
        .to_string()
}

/// A port of `TailscaleNodeService.extraArgs(_:)`.
///
/// `--login-server=…` only when this deployment runs its own control server:
/// the client's default IS Tailscale, so the flag is the exception.
pub fn extra_args(input: &Input) -> String {
    let login = input.tailscale_login_server.trim();
    if login.is_empty() {
        "--accept-dns=false".to_string()
    } else {
        format!("--login-server={login} --accept-dns=false")
    }
}

/// A port of `TailscaleNodeService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.tailscale_node_path;
    let name = node_name(input);
    let args = extra_args(input);
    format!(
        "services:\n  tailscale:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    \
         restart: unless-stopped\n    \
         # The HOST's network stack, so the interface it creates belongs\n    \
         # to this machine rather than to a container nobody routes to.\n    \
         # Measured on the lab mesh: with this, the host's own curl is\n    \
         # already routed into the mesh.\n    \
         network_mode: host\n    cap_add:\n      - NET_ADMIN\n      - NET_RAW\n    \
         devices:\n      - /dev/net/tun:/dev/net/tun\n    volumes:\n      \
         # The node's identity. Losing it means re-joining as a new\n      \
         # node and leaving a dead one behind in the server's list.\n      \
         - {path}/state:/var/lib/tailscale\n    environment:\n      \
         TS_STATE_DIR: /var/lib/tailscale\n      TS_HOSTNAME: {name}\n      \
         # Read from .env, which is 0600 and written once.\n      \
         TS_AUTHKEY: ${{TS_AUTHKEY}}\n      \
         # --accept-dns=false: see the type comment. The server's own\n      \
         # resolver must not depend on a container being up.\n      \
         TS_EXTRA_ARGS: {args}",
    )
}

/// A port of the Swift `envTemplate`: the key is not ours to invent, so the
/// file exists only to hold the one the control server mints.
///
/// Only the parity fixture calls it — the install writes the key it just
/// minted straight into `.env`, so the empty placeholder is never needed on a
/// host. Kept because the fixture is the check that the port still matches the
/// generator.
#[cfg(test)]
pub fn env_template() -> String {
    "TS_AUTHKEY=".to_string()
}

/// The client's own view: its backend state and its first mesh address.
///
/// Asked of the CLIENT rather than of a control server because only the client
/// answers for both — a node joined to Tailscale has no local server to query,
/// and asking one that is not there reported every healthy node as failed.
pub fn parse_status(text: &str) -> Option<(String, String)> {
    let value: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let state = value.get("BackendState")?.as_str()?.to_string();
    let address = value
        .get("Self")
        .and_then(|me| me.get("TailscaleIPs"))
        .and_then(|ips| ips.as_array())
        .and_then(|ips| ips.iter().find_map(|ip| ip.as_str()))
        .unwrap_or_default()
        .to_string();
    Some((state, address))
}

/// The last login failure the client logged, if any.
///
/// **The point is to quote the client, not to classify it.** "invalid key: API
/// key … not valid" is a fact about the key the owner supplied — a spent
/// single-use key looks exactly like a broken install otherwise, which is how
/// a live run of this very service was nearly misread.
pub fn last_login_error(log: &str) -> Option<String> {
    log.lines()
        .rev()
        .find(|line| line.contains("Received error:") || line.contains("backend error:"))
        .map(|line| {
            let text = line.split_once("error:").map(|(_, rest)| rest).unwrap_or(line);
            text.trim().chars().take(160).collect()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Swift generator's REAL output, dumped through `GRYONIXNEXUS_DUMP_DIR`
    /// (`scratchpad/dump-mesh-fixtures.swift.txt`). Compared byte for byte —
    /// a port checked against a READING of the generator only proves it
    /// matches how someone read it.
    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/mesh/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn scenario(name: &str) -> Input {
        let mut input = Input::default();
        match name {
            "default-public-en" | "default-public-ru" => {
                input.domain = "example.com".to_string();
                input.tailscale_login_server = "https://mesh.example.com".to_string();
            }
            "custom-public-en" => {
                input.domain = "example.com".to_string();
                input.headscale_path = "/srv/mesh".to_string();
                input.headscale_hostname = "control.example.com".to_string();
                input.headscale_base_domain = "mesh.internal".to_string();
                input.tailscale_node_path = "/srv/node".to_string();
                input.tailscale_node_name = "vault-host".to_string();
                input.tailscale_login_server = "https://control.example.com".to_string();
            }
            "subdomain-public-en" => {
                input.domain = "b5.grypak.de".to_string();
                input.additional_domains = vec!["b6.grypak.de".to_string()];
                input.tailscale_login_server = "https://mesh.b5.grypak.de".to_string();
            }
            // The node joining TAILSCALE's own service: the flag is ABSENT,
            // which no scenario carrying a control server can show.
            "tailscale-public-en" => {
                input.domain = "example.com".to_string();
                input.tailscale_node_name = "server".to_string();
            }
            other => panic!("unknown scenario {other}"),
        }
        input
    }

    const SCENARIOS: &[&str] = &["default-public-en", "default-public-ru", "custom-public-en",
                                 "subdomain-public-en", "tailscale-public-en"];

    #[test]
    fn fixture_parity_compose() {
        for name in SCENARIOS {
            let input = scenario(name);
            assert_eq!(
                compose_contents(&input),
                fixture(&format!("node-{name}__docker-compose.yml")),
                "{name}"
            );
        }
    }

    #[test]
    fn fixture_parity_env_template() {
        for name in SCENARIOS {
            assert_eq!(env_template(), fixture(&format!("node-{name}__env.template")), "{name}");
        }
    }

    #[test]
    fn fixture_parity_node_name() {
        for name in SCENARIOS {
            assert_eq!(node_name(&scenario(name)), fixture(&format!("node-{name}__node-name.txt")), "{name}");
        }
    }

    /// The compose DIRECTORY is the path the whole install writes into, and it
    /// is the one value here that a port could get right in the file and wrong
    /// in the code that uses it.
    #[test]
    fn fixture_parity_compose_directory() {
        for name in SCENARIOS {
            assert_eq!(
                scenario(name).tailscale_node_path,
                fixture(&format!("node-{name}__compose-directory.txt")),
                "{name}"
            );
        }
    }

    fn base(domain: &str) -> Input {
        let mut input = Input::default();
        input.domain = domain.to_string();
        input
    }

    /// The client's own words, taken from a REAL log line of a live run — the
    /// one that turned a spent auth key from "the install is broken" into a
    /// fact about the key.
    #[test]
    fn the_clients_last_login_error_is_quoted_rather_than_classified() {
        let log = "2026/08/15 12:22:48 control: RegisterReq: got response\n\
                   2026/08/15 12:22:48 Received error: invalid key: API key kJFWdPYQX421CNTRL not valid\n";
        let why = last_login_error(log).expect("the failure must be found");
        assert!(why.contains("invalid key"), "{why}");
        assert!(why.contains("not valid"), "{why}");
        assert!(last_login_error("nothing interesting here\n").is_none());
    }

    /// A node that HAS joined answers with a state and an address; one that has
    /// not answers with a state and nothing.
    #[test]
    fn the_clients_state_and_address_are_read_back() {
        let joined = r#"{"BackendState":"Running","Self":{"TailscaleIPs":["100.81.1.61","fd7a::1"]}}"#;
        assert_eq!(parse_status(joined), Some(("Running".to_string(), "100.81.1.61".to_string())));
        let out = r#"{"BackendState":"NeedsLogin","Self":{}}"#;
        assert_eq!(parse_status(out), Some(("NeedsLogin".to_string(), String::new())));
        assert_eq!(parse_status("not json"), None);
    }

    #[test]
    fn the_node_is_named_after_the_first_label_of_the_domain() {
        assert_eq!(node_name(&base("b5.grypak.de")), "b5");
        assert_eq!(node_name(&base("example.com")), "example");
    }

    #[test]
    fn an_explicit_name_wins() {
        let mut input = base("example.com");
        input.tailscale_node_name = "vault-host".to_string();
        assert_eq!(node_name(&input), "vault-host");
    }

    /// **No login server means Tailscale's own, and that is the client's
    /// default rather than a value we pass.** Generation fills the setting in
    /// from the presence of a Headscale, so a node and the server it belongs
    /// to cannot disagree; here the two shapes are pinned directly.
    #[test]
    fn the_flag_is_present_only_when_this_deployment_runs_the_control_server() {
        let mut input = base("example.com");
        assert_eq!(extra_args(&input), "--accept-dns=false", "joining Tailscale passes no login server");
        assert!(!compose_contents(&input).contains("--login-server"));

        input.tailscale_login_server = "https://control.example.com".to_string();
        assert_eq!(extra_args(&input), "--login-server=https://control.example.com --accept-dns=false");
        assert!(compose_contents(&input).contains("--login-server=https://control.example.com"));
    }

    /// Accepting the mesh's DNS would make this machine's resolver depend on a
    /// container being up: `apt`, `docker pull` and every ACME renewal run
    /// through it.
    #[test]
    fn the_node_never_accepts_dns_from_the_mesh() {
        assert!(compose_contents(&base("example.com")).contains("--accept-dns=false"));
    }
}
