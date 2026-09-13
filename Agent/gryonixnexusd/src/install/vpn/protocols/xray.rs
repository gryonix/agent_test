//! XRay VLESS + XTLS-Vision + REALITY — one TCP port, one config file, three
//! server-minted secrets.
//!
//! **The image has no shell, and that shapes the whole port.** The official
//! `xray-core` image is distroless: its ENTRYPOINT is the xray binary itself,
//! so the keys are minted by RUNNING the image with a subcommand
//! (`docker run --rm <image> uuid`, `… x25519`) and reading stdout. There is
//! nothing to `docker exec` into and no shell to pipe through — which is
//! convenient here, because the agent runs docker directly with no shell of
//! its own anyway.
//!
//! **The x25519 output format is version-dependent, and the pinned tag is
//! part of the contract.** Releases have printed `Private key:`/`Public key:`,
//! then `PrivateKey:`/`Password:`, then `PrivateKey:`/`Password (PublicKey):`.
//! [`parse_keys`] accepts all three shapes, exactly as the generator's two
//! `sed` expressions do — and the pin on [`IMAGE`] is what keeps the set
//! finite. An empty key is FATAL on both routes (`fail` in the script): a
//! server whose REALITY private key is the empty string starts and then
//! refuses every client, which reads as a broken client.
//!
//! **The client link is not derivable from the server config.** The config
//! holds the PRIVATE key; the vless:// link needs the PUBLIC one and the
//! shortId. That is why the generator persists `link.txt` next to the config,
//! and why this module renders the link rather than leaving the report to
//! reconstruct it — the report cannot, the public key is nowhere else on disk.

use crate::install::context::Input;

/// `XrayRealityService.composeProject`.
pub const COMPOSE_PROJECT: &str = "xray";

/// `XrayRealityService.containerName`, pinned on the Swift side for the
/// dashboard's restart literal.
pub const CONTAINER: &str = "xray";

/// Pinned deliberately: this is a known 26.x whose `x25519` output shape the
/// parser below was written against (see the module doc).
pub const IMAGE: &str = "ghcr.io/xtls/xray-core:26.7.11";

/// The image reads every `*.json` in this directory (`-confdir`); we mount one.
const CONTAINER_CONFIG_DIR: &str = "/usr/local/etc/xray";

/// The host directory, from settings.
pub fn dir(input: &Input) -> &str {
    &input.xray_reality_path
}

/// Where the single config file lives on the HOST. The directory — not the
/// file — is what the container mounts, so this path is also the gate the
/// executor uses to decide whether the secrets already exist.
pub fn config_path(input: &Input) -> String {
    format!("{}/config/config.json", dir(input))
}

/// The persisted client link. Kept next to the config because the public key
/// it carries exists nowhere else once the generator's shell variables are
/// gone.
pub fn link_path(input: &Input) -> String {
    format!("{}/link.txt", dir(input))
}

/// The endpoint hostname clients dial — the panel's own hostname rule. NOT the
/// SNI: that is the borrowed camouflage site, and confusing the two would
/// point every client at Microsoft.
pub fn hostname(input: &Input) -> String {
    super::super::panel::hostname(input)
}

/// A port of `XrayRealityService.composeFile`.
pub fn compose_contents(input: &Input) -> String {
    let path = dir(input);
    let port = input.xray_reality_port;
    format!(
        "services:
  xray:
    image: {IMAGE}
    container_name: {CONTAINER}
    restart: unless-stopped
    # Run as root (0:0): config.json is chmod 600 root-owned (setup
    # and the panel both keep it 600, since it holds the REALITY
    # private key), and the image runs as a non-root user that would
    # otherwise get \"permission denied\" reading it.
    user: \"0:0\"
    volumes:
      - {path}/config:{CONTAINER_CONFIG_DIR}:ro
    ports:
      - \"{port}:{port}/tcp\""
    )
}

/// A port of the `EOF_XRAY_CONFIG` heredoc.
///
/// The three secrets are parameters for the same reason Shadowsocks' key is:
/// the value written to disk and the value that reaches the client link must
/// provably be one string, and the parity test can hand it the generator's own
/// `${…}` placeholders and compare templates byte for byte.
pub fn config_json(input: &Input, uuid: &str, private_key: &str, short_id: &str) -> String {
    let port = input.xray_reality_port;
    let sni = &input.xray_reality_sni;
    format!(
        "{{
    \"log\": {{ \"loglevel\": \"warning\" }},
    \"inbounds\": [
        {{
            \"listen\": \"0.0.0.0\",
            \"port\": {port},
            \"protocol\": \"vless\",
            \"settings\": {{
                \"clients\": [ {{ \"id\": \"{uuid}\", \"flow\": \"xtls-rprx-vision\" }} ],
                \"decryption\": \"none\"
            }},
            \"streamSettings\": {{
                \"network\": \"tcp\",
                \"security\": \"reality\",
                \"realitySettings\": {{
                    \"dest\": \"{sni}:443\",
                    \"serverNames\": [ \"{sni}\" ],
                    \"privateKey\": \"{private_key}\",
                    \"shortIds\": [ \"{short_id}\" ]
                }}
            }},
            \"sniffing\": {{ \"enabled\": true, \"destOverride\": [ \"http\", \"tls\", \"quic\" ], \"routeOnly\": true }}
        }}
    ],
    \"outbounds\": [ {{ \"protocol\": \"freedom\", \"tag\": \"direct\" }} ]
}}
"
    )
}

/// A port of the `printf 'vless://…'` line — the file the report prints.
///
/// Ends with a newline because the generator's `printf` format does, and the
/// report `cat`s the file into a line of its own.
pub fn client_link(input: &Input, uuid: &str, public_key: &str, short_id: &str) -> String {
    format!(
        "vless://{uuid}@{host}:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={sni}&fp=chrome&pbk={public_key}&sid={short_id}&type=tcp#gryonixNexus\n",
        host = hostname(input),
        port = input.xray_reality_port,
        sni = input.xray_reality_sni,
    )
}

/// The private and public halves of `xray x25519`'s output, in that order.
///
/// A port of the generator's two `sed -n -e … -e … | head -n1` pipelines:
/// FIRST matching line wins, and the private-key expression deliberately does
/// not accept `Password…` (that is the public half in the 26.x spelling).
/// Returns `None` when either half is missing, which both routes treat as
/// fatal — see the module doc.
pub fn parse_keys(output: &str) -> Option<(String, String)> {
    fn first<'a>(output: &'a str, prefixes: &[&str]) -> Option<&'a str> {
        output.lines().find_map(|line| {
            prefixes.iter().find_map(|prefix| {
                line.strip_prefix(prefix).map(|rest| rest.trim_start_matches([' ', '\t']))
            })
        })
    }

    // `Password[^:]*:` in the script — the 26.7 spelling is
    // `Password (PublicKey):`, so everything up to the colon is swallowed.
    let public_line = output.lines().find_map(|line| {
        let rest = line.strip_prefix("Password")?;
        let (head, tail) = rest.split_once(':')?;
        // `[^:]*` cannot match a colon: a line with a second colon before the
        // first is not this key.
        if head.contains(':') {
            return None;
        }
        Some(tail.trim_start_matches([' ', '\t']))
    });

    let private = first(output, &["PrivateKey:", "Private key:"])?;
    let public = public_line.or_else(|| first(output, &["Public key:"]))?;
    if private.is_empty() || public.is_empty() {
        return None;
    }
    Some((private.to_string(), public.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three shapes the pinned tag's family has printed. Written as data
    /// the parser has never seen rather than as "the regex, again".
    #[test]
    fn every_documented_x25519_shape_parses() {
        let cases = [
            ("PrivateKey: aPriv\nPassword (PublicKey): aPub\n", "aPriv", "aPub"),
            ("PrivateKey: bPriv\nPassword: bPub\n", "bPriv", "bPub"),
            ("Private key: cPriv\nPublic key: cPub\n", "cPriv", "cPub"),
        ];
        for (output, private, public) in cases {
            assert_eq!(
                parse_keys(output),
                Some((private.to_string(), public.to_string())),
                "shape {output:?}"
            );
        }
    }

    /// Half an answer is not an answer — both routes treat it as fatal.
    #[test]
    fn a_missing_half_is_no_answer() {
        assert_eq!(parse_keys("PrivateKey: only\n"), None);
        assert_eq!(parse_keys("Password: only\n"), None);
        assert_eq!(parse_keys(""), None);
        assert_eq!(parse_keys("PrivateKey:\nPassword: p\n"), None);
    }

    /// `head -n1`: the first match wins, not the last.
    #[test]
    fn the_first_matching_line_wins() {
        let output = "PrivateKey: first\nPrivateKey: second\nPassword: pub\n";
        assert_eq!(parse_keys(output).unwrap().0, "first");
    }
}

#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::install::vpn::protocols::tests_support::{fixture, heredoc_body, scenario_input};

    /// The generator builds the link with `printf FORMAT ARGS`, so the fixture
    /// carries the format and the arguments separately. Rather than
    /// re-deriving the expected string from the Swift source (the one thing
    /// the parity method forbids), this substitutes the arguments into the
    /// format read out of the FIXTURE and compares that.
    fn link_from_fixture(steps: &str, uuid: &str, public_key: &str, short_id: &str) -> String {
        let format_line = steps
            .lines()
            .find(|line| line.trim_start().starts_with("printf 'vless://"))
            .expect("the steps must build the link with printf");
        let args_line = steps
            .lines()
            .find(|line| line.trim_start().starts_with("\"$XRAY_UUID\""))
            .expect("the printf arguments must follow on the next line");

        let format = format_line
            .trim_start()
            .trim_start_matches("printf '")
            .trim_end()
            .trim_end_matches('\\')
            .trim_end()
            .trim_end_matches('\'');
        let args: Vec<String> = args_line
            .trim_start()
            .split_once('>')
            .map(|(args, _redirect)| args)
            .unwrap_or(args_line)
            .split_whitespace()
            .map(|token| token.trim_matches('"').to_string())
            .collect();
        assert_eq!(args.len(), 6, "the link takes six arguments: {args:?}");

        let mut out = String::new();
        let mut values = [uuid, &args[1], &args[2], &args[3], public_key, short_id].into_iter();
        let mut rest = format;
        while let Some(at) = rest.find("%s") {
            out.push_str(&rest[..at]);
            out.push_str(values.next().expect("one value per %s"));
            rest = &rest[at + 2..];
        }
        out.push_str(rest);
        // The format's trailing `\n` is a printf escape, not two characters.
        out.replace("\\n", "\n")
    }

    fn assert_parity(scenario: &str) {
        let input = scenario_input(scenario);
        let steps = fixture(&format!("xray-{scenario}__setup-steps.txt"));
        assert_eq!(
            compose_contents(&input),
            fixture(&format!("xray-{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            dir(&input),
            fixture(&format!("xray-{scenario}__compose-directory.txt")),
            "{scenario}: compose directory"
        );
        assert_eq!(
            hostname(&input),
            fixture(&format!("xray-{scenario}__hostname.txt")),
            "{scenario}: hostname"
        );
        assert_eq!(
            config_json(&input, "${XRAY_UUID}", "${XRAY_PRIV}", "${XRAY_SID}"),
            heredoc_body(&steps, "EOF_XRAY_CONFIG"),
            "{scenario}: config.json"
        );
        assert_eq!(
            client_link(&input, "U", "P", "S"),
            link_from_fixture(&steps, "U", "P", "S"),
            "{scenario}: link.txt"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity("default-public-en");
    }

    #[test]
    fn custompaths_public_en() {
        assert_parity("custompaths-public-en");
    }

    /// The endpoint hostname moves the link but NOT the server config: the
    /// config knows only the borrowed SNI.
    #[test]
    fn customhost_public_en() {
        assert_parity("customhost-public-en");
        let input = scenario_input("customhost-public-en");
        assert!(client_link(&input, "U", "P", "S").contains("tunnel.example.com"));
        assert!(!config_json(&input, "U", "P", "S").contains("tunnel.example.com"));
    }

    /// The borrowed TLS site moves BOTH `dest` and `serverNames`, and the
    /// link's `sni` — three places from one setting.
    #[test]
    fn customsni_public_en() {
        assert_parity("customsni-public-en");
        let input = scenario_input("customsni-public-en");
        assert_eq!(config_json(&input, "U", "P", "S").matches("www.cloudflare.com").count(), 2);
        assert!(client_link(&input, "U", "P", "S").contains("sni=www.cloudflare.com"));
    }

    #[test]
    fn default_public_ru() {
        assert_parity("default-public-ru");
        let en = scenario_input("default-public-en");
        let ru = scenario_input("default-public-ru");
        assert_eq!(compose_contents(&en), compose_contents(&ru));
        assert_eq!(config_json(&en, "U", "P", "S"), config_json(&ru, "U", "P", "S"));
        assert_eq!(client_link(&en, "U", "P", "S"), client_link(&ru, "U", "P", "S"));
    }
}
