//! The four VPN protocols срез 4.9 deliberately left refused.
//!
//! **Why they were refused rather than half-ported.** Срез 4.9 shipped the
//! panel and plain WireGuard — and the panel IS the WireGuard server, so that
//! pair is one project. The other four each bring their own compose project,
//! their own subnet and their own imperative steps, and a panel brought up
//! advertising a protocol whose container nobody created is worse than an
//! honest `failed_precondition`: `services.json` is read at panel START to
//! decide what to offer, so the lie would be visible in the UI and invisible
//! in the logs.
//!
//! **What every file here owes the panel.** The panel's `services.json` is
//! written BEFORE `up -d` (срез 4.9's fourth finding — the panel reads it on
//! start), and it is the contract that says which protocols exist. A protocol
//! module produces its own project and its own entry; it never edits the
//! panel's assets, which are byte-identical `include_str!` files extracted
//! from the real generated script.
//!
//! **Subnets are assigned, not chosen** (ARCHITECTURE.md): 10.8 is the
//! scenario-B tunnel, 10.9 the panel's own WireGuard, 10.10 amneziaWG, 10.11
//! openVPN. Two protocols sharing a subnet is a routing collision that only
//! shows up once both are installed.
//!
//! ## What the four have in common (and what they do NOT)
//!
//! **None of them is an HTTP service.** All four `webIngress` answers are nil
//! on the Swift side, so nothing here merges a Caddy site — the panel owns the
//! VPN's single site. What they DO need is a firewall port each, and those
//! already live on `panel::Protocol::firewall_ports` because `services.json`
//! had to describe all five from срез 4.9 onwards.
//!
//! **Each mints a first-run secret, and every one of them is written ONCE.**
//! Re-minting on a re-run would invalidate the client profiles the user has
//! already imported — an ss:// link, a vless:// link, a `.ovpn` file, a panel
//! password. The generator expresses that with `[ ! -f … ]` check-then-act;
//! the port uses `O_CREAT|O_EXCL` or an explicit existence check followed by
//! an exclusive create, the same substitution every service slice made for
//! `.env`.
//!
//! **The per-service `gryonixnexus-update.sh` the bash version once wrote is NOT
//! ported**, for the reason `install_jellyfin_steps` records: it is only
//! reachable as `sudo <path>/gryonixnexus-update.sh`, and the sudoers line that
//! makes that legal is provisioned by the setup script, which this route does
//! not run. Writing an unreachable root-owned script would be theatre.
//!
//! **Language independence is measured, not assumed.** The only
//! language-dependent line in all four `setupSteps` is the `log` narration
//! (and AmneziaWG's one degraded-mode warning); the agent narrates its own
//! steps in English by schema decision (`InstallServiceEvent.text`). Each
//! module's `default_public_ru` test asserts artifact-for-artifact that
//! nothing else moves with the language.

pub mod amnezia;
pub mod openvpn;
pub mod shadowsocks;
pub mod xray;

/// Shared by the four parity suites: the fixture park is one directory dumped
/// by ONE run of the real Swift generator, so the scenario inputs have to be
/// spelled once, not four times.
#[cfg(test)]
pub mod tests_support {
    use crate::dns_records::Language;
    use crate::install::context::Input;

    /// One dumped artifact, by file name.
    pub fn fixture(name: &str) -> String {
        let path = format!(
            "{}/tests/fixtures/install/vpn/protocols/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    /// The body of a heredoc inside a dumped `setupSteps` text.
    ///
    /// The generator writes several of these protocols' files with
    /// `cat > … <<DELIM` / `DELIM`, so the bytes that land on a server are the
    /// lines BETWEEN those markers — that is the artifact a port has to match,
    /// not the step text around it. Deliberately strict: an unknown delimiter
    /// or a missing terminator panics rather than returning an empty string,
    /// because a parity test that silently compares two empty strings is the
    /// harness that passes on nothing this project keeps re-learning.
    pub fn heredoc_body(steps: &str, delimiter: &str) -> String {
        let open_quoted = format!("<<'{delimiter}'");
        let open_plain = format!("<<{delimiter}");
        let mut lines = steps.lines();
        loop {
            let line = lines
                .next()
                .unwrap_or_else(|| panic!("no heredoc opening for {delimiter} in these steps"));
            if line.contains(&open_quoted) || line.trim_end().ends_with(&open_plain) {
                break;
            }
        }
        let mut body = String::new();
        for line in lines {
            if line.trim_end() == delimiter {
                return body;
            }
            body.push_str(line);
            body.push('\n');
        }
        panic!("heredoc {delimiter} is never terminated in these steps");
    }

    /// The `Input` matching one dumped scenario's `ServiceContext`.
    ///
    /// The names are the dumper's (`scratchpad/dump-vpn-protocol-fixtures.swift.txt`),
    /// and an unknown one panics: a scenario that quietly fell back to
    /// defaults would compare a default-rendered artifact against a
    /// custom-path fixture and be read as a port defect.
    pub fn scenario_input(scenario: &str) -> Input {
        let mut input = Input {
            domain: "example.com".to_string(),
            ..Input::default()
        };
        match scenario {
            "default-public-en" => {}
            "custompaths-public-en" => {
                input.amnezia_wg_path = "/srv/awg".to_string();
                input.amnezia_wg_port = 51922;
                input.shadowsocks_path = "/srv/ss".to_string();
                input.shadowsocks_port = 9388;
                input.xray_reality_path = "/srv/xray".to_string();
                input.xray_reality_port = 9443;
                input.openvpn_path = "/srv/ovpn".to_string();
                input.openvpn_port = 1195;
                input.admin_username = "operator".to_string();
            }
            "customhost-public-en" => {
                input.additional_domains = vec!["example.org".to_string()];
                input.vpn_hostname = "tunnel.example.com".to_string();
            }
            "customsni-public-en" => {
                input.xray_reality_sni = "www.cloudflare.com".to_string();
            }
            "default-public-ru" => {
                input.language = Language::Ru;
            }
            other => panic!("unknown fixture scenario {other}"),
        }
        input
    }
}
