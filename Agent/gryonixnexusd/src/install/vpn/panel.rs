//! The DECLARATIVE half of the VPN panel — a port of `VPNPanelService`'s
//! constants, `hostname`, `composeFile`, `webIngress`/`dnsHostnames` and the
//! artifacts its `setupSteps` writes verbatim (the panel's own sources, the
//! `.env` and the admin-lockdown wrapper).
//!
//! Byte-parity fixtures come from two independent places, deliberately:
//! - `tests/fixtures/install/vpn/vpn-{wg,awg,ss,xray,ovpn,mirrored,relay}-*`
//!   were extracted from REAL generated setup scripts (heredoc bodies — the
//!   bytes that land on a server), which is the only way to get
//!   `services.json` at all: `ServiceInfraSections.vpnPanelServicesJSON` is
//!   private to the generator.
//! - `vpn-{default,customhost-mirrored,foreignhost-mirrored,custompaths}-*`
//!   were dumped from the REAL `VPNPanelService` through `GRYONIXNEXUS_DUMP_DIR`,
//!   because the script test park never varies the panel's settings: all
//!   seven script-derived compose files are BYTE IDENTICAL, so a port that
//!   hard-coded the default paths and the one port the park uses would have
//!   passed every one of them.

use super::super::caddy;
use super::super::context::Input;

/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "vpn";

pub const COMPOSE_PROJECT: &str = "vpnpanel";
pub const CONTAINER: &str = "vpnpanel";
pub const PATH: &str = "/opt/gryonix-vpn-panel";
/// Loopback-only port the panel binds; Caddy reverse-proxies `vpn.<domain>`
/// to it. Published as `127.0.0.1:51900:80` — the bind ADDRESS is the control
/// here, not the firewall, because docker publishes a port with its own DNAT
/// that never traverses the filter chain (ARCHITECTURE.md, the AdGuard note).
pub const WEB_UI_PORT: u16 = 51900;
pub const IMAGE: &str = "gryonix-vpn-panel:local";
/// The subnet the panel hands to its own WireGuard clients — clear of the
/// scenario B relay tunnel's 10.8.0.0/24.
pub const WG_SUBNET: &str = "10.9.0.0/24";
/// Root-owned wrapper the dashboard drives over sudo, and the one `lockdown.rs`
/// already executes for `GetLockdown`/`SetLockdown`. Installing the panel is
/// what puts it on disk — which is why the agent could call it long before it
/// could install it.
pub const LOCKDOWN_SCRIPT_PATH: &str = "/opt/gryonixnexus-admin-lockdown.sh";

/// The panel's sources, exactly as the generated setup script writes them.
/// See `super`'s module doc for why these are files rather than literals, and
/// for the measurement that says they carry no per-scenario interpolation.
pub const DOCKERFILE: &str = include_str!("assets/Dockerfile");
pub const APP_PY: &str = include_str!("assets/app.py");
pub const INDEX_HTML: &str = include_str!("assets/index.html");
pub const LOGIN_HTML: &str = include_str!("assets/login.html");
pub const RESET_HTML: &str = include_str!("assets/reset.html");
pub const ADMIN_LOCKDOWN_SH: &str = include_str!("assets/admin-lockdown.sh");

/// Every file the panel's build directory needs, in the order the setup
/// script writes them.
pub fn build_files() -> [(&'static str, &'static str); 5] {
    [
        ("Dockerfile", DOCKERFILE),
        ("app.py", APP_PY),
        ("index.html", INDEX_HTML),
        ("login.html", LOGIN_HTML),
        ("reset.html", RESET_HTML),
    ]
}

/// The VPN protocols the panel can present. All five are modelled because
/// `services.json` has to be able to describe any of them byte-exactly (its
/// fixtures cover all five), but only `WireGuard` has an installer in this
/// build — see `super`'s module doc and `execute::vpn_protocols_from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    /// Runs INSIDE the panel container (wg-quick on `wgpanel`), so it needs no
    /// compose project of its own — the whole reason it is the protocol this
    /// срез can implement.
    WireGuard,
    AmneziaWG,
    Shadowsocks,
    XrayReality,
    OpenVPN,
}

impl Protocol {
    /// The Swift `ServiceID.rawValue` a client names it by.
    pub fn service_id(self) -> &'static str {
        match self {
            Protocol::WireGuard => "wireguard-vpn",
            Protocol::AmneziaWG => "amnezia-wg",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::XrayReality => "xray-reality",
            Protocol::OpenVPN => "openvpn",
        }
    }

    /// The id inside `services.json`, which is NOT the catalog id — the panel's
    /// own `HANDLERS` registry keys on these.
    fn json_id(self) -> &'static str {
        match self {
            Protocol::WireGuard => "wireguard",
            Protocol::AmneziaWG => "amneziawg",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::XrayReality => "xray",
            Protocol::OpenVPN => "openvpn",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Protocol::WireGuard => "WireGuard",
            Protocol::AmneziaWG => "AmneziaWG",
            Protocol::Shadowsocks => "Shadowsocks",
            Protocol::XrayReality => "VLESS / Reality",
            Protocol::OpenVPN => "OpenVPN",
        }
    }

    /// The transport label the panel prints next to the endpoint.
    fn transport(self) -> &'static str {
        match self {
            Protocol::WireGuard | Protocol::AmneziaWG | Protocol::OpenVPN => "UDP",
            Protocol::Shadowsocks => "TCP+UDP",
            Protocol::XrayReality => "TCP",
        }
    }

    fn port(self, input: &Input) -> u16 {
        match self {
            Protocol::WireGuard => input.wireguard_vpn_port,
            Protocol::AmneziaWG => input.amnezia_wg_port,
            Protocol::Shadowsocks => input.shadowsocks_port,
            Protocol::XrayReality => input.xray_reality_port,
            Protocol::OpenVPN => input.openvpn_port,
        }
    }

    /// The firewall ports this protocol needs open, a port of each protocol
    /// service's `firewallPorts`. Shadowsocks answers on both transports.
    pub fn firewall_ports(self, input: &Input) -> Vec<super::super::firewall::Port> {
        use super::super::firewall::Port;
        let port = self.port(input);
        match self {
            Protocol::WireGuard | Protocol::AmneziaWG | Protocol::OpenVPN => vec![Port::udp(port)],
            Protocol::XrayReality => vec![Port::tcp(port)],
            Protocol::Shadowsocks => vec![Port::tcp(port), Port::udp(port)],
        }
    }
}

/// A port of `VPNPanelService.hostname`.
pub fn hostname(input: &Input) -> String {
    if input.vpn_hostname.is_empty() {
        format!("vpn.{}", input.domain)
    } else {
        input.vpn_hostname.clone()
    }
}

/// A port of `VPNPanelService.composeFile`.
pub fn compose_contents(input: &Input) -> String {
    let wg_port = input.wireguard_vpn_port;
    format!(
        "services:
  vpnpanel:
    build: {PATH}/build
    image: {IMAGE}
    container_name: {CONTAINER}
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
    env_file:
      - {PATH}/.env
    volumes:
      - {PATH}/data:/data
      # Manage the other protocol containers (restart/exec) and
      # their config dirs. Unused mounts are harmless empty dirs.
      - /var/run/docker.sock:/var/run/docker.sock
      - {shadowsocks}:/protocols/shadowsocks
      - {xray}:/protocols/xray
      - {openvpn}/data:/protocols/openvpn
      - {amnezia}/data:/protocols/amneziawg
      # Read-only: lets the panel find mailcow's database
      # credentials so it can offer the existing mailboxes as the
      # sender for password-reset mail. The DIRECTORY is
      # mounted, not mailcow.conf itself — docker materialises a
      # missing bind source, and an empty mailcow.conf directory
      # would make mailcow's own \"already configured?\" guard skip
      # generate_config.sh on a later install. An empty directory
      # is harmless: git clone still populates it.
      - {mailcow}:/protocols/mailcow:ro
    extra_hosts:
      # Reaching the host's SMTP listener (mailcow's Postfix) from
      # inside the container.
      - \"host.docker.internal:host-gateway\"
    ports:
      - \"127.0.0.1:{WEB_UI_PORT}:80\"
      # WireGuard (only listens when WireGuard is among the enabled
      # protocols; harmless otherwise).
      - \"{wg_port}:{wg_port}/udp\"",
        shadowsocks = input.shadowsocks_path,
        xray = input.xray_reality_path,
        openvpn = input.openvpn_path,
        amnezia = input.amnezia_wg_path,
        mailcow = input.mailcow_path,
    )
}

/// The panel's `.env`, in the order the setup script's `printf` block writes
/// it. Rewritten on EVERY run, unlike every other service's `.env` in this
/// port — `ADMIN_USER` and the WireGuard parameters have to track the current
/// configuration — which is exactly why the password is resolved separately
/// and passed in rather than generated here (see `execute::resolve_panel_password`).
pub fn env_contents(input: &Input, password: &str) -> String {
    format!(
        "ADMIN_USER={}\nADMIN_PASSWORD={}\nWG_HOST={}\nWG_PORT={}\nWG_SUBNET={}\n",
        input.admin_username,
        password,
        hostname(input),
        input.wireguard_vpn_port,
        WG_SUBNET
    )
}

/// A port of the private `ServiceInfraSections.vpnPanelServicesJSON` — the
/// file the panel's SPA renders, and the one its `__main__` reads AT STARTUP
/// to decide whether to bring WireGuard up.
///
/// The entry order is the generator's `add(…)` call order, not the caller's:
/// WireGuard, AmneziaWG, Shadowsocks, XRay, OpenVPN.
pub fn services_json(input: &Input, protocols: &[Protocol]) -> String {
    let host = hostname(input);
    let entries: Vec<String> = [
        Protocol::WireGuard,
        Protocol::AmneziaWG,
        Protocol::Shadowsocks,
        Protocol::XrayReality,
        Protocol::OpenVPN,
    ]
    .into_iter()
    .filter(|p| protocols.contains(p))
    .map(|p| {
        let port = p.port(input);
        format!(
            "{{\"id\":\"{}\",\"name\":\"{}\",\"endpoint\":\"{host}:{port} · {}\",\"host\":\"{host}\",\"port\":\"{port}\"}}",
            p.json_id(),
            p.display_name(),
            p.transport()
        )
    })
    .collect();
    format!("{{\"services\":[{}]}}\n", entries.join(","))
}

/// A port of `VPNPanelService.webIngress`: the panel is the only Caddy site
/// the VPN has, and it is guarded (`adminGuard: true`).
pub fn web_ingress(input: &Input) -> caddy::WebIngress {
    caddy::WebIngress {
        hostname: hostname(input),
        upstream_port: WEB_UI_PORT,
        admin_guard: true,
        upstream_https: false,
        public_paths: Vec::new(),
    }
}

/// Does this deployment publish the panel's page at all?
///
/// A port of `VPNClientAccess.publishesPanelSite`. Anything but the one known
/// value means yes, which is what every deployment did before the setting
/// existed — and the safe direction: a published page can be closed, a page
/// that was never published leaves somebody with no route to their devices if
/// the agent is unreachable.
pub fn publishes_site(input: &Input) -> bool {
    input.vpn_client_access != "app"
}

pub fn caddy_site_names(input: &Input) -> Vec<String> {
    if !publishes_site(input) {
        return Vec::new();
    }
    input.served_hostnames(&hostname(input))
}

pub fn caddy_site(input: &Input) -> String {
    if !publishes_site(input) {
        return String::new();
    }
    let ingress = web_ingress(input);
    // Overwrites `X-Forwarded-For` instead of appending to it: the panel's
    // own `client_ip()` (`vpn/assets/app.py`) trusts the FIRST entry of that
    // header for its login-throttle/ban bucket, and a plain `reverse_proxy`
    // lets any client — including a compromised container sharing this
    // host's docker bridge — put a forged address first in the list. See the
    // 2026-09-13 security audit, finding F1.
    caddy::site_overwriting_forwarded_for(
        SERVICE_ID,
        &caddy_site_names(input).join(", "),
        ingress.upstream_port,
        ingress.admin_guard,
        ingress.upstream_https,
        // Never `tls internal`: a local-only deployment has no public domain,
        // so it cannot host a VPN endpoint at all and the wizard drops the
        // whole category. There is no fixture for the branch because no
        // scenario can produce one.
        false,
    )
}

/// A port of `VPNPanelService.dnsHostnames` — part of the declarative
/// contract, and pinned against the generator below, but nothing in the crate
/// consumes it yet: the DNS artifact is still produced on the client
/// (`dns_records` builds its own list from the Input's raw service hostnames).
/// Same standing as `context::Input::served_hostnames` carried before a
/// service slice needed it.
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/vpn/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    // ─────────────────── assets: drift against the REAL script ───────────────────

    /// Each asset is compared against a fixture extracted from a DIFFERENT
    /// generated script (ru + AmneziaWG) than the crate's own copies (en +
    /// WireGuard). That makes this test fail on two separate futures: Swift's
    /// assets changing without this port following, and the assets ever
    /// gaining a per-scenario interpolation.
    #[test]
    fn every_panel_asset_matches_the_generators_own_bytes() {
        for (name, embedded) in [
            ("Dockerfile", DOCKERFILE),
            ("app.py", APP_PY),
            ("index.html", INDEX_HTML),
            ("login.html", LOGIN_HTML),
            ("reset.html", RESET_HTML),
            ("admin-lockdown.sh", ADMIN_LOCKDOWN_SH),
        ] {
            assert_eq!(embedded, fixture(&format!("assets/{name}")), "{name} drifted from the generator");
        }
    }

    /// The wrapper the agent's own `lockdown.rs` already executes has to be
    /// the file this install writes — the two halves would otherwise disagree
    /// about a path that is hard-coded on both sides.
    #[test]
    fn the_lockdown_wrapper_is_the_script_lockdown_rs_calls() {
        assert_eq!(LOCKDOWN_SCRIPT_PATH, crate::lockdown::WRAPPER_PATH);
        assert!(ADMIN_LOCKDOWN_SH.starts_with("#!/bin/bash\n"));
        assert!(ADMIN_LOCKDOWN_SH.contains(caddy::ADMIN_GUARD_PATH));
        // The four verbs lockdown.rs drives, and nothing added by this port.
        for verb in ["on)", "only)", "off)", "status)"] {
            assert!(ADMIN_LOCKDOWN_SH.contains(verb), "the wrapper lost its {verb} arm");
        }
    }

    // ─────────────────────────── fixture parity ───────────────────────────

    #[test]
    fn compose_matches_the_generator_on_defaults() {
        assert_eq!(compose_contents(&base()), fixture("vpn-default-public-en__docker-compose.yml"));
    }

    #[test]
    fn compose_matches_the_generator_with_every_path_and_the_port_moved() {
        let input = Input {
            admin_username: "operator".to_string(),
            mailcow_path: "/srv/mailcow".to_string(),
            wireguard_vpn_port: 51999,
            amnezia_wg_path: "/srv/awg".to_string(),
            shadowsocks_path: "/srv/ss".to_string(),
            xray_reality_path: "/srv/xray".to_string(),
            openvpn_path: "/srv/ovpn".to_string(),
            ..base()
        };
        assert_eq!(compose_contents(&input), fixture("vpn-custompaths-public-en__docker-compose.yml"));
    }

    /// The seven script-derived scenarios all carry the park's one
    /// configuration (port 51821, default paths) — worth pinning anyway,
    /// because these are the bytes a real server received.
    ///
    /// **The one byte of difference is real and deliberate.** These fixtures
    /// are heredoc BODIES, and `cat > file <<'EOF'` terminates the last line,
    /// so the file bash leaves on disk ends with a newline while the Swift
    /// string it came from does not. This port writes the Swift string, the
    /// same as every service slice since 4.2 — harmless for YAML and for a
    /// Caddyfile, and stated here rather than hidden behind a trimming
    /// comparison that would also hide a real trailing-content change.
    #[test]
    fn compose_matches_the_bytes_a_real_generated_script_wrote() {
        let input = Input { wireguard_vpn_port: 51821, ..base() };
        for scenario in [
            "vpn-wg-public-en",
            "vpn-awg-public-en",
            "vpn-ss-public-en",
            "vpn-xray-public-en",
            "vpn-ovpn-public-en",
            "vpn-mirrored-public-en",
            "vpn-relay-home-en",
        ] {
            assert_eq!(
                format!("{}\n", compose_contents(&input)),
                fixture(&format!("{scenario}__docker-compose.yml")),
                "{scenario}"
            );
        }
    }

    #[test]
    fn hostname_and_dns_records_match_the_generator() {
        assert_eq!(hostname(&base()), fixture("vpn-default-public-en__hostname.txt"));
        assert_eq!(dns_hostnames(&base()).join("\n"), fixture("vpn-default-public-en__dns-hostnames.txt"));

        let custom = Input { vpn_hostname: "tunnel.example.com".to_string(), ..base() };
        assert_eq!(hostname(&custom), fixture("vpn-customhost-mirrored-public-en__hostname.txt"));
    }

    #[test]
    fn caddy_site_matches_the_generator_on_defaults_and_on_mirrors() {
        assert_eq!(caddy_site(&base()), fixture("vpn-default-public-en__caddy-site.txt"));

        let mirrored = Input {
            vpn_hostname: "tunnel.example.com".to_string(),
            additional_domains: vec!["example.org".to_string(), "example.net".to_string()],
            ..base()
        };
        assert_eq!(
            caddy_site_names(&mirrored).join(", "),
            fixture("vpn-customhost-mirrored-public-en__caddy-site-names.txt")
        );
        assert_eq!(caddy_site(&mirrored), fixture("vpn-customhost-mirrored-public-en__caddy-site.txt"));
    }

    /// The mirroring guard: a panel hostname outside the deployment's domains
    /// must NOT be mirrored onto them. A site asking for a certificate for a
    /// name nobody owns fails ACME forever and burns the whole deployment's
    /// failure quota — the one invariant срез 4.1 had to add a seventh
    /// scenario for.
    #[test]
    fn a_foreign_panel_hostname_is_never_mirrored_onto_the_deployments_domains() {
        let input = Input {
            vpn_hostname: "vpn.other-company.net".to_string(),
            additional_domains: vec!["example.org".to_string()],
            ..base()
        };
        assert_eq!(
            caddy_site_names(&input).join(", "),
            fixture("vpn-foreignhost-mirrored-public-en__caddy-site-names.txt")
        );
        assert_eq!(caddy_site(&input), fixture("vpn-foreignhost-mirrored-public-en__caddy-site.txt"));
    }

    #[test]
    fn the_mirrored_script_scenario_reproduces_its_caddy_site() {
        let input = Input {
            additional_domains: vec!["example.org".to_string(), "example.net".to_string()],
            wireguard_vpn_port: 51821,
            ..base()
        };
        // Same heredoc newline as the compose fixtures above.
        assert_eq!(format!("{}\n", caddy_site(&input)), fixture("vpn-mirrored-public-en__caddy-site.txt"));
    }

    // ─────────────────────────── services.json ───────────────────────────

    /// One fixture per protocol, each from a real generated script. This is
    /// the only artifact whose generator function is private on the Swift
    /// side, so these bytes are the only description of it there is.
    #[test]
    fn services_json_matches_the_generator_for_every_protocol() {
        for (protocol, scenario, port) in [
            (Protocol::WireGuard, "vpn-wg-public-en", 51821),
            (Protocol::AmneziaWG, "vpn-awg-public-en", 51822),
            (Protocol::Shadowsocks, "vpn-ss-public-en", 8388),
            (Protocol::XrayReality, "vpn-xray-public-en", 8443),
            (Protocol::OpenVPN, "vpn-ovpn-public-en", 1194),
        ] {
            let input = Input {
                wireguard_vpn_port: port,
                amnezia_wg_port: port,
                shadowsocks_port: port,
                xray_reality_port: port,
                openvpn_port: port,
                ..base()
            };
            assert_eq!(
                services_json(&input, &[protocol]),
                fixture(&format!("{scenario}__services.json")),
                "{scenario}"
            );
        }
    }

    /// No generated scenario in the park ever selects two protocols at once,
    /// so the join and the ENTRY ORDER cannot be fixture-verified — they are
    /// pinned here instead, against the generator's own `add(…)` sequence.
    /// Each entry's bytes are already proven by the per-protocol fixtures
    /// above; this is the seam between them.
    #[test]
    fn multiple_protocols_are_joined_in_the_generators_own_order() {
        let input = base();
        let json = services_json(&input, &[Protocol::OpenVPN, Protocol::WireGuard, Protocol::Shadowsocks]);
        let wireguard = json.find("\"wireguard\"").expect("wireguard entry");
        let shadowsocks = json.find("\"shadowsocks\"").expect("shadowsocks entry");
        let openvpn = json.find("\"openvpn\"").expect("openvpn entry");
        assert!(wireguard < shadowsocks && shadowsocks < openvpn, "{json}");
        assert_eq!(json.matches("},{").count(), 2, "entries are joined with a bare comma: {json}");
        assert!(!json.contains("amnezia"), "an unselected protocol must not appear: {json}");
    }

    #[test]
    fn no_protocol_at_all_is_the_empty_registry_the_setup_script_seeds() {
        assert_eq!(services_json(&base(), &[]), "{\"services\":[]}\n");
    }

    // ─────────────────────────── .env ───────────────────────────

    #[test]
    fn env_matches_the_block_the_setup_script_actually_runs() {
        // The fixture was produced by RUNNING the generated printf block in
        // bash with the runtime-generated password stubbed — not by reading
        // the script and typing out what it looks like it would print.
        let input = Input { wireguard_vpn_port: 51821, ..base() };
        assert_eq!(env_contents(&input, "__PW__"), fixture("vpn-wg-public-en__env.txt"));
    }

    #[test]
    fn env_tracks_the_admin_username_and_the_custom_hostname() {
        let input = Input {
            admin_username: "operator".to_string(),
            vpn_hostname: "tunnel.example.com".to_string(),
            wireguard_vpn_port: 51999,
            ..base()
        };
        assert_eq!(
            env_contents(&input, "deadbeef"),
            "ADMIN_USER=operator\nADMIN_PASSWORD=deadbeef\nWG_HOST=tunnel.example.com\nWG_PORT=51999\nWG_SUBNET=10.9.0.0/24\n"
        );
    }

    // ─────────────────────────── firewall ports ───────────────────────────

    #[test]
    fn each_protocol_declares_the_ports_its_swift_service_declares() {
        use super::super::super::firewall::Port;
        let input = base();
        assert_eq!(Protocol::WireGuard.firewall_ports(&input), vec![Port::udp(51820)]);
        assert_eq!(Protocol::AmneziaWG.firewall_ports(&input), vec![Port::udp(51822)]);
        assert_eq!(Protocol::OpenVPN.firewall_ports(&input), vec![Port::udp(1194)]);
        assert_eq!(Protocol::XrayReality.firewall_ports(&input), vec![Port::tcp(8443)]);
        // Shadowsocks answers on both transports on the same port.
        assert_eq!(Protocol::Shadowsocks.firewall_ports(&input), vec![Port::tcp(8388), Port::udp(8388)]);
    }
}

#[cfg(test)]
mod client_access_tests {
    use super::*;

    fn input(access: &str) -> Input {
        Input {
            domain: "example.com".to_string(),
            vpn_client_access: access.to_string(),
            ..Input::default()
        }
    }

    /// The default and every deployment older than the setting publish the
    /// page, exactly as before.
    #[test]
    fn both_and_panel_publish_the_page() {
        for access in ["both", "panel", "", "something-a-newer-app-sent"] {
            assert!(publishes_site(&input(access)), "{access} must publish");
            assert!(!caddy_site(&input(access)).is_empty());
            assert_eq!(caddy_site_names(&input(access)), vec!["vpn.example.com"]);
        }
    }

    /// App-only drops the site AND its name together. Either one alone is the
    /// documented way to burn an ACME failure quota: a name nothing answers on,
    /// or a site whose name does not resolve.
    #[test]
    fn app_only_drops_the_site_and_its_name_together() {
        let input = input("app");
        assert!(!publishes_site(&input));
        assert!(caddy_site(&input).is_empty());
        assert!(caddy_site_names(&input).is_empty());
    }
}
