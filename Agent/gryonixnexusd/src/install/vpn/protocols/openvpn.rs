//! OpenVPN — the classic UDP VPN, and the only protocol here whose image is
//! BUILT on the server.
//!
//! **Why a local build.** The previously pinned `kylemanna/openvpn:2.4` ships
//! amd64-only and dies with "exec format error" on ARM hosts, and no
//! trustworthy multi-arch drop-in exists. Both routes therefore write a
//! Dockerfile plus three shims and run `docker build`, exactly as the VPN
//! panel does for `gryonix-vpn-panel:local`. Two consequences the port has to
//! respect: there is no registry to pull from (`UpdateSpec.builtOnServer`), and
//! the build inputs are rewritten on EVERY run, because a re-run is the only
//! way a newer generation reaches the host.
//!
//! **The shims are a contract with the panel, not internal detail.** The
//! unified VPN panel manages OpenVPN clients by `docker exec`-ing
//! `ovpn_getclient` / `ovpn_revokeclient` — kylemanna-compatible names it
//! already speaks. Renaming or "improving" them here would break client CRUD
//! in the panel while every test still passed, which is why they are ported
//! byte-for-byte from the real generated script rather than rewritten.
//!
//! **The client profile is captured stdout, and that is a GOTCHA, not a
//! style choice.** The generator writes `docker run … ovpn_getclient … >
//! <name>.ovpn`, and the shell creates that file BEFORE the command runs — a
//! failed run leaves an EMPTY profile, and the existence of the PKI is the
//! guard for the whole step, so the next run keeps it. The agent captures
//! stdout and writes the file only when the run succeeded and produced
//! something, the same fix `install::psono` made for `settings.yaml`.

use crate::install::context::Input;

/// `OpenVPNService.composeProject`.
pub const COMPOSE_PROJECT: &str = "openvpn";

/// `OpenVPNService.containerName`, pinned for the dashboard's restart literal.
pub const CONTAINER: &str = "openvpn";

/// Built on the server from [`DOCKERFILE`] — no registry holds this tag.
pub const IMAGE: &str = "gryonix-openvpn:local";

/// The client certificate common name baked into the profile the install
/// mints. The report prints the file by this name.
pub const CLIENT_NAME: &str = "gryonixnexus";

/// Tunnel-internal subnet — assigned, not chosen: 10.8 is the scenario-B
/// relay, 10.9 the panel's WireGuard, 10.10 AmneziaWG.
const SUBNET: &str = "10.11.0.0";

/// The host directory, from settings.
pub fn dir(input: &Input) -> &str {
    &input.openvpn_path
}

/// Where the PKI and the server config live — mounted as the container's
/// `/etc/openvpn`.
pub fn data_dir(input: &Input) -> String {
    format!("{}/data", dir(input))
}

/// The image build context.
pub fn build_dir(input: &Input) -> String {
    format!("{}/build", dir(input))
}

/// The CA certificate whose presence is the whole first-run guard: if it
/// exists, the PKI, the tls-crypt key, the server config and the client
/// profile were all built already.
pub fn ca_path(input: &Input) -> String {
    format!("{}/pki/ca.crt", data_dir(input))
}

/// The ready-to-import client profile the report prints inline.
pub fn client_profile_path(input: &Input) -> String {
    format!("{}/{CLIENT_NAME}.ovpn", dir(input))
}

/// A port of `OpenVPNService.composeFile`.
pub fn compose_contents(input: &Input) -> String {
    let path = dir(input);
    let port = input.openvpn_port;
    format!(
        "services:
  openvpn:
    image: {IMAGE}
    container_name: {CONTAINER}
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    sysctls:
      - net.ipv4.ip_forward=1
    volumes:
      - {path}/data:/etc/openvpn
    ports:
      - \"{port}:1194/udp\""
    )
}

/// The image build context: the Dockerfile and the three shims, by file name.
///
/// Fixed content — none of it interpolates anything from the request, which
/// the parity suite measures rather than assumes.
pub fn build_files() -> [(&'static str, &'static str); 4] {
    [
        ("Dockerfile", DOCKERFILE),
        ("gryonix-ovpn-run", RUN_SCRIPT),
        ("ovpn_getclient", GET_CLIENT),
        ("ovpn_revokeclient", REVOKE_CLIENT),
    ]
}

const DOCKERFILE: &str = "FROM alpine:3.22
RUN apk add --no-cache openvpn easy-rsa iptables openssl
ENV OPENVPN=/etc/openvpn \\
    EASYRSA=/usr/share/easy-rsa \\
    EASYRSA_PKI=/etc/openvpn/pki \\
    EASYRSA_ALGO=ec \\
    EASYRSA_CURVE=prime256v1 \\
    EASYRSA_CRL_DAYS=3650 \\
    EASYRSA_BATCH=1
RUN ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin/easyrsa
COPY ovpn_getclient ovpn_revokeclient gryonix-ovpn-run /usr/local/bin/
RUN chmod +x /usr/local/bin/ovpn_getclient /usr/local/bin/ovpn_revokeclient /usr/local/bin/gryonix-ovpn-run
CMD [\"gryonix-ovpn-run\"]
";

/// The container's entrypoint: a tun node and NAT for the tunnel subnet, then
/// the daemon. `mknod` is there because the device is not always present in
/// the container's `/dev`, and the NAT rule is added idempotently (`-C` then
/// `-A`) because the container restarts.
const RUN_SCRIPT: &str = "#!/bin/sh
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
iptables -t nat -C POSTROUTING -s 10.11.0.0/24 -j MASQUERADE 2>/dev/null || \\
  iptables -t nat -A POSTROUTING -s 10.11.0.0/24 -j MASQUERADE
exec openvpn --config /etc/openvpn/server.conf
";

/// kylemanna-compatible: prints a self-contained profile to stdout. The
/// endpoint comes from `gryonix-env`, written at install time, so the profile
/// this prints tomorrow still names the right host and port.
const GET_CLIENT: &str = "#!/bin/sh
set -eu
CN=\"$1\"
PKI=/etc/openvpn/pki
. /etc/openvpn/gryonix-env
cat <<PROFILE
client
dev tun
proto udp
remote $OVPN_HOST $OVPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verb 3
<ca>
$(cat \"$PKI/ca.crt\")
</ca>
<cert>
$(openssl x509 -in \"$PKI/issued/$CN.crt\")
</cert>
<key>
$(cat \"$PKI/private/$CN.key\")
</key>
<tls-crypt>
$(cat /etc/openvpn/tc.key)
</tls-crypt>
PROFILE
";

/// kylemanna-compatible: revoke plus a fresh CRL. `remove` also deletes the
/// client's files — the `index.txt` entry flips to `R`, which is what hides it
/// from the panel's client list.
const REVOKE_CLIENT: &str = "#!/bin/sh
set -eu
CN=\"$1\"
PKI=/etc/openvpn/pki
easyrsa revoke \"$CN\"
easyrsa gen-crl
cp -f \"$PKI/crl.pem\" /etc/openvpn/crl.pem
chmod 644 /etc/openvpn/crl.pem
if [ \"${2:-}\" = \"remove\" ]; then
  rm -f \"$PKI/issued/$CN.crt\" \"$PKI/private/$CN.key\" \"$PKI/reqs/$CN.req\"
fi
";

/// The endpoint the profile dials — the panel's hostname rule, and also the
/// server certificate's common name.
pub fn hostname(input: &Input) -> String {
    super::super::panel::hostname(input)
}

/// `data/gryonix-env` — the two values `ovpn_getclient` sources.
///
/// The PORT here is the HOST-side port, not the container's 1194: the profile
/// tells a client where to dial from the internet.
pub fn gryonix_env(input: &Input) -> String {
    format!("OVPN_HOST={}\nOVPN_PORT={}\n", hostname(input), input.openvpn_port)
}

/// A port of the `EOF_OVPN_SERVER` heredoc.
///
/// `port 1194` is the CONTAINER's port and never moves; the host-side port is
/// a compose publication. The certificate paths carry the hostname because
/// that is the common name the PKI step issues them under.
pub fn server_conf(input: &Input) -> String {
    let host = hostname(input);
    format!(
        "# Managed by gryonixNexus — OpenVPN server (container-internal port 1194).
server {SUBNET} 255.255.255.0
topology subnet
port 1194
proto udp
dev tun
ca /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/issued/{host}.crt
key /etc/openvpn/pki/private/{host}.key
dh none
ecdh-curve prime256v1
tls-crypt /etc/openvpn/tc.key
crl-verify /etc/openvpn/crl.pem
keepalive 10 60
persist-key
persist-tun
user nobody
group nobody
push \"redirect-gateway def1\"
push \"dhcp-option DNS 1.1.1.1\"
push \"dhcp-option DNS 1.0.0.1\"
explicit-exit-notify 1
verb 3
"
    )
}

/// The one-shot the PKI is built by, as the `sh -c` script the container runs.
///
/// Still a shell script, and deliberately so: it is the IMAGE's shell, not the
/// host's — `easyrsa` is a sequence of eight dependent commands inside the
/// container, and eight `docker run`s would be eight fresh containers. The
/// agent's no-shell rule is about the HOST.
pub fn pki_script(input: &Input) -> String {
    let host = hostname(input);
    format!(
        "
    set -eu
    easyrsa init-pki
    easyrsa build-ca nopass
    easyrsa --san=DNS:{host} build-server-full {host} nopass
    easyrsa build-client-full {CLIENT_NAME} nopass
    easyrsa gen-crl
    cp -f /etc/openvpn/pki/crl.pem /etc/openvpn/crl.pem
    chmod 644 /etc/openvpn/crl.pem
    openvpn --genkey secret /etc/openvpn/tc.key
  "
    )
}

#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::install::vpn::protocols::tests_support::{fixture, heredoc_body, scenario_input};

    /// The `sh -c "…"` body out of the fixture: everything between the opening
    /// quote at the end of the `docker run` line and the closing quote on its
    /// own line.
    fn pki_script_from_fixture(steps: &str) -> String {
        let mut lines = steps.lines();
        loop {
            let line = lines.next().expect("the steps must run the PKI one-shot");
            if line.contains("sh -c \"") {
                break;
            }
        }
        let mut body = String::from("\n");
        for line in lines {
            // The closing quote sits at the end of the last line, and the
            // indentation BEFORE it is part of the script the container runs —
            // dropping it would compare two strings that differ by two spaces
            // and call that parity.
            if let Some(prefix) = line.strip_suffix('"') {
                if prefix.trim().is_empty() {
                    body.push_str(prefix);
                    return body;
                }
            }
            body.push_str(line);
            body.push('\n');
        }
        panic!("the sh -c body is never closed");
    }

    /// `printf 'OVPN_HOST=%s\nOVPN_PORT=%s\n' 'host' 'port'`, read out of the
    /// fixture rather than re-derived from the Swift source.
    fn env_from_fixture(steps: &str) -> String {
        let line = steps
            .lines()
            .find(|line| line.trim_start().starts_with("printf 'OVPN_HOST="))
            .expect("the steps must write gryonix-env");
        let (format, args) = line
            .trim_start()
            .trim_start_matches("printf '")
            .split_once("' ")
            .expect("a quoted format followed by arguments");
        let values: Vec<String> = args
            .split_once('>')
            .map(|(args, _redirect)| args)
            .unwrap_or(args)
            .split_whitespace()
            .map(|token| token.trim_matches('\'').to_string())
            .collect();
        let mut out = String::new();
        let mut values = values.into_iter();
        let mut rest = format;
        while let Some(at) = rest.find("%s") {
            out.push_str(&rest[..at]);
            out.push_str(&values.next().expect("one value per %s"));
            rest = &rest[at + 2..];
        }
        out.push_str(rest);
        out.replace("\\n", "\n")
    }

    fn assert_parity(scenario: &str) {
        let input = scenario_input(scenario);
        let steps = fixture(&format!("ovpn-{scenario}__setup-steps.txt"));
        assert_eq!(
            compose_contents(&input),
            fixture(&format!("ovpn-{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            dir(&input),
            fixture(&format!("ovpn-{scenario}__compose-directory.txt")),
            "{scenario}: compose directory"
        );
        for (name, delimiter) in [
            ("Dockerfile", "EOF_OVPN_DOCKERFILE"),
            ("gryonix-ovpn-run", "EOF_OVPN_RUN"),
            ("ovpn_getclient", "EOF_OVPN_GETCLIENT"),
            ("ovpn_revokeclient", "EOF_OVPN_REVOKE"),
        ] {
            let ours = build_files()
                .into_iter()
                .find(|(candidate, _)| *candidate == name)
                .unwrap_or_else(|| panic!("{name} must be one of the build files"))
                .1;
            assert_eq!(ours, heredoc_body(&steps, delimiter), "{scenario}: build/{name}");
        }
        assert_eq!(
            server_conf(&input),
            heredoc_body(&steps, "EOF_OVPN_SERVER"),
            "{scenario}: data/server.conf"
        );
        assert_eq!(gryonix_env(&input), env_from_fixture(&steps), "{scenario}: data/gryonix-env");
        assert_eq!(pki_script(&input), pki_script_from_fixture(&steps), "{scenario}: the PKI one-shot");
    }

    #[test]
    fn default_public_en() {
        assert_parity("default-public-en");
    }

    #[test]
    fn custompaths_public_en() {
        assert_parity("custompaths-public-en");
    }

    /// One setting, four files: the certificate common name in `server.conf`,
    /// the `--san` and both subjects in the PKI script, and the endpoint in
    /// `gryonix-env`.
    #[test]
    fn customhost_public_en() {
        assert_parity("customhost-public-en");
        let input = scenario_input("customhost-public-en");
        assert!(server_conf(&input).contains("issued/tunnel.example.com.crt"));
        assert!(pki_script(&input).contains("--san=DNS:tunnel.example.com"));
        assert!(gryonix_env(&input).starts_with("OVPN_HOST=tunnel.example.com\n"));
    }

    /// The build context carries nothing from the request — measured, because
    /// "these files are static" is exactly the kind of claim that stops being
    /// true without anyone noticing.
    #[test]
    fn the_build_context_is_the_same_in_every_scenario() {
        for scenario in [
            "default-public-en",
            "custompaths-public-en",
            "customhost-public-en",
            "customsni-public-en",
            "default-public-ru",
        ] {
            let steps = fixture(&format!("ovpn-{scenario}__setup-steps.txt"));
            assert_eq!(DOCKERFILE, heredoc_body(&steps, "EOF_OVPN_DOCKERFILE"), "{scenario}");
            assert_eq!(RUN_SCRIPT, heredoc_body(&steps, "EOF_OVPN_RUN"), "{scenario}");
            assert_eq!(GET_CLIENT, heredoc_body(&steps, "EOF_OVPN_GETCLIENT"), "{scenario}");
            assert_eq!(REVOKE_CLIENT, heredoc_body(&steps, "EOF_OVPN_REVOKE"), "{scenario}");
        }
    }

    #[test]
    fn default_public_ru() {
        assert_parity("default-public-ru");
        let en = scenario_input("default-public-en");
        let ru = scenario_input("default-public-ru");
        assert_eq!(compose_contents(&en), compose_contents(&ru));
        assert_eq!(server_conf(&en), server_conf(&ru));
        assert_eq!(pki_script(&en), pki_script(&ru));
    }
}
