//! Scenario B's routing halves: the relay's DNAT/forward/SNAT ruleset, and the
//! home half's connection marks.
//!
//! **What was missing and why it mattered.** `firewall_base` gives a host with
//! no ruleset the smallest working one — SSH, HTTP/HTTPS, the drop-in surface.
//! That is the whole answer for a single host, and it is the WRONG answer for
//! either half of scenario B: the relay's job IS forwarding (it needs a forward
//! chain, DNAT into the tunnel, a masquerade for the home half's egress and a
//! separate SNAT for hairpinned VPN clients), and the home half needs the
//! connection marks that send a relayed reply back through the tunnel instead of
//! out its own ISP. Both were generated ONLY by the setup script, so a pair
//! built by the agent alone could not relay anything — the last structural gap
//! in "the agent replaces both setup scripts".
//!
//! Two things this must NOT copy from `NftablesConfig`, each for a reason the
//! project already paid for:
//!
//! - **`flush ruleset` stays out.** The setup script can afford it because it
//!   restarts docker straight afterwards; the agent installs onto a machine with
//!   live containers, and flushing erases docker's own NAT (GOTCHAS.md). Our
//!   filter table is replaced with `destroy table inet filter`, exactly as
//!   `firewall_base` does.
//! - **The NAT rules go in a table of OUR OWN**, `ip gryonixnexus_nat`, never
//!   docker's `ip nat`. Writing into `ip nat` would either duplicate rules on
//!   every re-apply or require flushing a table docker owns. A separate table is
//!   safe HERE and not for filtering: the reason ARCHITECTURE.md forbids a
//!   separate table for opening ports is that one `drop` verdict anywhere is
//!   final, so an `accept` elsewhere cannot undo a `policy drop` — NAT has no
//!   drop, every chain at the hook is offered the packet, and the first NAT
//!   expression that matches wins. docker's own DNAT only matches its published
//!   ports, and the relay's only matches the deployment's forwarded ones.
//!
//! And one thing it must not INVENT: the public interface. The setup script
//! leaves `@PUB_IF@` in the file and seds it at install time; the agent has no
//! sed step, so it asks the kernel (`ip route get`) and writes the real name.
//!
//! **Verification.** Not byte-parity — the deviations above make the files
//! deliberately different — but a rule-for-rule comparison against the REAL
//! Swift artifact: `tests/fixtures/relay/` holds the `EOF_NFT` heredoc bodies
//! extracted from generated scenario-B scripts, and the tests demand that every
//! rule line in them appears here (with `$pub_if` resolved and the NAT table
//! renamed) and that nothing extra is added. The sysctl files ARE byte-parity —
//! they land verbatim and have nothing to deviate about.

use std::fmt::Write as _;

use super::execute::EventSink;
use super::firewall;

/// The tunnel's interface name. `WireGuardDefaults.interfaceName` on the Swift
/// side; a constant on both, because the pair's config is generated, never
/// discovered.
pub const WG_INTERFACE: &str = "wg0";

/// SSH, as the base ruleset also spells it. The agent has no `SecurityPolicy` to
/// read a custom port from — `Input` carries none — so a deployment that moved
/// sshd would need that field before this could follow it. Stated rather than
/// silently assumed: a relay ruleset that closed the real SSH port would lock
/// the operator out of the one host they cannot reach any other way.
pub const SSH_PORT: u16 = 22;

/// One machine this relay forwards to.
///
/// **Scenario B has exactly one, and that is why the model had none.** A relay
/// serving several backends needs the ports to say WHICH one they belong to —
/// DNAT can send a port to one place, so two backends cannot share it, and the
/// singular `home_ip` could not express that at all.
///
/// The rendering keeps the first peer on the `$home_ip` variable, so a
/// two-machine deployment produces the file it always did, byte for byte. That
/// is not tidiness: the production relay's ruleset is left alone only while it
/// keeps the right shape, and a gratuitous rename would be a rewrite of a live
/// firewall to say the same thing.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Peer {
    /// Its address inside the tunnel — the DNAT destination.
    pub ip: String,
    /// TCP ports DNATed to THIS peer.
    pub tcp_ports: Vec<u16>,
    /// UDP ports DNATed to this peer — a VPN protocol's, always.
    pub udp_ports: Vec<u16>,
}

impl Peer {
    /// The nftables variable holding this peer's address. The first keeps the
    /// name scenario B has always used.
    fn var(index: usize) -> String {
        if index == 0 { "home_ip".to_string() } else { format!("peer{}_ip", index + 1) }
    }
}

/// Everything the relay's ruleset needs and cannot see for itself.
///
/// All of it is deployment knowledge, which is why it rides in the request
/// alongside `host_role`: the relay carries no services, so nothing on the host
/// says which ports are forwarded, and a live `wg0` says nothing about whose it
/// is (the proto's own comment on `host_role` explains that at length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topology {
    /// Every machine this relay forwards to, in the order the request named
    /// them. Scenario B sends exactly one.
    pub peers: Vec<Peer>,
    /// The relay's own public address, so hairpinned tunnel traffic aimed at it
    /// is recognised. Pinned deliberately: without the `ip daddr` match, relayed
    /// client traffic to ARBITRARY sites on these ports would be DNATed home.
    pub vps_public: String,
    /// The relay's WireGuard listen port. Accepted on input, and nothing else on
    /// this host is — measured 2026-08-13 on the production relay, whose ruleset
    /// had no accept for it at all: the tunnel was alive only because a keepalive
    /// kept renewing a conntrack entry, and a NEW peer could not hand-shake.
    pub wg_port: u16,
}

impl Topology {
    /// Scenario B, spelled the way it always was: one peer.
    ///
    /// Kept as a constructor rather than as a second shape, so there is one
    /// model and the two-machine case is a value of it.
    pub fn single(home_ip: String, vps_public: String, wg_port: u16, tcp: Vec<u16>, udp: Vec<u16>) -> Self {
        Topology {
            peers: vec![Peer { ip: home_ip, tcp_ports: tcp, udp_ports: udp }],
            vps_public,
            wg_port,
        }
    }

    /// The first peer's address. Several things below are anchored on it — the
    /// tunnel's subnet, the hairpin source — because every peer sits in the one
    /// /24 the tunnel owns.
    pub fn home_ip(&self) -> &str {
        self.peers.first().map(|p| p.ip.as_str()).unwrap_or("")
    }

    /// Every forwarded TCP port, across all peers.
    ///
    /// The HOME half reads these: from where it sits, a port either arrives
    /// through the tunnel or it does not, and which sibling a relay sends the
    /// others to is not its business. `has_port_collision` guarantees no port
    /// appears twice, so the union loses nothing.
    pub fn all_tcp_ports(&self) -> Vec<u16> {
        self.peers.iter().flat_map(|p| p.tcp_ports.iter().copied()).collect()
    }

    pub fn all_udp_ports(&self) -> Vec<u16> {
        self.peers.iter().flat_map(|p| p.udp_ports.iter().copied()).collect()
    }

    /// Every peer with the nftables variable that holds its address.
    fn addressed(&self) -> Vec<(String, &Peer)> {
        self.peers.iter().enumerate().map(|(i, peer)| (Peer::var(i), peer)).collect()
    }

    /// Is there enough here to write a relay ruleset at all?
    ///
    /// **A relay must never get the BASE ruleset as a fallback.** The base opens
    /// 22/80/443 and nothing else, so on a relay it would close the tunnel port
    /// and cut the deployment in half — a worse outcome than leaving the host's
    /// firewall exactly as it was and saying so.
    ///
    /// With several peers the bar is the same for each: a peer with no address
    /// or no forwarded TCP port cannot be DNATed to, and half a relay is worse
    /// than none.
    pub fn is_complete(&self) -> bool {
        !self.peers.is_empty()
            && !self.vps_public.is_empty()
            && self.wg_port > 0
            && self.peers.iter().all(|p| !p.ip.is_empty() && !p.tcp_ports.is_empty())
            && !self.has_port_collision()
    }

    /// **Two peers cannot share a forwarded port.** DNAT sends a port to ONE
    /// place, so a second claim on it is not a preference the ruleset can
    /// express — it is a rule that silently never matches. Refused rather than
    /// rendered, which is the same call the Swift validator makes for two
    /// services claiming one UDP port.
    pub fn has_port_collision(&self) -> bool {
        let mut tcp: Vec<u16> = Vec::new();
        let mut udp: Vec<u16> = Vec::new();
        for peer in &self.peers {
            for port in &peer.tcp_ports {
                if tcp.contains(port) {
                    return true;
                }
                tcp.push(*port);
            }
            for port in &peer.udp_ports {
                if udp.contains(port) {
                    return true;
                }
                udp.push(*port);
            }
        }
        false
    }

    /// The tunnel's /24, derived from the home address.
    ///
    /// Swift derives it from the VPS's own tunnel address instead; both halves
    /// are in one /24 by construction (the app hands out `.1` and `.2` of the
    /// same subnet), so the answer is the same and this needs no extra field.
    pub fn subnet(&self) -> String {
        format!("{}.0/24", octets_prefix(self.home_ip()))
    }

    /// The distinct SNAT source for hairpinned VPN-client flows: same /24 as the
    /// home half, host `.254`, which the app never auto-assigns.
    ///
    /// Its whole purpose is to stay APART from the relay masquerade, so the
    /// home admin-guard can allow a VPN client while blocking a relayed public
    /// visitor — both otherwise arrive with the same source address and the
    /// guard, which sees only L3, blocked everyone.
    pub fn hairpin_src(&self) -> String {
        format!("{}.254", octets_prefix(self.home_ip()))
    }
}

/// The first three octets of a dotted IPv4 address, or the address unchanged if
/// it does not look like one — a malformed address is the caller's to reject,
/// and silently producing a plausible-looking prefix from garbage would be worse.
fn octets_prefix(address: &str) -> String {
    let parts: Vec<&str> = address.split('.').collect();
    if parts.len() == 4 {
        parts[..3].join(".")
    } else {
        address.to_string()
    }
}

fn port_set(ports: &[u16]) -> String {
    ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
}

/// One rule per peer, indented to sit inside a chain body.
///
/// **The order is per PEER, not per protocol**, so a single-peer relay renders
/// exactly the lines it always did: its TCP rule then its UDP rule. A peer with
/// no UDP ports contributes no UDP line at all, which is what keeps scenario B
/// byte-identical whether or not a VPN is installed.
fn per_peer(
    topo: &Topology,
    tcp_line: impl Fn(&str, &str) -> String,
    udp_line: impl Fn(&str, &str) -> String,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    for (var, peer) in topo.addressed() {
        lines.push(tcp_line(&var, &port_set(&peer.tcp_ports)));
        if !peer.udp_ports.is_empty() {
            lines.push(udp_line(&var, &port_set(&peer.udp_ports)));
        }
    }
    lines.join("\n\x20       ")
}

/// The relay's ruleset: filter (input + forward) and our own NAT table.
pub fn relay_ruleset(topo: &Topology, pub_if: &str, drop_in_dir: &str) -> String {
    let wg = WG_INTERFACE;
    let chain = firewall::CHAIN;
    let mut out = String::new();
    let _ = write!(
        out,
        "#!/usr/sbin/nft -f\n\
         # Managed by gryonixNexus — written by the control-plane agent.\n\
         # Scenario B relay: firewall + DNAT of the deployment's ports into the\n\
         # tunnel, symmetric SNAT for the home half's egress.\n\
         #\n\
         # No `flush ruleset`: it would erase docker's NAT table and cut every\n\
         # container on this host off the network. Only our own tables are\n\
         # replaced, which is what makes re-applying this safe.\n\
         destroy table inet filter\n\
         destroy table ip {nat_table}\n\
         \n\
         define pub_if = \"{pub_if}\"\n\
{peer_defines}\
         define vps_public = {vps_public}\n\
         # A DISTINCT SNAT source for hairpinned VPN-client traffic, kept apart\n\
         # from the relay masquerade so the home admin guard can tell a VPN\n\
         # client from a relayed public visitor — both otherwise arrive with the\n\
         # same source and the guard, which sees only L3, blocked everyone.\n\
         define hairpin_src = {hairpin_src}\n\
         \n\
         table inet filter {{\n\
         \x20   # Filled by the agent when it installs a service that needs a\n\
         \x20   # port open (`flush chain` + `add rule`). Empty opens nothing.\n\
         \x20   chain {chain} {{\n\
         \x20   }}\n\
         \n\
         \x20   chain input {{\n\
         \x20       type filter hook input priority filter; policy drop;\n\
         \x20       iif \"lo\" accept\n\
         \x20       ct state established,related accept\n\
         \x20       ct state invalid drop\n\
         \x20       meta l4proto icmp icmp type {{ echo-request, destination-unreachable, time-exceeded, parameter-problem }} limit rate 10/second accept\n\
         \x20       meta l4proto ipv6-icmp accept\n\
         \x20       tcp dport {ssh} accept comment \"SSH\"\n\
         \x20       udp dport {wg_port} accept comment \"WireGuard\"\n\
         \x20       # The forwarded ports are NOT accepted here: that traffic is\n\
         \x20       # DNATed and only ever passes through the forward chain.\n\
         \x20       jump {chain}\n\
         \x20   }}\n\
         \n\
         \x20   # **MSS clamping, and it is not an optimisation.** Without it a\n\
         \x20   # relayed HTTPS connection completes its TCP handshake and then\n\
         \x20   # HANGS. Measured on the production pair 2026-08-13 by capturing\n\
         \x20   # on the home half's wg0: the client's TLS ClientHello arrived at\n\
         \x20   # sequence 1449 with the first 1448 bytes missing, and the home\n\
         \x20   # node answered with a SACK naming the hole. A public client\n\
         \x20   # sizes segments for ITS OWN path and knows nothing about a\n\
         \x20   # 1420-byte tunnel in the middle. Everything tested through this\n\
         \x20   # relay before then was small — an ACME challenge, an SMTP\n\
         \x20   # handshake — which is why nothing caught it.\n\
         \x20   #\n\
         \x20   # Its own chain at MANGLE priority: the filter chain below runs\n\
         \x20   # at filter priority and its verdicts would end traversal before\n\
         \x20   # an option rewrite could happen. `rt mtu` is the route's own\n\
         \x20   # MTU, so no number is hardcoded.\n\
         \x20   chain mangle_forward {{\n\
         \x20       type filter hook forward priority mangle; policy accept;\n\
         \x20       oifname \"{wg}\" tcp flags syn tcp option maxseg size set rt mtu\n\
         \x20       iifname \"{wg}\" tcp flags syn tcp option maxseg size set rt mtu\n\
         \x20   }}\n\
         \n\
         \x20   chain forward {{\n\
         \x20       # policy ACCEPT, and every drop below names an interface.\n\
         \x20       # nftables offers a forwarded packet to EVERY chain at this\n\
         \x20       # hook and one drop verdict anywhere is final, so a drop\n\
         \x20       # policy here would also veto docker's per-container accepts\n\
         \x20       # and leave containers with no network at all — which reads\n\
         \x20       # as \"docker is broken\". The other rulesets avoid that by\n\
         \x20       # declaring no forward chain; the relay cannot, its forward\n\
         \x20       # rules ARE the relay, so the default is inverted and the\n\
         \x20       # deny is spelled out for the paths this host routes.\n\
         \x20       type filter hook forward priority filter; policy accept;\n\
         \x20       iifname \"{wg}\" ct state invalid drop\n\
         \x20       oifname \"{wg}\" ct state invalid drop\n\
         \x20       ct state established,related accept\n\
         \x20       {relay_accepts}\n",
        relay_accepts = per_peer(
            topo,
            |var, ports| format!("iifname $pub_if oifname \"{wg}\" ip daddr ${var} tcp dport {{ {ports} }} accept"),
            |var, ports| format!("iifname $pub_if oifname \"{wg}\" ip daddr ${var} udp dport {{ {ports} }} accept"),
        ),
        nat_table = NAT_TABLE,
        ssh = SSH_PORT,
        wg_port = topo.wg_port,
        peer_defines = topo
            .addressed()
            .iter()
            .map(|(var, peer)| format!("         define {var} = {}\n", peer.ip))
            .collect::<String>(),
        vps_public = topo.vps_public,
        hairpin_src = topo.hairpin_src(),
    );
    let _ = write!(
        out,
        "\x20       # Hairpinned tunnel traffic to the deployment's own sites —\n\
         \x20       # DNATed back into the tunnel, so both interfaces are {wg}.\n\
         \x20       {hairpin_accepts}\n",
        hairpin_accepts = per_peer(
            topo,
            |var, ports| format!("iifname \"{wg}\" oifname \"{wg}\" ip daddr ${var} tcp dport {{ {ports} }} accept"),
            |var, ports| format!("iifname \"{wg}\" oifname \"{wg}\" ip daddr ${var} udp dport {{ {ports} }} accept"),
        ),
    );
    let _ = write!(
        out,
        "\x20       # Traffic the home half starts (outgoing mail, updates) —\n\
         \x20       # out through this relay.\n\
         \x20       iifname \"{wg}\" oifname $pub_if accept\n\
         \x20       # The deny the policy used to provide, restated for the two\n\
         \x20       # paths that need it: nothing else enters or leaves the\n\
         \x20       # tunnel, and this relay is not an open router between\n\
         \x20       # public interfaces. docker's bridges are named in neither,\n\
         \x20       # which is the point — no interface list to go stale.\n\
         \x20       iifname \"{wg}\" drop\n\
         \x20       oifname \"{wg}\" drop\n\
         \x20       iifname $pub_if oifname $pub_if drop\n\
         \x20   }}\n\
         }}\n\
         \n\
         # OUR OWN nat table, never docker's `ip nat`: replacing that one would\n\
         # take docker's published ports with it, and adding to it would\n\
         # duplicate these rules on every re-apply. Safe here and not for\n\
         # filtering — NAT has no drop verdict to be vetoed by.\n\
         table ip {nat_table} {{\n\
         \x20   chain prerouting {{\n\
         \x20       type nat hook prerouting priority dstnat;\n\
         \x20       {public_dnat}\n",
        nat_table = NAT_TABLE,
        public_dnat = per_peer(
            topo,
            |var, ports| format!("iifname $pub_if tcp dport {{ {ports} }} dnat to ${var}"),
            |var, ports| format!("iifname $pub_if udp dport {{ {ports} }} dnat to ${var}"),
        ),
    );
    let _ = writeln!(
        out,
        "\x20       {hairpin_dnat}",
        hairpin_dnat = per_peer(
            topo,
            |var, ports| {
                format!("iifname \"{wg}\" ip daddr $vps_public tcp dport {{ {ports} }} dnat to ${var}")
            },
            |var, ports| {
                format!("iifname \"{wg}\" ip daddr $vps_public udp dport {{ {ports} }} dnat to ${var}")
            },
        ),
    );
    let _ = write!(
        out,
        "\x20   }}\n\
         \x20   chain postrouting {{\n\
         \x20       type nat hook postrouting priority srcnat;\n\
         \x20       # First matching NAT wins, so the hairpin source precedes\n\
         \x20       # the masquerade below.\n\
         \x20       iifname \"{wg}\" oifname \"{wg}\" ip daddr $home_ip snat to $hairpin_src\n\
         \x20       # Relayed public traffic is deliberately NOT NATed: DNAT\n\
         \x20       # alone survives the round trip, so the real client IP rides\n\
         \x20       # all the way home instead of collapsing into this relay's\n\
         \x20       # tunnel address. The home half routes the reply back through\n\
         \x20       # the tunnel itself — see `relay_routes`.\n\
         \x20       oifname $pub_if ip saddr {subnet} masquerade\n\
         \x20   }}\n\
         }}\n\
         \n\
         include \"{drop_in_dir}/{glob}\"\n",
        subnet = topo.subnet(),
        glob = firewall::DROP_IN_GLOB,
    );
    out
}

/// Our NAT table's name. Not `nat`: that is docker's.
pub const NAT_TABLE: &str = "gryonixnexus_nat";

/// The home half's ruleset: the base one plus the two mark chains.
///
/// **The forwarded ports are accepted only from the tunnel, exactly as
/// `NftablesConfig.homeRuleset` writes them — but 22/80/443 stay
/// unconditional.** Two different requirements meet here. A home half whose
/// request carries the deployment's forwarded ports must accept them from the
/// tunnel or relayed mail dies at its own firewall (nukki, 2026-08-13: eight
/// such ports in its ruleset, and an early version of this function would have
/// dropped every one of them). And a request that carries NONE must still leave
/// Caddy reachable, or the very relaying this module exists for would be killed
/// by the file meant to enable it — hence the base's three, which are the only
/// ports a HOST process terminates here anyway (every service port is
/// docker-published, which the input chain does not control at all: measured
/// 2026-08-13).
/// Outbound SMTP leaves through the RELAY, not through the home ISP.
///
/// The relay proxies INBOUND mail (DNAT), and for a long time that was the
/// whole story — deliveries went out from the home connection directly.
/// Measured on the live pair 2026-08-14 against an independent authentication
/// verifier, that cost every outgoing message both checks a receiver looks at:
/// SPF **fail**, because the record is `v=spf1 mx -all` and the MX is the
/// RELAY's address rather than the house's, and `iprev` fail, because a home
/// connection's PTR is its ISP's dynamic name. With DMARC at `p=quarantine`
/// that is a deployment whose mail is quarantined by construction. The same
/// run with this mark in place reported `Source IP: <relay>` and SPF **pass**.
///
/// Nothing new is provisioned: it reuses the mark and the policy-routing table
/// the REPLY path already needs (`relay_routes`), which defaults via the
/// tunnel; the relay already accepts `iifname wg0 oifname <public>` and
/// masquerades `10.8.0.0/24` on the way out, and Docker's own masquerade
/// rewrites a container's source as it leaves through the tunnel interface, so
/// that rule matches.
///
/// `fib daddr type != local` is what keeps this off mail the host RECEIVES:
/// without it a LAN client's delivery to this very server would be marked too,
/// and its reply would go back through the tunnel to an address on the same
/// LAN. Port 25 only — submission (587/465) is inbound by definition.
const OUTBOUND_MAIL_MARK: &str = "\x20       # Outbound SMTP goes through the relay so it leaves from the\n\
                                  \x20       # address SPF authorises and PTR names; `!= local` keeps mail\n\
                                  \x20       # ARRIVING for this host out of it.\n\
                                  \x20       ct state new tcp dport 25 fib daddr type != local ct mark set 0x1\n";

/// The ports a home half's CURRENT file accepts from the tunnel.
///
/// Read back rather than remembered, because the question it answers is about
/// the host, not about us: "is this request about to remove something that is
/// keeping mail alive?" A home half accepts its forwarded ports only from the
/// tunnel, so those lines ARE the relayed services — the live pair carries
/// eight of them — and a request that names none would drop every one without
/// a word. That is the documented mine on this path
/// (`home_ruleset`'s own comment, nukki 2026-08-13); this is what lets the
/// caller be refused instead of obeyed.
pub fn tunnel_accepted_ports(conf: &str) -> Vec<u16> {
    let needle = format!("iifname \"{WG_INTERFACE}\"");
    let mut ports = Vec::new();
    for line in conf.lines() {
        let line = line.trim();
        if !line.starts_with(&needle) || !line.contains("dport") || !line.contains("accept") {
            continue;
        }
        let Some(open) = line.find('{') else { continue };
        let Some(close) = line[open..].find('}') else { continue };
        for piece in line[open + 1..open + close].split(',') {
            if let Ok(port) = piece.trim().parse::<u16>() {
                if !ports.contains(&port) {
                    ports.push(port);
                }
            }
        }
    }
    ports.sort_unstable();
    ports
}

pub fn home_ruleset(drop_in_dir: &str, topo: Option<&Topology>) -> String {
    let base = super::firewall_base::ruleset(drop_in_dir);
    let wg = WG_INTERFACE;
    // The forwarded ports, accepted ONLY from the tunnel — the shape
    // `NftablesConfig.homeRuleset` writes. Ports the base already opens are left
    // out rather than repeated: 80 and 443 are terminated by Caddy for LAN
    // traffic too, and an unconditional accept is what keeps a home half usable
    // from its own network.
    let tunnel_accepts = match topo {
        None => String::new(),
        Some(topo) => {
            // The UNION across peers: from this host's seat a port either
            // arrives through the tunnel or it does not, and which sibling a
            // relay sends the others to is not its business.
            let tcp: Vec<u16> = topo
                .all_tcp_ports()
                .into_iter()
                .filter(|port| !super::firewall_base::BASE_TCP_PORTS.contains(port))
                .collect();
            let mut lines = String::new();
            if !tcp.is_empty() {
                let _ = write!(
                    lines,
                    "\x20       iifname \"{wg}\" tcp dport {{ {} }} accept comment \"from the tunnel\"\n",
                    port_set(&tcp)
                );
            }
            let udp = topo.all_udp_ports();
            if !udp.is_empty() {
                let _ = write!(
                    lines,
                    "\x20       iifname \"{wg}\" udp dport {{ {} }} accept comment \"VPN clients\"\n",
                    port_set(&udp)
                );
            }
            lines
        }
    };
    let marks = format!(
        "\n\
         \x20   # Scenario B, home half. A relayed connection arrives from the\n\
         \x20   # tunnel with the REAL public client's source address, which\n\
         \x20   # nothing in the main routing table sends back through {wg}. The\n\
         \x20   # mark set here is what `relay_routes`' policy-routing table\n\
         \x20   # matches on.\n\
         \x20   chain prerouting {{\n\
         \x20       type filter hook prerouting priority mangle; policy accept;\n\
         \x20       ct state new iifname \"{wg}\" ct mark set 0x1\n\
         {OUTBOUND_MAIL_MARK}\
         \x20       # Restore the connection's mark onto every packet, both\n\
         \x20       # directions: `ct mark` alone is invisible to `ip rule`.\n\
         \x20       meta mark set ct mark\n\
         \x20   }}\n\
         \n\
         \x20   # Every relayed service here terminates in a LOCAL process\n\
         \x20   # (Caddy binds the host's address; the mail engines the same), so\n\
         \x20   # its replies are OUTPUT packets and the prerouting chain never\n\
         \x20   # sees them. Live-caught 2026-08-08: the request arrived marked\n\
         \x20   # and correct, Caddy's SYN-ACK carried no mark, fell through to\n\
         \x20   # the main table and never found the tunnel — the connection just\n\
         \x20   # hung. `type route hook output` is the kernel's own mechanism\n\
         \x20   # for re-running the route lookup after a mark changes.\n\
         \x20   chain output {{\n\
         \x20       type route hook output priority mangle; policy accept;\n\
         {OUTBOUND_MAIL_MARK}\
         \x20       meta mark set ct mark\n\
         \x20   }}\n\
         }}\n"
    );
    // The tunnel accepts go just before the jump that ends the input chain, so
    // they sit inside it and ahead of the drop-in chain — the same order the
    // generator writes.
    let jump = format!("\x20       jump {}\n", firewall::CHAIN);
    let base = match (tunnel_accepts.is_empty(), base.find(&jump)) {
        (false, Some(index)) => format!("{}{}{}", &base[..index], tunnel_accepts, &base[index..]),
        _ => base,
    };
    // The base file closes `table inet filter` on the last `}` before the
    // include; the chains go in ahead of it. Anchored on the closing brace at
    // column zero so it cannot match a chain's own.
    match base.rfind("}\n\ninclude ") {
        Some(index) => format!("{}{}{}", &base[..index], marks, &base[index + 2..]),
        // Should not happen — `firewall_base::ruleset` always ends that way, and
        // a test pins it. Returning the base unchanged is still a working
        // firewall, just without the marks, which the caller reports.
        None => base,
    }
}

/// sysctl for the relay: DNAT into the tunnel requires forwarding.
/// Byte-identical to `NftablesConfig.vpsSysctl` — it lands verbatim.
pub const RELAY_SYSCTL: &str = "\
# Managed by gryonixNexus — forwarding is mandatory: the VPS DNATs traffic into the tunnel.
net.ipv4.ip_forward = 1
# Loose rp_filter: strict mode may drop tunnel traffic.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
";

/// sysctl for the home half. No `ip_forward` — docker manages its own for its
/// bridges, and home does not route between two external interfaces.
/// Byte-identical to `NftablesConfig.homeSysctl`.
pub const HOME_SYSCTL: &str = "\
# Managed by gryonixNexus — loose rp_filter: relayed traffic arrives with a
# foreign source IP (the real public visitor, not a tunnel peer), which
# strict reverse-path filtering would otherwise drop as spoofed.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
";

/// Where each sysctl file goes — the same paths the setup script uses, because
/// the uninstall wrapper's cleanup globs already name them.
pub const RELAY_SYSCTL_PATH: &str = "/etc/sysctl.d/99-gryonixnexus-forwarding.conf";
pub const HOME_SYSCTL_PATH: &str = "/etc/sysctl.d/99-gryonixnexus-rpfilter.conf";

/// The public interface, as the kernel routes to the internet.
///
/// `ip route get` rather than "the first non-lo interface": a relay with several
/// addresses has exactly one default path, and that is the one the DNAT rules
/// have to name. Parsing is deliberately narrow — the `dev X` token — and any
/// surprise means no answer rather than a guess.
pub fn parse_public_interface(route_output: &str) -> Option<String> {
    let mut tokens = route_output.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next().map(str::to_string).filter(|name| !name.is_empty());
        }
    }
    None
}

/// Ask the kernel which interface reaches the internet.
///
/// Read-only, so it runs inside the sandbox like every other `ip`/`docker` query
/// in this crate — only the WRITES need the transient unit.
pub async fn public_interface() -> Option<String> {
    let output = tokio::process::Command::new(ip_bin()).args(["route", "get", "1.1.1.1"]).output().await.ok()?;
    if !output.status.success() {
        return None;
    }
    parse_public_interface(&String::from_utf8_lossy(&output.stdout))
}

/// Overridable for tests, the same technique `docker_bin`/`systemctl_bin` use.
fn ip_bin() -> String {
    std::env::var("GRYONIXNEXUSD_IP_BIN").unwrap_or_else(|_| "ip".to_string())
}

/// Write and apply this role's sysctl file.
///
/// **Not cosmetic on either half.** The relay cannot DNAT at all without
/// `ip_forward`, and the home half drops every relayed packet without loose
/// `rp_filter`: relayed traffic arrives carrying the REAL public client's source
/// address, which strict reverse-path filtering reads as spoofed. Both files sit
/// in `/etc/sysctl.d`, which `ProtectSystem=full` holds read-only for the agent,
/// so the write goes through a transient unit like every other `/etc` write.
///
/// Not fatal, for the same reason the firewall step is not: the services are up
/// by this point, and the step says exactly what did not happen.
pub(super) async fn apply_sysctl(path: &str, contents: &str, sink: &EventSink) -> Result<(), String> {
    let script = format!(
        "set -e\numask 022\ncat > '{path}' <<'GRYONIXNEXUS_SYSCTL_EOF'\n{contents}GRYONIXNEXUS_SYSCTL_EOF\n\
         chmod 0644 '{path}'\nsysctl -p '{path}' >/dev/null\n"
    );
    super::packages::run_outside_sandbox(&script, "applying the kernel network settings", sink).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The REAL relay ruleset from a generated scenario-B setup script (the
    /// `EOF_NFT` heredoc body of `setup-vps.sh`), with mail, a VPN and two
    /// domains selected. Extracted with
    /// `scratchpad/extract-heredoc-from-generated-script.sh`, which is how every
    /// host-half fixture in this crate is made.
    const SWIFT_RELAY: &str = include_str!("../../tests/fixtures/relay/vps.nft");
    const SWIFT_HOME: &str = include_str!("../../tests/fixtures/relay/home.nft");
    const SWIFT_RELAY_SYSCTL: &str = include_str!("../../tests/fixtures/relay/vps-sysctl.conf");
    const SWIFT_HOME_SYSCTL: &str = include_str!("../../tests/fixtures/relay/home-sysctl.conf");

    /// The fixture's own topology, read off the fixture rather than restated:
    /// 10.8.0.2 home, 203.0.113.10 public, 80/443 forwarded, one VPN UDP port.
    fn fixture_topology() -> Topology {
        Topology::single("10.8.0.2".into(), "203.0.113.10".into(), 51820, vec![80, 443], vec![51821])
    }

    /// Rules only: comments and blank lines dropped, whitespace collapsed.
    ///
    /// nft reads RULES, and the first version of the base module's own test
    /// failed on a comment that explained an absent rule (GOTCHAS.md). The same
    /// trap is worse here, where both files are mostly prose.
    fn rules(text: &str) -> Vec<String> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect()
    }

    /// The rules of one named chain, in order, from an already-flattened rule
    /// list. Everything from `chain <name> {` up to the line that closes it.
    ///
    /// Needed because a flat comparison of the whole file cannot see WHICH
    /// chain a rule sits in, and for the mark chains that is the entire point:
    /// `prerouting` never sees a locally-generated packet, `output` never sees
    /// a forwarded one, and the same rule text in the wrong one of the two does
    /// nothing at all.
    fn chain_rules(rules: &[String], name: &str) -> Vec<String> {
        let opener = format!("chain {name} {{");
        let mut out = Vec::new();
        let mut inside = false;
        for rule in rules {
            if rule == &opener {
                inside = true;
                continue;
            }
            if inside {
                if rule == "}" {
                    break;
                }
                out.push(rule.clone());
            }
        }
        out
    }

    /// The Swift artifact's rules, adjusted for the two deviations this module
    /// documents: no `flush ruleset`, and our own NAT table name.
    fn swift_rules_adjusted(text: &str) -> Vec<String> {
        rules(text)
            .into_iter()
            .filter(|line| line != "flush ruleset")
            .map(|line| line.replace("table ip nat {", &format!("table ip {NAT_TABLE} {{")))
            .collect()
    }

    /// **Every rule the setup script's relay ruleset has, this one has too.**
    ///
    /// The point of the whole module: a relay built by the agent has to route
    /// exactly what a relay built by setup routes. Comparing rule SETS rather
    /// than bytes is what lets the two files differ in the ways they must
    /// (`flush ruleset`, the NAT table name, the resolved interface) while
    /// pinning everything that decides where a packet goes.
    #[test]
    fn the_relay_routes_exactly_what_the_setup_script_routes() {
        let ours = relay_ruleset(&fixture_topology(), "@PUB_IF@", "/etc/nftables.d");
        let mine = rules(&ours);
        let theirs = swift_rules_adjusted(SWIFT_RELAY);
        for rule in &theirs {
            assert!(mine.contains(rule), "the relay ruleset is missing a rule the setup script has:\n  {rule}");
        }
        // And nothing extra: an accept nobody asked for is how a relay quietly
        // becomes an open router.
        for rule in &mine {
            assert!(
                theirs.contains(rule) || rule.starts_with("destroy table"),
                "the relay ruleset has a rule the setup script does not:\n  {rule}"
            );
        }
    }

    #[test]
    fn the_relay_never_flushes_everything_and_never_touches_dockers_nat_table() {
        let text = relay_ruleset(&fixture_topology(), "ens6", "/etc/nftables.d");
        let rules = rules(&text).join("\n");
        assert!(!rules.contains("flush ruleset"), "flushing everything erases docker's NAT");
        assert!(rules.contains("destroy table inet filter"));
        assert!(rules.contains(&format!("destroy table ip {NAT_TABLE}")));
        // docker's own table is `ip nat`; ours must never be spelled that way.
        assert!(!rules.contains("table ip nat {"), "that table is docker's");
    }

    /// The tunnel port, and the live measurement behind it.
    #[test]
    fn the_tunnel_port_is_accepted_on_input() {
        let text = relay_ruleset(&fixture_topology(), "ens6", "/etc/nftables.d");
        assert!(text.contains("udp dport 51820 accept comment \"WireGuard\""));
        // The production relay's ruleset had no such accept: the tunnel lived
        // only on a conntrack entry a keepalive kept renewing, and a NEW peer
        // could not hand-shake at all (measured 2026-08-13).
        let with_other_port = relay_ruleset(
            &Topology { wg_port: 51830, ..fixture_topology() },
            "ens6",
            "/etc/nftables.d",
        );
        assert!(with_other_port.contains("udp dport 51830 accept"));
    }

    #[test]
    fn a_deployment_with_no_udp_forward_emits_no_udp_rules() {
        let topo = Topology { peers: vec![Peer { udp_ports: vec![], ..fixture_topology().peers[0].clone() }], ..fixture_topology() };
        let text = relay_ruleset(&topo, "ens6", "/etc/nftables.d");
        assert!(!text.contains("udp dport {"), "an empty port set would be a syntax error, not a no-op");
        // The tunnel's own accept is a bare port, not a set, so it survives.
        assert!(text.contains("udp dport 51820 accept"));
    }

    #[test]
    fn the_hairpin_source_and_subnet_come_from_the_home_address() {
        let topo = fixture_topology();
        assert_eq!(topo.hairpin_src(), "10.8.0.254");
        assert_eq!(topo.subnet(), "10.8.0.0/24");
        // Swift derives the subnet from the VPS's tunnel address instead; both
        // halves share one /24, so the fixture proves the answers agree.
        assert!(swift_rules_adjusted(SWIFT_RELAY)
            .iter()
            .any(|rule| rule.contains("ip saddr 10.8.0.0/24 masquerade")));
        assert!(SWIFT_RELAY.contains("define hairpin_src = 10.8.0.254"));
    }

    /// An incomplete topology must never fall back to the BASE ruleset: that
    /// would close the tunnel port and cut the deployment in half.
    #[test]
    fn an_incomplete_topology_is_recognised() {
        assert!(fixture_topology().is_complete());
        for broken in [
            Topology { peers: vec![Peer { ip: String::new(), ..fixture_topology().peers[0].clone() }], ..fixture_topology() },
            Topology { vps_public: String::new(), ..fixture_topology() },
            Topology { wg_port: 0, ..fixture_topology() },
            Topology { peers: vec![Peer { tcp_ports: vec![], ..fixture_topology().peers[0].clone() }], ..fixture_topology() },
        ] {
            assert!(!broken.is_complete(), "{broken:?} must not be treated as a relay topology");
        }
    }

    /// **The home half's marks, and that the base ruleset survives around them.**
    #[test]
    fn the_home_ruleset_marks_relayed_connections_and_keeps_the_base_intact() {
        let text = home_ruleset("/etc/nftables.d", None);
        let mine = rules(&text);
        // The two chains, exactly as the setup script writes them.
        // PER CHAIN, in BOTH directions, and both halves of that are paid for.
        //
        // The one-directional version let the agent grow a rule the generator
        // never writes. Making it two-directional over a FLAT rule list still
        // was not enough, and the negative control is what showed it: deleting
        // the outbound-mail mark from `chain output` alone kept the suite
        // green, because the identical rule still stood in `chain prerouting`
        // and a set comparison cannot tell the two apart. These two chains
        // exist precisely because a mark in one is not a mark in the other
        // (prerouting never sees a locally-generated packet), so the check has
        // to be per chain or it is not checking the thing that matters.
        for chain in ["prerouting", "output"] {
            let theirs = chain_rules(&swift_rules_adjusted(SWIFT_HOME), chain);
            let ours = chain_rules(&mine, chain);
            assert!(!theirs.is_empty(), "the Swift artifact must have a `{chain}` chain to compare against");
            assert_eq!(ours, theirs, "`chain {chain}` differs from the generator's");
        }
        // And everything the base gave it: the drop-in surface and its jump.
        assert!(text.contains(&format!("chain {} {{", firewall::CHAIN)));
        assert!(text.contains(&format!("jump {}", firewall::CHAIN)));
        assert!(text.contains(&format!("include \"/etc/nftables.d/{}\"", firewall::DROP_IN_GLOB)));
        assert!(!rules(&text).join("\n").contains("flush ruleset"));
        // The marks belong INSIDE the filter table, before its closing brace —
        // a chain emitted after it would be a syntax error nft only reports at
        // apply time, on the host.
        let table_end = text.find("\ninclude ").expect("the include closes the file");
        assert!(text[..table_end].contains("chain output {"), "the mark chains must sit inside the table");
    }

    /// **The home half accepts the deployment's forwarded ports FROM THE
    /// TUNNEL, and this test exists because an earlier version did not.**
    ///
    /// Measured on the live home half (`nukki`, 2026-08-13) before this landed:
    /// its ruleset accepted eight ports `iifname "wg0"` — the mail set — and the
    /// function as first written would have replaced that file with one opening
    /// only 22/80/443, silently killing relayed mail at the home firewall while
    /// every other part of the pair looked healthy.
    ///
    /// The other half of the rule is just as deliberate: 80 and 443 stay
    /// UNCONDITIONAL, so a request that names no ports still leaves Caddy
    /// reachable instead of producing a firewall that defeats the relaying this
    /// module exists to enable.
    /// The reader that lets a rewrite be REFUSED rather than obeyed: it has to
    /// see exactly what the real home half carries, round-tripped through the
    /// function that writes it.
    ///
    /// Checked against the LIVE file too (nukki, 2026-08-15): its ruleset was
    /// written by an older generator, so its spacing is not guaranteed to be
    /// what today's writer produces — and the same rule read back the same
    /// seven ports, 25/143/465/587/993/4190 plus the VPN's 51821. A parser
    /// that only understood its own output would have protected nothing on
    /// the one host that has something to lose.
    #[test]
    fn the_tunnel_accepts_are_read_back_out_of_a_real_home_ruleset() {
        let topo = Topology { peers: vec![Peer { tcp_ports: vec![25, 80, 143, 443, 465, 587, 993, 4190], udp_ports: vec![51821], ..fixture_topology().peers[0].clone() }], ..fixture_topology() };
        let text = home_ruleset("/etc/nftables.d", Some(&topo));
        // 80 and 443 are NOT here: the base opens them unconditionally, so they
        // are not what a rewrite would take away.
        assert_eq!(tunnel_accepted_ports(&text), vec![25, 143, 465, 587, 993, 4190, 51821]);
    }

    /// A home half with nothing forwarded must read back as nothing to lose —
    /// otherwise the guard would refuse every such host for ever.
    #[test]
    fn a_home_half_without_forwarded_ports_reads_back_empty() {
        assert!(tunnel_accepted_ports(&home_ruleset("/etc/nftables.d", None)).is_empty());
        // And a single-host ruleset, which has no tunnel at all.
        assert!(tunnel_accepted_ports(&super::super::firewall_base::ruleset("/etc/nftables.d")).is_empty());
    }

    #[test]
    fn the_home_half_accepts_the_forwarded_ports_from_the_tunnel() {
        // The real port set from the production home half.
        let topo = Topology { peers: vec![Peer { tcp_ports: vec![25, 80, 143, 443, 465, 587, 993, 4190], udp_ports: vec![51821], ..fixture_topology().peers[0].clone() }], ..fixture_topology() };
        let text = home_ruleset("/etc/nftables.d", Some(&topo));
        assert!(
            text.contains("iifname \"wg0\" tcp dport { 25, 143, 465, 587, 993, 4190 } accept"),
            "the mail ports must be accepted from the tunnel:\n{text}"
        );
        assert!(text.contains("iifname \"wg0\" udp dport { 51821 } accept"));
        // 80/443 are not repeated behind the tunnel — the base already opens
        // them for everyone, which is what keeps the host usable from its LAN.
        assert!(text.contains("tcp dport { 22, 80, 443 } accept"));
        assert!(!text.contains("tcp dport { 25, 80, 143, 443"), "the base ports must not be repeated");
        // The accepts belong INSIDE the input chain, before the jump into the
        // drop-in chain — a rule after it would still work, but the order the
        // generator writes is the one an operator reading `nft list ruleset`
        // expects.
        let jump = text.find("jump gryonixnexus_services").expect("the input chain jumps");
        assert!(text.find("iifname \"wg0\" tcp dport").expect("the tunnel accept") < jump);

        // No topology: the base three and nothing else, never an empty set
        // (`tcp dport { }` is a syntax error nft only reports on the host).
        let bare = home_ruleset("/etc/nftables.d", None);
        assert!(!bare.contains("iifname \"wg0\" tcp dport"));
        assert!(bare.contains("tcp dport { 22, 80, 443 } accept"));
    }

    /// No forward chain on the home half: docker owns forwarding there, exactly
    /// as on a single host. The relay is the one exception in this crate.
    #[test]
    fn the_home_ruleset_declares_no_forward_chain() {
        assert!(!rules(&home_ruleset("/etc/nftables.d", None)).join("\n").contains("hook forward"));
    }

    #[test]
    fn both_sysctl_files_match_the_generator_byte_for_byte() {
        // These land verbatim and have nothing to deviate about, so unlike the
        // rulesets they are a straight parity check.
        assert_eq!(RELAY_SYSCTL, SWIFT_RELAY_SYSCTL);
        assert_eq!(HOME_SYSCTL, SWIFT_HOME_SYSCTL);
    }

    #[test]
    fn the_public_interface_is_read_from_the_kernels_own_answer() {
        // Real `ip route get 1.1.1.1` output from the relay.
        assert_eq!(
            parse_public_interface("1.1.1.1 via 217.154.155.1 dev ens6 src 217.154.155.150 uid 0 \n    cache "),
            Some("ens6".to_string())
        );
        // A tunnel-only answer still names its device; the caller decides
        // whether that is plausible, this only reports what the kernel said.
        assert_eq!(parse_public_interface("10.8.0.2 dev wg0 src 10.8.0.1 uid 0"), Some("wg0".to_string()));
        assert_eq!(parse_public_interface("something unexpected"), None);
        assert_eq!(parse_public_interface(""), None);
    }

    /// **Two backends behind one relay, which is what peers exist for.**
    ///
    /// Each gets its own address variable and its own rules; ports belong to a
    /// peer rather than to the relay, because DNAT sends a port to ONE place.
    #[test]
    fn a_second_peer_gets_its_own_address_and_its_own_rules() {
        let topo = Topology {
            peers: vec![
                Peer { ip: "10.8.0.2".into(), tcp_ports: vec![25, 587], udp_ports: vec![] },
                Peer { ip: "10.8.0.3".into(), tcp_ports: vec![8080], udp_ports: vec![51821] },
            ],
            vps_public: "203.0.113.10".into(),
            wg_port: 51820,
        };
        assert!(topo.is_complete());
        let text = relay_ruleset(&topo, "eth0", "/etc/nftables.d");

        // The first keeps the name scenario B has always used; the second gets
        // one of its own.
        assert!(text.contains("define home_ip = 10.8.0.2"), "{text}");
        assert!(text.contains("define peer2_ip = 10.8.0.3"), "{text}");

        // Public DNAT: each port set aimed at its OWN peer.
        assert!(text.contains("iifname $pub_if tcp dport { 25, 587 } dnat to $home_ip"), "{text}");
        assert!(text.contains("iifname $pub_if tcp dport { 8080 } dnat to $peer2_ip"), "{text}");
        assert!(text.contains("iifname $pub_if udp dport { 51821 } dnat to $peer2_ip"), "{text}");
        // ...and the first peer has no UDP, so it contributes no UDP line.
        assert!(!text.contains("udp dport { 51821 } dnat to $home_ip"), "{text}");

        // The forward chain and the hairpin follow the same split.
        assert!(text.contains("ip daddr $peer2_ip tcp dport { 8080 } accept"), "{text}");
        assert!(text.contains("ip daddr $peer2_ip snat to") || text.contains("snat to $hairpin_src"), "{text}");
    }

    /// **One peer must render exactly what scenario B always rendered.** The
    /// production relay's file is left alone only while it keeps the right
    /// shape, so a gratuitous change here would be a rewrite of a live
    /// firewall to say the same thing. The Swift parity test covers the bytes;
    /// this states the intent so the reason survives.
    #[test]
    fn one_peer_still_speaks_of_home_ip() {
        let text = relay_ruleset(&fixture_topology(), "eth0", "/etc/nftables.d");
        assert!(text.contains("define home_ip = "), "{text}");
        assert!(!text.contains("peer2_ip"), "a single peer introduces no second variable: {text}");
    }

    /// **A port cannot be forwarded to two places.** DNAT picks one, so the
    /// second rule would silently never match — refused rather than rendered,
    /// the same call the Swift validator makes for two services claiming one
    /// UDP port.
    #[test]
    fn two_peers_cannot_claim_the_same_port() {
        let clash = Topology {
            peers: vec![
                Peer { ip: "10.8.0.2".into(), tcp_ports: vec![443], udp_ports: vec![] },
                Peer { ip: "10.8.0.3".into(), tcp_ports: vec![443], udp_ports: vec![] },
            ],
            vps_public: "203.0.113.10".into(),
            wg_port: 51820,
        };
        assert!(clash.has_port_collision());
        assert!(!clash.is_complete(), "a relay that cannot express its own rules is not complete");

        // Different ports on the same two peers are fine.
        let fine = Topology {
            peers: vec![
                Peer { ip: "10.8.0.2".into(), tcp_ports: vec![443], udp_ports: vec![] },
                Peer { ip: "10.8.0.3".into(), tcp_ports: vec![8443], udp_ports: vec![] },
            ],
            vps_public: "203.0.113.10".into(),
            wg_port: 51820,
        };
        assert!(fine.is_complete());
    }

    /// A peer with no address or no forwarded port cannot be DNATed to, and
    /// half a relay is worse than none.
    #[test]
    fn every_peer_must_be_addressable() {
        let base = fixture_topology();
        let mut topo = Topology { peers: base.peers.clone(), ..fixture_topology() };
        topo.peers.push(Peer { ip: String::new(), tcp_ports: vec![8080], udp_ports: vec![] });
        assert!(!topo.is_complete(), "a peer with no address is not addressable");

        let mut topo = Topology { peers: base.peers.clone(), ..fixture_topology() };
        topo.peers.push(Peer { ip: "10.8.0.3".into(), tcp_ports: vec![], udp_ports: vec![] });
        assert!(!topo.is_complete(), "a peer with no forwarded port has nothing to relay");
    }

    /// The HOME half reads the UNION: from where it sits a port either arrives
    /// through the tunnel or it does not, and which sibling gets the rest is
    /// not its business.
    #[test]
    fn the_home_half_accepts_every_peers_ports() {
        let topo = Topology {
            peers: vec![
                Peer { ip: "10.8.0.2".into(), tcp_ports: vec![25], udp_ports: vec![] },
                Peer { ip: "10.8.0.3".into(), tcp_ports: vec![8080], udp_ports: vec![51821] },
            ],
            vps_public: "203.0.113.10".into(),
            wg_port: 51820,
        };
        assert_eq!(topo.all_tcp_ports(), vec![25, 8080]);
        assert_eq!(topo.all_udp_ports(), vec![51821]);
        let text = home_ruleset("/etc/nftables.d", Some(&topo));
        assert!(text.contains("tcp dport { 25, 8080 } accept"), "{text}");
        assert!(text.contains("udp dport { 51821 } accept"), "{text}");
    }
}
