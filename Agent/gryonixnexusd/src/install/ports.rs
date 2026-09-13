//! Pre-flight: is anything on this host already holding a port this install
//! is about to publish?
//!
//! **Why this exists.** The Swift side has always validated ports before it
//! generated anything (`MailInputValidator`: a valid range, no two services on
//! one UDP port, and in scenario B the relay tunnel already owns 51820), and
//! the agent route had no validation at all — it went straight to `up -d` and
//! let docker answer. Measured on `lab-vps` 2026-08-12: a leftover relay `wg0`
//! held UDP 51820, so installing the VPN died with docker's `address already in
//! use` after the whole install had already created directories, written
//! secrets and pulled images. The message was honest; the moment was not.
//!
//! **A live measurement decided the mechanism, not a guess.** The interesting
//! holder here is a WireGuard interface, which is a KERNEL socket with no
//! process behind it — `ss -lunp` prints its line with an empty process column.
//! It does appear in `/proc/net/udp` (measured on the relay 2026-08-13:
//! `00000000:CA6C` with no owning pid), so reading the four `/proc/net` tables
//! sees every holder that matters without shelling out to `ss` — which is not
//! guaranteed to be installed anyway.
//!
//! **The check must never refuse an idempotent re-install.** A second
//! `InstallService` on a host where the service is already running is a proven
//! property of this executor, and on such a host the wanted port IS bound —
//! by our own container. So a port published by a compose project that belongs
//! to the service being installed is not a conflict; the projects come from
//! `discover`, the host's own `docker compose ls`, never from a name derived
//! from the request.
//!
//! **Biased towards letting the install proceed.** A false "port is free" costs
//! nothing new: docker fails exactly as it does today. A false "port is taken"
//! is the worse defect this project keeps re-learning — a check that is red on a
//! healthy host accuses the product. So a TCP socket counts only in `LISTEN`,
//! and a UDP socket only when it is unconnected; an outbound flow that happens
//! to have picked one of these numbers as its ephemeral port is not a holder.
//!
//! **The ADDRESS half is load-bearing, and dropping it was a real bug waiting
//! to happen.** This module used to compare port numbers alone, which was
//! harmless only because it looked at PUBLIC ports (25, 51820) that nothing
//! else on a host ever binds. The moment it started answering for every port a
//! service publishes — which is what it has to do, see below — that shortcut
//! became fatal: every Debian/Ubuntu host answers DNS on `127.0.0.53:53` and
//! `127.0.0.54:53` (systemd-resolved, measured in `/proc/net/udp` on
//! `vps-middle` 2026-08-24), while both DNS filters in the catalog publish
//! `127.0.0.1:53`. Comparing numbers alone would have refused a DNS install on
//! every healthy machine in the fleet. Two DIFFERENT specific addresses
//! coexist; a wildcard on either side collides with anything.
//!
//! **What is checked comes from the compose text this agent itself writes.**
//! Not a hand-kept list: a second list is correct only until somebody edits a
//! compose body, and the drift is invisible. Until 2026-08-24 the pre-flight
//! only knew the PUBLIC ports (`published_public_ports`), so a loopback
//! publish — most of the catalog, every admin UI, and `53` — was outside the
//! gate on this route exactly as it was on the script route. Measured on
//! `vps-middle`: AdGuard installed onto a host already running Pi-hole, docker
//! refused the container with "Bind for 127.0.0.1:53 failed: port is already
//! allocated", and the install carried on regardless.

use std::collections::{BTreeMap, BTreeSet};

use tokio::process::Command;

use super::firewall::{Port, Proto};

/// A host mapping — the address half included, because it decides collisions
/// (see the module doc). `WILDCARD` is what compose means by a mapping that
/// names no address, and what docker then binds.
pub const WILDCARD: &str = "0.0.0.0";

/// Does a binding on `held` stop a bind on `want` from being made?
pub fn addresses_collide(want: &str, held: &str) -> bool {
    want == held || is_wildcard(want) || is_wildcard(held)
}

fn is_wildcard(address: &str) -> bool {
    address.is_empty() || address == WILDCARD || address == "::" || address == "[::]" || address == "*"
}

/// One mapping an install wants to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub address: String,
    pub port: Port,
}

impl Wanted {
    pub fn new(address: &str, port: Port) -> Self {
        Self { address: address.to_string(), port }
    }

    /// A mapping with no address of its own — every port the firewall opens.
    pub fn any(port: Port) -> Self {
        Self::new(WILDCARD, port)
    }
}

/// One socket the host already holds.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Binding {
    pub address: String,
    pub port: u16,
}

/// One port the install wants and cannot have, with whatever the host can say
/// about who has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub port: Port,
    /// `Some(container)` when docker published it — the only holder this host
    /// can NAME. `None` when the binding belongs to anything else: a plain
    /// daemon, or a kernel socket like a WireGuard interface, which has no
    /// process at all and therefore no name to report.
    pub holder: Option<String>,
}

impl Conflict {
    /// One sentence per conflict, for the refusal the client sees.
    pub fn describe(&self) -> String {
        match &self.holder {
            Some(holder) => format!("{}/{} is already published by {}", self.port.port, self.port.proto, holder),
            None => format!("{}/{} is already bound by something on this host", self.port.port, self.port.proto),
        }
    }
}

/// A host port docker has published, and the compose project that owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub project: String,
    pub container: String,
    /// The address half of the publish — `127.0.0.1` for every admin UI in the
    /// catalog, `0.0.0.0` for the ports the firewall opens.
    pub address: String,
    pub port: Port,
}

/// The `/proc/net` tables, in the order `bound_ports` reads them.
const PROC_TABLES: [(&str, Proto); 4] = [
    ("/proc/net/tcp", Proto::Tcp),
    ("/proc/net/tcp6", Proto::Tcp),
    ("/proc/net/udp", Proto::Udp),
    ("/proc/net/udp6", Proto::Udp),
];

/// `st` of a TCP socket that is listening. UDP has no such state — every UDP
/// row reads `07` (`TCP_CLOSE`) — which is why the two protocols are filtered
/// by different questions below.
const TCP_LISTEN: &str = "0A";

/// What one `/proc/net` table says this host holds, address included.
pub fn parse_bound_ports(table: &str, proto: Proto) -> BTreeSet<Binding> {
    let mut held = BTreeSet::new();
    for line in table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(_sl), Some(local), Some(remote), Some(state)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Some(local_port) = hex_port(local) else { continue };
        let Some(local_address) = hex_address(local) else { continue };
        let keep = match proto {
            Proto::Tcp => state.eq_ignore_ascii_case(TCP_LISTEN),
            // An unconnected socket owns the port for everyone; a connected one
            // owns only its own pair, and treating it as a holder would flag an
            // in-flight outbound flow that happened to pick this number.
            Proto::Udp => hex_port(remote) == Some(0),
        };
        if keep {
            held.insert(Binding { address: local_address, port: local_port });
        }
    }
    held
}

/// `ADDR:PORT` in `/proc/net` notation — the port half is hex, big-endian.
fn hex_port(address: &str) -> Option<u16> {
    let (_, port) = address.rsplit_once(':')?;
    u16::from_str_radix(port, 16).ok()
}

/// The address half of a `/proc/net` row.
///
/// IPv4 is written little-endian per byte (`0100007F` is 127.0.0.1 — measured,
/// not assumed). An IPv6 row is answered for only when it is the WILDCARD:
/// a specific v6 address cannot collide with the v4 mappings this agent
/// publishes, and guessing about dual-stack sockets would make the check red on
/// healthy hosts. `None` means "this row says nothing about our mappings".
fn hex_address(local: &str) -> Option<String> {
    let (address, _) = local.rsplit_once(':')?;
    match address.len() {
        8 => {
            let byte = |at: usize| u8::from_str_radix(&address[at..at + 2], 16).ok();
            if address.chars().all(|c| c == '0') {
                return Some(WILDCARD.to_string());
            }
            Some(format!("{}.{}.{}.{}", byte(6)?, byte(4)?, byte(2)?, byte(0)?))
        }
        32 if address.chars().all(|c| c == '0') => Some(WILDCARD.to_string()),
        _ => None,
    }
}

/// Parse `docker ps --format '{{.Label "com.docker.compose.project"}}\t{{.Names}}\t{{.Ports}}'`.
///
/// Only entries with `->` are published on the host; a bare `443/tcp` is merely
/// EXPOSED by the image and holds nothing (measured on `lab-vps`: AdGuard's
/// container prints both kinds in the same field).
pub fn parse_published_ports(listing: &str) -> Vec<Published> {
    let mut published = Vec::new();
    for line in listing.lines() {
        let mut columns = line.split('\t');
        let (Some(project), Some(container), Some(ports)) = (columns.next(), columns.next(), columns.next()) else {
            continue;
        };
        for mapping in ports.split(',') {
            let mapping = mapping.trim();
            let Some((host_side, container_side)) = mapping.split_once("->") else { continue };
            // `0.0.0.0:51830`, `[::]:51830` or `127.0.0.1:53` — the number after
            // the LAST colon, so an IPv6 literal's own colons do not confuse it.
            let Some((host_address, host_port)) = host_side.rsplit_once(':') else { continue };
            let Ok(host_port) = host_port.parse::<u16>() else { continue };
            let proto = match container_side.rsplit_once('/') {
                Some((_, "udp")) => Proto::Udp,
                Some((_, "tcp")) => Proto::Tcp,
                _ => continue,
            };
            published.push(Published {
                project: project.to_string(),
                container: container.to_string(),
                address: host_address.to_string(),
                port: Port { proto, port: host_port },
            });
        }
    }
    published
}

/// Which of the wanted mappings this host cannot give the install.
///
/// Pure, so the whole decision is testable against REAL `/proc/net` and
/// `docker ps` output captured from the fleet rather than against a mock of it.
pub fn conflicts(
    wanted: &[Wanted],
    bound: &BTreeMap<Proto, BTreeSet<Binding>>,
    published: &[Published],
    ours: &[String],
) -> Vec<Conflict> {
    let mut seen: BTreeSet<(String, u16, &'static str)> = BTreeSet::new();
    let mut conflicts = Vec::new();
    for want in wanted {
        let key = (
            want.address.clone(),
            want.port.port,
            if want.port.proto == Proto::Tcp { "tcp" } else { "udp" },
        );
        if !seen.insert(key) {
            continue;
        }
        let by_docker = published
            .iter()
            .find(|p| p.port == want.port && addresses_collide(&want.address, &p.address));
        // Our own container holding the port is what an idempotent re-install
        // looks like from here, and it is not a conflict.
        if let Some(entry) = by_docker {
            if ours.iter().any(|project| project == &entry.project) {
                continue;
            }
        }
        let is_bound = bound.get(&want.port.proto).is_some_and(|set| {
            set.iter()
                .any(|held| held.port == want.port.port && addresses_collide(&want.address, &held.address))
        });
        if !is_bound && by_docker.is_none() {
            continue;
        }
        conflicts.push(Conflict {
            port: want.port,
            holder: by_docker.map(|entry| format!("container '{}' (compose project '{}')", entry.container, entry.project)),
        });
    }
    conflicts
}

/// Every host mapping a compose body publishes.
///
/// The Rust half of `ComposePorts.published(in:)` in `ServiceCatalog`: the two
/// routes have to answer the same question about the same file, and this one
/// reads the very text the agent is about to write. Deliberately not a YAML
/// parser — the input is a body this crate produced, in one shape, and
/// `every_catalog_port_entry_is_understood` keeps that honest by requiring
/// every service's own compose to come back out of here.
pub fn published_in_compose(compose: &str) -> Vec<Wanted> {
    let mut found = Vec::new();
    // The indentation of the `ports:` key whose list is being read. Indentation
    // is what ends the list: `volumes:` sits at the same depth and its items
    // look identical.
    let mut list_indent: Option<usize> = None;
    for line in compose.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if trimmed == "ports:" {
            list_indent = Some(indent);
            continue;
        }
        let Some(open_indent) = list_indent else { continue };
        // Comments are written between entries in several services — part of
        // the list, not the end of it.
        if trimmed.starts_with('#') {
            continue;
        }
        let Some(entry) = trimmed.strip_prefix("- ").filter(|_| indent > open_indent) else {
            list_indent = None;
            continue;
        };
        if let Some(mapping) = compose_entry(entry) {
            found.push(mapping);
        }
    }
    found
}

/// One `ports:` entry — `"IP:HOST:CONTAINER/proto"` or `"HOST:CONTAINER"`.
///
/// `None` for anything else, the short `"3000"` form included: that asks docker
/// to pick the host port, so there is nothing for a pre-flight to reserve.
pub fn compose_entry(raw: &str) -> Option<Wanted> {
    let mut text = raw.trim();
    for quote in ['"', '\''] {
        if text.len() >= 2 && text.starts_with(quote) && text.ends_with(quote) {
            text = &text[1..text.len() - 1];
        }
    }
    let mut proto = Proto::Tcp;
    let mut body = text;
    if let Some((head, tail)) = text.rsplit_once('/') {
        proto = match tail.to_ascii_lowercase().as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            _ => return None,
        };
        body = head;
    }
    let parts: Vec<&str> = body.split(':').collect();
    let (address, host_side) = match parts.len() {
        3 => (parts[0], parts[1]),
        2 => (WILDCARD, parts[0]),
        _ => return None,
    };
    let port: u16 = host_side.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(Wanted::new(address, Port { proto, port }))
}

/// Read the host: every mapping held according to `/proc/net`.
///
/// A table that cannot be read is skipped rather than failed on — a kernel
/// without IPv6 has no `/proc/net/tcp6`, and "the check could not see
/// everything" must not become "the install is refused".
async fn bound_ports() -> BTreeMap<Proto, BTreeSet<Binding>> {
    let mut bound: BTreeMap<Proto, BTreeSet<Binding>> = BTreeMap::new();
    for (path, proto) in PROC_TABLES {
        let Ok(text) = tokio::fs::read_to_string(path).await else { continue };
        bound.entry(proto).or_default().extend(parse_bound_ports(&text, proto));
    }
    bound
}

/// Read the host: what docker has published, per compose project.
///
/// Failure is silence for the same reason: docker being unreachable is already
/// checked before the stream opens, and a listing this call could not get is
/// not evidence of a conflict.
async fn published_ports() -> Vec<Published> {
    let output = Command::new("docker")
        .args(["ps", "--format", "{{.Label \"com.docker.compose.project\"}}\t{{.Names}}\t{{.Ports}}"])
        .output()
        .await;
    match output {
        Ok(output) if output.status.success() => parse_published_ports(&String::from_utf8_lossy(&output.stdout)),
        _ => Vec::new(),
    }
}

/// The mappings docker reports for ONE compose project, right now.
///
/// Used to answer "did `up -d` actually publish what the file says?" — a
/// question `up -d`'s own exit status does not answer (see `compose_up`).
pub async fn published_ports_of_project(project: &str) -> Vec<Port> {
    published_ports()
        .await
        .into_iter()
        .filter(|entry| entry.project == project)
        .map(|entry| entry.port)
        .collect()
}

/// The whole pre-flight: what this install wants, against what the host holds.
///
/// `ours` is the compose projects of the service being installed, as
/// `discover` reports them.
/// What is listening on a port, as a PROCESS name — the one question
/// `/proc/net` cannot answer.
///
/// **It exists to tell two refusals apart** (owner, 2026-09-08). A port this
/// service wants can be held by a leftover from something else — the relay
/// `wg0` on 51820 that killed a VPN install on 2026-08-12 — or by THIS VERY
/// SERVICE, installed on the host by hand. The first is "stop what holds it";
/// the second is "we do not adopt an install we did not make". Both look
/// identical in `/proc/net/tcp`, which has no process column, so this asks
/// `ss` for the name and the caller decides.
///
/// Best-effort by design: a host without `ss`, or a socket whose owner the
/// kernel will not name, answers `None` and the caller falls back to the
/// wording that assumes nothing.
pub async fn holder_process(port: &Port) -> Option<String> {
    if !crate::install::packages::have_binary("ss") {
        return None;
    }
    let filter = format!("sport = :{}", port.port);
    let flag = match port.proto {
        Proto::Tcp => "-lptnH",
        Proto::Udp => "-lpunH",
    };
    let out = tokio::process::Command::new("ss")
        .args([flag, &filter])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .ok()?;
    holder_name_in(&String::from_utf8_lossy(&out.stdout))
}

/// The process name out of one `ss` line, or `None` when the kernel named
/// nobody. Pure, so the shape of the line is pinned by a test against output
/// taken off a real host rather than by a live run.
fn holder_name_in(text: &str) -> Option<String> {
    // `users:(("ollama",pid=2193,fd=4))` — the first quoted word is the name.
    let start = text.find("users:((\"")? + "users:((\"".len();
    let rest = &text[start..];
    let end = rest.find('"')?;
    let name = &rest[..end];
    (!name.is_empty()).then(|| name.to_string())
}

pub async fn check(wanted: &[Wanted], ours: &[String]) -> Vec<Conflict> {
    if wanted.is_empty() {
        return Vec::new();
    }
    let bound = bound_ports().await;
    let published = published_ports().await;
    conflicts(wanted, &bound, &published, ours)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line `ss -lptnH "sport = :11434"` printed on the owner's machine on
    /// 2026-09-08, where a hand-installed Ollama held the port the catalog's
    /// own Ollama publishes. This is the whole reason `holder_process` exists:
    /// `/proc/net/tcp` has the socket and no name for it.
    const NATIVE_OLLAMA_SS: &str =
        "LISTEN 0      4096   127.0.0.1:11434 0.0.0.0:* users:((\"ollama\",pid=2193,fd=4))";

    #[test]
    fn the_holder_of_a_port_is_named_from_the_real_line() {
        assert_eq!(holder_name_in(NATIVE_OLLAMA_SS), Some("ollama".to_string()));
    }

    /// A kernel socket has no process at all — the WireGuard interface that
    /// killed a VPN install on 2026-08-12 is exactly this shape — and a
    /// refusal that named one would be inventing it.
    #[test]
    fn a_socket_with_no_process_names_nobody() {
        assert_eq!(
            holder_name_in("LISTEN 0 128 0.0.0.0:51820 0.0.0.0:*"),
            None
        );
        assert_eq!(holder_name_in(""), None);
    }

    /// Real `/proc/net/udp` lines from the relay (`vps-small`, 2026-08-13),
    /// trimmed to the interesting rows. `CA6C` is 51820 — the scenario-B
    /// tunnel's `wg0`, a KERNEL socket: no process owns it, which is exactly
    /// why `ss -lunp` shows an empty process column for it and why this module
    /// reads `/proc` instead of asking about processes.
    const RELAY_PROC_UDP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   68: 0100007F:0143 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 27081 2 ffff89fec5215e80 0
  310: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   989        0 7969296 2 ffff89fec5210fc0 0
  365: 00000000:CA6C 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2879528 2 ffff89fec5214ec0 0
";

    /// Real `/proc/net/udp` rows from `vps-middle`, 2026-08-24 — the host the
    /// whole pre-flight was rebuilt for. Three sockets answer on port 53 and
    /// only ONE of them is a conflict for a DNS filter: `0100007F` is
    /// 127.0.0.1 (Pi-hole, through docker-proxy), while `3500007F` and
    /// `3600007F` are 127.0.0.53 and 127.0.0.54 — systemd-resolved, present on
    /// every Debian/Ubuntu host in the fleet. `14EB` is 5355 (LLMNR), kept
    /// because it is the row that a naive prefix match reads as "53 is taken".
    const MIDDLE_PROC_UDP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 2153: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2742187 2 000000000e2327d2 0
 2153: 3600007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10423 2 00000000dc4bf342 0
 2153: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10421 2 0000000005217025 0
 3359: 00000000:14EB 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10408 2 000000009063fdf3 0
";

    /// The same host with the DNS filter REMOVED — systemd-resolved and LLMNR
    /// alone, which is what a healthy machine with no filter installed looks
    /// like. The pair with `MIDDLE_PROC_UDP` is the point: a fixture on which
    /// both branches answer the same way proves neither.
    const MIDDLE_PROC_UDP_NO_FILTER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 2153: 3600007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10423 2 00000000dc4bf342 0
 2153: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10421 2 0000000005217025 0
 3359: 00000000:14EB 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10408 2 000000009063fdf3 0
";

    /// The TCP half of the same `vps-middle` pair, verbatim. Pi-hole's
    /// docker-proxy is on `0100007F` (127.0.0.1) and systemd-resolved on
    /// `3500007F`/`3600007F` — the filter row is what the "no filter" fixture
    /// below drops, and nothing else.
    const MIDDLE_PROC_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   2: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 10422 1 000000004c9dc27e 100 0 0 10 5
  17: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 10424 1 000000003177a356 100 0 0 10 5
  18: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2746582 1 00000000aab15fa4 100 0 0 10 0
";

    /// The same table with ONLY the filter's row removed.
    const MIDDLE_PROC_TCP_NO_FILTER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   2: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 10422 1 000000004c9dc27e 100 0 0 10 5
  17: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 10424 1 000000003177a356 100 0 0 10 5
";

    /// Real `/proc/net/tcp` head from `lab-vps` — `20FB` is 8443 (Xray, through
    /// docker-proxy) and `0A` is `LISTEN`.
    const LAB_PROC_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 136811 1 ffff8df1fe873900 100 0 0 10 0
   1: 00000000:20C4 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 133247 1 ffff8df1f62a7200 100 0 0 10 0
   2: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23642 1 ffff8df1f62a2f80 100 0 0 10 0
";

    /// Real `docker ps` output from `lab-vps` 2026-08-13 — the host that
    /// carries the whole VPN plus four other services. Note both kinds of port
    /// field in one listing: published (`0.0.0.0:51830->51830/udp`) and merely
    /// exposed (`443/tcp`, `5432/tcp`).
    const LAB_DOCKER_PS: &str = "vaultwarden\tvaultwarden\t127.0.0.1:8082->80/tcp
vpnpanel\tvpnpanel\t0.0.0.0:51830->51830/udp, [::]:51830->51830/udp, 127.0.0.1:51900->80/tcp
openvpn\topenvpn\t0.0.0.0:1194->1194/udp, [::]:1194->1194/udp
xray\txray\t0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
shadowsocks\tshadowsocks\t0.0.0.0:8388->8388/tcp, 0.0.0.0:8388->8388/udp, [::]:8388->8388/tcp, [::]:8388->8388/udp
awgvpn\tawgvpn\t
psono\tpsono\t127.0.0.1:8089->80/tcp
psono\tpsono-db-1\t5432/tcp
adguardhome\tadguardhome\t80/tcp, 67-68/udp, 443/tcp, 443/udp, 853/udp, 853/tcp, 3000/udp, 5443/tcp, 127.0.0.1:53->53/tcp, 127.0.0.1:53->53/udp, 5443/udp, 6060/tcp, 127.0.0.1:8087->3000/tcp
passbolt\tpassbolt\t443/tcp, 127.0.0.1:8090->80/tcp
";

    /// The two `vps-middle` rows that matter for the DNS shelf, verbatim.
    const MIDDLE_DOCKER_PS: &str = "vaultwarden\tvaultwarden\t127.0.0.1:8082->80/tcp
pihole\tpihole\t67/udp, 127.0.0.1:53->53/tcp, 127.0.0.1:53->53/udp, 123/udp, 443/tcp, 127.0.0.1:8092->80/tcp
";

    /// The mappings AdGuard's own compose body publishes, which is what an
    /// install of it asks this module for.
    fn adguard_wants() -> Vec<Wanted> {
        vec![
            Wanted::new("127.0.0.1", Port::tcp(8087)),
            Wanted::new("127.0.0.1", Port::tcp(53)),
            Wanted::new("127.0.0.1", Port::udp(53)),
        ]
    }

    fn bound_from(tcp: &str, udp: &str) -> BTreeMap<Proto, BTreeSet<Binding>> {
        let mut map = BTreeMap::new();
        map.insert(Proto::Tcp, parse_bound_ports(tcp, Proto::Tcp));
        map.insert(Proto::Udp, parse_bound_ports(udp, Proto::Udp));
        map
    }

    fn holds(held: &BTreeSet<Binding>, address: &str, port: u16) -> bool {
        held.contains(&Binding { address: address.to_string(), port })
    }

    #[test]
    fn a_wireguard_interface_is_visible_in_proc_even_though_no_process_owns_it() {
        let held = parse_bound_ports(RELAY_PROC_UDP, Proto::Udp);
        assert!(holds(&held, WILDCARD, 51820), "wg0's kernel socket has to count as a holder: {held:?}");
        assert!(holds(&held, "127.0.0.53", 53), "the resolver's stub is a holder too");
    }

    #[test]
    fn an_ipv4_address_is_decoded_little_endian() {
        // `0100007F` is 127.0.0.1 and NOT 1.0.0.127 — the byte order is the
        // whole reason the address half can be compared at all.
        let held = parse_bound_ports(MIDDLE_PROC_UDP, Proto::Udp);
        assert!(holds(&held, "127.0.0.1", 53), "{held:?}");
        assert!(holds(&held, "127.0.0.53", 53), "{held:?}");
        assert!(holds(&held, "127.0.0.54", 53), "{held:?}");
        assert!(holds(&held, WILDCARD, 5355), "{held:?}");
    }

    #[test]
    fn only_listening_tcp_sockets_count() {
        let held = parse_bound_ports(LAB_PROC_TCP, Proto::Tcp);
        assert!(holds(&held, WILDCARD, 8443));
        // The same table with the state changed to ESTABLISHED must hold
        // nothing: an outbound connection is not a listener.
        let established = LAB_PROC_TCP.replace(" 0A ", " 01 ");
        assert!(parse_bound_ports(&established, Proto::Tcp).is_empty());
    }

    #[test]
    fn a_connected_udp_socket_is_not_a_holder() {
        let connected = RELAY_PROC_UDP.replace("00000000:CA6C 00000000:0000", "00000000:CA6C 08080808:0035");
        assert!(!holds(&parse_bound_ports(&connected, Proto::Udp), WILDCARD, 51820));
    }

    #[test]
    fn published_ports_are_read_per_project_and_exposed_only_ports_are_ignored() {
        let published = parse_published_ports(LAB_DOCKER_PS);
        assert!(published.contains(&Published {
            project: "vpnpanel".into(),
            container: "vpnpanel".into(),
            address: "0.0.0.0".into(),
            port: Port::udp(51830)
        }));
        assert!(published.contains(&Published {
            project: "vaultwarden".into(),
            container: "vaultwarden".into(),
            address: "127.0.0.1".into(),
            port: Port::tcp(8082)
        }));
        // `5432/tcp` and `443/tcp` are exposed by the image, not published.
        assert!(!published.iter().any(|p| p.port == Port::tcp(5432)));
        assert!(!published.iter().any(|p| p.port == Port::tcp(443)));
    }

    #[test]
    fn the_leftover_tunnel_that_broke_a_real_install_is_reported_without_a_name() {
        let bound = bound_from(LAB_PROC_TCP, RELAY_PROC_UDP);
        let found = conflicts(&[Wanted::any(Port::udp(51820))], &bound, &parse_published_ports(LAB_DOCKER_PS), &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, Port::udp(51820));
        assert_eq!(found[0].holder, None, "a kernel socket has no name to report");
        assert!(found[0].describe().contains("51820/udp"));
    }

    #[test]
    fn a_port_held_by_another_project_names_the_container() {
        let bound = bound_from(LAB_PROC_TCP, RELAY_PROC_UDP);
        let found = conflicts(
            &[Wanted::any(Port::tcp(8443))],
            &bound,
            &parse_published_ports(LAB_DOCKER_PS),
            &["vpnpanel".into()],
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].holder.as_deref(), Some("container 'xray' (compose project 'xray')"));
    }

    #[test]
    fn our_own_running_containers_are_never_a_conflict() {
        let bound = bound_from(LAB_PROC_TCP, RELAY_PROC_UDP);
        let ours: Vec<String> = vec!["vpnpanel".into(), "xray".into(), "shadowsocks".into(), "openvpn".into()];
        let wanted = vec![
            Wanted::any(Port::udp(51830)),
            Wanted::any(Port::tcp(8443)),
            Wanted::any(Port::tcp(8388)),
            Wanted::any(Port::udp(8388)),
            Wanted::any(Port::udp(1194)),
        ];
        assert!(
            conflicts(&wanted, &bound, &parse_published_ports(LAB_DOCKER_PS), &ours).is_empty(),
            "a re-install of the VPN on the host that already runs it must not be refused"
        );
    }

    #[test]
    fn a_free_port_is_free() {
        let bound = bound_from(LAB_PROC_TCP, RELAY_PROC_UDP);
        assert!(conflicts(&[Wanted::any(Port::udp(51999))], &bound, &parse_published_ports(LAB_DOCKER_PS), &[]).is_empty());
    }

    #[test]
    fn a_docker_publish_counts_even_when_no_socket_is_visible() {
        // With `userland-proxy: false` docker publishes by DNAT alone and no
        // host socket exists, yet the port is still taken as far as the next
        // `up -d` is concerned.
        let empty = BTreeMap::new();
        let found = conflicts(&[Wanted::any(Port::udp(1194))], &empty, &parse_published_ports(LAB_DOCKER_PS), &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].holder.as_deref(), Some("container 'openvpn' (compose project 'openvpn')"));
    }

    #[test]
    fn one_conflict_per_mapping_even_when_the_request_repeats_it() {
        let bound = bound_from(LAB_PROC_TCP, RELAY_PROC_UDP);
        let found = conflicts(
            &[Wanted::any(Port::udp(51820)), Wanted::any(Port::udp(51820))],
            &bound,
            &parse_published_ports(LAB_DOCKER_PS),
            &[],
        );
        assert_eq!(found.len(), 1);
    }

    /// The defect this whole module was reworked for, on the real host's own
    /// tables: a second DNS filter, and the holder has a name.
    #[test]
    fn a_second_dns_filter_is_refused_and_pihole_is_named() {
        let bound = bound_from(MIDDLE_PROC_TCP, MIDDLE_PROC_UDP);
        let found = conflicts(&adguard_wants(), &bound, &parse_published_ports(MIDDLE_DOCKER_PS), &[]);
        let ports: Vec<String> = found.iter().map(|c| format!("{}/{}", c.port.port, c.port.proto)).collect();
        assert_eq!(ports, vec!["53/tcp", "53/udp"], "8087 is free on that host and must not be reported");
        for conflict in &found {
            assert_eq!(conflict.holder.as_deref(), Some("container 'pihole' (compose project 'pihole')"));
        }
    }

    /// The other half of the same fixture pair, and the more expensive failure
    /// to get wrong: systemd-resolved answers on 127.0.0.53:53 and
    /// 127.0.0.54:53 on EVERY host in the fleet. A check that called that a
    /// conflict would refuse to install a DNS filter on any healthy machine.
    #[test]
    fn systemd_resolved_alone_does_not_hold_the_filters_53() {
        let bound = bound_from(MIDDLE_PROC_TCP_NO_FILTER, MIDDLE_PROC_UDP_NO_FILTER);
        assert!(
            conflicts(&adguard_wants(), &bound, &[], &[]).is_empty(),
            "127.0.0.53 and 127.0.0.54 are different addresses from 127.0.0.1"
        );
    }

    #[test]
    fn a_wildcard_on_either_side_collides_with_anything() {
        assert!(addresses_collide(WILDCARD, "127.0.0.1"));
        assert!(addresses_collide("127.0.0.1", WILDCARD));
        assert!(addresses_collide("::", "10.8.0.1"));
        assert!(!addresses_collide("127.0.0.1", "127.0.0.53"));
        // A mail engine publishes on the wildcard, so an existing loopback
        // binding on 25 does stop it.
        let bound = bound_from(
            "  sl  local_address rem_address   st\n   0: 0100007F:0019 00000000:0000 0A x\n",
            RELAY_PROC_UDP,
        );
        assert_eq!(conflicts(&[Wanted::any(Port::tcp(25))], &bound, &[], &[]).len(), 1);
    }

    #[test]
    fn compose_entries_are_read_in_every_shape_the_catalog_writes() {
        assert_eq!(compose_entry("\"127.0.0.1:8087:3000\""), Some(Wanted::new("127.0.0.1", Port::tcp(8087))));
        assert_eq!(compose_entry("\"127.0.0.1:53:53/udp\""), Some(Wanted::new("127.0.0.1", Port::udp(53))));
        assert_eq!(compose_entry("\"25:25\""), Some(Wanted::any(Port::tcp(25))));
        assert_eq!(compose_entry("\"51820:51820/udp\""), Some(Wanted::any(Port::udp(51820))));
        // A bare container port asks docker to pick the host port: nothing to
        // reserve, so nothing to check.
        assert_eq!(compose_entry("\"3000\""), None);
    }

    #[test]
    fn only_the_ports_list_is_read_out_of_a_compose_body() {
        // `volumes:` sits at the same indentation as `ports:` and its items
        // look identical — reading past the end of the list would turn
        // `/opt/x/conf:/opt/x/conf` into a port.
        let compose = "services:\n  adguardhome:\n    image: adguard/adguardhome:v0.107.78\n    ports:\n      - \"127.0.0.1:8087:3000\"\n      # Loopback ONLY.\n      - \"127.0.0.1:53:53/tcp\"\n      - \"127.0.0.1:53:53/udp\"\n    volumes:\n      - /opt/adguardhome/conf:/opt/adguardhome/conf\n";
        let found = published_in_compose(compose);
        assert_eq!(
            found,
            vec![
                Wanted::new("127.0.0.1", Port::tcp(8087)),
                Wanted::new("127.0.0.1", Port::tcp(53)),
                Wanted::new("127.0.0.1", Port::udp(53)),
            ],
            "a comment between entries belongs to the list; a volume never does"
        );
    }
}
