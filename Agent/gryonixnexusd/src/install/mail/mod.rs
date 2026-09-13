//! The mail engines' install surface — declarative AND imperative, for all
//! three now.
//!
//! Three engines share one exclusive slot (mailcow / Mailu / docker-mailserver
//! — see ARCHITECTURE.md), so at most one of these is ever installed on a
//! host. They live under their own parent module because mail is the first
//! part of the catalog that needs more than AdGuard did:
//!
//! - **Firewall ports.** AdGuard opens nothing (its DNS is loopback-only, on
//!   purpose). Mail is the opposite: 25/465/587/143/993/4190 have to be open
//!   or the service is pointless. `FirewallPort` therefore appears here for
//!   the first time.
//! - **mailcow is not a compose project at all.** Its `composeFile` returns
//!   nil on the Swift side: it clones its own repository and runs its own
//!   `generate_config.sh`. The agent ORCHESTRATES that installer rather than
//!   composing the stack itself — the same "own the contract, not the engine"
//!   split that `dkim.rs` and `backup.rs` already follow.
//!
//! **The `mail` shelf is CLOSED as of the mail-polka-closing слайс.** Срез 4.9
//! gave `dockermailserver` an executor (`execute::install_docker_mailserver_steps`)
//! reachable from `Install/InstallService`; this слайс does the same for the
//! other two, closing the shelf ARCHITECTURE.md's Ф4 section named as
//! deliberately unfinished business:
//! - **mailcow** (`execute::install_mailcow_steps`) — the one engine in the
//!   whole catalog that is not a compose project this crate authors. Its
//!   install clones mailcow's own repository, runs upstream's
//!   `generate_config.sh` with `COMPOSE_VERSION` in the environment, then
//!   drives its HTTPS REST API for domain/DKIM provisioning — an
//!   orchestration with its own live-paid rules (`curl -f` forbidden, no
//!   call fatal, a deadline rather than a try count, `API_ALLOW_FROM` read
//!   out of the generated `mailcow.conf`), all preserved from GOTCHAS.md.
//!   `git`/`bash`/`curl` are spawned directly (no shell) because this crate
//!   has no Rust TLS client to talk to a self-signed HTTPS API with instead
//!   — see `mailcow.rs`'s own doc.
//! - **Mailu** (`execute::install_mailu_steps`) — a domain/DKIM import over
//!   its own `flask` CLI (piped YAML on stdin, never in argv) instead of a
//!   REST API, otherwise the same cert-sync/DKIM-dump/firewall shape
//!   docker-mailserver already established.
//! Neither `mailcow` nor `mailu` carries `#[allow(dead_code)]` on the module
//! any more — the prior state (declarative-only, unreachable from
//! `route()`) was documented rather than left silent, exactly to avoid the
//! shape `psono` and `seafile` cost this project once each: agent-backed
//! install buttons for a service the agent could not finish. That risk no
//! longer applies to these two.

pub mod dockermailserver;
pub mod mailcow;
pub mod mailu;

/// A port of `FirewallPort` (`ManagedService.swift`): a port a service needs
/// open, with the reason it is open written next to it.
///
/// Lives HERE rather than one level up only because mail is the first part of
/// the catalog that declares any — AdGuard deliberately declares none (its
/// resolver is loopback-only, and a published port would be reachable from
/// the internet whatever nftables says). It moves up to `install` the moment a
/// non-mail service needs it; putting it there now would be guessing at a
/// shape only one caller has ever exercised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallPort {
    pub port: u16,
    pub proto: Proto,
    /// Why this port is open. Carried, not dropped: the generated ruleset is
    /// read by whoever debugs a mail delivery failure at 3am.
    pub comment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    /// No mail engine declares a UDP port; this arm exists because the type is
    /// the shared shape a port list has, and the VPN protocols — the other half
    /// of what the agent-side firewall work unblocks — are all UDP. Dropping it
    /// would mean re-widening the type later for no gain now.
    #[allow(dead_code)]
    Udp,
}

impl Proto {
    /// Matches Swift's `Proto: String` raw values — the spelling that reaches
    /// the generated ruleset and the fixtures. Read by the fixture-parity
    /// tests, which is why the non-test build sees no caller.
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

impl FirewallPort {
    pub fn tcp(port: u16, comment: &str) -> Self {
        Self { port, proto: Proto::Tcp, comment: comment.to_string() }
    }

    /// Unused today for the same reason `Proto::Udp` is.
    #[allow(dead_code)]
    pub fn udp(port: u16, comment: &str) -> Self {
        Self { port, proto: Proto::Udp, comment: comment.to_string() }
    }
}
