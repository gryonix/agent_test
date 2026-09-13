//! Ф4 срез 4.9 — the VPN, ported.
//!
//! **The unit of installation here is "the VPN", not "a protocol".** Every
//! other service slice maps one catalog id to one installer, but the agent's
//! own catalog deliberately collapses every VPN piece into ONE service
//! (`discover::VPN_SERVICE`, id `vpn`) because that is how the app manages
//! them: `AgentServiceMapping.agentID(for:)` sends all five protocols and the
//! panel to the same row, `GetState` reports one card, and the generator
//! injects the panel automatically the moment any protocol is selected. An
//! installer that took `wireguard-vpn` as an id would be speaking a language
//! the other half of the agent does not: `known_service_id` would refuse it
//! (a client bug, `invalid_argument`), and teaching the catalog five new ids
//! would give `GetState` five rows where the app draws one card. So
//! `InstallService(service_id: "vpn")` installs the panel plus the protocols
//! the request names, and the protocol list rides in `settings` — the same
//! place every other per-service setting already travels.
//!
//! **All five protocols install through this module now.** Срез 4.9 shipped
//! the panel and plain WireGuard — the smallest coherent VPN, because the
//! panel IS the WireGuard server (wg-quick runs inside its container; there is
//! no wg-easy any more), so `wireguard-vpn` on the Swift side is a marker
//! service contributing a UDP port and nothing else. The other four —
//! AmneziaWG, Shadowsocks, XRay/Reality and OpenVPN — each bring their own
//! compose project and their own императивный half, and were refused up front
//! (`failed_precondition`) until those existed, because a panel advertising a
//! protocol whose container was never installed is worse than a refusal naming
//! the reason. They are ported in `protocols/`, installed BEFORE the panel
//! (which mounts their directories and announces them in `services.json`), and
//! the refusal is gone.
//!
//! **The panel's assets are FILES, not Rust string literals.**
//! `VPNPanelAssets` is 1500 lines of Python, CSS, JS and HTML whose only
//! requirement is byte-exactness; pasting it into `r#"…"#` literals would add
//! a delimiter-escaping hazard for no benefit. They live under `assets/` and
//! are embedded with `include_str!`, and every one of them was extracted from
//! a REAL generated setup script — the bytes between `<<'EOF_VPNPANEL_APP'`
//! and its terminator are literally what lands on a server today.
//!
//! **Measured while porting, not assumed:** all six asset files are identical
//! across scenarios that differ in language AND in selected protocol (en +
//! WireGuard vs ru + AmneziaWG), so the panel's sources carry no
//! interpolation at all — the same shape срез 4.1 found for the declarative
//! half. The parity test therefore compares the crate's copies against
//! fixtures extracted from the OTHER scenario, so it fails both if Swift's
//! assets change and if they ever stop being scenario-independent.

pub mod panel;
/// The four protocols срез 4.9 refused up front, ported — see
/// `protocols/mod.rs`.
pub mod protocols;
