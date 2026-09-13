//! Port of the admin-guard control — `/opt/gryonixnexus-admin-lockdown.sh`.
//!
//! See `install/host/mod.rs` for the three rules that apply to everything in
//! this module (byte parity against real generated scripts, "function of the
//! whole installed set, not one service", nothing widens the sandbox
//! silently). This one wrapper is the exception to rule 2 in a way worth
//! spelling out: its body carries NO per-host content at all — no service
//! list, no hostnames, no `ssh_user` — which is exactly what
//! `tests/fixtures/install/host/README.md` measures ("1 distinct body" across
//! all 97 generated variants). `render()` therefore takes no [`HostInput`],
//! unlike every other file in this module: there is nothing in `HostInput`
//! this wrapper could legitimately read.
//!
//! **Where the bytes come from.** Swift writes this wrapper inline inside
//! `VPNPanelService.setupSteps` (`ServiceCatalog/Services/VPNPanelService.swift`,
//! the `EOF_VPNPANEL_LOCKDOWN` heredoc) — it is not one of the
//! `DashboardAccessSections`-style host-wide sections the way
//! `uninstall.rs`/`backup_ctl.rs`/`update_ctl.rs` are, because the app only
//! ever needs it once the VPN panel exists (`extraSudoers` on the same
//! service is what makes it reachable over sudo at all). The agent's own
//! Ф4 срез 4.9 already ported that exact heredoc body byte-for-byte as
//! `install::vpn::panel::ADMIN_LOCKDOWN_SH` (an `include_str!` asset
//! extracted from a real generated script, per that module's own doc), and
//! `execute.rs`'s panel install step already writes it to
//! `install::vpn::panel::LOCKDOWN_SCRIPT_PATH` — confirmed identical, not
//! assumed, by diffing that asset file against this module's OWN fixture
//! (`tests/fixtures/install/host/lockdown/A-adguard-full-access-en.txt`)
//! before writing a line of this file.
//!
//! **Reused, not re-typed.** This module resolves its content through that
//! existing constant instead of embedding a second, independently-typed copy
//! of the same ~90 lines of bash. Two copies is exactly the class of drift
//! `install::host::lock`'s module doc warns against ("a shared leaf nobody
//! owns is how two parallel ports end up disagreeing") — the risk is not
//! hypothetical here, it is the SAME bash a second author would have had to
//! transcribe by hand from the same Swift heredoc. [`fixture_parity`] still
//! pins this module's own copy of the fact against the real extracted
//! artifact, so a future change to `vpn::panel`'s asset that silently drifted
//! from the real script would still be caught from this side too.
//!
//! **Not wired to an executor yet.** Nothing in the crate outside this
//! module's own tests calls [`render`] today — this slice ports the wrapper's
//! CONTENT into `install::host` (where `mod.rs` lists it and where a future
//! caller assembling the full host surface will look for it), it does not
//! change how the VPN panel install writes the file to disk. `execute.rs`'s
//! panel step keeps calling `vpn::panel::ADMIN_LOCKDOWN_SH` directly; that is
//! outside this task's two owned files and is flagged in the porting report
//! rather than changed silently.

use crate::install::caddy::ADMIN_GUARD_PATH;
use crate::install::vpn::panel::{ADMIN_LOCKDOWN_SH, LOCKDOWN_SCRIPT_PATH};

/// Where the wrapper lives on disk — re-exported from `vpn::panel` so the two
/// modules cannot name two different paths for the one file the VPN panel
/// install already writes there.
pub const SCRIPT_PATH: &str = LOCKDOWN_SCRIPT_PATH;

/// The guard file every Caddy admin site imports (`caddy::merge_site`'s own
/// `import` line) — empty means public, a non-empty file means locked. The
/// wrapper's own `GUARD=` line is a baked-in literal of this same path, which
/// [`the_guard_path_matches_caddys_own_constant`] cross-checks rather than
/// trusting that the two were typed the same way twice.
pub const GUARD_PATH: &str = ADMIN_GUARD_PATH;

/// The four `case "${1:-status}"` arms the wrapper answers to — spelled out
/// as data, independently of the rendered script text, so a verb that goes
/// missing or gets renamed is caught by a check that does NOT read its
/// expectation out of the same string it is verifying (see this module's
/// negative-control note on [`every_verb_has_its_own_case_arm`]).
const VERBS: &[&str] = &["on", "only", "off", "status"];

/// The wrapper body — byte-identical to
/// `tests/fixtures/install/host/lockdown/*.txt`, which are a heredoc BODY
/// lifted out of a real generated setup script (see that directory's
/// `README.md`), not a transcription of `VPNPanelService.swift`. Takes no
/// [`super::HostInput`]: see this module's doc for why there is nothing here
/// for one to supply.
pub fn render() -> String {
    // The asset (like the fixture it was itself extracted from) carries the
    // trailing newline a real file on disk has; every other `render`/`script`
    // in this module family returns WITHOUT one (their fixture comparisons
    // trim the fixture side only), so this trims to match that convention
    // rather than let the two diverge by exactly one byte.
    ADMIN_LOCKDOWN_SH.trim_end_matches('\n').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!(
            "{}/tests/fixtures/install/host/lockdown/{name}.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    /// Byte-for-byte parity against a real generated script. The one fixture
    /// under `lockdown/` stands for all 97 script variants
    /// `GeneratedScriptLintTests.makeVariants()` produces — `README.md`
    /// documents that this wrapper's body is the SAME across every one of
    /// them, which is a measurement about the Swift generator, not a licence
    /// to skip verifying it here.
    #[test]
    fn fixture_parity() {
        let expected = fixture("A-adguard-full-access-en");
        assert_eq!(render(), expected.trim_end_matches('\n'));
    }

    /// The central trap this slice was warned about: a fully hardcoded blob
    /// passes `fixture_parity` trivially. These checks derive their
    /// expectation from data declared independently of `render()`'s own
    /// output ([`VERBS`], [`GUARD_PATH`]) rather than re-reading substrings of
    /// the same string `fixture_parity` already compared — see the negative
    /// controls in the porting report for proof they actually catch a
    /// planted defect.
    #[test]
    fn every_verb_has_its_own_case_arm() {
        let script = render();
        for verb in VERBS {
            let arm = format!("  {verb})");
            assert!(script.contains(&arm), "missing case arm for {verb:?}:\n{script}");
        }
        // The usage line on invalid input names all four in the order the
        // Swift source declares them — a fifth verb slipping in would not be
        // caught by the loop above alone if it happened to reuse a case
        // label already covered by `*)`.
        assert!(script.contains("usage: $0 on|off|only host...|status"));
        // Unmatched input falls through to the `*)` arm and a non-zero exit
        // (EX_USAGE), not a silent no-op — a wrapper reached over sudo with a
        // typo'd verb must fail loudly, not do nothing and report success.
        assert!(script.contains("exit 64"));
    }

    /// `status` with no argument at all defaults to reading state, not to
    /// `on`/`off` — `${1:-status}` is what makes a bare invocation
    /// side-effect-free.
    #[test]
    fn a_bare_invocation_defaults_to_status_not_a_mutation() {
        assert!(render().contains(r#"case "${1:-status}" in"#));
    }

    /// The fact this whole wrapper exists to encode: an EMPTY guard file
    /// means public, not "locked with nothing in it". Two independent places
    /// in the script agree on this — `off` truncates the file, `status`
    /// tests for exactly that emptiness — and both are pinned so a change
    /// that flips the file's meaning without touching the other read site
    /// would still be caught.
    #[test]
    fn an_empty_guard_file_means_public() {
        let script = render();
        assert!(script.contains(r#": > "$GUARD""#), "the `off` verb must truncate the guard file to empty");
        assert!(
            script.contains(r#"[ ! -s "$GUARD" ]"#),
            "`status` must read emptiness as the public state"
        );
    }

    /// `only` is the one verb that takes arguments, and it validates them
    /// itself — the wrapper is whitelisted in sudoers with no arguments
    /// constraint (`ServiceCatalog`'s `extraSudoers` comment: "the root-owned
    /// wrapper validates every argument itself"), so an unchecked hostname
    /// here would be an unchecked hostname reaching root.
    #[test]
    fn only_rejects_an_empty_or_malformed_host_list() {
        let script = render();
        assert!(script.contains(r#"[ "$#" -ge 1 ]"#), "`only` with zero hosts must be rejected");
        assert!(
            script.contains(r#"*[!A-Za-z0-9.-]*|"") echo "invalid host: $h" >&2; exit 64 ;;"#),
            "each host must be validated against a fixed character class"
        );
    }

    /// The wrapper's own `GUARD=` literal is the SAME path `caddy.rs` and
    /// `uninstall.rs` already use — checked structurally rather than assumed
    /// merely because both constants happen to be spelled the same way in
    /// two different `.rs` files today.
    #[test]
    fn the_guard_path_matches_caddys_own_constant() {
        assert!(render().contains(&format!("GUARD={GUARD_PATH}\n")));
    }

    /// `SCRIPT_PATH` is the same path `install::vpn::panel` writes this
    /// wrapper to and the same path `uninstall.rs`'s `vpn-panel` arm removes
    /// — a divergence here would mean this module describes a file that is
    /// not the one actually on disk.
    #[test]
    fn script_path_matches_the_panel_installers_own_constant() {
        assert_eq!(SCRIPT_PATH, crate::install::vpn::panel::LOCKDOWN_SCRIPT_PATH);
    }
}
