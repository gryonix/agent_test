//! Ф4 — the AGENT half of the nftables drop-in contract.
//!
//! The generator half already shipped: `NftablesConfig` declares an EMPTY
//! chain `gryonixnexus_services` in `table inet filter`, jumps into it from
//! `input` in all three rulesets (scenario A, home, relay), and includes
//! `/etc/nftables.d/gryonixnexus-*.nft` at the top level of
//! `/etc/nftables.conf` so whatever this module writes survives a reboot.
//! Setup creates the directory with a placeholder before `nft -c` runs. This
//! module is the other end: it writes a service's drop-in and makes it live.
//!
//! **Why a chain inside the deployment's own table, and not a table of our
//! own.** nftables hands a packet to EVERY chain hooked at the same point and
//! a single drop verdict anywhere is final, so an `accept` in a separate
//! table can never undo this ruleset's `policy drop` — the same law that
//! already forbids a second forward chain on a docker host (GOTCHAS.md). The
//! opening has to happen INSIDE this table's input chain, which is why the
//! chain is declared by the generator that owns the file and left empty for
//! us to fill.
//!
//! **What this module never does.** It never re-reads `/etc/nftables.conf`
//! and never issues `flush ruleset`: that wipes EVERY table including
//! docker's own NAT and per-container accepts, and costs a docker restart to
//! recover (GOTCHAS.md). It only ever flushes the ONE chain it owns and adds
//! rules back into it, in a single `nft -f` transaction.
//!
//! **Per-service files, one shared chain.** Each service gets its own
//! `gryonixnexus-svc-<label>.nft`, so removing one service's ports cannot close
//! another's — but the CHAIN is shared, and `flush chain` empties all of it.
//! An apply therefore rebuilds the chain from EVERY drop-in at once, which is
//! what the `include` glob in the transaction below is for: the union is
//! re-established atomically instead of one service's apply silently dropping
//! its neighbours' rules. (`NftablesConfig.applyFirewall`'s comment describes
//! this as a single `gryonixnexus-services.nft`; per-service files are a
//! deliberate refinement of that sketch, and that comment now says so.)
//!
//! **A host whose ruleset predates the chain is a setup re-run, not a
//! failure to paper over.** `flush chain` on a chain that does not exist
//! fails, and the honest answer is the one the project already gives for
//! sudoers and wrapper changes: re-run setup on that host. The nft output
//! rides along in the error, because on this path it is the only explanation
//! there is.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

/// Where the generator's `include` glob looks. Overridable for tests only,
/// the same technique `execute::docker_bin`/`systemctl_bin` use; a server
/// never sets it.
/// The drop-in directory as a string, for the base ruleset's `include`.
pub fn drop_in_dir_display() -> String {
    drop_in_dir().display().to_string()
}

fn drop_in_dir() -> PathBuf {
    std::env::var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/nftables.d"))
}

// `pub(super)` so `firewall_base` can ASK the live ruleset a question — see its
// `live_relay_nat_present`.
pub(super) fn nft_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_NFT_BIN").unwrap_or_else(|_| "nft".to_string())
}

/// `NftablesConfig.agentChainName`, and the table it lives in. Pinned as
/// literals on this side too: the two halves are in different languages and
/// cannot share a constant (the binary is a self-contained musl build — see
/// `dns_records`'s module doc), so they are held together by tests on both
/// sides instead, exactly like the `GRYONIXNEXUS_*` markers.
pub const TABLE: &str = "inet filter";
pub const CHAIN: &str = "gryonixnexus_services";

/// The glob `/etc/nftables.conf` includes. Every file this module writes has
/// to match it or it would not survive a reboot.
pub const DROP_IN_GLOB: &str = "gryonixnexus-*.nft";

/// One `nft` invocation's budget. Applying a handful of rules is instant; the
/// timeout is here because an unbounded child process in an install is how a
/// run hangs forever instead of failing (the same rule every `docker run` on
/// this path follows).
const NFT_TIMEOUT: Duration = Duration::from_secs(30);

// `Ord` so a port table can be keyed by protocol (`install::ports` reads the
// four `/proc/net` tables into one map).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        })
    }
}

/// A port a service needs open on this host — the agent-side counterpart of
/// Swift's `FirewallPort` (and of `install::mail::FirewallPort`, its already
/// ported declarative twin). Deliberately NOT the same type: that one is what
/// a service DECLARES, this one is what actually reaches `nft`, and keeping
/// them apart is what lets the declaration carry a comment string this side
/// has no business putting in a rule built from a client request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Port {
    pub proto: Proto,
    pub port: u16,
}

impl Port {
    pub const fn tcp(port: u16) -> Self {
        Self { proto: Proto::Tcp, port }
    }

    pub const fn udp(port: u16) -> Self {
        Self { proto: Proto::Udp, port }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The drop-in was written and the live chain rebuilt from every drop-in.
    Applied,
    /// The service declares no ports, and any drop-in it had was removed —
    /// a re-install that turns a port off has to CLOSE it, not leave the old
    /// rule standing.
    Cleared,
    /// This host has no `/etc/nftables.d` at all, so it has no gryonixNexus
    /// ruleset to extend — nothing was written and nothing failed. The caller
    /// decides whether that is a step message or an error; for a service
    /// whose ports are the point (mail, VPN) it is worth saying out loud.
    SkippedNoDropInDir,
}

/// Cheap gate on the string that becomes a filename and a rule comment.
///
/// Today every caller passes a `&'static str` out of the executor's own
/// table, so this cannot fail in production — which is exactly why it is one
/// line rather than an argument: the day someone wires a client-supplied id
/// in here, the gate is already standing.
fn is_safe_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `/etc/nftables.d/gryonixnexus-svc-<label>.nft` — inside the glob the
/// generator includes, and namespaced away from `gryonixnexus-00-placeholder.nft`
/// so a service can never be named in a way that overwrites it.
pub fn drop_in_path(label: &str) -> PathBuf {
    drop_in_dir().join(format!("gryonixnexus-svc-{label}.nft"))
}

/// The drop-in itself: one `add rule` per protocol, ports grouped into a set
/// the way the generator's own rules are spelled, each rule commented with
/// the service it belongs to — `nft list ruleset` is the first thing anybody
/// reads when a service will not answer, and an uncommented accept there
/// explains nothing.
///
/// Ports are de-duplicated and sorted so a re-install with the same
/// configuration produces a byte-identical file (idempotent by construction,
/// the discipline the whole install port holds).
pub fn drop_in_contents(label: &str, ports: &[Port]) -> String {
    let mut out = String::new();
    out.push_str("# Managed by gryonixNexus — ports opened for ");
    out.push_str(label);
    out.push_str(" by gryonixnexusd.\n");
    out.push_str("# Included by /etc/nftables.conf; do not edit by hand.\n");
    for proto in [Proto::Tcp, Proto::Udp] {
        let mut set: Vec<u16> =
            ports.iter().filter(|p| p.proto == proto).map(|p| p.port).collect();
        set.sort_unstable();
        set.dedup();
        if set.is_empty() {
            continue;
        }
        let list = set.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
        out.push_str(&format!(
            "add rule {TABLE} {CHAIN} {proto} dport {{ {list} }} accept comment \"{label}\"\n"
        ));
    }
    out
}

/// The transaction handed to `nft -f -`.
///
/// Two statements, and the order is the whole point: empty the ONE chain we
/// own, then re-add every drop-in's rules — ours and every other service's.
/// `include` with the same glob `/etc/nftables.conf` uses is what makes the
/// union atomic; rebuilding from our own file alone would close the ports of
/// whatever else this host runs.
pub fn apply_script(dir: &Path) -> String {
    format!(
        "flush chain {TABLE} {CHAIN}\ninclude \"{}/{DROP_IN_GLOB}\"\n",
        dir.display()
    )
}

/// Write `label`'s drop-in and make the live ruleset match it.
///
/// An empty `ports` REMOVES the drop-in instead of writing an empty one, so
/// turning a service's port off in a re-install actually closes it.
pub async fn apply_service_ports(label: &str, ports: &[Port]) -> Result<Outcome, String> {
    if !is_safe_label(label) {
        return Err(format!("refusing to build a firewall drop-in for the label {label:?}"));
    }
    let dir = drop_in_dir();
    if !dir.is_dir() {
        return Ok(Outcome::SkippedNoDropInDir);
    }

    let path = drop_in_path(label);
    let outcome = if ports.is_empty() {
        match std::fs::remove_file(&path) {
            Ok(()) => Outcome::Cleared,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Outcome::Cleared,
            Err(err) => return Err(format!("could not remove {}: {err}", path.display())),
        }
    } else {
        std::fs::write(&path, drop_in_contents(label, ports))
            .map_err(|err| format!("could not write {}: {err}", path.display()))?;
        // 0644: `nft` reads it as root, and it holds no secret — the same
        // mode setup gives the placeholder next to it.
        set_mode(&path, 0o644)
            .map_err(|err| format!("could not set the mode of {}: {err}", path.display()))?;
        Outcome::Applied
    };

    apply(&dir).await?;
    Ok(outcome)
}

/// Rebuild the live chain from every drop-in. Split out from
/// `apply_service_ports` because the failure mode worth naming is not "the
/// file could not be written" but "the host's ruleset has no chain to fill".
async fn apply(dir: &Path) -> Result<(), String> {
    let script = apply_script(dir);
    let mut child = tokio::process::Command::new(nft_bin())
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("could not run nft: {err}"))?;

    // stdin is ALWAYS closed, even though this script is never empty — the
    // same rule `backup.rs` learned the hard way: a child left waiting for
    // EOF waits forever, and the install reads as hung rather than failed.
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(script.as_bytes())
            .await
            .map_err(|err| format!("could not feed the ruleset to nft: {err}"))?;
        stdin.shutdown().await.ok();
        drop(stdin);
    }

    let output = tokio::time::timeout(NFT_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| format!("nft timed out after {}s", NFT_TIMEOUT.as_secs()))?
        .map_err(|err| format!("could not run nft: {err}"))?;

    if output.status.success() {
        return Ok(());
    }

    let mut detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if detail.is_empty() {
        detail = String::from_utf8_lossy(&output.stdout).trim().to_string();
    }
    // The chain is declared by the generator, so its absence means this host
    // was set up before the drop-in contract existed — and the fix is the one
    // the project already prescribes for sudoers and wrapper changes.
    Err(format!(
        "could not apply the firewall drop-in: {detail}. If the chain {CHAIN} does not exist, \
         this host's ruleset predates it — re-run setup on the host to install the current one."
    ))
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_in_names_stay_inside_the_generators_include_glob() {
        let path = drop_in_path("docker-mailserver");
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("gryonixnexus-"), "{name} is outside the include glob");
        assert!(name.ends_with(".nft"), "{name} is outside the include glob");
        // Never the placeholder setup writes — that file is what keeps the
        // glob matching on a host with no agent-opened ports at all.
        assert_ne!(name, "gryonixnexus-00-placeholder.nft");
    }

    #[test]
    fn contents_group_ports_by_protocol_sorted_and_deduplicated() {
        let ports = [
            Port::tcp(465),
            Port::tcp(25),
            Port::udp(51820),
            Port::tcp(25),
        ];
        let text = drop_in_contents("docker-mailserver", &ports);
        assert!(
            text.contains("add rule inet filter gryonixnexus_services tcp dport { 25, 465 } accept comment \"docker-mailserver\"\n"),
            "{text}"
        );
        assert!(
            text.contains("add rule inet filter gryonixnexus_services udp dport { 51820 } accept comment \"docker-mailserver\"\n"),
            "{text}"
        );
        // Byte-identical for the same configuration in any order: a re-install
        // must not produce a different file.
        let shuffled = [Port::udp(51820), Port::tcp(25), Port::tcp(465)];
        assert_eq!(text, drop_in_contents("docker-mailserver", &shuffled));
    }

    #[test]
    fn contents_omit_a_protocol_with_no_ports() {
        let text = drop_in_contents("wireguard-vpn", &[Port::udp(51820)]);
        assert!(!text.contains(" tcp dport "), "{text}");
    }

    /// The transaction flushes ONLY our chain and rebuilds from the glob —
    /// never `flush ruleset` (which would wipe docker's NAT) and never a
    /// reload of `/etc/nftables.conf`.
    #[test]
    fn the_transaction_flushes_one_chain_and_includes_every_drop_in() {
        let script = apply_script(Path::new("/etc/nftables.d"));
        assert_eq!(
            script,
            "flush chain inet filter gryonixnexus_services\ninclude \"/etc/nftables.d/gryonixnexus-*.nft\"\n"
        );
        assert!(!script.contains("flush ruleset"));
        assert!(!script.contains("/etc/nftables.conf"));
    }

    // ─────────────── against a REAL stub nft and a real directory ───────────────
    //
    // The env vars these tests set are process-global, so they take a lock
    // rather than trusting cargo's thread scheduling — the same shape
    // `execute`'s own stub-binary tests use.

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-fw-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A stub `nft` that records its argv and its stdin, then exits `code`.
    fn stub_nft(dir: &Path, code: i32) -> (PathBuf, PathBuf, PathBuf) {
        let argv = dir.join("argv.txt");
        let stdin = dir.join("stdin.txt");
        let script = dir.join("nft");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > {}\ncat > {}\n[ {code} -eq 0 ] || echo 'Error: No such file or directory' 1>&2\nexit {code}\n",
                argv.display(),
                stdin.display()
            ),
        )
        .unwrap();
        set_mode(&script, 0o755).unwrap();
        (script, argv, stdin)
    }

    #[tokio::test]
    async fn a_host_without_the_drop_in_directory_is_skipped_without_running_nft() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("nodir");
        let (script, argv, _) = stub_nft(&dir, 0);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFT_BIN", &script);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR", dir.join("absent"));

        let outcome = apply_service_ports("vpn", &[Port::udp(51820)]).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFT_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR");
        assert_eq!(outcome, Ok(Outcome::SkippedNoDropInDir));
        assert!(!argv.exists(), "nft must not run on a host with no ruleset of ours");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn applying_writes_the_drop_in_and_feeds_nft_the_whole_transaction_on_stdin() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("apply");
        let nftd = dir.join("nftables.d");
        std::fs::create_dir_all(&nftd).unwrap();
        let (script, argv, stdin) = stub_nft(&dir, 0);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFT_BIN", &script);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR", &nftd);

        let outcome = apply_service_ports("vpn", &[Port::udp(51820)]).await;
        // A second service's ports land in their OWN file: the chain is
        // shared, the files are not.
        let second = apply_service_ports("docker-mailserver", &[Port::tcp(25), Port::tcp(465)]).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFT_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR");

        assert_eq!(outcome, Ok(Outcome::Applied));
        assert_eq!(second, Ok(Outcome::Applied));
        assert_eq!(std::fs::read_to_string(&argv).unwrap().trim(), "-f -");

        let vpn_file = nftd.join("gryonixnexus-svc-vpn.nft");
        let mail_file = nftd.join("gryonixnexus-svc-docker-mailserver.nft");
        assert!(vpn_file.exists() && mail_file.exists(), "both services keep their own drop-in");
        assert!(std::fs::read_to_string(&vpn_file).unwrap().contains("udp dport { 51820 }"));

        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&vpn_file).unwrap().permissions().mode() & 0o777, 0o644);

        // The transaction rebuilds the chain from EVERY drop-in — including
        // the neighbour's — and never reloads /etc/nftables.conf.
        let fed = std::fs::read_to_string(&stdin).unwrap();
        assert_eq!(fed, apply_script(&nftd));
        assert!(fed.starts_with("flush chain inet filter gryonixnexus_services\n"), "{fed}");
        assert!(fed.contains("gryonixnexus-*.nft"), "{fed}");
        assert!(!fed.contains("flush ruleset"), "{fed}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Turning a service's ports off has to CLOSE them: the drop-in is removed
    /// and the chain rebuilt without it, not left standing.
    #[tokio::test]
    async fn no_ports_removes_the_drop_in_and_still_rebuilds_the_chain() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("clear");
        let nftd = dir.join("nftables.d");
        std::fs::create_dir_all(&nftd).unwrap();
        let (script, _argv, stdin) = stub_nft(&dir, 0);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFT_BIN", &script);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR", &nftd);

        let _ = apply_service_ports("vpn", &[Port::udp(51820)]).await;
        let file = nftd.join("gryonixnexus-svc-vpn.nft");
        assert!(file.exists());
        let cleared = apply_service_ports("vpn", &[]).await;
        // Idempotent: clearing what is already clear is not an error.
        let again = apply_service_ports("vpn", &[]).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFT_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR");

        assert_eq!(cleared, Ok(Outcome::Cleared));
        assert_eq!(again, Ok(Outcome::Cleared));
        assert!(!file.exists());
        assert!(std::fs::read_to_string(&stdin).unwrap().contains("flush chain"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A ruleset with no `gryonixnexus_services` chain is a host set up before
    /// the drop-in contract existed. nft's own words travel, and so does the
    /// fix — the same answer the project gives for stale sudoers and wrappers.
    #[tokio::test]
    async fn a_failing_nft_reports_its_own_output_and_names_the_remedy() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("fail");
        let nftd = dir.join("nftables.d");
        std::fs::create_dir_all(&nftd).unwrap();
        let (script, _, _) = stub_nft(&dir, 1);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFT_BIN", &script);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR", &nftd);

        let outcome = apply_service_ports("vpn", &[Port::udp(51820)]).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFT_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR");

        let err = outcome.expect_err("a failing nft must not read as success");
        assert!(err.contains("No such file or directory"), "{err}");
        assert!(err.contains("re-run setup"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn labels_that_could_escape_the_filename_are_refused() {
        assert!(is_safe_label("docker-mailserver"));
        assert!(is_safe_label("vpn"));
        assert!(!is_safe_label(""));
        assert!(!is_safe_label("../etc/passwd"));
        assert!(!is_safe_label("svc name"));
        assert!(!is_safe_label("Svc"));
    }
}
