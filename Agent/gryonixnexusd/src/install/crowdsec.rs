//! Intrusion defence for the HOST: CrowdSec and its nftables bouncer.
//!
//! **Why this is host protection and not a catalog service** (owner's decision,
//! 2026-09-01). Every other thing this crate installs is a compose project with
//! a site, a hostname, an admin and a DNS record. CrowdSec has none of those: it
//! reads the journals of the machine it runs on and writes packet filter rules.
//! Modelling it as a `ManagedService` would mean answering four questions with
//! placeholders and giving the owner a card that configures nothing. It belongs
//! beside `firewall_base` and `lockdown` for that reason, and it still does —
//! but it is no longer UNCONDITIONAL the way the firewall is.
//!
//! **Optional, but recommended, as of 2026-09-09.** A deployment can now say
//! no (`Input.crowdsec_enabled = false`, off in the wizard), because a rented
//! GPU host with nothing else listening is a real deployment this fleet has,
//! and CrowdSec watching an empty journal is a service with a cost (an apt
//! source, a running daemon, a bouncer touching nftables) and no benefit on
//! it. The DEFAULT stays on, and it is spelled `true` on both sides of the
//! wire (`Input::default`, Swift's `ServiceSettings.crowdsecEnabled`) rather
//! than left to chance — the measurement below is what an unwatched host
//! actually costs, and "recommended" only means something if turning it off
//! takes an answer, not silence.
//!
//! **It IS shown to the owner, though — read-only.** `security.rs` serves
//! `Security/GetSecurityStatus`, a live window onto what this module installed
//! and what it has caught; the app's Security section draws it. That is a
//! window, not a switch: there is still nothing here to turn on or off.
//!
//! **What paid for this.** Measured on `vps-middle` 2026-09-01: 10 097 failed
//! root password attempts over three days, against a host whose SSH still
//! accepts passwords from the whole internet. Nothing on it was watching, and
//! nothing would have said so.
//!
//! ## The two facts this module exists to get right
//!
//! **1. The log source is journald, not a file.** CrowdSec's own sshd
//! collection ships a file acquisition for `/var/log/auth.log`. That file does
//! not exist on this fleet — Debian 13 with rsyslog inactive keeps sshd's
//! records in the journal only (measured on `vps-middle`; `ls /var/log/auth.log`
//! is `No such file`). Installing the default and stopping there would have
//! produced a running daemon, a green `systemctl status`, and ZERO parsed
//! lines. The acquisition written here is journald-based for exactly that
//! reason, and [`acquisition`] is asserted against it.
//!
//! **2. The bouncer stays in its OWN nftables table.** Ours is written by
//! `firewall_base`/`firewall_relay`, and both carry the same warning: no
//! `flush ruleset`, because it erases docker's NAT and takes the host's
//! networking with it. The same reasoning binds the other way — a bouncer that
//! wrote into our table would be a second author of a file we rewrite on every
//! provision, and one of the two would lose. nftables allows any number of
//! tables; the bouncer gets `crowdsec`/`crowdsec6` and we never touch them,
//! which is also its package default. [`bouncer_targets_its_own_table`] checks
//! the installed config rather than trusting that default, because a default is
//! a fact about a version.

use std::path::Path;

use super::execute::EventSink;
use super::packages::{have_binary, run_outside_sandbox, run_outside_sandbox_from_file};

/// CrowdSec's own repository installer, the same shape as docker's
/// `get.docker.com` in `packages.rs`. Fixed string; nothing from a request
/// reaches the transient unit that runs it.
const REPOSITORY_INSTALL_URL: &str = "https://install.crowdsec.net";

/// Where our acquisition drop-in lives. `acquis.d` is CrowdSec's supported
/// directory for exactly this — additional sources beside the package's own
/// `acquis.yaml` — so nothing the package owns is edited and an upgrade does
/// not fight us for the file.
pub const ACQUISITION_PATH: &str = "/etc/crowdsec/acquis.d/gryonixnexus.yaml";

/// The bouncer's config. Mostly read, not written — but two keys are ours to
/// keep: the API key (minted below) and `api_url` (pinned by `pin_lapi_port`).
const BOUNCER_CONFIG_PATH: &str = "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml";

/// The engine's own client credentials — the URL `cscli` and the agent half
/// use to reach the local API. Pinned to `LAPI_LISTEN_ADDR` alongside the
/// listen address, or `cscli bouncers add` cannot reach the API it just moved.
const CREDENTIALS_PATH: &str = "/etc/crowdsec/local_api_credentials.yaml";

/// **Where CrowdSec's local API listens — deliberately NOT its default,
/// `127.0.0.1:8080`.** That port is mailcow's on the loopback (`nginx-mailcow`
/// binds `127.0.0.1:8080`, the number half the catalog's service files cite as
/// "8080 mailcow"). Two listeners on one loopback port means whichever starts
/// second dies with "address already in use" — and when the loser is CrowdSec,
/// `crowdsec-firewall-bouncer` then crash-loops against an API that is not
/// there, its `postinst` (which restarts the unit and checks it) fails, the
/// package is left half-configured, and from then on EVERY `apt-get install`
/// on the host exits 100 on `dpkg --configure`. That is what stopped a live
/// install dead at "Installing packages" (owner, 2026-09-10, vps-lab). 8237 is
/// clear of the whole 8080–8096 service band and is loopback-only anyway.
const LAPI_LISTEN_ADDR: &str = "127.0.0.1:8237";

/// The unit names, spelled out so the two callers below cannot drift.
pub(crate) const ENGINE_UNIT: &str = "crowdsec";
pub(crate) const BOUNCER_UNIT: &str = "crowdsec-firewall-bouncer";

/// The name the bouncer registers under with the local API.
///
/// Ours and fixed, rather than the host name the package's own script uses: a
/// fixed name is what makes re-registering idempotent, and a bouncer list that
/// grows a dead entry every provision is a list nobody reads.
const BOUNCER_NAME: &str = "gryonixnexus-firewall-bouncer";

/// The literal the package leaves in its config when it could not mint a key.
///
/// Not a guess — read off `vps-middle` 2026-09-01 after the first live attempt:
/// `api_key: <API_KEY>`, `cscli bouncers list` empty, and the unit in a restart
/// loop on `API error: access forbidden`. The bouncer's post-installation
/// script asks the engine for a key, and on this host it ran BEFORE the engine
/// was configured, so there was nothing to ask.
const UNREGISTERED_KEY: &str = "<API_KEY>";

/// What apt installs, and **in two calls, engine first**.
///
/// Found live on `vps-middle` 2026-09-01: named together on one `apt-get
/// install` line, apt configured the BOUNCER first, and its post-installation
/// script could not mint itself an API key — `open /etc/crowdsec/config.yaml:
/// no such file or directory`, followed by "no api key was generated". The
/// package still installs and the unit still starts; it just talks to nothing.
/// Two calls make the ordering ours instead of apt's.
///
/// Named constants rather than literals inside the script so a test can assert
/// on the BACKEND: the bouncer package is named for it, and `-iptables` is not
/// interchangeable with `-nftables` — the iptables build writes into the
/// compatibility layer that shadows this fleet's own ruleset, which is a
/// firewall that looks correct and bans nothing.
pub(crate) const ENGINE_PACKAGE: &str = "crowdsec";
pub(crate) const BOUNCER_PACKAGE: &str = "crowdsec-firewall-bouncer-nftables";

/// The engine's own config, written by its post-installation script. Its
/// PRESENCE is how "installed" is told apart from "unpacked but not
/// configured" — a distinction that matters because a dpkg run can leave the
/// second state behind, and `cscli` is on PATH in both.
const ENGINE_CONFIG_PATH: &str = "/etc/crowdsec/config.yaml";

/// The acquisition CrowdSec parses our journals with.
///
/// Two sources, and both are journald:
///
/// - **sshd**, which is the one this whole module was bought by. `_SYSTEMD_UNIT`
///   matches `ssh.service` on Debian and `sshd.service` on Ubuntu/RHEL — both
///   are listed because this crate installs on either and a wrong unit name is
///   invisible: the daemon runs, parses nothing, and reports itself healthy.
/// - **Caddy**, because every service this product installs is behind it, so
///   the web half of the host has exactly one log to read. Its journal carries
///   the JSON access log Caddy writes by default.
///
/// `labels.type` is what binds a source to a parser collection; the names are
/// CrowdSec's, not ours.
pub fn acquisition() -> String {
    "# Managed by gryonixNexus. Journald, not files: this fleet runs Debian with\n\
     # rsyslog inactive, so /var/log/auth.log does not exist and a file-based\n\
     # acquisition would parse nothing while reporting itself healthy.\n\
     source: journalctl\n\
     journalctl_filter:\n\
     \x20 - \"_SYSTEMD_UNIT=ssh.service\"\n\
     \x20 - \"_SYSTEMD_UNIT=sshd.service\"\n\
     labels:\n\
     \x20 type: syslog\n\
     ---\n\
     source: journalctl\n\
     journalctl_filter:\n\
     \x20 - \"_SYSTEMD_UNIT=caddy.service\"\n\
     labels:\n\
     \x20 type: caddy\n"
        .to_string()
}

/// The collections CrowdSec needs to make sense of those two sources.
///
/// Installed by name rather than left to whatever the package chose: the sshd
/// collection is the reason this module exists, and `crowdsecurity/caddy` is
/// not a default anywhere. `--error` keeps a re-run silent instead of failing
/// on "already installed", which is what makes this idempotent.
const COLLECTIONS: &[&str] = &["crowdsecurity/sshd", "crowdsecurity/caddy", "crowdsecurity/linux"];

/// Put CrowdSec on the host and point it at the right journals — or leave it
/// off, when the deployment said so.
///
/// **`enabled` only turns installing it off, never removes it.** A host that
/// already carries CrowdSec from an earlier provision (when the default was
/// the only answer, or the owner has since turned the wizard's toggle back
/// on) keeps it across a run where the answer happens to be `false` — this
/// function's job is "make sure of", not "make exactly true", the same
/// one-way contract `ensure_caddy` and `ensure_docker` already carry. Ripping
/// out a running intrusion-defence daemon because a request field flipped is
/// a heavier, riskier action than this call was ever meant to take, and
/// nothing asked for it.
///
/// **Never fatal.** The services are up by the time this runs, and refusing a
/// whole install because a security package's repository was unreachable is the
/// wrong trade — the same call `ensure_autobackup_passphrase` makes. Every exit
/// announces itself through the sink instead, so a host without it says so
/// rather than looking provisioned.
pub(crate) async fn ensure_present(enabled: bool, sink: &EventSink) {
    if !enabled {
        let _ = sink
            .step("intrusion defence: off for this deployment (recommended, not required)")
            .await;
        return;
    }
    if !have_binary("apt-get") || !have_binary("systemd-run") {
        let _ = sink
            .step("skipping intrusion defence: this build only installs packages on Debian/Ubuntu")
            .await;
        return;
    }

    if !engine_configured() {
        let _ = sink.step("installing CrowdSec, the host's intrusion defence").await;
        // One transient unit for the whole thing, as `ensure_caddy` does: a
        // repository without the install that follows leaves a host with a
        // dangling source list.
        //
        // `dpkg --configure -a` first, because the state it has to recover from
        // is real and this run made it: a previous attempt that died in the
        // engine's postinst leaves the package unpacked, `cscli` on PATH and
        // nothing configured at all.
        let script = format!(
            "set -e\n\
             export DEBIAN_FRONTEND=noninteractive\n\
             curl -fsSL {REPOSITORY_INSTALL_URL} | sh\n\
             dpkg --configure -a || true\n\
             apt-get {APT_LOCK_WAIT} install -y {ENGINE_PACKAGE}\n\
             apt-get {APT_LOCK_WAIT} install -y {BOUNCER_PACKAGE}\n",
            APT_LOCK_WAIT = super::packages::APT_LOCK_WAIT,
        );
        // FROM A FILE, not from the transient unit's command line: the engine's
        // postinst parses `systemctl show` of the unit it is running under, and
        // a multi-line ExecStart makes that output unparseable. See
        // `packages::run_outside_sandbox_from_file` for the measurement.
        if let Err(why) = run_outside_sandbox_from_file(&script, "installing CrowdSec", sink).await {
            let _ = sink.warn(&format!("intrusion defence is NOT installed: {why}")).await;
            return;
        }
        if !engine_configured() {
            let _ = sink
                .warn("intrusion defence is NOT installed: CrowdSec did not finish configuring itself")
                .await;
            return;
        }
    }

    // Written on every provision, not only the first: this is the file that
    // decides whether the daemon reads anything at all, and a host installed
    // before this module existed has to get it too.
    if let Err(why) = write_acquisition() {
        let _ = sink.warn(&format!("could not write the CrowdSec acquisition: {why}")).await;
        return;
    }

    // Move the local API off 8080 BEFORE starting the engine — see
    // `LAPI_LISTEN_ADDR`. Every provision, and non-fatal: a host that already
    // carries the pin finds nothing to change, and a host where the rewrite
    // fails is no worse off than one this module never touched.
    if let Err(why) = pin_lapi_port() {
        let _ = sink
            .warn(&format!("could not move the CrowdSec local API off port 8080: {why}"))
            .await;
    }

    let collections = COLLECTIONS.join(" ");
    // `--error` lowers cscli's log level so an already-installed collection is
    // silent; the command still succeeds, which is what makes this idempotent.
    let _ = run_outside_sandbox(
        &format!("cscli collections install {collections} --error || true\ncscli hub update --error || true\n"),
        "installing the CrowdSec collections",
        sink,
    )
    .await;

    // `enable --now` for both, not `start`: an intrusion defence that does not
    // come back after a reboot is worse than none, because the host still looks
    // defended. The same lesson the docker unit taught, paid once.
    if let Err(why) = run_outside_sandbox(
        &format!("systemctl enable --now {ENGINE_UNIT}\nsystemctl restart {ENGINE_UNIT}\n"),
        "starting CrowdSec",
        sink,
    )
    .await
    {
        let _ = sink.warn(&format!("CrowdSec is installed but not running: {why}")).await;
        return;
    }

    // A key the bouncer cannot use is the same outcome as no bouncer at all,
    // and it is LOUD in the journal and silent in the app: the unit restarts
    // for ever on "access forbidden" while everything else reports success.
    match bouncer_registration_needed() {
        Ok(true) => {
            let _ = sink.step("registering the CrowdSec bouncer with the host's local API").await;
            // `-o raw` prints the key and nothing else. Deleting first makes a
            // re-run idempotent: `cscli bouncers add` refuses a name it already
            // knows, and a bouncer whose key was lost has to be able to get a
            // new one.
            let config = bouncer_config_path();
            let script = format!(
                "set -e\n\
                 cscli bouncers delete {BOUNCER_NAME} >/dev/null 2>&1 || true\n\
                 KEY=$(cscli bouncers add {BOUNCER_NAME} -o raw)\n\
                 [ -n \"$KEY\" ]\n\
                 sed -i \"s|^api_key:.*|api_key: $KEY|\" {config}\n"
            );
            if let Err(why) = run_outside_sandbox_from_file(&script, "registering the CrowdSec bouncer", sink).await
            {
                let _ = sink.warn(&format!("the CrowdSec bouncer has no API key: {why}")).await;
                return;
            }
        }
        Ok(false) => {}
        Err(why) => {
            let _ = sink.warn(&format!("could not read the CrowdSec bouncer's config: {why}")).await;
            return;
        }
    }

    match bouncer_targets_its_own_table() {
        Ok(true) => {
            // `try-restart` after `enable --now`: on a re-provision the bouncer
            // is already up, and `enable --now` would not restart it — but
            // `pin_lapi_port` may have just moved the API out from under the
            // running process, and it would otherwise crash-loop for ~15 s
            // until systemd cycled it. `try-restart` is a no-op on a unit that
            // is not running, so the first-install path is unchanged.
            if let Err(why) = run_outside_sandbox(
                &format!("systemctl enable --now {BOUNCER_UNIT}\nsystemctl try-restart {BOUNCER_UNIT}\n"),
                "starting the CrowdSec firewall bouncer",
                sink,
            )
            .await
            {
                let _ = sink.warn(&format!("the CrowdSec bouncer is not running: {why}")).await;
                return;
            }
        }
        // Refused rather than repaired, and the daemon is left running. A
        // bouncer aimed at a table we rewrite on every provision would have its
        // bans erased by the next install without either side noticing; a host
        // that DETECTS and does not ban is a state worth reporting, not one
        // worth silently fixing by editing a package's own config.
        Ok(false) => {
            let _ = sink
                .warn(
                    "the CrowdSec bouncer is not aimed at its own nftables table — left stopped so \
                     it cannot write into the firewall this host manages",
                )
                .await;
            return;
        }
        Err(why) => {
            let _ = sink.warn(&format!("could not read the CrowdSec bouncer's config: {why}")).await;
            return;
        }
    }

    let _ = sink.step("intrusion defence is watching this host's journals").await;
}

/// Is the engine INSTALLED, as opposed to merely unpacked?
///
/// Both halves are needed. `cscli` lands on PATH when dpkg unpacks the package,
/// which happens before the post-installation script runs — so a run that died
/// in that script leaves a host where the binary answers and the daemon has no
/// configuration at all. Measured on `vps-middle` 2026-09-01, on the first live
/// attempt, which is exactly the host this then had to repair.
pub(crate) fn engine_configured() -> bool {
    have_binary("cscli") && Path::new(&engine_config_path()).exists()
}

fn engine_config_path() -> String {
    std::env::var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG").unwrap_or_else(|_| ENGINE_CONFIG_PATH.to_string())
}

fn write_acquisition() -> std::io::Result<()> {
    let path = Path::new(ACQUISITION_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, acquisition())
}

fn credentials_path() -> String {
    std::env::var("GRYONIXNEXUSD_CROWDSEC_CREDENTIALS").unwrap_or_else(|_| CREDENTIALS_PATH.to_string())
}

/// Point the engine's `listen_uri`, the agent's client `url` and the bouncer's
/// `api_url` at `LAPI_LISTEN_ADDR` instead of the default `127.0.0.1:8080`.
///
/// One line deep in each file, the same way `bouncer_targets_its_own_table`
/// reads one — not a YAML parse, because the question is shallow, the files are
/// the package's, and an upgrade that reshapes them should degrade to "left it
/// alone", not a build error. Idempotent: a file already carrying our address
/// is written back unchanged (in fact not written at all).
///
/// All three must agree. `listen_uri` alone moves the door; the other two are
/// how `cscli` (which `cscli bouncers add` runs seconds later) and the bouncer
/// find it.
fn pin_lapi_port() -> Result<(), String> {
    rewrite_scalar(&engine_config_path(), "listen_uri:", LAPI_LISTEN_ADDR)?;
    rewrite_scalar(&credentials_path(), "url:", &format!("http://{LAPI_LISTEN_ADDR}"))?;
    rewrite_scalar(&bouncer_config_path(), "api_url:", &format!("http://{LAPI_LISTEN_ADDR}/"))?;
    Ok(())
}

/// Replace the value on the first non-comment line whose trimmed text starts
/// with `key` (a `foo:` token), keeping that line's own indentation. Missing
/// key or missing file is an error; an already-correct value writes nothing.
fn rewrite_scalar(path: &str, key: &str, value: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{path}: {err}"))?;
    let mut done = false;
    let mut changed = false;
    let rebuilt: Vec<String> = text
        .lines()
        .map(|line| {
            if done {
                return line.to_string();
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || !trimmed.starts_with(key) {
                return line.to_string();
            }
            done = true;
            let indent = &line[..line.len() - trimmed.len()];
            let replacement = format!("{indent}{key} {value}");
            if replacement != line {
                changed = true;
            }
            replacement
        })
        .collect();
    if !done {
        return Err(format!("{path}: no `{key}` line"));
    }
    if changed {
        let mut body = rebuilt.join("\n");
        if text.ends_with('\n') {
            body.push('\n');
        }
        std::fs::write(path, body).map_err(|err| format!("{path}: {err}"))?;
    }
    Ok(())
}

/// Does the installed bouncer write into a table of its own?
///
/// Read, never assumed: the package's default IS `crowdsec`/`crowdsec6`, but a
/// default is a fact about a version, and this is the one property that keeps
/// two firewall authors off one table. `Ok(false)` means the config exists and
/// names something else; `Err` means it could not be read at all.
fn bouncer_targets_its_own_table() -> Result<bool, String> {
    let text = std::fs::read_to_string(bouncer_config_path()).map_err(|err| err.to_string())?;
    // Deliberately not a YAML parse. The question is one line deep, the file is
    // the package's, and pulling a parser in to ask "does this key say
    // crowdsec" would make an upgrade that reshapes the file a build failure
    // instead of a `false`.
    let names_our_table = text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("table:"))
        .any(|line| {
            let value = line.trim_start_matches("table:").trim().trim_matches('"').trim_matches('\'');
            value == "crowdsec" || value == "crowdsec6"
        });
    Ok(names_our_table)
}

/// Overridable for tests, the same technique `systemd_run_bin` uses.
/// Does the bouncer still carry the placeholder its package writes when it
/// could not register?
///
/// Checked rather than assumed, and checked on the KEY rather than on
/// `cscli bouncers list`: the list can hold an entry whose key the config never
/// received, which is exactly the state a failed postinst leaves behind.
fn bouncer_registration_needed() -> Result<bool, String> {
    let text = std::fs::read_to_string(bouncer_config_path()).map_err(|err| err.to_string())?;
    let key = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("api_key:"))
        .map(|line| line.trim_start_matches("api_key:").trim().trim_matches('"').trim_matches('\''))
        .unwrap_or("");
    Ok(key.is_empty() || key == UNREGISTERED_KEY)
}

fn bouncer_config_path() -> String {
    std::env::var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG")
        .unwrap_or_else(|_| BOUNCER_CONFIG_PATH.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one fact a reader of this file would get wrong. `vps-middle` has no
    /// `/var/log/auth.log` at all, so a file acquisition parses nothing while
    /// the daemon reports itself healthy.
    #[test]
    fn the_acquisition_reads_journals_and_never_a_log_file() {
        let text = acquisition();
        // On the source lines, not on the whole file: the comment above them
        // names /var/log/auth.log deliberately, because the reason this is
        // journald is that the file is not there.
        for line in text.lines().filter(|line| !line.trim_start().starts_with('#')) {
            assert!(!line.contains("filenames"), "a file acquisition parses nothing here: {line}");
            assert!(!line.contains("source: file"), "a file acquisition parses nothing here: {line}");
        }
        assert_eq!(text.matches("source: journalctl").count(), 2, "{text}");
    }

    /// sshd is the source this module was bought by, and its unit is named
    /// differently on the two distributions this crate installs on. Getting it
    /// wrong is invisible: the daemon runs and parses nothing.
    #[test]
    fn sshd_is_matched_under_both_names_the_fleet_uses() {
        let text = acquisition();
        assert!(text.contains("_SYSTEMD_UNIT=ssh.service"), "{text}");
        assert!(text.contains("_SYSTEMD_UNIT=sshd.service"), "{text}");
    }

    /// A source without a `labels.type` is read and never parsed — the same
    /// silent-success failure as the wrong unit name.
    #[test]
    fn every_source_carries_the_label_that_binds_it_to_a_parser() {
        let text = acquisition();
        assert_eq!(text.matches("labels:").count(), text.matches("source:").count(), "{text}");
        assert!(text.contains("type: syslog"), "{text}");
        assert!(text.contains("type: caddy"), "{text}");
    }

    /// Two documents in one file need the separator, or CrowdSec reads one
    /// source and ignores the rest of the file.
    #[test]
    fn the_two_sources_are_two_yaml_documents() {
        assert!(acquisition().contains("\n---\n"), "{}", acquisition());
    }

    /// The collections have to cover both sources, or half the acquisition is
    /// parsed by nothing.
    #[test]
    fn a_collection_is_installed_for_every_source() {
        assert!(COLLECTIONS.contains(&"crowdsecurity/sshd"));
        assert!(COLLECTIONS.contains(&"crowdsecurity/caddy"));
    }

    static CONFIG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Runs `check` WHILE the config is in place, so it can call whichever
    /// reader it is about. The first version computed one answer up front and
    /// handed it over — which meant a test for a second reader silently asked
    /// its question after the file was already gone.
    fn with_bouncer_config(body: &str, check: impl FnOnce()) {
        let _guard = CONFIG_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let dir = std::env::temp_dir().join(format!("crowdsec-cfg-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bouncer.yaml");
        std::fs::write(&path, body).unwrap();
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG", &path);
        check();
        std::env::remove_var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_package_default_is_recognised_as_its_own_table() {
        with_bouncer_config(
            "mode: nftables\nnftables:\n  ipv4:\n    enabled: true\n    table: crowdsec\n    chain: crowdsec-chain\n",
            || assert_eq!(bouncer_targets_its_own_table(), Ok(true)),
        );
    }

    /// NEGATIVE CONTROL, and the one this module exists for. A bouncer aimed at
    /// the table `firewall_base` rewrites on every provision would have its
    /// bans erased by the next install, with nothing on either side to say so.
    #[test]
    fn a_bouncer_aimed_at_our_own_table_is_refused() {
        with_bouncer_config(
            "mode: nftables\nnftables:\n  ipv4:\n    enabled: true\n    table: filter\n",
            || assert_eq!(bouncer_targets_its_own_table(), Ok(false)),
        );
    }

    /// A config that cannot be read is not the same answer as one that names
    /// the wrong table, and the caller reports them differently.
    #[test]
    fn an_unreadable_config_is_an_error_and_not_a_false() {
        let _guard = CONFIG_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG", "/nonexistent/bouncer.yaml");
        let outcome = bouncer_targets_its_own_table();
        std::env::remove_var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG");
        assert!(outcome.is_err(), "{outcome:?}");
    }

    /// The state `vps-middle` was actually found in: the package could not mint
    /// a key because it was configured before the engine existed, so the config
    /// carries a placeholder and the unit restarts for ever on "access
    /// forbidden" while every other step reports success.
    #[test]
    fn the_packages_placeholder_key_is_read_as_unregistered() {
        with_bouncer_config("api_url: http://127.0.0.1:8080/\napi_key: <API_KEY>\n", || {
            assert_eq!(bouncer_registration_needed(), Ok(true))
        });
    }

    #[test]
    fn an_empty_key_is_read_as_unregistered() {
        with_bouncer_config("api_key:\n", || assert_eq!(bouncer_registration_needed(), Ok(true)));
    }

    /// NEGATIVE CONTROL: a bouncer that HAS a key must not be re-registered on
    /// every provision — that would mint a new key, rewrite the config and
    /// restart the unit each time an unrelated service is installed.
    #[test]
    fn a_registered_bouncer_is_left_alone() {
        with_bouncer_config("api_key: 5d41402abc4b2a76b9719d911017c592\n", || {
            assert_eq!(bouncer_registration_needed(), Ok(false))
        });
    }

    /// Quoting styles a package upgrade might introduce must not read as a
    /// different table.
    #[test]
    fn a_quoted_table_name_is_the_same_table() {
        with_bouncer_config("nftables:\n  ipv4:\n    table: \"crowdsec\"\n", || {
            assert_eq!(bouncer_targets_its_own_table(), Ok(true))
        });
    }

    /// The bouncer must be the nftables build. The iptables one writes into the
    /// compatibility layer that shadows this fleet's own ruleset — a firewall
    /// that looks correct and bans nothing.
    ///
    /// Asserted on the constant and not on this file's own text: a test that
    /// greps its own source for a forbidden string finds the string in itself.
    #[test]
    fn the_nftables_bouncer_is_the_one_installed() {
        assert!(BOUNCER_PACKAGE.ends_with("-nftables"), "{BOUNCER_PACKAGE}");
        assert!(!BOUNCER_PACKAGE.contains("iptables"), "{BOUNCER_PACKAGE}");
        assert_eq!(ENGINE_PACKAGE, "crowdsec");
    }

    /// `cscli` is on PATH as soon as dpkg UNPACKS the package, before the
    /// post-installation script runs — so a host whose install died in that
    /// script has the binary and no configuration, and a check on the binary
    /// alone would call it installed and never repair it.
    #[test]
    fn an_unpacked_but_unconfigured_engine_does_not_count_as_installed() {
        let _guard = CONFIG_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG", "/nonexistent/config.yaml");
        let answer = engine_configured();
        std::env::remove_var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG");
        assert!(!answer, "a missing config.yaml means the postinst never finished");
    }

    /// The two packages go in as TWO apt calls with the engine first. Named
    /// together on one line, apt configured the bouncer first and it could not
    /// mint itself an API key — the unit starts and talks to nothing.
    #[test]
    fn the_engine_is_installed_before_the_bouncer() {
        let source = include_str!("crowdsec.rs");
        let script = source.split("let script = format!(").nth(1).expect("the install script must be here");
        let engine = script.find("{ENGINE_PACKAGE}").expect("the engine must be installed");
        let bouncer = script.find("{BOUNCER_PACKAGE}").expect("the bouncer must be installed");
        assert!(engine < bouncer, "the bouncer cannot register itself before the engine exists");
    }

    /// The script must not reach the transient unit's command line, or the
    /// engine's own postinst cannot parse the systemd properties it reads.
    #[test]
    fn the_install_script_is_staged_to_a_file() {
        let source = include_str!("crowdsec.rs");
        assert!(source.contains("run_outside_sandbox_from_file(&script"), "a multi-line ExecStart breaks the postinst");
    }

    /// **The port move, on all three files that name it.** The engine's
    /// `listen_uri` is indented under `api: server:`; the credentials `url`
    /// and the bouncer's `api_url` are at the top level. Each keeps its own
    /// indentation and every other line is untouched.
    #[test]
    fn pinning_the_lapi_port_rewrites_the_three_files_and_nothing_else() {
        let _guard = CONFIG_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let dir = std::env::temp_dir().join(format!("crowdsec-lapi-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let engine = dir.join("config.yaml");
        let creds = dir.join("local_api_credentials.yaml");
        let bouncer = dir.join("bouncer.yaml");
        std::fs::write(&engine, "api:\n  server:\n    listen_uri: 127.0.0.1:8080\n    profiles_path: /etc/crowdsec/profiles.yaml\n").unwrap();
        std::fs::write(&creds, "url: http://127.0.0.1:8080\nlogin: abc\npassword: def\n").unwrap();
        std::fs::write(&bouncer, "mode: nftables\napi_url: http://127.0.0.1:8080/\napi_key: KEY\n").unwrap();
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG", &engine);
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_CREDENTIALS", &creds);
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG", &bouncer);

        assert_eq!(pin_lapi_port(), Ok(()));

        assert_eq!(
            std::fs::read_to_string(&engine).unwrap(),
            "api:\n  server:\n    listen_uri: 127.0.0.1:8237\n    profiles_path: /etc/crowdsec/profiles.yaml\n"
        );
        assert_eq!(
            std::fs::read_to_string(&creds).unwrap(),
            "url: http://127.0.0.1:8237\nlogin: abc\npassword: def\n"
        );
        assert_eq!(
            std::fs::read_to_string(&bouncer).unwrap(),
            "mode: nftables\napi_url: http://127.0.0.1:8237/\napi_key: KEY\n"
        );

        // Idempotent: a second run changes nothing and does not error.
        assert_eq!(pin_lapi_port(), Ok(()));
        assert!(std::fs::read_to_string(&engine).unwrap().contains("127.0.0.1:8237"));

        for var in ["GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG", "GRYONIXNEXUSD_CROWDSEC_CREDENTIALS", "GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG"] {
            std::env::remove_var(var);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The port must never be 8080** — that is mailcow's, and a collision
    /// wedges apt for the whole host (see `LAPI_LISTEN_ADDR`).
    #[test]
    fn the_lapi_port_is_not_mailcows() {
        assert_ne!(LAPI_LISTEN_ADDR, "127.0.0.1:8080");
        assert!(LAPI_LISTEN_ADDR.starts_with("127.0.0.1:"), "loopback only");
    }

    /// A missing file is an error, not a silent success — the same distinction
    /// `bouncer_targets_its_own_table` draws.
    #[test]
    fn pinning_a_missing_file_is_an_error() {
        let _guard = CONFIG_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG", "/nonexistent/config.yaml");
        let outcome = pin_lapi_port();
        std::env::remove_var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG");
        assert!(outcome.is_err(), "{outcome:?}");
    }
}
