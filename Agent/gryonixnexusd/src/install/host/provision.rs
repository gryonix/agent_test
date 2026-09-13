//! What an install leaves behind for every LATER operation to stand on.
//!
//! `install/host/*` renders the root-owned surface; this file decides WHICH
//! files that is and in what shape, so the executor's imperative half has one
//! list to walk instead of eight call sites.
//!
//! ## The two rules this file exists to enforce
//!
//! **1. The set, not the service.** Every wrapper is regenerated from the
//! union of what the host already carries and the service being installed —
//! `mod.rs`'s rule 2. Measured live on `lab-vps` 2026-08-12: after an agent
//! install of the VPN, `RemoveService(vpn)` answered `unsupported target: vpn`,
//! because that host's uninstall wrapper had been written by a setup run from
//! before the VPN existed. The gap is not "an agent-built host has no
//! wrappers" — it is that ANY host gets a stale one the moment the agent
//! installs something new.
//!
//! **2. The agent never grants access.** The sudoers whitelist is rewritten
//! only for a control user that ALREADY exists, and the name comes from the
//! existing file itself ([`control_user`]). No `useradd`, no `authorized_keys`,
//! no key material — owner's decision 2026-08-12, and the reason is worth
//! keeping next to the code: the agent already runs as root, so sudoers does
//! not bound what a compromised agent can do, but provisioning ACCOUNTS AND
//! KEYS would genuinely widen it — a compromised agent could hand out SSH
//! access to the host. What sudoers does bound is the app's SSH control user,
//! and keeping that whitelist current is the whole point. A host with no
//! control user simply gets no sudoers file, which is honest: there is nobody
//! for it to authorise.

//! ## The gap this wiring has, stated rather than discovered later
//!
//! Every wrapper here renders from ONE [`super::HostInput`], whose `install`
//! is the request's [`crate::install::context::Input`] — so the paths of
//! services installed EARLIER come from the same map. The settings map is flat
//! and per-service (`jellyfin_path`, `psono_path`, …), so a client CAN send
//! the whole deployment's knobs on every install, and the app's own seam says
//! it must. A client that sends only the service being installed gets default
//! paths for its neighbours: correct on a deployment that never moved one,
//! silently wrong on one that did. The generator has no equivalent problem —
//! it renders from the whole draft — and closing it here would mean the agent
//! remembering per-service settings, which is state the agent deliberately
//! does not keep.

use super::{access, backup_ctl, lockdown, metrics, report, restore, uninstall, update_ctl};
use super::{HostInput, HostRole};

/// One file the install must leave on disk.
#[derive(Debug, Clone, PartialEq)]
pub struct HostFile {
    pub path: String,
    pub contents: String,
    /// `None` keeps whatever mode the create leaves — used for systemd units,
    /// which the generator writes without a `chmod` of their own.
    pub mode: Option<u32>,
}

/// Everything the report needs that no one on the host can answer.
///
/// Separate from [`HostInput`] because it is the ONLY part of the host surface
/// that is not a function of the installed set: the same host, same services,
/// yields a different report when the deployment's PTR or tunnel changes.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportTopology(pub report::Topology);

/// The wrappers, units and scripts, in the order the setup script writes them.
///
/// Order is not cosmetic where one file names another: the report is rendered
/// last because it reads secrets the service installs have already written,
/// and the metrics unit follows its collector because systemd is told to start
/// it in the same step.
pub fn files(
    input: &HostInput,
    backups: &uninstall::BackupPaths,
    // What the host already carries, recovered rather than invented — see
    // [`app_public_key`]. `None` on a host whose wrapper never had the block.
    access: Option<&uninstall::DashboardAccess>,
) -> Vec<HostFile> {
    // **The relay carries almost nothing, and that is measured, not assumed.**
    // `vps-small` (the live scenario-B relay, 2026-08-12) holds exactly two:
    // the metrics collector and the uninstall wrapper. It has no services, so
    // there is nothing to back up, update, restore or control — Swift's
    // `vpsSection` writes none of those either, and writing them here would
    // put wrappers on a host whose own generator never puts them there.
    if input.role == HostRole::VpsRelay {
        return vec![
            HostFile {
                path: metrics::COLLECTOR_PATH.to_string(),
                contents: metrics::collector_script(),
                mode: Some(0o755),
            },
            HostFile {
                path: metrics::UNIT_PATH.to_string(),
                contents: metrics::unit(),
                mode: None,
            },
            HostFile {
                path: uninstall::SCRIPT_PATH.to_string(),
                contents: uninstall::render(input, backups, access),
                mode: Some(0o750),
            },
        ];
    }

    let mut files = vec![
        HostFile {
            path: backup_ctl::SCRIPT_PATH.to_string(),
            contents: backup_ctl::script(input),
            mode: Some(0o750),
        },
        HostFile {
            path: format!("/etc/systemd/system/{}", backup_ctl::SERVICE_NAME),
            contents: backup_ctl::unit(),
            mode: None,
        },
        HostFile {
            path: update_ctl::SCRIPT_PATH.to_string(),
            contents: update_ctl::wrapper(input),
            mode: Some(0o750),
        },
        HostFile {
            path: format!("/etc/systemd/system/{}", update_ctl::SERVICE_NAME),
            contents: update_ctl::autoupdate_unit(),
            mode: None,
        },
        HostFile {
            path: uninstall::SCRIPT_PATH.to_string(),
            // The strip-the-app-key block needs both a control user and the
            // key itself; `None` renders it as the generator's own no-op.
            contents: uninstall::render(input, backups, access),
            mode: Some(0o750),
        },
        HostFile {
            path: restore::SCRIPT_PATH.to_string(),
            contents: restore::render(input, backups),
            mode: Some(0o750),
        },
        HostFile {
            path: metrics::COLLECTOR_PATH.to_string(),
            contents: metrics::collector_script(),
            mode: Some(0o755),
        },
        HostFile {
            path: metrics::UNIT_PATH.to_string(),
            contents: metrics::unit(),
            mode: None,
        },
    ];

    // The admin-guard control. Written on every services host, not only where
    // the VPN panel is: `SetLockdown` (Ф2 срез 7) runs this wrapper by
    // absolute path, and on a host the agent built without a panel the RPC
    // would answer "wrapper not installed" for ever. (The relay returned
    // above — it has no Caddy and no admin sites.)
    files.push(HostFile {
        path: lockdown::SCRIPT_PATH.to_string(),
        contents: lockdown::render(),
        mode: Some(0o750),
    });

    // The wrapper the app's "install the agent" calls. Written on every
    // services host that has a control user, which is exactly where
    // `access.rs` emits its whitelist line — the grant and the script are two
    // halves of one thing.
    if let Some(user) = input.ssh_user.as_deref() {
        files.push(HostFile {
            path: access::AGENT_BOOTSTRAP_SCRIPT_PATH.to_string(),
            contents: super::agent_bootstrap::script(user),
            mode: Some(0o700),
        });
    }

    if let Some(access) = access::render(input, backups) {
        if let Some(body) = access.container_ctl_body {
            files.push(HostFile {
                path: access::CONTAINER_CONTROL_SCRIPT_PATH.to_string(),
                contents: body,
                mode: Some(0o750),
            });
        }
    }
    files
}

/// One rendered body, as it must land ON DISK.
///
/// **Every fixture in this module is a heredoc BODY, and a heredoc always
/// terminates its body with a newline** — `cat > f <<'EOF'` writes the lines
/// plus the `\n` that ends the last one. The parity tests strip that newline
/// before comparing (see `access::fixture_parity`'s `trim_end_matches`), which
/// is right for comparing bodies and wrong for writing files, so the writer
/// has to put it back.
///
/// Found live on `lab-vps` 2026-08-12, and it fails LOUDLY on exactly one of
/// these files: Ubuntu's `visudo` rejects a sudoers file whose last line is
/// unterminated (`syntax error: missing newline`), so the whole install ended
/// with the whitelist refused. macOS's BSD `visudo` accepts the same bytes, so
/// no check on a development machine could have caught it. The other files are
/// shell and systemd units, which do not care — but they would have differed
/// byte-for-byte from what the setup script leaves on the same host, which is
/// this module's whole rule 1.
pub fn as_written(contents: &str) -> String {
    let mut out = contents.trim_end_matches('\n').to_string();
    out.push('\n');
    out
}

/// The sudoers body for this host, or `None` when there is no control user to
/// authorise. Kept out of [`files`] because it is the one file that must not
/// be written directly: it is staged and validated with `visudo` first, and a
/// bad `/etc/sudoers.d` entry breaks `sudo` for the whole machine.
pub fn sudoers(input: &HostInput, backups: &uninstall::BackupPaths) -> Option<String> {
    access::render(input, backups).map(|access| access.sudoers_body)
}

/// The control user this host already has, read out of the sudoers file the
/// setup script left behind.
///
/// This is the whole of the "never grant access" rule in one function: the
/// agent learns the user's NAME from a file only a previous, human-authorised
/// setup could have created, and has no way to name a user that does not
/// already have a whitelist. No file — no user, and [`sudoers`] returns
/// `None`.
///
/// The parse is deliberately narrow: the first token of the first line that
/// looks like a sudoers rule (`<user> ALL=(ALL) NOPASSWD: …`). Comments and
/// blank lines are skipped, and anything else yields `None` rather than a
/// guess — a wrong name here would write a whitelist for an account that does
/// not exist, which reads to the operator as "the dashboard stopped working".
/// The app's public key, recovered from the uninstall wrapper already on this
/// host.
///
/// **Why recover it rather than drop the block.** The wrapper's last act on a
/// full erase is to strip the app's key from the control user's
/// `authorized_keys`; the agent has no idea what that key is (it never
/// installs one — see this module's rule 2), so a regenerated wrapper would
/// silently lose that step and leave the app able to SSH in after the erase it
/// just performed. Measured on the live relay 2026-08-12: the wrapper written
/// by setup carried the block, the agent's first regeneration did not.
///
/// Same principle as [`control_user`]: the agent reads what a previous,
/// human-authorised setup put there and carries it forward. It cannot invent a
/// key, and a host without the block simply keeps not having one.
pub fn app_public_key(uninstall_wrapper: &str) -> Option<String> {
    let line = uninstall_wrapper.lines().map(str::trim).find(|line| line.starts_with("APP_KEY='"))?;
    let key = line.strip_prefix("APP_KEY='")?.strip_suffix('\'')?;
    // A quote inside would mean the line was never one this wrapper wrote;
    // an empty key would strip nothing and is not worth carrying.
    if key.is_empty() || key.contains('\'') {
        return None;
    }
    Some(key.to_string())
}

pub fn control_user(sudoers_file: &str) -> Option<String> {
    for line in sudoers_file.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (user, rest) = line.split_once(char::is_whitespace)?;
        if !rest.trim_start().starts_with("ALL=") {
            return None;
        }
        if user.is_empty() || user.contains('/') {
            return None;
        }
        return Some(user.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_records::Language;
    use crate::install::context::Input;

    /// `files` without the recovered access — most cases do not exercise it.
    fn files_of(input: &HostInput, backups: &uninstall::BackupPaths) -> Vec<HostFile> {
        files(input, backups, None)
    }

    fn host(services: &[&str], user: Option<&str>, role: HostRole) -> HostInput {
        HostInput {
            services: services.iter().map(|s| s.to_string()).collect(),
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: Language::En,
            ssh_user: user.map(str::to_string),
            role,
        }
    }

    /// **The whole host half, rendered for every id the agent can install,
    /// WITH a control user.** This is the test that would have saved a live
    /// run: adding a service to `CATALOG_ORDER` without an arm in
    /// `access::service_sudoers_targets` made `files` PANIC, and a panic here
    /// does not surface as an error — the install stream simply stopped after
    /// "writing the host's management wrappers", with no COMPLETED event and
    /// no error trailer, which from the client's side is a clean end of
    /// stream. Measured on a real host 2026-08-14.
    ///
    /// The control user is the point of the fixture: without one the sudoers
    /// half is skipped entirely, which is exactly why the same install had
    /// already passed on another host that has none.
    #[test]
    fn the_whole_host_half_renders_for_every_installable_service() {
        let mut ids: Vec<&str> = Vec::new();
        for id in crate::install::execute::implemented_service_ids() {
            if id == "vpn" {
                // One aggregate id on the wire, the individual protocols on
                // the host — the mapping the uninstall wrapper documents.
                ids.extend(["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn", "vpn-panel"]);
            } else {
                ids.push(id);
            }
        }
        for id in &ids {
            let input = host(&[id], Some("server-user"), HostRole::SingleHost);
            let rendered = files(&input, &uninstall::BackupPaths::default(), None);
            assert!(!rendered.is_empty(), "`{id}` produced no host files at all");
        }
        // And all of them together, which is the shape a real host has.
        let input = host(&ids, Some("server-user"), HostRole::SingleHost);
        assert!(!files(&input, &uninstall::BackupPaths::default(), None).is_empty());
    }

    /// **The same walk, but over CATALOG_ORDER rather than over the ids the
    /// agent can INSTALL — and the difference is where the next gap lives.**
    ///
    /// The two lists are not the same and must not be: an implicit service
    /// (the VPN panel, the mesh node) is installed by another service's call,
    /// so it never appears in `implemented_service_ids`, while it certainly
    /// appears in `HostInput.services` — the app sends the deployment's whole
    /// service set, and the wrappers are a function of what is INSTALLED, not
    /// of what was just installed.
    ///
    /// Found by adding the mesh node: the report table panicked immediately
    /// (it walks CATALOG_ORDER), while `access` and `uninstall` both went on
    /// passing with no arm at all, because nothing fed them the new id. Their
    /// `unreachable!` would have fired on the first real host — the exact
    /// failure mode the test above exists for, one table over.
    #[test]
    fn the_whole_host_half_renders_for_every_id_a_host_can_carry() {
        for id in crate::install::host::CATALOG_ORDER {
            let input = host(&[id], Some("server-user"), HostRole::SingleHost);
            let rendered = files(&input, &uninstall::BackupPaths::default(), None);
            assert!(!rendered.is_empty(), "`{id}` produced no host files at all");
        }
        let input = host(crate::install::host::CATALOG_ORDER, Some("server-user"), HostRole::SingleHost);
        assert!(!files(&input, &uninstall::BackupPaths::default(), None).is_empty());
    }

    /// The name comes out of the file, and only out of the file.
    #[test]
    fn the_control_user_is_read_from_an_existing_whitelist() {
        let file = "# Managed by gryonixNexus — Server Dashboard command whitelist.\n\
                    # sudo matches these commands verbatim; do not add flags client-side.\n\
                    gryonixbot ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart sshd\n";
        assert_eq!(control_user(file).as_deref(), Some("gryonixbot"));
    }

    /// Anything that is not a whitelist is not an answer. A guess here would
    /// authorise an account that does not exist.
    #[test]
    fn nothing_that_is_not_a_rule_yields_a_user() {
        assert_eq!(control_user(""), None);
        assert_eq!(control_user("# only comments\n\n"), None);
        assert_eq!(control_user("Defaults env_keep += \"FOO\"\n"), None);
        assert_eq!(control_user("/usr/bin/something ALL=(ALL) NOPASSWD: x\n"), None);
    }

    /// No control user: no sudoers, and no container-ctl either — that wrapper
    /// exists ONLY to be reached over sudo (the agent controls containers
    /// through `control.rs`, as root, without it).
    #[test]
    fn a_host_with_no_control_user_gets_no_sudoers_and_no_container_wrapper() {
        let input = host(&["vaultwarden"], None, HostRole::SingleHost);
        let backups = uninstall::BackupPaths::default();
        assert_eq!(sudoers(&input, &backups), None);
        let paths: Vec<String> = files(&input, &backups, None).into_iter().map(|f| f.path).collect();
        assert!(!paths.contains(&access::CONTAINER_CONTROL_SCRIPT_PATH.to_string()), "{paths:?}");
        // Everything else is still written: those wrappers are what the AGENT
        // itself runs, as root, for Backup/Update/Restore/RemoveService.
        for expected in [
            backup_ctl::SCRIPT_PATH,
            update_ctl::SCRIPT_PATH,
            uninstall::SCRIPT_PATH,
            restore::SCRIPT_PATH,
            metrics::COLLECTOR_PATH,
            lockdown::SCRIPT_PATH,
        ] {
            assert!(paths.contains(&expected.to_string()), "{expected} missing from {paths:?}");
        }
    }

    /// With a control user, the whitelist names it and the container wrapper
    /// appears.
    #[test]
    fn a_host_with_a_control_user_gets_both() {
        let input = host(&["vaultwarden"], Some("gryonixbot"), HostRole::SingleHost);
        let backups = uninstall::BackupPaths::default();
        let body = sudoers(&input, &backups).expect("a control user means a whitelist");
        assert!(body.contains("gryonixbot ALL=(ALL) NOPASSWD:"), "{body}");
        let paths: Vec<String> = files(&input, &backups, None).into_iter().map(|f| f.path).collect();
        assert!(paths.contains(&access::CONTAINER_CONTROL_SCRIPT_PATH.to_string()));
    }

    /// A rendered whitelist must survive its own reader: what the agent writes
    /// has to name the same user the next install reads back out of it.
    #[test]
    fn what_is_written_is_what_is_read_back() {
        let input = host(&["vaultwarden", "vpn"], Some("gryonixbot"), HostRole::SingleHost);
        let body = sudoers(&input, &uninstall::BackupPaths::default()).unwrap();
        assert_eq!(control_user(&body).as_deref(), Some("gryonixbot"));
    }

    /// The relay carries no Caddy and no admin sites, so no lockdown wrapper —
    /// and no container-ctl even with a control user, which `access::render`
    /// already decides and this pins from the caller's side.
    /// **The relay's whole surface, pinned against a live one.** `vps-small`
    /// carries exactly the metrics collector and the uninstall wrapper — it
    /// has no services, so backup/update/restore/container-control/lockdown
    /// have nothing to act on and Swift's `vpsSection` writes none of them.
    #[test]
    fn the_relay_gets_only_what_a_live_relay_has() {
        let input = host(&[], Some("gryonixbot"), HostRole::VpsRelay);
        let paths: Vec<String> = files_of(&input, &uninstall::BackupPaths::default())
            .into_iter()
            .map(|f| f.path)
            .collect();
        assert_eq!(
            paths,
            vec![
                metrics::COLLECTOR_PATH.to_string(),
                metrics::UNIT_PATH.to_string(),
                uninstall::SCRIPT_PATH.to_string(),
            ],
            "the relay's surface is exactly these three"
        );
        // The whitelist is still rewritten — the relay has its OWN six lines
        // (restart the tunnel, reboot, `wg show`, the uninstall wrapper …),
        // and that is the one part of the dashboard a relay does serve.
        let body = sudoers(&input, &uninstall::BackupPaths::default()).unwrap();
        assert!(body.contains("wg-quick@wg0"), "{body}");
        assert!(!body.contains("docker"), "a relay runs no containers: {body}");
    }

    /// Every wrapper is a function of the SET. The live failure this file
    /// exists for was a wrapper that knew about four services and not the
    /// fifth, so what is pinned is that adding a service to the set changes
    /// the bytes of the wrappers that dispatch per service.
    #[test]
    fn adding_a_service_changes_the_wrappers_that_dispatch_on_it() {
        let backups = uninstall::BackupPaths::default();
        let before = files_of(&host(&["vaultwarden"], None, HostRole::SingleHost), &backups);
        let after = files_of(&host(&["vaultwarden", "nextcloud"], None, HostRole::SingleHost), &backups);
        for path in [backup_ctl::SCRIPT_PATH, update_ctl::SCRIPT_PATH, uninstall::SCRIPT_PATH] {
            let body = |set: &[HostFile]| {
                set.iter().find(|f| f.path == path).expect("wrapper must be written").contents.clone()
            };
            assert_ne!(body(&before), body(&after), "{path} must know about the new service");
            assert!(body(&after).contains("nextcloud"), "{path} must name the new service");
        }
    }

    /// **These are `ServiceRegistry` ids, not the agent's.** `vpn` is what
    /// `discover` reports and what the app manages, but the wrappers dispatch
    /// on the catalog's own ids — the panel and each protocol by name. Handing
    /// the aggregate id straight through would produce wrappers that dispatch
    /// on nothing, which is exactly the stale-wrapper failure this file exists
    /// to prevent, wearing a different hat. `execute::installed_catalog_ids`
    /// is the mapping; this is the assertion that it is NEEDED.
    #[test]
    fn the_aggregate_vpn_id_is_not_one_of_these() {
        let backups = uninstall::BackupPaths::default();
        let aggregate = files_of(&host(&["vpn"], None, HostRole::SingleHost), &backups);
        let expanded = files_of(&host(&["wireguard-vpn", "vpn-panel"], None, HostRole::SingleHost), &backups);
        let body = |set: &[HostFile], path: &str| {
            set.iter().find(|f| f.path == path).unwrap().contents.clone()
        };
        assert_ne!(
            body(&aggregate, uninstall::SCRIPT_PATH),
            body(&expanded, uninstall::SCRIPT_PATH),
            "the aggregate id must not render the same wrapper as the real ids"
        );
        assert!(
            body(&expanded, uninstall::SCRIPT_PATH).contains("vpn)"),
            "the expanded ids produce the wrapper's own vpn target"
        );
    }

    /// **What is written must end with a newline.** The bodies deliberately do
    /// not (they are heredoc bodies, and the parity tests strip the fixture's
    /// last newline to compare), so the writer adds it — see [`as_written`]
    /// for the live failure that says why this is not cosmetic.
    #[test]
    fn every_file_lands_on_disk_newline_terminated() {
        let input = host(&["vaultwarden", "vpn-panel"], Some("bot"), HostRole::SingleHost);
        let backups = uninstall::BackupPaths::default();
        for file in files(&input, &backups, None) {
            let written = as_written(&file.contents);
            assert!(written.ends_with('\n'), "{}", file.path);
            assert!(!written.ends_with("\n\n"), "{} must not gain a blank line", file.path);
            assert_eq!(written.trim_end_matches('\n'), file.contents.trim_end_matches('\n'));
        }
        let body = sudoers(&input, &backups).unwrap();
        assert!(as_written(&body).ends_with("gryonixnexus-admin-lockdown.sh\n"), "{body}");
    }

    /// **Every wrapper has to recognise the VPN from the SAME ids.**
    ///
    /// This is the test that was missing, and a live host paid for it: each
    /// module's fixtures were written by its own author with its own
    /// assumption about what `HostInput.services` contains, and `backup_ctl`
    /// keyed the panel's backup target on the agent's collapsed `"vpn"` while
    /// every other module read catalog ids. Both halves passed their own
    /// fixtures. On nukki (2026-08-12) the regenerated backup wrapper's
    /// service list had silently LOST the VPN panel — a scheduled backup that
    /// would simply stop covering it, with nothing to notice.
    ///
    /// So this asks the question from the outside: given the set a real host
    /// produces, does every file that should know about the VPN know?
    #[test]
    fn every_wrapper_recognises_the_vpn_from_the_catalog_ids() {
        let input = host(&["vaultwarden", "wireguard-vpn", "vpn-panel"], Some("bot"), HostRole::SingleHost);
        let backups = uninstall::BackupPaths::default();
        let body = |files: &[HostFile], path: &str| {
            files.iter().find(|f| f.path == path).expect("written").contents.clone()
        };
        let files = files(&input, &backups, None);

        let backup = body(&files, backup_ctl::SCRIPT_PATH);
        assert!(backup.contains("vpn-panel)"), "the backup wrapper needs a vpn-panel arm");
        assert!(
            backup.lines().any(|l| l.starts_with("SERVICES=") && l.contains("vpn-panel")),
            "the panel must be in the backup service list"
        );
        assert!(body(&files, uninstall::SCRIPT_PATH).contains("vpn)"), "uninstall needs a vpn target");
        assert!(
            sudoers(&input, &backups).unwrap().contains("vpnpanel"),
            "the whitelist must authorise controlling the panel's container"
        );
    }

    /// **The app key is carried forward, never invented.** A regenerated
    /// wrapper that lost the strip block would leave the app able to SSH in
    /// after the erase it just performed — found on the live relay, where the
    /// setup-written wrapper had the block and the first regeneration did not.
    #[test]
    fn the_app_key_is_recovered_from_the_wrapper_already_on_disk() {
        let existing = "  APP_KEY='ssh-ed25519 AAAAC3Nz key-comment'\n  USER_HOME=\"x\"\n";
        assert_eq!(
            app_public_key(existing).as_deref(),
            Some("ssh-ed25519 AAAAC3Nz key-comment")
        );
        // A wrapper without the block (agent-built host, or existing-user
        // mode) yields nothing, and nothing is invented.
        assert_eq!(app_public_key("  :\n"), None);
        assert_eq!(app_public_key("  APP_KEY=''\n"), None);

        // Carried through to the rendered wrapper.
        let input = host(&["vaultwarden"], Some("server-user"), HostRole::SingleHost);
        let backups = uninstall::BackupPaths::default();
        let access = uninstall::DashboardAccess {
            create_user: true,
            app_public_key: "ssh-ed25519 KEY app".to_string(),
        };
        let with = files(&input, &backups, Some(&access));
        let body = |set: &[HostFile]| {
            set.iter().find(|f| f.path == uninstall::SCRIPT_PATH).unwrap().contents.clone()
        };
        assert!(body(&with).contains("APP_KEY='ssh-ed25519 KEY app'"), "{}", body(&with));
        assert!(!body(&files_of(&input, &backups)).contains("APP_KEY="), "no key, no block");
        // And what it wrote is what the next run reads back.
        assert_eq!(app_public_key(&body(&with)).as_deref(), Some("ssh-ed25519 KEY app"));
    }

    /// Modes are part of the contract: a wrapper reached over sudo is 0750
    /// root-owned, and the metrics collector is 0755 because a systemd unit
    /// runs it. A unit file itself carries no explicit mode on either route.
    #[test]
    fn the_modes_are_the_generators() {
        let files = files_of(&host(&["vaultwarden"], Some("bot"), HostRole::SingleHost), &uninstall::BackupPaths::default());
        let mode = |path: &str| files.iter().find(|f| f.path == path).unwrap().mode;
        assert_eq!(mode(backup_ctl::SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(update_ctl::SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(uninstall::SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(restore::SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(access::CONTAINER_CONTROL_SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(lockdown::SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(metrics::COLLECTOR_PATH), Some(0o755));
        assert_eq!(mode(metrics::UNIT_PATH), None);
    }
}
