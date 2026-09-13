//! `install-report.txt` — the one place an install's generated credentials are
//! written down.
//!
//! **Why the agent needs this at all.** Every password in this project is
//! minted ON THE SERVER (`__RANDOM__` in the setup script, `O_CREAT|O_EXCL`
//! `.env` writes in the agent). The app never sees them except by reading this
//! file back (`CommandCatalog.installReport`, deliberately sudo-free: the
//! control user owns it at 0600). An agent-installed host that writes no
//! report is therefore a host whose admin passwords exist only inside `.env`
//! files nobody told the user about.
//!
//! **This is the one host-half file that cannot be byte-identical to the
//! generator's, and saying why matters more than the fact.** The other
//! wrappers are shell SOURCE — the same bytes on both routes. The report is
//! shell OUTPUT: the script emits `echo "… $(grep '^ADMIN_TOKEN=' …)"` and the
//! server's shell resolves it at run time. The agent has no shell in this path
//! (Ф4's whole point), so it resolves the same values itself and writes the
//! TEXT. Parity is therefore against what the generated block PRINTS, and the
//! test proves it the only way that is not a re-reading of the source: it runs
//! the real fixture through a real bash in a sandbox and diffs stdout against
//! [`render`].
//!
//! **What stays exactly as the script has it, on purpose.** The report is
//! prose for a human, with one machine-readable exception: `GRYONIXNEXUS_DKIM
//! <record> <value>`, which `DKIMRecordParser` on the app side parses out of
//! the very same text. That line is ASCII and fixed-shape in every language
//! and must not be "improved" here — the app strips it before display and
//! shows the record on its own screen.

use crate::install::context::Input;
use crate::install::host::{backup_ctl, HostInput, HostRole, CATALOG_ORDER};

pub mod l10n;

/// Where the report lands, mirroring `SetupMarkers.reportFilePath`. Pinned on
/// the app side too (`CommandCatalog.installReport` cats this literal), so it
/// is a contract with already-installed machines, not a preference.
pub const REPORT_PATH: &str = "/var/lib/gryonixnexus/install-report.txt";

/// The machine-readable DKIM twin, mirrored by `ServerControl`'s
/// `DKIMRecordParser`.
const DKIM_MARKER: &str = "GRYONIXNEXUS_DKIM";

/// The two engine-specific DKIM dumpers. Both print the same
/// `GRYONIXNEXUS_DKIM <name> <value>` shape (the third, mailcow's, is an API
/// call instead) — see `dkim.rs`, which runs these for `GetDkimRecords`.
const DMS_DKIM_WRAPPER: &str = "/opt/gryonixnexus-dms-dkim.sh";
const MAILU_DKIM_WRAPPER: &str = "/opt/gryonixnexus-mailu-dkim.sh";

/// mailcow's admin API is reachable on loopback HTTPS only: its HTTP port
/// redirects unconditionally, which would loop.
const MAILCOW_HTTPS_PORT: u16 = 18443;

/// The panel's directory is fixed by `VPNPanelService.path` — unlike the other
/// services it is not a settable path.
const VPN_PANEL_PATH: &str = "/opt/gryonix-vpn-panel";

/// `OpenVPNService.clientName` — the single profile the install mints.
const OPENVPN_CLIENT: &str = "gryonixnexus";

/// `ShadowsocksService.method`, an AEAD-2022 cipher, which is why the SIP002
/// link percent-encodes the password instead of base64-ing the userinfo.
const SHADOWSOCKS_METHOD: &str = "2022-blake3-aes-256-gcm";

/// Vaultwarden's `.env` path is HARDCODED in the generator's report step
/// (`VaultwardenService.reportSteps`), not taken from settings the way every
/// other service's is. The port repeats it deliberately — byte parity is the
/// rule and a "fix" here would make the two routes disagree — but it is a
/// latent defect on BOTH routes: a deployment that moved Vaultwarden would
/// have its report read a path nothing writes, and print an empty token.
const VAULTWARDEN_ENV: &str = "/opt/vaultwarden/.env";

/// The units whose state the report prints, per host role. Scenario B's relay
/// carries no docker and no Caddy, so it reports on the tunnel instead.
const SERVICES_HOST_UNITS: &[&str] = &["nftables", "docker", "caddy"];
const RELAY_UNITS: &[&str] = &["nftables", "wg-quick@wg0"];

// MARK: - Facts

/// Everything in the report the agent cannot know without touching the host.
///
/// A trait rather than a pre-collected struct so that WHICH file a service's
/// line reads stays in this module and is exercised by the test: a collector
/// would move `/opt/vaultwarden/.env` out of the code under test and the
/// hardcoded-path defect above would become invisible.
pub trait Facts {
    /// `systemctl is-active <unit>`, or the empty string — the script's `||
    /// true` means a failing call still prints whatever it printed.
    fn systemctl_is_active(&self, unit: &str) -> String;

    /// A file's contents, `None` when it cannot be read. Note the difference
    /// the shell makes between the two consumers: `[ -s file ]` treats an
    /// EMPTY file as absent, `$(cat file)` strips trailing newlines.
    fn read_file(&self, path: &str) -> Option<String>;

    /// Runs a DKIM dumper wrapper ONCE and hands back its stdout, or the empty
    /// string.
    ///
    /// Not an `Option`: a missing wrapper, a wrapper that exits non-zero, and
    /// a wrapper that runs cleanly and prints no `GRYONIXNEXUS_DKIM` line are
    /// THE SAME OUTCOME on the shell side (verified against a real bash —
    /// see `dkim_wrapper_lines`'s doc), so a signature that could still tell
    /// them apart would be a distinction `render` never uses. Collapsing it
    /// here also keeps each call to this method to exactly once: an earlier
    /// version consulted it a second time (a helper re-ran the same
    /// child process to ask "was it missing") purely to pick the branch this
    /// simpler type makes unnecessary — on a real host that meant running the
    /// DKIM dumper twice per report for identical text.
    fn dkim_wrapper(&self, path: &str) -> String;

    /// mailcow's `/api/v1/get/dkim/<domain>`, already reduced to `.dkim_txt`.
    /// The empty string means "not ready", which is a normal state minutes
    /// after an install, not an error.
    fn mailcow_dkim(&self, api_key: &str, domain: &str, https_port: u16) -> String;

    /// `wg show <interface>` — the relay's report shows the handshake, which
    /// is legitimately absent until the home half runs.
    fn wg_show(&self, interface: &str) -> String;
}

// MARK: - Topology

/// The parts of the report that describe the DEPLOYMENT rather than a service.
///
/// Separate from [`Input`] on purpose: `Input`'s defaults are pinned
/// value-for-value to Swift's `ServiceSettings`, and a public IP is not a
/// service setting. Putting them here also keeps the "wrapper is a function of
/// the installed set" rule intact — these change with the topology, not with
/// what is installed.
///
/// An enum rather than one struct with optional halves because the relay's
/// report is a DIFFERENT DOCUMENT, not a subset: it describes a machine with
/// no services, no docker and no Caddy on it.
#[derive(Debug, Clone, PartialEq)]
pub enum Topology {
    /// Scenario A, scenario B's home half, and local-only.
    ServicesHost {
        /// The address the PTR record must resolve to. `None` for a local-only
        /// deployment, which has no public address to publish a PTR for — and
        /// for which the DNS reminder is dropped too, because no DNS artifact
        /// was ever generated (Caddy self-signs).
        ptr_ip: Option<String>,
        /// The name the PTR should answer with (`ptrHostname`).
        ptr_hostname: String,
        /// Scenario B's home half only: `<vps public ip>:<wg port>`, printed
        /// as the first extra line of the report.
        tunnel_endpoint: Option<String>,
    },
    /// Scenario B's relay half.
    Relay {
        wg_port: u16,
        /// The ports DNAT'd onward, in the order the script lists them.
        forwarded_ports: Vec<u16>,
        /// The home half's tunnel address, the DNAT target.
        home_wg_address: String,
        ptr_hostname: String,
    },
}

// MARK: - Rendering

/// The host's report.
///
/// Dispatch is on the ROLE, not on the topology variant, so a caller that
/// hands the relay's topology to a services host gets a loud panic instead of
/// a plausible-looking report about the wrong machine — the report is the one
/// place a deployment's passwords are written down, and a wrong one is worse
/// than none.
pub fn render(input: &HostInput, topology: &Topology, facts: &dyn Facts) -> String {
    match (input.role, topology) {
        (HostRole::VpsRelay, Topology::Relay { .. }) => render_relay(input, topology, facts),
        (HostRole::SingleHost | HostRole::HomeBackend, Topology::ServicesHost { .. }) => {
            render_services_host(input, topology, facts)
        }
        (role, topology) => unreachable!(
            "report topology does not match the host role: {role:?} with {topology:?}"
        ),
    }
}

fn render_services_host(input: &HostInput, topology: &Topology, facts: &dyn Facts) -> String {
    let Topology::ServicesHost {
        ptr_ip,
        ptr_hostname,
        tunnel_endpoint,
    } = topology
    else {
        unreachable!("render_services_host is only reached through render")
    };
    let l = input.language;
    let mut out = String::new();
    // `log()` in the generated script is `printf '\n==> %s\n'` — the blank
    // line before the heading is part of the report, and the app's stored copy
    // has always had it.
    out.push('\n');
    out.push_str(&format!("==> {}\n", l10n::report_title(l)));
    out.push_str(&format!("{}{}\n", l10n::domain_label(l), input.install.domain));

    // `SetupScripts.reportSections` builds these in this order: the tunnel
    // line (home only), then the mail host, then the PTR reminder.
    if let Some(endpoint) = tunnel_endpoint {
        out.push_str(&format!("{}\n", tunnel_report_line(input, endpoint)));
    }
    if let Some(engine) = mail_engine(input) {
        let _ = engine;
        out.push_str(&format!(
            "{}mail.{}\n",
            l10n::mail_host_label(l),
            input.install.domain
        ));
    }
    if let Some(ip) = ptr_ip {
        out.push_str(&format!("{}\n", l10n::ptr_reminder(l, ip, ptr_hostname)));
    }
    // The host's own backup passphrase, read off the file the install wrote —
    // the generated report does exactly the same (`$(cat …)`), which is why the
    // two can be executed against each other. Only hosts that carry something
    // encrypted have one, so the LINE is conditional on the same question the
    // generation is (`needs_stored_passphrase`), not on the file happening to
    // exist: a host whose file is unreadable must still show the label rather
    // than silently dropping a line the other route prints.
    if backup_ctl::needs_stored_passphrase(input) {
        let secret = facts
            .read_file(backup_ctl::PASSPHRASE_PATH)
            .unwrap_or_default();
        out.push_str(&format!("{}{}\n", l10n::backup_passphrase_label(l), secret));
    }

    out.push('\n');
    out.push_str(&format!("{}\n", l10n::service_status_header(l)));
    out.push_str(&unit_status_block(SERVICES_HOST_UNITS, facts));
    out.push('\n');

    if !input.install.local_only {
        out.push_str(&format!("{}\n", l10n::caddy_dns_reminder(l)));
    }

    let credentials = service_lines(input, facts);
    if !credentials.is_empty() {
        out.push('\n');
        out.push_str(&format!("{}\n", l10n::service_credentials_header(l)));
        out.push_str(&credentials);
    }
    out
}

fn render_relay(input: &HostInput, topology: &Topology, facts: &dyn Facts) -> String {
    let Topology::Relay {
        wg_port,
        forwarded_ports,
        home_wg_address,
        ptr_hostname,
    } = topology
    else {
        unreachable!("render_relay is only reached through render")
    };
    let l = input.language;
    let ports = forwarded_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = String::new();
    out.push('\n');
    out.push_str(&format!("==> {}\n", l10n::report_title(l)));
    out.push_str(&format!(
        "{}\n",
        l10n::vps_report_wire_guard(l, i64::from(*wg_port))
    ));
    out.push_str(&format!(
        "{}\n",
        l10n::vps_report_firewall(l, &ports, home_wg_address)
    ));
    out.push_str(&format!("{}\n", l10n::vps_report_forwarding(l)));
    out.push('\n');
    out.push_str(&format!("{}\n", l10n::service_status_header(l)));
    out.push_str(&unit_status_block(RELAY_UNITS, facts));
    out.push('\n');
    out.push_str(&format!("{}\n", l10n::vps_handshake_note(l)));
    let wg = facts.wg_show("wg0");
    out.push_str(&wg);
    out.push('\n');
    out.push_str(&format!("{}\n", l10n::next_steps_header(l)));
    out.push_str(&format!("  {}\n", l10n::vps_next_step_home(l)));
    out.push_str(&format!(
        "  {}\n",
        l10n::vps_next_step_ptr(l, ptr_hostname)
    ));
    out
}

/// `printf '  %-14s %s\n'` over the role's units — the width is the script's,
/// and it is what keeps the column aligned for `wg-quick@wg0` (13 characters)
/// next to `nftables`.
fn unit_status_block(units: &[&str], facts: &dyn Facts) -> String {
    let mut out = String::new();
    for unit in units {
        let status = facts.systemctl_is_active(unit);
        out.push_str(&format!("  {unit:<14} {status}\n"));
    }
    out
}

/// `L10nScripts.tunnelReportLine` — a padded label, the fixed middle, and the
/// note, composed here because the Swift original composes two picks (see the
/// extractor's note on PARTS functions).
fn tunnel_report_line(input: &HostInput, endpoint: &str) -> String {
    let l = input.language;
    format!(
        "{}wg0 -> {endpoint} {}",
        l10n::pad_label(&l10n::tunnel_report_line_label(l)),
        l10n::tunnel_report_line_note(l)
    )
}

// MARK: - Which services report, and in what order

/// The mail engine on this host, if any. The engines are mutually exclusive by
/// category, so at most one can be here.
fn mail_engine(input: &HostInput) -> Option<&str> {
    ["mailcow", "mailu", "docker-mailserver"]
        .into_iter()
        .find(|id| input.services.iter().any(|s| s == id))
}

/// The report's services, in `ServiceRegistry.all` order with the mail engine
/// pulled to the front (`MailContext.allSelectedServices` inserts it at 0),
/// and with the VPN panel implied by any VPN protocol exactly as
/// `additionalServices` implies it.
fn reporting_services(input: &HostInput) -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = CATALOG_ORDER
        .iter()
        .copied()
        .filter(|id| input.services.iter().any(|s| s == id))
        .collect();
    let panel = "vpn-panel";
    let has_protocol = ids.iter().any(|id| VPN_PROTOCOLS.contains(id));
    if has_protocol && !ids.contains(&panel) {
        // `CATALOG_ORDER` already ends with the panel, so re-inserting it
        // there keeps the generated order rather than appending blindly.
        let at = CATALOG_ORDER.iter().position(|id| *id == panel).unwrap();
        let before = ids
            .iter()
            .position(|id| CATALOG_ORDER.iter().position(|c| c == id).unwrap() > at)
            .unwrap_or(ids.len());
        ids.insert(before, panel);
    }
    if let Some(engine) = mail_engine(input) {
        ids.retain(|id| *id != engine);
        let engine: &'static str = CATALOG_ORDER.iter().find(|id| **id == engine).unwrap();
        ids.insert(0, engine);
    }
    ids
}

/// `ServiceID.vpnProtocols` — the panel is implied by any of these.
const VPN_PROTOCOLS: &[&str] = &[
    "wireguard-vpn",
    "amnezia-wg",
    "shadowsocks",
    "xray-reality",
    "openvpn",
];

fn service_lines(input: &HostInput, facts: &dyn Facts) -> String {
    let mut out = String::new();
    for id in reporting_services(input) {
        out.push_str(&service_block(id, input, facts));
    }
    out
}

/// One service's credential block. Every arm mirrors that service's
/// `reportSteps`; a service whose `reportSteps` is empty (plain WireGuard —
/// the panel speaks for it) contributes nothing.
fn service_block(id: &str, input: &HostInput, facts: &dyn Facts) -> String {
    let l = input.language;
    // The host's whole service list, not just the request that brought us
    // here: the addresses printed below are chosen against the neighbours
    // (`HostInput::install_among_neighbours`).
    let among = input.install_among_neighbours();
    let i = &among;
    let mut out = String::new();
    match id {
        "mailcow" => {
            let path = &i.mailcow_path;
            out.push_str(&format!(
                "Mailcow:      https://mail.{}  ({}: {path})\n",
                i.domain,
                l10n::directory_label(l)
            ));
            out.push_str(&format!("  {}: admin\n", l10n::administrator_label(l)));
            out.push_str(&format!("  {}: moohoo\n", l10n::password_label(l)));
            out.push_str(&format!("  {}\n", l10n::mailcow_default_password_note(l)));
            out.push_str(&format!("  {}\n", l10n::mailcow_auto_cert_note(l)));
            // `grep … | tail -n1`: generate_config.sh appends a second
            // API_KEY line when it regenerates, and the LAST one is live.
            let key = conf_value_last(facts, &format!("{path}/mailcow.conf"), "API_KEY");
            for domain in std::iter::once(&i.domain).chain(i.additional_domains.iter()) {
                let record = format!("dkim._domainkey.{domain}");
                let value = facts.mailcow_dkim(&key, domain, MAILCOW_HTTPS_PORT);
                if value.is_empty() {
                    out.push_str(&format!("  {}\n", l10n::mailcow_dkim_not_ready(l)));
                } else {
                    out.push_str(&format!("  {}\n", l10n::mailcow_dkim_header(l, &record)));
                    out.push_str(&format!("  {value}\n"));
                    out.push_str(&format!("{DKIM_MARKER} {record} {value}\n"));
                }
            }
        }
        "mailu" => {
            let path = &i.mailu_path;
            let host = format!("mail.{}", i.domain);
            out.push_str(&format!("Mailu:        https://{host}/admin\n"));
            out.push_str(&format!(
                "  {}:     https://{host}/webmail\n",
                l10n::webmail_label(l)
            ));
            out.push_str(&format!(
                "  {}: {}@{}\n",
                l10n::administrator_label(l),
                i.admin_username,
                i.domain
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{path}/.env"), "INITIAL_ADMIN_PW")
            ));
            out.push_str(&format!("  {}\n", l10n::mailu_client_ports_note(l)));
            out.push_str(&format!("  {}:\n", l10n::dkim_records_label(l)));
            out.push_str(&dkim_wrapper_lines(
                facts,
                MAILU_DKIM_WRAPPER,
                &l10n::mailu_dkim_pending_note(l),
            ));
        }
        "docker-mailserver" => {
            let path = &i.docker_mailserver_path;
            let host = format!("mail.{}", i.domain);
            out.push_str("Docker Mailserver:\n");
            out.push_str(&format!(
                "  {}:     https://{host}\n",
                l10n::webmail_label(l)
            ));
            out.push_str(&format!(
                "  {}: {}@{}\n",
                l10n::first_mailbox_label(l),
                i.admin_username,
                i.domain
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{path}/.env"), "FIRST_MAILBOX_PASSWORD")
            ));
            out.push_str(&format!("  {}\n", l10n::dms_mailboxes_note(l)));
            out.push_str(&format!("  {}:\n", l10n::dkim_records_label(l)));
            out.push_str(&dkim_wrapper_lines(
                facts,
                DMS_DKIM_WRAPPER,
                &l10n::dms_dkim_pending_note(l),
            ));
        }
        "vaultwarden" => {
            // `Input.vaultwarden_hostname` empty means "derive
            // `vault.<domain>`" (`context::Input`'s own doc on this field
            // family) — the field is read through `vaultwarden::hostname`,
            // never raw, or an install that never overrode the hostname (the
            // common case) would print `https://` with no host at all.
            let host = crate::install::vaultwarden::hostname(i);
            out.push_str(&format!("Vaultwarden:  https://{host}\n"));
            out.push_str(&format!(
                "  {}: https://{host}/admin\n",
                l10n::admin_panel_label(l)
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::vaultwarden_admin_token_label(l),
                env_value(facts, VAULTWARDEN_ENV, "ADMIN_TOKEN")
            ));
            out.push_str(&format!("  {}\n", l10n::vaultwarden_register_note(l)));
            out.push_str(&format!(
                "  {}\n",
                if i.vaultwarden_allow_signups {
                    l10n::vaultwarden_signups_open(l)
                } else {
                    l10n::vaultwarden_signups_closed(l)
                }
            ));
        }
        "psono" => {
            out.push_str(&format!("Psono:        https://{}\n", crate::install::psono::hostname(i)));
            // Psono's `manage.py createuser` takes an EMAIL, not a bare
            // username (`psono::admin_login` is the exact call the executor
            // itself makes — `execute.rs` reads it, not `i.admin_username`
            // raw). The report has to print the identity that was actually
            // created, or it would tell the user to sign in with a login
            // that does not exist.
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                crate::install::psono::admin_login(i)
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{}/.env", i.psono_path), "PSONO_ADMIN_PASSWORD")
            ));
        }
        "passbolt" => {
            out.push_str(&format!("Passbolt:     https://{}\n", crate::install::passbolt::hostname(i)));
            // `[ -s <file> ]`: an EMPTY registration-url file counts as absent,
            // which is the state a re-run leaves behind once the admin exists.
            let url_file = format!("{}/.registration-url", i.passbolt_path);
            match facts.read_file(&url_file) {
                Some(text) if !text.is_empty() => {
                    out.push_str(&format!("  {}\n", l10n::passbolt_setup_url_label(l)));
                    out.push_str(&format!("  {}\n", strip_trailing_newlines(&text)));
                }
                _ => out.push_str(&format!(
                    "  {}\n",
                    l10n::passbolt_already_configured_note(l)
                )),
            }
        }
        "nextcloud" => {
            out.push_str(&format!("Nextcloud:    https://{}\n", crate::install::nextcloud::hostname(i)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                i.admin_username
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(
                    facts,
                    &format!("{}/.env", i.nextcloud_path),
                    "NEXTCLOUD_ADMIN_PASSWORD"
                )
            ));
        }
        "seafile" => {
            out.push_str(&format!("Seafile:      https://{}\n", crate::install::seafile::hostname(i)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                seafile_admin_login(i)
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(
                    facts,
                    &format!("{}/.env", i.seafile_path),
                    "SEAFILE_ADMIN_PASSWORD"
                )
            ));
        }
        "immich" => {
            out.push_str(&format!("Immich:       https://{}\n", crate::install::immich::hostname(i)));
            out.push_str(&format!("  {}\n", l10n::immich_admin_warning(l)));
        }
        "photoprism" => {
            let path = &i.photoprism_path;
            out.push_str(&format!("PhotoPrism:   https://{}\n", crate::install::photoprism::hostname(i)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                i.admin_username
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{path}/.env"), "PHOTOPRISM_ADMIN_PASSWORD")
            ));
            out.push_str(&format!(
                "  {}: {path}/originals\n",
                l10n::photoprism_originals_label(l)
            ));
        }
        "gitlab" => {
            let host = crate::install::gitlab::hostname(i);
            let host = host.as_str();
            out.push_str(&format!("GitLab:       https://{host}\n"));
            // "root" is GitLab's own fixed administrator name — it cannot be
            // told to use the shared `adminUsername` at install time.
            out.push_str(&format!("  {}: root\n", l10n::administrator_label(l)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(
                    facts,
                    &format!("{}/.env", i.gitlab_path),
                    "GITLAB_ROOT_PASSWORD"
                )
            ));
            out.push_str(&format!("  {}\n", l10n::gitlab_registration_closed_note(l)));
            out.push_str(&format!("  {}\n", l10n::gitlab_first_start_note(l)));
            out.push_str(&format!(
                "  {}\n",
                if i.gitlab_ssh_port == 0 {
                    l10n::gitlab_ssh_disabled_note(l)
                } else {
                    l10n::gitlab_ssh_note(l, host, i64::from(i.gitlab_ssh_port))
                }
            ));
        }
        "forgejo" => {
            let host = crate::install::forgejo::hostname(i);
            let host = host.as_str();
            out.push_str(&format!("Forgejo:      https://{host}\n"));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                i.admin_username
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(
                    facts,
                    &format!("{}/.env", i.forgejo_path),
                    "FORGEJO_ADMIN_PASSWORD"
                )
            ));
            out.push_str(&format!("  {}\n", l10n::forgejo_registration_closed_note(l)));
            out.push_str(&format!(
                "  {}\n",
                if i.forgejo_ssh_port == 0 {
                    l10n::forgejo_ssh_disabled_note(l)
                } else {
                    l10n::forgejo_ssh_note(l, host, i64::from(i.forgejo_ssh_port))
                }
            ));
        }
        "minecraft-java" => {
            let address = if i.minecraft_java_port == 25565 {
                format!("play.{}", i.domain)
            } else {
                format!("play.{}:{}", i.domain, i.minecraft_java_port)
            };
            out.push_str(&format!("Minecraft (Java):  {address}\n"));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::minecraft_flavour_label(l),
                i.minecraft_java_flavour
            ));
            if !i.minecraft_java_accepts_eula {
                out.push_str(&format!("  {}\n", l10n::minecraft_eula_not_accepted(l)));
            }
            // **The floating axis, said out loud.** With no VERSION the
            // image resolves the latest release, so the jar beside an existing
            // world changes on the next restart after one.
            if i.minecraft_java_version.trim().is_empty() {
                out.push_str(&format!("  {}\n", l10n::minecraft_version_follows_latest(l)));
            }
            if i.minecraft_java_whitelist.trim().is_empty() {
                out.push_str(&format!("  {}\n", l10n::minecraft_no_whitelist(l)));
            }
        }
        "minecraft-bedrock" => {
            out.push_str(&format!(
                "Minecraft (Bedrock): play.{}:{}\n",
                i.domain, i.minecraft_bedrock_port
            ));
            out.push_str(&format!("  {}\n", l10n::minecraft_bedrock_on_arm(l)));
            if !i.minecraft_bedrock_accepts_eula {
                out.push_str(&format!("  {}\n", l10n::minecraft_eula_not_accepted(l)));
            }
        }
        "crafty-controller" => {
            out.push_str(&format!(
                "Crafty Controller: https://{}\n",
                crate::install::crafty::hostname(i)
            ));
            out.push_str(&format!(
                "  {}: {}/config/default-creds.txt\n",
                l10n::crafty_first_login(l),
                i.crafty_path
            ));
        }
        "jellyfin" => {
            out.push_str(&format!("Jellyfin:     https://{}\n", crate::install::jellyfin::hostname(i)));
            out.push_str(&format!("  {}\n", l10n::jellyfin_admin_warning(l)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::jellyfin_library_label(l),
                i.jellyfin_media_path
            ));
        }
        "ollama" => {
            out.push_str(&format!(
                "Ollama:       127.0.0.1:{}\n",
                crate::install::ollama::API_PORT
            ));
            out.push_str(&format!("  {}\n", l10n::ollama_no_models_note(l)));
            out.push_str(&format!(
                "  docker exec -it {} ollama pull llama3.2\n",
                crate::install::ollama::CONTAINER
            ));
            out.push_str(&format!("  {}\n", l10n::ollama_model_size_note(l)));
            // The card's line reads the HOST rather than the deployment: the
            // override exists only if a driver answered during the install, so
            // testing for it is the difference between reporting what was asked
            // for and reporting what happened.
            if i.ollama_uses_gpu {
                let override_path = crate::install::ollama::gpu_override_path(i);
                if facts.read_file(&override_path).is_some() {
                    out.push_str(&format!("  {}\n", l10n::ollama_gpu_enabled_note(l)));
                } else {
                    out.push_str(&format!("  {}\n", l10n::ollama_gpu_missing_note(l)));
                }
            }
        }
        "litellm" => {
            out.push_str(&format!(
                "LiteLLM:      https://{}\n",
                crate::install::litellm::hostname(i)
            ));
            // `$(cat … || echo -)` on the shell side, and the difference the
            // Facts doc names is exactly this one: a missing file is a dash
            // rather than an empty label.
            let key = facts
                .read_file(crate::install::litellm::GATEWAY_KEY_PATH)
                .map(|text| text.trim_end_matches('\n').to_string())
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!("  {}: {key}\n", l10n::lite_llm_master_key_label(l)));
            out.push_str(&format!("  {}\n", l10n::lite_llm_keys_note(l)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::lite_llm_keys_file_label(l),
                crate::install::llm_keys::KEYS_ENV_PATH
            ));
        }
        "anythingllm" => {
            out.push_str(&format!(
                "AnythingLLM:  https://{}\n",
                crate::install::anythingllm::hostname(i)
            ));
            out.push_str(&format!("  {}\n", l10n::anythingllm_admin_warning(l)));
            // Printed only where the host runs neither a gateway nor an
            // engine — the same branch the Swift report takes. Not an error:
            // the embedder is in the container, so documents can be uploaded
            // and searched with no model at all.
            if crate::install::anythingllm::model_source(&input.services).is_none() {
                out.push_str(&format!("  {}\n", l10n::anythingllm_no_model_note(l)));
            }
            out.push_str(&format!("  {}\n", l10n::anythingllm_settings_note(l)));
        }
        "qdrant" => {
            // No address to print: the store publishes nothing. A service with
            // no line at all in the report reads as one that failed to
            // install, so it says what it is instead.
            out.push_str(&format!(
                "Qdrant:       127.0.0.1:{}\n",
                crate::install::qdrant::API_PORT
            ));
            out.push_str(&format!("  {}\n", l10n::qdrant_loopback_note(l)));
        }
        "searxng" => {
            // No address to publish: the callers are the containers beside it.
            // A service with no line at all reads as one that failed to
            // install, so it says what it is instead.
            out.push_str(&format!(
                "SearXNG:      127.0.0.1:{}\n",
                crate::install::searxng::WEB_UI_PORT
            ));
            out.push_str(&format!("  {}\n", l10n::searxng_loopback_note(l)));
        }
        "openclaw" => {
            out.push_str(&format!(
                "OpenClaw:     https://{}\n",
                crate::install::openclaw::hostname(i)
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::openclaw_token_note(l),
                env_value(facts, &format!("{}/.env", i.openclaw_path), "OPENCLAW_GATEWAY_TOKEN")
            ));
            out.push_str(&format!("  {}\n", l10n::openclaw_pairing_note(l)));
            // The provider is a field somebody fills in rather than one the
            // install can fill for them, so the report hands over the address
            // of whichever backend this host actually runs.
            match crate::install::openclaw::model_endpoint(&input.services) {
                Some(endpoint) => out.push_str(&format!(
                    "  {}: {endpoint}\n",
                    l10n::openclaw_model_note(l)
                )),
                None => out.push_str(&format!("  {}\n", l10n::openclaw_no_model_note(l))),
            }
        }
        "n8n" => {
            out.push_str(&format!("n8n:          https://{}\n", crate::install::n8n::hostname(i)));
            out.push_str(&format!("  {}\n", l10n::n8n_owner_warning(l)));
            // Said here because this is the one service whose site the admin
            // guard does not cover whole, and somebody who assumed it did
            // would publish more than they meant to.
            out.push_str(&format!("  {}\n", l10n::n8n_webhooks_public_note(l)));
        }
        "open-webui" => {
            out.push_str(&format!(
                "Open WebUI:   https://{}\n",
                crate::install::open_webui::hostname(i)
            ));
            out.push_str(&format!("  {}\n", l10n::open_web_ui_admin_warning(l)));
            // Printed only when the host runs no engine — the same branch the
            // Swift report takes, and for the same reason: an empty model list
            // with no explanation reads as a broken install.
            if crate::install::open_webui::engine_url(&input.services).is_none() {
                out.push_str(&format!("  {}\n", l10n::open_web_ui_no_engine_note(l)));
            }
        }
        "cloudflared" => {
            out.push_str("Cloudflare Tunnel:\n");
            out.push_str(&format!(
                "  {}: {}/.env\n",
                l10n::cloudflared_token_note(l),
                i.cloudflared_path
            ));
            out.push_str(&format!("  {}: https://127.0.0.1:443\n", l10n::cloudflared_routes_note(l)));
            out.push_str(&format!("  {}\n", l10n::cloudflared_no_ports_note(l)));
        }
        "headscale" => {
            let host = crate::install::headscale::hostname(i);
            let base = crate::install::headscale::base_domain(i);
            out.push_str(&format!("Headscale: https://{host}\n"));
            out.push_str(&format!("  {}\n", l10n::headscale_no_web_ui_note(l)));
            out.push_str(&format!("  {}:\n", l10n::headscale_create_user_note(l)));
            out.push_str(&format!(
                "    sudo docker exec {} headscale users create <name>\n",
                crate::install::headscale::CONTAINER
            ));
            out.push_str(&format!(
                "    sudo docker exec {} headscale preauthkeys create --user <id> --reusable --expiration 24h\n",
                crate::install::headscale::CONTAINER
            ));
            out.push_str(&format!("  {}:\n", l10n::headscale_join_note(l)));
            out.push_str(&format!("    tailscale up --login-server https://{host} --authkey <key>\n"));
            out.push_str(&format!("  {}: <device>.{base}\n", l10n::headscale_magic_dns_note(l)));
        }
        "tailscale-node" => {
            // Its own block even though it is implicit: the report is the one
            // place the owner learns the NAME their devices will use, and it
            // is derived (the first label of the domain), not something they
            // typed.
            let name = crate::install::tailscale::node_name(i);
            let base = crate::install::headscale::base_domain(i);
            out.push_str(&format!("{}: {name}.{base}\n", l10n::mesh_node_title(l)));
            out.push_str(&format!("  {}\n", l10n::mesh_node_explain_note(l)));
        }
        "adguard-home" => {
            let host = crate::install::adguard::hostname(i);
            let host = host.as_str();
            out.push_str(&format!("AdGuard Home: https://{host}\n"));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                i.admin_username
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(
                    facts,
                    &format!("{}/.env", i.adguard_path),
                    "ADGUARD_ADMIN_PASSWORD"
                )
            ));
            out.push_str(&format!(
                "  {}: https://{host}/dns-query\n",
                l10n::adguard_do_h_note(l)
            ));
            out.push_str(&format!("  {}\n", l10n::adguard_plain_dns_note(l)));
        }
        "pihole" => {
            let host = crate::install::pihole::hostname(i);
            let host = host.as_str();
            out.push_str(&format!("Pi-hole: https://{host}/admin\n"));
            // No administrator line: Pi-hole's login IS the password, there is
            // no user name to print. A line naming `admin_username` here would
            // be a credential the panel does not accept.
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{}/.env", i.pihole_path), "PIHOLE_ADMIN_PASSWORD")
            ));
            // Which clients can actually USE the filter — printed on every
            // install, because a resolver nobody can reach looks broken rather
            // than restricted.
            out.push_str(&format!(
                "  {}\n",
                if i.pihole_serves_network {
                    l10n::pihole_serves_network_note(l)
                } else {
                    l10n::pihole_loopback_note(l)
                }
            ));
        }
        "authelia" => {
            let host = crate::install::authelia::hostname(i);
            out.push_str(&format!("Authelia: https://{host}\n"));
            out.push_str(&format!("  {}: {}\n", l10n::administrator_label(l), i.admin_username));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{}/.env", i.authelia_path), "AUTHELIA_ADMIN_PASSWORD")
            ));
            // Which sites it stands in front of. The rendered report is read
            // by whoever is about to be asked for a password they did not
            // expect — naming them is the difference between a feature and a
            // surprise.
            let names = crate::install::authelia::protected_hostnames(i, &input.services);
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::authelia_protects_note(l),
                if names.is_empty() { "—".to_string() } else { names.join(", ") }
            ));
        }
        "homepage" => {
            let host = crate::install::homepage::hostname(i);
            out.push_str(&format!("Homepage: https://{host}\n"));
            out.push_str(&format!(
                "  {}: {}/config/services.yaml\n",
                l10n::homepage_generated_note(l),
                i.homepage_path
            ));
            out.push_str(&format!(
                "  {}: {}/config/bookmarks.yaml\n",
                l10n::homepage_own_edits_note(l),
                i.homepage_path
            ));
        }
        // Plain WireGuard has no report block of its own: the panel IS the
        // WireGuard server and speaks for it.
        "wireguard-vpn" => {}
        "amnezia-wg" => {
            // Every VPN protocol shares the panel's `vpn.<domain>` — same
            // "empty means derive" rule, resolved through the one function
            // that owns it (`vpn::panel::hostname`) rather than the raw
            // possibly-empty field.
            out.push_str(&format!(
                "AmneziaWG: {}:{} (UDP)\n",
                crate::install::vpn::panel::hostname(i), i.amnezia_wg_port
            ));
            out.push_str(&format!(
                "  {}\n",
                l10n::amnezia_admin_via_wire_guard_note(l)
            ));
        }
        "shadowsocks" => {
            let endpoint = format!("{}:{}", crate::install::vpn::panel::hostname(i), i.shadowsocks_port);
            out.push_str(&format!("Shadowsocks: {endpoint} (TCP+UDP)\n"));
            let password = shadowsocks_password(facts, &i.shadowsocks_path);
            out.push_str(&format!("  {}:\n", l10n::shadowsocks_link_label(l)));
            out.push_str(&format!(
                "  ss://{SHADOWSOCKS_METHOD}:{}@{endpoint}#gryonixNexus\n",
                percent_encode_userinfo(&password)
            ));
            out.push_str(&format!("  {}\n", l10n::shadowsocks_clients_note(l)));
            out.push_str(&format!("  {}\n", l10n::admin_via_wire_guard_note(l)));
        }
        "xray-reality" => {
            out.push_str(&format!(
                "VLESS/Reality: {}:{} (TCP)\n",
                crate::install::vpn::panel::hostname(i), i.xray_reality_port
            ));
            out.push_str(&format!("  {}:\n", l10n::xray_link_label(l)));
            let link = facts
                .read_file(&format!("{}/link.txt", i.xray_reality_path))
                .unwrap_or_default();
            out.push_str(&format!("  {}\n", strip_trailing_newlines(&link)));
            out.push_str(&format!("  {}\n", l10n::xray_clients_note(l)));
            out.push_str(&format!("  {}\n", l10n::admin_via_wire_guard_note(l)));
        }
        "openvpn" => {
            let path = &i.openvpn_path;
            out.push_str(&format!(
                "OpenVPN: {}:{} (UDP)\n",
                crate::install::vpn::panel::hostname(i), i.openvpn_port
            ));
            out.push_str(&format!("  {}:\n", l10n::open_vpn_config_label(l)));
            out.push_str(&format!("  ----- BEGIN {OPENVPN_CLIENT}.ovpn -----\n"));
            // `cat` — unlike the `$(cat …)` lines, this one keeps the file
            // exactly as it is, trailing newline and all. Verified against a
            // real bash: a file with NO trailing newline runs straight into
            // the very next `echo`'s text on the same line — `cat` never
            // synthesizes bytes the file does not have. An earlier version of
            // this port padded a missing trailing newline "for readability",
            // which is exactly a case of the two routes disagreeing: the
            // generated script would run the marker onto the profile's last
            // line, and this port would not.
            if let Some(profile) = facts.read_file(&format!("{path}/{OPENVPN_CLIENT}.ovpn")) {
                out.push_str(&profile);
            }
            out.push_str(&format!("  ----- END {OPENVPN_CLIENT}.ovpn -----\n"));
            out.push_str(&format!("  {}\n", l10n::open_vpn_clients_note(l)));
            out.push_str(&format!("  {}\n", l10n::admin_via_wire_guard_note(l)));
        }
        "vpn-panel" => {
            let host = crate::install::vpn::panel::hostname(i);
            let host = host.as_str();
            out.push_str(&format!("VPN Panel: https://{host}\n"));
            out.push_str(&format!(
                "  {}: https://{host}\n",
                l10n::admin_panel_label(l)
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                env_value(facts, &format!("{VPN_PANEL_PATH}/.env"), "ADMIN_USER")
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{VPN_PANEL_PATH}/.env"), "ADMIN_PASSWORD")
            ));
            out.push_str(&format!("  {}\n", l10n::vpn_clients_note(l)));
        }
        other => unreachable!("report block asked for an id outside CATALOG_ORDER: {other}"),
    }
    out
}

// MARK: - Reading what the shell read

/// `grep '^KEY=' file | cut -d= -f2-` — the FIRST match, everything after the
/// first `=`, and the empty string when the file or key is missing (the shell
/// pipeline prints nothing rather than failing).
fn env_value(facts: &dyn Facts, path: &str, key: &str) -> String {
    let text = facts.read_file(path).unwrap_or_default();
    let prefix = format!("{key}=");
    text.lines()
        .find(|line| line.starts_with(&prefix))
        .map(|line| line[prefix.len()..].to_string())
        .unwrap_or_default()
}

/// The same, but `| tail -n1` — mailcow's `generate_config.sh` appends a
/// second `API_KEY` when it regenerates and the LAST one is the live one.
fn conf_value_last(facts: &dyn Facts, path: &str, key: &str) -> String {
    let text = facts.read_file(path).unwrap_or_default();
    let prefix = format!("{key}=");
    text.lines()
        .filter(|line| line.starts_with(&prefix))
        .next_back()
        .map(|line| line[prefix.len()..].to_string())
        .unwrap_or_default()
}

/// `<wrapper> | grep '^GRYONIXNEXUS_DKIM ' | while read -r _ NAME VALUE` — the
/// records indented under the label, or the engine's "not ready" note.
///
/// **The `|| echo …` fallback fires whenever grep matches nothing — not only
/// when the wrapper is missing.** The generated script runs under
/// `set -euo pipefail` (the report block only ever suspends `-e`, never
/// `-o pipefail` — see `install/host/mod.rs`'s module doc), so the pipeline's
/// exit status is the last non-zero status among wrapper/grep/`while`, not
/// just the `while` loop's own. Two things collapse into the SAME outcome
/// that a first read of the shell suggests are different:
/// - a `while read` loop that iterates zero times exits 0 on its own (bash:
///   "the exit status … is the exit status of the last command executed, or
///   zero if none was executed") — so WITHOUT pipefail this fallback would be
///   dead code, verified by hand against a real bash;
/// - WITH pipefail, `grep` exiting 1 (no match) makes the pipeline non-zero
///   regardless of why grep saw no matching line: the wrapper missing (exec
///   fails), the wrapper failing, or the wrapper running cleanly and printing
///   text with no `GRYONIXNEXUS_DKIM` line in it. All three print the pending
///   note. A DMS host whose DKIM key has not been minted yet is exactly the
///   third case, and it is the common one, not an edge case.
///
/// The earlier port distinguished "wrapper produced `None`" (prints the
/// pending note) from "wrapper produced `Some("")`/no marker line" (printed
/// nothing) — plausible from reading the shell, contradicted by running it:
/// `printf 'hello\nworld\n' | grep …| while read …; done || echo NOT-READY`
/// prints NOT-READY under `set -o pipefail` exactly like a missing wrapper
/// does. So this function does not ask "was the wrapper missing" at all —
/// only "did any marker line survive the grep", which is what the real
/// pipeline's exit status actually tracks.
///
/// Note also what the shell's `while read -r _ NAME VALUE` does with a value
/// that contains spaces: it does NOT split it, the last variable takes the
/// rest of the line. DKIM values are one token anyway, but the port must not
/// "helpfully" re-split.
fn dkim_wrapper_lines(facts: &dyn Facts, wrapper: &str, pending_note: &str) -> String {
    // Exactly one call: on a real host this runs the DKIM dumper as a child
    // process, and the shell it mirrors only ever runs it once per report too.
    let stdout = facts.dkim_wrapper(wrapper);
    let marker = format!("{DKIM_MARKER} ");
    let mut lines = String::new();
    for line in stdout.lines().filter(|l| l.starts_with(&marker)) {
        let mut parts = line.splitn(3, ' ');
        let (_, name, value) = (parts.next(), parts.next(), parts.next());
        if let (Some(name), Some(value)) = (name, value) {
            lines.push_str(&format!("    {name} TXT {value}\n"));
        }
    }
    if lines.is_empty() {
        format!("    {pending_note}\n")
    } else {
        lines
    }
}

/// `sed -n 's/.*"password"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p` over
/// the Shadowsocks config — the LAST match wins, because `sed -n …p` prints
/// every match and command substitution keeps them all; in practice the file
/// has one.
fn shadowsocks_password(facts: &dyn Facts, path: &str) -> String {
    let text = facts
        .read_file(&format!("{path}/config.json"))
        .unwrap_or_default();
    let mut found = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.split_once("\"password\"") {
            let after = rest.1.trim_start();
            let Some(after) = after.strip_prefix(':') else {
                continue;
            };
            let after = after.trim_start();
            if let Some(after) = after.strip_prefix('"') {
                if let Some(end) = after.find('"') {
                    found.push(after[..end].to_string());
                }
            }
        }
    }
    found.join("\n")
}

/// The SIP002 userinfo escape the script does with three `sed` expressions.
/// Only these three characters — the password is base64, so `+`, `/` and `=`
/// are the only ones that can appear and need escaping.
fn percent_encode_userinfo(password: &str) -> String {
    password
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

/// Seafile and Psono both take the shared admin username, but Seafile's login
/// is an ADDRESS — its own installer insists on one.
fn seafile_admin_login(input: &Input) -> String {
    format!("{}@{}", input.admin_username, input.domain)
}

/// Command substitution strips trailing newlines; `cat` inside `echo "$(…)"`
/// therefore never contributes a blank line of its own.
fn strip_trailing_newlines(text: &str) -> &str {
    text.trim_end_matches('\n')
}

#[cfg(test)]
mod tests;
