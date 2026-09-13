//! docker-mailserver's install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/DockerMailserverService.swift`.
//!
//! Срез 4.1 ported the DECLARATIVE half only (compose file, env template,
//! hostname, DNS hostnames, firewall ports, Caddy ingress/site) and parked it
//! standalone, unreachable from `route()`. Срез 4.9 adds the second half of
//! the DECLARATIVE content — every FILE the install writes that is not the
//! compose file: the certificate-sync script and its two systemd units, and
//! the DKIM-dump wrapper. They live here, with the rest of the file contents,
//! for the same reason `seafile::csrf_trusted_origins_line` does: what a file
//! should CONTAIN is a function of `Input`, and only the writing of it is
//! imperative (`execute::install_docker_mailserver_steps`).
//!
//! **The eight live-run defects GOTCHAS.md records for this engine are the
//! reason most of this file exists**, and five of them meant the service did
//! not work AT ALL. Where each one now lives:
//! 1. `SSL_TYPE=manual` crash-looping with no certificate → the placeholder
//!    certificate, `placeholder_cert_args` + `certs_dir` (executed before the
//!    first `up -d`, which is the whole point of the ordering).
//! 2. A readiness probe that can never pass on a fresh install →
//!    `READINESS_PROBE_ARGS` is `setup help`, never `setup email list`.
//! 3. The DKIM selector (`dkim`, not the engine default `mail`) →
//!    `DKIM_SELECTOR`, spelled out in `dkim_config_args` AND in the dump
//!    wrapper's marker line, because `DNSRecordGenerator`/`dns_records`
//!    publishes `dkim._domainkey`.
//! 4. The DKIM dump glob (`config/opendkim/keys/*/dkim.txt`, NOT rspamd's
//!    tree) → `dkim_dump_script`, comments included: that comment is the
//!    record of a wrapper that was confidently wrong for months.
//! 5. Roundcube's TLS peer-name check → the compose network alias in
//!    `compose_contents`.
//! 6. Roundcube's sqlite living in the container layer → the
//!    `webmail-db:/var/roundcube/db` mount in `compose_contents`.
//! 7. Passwords in `docker exec` argv → the mailbox is created with the
//!    password on STDIN (`execute::dms_exec_stdin`); nothing here puts a
//!    secret in an argv builder.
//! 8. `setup email list` exiting 1 on an empty install → the guard lives in
//!    the wrapper this port deliberately does NOT write and in `mailbox.rs`,
//!    which already reimplements it; see `execute`'s own doc.
//!
//! **Two things this engine does NOT have, unlike AdGuard**:
//! - No hostname override. docker-mailserver's hostname is always
//!   `mail.<domain>` — the Swift type's own doc calls this out explicitly
//!   ("a second source of truth buys nothing and costs an ACME failure"),
//!   because that one name is a contract between the MX record, the A
//!   record, Caddy's certificate and the engine's own SMTP banner.
//! - `dns_hostnames` returns nothing (see that function's doc) — unlike
//!   AdGuard, whose one DNS name IS its ingress hostname.
//!
//! **Still not ported here**: `extraSudoers` (the agent provisions no
//! sudoers at all — it IS root, and the SSH route's whitelist is the setup
//! script's job), the mailbox wrapper (see `execute`), `reportSteps`,
//! `actions`, `updateSpec`, `uninstallSpec`.

use super::FirewallPort;
use crate::install::caddy::{self, WebIngress};
use crate::install::context::Input;

/// Exact pinned tag, genuinely multi-arch (the index carries amd64 AND
/// arm64) — unlike some of this catalog's other "multi-arch" tags, which
/// have turned out fictitious under an ELF-header check (see
/// `install::adguard`'s `IMAGE` doc and GOTCHAS.md). A floating `latest` is
/// avoided for the same reason as everywhere else: an unattended `pull`
/// must not be able to change the mail stack.
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "docker-mailserver";

pub const IMAGE: &str = "ghcr.io/docker-mailserver/docker-mailserver:15.1.0";
/// Roundcube supplies the webmail this engine has none of. The apache
/// flavour serves HTTP itself (no second container for its own nginx, the
/// way the fpm-alpine flavour would need), which is what Caddy proxies.
pub const WEBMAIL_IMAGE: &str = "roundcube/roundcubemail:1.6.17-apache";
pub const COMPOSE_PROJECT: &str = "dockermailserver";
pub const CONTAINER: &str = "mailserver";
pub const WEBMAIL_CONTAINER: &str = "mailserver-webmail";
/// Loopback port Caddy proxies the webmail to. Distinct from every other
/// service's upstream (8080/18443 mailcow, 8081 nextcloud, 8082
/// vaultwarden, 8083 Forgejo, 8084 GitLab, 8085 Mailu, 8087 AdGuard Home).
pub const WEB_UI_PORT: u16 = 8086;

/// `DockerMailserverService.certSyncScriptPath` / `.certSyncUnit`. Caddy owns
/// the ACME account for `mail.<domain>` on this host, so the engine is HANDED
/// the certificate instead of getting its own — one process per name, or two
/// clients race each other into Let's Encrypt's failure quota.
pub const CERT_SYNC_SCRIPT_PATH: &str = "/opt/gryonixnexus-dms-cert-sync.sh";
pub const CERT_SYNC_UNIT: &str = "gryonixnexus-dms-cert-sync";
/// `DockerMailserverService.dkimDumpScriptPath`. Pinned as a literal on THREE
/// sides now — the Swift generator, this module, and `dkim.rs`'s own engine
/// table, which runs exactly this path. That is why the agent has to write it
/// (see `execute::write_dms_management_scripts`).
pub const DKIM_DUMP_SCRIPT_PATH: &str = "/opt/gryonixnexus-dms-dkim.sh";
/// The mailbox wrapper's path. Carried as a constant even though this port
/// deliberately does not WRITE the file, so the reason is attached to the
/// name rather than living only in a commit message — see
/// `execute::write_dms_management_scripts`.
#[allow(dead_code)]
pub const MAILBOX_SCRIPT_PATH: &str = "/opt/gryonixnexus-dms-mailbox.sh";
pub const DKIM_MARKER: &str = "GRYONIXNEXUS_DKIM";
pub const DKIM_DUMP_DONE_MARKER: &str = "GRYONIXNEXUS_DKIM_DONE";
/// Spelled out, because the engine's own default is `mail` while the DNS
/// artifact this project generates publishes `dkim._domainkey` — a mismatch
/// nothing reports and every signature silently fails on (GOTCHAS.md,
/// live-found). Any new mail engine has to be checked against
/// `dns_records`'s selector the same way.
pub const DKIM_SELECTOR: &str = "dkim";
pub const DKIM_KEY_SIZE: u32 = 2048;

/// A port of the hostname embedded throughout `DockerMailserverService`
/// (`composeFile`'s `let hostname = "mail.\(context.domain)"`, echoed by
/// `requiredHostname(forDomain:)`, `envTemplate`, `certSyncStep`,
/// `webIngress` and `reportSteps`). Always `mail.<domain>` — see this
/// module's doc for why there is no override field, unlike AdGuard.
pub fn hostname(input: &Input) -> String {
    format!("mail.{}", input.domain)
}

/// Every mail domain this install signs for: the primary plus every
/// additional domain, in that order — a port of `setupSteps`'s
/// `[context.domain] + context.additionalDomains`. One DKIM key per entry.
pub fn mail_domains(input: &Input) -> Vec<String> {
    let mut domains = vec![input.domain.clone()];
    domains.extend(input.additional_domains.iter().cloned());
    domains
}

/// The first mailbox this install creates: the deployment's shared admin name
/// at the primary domain. Same identity `usesSharedAdminLogin` gives every
/// other service that has an account.
pub fn admin_mailbox(input: &Input) -> String {
    format!("{}@{}", input.admin_username, input.domain)
}

/// The directories `install -d -m 755` creates, in the Swift order. The
/// certificate directory is NOT in this list: it is 0700 (`certs_dir`).
pub fn directories_0755(input: &Input) -> Vec<String> {
    let path = &input.docker_mailserver_path;
    let mut dirs = vec![path.clone()];
    for name in ["mail-data", "mail-state", "mail-logs", "config", "webmail", "webmail-db"] {
        dirs.push(format!("{path}/{name}"));
    }
    dirs
}

/// `install -d -m 700 <path>/certs` — root-only on purpose: the container
/// reads it read-only and nothing else on the host has business there.
pub fn certs_dir(input: &Input) -> String {
    format!("{}/certs", input.docker_mailserver_path)
}

pub fn cert_pem_path(input: &Input) -> String {
    format!("{}/cert.pem", certs_dir(input))
}

pub fn key_pem_path(input: &Input) -> String {
    format!("{}/key.pem", certs_dir(input))
}

/// The argv of the self-signed PLACEHOLDER certificate, port for port from
/// `setupSteps`'s `openssl req` — one argv element per shell word, no shell.
///
/// **This is the fix for the defect that kept the engine from ever
/// starting.** `SSL_TYPE=manual` does not degrade when the files are
/// missing: the engine prints "File … does not exist!", shuts down, and
/// `restart: unless-stopped` turns that into a permanent crash loop — and a
/// container stuck in that loop never gets its first mailbox or its DKIM keys
/// either. Caddy only obtains the real certificate at the END of the install,
/// so on a fresh host there is nothing to point at yet. The placeholder lets
/// the engine boot; the sync timer replaces it the moment Caddy has the real
/// one.
pub fn placeholder_cert_args(input: &Input) -> Vec<String> {
    let host = hostname(input);
    vec![
        "req".to_string(),
        "-x509".to_string(),
        "-newkey".to_string(),
        "rsa:2048".to_string(),
        "-nodes".to_string(),
        "-days".to_string(),
        "3650".to_string(),
        "-subj".to_string(),
        format!("/CN={host}"),
        "-addext".to_string(),
        format!("subjectAltName=DNS:{host}"),
        "-keyout".to_string(),
        key_pem_path(input),
        "-out".to_string(),
        cert_pem_path(input),
    ]
}

/// The readiness probe, and it is `setup help` for a reason paid for live:
/// `setup email list` exits 1 for as long as no account exists — which is
/// exactly the state of every fresh install — so a probe built on it answered
/// "not ready" until the deadline ran out, and neither the first mailbox nor
/// the DKIM keys were EVER created. The probe has to be something that does
/// not depend on state.
pub const READINESS_PROBE_ARGS: &[&str] = &["setup", "help"];

/// `setup email list` — asked for the CURRENT mailboxes before adding the
/// first one. Its failure IS the answer "there are no accounts yet", so the
/// caller must not treat a non-zero exit as fatal.
pub const LIST_MAILBOXES_ARGS: &[&str] = &["setup", "email", "list"];

/// `setup email add <address>` — the password goes on STDIN, twice, never
/// here: `docker exec` argv is world-readable through /proc to every account
/// on the box (GOTCHAS.md defect 7, fixed by moving it to stdin).
pub fn add_mailbox_args(address: &str) -> Vec<String> {
    vec!["setup".to_string(), "email".to_string(), "add".to_string(), address.to_string()]
}

/// `setup config dkim keysize 2048 selector dkim domain <domain>` —
/// idempotent in the engine (a domain that already has a key is skipped), and
/// the selector is spelled out for the reason `DKIM_SELECTOR` documents.
pub fn dkim_config_args(domain: &str) -> Vec<String> {
    vec![
        "setup".to_string(),
        "config".to_string(),
        "dkim".to_string(),
        "keysize".to_string(),
        DKIM_KEY_SIZE.to_string(),
        "selector".to_string(),
        DKIM_SELECTOR.to_string(),
        "domain".to_string(),
        domain.to_string(),
    ]
}

/// A byte-exact port of `DockerMailserverService.composeFile(_:).composeContents`.
///
/// Two comments from the Swift source are worth keeping verbatim in the
/// generated file itself (not just in this module's doc) because they
/// explain artifacts a reader of the compose file — not of this port — will
/// actually see: the STARTTLS port list, and the Roundcube network alias
/// that exists only because PHP verifies the TLS peer name by default and
/// `mailserver` (the compose service name) does not match a certificate
/// issued for `mail.<domain>`. Both survive below unchanged.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.docker_mailserver_path;
    let hostname = hostname(input);
    format!(
        "services:\n  mailserver:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    hostname: {hostname}\n    restart: unless-stopped\n    env_file: .env\n    # Every client port, including the STARTTLS pair. This engine\n    # serves them all, so opening them is honest here.\n    ports:\n      - \"25:25\"\n      - \"143:143\"\n      - \"465:465\"\n      - \"587:587\"\n      - \"993:993\"\n      - \"4190:4190\"\n    volumes:\n      - {path}/mail-data:/var/mail\n      - {path}/mail-state:/var/mail-state\n      - {path}/mail-logs:/var/log/mail\n      - {path}/config:/tmp/docker-mailserver\n      - {path}/certs:/etc/gryonixnexus-certs:ro\n      - /etc/localtime:/etc/localtime:ro\n    # The container answers to its own certificate name INSIDE the\n    # compose network. Roundcube verifies the peer name (PHP does\n    # by default and Roundcube leaves imap_conn_options unset), so\n    # connecting to `mailserver` failed against a certificate\n    # issued for {hostname} — proven live. Aliasing here fixes\n    # the name instead of switching verification off.\n    networks:\n      default:\n        aliases:\n          - {hostname}\n    # Postfix and Dovecot change kernel-visible limits and need to\n    # drop privileges themselves; this is the capability set\n    # upstream documents for a non-privileged run.\n    cap_add:\n      - NET_ADMIN\n    stop_grace_period: 1m\n  webmail:\n    image: {WEBMAIL_IMAGE}\n    container_name: {WEBMAIL_CONTAINER}\n    restart: unless-stopped\n    depends_on:\n      - mailserver\n    environment:\n      # The mail container's alias, not its service name: this\n      # name is what the certificate is issued for, and the\n      # connection is verified. It still resolves inside the\n      # compose network, so the traffic never leaves the host and\n      # never touches the published ports.\n      ROUNDCUBEMAIL_DEFAULT_HOST: ssl://{hostname}\n      ROUNDCUBEMAIL_DEFAULT_PORT: \"993\"\n      ROUNDCUBEMAIL_SMTP_SERVER: tls://{hostname}\n      ROUNDCUBEMAIL_SMTP_PORT: \"587\"\n      ROUNDCUBEMAIL_PLUGINS: archive,zipdownload,managesieve\n      ROUNDCUBEMAIL_UPLOAD_MAX_FILESIZE: 25M\n    volumes:\n      - {path}/webmail:/var/roundcube/config\n      # /var/roundcube/db is where the image puts its sqlite file\n      # (ROUNDCUBEMAIL_DB_DIR); mounted anywhere else the database\n      # stays in the container layer and every recreate throws\n      # away the users' settings, contacts and address book.\n      - {path}/webmail-db:/var/roundcube/db\n    ports:\n      # Loopback only: Caddy terminates TLS in front of it, which\n      # also puts it under the lockdown guard like every other UI.\n      - \"127.0.0.1:{WEB_UI_PORT}:80\""
    )
}

/// A byte-exact port of `DockerMailserverService.envTemplate(_:)`.
///
/// **Signature note**: unlike `install::adguard::env_template()`, this takes
/// `&Input`. AdGuard's template is a static string (only the admin
/// password is a `__RANDOM__` placeholder); this engine's embeds
/// `OVERRIDE_HOSTNAME`/`POSTMASTER_ADDRESS`, which are per-deployment on the
/// Swift side too (`private static func envTemplate(_ context:
/// ServiceContext) -> String`) — the zero-argument shape was never available
/// to port faithfully.
///
/// `SSL_TYPE=manual` plus the two `SSL_*_PATH` lines are the reason
/// `placeholder_cert_args` has to run before the first `up -d`.
pub fn env_template(input: &Input) -> String {
    let hostname = hostname(input);
    format!(
        "# Managed by gryonixNexus. Generated on the server; the __RANDOM__ marker\n# is replaced once and then left alone on re-runs.\nOVERRIDE_HOSTNAME={hostname}\nPOSTMASTER_ADDRESS=postmaster@{domain}\n# The certificate is handed in by the sync timer below — Caddy owns the\n# ACME account on this host, and only one process can.\nSSL_TYPE=manual\nSSL_CERT_PATH=/etc/gryonixnexus-certs/cert.pem\nSSL_KEY_PATH=/etc/gryonixnexus-certs/key.pem\n# Rspamd is the modern filter and it also signs DKIM; Amavis, ClamAV and\n# SpamAssassin are the legacy chain and together they are most of the\n# memory this engine was chosen to avoid. ClamAV alone wants about a\n# gigabyte, which is most of a small server's headroom.\nENABLE_RSPAMD=1\nENABLE_OPENDKIM=0\nENABLE_AMAVIS=0\nENABLE_CLAMAV=0\nENABLE_SPAMASSASSIN=0\n# Sieve on 4190, the same port the other engines publish.\nENABLE_MANAGESIEVE=1\n# No fail2ban: it needs NET_ADMIN plus host firewall access, and the\n# deployment already has nftables in front of this container.\nENABLE_FAIL2BAN=0\n# Mailboxes live in a file the wrapper edits — no LDAP, no OIDC.\nACCOUNT_PROVISIONER=FILE\n# Only the webmail container may relay without authenticating, and it\n# reaches Postfix over the compose network.\nPERMIT_DOCKER=connected-networks\nPOSTFIX_MESSAGE_SIZE_LIMIT=50000000\nFIRST_MAILBOX_PASSWORD=__RANDOM__",
        domain = input.domain
    )
}

/// The key in `.env` the first mailbox's password is read back out of —
/// `grep '^FIRST_MAILBOX_PASSWORD=' .env | cut -d= -f2-` on the bash side.
pub const FIRST_MAILBOX_PASSWORD_KEY: &str = "FIRST_MAILBOX_PASSWORD";

/// A port of the certificate-sync SCRIPT written by
/// `DockerMailserverService.certSyncStep` — the body of its
/// `EOF_DMS_CERTSYNC` heredoc, byte for byte, comments included.
///
/// This is what keeps the placeholder certificate from being the FINAL state
/// of the install: Caddy holds the ACME account for `mail.<domain>`, and
/// Postfix/Dovecot read their certificate at start with no reload hook for a
/// file that changed underneath them, so the copy is followed by a restart of
/// the mail container only. "No certificate yet" is not an error — the timer
/// comes back every hour while the mail ports keep serving what they have.
pub fn cert_sync_script(input: &Input) -> String {
    let host = hostname(input);
    let path = &input.docker_mailserver_path;
    format!(
        r#"#!/bin/bash
set -eu
DOMAIN="{host}"
DMS="{path}"
DEST="$DMS/certs"
CADDY_DATA="/var/lib/caddy/.local/share/caddy/certificates"
SRC_CRT="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.crt" 2>/dev/null | head -n1)"
SRC_KEY="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.key" 2>/dev/null | head -n1)"
# No certificate yet (ACME still pending) is not an error: the timer
# comes back every hour and the mail ports keep serving what they have.
if [ -z "$SRC_CRT" ] || [ -z "$SRC_KEY" ]; then exit 0; fi
if cmp -s "$SRC_CRT" "$DEST/cert.pem" && cmp -s "$SRC_KEY" "$DEST/key.pem"; then exit 0; fi
cp "$SRC_CRT" "$DEST/cert.pem"
cp "$SRC_KEY" "$DEST/key.pem"
chmod 644 "$DEST/cert.pem"
chmod 600 "$DEST/key.pem"
cd "$DMS"
# Postfix and Dovecot read the certificate at start; the container has
# no reload hook for a file that changed under it.
docker compose -p {COMPOSE_PROJECT} restart {CONTAINER} >/dev/null 2>&1 || true
"#
    )
}

/// The `EOF_DMS_CERTSVC` heredoc body: a oneshot unit around the script
/// above. `Type=oneshot` because it copies and exits; the timer is what makes
/// it periodic.
pub fn cert_sync_service_unit() -> String {
    format!(
        "[Unit]\nDescription=Sync Caddy TLS certificate into Docker Mailserver (SMTP/IMAPS)\nAfter=docker.service\n[Service]\nType=oneshot\nExecStart={CERT_SYNC_SCRIPT_PATH}\n"
    )
}

/// The `EOF_DMS_CERTTIMER` heredoc body. `OnActiveSec=5min` gives Caddy time
/// to finish its first ACME order on a fresh install, `OnUnitActiveSec=1h`
/// covers every renewal after that, and `Persistent=true` catches up after a
/// host was off.
pub fn cert_sync_timer_unit() -> String {
    "[Unit]\nDescription=Periodic Caddy to Docker Mailserver TLS certificate sync\n[Timer]\nOnActiveSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
        .to_string()
}

/// A port of the DKIM-dump wrapper written by
/// `DockerMailserverService.managementScripts` — the body of its
/// `EOF_DMS_DKIM` heredoc, byte for byte.
///
/// **Its comments are the record of a wrapper that was confidently wrong**,
/// and they are ported with the code rather than summarised: an earlier
/// version globbed rspamd's tree, a path this image never writes, so
/// `GetDkimRecords` would have answered an empty list for ever while the key
/// sat on disk the whole time (GOTCHAS.md, found live 2026-08-09 — and a
/// generator-side test was GREEN throughout, because it only checked that the
/// script contained that glob).
///
/// The value is emitted BARE, without quotes: mailcow and Mailu both print
/// theirs unquoted, and `DKIMRecordParser`/`DKIMExport` add their own quoting
/// where a format needs it.
pub fn dkim_dump_script(input: &Input) -> String {
    let path = &input.docker_mailserver_path;
    format!(
        r#"#!/bin/bash
set -euo pipefail
# `setup config dkim` is what actually MINTS the key (see the install
# step that calls it), and it always writes BIND-format keys under
# opendkim/keys/<domain>/dkim.txt — REGARDLESS of ENABLE_RSPAMD vs
# ENABLE_OPENDKIM. Rspamd's dkim_signing module reads its signing key
# from that same path by the image's own default config; "opendkim"
# here names where the key lives, not which engine signs with it.
#
# An earlier version of this wrapper globbed
# `rspamd/dkim/*-dkim-*.public.dns.txt`, a path rspamd never writes on
# this image — verified live 2026-08-09 on a fresh install: the real
# key sat at opendkim/keys/<domain>/dkim.txt the whole time, and the
# glob matched nothing, so every report said "not ready yet" forever.
#
# dkim.txt is a BIND zone-file record, not a bare value:
#   dkim._domainkey IN TXT ( "v=DKIM1; h=sha256; k=rsa; "
#     "p=MIIB..." "dYRV...AB" )  ; ----- DKIM key dkim for <domain>
# The quoted segments concatenate directly (no separator) into the
# single value to publish — the first segment's own trailing space
# is what keeps "k=rsa;" and "p=..." apart, so no extra space is added
# here.
for F in {path}/config/opendkim/keys/*/dkim.txt; do
  [ -f "$F" ] || continue
  D="$(basename "$(dirname "$F")")"
  V="$(grep -o '"[^"]*"' "$F" | tr -d '"\n' | head -c 2000)"
  [ -n "$V" ] || continue
  # Bare, no quotes around $V — mailcow and Mailu both print the value
  # unquoted (see their own dkimMarker lines), and DKIMRecordParser /
  # DKIMExport downstream both expect the bare "v=DKIM1;...;p=..."
  # string, adding their own quoting where a format needs it (the BIND
  # zone export, the DNS provider's own form). A quoted value here
  # would ship the literal `"` characters into every artifact and
  # clipboard copy built from it.
  echo "{DKIM_MARKER} {DKIM_SELECTOR}._domainkey.$D $V"
done
echo "{DKIM_DUMP_DONE_MARKER}"
"#
    )
}

/// A port of `DockerMailserverService.dnsHostnames(_:)`, which returns `[]`
/// unconditionally — port faithfully, do not "fix" it. ARCHITECTURE.md
/// explains why: `mail.<domain>` (and its alias `mail.<alias>` for every
/// mirrored domain) is built by a SEPARATE branch inside
/// `DNSRecordGenerator`/`dns_records`, not by the per-service
/// `dnsHostnames`/`dns_hostnames` path every other service uses — mail is
/// the one service category `DNSRecordGenerator` has always treated
/// specially, because mailcow does not even declare a compose-based
/// `composeFile` (it clones its own installer), so the DNS generator cannot
/// lean on a service struct that may not describe a compose project at all.
/// Returning `[]` here is what keeps this port from inventing a second,
/// competing source for the same A record.
///
/// Unreached in the binary for the same reason AdGuard's is: the DNS artifact
/// is generated on the client today (срез 4.0's own note).
#[allow(dead_code)]
pub fn dns_hostnames(_input: &Input) -> Vec<String> {
    Vec::new()
}

/// A port of `DockerMailserverService.firewallPorts(_:)` — every client
/// port, unlike Mailu (whose front does not listen on the STARTTLS pair
/// 143/587 at all): this engine serves all five plus Sieve. Order and
/// wording match the Swift source exactly; the generated ruleset is read by
/// whoever debugs a delivery failure at 3am, so the ordering is not
/// cosmetic.
pub fn firewall_ports() -> Vec<FirewallPort> {
    vec![
        FirewallPort::tcp(25, "SMTP"),
        FirewallPort::tcp(465, "SMTPS"),
        FirewallPort::tcp(587, "Submission"),
        FirewallPort::tcp(143, "IMAP"),
        FirewallPort::tcp(993, "IMAPS"),
        FirewallPort::tcp(4190, "Sieve"),
    ]
}

/// A port of `DockerMailserverService.webIngress(_:)`: the webmail IS the
/// web face of this engine (the mail container itself has none), plain HTTP
/// upstream — `admin_guard` true and `upstream_https` false are both
/// `WebIngress`'s own Swift defaults, not something this service sets
/// explicitly, matching how `install::adguard::web_ingress` reads.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
}

/// The Caddy site NAMES this ingress publishes — see
/// `adguard::caddy_site_names`. The header these produce is what
/// `caddy::merge_site` matches an existing block on, so the ORDER is part of
/// the contract, not cosmetic.
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// A port of the docker-mailserver-specific slice of
/// `ServiceInfraSections.writeCaddyfile`: mirror the ingress hostname onto
/// every additional domain, then render through `caddy::site`. Same shape as
/// `install::adguard::caddy_site` — see that function's doc for why
/// `tls_internal` is `input.local_only` and not a choice this service makes
/// on its own.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_has_no_override_unlike_adguard() {
        assert_eq!(hostname(&base("example.com")), "mail.example.com");
    }

    #[test]
    fn dns_hostnames_is_always_empty() {
        assert!(dns_hostnames(&base("example.com")).is_empty());
    }

    #[test]
    fn firewall_ports_match_swift_order_and_wording() {
        let ports = firewall_ports();
        let rendered: Vec<String> =
            ports.iter().map(|p| format!("{}/{} {}", p.port, p.proto.as_str(), p.comment)).collect();
        assert_eq!(
            rendered,
            vec![
                "25/tcp SMTP",
                "465/tcp SMTPS",
                "587/tcp Submission",
                "143/tcp IMAP",
                "993/tcp IMAPS",
                "4190/tcp Sieve",
            ]
        );
    }

    #[test]
    fn web_ingress_defaults_admin_guard_true_and_https_false() {
        let ingress = web_ingress(&base("example.com"));
        assert!(ingress.admin_guard);
        assert!(!ingress.upstream_https);
        assert_eq!(ingress.upstream_port, WEB_UI_PORT);
    }

    #[test]
    fn caddy_site_mirrors_the_hostname_onto_additional_domains() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert_eq!(
            caddy_site_names(&input),
            vec!["mail.example.com".to_string(), "mail.example.org".to_string()]
        );
        assert!(caddy_site(&input).starts_with("mail.example.com, mail.example.org {"));
    }

    /// The guard every service slice needs its own case for: a hostname that
    /// does not sit under the primary domain has nothing to do with this
    /// deployment's domains, and mirroring it blindly would put a name nobody
    /// owns into the Caddy site — one certificate order that fails FOR EVER
    /// and burns the whole deployment's failure quota. This engine's hostname
    /// is always `mail.<domain>`, so the only way to reach that branch is a
    /// hostname whose suffix does not match, which is what this asserts.
    #[test]
    fn a_name_outside_the_primary_domain_is_never_mirrored() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert!(input.mirrored_hostnames("mail.other.net").is_empty());
    }

    #[test]
    fn mail_domains_are_the_primary_then_the_additional_ones_in_order() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_eq!(mail_domains(&input), vec!["example.com", "example.org", "example.net"]);
    }

    #[test]
    fn the_first_mailbox_follows_the_shared_admin_name() {
        let mut input = base("example.com");
        input.admin_username = "operator".to_string();
        assert_eq!(admin_mailbox(&input), "operator@example.com");
    }

    /// The certificate directory is the ONE directory of this service that is
    /// not 0755, and it holds the private key.
    #[test]
    fn the_certificate_directory_is_not_in_the_0755_list() {
        let input = base("example.com");
        assert!(!directories_0755(&input).contains(&certs_dir(&input)));
        assert_eq!(certs_dir(&input), "/opt/docker-mailserver/certs");
    }

    /// The selector is the whole point of spelling this argv out: the engine
    /// defaults to `mail`, and the DNS artifact publishes `dkim._domainkey`.
    #[test]
    fn the_dkim_argv_pins_the_selector_and_the_key_size() {
        assert_eq!(
            dkim_config_args("example.com"),
            vec!["setup", "config", "dkim", "keysize", "2048", "selector", "dkim", "domain", "example.com"]
        );
    }

    /// `setup email list` exits 1 while no account exists, so a probe built
    /// on it can never pass on a fresh install — the deadline just ran out
    /// every time.
    #[test]
    fn the_readiness_probe_is_not_the_list_subcommand() {
        assert_eq!(READINESS_PROBE_ARGS, &["setup", "help"]);
        assert_ne!(READINESS_PROBE_ARGS, LIST_MAILBOXES_ARGS);
    }

    /// Nothing that carries the password may appear in an argv builder.
    #[test]
    fn the_add_mailbox_argv_carries_no_password() {
        let args = add_mailbox_args("admin@example.com");
        assert_eq!(args, vec!["setup", "email", "add", "admin@example.com"]);
        assert!(!args.iter().any(|a| a.contains("s3cret")));
    }

    /// The placeholder certificate covers the ONE name the engine, the MX
    /// record and Caddy all agree on, and the key never lands in the argv of
    /// anything (it is a path, written by openssl itself).
    #[test]
    fn the_placeholder_certificate_names_the_mail_hostname_in_both_places() {
        let args = placeholder_cert_args(&base("example.com"));
        assert!(args.contains(&"/CN=mail.example.com".to_string()));
        assert!(args.contains(&"subjectAltName=DNS:mail.example.com".to_string()));
        assert!(args.contains(&"/opt/docker-mailserver/certs/key.pem".to_string()));
        assert!(args.contains(&"/opt/docker-mailserver/certs/cert.pem".to_string()));
    }

    /// The dump wrapper's glob is the defect GOTCHAS.md records: rspamd's own
    /// tree is NOT where the key lands, `config/opendkim/keys/<domain>/
    /// dkim.txt` is — regardless of which of the two signers is enabled.
    #[test]
    fn the_dkim_dump_script_globs_the_path_the_key_is_actually_written_to() {
        let script = dkim_dump_script(&base("example.com"));
        assert!(script.contains("for F in /opt/docker-mailserver/config/opendkim/keys/*/dkim.txt; do"));
        assert!(!script.contains("rspamd/dkim/*-dkim-*.public.dns.txt; do"));
        // Bare value, no quotes: the parser and every artifact built from it
        // expect `v=DKIM1;…;p=…` without the literal quote characters.
        assert!(script.contains("echo \"GRYONIXNEXUS_DKIM dkim._domainkey.$D $V\""));
    }

    /// A custom install path has to reach every file the install writes, not
    /// just the compose volumes — the cert-sync script and the DKIM glob both
    /// embed it.
    #[test]
    fn a_custom_install_path_reaches_the_scripts_too() {
        let mut input = base("example.com");
        input.docker_mailserver_path = "/srv/dms".to_string();
        assert!(cert_sync_script(&input).contains("DMS=\"/srv/dms\""));
        assert!(dkim_dump_script(&input).contains("for F in /srv/dms/config/opendkim/keys/*/dkim.txt; do"));
        assert_eq!(certs_dir(&input), "/srv/dms/certs");
    }

    /// The unit files name the script by the same literal `dkim.rs` and the
    /// Swift generator use; a drift here is a timer that runs nothing.
    #[test]
    fn the_cert_sync_units_point_at_the_script_this_module_writes() {
        assert!(cert_sync_service_unit().contains(&format!("ExecStart={CERT_SYNC_SCRIPT_PATH}")));
        assert!(cert_sync_timer_unit().contains("WantedBy=timers.target"));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — same
/// discipline as `install::adguard::fixture_parity` (see that module's doc
/// for the full rationale). Fixtures live under `tests/fixtures/install/`,
/// named `mail-dms-<scenario>__<artifact>`, and were dumped by a separate
/// one-off pass from the real `DockerMailserverService`, not written by
/// hand and not generated by this crate. If a fixture and this module's
/// output ever disagree, the working assumption is that the BUG IS IN THIS
/// PORT.
///
/// Срез 4.9 added a SECOND kind of fixture here: `__setup-steps.txt`, the
/// real `setupSteps(_:)` output joined by newlines. Срез 4.1's own note that
/// "setupSteps is shell the port replaces rather than rewrites" still holds
/// for the shell AROUND the artifacts — but the artifacts themselves (the
/// cert-sync script, its two units, the DKIM-dump wrapper) are FILES this
/// install still writes verbatim, and the only honest way to check a port of
/// a file's contents is against the real generator's real bytes. Everything
/// else the dump is used for is structural: the argv of `openssl`, the
/// directory list, the DKIM command, the probe.
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    /// `<scenario>__ingress.txt`: four lines, `hostname=…`/`upstreamPort=…`/
    /// `adminGuard=…`/`upstreamHTTPS=…` — same plain-text render the AdGuard
    /// fixture dump uses, confirmed against the file on disk (79 bytes, no
    /// trailing newline) rather than assumed from the task description.
    fn ingress_text(ingress: &WebIngress) -> String {
        format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}",
            ingress.hostname, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https
        )
    }

    /// `<scenario>__firewall-ports.txt`: one line per port, `<port>/<proto>
    /// <comment>` — confirmed against the file on disk (86 bytes for the
    /// six-line docker-mailserver set, joined by `\n`, no trailing newline),
    /// not assumed from the task description.
    fn firewall_ports_text() -> String {
        firewall_ports()
            .iter()
            .map(|p| format!("{}/{} {}", p.port, p.proto.as_str(), p.comment))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The body of a `cat > … <<'MARKER'` heredoc inside the dumped
    /// `setupSteps`, exactly as the shell would write it: every line between
    /// the opening and closing marker, each terminated by a newline.
    ///
    /// This is what makes a port of a FILE checkable. The alternative —
    /// reading the Swift source and trusting the transcription — is the exact
    /// habit that let a confidently wrong DKIM glob live in the generator for
    /// months with a green test beside it (GOTCHAS.md).
    fn heredoc_body(dump: &str, marker: &str) -> String {
        let open = format!("<<'{marker}'\n");
        let start = dump
            .find(&open)
            .unwrap_or_else(|| panic!("the dumped setupSteps carries no {marker} heredoc"))
            + open.len();
        let rest = &dump[start..];
        let close = format!("\n{marker}\n");
        let end = rest
            .find(&close)
            .unwrap_or_else(|| panic!("the {marker} heredoc is never closed in the dumped setupSteps"));
        format!("{}\n", &rest[..end])
    }

    fn assert_parity(input: &Input, scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("mail-dms-{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            env_template(input),
            fixture(&format!("mail-dms-{scenario}__env.template")),
            "{scenario}: env.template"
        );
        assert_eq!(hostname(input), fixture(&format!("mail-dms-{scenario}__hostname.txt")), "{scenario}: hostname.txt");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("mail-dms-{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames.txt"
        );
        assert_eq!(
            firewall_ports_text(),
            fixture(&format!("mail-dms-{scenario}__firewall-ports.txt")),
            "{scenario}: firewall-ports.txt"
        );
        assert_eq!(
            caddy_site(input),
            fixture(&format!("mail-dms-{scenario}__caddy-site.txt")),
            "{scenario}: caddy-site.txt"
        );
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("mail-dms-{scenario}__ingress.txt")),
            "{scenario}: ingress.txt"
        );
    }

    /// Every file the imperative half writes verbatim, diffed against the
    /// bytes the real Swift generator put in its own heredocs.
    fn assert_written_files_parity(input: &Input, scenario: &str) {
        let dump = fixture(&format!("mail-dms-{scenario}__setup-steps.txt"));
        assert_eq!(
            cert_sync_script(input),
            heredoc_body(&dump, "EOF_DMS_CERTSYNC"),
            "{scenario}: cert-sync script"
        );
        assert_eq!(
            cert_sync_service_unit(),
            heredoc_body(&dump, "EOF_DMS_CERTSVC"),
            "{scenario}: cert-sync service unit"
        );
        assert_eq!(
            cert_sync_timer_unit(),
            heredoc_body(&dump, "EOF_DMS_CERTTIMER"),
            "{scenario}: cert-sync timer unit"
        );
        assert_eq!(dkim_dump_script(input), heredoc_body(&dump, "EOF_DMS_DKIM"), "{scenario}: DKIM dump wrapper");
    }

    /// The imperative decisions the dump can prove structurally: the
    /// directory list and its two modes, the placeholder certificate's
    /// arguments, the readiness probe, the DKIM command (selector and key
    /// size), and the address of the first mailbox.
    fn assert_imperative_parity(input: &Input, scenario: &str) {
        let dump = fixture(&format!("mail-dms-{scenario}__setup-steps.txt"));

        // `install -d -m 755 <dirs…>` — one line, and the port's list has to
        // BE that line's arguments, in order.
        let dirs_line = dump
            .lines()
            .find(|line| line.starts_with("install -d -m 755 "))
            .unwrap_or_else(|| panic!("{scenario}: no 0755 install line in the dump"));
        let dumped: Vec<&str> =
            dirs_line.strip_prefix("install -d -m 755 ").expect("checked by find above").split(' ').collect();
        assert_eq!(directories_0755(input), dumped, "{scenario}: the 0755 directory list");
        assert!(
            dump.contains(&format!("install -d -m 700 {}\n", certs_dir(input))),
            "{scenario}: the certificate directory must be 0700"
        );

        // openssl: the bash version spreads it over continuation lines, so
        // the arguments are checked one by one against the port's argv.
        for expected in ["-newkey rsa:2048", "-days 3650", "-nodes"] {
            assert!(dump.contains(expected), "{scenario}: the dump is missing `{expected}`");
        }
        let args = placeholder_cert_args(input);
        // The VALUE this port passes for each flag, looked up by the flag
        // rather than by index: an index would still pass after two arguments
        // were swapped.
        let value_of = |flag: &str| -> String {
            let at = args.iter().position(|a| a == flag).unwrap_or_else(|| panic!("{scenario}: no {flag} in the argv"));
            args[at + 1].clone()
        };
        // The bash version quotes the two that carry an `=`; the port passes
        // them as single argv elements, which is the same thing without a
        // shell to quote for.
        assert!(
            dump.contains(&format!("-subj \"{}\"", value_of("-subj"))),
            "{scenario}: the certificate subject must match the dump"
        );
        assert!(
            dump.contains(&format!("-addext \"{}\"", value_of("-addext"))),
            "{scenario}: the certificate SAN must match the dump"
        );
        assert!(
            dump.contains(&format!("-keyout {}", value_of("-keyout"))),
            "{scenario}: the key path must match the dump"
        );
        assert!(
            dump.contains(&format!("-out {}", value_of("-out"))),
            "{scenario}: the certificate path must match the dump"
        );
        assert!(dump.contains(&format!("chmod 644 {}", cert_pem_path(input))), "{scenario}: cert.pem is 0644");
        assert!(dump.contains(&format!("chmod 600 {}", key_pem_path(input))), "{scenario}: key.pem is 0600");

        // The probe, and the proof it is not the list subcommand.
        assert!(dump.contains(&format!("dms_exec {}", READINESS_PROBE_ARGS.join(" "))), "{scenario}: the probe");
        // One DKIM command per mail domain, with this port's own argv.
        for domain in mail_domains(input) {
            assert!(
                dump.contains(&format!("dms_exec {}", dkim_config_args(&domain).join(" "))),
                "{scenario}: no DKIM command for {domain}"
            );
        }
        // The first mailbox's address, as the bash version spells it.
        assert!(
            dump.contains(&format!("dms_mailbox add \"{}\"", admin_mailbox(input))),
            "{scenario}: the first mailbox address"
        );
    }

    #[test]
    fn default_en() {
        let input = base("example.com");
        assert_parity(&input, "default-en");
        assert_written_files_parity(&input, "default-en");
        assert_imperative_parity(&input, "default-en");
    }

    #[test]
    fn mirrored_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "mirrored-en");
        assert_written_files_parity(&input, "mirrored-en");
        assert_imperative_parity(&input, "mirrored-en");
    }

    /// The fixture's own hostname/env/caddy-site content shows the "custom"
    /// scenario is a non-default `docker_mailserver_path` only
    /// (`/srv/dms`) — this engine has no hostname override to vary (see this
    /// module's doc), so the hostname/env/caddy-site fixtures for this
    /// scenario are byte-identical to `default-en` apart from the path
    /// substitution inside `docker-compose.yml`'s volumes. The setup-steps
    /// fixture is where that path really earns its scenario: it reaches the
    /// cert-sync script, the DKIM glob and every created directory.
    #[test]
    fn custom_en() {
        let mut input = base("example.com");
        input.docker_mailserver_path = "/srv/dms".to_string();
        assert_parity(&input, "custom-en");
        assert_written_files_parity(&input, "custom-en");
        assert_imperative_parity(&input, "custom-en");
    }

    /// The only scenario in which the first mailbox is not `admin@…`, which
    /// is what catches a port that hardcoded the local part instead of
    /// reading the deployment's shared admin name.
    #[test]
    fn adminuser_en() {
        let mut input = base("example.com");
        input.admin_username = "operator".to_string();
        assert_written_files_parity(&input, "adminuser-en");
        assert_imperative_parity(&input, "adminuser-en");
    }
}
