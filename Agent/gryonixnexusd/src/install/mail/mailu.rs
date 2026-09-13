//! Mailu's install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/MailuService.swift`.
//!
//! The mail-polka-closing слайс gave this engine an executor
//! (`execute::install_mailu_steps`), so this file now carries every FILE the
//! install writes verbatim — the compose file, the env template, the
//! certificate-sync script and its two systemd units, and the DKIM-dump
//! wrapper — the same "declarative content lives with the rest of the file,
//! only the WRITING of it is imperative" split
//! `mail::dockermailserver`'s own module doc explains. `extraSudoers` (the
//! agent provisions no sudoers at all — it IS root) and `reportSteps`/
//! `actions`/`updateSpec`/`uninstallSpec` are still NOT ported, for the same
//! reasons every other engine's slice gives.
//!
//! **Structurally the closest of the three mail engines to what this
//! generator already does** (Swift type doc, carried forward): a plain
//! compose stack plus one env file, not an installer that writes its own
//! configuration the way mailcow's `generate_config.sh` does — which is
//! exactly why Mailu (not mailcow, not docker-mailserver) is the one with a
//! real `compose_contents`/`env_template` pair to port here at all; see
//! `mailcow.rs`'s own doc for why that file has none.
//!
//! Three things pin the design, ported from the Swift type's own doc because
//! they are load-bearing on the declarative artifacts below, not just
//! imperative-step trivia:
//!
//! 1. **`TLS_FLAVOR=mail`.** Mailu's own ACME wants ports 80/443, which
//!    belong to Caddy here. This flavour tells Mailu to serve the web UI as
//!    plain HTTP (Caddy terminates TLS in front of it, see `web_ingress`)
//!    while still using a supplied certificate for SMTP/IMAP, which are NOT
//!    proxied and need real TLS of their own — the (unported) cert-sync step
//!    supplies it. Caddy owns the ACME account, and only one process on the
//!    host can.
//! 2. **The subnet is spelled out.** Mailu trusts its own docker network
//!    (`SUBNET`/`REAL_IP_FROM`, both derived from `mailu_subnet` below), and
//!    a value that does not match what docker actually handed out makes
//!    internal calls look external — authentication and relaying then fail
//!    in ways that read like configuration errors, the same trap
//!    mailcow's `API_ALLOW_FROM` sets (GOTCHAS.md).
//! 3. **DKIM comes from the engine, not from us** — the (unported) setup
//!    step mints keys through Mailu's own CLI; nothing in the declarative
//!    half below touches them.

use super::FirewallPort;
use crate::install::caddy::{self, WebIngress};
use crate::install::context::Input;

/// One CalVer line, patches included, matching every `ghcr.io/mailu/*`
/// component image below. The project releases as `<year>.<month>.<patch>`;
/// pinning the line takes fixes without taking a data-format change — the
/// same trade Forgejo's LTS pin makes (Swift type doc). Verified genuinely
/// multi-arch on the Swift side: every component image publishes amd64, arm
/// and arm64 manifests.
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "mailu";

pub const IMAGE_TAG: &str = "2024.06";
/// Session store and rspamd's backend. Not a Mailu image — Docker Hub, its
/// own floating tag — but part of this service's image set all the same.
pub const CACHE_IMAGE: &str = "redis:alpine";
pub const COMPOSE_PROJECT: &str = "mailu";
/// Loopback port Caddy proxies to. Distinct from every other service's
/// upstream (8080/18443 mailcow, 8081 nextcloud, 8082 vaultwarden, 8083
/// Forgejo, 8084 GitLab).
pub const WEB_UI_PORT: u16 = 8085;
/// Compose service that serves the web UI and every mail port —
/// `MailuService.frontService`. The cert-sync script restarts only this one:
/// it is the ONE service that terminates TLS itself, and restarting the
/// whole project would drop mail in flight for nothing.
pub const FRONT_SERVICE: &str = "front";
/// Compose service holding the CLI, the database and the DKIM keys —
/// `MailuService.adminService`. Both the domain/DKIM provisioning step and
/// the DKIM-dump wrapper `docker compose exec` into this one.
pub const ADMIN_SERVICE: &str = "admin";
/// Account inside the admin image every `docker compose exec` runs as —
/// `MailuService.adminRunAsUser`. Not hygiene: the engine does not work
/// without it.
///
/// The image declares no `USER`, so a bare `exec` lands as ROOT, and every
/// Mailu CLI call opens the SQLite database at `/data/main.db`, which SQLite
/// CREATES when it is missing. `configure_mailu`'s readiness probe starts
/// calling that CLI the moment the containers report up — in a race with the
/// container's own `flask db upgrade`, which runs as this account after
/// `/start.py` drops privileges. When root wins, the database is left
/// root-owned and the engine can never write its schema into it:
/// `start.py` calls `flask db upgrade` through `os.system`, so the failure is
/// silent, and every later call answers `no such table: domain` while the
/// admin container stays unhealthy — the live failure of 2026-08-12.
/// `config-import` mints the DKIM keys under `/dkim` the same way.
///
/// The NAME, never a uid: the image's Dockerfile passes `MAILU_UID=1000` into
/// `adduser -Sg ${MAILU_UID} … mailu`, where `-g` is the GECOS field and not
/// the uid, so `-S` allocates the account — it is uid **100** in 2024.06, not
/// the 1000 the build argument reads like. Measured out of the pinned image's
/// own `/etc/passwd`.
pub const ADMIN_RUN_AS_USER: &str = "mailu";
/// `MailuService.certSyncScriptPath`/`.certSyncUnit`. Caddy owns the ACME
/// account for `mail.<domain>` on this host, so Mailu is HANDED the
/// certificate instead of getting its own — the same reason
/// `mail::dockermailserver::CERT_SYNC_SCRIPT_PATH` exists, one process per
/// name or two ACME clients race each other into Let's Encrypt's failure
/// quota.
pub const CERT_SYNC_SCRIPT_PATH: &str = "/opt/gryonixnexus-mailu-cert-sync.sh";
pub const CERT_SYNC_UNIT: &str = "gryonixnexus-mailu-cert-sync";
/// `MailuService.dkimDumpScriptPath`. Pinned as a literal on both the Swift
/// generator and `dkim.rs`'s own engine table, which runs exactly this path
/// (`wrapper_default` for the `"mailu"` entry) — the reason the agent has to
/// write it is the same as docker-mailserver's: without it,
/// `GetDkimRecords` on a host installed through the agent answers "the
/// wrapper is not installed" for ever.
pub const DKIM_DUMP_SCRIPT_PATH: &str = "/opt/gryonixnexus-mailu-dkim.sh";
/// Byte-identical to `mail::dockermailserver::DKIM_MARKER`/mailcow's own —
/// `dkim.rs`'s module doc: one parser serves all three engines because all
/// three wrappers print the same wire format.
pub const DKIM_MARKER: &str = "GRYONIXNEXUS_DKIM";
pub const DKIM_DUMP_DONE_MARKER: &str = "GRYONIXNEXUS_DKIM_DONE";
/// `flask mailu config-export -j` — the readiness probe `setupSteps` uses
/// (`mu_exec flask mailu config-export -j`): it has to reach the database,
/// which is what is actually not ready yet while the containers report up.
pub const CONFIG_EXPORT_PROBE_ARGS: &[&str] = &["flask", "mailu", "config-export", "-j"];
/// `flask mailu config-import -q -u` — `-u` is MERGE mode and not optional
/// (without it the piped YAML is treated as the whole configuration rather
/// than an addition to it); `-q` because the app streams this log.
pub const CONFIG_IMPORT_ARGS: &[&str] = &["flask", "mailu", "config-import", "-q", "-u"];

/// A port of `MailuService.image(_:)`, reduced to what `compose_contents`
/// needs — the `Component` enum's `CaseIterable` use for `updateSpec` is
/// part of the update surface, not the declarative half ported here.
fn component_image(component: &str) -> String {
    format!("ghcr.io/mailu/{component}:{IMAGE_TAG}")
}

/// A port of the private `host(in:last:)` helper shared by
/// `resolverAddress`/`gatewayAddress`.
fn host_in_subnet(subnet: &str, last: &str) -> String {
    let base = subnet.split('/').next().unwrap_or(subnet);
    let mut octets: Vec<&str> = base.split('.').collect();
    if octets.len() != 4 {
        return base.to_string();
    }
    octets[3] = last;
    octets.join(".")
}

/// A port of `MailuService.resolverAddress(subnet:)`. Mailu's resolver has
/// to sit at a fixed address because every other container is pointed at it
/// by IP (`dns:`) — a name would need a resolver to look up. Takes the
/// `.254` of the configured subnet, which docker hands out last and no
/// service claims.
fn resolver_address(subnet: &str) -> String {
    host_in_subnet(subnet, "254")
}

/// A port of `MailuService.gatewayAddress(subnet:)`. The bridge gateway —
/// docker always takes the `.1` of the subnet, and it is the address a
/// connection from the host (Caddy, proxying into the published web UI
/// port) arrives from inside the containers. See the module doc's point 2:
/// this is `REAL_IP_FROM`, not `127.0.0.1` — the same trap as mailcow's
/// `API_ALLOW_FROM`.
fn gateway_address(subnet: &str) -> String {
    host_in_subnet(subnet, "1")
}

/// Ф4's mail-polka-closing слайс folded `MailuInput` into the shared
/// `install::context::Input` — the merge that struct's own doc, and this
/// module's former `MailuInput` doc, both anticipated the moment Mailu got
/// an executor built from the wire (the same merge `mail/dockermailserver`
/// made in срез 4.9). `Input.mailu_path`/`.mailu_subnet` are what used to be
/// `MailuInput.mailu_path`/`.mailu_subnet`; `domain`/`additional_domains`/
/// `local_only`/`admin_username` were already there for every other engine.
/// See `Input`'s own doc for the field-by-field reduction.
///
/// A port of `MailuService.requiredHostname(forDomain:)`, which is also
/// exactly what `envTemplate`'s local `hostname` and `webIngress` compute
/// inline as `"mail.\(context.domain)"`. Pinned to `mail.<domain>`
/// deliberately, even though Mailu itself accepts any hostname: the name is
/// a contract between four parties (the MX record, the A record, the
/// certificate Caddy obtains, and the `HOSTNAMES` Mailu answers on) — Swift
/// type doc.
pub fn hostname(input: &Input) -> String {
    format!("mail.{}", input.domain)
}

/// A port of `MailuService.composeFile(_:).composeContents`. Byte-exact,
/// including the blank line before the `networks:` block and the mixed
/// key ordering between services — `resolver` writes `image`/`env_file`/
/// `restart` while every other service writes `image`/`restart`/`env_file`,
/// which is simply what the Swift literal contains, not a typo to "fix"
/// here.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.mailu_path;
    let subnet = &input.mailu_subnet;
    let resolver_addr = resolver_address(subnet);
    let lines: Vec<String> = vec![
        "services:".to_string(),
        "  redis:".to_string(),
        format!("    image: {CACHE_IMAGE}"),
        "    restart: unless-stopped".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/redis:/data"),
        "  front:".to_string(),
        format!("    image: {}", component_image("nginx")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    logging:".to_string(),
        "      driver: json-file".to_string(),
        "    ports:".to_string(),
        // The web UI stays on loopback behind Caddy; the mail ports are the
        // only public binds, and they are not proxyable — SMTP and IMAP are
        // not HTTP.
        "      # The web UI stays on loopback behind Caddy; the mail ports".to_string(),
        "      # are the only public binds, and they are not proxyable —".to_string(),
        "      # SMTP and IMAP are not HTTP.".to_string(),
        format!("      - \"127.0.0.1:{WEB_UI_PORT}:80\""),
        "      - \"25:25\"".to_string(),
        "      - \"465:465\"".to_string(),
        "      - \"587:587\"".to_string(),
        "      - \"143:143\"".to_string(),
        "      - \"993:993\"".to_string(),
        "      - \"4190:4190\"".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/certs:/certs"),
        format!("      - {path}/overrides/nginx:/overrides:ro"),
        "  resolver:".to_string(),
        format!("    image: {}", component_image("unbound")),
        "    env_file: .env".to_string(),
        "    restart: unless-stopped".to_string(),
        "    networks:".to_string(),
        "      default:".to_string(),
        format!("        ipv4_address: {resolver_addr}"),
        "  admin:".to_string(),
        format!("    image: {}", component_image("admin")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/data:/data"),
        format!("      - {path}/dkim:/dkim"),
        "    depends_on:".to_string(),
        "      - redis".to_string(),
        "      - resolver".to_string(),
        "    dns:".to_string(),
        format!("      - {resolver_addr}"),
        "  imap:".to_string(),
        format!("    image: {}", component_image("dovecot")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/mail:/mail"),
        format!("      - {path}/overrides:/overrides:ro"),
        "    depends_on:".to_string(),
        "      - front".to_string(),
        "      - resolver".to_string(),
        "    dns:".to_string(),
        format!("      - {resolver_addr}"),
        "  smtp:".to_string(),
        format!("    image: {}", component_image("postfix")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/mailqueue:/queue"),
        format!("      - {path}/overrides:/overrides:ro"),
        "    depends_on:".to_string(),
        "      - front".to_string(),
        "      - resolver".to_string(),
        "    dns:".to_string(),
        format!("      - {resolver_addr}"),
        "  antispam:".to_string(),
        format!("    image: {}", component_image("rspamd")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/filter:/var/lib/rspamd"),
        format!("      - {path}/overrides/rspamd:/etc/rspamd/override.d:ro"),
        "    depends_on:".to_string(),
        "      - front".to_string(),
        "      - redis".to_string(),
        "      - resolver".to_string(),
        "    dns:".to_string(),
        format!("      - {resolver_addr}"),
        "  webmail:".to_string(),
        format!("    image: {}", component_image("webmail")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/webmail:/data"),
        format!("      - {path}/overrides/roundcube:/overrides:ro"),
        "    depends_on:".to_string(),
        "      - front".to_string(),
        String::new(),
        "networks:".to_string(),
        "  default:".to_string(),
        "    driver: bridge".to_string(),
        "    ipam:".to_string(),
        "      config:".to_string(),
        // Fixed on purpose: SUBNET below has to name the range docker really
        // used, and letting docker choose it would make the two disagree
        // the first time the pool shifts.
        "        # Fixed on purpose: SUBNET below has to name the range".to_string(),
        "        # docker really used, and letting docker choose it would".to_string(),
        "        # make the two disagree the first time the pool shifts.".to_string(),
        format!("        - subnet: {subnet}"),
    ];
    lines.join("\n")
}

/// A port of `MailuService.envTemplate(_:)`. Mailu reads ONE env file for
/// everything; the compose file above hands it to every container. Both
/// secrets (`SECRET_KEY`, `INITIAL_ADMIN_PW`) are generated on the server —
/// this module never sees the real secret, only the `__RANDOM__` template
/// the (unported) setup substitution loop replaces it with.
pub fn env_template(input: &Input) -> String {
    let domain = &input.domain;
    let admin = &input.admin_username;
    let subnet = &input.mailu_subnet;
    let gateway_addr = gateway_address(subnet);
    let host = hostname(input);
    // Every mail domain the deployment serves. The first is the technical
    // one Mailu bounces and postmaster mail from.
    let hostnames: String = std::iter::once(domain.clone())
        .chain(input.additional_domains.iter().cloned())
        .map(|d| format!("mail.{d}"))
        .collect::<Vec<_>>()
        .join(",");
    let lines: Vec<String> = vec![
        "# Managed by gryonixNexus. Generated on the server; secrets are the".to_string(),
        "# __RANDOM__ markers, replaced once and then left alone on re-runs.".to_string(),
        "SECRET_KEY=__RANDOM__".to_string(),
        format!("DOMAIN={domain}"),
        format!("HOSTNAMES={hostnames}"),
        "POSTMASTER=postmaster".to_string(),
        // See the type comment: Caddy owns 80/443 and the ACME account, so
        // Mailu serves plain HTTP for the proxy and uses the synced
        // certificate for SMTP/IMAP only.
        "# See the type comment: Caddy owns 80/443 and the ACME account, so Mailu".to_string(),
        "# serves plain HTTP for the proxy and uses the synced certificate for".to_string(),
        "# SMTP/IMAP only.".to_string(),
        "TLS_FLAVOR=mail".to_string(),
        format!("SUBNET={subnet}"),
        // The first administrator is created by the stack itself.
        // `ifmissing` rather than `update`: a re-run of setup must not
        // reset a password the owner has since changed.
        "# The first administrator is created by the stack itself. `ifmissing`".to_string(),
        "# rather than `update`: a re-run of setup must not reset a password the".to_string(),
        "# owner has since changed.".to_string(),
        format!("INITIAL_ADMIN_ACCOUNT={admin}"),
        format!("INITIAL_ADMIN_DOMAIN={domain}"),
        "INITIAL_ADMIN_PW=__RANDOM__".to_string(),
        "INITIAL_ADMIN_MODE=ifmissing".to_string(),
        // Behind a proxy Mailu would otherwise log and rate-limit Caddy's
        // address instead of the client's.
        //
        // The trusted address is the BRIDGE GATEWAY, not 127.0.0.1: Caddy
        // connects to a published port on the host, and the container sees
        // that connection arriving from the docker network's gateway. This
        // is the same trap as mailcow's API_ALLOW_FROM (see GOTCHAS.md) — a
        // loopback value here does not fail loudly, it silently makes every
        // client look like the proxy, which means the per-IP rate limit
        // bans everyone at once the first time one client gets a password
        // wrong.
        "# Behind a proxy Mailu would otherwise log and rate-limit Caddy's".to_string(),
        "# address instead of the client's.".to_string(),
        "#".to_string(),
        "# The trusted address is the BRIDGE GATEWAY, not 127.0.0.1: Caddy".to_string(),
        "# connects to a published port on the host, and the container sees that".to_string(),
        "# connection arriving from the docker network's gateway. This is the".to_string(),
        "# same trap as mailcow's API_ALLOW_FROM (see GOTCHAS.md) — a loopback".to_string(),
        "# value here does not fail loudly, it silently makes every client look".to_string(),
        "# like the proxy, which means the per-IP rate limit bans everyone at".to_string(),
        "# once the first time one client gets a password wrong.".to_string(),
        "REAL_IP_HEADER=X-Forwarded-For".to_string(),
        format!("REAL_IP_FROM={gateway_addr}"),
        "WEBROOT_REDIRECT=/webmail".to_string(),
        // ADMIN gates the admin interface ITSELF, WEB_ADMIN only says where
        // it would live. Without this the nginx template renders no
        // location for it at all: /admin falls through to
        // WEBROOT_REDIRECT and lands on the webmail, which reads as "the
        // admin UI is broken". Live-found 2026-08-05 — the setup report
        // points at /admin.
        "# ADMIN gates the admin interface ITSELF, WEB_ADMIN only says where it".to_string(),
        "# would live. Without this the nginx template renders no location for".to_string(),
        "# it at all: /admin falls through to WEBROOT_REDIRECT and lands on the".to_string(),
        "# webmail, which reads as \"the admin UI is broken\". Live-found".to_string(),
        "# 2026-08-05 — the setup report points at /admin.".to_string(),
        "ADMIN=true".to_string(),
        "WEB_ADMIN=/admin".to_string(),
        "WEB_WEBMAIL=/webmail".to_string(),
        "WEBMAIL=roundcube".to_string(),
        "WEBDAV=none".to_string(),
        // Off deliberately: ClamAV alone wants about a gigabyte of RAM,
        // which is most of a small server's headroom. Rspamd still filters
        // spam.
        "# Off deliberately: ClamAV alone wants about a gigabyte of RAM, which is".to_string(),
        "# most of a small server's headroom. Rspamd still filters spam.".to_string(),
        "ANTIVIRUS=none".to_string(),
        "MESSAGE_SIZE_LIMIT=50000000".to_string(),
        "RECIPIENT_DELIMITER=+".to_string(),
        "DMARC_RUA=postmaster".to_string(),
        "DMARC_RUF=postmaster".to_string(),
        format!("COMPOSE_PROJECT_NAME={COMPOSE_PROJECT}"),
        format!("MAILU_HOSTNAME={host}"),
    ];
    lines.join("\n")
}

/// A port of `MailuService.dnsHostnames(_:)`: always empty. The mail host's
/// A records come from the mail DNS branch of `DNSRecordGenerator`, not from
/// a service's `dnsHostnames`/mirroring path — ARCHITECTURE.md's
/// multidomain note spells out why: mailcow does not declare `dnsHostnames`
/// either, and `mail.<alias>` for every additional domain is built by a
/// separate branch in the DNS generator rather than by mirroring a service
/// hostname, because mirroring never reaches a mail engine that declares
/// none. `input` is accepted (not `()`) only to keep this function's
/// signature uniform with every other declarative accessor here — the
/// Swift method ignores its `context` argument the same way.
///
/// Unreached in the binary for the same reason
/// `mail::dockermailserver::dns_hostnames` is: the DNS artifact is
/// generated on the client today (срез 4.0's own note).
#[allow(dead_code)]
pub fn dns_hostnames(_input: &Input) -> Vec<String> {
    Vec::new()
}

/// A port of `MailuService.firewallPorts(_:)`. Only what the engine
/// actually listens on: Mailu's front serves 25, 465, 993 and 4190 — and NOT
/// the STARTTLS pair 143/587.
///
/// Measured on a running install rather than assumed, and measured under
/// both plausible TLS flavours: `mail` and `cert` produce the same four
/// ports, so this is the engine's shape and not a consequence of the
/// flavour the module doc pins. Opening the other two would put holes in
/// the firewall, DNAT on the relay and lines in the report for ports that
/// answer with a connection refused — the worst kind of documentation, the
/// kind that looks official. Ignores its (Swift) `context` argument, same as
/// `dns_hostnames`, so this takes none either.
pub fn firewall_ports() -> Vec<FirewallPort> {
    vec![
        FirewallPort::tcp(25, "SMTP"),
        FirewallPort::tcp(465, "SMTPS (implicit TLS)"),
        FirewallPort::tcp(993, "IMAPS (implicit TLS)"),
        FirewallPort::tcp(4190, "Sieve"),
    ]
}

/// A port of `MailuService.webIngress(_:)`: `WebIngress(hostname:
/// upstreamPort:)` with everything else defaulted on the Swift side —
/// `admin_guard` true, `upstream_https` false. Plain HTTP upstream:
/// `TLS_FLAVOR=mail` (module doc, point 1) makes Mailu's own nginx serve the
/// UI without TLS precisely so a terminating proxy can front it.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
}

/// The Caddy site NAMES this ingress publishes — see
/// `adguard::caddy_site_names`/`mail::dockermailserver::caddy_site_names`/
/// `mail::mailcow::caddy_site_names`. The header these produce is what
/// `caddy::merge_site` matches an existing block on, so the ORDER is part
/// of the contract, not cosmetic.
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// A port of the Mailu-specific slice of `ServiceInfraSections.writeCaddyfile`:
/// mirror the ingress hostname onto every additional domain (one site,
/// several names — one certificate request covering all of them), then
/// render through `caddy::site`. `tls_internal` is `input.local_only`,
/// exactly as `writeCaddyfile` passes `context.isLocalOnly` for every
/// service — see `hostname`'s own doc block above (formerly `MailuInput`'s)
/// on why that combination is theoretical for mail specifically, without the
/// flag being hardcoded away.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

/// Every mail domain this install imports and mints a DKIM key for: the
/// primary plus every additional domain, in that order — a port of
/// `setupSteps`'s `[context.domain] + context.additionalDomains`, the same
/// list `mail::dockermailserver::mail_domains` builds for its own engine.
pub fn mail_domains(input: &Input) -> Vec<String> {
    let mut domains = vec![input.domain.clone()];
    domains.extend(input.additional_domains.iter().cloned());
    domains
}

/// The `install -d -m 755 …` directories, in the Swift order — everything
/// except the three that are `-m 700` (`directories_0700`). `mailu_path`
/// itself is first, then the two 755 groups `setupSteps` writes as separate
/// `install -d` invocations (mail data and the four `overrides/*` trees).
pub fn directories_0755(input: &Input) -> Vec<String> {
    let path = &input.mailu_path;
    let mut dirs = vec![path.clone()];
    for name in ["mail", "mailqueue", "filter", "webmail", "redis"] {
        dirs.push(format!("{path}/{name}"));
    }
    for name in ["overrides", "overrides/nginx", "overrides/rspamd", "overrides/roundcube"] {
        dirs.push(format!("{path}/{name}"));
    }
    dirs
}

/// `install -d -m 700 <path>/certs <path>/dkim <path>/data` — root-only on
/// purpose: the containers run as their own uids and do not need host
/// accounts reading the private keys or the admin database.
pub fn directories_0700(input: &Input) -> Vec<String> {
    let path = &input.mailu_path;
    ["certs", "dkim", "data"].iter().map(|name| format!("{path}/{name}")).collect()
}

/// The YAML piped to `flask mailu config-import` — a byte-exact port of
/// `printf '%s\n' 'domain:' '\#(domainYAML)'`'s combined stdin: the literal
/// line `domain:`, then one `  - name: <domain>\n    dkim_key: -generate-`
/// block per mail domain, each ending in its own newline. `-generate-` is
/// Mailu's own request to mint a key it does not already have — idempotent
/// for this shape, so a re-run leaves existing keys alone and only adds
/// entries for domains added since.
pub fn domain_import_yaml(input: &Input) -> String {
    let entries: Vec<String> =
        mail_domains(input).iter().map(|d| format!("  - name: {d}\n    dkim_key: -generate-")).collect();
    format!("domain:\n{}\n", entries.join("\n"))
}

/// A port of the certificate-sync SCRIPT written by `MailuService`'s private
/// `certSyncStep` — the body of its `EOF_MU_CERTSYNC` heredoc, byte for
/// byte. Identical in shape to `mail::dockermailserver::cert_sync_script`
/// and for the same reason (Caddy holds the ACME account, Mailu is handed
/// the certificate), with two differences that come straight from the
/// engine: the destination is `$MAILU/certs` (this module's own
/// `directories_0700`'s first entry, not a name docker-mailserver shares),
/// and only `front` — the ONE service that terminates TLS itself — gets
/// restarted, unlike DMS's single mail container.
pub fn cert_sync_script(input: &Input) -> String {
    let host = hostname(input);
    let path = &input.mailu_path;
    format!(
        r#"#!/bin/bash
set -eu
DOMAIN="{host}"
MAILU="{path}"
DEST="$MAILU/certs"
CADDY_DATA="/var/lib/caddy/.local/share/caddy/certificates"
SRC_CRT="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.crt" 2>/dev/null | head -n1)"
SRC_KEY="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.key" 2>/dev/null | head -n1)"
# No certificate yet (ACME still pending) is not an error: the timer
# comes back every hour and the mail ports keep serving the old one.
if [ -z "$SRC_CRT" ] || [ -z "$SRC_KEY" ]; then exit 0; fi
if cmp -s "$SRC_CRT" "$DEST/cert.pem" && cmp -s "$SRC_KEY" "$DEST/key.pem"; then exit 0; fi
cp "$SRC_CRT" "$DEST/cert.pem"
cp "$SRC_KEY" "$DEST/key.pem"
chmod 600 "$DEST/cert.pem" "$DEST/key.pem"
cd "$MAILU"
# Only the services that terminate TLS themselves; restarting the whole
# project would drop deliveries in flight for nothing.
docker compose -p {COMPOSE_PROJECT} restart {FRONT_SERVICE} >/dev/null 2>&1 || true
"#
    )
}

/// The `EOF_MU_CERTSVC` heredoc body — `Type=oneshot` because it copies and
/// exits; the timer is what makes it periodic.
pub fn cert_sync_service_unit() -> String {
    format!(
        "[Unit]\nDescription=Sync Caddy TLS certificate into Mailu (SMTP/IMAPS)\nAfter=docker.service\n[Service]\nType=oneshot\nExecStart={CERT_SYNC_SCRIPT_PATH}\n"
    )
}

/// The `EOF_MU_CERTTIMER` heredoc body — identical shape to
/// docker-mailserver's own timer, and for the same reasons
/// (`OnActiveSec=5min` gives Caddy time to finish its first ACME order,
/// `OnUnitActiveSec=1h` covers renewals, `Persistent=true` catches up after
/// a host was off).
pub fn cert_sync_timer_unit() -> String {
    "[Unit]\nDescription=Periodic Caddy to Mailu TLS certificate sync\n[Timer]\nOnActiveSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
        .to_string()
}

/// A port of the DKIM-dump wrapper written by `MailuService`'s private
/// `dkimDumpStep` — the body of its `EOF_GD_MU_DKIM` heredoc, byte for
/// byte, INCLUDING the embedded `python3 -c` script: Mailu's own
/// `--dns`-projected export is JSON, and `flask mailu config-export`'s
/// `dns_dkim` field is a full BIND zone-file line
/// (`"<name> 600 IN TXT \"v=DKIM1…\""`), so the wrapper has to split the
/// name off the front and keep the quoted value — the private key is NOT in
/// that projection, which is why this dump can be whitelisted at all.
pub fn dkim_dump_script(input: &Input) -> String {
    let path = &input.mailu_path;
    format!(
        r#"#!/bin/bash
set -euo pipefail
cd {path} 2>/dev/null || {{ echo "{DKIM_DUMP_DONE_MARKER}"; exit 0; }}
# --dns asks Mailu for the records it would publish; the private key is
# NOT in that projection, which is why this dump can be whitelisted.
OUT="$(timeout 60 docker compose -p {COMPOSE_PROJECT} exec -T -u {ADMIN_RUN_AS_USER} {ADMIN_SERVICE} \
       flask mailu config-export -d -j domain 2>/dev/null || true)"
printf '%s' "$OUT" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
for domain in data.get("domain", []):
    record = domain.get("dns_dkim")
    if not record:
        continue
    # dns_dkim is a full zone line: "<name> 600 IN TXT \"v=DKIM1…\"".
    # The app wants the name and the value, so keep those two.
    name, _, rest = record.partition(" ")
    value = rest[rest.find("\"") :].strip() if "\"" in rest else rest.strip()
    print("{DKIM_MARKER} " + name.rstrip(".") + " " + value)
' 2>/dev/null || true
echo "{DKIM_DUMP_DONE_MARKER}"
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_is_always_mail_subdomain() {
        assert_eq!(hostname(&base("example.com")), "mail.example.com");
    }

    #[test]
    fn dns_hostnames_is_always_empty() {
        assert!(dns_hostnames(&base("example.com")).is_empty());
    }

    #[test]
    fn firewall_ports_are_the_four_the_engine_answers_on() {
        let ports = firewall_ports();
        assert_eq!(ports.len(), 4);
        assert_eq!(ports[0].port, 25);
        assert_eq!(ports[3].port, 4190);
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
        assert!(caddy_site(&input).starts_with("mail.example.com, mail.example.org {"));
    }

    #[test]
    fn resolver_and_gateway_addresses_take_the_last_octet_of_the_subnet() {
        assert_eq!(resolver_address("172.29.0.0/24"), "172.29.0.254");
        assert_eq!(gateway_address("172.29.0.0/24"), "172.29.0.1");
    }

    #[test]
    fn mail_domains_are_the_primary_then_the_additional_ones_in_order() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_eq!(mail_domains(&input), vec!["example.com", "example.org", "example.net"]);
    }

    /// The certificate directory is one of the THREE `-m 700` directories,
    /// and must not also appear in the `-m 755` list.
    #[test]
    fn the_0700_directories_are_not_in_the_0755_list() {
        let input = base("example.com");
        let dirs_0755 = directories_0755(&input);
        for dir in directories_0700(&input) {
            assert!(!dirs_0755.contains(&dir), "{dir} must not be 0755");
        }
        assert_eq!(directories_0700(&input), vec!["/opt/mailu/certs", "/opt/mailu/dkim", "/opt/mailu/data"]);
    }

    /// One `-generate-` block per mail domain, in order, and the whole thing
    /// is the literal stdin `printf '%s\n' 'domain:' '<domainYAML>'` writes.
    #[test]
    fn domain_import_yaml_has_one_generate_block_per_domain() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert_eq!(
            domain_import_yaml(&input),
            "domain:\n  - name: example.com\n    dkim_key: -generate-\n  - name: example.org\n    dkim_key: -generate-\n"
        );
    }

    /// A custom install path has to reach every file the install writes, not
    /// just the compose volumes — the cert-sync script and the DKIM `cd`
    /// both embed it.
    #[test]
    fn a_custom_install_path_reaches_the_scripts_too() {
        let mut input = base("example.com");
        input.mailu_path = "/srv/mailu".to_string();
        assert!(cert_sync_script(&input).contains("MAILU=\"/srv/mailu\""));
        assert!(dkim_dump_script(&input).contains("cd /srv/mailu 2>/dev/null"));
    }

    /// The unit files name the script by the same literal this module
    /// writes; a drift here is a timer that runs nothing.
    #[test]
    fn the_cert_sync_units_point_at_the_script_this_module_writes() {
        assert!(cert_sync_service_unit().contains(&format!("ExecStart={CERT_SYNC_SCRIPT_PATH}")));
        assert!(cert_sync_timer_unit().contains("WantedBy=timers.target"));
    }

    /// Mailu's cert-sync restarts ONLY `front` — the one service that
    /// terminates TLS itself — unlike docker-mailserver's single container.
    #[test]
    fn cert_sync_restarts_only_the_front_service() {
        let script = cert_sync_script(&base("example.com"));
        assert!(script.contains(&format!("restart {FRONT_SERVICE} >")));
        assert!(!script.contains("restart admin"));
    }

    /// The DKIM dump wrapper embeds the marker the app's parser reads, and
    /// its `--dns` export path — a plain `config-export` without `-d` does
    /// not carry `dns_dkim` at all.
    #[test]
    fn the_dkim_dump_script_uses_the_dns_projection_and_the_shared_marker() {
        let script = dkim_dump_script(&base("example.com"));
        assert!(script.contains("config-export -d -j domain"));
        assert!(script.contains(&format!("print(\"{DKIM_MARKER} \"")));
        assert!(script.contains(&format!("echo \"{DKIM_DUMP_DONE_MARKER}\"")));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — the same
/// discipline `install::adguard`'s `fixture_parity` module follows (see
/// that module's doc and `dns_records::fixture_parity`'s for the full
/// rationale). Ground truth is `MailuService`'s actual output, not a
/// re-reading of `MailuService.swift`; fixtures live under
/// `tests/fixtures/install/`, named `mail-mailu-<scenario>__<artifact>`,
/// and were dumped by a separate one-off pass, not generated by this crate.
/// If a fixture and this module's output ever disagree, the working
/// assumption is that the BUG IS IN THIS PORT.
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
    /// `adminGuard=…`/`upstreamHTTPS=…` — the same plain-text render
    /// `install::adguard::fixture_parity` uses, for the same dump.
    fn ingress_text(ingress: &WebIngress) -> String {
        format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}",
            ingress.hostname, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https
        )
    }

    /// `<scenario>__firewall-ports.txt`: one line per port, `<port>/<proto>
    /// <comment>` — the first artifact kind AdGuard never needed, since it
    /// opens no ports at all.
    fn firewall_ports_text(ports: &[FirewallPort]) -> String {
        ports.iter().map(|p| format!("{}/{} {}", p.port, p.proto.as_str(), p.comment)).collect::<Vec<_>>().join("\n")
    }

    fn assert_parity(input: &Input, scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            env_template(input),
            fixture(&format!("{scenario}__env.template")),
            "{scenario}: env.template"
        );
        assert_eq!(hostname(input), fixture(&format!("{scenario}__hostname.txt")), "{scenario}: hostname.txt");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames.txt"
        );
        assert_eq!(
            firewall_ports_text(&firewall_ports()),
            fixture(&format!("{scenario}__firewall-ports.txt")),
            "{scenario}: firewall-ports.txt"
        );
        assert_eq!(caddy_site(input), fixture(&format!("{scenario}__caddy-site.txt")), "{scenario}: caddy-site.txt");
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("{scenario}__ingress.txt")),
            "{scenario}: ingress.txt"
        );
    }

    /// Domain `example.com`, every field at its Swift default.
    #[test]
    fn default_en() {
        assert_parity(&base("example.com"), "mail-mailu-default-en");
    }

    /// `example.com` plus two mirrored additional domains — exercises
    /// `HOSTNAMES` growing a comma-joined list and the Caddy site mirroring
    /// `mail.<domain>` onto both.
    #[test]
    fn mirrored_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "mail-mailu-mirrored-en");
    }

    /// Non-default `mailu_path`/`mailu_subnet` — exercises every volume
    /// mount and the resolver/gateway addresses derived from the subnet,
    /// none of which the other two scenarios move off their defaults.
    #[test]
    fn custom_en() {
        let mut input = base("example.com");
        input.mailu_path = "/srv/mailu".to_string();
        input.mailu_subnet = "172.30.0.0/24".to_string();
        assert_parity(&input, "mail-mailu-custom-en");
    }

    /// The body of a `cat > … <<'MARKER'` heredoc inside the dumped
    /// `setupSteps`, exactly as the shell would write it — the same
    /// extraction `mail::dockermailserver::fixture_parity` uses, and for the
    /// same reason: reading the Swift source and trusting the transcription
    /// is the exact habit that let a confidently wrong DKIM glob live in
    /// that engine's generator for months with a green test beside it
    /// (GOTCHAS.md).
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

    /// Every file the imperative half writes verbatim, diffed against the
    /// bytes the real Swift generator put in its own heredocs.
    fn assert_written_files_parity(input: &Input, scenario: &str) {
        let dump = fixture(&format!("mail-mailu-{scenario}__setup-steps.txt"));
        assert_eq!(cert_sync_script(input), heredoc_body(&dump, "EOF_MU_CERTSYNC"), "{scenario}: cert-sync script");
        assert_eq!(
            cert_sync_service_unit(),
            heredoc_body(&dump, "EOF_MU_CERTSVC"),
            "{scenario}: cert-sync service unit"
        );
        assert_eq!(cert_sync_timer_unit(), heredoc_body(&dump, "EOF_MU_CERTTIMER"), "{scenario}: cert-sync timer unit");
        assert_eq!(dkim_dump_script(input), heredoc_body(&dump, "EOF_GD_MU_DKIM"), "{scenario}: DKIM dump wrapper");
    }

    /// The imperative decisions the dump can prove structurally: every
    /// `install -d` line (the bare path, the 0700 trio, and the two 0755
    /// groups), the domain-import YAML's entries, and the readiness/import
    /// commands.
    fn assert_imperative_parity(input: &Input, scenario: &str) {
        let dump = fixture(&format!("mail-mailu-{scenario}__setup-steps.txt"));

        assert!(
            dump.contains(&format!("install -d -m 755 {}\n", input.mailu_path)),
            "{scenario}: the bare mailu_path 0755 line"
        );
        assert!(
            dump.contains(&format!("install -d -m 700 {}\n", directories_0700(input).join(" "))),
            "{scenario}: the 0700 directory line"
        );
        let dirs_0755 = directories_0755(input);
        let mail_group = dirs_0755[1..6].join(" ");
        let overrides_group = dirs_0755[6..10].join(" ");
        assert!(dump.contains(&format!("install -d -m 755 {mail_group}\n")), "{scenario}: the mail-data 0755 line");
        assert!(
            dump.contains(&format!("install -d -m 755 {overrides_group}\n")),
            "{scenario}: the overrides 0755 line"
        );

        // One `-generate-` entry per mail domain — fed through `printf`, not
        // a `cat >` heredoc, so a substring check on the rendered line is
        // what a piped stdin actually allows checking structurally.
        for domain in mail_domains(input) {
            assert!(dump.contains(&format!("- name: {domain}")), "{scenario}: no domain-import entry for {domain}");
        }
        assert!(dump.contains("flask mailu config-export -j"), "{scenario}: the readiness probe");
        assert!(dump.contains("flask mailu config-import -q -u"), "{scenario}: the merge-mode import call");
    }

    #[test]
    fn default_en_imperative() {
        let input = base("example.com");
        assert_written_files_parity(&input, "default-en");
        assert_imperative_parity(&input, "default-en");
    }

    #[test]
    fn mirrored_en_imperative() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_written_files_parity(&input, "mirrored-en");
        assert_imperative_parity(&input, "mirrored-en");
    }

    #[test]
    fn custom_en_imperative() {
        let mut input = base("example.com");
        input.mailu_path = "/srv/mailu".to_string();
        input.mailu_subnet = "172.30.0.0/24".to_string();
        assert_written_files_parity(&input, "custom-en");
        assert_imperative_parity(&input, "custom-en");
    }
}
