//! Mailcow's install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/MailcowService.swift`.
//!
//! The mail-polka-closing слайс gave this engine an executor
//! (`execute::install_mailcow_steps`), so this file now also carries the
//! FILES that install writes verbatim (the cert-sync script and its two
//! systemd units, the DKIM-dump wrapper) and every pure helper the
//! executor needs to orchestrate mailcow's OWN installer — the
//! `mailcow.conf` patch, the JSON bodies for `add/domain`/`add/dkim`, the
//! `IPV4_NETWORK` parse `API_ALLOW_FROM` depends on. What is still NOT
//! ported: `reportSteps`/`actions`/`extraSudoers`/`uninstallSpec`, for the
//! same reasons every other engine's slice gives them a pass.
//!
//! **The orchestration shell itself is reimplemented natively, not
//! transliterated — the artifacts it produces are what has to match
//! byte-for-byte.** The same split `mail::dockermailserver`'s own module doc
//! draws: `git clone`/`generate_config.sh`/`docker compose`/`curl` are
//! spawned directly (no shell anywhere on this path, the same discipline
//! `control.rs`/`update.rs` hold), and the `sed` sequence that patches
//! `mailcow.conf` is a pure Rust string transform (`patch_conf_for_caddy`)
//! rather than four separate `sed -i` subprocesses — cheaper to test and
//! exactly as idempotent, since it is applied to the file's OWN bytes, not
//! assumed. `curl` — not a Rust TLS client — is what talks to mailcow's
//! HTTPS API: there is no TLS crate in this crate's dependency tree (adding
//! one is out of scope for this слайс), and `curl` is one more directly
//! spawned, fixed-argv binary in exactly the shape `openssl` already is for
//! docker-mailserver's placeholder certificate — not the "generic exec"
//! ARCHITECTURE.md forbids, which is about handing the CLIENT a
//! root-equivalent RPC, not about the agent itself invoking one well-known
//! binary for one well-understood purpose. `curl -f` stays forbidden and no
//! call is fatal — the exact GOTCHAS.md rule the bash version paid for
//! live, ported to Rust rather than re-litigated.
//!
//! **Mailcow is not a compose project we author, unlike every other engine
//! this crate will port.** `MailcowService.composeFile` returns `nil` on the
//! Swift side: mailcow clones its own upstream repository and runs its own
//! config generator, so there is no compose YAML and no env template for
//! this module to produce — the agent ORCHESTRATES mailcow's own installer
//! rather than composing the stack itself, the same "own the contract, not
//! the engine" split `dkim.rs`/`backup.rs`/`restore.rs` already follow for
//! mailcow specifically (their wrappers drive mailcow's REST API and its
//! `backup_and_restore.sh`, never reimplement them). What IS declarative for
//! mailcow, and therefore lives here: where it runs (path, compose project
//! name), its fixed hostname, the six firewall ports mail needs open, and
//! the Caddy site that fronts its web UI.
//!
//! **The one thing every other engine in this catalog does NOT need**: an
//! HTTPS upstream. Mailcow's own HTTP vhost unconditionally 301-redirects to
//! its HTTPS vhost, so proxying plain HTTP into it loops forever (GOTCHAS.md,
//! the mailcow section) — `web_ingress` sets `upstream_https: true`, which is
//! why `install::caddy::site`'s nested `transport http { tls_insecure_skip_verify }`
//! branch exists at all (see that module's own fixture, dumped specifically
//! because no AdGuard scenario could reach it).
//!
//! **No hostname override, unlike AdGuard.** `ServiceSettings` carries an
//! `adguardHostname` a user can set; it carries no `mailcowHostname` at all
//! — mailcow bakes `MAILCOW_HOSTNAME` in at install time and upstream does
//! not support renaming it (`MailcowService.swift`'s own comment on
//! `setupSteps`), so the app never offers a knob that would silently stop
//! matching what is actually on the server. `hostname` here is therefore an
//! unconditional `format!`, not the "empty means derive" branch `adguard::hostname`
//! has.

use super::{FirewallPort, Proto};
use crate::install::caddy::{self, WebIngress};
use crate::install::context::Input;

/// Fixed by mailcow itself: `generate_config.sh` writes
/// `COMPOSE_PROJECT_NAME=mailcowdockerized` into `mailcow.conf` — note the
/// missing hyphens, this is NOT the checkout directory name.
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "mailcow";

pub const COMPOSE_PROJECT: &str = "mailcowdockerized";
/// Upstream repository `setupSteps` clones and the branch it pins
/// (`MAILCOW_BRANCH=master` passed to `generate_config.sh`'s environment).
/// Unused by this slice's declarative surface — carried here because it is
/// as much a part of mailcow's fixed identity as `COMPOSE_PROJECT`, and the
/// imperative slice that eventually ports `setupSteps` needs it verbatim.
pub const REPO_URL: &str = "https://github.com/mailcow/mailcow-dockerized";
pub const BRANCH: &str = "master";
/// Local bind for mailcow's web UI. Mailcow's HTTP vhost unconditionally
/// redirects to the HTTPS vhost below, so Caddy proxies to THAT one instead
/// — see the module doc. `execute::patch_conf_for_caddy` is what binds both
/// to 127.0.0.1 in the generated `mailcow.conf`.
pub const WEB_UI_PORT: u16 = 8080;
pub const WEB_UI_HTTPS_PORT: u16 = 18443;
/// Containers the cert-sync timer (`cert_sync_script`, below) restarts after
/// copying Caddy's renewed certificate into mailcow's own `ssl` assets —
/// mailcow's mail daemons serve their own certificate independently of the
/// web UI's Caddy front, so they need their own reload.
pub const CERT_SYNC_CONTAINERS: [&str; 3] = ["postfix-mailcow", "dovecot-mailcow", "nginx-mailcow"];
/// `MailcowService.dkimDumpScriptPath`/(unnamed cert-sync path/unit
/// constants — the Swift source spells them inline rather than naming them,
/// this port names them for the same reason `mail::dockermailserver`/
/// `mail::mailu` name theirs). Caddy owns the ACME account for
/// `mail.<domain>` on this host, so mailcow's mail daemons are HANDED the
/// certificate instead of getting their own — one process per name, or two
/// ACME clients race each other into Let's Encrypt's failure quota.
pub const CERT_SYNC_SCRIPT_PATH: &str = "/opt/gryonixnexus-mailcow-cert-sync.sh";
pub const CERT_SYNC_UNIT: &str = "gryonixnexus-mailcow-cert-sync";
/// `MailcowService.dkimDumpScriptPath`. Pinned as a literal on THREE sides
/// now — the Swift generator, this module, and `dkim.rs`'s own engine
/// table (`wrapper_default` for the `"mailcow"` entry), which runs exactly
/// this path — the reason the agent has to write it is the same as the
/// other two engines': without it, `GetDkimRecords` on a host installed
/// through the agent answers "the wrapper is not installed" for ever.
/// **Not** `/opt/gryonixnexus-mailcow-dkim.sh`, unlike the cert-sync script
/// above and unlike `mail::mailu::DKIM_DUMP_SCRIPT_PATH` — mailcow's own
/// wrapper predates the naming convention the other two engines follow, and
/// the path is a contract with `dkim.rs`'s table, not a free choice.
pub const DKIM_DUMP_SCRIPT_PATH: &str = "/opt/gryonixnexus-dkim.sh";
/// Byte-identical to `mail::dockermailserver::DKIM_MARKER`/`mail::mailu`'s
/// own — `dkim.rs`'s module doc: one parser serves all three engines
/// because all three wrappers print the same wire format.
pub const DKIM_MARKER: &str = "GRYONIXNEXUS_DKIM";
pub const DKIM_DUMP_DONE_MARKER: &str = "GRYONIXNEXUS_DKIM_DONE";

/// `MailcowInput` folded into the shared `install::context::Input` the
/// moment this engine got an executor built from the wire — the merge both
/// structs' own docs anticipated (the same merge `mail/dockermailserver`
/// made in срез 4.9, and `mail/mailu` makes in this same слайс).
/// `Input.mailcow_path` is what used to be `MailcowInput.mailcow_path`;
/// `domain`/`additional_domains` were already there for every other engine.
/// There is still no `local_only` READ by anything below: mail is excluded
/// from the local-only scope entirely (ARCHITECTURE.md: "VPN и почта
/// исключены"), so `caddy_site` passes `tls_internal: false`
/// unconditionally rather than guess at a shape for a state that never
/// occurs, even though `Input` itself carries the field for every other
/// engine.
///
/// A port of `MailcowService.requiredHostname(forDomain:)` /
/// `MailcowService.webIngress(_:)`'s hostname: unconditionally `mail.<domain>`
/// — there is no override field to check, unlike `adguard::hostname` (see
/// the module doc).
pub fn hostname(input: &Input) -> String {
    format!("mail.{}", input.domain)
}

/// A port of `MailcowService.dnsHostnames(_:)`, which returns `[]` — and
/// carries WHY, not just the empty value: the comment on the Swift side
/// reads "mail.<domain> A-record is already produced by the mail DNS
/// generator". `DNSRecordGenerator` (ported in Ф4 слайс 4.0,
/// `dns_records.rs`) builds `mail.<domain>` — and, per ARCHITECTURE.md's
/// multidomain section, `mail.<alias>` for every additional domain — through
/// its OWN dedicated branch, precisely because mailcow declares no DNS
/// hostnames for the generic per-service mirroring pass to pick up. If this
/// function ever started returning something non-empty, that branch in
/// `dns_records.rs` would start double-declaring the record.
///
/// Unreached in the binary for the same reason
/// `mail::dockermailserver::dns_hostnames` is: the DNS artifact is
/// generated on the client today (срез 4.0's own note).
#[allow(dead_code)]
pub fn dns_hostnames(_input: &Input) -> Vec<String> {
    Vec::new()
}

/// A port of `MailcowService.firewallPorts(_:)` — six fixed TCP ports, same
/// order and same comments as the Swift side. Ignores its `Input`
/// entirely, exactly as the Swift method ignores its `ServiceContext`: the
/// list never varies by domain, path, or anything else about the
/// deployment.
pub fn firewall_ports() -> Vec<FirewallPort> {
    vec![
        FirewallPort { port: 25, proto: Proto::Tcp, comment: "SMTP".to_string() },
        FirewallPort { port: 465, proto: Proto::Tcp, comment: "SMTPS".to_string() },
        FirewallPort { port: 587, proto: Proto::Tcp, comment: "Submission".to_string() },
        FirewallPort { port: 143, proto: Proto::Tcp, comment: "IMAP".to_string() },
        FirewallPort { port: 993, proto: Proto::Tcp, comment: "IMAPS".to_string() },
        FirewallPort { port: 4190, proto: Proto::Tcp, comment: "Sieve".to_string() },
    ]
}

/// A port of `MailcowService.webIngress(_:)`: proxies to mailcow's HTTPS
/// vhost (self-signed, hence `upstream_https: true`) rather than its HTTP
/// one, which only redirects — see the module doc for why. `admin_guard`
/// takes `WebIngress`'s Swift-side default of `true`, exactly as
/// `MailcowService.swift` passes no argument for it and still gets the
/// guard imported into its site.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_HTTPS_PORT, admin_guard: true, upstream_https: true, public_paths: Vec::new() }
}

/// The Caddy site NAMES this ingress publishes — see
/// `adguard::caddy_site_names`/`mail::dockermailserver::caddy_site_names`.
/// The header these produce is what `caddy::merge_site` matches an existing
/// block on, so the ORDER is part of the contract, not cosmetic.
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// A port of the mailcow-specific slice of `ServiceInfraSections.writeCaddyfile`:
/// mirror the ingress hostname onto every additional domain, then render
/// through `caddy::site`. `tls_internal` is hardcoded `false` — see the
/// module doc and `hostname`'s own doc block above on why mail can never be local-only.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, false)
}

/// Every mail domain this install provisions a mailcow domain + DKIM key
/// for: the primary plus every additional domain, in that order — a port of
/// `setupSteps`'s `[context.domain] + context.additionalDomains`, the same
/// list `mail::dockermailserver::mail_domains`/`mail::mailu::mail_domains`
/// build for their own engines.
pub fn mail_domains(input: &Input) -> Vec<String> {
    let mut domains = vec![input.domain.clone()];
    domains.extend(input.additional_domains.iter().cloned());
    domains
}

/// `generate_config.sh`'s non-interactive environment, in the order
/// `setupSteps` sets it: `COMPOSE_VERSION=native` (the script does not
/// detect the compose flavour, only substitutes this into `mailcow.conf`;
/// this crate always installs the compose PLUGIN, so the value is always
/// `native`), `MAILCOW_HOSTNAME`, `MAILCOW_TZ=UTC`, `MAILCOW_BRANCH` (=
/// `BRANCH`).
pub fn generate_config_env(input: &Input) -> Vec<(&'static str, String)> {
    vec![
        ("COMPOSE_VERSION", "native".to_string()),
        ("MAILCOW_HOSTNAME", hostname(input)),
        ("MAILCOW_TZ", "UTC".to_string()),
        ("MAILCOW_BRANCH", BRANCH.to_string()),
    ]
}

/// `generate_config.sh` still prompts on stdin for low-memory hosts (≤2.5
/// GiB it asks "disable ClamAV? [Y/n]" and similar) even with every env var
/// set — a bounded set of yes-answers, ported verbatim from `setupSteps`'s
/// own comment: unexpected prompts either read one of these (or hit EOF and
/// take their own default), and a BOUNDED `printf` cannot die of SIGPIPE the
/// way `yes |` can under `pipefail`.
pub const GENERATE_CONFIG_STDIN: &str = "y\ny\ny\n";

pub fn mailcow_conf_path(input: &Input) -> String {
    format!("{}/mailcow.conf", input.mailcow_path)
}

/// Replace the line `KEY=…` with `KEY=<value>` if `KEY=` starts a line,
/// otherwise leave the text untouched — `sed 's/^KEY=.*/KEY=value/'`'s exact
/// semantics: a key sed's own pattern never matches, sed changes nothing and
/// exits 0, and this does the same rather than inventing an error state the
/// bash version never had.
fn replace_conf_line(conf: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key}=");
    let had_trailing_newline = conf.ends_with('\n');
    let mut out: Vec<String> =
        conf.lines().map(|line| if line.starts_with(&prefix) { format!("{key}={value}") } else { line.to_string() }).collect();
    if out.is_empty() {
        out.push(format!("{key}={value}"));
    }
    let mut joined = out.join("\n");
    if had_trailing_newline {
        joined.push('\n');
    }
    joined
}

/// The five `sed -i` substitutions `setupSteps` applies to a FRESH
/// `mailcow.conf`, right after `generate_config.sh` writes it — a pure
/// function over the file's own bytes rather than four spawned `sed`
/// processes (see the module doc). Only called once, inside the same
/// `mailcow.conf`-absent guard the bash version uses: on a re-run the
/// conf already exists and this must not run again (an operator may have
/// changed one of these five values by hand since).
pub fn patch_conf_for_caddy(conf: &str) -> String {
    let mut out = conf.to_string();
    out = replace_conf_line(&out, "HTTP_BIND", "127.0.0.1");
    out = replace_conf_line(&out, "HTTP_PORT", &WEB_UI_PORT.to_string());
    out = replace_conf_line(&out, "HTTPS_BIND", "127.0.0.1");
    out = replace_conf_line(&out, "HTTPS_PORT", &WEB_UI_HTTPS_PORT.to_string());
    out = replace_conf_line(&out, "SKIP_LETS_ENCRYPT", "y");
    out
}

/// `DOCKER_COMPOSE_VERSION`'s fix-up — UNLIKE `patch_conf_for_caddy`, this
/// runs on EVERY install, not just a fresh one (GOTCHAS.md: left empty, it
/// takes every mailcow helper that reads it down with it, and a conf
/// generated before this fix landed has the key ABSENT rather than wrong).
/// Replaces the line if present, APPENDS it if missing — the same two-branch
/// shape `setupSteps`'s own `if grep -q … ; then … ; else … ; fi` has.
pub fn patch_conf_compose_version(conf: &str) -> String {
    if conf.lines().any(|line| line.starts_with("DOCKER_COMPOSE_VERSION=")) {
        replace_conf_line(conf, "DOCKER_COMPOSE_VERSION", "native")
    } else {
        let mut out = conf.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("DOCKER_COMPOSE_VERSION=native\n");
        out
    }
}

/// `grep '^IPV4_NETWORK=' mailcow.conf | tail -n1 | cut -d= -f2- | tr -d
/// '[:space:]'` — the LAST matching line (generate_config.sh writes it
/// once, but "last wins" is the bash idiom this ports), value only, every
/// whitespace character stripped. `None` if the key is absent, which the
/// caller turns into `DEFAULT_NETWORK_PREFIX` — the same `${MC_NET:-…}`
/// fallback `setupSteps` applies at the point of use, not here, so a caller
/// that wants to know "was it actually on file" still can.
pub fn ipv4_network_prefix(conf: &str) -> Option<String> {
    conf.lines()
        .filter_map(|line| line.strip_prefix("IPV4_NETWORK="))
        .last()
        .map(|value| value.chars().filter(|c| !c.is_whitespace()).collect::<String>())
        .filter(|value| !value.is_empty())
}

/// `generate_config.sh`'s own default subnet prefix — used only when
/// `IPV4_NETWORK` is missing from the conf entirely, which does not happen
/// on a fresh install but is the bash version's own fallback
/// (`"${MC_NET:-172.22.1}"`) and is ported for the same reason: a moved
/// subnet (the generator picks a different one on collision, GOTCHAS.md) is
/// read correctly either way, and an ABSENT key still gets a sane answer
/// instead of an empty `API_ALLOW_FROM`.
pub const DEFAULT_NETWORK_PREFIX: &str = "172.22.1";

/// Whether `mailcow.conf` already has an API key — the guard `setupSteps`
/// checks before minting one, so a re-run never rotates a key already in
/// use (rotating it would orphan every already-configured client of the
/// API, which is nothing today, but the guard is the engine's own and this
/// ports it, not "improves" it away).
pub fn api_key_present(conf: &str) -> bool {
    conf.lines().any(|line| line.starts_with("API_KEY="))
}

/// `grep '^KEY=' conf | tail -n1 | cut -d= -f2-` — the last matching line's
/// value. Used for both `API_KEY` (after it is minted) and, in the DKIM-dump
/// wrapper's own bash, the same read; kept generic here so the executor does
/// not grow a second copy for a key this module already knows how to read.
pub fn read_conf_value(conf: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    conf.lines().filter_map(|line| line.strip_prefix(prefix.as_str())).last().map(str::to_string)
}

/// The two lines appended to `mailcow.conf` the FIRST time an API key is
/// minted — `printf 'API_KEY=%s\nAPI_ALLOW_FROM=%s.1,127.0.0.1\n' "$key"
/// "${MC_NET:-172.22.1}"`, byte for byte. `network_prefix` is the caller's
/// already-resolved value (`ipv4_network_prefix(…).unwrap_or(DEFAULT_NETWORK_PREFIX)`),
/// not resolved again here — one branch, one place that owns the fallback.
pub fn api_conf_append(api_key: &str, network_prefix: &str) -> String {
    format!("API_KEY={api_key}\nAPI_ALLOW_FROM={network_prefix}.1,127.0.0.1\n")
}

/// The API's base URL — always the HTTPS vhost, `-k` (self-signed) in every
/// caller: see the module doc on why the HTTP vhost cannot be used at all
/// (it redirects, and `curl` without `-L` reads the redirect's HTML body as
/// if it were JSON).
pub fn api_base() -> String {
    format!("https://127.0.0.1:{WEB_UI_HTTPS_PORT}/api/v1")
}

/// The JSON body `POST add/domain` takes — a byte-exact port of
/// `setupSteps`'s inline literal, key order included (mailcow's API does
/// not care about key order; a fixture comparing against the real
/// generator's text does).
pub fn add_domain_body(domain: &str) -> String {
    format!(
        "{{\"domain\":\"{domain}\",\"description\":\"Managed by gryonixNexus\",\"aliases\":\"400\",\"defquota\":\"3072\",\"maxquota\":\"10240\",\"quota\":\"10240\",\"mailboxes\":\"50\",\"active\":\"1\",\"restart_sogo\":\"10\"}}"
    )
}

/// The JSON body `POST add/dkim` takes. `dkim_selector` is spelled out for
/// the same reason `mail::dockermailserver::DKIM_SELECTOR` is: the DNS
/// artifact this project generates always publishes `dkim._domainkey`, and
/// mailcow's own default selector is not necessarily that.
pub fn add_dkim_body(domain: &str) -> String {
    format!("{{\"domains\":\"{domain}\",\"dkim_selector\":\"dkim\",\"key_size\":2048}}")
}

/// A port of the certificate-sync SCRIPT written by `MailcowService`'s
/// `setupSteps` — the body of its `EOF_MC_CERTSYNC` heredoc, byte for byte.
/// **Unlike docker-mailserver's and Mailu's own cert-sync scripts, this one
/// does NOT `chmod` the copied certificate/key** — port faithfully, not
/// "fixed": the Swift source has no such line, and mailcow's own containers
/// read `data/assets/ssl` with whatever mode `cp` preserves from Caddy's
/// certificate store.
pub fn cert_sync_script(input: &Input) -> String {
    let host = hostname(input);
    let path = &input.mailcow_path;
    let containers = CERT_SYNC_CONTAINERS.join(" ");
    format!(
        r#"#!/bin/bash
set -eu
DOMAIN="{host}"
MAILCOW="{path}"
DEST="$MAILCOW/data/assets/ssl"
CADDY_DATA="/var/lib/caddy/.local/share/caddy/certificates"
SRC_CRT="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.crt" 2>/dev/null | head -n1)"
SRC_KEY="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.key" 2>/dev/null | head -n1)"
if [ -z "$SRC_CRT" ] || [ -z "$SRC_KEY" ]; then exit 0; fi
if cmp -s "$SRC_CRT" "$DEST/cert.pem" && cmp -s "$SRC_KEY" "$DEST/key.pem"; then exit 0; fi
cp "$SRC_CRT" "$DEST/cert.pem"
cp "$SRC_KEY" "$DEST/key.pem"
cd "$MAILCOW"
docker compose restart {containers} >/dev/null 2>&1 || true
"#
    )
}

/// The `EOF_MC_CERTSVC` heredoc body.
pub fn cert_sync_service_unit() -> String {
    format!(
        "[Unit]\nDescription=Sync Caddy TLS certificate into Mailcow (SMTP/IMAPS)\nAfter=docker.service\n[Service]\nType=oneshot\nExecStart={CERT_SYNC_SCRIPT_PATH}\n"
    )
}

/// The `EOF_MC_CERTTIMER` heredoc body — same shape as
/// `mail::dockermailserver`'s and `mail::mailu`'s own timers, for the same
/// reasons (5-minute head start on a fresh ACME order, hourly renewal
/// coverage, `Persistent=true` catches up after a host was off).
pub fn cert_sync_timer_unit() -> String {
    "[Unit]\nDescription=Periodic Caddy to Mailcow TLS certificate sync\n[Timer]\nOnActiveSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
        .to_string()
}

/// A port of the DKIM-dump wrapper written by `MailcowService`'s
/// `setupSteps` — the body of its `EOF_GD_DKIM` heredoc, byte for byte,
/// INCLUDING the `curl -f`: this is the ONE mailcow curl call in the whole
/// engine that keeps `-f`, because unlike the provisioning loop's `mc_api`
/// (GOTCHAS.md: `-f` forbidden there, it would swallow the diagnostic body
/// and kill the whole install under `set -e`) a failure here is read by
/// `|| true` at the point of use and this dump is read-only diagnostics, not
/// an install step that must not abort.
pub fn dkim_dump_script(input: &Input) -> String {
    let path = &input.mailcow_path;
    format!(
        r#"#!/bin/bash
set -euo pipefail
CONF="{path}/mailcow.conf"
[ -r "$CONF" ] || {{ echo "{DKIM_DUMP_DONE_MARKER}"; exit 0; }}
MC_KEY="$(grep '^API_KEY=' "$CONF" | tail -n1 | cut -d= -f2-)"
API="https://127.0.0.1:{WEB_UI_HTTPS_PORT}/api/v1"
mc() {{ curl -fsSk --max-time 20 -H "X-API-Key: $MC_KEY" "$@"; }}
for D in $(mc "$API/get/domain/all" 2>/dev/null | jq -r '.[].domain_name // empty' 2>/dev/null || true); do
  TXT="$(mc "$API/get/dkim/$D" 2>/dev/null | jq -r '.dkim_txt // empty' 2>/dev/null || true)"
  if [ -n "$TXT" ]; then echo "{DKIM_MARKER} dkim._domainkey.$D $TXT"; fi
done
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
    fn hostname_is_always_mail_dot_domain() {
        assert_eq!(hostname(&base("example.com")), "mail.example.com");
    }

    #[test]
    fn dns_hostnames_is_empty() {
        assert!(dns_hostnames(&base("example.com")).is_empty());
    }

    #[test]
    fn firewall_ports_match_swift_order_and_comments() {
        let ports = firewall_ports();
        let rendered: Vec<String> = ports.iter().map(|p| format!("{}/{} {}", p.port, p.proto.as_str(), p.comment)).collect();
        assert_eq!(
            rendered,
            vec![
                "25/tcp SMTP".to_string(),
                "465/tcp SMTPS".to_string(),
                "587/tcp Submission".to_string(),
                "143/tcp IMAP".to_string(),
                "993/tcp IMAPS".to_string(),
                "4190/tcp Sieve".to_string(),
            ]
        );
    }

    #[test]
    fn web_ingress_proxies_https_with_admin_guard_on() {
        let ingress = web_ingress(&base("example.com"));
        assert!(ingress.admin_guard);
        assert!(ingress.upstream_https);
        assert_eq!(ingress.upstream_port, WEB_UI_HTTPS_PORT);
        assert_eq!(ingress.hostname, "mail.example.com");
    }

    #[test]
    fn caddy_site_mirrors_the_hostname_onto_additional_domains() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert!(caddy_site(&input).starts_with("mail.example.com, mail.example.org {"));
    }

    #[test]
    fn caddy_site_exercises_the_https_upstream_branch() {
        let site = caddy_site(&base("example.com"));
        assert!(site.contains("reverse_proxy https://127.0.0.1:18443"));
        assert!(site.contains("tls_insecure_skip_verify"));
    }

    #[test]
    fn mail_domains_are_the_primary_then_the_additional_ones_in_order() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_eq!(mail_domains(&input), vec!["example.com", "example.org", "example.net"]);
    }

    #[test]
    fn generate_config_env_carries_the_native_compose_flavour_and_the_hostname() {
        let env = generate_config_env(&base("example.com"));
        assert!(env.contains(&("COMPOSE_VERSION", "native".to_string())));
        assert!(env.contains(&("MAILCOW_HOSTNAME", "mail.example.com".to_string())));
        assert!(env.contains(&("MAILCOW_BRANCH", "master".to_string())));
    }

    #[test]
    fn replace_conf_line_only_touches_the_matching_key() {
        let conf = "FOO=1\nHTTP_BIND=0.0.0.0\nBAR=2\n";
        let patched = replace_conf_line(conf, "HTTP_BIND", "127.0.0.1");
        assert_eq!(patched, "FOO=1\nHTTP_BIND=127.0.0.1\nBAR=2\n");
    }

    /// `sed`'s own behaviour: a key that never matches leaves the file
    /// untouched rather than erroring or appending — appending is
    /// `patch_conf_compose_version`'s job, a DIFFERENT function for a
    /// deliberately different rule (see its own doc).
    #[test]
    fn replace_conf_line_is_a_no_op_when_the_key_is_absent() {
        let conf = "FOO=1\n";
        assert_eq!(replace_conf_line(conf, "HTTP_BIND", "127.0.0.1"), conf);
    }

    #[test]
    fn patch_conf_for_caddy_sets_all_five_keys() {
        let conf = "HTTP_BIND=0.0.0.0\nHTTP_PORT=80\nHTTPS_BIND=0.0.0.0\nHTTPS_PORT=443\nSKIP_LETS_ENCRYPT=n\n";
        let patched = patch_conf_for_caddy(conf);
        assert!(patched.contains("HTTP_BIND=127.0.0.1\n"));
        assert!(patched.contains("HTTP_PORT=8080\n"));
        assert!(patched.contains("HTTPS_BIND=127.0.0.1\n"));
        assert!(patched.contains("HTTPS_PORT=18443\n"));
        assert!(patched.contains("SKIP_LETS_ENCRYPT=y\n"));
    }

    #[test]
    fn patch_conf_compose_version_replaces_when_present() {
        let conf = "FOO=1\nDOCKER_COMPOSE_VERSION=\nBAR=2\n";
        assert_eq!(patch_conf_compose_version(conf), "FOO=1\nDOCKER_COMPOSE_VERSION=native\nBAR=2\n");
    }

    /// The bug GOTCHAS.md paid for live: an EMPTY value takes
    /// `backup_and_restore.sh restore` down with it, before it unpacks
    /// anything — so a present-but-empty key must still be REPLACED, not
    /// treated as "already set".
    #[test]
    fn patch_conf_compose_version_replaces_even_when_the_value_is_empty() {
        let conf = "DOCKER_COMPOSE_VERSION=\n";
        assert_eq!(patch_conf_compose_version(conf), "DOCKER_COMPOSE_VERSION=native\n");
    }

    #[test]
    fn patch_conf_compose_version_appends_when_missing() {
        let conf = "FOO=1\n";
        assert_eq!(patch_conf_compose_version(conf), "FOO=1\nDOCKER_COMPOSE_VERSION=native\n");
    }

    /// The generator moves the subnet on collision (GOTCHAS.md) — a
    /// hardcoded `172.22.1` would fail the API's IP ACL on a host where it
    /// moved, reading exactly like a wrong key.
    #[test]
    fn ipv4_network_prefix_reads_whatever_the_generator_actually_picked() {
        assert_eq!(ipv4_network_prefix("IPV4_NETWORK=172.23.5\n"), Some("172.23.5".to_string()));
        assert_eq!(ipv4_network_prefix("FOO=1\n"), None);
    }

    /// The LAST matching line wins — the same bash idiom `tail -n1` encodes,
    /// carried here for whatever writes a second line (a re-run, a manual
    /// edit) rather than assumed impossible.
    #[test]
    fn ipv4_network_prefix_takes_the_last_matching_line() {
        assert_eq!(ipv4_network_prefix("IPV4_NETWORK=172.22.1\nIPV4_NETWORK=172.23.5\n"), Some("172.23.5".to_string()));
    }

    #[test]
    fn api_key_present_checks_the_conf_not_a_guess() {
        assert!(!api_key_present("FOO=1\n"));
        assert!(api_key_present("FOO=1\nAPI_KEY=abc123\n"));
    }

    #[test]
    fn api_conf_append_is_the_two_line_printf() {
        assert_eq!(api_conf_append("deadbeef", "172.22.1"), "API_KEY=deadbeef\nAPI_ALLOW_FROM=172.22.1.1,127.0.0.1\n");
    }

    #[test]
    fn add_domain_and_dkim_bodies_carry_the_domain_and_the_pinned_selector() {
        assert!(add_domain_body("example.com").contains("\"domain\":\"example.com\""));
        let dkim = add_dkim_body("example.com");
        assert!(dkim.contains("\"domains\":\"example.com\""));
        assert!(dkim.contains("\"dkim_selector\":\"dkim\""));
    }

    /// A custom install path has to reach every file the install writes —
    /// the cert-sync script and the DKIM wrapper's `mailcow.conf` path both
    /// embed it.
    #[test]
    fn a_custom_install_path_reaches_the_scripts_too() {
        let mut input = base("example.com");
        input.mailcow_path = "/srv/mailcow".to_string();
        assert!(cert_sync_script(&input).contains("MAILCOW=\"/srv/mailcow\""));
        assert!(dkim_dump_script(&input).contains("CONF=\"/srv/mailcow/mailcow.conf\""));
        assert_eq!(mailcow_conf_path(&input), "/srv/mailcow/mailcow.conf");
    }

    /// Port faithfully, not "fixed": mailcow's own cert-sync script has no
    /// `chmod` line for the copied certificate/key, unlike DMS's and
    /// Mailu's.
    #[test]
    fn cert_sync_script_does_not_chmod_the_copied_certificate() {
        assert!(!cert_sync_script(&base("example.com")).contains("chmod"));
    }

    /// The one mailcow `curl` call that keeps `-f` — see this function's own
    /// doc for why that is not a contradiction of the GOTCHAS.md rule.
    #[test]
    fn the_dkim_dump_script_keeps_curl_dash_f_unlike_the_provisioning_loop() {
        assert!(dkim_dump_script(&base("example.com")).contains("curl -fsSk"));
    }

    /// The unit files name the script by the same literal this module
    /// writes; a drift here is a timer that runs nothing.
    #[test]
    fn the_cert_sync_units_point_at_the_script_this_module_writes() {
        assert!(cert_sync_service_unit().contains(&format!("ExecStart={CERT_SYNC_SCRIPT_PATH}")));
        assert!(cert_sync_timer_unit().contains("WantedBy=timers.target"));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — the same
/// discipline `install::adguard`'s `fixture_parity` follows (see that
/// module's doc for the full rationale). Ground truth is `MailcowService`'s
/// actual output, not a re-reading of `MailcowService.swift`; fixtures live
/// under `tests/fixtures/install/`, named `mail-mailcow-<scenario>__<artifact>`,
/// and were dumped by a separate one-off pass, not generated by this crate.
/// **No `docker-compose.yml`/`env.template` fixtures for mailcow** — unlike
/// every other engine this crate will port, `MailcowService.composeFile`
/// returns `nil` (see the module doc), so there is nothing for those two
/// artifacts to contain. If a fixture and this module's output ever
/// disagree, the working assumption is that the BUG IS IN THIS PORT.
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
    /// `adminGuard=…`/`upstreamHTTPS=…` — same plain-text render
    /// `install::adguard::fixture_parity` uses for `WebIngress`.
    fn ingress_text(ingress: &WebIngress) -> String {
        format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}",
            ingress.hostname, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https
        )
    }

    /// `<scenario>__firewall-ports.txt`: one `<port>/<proto> <comment>` line
    /// per port, in the same order `firewall_ports()` returns them.
    fn firewall_ports_text(ports: &[FirewallPort]) -> String {
        ports.iter().map(|p| format!("{}/{} {}", p.port, p.proto.as_str(), p.comment)).collect::<Vec<_>>().join("\n")
    }

    fn assert_parity(input: &Input, scenario: &str) {
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

    #[test]
    fn default_en() {
        assert_parity(&base("example.com"), "mail-mailcow-default-en");
    }

    #[test]
    fn mirrored_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "mail-mailcow-mirrored-en");
    }

    #[test]
    fn custom_en() {
        // Non-default path (mailcow_path unused by any function under test
        // here, but set to match the fixture's stated input) — see the
        // fixture's own hostname/domain, which is what actually varies
        // `hostname`/`caddy_site`'s output for this scenario.
        let mut input = base("example.com");
        input.mailcow_path = "/srv/mailcow".to_string();
        assert_parity(&input, "mail-mailcow-custom-en");
    }

    /// The body of a `cat > … <<'MARKER'` heredoc inside the dumped
    /// `setupSteps`, exactly as the shell would write it — the same
    /// extraction `mail::dockermailserver::fixture_parity`/
    /// `mail::mailu::fixture_parity` use, and for the same reason: reading
    /// the Swift source and trusting the transcription is the exact habit
    /// that let a confidently wrong DKIM glob live in a sibling engine's
    /// generator for months with a green test beside it (GOTCHAS.md).
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
        let dump = fixture(&format!("mail-mailcow-{scenario}__setup-steps.txt"));
        assert_eq!(cert_sync_script(input), heredoc_body(&dump, "EOF_MC_CERTSYNC"), "{scenario}: cert-sync script");
        assert_eq!(
            cert_sync_service_unit(),
            heredoc_body(&dump, "EOF_MC_CERTSVC"),
            "{scenario}: cert-sync service unit"
        );
        assert_eq!(
            cert_sync_timer_unit(),
            heredoc_body(&dump, "EOF_MC_CERTTIMER"),
            "{scenario}: cert-sync timer unit"
        );
        assert_eq!(dkim_dump_script(input), heredoc_body(&dump, "EOF_GD_DKIM"), "{scenario}: DKIM dump wrapper");
    }

    /// The imperative decisions the dump can prove structurally: the
    /// generator's env, the `mailcow.conf` patches, and one add/domain +
    /// add/dkim JSON body per mail domain.
    ///
    /// **Why the JSON bodies are checked by STRUCTURE, not by domain name.**
    /// The bash version's `add/domain`/`add/dkim` bodies embed `$MC_DOMAIN`,
    /// a shell variable `read` at RUNTIME from a here-document list — the
    /// dumped `setupSteps` text therefore never contains an actual domain
    /// name inside either JSON body, only inside that here-document. This
    /// port calls the HTTP API once per domain directly from a Rust loop
    /// (`add_domain_body(domain)`/`add_dkim_body(domain)`), so what the dump
    /// can prove structurally is: the field set/order the bash version's
    /// literal JSON has, and that every domain this port would loop over is
    /// actually present in the bash version's own domain list.
    fn assert_imperative_parity(input: &Input, scenario: &str) {
        let dump = fixture(&format!("mail-mailcow-{scenario}__setup-steps.txt"));

        assert!(dump.contains(&format!("MAILCOW_HOSTNAME={}", hostname(input))), "{scenario}: MAILCOW_HOSTNAME env");
        assert!(dump.contains("MAILCOW_BRANCH=master"), "{scenario}: MAILCOW_BRANCH env");

        // Every `sed -i 's/^KEY=.*/KEY=value/' mailcow.conf` line the dump
        // carries, PLUS proof that `patch_conf_for_caddy` actually produces
        // that same final value on a synthetic "before" conf — checking only
        // the dump's own text (what the negative control for this harness
        // found missing) proves the SWIFT SOURCE is right without proving
        // this PORT does the same thing; the synthetic `before`/`patched`
        // round trip is what closes that gap.
        let before = "HTTP_BIND=0.0.0.0\nHTTP_PORT=80\nHTTPS_BIND=0.0.0.0\nHTTPS_PORT=443\nSKIP_LETS_ENCRYPT=n\n";
        let patched = patch_conf_for_caddy(before);
        for (key, value) in [
            ("HTTP_BIND", "127.0.0.1".to_string()),
            ("HTTP_PORT", WEB_UI_PORT.to_string()),
            ("HTTPS_BIND", "127.0.0.1".to_string()),
            ("HTTPS_PORT", WEB_UI_HTTPS_PORT.to_string()),
            ("SKIP_LETS_ENCRYPT", "y".to_string()),
        ] {
            assert!(
                dump.contains(&format!("sed -i 's/^{key}=.*/{key}={value}/' mailcow.conf")),
                "{scenario}: the dump's own sed line for {key}"
            );
            assert!(
                patched.contains(&format!("{key}={value}\n")),
                "{scenario}: patch_conf_for_caddy did not actually set {key}={value}"
            );
        }

        assert!(dump.contains("DOCKER_COMPOSE_VERSION=native"), "{scenario}: the DOCKER_COMPOSE_VERSION fix-up");
        assert!(
            patch_conf_compose_version("FOO=1\n").contains("DOCKER_COMPOSE_VERSION=native\n"),
            "{scenario}: patch_conf_compose_version did not actually append the fix-up"
        );

        assert!(
            dump.contains(r#"{\"domain\":\"$MC_DOMAIN\",\"description\":\"Managed by gryonixNexus\""#),
            "{scenario}: add/domain field structure"
        );
        assert!(add_domain_body("example.com").contains("\"description\":\"Managed by gryonixNexus\""), "{scenario}: add_domain_body field structure");
        assert!(
            dump.contains(r#"{\"domains\":\"$MC_DOMAIN\",\"dkim_selector\":\"dkim\",\"key_size\":2048}"#),
            "{scenario}: add/dkim field structure"
        );
        assert!(add_dkim_body("example.com").contains("\"dkim_selector\":\"dkim\""), "{scenario}: add_dkim_body field structure");
        for domain in mail_domains(input) {
            assert!(dump.contains(domain.as_str()), "{scenario}: {domain} missing from the domain here-document list");
        }
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
        input.mailcow_path = "/srv/mailcow".to_string();
        assert_written_files_parity(&input, "custom-en");
        assert_imperative_parity(&input, "custom-en");
    }
}
