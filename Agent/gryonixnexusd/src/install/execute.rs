//! Ф4 срез 4.2 — the IMPERATIVE half of AdGuard Home's install: the agent
//! actually creates the files and runs docker, natively, behind
//! `Install/InstallService`. Срез 4.1 (`context`/`caddy`/`adguard`) ported
//! only the DECLARATIVE half — what content a compose file/env template/
//! Caddy site should hold. This module is what finally calls it and turns
//! that content into a running container: a port of `AdGuardHomeService.
//! setupSteps` plus the pieces of `ServiceInfraSections.composeSetup`/
//! `writeCaddyfile` that make its declarative artifacts real on disk.
//!
//! **No generic exec.** `docker` is spawned directly, one argv element per
//! argument, exactly the discipline `control.rs`/`update.rs` already hold —
//! there is no shell anywhere on this path.
//!
//! **The id gate is two-layered, and deliberately so.** `resolve` first asks
//! `discover::known_service_id` the same question every other RPC in this
//! crate asks — is this a real catalog id at all — and THEN asks whether
//! srez 4.2's own executor covers it. The two questions have different
//! answers on the wire: an id the catalog has never heard of is
//! `invalid_argument` (a client bug), but "vaultwarden" is a perfectly real
//! catalog id that this build simply has no installer for yet, which is
//! `failed_precondition` — the same shape `update::resolve` already draws
//! between "unknown id" and "no wrapper on this host".
//!
//! **Idempotent by construction.** Nothing here refuses a re-run; each step
//! decides for itself whether it has already happened: `.env` is written
//! only when absent (an existing file's secrets survive), `AdGuardHome.yaml`
//! present means the initial configuration already ran and is skipped, the
//! compose file and Caddy site are rewritten every time because rewriting
//! identical content is idempotent on its own.
//!
//! **Срез 4.9 — docker-mailserver, and three firsts.** It is the first
//! service here that opens FIREWALL ports (mail is pointless without
//! 25/465/587/143/993/4190, so a failure there is fatal — see
//! `firewall_step_text`), the first that installs a systemd unit and TIMER of
//! its own (the certificate sync: Caddy holds the ACME account for
//! `mail.<domain>` and the engine has to be handed the file), and the first
//! whose container cannot start at all until the installer has invented a
//! file for it (`SSL_TYPE=manual` crash-loops without a certificate, so a
//! self-signed placeholder is written BEFORE the first `up -d`). It also
//! writes the DKIM-dump wrapper `dkim.rs` in this same binary has always
//! executed — a gap that existed as long as both halves have (see
//! `write_dms_management_scripts`). It spawns ONE binary that is not
//! `docker`: `openssl`, directly, one argv element per argument, behind the
//! same env-var seam.
//!
//! Nothing here writes anywhere new under `/etc`: the unit files land in
//! `/etc/systemd/system` and the Caddy site in `/etc/caddy`, both already in
//! the agent unit's `ReadWritePaths` since 0.0.12/0.0.16. GOTCHAS.md's rule is
//! to RE-READ that list for every new write under `/etc` rather than assume
//! the old set is complete, and this is that check.
//!
//! **No live host in this build environment.** Everything that touches a
//! real docker daemon, a real AdGuard install API or a real Caddy/systemd
//! is exercised here only through PURE functions (argv builders, the DoH
//! patch, `.env` idempotence) or through a REAL stand-in this test binary
//! can stand up itself with no privileges — a stub `docker` script recording
//! its own argv (the same env-var-substitution technique
//! `backup.rs`/`update.rs`/`restore.rs`/`uninstall.rs`/`lockdown.rs` already
//! use for their wrapper binaries) and a real loopback `TcpListener` playing
//! AdGuard's HTTP API for the one test that exercises the hand-rolled HTTP
//! client. The full pipeline (mkdir → compose → env → docker → HTTP →
//! DoH-patch → Caddy → systemctl) is NOT exercised end to end here — that is
//! exactly what the owner said comes later, on a real host, on his signal.

use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use hyper::StatusCode;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::Sender;

use crate::state::Store;
use super::adguard;
use super::authelia;
// The AI shelf. `llm_keys` is beside them rather than inside one, because both
// the chat and the gateway mint the same shared secret through it.
use super::litellm;
use super::llm_keys;
use super::anythingllm;
use super::n8n;
use super::qdrant;
use super::searxng;
use super::openclaw;
use super::ollama;
use super::open_webui;
use super::catalog;
use super::homepage;
use super::pihole;
use super::cloudflared;
use super::headscale;
use super::tailscale;
use super::caddy;
use super::context::{AutheliaProtection, Input};
use super::forgejo;
use super::gitlab;
use super::firewall_base;
use super::firewall_relay;
use super::relay_routes;
use super::crowdsec;
use super::ssh_password;
use super::packages;
use super::ports;
use super::immich;
use super::crafty;
use super::jellyfin;
use super::minecraft;
use super::mail::dockermailserver as dms;
use super::mail::mailcow;
use super::mail::mailu;
use super::nextcloud;
use super::passbolt;
use super::photoprism;
use super::psono;
use super::seafile;
use super::vaultwarden;
use super::firewall;
use super::host;
use super::host::report;
use super::host::{HostInput, HostRole};
use super::vpn::panel;
use super::vpn::protocols::{amnezia, openvpn, shadowsocks, xray};
use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::dns_records::Language;
use crate::util::strip_ansi;
use std::sync::atomic::{AtomicU64, Ordering};

use super::journal;
use crate::{discover, pb};


/// The catalog ids this build's executor understands. Every other real
/// catalog id resolves through `discover::known_service_id` fine but is
/// refused by `resolve` below with `Rejection::NotImplemented` — see the
/// module doc on why that is a different wire answer from "unknown id".
/// Grows one срез at a time: срез 4.2 landed AdGuard Home, срез 4.3 added
/// Jellyfin and Vaultwarden (the other single-container services with no
/// database of their own), срез 4.4 added PhotoPrism — the first stack here
/// with a second container, срез 4.5 Immich — four containers, and still
/// nothing new for the executor. Срез 4.6 (Nextcloud, Forgejo), 4.7 (Seafile,
/// Psono) and 4.8 (GitLab) are the ones that DO cost the executor something
/// new: work after `up -d` — re-applied config, a CLI-created administrator,
/// a settings file the server writes on its own first start and the
/// installer then edits, a secret only the image itself can generate
/// (a keypair), and the longest first boot in the catalog.
/// Срез 4.9 adds docker-mailserver — the first service here that opens
/// FIREWALL ports, the first that writes a systemd timer of its own, and the
/// first whose container cannot even start until a file the installer creates
/// first (a placeholder certificate) exists. The mail-polka-closing слайс
/// adds `mailu` and `mailcow`, closing the `mail` shelf: Mailu reuses the
/// same firewall/cert-sync/DKIM-dump shape docker-mailserver already
/// established (plus work after `up -d` — a domain/DKIM import over its own
/// CLI, the same class of step Nextcloud/Forgejo/GitLab pay for); mailcow is
/// the one engine in the whole catalog that is NOT a compose project this
/// crate authors — it orchestrates mailcow's OWN installer (`git clone` +
/// `generate_config.sh` + its HTTPS REST API), the first (and, by design,
/// only) executor here that spawns `git`/`curl` at all.
/// The ids above, for the host-half wrapper's own coverage test: a service
/// this executor can install and that wrapper cannot remove is a live
/// defect no other test noticed.
#[cfg(test)]
pub fn implemented_service_ids() -> Vec<&'static str> {
    IMPLEMENTED_SERVICE_IDS.to_vec()
}

const IMPLEMENTED_SERVICE_IDS: &[&str] = &[
    "adguard-home",
    // The AI shelf. The engine is the shortest install shape in the catalog —
    // a directory, a compose file, `up`, and deliberately no model. The chat
    // and the gateway share one secret that whichever of them runs first mints
    // (see `llm_keys::ensure_gateway_key`), which is the ONE ordering hazard on
    // the shelf and the reason both arms call the same helper.
    "ollama",
    "open-webui",
    "litellm",
    // The retrieval pair. The chat is the most neighbour-dependent install in
    // this list — model backend AND vector store are both read off the host —
    // and the store beside it is the only service here that publishes nothing
    // at all yet still takes a generated secret, because it is a database.
    "anythingllm",
    "qdrant",
    // The two the assistant shelf ends with. The search engine is the shortest
    // install in the crate — one container, one generated secret and one
    // settings file this repository writes; the assistant is one container and
    // a state directory its own UI fills.
    "searxng",
    "openclaw",
    // The automation shelf. Its own shelf on the Swift side and its own arm
    // here: a Postgres beside the engine, and the one site in the catalog
    // that is not a single block (see `n8n::WEBHOOK_PATHS`).
    "n8n",
    // Second engine on the same shelf. Its install is the shortest shape in
    // the catalog — one container, one generated secret, no bootstrap API to
    // wait on — because Pi-hole reads its admin password from the environment
    // instead of serving a setup wizard to the first visitor.
    "pihole",
    // The start page. No secret at all; what it does have is a configuration
    // written from the OTHER services on the host.
    "homepage",
    // Single sign-on. Like the page, its configuration names the other
    // services — but where a missing row on the page is cosmetic, a missing
    // rule here is a site the portal refuses.
    "authelia",
    "cloudflared",
    // Installable alone: joining Tailscale's own coordination service needs no
    // Headscale on this host, so the node is no longer reachable only through
    // the control server's call.
    "tailscale-node",
    "headscale",
    "docker-mailserver",
    "forgejo",
    "gitlab",
    "immich",
    "jellyfin",
    // The games shelf. Both engines are the shortest install shape there is —
    // a directory, a compose file, `up` — because the server generates its own
    // world and there is nothing to configure afterwards.
    "minecraft-java",
    "minecraft-bedrock",
    // The panel in front of them, and the only one of the three with a site.
    "crafty-controller",
    "mailcow",
    "mailu",
    "nextcloud",
    // Third and last product on the `passwords` shelf, alongside
    // vaultwarden and psono above — see `install::passbolt`'s module doc.
    "passbolt",
    "photoprism",
    "psono",
    "seafile",
    "vaultwarden",
    // Срез 4.9. ONE id for the whole VPN, not one per protocol: the agent's
    // catalog already collapses every VPN piece into this single service
    // (`discover::VPN_SERVICE`) because that is how the app manages them, and
    // an installer that spoke a different language than `GetState` would put
    // five cards on a dashboard that draws one. Which protocols to install
    // rides in `settings` — see `vpn_protocols_from`.
    "vpn",
];

/// Deadline for one `docker compose` invocation (pull, up, or restart).
/// AdGuard is one small image with no migration/warm-up story, so this stays
/// far under `control.rs`'s 600s budget for an arbitrary compose stack.
const DOCKER_TIMEOUT_SECS: u64 = 300;

/// Deadline for the one-time `admin-lockdown.sh on` run at first install —
/// it only computes local interface addresses and writes/reloads Caddy, so it
/// stays far under `DOCKER_TIMEOUT_SECS`.
const ADMIN_LOCKDOWN_ON_TIMEOUT_SECS: u64 = 30;

/// How long `InstallService` waits for AdGuard's own install API to answer
/// after `up -d`, ported from `setupSteps`'s bash loop.
const READY_DEADLINE_SECS: u64 = 300;
const READY_POLL_INTERVAL_SECS: u64 = 5;
/// Every 6th poll (~30s at a 5s interval) is a heartbeat event — ported
/// verbatim from the bash `if [ "$((AG_TRY % 6))" -eq 0 ]`.
const READY_HEARTBEAT_EVERY: u32 = 6;
/// `curl`'s own `timeout 20` on each install-API call.
const ADGUARD_HTTP_TIMEOUT_SECS: u64 = 20;

/// The generator's `timeout 60` on each `wgpw` form. Short on purpose: the
/// failure it exists for is a container that never exits (the entrypoint
/// starting the panel instead of hashing), and two of those at the full docker
/// timeout would cost ten minutes of an install that can still succeed.
const WGPW_TIMEOUT_SECS: u64 = 60;

/// Seafile's own deadline, ported from `setupSteps`: the first start creates
/// three schemas and runs the whole migration set, minutes on a small ARM
/// board, and only then does seahub write the settings file this install has
/// to edit.
const SEAFILE_SETTINGS_DEADLINE_SECS: u64 = 600;

/// Psono's readiness deadline (`presetup` doubles as the probe — it needs a
/// working database connection, which is the part not ready yet while the
/// container already reports up).
const PSONO_READY_DEADLINE_SECS: u64 = 300;
/// `ps_exec`'s own `timeout 60` per `docker exec` attempt.
const PSONO_EXEC_TIMEOUT_SECS: u64 = 60;
/// The one-shot `docker run` that mints Psono's server keypair. The bash
/// version has NO timeout on it at all; this one does, because every
/// `docker run` in an install must be bounded (a subcommand an entrypoint
/// does not understand otherwise falls through to starting the server and
/// hangs the install forever). Generous rather than tight: this call runs
/// BEFORE `compose pull`, so it is also what implicitly pulls the combo
/// image the first time.
const PSONO_KEYGEN_TIMEOUT_SECS: u64 = 900;

/// Passbolt's readiness deadline: the entrypoint batch-generates the GPG
/// keypair before it installs the schema, and the private key file's
/// existence IS the readiness signal — see `provision_passbolt`'s own doc.
const PASSBOLT_READY_DEADLINE_SECS: u64 = 300;
/// `timeout 60 docker exec …` — the bash version's own per-call ceiling on
/// `pb_exec`.
const PASSBOLT_EXEC_TIMEOUT_SECS: u64 = 60;

const CADDYFILE_PATH: &str = "/etc/caddy/Caddyfile";

/// Nextcloud's `occ`: 30 attempts, 5s apart, ported from the bash
/// `for _ in $(seq 1 30)` — a COUNT here rather than a deadline because each
/// call already carries its own timeout and occ answers or refuses fast.
const OCC_READY_ATTEMPTS: u32 = 60;
const OCC_READY_INTERVAL_SECS: u64 = 5;
const OCC_CALL_TIMEOUT_SECS: u64 = 120;
/// Forgejo's readiness wait is a DEADLINE (see `configure_forgejo`), with the
/// same 120s per-call ceiling the bash version puts on `timeout docker exec`.
const FORGEJO_READY_DEADLINE_SECS: u64 = 300;
const FORGEJO_EXEC_TIMEOUT_SECS: u64 = 120;
/// GitLab's first boot is a full omnibus reconfigure plus database
/// migrations — many minutes on a small ARM machine, which is exactly the
/// wait that reads as a hung install without a heartbeat. Ten minutes, polled
/// every ten seconds, heartbeat every third poll (~30s), all ported from the
/// bash block.
const GITLAB_READY_DEADLINE_SECS: u64 = 600;
const GITLAB_POLL_INTERVAL_SECS: u64 = 10;
const GITLAB_HEARTBEAT_EVERY: u32 = 3;
const GITLAB_EXEC_TIMEOUT_SECS: u64 = 120;
/// `gitlab-rails runner` boots the ENTIRE Rails environment before it runs
/// anything — minutes on ARM, far past the probe's own ceiling, so it gets
/// its own.
const GITLAB_RUNNER_TIMEOUT_SECS: u64 = 300;
/// Written once, then respected: a user who deliberately re-opens sign-up in
/// the Admin Area must not have it closed again by the next run — the same
/// rule that keeps the root password from being reset.
const GITLAB_SIGNUP_MARKER: &str = ".gryonixnexus-signup-closed";

/// docker-mailserver's readiness deadline, ported from `setupSteps`: five
/// minutes on a clock, NOT a number of tries — each `docker exec` can burn its
/// own 120s ceiling, so counting attempts leaves the real wait unbounded (the
/// bug the mailcow API wait had). The probe itself is
/// `dms::READINESS_PROBE_ARGS`, and which command that is was paid for live —
/// see its own doc.
const DMS_READY_DEADLINE_SECS: u64 = 300;
/// `timeout 120 docker exec …` — the bash version's own per-call ceiling. A
/// cold engine really does take that long to answer `setup email add`.
const DMS_EXEC_TIMEOUT_SECS: u64 = 120;
/// The placeholder certificate is one `openssl req` on a 2048-bit key: fast,
/// but bounded like every child process here.
const OPENSSL_TIMEOUT_SECS: u64 = 120;
/// The cert-sync script's one immediate run. It only looks for a certificate
/// Caddy may not have yet and exits, so this is a generous bound on a
/// find/cmp/cp, not a wait for anything.
const CERT_SYNC_RUN_TIMEOUT_SECS: u64 = 120;
/// The drop-in label the firewall module names its file after
/// (`/etc/nftables.d/gryonixnexus-<label>.nft`). The catalog id, so the file on
/// a real host reads as the service it belongs to — and so a later uninstall
/// can find it by the same name.
const DMS_FIREWALL_LABEL: &str = "docker-mailserver";
const MAILU_FIREWALL_LABEL: &str = "mailu";
const MAILCOW_FIREWALL_LABEL: &str = "mailcow";

/// Mailu's readiness deadline, ported from `setupSteps`: `flask mailu
/// config-export -j` has to reach the database, which is what is actually
/// not ready yet while the containers report up — a DEADLINE, not a try
/// count, for the same reason every other engine's own wait in this file is
/// one (each attempt can burn its own exec timeout).
const MAILU_READY_DEADLINE_SECS: u64 = 300;
/// `timeout 120 docker compose … exec -T admin …` — the bash version's own
/// per-call ceiling.
const MAILU_EXEC_TIMEOUT_SECS: u64 = 120;
/// `timeout 120` on the piped `config-import` call.
const MAILU_IMPORT_TIMEOUT_SECS: u64 = 120;

/// `git clone` of mailcow's own repository. Generous: a fresh clone over a
/// slow link is still a one-time cost, and there is no partial-progress
/// signal worth polling for the way a deadline-with-heartbeat wait needs.
const MAILCOW_GIT_CLONE_TIMEOUT_SECS: u64 = 600;
/// `generate_config.sh`'s own non-interactive run — mostly instant once the
/// yes-answers are consumed, bounded generously because it is a one-shot
/// step that must not silently hang the whole install if an unexpected
/// prompt is ever added upstream.
const MAILCOW_GENERATE_CONFIG_TIMEOUT_SECS: u64 = 300;
/// One `docker compose pull`/`up` attempt. Mailcow pulls roughly fifteen
/// images on a fresh host (GOTCHAS.md); `retry`'s own linear backoff is what
/// absorbs a single transient registry timeout, not this ceiling — this is
/// the bound on ONE attempt succeeding or failing outright.
const MAILCOW_COMPOSE_TIMEOUT_SECS: u64 = 600;
/// `curl --max-time 20` — every mailcow API call's own ceiling, ported
/// verbatim from `mc_api`.
const MAILCOW_API_HTTP_TIMEOUT_SECS: u64 = 20;
/// The API-readiness deadline, ported from `setupSteps`: 300s on a clock,
/// not a try count — the exact bug class the mailcow API section of
/// GOTCHAS.md records (counting attempts left "5 minutes" turning into 25
/// with each attempt burning its own `--max-time 20`).
const MAILCOW_API_DEADLINE_SECS: u64 = 300;
const MAILCOW_API_POLL_INTERVAL_SECS: u64 = 5;
/// Heartbeat every ~30s at a 5s poll interval — `if [ "$((MC_TRY % 6))" -eq
/// 0 ]` ported verbatim.
const MAILCOW_API_HEARTBEAT_EVERY: u32 = 6;

/// Client strings are echoed back in error messages so a mistake is
/// diagnosable, but only a bounded prefix — the same limit `control.rs`/
/// `update.rs` hold their echoes to.
const ECHO_LIMIT: usize = 64;

fn truncate(value: &str) -> String {
    value.chars().take(ECHO_LIMIT).collect()
}

// ─────────────────────────── docker seam ───────────────────────────

/// The binary every docker call in this module spawns. Overridable through
/// the environment for tests, the same technique `backup::wrapper_path`/
/// `update::wrapper_path`/etc. already use for their root-owned wrappers — a
/// test points this at a stub script that records its own argv; a server
/// never sets it.
fn docker_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN").unwrap_or_else(|_| "docker".to_string()))
}

/// mailcow's own installer is the ONE place this crate spawns `git` — see
/// `install_mailcow_steps`'s doc. Same env-var seam as `docker_bin`.
fn git_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_INSTALL_GIT_BIN").unwrap_or_else(|_| "git".to_string()))
}

/// `generate_config.sh` is invoked through `bash <script>` rather than by
/// its own executable bit (which `git clone` preserves, but relying on it
/// would make this port depend on a bit the bash SSH-path version also
/// depends on implicitly and has never had to think about) — same env-var
/// seam as `docker_bin`.
fn bash_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_INSTALL_BASH_BIN").unwrap_or_else(|_| "bash".to_string()))
}

/// mailcow's REST API is HTTPS-only and self-signed — see the `mail::mailcow`
/// module doc for why `curl` is what talks to it instead of a Rust TLS
/// client. Same env-var seam as `docker_bin`.
fn curl_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_INSTALL_CURL_BIN").unwrap_or_else(|_| "curl".to_string()))
}

/// The compose file every one of these verbs is pointed at EXPLICITLY.
///
/// **`-f` is not optional here, and its absence was a real defect.** The bash
/// setup script `cd`s into the service directory before every compose call
/// (`VPNPanelService.setupSteps` even carries a comment about why the `cd` is
/// mandatory); the agent has no cwd to rely on — its unit declares no
/// `WorkingDirectory=`, so systemd starts it in `/`. `docker compose -p <name>
/// up -d` finds an EXISTING project's containers by label, which is why
/// `control.rs` can start/stop/restart without a file, but `up` has to be told
/// what to create and answers "no configuration file provided: not found"
/// without one. Every install slice from срез 4.2 to 4.8 built its argv this
/// way and none of them has been run against a real docker daemon yet, which
/// is exactly how it survived: the defect is invisible to a stubbed `docker`
/// that records argv and exits 0.
fn compose_file_args(project: &str, dir: &Path) -> Vec<String> {
    vec![
        "compose".to_string(),
        "-p".to_string(),
        project.to_string(),
        "-f".to_string(),
        dir.join("docker-compose.yml").to_string_lossy().into_owned(),
    ]
}

/// `docker compose -p <project> -f <dir>/docker-compose.yml pull -q`. `-q`
/// matches the bash version (`setupSteps`'s update script and its own inline
/// setup step both pass it) — a pull's own progress bars are not useful
/// streamed line by line.
pub fn compose_pull_args(project: &str, dir: &Path) -> Vec<String> {
    let mut args = compose_file_args(project, dir);
    args.push("pull".to_string());
    args.push("-q".to_string());
    args
}

/// `docker compose -p <project> -f <dir>/docker-compose.yml up -d`.
/// `docker compose up -d`, and then the question `up -d` does not answer:
/// **did the containers actually GET the ports this project publishes?**
///
/// `up -d` reports success for a container that is ALREADY running without
/// them. Measured on `vps-middle` 2026-08-24 through the script route, which
/// shares this defect exactly: a first run died when the container could not
/// bind `127.0.0.1:53`, a docker restart later brought that container back up
/// with NO published ports at all, and the next `up -d` found it running,
/// changed nothing and returned 0. Everything after that — the readiness wait,
/// the Caddy site, the credentials in the report — described a service that
/// did not exist.
///
/// The wanted mappings are read back out of the compose file this install just
/// wrote, so there is nothing to keep in step with it.
async fn compose_up(project: &str, dir: &Path, sink: &EventSink) -> Result<(), String> {
    run_docker_streaming(&compose_up_args(project, dir), sink).await?;
    verify_published_ports(project, dir).await?;
    verify_not_crash_looping(project, dir, sink).await
}

/// How many times `verify_published_ports` asks docker before believing it.
/// `docker ps` right after `up -d` can still be a moment behind, and a false
/// "the ports are missing" would fail a healthy install — the more expensive
/// way to be wrong.
const PORT_VERIFY_TRIES: u32 = 5;
const PORT_VERIFY_INTERVAL_SECS: u64 = 2;

/// Which of the compose file's mappings docker is NOT publishing for this
/// project. Pure, so the comparison is testable without a docker daemon.
///
/// Compared on port and protocol alone, deliberately: the address half is what
/// decides whether a bind can be MADE (see `ports`), while here the mapping is
/// already ours and the only question is whether it exists at all.
fn missing_publishes(wanted: &[ports::Wanted], live: &[firewall::Port]) -> Vec<String> {
    wanted
        .iter()
        .filter(|want| !live.contains(&want.port))
        .map(|want| format!("{}/{}", want.port.port, want.port.proto))
        .collect()
}

async fn verify_published_ports(project: &str, dir: &Path) -> Result<(), String> {
    let Ok(compose) = tokio::fs::read_to_string(dir.join("docker-compose.yml")).await else {
        // Nothing to compare against: mailcow writes its own compose, and a
        // file this call could not read is not evidence of a broken install.
        return Ok(());
    };
    let wanted = ports::published_in_compose(&compose);
    if wanted.is_empty() {
        return Ok(());
    }
    let mut missing: Vec<String> = Vec::new();
    for attempt in 0..PORT_VERIFY_TRIES {
        missing = missing_publishes(&wanted, &ports::published_ports_of_project(project).await);
        if missing.is_empty() {
            return Ok(());
        }
        if attempt + 1 < PORT_VERIFY_TRIES {
            tokio::time::sleep(Duration::from_secs(PORT_VERIFY_INTERVAL_SECS)).await;
        }
    }
    Err(format!(
        "the containers started without the ports they need ({}) — something else on this host took them",
        missing.join(", ")
    ))
}

/// How long the install watches a freshly started project, how often it looks,
/// and how many quiet looks end the watch early.
///
/// **The numbers are the update path's, and they were paid for twice.** The
/// first calibration here was two looks three seconds apart, on the reasoning
/// that a healthy service should not pay for a rare failure. A live negative
/// control on vps-middle (2026-08-26) killed it: a Minecraft server given a heap
/// the JVM cannot start on is still `running` at six seconds — the JVM has not
/// finished dying yet — so the watch left happy and the install passed on a
/// container that went on to loop for ever. A window shorter than the thing it
/// is watching for measures nothing.
///
/// So: fifteen seconds minimum, the same floor `container_update` arrived at
/// from its own live run. That is a real cost — a full install brings up
/// twenty-nine projects — and it is the price of the answer being true.
const LOOP_WATCH_SECS: u64 = 60;
const LOOP_WATCH_INTERVAL_SECS: u64 = 5;
/// Quiet looks in a row that end the watch early.
const LOOP_QUIET_SAMPLES: u32 = 3;

/// Did the project ever go QUIET — [`LOOP_QUIET_SAMPLES`] looks in a row with
/// nothing restarting and no restart counter moving?
///
/// **This replaced "is it restarting at the end", which had a blind spot big
/// enough to drive the original defect through.** A container that runs for four
/// seconds and then dies, for ever, is a crash loop — and it is `running` on
/// almost every sample, because running is most of its cycle. Asking what state
/// it is in at one particular instant answers about that instant. Asking
/// whether it ever settled answers about the service.
///
/// It reads the other way round from its predecessor, and that is the point:
/// the passing condition is something OBSERVED, not something absent. A watch
/// that ends without having seen the service hold still has not seen it work.
///
/// Immich is the case this must not fail: its server restarts once while the
/// database initialises, and then holds. One restart costs it a few samples and
/// it goes quiet well inside the window.
pub(crate) fn went_quiet(
    quiet_streak: u32,
    samples_required: u32,
) -> bool {
    quiet_streak >= samples_required
}

/// Refuse an install that leaves the host in a crash loop.
///
/// **Measured, not reasoned: the first live run of Minecraft (vps-middle,
/// 2026-08-26) reported SUCCESS on a container that had never once started.**
/// The image could not run the game version it resolved, so it exited 1 and
/// `restart: unless-stopped` brought it back, for ever. Every check the install
/// had passed: `up -d` returned 0, and the published ports were there — because
/// `docker-proxy` holds a publication for as long as the container is being
/// restarted. The port answered a TCP connect and then reset it. The install
/// printed the server's address and the report named an administrator nobody
/// could reach.
///
/// This does NOT wait for readiness: a service that is merely slow — Minecraft
/// generating its first world takes minutes — passes as soon as it stops
/// moving, and nothing here asks whether it has finished starting.
async fn verify_not_crash_looping(
    project: &str,
    dir: &Path,
    sink: &EventSink,
) -> Result<(), String> {
    use crate::container_ops::capture;
    use crate::container_update::{restart_counts, verdict, Look};

    let args = vec![
        "compose".to_string(),
        "-p".to_string(),
        project.to_string(),
        "-f".to_string(),
        dir.join("docker-compose.yml").to_string_lossy().to_string(),
        "ps".to_string(),
        "--format".to_string(),
        "{{.Name}} {{.State}}".to_string(),
    ];

    let mut quiet_baseline: Option<std::collections::BTreeMap<String, u64>> = None;
    let mut who = String::new();
    let mut quiet = 0u32;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(LOOP_WATCH_SECS);
    loop {
        // Docker not answering is not evidence of a broken install: every other
        // check here treats an unreadable answer as "no opinion" and so does
        // this one.
        let Ok(res) = capture("docker", &args, 60).await else { return Ok(()) };
        if res.success {
            // Names come from whichever look can supply them: a project caught
            // mid-restart reports no RUNNING container at all, and asking for
            // counters by an empty list would answer nothing on exactly the
            // sample that matters.
            let (names, restarting, label) = match verdict(&res.stdout) {
                Look::Running(names) => (names, false, String::new()),
                Look::Restarting(names) => {
                    (names.split(", ").map(str::to_string).collect(), true, names)
                }
                Look::Down(names) => {
                    (names.split(", ").map(str::to_string).collect(), false, names)
                }
            };
            let counts = restart_counts(&names).await;
            if !label.is_empty() {
                who = label;
            }
            match &quiet_baseline {
                Some(before) if !restarting && *before == counts => {
                    quiet += 1;
                    if went_quiet(quiet, LOOP_QUIET_SAMPLES) {
                        return Ok(());
                    }
                }
                _ => {
                    quiet_baseline = Some(counts);
                    quiet = 0;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(LOOP_WATCH_INTERVAL_SECS)).await;
    }

    let _ = sink;
    let name = if who.is_empty() { project.to_string() } else { who };
    Err(format!(
        "{name} never held still: over {LOOP_WATCH_SECS}s it kept restarting rather \
         than staying up, so the service is not running even though its ports are \
         published"
    ))
}

pub fn compose_up_args(project: &str, dir: &Path) -> Vec<String> {
    let mut args = compose_file_args(project, dir);
    args.push("up".to_string());
    args.push("-d".to_string());
    args
}

/// `docker compose -p <project> restart`. Never `down`/`rm` — this module
/// installs and reconfigures, it does not uninstall (that stays behind
/// `uninstall.rs`'s own wrapper, same rule `control::docker_args` states).
/// `docker compose -p <project> restart <service>` — ONE service of a
/// project, which is what Seafile's CSRF step needs: the settings file it
/// just rewrote is read by seahub only at start, and restarting the whole
/// project would take its database and cache down with it for no reason.
pub fn compose_restart_service_args(project: &str, dir: &Path, service: &str) -> Vec<String> {
    let mut args = compose_restart_args(project, dir);
    args.push(service.to_string());
    args
}

/// `docker run --rm <image> <command…>` — a ONE-SHOT container, used only
/// where the image itself owns a generator this crate must not reimplement
/// (Psono's `generateserverkeys.py`). Every argument is its own argv
/// element; there is no shell here either.
pub fn docker_run_once_args(image: &str, command: &[&str]) -> Vec<String> {
    let mut args = vec!["run".to_string(), "--rm".to_string(), image.to_string()];
    args.extend(command.iter().map(|part| part.to_string()));
    args
}

/// `docker run --rm -v <mount> <image> <command…>` — a one-shot with the
/// service's data directory bound in, which is how OpenVPN's PKI is built and
/// how its client profile is printed. The mount is `host:container` already
/// joined by the caller, because that is the single argv element docker wants.
pub fn docker_run_mounted_args(mount: &str, image: &str, command: &[&str]) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-v".to_string(),
        mount.to_string(),
        image.to_string(),
    ];
    args.extend(command.iter().map(|part| part.to_string()));
    args
}

/// `docker run --rm --entrypoint <binary> <image> <args…>` — the FIRST form
/// AmneziaWG's password hashing is tried in. The explicit entrypoint is what
/// stops an unrecognised sub-command from falling through to starting the
/// panel (see `hash_amnezia_password`).
pub fn docker_run_entrypoint_args(entrypoint: &str, image: &str, command: &[&str]) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--entrypoint".to_string(),
        entrypoint.to_string(),
        image.to_string(),
    ];
    args.extend(command.iter().map(|part| part.to_string()));
    args
}

/// `docker pull -q <image>` — for the two protocols that must have an image
/// on disk BEFORE the compose file is of any use: XRay mints its keys by
/// running the image, AmneziaWG hashes its password with it.
pub fn docker_pull_args(image: &str) -> Vec<String> {
    vec!["pull".to_string(), "-q".to_string(), image.to_string()]
}

/// `docker exec <container> <command…>`.
pub fn docker_exec_args(container: &str, command: &[&str]) -> Vec<String> {
    let mut args = vec!["exec".to_string(), container.to_string()];
    args.extend(command.iter().map(|part| part.to_string()));
    args
}

pub fn compose_restart_args(project: &str, dir: &Path) -> Vec<String> {
    let mut args = compose_file_args(project, dir);
    args.push("restart".to_string());
    args
}

// ─────────────────────────── secrets ───────────────────────────

/// 24 random bytes as lowercase hex — the same shape `openssl rand -hex 24`
/// produces on the bash side (`ServiceInfraSections.composeSetup`). Reads
/// straight from the kernel CSPRNG rather than pulling in a `rand` crate:
/// the agent keeps its dependency list short on purpose (see Cargo.toml's
/// own comment on `libc` being its only FFI), and a 24-byte read is the
/// entire need here.
fn random_hex_24() -> io::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 24];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// `openssl rand -hex 20`'s own shape (20 bytes, 40 hex characters) — what
/// mailcow's `setupSteps` mints its REST API key with. A distinct function
/// from `random_hex_24`/`random_hex_12` rather than a generalized
/// `random_hex(n)` both would call: three small functions of the same shape
/// is the pattern this file already has (`random_hex_24`/`random_hex_12`
/// predate this one), not a gap this slice needs to close.
fn random_hex_20() -> io::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 20];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Expand every `__RANDOM__` token, one INDEPENDENT secret per line — a port
/// of `composeSetup`'s bash loop: each line is read, `__RANDOM__` is
/// substituted (first occurrence only, `${line/__RANDOM__/…}`'s own rule) if
/// present, every other line passes through unchanged, and the result always
/// ends with a trailing newline (`printf '%s\n'` on every line of a
/// `while read` loop).
fn expand_random(template: &str) -> io::Result<String> {
    let mut out = String::new();
    for line in template.lines() {
        if line.contains("__RANDOM__") {
            out.push_str(&line.replacen("__RANDOM__", &random_hex_24()?, 1));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    Ok(out)
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Writes `contents` to `path`, created (or truncated) at `mode` directly
/// through `OpenOptions` rather than `std::fs::write` followed by
/// [`set_mode`]. The gap between those two calls leaves a brand-new file at
/// the process umask (typically 0644) — world-readable — for the instant in
/// between, which matters for exactly the files this is for: generated
/// passwords and password hashes. `vault.rs` and `llm_keys.rs::write_if_changed`
/// make the same call for their own secrets; this is the `execute.rs`
/// counterpart for the install-time writes flagged in the 2026-09-13
/// security audit (finding F4).
fn write_secret(path: &Path, contents: &str, mode: u32) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

fn create_dir_0755(path: &Path) -> io::Result<()> {
    create_dir_with_mode(path, 0o755)
}

/// The same thing with the mode spelled out by the caller. Needed because
/// docker-mailserver has exactly one directory that is NOT 0755: `certs`,
/// which holds the private key of the certificate the engine serves on port
/// 25/465/587/993 and is 0700 for that reason (`install -d -m 700` on the bash
/// side). The container mounts it read-only; nothing else on the host has
/// business there.
fn create_dir_with_mode(path: &Path, mode: u32) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    set_mode(path, mode)
}

/// A directory the CONTAINER's own unprivileged user has to write into, so it
/// carries a group as well as a mode.
///
/// Needed because a bind mount is not seeded from the image. When upstream
/// mounts a NAMED volume over a directory the image ships, docker copies that
/// directory's contents, ownership and mode into the fresh volume — which is
/// how Passbolt's server, running as www-data, comes to own the keypair it
/// generates. A bind mount is never seeded: the container sees the host
/// directory exactly as it is, so a 0755 root:root directory silently denies
/// every write the image expected to succeed.
///
/// The group is a raw gid, not a name: it has to match the id INSIDE the
/// container, and the host is not guaranteed to have a matching group at all.
fn create_dir_owned_by_group(path: &Path, mode: u32, gid: u32) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    // Only the GROUP is set. The owner is whoever created the directory, which
    // in production is the agent, which is root — so naming uid 0 explicitly
    // would change nothing and would additionally be privileged, failing for
    // any caller that is not root even when the group change alone is allowed.
    // Order matters: chown clears the setgid/setuid bits on some systems, so
    // the mode is applied after the ownership, never before.
    std::os::unix::fs::chown(path, None, Some(gid))?;
    set_mode(path, mode)
}

/// The same thing again, with the OWNER set as well as the group.
///
/// The group-only form above is enough where the image's user reaches the
/// directory through its group (Passbolt's www-data). It is not enough for
/// n8n, whose settings directory is 0700: at that mode the group bits grant
/// nothing, so the uid has to match or the container cannot write the file
/// holding its own encryption key. `install -d -m 700 -o 1000 -g 1000` on the
/// bash side, and the same order for the same reason — chown first, mode
/// after.
fn create_dir_owned_by_user(path: &Path, mode: u32, uid: u32, gid: u32) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    set_mode(path, mode)
}

/// Create a directory only when it is MISSING, and never touch the mode of
/// one that already exists. For directories the product does not own —
/// today Jellyfin's media library, which normally predates the install and
/// whose ownership and mode are the user's business (the bash version says
/// exactly this next to its `[ -d <media> ] || install -d -m 755 <media>`).
/// Returns whether it created anything.
fn create_dir_if_absent_0755(path: &Path) -> io::Result<bool> {
    if path.is_dir() {
        return Ok(false);
    }
    create_dir_0755(path)?;
    Ok(true)
}

/// Write `.env` from `template` ONLY when it is absent — the idempotence
/// rule every secret-bearing compose project in this project holds:
/// existing secrets must survive a re-run (`composeSetup`'s own
/// `if [ ! -f "$dir/.env" ]` guard). Returns whether it wrote a new file.
///
/// The check and the write are ONE atomic filesystem operation
/// (`O_CREAT|O_EXCL` via `create_new`), not a separate `exists()` followed
/// by a `write()` — two overlapping `InstallService` calls for the same
/// service (a plausible client retry after a dropped channel, or a
/// double-invoke before a UI disables its button) would otherwise both
/// observe "absent", both generate DIFFERENT random secrets, and race on
/// which one's `write` lands last — leaving a persisted secret that does
/// not match the one the LOSING call's own `configure_adguard` POSTs to
/// AdGuard's install API, a lockout indistinguishable from a corrupted
/// install. With `create_new`, only one call's create can ever succeed;
/// the other sees `AlreadyExists` and treats that exactly like "absent
/// found existing on entry" — it did not write, so it returns `false`.
fn write_env_if_absent(dir: &Path, template: &str) -> io::Result<bool> {
    use std::io::Write;
    let env_path = dir.join(".env");
    let mut file = match std::fs::OpenOptions::new().write(true).create_new(true).open(&env_path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(err) => return Err(err),
    };
    // Mode spelled out, not left to the umask — `.env` carries the admin
    // secret from the moment it exists, same reasoning `composeSetup`'s own
    // `chmod 600` comment states. Set BEFORE the secret is written, so
    // there is no window where the plaintext sits in a file world- or
    // group-readable.
    set_mode(&env_path, 0o600)?;
    let expanded = expand_random(template)?;
    file.write_all(expanded.as_bytes())?;
    Ok(true)
}

/// `grep '^KEY=' path | cut -d= -f2-` — the exact shape every report step
/// and the AdGuard configure call already read the generated secret with.
fn read_env_value(env_path: &Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(env_path).ok()?;
    let prefix = format!("{key}=");
    text.lines().find_map(|line| line.strip_prefix(prefix.as_str()).map(str::to_string))
}

// ─────────────────────────── DoH key patch ───────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohSpelling {
    /// v0.107.74+: `http.doh.insecure_enabled`.
    InsecureEnabled,
    /// Pre-v0.107.74: `tls.allow_unencrypted_doh`.
    AllowUnencryptedDoh,
}

impl DohSpelling {
    fn key(self) -> &'static str {
        match self {
            DohSpelling::InsecureEnabled => "insecure_enabled",
            DohSpelling::AllowUnencryptedDoh => "allow_unencrypted_doh",
        }
    }
}

/// A port of the grep/sed pair in `AdGuardHomeService.setupSteps`: try the
/// NEW key name, fall back to the OLD one, and say which (if either) was
/// found — the key moved between AdGuard versions, and a silently missing
/// setting means DoH clients get a 404 with nothing to explain it.
///
/// Matches `sed`'s own anchoring exactly: only a line that is, after leading
/// spaces, EXACTLY `<key>: false` (nothing else on the line) is flipped to
/// `true`. A key present but already `true`, or spelled with anything else
/// on the line, is left untouched — same as the bash version, which cannot
/// explain that case either: `grep` already found the key, so the "neither
/// spelling present" log line does not apply.
pub fn patch_doh_insecure(yaml: &str) -> (String, Option<DohSpelling>) {
    for spelling in [DohSpelling::InsecureEnabled, DohSpelling::AllowUnencryptedDoh] {
        let key = spelling.key();
        let prefix = format!("{key}:");
        if !yaml.lines().any(|line| line.trim_start().starts_with(prefix.as_str())) {
            continue;
        }
        let target = format!("{key}: false");
        let replacement = format!("{key}: true");
        let patched: Vec<String> = yaml
            .lines()
            .map(|line| {
                let indent_len = line.len() - line.trim_start().len();
                if &line[indent_len..] == target {
                    format!("{}{replacement}", &line[..indent_len])
                } else {
                    line.to_string()
                }
            })
            .collect();
        let mut joined = patched.join("\n");
        if yaml.ends_with('\n') {
            joined.push('\n');
        }
        return (joined, Some(spelling));
    }
    (yaml.to_string(), None)
}

// ─────────────────────────── language ───────────────────────────

/// A BCP-47-ish code (the app's own `AppLanguage` raw values) → the crate's
/// `Language` enum, reused from `dns_records` rather than duplicated a
/// third time. Unrecognized or empty codes fall back to English — see
/// `InstallServiceRequest.language`'s own doc for why this is a cosmetic
/// default, not a validated enum.
fn language_from_code(code: &str) -> Language {
    match code {
        "de" => Language::De,
        "fr" => Language::Fr,
        "es" => Language::Es,
        "ru" => Language::Ru,
        "uk" => Language::Uk,
        "it" => Language::It,
        "ja" => Language::Ja,
        "zh" => Language::Zh,
        _ => Language::En,
    }
}

// ─────────────────────────── gate + request shaping ───────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Not a service in the agent's catalog at all — the same gate every
    /// other RPC in this crate applies.
    UnknownService(String),
    /// A real catalog id, just not one this build's executor covers yet.
    NotImplemented(String),
    /// The container engine itself could not be queried before anything was
    /// touched — mirrors `control::engine_unreachable`'s pre-stream check.
    DockerUnavailable(String),
    /// The request is missing something the executor cannot proceed without
    /// (today: an empty domain). Not a catalog-id problem, so it gets its
    /// own variant rather than overloading `UnknownService`.
    InvalidRequest(String),
    /// This host has no Caddy — see [`caddy_is_installed`].
    NoReverseProxy,
    /// Something on this host already holds a port this install would publish,
    /// and it is not one of our own containers — see `install::ports`.
    PortsInUse(Vec<ports::Conflict>),
    /// This very service is already on the host, and this product did not put
    /// it there.
    AlreadyInstalledOutside { service: String, holder: String },
    /// The request asks for a service whose image refuses to start until a
    /// licence is accepted, and the request does not accept it — see
    /// [`licence_not_accepted`]. Carries the edition's display label.
    LicenceNotAccepted(&'static str),
    /// Names this service would ask Caddy for that another block already
    /// serves — see [`site_name_conflicts`].
    SiteNameTaken(Vec<String>),
    /// This host is already installing this service. Carries the job id, so the
    /// client's answer is to WATCH that run rather than to try again later —
    /// the case this exists for is a client that closed the app and came back,
    /// and telling it "busy" without the name would leave it no way in.
    InstallAlreadyRunning(String),
    /// No run by that name on this host. Either the id was never ours, or the
    /// journal has since been pruned — the client's answer is the same either
    /// way (ask `ListJobs` what this host actually has), so the two are
    /// not distinguished.
    UnknownJob(String),
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::UnknownService(id) => {
                (StatusCode::BAD_REQUEST, "invalid_argument", format!("unknown service '{}'", truncate(id)))
            }
            Rejection::NotImplemented(id) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!("this agent build has no installer for '{}' yet", truncate(id)),
            ),
            Rejection::DockerUnavailable(detail) => {
                (StatusCode::SERVICE_UNAVAILABLE, "unavailable", format!("container engine unavailable: {detail}"))
            }
            Rejection::InvalidRequest(detail) => (StatusCode::BAD_REQUEST, "invalid_argument", detail.clone()),
            Rejection::NoReverseProxy => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                "this host has no Caddy and the agent cannot install one here — every \
                 service is published through it, and automatic installation needs \
                 apt-get and systemd-run. Install Caddy by hand, or run the server \
                 setup on this machine, then install again"
                    .to_string(),
            ),
            Rejection::PortsInUse(conflicts) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "this host cannot publish every port this service needs: {}. \
                     Docker would fail with 'address already in use' partway through \
                     the install. Choose different ports for this service, or stop \
                     what holds them, then install again",
                    conflicts.iter().map(ports::Conflict::describe).collect::<Vec<_>>().join("; ")
                ),
            ),
            // **We do not adopt an install we did not make** (owner,
            // 2026-09-08: "если агент найдёт на сервере уже что-то из нашего
            // списка… чинить это всё, наследовать — это очень много ненужной
            // работы"). Taking over somebody else's copy means owning its
            // layout, its version, its data directory and its upgrade path
            // forever, and every one of those is a guess. So the refusal names
            // what is there and says the one thing that leads somewhere.
            Rejection::AlreadyInstalledOutside { service, holder } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "{service} is already installed on this host — {holder} is answering on \
                     the port it uses, and gryonixNexus did not install it. This app does not \
                     take over an install it did not make. To manage it from here: back its \
                     data up, remove it on the machine, and install it again from the app. \
                     Nothing has been changed"
                ),
            ),
            Rejection::SiteNameTaken(names) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "{} is already served by another service on this host. Caddy refuses a \
                     configuration that names one host twice, which would take HTTPS off every \
                     service on this machine, so nothing has been installed — give this service a \
                     name of its own",
                    names.join(", ")
                ),
            ),
            Rejection::LicenceNotAccepted(edition) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "{edition} will not be installed: Mojang's EULA is not accepted.                      The image refuses to start without it, so installing anyway would                      leave a container restarting forever on this host — which reads as                      a broken image rather than an unanswered question. Accept the                      licence in the app, then install again"
                ),
            ),
            Rejection::InstallAlreadyRunning(job) => (
                StatusCode::CONFLICT,
                "already_exists",
                format!("this host is already installing this service (job {job})"),
            ),
            Rejection::UnknownJob(job) => (
                StatusCode::NOT_FOUND,
                "not_found",
                format!("this host has no record of install job '{}'", truncate(job)),
            ),
        }
    }

    fn response(&self) -> Resp {
        let (status, code, message) = self.parts();
        connect_error(status, code, &message)
    }
}

/// Resolve a client id to the executor's own label, or say exactly why not.
/// Nothing has been touched on the host when this returns an error. Pure —
/// no docker call here, that is `run_install`'s separate pre-stream check —
/// so the id gate is fully testable without a container engine at all.
/// The first domain that appears twice across the primary and the extras, if
/// any. Case-insensitive, because DNS is: `Example.com` and `example.com` are
/// one name to Caddy and would collide exactly the same way.
fn first_repeated_domain(primary: &str, extras: &[String]) -> Option<String> {
    let mut seen: Vec<String> = vec![primary.trim().to_ascii_lowercase()];
    for extra in extras {
        let candidate = extra.trim().to_ascii_lowercase();
        if candidate.is_empty() {
            continue;
        }
        if seen.contains(&candidate) {
            return Some(extra.trim().to_string());
        }
        seen.push(candidate);
    }
    None
}

/// Services whose image refuses to start until a licence is accepted, and
/// whether this request accepts it.
///
/// **A gate, not a line in the report.** The itzg images read `EULA` and quit
/// when it is not `TRUE`, so an install that proceeds anyway does the whole
/// job — directories, compose file, image pull, `up -d` — and leaves a
/// container restarting forever. That reads as a broken image rather than as
/// an unanswered question, which is the same failure `SSL_TYPE=manual` without
/// a certificate once cost docker-mailserver.
///
/// The Swift validator refuses to generate this case before it writes
/// anything (`MailInputValidator`), and the form says so on itself — "without
/// this the server will not start, so it will not be installed". The agent
/// route had no equivalent, so the promise held on one path and broke on the
/// other; a client-side rule is not the agent's refusal, as a raw RPC to a
/// relay once proved on a live host.
fn licence_not_accepted(label: &str, input: &Input) -> Option<&'static str> {
    match label {
        "minecraft-java" if !input.minecraft_java_accepts_eula => Some("Minecraft (Java)"),
        "minecraft-bedrock" if !input.minecraft_bedrock_accepts_eula => Some("Minecraft (Bedrock)"),
        _ => None,
    }
}

pub fn resolve(service_id: &str) -> Result<&'static str, Rejection> {
    let label =
        discover::known_service_id(service_id).ok_or_else(|| Rejection::UnknownService(service_id.to_string()))?;
    if !IMPLEMENTED_SERVICE_IDS.contains(&label) {
        return Err(Rejection::NotImplemented(service_id.to_string()));
    }
    Ok(label)
}

/// The compose project each implemented service installs under — the same
/// literal its own module already carries (and the same one `discover` sees
/// through `docker compose ls`), never a name derived from the id.
fn compose_project(label: &str) -> &'static str {
    match label {
        "docker-mailserver" => dms::COMPOSE_PROJECT,
        "forgejo" => forgejo::COMPOSE_PROJECT,
        "gitlab" => gitlab::COMPOSE_PROJECT,
        "immich" => immich::COMPOSE_PROJECT,
        "mailcow" => mailcow::COMPOSE_PROJECT,
        "mailu" => mailu::COMPOSE_PROJECT,
        "nextcloud" => nextcloud::COMPOSE_PROJECT,
        "jellyfin" => jellyfin::COMPOSE_PROJECT,
        "ollama" => ollama::COMPOSE_PROJECT,
        "open-webui" => open_webui::COMPOSE_PROJECT,
        "litellm" => litellm::COMPOSE_PROJECT,
        "n8n" => n8n::COMPOSE_PROJECT,
        "anythingllm" => anythingllm::COMPOSE_PROJECT,
        "qdrant" => qdrant::COMPOSE_PROJECT,
        "searxng" => searxng::COMPOSE_PROJECT,
        "openclaw" => openclaw::COMPOSE_PROJECT,
        "minecraft-java" => minecraft::JAVA_COMPOSE_PROJECT,
        "minecraft-bedrock" => minecraft::BEDROCK_COMPOSE_PROJECT,
        "crafty-controller" => crafty::COMPOSE_PROJECT,
        "passbolt" => passbolt::COMPOSE_PROJECT,
        "photoprism" => photoprism::COMPOSE_PROJECT,
        "psono" => psono::COMPOSE_PROJECT,
        "seafile" => seafile::COMPOSE_PROJECT,
        "vaultwarden" => vaultwarden::COMPOSE_PROJECT,
        // The panel's project. Plain WireGuard has no project of its own — it
        // runs inside the panel's container — so the VPN as a whole installs
        // under this one name.
        "vpn" => panel::COMPOSE_PROJECT,
        "pihole" => pihole::COMPOSE_PROJECT,
        "homepage" => homepage::COMPOSE_PROJECT,
        "authelia" => authelia::COMPOSE_PROJECT,
        // Same fall-through hazard as the install dispatch — see its comment.
        _ => adguard::COMPOSE_PROJECT,
    }
}

/// Build the declarative `Input` this service's port already knows how to
/// render, straight off the wire. The only validation performed here is
/// "does the executor have enough to proceed at all" — format validation of
/// the domain/hostname (what `Domain`/`MailInputValidator` do on the Swift
/// side) is the caller's job: the request arrives over the paired SSH
/// tunnel from the same app that already validates these fields before
/// generating anything, the same trust boundary `RunBackupRequest.passphrase`
/// already relies on without a second validator here.
/// Services that cannot work without a public name: the three mail engines,
/// which need an address the internet can deliver to, and headscale, whose
/// whole point is being reachable from outside. Named by id rather than derived
/// — this crate has no `ManagedService`, and the Swift twin is
/// `requiresPublicDomain`, which is pinned by its own tests on that side.
const REQUIRES_PUBLIC_DOMAIN: [&str; 4] =
    ["mailcow", "mailu", "docker-mailserver", "headscale"];

/// The same ceiling `MailInputValidator.maxAdditionalDomains` applies.
const MAX_ADDITIONAL_DOMAINS: usize = 9;

fn build_input(req: &pb::InstallServiceRequest) -> Result<Input, String> {
    if req.domain.trim().is_empty() {
        return Err("domain is required".to_string());
    }
    // **A repeated name is not this deployment's problem, it is the HOST's.**
    // A site block is written as `<names> { … }` and the mirrors come straight
    // from this list (`Input::mirrored_hostnames`), so one duplicate produces a
    // site header naming the same host twice — and Caddy then refuses to load
    // the WHOLE file. That is every service on the machine losing HTTPS at the
    // next reload, not one service failing to install, which is why this is
    // refused here rather than left to the caller like the format checks above.
    if let Some(repeated) = first_repeated_domain(&req.domain, &req.additional_domains) {
        return Err(format!(
            "'{}' is listed twice among this deployment's domains. Caddy refuses to load a site              that names the same host twice, which would take HTTPS off every service on this              machine, so nothing was changed",
            truncate(&repeated)
        ));
    }
    // **A service that needs a public name cannot have one here.** Local-only
    // deployments have no public domain to run ACME or accept inbound mail
    // against, so a mail engine or headscale installed under it comes up as a
    // container that can never do its job — the exact "looks broken rather than
    // fails" outcome this project judges refusals by. The Swift validator has
    // always refused it; the agent took the flag and installed anyway.
    if req.local_only && REQUIRES_PUBLIC_DOMAIN.contains(&req.service_id.as_str()) {
        return Err(format!(
            "{} needs a public domain: it has to obtain a certificate and be reached from \
             outside, and a local-only deployment has no public name to do either with. \
             Nothing was changed",
            discover::known_service(&req.service_id).unwrap_or(&req.service_id)
        ));
    }
    // The same ceiling the app's own validator applies. Every extra domain is
    // another site on every web service and another certificate to obtain, and
    // a run that fails ACME on ten names at once burns the deployment's failure
    // quota rather than one name's.
    if req.additional_domains.len() > MAX_ADDITIONAL_DOMAINS {
        return Err(format!(
            "at most {MAX_ADDITIONAL_DOMAINS} additional domains are supported, and this \
             request carries {}. Nothing was changed",
            req.additional_domains.len()
        ));
    }
    let defaults = Input::default();
    let setting = |key: &str, fallback: &str| -> String {
        req.settings
            .get(key)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| fallback.to_string())
    };

    let adguard_path = setting("adguard_path", &defaults.adguard_path);
    let pihole_path = setting("pihole_path", &defaults.pihole_path);
    let homepage_path = setting("homepage_path", &defaults.homepage_path);
    let authelia_path = setting("authelia_path", &defaults.authelia_path);
    let headscale_path = setting("headscale_path", &defaults.headscale_path);
    let tailscale_node_path = setting("tailscale_node_path", &defaults.tailscale_node_path);
    let cloudflared_path = setting("cloudflared_path", &defaults.cloudflared_path);
    let vaultwarden_data_path = setting("vaultwarden_data_path", &defaults.vaultwarden_data_path);
    let jellyfin_path = setting("jellyfin_path", &defaults.jellyfin_path);
    let jellyfin_media_path = setting("jellyfin_media_path", &defaults.jellyfin_media_path);
    let minecraft_java_path = setting("minecraft_java_path", &defaults.minecraft_java_path);
    let minecraft_bedrock_path = setting("minecraft_bedrock_path", &defaults.minecraft_bedrock_path);
    let crafty_path = setting("crafty_path", &defaults.crafty_path);
    let ollama_path = setting("ollama_path", &defaults.ollama_path);
    let open_webui_path = setting("open_webui_path", &defaults.open_webui_path);
    let litellm_path = setting("litellm_path", &defaults.litellm_path);
    let n8n_path = setting("n8n_path", &defaults.n8n_path);
    let anythingllm_path = setting("anythingllm_path", &defaults.anythingllm_path);
    let qdrant_path = setting("qdrant_path", &defaults.qdrant_path);
    let searxng_path = setting("searxng_path", &defaults.searxng_path);
    let openclaw_path = setting("openclaw_path", &defaults.openclaw_path);
    let photoprism_path = setting("photoprism_path", &defaults.photoprism_path);
    let immich_path = setting("immich_path", &defaults.immich_path);
    let nextcloud_path = setting("nextcloud_path", &defaults.nextcloud_path);
    let forgejo_path = setting("forgejo_path", &defaults.forgejo_path);
    let gitlab_path = setting("gitlab_path", &defaults.gitlab_path);
    let seafile_path = setting("seafile_path", &defaults.seafile_path);
    let psono_path = setting("psono_path", &defaults.psono_path);
    let passbolt_path = setting("passbolt_path", &defaults.passbolt_path);
    // The panel MOUNTS all four protocol directories and mailcow's whether or
    // not those services exist, so every one of them is a bind-mount source
    // docker would materialise — and therefore a path worth gating even on an
    // install that names no protocol at all.
    let amnezia_wg_path = setting("amnezia_wg_path", &defaults.amnezia_wg_path);
    let shadowsocks_path = setting("shadowsocks_path", &defaults.shadowsocks_path);
    let xray_reality_path = setting("xray_reality_path", &defaults.xray_reality_path);
    let openvpn_path = setting("openvpn_path", &defaults.openvpn_path);
    let mailcow_path = setting("mailcow_path", &defaults.mailcow_path);
    let docker_mailserver_path = setting("docker_mailserver_path", &defaults.docker_mailserver_path);
    let mailu_path = setting("mailu_path", &defaults.mailu_path);
    // Unlike every other field on this request, these become filesystem
    // write targets: the executor does `create_dir_all` and, for the
    // service's own directories, an unconditional `chmod 0755` even on a
    // pre-existing one. A relative path or one riding a `..` component out
    // of wherever it was meant to land is cheap to catch here and expensive
    // to discover after it has already re-permissioned or written into the
    // wrong place. Checked for EVERY path-shaped setting, not just the one
    // whose service the request happens to name — a request is free to
    // carry all of them, and a gate that only covers the named service is a
    // gate that stops working the day the dispatch changes.
    for (key, value) in [
        ("adguard_path", &adguard_path),
        ("pihole_path", &pihole_path),
        ("homepage_path", &homepage_path),
        ("authelia_path", &authelia_path),
        ("headscale_path", &headscale_path),
        ("tailscale_node_path", &tailscale_node_path),
        ("cloudflared_path", &cloudflared_path),
        ("vaultwarden_data_path", &vaultwarden_data_path),
        ("jellyfin_path", &jellyfin_path),
        ("jellyfin_media_path", &jellyfin_media_path),
        ("minecraft_java_path", &minecraft_java_path),
        ("minecraft_bedrock_path", &minecraft_bedrock_path),
        ("crafty_path", &crafty_path),
        ("ollama_path", &ollama_path),
        ("open_webui_path", &open_webui_path),
        ("litellm_path", &litellm_path),
        ("n8n_path", &n8n_path),
        ("anythingllm_path", &anythingllm_path),
        ("qdrant_path", &qdrant_path),
        ("searxng_path", &searxng_path),
        ("openclaw_path", &openclaw_path),
        ("photoprism_path", &photoprism_path),
        ("immich_path", &immich_path),
        ("nextcloud_path", &nextcloud_path),
        ("forgejo_path", &forgejo_path),
        ("gitlab_path", &gitlab_path),
        ("seafile_path", &seafile_path),
        ("psono_path", &psono_path),
        ("passbolt_path", &passbolt_path),
        ("amnezia_wg_path", &amnezia_wg_path),
        ("shadowsocks_path", &shadowsocks_path),
        ("xray_reality_path", &xray_reality_path),
        ("openvpn_path", &openvpn_path),
        ("mailcow_path", &mailcow_path),
        ("docker_mailserver_path", &docker_mailserver_path),
        ("mailu_path", &mailu_path),
    ] {
        if !is_safe_absolute_path(value) {
            return Err(format!("{key} must be an absolute path with no '..' components: {}", truncate(value)));
        }
    }

    Ok(Input {
        domain: req.domain.clone(),
        additional_domains: req.additional_domains.clone(),
        language: language_from_code(&req.language),
        local_only: req.local_only,
        // Filled in by the caller, which is the only place that can ask the
        // host what it already carries — this function is synchronous and
        // takes nothing but the request. Empty until then, which reads as
        // "nothing else here" and yields the plain names.
        installed_services: Vec::new(),
        // **Empty means "use the default", exactly as every `settings` key does.**
        // Taking this one raw broke a live host: the VPN panel creates its
        // superadmin from `ADMIN_USER` in its `.env`, so an empty value gave the
        // panel an account with an EMPTY username while the install report
        // printed "Administrator: admin" — the credentials the owner is handed
        // did not exist (measured on lab-vps 2026-08-13). The rule was already
        // written down for the settings map (ARCHITECTURE.md: absent settings
        // take the Swift `ServiceSettings` default); this field simply was not
        // following it.
        admin_username: match req.admin_username.trim() {
            "" => defaults.admin_username.clone(),
            named => named.to_string(),
        },
        adguard_path,
        adguard_hostname: req.settings.get("adguard_hostname").cloned().unwrap_or_default(),
        authelia_path,
        authelia_hostname: req.settings.get("authelia_hostname").cloned().unwrap_or_default(),
        // Comma-separated, like every other list on this map. **Presence of
        // the KEY is the answer, not whether its value is empty** — those are
        // two different statements and conflating them was a live defect: a
        // person who unticked every service sent the key with an empty value,
        // the agent read that as "the app said nothing", and the default set
        // came back. Unticking everything has to mean everything.
        //
        // An absent key is an older app that has never heard of this setting;
        // that one takes the default.
        authelia_protected: match req.settings.get("authelia_protected_services") {
            Some(value) => AutheliaProtection::Explicit(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(str::to_string)
                    .collect(),
            ),
            None => AutheliaProtection::Default,
        },
        homepage_path,
        homepage_hostname: req.settings.get("homepage_hostname").cloned().unwrap_or_default(),
        pihole_path,
        pihole_hostname: req.settings.get("pihole_hostname").cloned().unwrap_or_default(),
        pihole_upstreams: match req.settings.get("pihole_upstreams").map(|s| s.trim()) {
            Some(value) if !value.is_empty() => value.to_string(),
            // Same rule as every other absent setting: the Swift default, not
            // an empty string. An empty `FTLCONF_dns_upstreams` leaves the
            // resolver with nowhere to forward, which reads as "the filter
            // blocks everything".
            _ => defaults.pihole_upstreams.clone(),
        },
        // A bool over the wire is a string, and ANY value other than "true"
        // reads as false — the direction that matters, because the false half
        // is the one that keeps this off the public internet.
        pihole_serves_network: req
            .settings
            .get("pihole_serves_network")
            .map(|value| value.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(defaults.pihole_serves_network),
        headscale_path,
        headscale_hostname: req.settings.get("headscale_hostname").cloned().unwrap_or_default(),
        headscale_base_domain: req.settings.get("headscale_base_domain").cloned().unwrap_or_default(),
        tailscale_node_path,
        tailscale_node_name: req.settings.get("tailscale_node_name").cloned().unwrap_or_default(),
        tailscale_login_server: req.settings.get("tailscale_login_server").cloned().unwrap_or_default(),
        tailscale_auth_key: req.settings.get("tailscale_auth_key").cloned().unwrap_or_default(),
        cloudflared_path,
        cloudflared_token: req.settings.get("cloudflared_token").cloned().unwrap_or_default(),
        vaultwarden_hostname: req.settings.get("vaultwarden_hostname").cloned().unwrap_or_default(),
        vaultwarden_container: setting("vaultwarden_container", &defaults.vaultwarden_container),
        vaultwarden_data_path,
        // Absent means the app never sent the toggle; the default has to be
        // the SAME "true" Swift's `ServiceSettings` carries, or an install
        // through the agent would quietly close registrations an install
        // through SSH leaves open. Anything other than an explicit "false"
        // reads as true, matching how the setting is spelled on the wire.
        vaultwarden_allow_signups: req
            .settings
            .get("vaultwarden_allow_signups")
            .map(|value| value.trim() != "false")
            .unwrap_or(defaults.vaultwarden_allow_signups),
        jellyfin_hostname: req.settings.get("jellyfin_hostname").cloned().unwrap_or_default(),
        jellyfin_path,
        jellyfin_media_path,
        minecraft_java_path,
        minecraft_java_version: req.settings.get("minecraft_java_version").cloned().unwrap_or_default(),
        minecraft_java_flavour: match req.settings.get("minecraft_java_flavour").map(|v| v.trim()) {
            Some(value) if !value.is_empty() => value.to_string(),
            _ => defaults.minecraft_java_flavour.clone(),
        },
        minecraft_java_memory_mb: req
            .settings
            .get("minecraft_java_memory_mb")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(defaults.minecraft_java_memory_mb),
        minecraft_java_port: req
            .settings
            .get("minecraft_java_port")
            .and_then(|value| value.trim().parse::<u16>().ok())
            .unwrap_or(defaults.minecraft_java_port),
        // A missing key is NOT acceptance. The one setting here where the
        // default has to be the refusing one: an install that assumed the
        // licence was accepted would put a container on the host that exits on
        // every start.
        minecraft_java_accepts_eula: req
            .settings
            .get("minecraft_java_accepts_eula")
            .map(|value| value.trim() == "true")
            .unwrap_or(defaults.minecraft_java_accepts_eula),
        minecraft_java_whitelist: req.settings.get("minecraft_java_whitelist").cloned().unwrap_or_default(),
        minecraft_java_operators: req.settings.get("minecraft_java_operators").cloned().unwrap_or_default(),
        minecraft_java_mods: req.settings.get("minecraft_java_mods").cloned().unwrap_or_default(),
        minecraft_bedrock_path,
        minecraft_bedrock_version: req.settings.get("minecraft_bedrock_version").cloned().unwrap_or_default(),
        minecraft_bedrock_port: req
            .settings
            .get("minecraft_bedrock_port")
            .and_then(|value| value.trim().parse::<u16>().ok())
            .unwrap_or(defaults.minecraft_bedrock_port),
        minecraft_bedrock_accepts_eula: req
            .settings
            .get("minecraft_bedrock_accepts_eula")
            .map(|value| value.trim() == "true")
            .unwrap_or(defaults.minecraft_bedrock_accepts_eula),
        crafty_path,
        crafty_hostname: req.settings.get("crafty_hostname").cloned().unwrap_or_default(),
        ollama_path,
        // Unparsable or absent keeps Swift's default (false), the same rule the
        // signup flag beside it follows.
        ollama_uses_gpu: req
            .settings
            .get("ollama_uses_gpu")
            .map(|value| value.trim() == "true")
            .unwrap_or(defaults.ollama_uses_gpu),
        open_webui_path,
        open_webui_hostname: req.settings.get("open_webui_hostname").cloned().unwrap_or_default(),
        // Absent means the default, which is OPEN — and it has to be: the
        // first account created in the chat becomes the administrator, so an
        // older app that never sends this key must not end up with a service
        // nobody can log in to.
        open_webui_allow_signups: req
            .settings
            .get("open_webui_allow_signups")
            .map(|value| value.trim() != "false")
            .unwrap_or(defaults.open_webui_allow_signups),
        litellm_path,
        litellm_hostname: req.settings.get("litellm_hostname").cloned().unwrap_or_default(),
        n8n_path,
        n8n_hostname: req.settings.get("n8n_hostname").cloned().unwrap_or_default(),
        anythingllm_path,
        anythingllm_hostname: req
            .settings
            .get("anythingllm_hostname")
            .cloned()
            .unwrap_or_default(),
        qdrant_path,
        searxng_path,
        openclaw_path,
        openclaw_hostname: req.settings.get("openclaw_hostname").cloned().unwrap_or_default(),
        photoprism_hostname: req.settings.get("photoprism_hostname").cloned().unwrap_or_default(),
        photoprism_path,
        immich_hostname: req.settings.get("immich_hostname").cloned().unwrap_or_default(),
        immich_path,
        nextcloud_hostname: req.settings.get("nextcloud_hostname").cloned().unwrap_or_default(),
        nextcloud_path,
        forgejo_hostname: req.settings.get("forgejo_hostname").cloned().unwrap_or_default(),
        forgejo_path,
        // Unparsable or absent keeps Swift's default rather than switching
        // git-over-SSH off: "off" is a deliberate choice (a 0), not what a
        // typo should mean, and silently dropping the published port would
        // leave every existing clone URL pointing at nothing.
        forgejo_ssh_port: req
            .settings
            .get("forgejo_ssh_port")
            .and_then(|value| value.trim().parse::<u16>().ok())
            .unwrap_or(defaults.forgejo_ssh_port),
        gitlab_hostname: req.settings.get("gitlab_hostname").cloned().unwrap_or_default(),
        gitlab_path,
        gitlab_ssh_port: req
            .settings
            .get("gitlab_ssh_port")
            .and_then(|value| value.trim().parse::<u16>().ok())
            .unwrap_or(defaults.gitlab_ssh_port),
        seafile_hostname: req.settings.get("seafile_hostname").cloned().unwrap_or_default(),
        seafile_path,
        psono_hostname: req.settings.get("psono_hostname").cloned().unwrap_or_default(),
        psono_path,
        passbolt_hostname: req.settings.get("passbolt_hostname").cloned().unwrap_or_default(),
        passbolt_path,
        vpn_hostname: req.settings.get("vpn_hostname").cloned().unwrap_or_default(),
        vpn_client_access: req
            .settings
            .get("vpn_client_access")
            .cloned()
            .unwrap_or_else(|| "both".to_string()),
        // Same rule as `forgejo_ssh_port`: an unparsable or absent value keeps
        // Swift's default rather than becoming 0. A VPN protocol has no "off"
        // port — 0 would publish `0:0/udp` and hand out an endpoint nobody can
        // dial, which is worse than the default the app itself shows.
        wireguard_vpn_port: port_setting(req, "wireguard_vpn_port", defaults.wireguard_vpn_port),
        amnezia_wg_path,
        amnezia_wg_port: port_setting(req, "amnezia_wg_port", defaults.amnezia_wg_port),
        shadowsocks_path,
        shadowsocks_port: port_setting(req, "shadowsocks_port", defaults.shadowsocks_port),
        xray_reality_path,
        xray_reality_port: port_setting(req, "xray_reality_port", defaults.xray_reality_port),
        xray_reality_sni: setting("xray_reality_sni", &defaults.xray_reality_sni),
        openvpn_path,
        openvpn_port: port_setting(req, "openvpn_port", defaults.openvpn_port),
        mailcow_path,
        docker_mailserver_path,
        mailu_path,
        // NOT a path — `setting()`, not the gated loop above. See
        // `Input.mailu_subnet`'s own doc for why a mismatch here is the
        // same silent trap as mailcow's `API_ALLOW_FROM`.
        mailu_subnet: setting("mailu_subnet", &defaults.mailu_subnet),
        // Off only on an explicit "false" — absent, or anything else, reads as
        // Swift's default (true), so an app that predates this key still gets
        // CrowdSec rather than silently losing it. See `Input.crowdsec_enabled`.
        crowdsec_enabled: req
            .settings
            .get("crowdsec_enabled")
            .map(|value| value.trim() != "false")
            .unwrap_or(defaults.crowdsec_enabled),
    })
}

/// A port number off the wire, or Swift's default. Zero is rejected the same
/// way an unparsable value is: for a VPN protocol it is not a meaningful
/// "switched off" the way `forgejo_ssh_port` uses it.
fn port_setting(req: &pb::InstallServiceRequest, key: &str, fallback: u16) -> u16 {
    req.settings
        .get(key)
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(fallback)
}

/// Which VPN protocols this install is being asked for, read from the
/// `vpn_protocols` setting (a comma-separated list of catalog ids — the same
/// spelling the app uses for `ServiceID.rawValue`).
///
/// Two refusals, both BEFORE anything is touched:
/// - an id that is not a VPN protocol at all — a client bug;
/// - a real protocol this build has no installer for. The panel would come up
///   ADVERTISING it (its endpoint lands in `services.json`, which is what the
///   SPA renders) while nothing was ever installed to answer on that port, so
///   a refusal naming the protocol is strictly better than a half-installed
///   VPN. The SSH path still installs all five.
///
/// An empty list means WireGuard: the panel is never installed alone on the
/// Swift side (it is injected BECAUSE a protocol was selected), so a request
/// that names none is a client that did not know it had to — and WireGuard is
/// the one protocol the panel itself implements.
fn vpn_protocols_from(req: &pb::InstallServiceRequest) -> Result<Vec<panel::Protocol>, Rejection> {
    const ALL: &[panel::Protocol] = &[
        panel::Protocol::WireGuard,
        panel::Protocol::AmneziaWG,
        panel::Protocol::Shadowsocks,
        panel::Protocol::XrayReality,
        panel::Protocol::OpenVPN,
    ];
    // All five now. The four that срез 4.9 refused each got their own compose
    // project and imperative steps in this slice, so there is no longer a
    // protocol the panel could advertise without something answering on its
    // port — the exact condition that refusal existed to prevent.
    const IMPLEMENTED: &[panel::Protocol] = ALL;

    let raw = req.settings.get("vpn_protocols").map(String::as_str).unwrap_or("");
    let mut chosen: Vec<panel::Protocol> = Vec::new();
    for name in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let protocol = ALL
            .iter()
            .find(|p| p.service_id() == name)
            .ok_or_else(|| Rejection::InvalidRequest(format!("'{}' is not a VPN protocol", truncate(name))))?;
        if !IMPLEMENTED.contains(protocol) {
            return Err(Rejection::NotImplemented(protocol.service_id().to_string()));
        }
        if !chosen.contains(protocol) {
            chosen.push(*protocol);
        }
    }
    if chosen.is_empty() {
        chosen.push(panel::Protocol::WireGuard);
    }
    Ok(chosen)
}

/// Is there a Caddy on this host for the install to publish through?
///
/// Two independent signs, because either one alone is misleading: the
/// configuration directory can exist on a host whose package was removed, and
/// the binary can exist before the package's first run has created the
/// directory. Both are cheap, and the check has to be conservative in the
/// direction of "yes" — refusing an install on a host that HAS Caddy would be
/// worse than the failure it prevents.
/// Is Caddy itself on this host?
///
/// **The BINARY, never the directory.** `/etc/caddy` used to count as proof,
/// and it stopped being proof the day bootstrap started creating it on every
/// host — it has to, because the sandbox hole for it is punched once at unit
/// start and a directory the Caddy package creates later would be read-only
/// (see `install/packages.rs`). A check that accepts the directory would now
/// pass everywhere and refuse nothing.
fn caddy_is_installed() -> bool {
    packages::have_binary("caddy")
        || ["/usr/bin/caddy", "/usr/local/bin/caddy", "/usr/sbin/caddy"]
            .iter()
            .any(|path| Path::new(path).exists())
}

/// Can this host install its own packages? Both tools are needed: `apt-get` is
/// the only package manager the agent knows, and `systemd-run` is how it
/// escapes its own sandbox to use it.
fn can_install_packages() -> bool {
    packages::have_binary("apt-get") && packages::have_binary("systemd-run")
}



/// Every port this install would publish on the host's public address.
///
/// **The list is the services' own declarations, never re-derived here** — the
/// same `firewall_ports()`/`ssh_port()` functions the install already uses to
/// write its nftables drop-in and its compose file. A second opinion about
/// which ports a service needs is a second place to be wrong.
///
/// Loopback publishes (every service's web port, `127.0.0.1:8082` and friends)
/// are deliberately out of scope: they are per-service constants the catalog
/// keeps distinct, and each one is already a `preferOne`/`exclusive` decision on
/// the client. What actually collided on a live host was a PUBLIC port, twice —
/// a leftover relay tunnel against the VPN's, and two mail engines against each
/// other's 25/143/993.
/// Every host mapping this install will publish, read out of the very compose
/// bodies the executor is about to write.
///
/// **The compose text is the source of truth, not a second list.** A hand-kept
/// table of "ports this service takes" is right only until somebody edits a
/// compose body, and the drift is invisible — the file publishes one port, the
/// table names another, and the pre-flight clears a port nothing ever wanted.
///
/// `published_public_ports` is still added on top, and it is not redundant:
/// mailcow generates its own compose ON THE HOST, so there is nothing here to
/// read for it, and its mail ports are the ones that keep a second mail stack
/// from being installed over it. Duplicates cost nothing — `conflicts`
/// de-duplicates on the mapping.
fn published_ports_of(label: &str, input: &Input, protocols: &[panel::Protocol]) -> Vec<ports::Wanted> {
    let mut wanted: Vec<ports::Wanted> =
        compose_text_of(label, input).map(|text| ports::published_in_compose(&text)).unwrap_or_default();
    wanted.extend(published_public_ports(label, input, protocols).into_iter().map(ports::Wanted::any));
    wanted
}

/// The compose body this label installs under, exactly as the executor writes
/// it. Split out of [`published_ports_of`] so the catalog-wide test can read
/// the same text the pre-flight reads.
fn compose_text_of(label: &str, input: &Input) -> Option<String> {
    match label {
        "adguard-home" => Some(adguard::compose_contents(input)),
        "pihole" => Some(pihole::compose_contents(input)),
        "homepage" => Some(homepage::compose_contents(input)),
        "authelia" => Some(authelia::compose_contents(input)),
        "cloudflared" => Some(cloudflared::compose_contents(input)),
        "tailscale-node" => Some(tailscale::compose_contents(input)),
        "headscale" => Some(headscale::compose_contents(input)),
        "docker-mailserver" => Some(dms::compose_contents(input)),
        "forgejo" => Some(forgejo::compose_contents(input)),
        "gitlab" => Some(gitlab::compose_contents(input)),
        "immich" => Some(immich::compose_contents(input)),
        "jellyfin" => Some(jellyfin::compose_contents(input)),
        "ollama" => Some(ollama::compose_contents(input)),
        // `open-webui` and `litellm` are NOT here: both of their files are a
        // function of the host's OTHER services (the engine URL, the gateway
        // route), and this table is handed only the input. Their own steps
        // write them, with the service list — the same reason `homepage` has
        // no entry either.
        "minecraft-java" => Some(minecraft::java_compose_contents(input)),
        "minecraft-bedrock" => Some(minecraft::bedrock_compose_contents(input)),
        "crafty-controller" => Some(crafty::compose_contents(input)),
        "mailu" => Some(mailu::compose_contents(input)),
        "nextcloud" => Some(nextcloud::compose_contents(input)),
        "passbolt" => Some(passbolt::compose_contents(input)),
        "photoprism" => Some(photoprism::compose_contents(input)),
        "psono" => Some(psono::compose_contents(input)),
        "seafile" => Some(seafile::compose_contents(input)),
        "vaultwarden" => Some(vaultwarden::compose_contents(input)),
        // The protocols share the panel's compose file; their own public ports
        // arrive through `published_public_ports` below.
        "vpn" => Some(panel::compose_contents(input)),
        // mailcow: `generate_config.sh` writes the compose on the host.
        _ => None,
    }
}

fn published_public_ports(label: &str, input: &Input, protocols: &[panel::Protocol]) -> Vec<firewall::Port> {
    match label {
        "vpn" => protocols.iter().flat_map(|protocol| protocol.firewall_ports(input)).collect(),
        "docker-mailserver" => mail_firewall_ports(&dms::firewall_ports()),
        "mailu" => mail_firewall_ports(&mailu::firewall_ports()),
        "mailcow" => mail_firewall_ports(&mailcow::firewall_ports()),
        // git-over-SSH is published straight onto the host, and 0 means the
        // feature is off — nothing is published and nothing to check.
        "forgejo" => forgejo::ssh_port(input).map(|port| vec![firewall::Port::tcp(port)]).unwrap_or_default(),
        "gitlab" => gitlab::ssh_port(input).map(|port| vec![firewall::Port::tcp(port)]).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// A minimal safety gate on a client-supplied filesystem path before it
/// becomes a `create_dir_all` + `chmod 0755` target: must be absolute, and
/// must not contain a `..` component that could walk it outside the
/// directory the operator actually meant. Not full canonicalization — a
/// symlink already sitting at a component could still redirect it — but it
/// closes the cheap case for free.
fn is_safe_absolute_path(path: &str) -> bool {
    let p = Path::new(path);
    p.is_absolute() && !p.components().any(|c| matches!(c, Component::ParentDir))
}

// ─────────────────────────── RPC entry point ───────────────────────────

/// Install AdGuard Home, streaming progress.
///
/// Errors travel on two channels: a refusal BEFORE anything is touched
/// (unknown id, this build has no installer for it, the container engine is
/// unreachable, the request is missing a domain) is a plain Connect error
/// response and the stream never opens; a failure DURING the run ends the
/// stream with an error trailer, but only after a COMPLETED event carrying
/// the freshly re-read service status — the same two-channel rule every
/// other destructive streamed verb in this crate follows.
pub async fn run_install(codec: Codec, req: pb::InstallServiceRequest,
                        store: Arc<Mutex<Store>>) -> Resp {
    let label = match resolve(&req.service_id) {
        Ok(label) => label,
        Err(rejection) => return rejection.response(),
    };
    // The same probe `control::control_service` uses before it opens ITS
    // stream: `docker compose ls` failing to run at all means the engine is
    // unreachable, and that is a fact worth knowing before anything here
    // starts creating directories nobody can ever finish serving.
    let existing_projects = match discover::projects_of_service(&req.service_id).await {
        Ok(projects) => projects,
        Err(err) => return Rejection::DockerUnavailable(err.to_string()).response(),
    };
    let mut input = match build_input(&req) {
        Ok(input) => input,
        Err(detail) => return Rejection::InvalidRequest(detail).response(),
    };
    // **What else this host carries, asked before anything is written.** A
    // default hostname is a function of the neighbours now
    // (`install::hostnames`): the second photo service on a machine takes
    // `photoprism.<domain>` rather than fighting the first for `photos.`. The
    // union `host_service_ids` returns is the same one the host wrappers are
    // rendered from — what `discover` reports plus what is being installed —
    // so the name a site is written under and the name the wrappers know
    // cannot disagree.
    input.installed_services = host_service_ids(label, &[]).await;
    if !input.installed_services.iter().any(|id| id == &req.service_id) {
        input.installed_services.push(req.service_id.clone());
    }
    let input = input;
    // **Before the stream opens, because the answer cannot change during the
    // run.** An unaccepted licence is not a host problem to be worked around
    // but a request that asks for a container which cannot start; see
    // [`licence_not_accepted`] for what installing it anyway leaves behind.
    if let Some(edition) = licence_not_accepted(label, &input) {
        return Rejection::LicenceNotAccepted(edition).response();
    }
    // **Checked before the stream opens, and it is the last thing an
    // agent-built host is missing.** Every installable service is published
    // through Caddy, and the site is written at the very END of an install —
    // so on a machine that has no Caddy at all the run does fifteen minutes of
    // real work (mailcow clones its repo, pulls twenty images, generates its
    // config, starts) and then dies on `could not create /etc/caddy:
    // Read-only file system`, which names the symptom and not the cause.
    // Measured exactly that way on a bare VM, 2026-08-12.
    //
    // The EROFS is itself a consequence worth stating: the unit lists
    // `-/etc/caddy` optionally, and systemd punches that hole ONCE, when the
    // namespace is built — a directory that did not exist at start stays
    // read-only for the running agent (GOTCHAS.md). So this cannot be fixed by
    // creating the directory afterwards; the honest answer is to refuse early
    // and say which step of the setup is missing.
    if !caddy_is_installed() && !can_install_packages() {
        return Rejection::NoReverseProxy.response();
    }
    // Resolved before the stream opens, so "this build cannot install
    // Shadowsocks" is a refusal rather than a panel that advertises a protocol
    // nothing ever installed.
    let protocols = match vpn_protocols_from(&req) {
        Ok(protocols) => protocols,
        Err(rejection) => return rejection.response(),
    };
    // **Before the stream opens, for the same reason as the Caddy gate above.**
    // A port another process already holds cannot be published, and docker only
    // says so at `up -d` — after directories, secrets and image pulls. Measured
    // on `lab-vps` 2026-08-12: a leftover relay `wg0` on 51820 killed a VPN
    // install that had already done all of that. The Swift validator rejects
    // this case before it generates anything; the agent route had no equivalent.
    // `existing_projects` is what keeps a re-install of a RUNNING service from
    // being refused by its own containers.
    let conflicts = ports::check(&published_ports_of(label, &input, &protocols), &existing_projects).await;
    if !conflicts.is_empty() {
        // **Is the thing holding the port this service itself?** A port taken
        // by a leftover from something else is "stop what holds it"; a port
        // taken by a hand-installed copy of the service being installed is a
        // different answer entirely, and the two are identical in `/proc/net`.
        // Asked only once a conflict exists, so the ordinary install pays
        // nothing for it.
        if let Some(holder) = self_installed_by_hand(&req.service_id, &conflicts).await {
            return Rejection::AlreadyInstalledOutside {
                service: crate::discover::known_service(&req.service_id)
                    .unwrap_or(&req.service_id)
                    .to_string(),
                holder,
            }
            .response();
        }
        return Rejection::PortsInUse(conflicts).response();
    }

    // **The site names, asked BEFORE the stream opens** — found by a live run
    // on 2026-09-04, and the reason the run was worth doing. The check itself
    // existed and worked: a second service asking for a name another block
    // already served was refused. It was refused by `write_caddy_site`, which
    // runs at the END of the install — so Psono was pulled, started, given an
    // administrator and a compose project, and only then told it could not
    // have a web address, under a message that said "nothing was changed". The
    // service was on the host; only its site was missing.
    //
    // Here it costs a file read and answers before anything exists to clean
    // up, exactly like the port preflight above it. The late check STAYS: two
    // installs racing each other can still collide between this and the write,
    // and that one now says what it actually left behind.
    let taken = site_name_conflicts(label, &input);
    if !taken.is_empty() {
        return Rejection::SiteNameTaken(taken).response();
    }

    // **Refused before the stream opens, and only askable now that runs have
    // names.** The whole point of the journal is that a client may leave, so
    // the client that comes BACK and taps Install again is the normal case, not
    // a pathological one — and two concurrent runs of one service would race on
    // the same compose project, the same .env and the same admin bootstrap. The
    // port preflight cannot catch this: it treats a port held by our OWN
    // project as a reinstall, which is exactly what the second run looks like.
    if let Some(job) = journal::running_job_for(&req.service_id) {
        return Rejection::InstallAlreadyRunning(job).response();
    }

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let service_id = req.service_id.clone();
    let host_ctx = HostContext::from_request(&req);
    // Opened HERE rather than inside the spawned task so the id exists before
    // the first event is built: STARTED is the earliest a client could decide
    // to close the app, so it is the event that has to carry the name back.
    let journal = journal::Journal::open(&service_id);

    tokio::spawn(async move {
        install(label, service_id, codec, tx, input, protocols, host_ctx, journal, store).await;
    });

    stream_response(json, rx)
}

/// `Install/WatchInstall` — attach to a run that is already going, or read back
/// one that has ended.
///
/// **One verb for both, because the client cannot know which it is asking
/// for.** By the time a phone is unlocked and the app is open again, the run it
/// started may have finished thirty seconds ago or may have twelve minutes
/// left; a client forced to pick a verb would be racing the host on every
/// reattach. So this replays the journal from where the caller left off and
/// then keeps following it, and simply ends when the run does.
///
/// The COMPLETED event's service snapshot is re-read HERE rather than restored
/// from the journal: a status is only worth anything fresh, and the file
/// deliberately does not store one (see the journal's module doc).
pub async fn run_watch_install(codec: Codec, req: pb::WatchInstallRequest,
                              store: Arc<Mutex<Store>>) -> Resp {
    if !journal::exists(&req.job_id) {
        return Rejection::UnknownJob(req.job_id).response();
    }
    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        follow_install(req.job_id, req.from_sequence, codec, tx, store).await;
    });
    stream_response(json, rx)
}

async fn follow_install(job_id: String, from_sequence: u64, codec: Codec, tx: Sender<Bytes>,
                        store: Arc<Mutex<Store>>) {
    let mut next = from_sequence;
    loop {
        let Some((events, closed, failure)) = journal::events_after(&job_id, next) else {
            // Pruned out from under the follower. Nothing left to say about it.
            return;
        };
        for mut event in events {
            next = event.sequence + 1;
            if event.phase == pb::ServiceOperationPhase::Completed as i32 {
                event.service = read_status(&event.service_id, &store).await;
            }
            let payload = codec.encode_payload(&event);
            if tx.send(envelope(0x00, &payload)).await.is_err() {
                // The watcher hung up too. Same rule as the install itself: not
                // a reason for anything to stop, just a reason to stop talking.
                return;
            }
        }
        if closed {
            // The same two-channel discipline the live stream holds: the failure
            // rides the trailer, AFTER the re-read status has been reported.
            if !failure.is_empty() {
                let _ = tx.send(error_trailer("internal", &failure)).await;
            }
            return;
        }
        if !journal::is_running(&job_id) {
            // An open journal nobody is writing to. Saying nothing here would
            // leave the client following an empty file for ever — the exact
            // shape of "reads as a hung agent" GOTCHAS.md warns about.
            let _ = tx.send(error_trailer(
                "aborted",
                "the agent stopped while this install was running; nothing is known about \
                 what it left behind. Re-running the install is safe — every step decides \
                 for itself whether it has already happened",
            ))
            .await;
            return;
        }
        tokio::time::sleep(journal::follow_poll()).await;
    }
}

// ─────────────────────────── executor ───────────────────────────

pub(crate) struct EventSink {
    tx: Sender<Bytes>,
    codec: Codec,
    service_id: String,
    /// The record this run leaves behind, or `None` when the host could not
    /// open one — see [`journal::Journal::open`] for why that is not fatal.
    journal: Option<journal::Journal>,
    /// Counts what was NARRATED, journal or no journal. A client resumes by
    /// sequence, so the number has to mean the same thing on both sides even on
    /// a host whose disk is full.
    sequence: AtomicU64,
}

impl EventSink {
    /// A sink nobody is listening to, for the host work that is NOT an install.
    ///
    /// **The narration is the price of reaching outside the sandbox, and one
    /// caller does not want it.** `packages::run_outside_sandbox_from_file` is
    /// the only route to PID 1's namespace this crate has, and it streams what
    /// the transient unit prints through a sink; the unary RPCs that reuse it
    /// (`Security/SetSshPasswordLogin` and its read) answer with a state, not
    /// with a stream, so there is no channel for those lines to go to.
    ///
    /// Dropping the receiver rather than draining it is deliberate: every
    /// `send` then fails immediately instead of filling a queue nobody empties,
    /// and every caller of `step`/`process_line` already discards the result —
    /// checked here, not assumed, because a sink that BLOCKED would hang the
    /// install path this type mainly serves.
    pub(crate) fn detached() -> Self {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        EventSink {
            tx,
            codec: Codec::Proto,
            service_id: String::new(),
            journal: None,
            sequence: AtomicU64::new(0),
        }
    }

    /// Build a sink for tests in sibling modules — the fields stay private so
    /// nothing outside this file can invent an event shape.
    #[cfg(test)]
    pub(super) fn for_test(tx: Sender<Bytes>, service_id: &str) -> Self {
        EventSink {
            tx,
            codec: Codec::Proto,
            service_id: service_id.to_string(),
            journal: None,
            sequence: AtomicU64::new(0),
        }
    }

    fn job_id(&self) -> String {
        self.journal
            .as_ref()
            .map(|j| j.job_id().to_string())
            .unwrap_or_default()
    }

    /// Close the record. Called exactly once, on every path out of `install` —
    /// including the failing ones, because "it failed and here is why" is the
    /// answer a returning client most needs and the one an unclosed journal
    /// cannot give: an open journal reads as RUNNING for as long as this
    /// process lives, and ABANDONED after that.
    fn close(&self, failure: Option<&str>) {
        if let Some(journal) = &self.journal {
            journal.finish(failure);
        }
    }

    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::InstallServiceEvent {
        pb::InstallServiceEvent {
            phase: phase as i32,
            service_id: self.service_id.clone(),
            text: String::new(),
            stream: String::new(),
            project: String::new(),
            service: None,
            job_id: self.job_id(),
            // Claimed in `send`, not here: the number counts events that were
            // actually narrated, and an event built but never sent would leave
            // a hole a resuming client would wait for for ever.
            sequence: 0,
        }
    }

    async fn send(&self, mut event: pb::InstallServiceEvent) -> Result<(), ()> {
        event.sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        // **Recorded BEFORE it is sent, and the order is the whole point.** The
        // send is the half that fails when the phone is put away; the append is
        // the half that has to survive exactly then. Doing it the other way
        // round would drop the last line of every run that got closed on.
        if let Some(journal) = &self.journal {
            journal.append(
                event.sequence,
                event.phase,
                &event.stream,
                &event.text,
                &event.project,
            );
        }
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, project: &str) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.project = project.to_string();
        self.send(event).await
    }

    /// A step the agent narrates itself — no child process produced this
    /// line, so `stream` is "agent" rather than "stdout"/"stderr".
    pub(super) async fn step(&self, text: impl Into<String>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = "agent".to_string();
        event.text = text.into();
        self.send(event).await
    }

    /// A `step` the client is meant to surface on the finished screen, not
    /// only leave in the scrollback log — a non-fatal install-step failure
    /// (CrowdSec's repository being unreachable, say) that otherwise reads as
    /// a fully successful run. Same wire shape as `step` (still one text
    /// line in the same `Progress` phase, so an older client that does not
    /// know the "warning" stream still prints it in the log exactly as
    /// before); `stream` is the only thing that marks it out for a client
    /// that does.
    pub(super) async fn warn(&self, text: impl Into<String>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = "warning".to_string();
        event.text = text.into();
        self.send(event).await
    }

    pub(super) async fn process_line(&self, stream: &str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(&self, service: Option<pb::Service>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.service = service;
        self.send(event).await
    }

    /// End the stream with a Connect error trailer. Always sent AFTER
    /// `completed` — never instead of it: a streamed operation carries no
    /// exit status of its own, so the freshly re-read state is the first
    /// thing worth reporting even when the run failed.
    async fn fail(&self, message: &str) -> Result<(), ()> {
        self.tx.send(error_trailer("internal", message)).await.map_err(|_| ())
    }
}

/// Re-read one service from the host AND record what was read.
///
/// **Both halves in one function on purpose** (2026-09-04). Every place an
/// install reports a status is a place that has just changed what the host has,
/// and until now none of them told the agent's own store: only `Discover` and
/// the start/stop/restart buttons ever wrote there, so a freshly installed
/// service was missing from `GetState` until somebody asked for a scan. Twelve
/// services running, ten reported, measured on a live host 2026-08-26. Writing
/// it at the three call sites instead would be three places to forget it, and
/// the third would be the one nobody updates.
///
/// **Three answers, not two.** `Ok(Some)` is "the host has it", `Ok(None)` is
/// "the host does not" — and both are recorded, the second by removing the row.
/// `Err` is "could not ask", and records NOTHING: a docker query that failed
/// must never erase a service that is running. The stream is told the same
/// thing either way (`None`), because a status it could not read and a service
/// that is not there both leave it with nothing to show.
async fn read_status(service_id: &str, store: &Arc<Mutex<Store>>) -> Option<pb::Service> {
    let read = discover::service_snapshot(service_id).await;
    let snapshot = match read {
        Ok(snapshot) => snapshot,
        Err(err) => {
            tracing::warn!(?err, service_id, "could not re-read status; state left as it was");
            return None;
        }
    };
    // Best effort, exactly as in `control_service`: a state write that fails
    // must not turn a successful install into a reported failure. What the
    // client was handed is the authority either way.
    if let Ok(store) = store.lock() {
        if let Err(err) = store.record_action(service_id, snapshot.as_ref()) {
            tracing::warn!(?err, service_id, "could not persist post-install status");
        }
    }
    snapshot
}

/// One entry point for every implemented service: the two-channel error
/// discipline, the STARTED/COMPLETED envelope and the post-run status re-read
/// are identical for all of them, so only the STEPS differ per service.
async fn install(
    label: &'static str,
    service_id: String,
    codec: Codec,
    tx: Sender<Bytes>,
    input: Input,
    // Only the `vpn` arm reads this: it is the one label whose id names a
    // GROUP of services rather than one, so what to install is part of the
    // request rather than implied by the id.
    protocols: Vec<panel::Protocol>,
    // The deployment knowledge the HOST surface needs and the agent must not
    // infer — see `HostContext`.
    host_ctx: HostContext,
    // The record this run leaves behind. `None` on a host that could not open
    // one: the install still runs, it simply cannot be reattached to.
    journal: Option<journal::Journal>,
    // The agent's own store, so what this run leaves on the host reaches
    // `GetState` without waiting for the next `Discover` — see `read_status`.
    store: Arc<Mutex<Store>>,
) {
    let sink = EventSink {
        tx,
        codec,
        service_id: service_id.clone(),
        journal,
        sequence: AtomicU64::new(0),
    };
    let _ = sink.started(compose_project(label)).await;

    // **Before anything else, and inside the stream on purpose.** Every arm
    // below shells out to docker, and every one of them ends by writing a Caddy
    // site; on a host that has neither, this is the step that puts them there.
    // It runs here rather than in the pre-stream gate because installing two
    // packages takes minutes on a small VPS and the operator deserves to watch
    // it, and it runs FIRST because a docker-less host fails on its first real
    // step anyway — better to fail on "installing docker" than on a docker
    // command whose error names nothing.
    // The firewall comes with the packages, before any service work: it opens
    // 22/80/443 and lays down the chain the per-service drop-ins flush into.
    // On a host built by setup this finds its own ruleset and does nothing.
    let outcome = match packages::ensure_present(&sink).await {
        Err(why) => Err(why),
        Ok(()) => {
            firewall_base::ensure_ruleset(&sink).await;
            match label {
        "vpn" => install_vpn_steps(&input, &protocols, &sink).await,
        "docker-mailserver" => install_docker_mailserver_steps(&input, &sink).await,
        "mailcow" => install_mailcow_steps(&input, &sink).await,
        "mailu" => install_mailu_steps(&input, &sink).await,
        "forgejo" => install_forgejo_steps(&input, &sink).await,
        "gitlab" => install_gitlab_steps(&input, &sink).await,
        "immich" => install_immich_steps(&input, &sink).await,
        "nextcloud" => install_nextcloud_steps(&input, &sink).await,
        "jellyfin" => install_jellyfin_steps(&input, &sink).await,
        "ollama" => install_ollama_steps(&input, &sink).await,
        // Two more arms that have to know what else is on this host, for the
        // reason `homepage` does: the chat's model backends and the gateway's
        // routing table are BOTH derived from the neighbours.
        "open-webui" => {
            let services = host_service_ids(label, &protocols).await;
            install_open_webui_steps(&input, &services, &sink).await
        }
        "litellm" => {
            let services = host_service_ids(label, &protocols).await;
            install_litellm_steps(&input, &services, &sink).await
        }
        "n8n" => install_n8n_steps(&input, &sink).await,
        // Like the chat and the gateway above: what this one installs is a
        // function of what else the host runs.
        "anythingllm" => {
            let services = host_service_ids(label, &protocols).await;
            install_anythingllm_steps(&input, &services, &sink).await
        }
        "qdrant" => install_qdrant_steps(&input, &sink).await,
        "searxng" => install_searxng_steps(&input, &sink).await,
        "openclaw" => install_openclaw_steps(&input, &sink).await,
        "minecraft-java" => install_minecraft_java_steps(&input, &sink).await,
        "minecraft-bedrock" => install_minecraft_bedrock_steps(&input, &sink).await,
        "crafty-controller" => install_crafty_steps(&input, &sink).await,
        "passbolt" => install_passbolt_steps(&input, &sink).await,
        "photoprism" => install_photoprism_steps(&input, &sink).await,
        "psono" => install_psono_steps(&input, &sink).await,
        "seafile" => install_seafile_steps(&input, &sink).await,
        "vaultwarden" => install_vaultwarden_steps(&input, &sink).await,
        "headscale" => install_headscale_steps(&input, &sink).await,
        "cloudflared" => install_cloudflared_steps(&input, &sink).await,
        "tailscale-node" => {
            install_mesh_node_steps(&input, &sink).await;
            Ok(())
        }
        "pihole" => install_pihole_steps(&input, &sink).await,
        // The one arm that needs to know what ELSE is on this host: the page
        // it writes IS that list. `host_service_ids` is the same union the
        // wrappers are rendered from, so the page and the wrappers cannot
        // disagree about which services exist.
        "homepage" => {
            let services = host_service_ids(label, &protocols).await;
            install_homepage_steps(&input, &services, &sink).await
        }
        // The other arm that has to know what else is here: the portal's rule
        // list names the sites it stands in front of, and a rule missing for
        // an installed site is a page the portal REFUSES (`default_policy:
        // deny`) — which reads as that service being broken.
        "authelia" => {
            let services = host_service_ids(label, &protocols).await;
            install_authelia_steps(&input, &services, &sink).await
        }
        // **AdGuard is the catch-all only because it was the first executor,
        // and that is a hazard worth naming rather than tidying away.** `label`
        // is already gated to `IMPLEMENTED_SERVICE_IDS` before the stream
        // opens, so nothing unknown reaches this — but an id added to that list
        // WITHOUT an arm here would install AdGuard Home under the new
        // service's name, and both the status re-read and the Caddy site would
        // agree with each other about the wrong thing. Pi-hole is the first id
        // that would have landed exactly there (same shelf, same catch-all),
        // which is why it has an explicit arm above rather than relying on the
        // match being read carefully.
        _ => install_adguard_steps(&input, &sink).await,
            }
        }
    };

    if let Err(why) = outcome {
        let status = read_status(&service_id, &store).await;
        let _ = sink.completed(status).await;
        let _ = sink.fail(&why).await;
        sink.close(Some(&why));
        return;
    }

    // The host surface comes AFTER the service, and only when the service went
    // up: the wrappers are a function of what is actually installed, and
    // regenerating them from a set that includes something that failed halfway
    // would advertise arms for a service the host does not have.
    if let Err(why) = provision_host_surface(&input, &host_ctx, &protocols, label, &sink).await {
        let status = read_status(&service_id, &store).await;
        let _ = sink.completed(status).await;
        let _ = sink.fail(&why).await;
        sink.close(Some(&why));
        return;
    }

    let status = read_status(&service_id, &store).await;
    let _ = sink.completed(status).await;
    sink.close(None);
}

// ─────────────────────────── the host surface ───────────────────────────

/// `Host/ProvisionHost` — bring the wrappers up to date without installing
/// anything.
///
/// Unary and NOT streamed: it writes a fixed set of files and restarts one
/// unit. The two hosts that can never reach `InstallService` are the reason it
/// exists — scenario B's relay, which carries no services at all, and any host
/// whose last service was just removed (`RemoveService` does not regenerate
/// wrappers either, so they keep dispatching on something that is gone).
pub async fn run_provision_host(codec: Codec, req: pb::ProvisionHostRequest) -> Resp {
    // The same builder the install path uses, fed an equivalent request: the
    // host surface renders from the whole deployment's settings, so the two
    // messages carry the same fields and must not read them differently.
    let install_req = pb::InstallServiceRequest {
        service_id: String::new(),
        domain: req.domain.clone(),
        additional_domains: req.additional_domains.clone(),
        local_only: req.local_only,
        admin_username: req.admin_username.clone(),
        language: req.language.clone(),
        settings: req.settings.clone(),
        host_role: req.host_role,
        ptr_ip: req.ptr_ip.clone(),
        ptr_hostname: req.ptr_hostname.clone(),
        tunnel_endpoint: req.tunnel_endpoint.clone(),
        relay_wg_port: req.relay_wg_port,
        relay_forwarded_ports: req.relay_forwarded_ports.clone(),
        relay_forwarded_udp_ports: req.relay_forwarded_udp_ports.clone(),
        home_wg_address: req.home_wg_address.clone(),
        dashboard_public_key: req.dashboard_public_key.clone(),
    };
    let input = match build_input(&install_req) {
        Ok(input) => input,
        Err(why) => return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", &why),
    };
    let mut host_ctx = HostContext::from_request(&install_req);
    // **Peers reach the agent only through THIS verb**, which is the whole
    // shape of the thing: `InstallService` installs where it is called and has
    // no opinion about the topology, while `ProvisionHost` is the one call a
    // relay ever receives. A peer with no address or no forwarded TCP port is
    // dropped rather than rendered — `Topology::is_complete` refuses a
    // half-formed relay anyway, and this keeps the reason at the edge.
    host_ctx.relay_peers = req
        .relay_peers
        .iter()
        .map(|peer| firewall_relay::Peer {
            ip: peer.tunnel_address.trim().to_string(),
            tcp_ports: peer.forwarded_ports.iter().filter_map(|p| u16::try_from(*p).ok()).collect(),
            udp_ports: peer.forwarded_udp_ports.iter().filter_map(|p| u16::try_from(*p).ok()).collect(),
        })
        .filter(|peer| !peer.ip.is_empty())
        .collect();

    // No sink to stream through, and nothing to stream: the events an install
    // sends are about docker, and this touches none. Errors come back as the
    // response, which is the whole reason this verb is unary.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let sink = EventSink { tx, codec, service_id: String::new(), journal: None, sequence: AtomicU64::new(0) };
    let outcome = provision_host_surface(&input, &host_ctx, &[], "", &sink).await;
    // A host whose mail engine is ALREADY installed never re-runs that
    // install, so a fix to how the engine signs would otherwise reach only
    // hosts installed after it — and "reinstall your mail server to stop
    // sending unsigned mail" is not a fix that arrives. This verb exists for
    // exactly that gap: it is what brings a host's managed layer up to date
    // without installing anything, and this IS part of that layer (we wrote
    // the config, via `setup config dkim`, and our own DKIM wrapper reads the
    // key it names).
    //
    // Safe to call unconditionally: it reads the engine's config file, so a
    // host without docker-mailserver has nothing to read and returns at once,
    // and a host already carrying the fix is a no-op rather than a rewrite
    // plus a pointless rspamd restart.
    stop_rspamd_reducing_the_signing_domain(&input, &sink).await;
    let notes = drain_notes(&mut rx, codec);
    if let Err(why) = outcome {
        return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &why);
    }

    let role = host_ctx.role.unwrap_or(HostRole::SingleHost);
    let services = host_service_ids("", &[]).await;
    let host_input = HostInput {
        services,
        install: input,
        language: Language::En,
        ssh_user: existing_control_user(),
        role,
    };
    let written = host::provision::files(
        &host_input,
        &host::uninstall::BackupPaths::default(),
        dashboard_access(&host_ctx.dashboard_public_key).as_ref(),
    )
        .into_iter()
        .map(|file| file.path)
        .collect();
    let response = pb::ProvisionHostResponse {
        written,
        control_user: host_input.ssh_user.unwrap_or_default(),
        notes,
    };
    codec.encode(&response).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

/// The host half of `<host>:<port>`, or the whole string when it carries no
/// port. Deliberately not a parse into a typed address: the value is written
/// into an nftables `define`, and an address this agent could not interpret is
/// still one nft can — refusing it here would only replace a working relay with
/// a silent skip.
fn endpoint_host(endpoint: &str) -> String {
    match endpoint.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => host.to_string(),
        _ => endpoint.to_string(),
    }
}

/// What the host half needs from the request and cannot get anywhere else.
///
/// Everything here is deployment knowledge: the role decides which wrappers
/// this host gets, and the rest exists only for the install report. The agent
/// deliberately does not infer any of it — see the proto's own comment on
/// `host_role` for why a live `wg0` is not evidence of anything.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostContext {
    pub role: Option<HostRole>,
    pub ptr_ip: String,
    pub ptr_hostname: String,
    pub tunnel_endpoint: String,
    pub relay_wg_port: u16,
    pub relay_forwarded_ports: Vec<u16>,
    pub relay_forwarded_udp_ports: Vec<u16>,
    pub home_wg_address: String,
    /// Every machine this relay forwards to, when the request named them.
    /// Empty means the singular fields above describe the one backend, which
    /// is scenario B and what every shipped client sends.
    pub relay_peers: Vec<firewall_relay::Peer>,
    /// The caller's own public key, used only when this host has no wrapper to
    /// recover one from — see [`dashboard_access`].
    pub dashboard_public_key: String,
}

impl HostContext {
    fn from_request(req: &pb::InstallServiceRequest) -> Self {
        // UNSPECIFIED is a client that predates the field, and it maps to the
        // role with the SMALLEST cleanup list (see the proto's comment): a
        // wrapper that removes a WireGuard tunnel from a host that never had
        // one is the outcome worth avoiding.
        let role = match pb::HostRole::try_from(req.host_role) {
            Ok(pb::HostRole::VpsRelay) => Some(HostRole::VpsRelay),
            Ok(pb::HostRole::HomeBackend) => Some(HostRole::HomeBackend),
            _ => Some(HostRole::SingleHost),
        };
        HostContext {
            role,
            ptr_ip: req.ptr_ip.trim().to_string(),
            ptr_hostname: req.ptr_hostname.trim().to_string(),
            tunnel_endpoint: req.tunnel_endpoint.trim().to_string(),
            relay_wg_port: u16::try_from(req.relay_wg_port).unwrap_or(0),
            relay_forwarded_ports: req
                .relay_forwarded_ports
                .iter()
                .filter_map(|port| u16::try_from(*port).ok())
                .collect(),
            relay_forwarded_udp_ports: req
                .relay_forwarded_udp_ports
                .iter()
                .filter_map(|port| u16::try_from(*port).ok())
                .collect(),
            home_wg_address: req.home_wg_address.trim().to_string(),
            relay_peers: Vec::new(),
            dashboard_public_key: req.dashboard_public_key.trim().to_string(),
        }
    }

    /// The relay's firewall topology, straight off the request.
    ///
    /// The same fields the report already uses, read for a second purpose — not
    /// a second set: the relay's DNAT destination and its forwarded ports are
    /// exactly what the report prints, and two lists would be two chances to
    /// disagree. `vps_public` comes out of `tunnel_endpoint`, which is the
    /// address the home half dials — i.e. this relay's own public address, the
    /// one hairpinned traffic is aimed at.
    fn relay_topology(&self) -> firewall_relay::Topology {
        // **A request that names PEERS wins; one that does not is scenario B.**
        // The singular fields are what every shipped client sends, and they
        // describe exactly one backend — so they are read as one peer rather
        // than deprecated, and a two-machine deployment renders the file it
        // always did. Presence decides, not emptiness: a peer list that is
        // there and empty is a relay with nothing behind it, which
        // `is_complete` refuses; an absent one falls back here.
        if !self.relay_peers.is_empty() {
            return firewall_relay::Topology {
                peers: self.relay_peers.clone(),
                vps_public: endpoint_host(&self.tunnel_endpoint),
                wg_port: self.relay_wg_port,
            };
        }
        firewall_relay::Topology::single(
            self.home_wg_address.clone(),
            endpoint_host(&self.tunnel_endpoint),
            self.relay_wg_port,
            self.relay_forwarded_ports.clone(),
            self.relay_forwarded_udp_ports.clone(),
        )
    }

    /// The report's topology for this role. `ptr_hostname` falls back to the
    /// deployment's domain, exactly as `MailInput`'s own default does — a
    /// report that printed an empty name in the PTR reminder would be worse
    /// than one that printed the obvious one.
    fn topology(&self, role: HostRole, input: &Input) -> report::Topology {
        let ptr_hostname = if self.ptr_hostname.is_empty() {
            input.domain.clone()
        } else {
            self.ptr_hostname.clone()
        };
        match role {
            HostRole::VpsRelay => report::Topology::Relay {
                wg_port: self.relay_wg_port,
                forwarded_ports: self.relay_forwarded_ports.clone(),
                home_wg_address: self.home_wg_address.clone(),
                ptr_hostname,
            },
            HostRole::SingleHost | HostRole::HomeBackend => report::Topology::ServicesHost {
                // No PTR for a local-only deployment: there is no public
                // address to publish one for, and the report drops the line.
                ptr_ip: if input.local_only || self.ptr_ip.is_empty() {
                    None
                } else {
                    Some(self.ptr_ip.clone())
                },
                ptr_hostname,
                tunnel_endpoint: if self.tunnel_endpoint.is_empty() {
                    None
                } else {
                    Some(self.tunnel_endpoint.clone())
                },
            },
        }
    }
}

/// The catalog ids one install adds to the host.
///
/// For every service but the VPN this is the id itself. The VPN is the one
/// label whose id names a GROUP: `vpn` is what the agent's own catalog reports
/// and what the app manages, but the wrappers dispatch on `ServiceRegistry`
/// ids, so the panel and each selected protocol have to appear by name.
fn installed_catalog_ids(label: &str, protocols: &[panel::Protocol]) -> Vec<&'static str> {
    if label != "vpn" {
        return discover::known_service_id(label).into_iter().collect();
    }
    let mut ids = vec!["vpn-panel"];
    ids.extend(protocols.iter().map(|protocol| protocol.service_id()));
    ids
}

/// The catalog ids a DISCOVERED service stands for.
///
/// The inverse of the mapping above, and it has to read the host rather than
/// the request: what is already installed is not in this call's arguments. For
/// the VPN that means the container names, which are pinned per protocol
/// precisely so the dashboard's restart literals stay valid.
fn discovered_catalog_ids(service: &pb::Service) -> Vec<&'static str> {
    if service.id != "vpn" {
        return discover::known_service_id(&service.id).into_iter().collect();
    }
    let mut ids = Vec::new();
    for container in &service.containers {
        let id = match container.name.as_str() {
            panel::CONTAINER => "vpn-panel",
            amnezia::CONTAINER => "amnezia-wg",
            shadowsocks::CONTAINER => "shadowsocks",
            xray::CONTAINER => "xray-reality",
            openvpn::CONTAINER => "openvpn",
            _ => continue,
        };
        ids.push(id);
    }
    // Plain WireGuard has no container of its own — it runs INSIDE the panel
    // (wg-quick on `wgpanel`), so the only record of it being offered is the
    // panel's own registry. Read it rather than assume: a panel installed for
    // Shadowsocks alone does not carry a WireGuard endpoint, and claiming
    // otherwise would put a wireguard arm in every wrapper on the host.
    if ids.contains(&"vpn-panel") && panel_offers_wireguard() {
        ids.push("wireguard-vpn");
    }
    ids
}

/// Does the panel's own registry list plain WireGuard? Absent or unreadable
/// means no — the file is written before the panel's first start, so its
/// absence is not a state a running panel is in.
fn panel_offers_wireguard() -> bool {
    let path = Path::new(panel::PATH).join("data/services.json");
    std::fs::read_to_string(path)
        .map(|text| text.contains("\"id\":\"wireguard\""))
        .unwrap_or(false)
}

/// Every catalog id on this host after this install: what `discover` reports
/// plus what was just installed, in `CATALOG_ORDER`.
async fn host_service_ids(label: &str, protocols: &[panel::Protocol]) -> Vec<String> {
    let mut ids: Vec<&'static str> = installed_catalog_ids(label, protocols);
    if let Ok(found) = discover::scan().await {
        for service in &found.services {
            for id in discovered_catalog_ids(service) {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
    }
    host::CATALOG_ORDER
        .iter()
        .filter(|id| ids.contains(id))
        .map(|id| (*id).to_string())
        .collect()
}

/// Write the root-owned surface every later operation stands on.
///
/// **Fatal on failure, deliberately.** A service that is up but whose host has
/// an uninstall wrapper that does not know about it is exactly the defect this
/// exists to fix, and it is invisible until someone tries to remove or back up
/// that service weeks later. The same reasoning that makes a failed Caddy
/// reload fatal: the file being on disk is not the point, the file being
/// CURRENT is.
/// Rewrites one service's Caddy site with the sign-on check, when the portal
/// guards it. A no-op for anything else, and never fatal: the service is up
/// and its site is correct either way — only the gate would be missing, and
/// saying so beats failing an install that otherwise worked.
async fn guard_site_if_protected(
    id: &str,
    input: &Input,
    protected: &[String],
    sink: &EventSink,
) {
    if !protected.iter().any(|p| p == id) {
        return;
    }
    let Some((names, site)) = catalog::site_for(id, input, true) else { return };
    match write_caddy_site(&names, &site) {
        Ok(()) => {
            let _ = sink.step(format!("{id} stays behind the sign-on portal")).await;
        }
        Err(why) => {
            let _ = sink.step(format!("could not keep {id} behind the sign-on portal: {why}")).await;
        }
    }
}

async fn provision_host_surface(
    input: &Input,
    host_ctx: &HostContext,
    protocols: &[panel::Protocol],
    label: &str,
    sink: &EventSink,
) -> Result<(), String> {
    let Some(role) = host_ctx.role else { return Ok(()) };
    let services = host_service_ids(label, protocols).await;

    // **The other half of making single sign-on real.** The portal rewrites
    // the sites it guards when IT is installed; this is what keeps them
    // guarded when one of THEM is installed afterwards. Without it,
    // reinstalling a protected service silently took it back out from behind
    // the login — its own installer renders its site with no idea a portal
    // exists — and nothing would have said so.
    //
    // Runs here rather than inside each service's steps because this is where
    // the host's whole service list is already known, and the decision needs
    // it: a site is guarded only when the portal is actually on this host.
    if !label.is_empty() && services.iter().any(|id| id == "authelia") {
        let protected = authelia::protected_ids(input, &services);
        for id in installed_catalog_ids(label, protocols) {
            guard_site_if_protected(id, input, &protected, sink).await;
        }
    }

    let ssh_user = existing_control_user();
    let host_input = HostInput {
        services,
        install: input.clone(),
        language: input.language,
        ssh_user,
        role,
    };
    let backups = host::uninstall::BackupPaths::default();

    // What this host already carries, recovered rather than invented: the
    // app's public key lives only in the wrapper a previous setup wrote, and
    // regenerating without it would drop the erase-time key removal.
    let existing_access = dashboard_access(&host_ctx.dashboard_public_key);

    let _ = sink.step("writing the host's management wrappers").await;
    for file in host::provision::files(&host_input, &backups, existing_access.as_ref()) {
        let path = PathBuf::from(&file.path);
        if let Some(parent) = path.parent() {
            create_dir_0755(parent)
                .map_err(|err| format!("could not create {}: {err}", parent.display()))?;
        }
        std::fs::write(&path, host::provision::as_written(&file.contents))
            .map_err(|err| format!("could not write {}: {err}", path.display()))?;
        if let Some(mode) = file.mode {
            set_mode(&path, mode)
                .map_err(|err| format!("could not set the mode of {}: {err}", path.display()))?;
        }
    }

    write_sudoers(&host_input, &backups, sink).await?;
    give_backup_directories_to_control_user(&host_input, sink).await?;
    ensure_autobackup_passphrase(&host_input, sink).await;
    start_metrics_collector(sink).await?;
    apply_network_role(role, host_ctx, sink).await;
    // After the firewall, never before: the bouncer inspects the ruleset it is
    // going to sit beside, and a host whose base ruleset has not been written
    // yet is one where "is the bouncer in its own table" is a question about
    // nothing. Never fatal — see the module's own doc.
    crowdsec::ensure_present(input.crowdsec_enabled, sink).await;
    // Last of the host-hardening steps, and last on purpose: it is the only one
    // that can change how this machine is REACHED, so it runs after everything
    // that had to reach it. Its own guard is what keeps it safe (a proven key
    // on the control user); see `ssh_password`'s module doc for why neither the
    // check nor the write can happen inside this process.
    ssh_password::close_password_login(
        host_input.ssh_user.as_deref(),
        existing_access.as_ref().map(|access| access.app_public_key.as_str()),
        sink,
    )
    .await;
    write_install_report(&host_input, host_ctx, role, sink).await?;
    Ok(())
}

/// Give the host a stored backup passphrase when something on it refuses to be
/// backed up in the clear.
///
/// **Without this, installing a password vault produced a server that could
/// never update it, and said so only into a status file.** The scheduled
/// backup runs unattended, so there is nobody to type a passphrase; a secret
/// store therefore refuses to back up at all, and `update-ctl` refuses to
/// update a service whose backup failed. Measured on the production host
/// 2026-08-19: Vaultwarden had been failing that way ever since it was
/// installed, because NEITHER install route ever created a passphrase — it
/// existed only if somebody happened to set one by hand.
///
/// Generated HERE rather than lazily inside the wrapper on the first backup,
/// and that is the load-bearing half: a passphrase minted during an unattended
/// run would encrypt archives with a secret nobody has ever seen, and an
/// archive whose passphrase died with the machine is not a backup. Made at
/// install time, it lands in the install report like every other credential
/// this product generates on the server.
///
/// `O_CREAT|O_EXCL`, never check-then-write: the file already on disk is the
/// one the existing archives were encrypted with, and replacing it would make
/// every one of them unreadable. Not fatal on failure — the services are up
/// by now, and refusing a whole install over a backup passphrase is the wrong
/// trade; it is announced instead, the same shape as the Caddy-enable step.
async fn ensure_autobackup_passphrase(input: &HostInput, sink: &EventSink) {
    if !host::backup_ctl::needs_stored_passphrase(input) {
        return;
    }
    let path = PathBuf::from(host::backup_ctl::PASSPHRASE_PATH);
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        if let Err(err) = create_dir_0755(parent) {
            let _ = sink
                .step(&format!("could not create {}: {err}", parent.display()))
                .await;
            return;
        }
    }
    let secret = match random_hex_20() {
        Ok(secret) => secret,
        Err(err) => {
            let _ = sink
                .step(&format!("could not generate a backup passphrase: {err}"))
                .await;
            return;
        }
    };
    match create_file_if_absent(&path, &secret, 0o600) {
        Ok(true) => {
            let _ = sink
                .step("generated this host's backup passphrase — it is in the install report")
                .await;
        }
        Ok(false) => {}
        Err(err) => {
            let _ = sink
                .step(&format!("could not store the backup passphrase: {err}"))
                .await;
        }
    }
}

/// Drain whatever the sink collected into plain lines, for the ONE verb that has
/// no stream to send them on.
///
/// `ProvisionHost` is unary, and it is the relay's only path into the agent, so
/// the events an install would narrate were simply discarded here — measured
/// 2026-08-13, a relay that refused to rewrite its own wrong-shaped ruleset said
/// so into a channel nobody read, which from the client's side was
/// indistinguishable from success.
fn drain_notes(rx: &mut tokio::sync::mpsc::Receiver<Bytes>, codec: Codec) -> Vec<String> {
    let mut notes = Vec::new();
    while let Ok(frame) = rx.try_recv() {
        // The frame is an envelope: 1 flag byte + 4 length bytes + payload.
        if frame.len() <= 5 {
            continue;
        }
        if let Some(event) = codec.decode_payload::<pb::InstallServiceEvent>(&frame[5..]) {
            if !event.text.trim().is_empty() {
                notes.push(event.text);
            }
        }
    }
    notes
}

/// The routing half of this host's role: the firewall shape it needs, its kernel
/// settings, and — on the home half — the policy routing that makes a relayed
/// reply find the tunnel.
///
/// **Here rather than beside the service steps, because the relay never has
/// any.** `ProvisionHost` is the relay's ONLY path into the agent (it carries no
/// services, so `InstallService` is never called on it), and both verbs come
/// through this function. A single host lands here too and gets exactly what it
/// got before: `firewall_base`'s own ruleset, no sysctl, no policy routing.
///
/// Nothing here is fatal. Every one of these steps runs AFTER the services are
/// up and published, so failing the whole call over a firewall would report a
/// working machine as broken — the judgement `firewall_base::ensure_ruleset` and
/// the Caddy-enable step already make. Each failure says what did not happen.
async fn apply_network_role(role: HostRole, host_ctx: &HostContext, sink: &EventSink) {
    let plan = match role {
        HostRole::SingleHost => firewall_base::Plan::SingleHost,
        HostRole::HomeBackend => firewall_base::Plan::HomeBackend(Some(host_ctx.relay_topology())),
        HostRole::VpsRelay => firewall_base::Plan::Relay(host_ctx.relay_topology()),
    };
    firewall_base::ensure(&plan, sink).await;
    match role {
        HostRole::SingleHost => {}
        HostRole::VpsRelay => {
            if let Err(why) =
                firewall_relay::apply_sysctl(firewall_relay::RELAY_SYSCTL_PATH, firewall_relay::RELAY_SYSCTL, sink)
                    .await
            {
                // Worth saying loudly: without `ip_forward` the DNAT rules above
                // are inert and the relay forwards nothing at all.
                let _ = sink.step(format!("WARNING: could not enable IPv4 forwarding: {why}")).await;
            }
        }
        HostRole::HomeBackend => {
            if let Err(why) =
                firewall_relay::apply_sysctl(firewall_relay::HOME_SYSCTL_PATH, firewall_relay::HOME_SYSCTL, sink).await
            {
                let _ = sink.step(format!("WARNING: could not relax reverse-path filtering: {why}")).await;
            }
            if let Err(why) = relay_routes::install(sink).await {
                let _ = sink
                    .step(format!("WARNING: could not install the relay route sync: {why} — relayed replies \
                                   would leave through this host's own ISP instead of the tunnel"))
                    .await;
            }
        }
    }
}

/// Hand each installed service's backup directory to the control user, so the
/// app can list and download archives over SFTP without sudo.
///
/// **The setup script's `install -d -m 750 "$dir"` inside `backup_ctl.sh`
/// itself (this crate's `backup_ctl::script`) is the ONLY thing that creates
/// these directories on an agent-built host, and it never names an owner** —
/// on a script-generated host that is fine, because
/// `DashboardAccessSections.serviceBackupDirs` already `install -d -o
/// '<user>'`-ed every one of them in the SAME setup-script section that wrote
/// the wrapper, before the wrapper's own `install -d` ever runs (idempotent:
/// the directory already exists with the right owner, so the wrapper's own
/// call is a no-op). The agent has no equivalent step, so on a host it
/// provisioned alone the FIRST creator of `/opt/backups/<id>` is either this
/// function or a scheduled run of `backup_ctl.sh` — root either way, unless
/// this runs. A control user that cannot even `ls` into its own backup
/// directory is not a loud failure: `BackupListParser` reads the directory
/// over SFTP as that user, so the dashboard's backup tab just stays silently
/// empty on every host the agent built.
///
/// **The exact same directories `backup_ctl.sh` dispatches into, not a
/// second list.** `host::backup_ctl::backup_dirs` is the wrapper's own
/// `build_targets` exposed read-only — see that function's doc for why a
/// parallel formula (even one that reproduces `uninstall::BackupPaths.for_id`
/// correctly today) would be one more place for the VPN-id disagreement this
/// module has already been burned by once (`install/host/mod.rs`'s "every
/// wrapper recognises the vpn from the SAME ids").
///
/// Skipped entirely with no control user: an agent-only host has nobody to
/// hand the directory to, and the generator's own `serviceBackupDirs` never
/// runs without `DashboardAccessInput` either (mod 2's "the agent never
/// grants access" — this reads what the setup script already decided, same as
/// `existing_control_user`).
async fn give_backup_directories_to_control_user(
    input: &HostInput,
    sink: &EventSink,
) -> Result<(), String> {
    let Some(user) = &input.ssh_user else { return Ok(()) };
    let dirs = host::backup_ctl::backup_dirs(input);
    if dirs.is_empty() {
        return Ok(());
    }
    for (id, dir) in &dirs {
        let path = PathBuf::from(dir);
        create_dir_with_mode(&path, 0o750)
            .map_err(|err| format!("could not create the {id} backup directory {dir}: {err}"))?;
        let chowned = tokio::process::Command::new("chown")
            .args([user.as_str(), dir.as_str()])
            .stdin(Stdio::null())
            .output()
            .await;
        if !matches!(&chowned, Ok(out) if out.status.success()) {
            return Err(format!("could not give the {id} backup directory to '{user}'"));
        }
    }
    let _ = sink.step("gave the control user its service backup directories").await;
    Ok(())
}

/// The dashboard access this host already has, read out of the uninstall
/// wrapper a previous setup left behind. `None` when that wrapper has no key
/// block — an agent-built host, or one set up in existing-user mode.
fn existing_dashboard_access() -> Option<host::uninstall::DashboardAccess> {
    let wrapper = std::fs::read_to_string(host::uninstall::SCRIPT_PATH).ok()?;
    let app_public_key = host::provision::app_public_key(&wrapper)?;
    // The block only exists when the generator was in create-user mode, so
    // finding it IS the answer to `create_user`.
    Some(host::uninstall::DashboardAccess { create_user: true, app_public_key })
}

/// The key the erase-time strip block should take back: the one this host was
/// actually handed, or — failing that — the one the caller says is its own.
///
/// **Order is the whole point.** Recovery from the wrapper wins because it
/// names the key that is really in `authorized_keys` on THIS machine, while
/// the request names the key of whichever paired device happens to be calling,
/// and with several devices those differ. The request is the fallback for the
/// case recovery structurally cannot serve: a host with no wrapper on disk,
/// which is exactly the host the agent built by itself.
fn dashboard_access(requested_key: &str) -> Option<host::uninstall::DashboardAccess> {
    if let Some(recovered) = existing_dashboard_access() {
        return Some(recovered);
    }
    let key = requested_key.trim();
    // A quote would break out of the shell literal the wrapper embeds this in,
    // the same guard `provision::app_public_key` applies to what it reads back.
    if key.is_empty() || key.contains('\'') || key.contains('\n') {
        return None;
    }
    Some(host::uninstall::DashboardAccess { create_user: true, app_public_key: key.to_string() })
}

/// The control user this host already has, or `None`.
///
/// Read out of the sudoers file a previous setup left behind — the agent never
/// creates an account and never installs a key (owner's decision 2026-08-12;
/// `host::provision`'s module doc carries the reasoning). No file means no
/// control user, and the whole access half is skipped.
pub(super) fn existing_control_user() -> Option<String> {
    std::fs::read_to_string(sudoers_path())
        .ok()
        .and_then(|text| host::provision::control_user(&text))
}

/// `/etc/sudoers.d/gryonixnexus-control`, and the staging name the generator
/// uses. The dot keeps sudo from reading the staged file at all — sudo ignores
/// names containing one — so a half-written or invalid whitelist is never live.
///
/// Redirectable through the environment for tests, the same technique
/// `docker_bin`/`systemctl_bin` use. This one earns it more than they do: the
/// failure being guarded against is an invalid file under `/etc/sudoers.d`,
/// which breaks `sudo` for every account on the machine, and that is worth a
/// test that actually writes, validates and moves files.
const SUDOERS_PATH: &str = "/etc/sudoers.d/gryonixnexus-control";

fn sudoers_path() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_SUDOERS_PATH").unwrap_or_else(|_| SUDOERS_PATH.to_string())
}

fn sudoers_staged_path() -> String {
    format!("{}.staged", sudoers_path())
}

/// Stage, validate with `visudo`, then move into place.
///
/// **Never written directly.** A syntactically invalid file under
/// `/etc/sudoers.d` breaks `sudo` for every account on the machine, which on a
/// remote server is indistinguishable from being locked out. The generator
/// stages and validates for the same reason, and a rejection is FATAL on both
/// routes — the staged file is removed so a later run does not inherit it.
async fn write_sudoers(
    input: &HostInput,
    backups: &host::uninstall::BackupPaths,
    sink: &EventSink,
) -> Result<(), String> {
    let Some(body) = host::provision::sudoers(input, backups) else {
        let _ = sink
            .step("this host has no gryonixNexus control user, so no sudoers whitelist was written")
            .await;
        return Ok(());
    };
    let staged_path = sudoers_staged_path();
    let staged = Path::new(&staged_path);
    std::fs::write(staged, host::provision::as_written(&body))
        .map_err(|err| format!("could not write {staged_path}: {err}"))?;
    set_mode(staged, 0o440)
        .map_err(|err| format!("could not set the mode of {staged_path}: {err}"))?;

    let checked = tokio::time::timeout(
        Duration::from_secs(VISUDO_TIMEOUT_SECS),
        tokio::process::Command::new(visudo_bin())
            .args(["-cf", &staged_path])
            .stdin(Stdio::null())
            .output(),
    )
    .await;
    let ok = matches!(&checked, Ok(Ok(out)) if out.status.success());
    if !ok {
        let _ = std::fs::remove_file(staged);
        let why = match checked {
            Ok(Ok(out)) => truncate(&String::from_utf8_lossy(&out.stderr)),
            Ok(Err(err)) => err.to_string(),
            Err(_) => format!("visudo timed out after {VISUDO_TIMEOUT_SECS}s"),
        };
        return Err(format!("the sudoers whitelist failed visudo and was not installed: {why}"));
    }
    std::fs::rename(staged, sudoers_path())
        .map_err(|err| format!("could not install {}: {err}", sudoers_path()))?;
    let _ = sink.step("updated the dashboard's sudoers whitelist").await;
    Ok(())
}

const VISUDO_TIMEOUT_SECS: u64 = 30;

fn visudo_bin() -> PathBuf {
    std::env::var("GRYONIXNEXUSD_INSTALL_VISUDO_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("visudo"))
}

/// `daemon-reload`, `enable` (best effort, as the generator's `|| true`) and
/// `restart` (not best effort — a collector that is not running means the
/// dashboard's history charts stay empty for ever).
async fn start_metrics_collector(sink: &EventSink) -> Result<(), String> {
    let bin = systemctl_bin();
    run_quiet(&bin, &["daemon-reload"])
        .await
        .map_err(|()| "systemctl daemon-reload failed after writing the metrics unit".to_string())?;
    // `|| true` on the bash side: a unit that cannot be enabled still runs
    // until reboot, and that is not worth failing an install for.
    let _ = run_quiet(&bin, &["enable", host::metrics::UNIT_NAME]).await;
    run_quiet(&bin, &["restart", host::metrics::UNIT_NAME]).await.map_err(|()| {
        format!("could not start {} — the dashboard's history would stay empty", host::metrics::UNIT_NAME)
    })?;
    let _ = sink.step("started the metrics collector").await;
    Ok(())
}

/// Render the install report and leave it where the app reads it.
///
/// Rendering runs on a blocking thread: every fact in it is a short child
/// process or a file read (`systemctl is-active`, a DKIM wrapper, `wg show`),
/// and the report module takes a synchronous `Facts` by design — the choice of
/// WHICH file each service's line reads belongs in that module and is what its
/// bash-parity test exercises.
async fn write_install_report(
    input: &HostInput,
    host_ctx: &HostContext,
    role: HostRole,
    sink: &EventSink,
) -> Result<(), String> {
    let topology = host_ctx.topology(role, &input.install);
    let for_render = input.clone();
    let rendered = tokio::task::spawn_blocking(move || {
        let facts = HostFacts;
        report::render(&for_render, &topology, &facts)
    })
    .await
    .map_err(|err| format!("could not render the install report: {err}"))?;

    let path = Path::new(report::REPORT_PATH);
    if let Some(parent) = path.parent() {
        create_dir_0755(parent)
            .map_err(|err| format!("could not create {}: {err}", parent.display()))?;
    }
    // 0600 from the moment the file exists: this is where every generated
    // password is written down, and `std::fs::write` + a follow-up chmod
    // would leave it world-readable for the instant in between.
    write_secret(path, &rendered, 0o600)
        .map_err(|err| format!("could not write {}: {err}", path.display()))?;
    // Ownership follows the control user when there is one. `CommandCatalog.
    // installReport` reads this file WITHOUT sudo, as that user, so a
    // root-owned 0600 report is unreadable to exactly the account meant to
    // read it — the generator chowns for the same reason. Best effort: a
    // report that exists but is root-owned is still better than none, and the
    // failure is visible in the step text rather than fatal.
    if let Some(user) = &input.ssh_user {
        let chowned = tokio::process::Command::new("chown")
            .args([user.as_str(), report::REPORT_PATH])
            .stdin(Stdio::null())
            .output()
            .await;
        if !matches!(&chowned, Ok(out) if out.status.success()) {
            let _ = sink
                .step(format!(
                    "could not give the install report to '{user}' — it stays root-owned,                      and the app reads it over sudo only"
                ))
                .await;
        }
    }
    let _ = sink.step("wrote the install report").await;
    Ok(())
}

/// The report's facts, answered against the real host.
struct HostFacts;

impl report::Facts for HostFacts {
    fn systemctl_is_active(&self, unit: &str) -> String {
        // `|| true` on the bash side: a failing call still prints whatever it
        // printed ("inactive", "unknown"), and that IS the answer.
        run_capture("systemctl", &["is-active", unit])
    }

    fn read_file(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn dkim_wrapper(&self, path: &str) -> String {
        run_capture(path, &[])
    }

    fn mailcow_dkim(&self, api_key: &str, domain: &str, https_port: u16) -> String {
        // Loopback HTTPS with a self-signed certificate — `-k` is not a
        // shortcut here, the certificate is mailcow's own and the connection
        // never leaves the host.
        let url = format!("https://127.0.0.1:{https_port}/api/v1/get/dkim/{domain}");
        let body = run_capture(
            "curl",
            &["-sk", "--max-time", "20", "-H", &format!("X-API-Key: {api_key}"), &url],
        );
        // The one field the report prints, pulled out without a JSON parser:
        // the response is mailcow's and the key is fixed.
        body.split("\"dkim_txt\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or("")
            .to_string()
    }

    fn wg_show(&self, interface: &str) -> String {
        run_capture("wg", &["show", interface])
    }
}

/// A short child process whose stdout IS the answer. Failure and an empty
/// answer are the same outcome here by design — see `report::Facts`.
fn run_capture(bin: &str, args: &[&str]) -> String {
    std::process::Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Headscale's install: directories, the config WE own, `up -d`, the STUN
/// port, the Caddy site. No secret to generate and no admin to bootstrap — a
/// mesh has no password login at all, devices join with a pre-auth key the
/// operator mints afterwards, which the install report explains.
///
/// **The firewall step is not fatal, unlike the mail engines'.** A missing
/// STUN port costs the DERP fallback, not the service: peers that can reach
/// each other directly — which on a home network is most of them — never
/// touch it, and the control server itself answers through Caddy on 443.
/// Refusing to finish an otherwise working install over a degraded fallback
/// would be the bad trade this file makes everywhere else too.
/// Cloudflare Tunnel's install: a directory, the compose file, an EMPTY `.env`
/// and — only if a token is already there — `up -d`.
///
/// **It deliberately does not start without a token.** A connector without one
/// retries for ever, saying the same thing each time, so a host would end up
/// with a container in a loop and nothing to explain it. Naming the state once,
/// here, is the difference between a service the owner knows is waiting for
/// them and one they find days later.
///
/// No Caddy site and no firewall step: the tunnel publishes nothing and opens
/// nothing, which is the entire reason to run it.
async fn install_cloudflared_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.cloudflared_path);
    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, cloudflared::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // A token in the REQUEST wins, and it is written directly rather than
    // through the template — exactly as the mesh node's minted join key is.
    // Keeping it out of `env_template()` is what lets that function stay
    // byte-identical to the Swift generator's, which has no token to
    // interpolate: the SSH route asks the owner to paste one.
    if !input.cloudflared_token.trim().is_empty() {
        let env_path = dir.join(".env");
        write_managed_files(&[ManagedFile {
            path: env_path.clone(),
            contents: format!("TUNNEL_TOKEN={}\n", input.cloudflared_token.trim()),
            mode: Some(0o600),
        }])
        .map_err(|err| format!("could not write {}: {err}", env_path.display()))?;
        let _ = sink.step("wrote the tunnel's connector token").await;
    } else {
        match write_env_if_absent(&dir, &cloudflared::env_template()) {
            Ok(true) => {
                let _ = sink.step("wrote an empty .env for the tunnel token").await;
            }
            Ok(false) => {
                let _ = sink.step("kept the existing .env").await;
            }
            Err(err) => return Err(format!("could not write .env: {err}")),
        }
    }

    let _ = sink.step("pulling the Cloudflare Tunnel image").await;
    run_docker_streaming(&compose_pull_args(cloudflared::COMPOSE_PROJECT, &dir), sink).await?;

    let env = std::fs::read_to_string(dir.join(".env")).unwrap_or_default();
    if cloudflared::has_token(&env) {
        let _ = sink.step("starting the Cloudflare Tunnel").await;
        compose_up(cloudflared::COMPOSE_PROJECT, &dir, sink).await?;
    } else {
        let _ = sink
            .step(format!(
                "Cloudflare Tunnel is installed but NOT started: put the tunnel's token in {}/.env \
                 and start it from the app",
                input.cloudflared_path
            ))
            .await;
    }
    Ok(())
}

async fn install_headscale_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.headscale_path);
    let config_dir = dir.join("config");
    let data_dir = dir.join("data");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&config_dir).map_err(|err| format!("could not create {}: {err}", config_dir.display()))?;
    create_dir_0755(&data_dir).map_err(|err| format!("could not create {}: {err}", data_dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, headscale::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // Rewritten every run: the file is ours, and a domain or hostname change
    // has to reach it. Headscale generates its own noise and DERP keys into
    // the DATA directory on first start and never rewrites them, so nothing
    // here destroys an existing mesh's identity.
    let config_path = config_dir.join("config.yaml");
    write_managed_files(&[ManagedFile { path: config_path.clone(), contents: headscale::config_yaml(input), mode: Some(0o600) }])
        .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;

    // Created only when ABSENT, unlike config.yaml: it holds the published
    // service names, and rewriting it every run would drop them on the next
    // re-install. It must exist BEFORE the first start — measured on v0.29.3:
    // with `extra_records_path` set and the file missing, headscale refuses to
    // start at all ("stat …: no such file or directory"), so this is not
    // tidiness, it is the difference between a server that runs and one that
    // restart-loops.
    //
    // The second half of the condition REPAIRS a file the SSH route used to
    // write: a doubled backslash inside a raw Swift string is not an escape,
    // so its `printf` put a LITERAL backslash-n on disk, and headscale then
    // refuses to start for ever ("unmarshalling records" — measured on a live
    // host 2026-08-20). A host installed that way and adopted later would
    // keep the restart loop, because the file exists. Only that exact content
    // is replaced: anything else may be published names.
    let records_path = config_dir.join(headscale::EXTRA_RECORDS_FILE);
    if headscale_records_need_writing(&records_path) {
        std::fs::write(&records_path, "[]\n")
            .map_err(|err| format!("could not write {}: {err}", records_path.display()))?;
        let _ = set_mode(&records_path, 0o644);
    }

    let _ = sink.step("pulling the Headscale image").await;
    run_docker_streaming(&compose_pull_args(headscale::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Headscale").await;
    compose_up(headscale::COMPOSE_PROJECT, &dir, sink).await?;

    // Its own wording rather than `firewall_step_text`, which is the MAIL
    // engines' — reusing it made a live install of this service announce that
    // it had "opened the mail ports", on a host with no mail engine at all.
    // Caught by the first real run, and the sort of thing no test would
    // question because the step still succeeded.
    let ports = vec![firewall::Port::udp(headscale::STUN_PORT)];
    match firewall::apply_service_ports("headscale", &ports).await {
        Ok(firewall::Outcome::Applied) => {
            let _ = sink.step("opened the DERP relay's STUN port in the firewall").await;
        }
        Ok(firewall::Outcome::Cleared) => {
            let _ = sink.step("removed this service's firewall ports").await;
        }
        Ok(firewall::Outcome::SkippedNoDropInDir) => {
            let _ = sink
                .step("the STUN port is NOT open: this host has no /etc/nftables.d drop-in directory — \
                       peers that cannot connect directly will have no fallback")
                .await;
        }
        Err(why) => {
            let _ = sink
                .step(format!("the DERP relay's STUN port could not be opened ({why}) — peers that cannot \
                               connect directly will have no fallback"))
                .await;
        }
    }

    write_caddy_site(&headscale::caddy_site_names(input), &headscale::caddy_site(input))?;
    reload_caddy(sink).await?;

    // The server joins its own mesh. Implicit, exactly as the VPN panel is
    // implicit to a protocol — and for a measured reason: a control server
    // that never joined has no mesh address, so the names the other devices
    // look up would have nothing to point at.
    //
    // **Through the LOOPBACK publish, not the public name.** The node runs on
    // the HOST's network stack, so headscale's own `127.0.0.1:8091` is
    // reachable from it with no ingress, no certificate and no DNS in the way
    // — and on the SSH route, where Caddy is installed AFTER every service,
    // the public name was a closed port at exactly this moment: the node spent
    // its single-use key on a join that could not complete and crash-looped on
    // "authkey expired" from then on (owner's vps-middle, 2026-08-24). An
    // explicit setting still wins: someone pointing the node at a control
    // server elsewhere is saying something this cannot guess.
    let mut node_input = input.clone();
    if node_input.tailscale_login_server.trim().is_empty() {
        node_input.tailscale_login_server = format!("http://127.0.0.1:{}", headscale::WEB_UI_PORT);
    }
    install_mesh_node_steps(&node_input, sink).await;

    Ok(())
}

/// The node half. **Never fatal**, deliberately: by the time it runs, the
/// control server is up and serving, and turning a working mesh into a failed
/// install because this machine did not join itself would be the bad half of
/// that trade. Every failure says what it was instead.
async fn install_mesh_node_steps(input: &Input, sink: &EventSink) {
    let dir = PathBuf::from(&input.tailscale_node_path);
    let state_dir = dir.join("state");
    let name = tailscale::node_name(input);

    let _ = sink.step("adding this server to its own mesh").await;
    if let Err(err) = create_dir_0755(&dir) {
        let _ = sink.step(format!("the mesh node was skipped: could not create {} ({err})", dir.display())).await;
        return;
    }
    // 0700: it holds the node's private identity, not configuration.
    if let Err(err) = std::fs::create_dir_all(&state_dir).and_then(|_| set_mode(&state_dir, 0o700)) {
        let _ = sink.step(format!("the mesh node was skipped: could not create {} ({err})", state_dir.display())).await;
        return;
    }

    let compose_path = dir.join("docker-compose.yml");
    if let Err(err) = write_managed_text(&compose_path, tailscale::compose_contents(input)) {
        let _ = sink.step(format!("the mesh node was skipped: could not write {} ({err})", compose_path.display())).await;
        return;
    }

    // The IDENTITY is the guard, not the presence of a state file, and the
    // difference is a crash loop. tailscaled writes `tailscaled.state` the
    // moment it starts — with nothing in it but a machine key — so a node
    // whose join FAILED leaves a file behind and an `exists()` test reads that
    // as "already joined". The re-run then skips minting, the container
    // retries the key it has already spent, and every restart from then on
    // dies with "authkey expired" (owner's vps-middle, 2026-08-24). A
    // registered profile is what a joined node has: `_current-profile` appears
    // in the file only once the control server has answered.
    if !mesh_node_has_identity(&state_dir) {
        // Joining Tailscale's own service, the key is the OWNER's and arrives
        // in the request; joining a Headscale on this host, it is minted below
        // and never leaves the machine. Which one applies is decided by the
        // login server, exactly as the compose file decides its flag.
        if !input.tailscale_login_server.trim().is_empty() || !input.tailscale_auth_key.trim().is_empty() {
            let supplied = input.tailscale_auth_key.trim();
            if supplied.is_empty() {
                let _ = sink
                    .step("no join key was supplied — this server will not enter the mesh until one is")
                    .await;
            } else {
                let env_path = dir.join(".env");
                if let Err(err) = write_managed_files(&[ManagedFile {
                    path: env_path.clone(),
                    contents: format!("TS_AUTHKEY={supplied}\n"),
                    mode: Some(0o600),
                }]) {
                    let _ = sink.step(format!("the join key could not be stored ({err})")).await;
                    return;
                }
            }
        } else {
        match mint_mesh_join_key().await {
            Ok(key) => {
                let env_path = dir.join(".env");
                let contents = format!("TS_AUTHKEY={key}\n");
                if let Err(err) = write_managed_files(&[ManagedFile {
                    path: env_path.clone(),
                    contents,
                    mode: Some(0o600),
                }]) {
                    let _ = sink.step(format!("the join key could not be stored ({err})")).await;
                    return;
                }
            }
            Err(why) => {
                // Said out loud rather than swallowed: without a key the
                // container comes up and joins nothing, which from the outside
                // looks exactly like a working node.
                let _ = sink
                    .step(format!("no join key could be minted ({why}) — this server will not be in its own mesh"))
                    .await;
            }
        }
        }
    }

    if let Err(why) = run_docker_streaming(&compose_pull_args(tailscale::COMPOSE_PROJECT, &dir), sink).await {
        let _ = sink.step(format!("the mesh node image could not be pulled ({why})")).await;
        return;
    }
    if let Err(why) = compose_up(tailscale::COMPOSE_PROJECT, &dir, sink).await {
        let _ = sink.step(format!("the mesh node could not be started ({why})")).await;
        return;
    }

    // Proof, not hope — and asked of the CLIENT, which is the only party that
    // knows for both control planes.
    //
    // **It used to ask the local Headscale, and that was wrong the moment the
    // node could join Tailscale instead**: on such a host there is no control
    // server to ask, so a perfectly healthy node would always be reported as
    // "has not joined". Measured on a live run. `tailscale status` also gives
    // the real failure in the client's own words, which is how "the key was
    // spent" stops looking like a broken install.
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(run) = run_docker_captured(
            &["exec".to_string(), tailscale::CONTAINER.to_string(), "tailscale".to_string(),
              "status".to_string(), "--json".to_string()],
            Duration::from_secs(20),
        )
        .await
        {
            if run.success {
                if let Some((state, address)) = tailscale::parse_status(&run.stdout) {
                    if state == "Running" {
                        let _ = sink.step(format!("this server joined the mesh as {name} ({address})")).await;
                        return;
                    }
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            // The client's own last error, when it has one: "invalid key: API
            // key … not valid" is a fact about the key, not about this install.
            let why = run_docker_captured(
                &["logs".to_string(), "--tail".to_string(), "50".to_string(),
                  tailscale::CONTAINER.to_string()],
                Duration::from_secs(15),
            )
            .await
            .ok()
            .and_then(|run| tailscale::last_login_error(&format!("{}{}", run.stdout, run.stderr)));
            match why {
                Some(reason) => {
                    let _ = sink.step(format!("the node is running but did not join: {reason}")).await;
                }
                None => {
                    let _ = sink.step("the node is running but has not joined the mesh yet").await;
                }
            }
            return;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Whether the mesh node's state directory holds a REGISTERED identity.
///
/// Not "does the file exist": tailscaled creates `tailscaled.state` with only
/// a machine key in it on its very first start, long before the control server
/// has answered. `_current-profile` is written when a join succeeds, so it is
/// the only thing in there that distinguishes a node that is in the mesh from
/// one that has been trying to get in and failing. See the call site.
fn mesh_node_has_identity(state_dir: &std::path::Path) -> bool {
    match std::fs::read_to_string(state_dir.join("tailscaled.state")) {
        Ok(text) => text.contains("_current-profile"),
        Err(_) => false,
    }
}

/// Mint a pre-auth key through the control server's own CLI, in this same
/// machine's container.
///
/// **The key never leaves the host.** It is created here and written into a
/// 0600 `.env` beside the node's compose file; nothing about it crosses the
/// network and nothing about it reaches the app. `--user` takes the numeric
/// ID rather than the name (checked against the CLI's own help), so the user
/// is looked up — and created once if this deployment has never had one.
async fn mint_mesh_join_key() -> Result<String, String> {
    async fn users() -> Result<Vec<crate::pb::MeshUser>, String> {
        let run = run_docker_captured(
            &["exec".to_string(), headscale::CONTAINER.to_string(), "headscale".to_string(),
              "users".to_string(), "list".to_string(), "-o".to_string(), "json".to_string()],
            Duration::from_secs(20),
        )
        .await?;
        if !run.success {
            return Err(run.why());
        }
        crate::mesh::parse_users(&run.stdout).map_err(|err| err.to_string())
    }

    let mut found = users().await?.into_iter().find(|user| user.name == tailscale::MESH_USER);
    if found.is_none() {
        let _ = run_docker_captured(
            &["exec".to_string(), headscale::CONTAINER.to_string(), "headscale".to_string(),
              "users".to_string(), "create".to_string(), tailscale::MESH_USER.to_string()],
            Duration::from_secs(20),
        )
        .await;
        found = users().await?.into_iter().find(|user| user.name == tailscale::MESH_USER);
    }
    let user = found.ok_or_else(|| format!("the mesh has no user named {}", tailscale::MESH_USER))?;

    let run = run_docker_captured(
        &["exec".to_string(), headscale::CONTAINER.to_string(), "headscale".to_string(),
          "preauthkeys".to_string(), "create".to_string(), "--user".to_string(), user.id.clone(),
          // `--reusable`, and that word is the difference between a node that
          // survives a restart and one that never comes back. A single-use key
          // is spent by the FIRST registration attempt, so a container
          // restarted before it has written its identity has nothing left to
          // authenticate with and crash-loops on "authkey expired" for ever.
          "--reusable".to_string(),
          "--expiration".to_string(), "24h".to_string(), "-o".to_string(), "json".to_string()],
        Duration::from_secs(20),
    )
    .await?;
    if !run.success {
        return Err(run.why());
    }
    let key = crate::mesh::parse_auth_key(&run.stdout).map_err(|err| err.to_string())?.key;
    if key.is_empty() {
        return Err("the control server returned an empty key".to_string());
    }
    Ok(key)
}

async fn install_adguard_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.adguard_path);
    let conf_dir = dir.join("conf");
    let work_dir = dir.join("work");

    // 1. Directories, mode spelled out rather than left to the umask — the
    //    same reasoning `composeSetup`'s own `install -d -m 755` comment
    //    states: containers that drop to a non-root user mount from here.
    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&conf_dir).map_err(|err| format!("could not create {}: {err}", conf_dir.display()))?;
    create_dir_0755(&work_dir).map_err(|err| format!("could not create {}: {err}", work_dir.display()))?;

    // 2. docker-compose.yml — rewritten every run; identical content makes
    //    this step idempotent on its own, nothing to guard.
    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, adguard::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // 3. .env, generated once — see write_env_if_absent's own doc.
    match write_env_if_absent(&dir, &adguard::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the admin secret").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    // 4. pull, then up — streamed.
    let _ = sink.step("pulling the AdGuard Home image").await;
    run_docker_streaming(&compose_pull_args(adguard::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting AdGuard Home").await;
    compose_up(adguard::COMPOSE_PROJECT, &dir, sink).await?;

    // 5. Wait for AdGuard's own API, on a DEADLINE, not a try count — every
    //    attempt can burn its own timeout, so counting attempts would make
    //    the real wait unbounded (the exact bug `setupSteps`'s own comment
    //    calls out). A heartbeat keeps a silent wait distinguishable from a
    //    hung install.
    let conf_yaml_path = conf_dir.join("AdGuardHome.yaml");
    if !conf_yaml_path.exists() {
        if wait_for_adguard(sink).await {
            configure_adguard(&dir, input, sink).await;
        } else {
            let _ = sink
                .step("AdGuard Home did not answer in time — the initial configuration was skipped")
                .await;
        }
    }

    // 6/7. Plain-HTTP DoH, then restart — nothing here is fatal, same rule
    //    the mailcow API / Nextcloud occ blocks follow: a failure here must
    //    not take the Caddy site (step 8) down with it.
    if let Ok(yaml) = std::fs::read_to_string(&conf_yaml_path) {
        let (patched, spelling) = patch_doh_insecure(&yaml);
        match spelling {
            Some(_) if patched != yaml => {
                if let Err(err) = std::fs::write(&conf_yaml_path, patched) {
                    let _ = sink.step(format!("could not write {}: {err}", conf_yaml_path.display())).await;
                } else {
                    let _ = sink.step("enabled plain-HTTP DNS-over-HTTPS").await;
                }
            }
            Some(_) => {} // key already true, or spelled with extra content — nothing to change
            None => {
                let _ = sink
                    .step("could not enable DNS-over-HTTPS behind the proxy — turn it on under Settings, Encryption")
                    .await;
            }
        }
        let _ = run_docker_streaming(&compose_restart_args(adguard::COMPOSE_PROJECT, &dir), sink).await;
    }

    // 8. Caddy site.
    write_caddy_site(&adguard::caddy_site_names(input), &adguard::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `PiholeService.setupSteps`.
///
/// Shorter than AdGuard's by one whole phase, and for a reason worth stating:
/// Pi-hole reads its admin password from the environment, so there is no
/// installation API to wait on and no window in which a setup wizard is served
/// to whoever opens the page first. What is left is the ordinary shape — dirs,
/// compose, a generated secret, `up`, wait, firewall, Caddy.
async fn install_pihole_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.pihole_path);
    let config_dir = dir.join("etc-pihole");

    // 1. Directories, mode spelled out rather than left to the umask.
    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&config_dir)
        .map_err(|err| format!("could not create {}: {err}", config_dir.display()))?;

    // 2. docker-compose.yml — rewritten every run; identical content makes
    //    this step idempotent on its own.
    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, pihole::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // 3. .env, generated once. Rotating it on a reinstall would lock the owner
    //    out of a panel whose password they already wrote down — and Pi-hole
    //    has no second credential to get back in with.
    match write_env_if_absent(&dir, &pihole::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the admin secret").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    // 4. pull, then up — streamed.
    let _ = sink.step("pulling the Pi-hole image").await;
    run_docker_streaming(&compose_pull_args(pihole::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Pi-hole").await;
    compose_up(pihole::COMPOSE_PROJECT, &dir, sink).await?;

    // 5. Wait for the resolver to answer a QUERY, not for the container to be
    //    up: Pi-hole downloads its blocklists on first start, and until that
    //    finishes it is running and answering nothing. A deadline rather than
    //    a try count — every probe can burn its own timeout, so counting tries
    //    makes the real wait unbounded. Not fatal: a filter still building its
    //    list is a working install a few minutes early, and failing here would
    //    take the Caddy site below with it.
    let _ = sink.step("waiting for the resolver to answer").await;
    if !wait_for_pihole(sink).await {
        let _ = sink
            .step("Pi-hole did not answer a query in time — it is installed and may still be building its blocklists")
            .await;
    }

    // 6. Firewall drop-in. Empty unless the resolver was asked to serve the
    //    network, and `open_firewall_ports` removes the drop-in for an empty
    //    list — so turning the switch OFF and reinstalling closes the port
    //    rather than leaving it open from the previous run.
    open_service_firewall_ports(PIHOLE_FIREWALL_LABEL, &pihole::firewall_ports(input), sink).await;

    // 7. Caddy site.
    write_caddy_site(&pihole::caddy_site_names(input), &pihole::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `HomepageService.setupSteps`.
///
/// **The derived file is rewritten every run, the owner's files are created
/// once and never touched again.** Those two halves are a pair: a start page
/// that silently stops listing a service installed last week is the failure
/// this service exists to prevent, and somebody's own rows vanishing on a
/// reinstall is the failure that would make them stop using it.
async fn install_homepage_steps(
    input: &Input,
    services: &[String],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(&input.homepage_path);
    let config_dir = dir.join("config");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&config_dir)
        .map_err(|err| format!("could not create {}: {err}", config_dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, homepage::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // Ours, derived, rewritten.
    let _ = sink.step("writing the page from this server's services").await;
    for (name, contents) in [
        ("services.yaml", homepage::services_yaml(input, services)),
        ("settings.yaml", homepage::settings_yaml(input, services)),
    ] {
        let path = config_dir.join(name);
        std::fs::write(&path, contents).map_err(|err| format!("could not write {}: {err}", path.display()))?;
    }
    // Theirs. Homepage will not start without the files existing at all, so
    // they are created empty — and only if absent, because from the first edit
    // on they are somebody's own page.
    for name in ["bookmarks.yaml", "widgets.yaml", "docker.yaml"] {
        let path = config_dir.join(name);
        if !path.exists() {
            std::fs::write(&path, "---\n")
                .map_err(|err| format!("could not write {}: {err}", path.display()))?;
        }
    }

    let _ = sink.step("pulling the Homepage image").await;
    run_docker_streaming(&compose_pull_args(homepage::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Homepage").await;
    compose_up(homepage::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&homepage::caddy_site_names(input), &homepage::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `AutheliaService.setupSteps`.
///
/// **The first account is created ONCE, and its password is never an
/// argument.** A rerun must not rotate the password of an administrator who
/// already wrote it down, and `authelia crypto hash generate argon2 --random`
/// makes the password AND its hash inside the image and prints both — so
/// nothing secret is ever in an argv that `/proc` hands to every account on
/// the box. The output is CAPTURED, not redirected: `docker run … > file`
/// creates the file before the command runs, so a failure would leave an empty
/// user database that the guard then treats as done (the lesson Psono's
/// `settings.yaml` paid for).
async fn install_authelia_steps(
    input: &Input,
    services: &[String],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(&input.authelia_path);
    let config_dir = dir.join("config");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    // 0700: the session database, the notification file and the user database
    // with its password hashes.
    create_dir_with_mode(&config_dir, 0o700)
        .map_err(|err| format!("could not create {}: {err}", config_dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, authelia::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let config_path = config_dir.join("configuration.yml");
    std::fs::write(&config_path, authelia::configuration_yaml(input, services))
        .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;

    match write_env_if_absent(&dir, &authelia::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the portal secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let users_path = config_dir.join("users_database.yml");
    if authelia_needs_first_user(&users_path) {
        let _ = sink.step("creating the first account").await;
        match make_authelia_first_user(input, &users_path, &dir).await {
            Ok(()) => {}
            // Not fatal: the portal is up and the configuration is correct, it
            // simply has nobody in it yet, and failing here would take the
            // Caddy site — and every other step after it — with it.
            Err(why) => {
                let _ = sink
                    .step(format!(
                        "could not create the first account — sign-in is not possible until a user is added to config/users_database.yml ({why})"
                    ))
                    .await;
            }
        }
    }

    let _ = sink.step("pulling the Authelia image").await;
    run_docker_streaming(&compose_pull_args(authelia::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Authelia").await;
    compose_up(authelia::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&authelia::caddy_site_names(input), &authelia::caddy_site(input))?;

    // **The step this service is useless without.** A service's Caddy site is
    // written by that service's own installer, which ran before this portal
    // existed and had no reason to ask anyone for a login — so installing
    // Authelia used to produce a configuration full of rules for sites Caddy
    // never asked it about. Measured on a live host: the portal listed
    // `dns.…` and `start.…`, the Caddyfile carried ZERO forward_auth blocks,
    // and both guarded services answered exactly as before. Installed, and
    // guarding nothing.
    //
    // So the sites it guards are rewritten here, from the one dispatcher that
    // can render any of them (`catalog::site_for`). Not fatal: the portal
    // itself is up and correct, and a site that still needs its own reinstall
    // is a smaller failure than an install that stops half-way.
    let mut guarded: Vec<String> = Vec::new();
    let mut unrenderable: Vec<String> = Vec::new();
    for id in authelia::protected_ids(input, services) {
        match catalog::site_for(&id, input, true) {
            Some((names, site)) => match write_caddy_site(&names, &site) {
                Ok(()) => guarded.push(id),
                Err(why) => {
                    let _ = sink.step(format!("could not put {id} behind the sign-on portal: {why}")).await;
                }
            },
            // A service with no site of its own cannot be guarded by a proxy
            // that only sees sites — saying so beats a rule nothing enforces.
            None => unrenderable.push(id),
        }
    }
    if !guarded.is_empty() {
        let _ = sink.step(format!("put these behind the sign-on portal: {}", guarded.join(", "))).await;
    }
    if !unrenderable.is_empty() {
        let _ = sink
            .step(format!(
                "these publish no site of their own, so the portal cannot stand in front of them: {}",
                unrenderable.join(", ")
            ))
            .await;
    }

    reload_caddy(sink).await?;

    Ok(())
}

/// Whether the mesh's extra-records file has to be written: absent, or holding
/// the unparseable `[]` + literal backslash-n an older SSH install left.
fn headscale_records_need_writing(path: &Path) -> bool {
    match std::fs::read_to_string(path) {
        Ok(text) => text == "[]\\n",
        Err(_) => true,
    }
}

/// Whether the first account still has to be made — ABSENT, or present and
/// unusable.
///
/// The second half is a repair, and it is safe for exactly the reason it is
/// needed: Authelia refuses to load a database whose hash does not start with
/// the crypt delimiter, so a file without one has never let anybody in and
/// cannot have had a person added to it. The SSH route wrote such a file on
/// any host that did not already hold the image — `docker run` prints its own
/// `Digest: sha256:…` while pulling, and the reader took that line — and a
/// host installed that way and adopted later would otherwise keep the restart
/// loop for ever, because the file exists.
fn authelia_needs_first_user(users_path: &Path) -> bool {
    match std::fs::read_to_string(users_path) {
        Ok(text) => !text.lines().any(|line| line.trim_start().starts_with("password: '$")),
        Err(_) => true,
    }
}

/// Runs the image's own hash generator and writes the user database from what
/// it printed. See `install_authelia_steps` for why the password is generated
/// there rather than here.
async fn make_authelia_first_user(
    input: &Input,
    users_path: &Path,
    dir: &Path,
) -> Result<(), String> {
    let run = run_docker_captured(
        &[
            "run".to_string(),
            "--rm".to_string(),
            authelia::IMAGE.to_string(),
            "authelia".to_string(),
            "crypto".to_string(),
            "hash".to_string(),
            "generate".to_string(),
            "argon2".to_string(),
            "--random".to_string(),
        ],
        Duration::from_secs(60),
    )
    .await?;
    if !run.success {
        return Err(run.why());
    }
    let field = |prefix: &str| -> Option<String> {
        run.stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix).map(|rest| rest.trim().to_string()))
            .filter(|value| !value.is_empty())
    };
    // The digest is required to carry the crypt delimiter. Nothing on this
    // path can print a second `Digest:` line today — stdout and stderr are
    // captured apart here, so docker's own pull chatter cannot reach the
    // parse the way it reached the shell route's `2>&1` — but a hash that
    // does not begin with `$` is one the portal will refuse at startup, and
    // writing it would trade a named failure for a restart loop.
    let (Some(password), Some(digest)) = (field("Random Password: "), field("Digest: ")) else {
        return Err("the image printed no password and digest".to_string());
    };
    if !digest.starts_with('$') {
        return Err(format!("the image printed a digest in a form Authelia cannot read: {digest}"));
    }
    let admin = &input.admin_username;
    let body = format!(
        "---
users:
  {admin}:
    disabled: false
    displayname: '{admin}'
    password: '{digest}'
    email: '{admin}@{}'
    groups:
      - admins
",
        input.domain
    );
    // 0600 from the moment the file exists: this file is password hashes,
    // and a write-then-chmod would leave it world-readable in between.
    write_secret(users_path, &body, 0o600)
        .map_err(|err| format!("could not write {}: {err}", users_path.display()))?;

    // The plaintext lands beside the other generated secrets, which is the one
    // place the install report knows to read from. Appended rather than
    // rewritten — `.env` already holds the three portal secrets and losing
    // them would lock every existing session out — but any EARLIER line of
    // this one key goes first: on the repair path the file already names the
    // password of the account that never worked, and two of them would leave
    // the report quoting whichever one its reader happened to take.
    use std::io::Write;
    let env_path = dir.join(".env");
    if let Ok(existing) = std::fs::read_to_string(&env_path) {
        let kept: String = existing
            .lines()
            .filter(|line| !line.starts_with("AUTHELIA_ADMIN_PASSWORD="))
            .map(|line| format!("{line}\n"))
            .collect();
        if kept.len() != existing.len() {
            std::fs::write(&env_path, kept)
                .map_err(|err| format!("could not rewrite {}: {err}", env_path.display()))?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&env_path)
        .map_err(|err| format!("could not open {}: {err}", env_path.display()))?;
    writeln!(file, "AUTHELIA_ADMIN_PASSWORD={password}")
        .map_err(|err| format!("could not record the password: {err}"))?;
    set_mode(&env_path, 0o600)
        .map_err(|err| format!("could not set the mode of {}: {err}", env_path.display()))?;
    Ok(())
}

const PIHOLE_FIREWALL_LABEL: &str = "pihole";

/// Firewall drop-in for a service that is not mail — same transaction, its own
/// wording, and NOT fatal.
///
/// Mail's version is fatal because an engine whose ports are shut is an engine
/// that cannot receive; here the opposite holds. An empty list is the normal
/// case (the resolver stays on the loopback), and even when ports ARE declared
/// the drop-in is a formality: a docker-published port bypasses the input
/// chain entirely, measured 2026-08-13. Turning a working install into a
/// failure over a firewall file that does not control the port would be a bad
/// trade — the same judgement `firewall_base` makes.
async fn open_service_firewall_ports(label: &str, ports: &[firewall::Port], sink: &EventSink) {
    let text = match firewall::apply_service_ports(label, ports).await {
        Ok(firewall::Outcome::Applied) => "opened this service's ports in the firewall".to_string(),
        // An empty list REMOVES the drop-in, which is what makes turning the
        // switch off and reinstalling actually close the port instead of
        // leaving the previous run's file behind.
        Ok(firewall::Outcome::Cleared) => "this service opens no ports in the firewall".to_string(),
        Ok(firewall::Outcome::SkippedNoDropInDir) =>
            "the ports are NOT open: this host has no /etc/nftables.d drop-in directory — re-run the server setup, then install again"
                .to_string(),
        Err(err) => format!("could not update this service's firewall ports: {err}"),
    };
    let _ = sink.step(text).await;
}

/// Polls Pi-hole with the same query its own image healthcheck uses
/// (`dig @127.0.0.1 pi.hole` inside the container), on a deadline with a
/// heartbeat — a silent wait is indistinguishable from a hung install in the
/// app's progress view.
async fn wait_for_pihole(sink: &EventSink) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    let mut tries: u32 = 0;
    while std::time::Instant::now() < deadline {
        let run = run_docker_captured(
            &[
                "exec".to_string(),
                pihole::CONTAINER.to_string(),
                "dig".to_string(),
                "+short".to_string(),
                "+norecurse".to_string(),
                "+retry=0".to_string(),
                "@127.0.0.1".to_string(),
                "pi.hole".to_string(),
            ],
            Duration::from_secs(10),
        )
        .await;
        if matches!(&run, Ok(run) if run.success) {
            return true;
        }
        tries += 1;
        if tries % 6 == 0 {
            let _ = sink
                .step("Pi-hole: waiting for the resolver to answer (it is downloading its blocklists)")
                .await;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    false
}

/// A port of `JellyfinService.setupSteps` — the shortest install in the
/// catalog: no secret, no `.env`, no admin bootstrap of its own.
///
/// **The per-service `gryonixnexus-update.sh` that the bash version writes is
/// deliberately NOT written here.** That script exists for the dashboard's
/// OLD update button, which reaches it as `sudo <path>/gryonixnexus-update.sh`
/// — and the sudoers line that allows it is provisioned by the setup script,
/// which this install path is replacing and does not run. Writing the file
/// without its whitelist entry would leave a script nothing can execute and
/// a button that fails with a password prompt; the agent's own update path
/// (`update.rs` → `update-ctl.sh`, backup + rollback) is what an
/// agent-installed service is driven by. ROADMAP.md already lists retiring
/// that older button.
async fn install_jellyfin_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.jellyfin_path);
    let media = PathBuf::from(&input.jellyfin_media_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    for name in ["config", "cache"] {
        let sub = dir.join(name);
        create_dir_0755(&sub).map_err(|err| format!("could not create {}: {err}", sub.display()))?;
    }
    // The library directory is created ONLY when missing, and never
    // re-permissioned: pointing at an existing library is the normal case,
    // and its ownership and mode are then the user's business, not ours —
    // the same distinction the bash version draws with
    // `[ -d <media> ] || install -d -m 755 <media>`.
    create_dir_if_absent_0755(&media).map_err(|err| format!("could not create {}: {err}", media.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, jellyfin::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let _ = sink.step("pulling the Jellyfin image").await;
    run_docker_streaming(&compose_pull_args(jellyfin::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Jellyfin").await;
    compose_up(jellyfin::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&jellyfin::caddy_site_names(input), &jellyfin::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `OllamaService.setupSteps`.
///
/// **It downloads no model, and that is the whole shape of it** (owner's
/// decision, 2026-09-07). A useful one is closer to forty gigabytes, so an
/// install that quietly fetched a default would spend somebody's disk on a
/// choice they were never shown. There is no arm here that could.
///
/// No Caddy site either: the API has no authentication of any kind, so
/// loopback is the security model rather than a preference.
async fn install_ollama_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.ollama_path);
    let models = dir.join("models");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&models)
        .map_err(|err| format!("could not create {}: {err}", models.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, ollama::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    gpu_override(input, sink).await?;

    let _ = sink.step("pulling the Ollama image").await;
    run_docker_streaming(&compose_pull_args(ollama::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Ollama").await;
    compose_up(ollama::COMPOSE_PROJECT, &dir, sink).await?;

    Ok(())
}

/// What the install does about the graphics card — a port of
/// `OllamaService.gpuSection`, and three outcomes rather than two.
///
/// **The driver is never installed, and the toolkit is only reached when one
/// already answers.** `nvidia-container-toolkit` teaches docker to hand an
/// existing device to a container; the driver under it is a kernel module with
/// a reboot on the far side, and an agent that puts kernel modules on somebody's
/// server can leave a machine that does not come back.
///
/// **The empty branch REMOVES the override rather than leaving it.** A setting
/// turned back off, or a card taken out, has to mean the engine stops asking
/// for a device — otherwise the deployment's answer and the host's behaviour
/// disagree until somebody reinstalls by hand.
async fn gpu_override(input: &Input, sink: &EventSink) -> Result<(), String> {
    let path = PathBuf::from(ollama::gpu_override_path(input));
    let wanted = input.ollama_uses_gpu && driver_answers();
    if !wanted {
        if input.ollama_uses_gpu {
            // Said out loud rather than left to the report: this is the moment
            // somebody is watching the install run.
            let _ = sink
                .step("no NVIDIA driver answered — the engine will run on the processor")
                .await;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("could not remove {}: {err}", path.display())),
        }
        return Ok(());
    }
    // Already taught to docker? Then nothing here needs a package or a daemon
    // restart — this step runs again on every re-install.
    if !docker_knows_the_nvidia_runtime() {
        packages::ensure_nvidia_container_toolkit(sink).await?;
    }
    std::fs::write(&path, ollama::gpu_override_contents())
        .map_err(|err| format!("could not write {}: {err}", path.display()))
}

/// Is the port this service wants held by THIS SERVICE, installed on the host
/// by hand?
///
/// **The whole question is whether adopting is on the table, and the answer is
/// no** (owner, 2026-09-08). A hand-installed copy has its own layout, its own
/// version and its own data directory, and taking it over would mean owning all
/// three forever on a guess. So this only has to be sure enough to say the
/// right sentence: the holder's process name has to carry the service's own id,
/// which is what a native install is called on every distribution that ships
/// one (`ollama`, `searxng`, `n8n`).
///
/// Docker-published conflicts are deliberately NOT this case: those are named
/// by the port refusal already, and a container of ours is a re-install rather
/// than a stranger.
async fn self_installed_by_hand(service_id: &str, conflicts: &[ports::Conflict]) -> Option<String> {
    for conflict in conflicts.iter().filter(|c| c.holder.is_none()) {
        let name = ports::holder_process(&conflict.port).await?;
        if name.to_lowercase().contains(&service_id.to_lowercase()) {
            return Some(name);
        }
    }
    None
}

/// Does a driver actually answer on this host? The binary being present is not
/// the question — a package can be installed against a kernel module that never
/// loaded, and the container would then fail at start rather than here.
fn driver_answers() -> bool {
    packages::have_binary("nvidia-smi") && !run_capture("nvidia-smi", &["-L"]).is_empty()
}

/// Whether docker has already been configured with NVIDIA's runtime. Read from
/// the daemon rather than from a file, because `nvidia-ctk` writes one of two
/// places depending on the version.
fn docker_knows_the_nvidia_runtime() -> bool {
    run_capture(&docker_bin().to_string_lossy(), &["info", "--format", "{{json .Runtimes}}"])
        .contains("nvidia")
}

/// A port of `OpenWebUIService.setupSteps`.
///
/// The chat mints the shared gateway secret when the gateway is on this host,
/// because it is installed FIRST — the shelf leads with the thing somebody
/// opens. `ensure_gateway_key` never overwrites, so the gateway's own step
/// later reads exactly this value.
async fn install_open_webui_steps(
    input: &Input,
    services: &[String],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(&input.open_webui_path);
    let data = dir.join("data");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&data).map_err(|err| format!("could not create {}: {err}", data.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, open_webui::compose_contents(input, services))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &open_webui::env_template()) {
        Ok(true) => {
            let _ = sink.step("generating the session key").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    if open_webui::engine_url(services).is_some() || gateway_is_installed(services) {
        // Nothing to do for the local engine — its URL is in the compose file —
        // but the gateway needs its shared secret in this service's own `.env`.
    }
    if gateway_is_installed(services) {
        let key = llm_keys::ensure_gateway_key(Path::new(litellm::GATEWAY_KEY_PATH))
            .map_err(|err| format!("could not mint the gateway key: {err:#}"))?;
        llm_keys::set_env_value(&dir.join(".env"), "LLM_GATEWAY_KEY", &key)
            .map_err(|err| format!("could not write the gateway key: {err:#}"))?;
    }

    let _ = sink.step("pulling the Open WebUI image").await;
    run_docker_streaming(&compose_pull_args(open_webui::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Open WebUI").await;
    compose_up(open_webui::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&open_webui::caddy_site_names(input), &open_webui::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `QdrantService.setupSteps`.
///
/// The key is minted here when this service is the first of its pair to
/// install, and read here when the chat beside it got there first —
/// `ensure_shared_secret` never overwrites, which is what makes both orders
/// correct.
async fn install_qdrant_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.qdrant_path);
    let storage = dir.join("storage");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    // The published image runs as root (its Dockerfile's USER_ID defaults to
    // 0), so a root-owned 0700 directory is exactly what it needs — and what
    // it holds is the documents as embeddings.
    create_dir_with_mode(&storage, 0o700)
        .map_err(|err| format!("could not create {}: {err}", storage.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, qdrant::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let _ = sink.step("reading the vector store key").await;
    let key = llm_keys::ensure_shared_secret(Path::new(qdrant::API_KEY_PATH), "")
        .map_err(|err| format!("could not mint the vector store key: {err:#}"))?;
    llm_keys::set_env_value(&dir.join(".env"), "QDRANT_API_KEY", &key)
        .map_err(|err| format!("could not write the vector store key: {err:#}"))?;

    let _ = sink.step("pulling the Qdrant image").await;
    run_docker_streaming(&compose_pull_args(qdrant::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Qdrant").await;
    compose_up(qdrant::COMPOSE_PROJECT, &dir, sink).await?;

    Ok(())
}

/// A port of `SearXNGService.setupSteps`.
///
/// **The settings file is written on EVERY install, and that is the opposite
/// of what the service below it does.** AnythingLLM's file is seeded once
/// because its own UI writes into it; this engine has no UI that writes
/// anything, so the file has exactly one author and re-running the install is
/// how a bad one gets fixed.
async fn install_searxng_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.searxng_path);
    let config = dir.join("config");
    let cache = dir.join("cache");

    let _ = sink.step("creating service directories").await;
    // Ownership is deliberately not set: their entrypoint starts as root,
    // chowns both mounts to the container's own user and drops privileges
    // itself. A uid guessed here would be a uid to keep in step with theirs.
    for path in [&dir, &config, &cache] {
        create_dir_0755(path).map_err(|err| format!("could not create {}: {err}", path.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, searxng::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let settings_path = PathBuf::from(searxng::settings_path(input));
    let _ = sink.step("writing the search settings").await;
    write_managed_text(&settings_path, searxng::settings_file())
        .map_err(|err| format!("could not write {}: {err}", settings_path.display()))?;
    set_mode(&settings_path, 0o644)
        .map_err(|err| format!("could not chmod {}: {err}", settings_path.display()))?;

    match write_env_if_absent(&dir, &searxng::env_template()) {
        Ok(true) => {
            let _ = sink.step("generating the instance secret").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the SearXNG image").await;
    run_docker_streaming(&compose_pull_args(searxng::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting SearXNG").await;
    compose_up(searxng::COMPOSE_PROJECT, &dir, sink).await?;

    Ok(())
}

/// A port of `OpenClawService.setupSteps`.
///
/// **Nothing here writes a messenger token, and nothing here seeds a model
/// provider.** Both are the person's to enter in the service's own UI — see
/// the module doc. What this does is create the state directory the container
/// owns, mint the token that guards the gateway, and publish the site.
async fn install_openclaw_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.openclaw_path);
    let state = dir.join("state");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    // uid 1000 (`node` in the image), which does not chown its own mount;
    // 0700 because what lands here is paired messenger sessions.
    create_dir_owned_by_user(&state, 0o700, OPENCLAW_CONTAINER_UID, OPENCLAW_CONTAINER_UID)
        .map_err(|err| format!("could not create {}: {err}", state.display()))?;

    // Seeded ONCE and never rewritten: the gateway will not start without a
    // configuration of its own, and it writes its OWN settings back into this
    // same file — the paired messengers, the model, the channels. A re-install
    // that rewrote it would undo the pairings a person made by scanning a QR
    // code. See `openclaw::SEEDED_CONFIG` for why the flag upstream offers
    // instead of a file is not the fix.
    let config_path = PathBuf::from(openclaw::config_path(input));
    if !config_path.exists() {
        let _ = sink.step("writing the gateway configuration").await;
        std::fs::write(&config_path, format!("{}\n", openclaw::SEEDED_CONFIG))
            .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;
    }
    // Applied on every run, not only on the one that created it: the container
    // has to write this file back, and a restore can leave it owned by root.
    std::os::unix::fs::chown(&config_path, Some(OPENCLAW_CONTAINER_UID), Some(OPENCLAW_CONTAINER_UID))
        .map_err(|err| format!("could not chown {}: {err}", config_path.display()))?;
    set_mode(&config_path, 0o600)
        .map_err(|err| format!("could not chmod {}: {err}", config_path.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, openclaw::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &openclaw::env_template()) {
        Ok(true) => {
            let _ = sink.step("generating the gateway token").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the OpenClaw image").await;
    run_docker_streaming(&compose_pull_args(openclaw::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting OpenClaw").await;
    compose_up(openclaw::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&openclaw::caddy_site_names(input), &openclaw::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// The uid the assistant's image runs as (`node`).
const OPENCLAW_CONTAINER_UID: u32 = 1000;

/// A port of `AnythingLLMService.setupSteps`.
///
/// **The settings file is seeded once and never rewritten**, which is the
/// whole reason this executor is longer than the compose write it wraps: what
/// the deployment derives from the neighbours is a starting point, and
/// everything after the first install belongs to the person changing it in the
/// service's own UI. A re-install that rewrote the file would silently undo
/// them — and because the container reads that file, it would look applied.
async fn install_anythingllm_steps(
    input: &Input,
    services: &[String],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(&input.anythingllm_path);
    let storage = dir.join("storage");
    let env_file = PathBuf::from(anythingllm::env_path(input));

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    // uid 1000 (`anythingllm` in the image), which does not chown its own
    // mounts; 0700 because what lands here is the documents.
    create_dir_owned_by_user(&storage, 0o700, ANYTHINGLLM_CONTAINER_UID, ANYTHINGLLM_CONTAINER_UID)
        .map_err(|err| format!("could not create {}: {err}", storage.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, anythingllm::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    if env_file.metadata().map(|meta| meta.len() > 0).unwrap_or(false) {
        let _ = sink.step("kept the existing settings").await;
    } else {
        let _ = sink.step("writing the settings the deployment implies").await;
        let mut lines = anythingllm::seeded_settings(services);
        // Three server secrets, generated here and never shown.
        for name in ["SIG_KEY", "SIG_SALT", "JWT_SECRET"] {
            lines.push(format!("{name}='{}'", random_hex(32)?));
        }
        // The two shared with a neighbour, minted by whichever of the pair
        // installs first — this one, when the chat leads its store.
        if anythingllm::uses_qdrant(services) {
            let key = llm_keys::ensure_shared_secret(Path::new(qdrant::API_KEY_PATH), "")
                .map_err(|err| format!("could not mint the vector store key: {err:#}"))?;
            lines.push(format!("QDRANT_API_KEY='{key}'"));
        }
        if anythingllm::model_source(services) == Some(anythingllm::ModelSource::Gateway) {
            let key = llm_keys::ensure_gateway_key(Path::new(litellm::GATEWAY_KEY_PATH))
                .map_err(|err| format!("could not mint the gateway key: {err:#}"))?;
            lines.push(format!("LITE_LLM_API_KEY='{key}'"));
        }
        write_private_file(&env_file, &format!("{}\n", lines.join("\n")))
            .map_err(|err| format!("could not write {}: {err}", env_file.display()))?;
    }
    // Applied on every run, not only on the run that created it: the container
    // has to be able to write this file back, and a restore or a hand-edit can
    // leave it owned by root.
    std::os::unix::fs::chown(
        &env_file,
        Some(ANYTHINGLLM_CONTAINER_UID),
        Some(ANYTHINGLLM_CONTAINER_UID),
    )
    .map_err(|err| format!("could not chown {}: {err}", env_file.display()))?;
    set_mode(&env_file, 0o600)
        .map_err(|err| format!("could not chmod {}: {err}", env_file.display()))?;

    let _ = sink.step("pulling the AnythingLLM image").await;
    run_docker_streaming(&compose_pull_args(anythingllm::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting AnythingLLM").await;
    compose_up(anythingllm::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&anythingllm::caddy_site_names(input), &anythingllm::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// The uid the AnythingLLM image runs as. A raw number for the reason every
/// other id in this file is one: it has to match the id INSIDE the container.
const ANYTHINGLLM_CONTAINER_UID: u32 = 1000;

/// `n` bytes of randomness as hex, for the secrets this crate generates
/// itself rather than shelling out to `openssl` the way the bash side does.
fn random_hex(n: usize) -> Result<String, String> {
    let mut bytes = vec![0u8; n];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").map_err(|err| err.to_string())?, &mut bytes)
        .map_err(|err| format!("reading /dev/urandom: {err}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Write a file whose twin on the SSH path is written by a heredoc.
///
/// **A heredoc always ends its file with a newline, and this has to as well.**
/// The generators the two delivery paths share hold the compose text WITHOUT a
/// trailing one — the Swift literal they are ports of ends without it, and the
/// fixtures compare byte for byte — so a plain `fs::write` leaves the agent's
/// copy one byte shorter than the script's. Seen on a live host, 2026-09-08:
/// `/opt/searxng/docker-compose.yml` was 1196 bytes after the generated script
/// and 1195 after the agent installed the same service onto the same box.
///
/// That is one byte with no runtime effect, and it is still worth closing: the
/// two paths are two ports of one thing, and every other place they meet is
/// held byte for byte on purpose. A host that has seen both should not be able
/// to tell which one wrote its files.
fn write_managed_text(path: &Path, contents: impl AsRef<str>) -> io::Result<()> {
    let contents = contents.as_ref();
    if contents.ends_with('\n') {
        std::fs::write(path, contents)
    } else {
        std::fs::write(path, format!("{contents}\n"))
    }
}

/// Write a file that must never exist world-readable, not even for the instant
/// between creating it and chmod-ing it.
fn write_private_file(path: &Path, contents: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

/// A port of `N8NService.setupSteps`.
///
/// Two directories rather than one, and they are not the same kind of
/// directory. The compose directory is the agent's, 0755 like every other
/// service's. `data` belongs to the CONTAINER's user: n8n runs as uid 1000 and
/// — unlike Forgejo, which is handed a `USER_UID` and chowns its own mount —
/// does nothing about a root-owned bind mount but exit on its first write. The
/// mode is 0700 because what lands in there is the key that decrypts every
/// credential the workflows use.
///
/// `postgres` is deliberately NOT pre-created: the official image initialises
/// its own data directory and refuses one it did not make.
async fn install_n8n_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.n8n_path);
    let data = dir.join("data");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_owned_by_user(&data, 0o700, N8N_CONTAINER_UID, N8N_CONTAINER_UID)
        .map_err(|err| format!("could not create {}: {err}", data.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, n8n::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &n8n::env_template()) {
        Ok(true) => {
            let _ = sink.step("generating the database password").await;
        }
        // Never regenerated: the password in an existing `.env` is the one
        // PostgreSQL already initialised its data directory with, and a fresh
        // one would leave the engine unable to open its own database.
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the n8n images").await;
    run_docker_streaming(&compose_pull_args(n8n::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting n8n").await;
    compose_up(n8n::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&n8n::caddy_site_names(input), &n8n::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// The uid the n8n image runs as (`node`). A raw number, like every other id
/// this file passes to `chown`: it has to match the id INSIDE the container,
/// and the host is not guaranteed to have a user of that name at all.
const N8N_CONTAINER_UID: u32 = 1000;

/// A port of `LiteLLMService.setupSteps`.
///
/// The provider keys are NOT written here: they live in the agent's own vault
/// and are rendered by `llm_keys::reconcile` on the way out of a vault write.
/// What this does is make sure the file EXISTS, because compose refuses to
/// start a service whose `env_file` is not there.
async fn install_litellm_steps(
    input: &Input,
    services: &[String],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(&input.litellm_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let key = llm_keys::ensure_gateway_key(Path::new(litellm::GATEWAY_KEY_PATH))
        .map_err(|err| format!("could not mint the gateway key: {err:#}"))?;
    llm_keys::ensure_keys_file(Path::new(llm_keys::KEYS_ENV_PATH))
        .map_err(|err| format!("could not create the provider keys file: {err:#}"))?;

    let config_path = dir.join("config.yaml");
    std::fs::write(&config_path, litellm::config_yaml(services))
        .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, litellm::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    llm_keys::set_env_value(&dir.join(".env"), "LITELLM_MASTER_KEY", &key)
        .map_err(|err| format!("could not write the master key: {err:#}"))?;

    let _ = sink.step("pulling the LiteLLM image").await;
    run_docker_streaming(&compose_pull_args(litellm::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting LiteLLM").await;
    compose_up(litellm::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&litellm::caddy_site_names(input), &litellm::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// Is the gateway one of the services this host carries?
fn gateway_is_installed(services: &[String]) -> bool {
    services.iter().any(|id| id == litellm::SERVICE_ID)
}

/// A port of `MinecraftJavaService.setupSteps`.
///
/// **No readiness probe, and that is deliberate.** A Minecraft server takes
/// minutes to generate a world on first boot, and there is nothing useful to
/// do while it does: no administrator to create, no configuration to push, no
/// second service waiting on it. Waiting would only turn a working install
/// into a five-minute progress bar that can time out.
async fn install_minecraft_java_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.minecraft_java_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    let data = dir.join("data");
    create_dir_0755(&data).map_err(|err| format!("could not create {}: {err}", data.display()))?;
    // The two drop-in directories the compose file mounts. Created here rather
    // than left to docker: a bind mount whose source is missing is created by
    // the daemon as ROOT-owned, and the uploads that land here are written by
    // this agent.
    for name in ["mods", "plugins"] {
        let extra = dir.join(name);
        create_dir_0755(&extra).map_err(|err| format!("could not create {}: {err}", extra.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, minecraft::java_compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // Written once: the RCON password is what the panel is configured with, and
    // regenerating it on a re-run would leave Crafty holding a password the
    // server no longer accepts.
    match write_env_if_absent(&dir, &minecraft::java_env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the RCON secret").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Minecraft (Java) image").await;
    run_docker_streaming(&compose_pull_args(minecraft::JAVA_COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting the Minecraft (Java) server").await;
    compose_up(minecraft::JAVA_COMPOSE_PROJECT, &dir, sink).await?;

    let ports: Vec<firewall::Port> =
        minecraft::java_firewall_ports(input).into_iter().map(|(port, _)| firewall::Port::tcp(port)).collect();
    open_service_firewall_ports("minecraft-java", &ports, sink).await;

    // No Caddy site: the game is not HTTP. What gets a name is the panel.
    Ok(())
}

/// A port of `MinecraftBedrockService.setupSteps`.
async fn install_minecraft_bedrock_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.minecraft_bedrock_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    let data = dir.join("data");
    create_dir_0755(&data).map_err(|err| format!("could not create {}: {err}", data.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, minecraft::bedrock_compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let _ = sink.step("pulling the Minecraft (Bedrock) image").await;
    run_docker_streaming(&compose_pull_args(minecraft::BEDROCK_COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting the Minecraft (Bedrock) server").await;
    compose_up(minecraft::BEDROCK_COMPOSE_PROJECT, &dir, sink).await?;

    // UDP, and a TCP rule would open nothing at all.
    let ports: Vec<firewall::Port> = minecraft::bedrock_firewall_ports(input)
        .into_iter()
        .map(|(port, _)| firewall::Port { proto: firewall::Proto::Udp, port })
        .collect();
    open_service_firewall_ports("minecraft-bedrock", &ports, sink).await;

    Ok(())
}

/// A port of `CraftyControllerService.setupSteps`. The one piece of the games
/// shelf with a web site, so the only one that writes a Caddy site.
async fn install_crafty_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.crafty_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    for name in ["backups", "logs", "servers", "config", "import"] {
        let sub = dir.join(name);
        create_dir_0755(&sub).map_err(|err| format!("could not create {}: {err}", sub.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, crafty::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let _ = sink.step("pulling the Crafty Controller image").await;
    run_docker_streaming(&compose_pull_args(crafty::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Crafty Controller").await;
    compose_up(crafty::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&crafty::caddy_site_names(input), &crafty::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `ImmichService.setupSteps`. Four containers, one compose
/// project, one generated secret — and, like PhotoPrism, nothing after
/// `up -d`: Immich has no way to be handed an administrator, the first
/// person to log in registers as one (which the report warns about in the
/// loudest terms it has).
///
/// ONLY the top directory is created. `library`, `ml-cache` and `postgres`
/// underneath it are bind-mount sources docker creates itself, and postgres
/// in particular refuses a data directory it did not initialise the
/// ownership of — the bash version creates exactly the same single
/// directory, with `install -d` and no explicit mode.
///
/// The per-service `gryonixnexus-update.sh` is skipped for the same reason as
/// Jellyfin's — see `install_jellyfin_steps`.
async fn install_immich_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.immich_path);

    let _ = sink.step("creating the service directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, immich::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // Written once: postgres was INITIALISED with whatever this file said the
    // first time, and a regenerated password would lock the server out of its
    // own database.
    match write_env_if_absent(&dir, &immich::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database secret").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Immich images").await;
    run_docker_streaming(&compose_pull_args(immich::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Immich").await;
    compose_up(immich::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&immich::caddy_site_names(input), &immich::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// Run `docker` and CAPTURE its combined output instead of streaming it —
/// the shape every "ask the container something" step needs (readiness
/// probes, `occ`, `forgejo admin user list`). The bash versions all spell
/// this the same way (`OUT="$(docker … 2>&1)"`) for the same reason: the
/// output IS the answer, and on failure it is the only explanation there is.
///
/// Returns whether the command succeeded plus that output. An error here
/// means docker could not be run at all; a non-zero exit is `Ok(false, …)`,
/// because for every caller in this module a failing probe is a normal state
/// to keep polling through, not a reason to abandon the install.
async fn run_docker_capture(args: &[String], timeout: Duration) -> Result<(bool, String), String> {
    let output = tokio::time::timeout(
        timeout,
        tokio::process::Command::new(docker_bin())
            .env("DOCKER_CONFIG", docker_config_dir())
            .args(args)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| format!("docker timed out after {}s", timeout.as_secs()))?
    .map_err(|err| format!("could not run docker: {err}"))?;

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), text))
}

/// The bash `_why` helpers, one function instead of three copies: the last
/// output, newlines squeezed out, bounded to one line — a service can answer
/// with a Go stack trace or a PHP backtrace, and the app streams this live.
fn why(output: &str) -> String {
    bounded(output, 300)
}

/// A port of `GitLabService.setupSteps`.
///
/// **Closing sign-up is the point of this block.** GitLab ships with sign-up
/// OPEN and there is no `gitlab.rb` key for it — the setting lives in the
/// DATABASE, so it can only be closed after the first reconfigure has seeded
/// one. On a public URL an open forge is the whole server.
///
/// Nothing here is fatal and no output is discarded, the same rule the
/// Nextcloud and Forgejo blocks follow.
async fn install_gitlab_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.gitlab_path);

    let _ = sink.step("creating the service directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, gitlab::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &gitlab::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the initial root password").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the GitLab image (several gigabytes)").await;
    run_docker_streaming(&compose_pull_args(gitlab::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting GitLab — the first boot takes several minutes").await;
    compose_up(gitlab::COMPOSE_PROJECT, &dir, sink).await?;

    configure_gitlab(&dir, sink).await;

    // **git over SSH is published on the HOST, so it needs the firewall.**
    // Everything else this shelf installs answers through Caddy on 443, which
    // is already open; this port is not, and docker publishing it is not the
    // same as the host accepting it. Measured live on 2026-09-08: installed by
    // the agent, GitLab answered on https and `nc -z <host> 2223` timed out —
    // an installation whose clone-over-SSH could never work. The generated
    // script has always covered this port in its own firewall step, which is
    // exactly the kind of drift between the two ports of one install that only
    // shows up on a real machine.
    let ssh_ports: Vec<firewall::Port> =
        gitlab::ssh_port(input).map(|port| vec![firewall::Port::tcp(port)]).unwrap_or_default();
    open_service_firewall_ports(gitlab::SERVICE_ID, &ssh_ports, sink).await;

    write_caddy_site(&gitlab::caddy_site_names(input), &gitlab::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

async fn configure_gitlab(dir: &Path, sink: &EventSink) {
    let marker = dir.join(GITLAB_SIGNUP_MARKER);
    if marker.exists() {
        // Already closed once. Re-closing would undo a deliberate choice made
        // in the Admin Area since — the same reason the root password is not
        // reset on a re-run.
        return;
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(GITLAB_READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut probe = (false, String::new());
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        probe = gitlab_exec(&["gitlab-ctl", "status"], GITLAB_EXEC_TIMEOUT_SECS).await;
        if probe.0 && puma_running(&probe.1) {
            ready = true;
            break;
        }
        attempt += 1;
        if attempt % GITLAB_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("GitLab: still starting up ({})", why(&probe.1))).await;
        }
        tokio::time::sleep(Duration::from_secs(GITLAB_POLL_INTERVAL_SECS)).await;
    }
    if !ready {
        let _ = sink
            .step(format!("GitLab: still starting — sign-up was NOT closed, close it in the Admin Area ({})", why(&probe.1)))
            .await;
        return;
    }

    let (ok, output) = gitlab_exec(
        &["gitlab-rails", "runner", "ApplicationSetting.last.update!(signup_enabled: false)"],
        GITLAB_RUNNER_TIMEOUT_SECS,
    )
    .await;
    if ok {
        if let Err(err) = std::fs::write(&marker, "") {
            // The setting IS closed; only the marker failed, so say so
            // rather than claiming the whole step failed.
            let _ = sink.step(format!("closed sign-up, but could not record it ({err})")).await;
        } else {
            let _ = sink.step("closed public sign-up").await;
        }
    } else {
        let _ = sink.step(format!("GitLab: could not close public sign-up ({})", why(&output))).await;
    }
}

/// Is the web server actually up? `gitlab-ctl status` reaches the runit
/// services, so it stays red until the reconfigure has DEFINED and started
/// them — unlike the container, which reports up within seconds. Puma by
/// name, because it is the one that serves the page: a `run:` line for
/// redis alone proves nothing.
pub fn puma_running(status: &str) -> bool {
    status.lines().any(|line| line.starts_with("run: puma"))
}

async fn gitlab_exec(argv: &[&str], timeout_secs: u64) -> (bool, String) {
    // `docker exec` with no `-u`: omnibus commands run as root inside the
    // image, which is what the bash version does too.
    let mut args = vec!["exec".to_string(), gitlab::CONTAINER.to_string()];
    args.extend(argv.iter().map(|a| a.to_string()));
    match run_docker_capture(&args, Duration::from_secs(timeout_secs)).await {
        Ok(result) => result,
        Err(err) => (false, err),
    }
}

/// A port of `NextcloudService.setupSteps`.
///
/// **The `occ` block is not optional polish.** Nextcloud writes
/// `trusted_domains`/`overwritehost` into `config.php` only when it FIRST
/// initialises the instance, and ignores the compose environment ever after
/// — so a reinstall onto another domain is met with "Access through
/// untrusted domain" and no way in. Re-applying the current names on every
/// run is a no-op when they already match.
///
/// **Nothing in that block is fatal and no output is discarded**, the same
/// rule the mailcow API and Nextcloud occ blocks have carried since a real
/// run died at step 9 of 22 with one exit code and not one line of
/// explanation: a freshly started instance answers `status` before it is
/// ready for `config:system:set`. A wrong trusted domain can be fixed from
/// the admin UI; a half-finished install cannot.
async fn install_nextcloud_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.nextcloud_path);

    let _ = sink.step("creating the service directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, nextcloud::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &nextcloud::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database and administrator secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Nextcloud images").await;
    run_docker_streaming(&compose_pull_args(nextcloud::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Nextcloud").await;
    compose_up(nextcloud::COMPOSE_PROJECT, &dir, sink).await?;

    configure_nextcloud(input, sink).await;

    write_caddy_site(&nextcloud::caddy_site_names(input), &nextcloud::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// `docker compose -p <project> ps -q <service>` — the id of a running
/// container of one compose SERVICE. The Nextcloud stack pins no
/// `container_name`, so this is the only way to name its app container.
pub fn compose_ps_id_args(project: &str, service: &str) -> Vec<String> {
    vec![
        "compose".to_string(),
        "-p".to_string(),
        project.to_string(),
        "ps".to_string(),
        "-q".to_string(),
        service.to_string(),
    ]
}

/// `docker exec -u <user> <container> <argv…>`.
pub fn exec_args(user: &str, container: &str, argv: &[&str]) -> Vec<String> {
    let mut args = vec!["exec".to_string(), "-u".to_string(), user.to_string(), container.to_string()];
    args.extend(argv.iter().map(|a| a.to_string()));
    args
}

/// The `occ` calls, in the order the bash block makes them. Never fatal —
/// see `install_nextcloud_steps`'s doc.
async fn configure_nextcloud(input: &Input, sink: &EventSink) {
    let project = nextcloud::COMPOSE_PROJECT;
    let container = match run_docker_capture(
        &compose_ps_id_args(project, nextcloud::APP_SERVICE),
        Duration::from_secs(OCC_CALL_TIMEOUT_SECS),
    )
    .await
    {
        Ok((true, out)) => out.lines().next().unwrap_or_default().trim().to_string(),
        _ => String::new(),
    };
    if container.is_empty() {
        let _ = sink.step("Nextcloud: could not find the app container — trusted domains were not applied").await;
        return;
    }

    // **`occ status` SUCCEEDS on an instance that is not installed, and
    // reading its exit status as readiness is why every setting below was
    // lost.** On a fresh container it answers "Nextcloud is not installed -
    // only a limited number of commands are available" and returns success, so
    // the wait broke out on its very first try and every `config:system:set`
    // after it failed with "There are no commands defined in the config:system
    // namespace" (owner's vps-middle, 2026-08-24 — the SSH route, but this
    // route reads the same answer the same way). The ANSWER is what has to be
    // read: `installed: true` is printed only once the installer has finished.
    let mut ready = (false, String::new());
    for _ in 0..OCC_READY_ATTEMPTS {
        let answer = occ(&container, &["status"]).await;
        if answer.0 && answer.1.contains("installed: true") {
            ready = answer;
            break;
        }
        ready = answer;
        tokio::time::sleep(Duration::from_secs(OCC_READY_INTERVAL_SECS)).await;
    }
    if !(ready.0 && ready.1.contains("installed: true")) {
        let _ = sink.step(format!("Nextcloud: occ is not answering, skipping configuration ({})", why(&ready.1))).await;
        return;
    }

    for (key, value) in occ_settings(input) {
        // `trusted_domains <n>` is TWO argv elements to occ (the config key
        // and its index), which is why the key is split rather than passed
        // whole — the bash version relies on word splitting for the same
        // effect.
        let mut argv = vec!["config:system:set"];
        argv.extend(key.split(' '));
        let value_arg = format!("--value={value}");
        argv.push(&value_arg);
        let (ok, output) = occ(&container, &argv).await;
        if !ok {
            let _ = sink.step(format!("Nextcloud: could not set {key} ({})", why(&output))).await;
        }
    }
    let _ = sink.step("applied the trusted domains and public URL").await;
}

/// Every `config:system:set` this install makes, in order — pure, so the one
/// rule that is easy to get silently wrong can be pinned by a test.
///
/// **Slots are 1-based, never 0**: slot 0 holds "localhost", written by the
/// image's own installer, and overwriting it cuts local access off. One slot
/// per name the Caddy site serves — the alias domains INCLUDED, or Nextcloud
/// answers them "untrusted domain" while Caddy happily holds a certificate
/// covering them. The overwrite values stay SINGULAR (see
/// `nextcloud`'s module doc): they are what absolute links are built from.
pub fn occ_settings(input: &Input) -> Vec<(String, String)> {
    let host = nextcloud::hostname(input);
    let mut settings: Vec<(String, String)> = nextcloud::served_hostnames(input)
        .iter()
        .enumerate()
        .map(|(index, name)| (format!("trusted_domains {}", index + 1), name.clone()))
        .collect();
    settings.push(("overwritehost".to_string(), host.clone()));
    settings.push(("overwriteprotocol".to_string(), "https".to_string()));
    settings.push(("overwrite.cli.url".to_string(), format!("https://{host}")));
    settings
}

async fn occ(container: &str, argv: &[&str]) -> (bool, String) {
    let mut full = vec!["php", "occ"];
    full.extend_from_slice(argv);
    match run_docker_capture(&exec_args("www-data", container, &full), Duration::from_secs(OCC_CALL_TIMEOUT_SECS)).await
    {
        Ok(result) => result,
        Err(err) => (false, err),
    }
}

/// A port of `ForgejoService.setupSteps`.
///
/// **The administrator is created over the CLI because `INSTALL_LOCK` leaves
/// no web wizard that could** — an instance without this step has no way in
/// at all. Nothing here is fatal and no output is discarded, the same rule
/// the Nextcloud block follows.
///
/// **The password does travel in the argv of `docker exec`, and that is
/// inherited, not chosen.** `forgejo admin user create` takes it only as a
/// flag: there is no stdin or environment path for it, unlike
/// docker-mailserver's `setup email add`, which is why the mail wrapper
/// could be fixed (GOTCHAS.md) and this cannot without inventing a flag the
/// product does not have. The exposure is the same one the existing SSH
/// install path already carries, and it lasts for the length of one call.
async fn install_forgejo_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.forgejo_path);

    let _ = sink.step("creating the service directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, forgejo::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &forgejo::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database and administrator secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Forgejo images").await;
    run_docker_streaming(&compose_pull_args(forgejo::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Forgejo").await;
    compose_up(forgejo::COMPOSE_PROJECT, &dir, sink).await?;

    configure_forgejo(&dir, input, sink).await;

    // The same host-published git-SSH port GitLab has, and the same omission —
    // see `install_gitlab_steps` for what it cost to find.
    let ssh_ports: Vec<firewall::Port> =
        forgejo::ssh_port(input).map(|port| vec![firewall::Port::tcp(port)]).unwrap_or_default();
    open_service_firewall_ports(forgejo::SERVICE_ID, &ssh_ports, sink).await;

    write_caddy_site(&forgejo::caddy_site_names(input), &forgejo::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

async fn configure_forgejo(dir: &Path, input: &Input, sink: &EventSink) {
    // A DEADLINE, not a number of tries: each attempt can burn its own
    // timeout, so counting attempts makes the real wait unbounded — the
    // exact bug the mailcow API wait had. `user list` doubles as the
    // readiness probe because, unlike `--version`, it has to reach the
    // database, which is what is actually not ready while the containers
    // already report up.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(FORGEJO_READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut listing = (false, String::new());
    while tokio::time::Instant::now() < deadline {
        listing = forgejo_exec(&["forgejo", "admin", "user", "list"]).await;
        if listing.0 {
            break;
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("Forgejo: waiting for the service to answer ({})", why(&listing.1))).await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    if !listing.0 {
        let _ = sink
            .step(format!("Forgejo: the administrator could not be created — it never answered ({})", why(&listing.1)))
            .await;
        return;
    }

    // Not `input.admin_username`: Forgejo refuses a reserved name outright,
    // so the account it is actually given can differ from the deployment's
    // shared one. See `forgejo::admin_username`.
    let admin = forgejo::admin_username(input);
    if admin_listed(&listing.1, &admin) {
        let _ = sink.step("the administrator already exists").await;
        return;
    }
    let Some(password) = read_env_value(&dir.join(".env"), "FORGEJO_ADMIN_PASSWORD") else {
        let _ = sink.step("Forgejo: no administrator password on file — the account was not created").await;
        return;
    };

    // The password is NOT reset on a re-run: the .env value is stable, so
    // the report keeps matching, and one the user has changed in the web UI
    // is left alone. That is why this whole block is skipped once the
    // account exists.
    let email = format!("{}@{}", admin, input.domain);
    let (ok, output) = forgejo_exec(&[
        "forgejo",
        "admin",
        "user",
        "create",
        "--admin",
        "--username",
        &admin,
        "--password",
        &password,
        "--email",
        &email,
        "--must-change-password=false",
    ])
    .await;
    if ok {
        let _ = sink.step("created the administrator").await;
    } else {
        let _ = sink.step(format!("Forgejo: could not create the administrator ({})", why(&output))).await;
    }
}

async fn forgejo_exec(argv: &[&str]) -> (bool, String) {
    match run_docker_capture(
        &exec_args("git", forgejo::CONTAINER, argv),
        Duration::from_secs(FORGEJO_EXEC_TIMEOUT_SECS),
    )
    .await
    {
        Ok(result) => result,
        Err(err) => (false, err),
    }
}

/// Is this username already in `forgejo admin user list`? Anchored to the
/// Username COLUMN (an id, then the name), never a bare substring: the
/// listing also has an Email column, so an unrelated account at
/// `<admin>@…` would otherwise look like the administrator already existing
/// and this step would silently skip creating it — a forge nobody can log
/// into, with one line in the log to say so.
pub fn admin_listed(listing: &str, username: &str) -> bool {
    listing.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let Some(id) = fields.next() else { return false };
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        fields.next() == Some(username)
    })
}

/// A port of `PhotoPrismService.setupSteps`. Two containers, one compose
/// project, and — unlike every other service here — NOTHING after `up -d`:
/// PhotoPrism creates its administrator from the environment on first start,
/// so there is no wizard to beat and no API to call.
///
/// `<path>/db` is deliberately NOT created here: it is MariaDB's own data
/// directory, docker creates the bind-mount source itself, and the image's
/// entrypoint chowns it to the user it runs as. `originals` and `storage`
/// ARE created with the mode spelled out, because PhotoPrism drops to its own
/// user and has to write into both — the same two directories (and the same
/// reason) the bash version names in its `install -d -m 755`.
///
/// The per-service `gryonixnexus-update.sh` is skipped for the same reason as
/// Jellyfin's — see `install_jellyfin_steps`.
async fn install_photoprism_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.photoprism_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    for name in ["originals", "storage"] {
        let sub = dir.join(name);
        create_dir_0755(&sub).map_err(|err| format!("could not create {}: {err}", sub.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, photoprism::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // Three secrets, one per line, each expanded independently — and written
    // once: a second run must not hand the running MariaDB a new password it
    // has never been initialised with.
    match write_env_if_absent(&dir, &photoprism::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database and administrator secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the PhotoPrism images").await;
    run_docker_streaming(&compose_pull_args(photoprism::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting PhotoPrism").await;
    compose_up(photoprism::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&photoprism::caddy_site_names(input), &photoprism::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `PassboltService.setupSteps`. Two containers, one compose
/// project, and the only service in this port whose install narrates a URL
/// instead of a password — see `install::passbolt`'s module doc for why the
/// server holds nothing that could set one.
///
/// **Freshness is decided BEFORE the first `up -d`, not after** — a port of
/// the bash `PB_FRESH` check: whether the server's own GPG key already
/// exists is also whether an earlier run already sent the one-time admin
/// invitation, and the entrypoint that writes that key runs on first start,
/// so the file cannot exist yet on a truly fresh container. Deciding after
/// `up -d` would race the entrypoint's own key generation.
/// The gid the Passbolt image's server runs under (www-data inside the
/// container). A number rather than a lookup: the id that matters is the one
/// in the container's passwd, and the host need not have that group at all.
const PASSBOLT_SERVER_GID: u32 = 33;

/// The two directories the Passbolt container writes into, with the modes the
/// IMAGE ships them as. Kept as data rather than inline literals so the policy
/// can be asserted without running the executor — creating them for real needs
/// root (chown to a foreign group is privileged), which no unit test has.
const PASSBOLT_SECRET_DIRS: &[(&str, u32)] = &[("gpg", 0o770), ("jwt", 0o750)];

async fn install_passbolt_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.passbolt_path);
    let secrets = PathBuf::from(passbolt::secrets_path(input));
    let gpg_key = PathBuf::from(passbolt::gpg_private_key_path(input));

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&dir.join("db")).map_err(|err| format!("could not create {}: {err}", dir.join("db").display()))?;
    // NOT 0755 root:root like every other directory this executor creates, and
    // the difference is what makes the service start at all. The image ships
    // /etc/passbolt/gpg as root:www-data 0770 and /etc/passbolt/jwt as
    // root:www-data 0750, and the server drops to www-data to write the GPG
    // keypair it generates on its first boot. Because these are BIND mounts —
    // and they have to be, the backup wrapper archives the service directory —
    // docker does not seed them from the image the way it seeds a named volume,
    // so the container gets the host's own modes. Measured live 2026-08-11:
    // with 0755 root:root the server crash-looped forever on
    // "/etc/passbolt/gpg/serverkey_private.asc: Permission denied", which reads
    // as a broken image rather than a wrong directory mode. The generator's
    // bash path had the identical defect and is fixed in the same change.
    for (name, mode) in PASSBOLT_SECRET_DIRS {
        let sub = secrets.join(name);
        create_dir_owned_by_group(&sub, *mode, PASSBOLT_SERVER_GID)
            .map_err(|err| format!("could not create {}: {err}", sub.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, passbolt::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // Two secrets, not three — see the module doc for why there is no
    // administrator password to generate here.
    match write_env_if_absent(&dir, &passbolt::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let fresh = !gpg_key.exists();

    let _ = sink.step("pulling the Passbolt images").await;
    run_docker_streaming(&compose_pull_args(passbolt::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Passbolt").await;
    compose_up(passbolt::COMPOSE_PROJECT, &dir, sink).await?;

    if fresh {
        provision_passbolt(input, &gpg_key, sink).await;
    }

    write_caddy_site(&passbolt::caddy_site_names(input), &passbolt::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// Wait for the server's own GPG keypair (the readiness signal, ported from
/// the bash `PB_READY` loop), then create the ONE-TIME admin invitation.
///
/// **This is a PENDING invitation, never a password.** `cake passbolt
/// register_user` cannot set one — Passbolt's server holds no key that
/// could, every account's private key is generated CLIENT-SIDE in the
/// browser — so the command's own stdout carries a single-use setup URL a
/// human has to open. Narrated over the step channel AND written to
/// `registrationURLPath`: the step channel is the only place an agent
/// install surfaces anything today (there is no install-report file on this
/// path the way the SSH script has one), and the file gives a future reader
/// of the host the same "one artifact this run produced" that a password
/// gets everywhere else in the catalog — consumed once instead of read many
/// times.
///
/// Nothing here is fatal — same rule the mailcow API / Nextcloud occ blocks
/// follow.
async fn provision_passbolt(input: &Input, gpg_key: &Path, sink: &EventSink) {
    let url_file = PathBuf::from(passbolt::registration_url_path(input));
    // A stale URL from an earlier failed run must not be mistaken for this
    // run's invitation — ported from the bash `rm -f` ahead of the decision
    // of what (if anything) to write next.
    let _ = std::fs::remove_file(&url_file);

    if !wait_for_file(
        gpg_key,
        PASSBOLT_READY_DEADLINE_SECS,
        sink,
        "Passbolt: waiting for the server to generate its key",
    )
    .await
    {
        let _ = sink
            .step(
                "Passbolt did not finish its first start in time — the administrator was never invited, invite them yourself once it is ready",
            )
            .await;
        return;
    }

    let admin = passbolt::admin_login(input);
    // `su -m -c … -s /bin/sh www-data`, ported verbatim from `pb_exec`: the
    // CLI has to run as the web server's own user. First/last name are
    // cosmetic profile fields, not login material, and are editable after
    // the admin's first sign-in.
    let command =
        format!("/usr/share/php/passbolt/bin/cake passbolt register_user -u '{admin}' -f 'Admin' -l 'Admin' -r admin");
    let run = run_docker_captured(
        &docker_exec_args(passbolt::CONTAINER, &["su", "-m", "-c", &command, "-s", "/bin/sh", "www-data"]),
        Duration::from_secs(PASSBOLT_EXEC_TIMEOUT_SECS),
    )
    .await;
    let run = match run {
        Ok(run) => run,
        Err(err) => {
            let _ = sink.step(format!("Passbolt: could not invite the administrator ({err})")).await;
            return;
        }
    };
    if !run.success {
        let _ = sink.step(format!("Passbolt: could not invite the administrator ({})", run.why())).await;
        return;
    }

    let mut combined = run.stdout.clone();
    combined.push_str(&run.stderr);
    match extract_last_url(&combined) {
        Some(url) => match create_file_if_absent(&url_file, &format!("{url}\n"), 0o600) {
            Ok(_) => {
                let _ = sink.step(format!("invited the administrator — one-time setup URL: {url}")).await;
            }
            Err(err) => {
                let _ = sink
                    .step(format!(
                        "invited the administrator, but could not save the setup URL ({err}) — read it from the agent's own log: {url}"
                    ))
                    .await;
            }
        },
        None => {
            let _ = sink
                .step(format!("Passbolt: the administrator invitation did not print a URL ({})", run.why()))
                .await;
        }
    }
}

/// A port of the bash `grep -oE 'https?://[^[:space:]]+' | tail -n1`: the
/// LAST whitespace-delimited token that starts with `http://`/`https://`.
/// `register_user`'s own output can carry framing text around the link, and
/// the last URL is the one the command itself prints.
pub fn extract_last_url(text: &str) -> Option<String> {
    text.split_whitespace().filter(|token| token.starts_with("http://") || token.starts_with("https://")).last().map(str::to_string)
}

/// A port of `VaultwardenService.setupSteps`.
///
/// **The `config.json` sync is the whole imperative half**, and it is not
/// cosmetic: settings saved in Vaultwarden's own `/admin` panel land in that
/// file, which OUTRANKS the compose environment. Without the sync a user who
/// once closed signups from `/admin` could never reopen them from the app —
/// the app's toggle would write an environment variable the server ignores.
/// The app's toggle is authoritative on every run.
async fn install_vaultwarden_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(vaultwarden::COMPOSE_DIRECTORY);
    let data_path = PathBuf::from(&input.vaultwarden_data_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, vaultwarden::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &vaultwarden::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the admin token").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    // The sync runs BEFORE the container comes up, so an existing instance
    // reads the corrected file on the restart below rather than serving the
    // stale policy for the length of the run.
    let config_path = data_path.join("config.json");
    let needs_restart = match sync_vaultwarden_config(&config_path, input) {
        Ok(changed) => {
            if changed {
                let _ = sink.step("updated the stored signups/domain settings").await;
            }
            changed
        }
        Err(err) => {
            // Not fatal, same rule the mailcow API / Nextcloud occ blocks
            // follow: a config file we could not parse must not stop the
            // service from being installed and served.
            let _ = sink.step(format!("could not update {}: {err}", config_path.display())).await;
            false
        }
    };

    let _ = sink.step("pulling the Vaultwarden image").await;
    run_docker_streaming(&compose_pull_args(vaultwarden::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Vaultwarden").await;
    compose_up(vaultwarden::COMPOSE_PROJECT, &dir, sink).await?;

    if needs_restart {
        // `docker restart <container>`, not `compose restart`: an already
        // running container does not pick up a rewritten config.json, and
        // this is the same container literal the dashboard and its sudoers
        // line name.
        let _ = sink.step("restarting Vaultwarden to pick up the new settings").await;
        let args = vec!["restart".to_string(), input.vaultwarden_container.clone()];
        run_docker_streaming(&args, sink).await?;
    }

    write_caddy_site(&vaultwarden::caddy_site_names(input), &vaultwarden::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `SeafileService.setupSteps`. Three containers, four independent
/// generated secrets, and the FIRST service in this port whose install has to
/// edit a file the server itself writes on its own first start.
///
/// **`<path>/db` IS created here**, unlike PhotoPrism's MariaDB data
/// directory which is deliberately left to docker. That is not an
/// inconsistency to tidy up: the bash version this ports names `<path>/db`
/// explicitly in its `install -d -m 755` alongside the data mount, and this
/// service has been installed and verified live in exactly that shape. A
/// port that "improves" on its source in the one place nobody can re-verify
/// today is a port that has stopped being one.
///
/// **The CSRF step is not cosmetic and not fatal.** Every name the Caddy
/// site answers on has to be a trusted origin or Django refuses the sign-in
/// POST with an error that reads like a wrong password (see
/// `seafile::csrf_trusted_origins_line`). It is not fatal for the same
/// reason the mailcow API and Nextcloud occ blocks are not: a service that
/// came up but could not be finished configuring must still get its Caddy
/// site, and the operator must be told why in words.
///
/// The per-service `gryonixnexus-update.sh` is skipped for the same reason as
/// Jellyfin's — see `install_jellyfin_steps`.
async fn install_seafile_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.seafile_path);
    let data = PathBuf::from(seafile::data_path(input));
    let db_dir = dir.join("db");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    // Modes spelled out rather than left to the umask: the container writes
    // into /shared as its own user — the bash version's own reason.
    create_dir_0755(&data).map_err(|err| format!("could not create {}: {err}", data.display()))?;
    create_dir_0755(&db_dir).map_err(|err| format!("could not create {}: {err}", db_dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, seafile::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // Four secrets, one per line, each expanded independently — and written
    // once: the database was INITIALISED with these, and the administrator
    // account was created from them on the first start, so regenerating any
    // of them locks the deployment out of its own service.
    match write_env_if_absent(&dir, &seafile::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database, JWT and administrator secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Seafile images").await;
    run_docker_streaming(&compose_pull_args(seafile::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Seafile").await;
    compose_up(seafile::COMPOSE_PROJECT, &dir, sink).await?;

    configure_seafile_csrf(&dir, &data, input, sink).await;

    write_caddy_site(&seafile::caddy_site_names(input), &seafile::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// Wait for seahub to write its settings file, then put the trusted CSRF
/// origins into it and restart the server so it reads them.
async fn configure_seafile_csrf(dir: &Path, data: &Path, input: &Input, sink: &EventSink) {
    let settings = data.join(seafile::SEAHUB_SETTINGS_RELATIVE_PATH);
    if !wait_for_file(&settings, SEAFILE_SETTINGS_DEADLINE_SECS, sink, "Seafile: waiting for the first start to finish")
        .await
    {
        let _ = sink
            .step(
                "Seafile did not finish its first start in time — the trusted CSRF origins were not applied, so signing in may fail with an error that looks like a wrong password",
            )
            .await;
        return;
    }

    let existing = match std::fs::read_to_string(&settings) {
        Ok(text) => text,
        Err(err) => {
            let _ = sink.step(format!("could not read {}: {err}", settings.display())).await;
            return;
        }
    };
    let rewritten = seafile::rewritten_seahub_settings(&existing, &seafile::csrf_trusted_origins_line(input));
    if rewritten == existing {
        // Already exactly right — and skipping the write here is what keeps
        // a re-run from restarting a healthy server for nothing, the same
        // "already agrees" branch `sync_vaultwarden_config` draws.
        let _ = sink.step("the trusted CSRF origins were already up to date").await;
        return;
    }
    if let Err(err) = std::fs::write(&settings, rewritten) {
        let _ = sink.step(format!("could not write {}: {err}", settings.display())).await;
        return;
    }
    let _ = sink.step("wrote the trusted CSRF origins").await;
    // Only the server, never the whole project: seahub reads this file at
    // start, and its database and cache have no reason to go down with it.
    let _ = run_docker_streaming(
        &compose_restart_service_args(seafile::COMPOSE_PROJECT, &dir, seafile::SERVER_SERVICE),
        sink,
    )
    .await;
}

/// Poll for a file the SERVICE creates, on a deadline with a heartbeat — the
/// same shape as `wait_for_adguard`, and for the same reason its own comment
/// gives: counting attempts instead of watching a clock makes the real wait
/// unbounded.
async fn wait_for_file(path: &Path, deadline_secs: u64, sink: &EventSink, heartbeat: &str) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(deadline_secs);
    let mut attempt: u32 = 0;
    while tokio::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(heartbeat).await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    path.exists()
}

/// A port of `PsonoService.setupSteps` — three steps in the bash version,
/// and the widest imperative half in this port so far.
///
/// **`settings.yaml` must exist BEFORE `up -d`.** The compose file
/// bind-mounts it as a FILE; docker creates a missing bind-mount source
/// itself, and for a file mount it creates a DIRECTORY there instead, which
/// the server then cannot read at all. The order below is the bash order for
/// exactly that reason, not by accident.
///
/// **The keypair is generated by the IMAGE, not by this crate.**
/// `PRIVATE_KEY`/`PUBLIC_KEY` in `settings.yaml` are a matched Curve25519
/// pair, so the `__RANDOM__` mechanism every other service's secrets use
/// would produce a public key that does not belong to the private one. The
/// image's own `generateserverkeys.py` runs once and its stdout is captured
/// verbatim — which is also why the capture keeps stdout and stderr apart.
///
/// The per-service `gryonixnexus-update.sh` is skipped for the same reason as
/// Jellyfin's — see `install_jellyfin_steps`.
async fn install_psono_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.psono_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    for name in ["db", "config", "config/webclient"] {
        let sub = dir.join(name);
        create_dir_0755(&sub).map_err(|err| format!("could not create {}: {err}", sub.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, psono::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // Rewritten every run like the compose file: it holds no secret, only
    // which server the two client apps talk to, and that has to follow the
    // hostname if it ever changes.
    let client_config = PathBuf::from(psono::webclient_config_path(input));
    std::fs::write(&client_config, psono::webclient_config_json(input))
        .map_err(|err| format!("could not write {}: {err}", client_config.display()))?;

    match write_env_if_absent(&dir, &psono::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database and administrator secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let fresh = write_psono_settings_if_absent(&dir, input, sink).await?;

    let _ = sink.step("pulling the Psono images").await;
    run_docker_streaming(&compose_pull_args(psono::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Psono").await;
    compose_up(psono::COMPOSE_PROJECT, &dir, sink).await?;

    provision_psono(input, fresh, sink).await;

    write_caddy_site(&psono::caddy_site_names(input), &psono::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// Generate `settings.yaml` once. Returns whether THIS run created it — the
/// answer decides whether the administrator gets created afterwards, exactly
/// like the bash version's `PS_FRESH`.
///
/// **Fatal on failure, and it leaves NO file behind when it fails.** The bash
/// version redirects the generator's stdout straight into the file
/// (`docker run … > settings.yaml`), so a generator that fails leaves an
/// EMPTY settings.yaml on disk — and the guard for the whole step is that
/// file's existence, so the next run would skip key generation entirely and
/// bring up a server with no keys and no explanation. Capturing first and
/// writing only a complete file is the same end state on success and a
/// recoverable one on failure.
async fn write_psono_settings_if_absent(dir: &Path, input: &Input, sink: &EventSink) -> Result<bool, String> {
    let settings = PathBuf::from(psono::settings_path(input));
    if settings.exists() {
        // Never regenerated: existing encrypted datastores are decrypted
        // against these keys.
        let _ = sink.step("kept the existing server keys").await;
        return Ok(false);
    }

    let _ = sink.step("generating the server keypair").await;
    let run = run_docker_captured(
        &docker_run_once_args(psono::IMAGE, &["python3", "./psono/generateserverkeys.py"]),
        Duration::from_secs(PSONO_KEYGEN_TIMEOUT_SECS),
    )
    .await?;
    if !run.success {
        return Err(format!("could not generate the Psono server keys: {}", run.why()));
    }

    // Written moments ago by this same run; missing means something is
    // seriously wrong, and a settings file with an empty database password
    // would be a server that cannot reach its own database.
    let Some(db_password) = read_env_value(&dir.join(".env"), "PSONO_DB_PASSWORD") else {
        return Err("psono .env carries no PSONO_DB_PASSWORD".to_string());
    };

    let mut contents = run.stdout;
    contents.push_str(&psono::settings_tail(input, &db_password));
    match create_file_if_absent(&settings, &contents, 0o600) {
        Ok(created) => {
            if created {
                let _ = sink.step("wrote the server configuration").await;
            }
            Ok(created)
        }
        Err(err) => Err(format!("could not write {}: {err}", settings.display())),
    }
}

/// `presetup` + `migrate` + (on a fresh install) the administrator.
///
/// Both migrations run on EVERY pass, not only a fresh install: they are
/// idempotent, and this catalog's other services update by pulling a new
/// image and restarting alone, which would silently skip a migration a newer
/// Psono needs.
///
/// Nothing here is fatal — same rule the mailcow API / Nextcloud occ blocks
/// follow — but nothing is silent either: every failure is narrated with the
/// engine's own words, because that output is the only explanation there is.
///
/// **The administrator's password travels in argv**, which `/proc` hands to
/// every local account for as long as the call runs. That is not a choice
/// this module gets to make: `manage.py createuser` takes the password as a
/// positional argument and offers no stdin path, and the alternative —
/// skipping the account — leaves an instance with registration closed and
/// nobody able to log into it at all. Called out here rather than smoothed
/// over: the docker-mailserver mailbox wrapper had the same exposure and was
/// fixed by moving the password to stdin, which is not available here.
async fn provision_psono(input: &Input, fresh: bool, sink: &EventSink) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(PSONO_READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut last_why = String::new();
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        match psono_manage(&["presetup"]).await {
            Ok(run) if run.success => {
                ready = true;
                break;
            }
            Ok(run) => last_why = run.why(),
            Err(err) => last_why = err,
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("Psono: waiting for the database to answer ({last_why})")).await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    if !ready {
        let _ = sink.step(format!("Psono did not become ready — finish the setup yourself ({last_why})")).await;
        return;
    }

    match psono_manage(&["migrate"]).await {
        Ok(run) if run.success => {}
        Ok(run) => {
            let _ = sink.step(format!("Psono: the database migration failed ({})", run.why())).await;
        }
        Err(err) => {
            let _ = sink.step(format!("Psono: the database migration failed ({err})")).await;
        }
    }

    if !fresh {
        return;
    }
    let env_path = PathBuf::from(&input.psono_path).join(".env");
    let Some(password) = read_env_value(&env_path, "PSONO_ADMIN_PASSWORD") else {
        return;
    };
    if password.is_empty() {
        return;
    }
    let admin = psono::admin_login(input);
    // `promoteuser` grants the admin-portal role; `verifyuseremail` exists
    // because this catalog wires no SMTP relay, so nothing would ever click
    // an activation link.
    let steps: [Vec<&str>; 3] = [
        vec!["createuser", &admin, &password, &admin],
        vec!["promoteuser", &admin, "superuser"],
        vec!["verifyuseremail", &admin],
    ];
    for step in steps {
        match psono_manage(&step).await {
            Ok(run) if run.success => {}
            Ok(run) => {
                let _ = sink
                    .step(format!("Psono: creating the administrator failed — create it yourself ({})", run.why()))
                    .await;
                return;
            }
            Err(err) => {
                let _ = sink
                    .step(format!("Psono: creating the administrator failed — create it yourself ({err})"))
                    .await;
                return;
            }
        }
    }
    let _ = sink.step("created the administrator account").await;
}

/// `docker exec psono python3 ./psono/manage.py <args…>` — a port of the
/// bash `ps_exec` helper, bounded by its own timeout the same way.
async fn psono_manage(args: &[&str]) -> Result<CapturedRun, String> {
    let mut command = vec!["python3", "./psono/manage.py"];
    command.extend_from_slice(args);
    run_docker_captured(
        &docker_exec_args(psono::CONTAINER, &command),
        Duration::from_secs(PSONO_EXEC_TIMEOUT_SECS),
    )
    .await
}

// ─────────────────────────── docker-mailserver ───────────────────────────

/// A port of `DockerMailserverService.setupSteps` — срез 4.9, and the widest
/// install in this port: two containers, a certificate the installer has to
/// invent before the engine will start at all, a systemd timer that replaces
/// it later, firewall ports, a first mailbox whose password never touches
/// argv, one DKIM key per mail domain, and one root-owned wrapper another
/// module of this same agent already calls.
///
/// **The order below is not arrangeable.** The placeholder certificate exists
/// BEFORE the first `up -d` because `SSL_TYPE=manual` does not degrade when
/// the files are missing — it crash-loops, and a container in that loop never
/// gets its first mailbox or its DKIM keys either (GOTCHAS.md defect 1). The
/// firewall comes right after `up -d`, before the five-minute readiness wait,
/// so the one FATAL step of the second half fails fast instead of after five
/// minutes. The Caddy site is last, as everywhere else.
///
/// **What is fatal and what is not**, deliberately split:
/// - fatal: the directories, the compose file, `.env`, `pull`/`up`, the
///   FIREWALL (a mail server whose 25/465/587/993/4190 are closed is silently
///   broken, and "silently" is the part that makes it worse than a failure),
///   the files under `/opt` this install owns, and the Caddy reload.
/// - not fatal: the placeholder certificate, the cert-sync timer's
///   `systemctl` calls, the readiness wait, the first mailbox, every DKIM
///   key. Same rule the mailcow API and Nextcloud `occ` blocks have carried
///   since a real run died at step 9 of 22 with one exit code and no
///   explanation — and the same rule the bash version this ports applies to
///   exactly these steps (`|| log`, `|| true`). A mailbox is addable
///   afterwards; a half-finished install is not repairable from the app.
///   The placeholder certificate is the uncomfortable one: failing it leaves
///   an engine that will crash-loop, and it is STILL not fatal here, because
///   the bash version treats it that way and this port does not get to
///   improve on a live-verified source in the one place nobody can re-verify
///   today (the argument `seafile`'s own module doc already makes about
///   `<path>/db`). What it does get to do is say so in the loudest words the
///   step channel has.
async fn install_docker_mailserver_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.docker_mailserver_path);

    let _ = sink.step("creating service directories").await;
    for path in dms::directories_0755(input) {
        let sub = PathBuf::from(&path);
        create_dir_with_mode(&sub, 0o755).map_err(|err| format!("could not create {path}: {err}"))?;
    }
    // The one directory of this service that is not 0755 — it holds the
    // private key of the certificate the mail ports serve.
    let certs = PathBuf::from(dms::certs_dir(input));
    create_dir_with_mode(&certs, 0o700).map_err(|err| format!("could not create {}: {err}", certs.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, dms::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // Written once: `FIRST_MAILBOX_PASSWORD` is the password of a mailbox that
    // already exists after the first run, and the install report is the only
    // place it was ever written down.
    match write_env_if_absent(&dir, &dms::env_template(input)) {
        Ok(true) => {
            let _ = sink.step("generated the first mailbox's password").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    // BEFORE the first `up -d`. See this function's doc.
    write_placeholder_cert(input, sink).await;

    let _ = sink.step("pulling the Docker Mailserver images").await;
    run_docker_streaming(&compose_pull_args(dms::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Docker Mailserver").await;
    compose_up(dms::COMPOSE_PROJECT, &dir, sink).await?;

    // The first service in this port that needs ports open, and the one step
    // of the second half that is fatal.
    open_mail_firewall_ports(DMS_FIREWALL_LABEL, &dms::firewall_ports(), sink).await?;

    install_cert_sync(input, sink).await?;
    write_dms_management_scripts(input, sink)?;
    configure_dms(input, sink).await;

    write_caddy_site(&dms::caddy_site_names(input), &dms::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A mail engine's ports, translated into the firewall module's own type.
/// The LIST is never re-derived here — it is whatever `ports` the caller
/// passes straight from that engine's own `firewall_ports()` (the same
/// declarative port the generated nftables ruleset, the relay's DNAT and the
/// install report all read on the Swift side), so there is exactly one
/// answer to "which ports does this engine need" per engine. Shared across
/// all three mail engines rather than one copy per module: the TYPE
/// (`super::mail::FirewallPort`/`Proto`) is already the same one all three
/// `mail::*` modules import from their shared parent, so a generic
/// conversion costs nothing three near-identical ones would not.
fn mail_firewall_ports(ports: &[super::mail::FirewallPort]) -> Vec<firewall::Port> {
    ports
        .iter()
        .map(|port| firewall::Port {
            port: port.port,
            proto: match port.proto {
                super::mail::Proto::Tcp => firewall::Proto::Tcp,
                super::mail::Proto::Udp => firewall::Proto::Udp,
            },
        })
        .collect()
}

/// What the install should DO with the firewall module's answer — pure, so the
/// one rule that matters can be pinned without an nftables-capable host.
///
/// A failure is FATAL: a mail server that cannot be reached on 25 accepts no
/// mail, and nothing about that looks like a firewall problem from the outside
/// — the sender sees a timeout and the owner sees a running container. That is
/// worse than an install that stops and says why.
///
/// `SkippedNoDropInDir` is NOT a failure: it means this host has never had the
/// `/etc/nftables.d` include provisioned (only a setup re-run does that), so
/// there is nothing the agent can write into. The install continues and the
/// operator is told, in the one channel this operation has.
fn firewall_step_text(outcome: Result<firewall::Outcome, String>) -> Result<String, String> {
    match outcome {
        Ok(firewall::Outcome::Applied) => Ok("opened the mail ports in the firewall".to_string()),
        // Unreachable for mail (it always declares ports) but not worth a
        // panic: the arm exists because the module can also be asked to CLOSE
        // a service's ports, which is what an empty list means.
        Ok(firewall::Outcome::Cleared) => Ok("removed this service's firewall ports".to_string()),
        Ok(firewall::Outcome::SkippedNoDropInDir) => Ok(
            "the mail ports are NOT open: this host has no /etc/nftables.d drop-in directory — re-run the server setup, then install again"
                .to_string(),
        ),
        Err(err) => Err(format!("could not open the mail ports in the firewall: {err}")),
    }
}

async fn open_mail_firewall_ports(
    label: &str,
    ports: &[super::mail::FirewallPort],
    sink: &EventSink,
) -> Result<(), String> {
    let outcome = firewall::apply_service_ports(label, &mail_firewall_ports(ports)).await;
    let text = firewall_step_text(outcome)?;
    let _ = sink.step(text).await;
    Ok(())
}

// ─────────────────────────── Mailu ───────────────────────────

/// Mailu's install steps — a port of `MailuService.setupSteps`, plumbed
/// through the same shape every other engine in this file uses. Unlike
/// mailcow, Mailu is a compose project this crate authors itself (see
/// `mail::mailu`'s own doc), so `compose_pull_args`/`compose_up_args`/
/// `run_docker_streaming` are the same helpers every OTHER service's
/// install already calls — mail is different here only in what happens
/// AFTER `up -d`: firewall ports (fatal, same as docker-mailserver), a
/// cert-sync timer and DKIM-dump wrapper (same shape as
/// docker-mailserver's own, over Mailu's constants), and a domain/DKIM
/// import over the stack's own CLI instead of a REST API.
async fn install_mailu_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.mailu_path);

    let _ = sink.step("creating service directories").await;
    for path in mailu::directories_0755(input) {
        create_dir_with_mode(&PathBuf::from(&path), 0o755).map_err(|err| format!("could not create {path}: {err}"))?;
    }
    // 0700: private keys, the admin database and the DKIM keys — the
    // containers run as their own uids and no host account needs to read
    // them.
    for path in mailu::directories_0700(input) {
        create_dir_with_mode(&PathBuf::from(&path), 0o700).map_err(|err| format!("could not create {path}: {err}"))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, mailu::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &mailu::env_template(input)) {
        Ok(true) => {
            let _ = sink.step("generated Mailu's secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Mailu images").await;
    run_docker_streaming(&compose_pull_args(mailu::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Mailu").await;
    compose_up(mailu::COMPOSE_PROJECT, &dir, sink).await?;

    // Same rule as docker-mailserver: fail fast, before the five-minute
    // readiness wait, rather than after it.
    open_mail_firewall_ports(MAILU_FIREWALL_LABEL, &mailu::firewall_ports(), sink).await?;

    install_cert_sync_unit(&mailu_cert_sync_files(input), mailu::CERT_SYNC_SCRIPT_PATH, mailu::CERT_SYNC_UNIT, sink)
        .await?;
    write_managed_files(&mailu_management_files(input))?;

    configure_mailu(input, sink).await;

    write_caddy_site(&mailu::caddy_site_names(input), &mailu::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// `docker compose -p mailu -f <dir>/docker-compose.yml exec -T -u mailu
/// admin <argv…>` — Mailu's compose file names no `container_name:` for
/// `admin` (unlike docker-mailserver's fixed `mailserver`), so the container
/// has to be reached by SERVICE name through compose, not `docker exec
/// <container>` directly.
///
/// `-u` is load-bearing, not hardening: without it the exec lands as root,
/// and a root Mailu CLI call CREATES `/data/main.db` ahead of the engine's
/// own `flask db upgrade`, leaving a database the engine can never write its
/// schema into. See `mailu::ADMIN_RUN_AS_USER` for the measurement.
fn mailu_admin_exec_args(dir: &Path, argv: &[&str]) -> Vec<String> {
    let mut args = compose_file_args(mailu::COMPOSE_PROJECT, dir);
    args.push("exec".to_string());
    args.push("-T".to_string());
    args.push("-u".to_string());
    args.push(mailu::ADMIN_RUN_AS_USER.to_string());
    args.push(mailu::ADMIN_SERVICE.to_string());
    args.extend(argv.iter().map(|a| a.to_string()));
    args
}

/// Wait for the stack (a DEADLINE, not a try count — see
/// `MAILU_READY_DEADLINE_SECS`), then import every mail domain with
/// `-generate-` DKIM keys. Nothing here is fatal and no output is
/// discarded — the same rule the mailcow API and Nextcloud `occ` blocks
/// follow: a failure here is fixable from the admin UI afterwards, not a
/// reason to abort the rest of the install.
async fn configure_mailu(input: &Input, sink: &EventSink) {
    let dir = PathBuf::from(&input.mailu_path);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(MAILU_READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut last_why = String::new();
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        match run_docker_captured(
            &mailu_admin_exec_args(&dir, mailu::CONFIG_EXPORT_PROBE_ARGS),
            Duration::from_secs(MAILU_EXEC_TIMEOUT_SECS),
        )
        .await
        {
            Ok(run) if run.success => {
                ready = true;
                break;
            }
            Ok(run) => last_why = bounded(&format!("{}{}", run.stdout, run.stderr), 300),
            Err(err) => last_why = err,
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("Mailu: waiting for the stack to answer ({last_why})")).await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    if !ready {
        let _ = sink
            .step(format!("Mailu never answered — no mail domains or DKIM keys were imported ({last_why})"))
            .await;
        return;
    }

    let yaml = mailu::domain_import_yaml(input);
    let args = mailu_admin_exec_args(&dir, mailu::CONFIG_IMPORT_ARGS);
    match run_docker_with_stdin(&args, &yaml, Duration::from_secs(MAILU_IMPORT_TIMEOUT_SECS)).await {
        Ok(run) if run.success => {
            let _ = sink.step("imported the mail domains and minted their DKIM keys").await;
        }
        Ok(run) => {
            let _ = sink
                .step(format!("Mailu: could not import the mail domains ({})", bounded(&format!("{}{}", run.stdout, run.stderr), 300)))
                .await;
        }
        Err(err) => {
            let _ = sink.step(format!("Mailu: could not import the mail domains ({err})")).await;
        }
    }
}

// ─────────────────────────── mailcow ───────────────────────────

/// mailcow's install steps — an orchestration of mailcow's OWN installer
/// (`git clone` + `generate_config.sh` + its HTTPS REST API), not a compose
/// project this crate authors: see the `mail::mailcow` module doc for why,
/// and for why `git`/`bash`/`curl` are spawned directly here rather than a
/// Rust TLS client.
///
/// **Unlike every other engine's install, this one does NOT
/// `create_dir_all` its own directory first.** `git clone <url> <path>`
/// creates the destination itself (and REFUSES to clone into an existing
/// non-empty one) — creating it ahead of time would only add a way to make
/// that refusal happen on a perfectly good fresh host.
///
/// Order mirrors `setupSteps` exactly where mailcow's OWN installer imposes
/// it (clone → generate_config.sh's one-time sed patches → the
/// `DOCKER_COMPOSE_VERSION` fix-up that runs on EVERY install → permissions
/// → pull/up with retry → API provisioning), with the same two additions
/// every other engine's agent install makes that `setupSteps` itself does
/// not: opening the firewall ports through the drop-in mechanism (fatal,
/// same as docker-mailserver), and writing the Caddy site through
/// `write_caddy_site`/`reload_caddy` instead of the SSH path's
/// `writeCaddyfile`.
async fn install_mailcow_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.mailcow_path);
    let conf_path = PathBuf::from(mailcow::mailcow_conf_path(input));

    if !dir.join(".git").is_dir() {
        let _ = sink.step("cloning mailcow").await;
        run_child_streaming(
            &git_bin(),
            &["clone".to_string(), mailcow::REPO_URL.to_string(), dir.to_string_lossy().to_string()],
            None,
            &[],
            None,
            Duration::from_secs(MAILCOW_GIT_CLONE_TIMEOUT_SECS),
            sink,
        )
        .await?;
    }

    if !conf_path.is_file() {
        let _ = sink.step("generating mailcow's configuration").await;
        let env = mailcow::generate_config_env(input);
        run_child_streaming(
            &bash_bin(),
            &["generate_config.sh".to_string()],
            Some(&dir),
            &env,
            Some(mailcow::GENERATE_CONFIG_STDIN),
            Duration::from_secs(MAILCOW_GENERATE_CONFIG_TIMEOUT_SECS),
            sink,
        )
        .await?;

        let conf = std::fs::read_to_string(&conf_path)
            .map_err(|err| format!("could not read {} after generate_config.sh: {err}", conf_path.display()))?;
        std::fs::write(&conf_path, mailcow::patch_conf_for_caddy(&conf))
            .map_err(|err| format!("could not write {}: {err}", conf_path.display()))?;
    }

    // Runs on EVERY install, not just a fresh one — see the function's own
    // doc on why an ABSENT key (not a wrong one) is the failure mode this
    // guards against.
    {
        let conf = std::fs::read_to_string(&conf_path)
            .map_err(|err| format!("could not read {}: {err}", conf_path.display()))?;
        let patched = mailcow::patch_conf_compose_version(&conf);
        if patched != conf {
            std::fs::write(&conf_path, patched).map_err(|err| format!("could not write {}: {err}", conf_path.display()))?;
        }
    }

    // A clone made under a tight umask stays broken forever without this:
    // mailcow's containers drop to their own users and mount this tree, so
    // root-only modes make the worker fail to even traverse the checkout.
    // `mailcow.conf` holds the database passwords, so it is pulled back to
    // 0600 immediately after.
    chmod_recursive_a_plus_rx(&dir).map_err(|err| format!("could not fix up permissions under {}: {err}", dir.display()))?;
    set_mode(&conf_path, 0o600).map_err(|err| format!("could not set the mode of {}: {err}", conf_path.display()))?;

    let _ = sink.step("pulling the Mailcow images").await;
    run_mailcow_compose_retrying(&dir, &["compose".to_string(), "pull".to_string(), "-q".to_string()], 4, sink).await?;
    let _ = sink.step("starting Mailcow").await;
    run_mailcow_compose_retrying(&dir, &["compose".to_string(), "up".to_string(), "-d".to_string()], 2, sink).await?;

    open_mail_firewall_ports(MAILCOW_FIREWALL_LABEL, &mailcow::firewall_ports(), sink).await?;

    install_cert_sync_unit(
        &mailcow_cert_sync_files(input),
        mailcow::CERT_SYNC_SCRIPT_PATH,
        mailcow::CERT_SYNC_UNIT,
        sink,
    )
    .await?;
    write_managed_files(&mailcow_management_files(input))?;

    provision_mailcow(input, &dir, sink).await;

    write_caddy_site(&mailcow::caddy_site_names(input), &mailcow::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// `docker compose <args…>` from mailcow's OWN checkout directory —
/// deliberately WITHOUT `-f`, unlike every other engine's compose calls in
/// this file. mailcow's `generate_config.sh` can write more than one
/// compose file into that directory (an override alongside the base
/// `docker-compose.yml`), and compose only picks up an override by
/// discovering it in the CURRENT DIRECTORY — pinning `-f` to one file would
/// silently drop whatever mailcow itself decided to add. `current_dir` is
/// what stands in for the bash version's `cd`.
///
/// Ported from `setupSteps`'s own `retry` helper: `tries` attempts, linear
/// backoff `5 * attempt` seconds between them — fresh servers pull many
/// large images at once (mailcow alone is roughly fifteen), and a single
/// transient registry timeout must not abort the whole install.
async fn run_mailcow_compose_retrying(dir: &Path, args: &[String], tries: u32, sink: &EventSink) -> Result<(), String> {
    for attempt in 1..=tries {
        match run_child_streaming(&docker_bin(), args, Some(dir), &[], None, Duration::from_secs(MAILCOW_COMPOSE_TIMEOUT_SECS), sink)
            .await
        {
            Ok(()) => return Ok(()),
            Err(err) if attempt < tries => {
                let _ = sink
                    .step(format!("mailcow: `docker {}` failed, retrying ({attempt}/{tries}): {err}", args.join(" ")))
                    .await;
                tokio::time::sleep(Duration::from_secs(5 * u64::from(attempt))).await;
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("the loop above always returns before `attempt` reaches `tries`")
}

/// `chmod -R a+rX <root>` — a pure filesystem walk rather than a spawned
/// `chmod`, ported to Rust's own `a+rX` semantics: every entry gets read
/// added for all three classes, and execute is added for all three classes
/// ONLY on a directory or a file that already has execute set for AT LEAST
/// ONE class (capital `X`, as opposed to lowercase `x`, which would make
/// every plain data file executable). Symlinks are left alone — `chmod -R`
/// does not follow them for the mode of the link itself either.
fn chmod_recursive_a_plus_rx(root: &Path) -> Result<(), String> {
    fn visit(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Ok(());
        }
        let is_dir = meta.is_dir();
        let mut mode = meta.permissions().mode() & 0o7777;
        mode |= 0o444;
        if is_dir || (mode & 0o111) != 0 {
            mode |= 0o111;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        if is_dir {
            for entry in std::fs::read_dir(path)? {
                visit(&entry?.path())?;
            }
        }
        Ok(())
    }
    visit(root).map_err(|err| err.to_string())
}

/// Every mail domain: an `add/domain` and an `add/dkim` call each, both
/// idempotent (created only when missing, same as `setupSteps`) — first the
/// deadlined wait for the API itself (a DEADLINE, not a try count, see
/// `MAILCOW_API_DEADLINE_SECS`; each attempt can burn its own
/// `--max-time 20`, which is the exact bug GOTCHAS.md records for a
/// try-count version of this wait). Nothing here is fatal and no output is
/// discarded — the same rule Nextcloud's `occ` block and Mailu's own
/// `configure_mailu` follow.
async fn provision_mailcow(input: &Input, dir: &Path, sink: &EventSink) {
    let conf_path = PathBuf::from(mailcow::mailcow_conf_path(input));
    let conf = match std::fs::read_to_string(&conf_path) {
        Ok(text) => text,
        Err(err) => {
            let _ = sink
                .step(format!("Mailcow: could not read mailcow.conf — no domains or DKIM keys were provisioned ({err})"))
                .await;
            return;
        }
    };

    if !mailcow::api_key_present(&conf) {
        let _ = sink.step("enabling the Mailcow REST API").await;
        let network_prefix = mailcow::ipv4_network_prefix(&conf).unwrap_or_else(|| mailcow::DEFAULT_NETWORK_PREFIX.to_string());
        let api_key = match random_hex_20() {
            Ok(key) => key,
            Err(err) => {
                let _ = sink.step(format!("Mailcow: could not generate an API key ({err})")).await;
                return;
            }
        };
        let appended = mailcow::api_conf_append(&api_key, &network_prefix);
        let append_result = {
            use std::io::Write as _;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&conf_path)
                .and_then(|mut file| file.write_all(appended.as_bytes()))
        };
        if let Err(err) = append_result {
            let _ = sink.step(format!("Mailcow: could not write the API key to mailcow.conf ({err})")).await;
            return;
        }
        // The php container reads its environment from mailcow.conf only at
        // start, so the new key does not take effect until it is recreated.
        if let Err(err) =
            run_mailcow_compose_retrying(dir, &["compose".to_string(), "up".to_string(), "-d".to_string()], 1, sink).await
        {
            let _ = sink.step(format!("Mailcow: could not reload the stack after adding the API key ({err})")).await;
            return;
        }
    }

    let conf = match std::fs::read_to_string(&conf_path) {
        Ok(text) => text,
        Err(err) => {
            let _ = sink.step(format!("Mailcow: could not re-read mailcow.conf ({err})")).await;
            return;
        }
    };
    let Some(api_key) = mailcow::read_conf_value(&conf, "API_KEY") else {
        let _ = sink.step("Mailcow: no API key on file — no domains or DKIM keys were provisioned").await;
        return;
    };

    let _ = sink.step("provisioning mail domains").await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(MAILCOW_API_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut ready = false;
    let mut last_why = String::new();
    while tokio::time::Instant::now() < deadline {
        match mailcow_api_call("GET", "/get/domain/all", &api_key, None).await {
            Ok((code, _)) if (200..300).contains(&code) => {
                ready = true;
                break;
            }
            Ok((code, body)) => last_why = mailcow_why(code, &body),
            Err(err) => last_why = err,
        }
        attempt += 1;
        if attempt % MAILCOW_API_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("Mailcow: waiting for the API to answer ({last_why})")).await;
        }
        tokio::time::sleep(Duration::from_secs(MAILCOW_API_POLL_INTERVAL_SECS)).await;
    }
    if !ready {
        let _ = sink
            .step(format!("Mailcow: the API never answered — no domains or DKIM keys were provisioned ({last_why})"))
            .await;
        return;
    }

    for domain in mailcow::mail_domains(input) {
        let has_domain = matches!(
            mailcow_api_call("GET", &format!("/get/domain/{domain}"), &api_key, None).await,
            Ok((code, body)) if (200..300).contains(&code) && mailcow_json_has_field(&body, "domain_name")
        );
        if !has_domain {
            match mailcow_api_call("POST", "/add/domain", &api_key, Some(&mailcow::add_domain_body(&domain))).await {
                Ok((code, _)) if (200..300).contains(&code) => {
                    let _ = sink.step(format!("added the mail domain {domain}")).await;
                }
                Ok((code, body)) => {
                    let _ = sink
                        .step(format!(
                            "Mailcow: could not add the domain {domain} over the API — add it under Configuration → Domains in the admin UI. ({})",
                            mailcow_why(code, &body)
                        ))
                        .await;
                }
                Err(err) => {
                    let _ = sink
                        .step(format!(
                            "Mailcow: could not add the domain {domain} over the API — add it under Configuration → Domains in the admin UI. ({err})"
                        ))
                        .await;
                }
            }
        }

        let has_dkim = matches!(
            mailcow_api_call("GET", &format!("/get/dkim/{domain}"), &api_key, None).await,
            Ok((code, body)) if (200..300).contains(&code) && mailcow_json_has_field(&body, "pubkey")
        );
        if !has_dkim {
            match mailcow_api_call("POST", "/add/dkim", &api_key, Some(&mailcow::add_dkim_body(&domain))).await {
                Ok((code, _)) if (200..300).contains(&code) => {
                    let _ = sink.step(format!("generated the DKIM key for {domain}")).await;
                }
                Ok((code, body)) => {
                    let _ = sink
                        .step(format!(
                            "Mailcow: could not create the DKIM key for {domain} over the API — create it under Configuration → ARC/DKIM keys in the admin UI. ({})",
                            mailcow_why(code, &body)
                        ))
                        .await;
                }
                Err(err) => {
                    let _ = sink
                        .step(format!(
                            "Mailcow: could not create the DKIM key for {domain} over the API — create it under Configuration → ARC/DKIM keys in the admin UI. ({err})"
                        ))
                        .await;
                }
            }
        }
    }
}

/// Does the parsed JSON body have `field` set to something other than
/// `null`/`false`? The Rust equivalent of `jq -e '.field'`'s own exit-code
/// rule, which is what `setupSteps` uses to decide "does this domain/DKIM
/// key already exist" — an unparsable body (mailcow's own error responses
/// are not always JSON) answers `false`, the same as `jq -e` failing to
/// parse its input.
fn mailcow_json_has_field(body: &str, field: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get(field).cloned())
        .map(|value| !value.is_null() && value != serde_json::Value::Bool(false))
        .unwrap_or(false)
}

/// `HTTP <code> <300 chars of body, CR/LF stripped>` — the Rust port of
/// `mc_why()`'s exact shape, used everywhere a mailcow API call's failure
/// needs to be reported without flooding the streamed log.
fn mailcow_why(code: u16, body: &str) -> String {
    format!("HTTP {code} {}", bounded(&body.replace(['\r', '\n'], ""), 300))
}

/// One call to mailcow's REST API. `curl`, spawned directly (see the
/// `mail::mailcow` module doc for why this crate has no Rust TLS client to
/// call instead) — never `-f`: GOTCHAS.md's mailcow API section is explicit
/// that `-f` discards the body, which is the only explanation a failure
/// ever carries, and a bare non-2xx exit under `set -e` used to kill the
/// entire install and the install-key revocation with it. Status and body
/// are both ALWAYS returned; the caller decides what counts as success,
/// mirroring `mc_api`'s own `$MC_CODE -ge 200 -lt 300` check rather than
/// baking a verdict in here.
async fn mailcow_api_call(method: &str, path: &str, api_key: &str, body: Option<&str>) -> Result<(u16, String), String> {
    let url = format!("{}{path}", mailcow::api_base());
    let mut args: Vec<String> = vec![
        "-sS".to_string(),
        "-k".to_string(),
        "--max-time".to_string(),
        MAILCOW_API_HTTP_TIMEOUT_SECS.to_string(),
        // The status code is appended AFTER the body on stdout, separated by
        // a newline this crate's own marker (not curl's) introduces — the
        // bash version writes the body to a file and the status to a
        // variable via `-o`/`-w` together; this port has no file to hand
        // curl that a concurrent call could collide on, so both travel on
        // stdout instead.
        "-w".to_string(),
        "\nHTTPSTATUS:%{http_code}".to_string(),
        "-H".to_string(),
        format!("X-API-Key: {api_key}"),
        "-H".to_string(),
        "Content-Type: application/json".to_string(),
    ];
    if method == "POST" {
        args.push("-X".to_string());
        args.push("POST".to_string());
    }
    if let Some(body) = body {
        args.push("-d".to_string());
        args.push(body.to_string());
    }
    args.push(url);

    let output = tokio::time::timeout(
        Duration::from_secs(MAILCOW_API_HTTP_TIMEOUT_SECS + 5),
        tokio::process::Command::new(curl_bin()).args(&args).stdin(Stdio::null()).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| "curl timed out".to_string())?
    .map_err(|err| format!("could not run curl: {err}"))?;

    if !output.status.success() {
        // curl itself failing (not connect refused, TLS handshake, DNS —
        // those are 2xx/4xx/5xx HTTP outcomes curl reports normally) means
        // no HTTP exchange happened at all; there is no status/body to
        // parse.
        return Err(format!("curl exited {}: {}", output.status.code().unwrap_or(-1), bounded(&String::from_utf8_lossy(&output.stderr), 300)));
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let marker = "\nHTTPSTATUS:";
    let Some(at) = text.rfind(marker) else {
        return Err("curl did not report a status code".to_string());
    };
    let body_text = text[..at].to_string();
    let code: u16 = text[at + marker.len()..].trim().parse().unwrap_or(0);
    Ok((code, body_text))
}

/// Overridable through the environment for tests, the same technique
/// `docker_bin`/`systemctl_bin` use — a test points this at a stub script
/// that records its own argv; a server never sets it.
fn openssl_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_INSTALL_OPENSSL_BIN").unwrap_or_else(|_| "openssl".to_string()))
}

/// Is this a file with something in it? The bash guard is `[ ! -s <path> ]` on
/// BOTH halves of the pair, so a zero-length leftover counts as missing — a
/// half-written certificate is exactly as unusable as no certificate, and
/// `openssl` truncates its output file before it fails.
fn is_nonempty_file(path: &Path) -> bool {
    std::fs::metadata(path).map(|meta| meta.is_file() && meta.len() > 0).unwrap_or(false)
}

/// The self-signed placeholder certificate, created only when the pair is not
/// already there — so the real certificate the sync timer copied in survives
/// every re-run.
async fn write_placeholder_cert(input: &Input, sink: &EventSink) {
    let cert = PathBuf::from(dms::cert_pem_path(input));
    let key = PathBuf::from(dms::key_pem_path(input));
    if is_nonempty_file(&cert) && is_nonempty_file(&key) {
        return;
    }

    let _ = sink.step("writing a self-signed placeholder certificate so the engine can start").await;
    let args = dms::placeholder_cert_args(input);
    let outcome = tokio::time::timeout(
        Duration::from_secs(OPENSSL_TIMEOUT_SECS),
        tokio::process::Command::new(openssl_bin())
            .args(&args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let failed = match outcome {
        Ok(Ok(output)) if output.status.success() => None,
        Ok(Ok(output)) => Some(why(&String::from_utf8_lossy(&output.stderr))),
        Ok(Err(err)) => Some(err.to_string()),
        Err(_) => Some(format!("openssl timed out after {OPENSSL_TIMEOUT_SECS}s")),
    };
    if let Some(reason) = failed {
        let _ = sink
            .step(format!(
                "could not write the placeholder certificate — the mail engine will keep restarting until one exists ({reason})"
            ))
            .await;
        return;
    }
    // The key is the private half; the certificate is public. Modes spelled
    // out at the point of creation rather than left to the umask, the same
    // rule every secret in this module follows.
    if let Err(err) = set_mode(&cert, 0o644) {
        let _ = sink.step(format!("could not set the mode of {}: {err}", cert.display())).await;
    }
    if let Err(err) = set_mode(&key, 0o600) {
        let _ = sink.step(format!("could not set the mode of {}: {err}", key.display())).await;
    }
}

/// The certificate-sync script, its two systemd units, and the timer that runs
/// them — a port of `DockerMailserverService.certSyncStep`.
///
/// **Without this the placeholder certificate is the FINAL state of the
/// install.** Caddy holds the ACME account for `mail.<domain>` (one process
/// per name, or two ACME clients race each other into Let's Encrypt's failure
/// quota), so the engine has to be HANDED the certificate; Roundcube verifies
/// the peer name and the CA, so on the placeholder alone webmail cannot log in
/// at all, and every mail client sees an untrusted certificate for ever.
///
/// The file writes are fatal (the bash version runs them under `set -e`); the
/// `systemctl` calls and the immediate run are not (`|| true` there, and a
/// timer that could not be enabled is a degraded install, not a failed one).
///
/// **This is the first install slice that writes under
/// `/etc/systemd/system`** — already inside the agent unit's
/// `ReadWritePaths` since 0.0.12, which is why no unit change is needed. The
/// rule GOTCHAS.md states is to CHECK that list on every new write under
/// `/etc`, not to assume it, and this is that check: `/etc/gryonixnexus`,
/// `/etc/systemd/system` and `/etc/caddy` are all it covers, and this slice
/// needs the second and third of those.
async fn install_cert_sync(input: &Input, sink: &EventSink) -> Result<(), String> {
    install_cert_sync_unit(&cert_sync_files(input), dms::CERT_SYNC_SCRIPT_PATH, dms::CERT_SYNC_UNIT, sink).await
}

/// The general shape `install_cert_sync` (docker-mailserver) follows,
/// parameterized over which files/script/timer — mailcow's and Mailu's own
/// cert-sync installs (`install_mailcow_cert_sync`/`install_mailu_cert_sync`)
/// call this directly rather than duplicating the systemd dance a third and
/// fourth time; DMS's own call site is untouched (same files, same paths,
/// same behavior — this is a name split, not a behavior change).
async fn install_cert_sync_unit(
    files: &[ManagedFile],
    script_path: &str,
    timer_unit: &str,
    sink: &EventSink,
) -> Result<(), String> {
    write_managed_files(files)?;

    let _ = sink.step("installing the certificate-sync timer").await;
    if run_quiet(&systemctl_bin(), &["daemon-reload"]).await.is_err() {
        let _ = sink.step("systemctl daemon-reload failed — the certificate-sync timer may not be active").await;
    }
    let timer = format!("{timer_unit}.timer");
    if run_quiet(&systemctl_bin(), &["enable", "--now", &timer]).await.is_err() {
        let _ = sink
            .step("could not enable the certificate-sync timer — mail clients will keep seeing the placeholder certificate")
            .await;
    }
    // Once, right now: on a fresh host Caddy has no certificate yet and the
    // script exits 0 having done nothing, but on a REINSTALL the real
    // certificate is already on disk and this is what puts it back in front of
    // the engine without waiting for the timer.
    let ran = tokio::time::timeout(
        Duration::from_secs(CERT_SYNC_RUN_TIMEOUT_SECS),
        tokio::process::Command::new(script_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await;
    if !matches!(ran, Ok(Ok(status)) if status.success()) {
        let _ = sink.step("the first certificate-sync run did not succeed — the timer will retry within the hour").await;
    }
    Ok(())
}

/// One file this install owns outside the service directory: where it goes,
/// what is in it, and the mode it must end up with (`None` leaves the default,
/// which is what the bash version's plain `cat >` does for the two unit
/// files).
///
/// The list is a VALUE rather than a sequence of writes so the decisions —
/// which files, at which paths, with which modes — can be pinned by a test on
/// a machine that is not root and has no `/etc/systemd/system` to write into.
/// The writing itself (`write_managed_files`) is three lines with nothing to
/// decide.
struct ManagedFile {
    path: PathBuf,
    contents: String,
    mode: Option<u32>,
}

/// The certificate-sync script and its two systemd units. Rewritten every run:
/// identical content is idempotent on its own, and a changed domain or install
/// path has to reach them.
fn cert_sync_files(input: &Input) -> Vec<ManagedFile> {
    let unit_dir = Path::new("/etc/systemd/system");
    vec![
        ManagedFile {
            path: PathBuf::from(dms::CERT_SYNC_SCRIPT_PATH),
            contents: dms::cert_sync_script(input),
            // Root-only and executable: it is run by systemd as root and it
            // copies a private key.
            mode: Some(0o700),
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.service", dms::CERT_SYNC_UNIT)),
            contents: dms::cert_sync_service_unit(),
            mode: None,
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.timer", dms::CERT_SYNC_UNIT)),
            contents: dms::cert_sync_timer_unit(),
            mode: None,
        },
    ]
}

/// The management wrappers this install writes — exactly one, and which one is
/// the decision worth pinning: see `write_dms_management_scripts`.
fn dms_management_files(input: &Input) -> Vec<ManagedFile> {
    vec![ManagedFile {
        path: PathBuf::from(dms::DKIM_DUMP_SCRIPT_PATH),
        contents: dms::dkim_dump_script(input),
        mode: Some(0o700),
    }]
}

/// Mailu's cert-sync script and its two systemd units — the same shape
/// `cert_sync_files` (docker-mailserver's) has, over `mail::mailu`'s own
/// constants/content instead.
fn mailu_cert_sync_files(input: &Input) -> Vec<ManagedFile> {
    let unit_dir = Path::new("/etc/systemd/system");
    vec![
        ManagedFile {
            path: PathBuf::from(mailu::CERT_SYNC_SCRIPT_PATH),
            contents: mailu::cert_sync_script(input),
            mode: Some(0o700),
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.service", mailu::CERT_SYNC_UNIT)),
            contents: mailu::cert_sync_service_unit(),
            mode: None,
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.timer", mailu::CERT_SYNC_UNIT)),
            contents: mailu::cert_sync_timer_unit(),
            mode: None,
        },
    ]
}

/// Mailu's DKIM-dump wrapper — the reason it has to be written is the same
/// as docker-mailserver's: `dkim.rs`'s engine table already runs
/// `/opt/gryonixnexus-mailu-dkim.sh` (its `wrapper_default` for the `"mailu"`
/// entry), so an install that skipped writing it would leave `GetDkimRecords`
/// answering "the wrapper is not installed" for ever on an agent-installed
/// host.
fn mailu_management_files(input: &Input) -> Vec<ManagedFile> {
    vec![ManagedFile {
        path: PathBuf::from(mailu::DKIM_DUMP_SCRIPT_PATH),
        contents: mailu::dkim_dump_script(input),
        mode: Some(0o700),
    }]
}

/// mailcow's cert-sync script and its two systemd units — the same shape
/// `cert_sync_files` has, over `mail::mailcow`'s own constants/content.
fn mailcow_cert_sync_files(input: &Input) -> Vec<ManagedFile> {
    let unit_dir = Path::new("/etc/systemd/system");
    vec![
        ManagedFile {
            path: PathBuf::from(mailcow::CERT_SYNC_SCRIPT_PATH),
            contents: mailcow::cert_sync_script(input),
            mode: Some(0o700),
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.service", mailcow::CERT_SYNC_UNIT)),
            contents: mailcow::cert_sync_service_unit(),
            mode: None,
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.timer", mailcow::CERT_SYNC_UNIT)),
            contents: mailcow::cert_sync_timer_unit(),
            mode: None,
        },
    ]
}

/// mailcow's DKIM-dump wrapper — `dkim.rs`'s engine table runs
/// `/opt/gryonixnexus-dkim.sh` (its `wrapper_default` for the `"mailcow"`
/// entry) for the same reason the other two engines' wrappers are written.
fn mailcow_management_files(input: &Input) -> Vec<ManagedFile> {
    vec![ManagedFile {
        path: PathBuf::from(mailcow::DKIM_DUMP_SCRIPT_PATH),
        contents: mailcow::dkim_dump_script(input),
        mode: Some(0o700),
    }]
}

fn write_managed_files(files: &[ManagedFile]) -> Result<(), String> {
    for file in files {
        std::fs::write(&file.path, &file.contents)
            .map_err(|err| format!("could not write {}: {err}", file.path.display()))?;
        if let Some(mode) = file.mode {
            set_mode(&file.path, mode)
                .map_err(|err| format!("could not set the mode of {}: {err}", file.path.display()))?;
        }
    }
    Ok(())
}

/// The root-owned management wrapper this install writes — and the one it
/// deliberately does not.
///
/// **The DKIM-dump wrapper IS written**, because another module of this same
/// agent already runs exactly that path: `dkim.rs`'s engine table names
/// `/opt/gryonixnexus-dms-dkim.sh` and executes it directly (the agent is root,
/// so no sudoers line is involved). Without it, `GetDkimRecords` on a host
/// installed through the agent would answer "the wrapper is not installed" for
/// ever, and the user would have no way to learn the DKIM record they must
/// publish — which is not cosmetic: unsigned mail from a new IP is mail that
/// does not arrive. This gap is the round's own finding, and it is exactly the
/// shape of the ones `psono`/`seafile` already cost this project: two halves of
/// the agent that each look complete on their own.
///
/// **The mailbox wrapper is NOT written**, for the reason
/// `install_jellyfin_steps` gives about `gryonixnexus-update.sh`: nothing on this
/// path can reach it. The SSH route calls it as
/// `sudo /opt/gryonixnexus-dms-mailbox.sh`, and the sudoers line that permits
/// that is provisioned by the setup script this install path replaces and does
/// not run — a file without its whitelist entry is a file nothing can execute.
/// The agent's own route does not want it either: `mailbox.rs` reimplements
/// that wrapper one-for-one (password on stdin, its own address check, the
/// `del`-after-`add` retry, ANSI stripping, stdout-only parsing) and is
/// live-verified in that shape. Writing an unreachable copy of it would add a
/// second source of truth for the same rules.
fn write_dms_management_scripts(input: &Input, _sink: &EventSink) -> Result<(), String> {
    write_managed_files(&dms_management_files(input))
}

/// Wait for the engine, then create the first mailbox and one DKIM key per
/// mail domain. Nothing here is fatal and no output is discarded.
async fn configure_dms(input: &Input, sink: &EventSink) {
    // A DEADLINE, not a try count — see `DMS_READY_DEADLINE_SECS`.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(DMS_READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut probe = (false, String::new());
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        probe = dms_exec(dms::READINESS_PROBE_ARGS).await;
        if probe.0 {
            ready = true;
            break;
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("Docker Mailserver: waiting for the engine to answer ({})", why(&probe.1))).await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    if !ready {
        let _ = sink
            .step(format!(
                "Docker Mailserver never answered — no mailbox and no DKIM keys were created ({})",
                why(&probe.1)
            ))
            .await;
        return;
    }

    create_first_mailbox(input, sink).await;

    // One key per mail domain. Idempotent inside the engine: a domain that
    // already has a key is skipped, so a re-run adds keys for domains added
    // since and leaves the rest alone.
    for domain in dms::mail_domains(input) {
        let argv = dms::dkim_config_args(&domain);
        let (ok, output) = dms_exec(&borrowed(&argv)).await;
        if ok {
            let _ = sink.step(format!("generated the DKIM key for {domain}")).await;
        } else {
            let _ = sink
                .step(format!("Docker Mailserver: could not generate the DKIM key for {domain} ({})", why(&output)))
                .await;
        }
    }

    stop_rspamd_reducing_the_signing_domain(input, sink).await;
}

/// The edit itself, as a pure function so it is testable without a container.
/// `None` means "nothing to change", which is also what an already-fixed file
/// must produce: this step runs on every re-install and a needless rewrite
/// would restart rspamd for nothing.
fn dkim_signing_without_esld(current: &str) -> Option<String> {
    if !current.contains("use_esld = true;") {
        return None;
    }
    Some(current.replace("use_esld = true;", "use_esld = false;"))
}

/// **Without this the engine signs NOTHING on a subdomain, and says so
/// nowhere.**
///
/// `setup config dkim` writes rspamd's `dkim_signing.conf` with
/// `use_esld = true`, which reduces the signing domain to the effective
/// second-level domain BEFORE looking it up in the key map — and that map is
/// keyed by the exact domain the key was minted for. A deployment on
/// `b5.example.com` therefore filed its key under `b5.example.com`, rspamd
/// asked for `example.com`, missed, and `try_fallback = false` turned the miss
/// into no signature at all.
///
/// Measured live on the scenario-B pair 2026-08-14, and the shape of the
/// evidence is why this is not a guess: the private key was on disk, the DNS
/// record was published and byte-matched it, rspamd's own config named both —
/// and an independent verifier still answered `DKIM check: none (message not
/// signed)` for a message submitted the way a real client submits, with SASL
/// auth. Flipping this one word produced `DKIM_SIGNED{b5.grypak.de:s=dkim}` in
/// rspamd's log (plus its first DNS lookup, the pubkey check) and `DKIM check:
/// pass` from the verifier; flipping it back made both disappear again.
///
/// It matters more than one authentication check: scenario B sends from the
/// home IP, so SPF fails by construction (the record authorises the relay),
/// and with DMARC at `p=quarantine` an unsigned message has NOTHING aligned.
/// DKIM is the only pass this topology can earn.
///
/// Unconditional rather than "only when the domain is a subdomain": our keys
/// are always filed under the exact domain we minted and published, so eSLD
/// reduction is never what we want, and a condition would be a second thing to
/// get wrong.
async fn stop_rspamd_reducing_the_signing_domain(input: &Input, sink: &EventSink) {
    let path = std::path::Path::new(&input.docker_mailserver_path)
        .join("config/rspamd/override.d/dkim_signing.conf");
    let Ok(current) = std::fs::read_to_string(&path) else { return };
    let Some(fixed) = dkim_signing_without_esld(&current) else { return };
    if let Err(error) = std::fs::write(&path, fixed) {
        let _ = sink
            .step(format!("Docker Mailserver: could not stop rspamd reducing the signing domain ({error})"))
            .await;
        return;
    }
    // rspamd reads this at start, so without the restart the fix would apply
    // only after the next unrelated container restart — the kind of delay that
    // makes a verified fix look like it did not work.
    let (ok, output) = dms_exec(&["supervisorctl", "restart", "rspamd"]).await;
    if ok {
        let _ = sink.step("DKIM signing now uses the full mail domain".to_string()).await;
    } else {
        let _ = sink
            .step(format!("Docker Mailserver: DKIM signing fixed, but rspamd did not restart ({})", why(&output)))
            .await;
    }
}

/// The first mailbox: the deployment's shared admin name at the primary
/// domain, with the password generated into `.env` on the first run.
///
/// **The password goes on STDIN, twice**, never in argv — `docker exec` argv is
/// world-readable through `/proc` to every account on the box, which is
/// GOTCHAS.md defect 7 and was fixed in the wrapper the same way. The helper
/// asks for it twice, so it is fed twice, and the pipe is CLOSED afterwards:
/// `docker exec -i` waits for EOF, and leaving it open hangs the call until
/// the deadline in a way that reads as a stuck engine.
async fn create_first_mailbox(input: &Input, sink: &EventSink) {
    let address = dms::admin_mailbox(input);

    // The listing is read from STDOUT ONLY. `setup email list` writes
    // `doveadm(<address>): Error: User doesn't exist` to STDERR for an account
    // Dovecot cannot resolve, and that line contains a real address — merging
    // the two streams here would let it answer "the mailbox already exists"
    // and skip creating the only account this install has. `mailbox.rs` holds
    // the same rule for the same reason. Its own failure is the answer "there
    // are no accounts yet" (the account file does not exist until the first
    // one is added), so it is never treated as an error.
    let listing = match dms_exec_captured(dms::LIST_MAILBOXES_ARGS).await {
        Ok(run) => strip_ansi(&run.stdout),
        Err(_) => String::new(),
    };
    if mailbox_listed(&listing, &address) {
        let _ = sink.step(format!("the mailbox {address} already exists")).await;
        return;
    }

    let env_path = PathBuf::from(&input.docker_mailserver_path).join(".env");
    let Some(password) = read_env_value(&env_path, dms::FIRST_MAILBOX_PASSWORD_KEY) else {
        let _ = sink.step("Docker Mailserver: no first-mailbox password on file — the mailbox was not created").await;
        return;
    };
    if password.is_empty() {
        let _ = sink.step("Docker Mailserver: the first-mailbox password is empty — the mailbox was not created").await;
        return;
    }

    let argv = dms::add_mailbox_args(&address);
    // Twice: the helper prompts for the password and then for its
    // confirmation.
    let stdin = format!("{password}\n{password}\n");
    match dms_exec_with_stdin(&borrowed(&argv), &stdin).await {
        Ok(run) if run.success => {
            let _ = sink.step(format!("created the mailbox {address}")).await;
        }
        Ok(run) => {
            let _ = sink.step(format!("Docker Mailserver: could not create {address} ({})", dms_why(&run))).await;
        }
        Err(err) => {
            let _ = sink.step(format!("Docker Mailserver: could not create {address} ({err})")).await;
        }
    }
}

/// `Vec<String>` → the `&[&str]` every argv helper here takes. One place, so
/// no call site grows its own collect.
fn borrowed(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// One command in the mail container, output CAPTURED and ANSI-stripped.
///
/// **The engine colours its OWN errors** (`\e[1;31mERROR\e[0m`), and those
/// errors are the only explanation a user ever gets, so every path out of this
/// engine — not just the listing — goes through the stripper. That rule
/// covers all of DMS by GOTCHAS.md, and `mailbox.rs` already holds it.
async fn dms_exec(args: &[&str]) -> (bool, String) {
    match dms_exec_captured(args).await {
        Ok(run) => (run.success, dms_why(&run)),
        Err(err) => (false, err),
    }
}

/// The engine's own words, in the order they must be processed: STRIP the
/// colours first, then bound the length. Bounding first can cut an escape
/// sequence in half and leave the tail of it in the text a user reads.
fn dms_why(run: &CapturedRun) -> String {
    let mut combined = run.stdout.clone();
    combined.push_str(&run.stderr);
    bounded(&strip_ansi(&combined), 300)
}

async fn dms_exec_captured(args: &[&str]) -> Result<CapturedRun, String> {
    run_docker_captured(&docker_exec_args(dms::CONTAINER, args), Duration::from_secs(DMS_EXEC_TIMEOUT_SECS)).await
}

/// `docker exec -i <container> <argv…>` with `stdin_text` written and the pipe
/// CLOSED — the only channel a secret travels on here.
async fn dms_exec_with_stdin(args: &[&str], stdin_text: &str) -> Result<CapturedRun, String> {
    let mut argv = vec!["exec".to_string(), "-i".to_string(), dms::CONTAINER.to_string()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let mut child = tokio::process::Command::new(docker_bin())
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run docker: {err}"))?;

    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(stdin_text.as_bytes()).await.map_err(|err| format!("could not write the password: {err}"))?;
        // Dropped through `shutdown`, not left open: the helper waits for EOF.
        pipe.shutdown().await.map_err(|err| format!("could not close the password pipe: {err}"))?;
    }

    let output = tokio::time::timeout(Duration::from_secs(DMS_EXEC_TIMEOUT_SECS), child.wait_with_output())
        .await
        .map_err(|_| format!("docker timed out after {DMS_EXEC_TIMEOUT_SECS}s"))?
        .map_err(|err| format!("docker did not finish: {err}"))?;
    Ok(CapturedRun {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Is this address already in `setup email list`? A port of the bash
/// `grep -qE "(^|[[:space:]*])<address>([[:space:]]|$)"`, boundary for
/// boundary rather than a bare substring test.
///
/// The boundaries are the point, and the lesson is Forgejo's: the listing
/// carries more than addresses (`* user@example.com ( 6.0K / ~ ) [0%]`, plus
/// headers and, on a fresh stack, a sentence saying there are no accounts), and
/// a lookalike passing for this one would silently skip creating the ONLY
/// account the install makes — a mail server nobody can log into, with one line
/// in the log to say so. The leading `*` is accepted because it is the
/// listing's own bullet; `\r` is accepted after the address because a CRLF line
/// ending must not hide a real match.
pub fn mailbox_listed(listing: &str, address: &str) -> bool {
    if address.is_empty() {
        return false;
    }
    listing.lines().any(|line| {
        let bytes = line.as_bytes();
        line.match_indices(address).any(|(at, _)| {
            let before = at == 0 || matches!(bytes[at - 1], b' ' | b'\t' | b'*');
            let end = at + address.len();
            let after = end == bytes.len() || matches!(bytes[end], b' ' | b'\t' | b'\r');
            before && after
        })
    })
}

/// A port of the `jq` pair in `VaultwardenService.setupSteps`, condition for
/// condition. Returns whether the file was rewritten; a missing file is "no
/// change" (the compose environment still rules and needs no rewrite).
///
/// The two conditions are the ones the bash version spells as
/// `.signups_allowed == <toggle> and ((.domain // $d) == $d)`:
/// - `signups_allowed` must equal the app's toggle. ABSENT counts as
///   different (jq's `null == false` is false, `null == true` is false), so
///   a config file that never stored the key gets it written.
/// - `domain` is only compared when PRESENT and truthy — `//` is jq's
///   alternative operator, so `null`/`false` fall through to `$d` and
///   compare equal. That is deliberate: absent means the compose environment
///   still rules, but a stored value OUTRANKS it, so a reinstall onto
///   another domain would otherwise keep serving links to the old one.
/// The write mirrors the same asymmetry: `signups_allowed` is always set,
/// `domain` only `if has("domain")`.
pub fn sync_vaultwarden_config(config_path: &Path, input: &Input) -> Result<bool, String> {
    let text = match std::fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.to_string()),
    };
    let mut value: serde_json::Value = serde_json::from_str(&text).map_err(|err| err.to_string())?;
    let object = value.as_object_mut().ok_or_else(|| "config.json is not a JSON object".to_string())?;

    let desired_domain = format!("https://{}", vaultwarden::hostname(input));
    let signups_match = object.get("signups_allowed") == Some(&serde_json::Value::Bool(input.vaultwarden_allow_signups));
    let domain_match = match object.get("domain") {
        None | Some(serde_json::Value::Null) | Some(serde_json::Value::Bool(false)) => true,
        Some(stored) => stored.as_str() == Some(desired_domain.as_str()),
    };
    if signups_match && domain_match {
        return Ok(false);
    }

    object.insert("signups_allowed".to_string(), serde_json::Value::Bool(input.vaultwarden_allow_signups));
    if object.contains_key("domain") {
        object.insert("domain".to_string(), serde_json::Value::String(desired_domain));
    }
    let rendered = serde_json::to_string_pretty(&value).map_err(|err| err.to_string())?;
    std::fs::write(config_path, rendered).map_err(|err| err.to_string())?;
    // The file holds the instance's own secrets; the bash version chmods it
    // 0600 after every rewrite for the same reason.
    set_mode(config_path, 0o600).map_err(|err| err.to_string())?;
    Ok(true)
}

/// What a captured `docker` run produced. Kept separate from
/// `run_docker_streaming`'s live narration because two callers need the
/// OUTPUT itself rather than a progress feed: Psono's keypair generator
/// (whose stdout IS the file being written, so stderr must never mix into
/// it) and its `manage.py` calls (whose combined output is the only
/// explanation of why a wait is still going — the `ps_why` bash helper).
struct CapturedRun {
    success: bool,
    stdout: String,
    stderr: String,
}

impl CapturedRun {
    /// A port of `ps_why`: one bounded line of whatever the engine said.
    fn why(&self) -> String {
        let mut combined = self.stdout.clone();
        combined.push_str(&self.stderr);
        bounded(&combined, 300)
    }
}

async fn run_docker_captured(args: &[String], timeout: Duration) -> Result<CapturedRun, String> {
    let output = tokio::time::timeout(
        timeout,
        tokio::process::Command::new(docker_bin()).args(args).stdin(Stdio::null()).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| format!("docker timed out after {}s", timeout.as_secs()))?
    .map_err(|err| format!("could not run docker: {err}"))?;
    Ok(CapturedRun {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// `docker <args…>` with `stdin_text` written and the pipe CLOSED before
/// waiting for output — the general form `dms_exec_with_stdin` special-cases
/// to `docker exec -i <container>`. Used where the argv is already fully
/// built (Mailu's `compose … exec -T admin flask mailu config-import …`,
/// which pipes the domain-import YAML on stdin rather than putting it in an
/// argument — `docker exec` argv is world-readable through `/proc`, the same
/// reason every other secret-bearing call in this crate avoids it).
async fn run_docker_with_stdin(args: &[String], stdin_text: &str, timeout: Duration) -> Result<CapturedRun, String> {
    let mut child = tokio::process::Command::new(docker_bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run docker: {err}"))?;

    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(stdin_text.as_bytes()).await.map_err(|err| format!("could not write to stdin: {err}"))?;
        pipe.shutdown().await.map_err(|err| format!("could not close stdin: {err}"))?;
    }

    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| format!("docker timed out after {}s", timeout.as_secs()))?
        .map_err(|err| format!("docker did not finish: {err}"))?;
    Ok(CapturedRun {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Create a file with `contents` ONLY when it does not exist yet, in one
/// atomic filesystem operation (`O_CREAT|O_EXCL`), and give it `mode`.
/// Returns whether this call is the one that created it.
///
/// The same race `write_env_if_absent`'s doc spells out, on a file where
/// losing it costs more: Psono's `settings.yaml` holds the server's
/// Curve25519 PRIVATE key, and two overlapping installs each generating
/// their own keypair would leave one of them persisted while the other was
/// briefly live. Whoever loses the create treats it exactly as "it was
/// already there" and skips the first-run work.
fn create_file_if_absent(path: &Path, contents: &str, mode: u32) -> io::Result<bool> {
    match std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(contents.as_bytes())?;
            set_mode(path, mode)?;
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err),
    }
}

/// Where the docker CLI is allowed to keep its config.
///
/// **Found on a live host, and it is the same wall `backup::wrapper_home`
/// hit.** The unit sets `ProtectHome=true`, so the inherited `HOME=/root` is
/// an EMPTY READ-ONLY directory; `docker build` wants to create `/root/.docker`
/// before it does anything and dies with
///
///   ERROR: mkdir /root/.docker: read-only file system
///
/// Measured on `lab-vps` 2026-08-12, the first live VPN install: OpenVPN's
/// image build failed there, and so would the PANEL's — every VPN install
/// through the agent, since срез 4.9, on any host. `pull`, `up` and `ps` are
/// unaffected (they do not write config), which is why nothing before this
/// noticed.
///
/// The fix belongs here, not in the unit: the hardening is deliberate and has
/// nothing to do with docker, and an agent-side fix ships with the binary
/// instead of waiting for a setup re-run. `DOCKER_CONFIG` rather than `HOME`
/// because it is the exact variable the CLI reads for this, and a broad `HOME`
/// override would change behaviour for every child docker spawns.
fn docker_config_dir() -> PathBuf {
    let dir = crate::backup::wrapper_home().join(".docker");
    // Best effort, exactly like `wrapper_home`'s own: docker creates it when
    // it can, and if neither can, its error is still the explanation.
    let _ = std::fs::create_dir_all(&dir);
    dir
}

async fn run_docker_streaming(args: &[String], sink: &EventSink) -> Result<(), String> {
    let mut child = tokio::process::Command::new(docker_bin())
        .env("DOCKER_CONFIG", docker_config_dir())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run docker: {err}"))?;

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());

    // ONE deadline for the whole invocation, not a per-line one — a pull can
    // be silent for a while, and a quiet moment is not a hung command
    // (same reasoning `control::run_project`'s own comment states).
    let outcome = tokio::time::timeout(Duration::from_secs(DOCKER_TIMEOUT_SECS), async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.process_line("stdout", text).await; }
                        _ => out = None,
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.process_line("stderr", text).await; }
                        _ => err = None,
                    }
                }
                else => break,
            }
        }
        child.wait().await
    })
    .await;

    match outcome {
        Err(_) => Err(format!("docker timed out after {DOCKER_TIMEOUT_SECS}s")),
        Ok(Err(io)) => Err(format!("docker did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(match status.code() {
            Some(code) => format!("docker exited {code}"),
            None => "docker was killed by a signal".to_string(),
        }),
    }
}

/// The general shape `run_docker_streaming` follows, for a binary that is
/// NOT `docker` — mailcow's install is the only caller (`git clone`,
/// `bash generate_config.sh`, and its own `docker compose` invocations,
/// which need a working directory rather than `-f`, see
/// `install_mailcow_steps`'s doc). A separate function rather than a
/// generalized `run_docker_streaming(bin: &Path, …)`: every OTHER service's
/// install already calls `run_docker_streaming(args, sink)` with the
/// two-argument shape, and widening that signature would be a larger, riskier
/// diff across this whole file for one caller's benefit. The select loop
/// is otherwise identical.
pub(super) async fn run_child_streaming(
    bin: &Path,
    args: &[String],
    cwd: Option<&Path>,
    envs: &[(&str, String)],
    stdin_text: Option<&str>,
    timeout: Duration,
    sink: &EventSink,
) -> Result<(), String> {
    let bin_name = bin.display().to_string();
    let mut command = tokio::process::Command::new(bin);
    // Every caller of this is either docker itself or a script that drives it
    // (mailcow's `generate_config.sh`), so it needs the same writable config
    // directory `run_docker_streaming` gives — see `docker_config_dir`. Set
    // BEFORE the explicit `envs`, so a caller can still override it.
    command.env("DOCKER_CONFIG", docker_config_dir());
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .stdin(if stdin_text.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|err| format!("could not run {bin_name}: {err}"))?;

    // Written and CLOSED before anything reads the output — `generate_config.sh`
    // reads its yes-answers up front; leaving the pipe open would hang the
    // process waiting for more input that is never coming.
    if let Some(text) = stdin_text {
        if let Some(mut pipe) = child.stdin.take() {
            pipe.write_all(text.as_bytes()).await.map_err(|err| format!("could not write to {bin_name}'s stdin: {err}"))?;
            pipe.shutdown().await.map_err(|err| format!("could not close {bin_name}'s stdin: {err}"))?;
        }
    }

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());

    let outcome = tokio::time::timeout(timeout, async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.process_line("stdout", text).await; }
                        _ => out = None,
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.process_line("stderr", text).await; }
                        _ => err = None,
                    }
                }
                else => break,
            }
        }
        child.wait().await
    })
    .await;

    match outcome {
        Err(_) => Err(format!("{bin_name} timed out after {}s", timeout.as_secs())),
        Ok(Err(io)) => Err(format!("{bin_name} did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(match status.code() {
            Some(code) => format!("{bin_name} exited {code}"),
            None => format!("{bin_name} was killed by a signal"),
        }),
    }
}

/// Poll AdGuard's own `get_addresses` endpoint until it answers 2xx or the
/// deadline passes. Returns whether it became ready.
async fn wait_for_adguard(sink: &EventSink) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    while tokio::time::Instant::now() < deadline {
        let ready = http_request(
            "127.0.0.1",
            adguard::WEB_UI_PORT,
            "GET",
            "/control/install/get_addresses",
            None,
            Duration::from_secs(ADGUARD_HTTP_TIMEOUT_SECS),
        )
        .await
        .map(|(code, _body)| (200..300).contains(&code))
        .unwrap_or(false);
        if ready {
            return true;
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step("AdGuard Home: waiting for the service to answer").await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    false
}

/// Initial configuration through AdGuard's own installation API. Without it
/// AdGuard serves its setup wizard to whoever opens the page — and this page
/// is on a public hostname, so the first visitor would name the
/// administrator and own the resolver. The password is generated on the
/// server and travels in a request BODY, never argv (`/proc` hands argv to
/// every account), and AdGuard stores it as a bcrypt hash. Nothing here is
/// fatal, same rule the mailcow API / Nextcloud occ blocks follow.
async fn configure_adguard(dir: &Path, input: &Input, sink: &EventSink) {
    let env_path = dir.join(".env");
    let Some(password) = read_env_value(&env_path, "ADGUARD_ADMIN_PASSWORD") else {
        return;
    };
    // The web port MUST be the one the compose file publishes to, and the
    // DNS port the one bound inside the container — this call is what
    // AdGuard writes into its own config and listens on from here on.
    let body = format!(
        "{{\"web\":{{\"ip\":\"0.0.0.0\",\"port\":{}}},\"dns\":{{\"ip\":\"0.0.0.0\",\"port\":53}},\"username\":\"{}\",\"password\":\"{}\"}}",
        adguard::CONTAINER_WEB_PORT,
        json_escape(&input.admin_username),
        json_escape(&password),
    );
    let result = http_request(
        "127.0.0.1",
        adguard::WEB_UI_PORT,
        "POST",
        "/control/install/configure",
        Some(body.as_bytes()),
        Duration::from_secs(ADGUARD_HTTP_TIMEOUT_SECS),
    )
    .await;
    match result {
        Ok((code, _)) if (200..300).contains(&code) => {}
        Ok((code, body)) => {
            let _ = sink
                .step(format!(
                    "AdGuard Home: the initial configuration failed — the setup wizard is still open, finish it yourself right away ({code} {})",
                    bounded(&body, 300)
                ))
                .await;
        }
        Err(err) => {
            let _ = sink
                .step(format!(
                    "AdGuard Home: the initial configuration failed — the setup wizard is still open, finish it yourself right away ({err})"
                ))
                .await;
        }
    }
}

fn bounded(text: &str, limit: usize) -> String {
    text.chars().filter(|c| *c != '\r' && *c != '\n').take(limit).collect()
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out
}

/// Names this install would ask Caddy for that another service's block already
/// holds, or empty when there is no clash — asked from the request alone,
/// before anything is created.
///
/// **The names come from the same table the site itself is rendered from**
/// (`catalog::site_names_for`), so a service whose hostname is settings-driven
/// is checked on the name it will actually take. A label with no site of its
/// own answers nothing: the mesh connector publishes through Cloudflare and the
/// raw VPN protocols speak the panel's name.
///
/// The OWNER is the catalog id the request named, which is what the block will
/// carry — so this service's own previous block, and any block written before
/// blocks said whose they were, are its own to replace. See `caddy::conflicting_names`.
fn site_name_conflicts(label: &str, input: &Input) -> Vec<String> {
    let existing = std::fs::read_to_string(CADDYFILE_PATH).unwrap_or_default();
    site_name_conflicts_in(&existing, label, input)
}

/// The half that decides, without the file — so a test can ask it. The
/// caller above supplies the host's Caddyfile; a missing file reads as "no
/// sites yet", not as an error.
fn site_name_conflicts_in(existing: &str, label: &str, input: &Input) -> Vec<String> {
    // The VPN installs under one id and its site belongs to the panel; every
    // other label names itself. The panel may also publish no site at all.
    let ingress_id = if label == "vpn" { "vpn-panel" } else { label };
    if label == "vpn" && !panel::publishes_site(input) {
        return Vec::new();
    }
    let names = catalog::site_names_for(ingress_id, input);
    if names.is_empty() {
        return Vec::new();
    }
    caddy::conflicting_names(existing, &names, label)
}

fn write_caddy_site(names: &[String], site: &str) -> Result<(), String> {
    // Every site imports the admin guard, so the file must exist even when
    // no VPN panel has ever run the lockdown wrapper on this host — a
    // missing import is a fatal Caddy config error, not a permissive
    // default (same rule `writeCaddyfile`'s own comment states).
    let guard_path = Path::new(caddy::ADMIN_GUARD_PATH);
    if !guard_path.exists() {
        if let Some(parent) = guard_path.parent() {
            create_dir_0755(parent).map_err(|err| format!("could not create {}: {err}", parent.display()))?;
        }
        std::fs::write(guard_path, "").map_err(|err| format!("could not create {}: {err}", guard_path.display()))?;
    }
    // A host reachable through the agent may already carry other services'
    // sites — written by the SSH-script setup path, or by an earlier
    // install-slice — that this crate cannot re-render (most catalog
    // services have no declarative port yet). Overwriting the whole file
    // with just this one site would delete every one of those on the next
    // reload; `caddy::merge_site` folds this service's own block in and
    // leaves everything else untouched. Missing file reads as "no sites
    // yet", not an error.
    let existing = std::fs::read_to_string(CADDYFILE_PATH).unwrap_or_default();
    // **Whose block this is, read back out of the block itself.** Passing the
    // owner as a second argument would be a second place for it to be stated,
    // and the two would disagree the first time somebody changed one — while
    // the file on disk went on carrying the other. `site()` wrote it; this
    // reads it.
    let owner = caddy::owner_of(site).unwrap_or_default();
    let clashing = caddy::conflicting_names(&existing, names, &owner);
    if !clashing.is_empty() {
        // **Reached only by a race**, now that `site_name_conflicts` asks the
        // same question before the stream opens: two installs of different
        // services can still both pass that check and then both write. So the
        // message no longer says "nothing was changed" — by this point the
        // service is on the host and running, and only its web address is
        // missing. Saying otherwise sent somebody looking for a service that
        // was there all along (live run, 2026-09-04).
        return Err(format!(
            "{} is already served by another service on this host, so this one was left \
             without a web address. Caddy refuses a configuration that names one host \
             twice, which would take HTTPS off every service on this machine. The service \
             itself is installed and running — give it a name of its own and install \
             again, or remove it",
            clashing.join(", ")
        ));
    }
    let merged = caddy::merge_site(&existing, names, site);
    std::fs::write(CADDYFILE_PATH, merged).map_err(|err| format!("could not write {CADDYFILE_PATH}: {err}"))
}

/// Unlike the DoH patch or the admin-password POST, a Caddy that never
/// picks up the new site is not a cosmetic miss — it is the entire
/// web-facing point of the install failing to take effect, so this is
/// fatal (propagated with `?` by the caller) rather than logged and
/// shrugged off. `systemctl reload` fails outright on a unit that has
/// never been started (nothing to reload), which is exactly the state a
/// freshly provisioned host's `caddy.service` is in before its first site
/// ever gets written — `restart` is the fallback that actually starts it.
async fn reload_caddy(sink: &EventSink) -> Result<(), String> {
    let _ = sink.step("reloading Caddy").await;
    if run_quiet(&systemctl_bin(), &["reload", "caddy"]).await.is_ok() {
        ensure_caddy_enabled(sink).await;
        return Ok(());
    }
    let _ = sink.step("reload failed, trying a full restart").await;
    run_quiet(&systemctl_bin(), &["restart", "caddy"])
        .await
        .map_err(|()| "could not reload or restart caddy — the site was written but is not live".to_string())?;
    ensure_caddy_enabled(sink).await;
    Ok(())
}

/// Make Caddy come back after a reboot.
///
/// **A running Caddy is not an enabled one, and the difference is invisible on
/// the day of the install.** Measured live 2026-08-13: on a host where Caddy
/// was installed but never enabled, the install's `restart` made the site live
/// and the unit stayed `disabled` — the certificate worked, the report said
/// success, and the next reboot would have taken HTTPS down for every service
/// on the machine. The setup script never hit this because it enables Caddy
/// itself; the agent, which is meant to replace that script, did not.
///
/// Best effort and NOT fatal, unlike the reload above: the site IS live at this
/// point, so refusing the whole install would trade a working deployment for a
/// reboot-time risk. It is announced instead of swallowed — silence here is
/// what let the gap live in the first place.
async fn ensure_caddy_enabled(sink: &EventSink) {
    if run_quiet(&systemctl_bin(), &["is-enabled", "caddy"]).await.is_ok() {
        return;
    }
    if run_quiet(&systemctl_bin(), &["enable", "caddy"]).await.is_ok() {
        let _ = sink.step("enabled Caddy so it survives a reboot").await;
    } else {
        let _ = sink
            .step("WARNING: could not enable the Caddy unit — HTTPS will not come back after a reboot")
            .await;
    }
}

/// Overridable through the environment for tests, the same technique
/// `docker_bin` uses — a test points this at a stub script that records
/// argv and exits how the test wants; a server never sets it.
pub(super) fn systemctl_bin_public() -> String {
    systemctl_bin()
}

pub(super) async fn run_quiet_public(bin: &str, args: &[&str]) -> Result<(), ()> {
    run_quiet(bin, args).await
}

fn systemctl_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN").unwrap_or_else(|_| "systemctl".to_string())
}

async fn run_quiet(bin: &str, args: &[&str]) -> Result<(), ()> {
    match tokio::process::Command::new(bin).args(args).stdout(Stdio::null()).stderr(Stdio::null()).status().await {
        Ok(status) if status.success() => Ok(()),
        _ => Err(()),
    }
}

// ─────────────────────────── the VPN (срез 4.9) ───────────────────────────

/// `docker build -t <image> <dir>` — the panel is the only thing in the
/// catalog with no published image at all (it is OUR application, built from
/// the sources this install writes), so it is also the only service here that
/// must NOT be pulled: `compose pull` on `gryonix-vpn-panel:local` asks a
/// registry for a tag no registry has ever heard of.
pub fn docker_build_args(image: &str, dir: &Path) -> Vec<String> {
    vec![
        "build".to_string(),
        "-t".to_string(),
        image.to_string(),
        dir.to_string_lossy().into_owned(),
    ]
}

/// `docker ps -aq --filter name=^<container>$` — "does this container already
/// exist", the question that decides whether the panel needs a restart after
/// `up -d`. Anchored, because `--filter name=` is a substring match and a
/// neighbouring `vpnpanel-old` would otherwise answer for it.
pub fn docker_container_exists_args(container: &str) -> Vec<String> {
    vec![
        "ps".to_string(),
        "-aq".to_string(),
        "--filter".to_string(),
        format!("name=^{container}$"),
    ]
}

/// 8 random bytes as lowercase hex — 16 characters, `openssl rand -hex 8`'s
/// shape, which is what XRay's REALITY shortId is.
fn random_hex_8() -> io::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// 32 random bytes in standard base64 — `openssl rand -base64 32`'s shape, and
/// the only encoding Shadowsocks' 2022-blake3 ciphers accept for their
/// pre-shared key.
///
/// Hand-rolled for the same reason `random_hex_*` are: no dependency is worth
/// 20 lines. Pinned against RFC 4648's own vectors by
/// [`tests::base64_matches_the_rfc_vectors`] — a base64 encoder that is
/// slightly wrong produces a key the server accepts and no client can
/// reproduce, which would look like a protocol bug.
fn random_base64_32() -> io::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(base64_encode(&buf))
}

/// Standard base64 with padding (RFC 4648 §4) — the alphabet `openssl
/// rand -base64` uses.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let triple = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for shift in [18, 12, 6, 0] {
            out.push(ALPHABET[((triple >> shift) & 0x3f) as usize] as char);
        }
        // The last chunk's padding: one missing byte drops one character, two
        // drop two.
        if chunk.len() < 3 {
            out.truncate(out.len() - (3 - chunk.len()));
            out.push_str(&"=".repeat(3 - chunk.len()));
        }
    }
    out
}

/// One-shot `docker run` whose stdout is the answer, trimmed the way the
/// generator's `| tr -d '\r\n'` trims it. A non-zero exit is an error naming
/// the step, because every caller of this needs the value it asked for.
async fn docker_run_capture_trimmed(args: &[String], what: &str) -> Result<String, String> {
    match run_docker_capture(args, Duration::from_secs(DOCKER_TIMEOUT_SECS)).await? {
        (true, out) => Ok(out.trim().to_string()),
        (false, out) => Err(format!("{what} failed: {}", truncate(&out))),
    }
}

/// 12 random bytes as lowercase hex — 24 characters, the exact shape
/// `openssl rand -hex 12` produces and the exact shape the panel's password
/// resolution validates.
fn random_hex_12() -> io::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 12];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Is a stored panel password one this system generated?
///
/// A port of the bash `case`: exactly 24 lowercase hex characters. Anything
/// else is a stale custom password from a removed feature (special characters
/// mangled by compose interpolation) and gets rotated rather than carried
/// forward. Split out as a pure function because it is the whole decision —
/// carry the operator's saved credential, or invalidate it.
pub fn is_generated_panel_password(value: &str) -> bool {
    value.len() == 24 && value.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// The panel's `.env` is rewritten on EVERY run (`ADMIN_USER` and the
/// WireGuard parameters have to track the current configuration), so the
/// password cannot simply be "written once" the way every other service's
/// secret is. It is read back out of the existing file instead and preserved,
/// which is what keeps a saved install report accurate across a re-run.
fn resolve_panel_password(dir: &Path) -> io::Result<(String, bool)> {
    let existing = read_env_value(&dir.join(".env"), "ADMIN_PASSWORD").unwrap_or_default();
    if is_generated_panel_password(&existing) {
        return Ok((existing, true));
    }
    Ok((random_hex_12()?, false))
}

/// A port of `VPNPanelService.setupSteps` plus the two sections
/// `ServiceInfraSections` contributes for it (`composeSetup`'s file writing
/// and the private `vpnPanelServicesJSON`).
///
/// **`services.json` is written BEFORE `up -d`, unlike the bash path.** The
/// panel's `__main__` reads that file at STARTUP to decide whether to bring
/// WireGuard up (`if any(s.get("id") == "wireguard" …): ensure_server();
/// wg_up(…)`). The generated script writes an EMPTY registry in the service
/// section and the real one in a later section, so on a first install the
/// tunnel stays down until that section's `docker restart` — this order makes
/// the first start the correct one. The restart is still issued when the
/// container already existed, because `up -d` will not recreate a container
/// whose configuration did not change and the panel would otherwise keep
/// serving the previous registry.
async fn install_vpn_steps(
    input: &Input,
    protocols: &[panel::Protocol],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(panel::PATH);
    let build = dir.join("build");
    let data = dir.join("data");

    // The protocols come FIRST, in the generator's own section order: the
    // panel mounts each protocol's directory (docker would materialise a
    // missing bind source as an empty root-owned directory) and its
    // `services.json` — written below, before `up -d` — advertises exactly
    // what is installed. A protocol brought up after the panel would be
    // announced by a panel that had already decided what exists.
    for protocol in protocols {
        install_vpn_protocol(input, *protocol, sink).await?;
    }

    let _ = sink.step("creating service directories").await;
    for path in [&dir, &build, &data] {
        create_dir_0755(path).map_err(|err| format!("could not create {}: {err}", path.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, panel::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // The panel's own sources. Rewritten every run: identical content is
    // idempotent, and a re-run is how a newer app version reaches the server
    // at all (the image is `:local`, built here, so there is no registry that
    // could deliver it).
    for (name, contents) in panel::build_files() {
        let path = build.join(name);
        std::fs::write(&path, contents)
            .map_err(|err| format!("could not write {}: {err}", path.display()))?;
    }
    let _ = sink.step("wrote the panel's sources").await;

    let (password, kept) = resolve_panel_password(&dir).map_err(|err| format!("could not resolve the panel password: {err}"))?;
    let env_path = dir.join(".env");
    // 0600 from the moment the file exists — it holds the panel password.
    write_secret(&env_path, &panel::env_contents(input, &password), 0o600)
        .map_err(|err| format!("could not write {}: {err}", env_path.display()))?;
    let _ = sink
        .step(if kept { "kept the existing panel password" } else { "generated the panel password" })
        .await;

    let services_path = data.join("services.json");
    std::fs::write(&services_path, panel::services_json(input, protocols))
        .map_err(|err| format!("could not write {}: {err}", services_path.display()))?;

    // Admin-lockdown plumbing. The guard file is created only the FIRST time
    // (`create_file_if_absent` never overwrites on a re-run), so a re-run
    // keeps whatever state the dashboard's switch last set; the wrapper
    // itself is rewritten every time, because it is generated content and a
    // re-run is how a fix reaches it.
    let caddy_dir = Path::new(caddy::ADMIN_GUARD_PATH).parent().unwrap_or(Path::new("/etc/caddy"));
    create_dir_0755(caddy_dir).map_err(|err| format!("could not create {}: {err}", caddy_dir.display()))?;
    let guard_path = Path::new(caddy::ADMIN_GUARD_PATH);
    let first_install = create_file_if_absent(guard_path, "", 0o644)
        .map_err(|err| format!("could not create {}: {err}", caddy::ADMIN_GUARD_PATH))?;
    let lockdown = Path::new(panel::LOCKDOWN_SCRIPT_PATH);
    std::fs::write(lockdown, panel::ADMIN_LOCKDOWN_SH)
        .map_err(|err| format!("could not write {}: {err}", lockdown.display()))?;
    // 0750 root-owned, exactly as the setup script leaves it: it is a wrapper
    // reached over sudo from the dashboard, and the agent executes it directly
    // (`lockdown.rs`).
    set_mode(lockdown, 0o750).map_err(|err| format!("could not set the mode of {}: {err}", lockdown.display()))?;
    let _ = sink.step("installed the admin-lockdown wrapper").await;
    if first_install {
        // Ship locked by default instead of public: run the wrapper's own
        // `on` verb once, right here, the same action the dashboard's switch
        // takes later. Reuses `write_guard`'s self-IP detection and
        // `reload_caddy` instead of re-typing that logic in Rust. A re-run
        // never reaches this branch — the guard file exists by then — so an
        // owner who later chose `off` from the dashboard is never fought by
        // the installer.
        let ran = tokio::time::timeout(
            Duration::from_secs(ADMIN_LOCKDOWN_ON_TIMEOUT_SECS),
            tokio::process::Command::new(lockdown)
                .arg("on")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await;
        if matches!(ran, Ok(Ok(status)) if status.success()) {
            let _ = sink.step("locked the admin panels to VPN-only access").await;
        } else {
            let _ = sink
                .step("could not lock the admin panels by default — lock them from the dashboard")
                .await;
        }
    }

    // Did the container exist before this run? Asked BEFORE `up -d`, because
    // afterwards the answer is always yes.
    let existed = match run_docker_capture(
        &docker_container_exists_args(panel::CONTAINER),
        Duration::from_secs(DOCKER_TIMEOUT_SECS),
    )
    .await
    {
        Ok((true, out)) => !out.trim().is_empty(),
        // Not fatal and not assumed either way: a failed probe only costs a
        // redundant restart below.
        _ => false,
    };

    let _ = sink.step("building the VPN panel image").await;
    run_docker_streaming(&docker_build_args(panel::IMAGE, &build), sink).await?;
    let _ = sink.step("starting the VPN panel").await;
    compose_up(panel::COMPOSE_PROJECT, &dir, sink).await?;

    if existed {
        // Best-effort, like the generated script's own `|| true`: the panel is
        // already up, this only makes it re-read the registry.
        let _ = run_docker_streaming(&compose_restart_args(panel::COMPOSE_PROJECT, &dir), sink).await;
    }

    apply_vpn_firewall(input, protocols, sink).await?;

    write_caddy_site(&panel::caddy_site_names(input), &panel::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// One protocol's own compose project — everything the panel does not host
/// itself.
///
/// WireGuard is the exception with no case here: the panel IS the WireGuard
/// server (wg-quick on `wgpanel` inside its container), so there is no second
/// project to create. Every other protocol brings its own directory, its own
/// first-run secret and its own `up -d`.
async fn install_vpn_protocol(
    input: &Input,
    protocol: panel::Protocol,
    sink: &EventSink,
) -> Result<(), String> {
    match protocol {
        panel::Protocol::WireGuard => Ok(()),
        panel::Protocol::AmneziaWG => install_amnezia_steps(input, sink).await,
        panel::Protocol::Shadowsocks => install_shadowsocks_steps(input, sink).await,
        panel::Protocol::XrayReality => install_xray_steps(input, sink).await,
        panel::Protocol::OpenVPN => install_openvpn_steps(input, sink).await,
    }
}

/// Shadowsocks: a directory, a compose file, and one config file that is also
/// the secret.
///
/// The config is created EXCLUSIVELY. Re-minting the key on a re-run would
/// disconnect every client that already imported the ss:// link, and the mode
/// is re-applied either way so an install that predates a mode fix is
/// repaired rather than left at whatever it had.
async fn install_shadowsocks_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(shadowsocks::dir(input));
    let _ = sink.step("creating the Shadowsocks directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, shadowsocks::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let config_path = PathBuf::from(shadowsocks::config_path(input));
    let key = random_base64_32().map_err(|err| format!("could not generate the Shadowsocks key: {err}"))?;
    let created = create_file_if_absent(&config_path, &shadowsocks::config_json(input, &key), 0o600)
        .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;
    set_mode(&config_path, 0o600)
        .map_err(|err| format!("could not set the mode of {}: {err}", config_path.display()))?;
    let _ = sink
        .step(if created { "generated the Shadowsocks key" } else { "kept the existing Shadowsocks key" })
        .await;

    run_docker_streaming(&compose_pull_args(shadowsocks::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Shadowsocks").await;
    compose_up(shadowsocks::COMPOSE_PROJECT, &dir, sink).await?;
    Ok(())
}

/// XRay VLESS/Reality: three secrets minted by the IMAGE, then one config and
/// one client link.
///
/// The image is distroless — its entrypoint is the xray binary — so `uuid` and
/// `x25519` are one-shot `docker run`s whose stdout is captured. An empty or
/// unparsable keypair is FATAL: a server whose REALITY private key is empty
/// starts and then refuses every client, which reads as a broken client rather
/// than a broken install.
async fn install_xray_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(xray::dir(input));
    let config_dir = dir.join("config");
    let _ = sink.step("creating the XRay directories").await;
    for path in [&dir, &config_dir] {
        create_dir_0755(path).map_err(|err| format!("could not create {}: {err}", path.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, xray::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let config_path = PathBuf::from(xray::config_path(input));
    let link_path = PathBuf::from(xray::link_path(input));
    if config_path.exists() {
        let _ = sink.step("kept the existing XRay keys").await;
    } else {
        // The keys come from the image, so it has to be here before they can
        // be asked for. Streamed rather than captured: this is the one long
        // step of the protocol.
        let _ = sink.step("pulling the XRay image").await;
        run_docker_streaming(&docker_pull_args(xray::IMAGE), sink).await?;

        let uuid = docker_run_capture_trimmed(&docker_run_once_args(xray::IMAGE, &["uuid"]), "xray uuid").await?;
        let keys = docker_run_capture_trimmed(&docker_run_once_args(xray::IMAGE, &["x25519"]), "xray x25519").await?;
        let (private_key, public_key) = xray::parse_keys(&keys)
            .ok_or_else(|| format!("xray x25519 returned no usable keypair: {}", truncate(&keys)))?;
        if uuid.is_empty() {
            return Err("xray uuid returned nothing".to_string());
        }
        let short_id = random_hex_8().map_err(|err| format!("could not generate the XRay shortId: {err}"))?;

        std::fs::write(&config_path, xray::config_json(input, &uuid, &private_key, &short_id))
            .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;
        // The link carries the PUBLIC key, which is in no other file — losing
        // it means the user can never build a client profile again.
        std::fs::write(&link_path, xray::client_link(input, &uuid, &public_key, &short_id))
            .map_err(|err| format!("could not write {}: {err}", link_path.display()))?;
        let _ = sink.step("generated the XRay keys and client link").await;
    }
    for path in [&config_path, &link_path] {
        set_mode(path, 0o600).map_err(|err| format!("could not set the mode of {}: {err}", path.display()))?;
    }

    run_docker_streaming(&compose_pull_args(xray::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting XRay").await;
    compose_up(xray::COMPOSE_PROJECT, &dir, sink).await?;
    Ok(())
}

/// AmneziaWG: a panel password hashed by the image's own `wgpw`.
///
/// Two forms are tried in the generator's order (explicit `--entrypoint`
/// first, bare sub-command second) because an unrecognised sub-command makes
/// the entrypoint START THE PANEL instead — a long-running server that wedged
/// a real install with no output. Every docker call here is bounded, so that
/// failure mode costs a timeout rather than the installation.
///
/// No hash is a DEGRADED but working VPN, not a failure: the built-in panel
/// then has no password, but it binds loopback only and nothing proxies it —
/// clients are managed from the unified panel either way.
async fn install_amnezia_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(amnezia::dir(input));
    let _ = sink.step("creating the AmneziaWG directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, amnezia::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let env_path = PathBuf::from(amnezia::env_path(input));
    if env_path.exists() {
        // The generator re-runs its escaping `sed` on every pass, which is
        // also what repairs an install made before that fix existed. Rewritten
        // only when it actually changes, so a re-run does not churn the file.
        let existing = std::fs::read_to_string(&env_path)
            .map_err(|err| format!("could not read {}: {err}", env_path.display()))?;
        let repaired = reescape_amnezia_env(&existing);
        if repaired != existing {
            std::fs::write(&env_path, &repaired)
                .map_err(|err| format!("could not write {}: {err}", env_path.display()))?;
            let _ = sink.step("repaired the AmneziaWG password hash escaping").await;
        } else {
            let _ = sink.step("kept the existing AmneziaWG panel password").await;
        }
    } else {
        let password =
            random_hex_12().map_err(|err| format!("could not generate the AmneziaWG password: {err}"))?;
        // Best-effort, exactly like the generator's `|| true`: `wgpw` runs
        // from a local image just as well, and a registry hiccup should not
        // stop an install whose next step can still succeed.
        let _ = sink.step("pulling the AmneziaWG image").await;
        let _ = run_docker_streaming(&docker_pull_args(amnezia::IMAGE), sink).await;

        let hash = hash_amnezia_password(&password).await;
        if hash.is_none() {
            let _ = sink
                .step(
                    "could not hash a panel password (the image's wgpw tool did not answer) — \
                     AmneziaWG's built-in panel stays open on localhost only; the VPN itself \
                     works and clients are managed from the VPN panel",
                )
                .await;
        }
        std::fs::write(&env_path, amnezia::env_contents(&password, hash.as_deref()))
            .map_err(|err| format!("could not write {}: {err}", env_path.display()))?;
        let _ = sink.step("generated the AmneziaWG panel password").await;
    }
    set_mode(&env_path, 0o600)
        .map_err(|err| format!("could not set the mode of {}: {err}", env_path.display()))?;

    run_docker_streaming(&compose_pull_args(amnezia::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting AmneziaWG").await;
    compose_up(amnezia::COMPOSE_PROJECT, &dir, sink).await?;
    Ok(())
}

/// The two `wgpw` invocation forms, in the generator's order. `None` means
/// neither answered with a bcrypt hash — the degraded path.
async fn hash_amnezia_password(password: &str) -> Option<String> {
    let forms = [
        docker_run_entrypoint_args("wgpw", amnezia::IMAGE, &[password]),
        docker_run_once_args(amnezia::IMAGE, &["wgpw", password]),
    ];
    for args in forms {
        // A short bound of its own: the failure this guards against is a
        // container that never exits, and it must not cost the install the
        // full docker timeout twice.
        if let Ok((true, out)) = run_docker_capture(&args, Duration::from_secs(WGPW_TIMEOUT_SECS)).await {
            if let Some(hash) = amnezia::parse_hash(&out) {
                return Some(hash);
            }
        }
    }
    None
}

/// Re-apply the `$` escaping to an existing `.env`'s `PASSWORD_HASH` line.
///
/// Idempotent for the same reason `amnezia::escape_hash` is: this runs on
/// every install, including over a file this code wrote last time.
fn reescape_amnezia_env(contents: &str) -> String {
    let ends_with_newline = contents.ends_with('\n');
    let mut out = String::with_capacity(contents.len());
    for (index, line) in contents.lines().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        match line.strip_prefix("PASSWORD_HASH=") {
            Some(hash) => {
                out.push_str("PASSWORD_HASH=");
                out.push_str(&amnezia::escape_hash(hash));
            }
            None => out.push_str(line),
        }
    }
    if ends_with_newline {
        out.push('\n');
    }
    out
}

/// OpenVPN: the only protocol whose image is BUILT here, and the only one
/// whose client profile is captured stdout.
///
/// The order is the generator's and matters: the build context and the image
/// come before the PKI (the PKI one-shot runs INSIDE that image), and the
/// profile is generated last, from a PKI that already exists. The profile is
/// written only when the run actually produced one — `docker run … > file` in
/// the shell creates the file BEFORE the command runs, so a failed run there
/// leaves an EMPTY profile that the existence guard then preserves forever
/// (the same defect `psono`'s `settings.yaml` had).
async fn install_openvpn_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(openvpn::dir(input));
    let data = PathBuf::from(openvpn::data_dir(input));
    let build = PathBuf::from(openvpn::build_dir(input));
    let _ = sink.step("creating the OpenVPN directories").await;
    for path in [&dir, &data, &build] {
        create_dir_0755(path).map_err(|err| format!("could not create {}: {err}", path.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, openvpn::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // Rewritten every run: the image is `:local`, so a re-run is the only way
    // a newer generation of these shims reaches the host.
    for (name, contents) in openvpn::build_files() {
        let path = build.join(name);
        std::fs::write(&path, contents)
            .map_err(|err| format!("could not write {}: {err}", path.display()))?;
    }
    let _ = sink.step("building the OpenVPN image").await;
    run_docker_streaming(&docker_build_args(openvpn::IMAGE, &build), sink).await?;

    let ca_path = PathBuf::from(openvpn::ca_path(input));
    let profile_path = PathBuf::from(openvpn::client_profile_path(input));
    if ca_path.exists() {
        let _ = sink.step("kept the existing OpenVPN PKI").await;
    } else {
        let _ = sink.step("building the OpenVPN PKI").await;
        let mount = format!("{}:/etc/openvpn", data.display());
        let script = openvpn::pki_script(input);
        run_docker_streaming(
            &docker_run_mounted_args(&mount, openvpn::IMAGE, &["sh", "-c", &script]),
            sink,
        )
        .await?;

        let env_path = data.join("gryonix-env");
        std::fs::write(&env_path, openvpn::gryonix_env(input))
            .map_err(|err| format!("could not write {}: {err}", env_path.display()))?;
        let conf_path = data.join("server.conf");
        std::fs::write(&conf_path, openvpn::server_conf(input))
            .map_err(|err| format!("could not write {}: {err}", conf_path.display()))?;

        let (ok, profile) = run_docker_capture(
            &docker_run_mounted_args(
                &mount,
                openvpn::IMAGE,
                &["ovpn_getclient", openvpn::CLIENT_NAME],
            ),
            Duration::from_secs(DOCKER_TIMEOUT_SECS),
        )
        .await?;
        if !ok || profile.trim().is_empty() {
            return Err(format!(
                "could not generate the OpenVPN client profile: {}",
                truncate(&profile)
            ));
        }
        std::fs::write(&profile_path, &profile)
            .map_err(|err| format!("could not write {}: {err}", profile_path.display()))?;
        let _ = sink.step("generated the OpenVPN PKI and client profile").await;
    }
    set_mode(&profile_path, 0o640)
        .map_err(|err| format!("could not set the mode of {}: {err}", profile_path.display()))?;

    // No pull: `gryonix-openvpn:local` exists in no registry, and asking would
    // fail the step for a tag that was just built here.
    let _ = sink.step("starting OpenVPN").await;
    compose_up(openvpn::COMPOSE_PROJECT, &dir, sink).await?;
    Ok(())
}

/// Open the selected protocols' ports through the generator's drop-in chain.
///
/// **Fatal, unlike most post-`up` steps.** A VPN whose port is closed is a VPN
/// that does not connect, and the failure would surface as a client timing out
/// against a server that looks healthy — the same reasoning that makes a Caddy
/// reload failure fatal rather than a step message.
///
/// A host with no `/etc/nftables.d` is NOT a failure: it has no gryonixNexus
/// ruleset for the drop-in to extend, so there is nothing to open and nothing
/// blocking. It is said out loud rather than passed over in silence.
async fn apply_vpn_firewall(
    input: &Input,
    protocols: &[panel::Protocol],
    sink: &EventSink,
) -> Result<(), String> {
    let ports: Vec<firewall::Port> =
        protocols.iter().flat_map(|protocol| protocol.firewall_ports(input)).collect();
    match firewall::apply_service_ports("vpn", &ports).await? {
        firewall::Outcome::Applied => {
            let _ = sink.step("opened the VPN ports in the firewall").await;
        }
        firewall::Outcome::Cleared => {
            let _ = sink.step("removed this service's firewall ports").await;
        }
        firewall::Outcome::SkippedNoDropInDir => {
            let _ = sink
                .step("this host has no gryonixNexus nftables ruleset, so no firewall rule was added")
                .await;
        }
    }
    Ok(())
}

// ─────────────────────────── minimal HTTP client ───────────────────────────
//
// No HTTP client crate: the agent's dependency list stays short by design
// (see Cargo.toml), and every request here is a handful of bytes to
// 127.0.0.1 with no redirects, no chunked transfer to speak of, no TLS. A
// hand-rolled HTTP/1.1 request/response over `TcpStream`, closed with
// `Connection: close` so reading to EOF is the whole response, is the entire
// need. `tests::a_real_loopback_server_round_trips_status_and_body` proves
// this against a REAL socket, not a parser fed canned bytes.

async fn http_request(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, String), String> {
    let addr = format!("{host}:{port}");
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("connect to {addr} timed out"))?
        .map_err(|err| format!("connect to {addr}: {err}"))?;

    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(body) = body {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    let mut buf = request.into_bytes();
    if let Some(body) = body {
        buf.extend_from_slice(body);
    }

    tokio::time::timeout(timeout, stream.write_all(&buf))
        .await
        .map_err(|_| "request write timed out".to_string())?
        .map_err(|err| format!("request write: {err}"))?;

    let mut response = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut response))
        .await
        .map_err(|_| "response read timed out".to_string())?
        .map_err(|err| format!("response read: {err}"))?;

    parse_http_response(&response)
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, String), String> {
    let text = String::from_utf8_lossy(raw);
    let mut halves = text.splitn(2, "\r\n\r\n");
    let head = halves.next().unwrap_or("");
    let body = halves.next().unwrap_or("").to_string();
    let status_line = head.lines().next().ok_or_else(|| "empty response".to_string())?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("could not parse status line: {status_line}"))?;
    Ok((code, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::collections::HashMap;

    /// **The mode must be right the instant the file exists — not after a
    /// follow-up `chmod`.** `write_secret` exists so `execute.rs`'s
    /// generated-password writes are never briefly world-readable at the
    /// process umask between a plain `std::fs::write` and a `set_mode` call
    /// after it (2026-09-13 security audit, finding F4); this checks the mode
    /// `OpenOptions` actually produced, with no `set_mode` of its own in
    /// between creation and the read.
    #[test]
    fn write_secret_creates_the_file_at_the_right_mode_directly() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("gryonixnexusd-write-secret-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        write_secret(&path, "hunter2", 0o600).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode, 0o600, "the file must be 0600 from the moment it exists, not after a later chmod");
    }

    // ─────────────── the site names, before anything is created ───────────────

    fn site_input() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    /// **Found by a live run, 2026-09-04.** The refusal itself worked and had
    /// worked for weeks — it just arrived at the END of the install, from
    /// `write_caddy_site`. Psono was pulled, started and given an
    /// administrator before being told it could not have a web address, under
    /// a message that said nothing had changed. Asked here, it costs a file
    /// read and answers before there is anything to clean up.
    #[test]
    fn a_name_another_block_already_holds_is_refused_before_anything_is_created() {
        let mut input = site_input();
        // What Vaultwarden's block on the host looks like, written by us.
        let existing = caddy::merge_site(
            "",
            &["vault.example.com".to_string()],
            &caddy::site("vaultwarden", "vault.example.com", 8082, false, false, false),
        );
        input.psono_hostname = "vault.example.com".to_string();
        assert_eq!(
            site_name_conflicts_in(&existing, "psono", &input),
            vec!["vault.example.com".to_string()]
        );
    }

    /// The same install again is not a conflict with itself — without this
    /// every reinstall would be refused before it started, which is a worse
    /// failure than the one being fixed.
    #[test]
    fn a_service_reinstalling_over_its_own_block_is_not_refused() {
        let existing = caddy::merge_site(
            "",
            &["vault.example.com".to_string()],
            &caddy::site("vaultwarden", "vault.example.com", 8082, false, false, false),
        );
        assert!(site_name_conflicts_in(&existing, "vaultwarden", &site_input()).is_empty());
    }

    /// A label with no site of its own answers NOTHING rather than an empty
    /// name: the mesh connector publishes through Cloudflare and the raw VPN
    /// protocols speak the panel's name. A check that invented a name for
    /// them would refuse installs over a site nobody asked for.
    #[test]
    fn a_service_with_no_site_of_its_own_is_never_refused_for_one() {
        let existing = caddy::merge_site(
            "",
            &["vault.example.com".to_string()],
            &caddy::site("vaultwarden", "vault.example.com", 8082, false, false, false),
        );
        for label in ["cloudflared", "minecraft-java", "tailscale-node"] {
            assert!(site_name_conflicts_in(&existing, label, &site_input()).is_empty(), "{label}");
        }
    }

    /// **The VPN installs under one id and its site belongs to the panel.**
    /// Asking the ingress table for `vpn` answers nothing at all, so a check
    /// that passed the label straight through would never see the panel's
    /// name — and the one service on this host most likely to be reinstalled
    /// would be the one this preflight could not protect.
    #[test]
    fn the_vpn_label_is_checked_on_the_panels_own_name() {
        let mut input = site_input();
        let names = catalog::site_names_for("vpn-panel", &input);
        assert!(!names.is_empty(), "the panel publishes no name to check");
        let stranger = caddy::merge_site("", &names,
                                         &caddy::site("nextcloud", &names.join(", "), 8080, false, false, false));
        assert_eq!(site_name_conflicts_in(&stranger, "vpn", &input), names);

        // And a panel that publishes no site is never refused for one — the
        // deployment whose VPN devices are managed from the app alone.
        input.vpn_client_access = "app".to_string();
        assert!(site_name_conflicts_in(&stranger, "vpn", &input).is_empty());
    }

    /// Env overrides are process-wide and cargo runs tests in parallel
    /// threads — without this lock, two tests setting
    /// `GRYONIXNEXUSD_INSTALL_DOCKER_BIN` at once would flip each other's
    /// override at random. Same technique `backup.rs`/`update.rs` use.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn write_stub(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let script = dir.join(name);
        std::fs::write(&script, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        script
    }

    // ---------------------------------------------------- the crash-loop guard

    /// The passing condition is something OBSERVED: the project held still for
    /// three looks running.
    #[test]
    fn a_project_that_held_still_passes() {
        assert!(went_quiet(3, LOOP_QUIET_SAMPLES));
        assert!(went_quiet(4, LOOP_QUIET_SAMPLES));
    }

    /// **The shape that defeated the rule this replaced.** A container that runs
    /// four seconds and dies, for ever, is `running` on almost every sample —
    /// so "is it restarting right now" answered no and let it through. What it
    /// never does is hold still, and a streak that keeps being broken never
    /// reaches the floor.
    #[test]
    fn a_project_that_never_held_still_does_not_pass() {
        assert!(!went_quiet(0, LOOP_QUIET_SAMPLES));
        assert!(!went_quiet(2, LOOP_QUIET_SAMPLES));
    }

    /// The floor is the update path's, measured there and re-measured here: at
    /// two looks a Minecraft server given an impossible heap still reads
    /// `running`, because the JVM has not finished dying.
    #[test]
    fn the_floor_is_three_looks() {
        assert_eq!(LOOP_QUIET_SAMPLES, 3);
        assert!(!went_quiet(LOOP_QUIET_SAMPLES - 1, LOOP_QUIET_SAMPLES));
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-install-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ────────────────── the port docker published and nobody opened ──────────

    /// **Every service that publishes a port ON THE HOST has to open it, and
    /// the source says so itself.** Found live on 2026-09-08: GitLab installed
    /// by the agent answered on https and its git-SSH port timed out from
    /// outside — docker had published 2223 and nftables had never heard of it,
    /// so `git clone` over SSH could not work on an install that reported
    /// success. The generated script's own firewall step has always covered
    /// that port; only this path had not.
    ///
    /// A scan rather than a call, because what fails is an install function
    /// somebody writes NEXT: the two here are the only services whose port is
    /// published straight onto the host rather than proxied by Caddy, and they
    /// are also the two `published_public_ports` already names for the port
    /// preflight. That list is the definition — if a third joins it, its
    /// install has to open the port too.
    #[test]
    fn every_host_published_port_is_also_opened_in_the_firewall() {
        let source = include_str!("execute.rs");
        for label in ["gitlab", "forgejo"] {
            let install = source
                .split(&format!("async fn install_{label}_steps"))
                .nth(1)
                .unwrap_or_else(|| panic!("no install_{label}_steps in this file"));
            // Up to the end of that function: the next `\nasync fn` starts another.
            let body = install.split("\nasync fn").next().unwrap_or(install);
            assert!(body.contains("open_service_firewall_ports"),
                    "{label} publishes git-over-SSH on the host and never opens it");
        }
    }

    // ────────────────── the byte the two delivery paths differed by ───────────

    /// **The one byte a live host caught the two ports differing by.** The
    /// generated script writes every compose file with a heredoc, which always
    /// ends the file with a newline; the agent wrote the generator's string as
    /// it stands, and that string deliberately has none. Measured on
    /// 31.70.137.80 on 2026-09-08: the same SearXNG, installed by each path in
    /// turn, left a 1196-byte file and then a 1195-byte one.
    #[test]
    fn a_managed_file_ends_the_way_a_heredoc_would_end_it() {
        let dir = tmp("managed-text");
        let path = dir.join("docker-compose.yml");

        write_managed_text(&path, "services:\n  x: {}").unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.ends_with('\n'), "a heredoc would have ended it with one");
        assert_eq!(written, "services:\n  x: {}\n");

        // And a generator that already ends with one is not given a second.
        write_managed_text(&path, "services:\n  x: {}\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "services:\n  x: {}\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rule above is worth nothing if a service is added later with a bare
    /// `fs::write`, so the source says so itself: no compose file is written
    /// any other way.
    #[test]
    fn no_compose_file_is_written_around_that_rule() {
        let source = include_str!("execute.rs");
        // Split so the needle does not match the line that carries it — the
        // scan would otherwise fail on its own test.
        let needle = format!("std::fs::write{}", "(&compose_path");
        assert!(!source.contains(&needle),
                "compose files go through write_managed_text — see its doc for the byte");
    }

    // ────────────────── bind mounts the container writes into ──────────────────

    /// The modes and group here are the IMAGE's, not a preference — see
    /// `create_dir_owned_by_group`. Getting them wrong does not degrade the
    /// service, it prevents it from ever starting: measured live 2026-08-11,
    /// the Passbolt server crash-looped forever on
    /// "/etc/passbolt/gpg/serverkey_private.asc: Permission denied" because
    /// these two directories were created 0755 root:root like every other one.
    ///
    /// Asserted as data because the real thing cannot run here: chowning to a
    /// group the test user does not belong to is privileged, and no unit test
    /// is root. What CAN be checked is that the decision did not drift.
    #[test]
    fn passbolts_secret_directories_keep_the_modes_its_image_ships() {
        assert_eq!(PASSBOLT_SECRET_DIRS, &[("gpg", 0o770), ("jwt", 0o750)]);
        assert_eq!(
            PASSBOLT_SERVER_GID, 33,
            "www-data inside the container — the id in the CONTAINER's passwd, \
             not one looked up on the host"
        );
    }

    /// The mechanics the case above depends on, run for real against a group
    /// the test process already belongs to — so the assertion above is about
    /// the POLICY only, and this one proves the code that applies it works.
    #[test]
    fn a_group_owned_directory_gets_both_its_group_and_its_mode() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp("group-owned").join("gpg");
        // The process's own gid always succeeds; a foreign one would need root.
        let gid = unsafe { libc::getgid() };
        create_dir_owned_by_group(&dir, 0o770, gid).unwrap();

        let meta = std::fs::metadata(&dir).unwrap();
        assert_eq!(meta.gid(), gid);
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o770,
            "the mode is applied AFTER the chown, which is what makes it stick"
        );
    }

    // ─────────────────────────── argv construction ───────────────────────────

    #[test]
    fn compose_argv_is_exact_and_never_touches_down_or_rm() {
        let dir = Path::new("/opt/adguardhome");
        assert_eq!(
            compose_pull_args("adguardhome", dir),
            ["compose", "-p", "adguardhome", "-f", "/opt/adguardhome/docker-compose.yml", "pull", "-q"]
        );
        assert_eq!(
            compose_up_args("adguardhome", dir),
            ["compose", "-p", "adguardhome", "-f", "/opt/adguardhome/docker-compose.yml", "up", "-d"]
        );
        assert_eq!(
            compose_restart_args("adguardhome", dir),
            ["compose", "-p", "adguardhome", "-f", "/opt/adguardhome/docker-compose.yml", "restart"]
        );
        for args in [
            compose_pull_args("x", dir),
            compose_up_args("x", dir),
            compose_restart_args("x", dir),
        ] {
            assert!(!args.contains(&"down".to_string()));
            assert!(!args.contains(&"rm".to_string()));
        }
    }

    /// Every compose verb this module runs names its file explicitly. The
    /// agent's unit sets no `WorkingDirectory=`, so systemd starts it in `/`
    /// and a compose call that relied on the cwd the way the bash setup script
    /// does (it `cd`s first) would fail with "no configuration file provided"
    /// on a real daemon — invisible to a stubbed docker that only records argv.
    #[test]
    fn every_compose_verb_points_at_its_project_file_instead_of_trusting_the_cwd() {
        let dir = Path::new("/opt/service");
        for args in [
            compose_pull_args("p", dir),
            compose_up_args("p", dir),
            compose_restart_args("p", dir),
            compose_restart_service_args("p", dir, "svc"),
        ] {
            let f = args.iter().position(|a| a == "-f").expect("no -f in {args:?}");
            assert_eq!(args[f + 1], "/opt/service/docker-compose.yml", "{args:?}");
        }
    }

    #[test]
    fn a_project_name_stays_one_argument() {
        let args = compose_up_args("weird name", Path::new("/opt/x"));
        assert_eq!(args.len(), 7);
        assert_eq!(args[2], "weird name");
    }

    /// Every docker child gets a config directory it can actually write to.
    ///
    /// **The live defect this pins, 2026-08-12 on `lab-vps`:** the unit's
    /// `ProtectHome=true` makes the inherited `HOME=/root` empty and
    /// read-only, and `docker build` creates `/root/.docker` before it does
    /// anything — so it died with `mkdir /root/.docker: read-only file
    /// system`. Not an OpenVPN problem: the VPN PANEL builds an image the same
    /// way, so every VPN install through the agent had been broken since срез
    /// 4.9, on a step no stubbed docker could fail at (`pull`, `up` and `ps`
    /// never write config, which is why the first seven slices were silent
    /// about it). The same wall `backup::wrapper_home` hit for gpg, one
    /// hardening flag and five months apart.
    ///
    /// What is pinned is the contract, not the path: the child sees
    /// `DOCKER_CONFIG`, and it can create files under it.
    #[tokio::test]
    async fn every_docker_child_gets_a_config_directory_it_can_write_to() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // GRYONIXNEXUSD_STATE_DIR is shared with `backup`'s and `update`'s test
        // modules, which have their own ENV_LOCK — see STATE_DIR_ENV_LOCK.
        let _state_guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("docker-config-home");
        let recorder = dir.join("env.txt");
        // The shape of the real failure: write something under the config
        // directory, exactly as `docker build` does before it builds anything.
        let script = write_stub(
            &dir,
            "docker",
            &format!(
                "#!/bin/sh\nset -e\nmkdir -p \"$DOCKER_CONFIG\"\n: > \"$DOCKER_CONFIG/probe\"\n\
                 printf '%s\\n' \"$DOCKER_CONFIG\" > {}\n",
                recorder.display()
            ),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);
        let state = dir.join("state");
        std::env::set_var("GRYONIXNEXUSD_STATE_DIR", &state);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "vpn".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let streamed = run_docker_streaming(&docker_build_args("gryonix-openvpn:local", &dir), &sink).await;
        let captured = run_docker_capture(&docker_pull_args("busybox"), Duration::from_secs(30)).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
        while rx.try_recv().is_ok() {}

        assert!(streamed.is_ok(), "the streaming path must reach a writable config dir: {streamed:?}");
        assert!(matches!(captured, Ok((true, _))), "and so must the capturing one: {captured:?}");
        let seen = std::fs::read_to_string(&recorder).unwrap();
        let config = PathBuf::from(seen.trim());
        assert!(config.starts_with(&state), "DOCKER_CONFIG must live under the state directory: {config:?}");
        assert!(config.join("probe").exists(), "the child could not write under DOCKER_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A real stub `docker` script recording its own argv — the same
    /// end-to-end technique `update.rs`'s `write_stub` + env-var tests use
    /// for their wrapper, applied here to the docker seam.
    #[tokio::test]
    async fn run_docker_streaming_reaches_the_stub_with_the_built_argv_and_streams_its_output() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("docker-argv");
        let recorder = dir.join("argv.txt");
        let script = write_stub(
            &dir,
            "docker",
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > {}\necho pulling-line\necho warn-line 1>&2\n",
                recorder.display()
            ),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "adguard-home".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = run_docker_streaming(&compose_pull_args("adguardhome", Path::new("/opt/adguardhome")), &sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(result.is_ok(), "{result:?}");

        let recorded = std::fs::read_to_string(&recorder).unwrap();
        assert_eq!(recorded.trim(), "compose -p adguardhome -f /opt/adguardhome/docker-compose.yml pull -q");

        let mut lines = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            assert_eq!(frame[0], 0x00);
            let event = pb::InstallServiceEvent::decode(&frame[5..]).unwrap();
            lines.push((event.stream, event.text));
        }
        assert!(lines.contains(&("stdout".to_string(), "pulling-line".to_string())));
        assert!(lines.contains(&("stderr".to_string(), "warn-line".to_string())));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_docker_streaming_reports_a_nonzero_exit_as_an_error() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("docker-fail");
        let script = write_stub(&dir, "docker", "#!/bin/sh\necho boom 1>&2\nexit 3\n");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "adguard-home".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = run_docker_streaming(&compose_up_args("adguardhome", Path::new("/opt/adguardhome")), &sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert_eq!(result, Err("docker exited 3".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────── id gate ───────────────────────────

    #[test]
    fn unknown_service_id_is_refused_before_anything_runs() {
        assert_eq!(resolve("nope"), Err(Rejection::UnknownService("nope".into())));
        assert!(matches!(resolve("adguard-home; rm -rf /"), Err(Rejection::UnknownService(_))));
    }

    #[test]
    fn every_catalog_id_now_has_an_executor_so_the_not_implemented_layer_is_unreachable() {
        // This test used to name one real-but-unbuilt service and move to the
        // next one every срез — mailcow, then passbolt. It has run out of
        // examples: the mail engines and Passbolt landed together, and the
        // installer now covers the agent's catalog completely.
        //
        // The `NotImplemented` layer stays anyway, and this is what keeps it
        // honest. It exists for the window between a service joining the
        // catalog (where `discover` must know it the moment the app can
        // install it — that is its own rule, paid for three times) and its
        // executor landing; the next service to be added will sit in exactly
        // that window. The day the two lists disagree again, this assertion
        // is what says so, instead of a hand-picked example going stale.
        for id in discover::all_service_ids() {
            assert_eq!(
                resolve(id),
                Ok(id),
                "{id} is in the agent's catalog but has no executor — it must be refused as \
                 NotImplemented rather than UnknownService, and this test should name it"
            );
        }
    }

    /// The VPN is addressed by the ONE id the agent's catalog models it with.
    /// A protocol's own catalog id is not a thing the installer takes — the
    /// same id `GetState` would have to answer for, and it answers `vpn`.
    #[test]
    fn the_vpn_is_installed_under_the_aggregate_id_not_a_protocols_own() {
        assert_eq!(resolve("vpn"), Ok("vpn"));
        assert_eq!(compose_project("vpn"), "vpnpanel");
        // `wireguard-vpn` is a real Swift ServiceID, but not a row in the
        // agent's catalog — it collapses into `vpn` there, so as an INSTALL id
        // it is a client bug, not a "later build" promise.
        assert_eq!(resolve("wireguard-vpn"), Err(Rejection::UnknownService("wireguard-vpn".into())));
    }

    // ───────────────────── VPN protocol selection ─────────────────────

    // ────────────────── the host surface ──────────────────

    /// **A host with no Caddy is refused BEFORE the stream opens.**
    ///
    /// Measured on a bare VM 2026-08-12: a mailcow install ran fifteen minutes
    /// of real work — repository clone, twenty images pulled, config
    /// generated, engine started, REST API enabled, mail domain added — and
    /// then died with `could not create /etc/caddy: Read-only file system`.
    /// Every service is published through Caddy and the site is written last,
    /// so on that machine every install would fail the same way, at the end,
    /// with a message that names the symptom rather than the missing setup.
    ///
    /// **The check is about the BINARY only.** It used to accept `/etc/caddy`
    /// as proof too, and that stopped being proof the day bootstrap started
    /// creating that directory on every host — it must, because the sandbox
    /// hole for it is punched once at unit start (`install/packages.rs`). A
    /// check that still accepted the directory would pass everywhere and refuse
    /// nothing, which is the quietest way for a gate to die.
    #[test]
    fn a_host_without_caddy_is_recognised() {
        // On a developer machine the binary is absent, which is exactly the
        // shape of a bare server — and the assertion that matters is that the
        // function looks at the FILESYSTEM rather than assuming.
        let has_bin = packages::have_binary("caddy")
            || ["/usr/bin/caddy", "/usr/local/bin/caddy", "/usr/sbin/caddy"]
                .iter()
                .any(|path| Path::new(path).exists());
        assert_eq!(caddy_is_installed(), has_bin);
        // And the refusal says what to do about it, not what failed — including
        // the two tools whose absence is the only thing that still makes an
        // agent-built host impossible.
        let (status, code, message) = Rejection::NoReverseProxy.parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains("no Caddy"), "{message}");
        assert!(message.contains("apt-get") && message.contains("systemd-run"), "{message}");
    }

    /// **An empty `admin_username` takes the default, and a live host paid for
    /// this one.**
    ///
    /// The VPN panel builds its superadmin from `ADMIN_USER` in its `.env`. With
    /// this field passed through raw, a request that omitted it gave the panel an
    /// account whose username was the EMPTY STRING — while the install report,
    /// which has its own default, told the owner "Administrator: admin". Measured
    /// on `lab-vps` 2026-08-13: `users.json` held `"username": ""`, and logging in
    /// with what the report said was impossible.
    ///
    /// The rule it was breaking is already written down for the settings map:
    /// absent or empty means the Swift `ServiceSettings` default, because the app
    /// sends only what changed.
    #[test]
    fn an_omitted_admin_username_becomes_the_default_rather_than_an_empty_account() {
        let base = pb::InstallServiceRequest { domain: "example.com".into(), ..Default::default() };
        assert_eq!(build_input(&base).expect("a domain is enough").admin_username, "admin");
        let blank = pb::InstallServiceRequest { admin_username: "   ".into(), ..base.clone() };
        assert_eq!(build_input(&blank).expect("whitespace is empty too").admin_username, "admin");
        // A real value still wins, trimmed.
        let named = pb::InstallServiceRequest { admin_username: " owner ".into(), ..base };
        assert_eq!(build_input(&named).expect("a named admin").admin_username, "owner");
    }

    /// **The relay's firewall topology comes off the request, and the endpoint
    /// is split rather than parsed.**
    ///
    /// The relay reaches the agent through `ProvisionHost` alone — it carries no
    /// services — so these fields are the only description of the deployment it
    /// will ever get. `vps_public` is the host half of `tunnel_endpoint`, the
    /// address the home half dials, which is what hairpinned traffic is aimed at.
    #[test]
    fn the_relay_topology_is_read_from_the_request() {
        let req = pb::InstallServiceRequest {
            host_role: pb::HostRole::VpsRelay as i32,
            tunnel_endpoint: "217.154.155.150:51820".to_string(),
            relay_wg_port: 51820,
            relay_forwarded_ports: vec![80, 443, 25],
            relay_forwarded_udp_ports: vec![51821],
            home_wg_address: "10.8.0.2".to_string(),
            ..Default::default()
        };
        let topology = HostContext::from_request(&req).relay_topology();
        assert_eq!(topology.vps_public, "217.154.155.150");
        assert_eq!(topology.home_ip(), "10.8.0.2");
        assert_eq!(topology.wg_port, 51820);
        assert_eq!(topology.all_tcp_ports(), vec![80, 443, 25]);
        assert_eq!(topology.all_udp_ports(), vec![51821]);
        assert!(topology.is_complete());

        // A bare address stays whole, and so does anything that is not
        // `host:port` — the value ends up in an nftables `define`, and nft
        // understands addresses this function has no business rejecting.
        assert_eq!(endpoint_host("203.0.113.10"), "203.0.113.10");
        assert_eq!(endpoint_host("relay.example.com:51820"), "relay.example.com");
        assert_eq!(endpoint_host("not:a:port"), "not:a:port");
        assert_eq!(endpoint_host(""), "");

        // A request with no topology at all must NOT produce something that
        // looks complete: the relay ruleset would then be written from nothing,
        // and a relay with no tunnel port is a deployment cut in half.
        let empty = HostContext::from_request(&pb::InstallServiceRequest {
            host_role: pb::HostRole::VpsRelay as i32,
            ..Default::default()
        });
        assert!(!empty.relay_topology().is_complete());
    }

    /// **The port pre-flight covers every service that publishes one, and the
    /// list comes from the services themselves.**
    ///
    /// The failure this prevents was measured, not imagined: a leftover
    /// scenario-B `wg0` on UDP 51820 made a VPN install die at `up -d` with
    /// docker's `address already in use`, after directories, secrets and image
    /// pulls (`lab-vps`, 2026-08-12). The Swift validator refuses that request
    /// before it generates anything; this route had nothing.
    ///
    /// Two things are pinned here rather than one. That each publishing service
    /// contributes its ports — a service whose ports are the point (mail, VPN,
    /// git-over-SSH) is exactly where a silent gap would cost most — and that
    /// nothing else invents ports: a service with no public publish must produce
    /// an EMPTY list, or every install of it would start querying the host about
    /// ports it never binds.
    #[test]
    fn the_port_preflight_asks_about_the_ports_the_services_themselves_declare() {
        let mut input = Input::default();
        input.domain = "example.com".to_string();

        // VPN: whatever protocols the request named, at the ports it named.
        input.wireguard_vpn_port = 51820;
        input.shadowsocks_port = 8388;
        let vpn = published_public_ports("vpn", &input, &[panel::Protocol::WireGuard, panel::Protocol::Shadowsocks]);
        assert_eq!(vpn, vec![firewall::Port::udp(51820), firewall::Port::tcp(8388), firewall::Port::udp(8388)]);
        // A VPN install that names no protocol publishes nothing of its own.
        assert!(published_public_ports("vpn", &input, &[]).is_empty());

        // Mail: the engine's own declaration, which is also what the firewall
        // drop-in is built from — never a second list.
        for engine in ["docker-mailserver", "mailu", "mailcow"] {
            let ports = published_public_ports(engine, &input, &[]);
            assert!(ports.contains(&firewall::Port::tcp(25)), "{engine} must claim SMTP: {ports:?}");
            assert!(ports.contains(&firewall::Port::tcp(993)), "{engine} must claim IMAPS: {ports:?}");
        }

        // git-over-SSH, and 0 meaning the feature is off.
        input.forgejo_ssh_port = 2222;
        input.gitlab_ssh_port = 2022;
        assert_eq!(published_public_ports("forgejo", &input, &[]), vec![firewall::Port::tcp(2222)]);
        assert_eq!(published_public_ports("gitlab", &input, &[]), vec![firewall::Port::tcp(2022)]);
        input.forgejo_ssh_port = 0;
        assert!(published_public_ports("forgejo", &input, &[]).is_empty());

        // Everything else publishes on loopback only, and must ask nothing.
        for label in ["adguard-home", "vaultwarden", "nextcloud", "immich", "photoprism", "psono", "passbolt"] {
            assert!(published_public_ports(label, &input, &[]).is_empty(), "{label} publishes no public port");
        }

        // And the refusal names the port, the protocol and what to do.
        let (status, code, message) = Rejection::PortsInUse(vec![ports::Conflict {
            port: firewall::Port::udp(51820),
            holder: None,
        }])
        .parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains("51820/udp"), "{message}");
        assert!(message.contains("address already in use"), "{message}");
    }

    /// **The other answer to a taken port: this service is already here, by
    /// hand** (owner, 2026-09-08). The refusal has to say the one thing that
    /// leads somewhere — back it up and install it again from the app — and it
    /// must NOT offer to take the existing copy over, which is the work this
    /// product refuses to inherit.
    #[test]
    fn a_hand_installed_copy_is_refused_with_the_way_forward() {
        let (status, code, message) = Rejection::AlreadyInstalledOutside {
            service: "Ollama".to_string(),
            holder: "ollama".to_string(),
        }
        .parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains("Ollama is already installed"), "{message}");
        assert!(message.contains("back its data up"), "{message}");
        assert!(message.contains("install it again from the app"), "{message}");
        assert!(message.contains("Nothing has been changed"), "{message}");
        // The refusal must not read as an offer to adopt what is there.
        assert!(!message.to_lowercase().contains("take over the existing"), "{message}");
    }

    /// **A service that needs a public name cannot be installed without one.**
    /// The Swift validator has always refused this (`requiresPublicDomain`);
    /// the agent took `local_only` and installed anyway, leaving a mail engine
    /// that can obtain no certificate and receive no mail — a container that
    /// looks broken rather than an install that failed, which is the outcome
    /// this project judges a missing refusal by.
    #[test]
    fn a_service_needing_a_public_name_is_refused_on_a_local_only_deployment() {
        for id in ["mailcow", "mailu", "docker-mailserver", "headscale"] {
            let mut req = pb::InstallServiceRequest::default();
            req.service_id = id.to_string();
            req.domain = "192.168.1.50".to_string();
            req.local_only = true;
            let err = build_input(&req).err().unwrap_or_else(|| panic!("{id} was accepted"));
            assert!(err.contains("public domain"), "{id}: {err}");
        }
    }

    /// The negative half: the SAME services install fine when the deployment
    /// has a real domain, so the refusal is about local-only rather than about
    /// those services.
    #[test]
    fn the_same_services_are_accepted_when_the_deployment_has_a_domain() {
        for id in ["mailcow", "mailu", "docker-mailserver", "headscale"] {
            let mut req = pb::InstallServiceRequest::default();
            req.service_id = id.to_string();
            req.domain = "example.com".to_string();
            req.local_only = false;
            assert!(build_input(&req).is_ok(), "{id} should install on a public deployment");
        }
    }

    /// And a service that needs no public name still installs local-only —
    /// otherwise the check would be refusing local-only itself.
    #[test]
    fn a_service_that_needs_no_public_name_still_installs_local_only() {
        let mut req = pb::InstallServiceRequest::default();
        req.service_id = "adguard-home".to_string();
        req.domain = "192.168.1.50".to_string();
        req.local_only = true;
        assert!(build_input(&req).is_ok());
    }

    /// The app's own ceiling, applied here too: each extra domain is another
    /// site on every web service and another certificate to obtain.
    #[test]
    fn more_additional_domains_than_the_app_allows_are_refused() {
        let mut req = pb::InstallServiceRequest::default();
        req.service_id = "adguard-home".to_string();
        req.domain = "example.com".to_string();

        req.additional_domains =
            (0..MAX_ADDITIONAL_DOMAINS).map(|n| format!("example{n}.org")).collect();
        assert!(build_input(&req).is_ok(), "the ceiling itself must be allowed");

        req.additional_domains =
            (0..MAX_ADDITIONAL_DOMAINS + 1).map(|n| format!("example{n}.org")).collect();
        let err = build_input(&req).expect_err("one over the ceiling is refused");
        assert!(err.contains(&MAX_ADDITIONAL_DOMAINS.to_string()), "{err}");
    }

    /// **A domain listed twice is refused, because the cost lands on the whole
    /// host rather than on this install.**
    ///
    /// The mirrors are built straight off this list, so a repeat writes a site
    /// header naming one host twice — and Caddy then refuses to load the whole
    /// file, taking HTTPS off every service on the machine at the next reload.
    #[test]
    fn a_domain_listed_twice_is_refused_before_anything_is_written() {
        let mut req = pb::InstallServiceRequest::default();
        req.service_id = "adguard-home".to_string();
        req.domain = "example.com".to_string();

        // The ordinary case: two different extras are fine.
        req.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert!(build_input(&req).is_ok());

        // A repeat among the extras...
        req.additional_domains = vec!["example.org".to_string(), "example.org".to_string()];
        let err = build_input(&req).expect_err("a repeated domain is refused");
        assert!(err.contains("example.org"), "{err}");
        assert!(err.contains("twice"), "{err}");

        // ...and the primary domain repeated as an extra, which is the same
        // collision by a different route: the mirror would equal the name.
        req.additional_domains = vec!["example.com".to_string()];
        assert!(build_input(&req).is_err());

        // DNS is case-insensitive, so this is the same name and the same
        // collision — a check that compared bytes would miss it.
        req.additional_domains = vec!["Example.COM".to_string()];
        assert!(build_input(&req).is_err());

        // An empty entry is not a duplicate of another empty entry: it carries
        // no name at all, and refusing here would reject a request over
        // something that names nothing.
        req.additional_domains = vec![String::new(), String::new()];
        assert!(build_input(&req).is_ok());
    }

    /// **An unaccepted licence is refused BEFORE anything is written.**
    ///
    /// The failure this pins is not a wrong file but a crash loop: the itzg
    /// images quit unless `EULA` is `TRUE`, so an install that proceeds anyway
    /// pulls the image, runs `up -d` and leaves a container restarting for
    /// ever. The Swift validator refuses this case and the form promises it
    /// ("it will not be installed"); this is the agent keeping the same
    /// promise on its own route, where a raw RPC reaches it directly.
    #[test]
    fn a_minecraft_install_without_the_licence_is_refused() {
        let mut input = Input::default();

        // Neither edition is accepted by default, so both are refused...
        assert_eq!(licence_not_accepted("minecraft-java", &input), Some("Minecraft (Java)"));
        assert_eq!(licence_not_accepted("minecraft-bedrock", &input), Some("Minecraft (Bedrock)"));

        // ...and accepting one says nothing about the other: two products,
        // two questions, and answering for both at once is exactly what a
        // saved draft is not allowed to do.
        input.minecraft_java_accepts_eula = true;
        assert_eq!(licence_not_accepted("minecraft-java", &input), None);
        assert_eq!(licence_not_accepted("minecraft-bedrock", &input), Some("Minecraft (Bedrock)"));
        input.minecraft_bedrock_accepts_eula = true;
        assert_eq!(licence_not_accepted("minecraft-bedrock", &input), None);

        // The panel carries no licence of its own — it is the games shelf's
        // implicit member, and gating it would refuse the one surface that
        // exists to manage a server that IS allowed to run.
        assert_eq!(licence_not_accepted("crafty-controller", &Input::default()), None);
        // And no other service is touched by this gate.
        for label in ["adguard-home", "nextcloud", "vaultwarden", "vpn"] {
            assert_eq!(licence_not_accepted(label, &Input::default()), None, "{label} needs no licence");
        }

        // The refusal is a pre-stream `failed_precondition`, and it says which
        // edition, why it would not work, and what to do about it.
        let (status, code, message) = Rejection::LicenceNotAccepted("Minecraft (Java)").parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains("Minecraft (Java)"), "{message}");
        assert!(message.contains("EULA"), "{message}");
        assert!(message.contains("restarting forever"), "{message}");
    }

    /// **Every settings key this crate reads, as data.**
    ///
    /// The app spells the same list in `AgentInstallSettings.keys` and sends
    /// all of them on every install, because the host's wrappers are rendered
    /// from the whole deployment's knobs, not one service's. The two lists are
    /// the same deliberate duplication as the `GRYONIXNEXUS_*` markers — a musl
    /// binary cannot link a Swift package — so each side pins it: this test
    /// fails when the crate starts reading a key the app does not send.
    ///
    /// Scanning the SOURCE rather than listing call sites by hand is the
    /// point: a new `settings.get("…")` anywhere in this file is caught
    /// without anyone remembering to update a list.
    #[test]
    fn every_setting_key_the_crate_reads_is_one_the_app_sends() {
        // Sent by `AgentInstallSettings.map(from:)`, plus the two the request
        // carries per call rather than per deployment.
        const SENT: &[&str] = &[
            "mailcow_path", "mailu_path", "mailu_subnet", "docker_mailserver_path",
            "vaultwarden_hostname", "vaultwarden_container", "vaultwarden_data_path",
            "vaultwarden_allow_signups",
            "psono_hostname", "psono_path", "passbolt_hostname", "passbolt_path",
            "nextcloud_hostname", "nextcloud_path", "seafile_hostname", "seafile_path",
            "immich_hostname", "immich_path", "photoprism_hostname", "photoprism_path",
            "jellyfin_hostname", "jellyfin_path", "jellyfin_media_path",
            "minecraft_java_path", "minecraft_java_version", "minecraft_java_flavour",
            "minecraft_java_memory_mb", "minecraft_java_port", "minecraft_java_accepts_eula",
            "minecraft_java_whitelist", "minecraft_java_operators", "minecraft_java_mods",
            "minecraft_bedrock_path", "minecraft_bedrock_version", "minecraft_bedrock_port",
            "minecraft_bedrock_accepts_eula",
            "crafty_hostname", "crafty_path",
            "ollama_path", "ollama_uses_gpu",
            "open_webui_path", "open_webui_hostname", "open_webui_allow_signups",
            "litellm_path", "litellm_hostname",
            "n8n_path", "n8n_hostname",
            "anythingllm_path", "anythingllm_hostname", "qdrant_path",
            "searxng_path", "openclaw_path", "openclaw_hostname",
            "forgejo_hostname", "forgejo_path", "forgejo_ssh_port",
            "gitlab_hostname", "gitlab_path", "gitlab_ssh_port",
            "adguard_hostname", "adguard_path",
            "pihole_hostname", "pihole_path", "pihole_upstreams", "pihole_serves_network",
            "homepage_hostname", "homepage_path",
            "authelia_hostname", "authelia_path", "authelia_protected_services",
            "cloudflared_path",
            "headscale_base_domain", "headscale_hostname", "headscale_path",
            "tailscale_node_name", "tailscale_node_path", "tailscale_login_server",
            "vpn_hostname", "vpn_client_access", "wireguard_vpn_port",
            "amnezia_wg_path", "amnezia_wg_port",
            "shadowsocks_path", "shadowsocks_port",
            "xray_reality_path", "xray_reality_port", "xray_reality_sni",
            "openvpn_path", "openvpn_port",
            "crowdsec_enabled",
            // Per call, not per deployment: WHAT to install, not how — and,
            // for the tunnel, a credential that is fetched fresh each time
            // rather than stored anywhere.
            "vpn_protocols",
            "cloudflared_token",
            "tailscale_auth_key",
        ];

        let source = include_str!("execute.rs");
        let mut read = std::collections::BTreeSet::new();
        for (pattern, skip) in [("settings.get(\"", 13), ("setting(\"", 9)] {
            let mut rest = source;
            while let Some(at) = rest.find(pattern) {
                rest = &rest[at + skip..];
                if let Some(end) = rest.find('"') {
                    let key = &rest[..end];
                    // `setting("…")` also matches `port_setting(req, "…")`,
                    // which is what we want, and nothing else in this file
                    // spells a key any other way.
                    if !key.is_empty() && key.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()) {
                        read.insert(key.to_string());
                    }
                }
            }
        }
        assert!(!read.is_empty(), "the scan found no keys at all — it is broken, not the product");
        let unsent: Vec<&String> = read.iter().filter(|key| !SENT.contains(&key.as_str())).collect();
        assert!(
            unsent.is_empty(),
            "the crate reads settings keys the app never sends: {unsent:?}. A key read here \
             and absent there is a service installed into a directory the app does not know \
             about — add it to AgentInstallSettings too."
        );
    }

    /// The wrappers dispatch on `ServiceRegistry` ids; the agent's catalog
    /// collapses the whole VPN into one. This is the mapping between them, and
    /// getting it wrong produces wrappers that dispatch on nothing.
    #[test]
    fn the_vpn_expands_to_the_panel_and_its_protocols() {
        assert_eq!(
            installed_catalog_ids("vpn", &[panel::Protocol::WireGuard, panel::Protocol::OpenVPN]),
            vec!["vpn-panel", "wireguard-vpn", "openvpn"]
        );
        // Every other label is its own catalog id, and it comes back as the
        // TABLE's static string rather than the caller's bytes.
        assert_eq!(installed_catalog_ids("vaultwarden", &[]), vec!["vaultwarden"]);
        assert!(installed_catalog_ids("not-a-service", &[]).is_empty());
    }

    /// What is already on the host is not in the request, so it is read back
    /// from the containers — whose names are pinned per protocol precisely so
    /// that literals like these stay valid.
    #[test]
    fn a_discovered_vpn_is_read_back_from_its_container_names() {
        let service = pb::Service {
            id: "vpn".to_string(),
            containers: ["vpnpanel", "awgvpn", "shadowsocks", "xray", "openvpn", "something-else"]
                .iter()
                .map(|name| pb::Container { name: name.to_string(), ..Default::default() })
                .collect(),
            ..Default::default()
        };
        let ids = discovered_catalog_ids(&service);
        for expected in ["vpn-panel", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"] {
            assert!(ids.contains(&expected), "{expected} missing from {ids:?}");
        }
        // Plain WireGuard has no container: it runs inside the panel, and the
        // only record of it being OFFERED is the panel's registry, which does
        // not exist in this test's environment.
        assert!(!ids.contains(&"wireguard-vpn"), "{ids:?}");

        let other = pb::Service { id: "nextcloud".to_string(), ..Default::default() };
        assert_eq!(discovered_catalog_ids(&other), vec!["nextcloud"]);
    }

    /// A client that predates `host_role` is not running scenario B through the
    /// agent, and the safe default is the role whose wrapper cleans the LEAST.
    #[test]
    fn an_unspecified_role_is_a_single_host() {
        let ctx = HostContext::from_request(&install_request(&[]));
        assert_eq!(ctx.role, Some(HostRole::SingleHost));
    }

    /// The report's topology follows the role, and local-only drops the PTR —
    /// there is no public address to publish one for.
    #[test]
    fn the_topology_follows_the_role_and_the_scope() {
        let mut req = install_request(&[]);
        req.ptr_ip = "203.0.113.7".to_string();
        req.ptr_hostname = "mail.example.com".to_string();
        req.tunnel_endpoint = "198.51.100.4:51820".to_string();
        let ctx = HostContext::from_request(&req);

        let public = Input { domain: "example.com".to_string(), ..Input::default() };
        match ctx.topology(HostRole::HomeBackend, &public) {
            report::Topology::ServicesHost { ptr_ip, ptr_hostname, tunnel_endpoint } => {
                assert_eq!(ptr_ip.as_deref(), Some("203.0.113.7"));
                assert_eq!(ptr_hostname, "mail.example.com");
                assert_eq!(tunnel_endpoint.as_deref(), Some("198.51.100.4:51820"));
            }
            other => panic!("expected a services host, got {other:?}"),
        }

        let local = Input { local_only: true, ..public.clone() };
        match ctx.topology(HostRole::SingleHost, &local) {
            report::Topology::ServicesHost { ptr_ip, .. } => assert_eq!(ptr_ip, None),
            other => panic!("expected a services host, got {other:?}"),
        }

        // An empty hostname falls back to the domain rather than printing a
        // reminder about "".
        let mut bare = install_request(&[]);
        bare.host_role = pb::HostRole::VpsRelay as i32;
        bare.relay_wg_port = 51820;
        bare.relay_forwarded_ports = vec![80, 443];
        bare.home_wg_address = "10.8.0.2".to_string();
        match HostContext::from_request(&bare).topology(HostRole::VpsRelay, &public) {
            report::Topology::Relay { wg_port, forwarded_ports, home_wg_address, ptr_hostname } => {
                assert_eq!(wg_port, 51820);
                assert_eq!(forwarded_ports, vec![80, 443]);
                assert_eq!(home_wg_address, "10.8.0.2");
                assert_eq!(ptr_hostname, "example.com");
            }
            other => panic!("expected a relay, got {other:?}"),
        }
    }

    /// **A rejected whitelist must never reach `/etc/sudoers.d`.** An invalid
    /// file there breaks `sudo` for every account on the machine, which on a
    /// remote server is indistinguishable from being locked out — so the file
    /// is staged under a name sudo ignores, validated, and only then moved.
    /// This runs a real `visudo` stub against real files.
    #[tokio::test]
    async fn a_whitelist_visudo_rejects_is_not_installed() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("sudoers");
        let live = dir.join("gryonixnexus-control");
        std::fs::write(&live, "previous ALL=(ALL) NOPASSWD: /bin/true\n").unwrap();
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SUDOERS_PATH", &live);

        let input = HostInput {
            services: vec!["vaultwarden".to_string()],
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: Language::En,
            ssh_user: Some("gryonixbot".to_string()),
            role: HostRole::SingleHost,
        };
        let backups = host::uninstall::BackupPaths::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "vaultwarden".to_string(), journal: None, sequence: AtomicU64::new(0) };

        std::env::set_var("GRYONIXNEXUSD_INSTALL_VISUDO_BIN", write_stub(&dir, "visudo-bad", "#!/bin/sh\necho 'parse error' 1>&2\nexit 1\n"));
        let rejected = write_sudoers(&input, &backups, &sink).await;
        assert!(rejected.is_err(), "a rejected whitelist must fail the install");
        assert_eq!(
            std::fs::read_to_string(&live).unwrap(),
            "previous ALL=(ALL) NOPASSWD: /bin/true\n",
            "the live whitelist must be untouched"
        );
        assert!(!dir.join("gryonixnexus-control.staged").exists(), "the staged file must be cleaned up");

        std::env::set_var("GRYONIXNEXUSD_INSTALL_VISUDO_BIN", write_stub(&dir, "visudo-ok", "#!/bin/sh\nexit 0\n"));
        write_sudoers(&input, &backups, &sink).await.expect("an accepted whitelist installs");
        let installed = std::fs::read_to_string(&live).unwrap();
        assert!(installed.contains("gryonixbot ALL=(ALL) NOPASSWD:"), "{installed}");
        assert!(!dir.join("gryonixnexus-control.staged").exists());
        // And what was written is what the NEXT install reads back as the user.
        assert_eq!(existing_control_user().as_deref(), Some("gryonixbot"));

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_VISUDO_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SUDOERS_PATH");
        while rx.try_recv().is_ok() {}
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No whitelist file, no control user — and that is not a failure, it is a
    /// host nobody has ever given SSH management access to.
    #[tokio::test]
    async fn a_host_without_a_whitelist_is_not_a_failure() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("sudoers-absent");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SUDOERS_PATH", dir.join("gryonixnexus-control"));
        assert_eq!(existing_control_user(), None);

        let input = HostInput {
            services: vec!["vaultwarden".to_string()],
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: Language::En,
            ssh_user: None,
            role: HostRole::SingleHost,
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "vaultwarden".to_string(), journal: None, sequence: AtomicU64::new(0) };
        write_sudoers(&input, &host::uninstall::BackupPaths::default(), &sink)
            .await
            .expect("no control user is a normal state");
        assert!(!dir.join("gryonixnexus-control").exists(), "nothing may be written for nobody");

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SUDOERS_PATH");
        while rx.try_recv().is_ok() {}
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn install_request(settings: &[(&str, &str)]) -> pb::InstallServiceRequest {
        pb::InstallServiceRequest {
            service_id: "vpn".to_string(),
            domain: "example.com".to_string(),
            settings: settings.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn no_protocol_named_means_wireguard() {
        // The panel is never installed on its own: the generator injects it
        // BECAUSE a protocol was selected, and WireGuard is the one the panel
        // itself implements.
        assert_eq!(vpn_protocols_from(&install_request(&[])), Ok(vec![panel::Protocol::WireGuard]));
        assert_eq!(
            vpn_protocols_from(&install_request(&[("vpn_protocols", "  ")])),
            Ok(vec![panel::Protocol::WireGuard])
        );
    }

    #[test]
    fn a_protocol_list_is_parsed_trimmed_and_deduplicated() {
        assert_eq!(
            vpn_protocols_from(&install_request(&[("vpn_protocols", " wireguard-vpn , wireguard-vpn ")])),
            Ok(vec![panel::Protocol::WireGuard])
        );
    }

    #[test]
    fn something_that_is_not_a_vpn_protocol_is_a_client_bug() {
        assert!(matches!(
            vpn_protocols_from(&install_request(&[("vpn_protocols", "nextcloud")])),
            Err(Rejection::InvalidRequest(_))
        ));
    }

    /// All five protocols are installable now.
    ///
    /// This test used to assert the OPPOSITE for four of them: срез 4.9
    /// refused AmneziaWG, Shadowsocks, XRay and OpenVPN up front, because a
    /// panel advertising an endpoint (its entry lands in `services.json`,
    /// which is what the SPA renders) with nothing installed to answer on that
    /// port is worse than an honest `failed_precondition`. Each now has its
    /// own compose project and its own installer, so the condition that
    /// justified the refusal is gone — and this assertion is what would notice
    /// if one of them were ever removed from the dispatcher without the gate
    /// being narrowed to match.
    #[test]
    fn every_protocol_in_the_catalog_can_be_installed() {
        for name in ["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"] {
            let chosen = vpn_protocols_from(&install_request(&[("vpn_protocols", name)]))
                .unwrap_or_else(|err| panic!("{name} must be installable, got {err:?}"));
            assert_eq!(chosen.len(), 1, "{name}");
            assert_eq!(chosen[0].service_id(), name);
        }
        assert_eq!(
            vpn_protocols_from(&install_request(&[(
                "vpn_protocols",
                "wireguard-vpn,amnezia-wg,shadowsocks,xray-reality,openvpn"
            )]))
            .expect("the whole catalog at once")
            .len(),
            5
        );
    }

    /// RFC 4648's own test vectors, plus the shape `openssl rand -base64 32`
    /// produces.
    ///
    /// A hand-rolled encoder that is slightly wrong mints a Shadowsocks key
    /// the server accepts and no client can reproduce — a failure that reads
    /// as a protocol bug, from a function nothing else in this crate exercises.
    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected, "{input:?}");
        }
        // 32 bytes → 44 characters ending in one `=`, exactly what the
        // generator's `openssl rand -base64 32` writes into config.json.
        let key = base64_encode(&[0xABu8; 32]);
        assert_eq!(key.len(), 44);
        assert!(key.ends_with('='));
        assert!(!key.ends_with("=="));
    }

    /// The order of a VPN install, pinned STRUCTURALLY over the source — the
    /// same technique `the_installs_order_is_the_one_the_engine_actually_needs`
    /// uses for docker-mailserver, and for the same reason: the full pipeline
    /// needs a real docker and writes to `/opt` and `/etc/caddy`, so no test
    /// on this machine runs it end to end and a reordering would be invisible.
    ///
    /// Two orderings here are not cosmetic:
    /// - the protocols BEFORE the panel: the panel mounts each protocol's
    ///   directory, and its `services.json` — written before its own `up -d`,
    ///   срез 4.9's fourth finding — advertises exactly what exists;
    /// - `services.json` BEFORE the panel's `up -d`, because the panel reads
    ///   it at START to decide whether to bring WireGuard up.
    #[test]
    fn the_protocols_are_installed_before_the_panel_that_advertises_them() {
        let source = include_str!("execute.rs");
        let start = source.find("async fn install_vpn_steps").expect("the function must exist");
        let body = &source[start..];
        let end = body.find("\n/// One protocol's own compose project").expect("the function must end");
        let body = &body[..end];

        let at = |needle: &str| -> usize { body.find(needle).unwrap_or_else(|| panic!("no `{needle}` in the body")) };
        let protocols = at("install_vpn_protocol(input, *protocol, sink)");
        let services_json = at("panel::services_json(input, protocols)");
        let build = at("docker_build_args(panel::IMAGE, &build)");
        let up = at("compose_up(panel::COMPOSE_PROJECT, &dir, sink)");
        let firewall = at("apply_vpn_firewall(input, protocols, sink)");
        let caddy = at("write_caddy_site(&panel::caddy_site_names");

        assert!(protocols < services_json, "protocols exist before the panel is told about them");
        assert!(services_json < build, "the registry is on disk before the image that reads it is built");
        assert!(build < up, "build before up — the image is :local and no registry has it");
        assert!(up < firewall, "ports are opened once something is listening on them");
        assert!(firewall < caddy, "the Caddy site is written last, as in every other service here");
    }

    /// OpenVPN's own internal order, pinned for the same reason.
    ///
    /// The PKI one-shot runs INSIDE the image this step builds, and the client
    /// **A request that carries the connector token must WRITE it, and one
    /// that does not must not clobber what is already there.**
    ///
    /// The two halves matter for opposite reasons. Without the first, a
    /// tunnel install ends with a connector that has no credential and the
    /// deployment is a set of names pointing nowhere. Without the second, a
    /// re-install from a client that happens not to have fetched the token
    /// would empty the file and take a working tunnel down — the same shape as
    /// the `.env` rule every other service follows.
    #[test]
    fn the_tunnel_token_is_written_when_sent_and_left_alone_when_not() {
        let source = include_str!("execute.rs");
        let start = source.find("async fn install_cloudflared_steps").expect("the function must exist");
        let body = &source[start..];
        let end = body.find("\nasync fn install_headscale_steps").expect("the function must end");
        let body = &body[..end];

        let write_at = body.find("TUNNEL_TOKEN={}").expect("the token must be written into .env");
        let guard_at = body.find("input.cloudflared_token.trim().is_empty()").expect("guarded on the token");
        assert!(guard_at < write_at, "the write must sit inside the guard, not before it");
        assert!(body.contains("mode: Some(0o600)"), "the credential's file must be 0600");
        // The other branch keeps `write_env_if_absent`, which is what leaves a
        // host's existing token in place.
        assert!(body.contains("write_env_if_absent"), "an absent token must not rewrite the file");
    }

    /// profile is printed from a PKI that must already exist — so `build`,
    /// then PKI, then profile. Any other order fails on a host, silently
    /// passes here.
    #[test]
    fn the_openvpn_image_is_built_before_the_pki_that_runs_inside_it() {
        let source = include_str!("execute.rs");
        let start = source.find("async fn install_openvpn_steps").expect("the function must exist");
        let body = &source[start..];
        let end = body.find("\n/// Open the selected protocols' ports").expect("the function must end");
        let body = &body[..end];

        let at = |needle: &str| -> usize { body.find(needle).unwrap_or_else(|| panic!("no `{needle}` in the body")) };
        let build_files = at("openvpn::build_files()");
        let build = at("docker_build_args(openvpn::IMAGE, &build)");
        let pki = at("openvpn::pki_script(input)");
        let env = at("openvpn::gryonix_env(input)");
        let profile = at("openvpn::CLIENT_NAME");
        let up = at("compose_up(openvpn::COMPOSE_PROJECT, &dir, sink)");

        assert!(build_files < build, "the Dockerfile and shims exist before the build reads them");
        assert!(build < pki, "the PKI one-shot runs inside the image built above it");
        assert!(pki < env, "gryonix-env is written once the PKI it describes exists");
        assert!(env < profile, "ovpn_getclient sources gryonix-env — it has to be there first");
        assert!(profile < up, "the profile is minted before the daemon starts");
        assert!(
            !body.contains("compose_pull_args(openvpn::COMPOSE_PROJECT"),
            "gryonix-openvpn:local is in no registry — a pull would fail the step for a tag just built here"
        );
    }

    /// Every protocol the gate accepts must have a case in the dispatcher, and
    /// the dispatcher is where a half-ported protocol would hide: it would
    /// install nothing, silently, while the panel advertised it.
    #[test]
    fn every_accepted_protocol_has_an_installer_or_is_the_panel_itself() {
        for name in ["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"] {
            let protocol = vpn_protocols_from(&install_request(&[("vpn_protocols", name)])).unwrap()[0];
            let project = match protocol {
                // The panel IS the WireGuard server — no second project.
                panel::Protocol::WireGuard => panel::COMPOSE_PROJECT,
                panel::Protocol::AmneziaWG => amnezia::COMPOSE_PROJECT,
                panel::Protocol::Shadowsocks => shadowsocks::COMPOSE_PROJECT,
                panel::Protocol::XrayReality => xray::COMPOSE_PROJECT,
                panel::Protocol::OpenVPN => openvpn::COMPOSE_PROJECT,
            };
            assert!(!project.is_empty(), "{name}");
        }
    }

    #[test]
    fn a_zero_or_unparsable_port_keeps_the_apps_own_default() {
        let req = install_request(&[("wireguard_vpn_port", "0"), ("openvpn_port", "not-a-port")]);
        let input = build_input(&req).expect("valid request");
        assert_eq!(input.wireguard_vpn_port, Input::default().wireguard_vpn_port);
        assert_eq!(input.openvpn_port, Input::default().openvpn_port);
        let moved = build_input(&install_request(&[("wireguard_vpn_port", "51999")])).unwrap();
        assert_eq!(moved.wireguard_vpn_port, 51999);
    }

    /// Every path-shaped setting is gated, including the four protocol
    /// directories the panel mounts whether or not those protocols exist —
    /// they are bind-mount sources docker would materialise.
    #[test]
    fn a_protocol_path_that_escapes_is_refused_like_every_other_path() {
        for key in ["amnezia_wg_path", "shadowsocks_path", "xray_reality_path", "openvpn_path", "mailcow_path"] {
            let req = install_request(&[(key, "/opt/../../etc")]);
            assert!(build_input(&req).is_err(), "{key} must be gated");
            assert!(build_input(&install_request(&[(key, "relative/path")])).is_err(), "{key} must be absolute");
        }
    }

    // ───────────────────── the panel's password ─────────────────────

    #[test]
    fn only_a_24_char_lowercase_hex_password_counts_as_generated() {
        assert!(is_generated_panel_password("0123456789abcdef01234567"));
        assert!(!is_generated_panel_password(""));
        // 48 hex chars is `openssl rand -hex 24` — the OTHER secret shape in
        // this crate, and not this one.
        assert!(!is_generated_panel_password(&"ab".repeat(24)));
        assert!(!is_generated_panel_password("0123456789ABCDEF01234567"));
        assert!(!is_generated_panel_password("hunter2-hunter2-hunter22"));
    }

    /// The panel's `.env` is rewritten on every run, so preserving the
    /// password is what keeps a saved install report accurate — and rotating a
    /// non-generated one is what clears a stale custom password that compose
    /// interpolation would mangle.
    #[test]
    fn a_generated_panel_password_survives_a_rerun_and_anything_else_rotates() {
        let dir = tmp("panel-pw");

        // No .env at all: fresh secret, 24 hex chars.
        let (fresh, kept) = resolve_panel_password(&dir).unwrap();
        assert!(!kept);
        assert!(is_generated_panel_password(&fresh), "{fresh}");

        // A generated one is carried forward untouched.
        std::fs::write(dir.join(".env"), format!("ADMIN_USER=admin\nADMIN_PASSWORD={fresh}\nWG_PORT=51820\n")).unwrap();
        assert_eq!(resolve_panel_password(&dir).unwrap(), (fresh.clone(), true));

        // Anything else is replaced rather than carried.
        std::fs::write(dir.join(".env"), "ADMIN_PASSWORD=my own p@ssword\n").unwrap();
        let (rotated, kept) = resolve_panel_password(&dir).unwrap();
        assert!(!kept);
        assert_ne!(rotated, "my own p@ssword");
        assert!(is_generated_panel_password(&rotated), "{rotated}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ───────────────────── the panel's docker argv ─────────────────────

    /// The panel is BUILT, never pulled: `gryonix-vpn-panel:local` is our own
    /// application compiled on the server, and no registry has heard of that
    /// tag — a `compose pull` would fail on it.
    #[test]
    fn the_panel_is_built_from_its_own_sources_and_never_pulled() {
        assert_eq!(
            docker_build_args(panel::IMAGE, Path::new("/opt/gryonix-vpn-panel/build")),
            ["build", "-t", "gryonix-vpn-panel:local", "/opt/gryonix-vpn-panel/build"]
        );
    }

    /// `--filter name=` is a SUBSTRING match, so the "does it already exist"
    /// probe has to anchor — a leftover `vpnpanel-old` would otherwise answer
    /// for `vpnpanel` and make every install skip the restart it needs.
    #[test]
    fn the_container_probe_anchors_the_name() {
        let args = docker_container_exists_args("vpnpanel");
        assert_eq!(args, ["ps", "-aq", "--filter", "name=^vpnpanel$"]);
    }

    #[test]
    fn every_implemented_id_resolves_to_its_own_compose_project() {
        // The gate and the project table have to agree: an id that resolves
        // but falls through `compose_project`'s match would install one
        // service and report another's project in STARTED.
        for id in IMPLEMENTED_SERVICE_IDS {
            assert_eq!(resolve(id), Ok(*id), "{id} must resolve");
        }
        assert_eq!(compose_project("adguard-home"), adguard::COMPOSE_PROJECT);
        assert_eq!(compose_project("jellyfin"), jellyfin::COMPOSE_PROJECT);
        assert_eq!(compose_project("photoprism"), photoprism::COMPOSE_PROJECT);
        assert_eq!(compose_project("immich"), immich::COMPOSE_PROJECT);
        assert_eq!(compose_project("nextcloud"), nextcloud::COMPOSE_PROJECT);
        assert_eq!(compose_project("forgejo"), forgejo::COMPOSE_PROJECT);
        assert_eq!(compose_project("gitlab"), gitlab::COMPOSE_PROJECT);
        assert_eq!(compose_project("vaultwarden"), vaultwarden::COMPOSE_PROJECT);
        assert_eq!(compose_project("seafile"), seafile::COMPOSE_PROJECT);
        assert_eq!(compose_project("psono"), psono::COMPOSE_PROJECT);
        assert_eq!(compose_project("passbolt"), passbolt::COMPOSE_PROJECT);
    }

    #[test]
    fn adguard_home_resolves() {
        assert_eq!(resolve("adguard-home"), Ok("adguard-home"));
    }

    #[test]
    fn rejection_codes_are_distinct_and_echo_the_id() {
        let (status, code, message) = Rejection::UnknownService("zzz".into()).parts();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "invalid_argument");
        assert!(message.contains("zzz"));

        let (status, code, message) = Rejection::NotImplemented("gitlab".into()).parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains("gitlab"));

        let (status, code, _) = Rejection::DockerUnavailable("boom".into()).parts();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "unavailable");
    }

    #[test]
    fn echoed_client_input_is_bounded() {
        let long = "a".repeat(5000);
        let (_, _, message) = Rejection::UnknownService(long).parts();
        assert!(message.len() < 200, "message was {} bytes", message.len());
    }

    // ─────────────────────────── reload_caddy ───────────────────────────

    /// The exact scenario a freshly provisioned host is in: `caddy` is
    /// installed but the unit has never been started, so `reload` fails
    /// (nothing to reload) and `restart` is what actually brings it up.
    #[tokio::test]
    async fn reload_falls_back_to_restart_and_succeeds_when_restart_does() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("systemctl-restart-ok");
        let script = write_stub(&dir, "systemctl", "#!/bin/sh\ncase \"$1\" in\n  reload) exit 1 ;;\n  restart) exit 0 ;;\nesac\n");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "adguard-home".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = reload_caddy(&sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN");
        assert_eq!(result, Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Both reload and restart failing must NOT be swallowed — this is the
    /// bug the review caught: the old version returned `Ok`-shaped success
    /// (a bare `()`, nothing to check) no matter what happened here, so the
    /// RPC reported COMPLETED as if the site had actually gone live.
    #[tokio::test]
    async fn reload_and_restart_both_failing_is_a_real_error_not_a_silent_no_op() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("systemctl-both-fail");
        let script = write_stub(&dir, "systemctl", "#!/bin/sh\nexit 1\n");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "adguard-home".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = reload_caddy(&sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN");
        assert!(result.is_err(), "both systemctl calls failing must surface as Err");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The live gap of 2026-08-13: the site went live and the unit stayed
    /// `disabled`, so HTTPS would not have come back after a reboot. The stub
    /// records argv, and the assertion is that `enable` is among the calls —
    /// a test that only checked the return value passed BEFORE the fix.
    #[tokio::test]
    async fn a_caddy_unit_that_is_not_enabled_gets_enabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("systemctl-enable");
        let log = dir.join("argv.log");
        let script = write_stub(
            &dir,
            "systemctl",
            &format!(
                "#!/bin/sh\necho \"$@\" >> '{}'\ncase \"$1\" in\n  reload) exit 1 ;;\n  is-enabled) exit 1 ;;\n  *) exit 0 ;;\nesac\n",
                log.display()
            ),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "vaultwarden".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = reload_caddy(&sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN");
        assert_eq!(result, Ok(()));
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(calls.contains("restart caddy"), "the site must be made live first: {calls}");
        assert!(calls.contains("enable caddy"), "a disabled unit must be enabled: {calls}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other direction, so the fix does not become "run enable on every
    /// install forever": a unit that is already enabled is left alone.
    #[tokio::test]
    async fn an_already_enabled_caddy_unit_is_not_touched_again() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("systemctl-already-enabled");
        let log = dir.join("argv.log");
        let script = write_stub(
            &dir,
            "systemctl",
            &format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 0\n", log.display()),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "vaultwarden".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = reload_caddy(&sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN");
        assert_eq!(result, Ok(()));
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(calls.contains("is-enabled caddy"), "it must ASK before enabling: {calls}");
        assert!(!calls.contains("enable caddy\n") || calls.matches("enable caddy").count() == 1,
                "an already-enabled unit must not be re-enabled: {calls}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────── the erase-time app key ───────────────────────

    /// A host the agent built alone has no wrapper to recover the key from,
    /// and before this the generated wrapper simply carried no strip block —
    /// `--all` would have left the app with live SSH access. Measured on
    /// `vps-middle` 2026-08-13: zero `authorized_keys` references where a
    /// setup-built host carries six.
    #[test]
    fn with_no_wrapper_on_disk_the_requested_key_is_what_gets_revoked() {
        let access = dashboard_access("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRequested app")
            .expect("a well-formed requested key is usable");
        assert!(access.create_user, "the strip block only renders in create-user mode");
        assert_eq!(access.app_public_key, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRequested app");
    }

    /// The guard that keeps the key inside the shell literal the wrapper
    /// embeds it in — the same one `provision::app_public_key` applies to what
    /// it reads back off disk.
    #[test]
    fn a_key_that_could_break_out_of_the_shell_literal_is_refused() {
        assert!(dashboard_access("").is_none());
        assert!(dashboard_access("   ").is_none());
        assert!(dashboard_access("ssh-ed25519 AAA' ; rm -rf / ; echo '").is_none());
        assert!(dashboard_access("ssh-ed25519 AAA\nssh-ed25519 BBB").is_none());
    }

    // ─────────────────────────── adguard_path safety ───────────────────────────

    #[test]
    fn a_relative_or_dotdot_riding_path_is_rejected() {
        assert!(!is_safe_absolute_path("opt/adguardhome"));
        assert!(!is_safe_absolute_path("/opt/../etc"));
        assert!(!is_safe_absolute_path("../etc"));
        assert!(is_safe_absolute_path("/opt/adguardhome"));
        assert!(is_safe_absolute_path("/srv/adguard"));
    }

    #[test]
    fn build_input_refuses_a_dotdot_riding_adguard_path_before_anything_is_touched() {
        let mut req = base_request();
        req.settings.insert("adguard_path".to_string(), "/opt/../etc".to_string());
        let err = build_input(&req).unwrap_err();
        assert!(err.contains("adguard_path"), "{err}");
    }

    // ─────────────────────────── build_input ───────────────────────────

    fn base_request() -> pb::InstallServiceRequest {
        pb::InstallServiceRequest {
            service_id: "adguard-home".to_string(),
            domain: "example.com".to_string(),
            additional_domains: Vec::new(),
            local_only: false,
            admin_username: "admin".to_string(),
            language: "ru".to_string(),
            settings: HashMap::new(),
            // The host-surface half of the request. Left at its defaults here
            // — a test that cares sets what it needs, and UNSPECIFIED is the
            // wire's own "single host", which is what these cases are.
            ..Default::default()
        }
    }

    #[test]
    fn an_empty_domain_is_refused() {
        let mut req = base_request();
        req.domain = "   ".to_string();
        assert_eq!(build_input(&req), Err("domain is required".to_string()));
    }

    #[test]
    fn settings_feed_the_service_specific_fields_with_defaults_when_absent() {
        let input = build_input(&base_request()).unwrap();
        assert_eq!(input.adguard_path, "/opt/adguardhome");
        assert_eq!(input.adguard_hostname, "");
        assert!(matches!(input.language, Language::Ru));

        let mut req = base_request();
        req.settings.insert("adguard_path".to_string(), "/srv/adguard".to_string());
        req.settings.insert("adguard_hostname".to_string(), "filter.example.com".to_string());
        let input = build_input(&req).unwrap();
        assert_eq!(input.adguard_path, "/srv/adguard");
        assert_eq!(input.adguard_hostname, "filter.example.com");
    }

    #[test]
    fn an_unrecognized_language_code_falls_back_to_english() {
        let mut req = base_request();
        req.language = "xx-nonexistent".to_string();
        let input = build_input(&req).unwrap();
        assert!(matches!(input.language, Language::En));
    }

    // ─────────────────────────── __RANDOM__ expansion ───────────────────────────

    #[test]
    fn each_random_line_gets_its_own_independent_secret() {
        let template = "A=__RANDOM__\nB=__RANDOM__\nC=fixed\n";
        let expanded = expand_random(template).unwrap();
        let lines: Vec<&str> = expanded.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("A="));
        assert!(lines[1].starts_with("B="));
        assert_eq!(lines[2], "C=fixed");
        let a = lines[0].strip_prefix("A=").unwrap();
        let b = lines[1].strip_prefix("B=").unwrap();
        assert_ne!(a, b, "two __RANDOM__ lines must not receive the same secret");
        assert_eq!(a.len(), 48, "24 bytes as hex is 48 characters, matching `openssl rand -hex 24`");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn expansion_ends_with_a_trailing_newline_like_the_bash_loop() {
        let expanded = expand_random("ADGUARD_ADMIN_PASSWORD=__RANDOM__").unwrap();
        assert!(expanded.ends_with('\n'));
        assert_eq!(expanded.lines().count(), 1);
    }

    // ─────────────────────────── .env idempotence ───────────────────────────

    #[test]
    fn env_is_written_only_when_absent_and_gets_mode_0600() {
        let dir = tmp("env-idempotence");
        let wrote = write_env_if_absent(&dir, &adguard::env_template()).unwrap();
        assert!(wrote);
        let env_path = dir.join(".env");
        assert!(env_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let first = std::fs::read_to_string(&env_path).unwrap();

        // Re-running must NOT touch the existing secret.
        let wrote_again = write_env_if_absent(&dir, &adguard::env_template()).unwrap();
        assert!(!wrote_again);
        let second = std::fs::read_to_string(&env_path).unwrap();
        assert_eq!(first, second, "an existing .env's secret must survive a re-run");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_env_value_reads_the_generated_secret() {
        let dir = tmp("env-read");
        std::fs::write(dir.join(".env"), "ADGUARD_ADMIN_PASSWORD=deadbeef\nOTHER=1\n").unwrap();
        assert_eq!(
            read_env_value(&dir.join(".env"), "ADGUARD_ADMIN_PASSWORD"),
            Some("deadbeef".to_string())
        );
        assert_eq!(read_env_value(&dir.join(".env"), "MISSING"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────── DoH key patch ───────────────────────────

    #[test]
    fn the_new_spelling_is_preferred_and_flipped_to_true() {
        let yaml = "tls:\n  enabled: true\nhttp:\n  doh:\n    insecure_enabled: false\n";
        let (patched, spelling) = patch_doh_insecure(yaml);
        assert_eq!(spelling, Some(DohSpelling::InsecureEnabled));
        assert!(patched.contains("    insecure_enabled: true"));
        assert!(!patched.contains("insecure_enabled: false"));
    }

    #[test]
    fn the_old_spelling_is_used_when_the_new_one_is_absent() {
        let yaml = "tls:\n  allow_unencrypted_doh: false\n  enabled: true\n";
        let (patched, spelling) = patch_doh_insecure(yaml);
        assert_eq!(spelling, Some(DohSpelling::AllowUnencryptedDoh));
        assert!(patched.contains("  allow_unencrypted_doh: true"));
    }

    #[test]
    fn neither_spelling_present_leaves_the_file_untouched_and_says_so() {
        let yaml = "tls:\n  enabled: true\n";
        let (patched, spelling) = patch_doh_insecure(yaml);
        assert_eq!(spelling, None);
        assert_eq!(patched, yaml);
    }

    #[test]
    fn a_key_already_true_is_recognized_but_not_rewritten() {
        let yaml = "http:\n  doh:\n    insecure_enabled: true\n";
        let (patched, spelling) = patch_doh_insecure(yaml);
        assert_eq!(spelling, Some(DohSpelling::InsecureEnabled));
        assert_eq!(patched, yaml, "an already-true key must not be rewritten, only recognized");
    }

    #[test]
    fn a_line_with_trailing_content_is_not_treated_as_the_exact_false_match() {
        // sed's own anchoring: `insecure_enabled: false  # comment` is NOT
        // `^ *insecure_enabled: false$` — the key is still "found" (grep
        // matches the prefix), so no "missing" message, but the line itself
        // must be left exactly as it was.
        let yaml = "    insecure_enabled: false  # todo\n";
        let (patched, spelling) = patch_doh_insecure(yaml);
        assert_eq!(spelling, Some(DohSpelling::InsecureEnabled));
        assert_eq!(patched, yaml);
    }

    #[test]
    fn preserves_indentation_and_trailing_newline_shape() {
        let yaml = "a:\n  b:\n      insecure_enabled: false";
        let (patched, _) = patch_doh_insecure(yaml);
        assert_eq!(patched, "a:\n  b:\n      insecure_enabled: true");
        assert!(!patched.ends_with('\n'), "no trailing newline in, none out");
    }

    // ─────────────────────────── language mapping ───────────────────────────

    #[test]
    fn every_wired_code_maps_and_unknown_falls_back_to_english() {
        assert!(matches!(language_from_code("de"), Language::De));
        assert!(matches!(language_from_code("fr"), Language::Fr));
        assert!(matches!(language_from_code("es"), Language::Es));
        assert!(matches!(language_from_code("ru"), Language::Ru));
        assert!(matches!(language_from_code("uk"), Language::Uk));
        assert!(matches!(language_from_code("it"), Language::It));
        assert!(matches!(language_from_code("ja"), Language::Ja));
        assert!(matches!(language_from_code("zh"), Language::Zh));
        assert!(matches!(language_from_code("en"), Language::En));
        assert!(matches!(language_from_code(""), Language::En));
        assert!(matches!(language_from_code("klingon"), Language::En));
    }

    // ─────────────────────────── JSON body shaping ───────────────────────────

    #[test]
    fn json_escape_handles_quotes_and_backslashes() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(json_escape("plain"), "plain");
    }

    #[test]
    fn bounded_strips_newlines_and_caps_length() {
        assert_eq!(bounded("line1\r\nline2\n", 100), "line1line2");
        assert_eq!(bounded(&"x".repeat(500), 300).len(), 300);
    }

    // ─────────────────────────── HTTP client, against a REAL loopback socket ───────────────────────────

    /// `http_request`/`parse_http_response` against a REAL `TcpListener` on
    /// loopback, standing in for AdGuard's install API — not a canned-bytes
    /// unit test of the parser alone. Proves the request this module sends
    /// is one a real HTTP/1.1 server can read, and that the response this
    /// module parses is what a real server sends back.
    #[tokio::test]
    async fn a_real_loopback_server_round_trips_status_and_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = br#"{"ok":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(body).await.unwrap();
            socket.shutdown().await.unwrap();
            request
        });

        let (code, body) = http_request(
            "127.0.0.1",
            addr.port(),
            "POST",
            "/control/install/configure",
            Some(br#"{"username":"admin"}"#),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let request = server.await.unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, r#"{"ok":true}"#);
        assert!(request.starts_with("POST /control/install/configure HTTP/1.1\r\n"));
        assert!(request.contains("Content-Length: 20\r\n"));
        assert!(request.ends_with(r#"{"username":"admin"}"#));
    }

    #[tokio::test]
    async fn connecting_to_a_closed_port_fails_fast_with_a_readable_error() {
        // Bind and immediately drop, so the port is (almost certainly) not
        // listening by the time we connect — enough to prove connection
        // failure is a `Result::Err`, not a panic or a hang.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let result = http_request("127.0.0.1", addr.port(), "GET", "/", None, Duration::from_secs(2)).await;
        assert!(result.is_err());
    }

    #[test]
    fn parse_http_response_reads_status_and_body_and_rejects_garbage() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno";
        assert_eq!(parse_http_response(raw), Ok((404, "no".to_string())));
        assert!(parse_http_response(b"not http at all").is_err());
        assert!(parse_http_response(b"").is_err());
    }

    // ─────────────────────── срез 4.3: jellyfin + vaultwarden ───────────────────────

    fn wire_request(service_id: &str, settings: &[(&str, &str)]) -> pb::InstallServiceRequest {
        let mut req = pb::InstallServiceRequest {
            service_id: service_id.to_string(),
            domain: "example.com".to_string(),
            ..Default::default()
        };
        for (key, value) in settings {
            req.settings.insert(key.to_string(), value.to_string());
        }
        req
    }

    /// Absent settings must land on Swift's OWN `ServiceSettings` defaults:
    /// the app sends only what the operator changed, so a different default
    /// here means the agent installs into a different directory (or with a
    /// different signups policy) than the app reports it did.
    #[test]
    fn an_empty_request_falls_back_to_the_swift_side_defaults() {
        let input = build_input(&wire_request("vaultwarden", &[])).unwrap();
        assert_eq!(input.vaultwarden_container, "vaultwarden");
        assert_eq!(input.vaultwarden_data_path, "/opt/vaultwarden/data");
        assert!(input.vaultwarden_allow_signups);
        assert_eq!(input.jellyfin_path, "/opt/jellyfin");
        assert_eq!(input.jellyfin_media_path, "/srv/media");
        assert_eq!(input.photoprism_path, "/opt/photoprism");
        assert_eq!(input.immich_path, "/opt/immich");
        assert_eq!(input.nextcloud_path, "/opt/nextcloud");
        assert_eq!(input.forgejo_path, "/opt/forgejo");
        assert_eq!(input.forgejo_ssh_port, 2222);
        assert_eq!(input.gitlab_path, "/opt/gitlab-ce");
        assert_eq!(input.gitlab_ssh_port, 2223);
        assert_eq!(input.adguard_path, "/opt/adguardhome");
        assert_eq!(input.seafile_path, "/opt/seafile");
        assert_eq!(input.psono_path, "/opt/psono");
        assert_eq!(input.passbolt_path, "/opt/passbolt");
    }

    /// Only an explicit "false" closes registrations — an unrecognized or
    /// empty value must not silently close a password server's signups that
    /// the SSH path would have left open.
    #[test]
    fn the_signups_toggle_is_only_closed_by_an_explicit_false() {
        let closed = build_input(&wire_request("vaultwarden", &[("vaultwarden_allow_signups", "false")])).unwrap();
        assert!(!closed.vaultwarden_allow_signups);
        let open = build_input(&wire_request("vaultwarden", &[("vaultwarden_allow_signups", "true")])).unwrap();
        assert!(open.vaultwarden_allow_signups);
        let garbage = build_input(&wire_request("vaultwarden", &[("vaultwarden_allow_signups", "yes")])).unwrap();
        assert!(garbage.vaultwarden_allow_signups);
    }

    /// EVERY path-shaped setting is gated, not just the named service's —
    /// a gate that only covers the dispatched service stops working the day
    /// the dispatch changes.
    #[test]
    fn every_path_setting_is_gated_whatever_service_the_request_names() {
        for key in [
            "adguard_path",
            "vaultwarden_data_path",
            "jellyfin_path",
            "jellyfin_media_path",
            "photoprism_path",
            "immich_path",
            "nextcloud_path",
            "forgejo_path",
            "gitlab_path",
            "seafile_path",
            "psono_path",
            "passbolt_path",
        ] {
            let relative = build_input(&wire_request("jellyfin", &[(key, "opt/somewhere")]));
            assert!(relative.is_err(), "{key}: a relative path must be refused");
            let escaping = build_input(&wire_request("jellyfin", &[(key, "/opt/../etc")]));
            assert!(escaping.is_err(), "{key}: a '..' component must be refused");
        }
    }

    /// A library that already exists keeps ITS mode — the product does not
    /// own the user's media directory and must not re-permission it.
    #[test]
    fn an_existing_library_directory_is_left_exactly_as_it_was() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("library");
        let existing = dir.join("library");
        std::fs::create_dir_all(&existing).unwrap();
        set_mode(&existing, 0o700).unwrap();

        assert!(!create_dir_if_absent_0755(&existing).unwrap());
        let mode = std::fs::metadata(&existing).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "an existing library must keep its own mode");

        let fresh = dir.join("fresh");
        assert!(create_dir_if_absent_0755(&fresh).unwrap());
        assert_eq!(std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777, 0o755);
    }

    /// Every `ports:` entry of every service the agent installs has to be
    /// understood by the pre-flight's parser.
    ///
    /// **A parser that silently drops a shape it does not read is the whole
    /// hazard here**: the service would install, publish a port nothing
    /// checked, and lose the race exactly as AdGuard did on `vps-middle`. So
    /// the entries are counted a SECOND way — by shape, straight off the text,
    /// with no code shared with the parser — and the two counts have to agree.
    #[test]
    fn every_catalog_port_entry_is_understood() {
        let input = Input { domain: "example.com".to_string(), ..Input::default() };
        let mut seen_any = false;
        for label in IMPLEMENTED_SERVICE_IDS {
            let Some(compose) = compose_text_of(label, &input) else { continue };
            // A published entry, judged by its shape alone: an optional IPv4
            // address, then two port numbers. A volume (`- /opt/x:/opt/x`, or
            // `- data:/var/lib`) can never match this, which is what makes it
            // an independent count rather than the parser written twice.
            let by_shape = compose
                .lines()
                .map(str::trim)
                .filter(|line| {
                    let Some(entry) = line.strip_prefix("- ") else { return false };
                    let entry = entry.trim_matches('"');
                    let body = entry.split('/').next().unwrap_or(entry);
                    let fields: Vec<&str> = body.split(':').collect();
                    match fields.len() {
                        2 => fields.iter().all(|f| f.parse::<u16>().is_ok()),
                        3 => {
                            fields[0].split('.').count() == 4
                                && fields[1..].iter().all(|f| f.parse::<u16>().is_ok())
                        }
                        _ => false,
                    }
                })
                .count();
            let parsed = ports::published_in_compose(&compose).len();
            assert_eq!(parsed, by_shape, "{label}: the pre-flight reads {parsed} of {by_shape} published ports");
            seen_any |= by_shape > 0;
        }
        assert!(seen_any, "the fixture stopped producing compose bodies with ports at all");
    }

    /// The `vps-middle` defect, at the level the RPC actually decides it: what
    /// AdGuard asks the host for has to include its loopback publishes, or the
    /// agent route keeps installing a second DNS filter over the first.
    #[test]
    fn adguard_asks_for_its_loopback_publishes_and_not_only_public_ports() {
        let input = Input { domain: "example.com".to_string(), ..Input::default() };
        let wanted = published_ports_of("adguard-home", &input, &[]);
        let mapping = |address: &str, port: firewall::Port| {
            wanted.iter().any(|w| w.address == address && w.port == port)
        };
        assert!(mapping("127.0.0.1", firewall::Port::tcp(53)), "{wanted:?}");
        assert!(mapping("127.0.0.1", firewall::Port::udp(53)), "{wanted:?}");
        assert!(mapping("127.0.0.1", firewall::Port::tcp(8087)), "{wanted:?}");
    }

    /// The `vps-middle` container, in the terms this check sees it: AdGuard
    /// running with an EMPTY published-port set while its compose file
    /// declares three mappings. `up -d` answered 0 for exactly that state.
    #[test]
    fn a_container_running_without_its_ports_is_reported_by_name() {
        let input = Input { domain: "example.com".to_string(), ..Input::default() };
        let wanted = ports::published_in_compose(&adguard::compose_contents(&input));
        assert_eq!(wanted.len(), 3, "the fixture stopped publishing what this test is about");

        let missing = missing_publishes(&wanted, &[]);
        assert_eq!(missing, vec!["8087/tcp", "53/tcp", "53/udp"]);

        // The same containers WITH their ports are not a complaint — the
        // second half of the pair, without which the assertion above proves
        // only that the function returns something.
        let live: Vec<firewall::Port> = wanted.iter().map(|w| w.port).collect();
        assert!(missing_publishes(&wanted, &live).is_empty());
    }

    fn vw_input() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn a_missing_vaultwarden_config_is_no_change_at_all() {
        let dir = tmp("vw-missing");
        assert_eq!(sync_vaultwarden_config(&dir.join("config.json"), &vw_input()), Ok(false));
    }

    /// The stored policy already agrees — the file must NOT be rewritten,
    /// which is also what keeps the install from restarting a healthy
    /// container on every re-run.
    #[test]
    fn a_config_that_already_agrees_is_left_untouched() {
        let dir = tmp("vw-agrees");
        let path = dir.join("config.json");
        let original = "{\"signups_allowed\":true,\"domain\":\"https://vault.example.com\",\"other\":1}";
        std::fs::write(&path, original).unwrap();
        assert_eq!(sync_vaultwarden_config(&path, &vw_input()), Ok(false));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    /// The app's toggle OUTRANKS what /admin stored — this is the whole
    /// reason the sync exists: without it a user who once closed signups in
    /// /admin could never reopen them from the app.
    #[test]
    fn the_apps_toggle_wins_over_the_stored_one_and_keeps_the_other_keys() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("vw-toggle");
        let path = dir.join("config.json");
        std::fs::write(&path, "{\"signups_allowed\":false,\"icon_service\":\"internal\"}").unwrap();

        assert_eq!(sync_vaultwarden_config(&path, &vw_input()), Ok(true));
        let stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(stored["signups_allowed"], serde_json::Value::Bool(true));
        assert_eq!(stored["icon_service"], serde_json::Value::String("internal".into()));
        // Absent means the compose environment still rules: the sync must
        // not INVENT a stored domain, because a stored one outranks env.
        assert!(stored.get("domain").is_none(), "domain must not be added when it was absent");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// A stored domain from an earlier install on another name would keep
    /// serving links to that name — present means it outranks the compose
    /// environment, so it gets rewritten.
    #[test]
    fn a_stored_domain_from_an_older_install_is_rewritten() {
        let dir = tmp("vw-domain");
        let path = dir.join("config.json");
        std::fs::write(&path, "{\"signups_allowed\":true,\"domain\":\"https://vault.old-domain.net\"}").unwrap();

        assert_eq!(sync_vaultwarden_config(&path, &vw_input()), Ok(true));
        let stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(stored["domain"], serde_json::Value::String("https://vault.example.com".into()));
    }

    /// jq's `(.domain // $d) == $d`: a null (or false) stored domain falls
    /// through to the desired one and compares EQUAL, so it is not a reason
    /// to rewrite on its own.
    #[test]
    fn a_null_stored_domain_is_not_a_reason_to_rewrite() {
        let dir = tmp("vw-null-domain");
        let path = dir.join("config.json");
        let original = "{\"signups_allowed\":true,\"domain\":null}";
        std::fs::write(&path, original).unwrap();
        assert_eq!(sync_vaultwarden_config(&path, &vw_input()), Ok(false));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    /// A config file we cannot parse is an ERROR the caller narrates, not a
    /// silent success — but it is also not fatal to the install (see
    /// `install_vaultwarden_steps`).
    #[test]
    fn an_unparsable_config_is_reported_rather_than_overwritten() {
        let dir = tmp("vw-garbage");
        let path = dir.join("config.json");
        std::fs::write(&path, "not json at all").unwrap();
        assert!(sync_vaultwarden_config(&path, &vw_input()).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json at all");
    }

    /// The Email column is the trap: `forgejo admin user list` prints
    /// `<id> <username> <email> …`, so a bare substring match on the
    /// username would also hit an unrelated account whose ADDRESS starts
    /// with it — and the install would then skip creating the administrator,
    /// leaving a forge nobody can log into.
    #[test]
    fn an_admin_is_recognised_by_the_username_column_only() {
        let listing = "ID   Username   Email                  IsActive\n\
                       1    alice      admin@example.com      true\n";
        assert!(!admin_listed(listing, "admin"), "an address must not count as the username");
        assert!(admin_listed(listing, "alice"));
        assert!(!admin_listed("", "admin"));
        // The header row has no numeric id and must never match.
        assert!(!admin_listed("ID Username Email\n", "Username"));
    }

    /// A port that treated an unparsable port as "off" would silently drop
    /// the published SSH port and break every existing clone URL.
    #[test]
    fn an_unparsable_ssh_port_keeps_the_default_rather_than_switching_ssh_off() {
        let garbage = build_input(&wire_request("forgejo", &[("forgejo_ssh_port", "yes please")])).unwrap();
        assert_eq!(garbage.forgejo_ssh_port, 2222);
        let off = build_input(&wire_request("forgejo", &[("forgejo_ssh_port", "0")])).unwrap();
        assert_eq!(off.forgejo_ssh_port, 0);
        let custom = build_input(&wire_request("forgejo", &[("forgejo_ssh_port", "2022")])).unwrap();
        assert_eq!(custom.forgejo_ssh_port, 2022);
    }

    /// Slot 0 is the image installer's own "localhost" entry: writing over
    /// it cuts local access off, which is why the first name goes into slot
    /// 1. Every mirrored name gets its own slot — a name Caddy serves but
    /// Nextcloud does not trust answers "Access through untrusted domain".
    #[test]
    fn occ_writes_trusted_domains_from_slot_one_and_covers_every_mirror() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.additional_domains = vec!["example.org".to_string()];
        let settings = occ_settings(&input);
        assert_eq!(
            settings,
            vec![
                ("trusted_domains 1".to_string(), "files.example.com".to_string()),
                ("trusted_domains 2".to_string(), "files.example.org".to_string()),
                ("overwritehost".to_string(), "files.example.com".to_string()),
                ("overwriteprotocol".to_string(), "https".to_string()),
                ("overwrite.cli.url".to_string(), "https://files.example.com".to_string()),
            ]
        );
    }

    /// `trusted_domains <n>` is TWO argv elements to occ, and `--value=` is
    /// one — a key passed whole would set a config named "trusted_domains 1".
    #[test]
    fn an_occ_call_splits_the_key_and_keeps_the_value_in_one_argument() {
        let mut argv = vec!["config:system:set"];
        let key = "trusted_domains 2";
        argv.extend(key.split(' '));
        let value = "--value=cloud.example.org".to_string();
        argv.push(&value);
        let args = exec_args("www-data", "abc123", &["php", "occ"]);
        assert_eq!(args, vec!["exec", "-u", "www-data", "abc123", "php", "occ"]);
        assert_eq!(argv, vec!["config:system:set", "trusted_domains", "2", "--value=cloud.example.org"]);
    }

    /// The container reports up within seconds; the runit services do not.
    /// Puma BY NAME, because it is the one that serves the page — a `run:`
    /// line for redis alone proves nothing, and a probe satisfied by it
    /// would try to close sign-up against a database that is still migrating.
    #[test]
    fn readiness_needs_puma_specifically_and_running() {
        assert!(puma_running("run: puma: (pid 123) 45s; run: log: (pid 124) 45s\n"));
        assert!(!puma_running("run: redis: (pid 99) 60s\n"));
        assert!(!puma_running("down: puma: 1s, normally up\n"));
        // Not a substring match: another service whose status line merely
        // mentions puma must not pass.
        assert!(!puma_running("run: gitlab-workhorse: (pid 5) 1s; waiting for puma\n"));
        assert!(!puma_running(""));
    }

    #[test]
    fn an_unparsable_gitlab_ssh_port_keeps_the_default() {
        let garbage = build_input(&wire_request("gitlab", &[("gitlab_ssh_port", "")])).unwrap();
        assert_eq!(garbage.gitlab_ssh_port, 2223);
        let off = build_input(&wire_request("gitlab", &[("gitlab_ssh_port", "0")])).unwrap();
        assert_eq!(off.gitlab_ssh_port, 0);
    }

    // ─────────────────────── seafile + psono ───────────────────────

    /// Seafile restarts ONE service of its project, and the service name
    /// stays its own argv element — a project or service with a space in it
    /// must never become two arguments.
    #[test]
    fn restarting_one_service_names_the_project_and_the_service_separately() {
        assert_eq!(
            compose_restart_service_args("seafile", Path::new("/opt/seafile"), "seafile"),
            ["compose", "-p", "seafile", "-f", "/opt/seafile/docker-compose.yml", "restart", "seafile"]
        );
        let args = compose_restart_service_args("weird name", Path::new("/opt/seafile"), "weird service");
        assert_eq!(args.len(), 7);
        assert_eq!(args[2], "weird name");
        assert_eq!(args[6], "weird service");
    }

    /// The keypair generator and the `manage.py` calls: every argument its
    /// own element, no shell anywhere, and `--rm` on the one-shot so a
    /// re-run does not accumulate dead containers.
    #[test]
    fn the_psono_argv_is_exact() {
        assert_eq!(
            docker_run_once_args(psono::IMAGE, &["python3", "./psono/generateserverkeys.py"]),
            ["run", "--rm", psono::IMAGE, "python3", "./psono/generateserverkeys.py"]
        );
        assert_eq!(
            docker_exec_args(psono::CONTAINER, &["python3", "./psono/manage.py", "presetup"]),
            ["exec", "psono", "python3", "./psono/manage.py", "presetup"]
        );
        // Never `down`/`rm` from this module — the same rule the compose
        // builders hold.
        assert!(!docker_exec_args("psono", &["migrate"]).contains(&"down".to_string()));
    }

    /// The settings file is created exactly once, keeps 0600, and a second
    /// caller is told it did not create it — which is what stops the
    /// administrator from being created twice.
    #[test]
    fn a_secret_file_is_created_once_and_the_loser_is_told_so() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("psono-settings");
        let path = dir.join("settings.yaml");

        assert!(create_file_if_absent(&path, "PRIVATE_KEY: 'first'\n", 0o600).unwrap());
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        assert!(!create_file_if_absent(&path, "PRIVATE_KEY: 'second'\n", 0o600).unwrap());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "PRIVATE_KEY: 'first'\n",
            "an existing keypair must never be overwritten"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A real stub `docker` proving the capture keeps stdout and stderr
    /// APART: Psono's settings.yaml is the generator's stdout verbatim, and
    /// a warning line mixed into it would be YAML the server cannot read.
    #[tokio::test]
    async fn a_captured_run_keeps_stdout_out_of_stderr() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("docker-capture");
        let script = write_stub(&dir, "docker", "#!/bin/sh\necho \"PRIVATE_KEY: 'x'\"\necho noise 1>&2\n");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);

        let run = run_docker_captured(
            &docker_run_once_args("image", &["python3", "gen.py"]),
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(run.success);
        assert_eq!(run.stdout, "PRIVATE_KEY: 'x'\n");
        assert_eq!(run.stderr, "noise\n");
        // `why` is the bash `ps_why`: one bounded line of everything.
        assert_eq!(run.why(), "PRIVATE_KEY: 'x'noise");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_captured_run_reports_a_failure_without_pretending_it_succeeded() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("docker-capture-fail");
        let script = write_stub(&dir, "docker", "#!/bin/sh\necho 'db is down' 1>&2\nexit 1\n");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);

        let run = run_docker_captured(&docker_exec_args("psono", &["presetup"]), Duration::from_secs(30))
            .await
            .unwrap();

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(!run.success);
        assert!(run.why().contains("db is down"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The wait returns immediately for a file that is already there (the
    /// re-run case), and reports failure rather than hanging when it never
    /// appears.
    #[tokio::test]
    async fn waiting_for_a_file_answers_at_once_when_it_exists() {
        let dir = tmp("wait-file");
        let path = dir.join("seahub_settings.py");
        std::fs::write(&path, "SECRET_KEY = 'x'\n").unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "seafile".to_string(), journal: None, sequence: AtomicU64::new(0) };

        assert!(wait_for_file(&path, 5, &sink, "waiting").await);
        assert!(!wait_for_file(&dir.join("never"), 0, &sink, "waiting").await);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ───────────────── docker-mailserver (срез 4.9) ─────────────────

    fn dms_input() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn docker_mailserver_resolves_and_installs_under_its_own_project() {
        assert_eq!(resolve("docker-mailserver"), Ok("docker-mailserver"));
        assert_eq!(compose_project("docker-mailserver"), dms::COMPOSE_PROJECT);
        // The project name the agent reports in STARTED has to be the one
        // `docker compose ls` shows — a literal, never derived from the id
        // (which carries dashes the project does not).
        assert_eq!(compose_project("docker-mailserver"), "dockermailserver");
    }

    /// The `mail` shelf is now CLOSED: all three engines resolve and install
    /// under their own project — mailcow's the one whose project name is
    /// NOT derived from its id at all (`mailcowdockerized`, no hyphens,
    /// `generate_config.sh`'s own literal), unlike every other service's
    /// project name (which merely drops the id's dashes).
    #[test]
    fn the_mail_shelf_is_closed_all_three_engines_resolve_and_install_under_their_own_project() {
        assert_eq!(resolve("mailcow"), Ok("mailcow"));
        assert_eq!(compose_project("mailcow"), mailcow::COMPOSE_PROJECT);
        assert_eq!(compose_project("mailcow"), "mailcowdockerized");

        assert_eq!(resolve("mailu"), Ok("mailu"));
        assert_eq!(compose_project("mailu"), mailu::COMPOSE_PROJECT);
        assert_eq!(compose_project("mailu"), "mailu");
    }

    // ───────────────── mailcow / Mailu (mail-polka-closing слайс) ─────────────────

    #[test]
    fn mailu_admin_exec_args_reaches_the_service_by_name_through_compose_not_by_container() {
        let dir = Path::new("/opt/mailu");
        assert_eq!(
            mailu_admin_exec_args(dir, mailu::CONFIG_EXPORT_PROBE_ARGS),
            [
                "compose",
                "-p",
                "mailu",
                "-f",
                "/opt/mailu/docker-compose.yml",
                "exec",
                "-T",
                "-u",
                "mailu",
                "admin",
                "flask",
                "mailu",
                "config-export",
                "-j"
            ]
        );
    }

    /// Asked of the SET, not of the one call this module happens to build
    /// first: EVERY way the installer reaches Mailu's admin container has to
    /// carry `-u`, because the image declares no `USER` and a root Mailu CLI
    /// call creates `/data/main.db` ahead of the engine's own `flask db
    /// upgrade` — leaving a root-owned database the engine can never write
    /// its schema into (`mailu::ADMIN_RUN_AS_USER`). Both argv sets go
    /// through the same builder today; the point of the check is the day one
    /// of them stops.
    #[test]
    fn no_mailu_admin_exec_runs_as_root() {
        let dir = Path::new("/opt/mailu");
        for argv in [mailu::CONFIG_EXPORT_PROBE_ARGS, mailu::CONFIG_IMPORT_ARGS] {
            let args = mailu_admin_exec_args(dir, argv);
            let exec = args.iter().position(|a| a == "exec").expect("an exec verb");
            let service = args.iter().position(|a| a == mailu::ADMIN_SERVICE).expect("the admin service name");
            let user = args.iter().position(|a| a == "-u").expect("a -u flag");
            assert!(exec < user && user + 1 < service, "-u has to sit between `exec` and the service name: {args:?}");
            assert_eq!(args[user + 1], mailu::ADMIN_RUN_AS_USER);
        }
    }

    /// mailcow's own compose calls deliberately have NO `-f`, unlike every
    /// other engine's in this file — see `run_mailcow_compose_retrying`'s own
    /// doc for why (compose has to discover whatever override
    /// `generate_config.sh` may have written into the directory itself) —
    /// and DO run with the checkout as their working directory, which is what
    /// stands in for the bash version's `cd`.
    #[tokio::test]
    async fn mailcow_compose_calls_carry_no_dash_f_and_run_with_the_checkout_as_cwd() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("mailcow-compose-argv");
        let recorder = dir.join("argv.txt");
        let script = write_stub(
            &dir,
            "docker",
            &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" > {}\npwd >> {}\n", recorder.display(), recorder.display()),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "mailcow".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result =
            run_mailcow_compose_retrying(&dir, &["compose".to_string(), "pull".to_string(), "-q".to_string()], 1, &sink)
                .await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(result.is_ok(), "{result:?}");

        let recorded = std::fs::read_to_string(&recorder).unwrap();
        let mut lines = recorded.lines();
        assert_eq!(lines.next().unwrap(), "compose pull -q", "no -f, unlike every other engine's compose call");
        assert_eq!(
            std::fs::canonicalize(lines.next().unwrap()).unwrap(),
            std::fs::canonicalize(&dir).unwrap(),
            "the checkout must be the working directory, the bash version's `cd`"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mailcow_json_has_field_matches_jqs_own_e_flag_rule() {
        assert!(mailcow_json_has_field(r#"{"domain_name":"example.com"}"#, "domain_name"));
        assert!(!mailcow_json_has_field(r#"{"domain_name":null}"#, "domain_name"));
        assert!(!mailcow_json_has_field(r#"{"errors":["not found"]}"#, "domain_name"));
        assert!(!mailcow_json_has_field("not json at all", "domain_name"));
        // jq -e treats a `false` value as failure too, not just null/absent.
        assert!(!mailcow_json_has_field(r#"{"pubkey":false}"#, "pubkey"));
    }

    #[test]
    fn mailcow_why_matches_mc_whys_own_shape() {
        assert_eq!(mailcow_why(404, "route not found\r\n"), "HTTP 404 route not found");
        let long = "x".repeat(500);
        assert_eq!(mailcow_why(500, &long).len(), "HTTP 500 ".len() + 300);
    }

    /// `chmod -R a+rX`'s own semantics: read for everyone always, execute for
    /// everyone ONLY on a directory or a file that already had execute for
    /// at least one class — never turned a plain data file executable.
    #[test]
    fn chmod_recursive_a_plus_rx_adds_read_everywhere_and_execute_only_where_earned() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmp("chmod-a-plus-rx");
        let sub = root.join("sub");
        std::fs::create_dir(&sub).unwrap();
        let data_file = root.join("data.txt");
        std::fs::write(&data_file, "x").unwrap();
        std::fs::set_permissions(&data_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let script_file = sub.join("run.sh");
        std::fs::write(&script_file, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&script_file, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A directory with a tight mode, the shape a clone under `umask 077`
        // actually produces.
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

        chmod_recursive_a_plus_rx(&root).unwrap();

        let mode_of = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_of(&root), 0o755, "a directory gets read AND execute for everyone");
        assert_eq!(mode_of(&sub), 0o755, "a subdirectory gets the same");
        assert_eq!(mode_of(&data_file), 0o644, "a plain file gets read only, never execute");
        assert_eq!(mode_of(&script_file), 0o755, "a file that already had execute for its owner keeps it for everyone");
    }

    /// `chmod -R` does not follow symlinks for the mode of the link itself —
    /// a defect here would either fail on a dangling link or silently chmod
    /// whatever the link points at, neither of which mailcow's own `chmod -R
    /// a+rX .` does either.
    #[test]
    fn chmod_recursive_a_plus_rx_leaves_symlinks_alone() {
        let root = tmp("chmod-a-plus-rx-symlink");
        let link = root.join("dangling");
        std::os::unix::fs::symlink("/nonexistent/target", &link).unwrap();
        // Must not error out on a dangling symlink, and must not try to
        // chmod through it.
        chmod_recursive_a_plus_rx(&root).unwrap();
    }

    /// `openssl rand -hex 20`'s own shape: 20 bytes as lowercase hex, so 40
    /// characters, all `[0-9a-f]`.
    #[test]
    fn random_hex_20_is_forty_lowercase_hex_characters() {
        let hex = random_hex_20().unwrap();
        assert_eq!(hex.len(), 40);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// `install -d -m 755` for everything but `certs`, which is 0700 because it
    /// holds the private key of the certificate the mail ports serve. Checked
    /// against the real filesystem, not against the argument passed in.
    #[test]
    fn the_certificate_directory_ends_up_root_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("dms-dirs");
        let service = dir.join("service");
        let certs = dir.join("certs");
        create_dir_with_mode(&service, 0o755).unwrap();
        create_dir_with_mode(&certs, 0o700).unwrap();
        assert_eq!(std::fs::metadata(&service).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(std::fs::metadata(&certs).unwrap().permissions().mode() & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A zero-length file counts as MISSING, which is the whole reason the bash
    /// guard is `[ ! -s … ]` and not `[ ! -f … ]`: `openssl` truncates its
    /// output before it fails, so a failed first attempt leaves an empty
    /// cert.pem that must not be mistaken for a certificate.
    #[test]
    fn an_empty_certificate_counts_as_missing() {
        let dir = tmp("dms-cert-empty");
        let empty = dir.join("cert.pem");
        std::fs::write(&empty, "").unwrap();
        let real = dir.join("key.pem");
        std::fs::write(&real, "-----BEGIN-----\n").unwrap();
        assert!(!is_nonempty_file(&empty));
        assert!(is_nonempty_file(&real));
        assert!(!is_nonempty_file(&dir.join("absent")));
        assert!(!is_nonempty_file(&dir), "a directory is not a certificate");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The placeholder certificate is created with EXACTLY the argv the
    /// declarative port builds — proven by running a real child process that
    /// records its own arguments, not by reading the call site.
    #[tokio::test]
    async fn the_placeholder_certificate_runs_openssl_with_the_ported_argv() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("dms-openssl");
        let argv_file = dir.join("argv");
        let stub =
            write_stub(&dir, "openssl", &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\n", argv_file.display()));
        std::env::set_var("GRYONIXNEXUSD_INSTALL_OPENSSL_BIN", &stub);

        let mut input = dms_input();
        input.docker_mailserver_path = dir.join("dms").display().to_string();
        std::fs::create_dir_all(dir.join("dms/certs")).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "docker-mailserver".to_string(), journal: None, sequence: AtomicU64::new(0) };
        write_placeholder_cert(&input, &sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_OPENSSL_BIN");
        let recorded: Vec<String> = std::fs::read_to_string(&argv_file).unwrap().lines().map(str::to_string).collect();
        assert_eq!(recorded, dms::placeholder_cert_args(&input));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// And it is SKIPPED when a certificate pair is already on disk — which is
    /// what keeps a re-run from throwing away the real certificate the sync
    /// timer copied in.
    #[tokio::test]
    async fn an_existing_certificate_pair_is_never_replaced() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("dms-openssl-skip");
        let argv_file = dir.join("argv");
        let stub =
            write_stub(&dir, "openssl", &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\n", argv_file.display()));
        std::env::set_var("GRYONIXNEXUSD_INSTALL_OPENSSL_BIN", &stub);

        let mut input = dms_input();
        input.docker_mailserver_path = dir.join("dms").display().to_string();
        std::fs::create_dir_all(dir.join("dms/certs")).unwrap();
        std::fs::write(dms::cert_pem_path(&input), "-----BEGIN CERTIFICATE-----\n").unwrap();
        std::fs::write(dms::key_pem_path(&input), "-----BEGIN PRIVATE KEY-----\n").unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "docker-mailserver".to_string(), journal: None, sequence: AtomicU64::new(0) };
        write_placeholder_cert(&input, &sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_OPENSSL_BIN");
        assert!(!argv_file.exists(), "openssl must not run when both halves are already on disk");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The first mailbox's password reaches the engine on STDIN, TWICE, and
    /// never in argv — GOTCHAS.md defect 7, proven against a real child process
    /// that records both channels separately.
    #[tokio::test]
    async fn the_first_mailbox_password_travels_on_stdin_and_not_in_argv() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("dms-stdin");
        let argv_file = dir.join("argv");
        let stdin_file = dir.join("stdin");
        let stub = write_stub(
            &dir,
            "docker",
            &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\ncat > {}\n", argv_file.display(), stdin_file.display()),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &stub);

        let run = dms_exec_with_stdin(&["setup", "email", "add", "admin@example.com"], "s3cret\ns3cret\n")
            .await
            .expect("the stub must run");

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(run.success);
        let argv = std::fs::read_to_string(&argv_file).unwrap();
        // `-i` is what makes the pipe reach the container at all.
        assert_eq!(argv, "exec\n-i\nmailserver\nsetup\nemail\nadd\nadmin@example.com\n");
        assert!(!argv.contains("s3cret"), "the password must never appear in argv: /proc hands it to everyone");
        // Twice, because the helper prompts for it and then for its
        // confirmation — and the pipe was CLOSED, or `cat` would still be
        // waiting and this call would have timed out instead of returning.
        assert_eq!(std::fs::read_to_string(&stdin_file).unwrap(), "s3cret\ns3cret\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The engine colours its OWN errors, and those errors are the only
    /// explanation a user gets.
    #[tokio::test]
    async fn the_engines_own_colours_are_stripped_from_what_it_says() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("dms-ansi");
        let stub = write_stub(
            &dir,
            "docker",
            "#!/bin/sh\nprintf 'plain\\n'\nprintf '\\033[1;31mERROR\\033[0m unknown user\\n' 1>&2\nexit 1\n",
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &stub);

        let (ok, text) = dms_exec(&["setup", "help"]).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(!ok);
        assert!(text.contains("ERROR unknown user"), "got {text:?}");
        assert!(!text.contains('\u{1b}'), "no escape sequence may survive into what a user reads");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_existing_mailbox_is_recognised_in_every_live_listing_format() {
        // The live formats of `setup email list` (DMS 15.1.0), all of which have
        // to be recognised: a mailbox with mail, one already touched, and one
        // created moments ago whose maildir does not exist yet.
        for line in [
            "* admin@example.com ( 6.0K / ~ ) [0%]",
            "* admin@example.com ( 0 / ~ ) [0%]",
            "* admin@example.com (  /  ) [%]",
        ] {
            assert!(mailbox_listed(line, "admin@example.com"), "not matched: {line:?}");
        }
        // With a CRLF line ending, and as the only token on a line.
        assert!(mailbox_listed("* admin@example.com\r\n", "admin@example.com"));
        assert!(mailbox_listed("admin@example.com", "admin@example.com"));
    }

    /// The boundaries are the point — this is the Forgejo lesson applied to
    /// mail: a lookalike passing for the administrator's mailbox would skip
    /// creating the ONLY account the install makes, leaving a mail server
    /// nobody can log into and one line in the log about it.
    #[test]
    fn a_lookalike_address_is_not_the_administrators_mailbox() {
        for line in [
            "* notadmin@example.com ( 0 / ~ ) [0%]",
            "* admin@example.com.evil.net ( 0 / ~ ) [0%]",
            "* xadmin@example.com ( 0 / ~ ) [0%]",
            "* admin@example.commercial ( 0 / ~ ) [0%]",
        ] {
            assert!(!mailbox_listed(line, "admin@example.com"), "wrongly matched: {line:?}");
        }
        assert!(!mailbox_listed("", "admin@example.com"));
        assert!(!mailbox_listed("* admin@example.com", ""));
    }

    /// The phantom-mailbox line: `setup email list` writes
    /// `doveadm(<address>): Error: User doesn't exist` on STDERR for an account
    /// Dovecot cannot resolve, and that line carries a REAL address wrapped in
    /// parentheses. It reaches this matcher only if someone merges stderr into
    /// stdout, and even then the boundary rule refuses it — belt and braces,
    /// because "the mailbox already exists" is the answer that SKIPS creating
    /// it.
    #[test]
    fn the_stderr_diagnostic_line_never_reads_as_an_existing_mailbox() {
        let noise = "doveadm(admin@example.com): Error: User doesn't exist";
        assert!(!mailbox_listed(noise, "admin@example.com"));
    }

    /// Every mail port, as tcp, in the order the declarative half declares —
    /// and never re-derived here: the list comes from `dms::firewall_ports()`,
    /// the same one the generated nftables ruleset and the install report read.
    #[test]
    fn the_firewall_receives_exactly_the_engines_declared_ports() {
        let rendered: Vec<(u16, &str)> = mail_firewall_ports(&dms::firewall_ports())
            .iter()
            .map(|p| {
                (
                    p.port,
                    match p.proto {
                        firewall::Proto::Tcp => "tcp",
                        firewall::Proto::Udp => "udp",
                    },
                )
            })
            .collect();
        assert_eq!(rendered, vec![(25, "tcp"), (465, "tcp"), (587, "tcp"), (143, "tcp"), (993, "tcp"), (4190, "tcp")]);
    }

    /// A firewall that could not be programmed is FATAL for mail, and a host
    /// with no drop-in directory is not: the first is a mail server nobody can
    /// reach on 25 while looking perfectly healthy, the second is a host that
    /// needs its setup re-run and is told so.
    #[test]
    fn a_firewall_failure_is_fatal_but_a_missing_drop_in_directory_is_only_reported() {
        let applied = firewall_step_text(Ok(firewall::Outcome::Applied)).expect("Applied is not an error");
        assert!(applied.contains("opened the mail ports"));

        let skipped = firewall_step_text(Ok(firewall::Outcome::SkippedNoDropInDir))
            .expect("a missing drop-in directory is a step, not an error");
        assert!(skipped.contains("NOT open"), "the operator has to be told the ports are closed: {skipped:?}");
        assert!(skipped.contains("re-run"), "and what to do about it: {skipped:?}");

        let failed = firewall_step_text(Err("nft: syntax error".to_string()));
        assert_eq!(failed, Err("could not open the mail ports in the firewall: nft: syntax error".to_string()));
    }

    /// The three files the cert-sync half owns, at the paths the Swift
    /// generator and any later uninstall both name, with the script root-only.
    #[test]
    fn the_cert_sync_files_are_the_script_and_its_two_units() {
        let input = dms_input();
        let files = cert_sync_files(&input);
        let paths: Vec<String> = files.iter().map(|f| f.path.display().to_string()).collect();
        assert_eq!(
            paths,
            vec![
                "/opt/gryonixnexus-dms-cert-sync.sh".to_string(),
                "/etc/systemd/system/gryonixnexus-dms-cert-sync.service".to_string(),
                "/etc/systemd/system/gryonixnexus-dms-cert-sync.timer".to_string(),
            ]
        );
        assert_eq!(files[0].mode, Some(0o700), "the script copies a private key");
        assert_eq!(files[0].contents, dms::cert_sync_script(&input));
        assert!(files[1].contents.contains("ExecStart=/opt/gryonixnexus-dms-cert-sync.sh"));
        assert!(files[2].contents.contains("OnUnitActiveSec=1h"));
    }

    /// **The DKIM wrapper is written and the mailbox wrapper is not**, and both
    /// halves of that are deliberate: `dkim.rs` in this same binary runs
    /// `/opt/gryonixnexus-dms-dkim.sh` directly, so without it `GetDkimRecords`
    /// answers "not installed" for ever on an agent-installed host; the mailbox
    /// wrapper is only reachable as `sudo …`, through a sudoers line this path
    /// does not provision, and `mailbox.rs` already reimplements it.
    #[test]
    fn the_dkim_wrapper_is_written_and_the_mailbox_wrapper_is_deliberately_not() {
        let input = dms_input();
        let files = dms_management_files(&input);
        let paths: Vec<String> = files.iter().map(|f| f.path.display().to_string()).collect();
        assert_eq!(paths, vec![dms::DKIM_DUMP_SCRIPT_PATH.to_string()]);
        assert!(
            !paths.contains(&dms::MAILBOX_SCRIPT_PATH.to_string()),
            "the mailbox wrapper is unreachable on this path — see write_dms_management_scripts"
        );
        assert_eq!(files[0].mode, Some(0o700));
        assert_eq!(files[0].contents, dms::dkim_dump_script(&input));
    }

    /// The path `dkim.rs` executes and the path this install writes have to be
    /// the SAME literal — the gap this срез closes is exactly the one that
    /// opens when two halves of the agent each look complete on their own.
    #[test]
    fn the_wrapper_this_install_writes_is_the_one_the_dkim_rpc_runs() {
        assert_eq!(dms::DKIM_DUMP_SCRIPT_PATH, "/opt/gryonixnexus-dms-dkim.sh");
    }

    /// **The ORDER of this install is its most important rule and the easiest
    /// one to lose**, so it is pinned STRUCTURALLY — over the source of the
    /// function itself, the same technique this project already uses on
    /// generated shell (every `return 1` must have a marker beside it, every
    /// `backup <path>` must have a removal glob covering its copies).
    ///
    /// Why not by running it: the pipeline writes to `/opt`, `/etc/caddy` and
    /// `/etc/systemd/system` and needs a real docker, so no test on this
    /// machine can execute it end to end (see this module's own doc). A
    /// reordering would therefore be invisible to every other test here, and
    /// the two orderings that matter are not cosmetic:
    /// - the placeholder certificate BEFORE the first `up -d`, or
    ///   `SSL_TYPE=manual` crash-loops for ever and the container never gets
    ///   its first mailbox or its DKIM keys (GOTCHAS.md defect 1);
    /// - the firewall BEFORE the five-minute readiness wait, so the one fatal
    ///   step of the second half fails fast instead of after five minutes.
    #[test]
    fn the_installs_order_is_the_one_the_engine_actually_needs() {
        let source = include_str!("execute.rs");
        let start = source
            .find("async fn install_docker_mailserver_steps")
            .expect("the function must exist to have an order at all");
        let body = &source[start..];
        let end = body.find("\n/// A mail engine's ports").expect("the function must end before the next item");
        let body = &body[..end];

        let at = |needle: &str| -> usize { body.find(needle).unwrap_or_else(|| panic!("no `{needle}` in the body")) };
        let cert = at("write_placeholder_cert(input, sink)");
        // The `&dir` argument is срез 4.9's fix: every compose verb here names
        // its project file instead of trusting a working directory the agent
        // does not have.
        let pull = at("compose_pull_args(dms::COMPOSE_PROJECT, &dir)");
        let up = at("compose_up(dms::COMPOSE_PROJECT, &dir, sink)");
        let firewall = at("open_mail_firewall_ports(DMS_FIREWALL_LABEL");
        let configure = at("configure_dms(input, sink)");
        let caddy = at("write_caddy_site(&dms::caddy_site_names");

        assert!(cert < pull, "the placeholder certificate must exist before the images are even pulled");
        assert!(pull < up, "pull before up");
        assert!(up < firewall, "the ports are opened once something is listening on them");
        assert!(firewall < configure, "the fatal step comes before the five-minute readiness wait");
        assert!(configure < caddy, "the Caddy site is written last, as in every other service here");
    }

    /// The edit that made the difference between "signs nothing" and
    /// "DKIM check: pass" on a real server — see
    /// `stop_rspamd_reducing_the_signing_domain` for the live measurement.
    #[test]
    fn the_signing_domain_stops_being_reduced_to_the_esld() {
        let upstream = "enabled = true;\nuse_esld = true;\ncheck_pubkey = true;\n";
        let fixed = dkim_signing_without_esld(upstream).expect("an upstream config must be changed");
        assert!(fixed.contains("use_esld = false;"));
        // Nothing ELSE may move: the file belongs to the engine, and the next
        // `setup config dkim` writes its own key entries into it.
        assert_eq!(fixed.replace("use_esld = false;", "use_esld = true;"), upstream);
        // Re-installing is the common case, so an already-fixed file is a
        // no-op rather than a rewrite plus a pointless rspamd restart.
        assert_eq!(dkim_signing_without_esld(&fixed), None);
        assert_eq!(dkim_signing_without_esld("enabled = true;\n"), None);
    }

    /// `ProvisionHost` is the only way this fix reaches a host whose mail
    /// engine was installed before it existed — an install never runs again on
    /// such a host, and "reinstall your mail server to stop sending unsigned
    /// mail" is not a fix that arrives. Nothing else in the suite would notice
    /// the call being dropped: the verb's own tests are about the files it
    /// writes, and this one edits a file it does not write.
    #[test]
    fn provision_host_also_stops_the_signing_domain_being_reduced() {
        let source = include_str!("execute.rs");
        let start = source.find("pub async fn run_provision_host").expect("the verb must exist");
        let body = &source[start..];
        let end = body.find("\nasync fn provision_host_surface").expect("the function must end before the next item");
        let body = &body[..end];
        let surface = body.find("provision_host_surface(&input").expect("the host surface must be provisioned");
        let fix = body
            .find("stop_rspamd_reducing_the_signing_domain(&input, &sink)")
            .expect("ProvisionHost must apply the DKIM signing fix");
        let drained = body.find("drain_notes(&mut rx").expect("the notes must be drained");
        assert!(surface < fix, "the host surface comes first");
        // Its step lands in `notes`, which is how a unary verb reports at all —
        // after the drain it would be written and never mentioned.
        assert!(fix < drained, "the fix must run before the notes are drained or its step is lost");
    }

    /// The fix reads a file that `setup config dkim` CREATES, so its position
    /// is load-bearing: run before the keys are minted it would find nothing,
    /// return early, and leave the deployment unsigned exactly as before —
    /// with every other test here still green.
    #[test]
    fn the_signing_fix_runs_after_the_keys_are_minted() {
        let source = include_str!("execute.rs");
        let start = source.find("async fn configure_dms").expect("configure_dms must exist");
        let body = &source[start..];
        let end = body.find("\n/// The edit itself").expect("the function must end before the next item");
        let body = &body[..end];
        let mint = body.find("dms::dkim_config_args(&domain)").expect("the key loop must be here");
        let fix = body.find("stop_rspamd_reducing_the_signing_domain(input, sink)").expect("the fix must be here");
        assert!(mint < fix, "the signing fix must run after the keys (and their config file) exist");
    }

    /// Managed files really do land with their mode, checked against the
    /// filesystem on a path a test is allowed to write.
    #[test]
    fn managed_files_are_written_with_the_mode_they_asked_for() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("dms-managed");
        let script = dir.join("wrapper.sh");
        let plain = dir.join("unit.timer");
        write_managed_files(&[
            ManagedFile { path: script.clone(), contents: "#!/bin/bash\n".to_string(), mode: Some(0o700) },
            ManagedFile { path: plain.clone(), contents: "[Timer]\n".to_string(), mode: None },
        ])
        .unwrap();
        assert_eq!(std::fs::metadata(&script).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::read_to_string(&plain).unwrap(), "[Timer]\n");
        assert!(write_managed_files(&[ManagedFile {
            path: dir.join("no/such/dir/file"),
            contents: String::new(),
            mode: None
        }])
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **This engine's template mentions `__RANDOM__` in a COMMENT**, so the
    /// expansion substitutes there too — a secret written into a comment
    /// nothing reads. Recorded rather than "fixed": the bash side expands
    /// `__RANDOM__` per LINE with no idea whether a line is a comment
    /// (`ServiceInfraSections.composeSetup`'s `case "$line" in *__RANDOM__*`),
    /// so both routes produce the same file, and a port that tidied it up here
    /// would make the agent's `.env` differ from the SSH install's for no gain.
    /// What the test does pin is the thing that IS load-bearing: each line gets
    /// its OWN secret, so the throwaway in the comment can never be the
    /// mailbox's password.
    #[test]
    fn every_line_of_the_env_template_gets_its_own_secret() {
        let expanded = expand_random(&dms::env_template(&dms_input())).unwrap();
        let value_of = |prefix: &str| -> String {
            expanded
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
                .unwrap_or_else(|| panic!("no {prefix} line"))
                .to_string()
        };
        let password = value_of("FIRST_MAILBOX_PASSWORD=");
        assert_eq!(password.len(), 48, "24 random bytes as hex");
        assert!(password.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!expanded.contains("__RANDOM__"), "no marker may survive into the file");

        let comment = expanded.lines().next().expect("the header comment").to_string();
        assert!(comment.starts_with('#'));
        assert!(
            !comment.contains(&password),
            "the comment's throwaway substitution must not be the mailbox password: {comment:?}"
        );
    }

    /// The request's own path setting reaches the install, and the default is
    /// Swift's — a different default would install into a directory other than
    /// the one the app reports.
    #[test]
    fn the_docker_mailserver_path_defaults_to_swifts_and_is_gated_like_the_rest() {
        let input = build_input(&pb::InstallServiceRequest {
            service_id: "docker-mailserver".to_string(),
            domain: "example.com".to_string(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(input.docker_mailserver_path, "/opt/docker-mailserver");

        let mut settings = HashMap::new();
        settings.insert("docker_mailserver_path".to_string(), "/srv/dms".to_string());
        let custom = build_input(&pb::InstallServiceRequest {
            service_id: "docker-mailserver".to_string(),
            domain: "example.com".to_string(),
            settings,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(custom.docker_mailserver_path, "/srv/dms");

        // Same gate as every other path-shaped setting: this one becomes a
        // `create_dir_all` + `chmod` target.
        let mut bad = HashMap::new();
        bad.insert("docker_mailserver_path".to_string(), "/opt/../etc/systemd/system".to_string());
        let refused = build_input(&pb::InstallServiceRequest {
            service_id: "docker-mailserver".to_string(),
            domain: "example.com".to_string(),
            settings: bad,
            ..Default::default()
        });
        assert!(refused.is_err());
    }

    // ─────────────────────────── Passbolt ───────────────────────────

    #[test]
    fn passbolt_resolves_and_installs_under_its_own_project() {
        assert_eq!(resolve("passbolt"), Ok("passbolt"));
        assert_eq!(compose_project("passbolt"), passbolt::COMPOSE_PROJECT);
    }

    /// A port of the bash `grep -oE 'https?://[^[:space:]]+' | tail -n1` —
    /// the LAST url-shaped token wins, framing text around it is ignored,
    /// and no url at all is `None`, never a panic or an empty string.
    #[test]
    fn extract_last_url_takes_the_final_url_shaped_token() {
        assert_eq!(
            extract_last_url("Registration email sent!\nSetup URL: https://passbolt.example.com/setup/install/1/2\n"),
            Some("https://passbolt.example.com/setup/install/1/2".to_string())
        );
        assert_eq!(
            extract_last_url("http://one.example.com https://two.example.com"),
            Some("https://two.example.com".to_string())
        );
        assert_eq!(extract_last_url("no url in this output at all"), None);
        assert_eq!(extract_last_url(""), None);
    }

    /// Freshness is decided from the GPG key file alone, and that decision
    /// gates the ENTIRE invitation step — a stale invitation must never be
    /// resent to an instance that already has an administrator.
    #[test]
    fn freshness_follows_the_gpg_key_file_not_the_containers_own_state() {
        let dir = tmp("passbolt-fresh");
        let key = dir.join("serverkey_private.asc");
        assert!(!key.exists(), "a brand new install has no key yet");
        std::fs::write(&key, "-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap();
        assert!(key.exists(), "an existing key means an earlier run already invited the administrator");
    }

    /// **The restart loop the SSH route wrote, stated as a test.** Its
    /// `printf '[]\\n'` came out of a raw Swift string as a LITERAL
    /// backslash-n, and headscale refuses to start on a records file it
    /// cannot parse — for ever, because the "create it only when absent"
    /// guard is happy with a file that exists. Measured on a live host
    /// 2026-08-20.
    #[test]
    fn an_unparseable_records_file_is_rewritten_and_real_records_are_not() {
        let dir = std::env::temp_dir().join(format!("gd-records-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("extra-records.json");

        let _ = std::fs::remove_file(&path);
        assert!(headscale_records_need_writing(&path), "an absent file must be created");

        std::fs::write(&path, "[]\\n").unwrap();
        assert!(headscale_records_need_writing(&path), "the literal backslash-n an older install wrote must be repaired");

        std::fs::write(&path, "[]\n").unwrap();
        assert!(!headscale_records_need_writing(&path), "a correct empty file must be left alone");

        std::fs::write(&path, "[{\"name\":\"vault.example.com\",\"value\":\"100.64.0.1\"}]\n").unwrap();
        assert!(
            !headscale_records_need_writing(&path),
            "published names must never be dropped by a re-install"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same shape for Authelia. A users database whose hash does not
    /// begin with the crypt delimiter is one the portal refuses at startup,
    /// so it has never admitted anybody and can be replaced; one that does
    /// carry a hash may have had people added to it and must not be.
    #[test]
    fn a_users_database_the_portal_cannot_load_is_rewritten_and_a_working_one_is_not() {
        let dir = std::env::temp_dir().join(format!("gd-users-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("users_database.yml");

        let _ = std::fs::remove_file(&path);
        assert!(authelia_needs_first_user(&path), "an absent database must be created");

        // What a fresh SSH install wrote on a host without the image: docker's
        // own `Digest: sha256:…` line, read as if it were the password hash.
        std::fs::write(&path, "users:\n  admin:\n    password: 'sha256:5dd0d3e6'\n").unwrap();
        assert!(authelia_needs_first_user(&path), "a docker digest is not a password hash");

        std::fs::write(&path, "users:\n  admin:\n    password: '$argon2id$v=19$m=65536,t=3,p=4$x$y'\n").unwrap();
        assert!(!authelia_needs_first_user(&path), "a working database must never be rewritten");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
