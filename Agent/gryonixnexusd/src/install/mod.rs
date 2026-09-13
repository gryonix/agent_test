//! Install artifacts, ported into the crate — Ф4 срез 4.1 (declarative),
//! срез 4.2 (imperative + the RPC) and срез 4.3 (two more services through
//! the same executor), the SERVICE slices (срез 4.0 was `dns_records`, a
//! pure function with no docker/shell surface at all).
//!
//! **The two halves.** `AdGuardHomeService`
//! (`Packages/gryonixNexus/Sources/ServiceCatalog/Services/AdGuardHomeService.swift`)
//! splits cleanly into a DECLARATIVE half (compose file, env template,
//! hostname, DNS hostnames, Caddy ingress — the same function of `Input`
//! every time: `context`/`caddy`/`adguard`) and an IMPERATIVE half
//! (`setupSteps` — creates directories, generates secrets, runs docker,
//! polls AdGuard's own installation API, POSTs the generated admin password
//! over loopback HTTP, flips a DoH-insecure flag that moved key names
//! between AdGuard versions: `execute`). Срез 4.1 ported only the first half
//! with no RPC and no route reachable, exactly like `dns_records`/
//! `dns_l10n` before it; срез 4.2 ports the second half AND wires
//! `Install/InstallService` into `api.rs` — this module is reachable now.
//!
//! **Why AdGuard Home first.** ROADMAP.md picked it for the reason Ф2 has
//! always gone service-by-service: it is the simplest thing in the catalog —
//! one container, a single pinned image, no database, no multi-step admin
//! bootstrap baked into the declarative half at all.
//!
//! **Module layout**, mirroring `dns_records`/`dns_l10n`'s split between
//! engine and shared building block, adapted to what THIS engine needs:
//! - `context` — the install-time `Input`, a reduction of Swift's
//!   `ServiceContext`/`MailContext` to the fields AdGuard's declarative
//!   functions actually read (the same "small, provable subset" discipline
//!   `dns_records::Input`'s doc explains and justifies).
//! - `caddy` — a port of `ServiceInfraSections.caddySite`/the join
//!   `writeCaddyfile` does — infrastructure every future service slice will
//!   also need, which is why it is its own module instead of living inside
//!   `adguard`.
//! - `adguard` — the service itself: image/compose constants, compose file,
//!   env template, hostname, DNS hostnames, ingress, and the one Caddy site
//!   it produces.
//! - `jellyfin` / `vaultwarden` — срез 4.3, same declarative shape as
//!   `adguard` and driven by the same executor. Both are single-container
//!   services with no database: Jellyfin has no `.env` at all (`envTemplate`
//!   is nil on the Swift side), Vaultwarden has one generated `ADMIN_TOKEN`
//!   plus the only imperative step in this slice that is not docker — the
//!   `config.json` sync, because settings saved in its own /admin panel
//!   OUTRANK the compose environment (see `execute::sync_vaultwarden_config`).
//! - `execute` — the IMPERATIVE executor behind `Install/InstallService`:
//!   creates the service's directories, writes its compose file and secrets,
//!   runs `docker` directly (no shell), waits for AdGuard's own API, POSTs
//!   the generated admin password, patches the DoH key, writes the Caddy
//!   site and reloads Caddy — all natively, no generated bash script handed
//!   to an SSH session. One entry point (`install`) holds the two-channel
//!   error discipline and the STARTED/COMPLETED envelope for every service;
//!   only the STEPS differ, and the id gate (`IMPLEMENTED_SERVICE_IDS`) is
//!   what says which of them this build can run at all.
//!
//! **Verification.** The declarative half follows the same byte-parity
//! discipline as `dns_records`: fixtures dumped from the REAL Swift output
//! live under `tests/fixtures/install/`, diffed byte-for-byte by the
//! `fixture_parity` test module at the bottom of each service module,
//! negative-controlled before landing (see that module's doc for the
//! numbers). The imperative half has no live host in this build environment
//! (see `execute`'s own module doc) — it is unit-tested down to every pure
//! decision (argv construction, the id gate, `__RANDOM__` expansion, `.env`
//! idempotence, the DoH key patch) and, where a real child process or a
//! real loopback socket costs nothing to stand up in a test, against the
//! REAL thing rather than a mock of it.

pub mod adguard;
pub mod authelia;
/// The AI shelf: the local model engine, and the chat interface in front of
/// it. The chat is the second module in this crate whose compose file is a
/// function of the HOST's other services rather than of its own input alone —
/// see its module doc.
pub mod ollama;
pub mod open_webui;
pub mod litellm;
pub mod anythingllm;
pub mod n8n;
pub mod qdrant;
pub mod searxng;
/// The assistant that answers in somebody's messengers. Its pairings are made
/// in its own UI and never travel through an install request — see its module
/// doc.
pub mod openclaw;
/// The provider keys the gateway reads, rendered from the agent's own vault.
/// The first place this crate ACTS on a vault row rather than storing it — see
/// its module doc for why that is a reconciliation and not a new verb.
pub mod llm_keys;
pub mod catalog;
pub mod homepage;
pub mod pihole;
pub mod cloudflared;
pub mod headscale;
pub mod tailscale;
pub mod caddy;
pub mod context;
/// Default service hostnames — the plain name for a shelf of one, the
/// service's own name once the shelf carries two (see the module doc).
pub mod hostnames;
pub mod execute;
// The record an install leaves behind. Its own module rather than part of
// `execute` because two RPCs read it without installing anything, and because
// the thing being fixed — a run that outlives the client that started it — is a
// property of the JOURNAL, not of any executor.
pub mod journal;
/// docker and Caddy — the two packages every executor assumes and none of them
/// used to install. See the module's own doc for why the sandbox makes this
/// harder than `apt-get install` and how it is escaped without weakening it.
pub mod packages;
/// Intrusion defence for the host itself — CrowdSec and its nftables bouncer.
/// Beside `firewall_base` and `lockdown` rather than in the catalog: it has no
/// site, no hostname and no admin, it reads the machine's own journals
/// (owner's decision 2026-09-01).
pub mod crowdsec;
/// Closing SSH password login on a host this product provisions — beside
/// `crowdsec` for the same reason and bought by the same measurement: CrowdSec
/// answers who is knocking, this answers whether the door opens at all
/// (owner's decision 2026-09-02). Also the policy behind the app's own switch
/// (`Security/GetSshPasswordState` / `SetSshPasswordLogin`, owner 2026-09-07):
/// one module, so the install and the button cannot decide differently.
pub mod ssh_password;
/// The agent half of the nftables drop-in contract — shared infrastructure
/// like `caddy`, not a service. The generator already declares the empty
/// `gryonixnexus_services` chain, the jump into it and the include of
/// `/etc/nftables.d`; this is what fills it. Needed by every service whose
/// ports are the point (VPN, mail), which is why it landed with the VPN
/// slice rather than inside it.
pub mod firewall;
/// The base nftables ruleset for a host that has none — the surface the
/// per-service drop-ins above land on. See the module's own doc.
pub mod firewall_base;
/// Scenario B's two routing halves — the relay's DNAT/forward/SNAT ruleset and
/// the home half's connection marks. The last thing the setup script generated
/// and the agent did not, so a pair built by the agent alone could not relay.
pub mod firewall_relay;
/// The home half's policy routing — the mark set by `firewall_relay` is acted
/// on here, and without it a relayed reply leaves through the home ISP and the
/// connection hangs. Three files, all byte-parity ports.
pub mod relay_routes;
/// The port pre-flight: what this host already holds, so a publish that cannot
/// succeed is refused BEFORE the stream opens instead of dying at `up -d` with
/// docker's `address already in use` after a full install's worth of work. See
/// the module's own doc for the live measurement behind the mechanism.
pub mod ports;
/// Срез 4.3's two additions, both single-container services with no database
/// and no admin bootstrap API of their own — the next-simplest things in the
/// catalog after AdGuard, and both wired all the way to
/// `Install/InstallService` (declarative AND imperative), unlike `mail`.
/// Срез 4.6: Nextcloud and Forgejo — the two services whose install does
/// real work AFTER `up -d`. Nextcloud has to re-apply its trusted domains
/// through `occ` on every run (the compose environment is read only when the
/// instance first initialises itself), and Forgejo has to create its
/// administrator over the CLI, because `INSTALL_LOCK` leaves no web wizard
/// that could.
pub mod forgejo;
/// Срез 4.8: GitLab CE — one container that is really a whole stack, and the
/// longest first boot in the catalog (a full omnibus reconfigure plus
/// database migrations, many minutes on ARM).
pub mod gitlab;
pub mod immich;
pub mod crafty;
pub mod jellyfin;
pub mod minecraft;
/// Срез 4.4: the first MULTI-container service in this port (server plus its
/// own MariaDB) — and the proof that "more containers" costs the executor
/// nothing, because `docker compose up -d` brings up whatever the file
/// declares. What it does cost is secrets: three independent `__RANDOM__`
/// lines instead of one.
pub mod nextcloud;
/// Third and last product on the `passwords` shelf, closing it alongside
/// Vaultwarden and Psono. Two containers like PhotoPrism (server plus its
/// own MariaDB), but the only service in this port whose install narrates a
/// URL instead of a password: Passbolt's server holds no key that could set
/// one (every account's private key is generated client-side in the
/// browser), so the CLI can only create a pending invitation.
pub mod passbolt;
pub mod photoprism;
/// Seafile and Psono — the second products on the `files` and `passwords`
/// shelves, both wired all the way to `Install/InstallService`. Between them
/// they add the two imperative shapes no earlier service needed: a settings
/// file the SERVER writes on its first start and the installer then has to
/// edit (Seafile's CSRF origins), and a secret this crate cannot generate
/// itself because it is a matched keypair, so the image's own generator is
/// run once and its stdout captured (Psono's `settings.yaml`).
pub mod psono;
pub mod seafile;
pub mod vaultwarden;
/// Срез 4.9: the VPN — one catalog id (`vpn`) covering the panel and the
/// protocols, because that is how the agent already MANAGES them.
pub mod vpn;
/// The mail engines (mailcow / Mailu / docker-mailserver) — one exclusive
/// slot, three ports, grouped under their own parent because mail is the
/// first part of the catalog that opens firewall ports and the first whose
/// biggest member is not a compose project at all. See `mail/mod.rs`.
///
/// Срез 4.9 wired ONE of the three all the way through: docker-mailserver has
/// an executor and an `Install/InstallService` entry, so the parent module is
/// no longer dead code. mailcow and Mailu keep their own `#[allow(dead_code)]`
/// inside `mail/mod.rs`, which is also where the reason each is its own future
/// срез is written down.
pub mod mail;
/// The HOST half of install — the root-owned wrappers, the metrics collector,
/// the sudoers whitelist and the install report. Everything the setup script
/// leaves behind that is not one service's compose project; see `host/mod.rs`.
#[allow(dead_code)]
pub mod host;
