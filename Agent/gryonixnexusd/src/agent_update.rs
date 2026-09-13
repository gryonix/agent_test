//! Checks for a newer `gryonixnexusd`, and — only once the owner confirms
//! from the app — downloads it, verifies it, rebuilds it, and restarts.
//!
//! **Why this exists at all.** An urgent agent fix could, before this, only
//! reach an already-installed server through a new client app release:
//! `Tools/pack-agent-sources.sh` bundles the agent's source into the app, and
//! the bootstrap only rebuilds when the app pushes a newer bundle. If the
//! app's own release is waiting on App Store review — up to a week, per the
//! owner (2026-09-13) — the fix waits with it. See `docs_ai/gryonixNexus/
//! ROADMAP.md`, "Обновление агента в обход App Store", for the full plan;
//! `agent_test` (the repo [`DEFAULT_MANIFEST_URL`] points at) is the working
//! name while the mechanism is being tried.
//!
//! **Two halves, on purpose.** [`spawn`] only ever checks and logs — the
//! owner chose "спрашивать подтверждение" (2026-09-13), so nothing downloads,
//! verifies or rebuilds anything until [`apply_agent_update`] is called,
//! which only the app does, which only happens once the owner taps confirm.
//! `curl`, not a Rust TLS client, for both halves — the same reason
//! `install::mail::mailcow`'s API calls do: this crate carries no HTTP client
//! dependency, and a handful of process spawns is not worth adding one for.
//!
//! **Live-tested end to end on `a.grypak.de`, 2026-09-13** (see docs_ai's
//! ROADMAP.md): check, download, `sha256`, docker build, smoke test, swap,
//! restart, `reconcile_on_startup()`. The first run of that swap failed
//! `EXDEV` — `built` and `bin_dest()` do not share a filesystem under
//! `ProtectSystem=full`'s sandbox even with the whole directory granted —
//! see [`swap_binary`]'s own doc for the fix, which is why it copies rather
//! than renames directly from the staging tree.
//!
//! **Signed, not just hashed.** `sha256` alone only proves the download
//! matches what `latest.json` claims — it says nothing about whether
//! `latest.json` itself can be trusted, and it lives in the same repository
//! a compromised account would rewrite along with the binary. Every
//! manifest's `version`/`tag`/`sha256` triple is signed with an Ed25519 key
//! that never touches `agent_test`; [`SIGNING_PUBLIC_KEY_HEX`] is the only
//! half of that keypair this binary carries, and [`check`] refuses a
//! manifest whose signature does not verify against it before trusting any
//! of its fields. `Tools/agent-update-keygen.py` / `Tools/
//! sign-agent-release.py` are the other side, run by hand on the machine
//! that holds the private key — never in this crate.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::pb;

/// Overridable for the day this repo's real name replaces the "agent_test"
/// working name — and for tests, alongside the other env seams below.
const MANIFEST_URL_ENV: &str = "GRYONIXNEXUSD_AGENT_UPDATE_MANIFEST_URL";
const DEFAULT_MANIFEST_URL: &str = "https://raw.githubusercontent.com/gryonix/agent_test/main/latest.json";

/// The other half of the keypair `Tools/agent-update-keygen.py` generated
/// (2026-09-13) never leaves the machine that signs releases — this is the
/// public half, safe to bake in and commit, and it is baked in ON PURPOSE:
/// fetching it from `agent_test` instead would let whoever can rewrite that
/// repo's binary also rewrite the key that is supposed to catch them. Losing
/// the private key means rotating this constant in a NEW agent build before
/// anything signed with the new key can be trusted — there is no recovery
/// that does not go through a release.
const SIGNING_PUBLIC_KEY_HEX: &str = "22e7be06fa63ad3319c386b23dfefaf0efc1e1f96560582bad42eeadecbb0be5";
/// Test-only escape hatch — same seam pattern as [`MANIFEST_URL_ENV`]. A test
/// fixture signs with its OWN keypair and points this at the matching public
/// half, rather than either faking a signature against the real key (cannot
/// — that is the point) or hardcoding the real private key into the test
/// binary (defeats the point just as thoroughly).
const SIGNING_PUBLIC_KEY_ENV: &str = "GRYONIXNEXUSD_AGENT_UPDATE_SIGNING_PUBLIC_KEY_HEX";

fn signing_public_key() -> VerifyingKey {
    let hex = std::env::var(SIGNING_PUBLIC_KEY_ENV).unwrap_or_else(|_| SIGNING_PUBLIC_KEY_HEX.to_string());
    let bytes: [u8; 32] = hex_decode_32(&hex).expect("the signing public key must be 32 valid hex bytes");
    VerifyingKey::from_bytes(&bytes).expect("the signing public key must be a valid Ed25519 point")
}

fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// What [`sign-agent-release.py`] signs and what this verifies — `url` is
/// deliberately excluded, see that script's own doc for why.
fn signed_payload(manifest: &Manifest) -> Vec<u8> {
    format!("{}\n{}\n{}\n", manifest.version, manifest.tag, manifest.sha256).into_bytes()
}

/// Refuses a manifest whose signature does not verify against
/// [`SIGNING_PUBLIC_KEY_HEX`] — called before ANY of the manifest's fields
/// are trusted, so a repo that can rewrite `latest.json` freely still cannot
/// make this agent download, verify or run anything it did not sign.
fn verify_manifest_signature(manifest: &Manifest) -> Result<(), String> {
    use base64::Engine;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&manifest.signature)
        .map_err(|err| format!("manifest signature is not valid base64: {err}"))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "manifest signature is not 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_bytes);
    signing_public_key()
        .verify(&signed_payload(manifest), &signature)
        .map_err(|_| "manifest signature does not verify".to_string())
}

/// Checked twice a day, the same "not hourly" reasoning `AppUpdate.kt`'s own
/// `INTERVAL_MS` gives for the Android app's update check: a release does
/// not happen hourly, and a tighter interval only adds rows to a web log.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const HTTP_TIMEOUT_SECS: u64 = 15;
const DOWNLOAD_TIMEOUT_SECS: u64 = 120;
/// A cargo build on a small VPS, inside a throwaway `rust:1-alpine` container
/// that also has to install its own toolchain first — minutes, not seconds.
const BUILD_TIMEOUT_SECS: u64 = 15 * 60;
const SMOKE_TEST_TIMEOUT_SECS: u64 = 10;

/// Same env-var seam `jobs.rs`'s own `state_dir` reads, so a test can point
/// every part of this module at one sandboxed directory.
const STATE_DIR_ENV: &str = "GRYONIXNEXUSD_STATE_DIR";
const STATE_DIR_FALLBACK: &str = "/var/lib/gryonixnexus/agent";

fn state_dir() -> PathBuf {
    PathBuf::from(std::env::var(STATE_DIR_ENV).unwrap_or_else(|_| STATE_DIR_FALLBACK.to_string()))
}

fn apply_state_path() -> PathBuf {
    state_dir().join("agent-update-apply.json")
}

fn staging_dir() -> PathBuf {
    state_dir().join("agent-update-staging")
}

fn manifest_url() -> String {
    std::env::var(MANIFEST_URL_ENV).unwrap_or_else(|_| DEFAULT_MANIFEST_URL.to_string())
}

/// Same env-var seam as `install::execute::curl_bin`, kept separate rather
/// than shared: that one is scoped to install-time calls and reused by
/// several of them, this is the one caller this module needs.
fn curl_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN").unwrap_or_else(|_| "curl".to_string()))
}

fn tar_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_TAR_BIN").unwrap_or_else(|_| "tar".to_string()))
}

fn docker_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_DOCKER_BIN").unwrap_or_else(|_| "docker".to_string()))
}

fn systemctl_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_SYSTEMCTL_BIN").unwrap_or_else(|_| "systemctl".to_string()))
}

/// Where the rebuilt binary is installed, and what `ApplyAgentUpdate`
/// replaces — `Server/systemd/gryonixnexusd.service`'s own `ExecStart=`.
/// Overridable so a test never touches a real system path.
fn bin_dest() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_BIN_DEST").unwrap_or_else(|_| "/usr/local/bin/gryonixnexusd".to_string()))
}

/// The `rust:1-alpine` image `Server/bootstrap/install-agent.sh`'s own
/// `build_in_docker` already uses — reused rather than re-decided, since it
/// is the already-proven build path every fresh install goes through.
fn rust_image() -> String {
    std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_RUST_IMAGE").unwrap_or_else(|_| "rust:1-alpine".to_string())
}

// ────────────────────────────── checking ───────────────────────────────

/// `latest.json`'s own shape — see `Tools/publish-agent-test.sh` in
/// `gryonixNexus`, which is what writes it.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    pub tag: String,
    pub url: String,
    pub sha256: String,
    /// Base64 Ed25519 signature over [`signed_payload`] — checked in
    /// [`check`] before any other field is trusted.
    pub signature: String,
}

/// What [`check`] answers when the manifest names something newer than the
/// version passed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableUpdate {
    pub manifest: Manifest,
}

/// The last result [`spawn`]'s loop got, read back by
/// [`get_agent_update_status`] rather than re-fetched on every call — the
/// same "cheap to ask, not a network round trip" shape `GetUpdatePolicy`
/// answers for docker service updates. `None` covers both "not checked yet"
/// and "checked, nothing newer"; the RPC does not need to tell those apart.
static LAST_CHECK: std::sync::Mutex<Option<AvailableUpdate>> = std::sync::Mutex::new(None);

/// Fetches the manifest and compares it against `installed`.
///
/// **`Err` is a check that did not complete; `Ok(None)` is one that did and
/// found nothing newer.** The two must not collapse into one "nothing to
/// report" outcome — an unreachable manifest (the server is offline, the
/// repo moved) is worth a debug line, not silence indistinguishable from
/// "already up to date", which is what the caller would see if this
/// swallowed the difference.
pub async fn check(installed: &str) -> Result<Option<AvailableUpdate>, String> {
    let body = fetch_manifest().await?;
    let manifest: Manifest = serde_json::from_str(&body).map_err(|err| format!("malformed manifest: {err}"))?;
    verify_manifest_signature(&manifest).map_err(|err| format!("refusing an unsigned or forged manifest: {err}"))?;
    if is_newer(&manifest.version, installed) {
        Ok(Some(AvailableUpdate { manifest }))
    } else {
        Ok(None)
    }
}

async fn fetch_manifest() -> Result<String, String> {
    let output = tokio::time::timeout(
        Duration::from_secs(HTTP_TIMEOUT_SECS + 5),
        tokio::process::Command::new(curl_bin())
            .args(["-sS", "-f", "--max-time", &HTTP_TIMEOUT_SECS.to_string(), &manifest_url()])
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "curl timed out".to_string())?
    .map_err(|err| format!("could not run curl: {err}"))?;
    if !output.status.success() {
        return Err(format!("curl exited {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|err| format!("manifest was not UTF-8: {err}"))
}

/// Numeric, dot-separated comparison (`"0.0.109" > "0.0.108"`). The crate's
/// own versions are `0.0.N` and never carry anything a semver crate's
/// pre-release/build-metadata rules would matter for, so pulling in `semver`
/// for three integers is not worth the dependency. Either side failing to
/// parse reads as "not newer" rather than panicking: a malformed manifest —
/// this crate's own or a stranger's, since the URL is configurable — must
/// leave a background task quiet, not crash it.
fn is_newer(candidate: &str, installed: &str) -> bool {
    match (parse_version(candidate), parse_version(installed)) {
        (Some(candidate), Some(installed)) => candidate > installed,
        _ => false,
    }
}

fn parse_version(value: &str) -> Option<Vec<u64>> {
    value.split('.').map(|part| part.parse::<u64>().ok()).collect()
}

/// Runs [`check`] once now and then every [`CHECK_INTERVAL`], for as long as
/// the process lives, caching the result for [`get_agent_update_status`] and
/// logging when something newer appears. Never fetches source, verifies a
/// digest or rebuilds anything — see the module doc for why.
pub fn spawn() {
    tokio::spawn(async move {
        loop {
            match check(env!("CARGO_PKG_VERSION")).await {
                Ok(found) => {
                    if let Some(update) = &found {
                        tracing::info!(
                            version = %update.manifest.version,
                            tag = %update.manifest.tag,
                            "a newer gryonixnexusd is published — confirm from the app to fetch it"
                        );
                    }
                    *LAST_CHECK.lock().unwrap_or_else(|p| p.into_inner()) = found;
                }
                Err(err) => tracing::debug!(%err, "agent update check did not complete"),
            }
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    });
}

// ──────────────────────────── apply state ────────────────────────────

/// Survives the restart `apply_agent_update` triggers — an in-memory flag
/// would not, since the process holding it is what gets replaced.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct ApplyState {
    /// Set right before the binary is swapped and the restart triggered;
    /// cleared the moment ANY process start reconciles it. Its PRESENCE, not
    /// its value, is what [`reconcile_on_startup`] acts on.
    #[serde(default)]
    applying_version: Option<String>,
    #[serde(default)]
    apply_attempted: bool,
    #[serde(default)]
    last_apply_succeeded: bool,
    #[serde(default)]
    last_apply_reason: String,
}

fn load_apply_state() -> ApplyState {
    std::fs::read_to_string(apply_state_path())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_apply_state(state: &ApplyState) {
    let Ok(text) = serde_json::to_string(state) else { return };
    if let Err(err) = write_state_file(&apply_state_path(), &text) {
        tracing::warn!(%err, "could not persist the agent update state");
    }
}

/// 0600 from the moment the file exists, the same reasoning `execute.rs`'s
/// `write_secret` gives for its own writes — this file is not a secret, but
/// the habit of a write+chmod race is worth not repeating regardless.
fn write_state_file(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    file.write_all(text.as_bytes())
}

/// Called once at agent startup, before [`spawn`]. If a PREVIOUS process
/// wrote [`ApplyState::applying_version`] before triggering its own restart,
/// this is where that loop closes.
///
/// **Runs on every startup, not just the one right after an apply.** There
/// is no reliable way to tell "this restart is the one ApplyAgentUpdate
/// asked for" from "systemd restarted a crashed unit" from inside the new
/// process alone — but the check is the same fact either way: does the
/// version this process reports match what the marker expected? Reconciling
/// (and clearing the marker) on every startup means a stray unrelated
/// restart between the marker being written and the real swap+restart landing
/// reads as a failure rather than lingering forever as "still applying".
pub fn reconcile_on_startup() {
    let mut state = load_apply_state();
    let Some(expected) = state.applying_version.take() else { return };
    let running = env!("CARGO_PKG_VERSION");
    state.apply_attempted = true;
    if expected == running {
        state.last_apply_succeeded = true;
        state.last_apply_reason.clear();
        tracing::info!(version = %running, "agent update applied — running the new version");
    } else {
        state.last_apply_succeeded = false;
        state.last_apply_reason = format!("expected to come back as {expected}, started as {running} instead");
        tracing::warn!(expected = %expected, running = %running, "agent update did not take effect");
    }
    save_apply_state(&state);
}

// ────────────────────────────── RPCs ──────────────────────────────

pub async fn get_agent_update_status(codec: Codec, _req: pb::GetAgentUpdateStatusRequest) -> Resp {
    let available = LAST_CHECK.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let state = load_apply_state();
    let status = pb::AgentUpdateStatus {
        installed_version: env!("CARGO_PKG_VERSION").to_string(),
        update_available: available.is_some(),
        available_version: available.as_ref().map(|u| u.manifest.version.clone()).unwrap_or_default(),
        available_tag: available.as_ref().map(|u| u.manifest.tag.clone()).unwrap_or_default(),
        apply_attempted: state.apply_attempted,
        last_apply_succeeded: state.last_apply_succeeded,
        last_apply_reason: state.last_apply_reason,
    };
    codec
        .encode(&status)
        .unwrap_or_else(|err| connect_error(hyper::StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

pub async fn apply_agent_update(codec: Codec, _req: pb::ApplyAgentUpdateRequest) -> Resp {
    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        run_apply(codec, tx).await;
    });
    stream_response(json, rx)
}

/// Narrates one run of `ApplyAgentUpdate` to both the live stream and the
/// journal — the same split `update::EventSink` keeps for `RunUpdate`, for
/// the same reason: a client that closed can still ask `Jobs.WatchJob` how
/// far this got, right up to the moment the process serving it restarts.
struct ApplySink {
    tx: Sender<Bytes>,
    codec: Codec,
    journal: Option<crate::jobs::Journal>,
}

impl ApplySink {
    fn job_id(&self) -> String {
        crate::jobs::id_of(&self.journal)
    }

    async fn emit(&self, phase: pb::JobPhase, text: &str, reason: &str) {
        let event = pb::AgentUpdateEvent {
            phase: phase as i32,
            text: text.to_string(),
            reason: reason.to_string(),
            job_id: self.job_id(),
        };
        let payload = self.codec.encode_payload(&event);
        let _ = self.tx.send(envelope(0x00, &payload)).await;
    }

    async fn started(&self) {
        crate::jobs::tee(&self.journal, pb::JobPhase::Started as i32, "agent", "checking for an update");
        self.emit(pb::JobPhase::Started, "checking for an update", "").await;
    }

    async fn progress(&self, text: &str) {
        crate::jobs::tee(&self.journal, pb::JobPhase::Progress as i32, "agent", text);
        self.emit(pb::JobPhase::Progress, text, "").await;
    }

    /// Reached only on a refusal BEFORE anything was touched — see
    /// `AgentUpdateEvent.reason`'s own doc in the schema. The running agent
    /// is untouched whenever this fires.
    async fn failed(&self, reason: &str) {
        if let Some(journal) = &self.journal {
            journal.finish(Some(reason));
        }
        self.emit(pb::JobPhase::Failed, "", reason).await;
        let _ = self.tx.send(error_trailer("failed_precondition", reason)).await;
    }

    /// The LAST event the old process ever sends. What happens after this is
    /// not narrated here — a now-dead process cannot narrate anything — see
    /// `GetAgentUpdateStatus` for how a client learns the rest.
    async fn restarting(&self) {
        if let Some(journal) = &self.journal {
            journal.append(pb::JobPhase::Completed, "agent", "installed — restarting");
            journal.finish(None);
        }
        self.emit(pb::JobPhase::Completed, "installed — restarting", "").await;
    }
}

async fn run_apply(codec: Codec, tx: Sender<Bytes>) {
    let journal = crate::jobs::Journal::open(pb::JobKind::AgentUpdate, "gryonixnexusd");
    let sink = ApplySink { tx, codec, journal };
    sink.started().await;

    let update = match check(env!("CARGO_PKG_VERSION")).await {
        Ok(Some(update)) => update,
        Ok(None) => {
            sink.failed("no update is currently available").await;
            return;
        }
        Err(err) => {
            sink.failed(&format!("could not check for an update: {err}")).await;
            return;
        }
    };

    sink.progress(&format!("downloading {}", update.manifest.tag)).await;
    let tarball = match download(&update.manifest.url).await {
        Ok(bytes) => bytes,
        Err(err) => {
            sink.failed(&format!("could not download the release: {err}")).await;
            return;
        }
    };

    sink.progress("verifying the checksum").await;
    let actual = sha256_hex(&tarball);
    if actual != update.manifest.sha256 {
        sink.failed(&format!(
            "checksum mismatch: manifest names {}, downloaded file hashes to {actual} — refusing to build or run this",
            update.manifest.sha256
        ))
        .await;
        return;
    }

    let staging = staging_dir();
    let _ = std::fs::remove_dir_all(&staging);
    if let Err(err) = std::fs::create_dir_all(&staging) {
        sink.failed(&format!("could not create a staging directory: {err}")).await;
        return;
    }

    sink.progress("unpacking").await;
    if let Err(err) = extract(&tarball, &staging).await {
        sink.failed(&err).await;
        let _ = std::fs::remove_dir_all(&staging);
        return;
    }

    let agent_dir = staging.join("Agent");
    let crate_dir = agent_dir.join("gryonixnexusd");
    if !crate_dir.join("Cargo.toml").is_file() {
        sink.failed("the downloaded release does not have the expected Agent/gryonixnexusd layout").await;
        let _ = std::fs::remove_dir_all(&staging);
        return;
    }

    sink.progress("building — this can take a few minutes").await;
    if let Err(err) = build_in_docker(&agent_dir).await {
        sink.failed(&err).await;
        let _ = std::fs::remove_dir_all(&staging);
        return;
    }

    let built = crate_dir.join("target").join("release").join("gryonixnexusd");
    if !built.is_file() {
        sink.failed("the build produced no binary").await;
        let _ = std::fs::remove_dir_all(&staging);
        return;
    }

    sink.progress("checking the new binary starts").await;
    if let Err(err) = smoke_test(&built, &update.manifest.version).await {
        sink.failed(&err).await;
        let _ = std::fs::remove_dir_all(&staging);
        return;
    }

    // Point of no return: the marker is written BEFORE the swap, so even a
    // crash between the two still leaves a record of what was attempted —
    // reconcile_on_startup reads exactly this on the next start, whichever
    // process that turns out to be.
    save_apply_state(&ApplyState { applying_version: Some(update.manifest.version.clone()), ..load_apply_state() });

    sink.progress("installing").await;
    if let Err(err) = swap_binary(&built) {
        sink.failed(&format!("could not install the new binary: {err}")).await;
        // The swap never took, so there is nothing for a future startup to
        // reconcile — clear the marker rather than leave a stale one behind.
        save_apply_state(&ApplyState { applying_version: None, ..load_apply_state() });
        let _ = std::fs::remove_dir_all(&staging);
        return;
    }

    let _ = std::fs::remove_dir_all(&staging);
    sink.restarting().await;
    // Detached: awaiting this would be awaiting our own death. Best effort —
    // if this spawn itself somehow fails, systemd's own Restart=always still
    // brings the (already swapped) new binary up on its next crash-restart,
    // later than intended but not never.
    let _ = tokio::process::Command::new(systemctl_bin())
        .args(["restart", "gryonixnexusd"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

async fn download(url: &str) -> Result<Vec<u8>, String> {
    let output = tokio::time::timeout(
        Duration::from_secs(DOWNLOAD_TIMEOUT_SECS + 5),
        tokio::process::Command::new(curl_bin())
            .args(["-sS", "-f", "-L", "--max-time", &DOWNLOAD_TIMEOUT_SECS.to_string(), url])
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "the download timed out".to_string())?
    .map_err(|err| format!("could not run curl: {err}"))?;
    if !output.status.success() {
        return Err(format!("curl exited {}", output.status));
    }
    Ok(output.stdout)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `--strip-components=1`: a GitHub codeload tarball wraps everything in one
/// top-level `<repo>-<ref>/` directory, and `into` is meant to end up holding
/// `Agent/` directly, matching `Tools/pack-agent-sources.sh`'s own layout.
async fn extract(tarball: &[u8], into: &std::path::Path) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new(tar_bin())
        .args(["-xzf", "-", "--strip-components=1", "-C"])
        .arg(into)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run tar: {err}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(tarball).await;
    }
    let output = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .map_err(|_| "tar timed out".to_string())?
        .map_err(|err| format!("could not run tar: {err}"))?;
    if !output.status.success() {
        return Err(format!("tar exited {}: {}", output.status, bounded_tail(&output.stderr, 500)));
    }
    Ok(())
}

/// The exact command `Server/bootstrap/install-agent.sh`'s own
/// `build_in_docker`/`container_build_command` already run for a fresh
/// install — reused rather than re-decided, since it is the already-proven
/// path every install goes through. `AGENT_DIR` there is `agent_dir` here.
async fn build_in_docker(agent_dir: &std::path::Path) -> Result<(), String> {
    let mount = format!("{}:/src", agent_dir.display());
    let script = "if ! apk add --no-cache build-base protoc protobuf-dev >/tmp/apk.log 2>&1; then \
                   cat /tmp/apk.log >&2; exit 1; fi; cargo build --release --locked";
    let output = tokio::time::timeout(
        Duration::from_secs(BUILD_TIMEOUT_SECS),
        tokio::process::Command::new(docker_bin())
            .args(["run", "--rm", "-v", &mount, "-w", "/src/gryonixnexusd", &rust_image(), "sh", "-c", script])
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "the build timed out".to_string())?
    .map_err(|err| format!("could not run docker: {err}"))?;
    if !output.status.success() {
        return Err(format!("the build failed:\n{}", bounded_tail(&output.stderr, 2000)));
    }
    Ok(())
}

/// The last character-boundary-safe `max_chars` characters of a byte stream,
/// prefixed with an ellipsis when it was cut — for compiler/wrapper output
/// that could otherwise run to megabytes.
fn bounded_tail(bytes: &[u8], max_chars: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_chars {
        chars.into_iter().collect()
    } else {
        format!("…{}", chars[chars.len() - max_chars..].iter().collect::<String>())
    }
}

/// Runs the newly built binary's own `version` dispatch (the same one
/// `main.rs` answers without root or a usable state.db) and checks it prints
/// what this run expected to build — BEFORE the binary ever gets close to
/// `/usr/local/bin`. Catches a binary that does not even start, or one built
/// from the wrong tree, as a refusal rather than a broken install.
async fn smoke_test(binary: &std::path::Path, expected_version: &str) -> Result<(), String> {
    let output = tokio::time::timeout(
        Duration::from_secs(SMOKE_TEST_TIMEOUT_SECS),
        tokio::process::Command::new(binary).arg("version").stdin(Stdio::null()).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| "the new binary did not answer 'version' in time".to_string())?
    .map_err(|err| format!("could not run the new binary: {err}"))?;
    if !output.status.success() {
        return Err(format!("the new binary exited {} answering 'version'", output.status));
    }
    let printed = String::from_utf8_lossy(&output.stdout);
    if !printed.contains(expected_version) {
        return Err(format!("the new binary reports '{}', expected {expected_version}", printed.trim()));
    }
    Ok(())
}

/// `rename()`, not an in-place overwrite: this process is itself the file
/// being replaced, and `rename()` re-points the directory entry without
/// touching the inode this process is still executing from — the standard
/// way a running Unix binary replaces itself. An open-for-write on the same
/// path would fail `ETXTBSY` instead.
///
/// `built` is NOT renamed directly: it lives under the state dir's staging
/// tree, and `rename(2)` requires both paths to share a filesystem. Proven
/// live on `a.grypak.de` (2026-09-13) that they do not, even with the whole
/// `/usr/local/bin` directory granted writable — systemd's `ReadWritePaths`
/// exceptions under `ProtectSystem=full` land on a different mount than the
/// state dir, so a straight `rename(built, bin_dest())` fails `EXDEV`
/// ("Cross-device link"). The fix is to copy the bytes across that boundary
/// FIRST, landing next to the destination (guaranteed same filesystem), and
/// only `rename()` from there — the swap that actually replaces the live
/// binary is atomic by construction, and the cross-filesystem step never
/// touches the live path.
fn swap_binary(built: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let dest = bin_dest();
    let staged = dest.with_extension("new");
    std::fs::copy(built, &staged).map_err(|err| format!("could not stage the new binary next to the old one: {err}"))?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).map_err(|err| {
        let _ = std::fs::remove_file(&staged);
        format!("could not set the new binary's mode: {err}")
    })?;
    std::fs::rename(&staged, &dest).map_err(|err| {
        let _ = std::fs::remove_file(&staged);
        format!("{err}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    /// One lock for every env var this module reads, shared across its own
    /// tests the same way `jobs.rs`'s tests share `util::STATE_DIR_ENV_LOCK`
    /// for theirs — env vars are process-wide, and the default test runner
    /// runs tests on separate threads of the same process.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn sandbox(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-agent-update-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ──────────────────────────── manifest signing ─────────────────────────
    // A fixed keypair, generated once for this test module only — nothing to
    // do with SIGNING_PUBLIC_KEY_HEX, and never meant to sign anything real.
    // Tests point SIGNING_PUBLIC_KEY_ENV at TEST_PUBLIC_KEY_HEX so `check()`
    // verifies fixtures against THIS key rather than the production one,
    // which no test has (or should have) the private half of.
    const TEST_PRIVATE_KEY_HEX: &str = "f10c702fd5a5263b92ccd3a5cd3463159ce7fc07f634cf2bde1afaeb07dacd58";
    const TEST_PUBLIC_KEY_HEX: &str = "48944c96c921bac5e29136ddb80f73254530c00b6cc712ca4a78e56e5bb70f18";

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&hex_decode_32(TEST_PRIVATE_KEY_HEX).unwrap())
    }

    /// Builds a `latest.json` body signed with [`test_signing_key`] — the
    /// fixture every `check()` test below starts from, tampered with per
    /// case where a test needs an invalid one.
    fn signed_manifest_json(version: &str, tag: &str, url: &str, sha256: &str) -> String {
        use ed25519_dalek::Signer;
        let manifest = Manifest { version: version.into(), tag: tag.into(), url: url.into(), sha256: sha256.into(), signature: String::new() };
        let signature = test_signing_key().sign(&signed_payload(&manifest));
        use base64::Engine;
        let signature = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        format!(r#"{{"version":"{version}","tag":"{tag}","url":"{url}","sha256":"{sha256}","signature":"{signature}"}}"#)
    }

    // ─────────────────────────── version comparison ───────────────────────

    #[test]
    fn version_comparison_is_numeric_not_lexicographic() {
        assert!(is_newer("0.0.109", "0.0.108"));
        // The bug numeric comparison exists to avoid: "9" sorts after "10"
        // as text, so a naive string compare would call 0.0.9 newer.
        assert!(!is_newer("0.0.9", "0.0.10"));
        assert!(is_newer("0.0.10", "0.0.9"));
        assert!(!is_newer("0.0.108", "0.0.108"));
        assert!(!is_newer("0.0.107", "0.0.108"));
    }

    #[test]
    fn a_malformed_or_non_numeric_version_is_never_newer() {
        assert!(!is_newer("not-a-version", "0.0.108"));
        assert!(!is_newer("0.0.108", "not-a-version"));
        assert!(!is_newer("", ""));
    }

    // ────────────────────────────── check() ────────────────────────────────

    fn stub_curl(dir: &std::path::Path, body: &str, status: i32) -> PathBuf {
        let path = dir.join("curl");
        let mut file = std::fs::File::create(&path).unwrap();
        // `curl -f` would itself fail the process on a non-2xx status in the
        // real binary; the stub is only asked to reproduce curl's EXIT CODE
        // for that case; a caller that passes `status != 0` need not also
        // pass a body; there is nothing our own `fetch_manifest` reads from a
        // failed run.
        writeln!(file, "#!/bin/bash\ncat <<'BODY'\n{body}\nBODY\nexit {status}").unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        path
    }

    /// Every `check()` test below sets both seams (the curl stub AND the test
    /// public key) before awaiting and clears both after — a helper that
    /// only SET them around a lazily-constructed future would remove the env
    /// vars before `check()` actually ran, since futures do nothing until
    /// polled, so this stays inline rather than becoming one.
    #[tokio::test]
    async fn a_newer_manifest_version_is_reported() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("newer");
        let body = signed_manifest_json("0.0.999", "v0.0.999", "https://example.com/x.tar.gz", "deadbeef");
        let curl = stub_curl(&dir, &body, 0);
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        std::env::set_var(SIGNING_PUBLIC_KEY_ENV, TEST_PUBLIC_KEY_HEX);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        std::env::remove_var(SIGNING_PUBLIC_KEY_ENV);
        let _ = std::fs::remove_dir_all(&dir);

        let update = result.unwrap().expect("a newer version must be reported");
        assert_eq!(update.manifest.version, "0.0.999");
        assert_eq!(update.manifest.tag, "v0.0.999");
    }

    #[tokio::test]
    async fn a_manifest_that_is_not_newer_reports_nothing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("current");
        let body = signed_manifest_json("0.0.108", "v0.0.108", "https://example.com/x.tar.gz", "deadbeef");
        let curl = stub_curl(&dir, &body, 0);
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        std::env::set_var(SIGNING_PUBLIC_KEY_ENV, TEST_PUBLIC_KEY_HEX);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        std::env::remove_var(SIGNING_PUBLIC_KEY_ENV);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    async fn a_manifest_with_a_tampered_field_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("tampered");
        // Signed for 0.0.999, then the sha256 an attacker wants trusted is
        // swapped in AFTER signing — the signature no longer covers this
        // body, so this must be rejected even though the JSON is well-formed
        // and the version really would be newer.
        let body = signed_manifest_json("0.0.999", "v0.0.999", "https://example.com/x.tar.gz", "deadbeef")
            .replace("deadbeef", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd");
        let curl = stub_curl(&dir, &body, 0);
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        std::env::set_var(SIGNING_PUBLIC_KEY_ENV, TEST_PUBLIC_KEY_HEX);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        std::env::remove_var(SIGNING_PUBLIC_KEY_ENV);
        let _ = std::fs::remove_dir_all(&dir);

        let err = result.expect_err("a tampered manifest must not be trusted");
        assert!(err.contains("signature"), "the failure must name the reason: {err}");
    }

    #[tokio::test]
    async fn a_manifest_with_an_invalid_signature_field_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("bad-sig-field");
        let body = r#"{"version":"0.0.999","tag":"v0.0.999","url":"https://example.com/x.tar.gz","sha256":"deadbeef","signature":"not-base64!!"}"#;
        let curl = stub_curl(&dir, body, 0);
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        std::env::set_var(SIGNING_PUBLIC_KEY_ENV, TEST_PUBLIC_KEY_HEX);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        std::env::remove_var(SIGNING_PUBLIC_KEY_ENV);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_failed_fetch_is_an_error_not_a_silent_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("fetch-fail");
        let curl = stub_curl(&dir, "", 22); // curl's own exit code for -f on an HTTP error
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(result.is_err(), "a curl failure must not read as 'nothing to report'");
    }

    #[tokio::test]
    async fn a_malformed_manifest_body_is_an_error() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("garbage");
        let curl = stub_curl(&dir, "not json at all", 0);
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(result.is_err());
    }

    // ─────────────────────────────── digest ────────────────────────────────

    #[test]
    fn sha256_matches_a_known_vector() {
        // sha256("") — the standard empty-string test vector, so this is
        // pinned against a value nobody here computed by hand.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // ─────────────────────────── apply-state reconciliation ───────────────

    fn with_state_dir<T>(name: &str, body: impl FnOnce() -> T) -> T {
        let dir = sandbox(name);
        std::env::set_var(STATE_DIR_ENV, &dir);
        let out = body();
        std::env::remove_var(STATE_DIR_ENV);
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn no_marker_means_reconcile_does_nothing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_state_dir("no-marker", || {
            reconcile_on_startup();
            let state = load_apply_state();
            assert!(!state.apply_attempted);
        });
    }

    #[test]
    fn coming_back_as_the_expected_version_reads_as_success() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_state_dir("success", || {
            save_apply_state(&ApplyState {
                applying_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                ..Default::default()
            });
            reconcile_on_startup();
            let state = load_apply_state();
            assert!(state.apply_attempted);
            assert!(state.last_apply_succeeded);
            assert!(state.last_apply_reason.is_empty());
            assert_eq!(state.applying_version, None, "the marker must be cleared once reconciled");
        });
    }

    #[test]
    fn coming_back_as_a_different_version_reads_as_failure() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_state_dir("mismatch", || {
            save_apply_state(&ApplyState { applying_version: Some("99.99.99".to_string()), ..Default::default() });
            reconcile_on_startup();
            let state = load_apply_state();
            assert!(state.apply_attempted);
            assert!(!state.last_apply_succeeded);
            assert!(state.last_apply_reason.contains("99.99.99"));
            assert_eq!(state.applying_version, None);
        });
    }

    #[test]
    fn a_missing_state_file_reads_as_the_defaults() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_state_dir("missing", || {
            let state = load_apply_state();
            assert_eq!(state, ApplyState::default());
        });
    }

    // ──────────────────────────────── extract ──────────────────────────────

    fn make_tarball(dir: &std::path::Path) -> Vec<u8> {
        // A real gzip'd tarball with ONE top-level wrapper directory, the
        // same shape a GitHub codeload archive has — built with the real
        // `tar` on this machine so the test proves `extract`'s
        // `--strip-components=1` against actual tar behaviour, not a
        // hand-rolled stand-in for it.
        let root = dir.join("agent_test-v0.0.999");
        std::fs::create_dir_all(root.join("Agent").join("gryonixnexusd")).unwrap();
        std::fs::write(root.join("Agent").join("gryonixnexusd").join("Cargo.toml"), "[package]\n").unwrap();
        let archive = dir.join("out.tar.gz");
        let status = std::process::Command::new("tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(dir)
            .arg("agent_test-v0.0.999")
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::read(&archive).unwrap()
    }

    #[tokio::test]
    async fn extract_strips_the_codeload_wrapper_directory() {
        let src = sandbox("extract-src");
        let tarball = make_tarball(&src);
        let dest = sandbox("extract-dest");

        extract(&tarball, &dest).await.unwrap();

        assert!(dest.join("Agent").join("gryonixnexusd").join("Cargo.toml").is_file());
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dest);
    }

    // ─────────────────────────────── smoke test ─────────────────────────────

    fn stub_binary(dir: &std::path::Path, prints: &str, status: i32) -> PathBuf {
        let path = dir.join("gryonixnexusd-stub");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "#!/bin/bash\necho '{prints}'\nexit {status}").unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        path
    }

    #[tokio::test]
    async fn a_binary_that_prints_the_expected_version_passes() {
        let dir = sandbox("smoke-ok");
        let bin = stub_binary(&dir, "gryonixnexusd 0.0.999", 0);
        assert!(smoke_test(&bin, "0.0.999").await.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_binary_that_prints_the_wrong_version_fails() {
        let dir = sandbox("smoke-wrong");
        let bin = stub_binary(&dir, "gryonixnexusd 0.0.1", 0);
        let err = smoke_test(&bin, "0.0.999").await.unwrap_err();
        assert!(err.contains("0.0.1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_binary_that_exits_nonzero_fails() {
        let dir = sandbox("smoke-crash");
        let bin = stub_binary(&dir, "boom", 1);
        assert!(smoke_test(&bin, "0.0.999").await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────────── swap_binary ────────────────────────────

    #[test]
    fn swap_binary_replaces_the_destination_atomically() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("swap");
        let built = dir.join("new-binary");
        std::fs::write(&built, b"new contents").unwrap();
        let dest = dir.join("installed");
        std::fs::write(&dest, b"old contents").unwrap();

        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_BIN_DEST", &dest);
        let result = swap_binary(&built);
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_BIN_DEST");

        assert!(result.is_ok());
        assert_eq!(std::fs::read(&dest).unwrap(), b"new contents");
        assert!(built.exists(), "the copy source is untouched — run_apply, not swap_binary, owns the staging tree's cleanup");
        assert!(!dest.with_extension("new").exists(), "the staged copy must be renamed away, not left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bug proven live on `a.grypak.de` (2026-09-13): `built` and `dest`
    /// on different filesystems must still succeed, because `std::fs::copy`
    /// (not `rename`) crosses that boundary.
    #[test]
    fn swap_binary_survives_a_cross_filesystem_source() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // /dev/shm is tmpfs — reliably a different filesystem than the OS
        // temp dir on any real machine, unlike two paths under the same
        // sandbox() call, which share a device and would not exercise EXDEV.
        let shm = std::path::PathBuf::from("/dev/shm");
        if !shm.is_dir() {
            return; // no tmpfs on this machine (e.g. macOS) — nothing to prove here
        }
        let built = shm.join(format!("gryonixnexusd-swap-test-{}", std::process::id()));
        std::fs::write(&built, b"new contents").unwrap();
        let dir = sandbox("swap-xdev");
        let dest = dir.join("installed");
        std::fs::write(&dest, b"old contents").unwrap();

        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_BIN_DEST", &dest);
        let result = swap_binary(&built);
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_BIN_DEST");

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"new contents");
        let _ = std::fs::remove_file(&built);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
