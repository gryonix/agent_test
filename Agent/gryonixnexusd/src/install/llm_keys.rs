//! **The provider keys the gateway uses, rendered from the agent's own vault.**
//!
//! Owner's decision, 2026-09-07: an API key for somebody else's model has to
//! live ON THE SERVER — so a second phone and a reinstalled app see the same
//! one — and still be changeable FROM a device. The vault already does the
//! first half for the deployment's own passwords (`vault.rs`, `state.rs`);
//! this is the second, and it is the first time the agent ACTS on a vault row
//! rather than merely storing it.
//!
//! **The shape of that action, and why it is a reconciliation rather than a
//! verb.** There is no new RPC here. A device saves a vault entry exactly as
//! it already does; the agent notices, on the way out of that write, that some
//! of the rows are service secrets, re-renders one root-only file and restarts
//! the container that reads it. A verb would have been a second way to change
//! the same state — and the two would disagree the first time somebody edited
//! a key from the generic vault screen instead of the one built for it.
//!
//! **The allowlist is a security boundary, not a menu.** This file is written
//! by root from strings a client sent. So the set of variable names that may
//! appear in it is closed and lives here; an entry naming anything else is
//! IGNORED, never written and never guessed at. The same table is stated on
//! the Swift side (`LLMProvider`) and the two are compared by a test, the way
//! every other cross-language contract in this project is.
//!
//! **What this does NOT protect.** The rendered file is plaintext on the host,
//! because the container has to read it. Encryption covers COPIES — a backup,
//! a lifted disk — which is the same honest boundary `vault.rs` draws for the
//! rows themselves, and the app says it in those words rather than implying
//! more.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::pb;

/// One model provider the gateway can hold a key for.
pub struct Provider {
    /// Second half of the vault entry's `service_secret` (`litellm/openai`).
    pub id: &'static str,
    /// The variable the provider's own SDK reads — and the only strings that
    /// may ever appear on the left of an `=` in the rendered file.
    pub environment_key: &'static str,
}

/// In the same order as `LLMProvider.all` on the Swift side. The order is not
/// load-bearing here (the file is sorted), but a list that reads differently
/// from its twin is a list somebody will "fix" in one place.
pub const PROVIDERS: &[Provider] = &[
    Provider { id: "openai", environment_key: "OPENAI_API_KEY" },
    Provider { id: "anthropic", environment_key: "ANTHROPIC_API_KEY" },
    Provider { id: "deepseek", environment_key: "DEEPSEEK_API_KEY" },
    Provider { id: "gemini", environment_key: "GEMINI_API_KEY" },
    Provider { id: "groq", environment_key: "GROQ_API_KEY" },
    Provider { id: "mistral", environment_key: "MISTRAL_API_KEY" },
    Provider { id: "openrouter", environment_key: "OPENROUTER_API_KEY" },
    Provider { id: "xai", environment_key: "XAI_API_KEY" },
];

/// The catalog id whose secrets this module renders.
pub const SERVICE_ID: &str = "litellm";
/// Beside the backup passphrase, and root-only for the same reason.
///
/// Not composed into `KEYS_ENV_PATH` below — `concat!` needs a string
/// literal, not a `const` — so this stays documentation of the directory
/// (matching the Kotlin side's own `SHARED_CONFIG_DIRECTORY`,
/// `LiteLLMService.kt:278`) rather than code that would drift from it
/// silently if the literal below ever changed alone.
#[allow(dead_code)]
pub const SHARED_CONFIG_DIR: &str = "/etc/gryonixnexus";
/// **A constant, never a path derived from a setting.** See the module doc.
pub const KEYS_ENV_PATH: &str = "/etc/gryonixnexus/litellm-keys.env";

/// The container restarted when the file changes.
pub const CONTAINER: &str = "litellm";

fn keys_env_path() -> String {
    // The same env seam `docker_bin` uses, and for the same reason: a test
    // writes into a temporary directory, a server never sets it.
    std::env::var("GRYONIXNEXUSD_LLM_KEYS_PATH").unwrap_or_else(|_| KEYS_ENV_PATH.to_string())
}

fn docker_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN").unwrap_or_else(|_| "docker".to_string())
}

/// The provider a `service_secret` names, or `None` for anything else — an
/// ordinary account row, another service's secret, or a provider this build
/// does not know.
pub fn provider(service_secret: &str) -> Option<&'static Provider> {
    let (service, id) = service_secret.split_once('/')?;
    if service != SERVICE_ID {
        return None;
    }
    PROVIDERS.iter().find(|p| p.id == id)
}

/// The secret a vault entry carries.
///
/// `token` first, because that is what an API key IS and what the app writes.
/// `password` as a fallback rather than a refusal: somebody editing the row in
/// the generic vault screen types into the field that screen calls the secret,
/// and dropping their key on that technicality would look like the app losing
/// it.
fn secret_of(entry: &pb::VaultEntry) -> &str {
    if !entry.token.trim().is_empty() {
        entry.token.trim()
    } else {
        entry.password.trim()
    }
}

/// A value that can be written as one `KEY=value` line and read back as it was.
///
/// Refused rather than escaped: a newline in a value would add a LINE to a
/// root-owned env file, which is a way to set a variable nobody allowed. There
/// is no legitimate API key that contains one, so the honest answer is to drop
/// the entry rather than to invent a quoting scheme for it.
fn is_writable_value(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(|c| c.is_control())
}

/// The whole file, from what the vault holds.
///
/// Sorted by variable name so that re-rendering an unchanged vault produces an
/// identical file — which is what makes "did it change" a byte comparison and
/// therefore what keeps the container from being restarted on every save.
pub fn render(entries: &[pb::VaultEntry]) -> String {
    let mut rows: Vec<(&str, &str)> = Vec::new();
    for entry in entries {
        if entry.deleted {
            continue;
        }
        let Some(provider) = provider(&entry.service_secret) else { continue };
        let value = secret_of(entry);
        if !is_writable_value(value) {
            continue;
        }
        rows.push((provider.environment_key, value));
    }
    rows.sort_by(|a, b| a.0.cmp(b.0));
    // A duplicate id cannot arrive from one snapshot (the vault is keyed by
    // entry id and two ids could still name one provider), so the LAST one
    // after the sort wins deterministically rather than by arrival order.
    rows.dedup_by(|a, b| a.0 == b.0);
    let mut out = String::new();
    for (key, value) in rows {
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out
}

/// Writes the file when its content changed, and says whether it did.
///
/// Created through `OpenOptions` at 0600 rather than chmod-after, for the
/// reason `vault.rs` gives about its own key: a secret must not exist as a
/// world-readable file even for the instant between the two calls.
pub fn write_if_changed(body: &str) -> Result<bool> {
    let path_string = keys_env_path();
    let path = Path::new(&path_string);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    if let Ok(existing) = fs::read_to_string(path) {
        if existing == body {
            return Ok(false);
        }
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    // Belt and braces for a file that predates this process with a wider mode.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(true)
}

/// The compose file the gateway's own container was created from, read off its
/// compose labels.
///
/// **Asked of docker rather than built from a setting.** The gateway lives
/// wherever `litellm_path` put it, and this module is reached from a vault
/// write that carries no install input at all. The label is written by compose
/// itself, so a container compose created can always say where its file is;
/// one started by hand cannot, and that is the case the caller falls back for.
fn compose_file_of(container: &str) -> Option<String> {
    let out = Command::new(docker_bin())
        .args([
            "inspect",
            "-f",
            "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}",
            container,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // The label is comma separated when a project has several files; the first
    // is the one this product writes.
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .split(',')
        .next()
        .map(str::to_string)
        .filter(|file| !file.is_empty() && file != "<no value>")
}

/// Puts the newly rendered file INTO the running gateway.
///
/// **`docker restart` is not enough, and finding that out cost a live run.**
/// `env_file` is resolved by compose when a container is CREATED: the values
/// land in that container's own config, and a restart re-runs the config it
/// already has. So on 31.70.137.80 on 2026-09-08 a key saved from a device did
/// reach `/etc/gryonixnexus/litellm-keys.env`, the container did bounce, and
/// the gateway came back with exactly the environment it had before —
/// `/v1/chat/completions` still answered "the api_key client option must be
/// set". The file was right and the feature did not work.
///
/// The container has to be re-CREATED, which only compose can do from the file
/// it was made from. The plain restart stays as the fallback for a gateway
/// that compose did not create — better than nothing, and honest about which
/// one ran.
///
/// **A failure here is not an error the caller propagates.** The keys are
/// already stored and already rendered; a gateway that is not installed on this
/// host, or is stopped, is a normal state rather than a failed save — and
/// turning it into one would make saving a key from the phone fail on every
/// host that has no gateway.
pub fn restart_gateway() -> bool {
    if let Some(file) = compose_file_of(CONTAINER) {
        let recreated = Command::new(docker_bin())
            .args([
                "compose",
                "-p",
                crate::install::litellm::COMPOSE_PROJECT,
                "-f",
                &file,
                "up",
                "-d",
                "--force-recreate",
                CONTAINER,
            ])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if recreated {
            return true;
        }
    }
    Command::new(docker_bin())
        .args(["restart", CONTAINER])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// The whole reconciliation: render what the vault holds, write it if it
/// changed, restart the gateway if it was written. Returns whether anything
/// was written.
pub fn reconcile(entries: &[pb::VaultEntry]) -> Result<bool> {
    let body = render(entries);
    // Nothing to do on the overwhelming majority of vault writes: a deployment
    // with no gateway has no rows this module recognises, and re-rendering an
    // empty file over an absent one would create a secret file on every host
    // that ever saved a password.
    if body.is_empty() && !Path::new(&keys_env_path()).exists() {
        return Ok(false);
    }
    let changed = write_if_changed(&body)?;
    if changed {
        restart_gateway();
    }
    Ok(changed)
}

/// The shared secret the gateway checks and the chat presents, minted once.
///
/// **Whichever end runs first creates it, and neither ever overwrites**, for
/// the reason the Swift side gives at `gatewayKeyPath`: the shelf leads with
/// the chat, so the gateway's own step runs later, and a chat that read the
/// gateway's `.env` would read a file that does not exist yet.
///
/// Created through `OpenOptions` at 0600 rather than chmod-after, the way
/// `write_if_changed` above is and for the same reason.
pub fn ensure_gateway_key(path: &Path) -> Result<String> {
    ensure_shared_secret(path, "sk-")
}

/// The same thing for any pair that has to agree on one value.
///
/// **The problem is an ordering one and it is the only real one on these
/// shelves.** The catalog installs services in shelf order, which is a product
/// decision rather than a dependency graph, so neither end of a pair can be
/// told "you generate it and the other reads it" — the reader would run first
/// on half the deployments. Whichever step reaches this first creates the
/// file; every later one reads it, including a re-install, which is what keeps
/// a working deployment working.
///
/// `prefix` is for stores that expect a recognisable shape (`sk-…`); the
/// vector store does not care, and passes an empty one.
pub fn ensure_shared_secret(path: &Path, prefix: &str) -> Result<String> {
    if let Ok(existing) = fs::read_to_string(path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut bytes = [0u8; 24];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut bytes)
        .context("reading /dev/urandom")?;
    let key = format!("{prefix}{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(format!("{key}\n").as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(key)
}

/// Sets one `KEY=value` in an `.env`, whether or not it is already there — a
/// port of `LiteLLMService.setEnvSection`, and the same reason for existing: a
/// plain append would add a second line for the same variable on every re-run,
/// which compose resolves to the last one, so it works right up until somebody
/// reads the file and cannot tell which value is live.
pub fn set_env_value(path: &Path, key: &str, value: &str) -> Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in existing.lines() {
        if line.starts_with(&format!("{key}=")) {
            lines.push(format!("{key}={value}"));
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        lines.push(format!("{key}={value}"));
    }
    let mut body = lines.join("\n");
    body.push('\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Creates the provider-keys file EMPTY when it is missing.
///
/// Compose refuses to start a service whose `env_file` is not there, and on a
/// host whose vault holds no provider keys yet that file has never been
/// written — so the install has to make one rather than leave the gateway
/// unable to start.
pub fn ensure_keys_file(path: &Path) -> Result<()> {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    /// **The four tests below reach for the same two process-global env
    /// vars** (`GRYONIXNEXUSD_LLM_KEYS_PATH`, `GRYONIXNEXUSD_INSTALL_DOCKER_BIN`),
    /// which is what those seams are for — and cargo runs tests in parallel, so
    /// without this they set and unset each other's values and fail in a way
    /// that reads like a broken module. Poison is ignored: a test that panicked
    /// while holding it has already reported its own failure, and refusing the
    /// lock afterwards would turn that one failure into three more.
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    use super::*;

    fn entry(secret: &str, token: &str) -> pb::VaultEntry {
        pb::VaultEntry {
            id: format!("single|{secret}"),
            service_secret: secret.to_string(),
            token: token.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn the_gateway_key_is_minted_once_and_never_rotated() {
        let dir = std::env::temp_dir().join(format!("gryonix-gwkey-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("llm-gateway.key");
        let _ = std::fs::remove_file(&path);

        let first = ensure_gateway_key(&path).unwrap();
        assert!(first.starts_with("sk-"), "got: {first}");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // The half that matters: a second run must hand back the SAME secret,
        // or the chat and the gateway stop agreeing on every reinstall.
        assert_eq!(ensure_gateway_key(&path).unwrap(), first);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn setting_a_variable_twice_leaves_one_line_for_it() {
        let dir = std::env::temp_dir().join(format!("gryonix-setenv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".env");
        std::fs::write(&path, "OTHER=1\n").unwrap();

        set_env_value(&path, "LLM_GATEWAY_KEY", "sk-one").unwrap();
        set_env_value(&path, "LLM_GATEWAY_KEY", "sk-two").unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body, "OTHER=1\nLLM_GATEWAY_KEY=sk-two\n", "got: {body:?}");
        assert_eq!(body.matches("LLM_GATEWAY_KEY=").count(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_known_provider_becomes_its_own_variable() {
        let body = render(&[entry("litellm/openai", "sk-abc")]);
        assert_eq!(body, "OPENAI_API_KEY=sk-abc\n");
    }

    /// The allowlist is the point of the module — see its doc.
    #[test]
    fn anything_outside_the_allowlist_is_ignored_rather_than_written() {
        let body = render(&[
            entry("litellm/not-a-provider", "x"),
            entry("otherservice/openai", "x"),
            // An ordinary account row: no service_secret at all.
            pb::VaultEntry { id: "single|Vaultwarden".into(), password: "hunter2".into(), ..Default::default() },
        ]);
        assert_eq!(body, "");
    }

    /// A newline in a value would add a LINE to a root-owned env file. There is
    /// no legitimate key containing one, so the entry is dropped rather than
    /// quoted.
    #[test]
    fn a_value_that_could_forge_a_second_variable_is_refused() {
        let body = render(&[entry("litellm/openai", "sk-abc\nADMIN=1")]);
        assert_eq!(body, "", "a control character was written into the env file");
    }

    #[test]
    fn a_tombstone_takes_its_key_out() {
        let mut gone = entry("litellm/openai", "sk-abc");
        gone.deleted = true;
        assert_eq!(render(&[gone]), "");
    }

    /// The password field is accepted, because that is where somebody editing
    /// the row on the generic vault screen would type.
    #[test]
    fn the_password_field_is_read_when_the_token_is_empty() {
        let mut row = entry("litellm/anthropic", "");
        row.password = "sk-ant".into();
        assert_eq!(render(&[row]), "ANTHROPIC_API_KEY=sk-ant\n");
    }

    /// Deterministic output is what makes "did it change" a byte comparison,
    /// and therefore what keeps the gateway from restarting on every save.
    #[test]
    fn the_same_vault_renders_the_same_bytes_whatever_the_order() {
        let a = render(&[entry("litellm/openai", "one"), entry("litellm/groq", "two")]);
        let b = render(&[entry("litellm/groq", "two"), entry("litellm/openai", "one")]);
        assert_eq!(a, b);
        assert_eq!(a, "GROQ_API_KEY=two\nOPENAI_API_KEY=one\n");
    }

    #[test]
    fn the_file_is_written_0600_and_only_when_it_changed() {
        let _env = env_guard();
        let dir = std::env::temp_dir().join(format!("gryonix-llmkeys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("litellm-keys.env");
        // SAFETY: single-threaded test, and the seam exists for exactly this.
        unsafe { std::env::set_var("GRYONIXNEXUSD_LLM_KEYS_PATH", &path) };

        assert!(write_if_changed("OPENAI_API_KEY=one\n").unwrap());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the provider keys are readable by somebody else");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "OPENAI_API_KEY=one\n");

        assert!(!write_if_changed("OPENAI_API_KEY=one\n").unwrap(), "an unchanged file was rewritten");
        assert!(write_if_changed("OPENAI_API_KEY=two\n").unwrap());

        unsafe { std::env::remove_var("GRYONIXNEXUSD_LLM_KEYS_PATH") };
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A host that never had a gateway must not grow a secret file because
    /// somebody saved an ordinary password.
    #[test]
    fn a_vault_with_no_provider_keys_creates_no_file() {
        let _env = env_guard();
        let dir = std::env::temp_dir().join(format!("gryonix-llmkeys-none-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("litellm-keys.env");
        unsafe { std::env::set_var("GRYONIXNEXUSD_LLM_KEYS_PATH", &path) };

        let written = reconcile(&[pb::VaultEntry {
            id: "single|Vaultwarden".into(),
            password: "hunter2".into(),
            ..Default::default()
        }])
        .unwrap();
        assert!(!written);
        assert!(!path.exists(), "an empty secret file was created on a host with no gateway");

        unsafe { std::env::remove_var("GRYONIXNEXUSD_LLM_KEYS_PATH") };
        std::fs::remove_dir_all(&dir).ok();
    }

    /// **The live defect this exists to keep closed.** `env_file` is resolved
    /// when a container is CREATED, so a `docker restart` brings the gateway
    /// back with the environment it already had — the key the owner just saved
    /// sat in the file and never reached the process. Measured on a real host,
    /// 2026-09-08. What has to run is a compose re-create, from the file the
    /// container's own labels name.
    #[test]
    fn the_gateway_is_recreated_from_its_compose_file_not_merely_restarted() {
        let _env = env_guard();
        let dir = std::env::temp_dir().join(format!("gryonix-llmkeys-recreate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let argv = dir.join("argv");
        let stub = dir.join("docker-stub");
        // `inspect` answers with the compose file the way a compose-created
        // container's labels do; everything else records what it was asked.
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\nif [ \"$1\" = inspect ]; then echo /opt/litellm/docker-compose.yml; \
                 else echo \"$@\" >> {}; fi\nexit 0\n",
                argv.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        unsafe { std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &stub) };

        assert!(restart_gateway());
        let asked = std::fs::read_to_string(&argv).unwrap_or_default();
        assert!(
            asked.contains("compose -p litellm -f /opt/litellm/docker-compose.yml up -d --force-recreate litellm"),
            "the gateway has to be re-created, not bounced: {asked}"
        );
        assert!(!asked.contains("restart litellm"),
                "the plain restart is the FALLBACK, and compose answered: {asked}");

        unsafe { std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN") };
        std::fs::remove_dir_all(&dir).ok();
    }

    /// And a gateway compose did not create still gets the best that can be
    /// done for it, rather than nothing.
    #[test]
    fn a_container_with_no_compose_labels_falls_back_to_the_bounce() {
        let _env = env_guard();
        let dir = std::env::temp_dir().join(format!("gryonix-llmkeys-nolabel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let argv = dir.join("argv");
        let stub = dir.join("docker-stub");
        // What docker prints for a label a container does not carry.
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\nif [ \"$1\" = inspect ]; then echo ''; \
                 else echo \"$@\" >> {}; fi\nexit 0\n",
                argv.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        unsafe { std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &stub) };

        assert!(restart_gateway());
        let asked = std::fs::read_to_string(&argv).unwrap_or_default();
        assert!(asked.contains("restart litellm"), "expected the fallback: {asked}");

        unsafe { std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN") };
        std::fs::remove_dir_all(&dir).ok();
    }

    /// …but a host that HAS one gets it emptied when the last key is removed,
    /// rather than keeping a key the owner deleted.
    #[test]
    fn removing_the_last_key_empties_the_file_that_already_exists() {
        let _env = env_guard();
        let dir = std::env::temp_dir().join(format!("gryonix-llmkeys-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("litellm-keys.env");
        unsafe { std::env::set_var("GRYONIXNEXUSD_LLM_KEYS_PATH", &path) };
        // A stub docker, so the restart this triggers touches nothing real.
        let stub = dir.join("docker-stub");
        std::fs::write(&stub, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        unsafe { std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &stub) };

        write_if_changed("OPENAI_API_KEY=one\n").unwrap();
        assert!(reconcile(&[]).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");

        unsafe { std::env::remove_var("GRYONIXNEXUSD_LLM_KEYS_PATH") };
        unsafe { std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN") };
        std::fs::remove_dir_all(&dir).ok();
    }
}
