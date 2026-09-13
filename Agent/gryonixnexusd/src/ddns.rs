//! Dynamic DNS, as the app turns it on and reads it back.
//!
//! The updater itself is a root-owned wrapper and a timer
//! (`install::host::ddns`); this file writes them, arms the timer and reports
//! what the last run did. The agent owns the CONTRACT, not a second copy of
//! the engine — the same division every other wrapper-backed verb here follows.
//!
//! **The token is written and never read back.** `GetDynamicDNS` answers
//! whether the host holds one, not what it is: a management call that could
//! hand a credential back to whoever asked would make every device that can
//! reach the socket a way to exfiltrate it.

use std::path::Path;

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::install::host::ddns;
use crate::pb;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    BadRequest(String),
    Host(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::BadRequest(detail) => write!(f, "{detail}"),
            Refusal::Host(detail) => write!(f, "the host could not be configured: {detail}"),
        }
    }
}

impl Refusal {
    fn response(&self) -> Resp {
        let (status, code) = match self {
            Refusal::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_argument"),
            Refusal::Host(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        connect_error(status, code, &self.to_string())
    }
}

/// A name fit to keep pointing at this host.
///
/// Not an injection gate — the value is written into a config file, not a
/// command line — but a correctness one: the file is SOURCED by the updater,
/// and a name with a space in it would silently become two names.
fn checked_name(raw: &str) -> Result<String, Refusal> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(Refusal::BadRequest("a hostname needs 1 to 253 characters".to_string()));
    }
    if trimmed.starts_with('-')
        || trimmed.starts_with('.')
        || trimmed.ends_with('.')
        || !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(Refusal::BadRequest(format!("{trimmed} is not a hostname")));
    }
    Ok(trimmed.to_ascii_lowercase())
}

pub async fn set(codec: Codec, req: pb::SetDynamicDnsRequest) -> Resp {
    let mut names = Vec::new();
    for raw in &req.names {
        match checked_name(raw) {
            Ok(name) => names.push(name),
            Err(refusal) => return refusal.response(),
        }
    }

    // No names means OFF. Stated as its own path rather than as an empty
    // configuration: a timer left armed with nothing to update is a promise
    // the host keeps making to an API for no reason.
    if names.is_empty() {
        if let Err(why) = disable().await {
            return Refusal::Host(why).response();
        }
        return encode(codec, read_state());
    }

    let zone = match checked_name(&req.zone) {
        Ok(zone) => zone,
        Err(_) => return Refusal::BadRequest(format!("{} is not a zone name", req.zone)).response(),
    };
    // An empty token keeps the one the host already holds, so turning a name on
    // and off does not mean handing the credential over again.
    let token = match req.token.trim() {
        "" => match existing_token() {
            Some(token) => token,
            None => {
                return Refusal::BadRequest(
                    "this host holds no Cloudflare token yet, so one has to be sent with the first call"
                        .to_string(),
                )
                .response()
            }
        },
        supplied => supplied.to_string(),
    };

    if let Err(why) = enable(&token, &zone, &names).await {
        return Refusal::Host(why).response();
    }
    encode(codec, read_state())
}

pub async fn get(codec: Codec, _req: pb::GetDynamicDnsRequest) -> Resp {
    encode(codec, read_state())
}

fn encode(codec: Codec, state: pb::DynamicDnsState) -> Resp {
    codec
        .encode(&state)
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

/// Write the wrapper, its units and the configuration, then arm the timer.
async fn enable(token: &str, zone: &str, names: &[String]) -> Result<(), String> {
    let conf = ddns::conf(token, zone, names)?;

    write_root_only(Path::new(ddns::CONF_PATH), &conf, 0o600)?;
    write_root_only(Path::new(ddns::SCRIPT_PATH), &ddns::script(), 0o700)?;
    write_root_only(Path::new(ddns::SERVICE_UNIT_PATH), &ddns::service_unit(), 0o644)?;
    write_root_only(Path::new(ddns::TIMER_UNIT_PATH), &ddns::timer_unit(), 0o644)?;

    run_systemctl(&["daemon-reload"]).await?;
    run_systemctl(&["enable", "--now", ddns::TIMER_UNIT]).await?;
    // One run now rather than waiting out the first interval: the owner has
    // just asked for this, and an address that is already wrong stays wrong
    // for five minutes otherwise.
    let _ = run_systemctl(&["start", "gryonixnexus-ddns.service"]).await;
    Ok(())
}

async fn disable() -> Result<(), String> {
    let _ = run_systemctl(&["disable", "--now", ddns::TIMER_UNIT]).await;
    // The configuration goes with it — it holds a credential, and a token left
    // behind by a feature nobody is using is the kind of thing that is only
    // ever found by someone else.
    let _ = std::fs::remove_file(ddns::CONF_PATH);
    Ok(())
}

fn write_root_only(path: &Path, contents: &str, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    std::fs::write(path, contents).map_err(|err| format!("{}: {err}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|err| format!("{}: {err}", path.display()))
}

async fn run_systemctl(args: &[&str]) -> Result<(), String> {
    let output = tokio::process::Command::new("systemctl")
        .args(args)
        .output()
        .await
        .map_err(|err| format!("could not run systemctl ({err})"))?;
    if output.status.success() {
        return Ok(());
    }
    let why = String::from_utf8_lossy(&output.stderr).trim().chars().take(200).collect::<String>();
    Err(format!("systemctl {}: {why}", args.join(" ")))
}

fn existing_token() -> Option<String> {
    read_conf_value("DDNS_TOKEN").filter(|token| !token.is_empty())
}

fn read_conf_value(key: &str) -> Option<String> {
    let text = std::fs::read_to_string(ddns::CONF_PATH).ok()?;
    text.lines()
        .find_map(|line| line.trim().strip_prefix(&format!("{key}=")))
        .map(|value| value.trim().trim_matches('\'').to_string())
}

/// What the host currently does — read from the host, never remembered.
fn read_state() -> pb::DynamicDnsState {
    let zone = read_conf_value("DDNS_ZONE").unwrap_or_default();
    let names: Vec<String> = read_conf_value("DDNS_NAMES")
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let recent: Vec<String> = std::fs::read_to_string(ddns::STATUS_PATH)
        .unwrap_or_default()
        .lines()
        .rev()
        .take(10)
        .map(str::to_string)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    pb::DynamicDnsState {
        enabled: !names.is_empty() && Path::new(ddns::CONF_PATH).exists(),
        zone,
        names,
        has_token: existing_token().is_some(),
        recent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The file is sourced by a shell, so a name with a space would quietly
    /// become two names — and one of them would be nonsense.
    #[test]
    fn a_name_that_is_not_a_hostname_is_refused() {
        assert!(checked_name("home.example.com").is_ok());
        assert!(checked_name("").is_err());
        assert!(checked_name("two names").is_err());
        assert!(checked_name("-leading.example.com").is_err());
        assert!(checked_name("https://home.example.com").is_err());
    }

    /// Names are lower-cased because DNS is case-insensitive and the updater
    /// compares them as strings against what the API returns.
    #[test]
    fn a_name_is_normalised_the_way_the_api_returns_it() {
        assert_eq!(checked_name("Home.Example.COM").unwrap(), "home.example.com");
    }
}
