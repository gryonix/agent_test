//! Headscale's control plane, driven through the `headscale` CLI inside its
//! own container.
//!
//! **Why the CLI and not an API.** Headscale's gRPC API needs an API key
//! minted by that same CLI and a second socket to reach it; the CLI is already
//! there, already authenticated by being inside the container, and speaks JSON
//! with `-o json`. The same reasoning the mailbox verbs use for
//! docker-mailserver: the engine has a management entry point, so this file
//! carries the CONTRACT, not a second implementation of it.
//!
//! **Nothing here echoes the engine's raw JSON, and that is a security
//! decision rather than tidiness.** A node's record embeds the pre-auth key it
//! joined with, secret and all — read off a live server while building this —
//! so every parser below names the fields it takes. Handing the engine's
//! output straight through would have published every device's join key to
//! anything that listed nodes.
//!
//! **An empty listing arrives as `null`, not `[]`** (measured on a fresh
//! server: `headscale nodes list -o json` prints exactly `null`). A parser
//! that only accepted an array would report a working, empty mesh as a broken
//! engine.

use std::process::Stdio;
use std::time::Duration;

use hyper::StatusCode;
use serde_json::Value;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

/// The container the CLI lives in — the name `install::headscale` gives it.
const CONTAINER: &str = "headscale";
/// Long enough for a cold container, short enough that a hung engine is not
/// mistaken for a slow one. Every call here is a local command.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Why a call could not be answered. The split matters to the caller: a host
/// without the service is a precondition the app can explain, an engine that
/// answered badly is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No Headscale on this host.
    NotInstalled,
    /// The request named something the engine rejects.
    BadRequest(String),
    /// The engine ran and said something unusable.
    Engine(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NotInstalled => write!(
                f,
                "this server does not run Headscale, so it has no mesh to manage — \
                 install it first"
            ),
            Refusal::BadRequest(detail) => write!(f, "{detail}"),
            Refusal::Engine(detail) => write!(f, "the mesh control server could not do that: {detail}"),
        }
    }
}

impl Refusal {
    fn response(&self) -> Resp {
        let (status, code) = match self {
            Refusal::NotInstalled => (StatusCode::UNPROCESSABLE_ENTITY, "failed_precondition"),
            Refusal::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_argument"),
            Refusal::Engine(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        connect_error(status, code, &self.to_string())
    }
}

/// Run one `headscale` subcommand and hand back its stdout.
///
/// A missing container is told apart from a failing command on purpose: the
/// first is "this host has no mesh", which the app can act on, and the second
/// is an engine error worth showing verbatim.
async fn headscale(args: &[&str]) -> Result<String, Refusal> {
    let mut command = tokio::process::Command::new("docker");
    command.arg("exec").arg(CONTAINER).arg("headscale").args(args);
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| Refusal::Engine(format!("could not run docker ({err})")))?;
    let output = tokio::time::timeout(TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| Refusal::Engine(format!("the mesh control server did not answer within {}s", TIMEOUT.as_secs())))?
        .map_err(|err| Refusal::Engine(format!("could not run docker ({err})")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if output.status.success() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let lowered = stderr.to_lowercase();
    // A host without the service is a PRECONDITION the app can explain; an
    // engine that ran and complained is an error worth showing verbatim.
    if lowered.contains("no such container") || lowered.contains("is not running") {
        return Err(Refusal::NotInstalled);
    }
    Err(Refusal::Engine(truncate(if stderr.trim().is_empty() { &stdout } else { &stderr })))
}

fn truncate(text: &str) -> String {
    let one_line: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    one_line.chars().take(300).collect()
}

/// `null` is an EMPTY listing, not a failure — see this module's doc.
fn array_or_empty(text: &str) -> Result<Vec<Value>, Refusal> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }
    let value: Value = serde_json::from_str(trimmed)
        .map_err(|err| Refusal::Engine(format!("unreadable answer ({err})")))?;
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => Ok(items),
        other => Err(Refusal::Engine(format!("expected a list, got {other}"))),
    }
}

pub fn parse_users(text: &str) -> Result<Vec<pb::MeshUser>, Refusal> {
    Ok(array_or_empty(text)?
        .into_iter()
        .filter_map(|item| {
            let id = item.get("id")?;
            let name = item.get("name")?.as_str()?.to_string();
            Some(pb::MeshUser { id: id.to_string().trim_matches('"').to_string(), name })
        })
        .collect())
}

/// Only the fields the app shows. The engine's record also carries the node's
/// keys AND the pre-auth key it joined with — see this module's doc.
pub fn parse_nodes(text: &str) -> Result<Vec<pb::MeshNode>, Refusal> {
    Ok(array_or_empty(text)?
        .into_iter()
        .filter_map(|item| {
            let id = item.get("id")?.to_string().trim_matches('"').to_string();
            let name = item
                .get("given_name")
                .and_then(Value::as_str)
                .or_else(|| item.get("name").and_then(Value::as_str))
                .unwrap_or_default()
                .to_string();
            let addresses = item
                .get("ip_addresses")
                .and_then(Value::as_array)
                .map(|list| list.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default();
            let user = item
                .get("user")
                .and_then(|u| u.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let online = item.get("online").and_then(Value::as_bool).unwrap_or(false);
            let last_seen = item
                .get("last_seen")
                .and_then(|t| t.get("seconds"))
                .and_then(Value::as_i64)
                .unwrap_or(0);
            Some(pb::MeshNode { id, name, addresses, user, online, last_seen })
        })
        .collect())
}

pub fn parse_auth_key(text: &str) -> Result<pb::MeshAuthKey, Refusal> {
    let value: Value = serde_json::from_str(text.trim())
        .map_err(|err| Refusal::Engine(format!("unreadable answer ({err})")))?;
    let key = value
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::Engine("the engine returned no key".to_string()))?
        .to_string();
    Ok(pb::MeshAuthKey {
        key,
        reusable: value.get("reusable").and_then(Value::as_bool).unwrap_or(false),
        expires_at: value
            .get("expiration")
            .and_then(|t| t.get("seconds"))
            .and_then(Value::as_i64)
            .unwrap_or(0),
    })
}

/// The engine takes these straight into argv, so anything that is not a plain
/// identifier is refused HERE rather than quoted and hoped for.
fn checked_id(raw: &str, what: &str) -> Result<String, Refusal> {
    let trimmed = raw.trim();
    // A LEADING DASH is the case worth spelling out: `--force` is made of
    // characters this filter otherwise allows, and the CLI would read it as a
    // FLAG rather than as the value it stands in for. Caught by this file's
    // own test, which is why the check is here and not left to the shell
    // (there is no shell — these go straight into argv).
    if trimmed.is_empty()
        || trimmed.starts_with('-')
        || !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(Refusal::BadRequest(format!("'{}' is not a {what}", truncate(raw))));
    }
    Ok(trimmed.to_string())
}

fn checked_name(raw: &str) -> Result<String, Refusal> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(Refusal::BadRequest("a mesh user needs a name of 1 to 64 characters".to_string()));
    }
    // Same leading-dash rule as ids, for the same reason.
    if trimmed.starts_with('-')
        || !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(Refusal::BadRequest(
            "a mesh user's name may contain letters, digits, dot, dash and underscore".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

async fn users() -> Result<pb::MeshUserList, Refusal> {
    let out = headscale(&["users", "list", "-o", "json"]).await?;
    Ok(pb::MeshUserList { users: parse_users(&out)? })
}

async fn nodes() -> Result<pb::MeshNodeList, Refusal> {
    let out = headscale(&["nodes", "list", "-o", "json"]).await?;
    Ok(pb::MeshNodeList { nodes: parse_nodes(&out)? })
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec
        .encode(message)
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

pub async fn list_users(codec: Codec, _req: pb::ListMeshUsersRequest) -> Resp {
    match users().await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

pub async fn create_user(codec: Codec, req: pb::CreateMeshUserRequest) -> Resp {
    let name = match checked_name(&req.name) {
        Ok(name) => name,
        Err(refusal) => return refusal.response(),
    };
    if let Err(refusal) = headscale(&["users", "create", &name]).await {
        return refusal.response();
    }
    match users().await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

pub async fn create_auth_key(codec: Codec, req: pb::CreateMeshAuthKeyRequest) -> Resp {
    let user = match checked_id(&req.user_id, "mesh user id") {
        Ok(id) => id,
        Err(refusal) => return refusal.response(),
    };
    // The engine spells this as a duration; a plain hour count is what the app
    // can offer without teaching anyone the engine's grammar.
    let hours = if req.expiration_hours == 0 { 24 } else { req.expiration_hours.min(24 * 365) };
    let expiration = format!("{hours}h");
    let mut args: Vec<&str> = vec!["preauthkeys", "create", "--user", &user, "--expiration", &expiration];
    if req.reusable {
        args.push("--reusable");
    }
    args.extend(["-o", "json"]);
    match headscale(&args).await {
        Ok(out) => match parse_auth_key(&out) {
            Ok(key) => encode(codec, &key),
            Err(refusal) => refusal.response(),
        },
        Err(refusal) => refusal.response(),
    }
}

pub async fn list_nodes(codec: Codec, _req: pb::ListMeshNodesRequest) -> Resp {
    match nodes().await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

pub async fn delete_node(codec: Codec, req: pb::DeleteMeshNodeRequest) -> Resp {
    let id = match checked_id(&req.node_id, "node id") {
        Ok(id) => id,
        Err(refusal) => return refusal.response(),
    };
    // `--force` because there is no one to answer the confirmation prompt: an
    // unanswered prompt is a call that hangs until the deadline and reads as a
    // broken engine.
    if let Err(refusal) = headscale(&["nodes", "delete", "--identifier", &id, "--force"]).await {
        return refusal.response();
    }
    match nodes().await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

/// A name fit to publish.
///
/// It does not reach a command line — it goes into a JSON file — so this is
/// not an injection gate but a correctness one: a name with a space or a
/// scheme in it is a record that never resolves, and finding that out means
/// debugging DNS rather than reading an error.
fn checked_hostname(raw: &str) -> Result<String, Refusal> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(Refusal::BadRequest("a hostname needs 1 to 253 characters".to_string()));
    }
    if trimmed.starts_with('-')
        || trimmed.starts_with('.')
        || trimmed.ends_with('.')
        || !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(Refusal::BadRequest(format!(
            "{trimmed} is not a hostname — publish the name a service is served under, \
             with no scheme and no path"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Publish this deployment's service names inside the mesh.
///
/// **Why this is a file and not a CLI call.** Headscale has no verb for extra
/// records: they are a configuration FILE it watches. Measured on v0.29.3, and
/// both halves of the behaviour matter — a change to the file reaches the
/// clients within seconds with no restart, and a MISSING file makes the server
/// refuse to start at all, which is why the install writes an empty one before
/// the first `up` rather than leaving it to this call.
///
/// The address comes from the node LISTING rather than from the caller: it is
/// assigned when the node joins, and a caller that guessed it would publish a
/// name pointing at nothing.
pub async fn publish_names(codec: Codec, req: pb::PublishMeshNamesRequest) -> Resp {
    let mut names = Vec::new();
    for raw in &req.names {
        match checked_hostname(raw) {
            Ok(name) => names.push(name),
            Err(refusal) => return refusal.response(),
        }
    }

    let all = match nodes().await {
        Ok(list) => list.nodes,
        Err(refusal) => return refusal.response(),
    };
    let wanted = match req.node_name.trim() {
        "" => own_node_name().await.unwrap_or_default(),
        named => named.to_string(),
    };
    let node = if wanted.is_empty() {
        // No container to ask and no name given. Fall back to the one node
        // under the install's own mesh user — right on a deployment where the
        // owner keeps their laptops under a user of their own, which is what
        // the install report tells them to do.
        //
        // **Not the primary rule, and the live run is why.** Keying on the
        // user alone breaks the moment a second device joins under the SAME
        // user (a probe node did exactly that, and publishing then refused
        // with "more than one server node" on a perfectly healthy mesh). The
        // server's own node is identified by NAME, and the name is a fact the
        // node container carries.
        let mut own = all.iter().filter(|node| node.user == super::install::tailscale::MESH_USER);
        match (own.next(), own.next()) {
            (Some(only), None) => only.clone(),
            (Some(_), Some(_)) => {
                return Refusal::BadRequest(
                    "this mesh has more than one node under the server's own user, and the node \
                     container is not running to say which one is this server — name it"
                        .to_string(),
                )
                .response()
            }
            _ => {
                return Refusal::BadRequest(
                    "this server has not joined its own mesh yet, so it has no address to publish"
                        .to_string(),
                )
                .response()
            }
        }
    } else {
        match all.iter().find(|node| node.name == wanted) {
            Some(node) => node.clone(),
            None => return Refusal::BadRequest(format!("no node named {wanted} in this mesh")).response(),
        }
    };

    // IPv4 only: the records are what a browser and a mail client resolve, and
    // every deployment address in this project is v4. The listing carries both.
    let address = match node.addresses.iter().find(|address| address.contains('.')) {
        Some(address) => address.clone(),
        None => {
            return Refusal::Engine(format!("node {} has no IPv4 mesh address", node.name)).response()
        }
    };

    let records: Vec<pb::MeshName> =
        names.into_iter().map(|name| pb::MeshName { name, address: address.clone() }).collect();
    if let Err(refusal) = write_extra_records(&records).await {
        return refusal.response();
    }
    encode(codec, &pb::MeshNameList { records })
}

/// The file's shape, as the ENGINE spells it: Go's `tailcfg.DNSRecord` carries
/// no json tags, so the keys are capitalised.
fn extra_records_json(records: &[pb::MeshName]) -> String {
    let items: Vec<Value> = records
        .iter()
        .map(|record| {
            serde_json::json!({ "Name": record.name, "Type": "A", "Value": record.address })
        })
        .collect();
    format!("{}\n", serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".to_string()))
}

/// Write it beside the server's own config, found through the container's bind
/// mount — the agent has no `ServiceContext`, exactly as the mailbox verbs
/// have none when they look for docker-mailserver's account file.
async fn write_extra_records(records: &[pb::MeshName]) -> Result<(), Refusal> {
    let dir = host_config_dir().await.ok_or_else(|| {
        Refusal::Engine(
            "the control server's configuration is not on a bind mount, so its records file \
             cannot be reached from here"
                .to_string(),
        )
    })?;
    let path = std::path::Path::new(&dir).join(crate::install::headscale::EXTRA_RECORDS_FILE);
    // Written through a temporary file and renamed: the server WATCHES this
    // path, so a partial write is a moment in which it reads half a file.
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, extra_records_json(records))
        .map_err(|err| Refusal::Engine(format!("could not write {}: {err}", temp.display())))?;
    std::fs::rename(&temp, &path)
        .map_err(|err| Refusal::Engine(format!("could not replace {}: {err}", path.display())))?;
    Ok(())
}

/// The name this server answers to inside the mesh, asked of the node
/// container itself.
///
/// The install puts it in `TS_HOSTNAME`, so the running container is the one
/// place that cannot disagree with what actually joined — better than
/// re-deriving it from a domain this RPC does not receive, and better than
/// inferring it from the user (see the caller).
async fn own_node_name() -> Option<String> {
    let output = tokio::process::Command::new("docker")
        .args(["inspect", "--format", "{{json .Config.Env}}", crate::install::tailscale::CONTAINER])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let env: Vec<String> = serde_json::from_slice(&output.stdout).ok()?;
    env.iter()
        .find_map(|entry| entry.strip_prefix("TS_HOSTNAME="))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

#[derive(Debug, serde::Deserialize)]
struct Mount {
    #[serde(rename = "Source", default)]
    source: String,
    #[serde(rename = "Destination", default)]
    destination: String,
}

async fn host_config_dir() -> Option<String> {
    let output = tokio::process::Command::new("docker")
        .args(["inspect", "--format", "{{json .Mounts}}", CONTAINER])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mounts: Vec<Mount> = serde_json::from_slice(&output.stdout).ok()?;
    mounts
        .into_iter()
        .find(|mount| mount.destination == "/etc/headscale" && !mount.source.is_empty())
        .map(|mount| mount.source)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keys are the ENGINE's, and they are capitalised because Go's
    /// `tailcfg.DNSRecord` declares no json tags. A lower-cased file would be
    /// accepted by Go's case-insensitive decoder today and is still not what
    /// the engine writes — this pins what was read out of the binary.
    #[test]
    fn the_records_file_uses_the_engines_own_key_names() {
        let json = extra_records_json(&[pb::MeshName {
            name: "vault.example.com".to_string(),
            address: "100.64.0.1".to_string(),
        }]);
        assert!(json.contains("\"Name\": \"vault.example.com\""), "{json}");
        assert!(json.contains("\"Type\": \"A\""), "{json}");
        assert!(json.contains("\"Value\": \"100.64.0.1\""), "{json}");
    }

    /// Clearing is a real operation, not an error: it is how a deployment
    /// stops publishing. The file must stay valid JSON.
    #[test]
    fn publishing_nothing_writes_an_empty_array() {
        assert_eq!(extra_records_json(&[]).trim(), "[]");
    }

    /// The shape a FRESH server answers with. Measured, not imagined: an empty
    /// mesh prints the four letters `null`, and a parser that only took arrays
    /// would call a working server broken.
    #[test]
    fn an_empty_listing_is_empty_rather_than_an_error() {
        assert_eq!(parse_nodes("null").unwrap(), Vec::new());
        assert_eq!(parse_nodes("").unwrap(), Vec::new());
        assert_eq!(parse_users("null").unwrap(), Vec::new());
        assert_eq!(parse_nodes("[]").unwrap(), Vec::new());
    }

    /// Real output, trimmed to the fields this file reads — including the
    /// embedded pre-auth key, which must NOT come out the other side.
    #[test]
    fn a_node_gives_up_only_the_fields_the_app_shows() {
        let json = r#"[{
            "id": 1,
            "machine_key": "mkey:9ec8",
            "node_key": "nodekey:d2d8",
            "ip_addresses": ["100.64.0.1", "fd7a:115c:a1e0::1"],
            "name": "shapenode",
            "given_name": "shapenode",
            "user": {"id": 1, "name": "meshops"},
            "last_seen": {"seconds": 1786724741},
            "online": true,
            "pre_auth_key": {"key": "hskey-auth-SECRET"}
        }]"#;
        let nodes = parse_nodes(json).unwrap();
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        assert_eq!(node.id, "1");
        assert_eq!(node.name, "shapenode");
        assert_eq!(node.addresses, vec!["100.64.0.1", "fd7a:115c:a1e0::1"]);
        assert_eq!(node.user, "meshops");
        assert!(node.online);
        assert_eq!(node.last_seen, 1_786_724_741);
        // The whole reason this parser names its fields.
        let rendered = format!("{node:?}");
        assert!(!rendered.contains("SECRET"), "a node's join key must not reach the client");
        assert!(!rendered.contains("mkey"), "a node's machine key is not the app's business");
    }

    #[test]
    fn a_minted_key_carries_its_secret_and_its_terms() {
        let json = r#"{"key": "hskey-auth-abc", "reusable": true, "expiration": {"seconds": 1786728304}}"#;
        let key = parse_auth_key(json).unwrap();
        assert_eq!(key.key, "hskey-auth-abc");
        assert!(key.reusable);
        assert_eq!(key.expires_at, 1_786_728_304);
        // An engine that answered without a key is an error, not an empty key
        // the operator would paste into a device and watch fail.
        assert!(parse_auth_key(r#"{"reusable": true}"#).is_err());
    }

    /// These values reach the engine's argv. Anything that is not a plain
    /// identifier is refused here rather than quoted and hoped for.
    #[test]
    fn ids_and_names_are_checked_before_they_reach_argv() {
        assert!(checked_id("12", "node id").is_ok());
        assert!(checked_id("a-b", "node id").is_ok());
        for bad in ["", " ", "1; rm -rf /", "--force", "1 2", "$(id)"] {
            assert!(checked_id(bad, "node id").is_err(), "{bad:?} must be refused");
        }
        assert!(checked_name("laptops").is_ok());
        assert!(checked_name("home_2.lab").is_ok());
        for bad in ["", "  ", "has space", "semi;colon", "--reusable", &"x".repeat(65)] {
            assert!(checked_name(bad).is_err(), "{bad:?} must be refused");
        }
    }

    /// A missing container is a precondition the app can explain; anything
    /// else the engine says is an internal error worth showing.
    #[test]
    fn the_two_failures_are_told_apart() {
        assert_eq!(
            Refusal::NotInstalled.to_string(),
            "this server does not run Headscale, so it has no mesh to manage — install it first"
        );
        assert!(Refusal::Engine("boom".into()).to_string().contains("boom"));
    }
}
