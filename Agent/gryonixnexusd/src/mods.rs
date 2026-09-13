//! Mods for the Minecraft servers: the Modrinth catalogue, searched FROM THE
//! HOST, and the jars an owner sends up by hand.
//!
//! **Why the search is here and not in the app** (owner, 2026-09-08: "давай
//! вариант б"). The app's whole network posture is one sentence — it talks to
//! the machines it owns over SSH and to nothing else — and a phone querying
//! api.modrinth.com would end that quietly, in a way nobody would notice until
//! somebody read the app's traffic. The server is already the side that
//! downloads the mods, so moving the QUESTION to the same place the answer is
//! acted on costs one RPC and keeps the sentence true.
//!
//! **`curl`, not an HTTP client crate.** This binary is a static musl build
//! with no TLS stack in it, and adding one — plus a certificate store to keep
//! current — to ask a search engine a question would be the largest dependency
//! in the agent by far. The host already has curl and a CA bundle; the dynamic
//! DNS updater this project writes uses exactly the same tool for exactly the
//! same reason. `-f` is banned here as everywhere else in this repository: it
//! throws away the body, and the body is where the explanation is.
//!
//! **Nothing takes a path from the caller.** The directories are derived from
//! the compose project's own `ConfigFiles` (`discover::directory_of_service`),
//! and a file name that is not a plain `*.jar` is REFUSED rather than
//! sanitised: a name quietly rewritten is a file its owner cannot find again,
//! and a `../` quietly accepted turns an upload verb into a write-anywhere
//! verb.

use std::path::{Path, PathBuf};

use hyper::StatusCode;
use tokio::process::Command;

use crate::api::{connect_error, Codec, Resp};
use crate::discover;
use crate::pb;

/// The only service this verb answers for today. Named rather than assumed so
/// that a second engine (Bedrock takes no mods; a future Java-like one might)
/// is a table entry instead of a new RPC.
const MINECRAFT_JAVA: &str = "minecraft-java";

/// Modrinth's rate limit is 300 requests a minute per address and their API
/// terms ask for a user agent that identifies the caller. A generic one is
/// what they say they block.
const USER_AGENT: &str = concat!("gryonixNexus/", env!("CARGO_PKG_VERSION"), " (+https://gryonix.com)");

const API: &str = "https://api.modrinth.com/v2";
const DEFAULT_LIMIT: u32 = 10;
const MAX_LIMIT: u32 = 50;
/// A mod jar is single-digit megabytes; the largest packs are tens. The cap is
/// here so that a mistake — a video, a disk image, the wrong file entirely —
/// is refused before it is written rather than after the disk is full.
const MAX_UPLOAD_BYTES: usize = 256 * 1024 * 1024;
/// What the host keeps for itself. An upload that would leave less than this
/// is refused: a Minecraft world grows while nobody is watching, and a full
/// disk stops the server rather than the upload.
const DISK_HEADROOM_BYTES: u64 = 512 * 1024 * 1024;

/// Loaders this verb will put into a query. An allow-list rather than an
/// escape: these strings land in a URL, and the set of things Modrinth calls a
/// loader is small, known and slow to change.
const LOADERS: &[&str] =
    &["fabric", "forge", "neoforge", "quilt", "paper", "purpur", "spigot", "bukkit", "datapack"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    BadRequest(String),
    NotInstalled(String),
    Upstream(String),
    Host(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::BadRequest(detail) => write!(f, "{detail}"),
            Refusal::NotInstalled(detail) => write!(f, "{detail}"),
            Refusal::Upstream(detail) => write!(f, "the mod catalogue could not be reached: {detail}"),
            Refusal::Host(detail) => write!(f, "the host could not do that: {detail}"),
        }
    }
}

impl Refusal {
    fn response(&self) -> Resp {
        let (status, code) = match self {
            Refusal::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_argument"),
            Refusal::NotInstalled(_) => (StatusCode::NOT_FOUND, "not_found"),
            // 502 rather than 500: the failure is somebody else's server, and
            // a client that retries against this host will keep getting it.
            Refusal::Upstream(_) => (StatusCode::BAD_GATEWAY, "unavailable"),
            Refusal::Host(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        connect_error(status, code, &self.to_string())
    }
}

// ─────────────────────────────── the verbs ───────────────────────────────

pub async fn search(codec: Codec, req: pb::SearchModsRequest) -> Resp {
    match search_now(&req).await {
        Ok(result) => encode(codec, &result),
        Err(refusal) => refusal.response(),
    }
}

pub async fn versions(codec: Codec, req: pb::ModVersionsRequest) -> Resp {
    match versions_now(&req).await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

pub async fn list_files(codec: Codec, req: pb::ListModFilesRequest) -> Resp {
    match list_now(&req.service_id).await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

pub async fn upload(codec: Codec, req: pb::UploadModFileRequest) -> Resp {
    match upload_now(&req).await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

pub async fn delete(codec: Codec, req: pb::DeleteModFileRequest) -> Resp {
    match delete_now(&req).await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

fn encode<M: prost::Message + serde::Serialize>(codec: Codec, message: &M) -> Resp {
    codec.encode(message).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

// ─────────────────────────────── catalogue ───────────────────────────────

async fn search_now(req: &pb::SearchModsRequest) -> Result<pb::ModSearchResult, Refusal> {
    checked_service(&req.service_id)?;
    let loader = checked_loader(&req.loader)?;
    let version = checked_game_version(&req.game_version)?;
    let limit = match req.limit {
        0 => DEFAULT_LIMIT,
        n => n.min(MAX_LIMIT),
    };

    let mut facets = vec![format!("[\"categories:{loader}\"]")];
    if !version.is_empty() {
        facets.push(format!("[\"versions:{version}\"]"));
    }
    // Modpacks are excluded at the source rather than filtered on screen: this
    // path installs single projects into a running server, and a pack is a
    // whole server layout — accepting one would produce a list whose rows
    // cannot all be added.
    facets.push("[\"project_type:mod\",\"project_type:plugin\"]".to_string());
    let facets = format!("[{}]", facets.join(","));

    let url = format!(
        "{API}/search?query={}&facets={}&limit={limit}&offset={}&index=relevance",
        encode_component(&req.query),
        encode_component(&facets),
        req.offset
    );
    let body = get(&url).await?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|err| Refusal::Upstream(format!("unreadable answer: {err}")))?;
    let hits = json.get("hits").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    Ok(pb::ModSearchResult {
        projects: hits.iter().map(project_from).collect(),
        total: json.get("total_hits").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        filtered_by_version: !version.is_empty(),
    })
}

fn project_from(hit: &serde_json::Value) -> pb::ModProject {
    let text = |key: &str| hit.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string();
    pb::ModProject {
        slug: text("slug"),
        project_id: text("project_id"),
        title: text("title"),
        description: text("description"),
        downloads: hit.get("downloads").and_then(|v| v.as_u64()).unwrap_or(0),
        project_type: text("project_type"),
        license: text("license"),
        author: text("author"),
    }
}

async fn versions_now(req: &pb::ModVersionsRequest) -> Result<pb::ModVersionList, Refusal> {
    checked_service(&req.service_id)?;
    let loader = checked_loader(&req.loader)?;
    let version = checked_game_version(&req.game_version)?;
    let project = checked_project(&req.project)?;

    let mut url = format!("{API}/project/{project}/version?loaders={}", encode_component(&format!("[\"{loader}\"]")));
    if !version.is_empty() {
        url.push_str(&format!("&game_versions={}", encode_component(&format!("[\"{version}\"]"))));
    }
    let body = get(&url).await?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|err| Refusal::Upstream(format!("unreadable answer: {err}")))?;
    let rows = json.as_array().cloned().unwrap_or_default();
    Ok(pb::ModVersionList { versions: rows.iter().map(version_from).collect() })
}

fn version_from(row: &serde_json::Value) -> pb::ModVersion {
    let text = |key: &str| row.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let list = |key: &str| {
        row.get(key)
            .and_then(|v| v.as_array())
            .map(|items| items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    pb::ModVersion {
        version_id: text("id"),
        version_number: text("version_number"),
        name: text("name"),
        version_type: text("version_type"),
        published_at: text("date_published"),
        game_versions: list("game_versions"),
        loaders: list("loaders"),
    }
}

/// One GET, with the status kept. `-f` would turn a 400 with an explanation
/// into an exit code with none, which is the mistake this project has paid for
/// twice elsewhere.
async fn get(url: &str) -> Result<String, Refusal> {
    let output = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "20",
            "-H",
            &format!("User-Agent: {USER_AGENT}"),
            "-H",
            "Accept: application/json",
            "-w",
            "\n%{http_code}",
            "--url",
            url,
        ])
        .output()
        .await
        .map_err(|err| Refusal::Host(format!("curl could not be run: {err}")))?;
    if !output.status.success() {
        return Err(Refusal::Upstream(String::from_utf8_lossy(&output.stderr).trim().to_string()));
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let (body, status) = text
        .rsplit_once('\n')
        .ok_or_else(|| Refusal::Upstream("no answer".to_string()))?;
    match status.trim() {
        "200" => Ok(body.to_string()),
        // The body is carried into the refusal on purpose: Modrinth says why,
        // and "429" alone would read as this host being broken.
        other => Err(Refusal::Upstream(format!("HTTP {other}: {}", body.trim()))),
    }
}

// ───────────────────────────── uploaded files ─────────────────────────────

async fn list_now(service_id: &str) -> Result<pb::ModFileList, Refusal> {
    let dir = service_directory(service_id).await?;
    let mut files = Vec::new();
    for slot in [pb::ModSlot::Mods, pb::ModSlot::Plugins] {
        let path = dir.join(slot_directory(slot));
        let mut entries = match tokio::fs::read_dir(&path).await {
            Ok(entries) => entries,
            // A directory that is not there yet is an empty one: the install
            // creates both, and an older install predates them.
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.to_ascii_lowercase().ends_with(".jar") {
                continue;
            }
            let meta = match entry.metadata().await {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            files.push(pb::ModFile {
                name,
                slot: slot as i32,
                size_bytes: meta.len(),
                modified_unix: modified_unix(&meta),
            });
        }
    }
    files.sort_by(|a, b| (a.slot, a.name.to_ascii_lowercase()).cmp(&(b.slot, b.name.to_ascii_lowercase())));
    Ok(pb::ModFileList { files, disk_free_bytes: free_bytes(&dir) })
}

async fn upload_now(req: &pb::UploadModFileRequest) -> Result<pb::ModFileList, Refusal> {
    let dir = service_directory(&req.service_id).await?;
    let slot = checked_slot(req.slot)?;
    let name = checked_name(&req.name)?;
    if req.content.is_empty() {
        return Err(Refusal::BadRequest("that file is empty".to_string()));
    }
    if req.content.len() > MAX_UPLOAD_BYTES {
        return Err(Refusal::BadRequest(format!(
            "that file is {} MB, and the limit is {} MB",
            req.content.len() / 1024 / 1024,
            MAX_UPLOAD_BYTES / 1024 / 1024
        )));
    }
    // The jar's own magic, which is a zip's. Checked because the extension is
    // the caller's claim and this file is handed to a server that will try to
    // load it: a text file renamed to .jar takes the whole server down at the
    // next start, and it is far cheaper to say no here.
    if !req.content.starts_with(b"PK\x03\x04") && !req.content.starts_with(b"PK\x05\x06") {
        return Err(Refusal::BadRequest("that file is not a jar".to_string()));
    }
    let free = free_bytes(&dir);
    if free != 0 && (req.content.len() as u64 + DISK_HEADROOM_BYTES) > free {
        return Err(Refusal::Host(format!("only {} MB free on that disk", free / 1024 / 1024)));
    }

    let target_dir = dir.join(slot_directory(slot));
    tokio::fs::create_dir_all(&target_dir)
        .await
        .map_err(|err| Refusal::Host(format!("could not create {}: {err}", target_dir.display())))?;
    // Written beside the target and renamed: a half-written jar in the
    // directory is one the image would synchronise into the server at the next
    // restart, and a rename within one filesystem is the only atomic move
    // there is.
    let staging = target_dir.join(format!(".{name}.part"));
    tokio::fs::write(&staging, &req.content)
        .await
        .map_err(|err| Refusal::Host(format!("could not write {}: {err}", staging.display())))?;
    let target = target_dir.join(&name);
    if let Err(err) = tokio::fs::rename(&staging, &target).await {
        let _ = tokio::fs::remove_file(&staging).await;
        return Err(Refusal::Host(format!("could not put {} in place: {err}", target.display())));
    }
    set_mode_0644(&target);
    list_now(&req.service_id).await
}

async fn delete_now(req: &pb::DeleteModFileRequest) -> Result<pb::ModFileList, Refusal> {
    let dir = service_directory(&req.service_id).await?;
    let slot = checked_slot(req.slot)?;
    let name = checked_name(&req.name)?;
    let target = dir.join(slot_directory(slot)).join(&name);
    match tokio::fs::remove_file(&target).await {
        Ok(()) => list_now(&req.service_id).await,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Gone is the state the caller asked for. A refusal here would
            // make a second tap on a slow screen look like a failure.
            list_now(&req.service_id).await
        }
        Err(err) => Err(Refusal::Host(format!("could not remove {}: {err}", target.display()))),
    }
}

// ─────────────────────────────── checking ───────────────────────────────

fn checked_service(service_id: &str) -> Result<&'static str, Refusal> {
    match service_id.trim() {
        MINECRAFT_JAVA => Ok(MINECRAFT_JAVA),
        "" => Err(Refusal::BadRequest("no service was named".to_string())),
        other => Err(Refusal::BadRequest(format!("{other} does not take mods"))),
    }
}

async fn service_directory(service_id: &str) -> Result<PathBuf, Refusal> {
    let id = checked_service(service_id)?;
    match discover::directory_of_service(id).await {
        Ok(Some(dir)) => Ok(dir),
        Ok(None) => Err(Refusal::NotInstalled(format!("{id} is not installed on this server"))),
        Err(err) => Err(Refusal::Host(err.to_string())),
    }
}

fn checked_loader(loader: &str) -> Result<&'static str, Refusal> {
    let wanted = loader.trim().to_ascii_lowercase();
    if wanted.is_empty() {
        return Err(Refusal::BadRequest(
            "no loader was named, and a list not filtered by one is a list of things this server cannot load"
                .to_string(),
        ));
    }
    LOADERS
        .iter()
        .find(|known| **known == wanted)
        .copied()
        .ok_or_else(|| Refusal::BadRequest(format!("{wanted} is not a loader this server knows")))
}

/// Versions are `1.21.4`, `1.21`, `24w03a`, `1.20.1-rc1`. Checked by CHARSET
/// rather than by pattern: the game's own version strings have never held to
/// one shape, and this only has to be safe to put in a URL.
fn checked_game_version(version: &str) -> Result<String, Refusal> {
    let version = version.trim();
    if version.is_empty() {
        return Ok(String::new());
    }
    if version.len() > 32
        || !version.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
    {
        return Err(Refusal::BadRequest(format!("{version} is not a game version")));
    }
    Ok(version.to_string())
}

fn checked_project(project: &str) -> Result<String, Refusal> {
    let project = project.trim();
    if project.is_empty() || project.len() > 64 {
        return Err(Refusal::BadRequest("that is not a project".to_string()));
    }
    if !project.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '!')) {
        return Err(Refusal::BadRequest(format!("{project} is not a project")));
    }
    Ok(project.to_string())
}

fn checked_slot(slot: i32) -> Result<pb::ModSlot, Refusal> {
    match pb::ModSlot::try_from(slot) {
        Ok(pb::ModSlot::Mods) => Ok(pb::ModSlot::Mods),
        Ok(pb::ModSlot::Plugins) => Ok(pb::ModSlot::Plugins),
        _ => Err(Refusal::BadRequest("no directory was named".to_string())),
    }
}

fn slot_directory(slot: pb::ModSlot) -> &'static str {
    match slot {
        pb::ModSlot::Plugins => "plugins",
        _ => "mods",
    }
}

/// A base name, ending in `.jar`, out of a deliberately small alphabet.
///
/// **Refused, not sanitised.** Mod files are named by their authors and people
/// recognise them by those names; a file quietly renamed on the way up is one
/// its owner cannot match against what they downloaded. And the one thing this
/// check exists to stop — a separator — is exactly what a sanitiser would
/// silently swallow.
fn checked_name(name: &str) -> Result<String, Refusal> {
    let name = name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(Refusal::BadRequest("that file has no usable name".to_string()));
    }
    if !name.to_ascii_lowercase().ends_with(".jar") {
        return Err(Refusal::BadRequest("only .jar files go in there".to_string()));
    }
    if name.starts_with('.') {
        return Err(Refusal::BadRequest("a file name cannot start with a dot".to_string()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+' | '(' | ')' | ' '))
    {
        return Err(Refusal::BadRequest(format!("{name} has characters a file name cannot have")));
    }
    Ok(name.to_string())
}

/// Percent-encoding for one query component. Written here rather than pulled
/// in: the alphabet is fixed by RFC 3986 and this is the whole of it.
fn encode_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn modified_unix(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn free_bytes(dir: &Path) -> u64 {
    match crate::metrics::statvfs_usage(&dir.to_string_lossy()) {
        Some((size, used)) => (size - used).max(0) as u64,
        None => 0,
    }
}

/// World-readable, because the container reads this directory as whatever user
/// the image runs as. Never executable: nothing here is run by the host.
fn set_mode_0644(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole reason a name is checked rather than cleaned: every one of
    /// these is a write outside the directory the caller was given.
    #[test]
    fn a_name_that_could_leave_the_directory_is_refused() {
        for bad in [
            "../../etc/cron.d/evil.jar",
            // Absolute, and deliberately NOT under /etc: the sandbox test
            // scans this crate for /etc paths and would read a refusal
            // fixture as a place the daemon writes.
            "/srv/anywhere/else.jar",
            "mods/../../x.jar",
            "a\0b.jar",
            ".hidden.jar",
        ] {
            assert!(checked_name(bad).is_err(), "{bad} should be refused");
        }
        assert_eq!(checked_name(" sodium-fabric-0.6.0.jar ").unwrap(), "sodium-fabric-0.6.0.jar");
        assert_eq!(checked_name("Fabric API (1.21.4).jar").unwrap(), "Fabric API (1.21.4).jar");
    }

    /// Anything that is not a jar is refused BEFORE it is written: the file is
    /// handed to a server that tries to load it at the next start.
    #[test]
    fn only_jars_are_accepted_by_name() {
        assert!(checked_name("mod.zip").is_err());
        assert!(checked_name("mod.jar.sh").is_err());
        assert!(checked_name("mod.JAR").is_ok());
    }

    /// A loader is an allow-list because it lands in a URL, and an unfiltered
    /// search is a list of things this server cannot load.
    #[test]
    fn only_known_loaders_reach_the_query() {
        assert_eq!(checked_loader("Fabric").unwrap(), "fabric");
        assert!(checked_loader("").is_err());
        assert!(checked_loader("fabric\"]],[[\"x").is_err());
        assert!(checked_loader("../../").is_err());
    }

    #[test]
    fn a_game_version_is_checked_by_charset() {
        assert_eq!(checked_game_version(" 1.21.4 ").unwrap(), "1.21.4");
        assert_eq!(checked_game_version("24w03a").unwrap(), "24w03a");
        assert_eq!(checked_game_version("").unwrap(), "");
        assert!(checked_game_version("1.21.4\"]").is_err());
        assert!(checked_game_version("../etc").is_err());
    }

    /// The facet string is JSON inside a URL, and every character that would
    /// end the parameter has to leave as an escape.
    #[test]
    fn a_query_component_is_percent_encoded() {
        assert_eq!(encode_component("[[\"categories:fabric\"]]"), "%5B%5B%22categories%3Afabric%22%5D%5D");
        assert_eq!(encode_component("just enough items"), "just%20enough%20items");
        assert_eq!(encode_component("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn a_project_id_is_checked_before_it_lands_in_a_path() {
        assert_eq!(checked_project("fabric-api").unwrap(), "fabric-api");
        assert!(checked_project("../../v2/user").is_err());
        assert!(checked_project("").is_err());
    }

    #[test]
    fn only_the_java_server_takes_mods() {
        assert!(checked_service("minecraft-java").is_ok());
        assert!(checked_service("minecraft-bedrock").is_err());
        assert!(checked_service("").is_err());
    }

    #[test]
    fn a_slot_decides_the_directory_and_an_unset_one_is_refused() {
        assert_eq!(slot_directory(pb::ModSlot::Mods), "mods");
        assert_eq!(slot_directory(pb::ModSlot::Plugins), "plugins");
        assert!(checked_slot(pb::ModSlot::Unspecified as i32).is_err());
        assert!(checked_slot(99).is_err());
    }
}
