//! Adoption scan: inspect an already-configured host and report what is
//! installed, so a device with no prior state can take it over.
//!
//! The signal is `docker compose ls` — the running compose projects. Project
//! names map to catalog ids the way the current setup lays them down
//! (COMPOSE_PROJECT_NAME=mailcowdockerized, the vpn-panel stack, …). Anything
//! unrecognized is surfaced in `notes` rather than silently dropped. As the
//! Swift engine moves into the agent (Phase 4) this mapping draws from the
//! catalog directly instead of the literals here.

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::process::Command;

use crate::pb;

/// The running/known compose projects on the host (`docker compose ls`).
async fn compose_projects() -> Result<Vec<ComposeProject>> {
    let output = Command::new("docker")
        .args(["compose", "ls", "--all", "--format", "json"])
        .output()
        .await
        .context("run `docker compose ls`")?;
    if !output.status.success() {
        anyhow::bail!(
            "docker compose ls failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_compose_ls(&String::from_utf8_lossy(&output.stdout))
}

/// The container names of one service, across every compose project that maps
/// to it (a service like mailcow is one project; the mapping is the same one
/// Discover uses). Empty if nothing matches. Used by Logs to know which
/// containers to tail.
pub async fn containers_of_service(service_id: &str) -> Result<Vec<String>> {
    let projects = compose_projects().await?;
    let mut names = Vec::new();
    for project in members_of(&projects, service_id) {
        names.extend(containers_for(&project.name).await?.into_iter().map(|c| c.name));
    }
    Ok(names)
}

/// The compose projects one catalog service is made of, in the order the host
/// reports them. Empty when the service is not installed here.
///
/// This is what management resolves a client-supplied id to, and the reason a
/// client string never reaches a command line: the project NAMES come from the
/// host's own `docker compose ls`, and the id only selects among them.
pub async fn projects_of_service(service_id: &str) -> Result<Vec<String>> {
    let projects = compose_projects().await?;
    Ok(members_of(&projects, service_id)
        .into_iter()
        .map(|p| p.name.clone())
        .collect())
}

/// Where one service's compose file LIVES, from the host's own
/// `docker compose ls`. `None` when the service is not installed here, or
/// when the daemon reports a project with no config file at all.
///
/// **The only sanctioned answer to "which directory is this service's?"** A
/// verb that writes files there must not take a path from its caller, and must
/// not rebuild the default from settings either: the owner may have installed
/// it somewhere else entirely, and the compose file is the one place that
/// records where.
pub async fn directory_of_service(service_id: &str) -> Result<Option<std::path::PathBuf>> {
    let projects = compose_projects().await?;
    for project in members_of(&projects, service_id) {
        // Compose reports the files comma-separated when a project was
        // started with several; the first is the one this product writes.
        let first = project.config_files.split(',').next().unwrap_or("").trim();
        if first.is_empty() {
            continue;
        }
        if let Some(dir) = std::path::Path::new(first).parent() {
            return Ok(Some(dir.to_path_buf()));
        }
    }
    Ok(None)
}

/// One service as it is right now — the same shape Discover reports, for a
/// single id. `None` when the service is not installed on this host.
pub async fn service_snapshot(service_id: &str) -> Result<Option<pb::Service>> {
    let projects = compose_projects().await?;
    let members = members_of(&projects, service_id);
    if members.is_empty() {
        return Ok(None);
    }
    let display = catalog_id(members[0]).map(|(_, name)| name).unwrap_or(service_id);
    Ok(Some(build_service(service_id, display, &members).await))
}

/// Projects belonging to one catalog id, first-seen order preserved.
fn members_of<'a>(projects: &'a [ComposeProject], service_id: &str) -> Vec<&'a ComposeProject> {
    projects
        .iter()
        .filter(|p| catalog_id(p).map(|(id, _)| id) == Some(service_id))
        .collect()
}

/// Merge a group of compose projects into the one service they represent.
/// Shared by the full scan and the per-service status read so the two cannot
/// report the same host differently.
async fn build_service(id: &str, display: &str, members: &[&ComposeProject]) -> pb::Service {
    let mut containers = Vec::new();
    for project in members {
        if let Ok(mut found) = containers_for(&project.name).await {
            containers.append(&mut found);
        }
    }
    // Prefer status derived from the real containers; fall back to the
    // `docker compose ls` string only if the per-project query failed.
    let status = status_from_containers(&containers)
        .unwrap_or_else(|| status_of(&members[0].status));
    let version = version_of(id, &containers);
    pb::Service {
        id: id.to_string(),
        display_name: display.to_string(),
        status: status as i32,
        version,
        containers,
        // **A scan cannot answer this and must not pretend to.** Who installed
        // a service is the store's memory, not something readable off
        // `docker compose ls`; `Store::snapshot` fills it in from the column
        // `record_action` raises. False here means "no claim", not "ours".
        installed_outside: false,
    }
}

/// Scan the host and return the services found plus notes on anything
/// ambiguous. Read-only: never mutates the server.
pub async fn scan() -> Result<pb::DiscoverResult> {
    let projects = compose_projects().await?;
    let (groups, notes) = group_projects(&projects);

    let mut services = Vec::new();
    for (id, display, members) in &groups {
        // One catalog service can span several compose projects (VPN = the panel
        // plus each protocol engine); merge their containers into one service.
        services.push(build_service(id, display, members).await);
    }
    Ok(pb::DiscoverResult { services, notes })
}

/// Classify every compose project into its catalog id, GROUPING projects that
/// map to the same id (kept in first-seen order), and collecting notes for the
/// unrecognized. Grouping is what keeps VPN — panel + protocols, each its own
/// compose project — a single service instead of one duplicate per project.
fn group_projects<'a>(
    projects: &'a [ComposeProject],
) -> (Vec<(&'static str, &'static str, Vec<&'a ComposeProject>)>, Vec<String>) {
    let mut groups: Vec<(&'static str, &'static str, Vec<&'a ComposeProject>)> = Vec::new();
    let mut notes = Vec::new();
    for project in projects {
        match catalog_id(project) {
            Some((id, display)) => match groups.iter_mut().find(|g| g.0 == id) {
                Some(group) => group.2.push(project),
                None => groups.push((id, display, vec![project])),
            },
            None => notes.push(format!(
                "unrecognized compose project '{}' ({})",
                project.name, project.config_files
            )),
        }
    }
    (groups, notes)
}

/// The containers of one compose project, via its compose label. `docker ps`
/// emits NDJSON (one object per line), not a JSON array.
pub(crate) async fn containers_for(project: &str) -> Result<Vec<pb::Container>> {
    let output = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
            "--format",
            "json",
        ])
        .output()
        .await
        .context("run `docker ps`")?;
    if !output.status.success() {
        anyhow::bail!(
            "docker ps failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(parse_docker_ps(&String::from_utf8_lossy(&output.stdout)))
}

/// One row of `docker compose ls --format json`.
#[derive(Debug, Deserialize)]
struct ComposeProject {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "ConfigFiles", default)]
    config_files: String,
}

fn parse_compose_ls(stdout: &str) -> Result<Vec<ComposeProject>> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed).context("parse `docker compose ls` json")
}

/// compose project name → (catalog id, display name). ONE table, because it now
/// answers two questions that must never disagree: "what is this project?" (the
/// scan) and "is this client-supplied id a service I manage?" (every management
/// call). Two tables would drift, and the drift would show up as a management
/// call that resolves to nothing on a host where the scan sees the service.
///
/// Mail engines: three entries, at most one of them ever installed (they fight
/// over ports 25/143/993) — but an adopted host may carry any of the three.
const CATALOG: &[(&str, &str, &str)] = &[
    ("mailcowdockerized", "mailcow", "Mailcow"),
    ("mailu", "mailu", "Mailu"),
    ("dockermailserver", "docker-mailserver", "Docker Mailserver"),
    ("vaultwarden", "vaultwarden", "Vaultwarden"),
    ("nextcloud", "nextcloud", "Nextcloud"),
    ("immich", "immich", "Immich"),
    ("forgejo", "forgejo", "Forgejo"),
    ("gitlab", "gitlab", "GitLab"),
    // Added when the catalog grew a media category. A service the app can
    // install and the agent does not know is a service whose card silently
    // falls back to SSH for everything — and, since Phase 2, one that answers
    // "unknown service" to a management call the dashboard is already drawing
    // buttons for. Every new catalog service belongs here in the same round.
    ("jellyfin", "jellyfin", "Jellyfin"),
    ("photoprism", "photoprism", "PhotoPrism"),
    ("seafile", "seafile", "Seafile"),
    // Psono was missing from this table entirely until the install slice
    // reached it — the app can install it, so without this row the agent
    // answered "unknown service" to every management call for a service
    // whose card the dashboard was already drawing buttons for, and the
    // installer could not accept the id at all. Exactly the gap the comment
    // above warns about, and exactly how Seafile itself was found missing
    // (crate 0.0.10).
    ("psono", "psono", "Psono"),
    // Passbolt is the THIRD service found missing the same way (after Seafile
    // and Psono), and it was the one already sitting in `ServiceRegistry`
    // while both halves of this contract ignored it: an adopted host running
    // Passbolt reported it as an unrecognised project in `notes`, so `GetState`
    // listed no row and the app fell back to SSH for a service it installs
    // itself. Management deliberately did not wait for an install executor
    // here (exactly as it did not for Seafile); the executor arrived later,
    // and `install::IMPLEMENTED_SERVICE_IDS` now carries every id in this
    // table.
    ("passbolt", "passbolt", "Passbolt"),
    // The compose project and the catalog id differ here (`adguardhome` vs
    // `adguard-home`): the project name is what the host reports, the id is
    // what the app addresses it by, and this table is the only place the two
    // are allowed to be spelled differently.
    ("adguardhome", "adguard-home", "AdGuard Home"),
    // Second engine on the same shelf. Its compose project and its catalog id
    // agree, unlike AdGuard's above.
    ("pihole", "pihole", "Pi-hole"),
    // The start page. Last, like its shelf.
    ("homepage", "homepage", "Homepage"),
    // Single sign-on in front of the panels.
    ("authelia", "authelia", "Authelia"),
    // The mesh control server. Its own shelf in the app's catalog, not a
    // member of the DNS one: it binds nothing those fight over.
    ("headscale", "headscale", "Headscale"),
    // The mesh CLIENT, reporting as itself. It folded into the control server
    // while it could only ever arrive with one; now it is also the second
    // engine on the mesh shelf — a host can run it with no Headscale at all,
    // and reporting such a host as running Headscale would be a plain lie.
    ("tailscale", "tailscale-node", "Tailscale"),
    ("cloudflared", "cloudflared", "Cloudflare Tunnel"),
    // The game servers, and the panel that operates them. Compose project and
    // catalog id agree for all three.
    ("minecraft-java", "minecraft-java", "Minecraft (Java)"),
    ("minecraft-bedrock", "minecraft-bedrock", "Minecraft (Bedrock)"),
    ("crafty", "crafty-controller", "Crafty Controller"),
    // The AI shelf. Compose project and catalog id agree for all three, and
    // the engine is here despite publishing no site: `Discover` answers what
    // the host RUNS, and a service the app installed but the agent cannot see
    // is a card with no state on it.
    ("ollama", "ollama", "Ollama"),
    ("open-webui", "open-webui", "Open WebUI"),
    ("litellm", "litellm", "LiteLLM"),
    // The automation shelf. Compose project and catalog id agree, and its
    // Postgres is a service INSIDE this project rather than a project of its
    // own, so nothing else here needs to know about it.
    ("n8n", "n8n", "n8n"),
    // The retrieval pair. The store is here despite publishing no site, for
    // the reason the engine is: `Discover` answers what the host RUNS, and a
    // service the app installed but the agent cannot see is a card with no
    // state on it.
    ("anythingllm", "anythingllm", "AnythingLLM"),
    ("qdrant", "qdrant", "Qdrant"),
    ("searxng", "searxng", "SearXNG"),
    ("openclaw", "openclaw", "OpenClaw"),
];

/// Every VPN piece reports as this one aggregate service — see `is_vpn_project`.
const VPN_SERVICE: (&str, &str) = ("vpn", "VPN");

/// Map a compose project to a catalog id. Confident names match exactly; the
/// VPN pieces all collapse to one id (see `is_vpn_project`); everything else
/// falls through to `notes`.
fn catalog_id(project: &ComposeProject) -> Option<(&'static str, &'static str)> {
    if let Some(entry) = CATALOG.iter().find(|(name, _, _)| *name == project.name) {
        return Some((entry.1, entry.2));
    }
    if is_vpn_project(project) {
        return Some(VPN_SERVICE);
    }
    None
}

/// The catalog id of a compose project named by its NAME and config files,
/// for callers that hold those two strings rather than a `ComposeProject`.
///
/// It exists so the Containers section can mark a group as a service the
/// configurator installed WITHOUT keeping a second copy of this table. Two
/// tables would drift, and the drift would show up as a row the section calls a
/// stranger while the dashboard draws a service card for it — the same failure
/// the one-table note above is about.
pub(crate) fn catalog_id_of_project(
    name: &str,
    config_files: &str,
) -> Option<(&'static str, &'static str)> {
    catalog_id(&ComposeProject {
        name: name.to_string(),
        status: String::new(),
        config_files: config_files.to_string(),
    })
}

/// Is this a catalog id the agent manages, and what is it called? `None` for
/// anything else.
///
/// This is the ONLY gate between a client-supplied string and work on the host:
/// the agent is root and holds the docker socket, so an id that is not in the
/// catalog is refused here, before any resolution or execution happens. It
/// answers for services that are not installed too — "unknown id" and "not on
/// this host" are different failures and the caller says so differently.
pub fn known_service(service_id: &str) -> Option<&'static str> {
    if service_id == VPN_SERVICE.0 {
        return Some(VPN_SERVICE.1);
    }
    CATALOG
        .iter()
        .find(|(_, id, _)| *id == service_id)
        .map(|(_, _, display)| *display)
}

/// The catalog id itself, as the agent's OWN static string, for the callers that
/// have to build something out of it (the backup wrapper's service label).
///
/// Returning `&'static str` rather than echoing the caller's `&str` is the point:
/// what ends up in an argument vector is the table's constant, so a client can
/// only ever CHOOSE among the ids the agent knows — it cannot supply text that
/// travels any further than this lookup.
pub fn known_service_id(service_id: &str) -> Option<&'static str> {
    if service_id == VPN_SERVICE.0 {
        return Some(VPN_SERVICE.0);
    }
    CATALOG
        .iter()
        .find(|(_, id, _)| *id == service_id)
        .map(|(_, id, _)| *id)
}

/// Every id this catalog answers for, the aggregate VPN service included — for
/// the tests that have to cross-check the WHOLE table. A hand-copied list in a
/// test is the same drift hazard as a second table in the product: the one in
/// `uninstall` silently stopped covering Psono and Passbolt the day each was
/// added, and a test that skips an id proves nothing about it.
#[cfg(test)]
pub fn all_service_ids() -> Vec<&'static str> {
    CATALOG
        .iter()
        .map(|(_, id, _)| *id)
        .chain(std::iter::once(VPN_SERVICE.0))
        .collect()
}

/// Every VPN piece is ONE catalog service: the protocols share the panel and are
/// never managed individually (see the VPN-panel design). The panel and each
/// protocol are separate compose projects, so match them all — the panel, the
/// obvious *vpn*/*wireguard* names, and the protocol engines by name
/// (shadowsocks and xray don't say "vpn" anywhere, so they are listed).
fn is_vpn_project(project: &ComposeProject) -> bool {
    const VPN_PROJECTS: &[&str] = &[
        "vpnpanel",
        "vpn-panel",
        "gryonix-vpn-panel",
        "openvpn",
        "awgvpn",
        "amneziawg",
        "wireguard",
        "shadowsocks",
        "xray",
    ];
    let name = project.name.to_lowercase();
    VPN_PROJECTS.contains(&name.as_str())
        || name.contains("vpn")
        || name.contains("wireguard")
        || project.config_files.contains("vpn-panel")
}

/// `docker compose ls` reports e.g. "running(20)", "exited(3)", or a mix like
/// "running(18), exited(2)".
pub(crate) fn status_of(status: &str) -> pb::ServiceStatus {
    let running = status.contains("running");
    let stopped =
        status.contains("exited") || status.contains("created") || status.contains("dead");
    match (running, stopped) {
        (true, true) => pb::ServiceStatus::Partial,
        (true, false) => pb::ServiceStatus::Running,
        (false, true) => pb::ServiceStatus::Stopped,
        (false, false) => pb::ServiceStatus::Unspecified,
    }
}

/// One row of `docker ps --format json`. `State` is the machine word
/// ("running", "exited", …); `Status` is the human string that also carries the
/// health hint ("Up 3 minutes (healthy)").
#[derive(Debug, Deserialize)]
struct DockerPsRow {
    #[serde(rename = "Names", default)]
    names: String,
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "State", default)]
    state: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "Ports", default)]
    ports: String,
}

/// `docker ps --format json` is NDJSON — one object per line. A malformed line
/// is skipped rather than failing the whole scan.
pub(crate) fn parse_docker_ps(stdout: &str) -> Vec<pb::Container> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|line| serde_json::from_str::<DockerPsRow>(line).ok())
        .map(|row| pb::Container {
            name: row.names,
            image: row.image,
            health: health_from_status(&row.status),
            state: row.state,
            ports: row.ports,
        })
        .collect()
}

/// Pull the health word out of a `docker ps` Status string
/// ("Up 3 minutes (healthy)" → "healthy"); "" when the container has no
/// healthcheck or isn't up.
pub(crate) fn health_from_status(status: &str) -> String {
    for token in ["healthy", "unhealthy", "starting"] {
        if status.contains(token) {
            return token.to_string();
        }
    }
    String::new()
}

/// Derive service status from its real containers: all running → Running, none
/// running → Stopped, a mix → Partial. An unhealthy container downgrades an
/// otherwise-running stack to Error. `None` when there are no containers, so the
/// caller keeps the string-derived status.
pub(crate) fn status_from_containers(containers: &[pb::Container]) -> Option<pb::ServiceStatus> {
    if containers.is_empty() {
        return None;
    }
    let running = containers.iter().filter(|c| c.state == "running").count();
    let unhealthy = containers.iter().any(|c| c.health == "unhealthy");
    Some(if unhealthy {
        pb::ServiceStatus::Error
    } else if running == containers.len() {
        pb::ServiceStatus::Running
    } else if running == 0 {
        pb::ServiceStatus::Stopped
    } else {
        pb::ServiceStatus::Partial
    })
}

/// Best-effort version: the image tag of the container whose image name matches
/// the service id (e.g. vaultwarden/server:1.32.0 → "1.32.0"). "" when nothing
/// matches — the field is documented as optional.
fn version_of(id: &str, containers: &[pb::Container]) -> String {
    containers
        .iter()
        .find(|c| c.image.to_lowercase().contains(id))
        .and_then(|c| c.image.rsplit_once(':').map(|(_, tag)| tag.to_string()))
        .filter(|tag| !tag.contains('/')) // guard against a registry-port colon
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
        {"Name":"mailcowdockerized","Status":"running(20)","ConfigFiles":"/opt/mailcow-dockerized/docker-compose.yml"},
        {"Name":"vaultwarden","Status":"exited(1)","ConfigFiles":"/opt/vaultwarden/docker-compose.yml"},
        {"Name":"gryonix-vpn-panel","Status":"running(3), exited(1)","ConfigFiles":"/opt/vpn-panel/docker-compose.yml"},
        {"Name":"randomstack","Status":"running(2)","ConfigFiles":"/srv/random/compose.yml"}
    ]"#;

    #[test]
    fn groups_known_projects_and_notes_the_rest() {
        let projects = parse_compose_ls(SAMPLE).unwrap();
        let (groups, notes) = group_projects(&projects);

        let ids: Vec<_> = groups.iter().map(|g| g.0).collect();
        assert_eq!(ids, ["mailcow", "vaultwarden", "vpn"]);
        // Each group here has exactly one member project.
        assert!(groups.iter().all(|g| g.2.len() == 1));

        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("randomstack"));
    }

    #[test]
    fn forgejo_is_recognized_with_its_database() {
        // Forgejo ships as one compose project holding the server AND its
        // PostgreSQL, so the group is a single project with two containers —
        // it must not land in `notes` as an unknown stack.
        let sample = r#"[
            {"Name":"forgejo","Status":"running(2)","ConfigFiles":"/opt/forgejo/docker-compose.yml"}
        ]"#;
        let projects = parse_compose_ls(sample).unwrap();
        let (groups, notes) = group_projects(&projects);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "forgejo");
        assert!(notes.is_empty());
    }

    #[test]
    fn both_git_forges_are_recognized_side_by_side() {
        // The catalog lets Forgejo and GitLab be installed on one server, so
        // discovery has to return TWO services here — a table that knew only
        // one of them would report the other as an unknown stack in `notes`,
        // and its service card would lose the Logs button.
        let sample = r#"[
            {"Name":"forgejo","Status":"running(2)","ConfigFiles":"/opt/forgejo/docker-compose.yml"},
            {"Name":"gitlab","Status":"running(1)","ConfigFiles":"/opt/gitlab-ce/docker-compose.yml"}
        ]"#;
        let projects = parse_compose_ls(sample).unwrap();
        let (groups, notes) = group_projects(&projects);
        let ids: Vec<_> = groups.iter().map(|g| g.0).collect();
        assert_eq!(ids, ["forgejo", "gitlab"]);
        assert!(notes.is_empty());
    }

    #[test]
    fn every_vpn_project_collapses_into_one_service() {
        // The real deployment ships the panel plus five protocol engines as
        // separate compose projects; they must surface as a SINGLE vpn service.
        let sample = r#"[
            {"Name":"vpnpanel","Status":"running(1)","ConfigFiles":"/opt/gryonix-vpn-panel/docker-compose.yml"},
            {"Name":"openvpn","Status":"running(1)","ConfigFiles":"/opt/openvpn/docker-compose.yml"},
            {"Name":"awgvpn","Status":"running(1)","ConfigFiles":"/opt/awgvpn/docker-compose.yml"},
            {"Name":"shadowsocks","Status":"running(1)","ConfigFiles":"/opt/shadowsocks/docker-compose.yml"},
            {"Name":"xray","Status":"running(1)","ConfigFiles":"/opt/xray/docker-compose.yml"}
        ]"#;
        let projects = parse_compose_ls(sample).unwrap();
        let (groups, notes) = group_projects(&projects);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "vpn");
        assert_eq!(groups[0].2.len(), 5, "panel + 4 protocols in one group");
        assert!(notes.is_empty(), "shadowsocks and xray are recognized as VPN");
    }

    #[test]
    fn empty_output_is_no_services() {
        assert!(parse_compose_ls("").unwrap().is_empty());
        assert!(parse_compose_ls("   \n").unwrap().is_empty());
    }

    const DOCKER_PS: &str = r#"{"Names":"vaultwarden","Image":"vaultwarden/server:1.32.0","State":"running","Status":"Up 3 minutes (healthy)"}
{"Names":"vaultwarden-backup","Image":"alpine:3.20","State":"exited","Status":"Exited (0) 2 minutes ago"}
"#;

    #[test]
    fn parses_docker_ps_ndjson_with_health() {
        let containers = parse_docker_ps(DOCKER_PS);
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0].name, "vaultwarden");
        assert_eq!(containers[0].image, "vaultwarden/server:1.32.0");
        assert_eq!(containers[0].state, "running");
        assert_eq!(containers[0].health, "healthy");
        assert_eq!(containers[1].state, "exited");
        assert_eq!(containers[1].health, "");
    }

    #[test]
    fn skips_malformed_docker_ps_lines() {
        let containers = parse_docker_ps("not json\n{\"Names\":\"ok\",\"State\":\"running\"}\n");
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].name, "ok");
    }

    #[test]
    fn status_from_containers_mix_is_partial() {
        let containers = parse_docker_ps(DOCKER_PS);
        assert_eq!(
            status_from_containers(&containers),
            Some(pb::ServiceStatus::Partial)
        );
    }

    #[test]
    fn status_from_containers_unhealthy_is_error() {
        let containers = vec![pb::Container {
            name: "x".into(),
            image: "img:1".into(),
            state: "running".into(),
            health: "unhealthy".into(),
            ports: String::new(),
        }];
        assert_eq!(
            status_from_containers(&containers),
            Some(pb::ServiceStatus::Error)
        );
    }

    #[test]
    fn status_from_containers_empty_defers_to_string() {
        assert_eq!(status_from_containers(&[]), None);
    }

    #[test]
    fn service_id_resolves_project_including_loose_vpn_match() {
        let projects = parse_compose_ls(SAMPLE).unwrap();
        let of = |sid: &str| -> Vec<&str> {
            projects
                .iter()
                .filter(|p| catalog_id(p).map(|(id, _)| id) == Some(sid))
                .map(|p| p.name.as_str())
                .collect()
        };
        assert_eq!(of("mailcow"), ["mailcowdockerized"]);
        assert_eq!(of("vpn"), ["gryonix-vpn-panel"]);
        assert!(of("nextcloud").is_empty());
    }

    #[test]
    fn the_catalog_answers_for_every_service_the_app_can_install() {
        // The OTHER direction of the same contract, and the only one the tests
        // above cannot make: every check here iterates `CATALOG` itself, so a
        // missing row is invisible to all of them — which is precisely how
        // Seafile, then Psono, then Passbolt each shipped as a service the app
        // installed and the agent called unknown.
        //
        // The list is deliberately a second copy of the Swift `ServiceRegistry`
        // (minus the VPN protocols, which collapse into the aggregate id). A
        // musl binary and a Swift package cannot share a source of truth in
        // either direction, so the duplication is pinned from both sides — the
        // same arrangement the `GRYONIXNEXUS_*` markers use.
        // `AgentServiceMappingTests` holds up the Swift end.
        for id in [
            "mailcow",
            "mailu",
            "docker-mailserver",
            "vaultwarden",
            "psono",
            "passbolt",
            "nextcloud",
            "seafile",
            "immich",
            "photoprism",
            "gitlab",
            "forgejo",
            "jellyfin",
            "adguard-home",
            "headscale",
            "cloudflared",
            "vpn",
        ] {
            assert!(
                known_service(id).is_some(),
                "{id} is in the app's catalog but not the agent's: the scan reports it as an \
                 unrecognised project and every management call for it is refused"
            );
        }
    }

    #[test]
    fn every_id_the_scan_can_report_is_a_known_service() {
        // Structural pin, not a list to keep in sync by hand: management
        // validates client input with `known_service`, so any id the scan can
        // produce MUST be accepted there. A service added to the scan alone
        // would be visible in the app and unmanageable, with nothing to say why.
        for (project, id, display) in CATALOG {
            assert_eq!(known_service(id), Some(*display), "catalog id {id} ({project})");
        }
        assert_eq!(known_service(VPN_SERVICE.0), Some(VPN_SERVICE.1));
        assert_eq!(known_service("no-such-service"), None);
        // The reverse direction: the aggregate id is not a compose project name.
        assert!(!CATALOG.iter().any(|(name, _, _)| *name == VPN_SERVICE.0));
        // Same rule, one layer further out: backups resolve every id to a
        // wrapper label, so an id the scan can report but backups cannot name is
        // a service whose backup screen answers "unknown service" while its card
        // is on the dashboard. Checked from the table rather than a second list,
        // so the next service added above joins the check by itself.
        for (project, id, _) in CATALOG {
            assert!(
                crate::backup::wrapper_target(id).is_some(),
                "catalog id {id} ({project}) has no backup wrapper label"
            );
        }
        assert!(crate::backup::wrapper_target(VPN_SERVICE.0).is_some());
    }

    #[test]
    fn all_three_mail_engines_are_recognized() {
        // Only one is ever installed at a time, but the agent adopts hosts it
        // did not set up — docker-mailserver was missing here while the app's
        // own mapping already knew it, so such a host reported its mail stack
        // as an unknown compose project.
        let sample = r#"[
            {"Name":"dockermailserver","Status":"running(2)","ConfigFiles":"/opt/dockermailserver/docker-compose.yml"}
        ]"#;
        let projects = parse_compose_ls(sample).unwrap();
        let (groups, notes) = group_projects(&projects);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "docker-mailserver");
        assert!(notes.is_empty());
    }

    #[test]
    fn members_of_groups_every_vpn_project_and_nothing_else() {
        let projects = parse_compose_ls(SAMPLE).unwrap();
        let names: Vec<&str> = members_of(&projects, "vpn").iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["gryonix-vpn-panel"]);
        assert!(members_of(&projects, "nextcloud").is_empty());
    }

    #[test]
    fn version_from_matching_image_tag() {
        let containers = parse_docker_ps(DOCKER_PS);
        assert_eq!(version_of("vaultwarden", &containers), "1.32.0");
    }
}
