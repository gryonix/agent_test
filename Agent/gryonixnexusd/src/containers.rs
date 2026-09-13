//! The Containers section: every container on this host, not only the ones the
//! configurator installed.
//!
//! `discover` answers a different question. It asks "which CATALOG services are
//! here", which is what adoption needs, and drops everything else into `notes`.
//! Those notes were the whole of what a user could learn about a stack the app
//! did not install — a line of text with no status and no buttons. This module
//! reads the same two commands and reports the host as it is.
//!
//! **The gate is unchanged in kind, and that is the point.** There is still no
//! generic exec: a request names a group by a KEY, the key is looked up in the
//! inventory the agent just read from the host, and what travels onward is the
//! string the HOST reported. Client text selects among what `docker compose ls`
//! and `docker ps` printed; it never becomes an argument. Same rule that keeps
//! `discover::known_service` between a catalog id and a command line.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use hyper::StatusCode;
use serde::Deserialize;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use tokio::process::Command;
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::pb;

/// A container's own name is not enough to address it, and the difference
/// matters for every verb that follows: a stack is what people start and stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    ComposeProject,
    Standalone,
}

impl GroupKind {
    fn as_pb(self) -> pb::ContainerGroupKind {
        match self {
            GroupKind::ComposeProject => pb::ContainerGroupKind::ComposeProject,
            GroupKind::Standalone => pb::ContainerGroupKind::Standalone,
        }
    }
}

/// Read the whole host: every compose project with its containers, plus every
/// container running without a compose project of its own.
///
/// `names` is the owner's rename table (key → name), read from the agent's
/// state. It is applied here rather than by the caller so that the derived name
/// and the shown name can never be computed in two places.
pub async fn inventory(names: &[(String, String)]) -> Result<pb::ContainerInventory> {
    let projects = match compose_projects().await {
        Ok(projects) => projects,
        // No engine, or an engine that will not answer, is a STATE the user is
        // entitled to see, not an error that blanks the screen: an empty list
        // reads as "nothing runs on this machine", which is a different and
        // wrong answer.
        Err(err) => {
            return Ok(pb::ContainerInventory {
                groups: Vec::new(),
                unavailable_reason: err.to_string(),
            })
        }
    };

    let mut read = Vec::new();
    for project in &projects {
        let containers = crate::discover::containers_for(&project.name)
            .await
            .unwrap_or_default();
        read.push((project, containers));
    }
    // Everything `docker ps` knows, asked AFTER the projects rather than by
    // parsing compose labels out of `docker ps`: label values can contain the
    // same commas the label list is joined with, and a parser that splits on
    // them would drop a container on the day someone writes a comma into one.
    let loose = all_containers().await.unwrap_or_default();

    Ok(assemble(&read, &loose, names))
}

/// The whole shape of the section, with the host reads already done.
///
/// Split from `inventory` so the grouping can be asked a question without a
/// container engine on the machine running the test. Building the list is where
/// the decisions are — what counts as standalone, which group is a catalog
/// service, whose name wins — and a rule that can only be exercised against a
/// live docker is a rule that gets exercised on the owner's server.
fn assemble(
    projects: &[(&ComposeProject, Vec<pb::Container>)],
    all: &[pb::Container],
    names: &[(String, String)],
) -> pb::ContainerInventory {
    let mut groups = Vec::new();
    let mut claimed: Vec<&str> = Vec::new();

    for (project, containers) in projects {
        claimed.extend(containers.iter().map(|c| c.name.as_str()));
        let status = crate::discover::status_from_containers(containers)
            .unwrap_or_else(|| crate::discover::status_of(&project.status));
        groups.push(group(
            &project.name,
            GroupKind::ComposeProject,
            status,
            containers.clone(),
            split_config_files(&project.config_files),
            crate::discover::catalog_id_of_project(&project.name, &project.config_files),
            names,
        ));
    }

    for container in all {
        if claimed.contains(&container.name.as_str()) {
            continue;
        }
        let status = crate::discover::status_from_containers(std::slice::from_ref(container))
            .unwrap_or(pb::ServiceStatus::Unspecified);
        groups.push(group(
            &container.name,
            GroupKind::Standalone,
            status,
            vec![container.clone()],
            Vec::new(),
            None,
            names,
        ));
    }

    disambiguate(&mut groups);
    groups.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
    pb::ContainerInventory {
        groups,
        unavailable_reason: String::new(),
    }
}

/// **No two rows may show the same name, and that is settled for the WHOLE
/// inventory rather than patched per service.**
///
/// The naming rule used to answer one group at a time, so it could not see a
/// collision even in principle: every VPN piece is one catalog service, the
/// catalog calls that service "VPN", and a host running the panel beside four
/// protocols therefore drew five identical rows with different buttons behind
/// them. Deriving a name is a question about one group; whether that name
/// IDENTIFIES the group is a question about all of them, and it has to be asked
/// where all of them are.
///
/// It runs on the DERIVED name, never on the owner's. Two consequences, both
/// wanted: renaming one group cannot change what another group is called (the
/// answer is a function of the host, not of the owner's edits), and a group the
/// owner renamed still carries a unique automatic name underneath, so the way
/// back is not a way back into the ambiguity.
fn disambiguate(groups: &mut [pb::ContainerGroup]) {
    let mut classes: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    for (index, group) in groups.iter().enumerate() {
        classes
            .entry(group.derived_name.to_lowercase())
            .or_default()
            .push(index);
    }

    for members in classes.into_values() {
        if members.len() < 2 {
            continue;
        }
        // Escalate the whole class together, and stop at the first level that
        // separates it. Levels are ALTERNATIVES, not additions: a name carrying
        // every qualifier we could think of answers the question worse than the
        // one qualifier that happens to differ.
        for level in 1..=LAST_QUALIFIER_LEVEL {
            let named: Vec<String> = members
                .iter()
                .map(|&index| qualified(&groups[index], level))
                .collect();
            let distinct = {
                let mut seen: Vec<String> = named.iter().map(|n| n.to_lowercase()).collect();
                seen.sort();
                seen.dedup();
                seen.len() == named.len()
            };
            if !distinct && level < LAST_QUALIFIER_LEVEL {
                continue;
            }
            for (&index, name) in members.iter().zip(named.iter()) {
                let group = &mut groups[index];
                // The owner's own name is never appended to. They named it; a
                // suffix bolted onto their text is an edit of their decision.
                if !group.renamed {
                    group.display_name = name.clone();
                }
                group.derived_name = name.clone();
            }
            break;
        }
    }
}

/// The last level `qualified` answers for. The final level cannot collide by
/// construction — see its arm — so escalation always terminates.
const LAST_QUALIFIER_LEVEL: u8 = 3;

/// One group's name at a given level of insistence.
///
/// 1. what the group IS ("VPN \u{00b7} Shadowsocks") — the only level anyone wants
///    to read, and the reason the VPN table exists;
/// 2. the key the host itself printed, for a class the first level cannot part;
/// 3. what kind of thing it is. Two compose projects cannot share a name and
///    neither can two containers, so a class still tied at level 2 is exactly
///    one project and one container, and this parts it.
fn qualified(group: &pb::ContainerGroup, level: u8) -> String {
    let base = &group.derived_name;
    match level {
        1 => format!(
            "{base} \u{00b7} {}",
            qualifier(&group.key, &group.service_id, base)
        ),
        2 => format!("{base} \u{00b7} {}", group.key),
        _ => {
            let kind = if group.kind == pb::ContainerGroupKind::Standalone as i32 {
                "container"
            } else {
                "project"
            };
            format!("{base} ({kind})")
        }
    }
}

/// What tells two rows with the same base name apart.
///
/// The VPN table is not decoration. Every VPN piece is one catalog service, so
/// the base name is always "VPN" and the only useful thing left to say is WHICH
/// piece — and the generic rule cannot say it: `awgvpn` spells itself "Awgvpn"
/// and `vpnpanel` spells itself "Vpnpanel", which is a list of names the app
/// looks like it does not recognise. Everything else falls back to the derived
/// spelling of its own key, and to the key itself when even that repeats the
/// base (level 2 then has nothing new to add, and level 3 finishes the job).
fn qualifier(key: &str, service_id: &str, base: &str) -> String {
    if service_id == "vpn" {
        if let Some((_, piece)) = VPN_PIECES.iter().find(|(name, _)| *name == normalise(key)) {
            return (*piece).to_string();
        }
    }
    let derived = display_name_for(key);
    if !derived.is_empty() && !derived.eq_ignore_ascii_case(base) {
        return derived;
    }
    key.to_string()
}

/// Which piece of the VPN a compose project is. Keyed by `normalise`, so the
/// spellings the SSH path and the agent path each produce are one row.
const VPN_PIECES: &[(&str, &str)] = &[
    ("vpnpanel", "panel"),
    ("gryonixvpnpanel", "panel"),
    ("awgvpn", "AmneziaWG"),
    ("amneziawg", "AmneziaWG"),
    ("wireguard", "WireGuard"),
    ("shadowsocks", "Shadowsocks"),
    ("xray", "XRay"),
    ("openvpn", "OpenVPN"),
];

/// Assemble one row. Split out so the compose and standalone paths cannot
/// disagree about what a group looks like.
fn group(
    key: &str,
    kind: GroupKind,
    status: pb::ServiceStatus,
    containers: Vec<pb::Container>,
    config_files: Vec<String>,
    service: Option<(&'static str, &'static str)>,
    names: &[(String, String)],
) -> pb::ContainerGroup {
    // A catalog service is named by the CATALOG, never by the rule: the app
    // already ships a name for it, and deriving a second one would put two
    // spellings of the same service on two screens.
    let derived = match service {
        Some((_, display)) => display.to_string(),
        None => display_name_for(key),
    };
    let chosen = names
        .iter()
        .find(|(stored, _)| stored == key)
        .map(|(_, name)| name.clone());
    pb::ContainerGroup {
        key: key.to_string(),
        kind: kind.as_pb() as i32,
        display_name: chosen.clone().unwrap_or_else(|| derived.clone()),
        derived_name: derived,
        renamed: chosen.is_some(),
        service_id: service.map(|(id, _)| id.to_string()).unwrap_or_default(),
        status: status as i32,
        containers,
        config_files,
    }
}

/// Is this a key the host currently reports? The gate for every verb that takes
/// one, and the reason it returns the INVENTORY'S string rather than a bool:
/// what travels onward is the host's own text, not the caller's.
pub fn resolve<'a>(inv: &'a pb::ContainerInventory, key: &str) -> Option<&'a pb::ContainerGroup> {
    inv.groups.iter().find(|g| g.key == key)
}

// ─────────────────────────────── docker reads ───────────────────────────────

#[derive(Debug, Deserialize)]
struct ComposeProject {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "ConfigFiles", default)]
    config_files: String,
}

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
    let trimmed = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&trimmed).context("parse `docker compose ls` json")
}

/// Every container `docker ps` knows, with no filter.
///
/// The PARSER is `discover`'s, not a second copy of it. A second reader of the
/// same NDJSON is how a fixed bug comes back: the fields, the skipped malformed
/// line and the health word all have to agree, and two copies agree only until
/// one of them is edited.
async fn all_containers() -> Result<Vec<pb::Container>> {
    let output = Command::new("docker")
        .args(["ps", "-a", "--format", "json"])
        .output()
        .await
        .context("run `docker ps`")?;
    if !output.status.success() {
        anyhow::bail!(
            "docker ps failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(crate::discover::parse_docker_ps(
        &String::from_utf8_lossy(&output.stdout),
    ))
}

/// `docker compose ls` joins several compose files with a comma.
fn split_config_files(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// How long an owner-supplied name may be. Bounded because the string is stored
/// on the server and rendered on every device that pairs with it: a paired
/// device must not be able to make either arbitrarily large. The limit is
/// generous — it is a guard, not a style rule.
const NAME_LIMIT: usize = 64;

/// Check an owner-supplied name before it is stored.
///
/// Control characters are refused rather than stripped. Stripping would store a
/// name that is not the one the person typed and then show it back to them as
/// if it were — the failure mode of every silent fixup. Empty stays legal: it
/// is how a rename is undone.
pub fn sanitise_name(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.chars().count() > NAME_LIMIT {
        return Err(format!("a name may be at most {NAME_LIMIT} characters"));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("a name may not contain control characters".to_string());
    }
    Ok(trimmed.to_string())
}

// ────────────────────────────── the naming rule ──────────────────────────────

/// Turn a compose project or container name into something a person reads:
/// `mailcow-dockerized-1` → "Mailcow Dockerized", `adguardhome` → "AdGuard
/// Home", `nextcloud_db_1` → "Nextcloud DB".
///
/// A dictionary rather than pure capitalisation, because the failure of pure
/// capitalisation is not ugliness but WRONGNESS: "Gitlab", "Postgresql" and
/// "Phpmyadmin" are misspellings of products, and a list of misspelled product
/// names reads as a list the app does not recognise.
pub fn display_name_for(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(full) = WHOLE_NAMES
        .iter()
        .find(|(key, _)| *key == normalise(trimmed))
    {
        return full.1.to_string();
    }
    let tokens: Vec<String> = split_tokens(trimmed);
    if tokens.is_empty() {
        return trimmed.to_string();
    }
    tokens
        .iter()
        .map(|token| spell(token))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Lowercase alphanumerics only — so `adguard-home`, `adguard_home` and
/// `adguardhome` are one key in the dictionary rather than three rows that can
/// fall out of step.
fn normalise(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Split on the separators compose uses, dropping the replica index docker
/// appends (`-1`, `_1`). The index is dropped only when it is the LAST token:
/// `s3-1-backup` keeps its middle, and a stack genuinely called `web2` keeps
/// its name because the digit is not its own token.
fn split_tokens(raw: &str) -> Vec<String> {
    let mut tokens: Vec<String> = raw
        .split(|c: char| c == '-' || c == '_' || c == '.' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect();
    if tokens.len() > 1 {
        if let Some(last) = tokens.last() {
            if last.chars().all(|c| c.is_ascii_digit()) {
                tokens.pop();
            }
        }
    }
    tokens
}

/// One token, spelled the way its product spells itself. Unknown tokens get
/// Title Case — the honest default, and the reason the dictionary can stay a
/// list rather than an obligation.
fn spell(token: &str) -> String {
    let key = normalise(token);
    if let Some((_, spelled)) = TOKENS.iter().find(|(k, _)| *k == key) {
        return spelled.to_string();
    }
    let mut chars = token.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Names that only make sense whole: the pieces are not words, or the product
/// puts a space where the project name has none.
const WHOLE_NAMES: &[(&str, &str)] = &[
    ("adguardhome", "AdGuard Home"),
    ("audiobookshelf", "Audiobookshelf"),
    ("dockermailserver", "Docker Mailserver"),
    ("homeassistant", "Home Assistant"),
    ("mailcowdockerized", "Mailcow"),
    ("nginxproxymanager", "Nginx Proxy Manager"),
    ("nodered", "Node-RED"),
    ("paperlessngx", "Paperless-ngx"),
    ("uptimekuma", "Uptime Kuma"),
    ("zigbee2mqtt", "Zigbee2MQTT"),
];

/// Per-token spellings. Products first, then the infrastructure words that show
/// up as compose service names (`db`, `api`, `redis`) — those are most of what
/// a container inside a stack is called.
const TOKENS: &[(&str, &str)] = &[
    ("adguard", "AdGuard"),
    ("adminer", "Adminer"),
    ("amneziawg", "AmneziaWG"),
    ("api", "API"),
    ("authelia", "Authelia"),
    ("bookstack", "BookStack"),
    ("caddy", "Caddy"),
    ("calibre", "Calibre"),
    ("clamav", "ClamAV"),
    ("cloudflared", "Cloudflared"),
    ("db", "DB"),
    ("dns", "DNS"),
    ("dovecot", "Dovecot"),
    ("forgejo", "Forgejo"),
    ("fpm", "FPM"),
    ("freshrss", "FreshRSS"),
    ("frigate", "Frigate"),
    ("gitea", "Gitea"),
    ("github", "GitHub"),
    ("gitlab", "GitLab"),
    ("grafana", "Grafana"),
    ("headscale", "Headscale"),
    ("imap", "IMAP"),
    ("immich", "Immich"),
    ("influxdb", "InfluxDB"),
    ("ipv6", "IPv6"),
    ("jellyfin", "Jellyfin"),
    ("jellyseerr", "Jellyseerr"),
    ("jenkins", "Jenkins"),
    ("keycloak", "Keycloak"),
    ("komga", "Komga"),
    ("loki", "Loki"),
    ("mailcow", "Mailcow"),
    ("mailu", "Mailu"),
    ("mariadb", "MariaDB"),
    ("meilisearch", "Meilisearch"),
    ("memcached", "Memcached"),
    ("minio", "MinIO"),
    ("mongo", "MongoDB"),
    ("mongodb", "MongoDB"),
    ("mosquitto", "Mosquitto"),
    ("mysql", "MySQL"),
    ("navidrome", "Navidrome"),
    ("nextcloud", "Nextcloud"),
    ("nginx", "Nginx"),
    ("openvpn", "OpenVPN"),
    ("outline", "Outline"),
    ("owncloud", "ownCloud"),
    ("passbolt", "Passbolt"),
    ("pgadmin", "pgAdmin"),
    ("php", "PHP"),
    ("phpmyadmin", "phpMyAdmin"),
    ("photoprism", "PhotoPrism"),
    ("pihole", "Pi-hole"),
    ("plex", "Plex"),
    ("postfix", "Postfix"),
    ("postgres", "Postgres"),
    ("postgresql", "PostgreSQL"),
    ("prometheus", "Prometheus"),
    ("psono", "Psono"),
    ("qbittorrent", "qBittorrent"),
    ("rabbitmq", "RabbitMQ"),
    ("redis", "Redis"),
    ("rspamd", "Rspamd"),
    ("sabnzbd", "SABnzbd"),
    ("seafile", "Seafile"),
    ("shadowsocks", "Shadowsocks"),
    ("smtp", "SMTP"),
    ("solr", "Solr"),
    ("sql", "SQL"),
    ("ssl", "SSL"),
    ("syncthing", "Syncthing"),
    ("tailscale", "Tailscale"),
    ("telegraf", "Telegraf"),
    ("traefik", "Traefik"),
    ("transmission", "Transmission"),
    ("ui", "UI"),
    ("unifi", "UniFi"),
    ("valkey", "Valkey"),
    ("vaultwarden", "Vaultwarden"),
    ("vpn", "VPN"),
    ("watchtower", "Watchtower"),
    ("wireguard", "WireGuard"),
    ("wordpress", "WordPress"),
    ("xray", "XRay"),
];

// ───────────────────────────── control by key ───────────────────────────────

/// Deadline for ONE group, same ten minutes `control.rs` gives one compose
/// project: a stack the app did not install can be as slow as one it did.
const GROUP_TIMEOUT_SECS: u64 = 600;

/// Why a request naming a group was refused BEFORE the host was touched.
pub enum Refusal {
    /// Not a key this host reports. The gate.
    UnknownKey,
    /// The action field was left at its zero value. Refused rather than
    /// defaulted: a client that forgot to set it must not act on a live stack
    /// by accident. Same rule as `control::Rejection::UnspecifiedAction`.
    UnspecifiedAction,
    /// The container engine itself would not answer.
    EngineUnavailable(String),
}

impl Refusal {
    /// The same refusal as plain text, for the callers that have no stream to
    /// put it on — the scheduler runs with nobody listening and still has to
    /// record WHY a run did not happen.
    pub fn reason(&self) -> String {
        match self {
            Refusal::UnknownKey => "this host reports no container group with that key".to_string(),
            Refusal::UnspecifiedAction => "action is required (start, stop or restart)".to_string(),
            Refusal::EngineUnavailable(detail) => format!("container engine unavailable: {detail}"),
        }
    }

    pub fn response(&self) -> Resp {
        match self {
            Refusal::UnknownKey => connect_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "this host reports no container group with that key",
            ),
            Refusal::UnspecifiedAction => connect_error(
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "action is required (start, stop or restart)",
            ),
            // The engine's own words travel: "docker: command not found" and
            // "permission denied on the socket" need opposite fixes, and hiding
            // the difference is what made the SSH path's silent failures cost
            // so much.
            Refusal::EngineUnavailable(detail) => connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                &format!("container engine unavailable: {detail}"),
            ),
        }
    }
}

/// The argv for one group's action. No shell anywhere on this path.
///
/// A compose project and a lone container take DIFFERENT commands, and the
/// difference is not cosmetic: `docker compose -p X stop` finds a project's
/// containers by label, while a container started with `docker run` carries no
/// project label at all and would match nothing.
///
/// `stop` is `stop` and NEVER `down` — down REMOVES containers, so `start`
/// could not bring the same ones back. That is uninstall, and it has its own
/// verb and its own confirmation. The same rule `control.rs` states, restated
/// here because this path is the one where the stack is a stranger's.
pub fn docker_args(key: &str, kind: GroupKind, action: pb::ServiceAction) -> Vec<String> {
    let verb = match action {
        pb::ServiceAction::Start => "start",
        pb::ServiceAction::Stop => "stop",
        // Unreachable: the action is validated before this is called. Restart
        // is the least destructive of the three if a future caller skips it.
        pb::ServiceAction::Restart | pb::ServiceAction::Unspecified => "restart",
    };
    match kind {
        GroupKind::ComposeProject => vec![
            "compose".to_string(),
            "-p".to_string(),
            key.to_string(),
            verb.to_string(),
        ],
        GroupKind::Standalone => vec![verb.to_string(), key.to_string()],
    }
}

/// The same question from outside the module: a stack and a lone container
/// take different argv, and every verb that acts on a group needs to know
/// which it has.
pub fn kind_of_group(group: &pb::ContainerGroup) -> GroupKind {
    kind_of(group)
}

fn kind_of(group: &pb::ContainerGroup) -> GroupKind {
    if group.kind == pb::ContainerGroupKind::Standalone as i32 {
        GroupKind::Standalone
    } else {
        GroupKind::ComposeProject
    }
}

/// Start / stop / restart one group, streaming progress.
///
/// Two error channels, exactly as `ControlService` has: a refusal before
/// anything is touched is a plain Connect error with no stream at all, while a
/// failure DURING the run ends the stream with an error trailer — but only
/// AFTER a COMPLETED event carrying the freshly re-read group. The first
/// question after a failed restart is always "what state is it in now".
pub async fn control_group(
    codec: Codec,
    req: pb::ControlContainerGroupRequest,
    names: Vec<(String, String)>,
) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("container", &req.key) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let action = pb::ServiceAction::try_from(req.action).unwrap_or(pb::ServiceAction::Unspecified);
    if action == pb::ServiceAction::Unspecified {
        return Refusal::UnspecifiedAction.response();
    }
    let inv = match inventory(&names).await {
        Ok(inv) => inv,
        Err(err) => return Refusal::EngineUnavailable(err.to_string()).response(),
    };
    if !inv.unavailable_reason.is_empty() {
        return Refusal::EngineUnavailable(inv.unavailable_reason).response();
    }
    let Some(group) = resolve(&inv, &req.key) else {
        return Refusal::UnknownKey.response();
    };

    // From here on the strings are the HOST's, never the caller's.
    let key = group.key.clone();
    let kind = kind_of(group);
    let container_names: Vec<String> = group.containers.iter().map(|c| c.name.clone()).collect();

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);

    tokio::spawn(async move {
        let _claim = claim;
        let sink = GroupSink {
            tx,
            codec,
            key: key.clone(),
            action,
            journal: crate::jobs::Journal::open(pb::JobKind::ContainerControl, &key),
        };
        let _ = sink.started(&container_names).await;

        let failure = run_group(&key, kind, action, &sink).await.err();

        // Re-read AFTER the action, whatever happened. The client is told the
        // state it is in, not just that something went wrong.
        let mut problems: Vec<String> = failure.into_iter().collect();
        match inventory(&names).await {
            Ok(fresh) => {
                let _ = sink.completed(resolve(&fresh, &key).cloned()).await;
            }
            Err(err) => problems.push(format!("status re-read: {err}")),
        }
        if !problems.is_empty() {
            let _ = sink.fail(&problems.join("; ")).await;
        }
    });

    stream_response(json, rx)
}

/// Run one group's action, forwarding output line by line. `Err` carries a
/// short reason; the process output has already been streamed.
async fn run_group(
    key: &str,
    kind: GroupKind,
    action: pb::ServiceAction,
    sink: &GroupSink,
) -> Result<(), String> {
    let args = docker_args(key, kind, action);
    let mut child = Command::new("docker")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run docker: {err}"))?;

    let mut out = child.stdout.take().map(|s| BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| BufReader::new(s).lines());

    // ONE deadline for the whole run, not one per line: `docker compose
    // restart` on a twenty-container stack is silent for long stretches, and a
    // quiet minute is not a hung command. Dropping the future drops the child,
    // and `kill_on_drop` reaps it.
    let outcome = tokio::time::timeout(Duration::from_secs(GROUP_TIMEOUT_SECS), async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.progress("stdout", text).await; }
                        _ => out = None,
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        // compose narrates on stderr ("Restarting 3/3"), so an
                        // stderr line is progress, not proof of failure — the
                        // exit status is.
                        Ok(Some(text)) => { let _ = sink.progress("stderr", text).await; }
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
        Err(_) => Err(format!("timed out after {GROUP_TIMEOUT_SECS}s")),
        Ok(Err(io)) => Err(format!("docker did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(match status.code() {
            Some(code) => format!("docker exited {code}"),
            None => "docker was killed by a signal".to_string(),
        }),
    }
}

/// Frames and pushes one operation's events. Every send failing means the
/// client is gone; callers read that as "stop talking", never as an error.
struct GroupSink {
    tx: Sender<bytes::Bytes>,
    codec: Codec,
    key: String,
    action: pb::ServiceAction,
    /// The record this run leaves behind, so a client that closed can ask how
    /// it went — see `crate::jobs`. `None` when the host could not open one,
    /// which costs the reattach and nothing else.
    journal: Option<crate::jobs::Journal>,
}

impl GroupSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::ContainerOperationEvent {
        pb::ContainerOperationEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            key: self.key.clone(),
            action: self.action as i32,
            text: String::new(),
            stream: String::new(),
            containers: Vec::new(),
            group: None,
        }
    }

    async fn send(&self, event: pb::ContainerOperationEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, containers: &[String]) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.containers = containers.to_vec();
        self.send(event).await
    }

    async fn progress(&self, stream: &str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(&self, group: Option<pb::ContainerGroup>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.group = group;
        self.send(event).await
    }

    /// End the stream with a Connect error trailer. Without it a failed action
    /// looks exactly like a successful one: a streamed operation carries no
    /// exit status of its own.
    async fn fail(&self, message: &str) -> Result<(), ()> {
        // **The failure is the run's ending, and the record needs it in the
        // same words the trailer carries.** Without this the journal would be
        // closed by the drop below with "outcome not reported", which is true
        // of an early return and a lie about a failure that was named.
        crate::jobs::finish(&self.journal, Some(message));
        self.tx
            .send(error_trailer("internal", message))
            .await
            .map_err(|_| ())
    }
}

/// The container names of one group, for the logs verb. `Err` is a refusal
/// before the stream opens.
pub async fn containers_of_group(
    key: &str,
    names: &[(String, String)],
) -> Result<(String, Vec<String>), Refusal> {
    let inv = inventory(names)
        .await
        .map_err(|err| Refusal::EngineUnavailable(err.to_string()))?;
    if !inv.unavailable_reason.is_empty() {
        return Err(Refusal::EngineUnavailable(inv.unavailable_reason));
    }
    let group = resolve(&inv, key).ok_or(Refusal::UnknownKey)?;
    Ok((
        group.key.clone(),
        group.containers.iter().map(|c| c.name.clone()).collect(),
    ))
}

// ─────────────────────────────── one container ───────────────────────────────

/// Everything about one container that the list does not carry.
///
/// The NAME is gated against the inventory first, so what reaches `docker
/// inspect` is a string the host itself printed. The container row is taken
/// from the inventory rather than rebuilt from the inspect output: the port
/// string is the one `docker ps` prints, and a detail screen whose ports are
/// spelled differently from the list's would read as two different containers.
pub async fn inspect(
    codec: Codec,
    req: pb::InspectContainerRequest,
    names: &[(String, String)],
) -> Resp {
    let inv = match inventory(names).await {
        Ok(inv) => inv,
        Err(err) => return Refusal::EngineUnavailable(err.to_string()).response(),
    };
    if !inv.unavailable_reason.is_empty() {
        return Refusal::EngineUnavailable(inv.unavailable_reason).response();
    }
    let Some(container) = inv
        .groups
        .iter()
        .flat_map(|g| g.containers.iter())
        .find(|c| c.name == req.name)
    else {
        return connect_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "this host reports no container with that name",
        );
    };

    let name = container.name.clone();
    let raw = match run_inspect(&name).await {
        Ok(raw) => raw,
        Err(err) => return Refusal::EngineUnavailable(err.to_string()).response(),
    };
    let detail = build_detail(container.clone(), raw.as_deref());
    codec.encode(&detail).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

async fn run_inspect(name: &str) -> Result<Option<String>> {
    let output = Command::new("docker")
        .args(["inspect", name])
        .output()
        .await
        .context("run `docker inspect`")?;
    if !output.status.success() {
        // A container that vanished between the list read and this one is not
        // an engine failure — the caller still gets the row it already has.
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
}

/// Assemble the detail from the list row plus whatever `docker inspect` said.
///
/// Separate from the command so the parsing can be asked a question without a
/// container engine on the machine running the test — the same split that makes
/// `assemble` testable, and for the same reason.
fn build_detail(container: pb::Container, raw: Option<&str>) -> pb::ContainerDetail {
    let mut detail = pb::ContainerDetail {
        container: Some(container),
        ..Default::default()
    };
    let Some(rows) = raw.and_then(|raw| serde_json::from_str::<Vec<InspectRow>>(raw).ok()) else {
        // Missing detail is a THINNER answer, never an error: the row the
        // client already has is still true.
        return detail;
    };
    let Some(row) = rows.into_iter().next() else {
        return detail;
    };

    detail.created_at = row.created;
    detail.restart_policy = row.host_config.restart_policy.name;
    detail.compose_project = row
        .config
        .labels
        .get("com.docker.compose.project")
        .cloned()
        .unwrap_or_default();
    detail.compose_service = row
        .config
        .labels
        .get("com.docker.compose.service")
        .cloned()
        .unwrap_or_default();
    detail.command = row.config.cmd.unwrap_or_default().join(" ");
    detail.env = row
        .config
        .env
        .into_iter()
        .filter_map(|entry| {
            // `docker inspect` gives "KEY=value", and a value may itself contain
            // '=' — so the split is on the FIRST one only.
            let (key, value) = entry.split_once('=')?;
            Some(pb::ContainerEnvVar {
                sensitive: looks_sensitive(key),
                key: key.to_string(),
                value: value.to_string(),
            })
        })
        .collect();
    detail.mounts = row
        .mounts
        .into_iter()
        .map(|mount| pb::ContainerMount {
            // Both travel: the path is what a tar reads, the name is what
            // `docker volume` commands take, and for a named volume they are
            // different strings.
            name: mount.name.clone(),
            source: if mount.source.is_empty() { mount.name } else { mount.source },
            destination: mount.destination,
            mode: if mount.rw { "rw".to_string() } else { "ro".to_string() },
            kind: mount.kind,
        })
        .collect();
    detail
}

/// Does this variable name look like a credential?
///
/// **The bias is deliberate and one-directional.** A false positive costs one
/// tap; a false negative puts a database password on a screen someone else can
/// read. So the list is generous — `PUBLIC_KEY` is hidden too, and that is the
/// correct trade rather than a bug to fix.
///
/// `URL`/`URI`/`DSN` are here because a connection string carries the password
/// inside it: `DATABASE_URL` is the single most common way a credential reaches
/// a container, and a rule that only looked for the word "password" would miss
/// exactly that one.
fn looks_sensitive(key: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "PASSWORD", "PASSWD", "PWD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "AUTH", "SALT",
        "PRIVATE", "URL", "URI", "DSN", "CERT", "SIGNATURE", "SESSION", "COOKIE", "API",
    ];
    let upper = key.to_uppercase();
    NEEDLES.iter().any(|needle| upper.contains(needle))
}

#[derive(Debug, Deserialize)]
struct InspectRow {
    #[serde(rename = "Created", default)]
    created: String,
    #[serde(rename = "Config", default)]
    config: InspectConfig,
    #[serde(rename = "HostConfig", default)]
    host_config: InspectHostConfig,
    #[serde(rename = "Mounts", default)]
    mounts: Vec<InspectMount>,
}

#[derive(Debug, Default, Deserialize)]
struct InspectConfig {
    #[serde(rename = "Env", default)]
    env: Vec<String>,
    #[serde(rename = "Cmd", default)]
    cmd: Option<Vec<String>>,
    #[serde(rename = "Labels", default)]
    labels: std::collections::HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
struct InspectHostConfig {
    #[serde(rename = "RestartPolicy", default)]
    restart_policy: InspectRestartPolicy,
}

#[derive(Debug, Default, Deserialize)]
struct InspectRestartPolicy {
    #[serde(rename = "Name", default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct InspectMount {
    #[serde(rename = "Type", default)]
    kind: String,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Source", default)]
    source: String,
    #[serde(rename = "Destination", default)]
    destination: String,
    #[serde(rename = "RW", default)]
    rw: bool,
}

/// Inspect every container of one group.
///
/// What backup detection reads. Gated the same way as everything else here: the
/// key is resolved against the inventory first, and the names handed to `docker
/// inspect` are the ones the host printed.
///
/// A container whose inspect fails contributes its LIST ROW and nothing more,
/// rather than failing the whole group: a plan built from four containers out of
/// five is worth showing, with the gap visible, and a group that refuses to
/// produce a plan at all is a group that cannot be backed up from the app.
pub async fn details_of_group(
    key: &str,
    names: &[(String, String)],
) -> Result<(pb::ContainerGroup, Vec<pb::ContainerDetail>), Refusal> {
    let inv = inventory(names)
        .await
        .map_err(|err| Refusal::EngineUnavailable(err.to_string()))?;
    if !inv.unavailable_reason.is_empty() {
        return Err(Refusal::EngineUnavailable(inv.unavailable_reason));
    }
    let group = resolve(&inv, key).ok_or(Refusal::UnknownKey)?.clone();

    let mut details = Vec::new();
    for container in &group.containers {
        let raw = run_inspect(&container.name).await.ok().flatten();
        details.push(build_detail(container.clone(), raw.as_deref()));
    }
    Ok((group, details))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(name: &str, status: &str, files: &str) -> ComposeProject {
        ComposeProject {
            name: name.to_string(),
            status: status.to_string(),
            config_files: files.to_string(),
        }
    }

    fn container(name: &str, state: &str) -> pb::Container {
        pb::Container {
            name: name.to_string(),
            image: "img:1".to_string(),
            state: state.to_string(),
            health: String::new(),
            ports: String::new(),
        }
    }

    // ───────────────────────────── the naming rule ─────────────────────────

    /// The owner's own example, and the shape most compose containers have.
    #[test]
    fn the_replica_index_is_dropped_and_the_words_are_spelled() {
        assert_eq!(display_name_for("mailcow-dockerized-1"), "Mailcow Dockerized");
        assert_eq!(display_name_for("nextcloud_db_1"), "Nextcloud DB");
        assert_eq!(display_name_for("some-random-stack"), "Some Random Stack");
    }

    /// Pure Title Case would answer "Gitlab", "Postgresql" and "Phpmyadmin" —
    /// misspellings of products, which is worse than an ugly name because a
    /// list of misspelled products reads as a list the app does not recognise.
    #[test]
    fn products_are_spelled_the_way_they_spell_themselves() {
        assert_eq!(display_name_for("gitlab"), "GitLab");
        assert_eq!(display_name_for("postgresql"), "PostgreSQL");
        assert_eq!(display_name_for("phpmyadmin"), "phpMyAdmin");
        assert_eq!(display_name_for("pihole"), "Pi-hole");
        assert_eq!(display_name_for("photoprism-worker"), "PhotoPrism Worker");
    }

    /// Separators are three, and a product whose name has none of them still
    /// has to come out with the space its product puts there.
    #[test]
    fn one_word_names_that_are_two_words_are_a_whole_name_lookup() {
        assert_eq!(display_name_for("adguardhome"), "AdGuard Home");
        assert_eq!(display_name_for("adguard-home"), "AdGuard Home");
        assert_eq!(display_name_for("adguard_home"), "AdGuard Home");
        assert_eq!(display_name_for("uptimekuma"), "Uptime Kuma");
    }

    /// A digit is dropped only when it is a token of its own AND the last one.
    /// Otherwise `web2` becomes "Web" and `s3-1-backup` loses its middle — a
    /// rename the owner never asked for, on a name they chose.
    #[test]
    fn only_a_trailing_standalone_digit_is_a_replica_index() {
        assert_eq!(display_name_for("web2"), "Web2");
        assert_eq!(display_name_for("s3-1-backup"), "S3 1 Backup");
        // A bare number is the whole name: dropping it would leave nothing.
        assert_eq!(display_name_for("2048"), "2048");
    }

    /// Docker prefixes an inspected container name with a slash, and a name
    /// beginning with "/" is the raw string leaking through the rule.
    #[test]
    fn a_leading_slash_and_surrounding_space_are_not_part_of_the_name() {
        assert_eq!(display_name_for("/vaultwarden"), "Vaultwarden");
        assert_eq!(display_name_for("  redis  "), "Redis");
    }

    // ────────────────────────────── the inventory ───────────────────────────

    #[test]
    fn a_container_no_project_claimed_is_its_own_row() {
        let projects = vec![project("nextcloud", "running(2)", "/opt/nextcloud/compose.yml")];
        let members = vec![container("nextcloud-app-1", "running"), container("nextcloud-db-1", "running")];
        let read = vec![(&projects[0], members.clone())];
        let mut all = members;
        all.push(container("watchtower", "running"));

        let inv = assemble(&read, &all, &[]);
        let names: Vec<&str> = inv.groups.iter().map(|g| g.display_name.as_str()).collect();
        assert_eq!(names, vec!["Nextcloud", "Watchtower"]);

        let loose = inv.groups.iter().find(|g| g.key == "watchtower").unwrap();
        assert_eq!(loose.kind, pb::ContainerGroupKind::Standalone as i32);
        assert_eq!(loose.containers.len(), 1);
        assert!(loose.config_files.is_empty());
    }

    /// The whole point of the section: a stack the app never installed is a row
    /// with a status, not a line of text in `notes`.
    #[test]
    fn a_stranger_stack_is_a_row_with_a_status_and_no_service_id() {
        let projects = vec![project("some-random-stack", "running(1)", "/srv/x/compose.yml")];
        let members = vec![container("some-random-stack-web-1", "running")];
        let read = vec![(&projects[0], members.clone())];

        let inv = assemble(&read, &members, &[]);
        assert_eq!(inv.groups.len(), 1);
        let row = &inv.groups[0];
        assert_eq!(row.display_name, "Some Random Stack");
        assert_eq!(row.service_id, "");
        assert_eq!(row.status, pb::ServiceStatus::Running as i32);
        assert_eq!(row.config_files, vec!["/srv/x/compose.yml".to_string()]);
    }

    /// A catalog service is named by the CATALOG, not by the rule: the app
    /// already ships a name for it, and a second spelling on a second screen is
    /// the same service looking like two.
    ///
    /// **The fixture is chosen so the two answers DISAGREE, and that is the
    /// whole test.** The first version of it used `mailcowdockerized`, where
    /// the catalog says "Mailcow" and the rule also says "Mailcow" — so
    /// deleting the catalog branch entirely left it green. It proved nothing.
    /// `gryonix-vpn-panel` is a project the catalog collapses to "VPN" while
    /// the rule would derive "Gryonix VPN Panel"; only a fixture like that can
    /// tell which branch answered.
    #[test]
    fn a_catalog_service_keeps_its_catalog_name_and_id() {
        let projects = vec![project("gryonix-vpn-panel", "running(3)", "/opt/vpn-panel/docker-compose.yml")];
        let members = vec![container("gryonix-vpn-panel-panel-1", "running")];
        let read = vec![(&projects[0], members.clone())];

        let inv = assemble(&read, &members, &[]);
        let row = &inv.groups[0];
        assert_eq!(row.service_id, "vpn");
        assert_eq!(row.display_name, "VPN");
        assert_eq!(row.derived_name, "VPN");
        // The rule, asked directly, answers something else — which is what makes
        // the assertions above an assertion about the catalog branch.
        assert_eq!(display_name_for("gryonix-vpn-panel"), "Gryonix VPN Panel");
    }

    /// The owner's name wins, and the derived one still travels — so the UI can
    /// offer the way back without asking the agent to re-derive it.
    #[test]
    fn an_owner_name_wins_and_the_derived_one_still_travels() {
        let projects = vec![project("some-random-stack", "running(1)", "/srv/x/compose.yml")];
        let members = vec![container("some-random-stack-web-1", "running")];
        let read = vec![(&projects[0], members.clone())];
        let names = vec![("some-random-stack".to_string(), "Photo backup".to_string())];

        let inv = assemble(&read, &members, &names);
        let row = &inv.groups[0];
        assert_eq!(row.display_name, "Photo backup");
        assert_eq!(row.derived_name, "Some Random Stack");
        assert!(row.renamed);
    }

    // ───────────────────────── no two rows share a name ─────────────────────

    /// The owner's own complaint: a host with several VPN protocols drew a
    /// column of rows all called "VPN".
    ///
    /// The fixture is the real thing — the panel plus four protocols under the
    /// project names the installer actually uses — because the rule is about
    /// what a HOST reports, not about strings chosen to suit it.
    #[test]
    fn several_vpn_pieces_are_told_apart_by_which_piece_they_are() {
        let projects = vec![
            project("vpnpanel", "running(1)", "/opt/vpn-panel/docker-compose.yml"),
            project("shadowsocks", "running(1)", "/opt/shadowsocks/docker-compose.yml"),
            project("xray", "running(1)", "/opt/xray/docker-compose.yml"),
            project("awgvpn", "running(1)", "/opt/amnezia/docker-compose.yml"),
            project("openvpn", "running(1)", "/opt/openvpn/docker-compose.yml"),
        ];
        let members: Vec<Vec<pb::Container>> = projects
            .iter()
            .map(|p| vec![container(&format!("{}-svc-1", p.name), "running")])
            .collect();
        let read: Vec<(&ComposeProject, Vec<pb::Container>)> = projects
            .iter()
            .zip(members.iter().cloned())
            .collect();
        let all: Vec<pb::Container> = members.iter().flatten().cloned().collect();

        let inv = assemble(&read, &all, &[]);
        let mut names: Vec<&str> = inv.groups.iter().map(|g| g.display_name.as_str()).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "VPN \u{00b7} AmneziaWG",
                "VPN \u{00b7} OpenVPN",
                "VPN \u{00b7} Shadowsocks",
                "VPN \u{00b7} XRay",
                "VPN \u{00b7} panel",
            ]
        );
        // Still one service, addressed by the key the host printed: the naming
        // rule must not have moved anything the verbs depend on.
        for group in &inv.groups {
            assert_eq!(group.service_id, "vpn");
        }
        assert!(inv.groups.iter().any(|g| g.key == "awgvpn"));
    }

    /// A lone VPN piece is not a collision, so it is not qualified — the app
    /// should not read "VPN \u{00b7} panel" on a host running plain WireGuard. This is
    /// the other half of the rule and it is asserted separately because a rule
    /// that qualifies unconditionally would pass the test above.
    #[test]
    fn a_single_group_is_never_qualified() {
        let projects = vec![project("vpnpanel", "running(1)", "/opt/vpn-panel/docker-compose.yml")];
        let members = vec![container("vpnpanel-panel-1", "running")];
        let read = vec![(&projects[0], members.clone())];

        let inv = assemble(&read, &members, &[]);
        assert_eq!(inv.groups[0].display_name, "VPN");
        assert_eq!(inv.groups[0].derived_name, "VPN");
    }

    /// The rule is general, not a patch on the VPN: two strangers that happen
    /// to spell the same are parted by the keys the host printed.
    #[test]
    fn two_strangers_that_spell_the_same_are_parted_by_their_keys() {
        let projects = vec![project("nextcloud-db", "running(1)", "/srv/a/compose.yml")];
        let members = vec![container("nextcloud-db-pg-1", "running")];
        let read = vec![(&projects[0], members.clone())];
        let mut all = members;
        all.push(container("nextcloud_db_1", "running"));

        let inv = assemble(&read, &all, &[]);
        let mut names: Vec<&str> = inv.groups.iter().map(|g| g.display_name.as_str()).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "Nextcloud DB \u{00b7} nextcloud-db",
                "Nextcloud DB \u{00b7} nextcloud_db_1",
            ]
        );
    }

    /// The last level, and the reason escalation terminates: a project and a
    /// loose container may carry the SAME key, so neither the spelling nor the
    /// key can part them — what they ARE can, and nothing else is left.
    #[test]
    fn a_project_and_a_container_sharing_a_key_are_parted_by_what_they_are() {
        let projects = vec![project("redis", "running(1)", "/srv/r/compose.yml")];
        let members = vec![container("redis-server-1", "running")];
        let read = vec![(&projects[0], members.clone())];
        let mut all = members;
        all.push(container("redis", "running"));

        let inv = assemble(&read, &all, &[]);
        let mut names: Vec<&str> = inv.groups.iter().map(|g| g.display_name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["Redis (container)", "Redis (project)"]);
    }

    /// A name the owner typed is never appended to — but the automatic name
    /// underneath it still gets parted, so reverting does not revert into the
    /// ambiguity. Both halves in one assertion, because a rule that only did
    /// the first half would look right on screen and be wrong the moment
    /// someone pressed "use the automatic name".
    #[test]
    fn an_owner_name_is_left_alone_while_the_one_underneath_is_parted() {
        let projects = vec![
            project("vpnpanel", "running(1)", "/opt/vpn-panel/docker-compose.yml"),
            project("shadowsocks", "running(1)", "/opt/shadowsocks/docker-compose.yml"),
        ];
        let members: Vec<Vec<pb::Container>> = projects
            .iter()
            .map(|p| vec![container(&format!("{}-svc-1", p.name), "running")])
            .collect();
        let read: Vec<(&ComposeProject, Vec<pb::Container>)> =
            projects.iter().zip(members.iter().cloned()).collect();
        let all: Vec<pb::Container> = members.iter().flatten().cloned().collect();
        let names = vec![("vpnpanel".to_string(), "My VPN".to_string())];

        let inv = assemble(&read, &all, &names);
        let panel = inv.groups.iter().find(|g| g.key == "vpnpanel").unwrap();
        assert_eq!(panel.display_name, "My VPN");
        assert_eq!(panel.derived_name, "VPN \u{00b7} panel");
        let ss = inv.groups.iter().find(|g| g.key == "shadowsocks").unwrap();
        assert_eq!(ss.display_name, "VPN \u{00b7} Shadowsocks");
    }

    /// A stopped project still has a row. A section that only lists what is up
    /// cannot answer "why is this down", which is when it is opened.
    #[test]
    fn a_stopped_project_is_listed_with_a_stopped_status() {
        let projects = vec![project("vaultwarden", "exited(1)", "/opt/vaultwarden/compose.yml")];
        let members = vec![container("vaultwarden", "exited")];
        let read = vec![(&projects[0], members.clone())];

        let inv = assemble(&read, &members, &[]);
        assert_eq!(inv.groups[0].status, pb::ServiceStatus::Stopped as i32);
    }

    // ───────────────────────────────── the gate ─────────────────────────────

    /// `resolve` is the gate every verb that takes a key goes through, and it
    /// hands back the HOST's string rather than a bool: what travels onward is
    /// the inventory's text, never the caller's.
    #[test]
    fn resolve_answers_only_for_a_key_the_host_reports() {
        let projects = vec![project("nextcloud", "running(1)", "/opt/nextcloud/compose.yml")];
        let members = vec![container("nextcloud-app-1", "running")];
        let read = vec![(&projects[0], members.clone())];
        let inv = assemble(&read, &members, &[]);

        assert!(resolve(&inv, "nextcloud").is_some());
        assert!(resolve(&inv, "nextcloud; rm -rf /").is_none());
        assert!(resolve(&inv, "").is_none());
    }

    // ──────────────────────── control argv and inspect ─────────────────────

    /// A compose project and a lone container take DIFFERENT commands, and the
    /// difference is not cosmetic: `docker compose -p X stop` finds containers
    /// by project label, and a `docker run` container carries no such label —
    /// the compose form would match nothing and report success on a container
    /// it never touched.
    #[test]
    fn a_project_and_a_lone_container_take_different_commands() {
        assert_eq!(
            docker_args("nextcloud", GroupKind::ComposeProject, pb::ServiceAction::Restart),
            vec!["compose", "-p", "nextcloud", "restart"]
        );
        assert_eq!(
            docker_args("watchtower", GroupKind::Standalone, pb::ServiceAction::Restart),
            vec!["restart", "watchtower"]
        );
    }

    /// `down` REMOVES containers, so `start` could not bring the same ones
    /// back — that is uninstall, and it has its own verb and its own
    /// confirmation. On this path the stack is a stranger's, which is exactly
    /// where turning "off for a minute" into a teardown would be unrecoverable.
    #[test]
    fn stop_is_stop_and_never_down() {
        for kind in [GroupKind::ComposeProject, GroupKind::Standalone] {
            let args = docker_args("x", kind, pb::ServiceAction::Stop);
            assert!(args.iter().any(|a| a == "stop"), "{args:?}");
            assert!(!args.iter().any(|a| a == "down"), "{args:?}");
            assert!(!args.iter().any(|a| a == "rm"), "{args:?}");
        }
    }

    /// The key is its own argv element, so even a hostile project name is one
    /// argument and never a second command. There is no shell on this path.
    #[test]
    fn a_hostile_key_stays_a_single_argument() {
        let args = docker_args("x; rm -rf /", GroupKind::Standalone, pb::ServiceAction::Stop);
        assert_eq!(args, vec!["stop", "x; rm -rf /"]);
    }

    /// A connection string carries the password INSIDE it, and `DATABASE_URL`
    /// is the commonest way a credential reaches a container — a rule that only
    /// looked for "password" would miss exactly that one.
    #[test]
    fn a_connection_string_counts_as_a_credential() {
        assert!(looks_sensitive("DATABASE_URL"));
        assert!(looks_sensitive("POSTGRES_PASSWORD"));
        assert!(looks_sensitive("admin_token"));
        assert!(looks_sensitive("JWT_SECRET"));
        assert!(!looks_sensitive("TZ"));
        assert!(!looks_sensitive("PUID"));
        assert!(!looks_sensitive("LANG"));
    }

    const INSPECT: &str = r#"[{
      "Created": "2026-08-01T10:00:00Z",
      "Config": {
        "Env": ["TZ=Europe/Berlin", "DATABASE_URL=postgres://u:p@db/x?a=b", "EMPTY="],
        "Cmd": ["nginx", "-g", "daemon off;"],
        "Labels": {"com.docker.compose.project": "some-stack", "com.docker.compose.service": "web"}
      },
      "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
      "Mounts": [
        {"Type": "bind", "Source": "/srv/data", "Destination": "/data", "RW": true},
        {"Type": "volume", "Name": "cache", "Source": "", "Destination": "/cache", "RW": false}
      ]
    }]"#;

    /// A value may itself contain '=', so the split is on the FIRST one only —
    /// a naive split would truncate every connection string, which is the one
    /// kind of value people open this screen to read.
    #[test]
    fn env_splits_on_the_first_equals_and_marks_the_credential() {
        let detail = build_detail(container("web", "running"), Some(INSPECT));
        let url = detail.env.iter().find(|e| e.key == "DATABASE_URL").unwrap();
        assert_eq!(url.value, "postgres://u:p@db/x?a=b");
        assert!(url.sensitive);
        let tz = detail.env.iter().find(|e| e.key == "TZ").unwrap();
        assert_eq!(tz.value, "Europe/Berlin");
        assert!(!tz.sensitive);
        // A variable set to nothing is still a variable that is SET, and that
        // is a different fact from one that is absent.
        let empty = detail.env.iter().find(|e| e.key == "EMPTY").unwrap();
        assert_eq!(empty.value, "");
    }

    #[test]
    fn mounts_carry_where_they_come_from_and_whether_they_are_writable() {
        let detail = build_detail(container("web", "running"), Some(INSPECT));
        assert_eq!(detail.mounts.len(), 2);
        assert_eq!(detail.mounts[0].source, "/srv/data");
        assert_eq!(detail.mounts[0].mode, "rw");
        assert_eq!(detail.mounts[0].kind, "bind");
        // A named volume has no host Source; its NAME is what identifies it, and
        // an empty source column would say the mount comes from nowhere.
        assert_eq!(detail.mounts[1].source, "cache");
        assert_eq!(detail.mounts[1].mode, "ro");
        assert_eq!(detail.restart_policy, "unless-stopped");
        assert_eq!(detail.compose_project, "some-stack");
        assert_eq!(detail.command, "nginx -g daemon off;");
    }

    /// A container that vanished between the list read and the inspect is a
    /// THINNER answer, never an error: the row the client already has is still
    /// true, and failing the whole screen over a missing detail would hide it.
    #[test]
    fn missing_detail_is_a_thinner_answer_not_a_failure() {
        for raw in [None, Some("not json"), Some("[]")] {
            let detail = build_detail(container("web", "running"), raw);
            assert_eq!(detail.container.as_ref().unwrap().name, "web");
            assert!(detail.env.is_empty());
            assert!(detail.mounts.is_empty());
        }
    }

    /// `-a` and `--all` are the difference between "what is running" and "what
    /// is here", and the section is opened precisely when something is DOWN.
    /// Neither flag can be exercised on a machine without a container engine,
    /// so it is pinned against the source instead — the same way the install
    /// pipeline's step order is pinned, and for the same reason: a dropped flag
    /// would be invisible to every test and visible only as a stopped stack
    /// that has silently vanished from the list.
    #[test]
    fn stopped_things_are_asked_for_explicitly() {
        let src = include_str!("containers.rs");
        let body = |name: &str| -> String {
            let start = src.find(name).expect("function present");
            src[start..].chars().take(600).collect()
        };
        let ps = body("async fn all_containers(");
        assert!(ps.contains(r#""ps", "-a""#), "docker ps must ask for stopped containers too");
        let ls = body("async fn compose_projects(");
        assert!(ls.contains(r#""--all""#), "docker compose ls must ask for stopped projects too");
    }

    /// Empty is legal and means "undo the rename" — that is why clearing is
    /// this same verb rather than a second one.
    #[test]
    fn an_owner_name_is_bounded_and_empty_means_undo() {
        assert_eq!(sanitise_name("  Photo backup "), Ok("Photo backup".to_string()));
        assert_eq!(sanitise_name(""), Ok(String::new()));
        assert_eq!(sanitise_name("   "), Ok(String::new()));
        assert!(sanitise_name(&"x".repeat(NAME_LIMIT + 1)).is_err());
        assert!(sanitise_name("two\nlines").is_err());
    }
}
