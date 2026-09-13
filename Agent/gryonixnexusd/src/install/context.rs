//! Install-time context for the AdGuard Home slice — the equivalent of
//! `dns_records::Input`, sized to what AdGuard's declarative artifacts
//! actually read.
//!
//! Carries only the fields `AdGuardHomeService`'s declarative methods pull
//! out of Swift's `ServiceContext`/`MailContext`, not either struct whole —
//! the same "small, provable subset" discipline `dns_records::Input`'s
//! module doc explains: naming only what is actually read is what keeps
//! this file honest about what the NEXT service slice will also need to
//! carry, rather than accreting fields nothing here consumes.

use crate::dns_records::Language;

/// A port of the `ServiceContext`/`MailContext` fields
/// `AdGuardHomeService`'s declarative surface reads, field for field:
/// - `domain` / `additional_domains` — `ServiceContext.domain` /
///   `.additionalDomains`.
/// - `language` — `ServiceContext.language`. Reused type: see
///   `dns_records::Language`'s own doc for why it stands alone in the crate
///   rather than depending on Swift.
/// - `local_only` — `MailContext.isLocalOnly` (`scope == .localOnly`):
///   decides whether the Caddy site self-signs (`tls internal`) instead of
///   running ACME against a domain the deployment does not have.
/// - `admin_username` — `ServiceSettings.adminUsername`. Carried for parity
///   with the Swift context even though nothing in THIS slice reads it — it
///   only feeds the AdGuard install-API call inside `setupSteps`, and
///   `setupSteps` is explicitly not ported here (see `install::mod`'s doc).
/// - `pihole_path` — `ServiceSettings.piholePath`, Swift default
///   `/opt/pihole`; `pihole_upstreams` and `pihole_serves_network` likewise
///   mirror their Swift defaults, and the second of those is the one whose
///   default is load-bearing (see the field).
/// - `adguard_path` — `ServiceSettings.adguardPath`, Swift default
///   `"/opt/adguardhome"` (the default lives on the Swift struct, not here;
///   every fixture scenario below sets it explicitly).
/// - `adguard_hostname` — `ServiceSettings.adguardHostname`. Empty means
///   "derive `dns.<domain>`" — see `adguard::hostname`.
/// - `vaultwarden_*` / `jellyfin_*` — the same reduction for срез 4.3's two
///   services (`ServiceSettings.vaultwardenHostname`/`vaultwardenContainer`/
///   `vaultwardenDataPath`/`vaultwardenAllowSignups`, `jellyfinHostname`/
///   `jellyfinPath`/`jellyfinMediaPath`) and срез 4.4's
///   (`photoprismHostname`/`photoprismPath`), 4.5's (`immichHostname`/
///   `immichPath`), 4.6's (`nextcloudHostname`/`nextcloudPath`,
///   `forgejoHostname`/`forgejoPath`/`forgejoSSHPort`), 4.7's
///   (`seafileHostname`/`seafilePath`, `psonoHostname`/`psonoPath`), 4.8's
///   (`gitlabHostname`/`gitlabPath`/`gitlabSSHPort`), 4.9's
///   (`dockerMailserverPath`), Passbolt's (`passboltHostname`/`passboltPath`)
///   and the ones that closed the `mail` shelf (`mailuPath`/`mailuSubnet`;
///   `mailcowPath` was already here — see below). One struct rather than one
///   per service: an install request names ONE service but arrives with the
///   same deployment-wide fields (`domain`, `additional_domains`,
///   `local_only`) every service reads, and the executor builds exactly one
///   `Input` from it. Each mail engine folded its own standalone input struct
///   into this one the moment it got an executor built from the wire —
///   `mail/dockermailserver` with срез 4.9, `mail/mailcow` and `mail/mailu`
///   when their own slice landed — exactly the merge all three structs' docs
///   anticipated. There is deliberately no
///   `mailcow_admin_username`/`mailcow_hostname` pair here: mailcow's in-app
///   admin identity is the fixed `admin`/`moohoo` upstream ships
///   (`MailcowService.reportSteps`' own comment — rotating it at install time
///   proved unreliable, a races-with-init problem paid for live), and its
///   hostname has no override for the same reason `docker_mailserver_path`
///   has no matching hostname field (see that field's own doc).
/// What the request said about which services single sign-on guards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutheliaProtection {
    /// The setting was not on the request at all — an app that predates it.
    Default,
    /// The app named a list. It may be empty, and an empty one means exactly
    /// that: guard nothing.
    Explicit(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Input {
    pub domain: String,
    pub additional_domains: Vec<String>,
    pub language: Language,
    pub local_only: bool,
    /// Every service this host will carry once the run finishes: what
    /// `discover` already found, plus the one being installed, as catalog ids.
    ///
    /// **Here because a default hostname is a function of the neighbours**
    /// (`install::hostnames`): one photo service is `photos.<domain>`, two make
    /// each say which it is. Empty is a working answer and means "nothing else
    /// is on this host", which is precisely when the plain name is right — so
    /// an older caller that never fills it in gets the names the catalog used
    /// to hand out anyway.
    pub installed_services: Vec<String>,
    pub admin_username: String,
    pub adguard_path: String,
    /// `ServiceSettings.autheliaPath`, Swift default `/opt/authelia`.
    pub authelia_path: String,
    /// `ServiceSettings.autheliaHostname`; empty means `auth.<domain>`.
    pub authelia_hostname: String,
    /// `ServiceSettings.autheliaProtectedServices`, as catalog ids.
    ///
    /// **A `Vec` could not say what this has to say.** "The app sent an empty
    /// list" and "the app never mentioned this setting" are different answers
    /// — the first means protect nothing, the second means an older app that
    /// should get the default — and as a plain `Vec` they were the same value.
    /// Found by trying to install a portal that guards nothing and getting the
    /// default set instead.
    pub authelia_protected: AutheliaProtection,
    /// `ServiceSettings.homepagePath`, Swift default `/opt/homepage`.
    pub homepage_path: String,
    /// `ServiceSettings.homepageHostname`; empty means `start.<domain>`.
    pub homepage_hostname: String,
    /// `ServiceSettings.piholePath`, Swift default `/opt/pihole`.
    pub pihole_path: String,
    /// `ServiceSettings.piholeHostname`; empty means `dns.<domain>`.
    pub pihole_hostname: String,
    /// `ServiceSettings.piholeUpstreams`, Pi-hole's own semicolon syntax.
    pub pihole_upstreams: String,
    /// `ServiceSettings.piholeServesNetwork`. False publishes plain DNS on the
    /// loopback only — the bind address is the only thing standing between
    /// this and an open resolver, so the safe half is the default on both
    /// sides of the port.
    pub pihole_serves_network: bool,
    pub adguard_hostname: String,
    pub headscale_path: String,
    pub headscale_hostname: String,
    pub headscale_base_domain: String,
    /// The server's own mesh node — its state directory and the name it
    /// answers to inside the mesh.
    pub tailscale_node_path: String,
    pub tailscale_node_name: String,
    /// Which coordination service the node joins — empty means Tailscale's own.
    pub tailscale_login_server: String,
    /// The owner's Tailscale auth key, when joining THEIR service. Per-install
    /// like the tunnel's connector token, and for the same reason: it is a
    /// credential, and the Headscale path mints its own locally instead.
    pub tailscale_auth_key: String,
    pub cloudflared_path: String,
    /// The tunnel's connector credential, when the caller has one.
    ///
    /// **Per-install, not a stored setting.** It is fetched from Cloudflare by
    /// whoever is installing and written into the service's own 0600 `.env`;
    /// nothing on either side keeps a copy, and it is absent from the default
    /// input on purpose — an empty value means "the owner will paste it", which
    /// is what the SSH route does.
    pub cloudflared_token: String,
    pub vaultwarden_hostname: String,
    pub vaultwarden_container: String,
    pub vaultwarden_data_path: String,
    pub vaultwarden_allow_signups: bool,
    pub jellyfin_hostname: String,
    pub jellyfin_path: String,
    pub jellyfin_media_path: String,
    // The game servers and the panel in front of them.
    pub minecraft_java_path: String,
    pub minecraft_java_version: String,
    pub minecraft_java_flavour: String,
    pub minecraft_java_memory_mb: u32,
    pub minecraft_java_port: u16,
    pub minecraft_java_accepts_eula: bool,
    pub minecraft_java_whitelist: String,
    pub minecraft_java_operators: String,
    /// Modrinth projects, comma separated, in the image's own
    /// `MODRINTH_PROJECTS` syntax (`slug`, or pinned `slug:versionId`). What
    /// the owner UPLOADS is not here: those are files under `mods/` and
    /// `plugins/` beside the compose file.
    pub minecraft_java_mods: String,
    pub minecraft_bedrock_path: String,
    pub minecraft_bedrock_version: String,
    pub minecraft_bedrock_port: u16,
    pub minecraft_bedrock_accepts_eula: bool,
    pub crafty_path: String,
    pub crafty_hostname: String,
    // The AI shelf. `ServiceSettings.ollamaPath` / `openWebUIPath` /
    // `openWebUIHostname` / `openWebUIAllowSignups`.
    //
    // There is deliberately no `model_backend` beside them: that setting picks
    // WHICH SERVICES a selection installs, and by the time a request reaches
    // this crate that decision is already made — the request names the service.
    // Carrying it here would be a second opinion on a question already answered.
    pub ollama_path: String,
    /// Whether this deployment asks the engine to use an NVIDIA card.
    ///
    /// A question about the MACHINE, and what the install does with the answer
    /// is conditional on what it finds — see `install_ollama_steps`. A wrong
    /// answer costs a line in the report, never the deployment.
    pub ollama_uses_gpu: bool,
    pub open_webui_path: String,
    pub open_webui_hostname: String,
    /// Open registration on the chat. True on both sides, and it has to be:
    /// the first account created there becomes the administrator, so a false
    /// default would install a service nobody can ever log in to.
    pub open_webui_allow_signups: bool,
    /// Where the gateway's compose file and routing table live. The KEYS are
    /// not under it — they are written at a fixed path this crate owns
    /// (`llm_keys::KEYS_ENV_PATH`), because a root-only secret file whose
    /// location a client can move is a client that can make root write
    /// wherever it likes.
    pub litellm_path: String,
    /// `ServiceSettings.liteLLMHostname`; empty means `llm.<domain>`.
    pub litellm_hostname: String,
    /// Where the automation engine keeps its compose file, its settings
    /// directory and its database volume.
    pub n8n_path: String,
    /// `ServiceSettings.n8nHostname`; empty means `flows.<domain>`.
    pub n8n_hostname: String,
    /// Where the retrieval chat keeps documents, its database and the
    /// settings file the container writes back into. One directory, because
    /// the backup takes it whole.
    pub anythingllm_path: String,
    /// `ServiceSettings.anythingLLMHostname`; empty means `docs.<domain>`.
    pub anythingllm_hostname: String,
    /// Where the vector store keeps its segments. No hostname beside it: the
    /// store publishes nothing.
    pub qdrant_path: String,
    /// Where the search engine keeps its compose file, the settings file this
    /// deployment writes for it, and its cache. No hostname beside it: the
    /// engine is called by the containers on this host, not opened.
    pub searxng_path: String,
    /// Where the messenger assistant keeps its state — the paired sessions,
    /// its config and its workspace.
    pub openclaw_path: String,
    /// `ServiceSettings.openclawHostname`; empty means `agent.<domain>`.
    pub openclaw_hostname: String,
    pub photoprism_hostname: String,
    pub photoprism_path: String,
    pub immich_hostname: String,
    pub immich_path: String,
    pub nextcloud_hostname: String,
    pub nextcloud_path: String,
    pub forgejo_hostname: String,
    pub forgejo_path: String,
    /// Public port of Forgejo's git-over-SSH, or 0 for "switched off" — a
    /// BRANCH of the compose file, not a number in it (see `forgejo::ssh_port`).
    pub forgejo_ssh_port: u16,
    pub gitlab_hostname: String,
    pub gitlab_path: String,
    /// Public port of GitLab's git-over-SSH, or 0 for "switched off" — the
    /// same branch/number distinction `forgejo_ssh_port` carries.
    pub gitlab_ssh_port: u16,
    pub seafile_hostname: String,
    pub seafile_path: String,
    pub psono_hostname: String,
    pub psono_path: String,
    /// Third and last product on the `passwords` shelf. No `admin_username`
    /// field beside it: the field already carried on this `Input` for every
    /// other service reads `passbolt::admin_login`'s own default, so a
    /// duplicate here would just be a second name for the same value.
    pub passbolt_hostname: String,
    pub passbolt_path: String,
    /// Срез 4.9 — the VPN. `vpn_hostname` is `ServiceSettings.vpnHostname`
    /// (empty means "derive `vpn.<domain>`"); the protocol paths are mounted
    /// into the panel's container UNCONDITIONALLY, whether or not that
    /// protocol is installed (docker materialises a missing bind source as an
    /// empty directory), so all four belong to the panel's declarative half
    /// even though only WireGuard has an installer in this build. The ports
    /// are all five protocols' because `services.json` has to describe any of
    /// them byte-exactly. `mailcow_path` is here for the same reason: the
    /// panel mounts it read-only to offer existing mailboxes as the sender
    /// for password-reset mail.
    pub vpn_hostname: String,
    /// `ServiceSettings.vpnClientAccess` — "app", "panel" or "both".
    ///
    /// Decides whether the PANEL'S PAGE is published, never whether the panel
    /// runs: it is the WireGuard server and always runs. Anything other than
    /// the three known values means `both`, which is what a deployment made
    /// before this setting existed does.
    pub vpn_client_access: String,
    pub wireguard_vpn_port: u16,
    pub amnezia_wg_path: String,
    pub amnezia_wg_port: u16,
    pub shadowsocks_path: String,
    pub shadowsocks_port: u16,
    pub xray_reality_path: String,
    pub xray_reality_port: u16,
    /// `ServiceSettings.xrayRealitySNI` — the well-known TLS 1.3 site Reality
    /// borrows its handshake from, and the ONLY protocol setting that is not a
    /// path or a port. It reaches exactly one file (XRay's `config.json`, as
    /// both `dest` and `serverNames`) and one client link, so a port that
    /// pinned the default would pass every scenario that does not move it —
    /// which is why the fixture park has a scenario that does.
    pub xray_reality_sni: String,
    pub openvpn_path: String,
    pub openvpn_port: u16,
    pub mailcow_path: String,
    /// `ServiceSettings.dockerMailserverPath`. There is deliberately no
    /// `docker_mailserver_hostname` beside it: all three mail engines pin
    /// `mail.<domain>` unconditionally (`requiredHostname(forDomain:)`), and a
    /// second source of truth for that one name would buy nothing and cost an
    /// ACME failure — it is a contract between the MX record, the A record,
    /// Caddy's certificate and the engine's own SMTP banner at once.
    pub docker_mailserver_path: String,
    /// `ServiceSettings.mailuPath`.
    pub mailu_path: String,
    /// `ServiceSettings.mailuSubnet`. NOT a filesystem path — `build_input`'s
    /// absolute-path gate does not apply to it — but spelled out for the same
    /// reason `MailuInput`'s own former doc gave: Mailu's containers trust
    /// requests that appear to originate from this range (`REAL_IP_FROM`/
    /// `dns:`), and a value that does not match what docker actually handed
    /// the `mailu` network makes an internal call look external, the same
    /// trap `mailcow`'s `API_ALLOW_FROM` sets (GOTCHAS.md).
    pub mailu_subnet: String,
    /// Whether this deployment wants CrowdSec on the host at all.
    ///
    /// **True by default, and that default is load-bearing.** CrowdSec used to
    /// be unconditional (`crowdsec`'s own module doc, owner's decision
    /// 2026-09-01); the owner asked for an opt-OUT rather than an opt-in
    /// 2026-09-09, so an app that predates this field — or sends no opinion —
    /// must still get the intrusion defence every host got before the switch
    /// existed. A wrong answer here is a host with no watch on its SSH log, so
    /// silence has to mean "recommended", not "off".
    pub crowdsec_enabled: bool,
}

/// The per-service defaults are Swift's `ServiceSettings` initializer
/// defaults, value for value — the request only carries what the operator
/// actually changed, so a missing setting has to mean the same thing on both
/// sides or the agent would install into a different directory than the app
/// reports. `domain` deliberately has no useful default (the executor
/// refuses an empty one before anything is touched).
impl Default for Input {
    fn default() -> Self {
        Self {
            domain: String::new(),
            additional_domains: Vec::new(),
            language: Language::En,
            local_only: false,
            installed_services: Vec::new(),
            admin_username: "admin".to_string(),
            adguard_path: "/opt/adguardhome".to_string(),
            authelia_path: "/opt/authelia".to_string(),
            authelia_hostname: String::new(),
            authelia_protected: AutheliaProtection::Default,
            homepage_path: "/opt/homepage".to_string(),
            homepage_hostname: String::new(),
            pihole_path: "/opt/pihole".to_string(),
            pihole_hostname: String::new(),
            pihole_upstreams: "1.1.1.1;1.0.0.1".to_string(),
            pihole_serves_network: false,
            adguard_hostname: String::new(),
            headscale_path: "/opt/headscale".to_string(),
            headscale_hostname: String::new(),
            headscale_base_domain: String::new(),
            tailscale_node_path: "/opt/tailscale".to_string(),
            tailscale_node_name: String::new(),
            tailscale_login_server: String::new(),
            tailscale_auth_key: String::new(),
            cloudflared_path: "/opt/cloudflared".to_string(),
            cloudflared_token: String::new(),
            vaultwarden_hostname: String::new(),
            vaultwarden_container: "vaultwarden".to_string(),
            vaultwarden_data_path: "/opt/vaultwarden/data".to_string(),
            vaultwarden_allow_signups: true,
            jellyfin_hostname: String::new(),
            jellyfin_path: "/opt/jellyfin".to_string(),
            jellyfin_media_path: "/srv/media".to_string(),
            // Defaults mirror `ServiceSettings` exactly — a difference here
            // would install into a different directory than the app shows.
            minecraft_java_path: "/opt/minecraft-java".to_string(),
            minecraft_java_version: String::new(),
            minecraft_java_flavour: "PAPER".to_string(),
            minecraft_java_memory_mb: 2048,
            minecraft_java_port: 25565,
            minecraft_java_accepts_eula: false,
            minecraft_java_whitelist: String::new(),
            minecraft_java_operators: String::new(),
            minecraft_java_mods: String::new(),
            minecraft_bedrock_path: "/opt/minecraft-bedrock".to_string(),
            minecraft_bedrock_version: String::new(),
            minecraft_bedrock_port: 19132,
            minecraft_bedrock_accepts_eula: false,
            crafty_path: "/opt/crafty".to_string(),
            crafty_hostname: String::new(),
            ollama_path: "/opt/ollama".to_string(),
            ollama_uses_gpu: false,
            open_webui_path: "/opt/open-webui".to_string(),
            open_webui_hostname: String::new(),
            open_webui_allow_signups: true,
            litellm_path: "/opt/litellm".to_string(),
            litellm_hostname: String::new(),
            n8n_path: "/opt/n8n".to_string(),
            n8n_hostname: String::new(),
            anythingllm_path: "/opt/anythingllm".to_string(),
            anythingllm_hostname: String::new(),
            qdrant_path: "/opt/qdrant".to_string(),
            searxng_path: "/opt/searxng".to_string(),
            openclaw_path: "/opt/openclaw".to_string(),
            openclaw_hostname: String::new(),
            photoprism_hostname: String::new(),
            photoprism_path: "/opt/photoprism".to_string(),
            immich_hostname: String::new(),
            immich_path: "/opt/immich".to_string(),
            nextcloud_hostname: String::new(),
            nextcloud_path: "/opt/nextcloud".to_string(),
            forgejo_hostname: String::new(),
            forgejo_path: "/opt/forgejo".to_string(),
            forgejo_ssh_port: 2222,
            gitlab_hostname: String::new(),
            // Not /opt/gitlab: omnibus owns that path INSIDE the container,
            // and Swift's own default keeps the two apart.
            gitlab_path: "/opt/gitlab-ce".to_string(),
            // 2223, one past Forgejo's — the two forges may be installed side
            // by side (the catalog does not forbid it), and both publish.
            gitlab_ssh_port: 2223,
            seafile_hostname: String::new(),
            seafile_path: "/opt/seafile".to_string(),
            psono_hostname: String::new(),
            psono_path: "/opt/psono".to_string(),
            passbolt_hostname: String::new(),
            passbolt_path: "/opt/passbolt".to_string(),
            vpn_hostname: String::new(),
            vpn_client_access: "both".to_string(),
            wireguard_vpn_port: 51820,
            amnezia_wg_path: "/opt/awgvpn".to_string(),
            amnezia_wg_port: 51822,
            shadowsocks_path: "/opt/shadowsocks".to_string(),
            shadowsocks_port: 8388,
            xray_reality_path: "/opt/xray".to_string(),
            xray_reality_port: 8443,
            xray_reality_sni: "www.microsoft.com".to_string(),
            openvpn_path: "/opt/openvpn".to_string(),
            openvpn_port: 1194,
            mailcow_path: "/opt/mailcow-dockerized".to_string(),
            docker_mailserver_path: "/opt/docker-mailserver".to_string(),
            mailu_path: "/opt/mailu".to_string(),
            mailu_subnet: "172.29.0.0/24".to_string(),
            crowdsec_enabled: true,
        }
    }
}

impl Input {
    /// A port of `ServiceContext.mirroredHostnames(of:)` /
    /// `MailContext.mirroredHostnames(of:)` — the two Swift copies already
    /// agree byte-for-byte with each other, and this is a third copy of the
    /// same three lines for the same duplication-over-shared-dependency
    /// reason the whole crate stands on (`dns_records`'s module doc; the
    /// binary is a self-contained musl build, Swift packages cannot be a
    /// dependency of it in either direction). Only names that sit under the
    /// primary domain are mirrored — a hostname of a service's own
    /// (`filter.example.com` picked deliberately outside `domain`) has
    /// nothing to do with this deployment's domains and is left alone.
    pub fn mirrored_hostnames(&self, hostname: &str) -> Vec<String> {
        let suffix = format!(".{}", self.domain);
        let Some(prefix) = hostname.strip_suffix(&suffix) else {
            return Vec::new();
        };
        self.additional_domains.iter().map(|d| format!("{prefix}.{d}")).collect()
    }

    /// A port of `ServiceContext.servedHostnames(of:)`: the hostname itself
    /// plus its mirror on every additional domain — every name a Host-header
    /// check would need to accept for this site. AdGuard's declarative
    /// surface does not call this today (nothing here validates a Host
    /// header), but it is part of the `ServiceContext` contract this `Input`
    /// stands in for, and the next service slice may well need it.
    #[allow(dead_code)]
    pub fn served_hostnames(&self, hostname: &str) -> Vec<String> {
        let mut names = vec![hostname.to_string()];
        names.extend(self.mirrored_hostnames(hostname));
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn mirrors_only_names_under_the_primary_domain() {
        let mut input = base();
        input.additional_domains = vec!["example.org".to_string()];
        assert!(input.mirrored_hostnames("dns.other.net").is_empty());
        assert_eq!(input.mirrored_hostnames("dns.example.com"), vec!["dns.example.org".to_string()]);
    }

    #[test]
    fn served_hostnames_prepends_the_name_itself_in_order() {
        let mut input = base();
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_eq!(
            input.served_hostnames("dns.example.com"),
            vec!["dns.example.com".to_string(), "dns.example.org".to_string(), "dns.example.net".to_string()]
        );
    }
}
