//! Authelia's declarative install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/AutheliaService.swift`.
//!
//! **It protects the services the owner names, and by default only the ones
//! that have no app of their own.** A forward-auth gate in front of Nextcloud,
//! Immich or Vaultwarden breaks their MOBILE CLIENTS outright — those speak to
//! an API with their own credentials and cannot follow a browser login — and
//! the failure looks like the app being broken, not like a gate being closed.
//!
//! The configuration keys are the 4.39 schema, read out of the pinned image's
//! own binary rather than from documentation: `jwt_secret` moved under
//! `identity_validation.reset_password` and the session domain moved into
//! `session.cookies[]` in 4.38, and a config written to the older shape starts
//! nothing.

use super::caddy::{self, WebIngress};
use super::context::{AutheliaProtection, Input};

/// Exact pinned tag. arm64 verified by the ELF header inside the layer:
/// `app/authelia` in the linux/arm64 manifest is a real AArch64 binary
/// (e_machine 0xB7).
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "authelia";

pub const IMAGE: &str = "ghcr.io/authelia/authelia:4.39.20";
pub const COMPOSE_PROJECT: &str = "authelia";
pub const CONTAINER: &str = "authelia";
/// Loopback port Caddy proxies to (8092 Pi-hole, 8093 Homepage).
pub const WEB_UI_PORT: u16 = 8094;
/// Port Authelia binds INSIDE the container — its own default.
pub const CONTAINER_WEB_PORT: u16 = 9091;

/// What SSO guards unless the owner says otherwise: the surfaces that are
/// nothing but a browser admin page. Mirrors
/// `AutheliaService.defaultProtected`.
pub const DEFAULT_PROTECTED: &[&str] = &["adguard-home", "pihole", "homepage"];

pub fn hostname(input: &Input) -> String {
    if input.authelia_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.authelia_hostname.clone()
    }
}

/// The Caddy directive a protected site carries. A port of
/// `AutheliaService.forwardAuthBlock` — the indentation is part of the file,
/// so it is reproduced rather than rebuilt.
pub fn forward_auth_block() -> String {
    format!(
        "forward_auth 127.0.0.1:{WEB_UI_PORT} {{\n        uri /api/authz/forward-auth\n        copy_headers Remote-User Remote-Groups Remote-Name Remote-Email\n    }}"
    )
}

pub fn compose_contents(input: &Input) -> String {
    let path = &input.authelia_path;
    format!(
        "services:\n  authelia:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      # The 4.39 names. Every one of them can also be given in the\n      # file; they are here so the file itself carries no secret\n      # and can be read by whoever debugs a login failure.\n      AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET: ${{AUTHELIA_JWT_SECRET}}\n      AUTHELIA_SESSION_SECRET: ${{AUTHELIA_SESSION_SECRET}}\n      AUTHELIA_STORAGE_ENCRYPTION_KEY: ${{AUTHELIA_STORAGE_ENCRYPTION_KEY}}\n    volumes:\n      - {path}/config:/config\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_WEB_PORT}\""
    )
}

pub fn env_template() -> String {
    "AUTHELIA_JWT_SECRET=__RANDOM__\nAUTHELIA_SESSION_SECRET=__RANDOM__\nAUTHELIA_STORAGE_ENCRYPTION_KEY=__RANDOM__".to_string()
}

/// The one id SSO must never stand in front of, whatever the request says —
/// a port of `AutheliaService.neverProtected`. The mesh control server is what
/// a device contacts before it has any way in, and `tailscale up` cannot do a
/// browser login: the gate does not ask it for a password, it makes joining
/// impossible. Filtered here rather than trusted to the client, because a
/// deployment saved before the exclusion existed still names it.
pub const NEVER_PROTECTED: &[&str] = &["headscale"];

/// Which services this host protects — the request's list when it carries one,
/// the default otherwise, intersected with what is actually installed and with
/// `NEVER_PROTECTED` taken out.
///
/// The intersection is not tidiness: a rule naming a site that does not exist
/// is harmless, but a rule MISSING for a site that does is a page the portal
/// refuses (`default_policy: deny`), which reads as the service being broken.
pub fn protected_ids(input: &Input, services: &[String]) -> Vec<String> {
    let wanted: Vec<&str> = match &input.authelia_protected {
        AutheliaProtection::Default => DEFAULT_PROTECTED.to_vec(),
        // Explicit, including explicitly empty — see the field's own doc.
        AutheliaProtection::Explicit(ids) => ids.iter().map(String::as_str).collect(),
    };
    super::host::CATALOG_ORDER
        .iter()
        .filter(|id| {
            wanted.contains(id) && services.iter().any(|s| s == *id) && !NEVER_PROTECTED.contains(id)
        })
        .map(|id| (*id).to_string())
        .collect()
}

/// The site NAMES SSO stands in front of — each protected service's hostname
/// plus its mirrors, because the rule matches the name the browser used.
pub fn protected_hostnames(input: &Input, services: &[String]) -> Vec<String> {
    let mut names = Vec::new();
    for id in protected_ids(input, services) {
        let Some(host) = super::catalog::web_hostname(&id, input) else { continue };
        names.push(host.clone());
        names.extend(input.mirrored_hostnames(&host));
    }
    names
}

pub fn configuration_yaml(input: &Input, services: &[String]) -> String {
    let portal = hostname(input);
    let names = protected_hostnames(input, services);
    // **`deny` is REFUSED by the portal when there are no rules, and that is
    // not a warning — it is a container that cannot start.**
    //
    //   access_control: 'default_policy' option 'deny' is invalid: when no
    //   rules are specified it must be 'two_factor' or 'one_factor'
    //
    // Measured on a live host against the pinned 4.39.20. "Protect nothing" is
    // a real answer the owner can give — the whole reason an EMPTY list is a
    // different instruction from an absent one — so this combination is
    // reachable, and it produced a permanent restart loop: the exact failure a
    // dead portal causes, which GOTCHAS records as taking every protected site
    // down with it.
    //
    // With no rules the default applies to nothing (no site carries
    // `forward_auth`), so the value is inert; `two_factor` is chosen because it
    // is the STRICTER of the two the portal will accept, which keeps the
    // meaning the `deny` was there for — nothing is silently let through.
    let default_policy = if names.is_empty() { "two_factor" } else { "deny" };
    let rules = if names.is_empty() {
        "  rules: []".to_string()
    } else {
        let body: Vec<String> = names
            .iter()
            .map(|name| format!("    - domain: '{name}'\n      policy: one_factor"))
            .collect();
        format!("  rules:\n{}", body.join("\n"))
    };
    format!(
        "---\ntheme: light\nserver:\n  address: 'tcp://0.0.0.0:{CONTAINER_WEB_PORT}'\nlog:\n  level: info\nauthentication_backend:\n  file:\n    path: /config/users_database.yml\naccess_control:\n  # Anything not named below is not reachable through the portal. A\n  # permissive default here would put every future site behind SSO the\n  # day it is created, including the ones whose mobile apps cannot use\n  # it.\n  default_policy: {default_policy}\n{rules}\nsession:\n  cookies:\n    - name: authelia_session\n      domain: '{domain}'\n      authelia_url: 'https://{portal}'\nstorage:\n  local:\n    path: /config/db.sqlite3\nnotifier:\n  # A file, not mail: password reset is the only thing this notifies\n  # about, and a mail server is not something this deployment is\n  # guaranteed to have. The file is inside the config volume and\n  # readable only by root.\n  filesystem:\n    filename: /config/notification.txt",
        domain = input.domain
    )
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// **`admin_guard` is FALSE here, and copying it from a neighbour would be
/// catastrophic.** The guard restricts a site to the VPN; this is the site
/// somebody has to reach in order to log in to the sites that ARE restricted.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: false, upstream_https: false, public_paths: Vec::new() }
}

pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    /// The portal itself is never behind the guard — see `web_ingress`.
    #[test]
    fn the_portal_is_not_behind_the_admin_guard() {
        assert!(!web_ingress(&base("example.com")).admin_guard);
        assert!(!caddy_site(&base("example.com")).contains("admin-guard"));
    }

    /// A rule is written only for a service that is actually installed: the
    /// portal denies by default, so a MISSING rule is a page it refuses.
    #[test]
    fn only_installed_services_get_a_rule() {
        let input = base("example.com");
        let yaml = configuration_yaml(&input, &["authelia".to_string(), "adguard-home".to_string()]);
        assert!(yaml.contains("- domain: 'dns.example.com'"), "{yaml}");
        assert!(!yaml.contains("start.example.com"), "homepage is not installed here: {yaml}");
        assert!(yaml.contains("default_policy: deny"), "{yaml}");
    }

    /// A host with nothing protected still produces a VALID file — an empty
    /// rule list, not a missing key.
    ///
    /// **And a default policy the portal will ACCEPT.** `deny` with no rules is
    /// refused outright by 4.39.20 — "when no rules are specified it must be
    /// 'two_factor' or 'one_factor'" — and the refusal is fatal, so the
    /// container restart-loops for ever. Found on a live host 2026-08-22, on
    /// the configuration the owner gets by protecting nothing, which is a
    /// choice this catalog deliberately supports.
    #[test]
    fn nothing_protected_is_still_a_valid_file() {
        let input = base("example.com");
        let yaml = configuration_yaml(&input, &["authelia".to_string()]);
        assert!(yaml.contains("  rules: []"), "{yaml}");
        // The stricter of the two the portal accepts, so "nothing is let
        // through by default" still holds.
        assert!(yaml.contains("default_policy: two_factor"), "{yaml}");
        assert!(!yaml.contains("default_policy: deny"), "deny with no rules will not start: {yaml}");
    }

    /// **"Guard nothing" and "the app never said" are different answers, and
    /// as a plain list they were the same value.** Found by trying to install
    /// a portal that guards nothing — on a host where two of the default set
    /// were installed, so the default coming back was a real gate nobody
    /// asked for.
    #[test]
    fn an_explicitly_empty_list_guards_nothing_while_an_absent_one_takes_the_default() {
        let installed = vec!["authelia".to_string(), "pihole".to_string()];

        let mut explicit = base("example.com");
        explicit.authelia_protected = AutheliaProtection::Explicit(Vec::new());
        assert!(protected_ids(&explicit, &installed).is_empty(),
                "unticking every service has to mean every service");

        let absent = base("example.com");
        assert_eq!(absent.authelia_protected, AutheliaProtection::Default);
        assert_eq!(protected_ids(&absent, &installed), vec!["pihole".to_string()],
                   "an app that never mentioned the setting still gets the default set");
    }

    /// Every name the browser can use, because the rule matches the name.
    #[test]
    fn mirrors_get_their_own_rule() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        let yaml = configuration_yaml(&input, &["authelia".to_string(), "adguard-home".to_string()]);
        assert!(yaml.contains("- domain: 'dns.example.com'"), "{yaml}");
        assert!(yaml.contains("- domain: 'dns.example.org'"), "{yaml}");
    }

    /// **The dispatcher that makes the gate real must know every site.** The
    /// portal rewrites the sites it guards; a protected service the renderer
    /// cannot draw would get a rule in the portal and no check in Caddy —
    /// installed, and guarding nothing, which is the exact defect this whole
    /// mechanism was added to fix (found on a live host).
    #[test]
    fn every_service_the_default_set_names_can_actually_be_rendered() {
        let input = base("example.com");
        for id in DEFAULT_PROTECTED {
            assert!(
                super::super::catalog::site_for(id, &input, true).is_some(),
                "{id} is protected by default but its site cannot be rendered"
            );
        }
    }

    /// And what a rendered guarded site actually carries.
    #[test]
    fn a_guarded_site_carries_the_forward_auth_check() {
        let input = base("example.com");
        let (_, guarded) = super::super::catalog::site_for("pihole", &input, true).expect("renderable");
        let (_, plain) = super::super::catalog::site_for("pihole", &input, false).expect("renderable");
        assert!(guarded.contains("forward_auth 127.0.0.1:8094"), "{guarded}");
        assert!(guarded.contains("/api/authz/forward-auth"), "{guarded}");
        assert!(!plain.contains("forward_auth"), "an unguarded site must be untouched: {plain}");
    }

    /// The default is the surfaces with no app of their own — and it must NOT
    /// include the ones whose mobile clients a gate would break.
    #[test]
    fn the_default_set_excludes_everything_with_a_mobile_client() {
        for breakable in ["nextcloud", "immich", "vaultwarden", "seafile", "photoprism"] {
            assert!(!DEFAULT_PROTECTED.contains(&breakable), "{breakable} must not be protected by default");
        }
    }
}

/// Byte-for-byte parity against REAL Swift-generated output.
///
/// **Two of these carry the design.** `configuration.yml` names the sites the
/// portal stands in front of, derived from different sources on the two sides
/// — so only the rendered file can say they agree. And the last pair asserts
/// the thing the whole approach rests on: a site nobody protected renders
/// exactly the bytes it rendered before SSO existed.
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn ids(scenario: &str, kind: &str) -> Vec<String> {
        fixture(&format!("{scenario}__{kind}.txt"))
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    fn ingress_text(ingress: &WebIngress) -> String {
        format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}",
            ingress.hostname, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https
        )
    }

    fn assert_parity(input: &mut Input, scenario: &str) {
        let services = ids(scenario, "service-ids");
        assert!(!services.is_empty(), "{scenario}: the id fixture is empty — the test would prove nothing");
        // Driven from the SAME list the Swift half was given, rather than one
        // retyped into this test.
        input.authelia_protected = AutheliaProtection::Explicit(ids(scenario, "protected-ids"));

        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(env_template(), fixture(&format!("{scenario}__env.template")), "{scenario}: env.template");
        assert_eq!(hostname(input), fixture(&format!("{scenario}__hostname.txt")), "{scenario}: hostname.txt");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames.txt"
        );
        assert_eq!(caddy_site(input), fixture(&format!("{scenario}__caddy-site.txt")), "{scenario}: caddy-site.txt");
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("{scenario}__ingress.txt")),
            "{scenario}: ingress.txt"
        );
        assert_eq!(
            protected_hostnames(input, &services).join("\n"),
            fixture(&format!("{scenario}__protected.txt")),
            "{scenario}: protected.txt"
        );
        assert_eq!(
            configuration_yaml(input, &services),
            fixture(&format!("{scenario}__configuration.yml")),
            "{scenario}: configuration.yml"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity(&mut base("example.com"), "authelia-default-public-en");
    }

    #[test]
    fn nothing_protected_public_en() {
        assert_parity(&mut base("example.com"), "authelia-nothing-protected-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert_parity(&mut input, "authelia-mirrored-public-en");
    }

    /// An explicit set that is NOT the default, including a service whose
    /// mobile client a gate breaks — the owner may choose that, and both sides
    /// have to write the same file when they do.
    #[test]
    fn custom_set_public_en() {
        assert_parity(&mut base("example.com"), "authelia-custom-set-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&mut input, "authelia-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.authelia_hostname = "login.example.com".to_string();
        assert_parity(&mut input, "authelia-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.authelia_path = "/srv/authelia".to_string();
        assert_parity(&mut input, "authelia-custompath-public-en");
    }

    /// The guard of the whole approach: an unprotected site is byte-identical
    /// to what it was before this service existed, and a protected one carries
    /// the block in the right place.
    #[test]
    fn a_site_is_unchanged_unless_it_is_protected() {
        assert_eq!(
            caddy::site("adguard-home", "dns.example.com", 8087, true, false, false),
            fixture("authelia-site-unprotected__caddy-site.txt")
        );
        assert_eq!(
            caddy::site_with_sso("adguard-home", "dns.example.com", 8087, true, false, false, true),
            fixture("authelia-site-protected__caddy-site.txt")
        );
    }

    /// **The mesh control server is never put behind the portal, even when the
    /// request names it.** `tailscale up` cannot follow a browser login, so the
    /// gate does not ask a device for a password — it makes joining the mesh
    /// impossible, exactly as the VPN guard did. The filter lives here rather
    /// than in the client because a deployment saved before this existed still
    /// carries the id.
    #[test]
    fn the_mesh_control_server_is_never_protected_even_when_asked_for() {
        let mut input = Input::default();
        input.domain = "example.com".to_string();
        input.authelia_protected =
            AutheliaProtection::Explicit(vec!["headscale".to_string(), "homepage".to_string()]);
        let services = vec!["headscale".to_string(), "homepage".to_string(), "authelia".to_string()];
        let ids = protected_ids(&input, &services);
        assert!(!ids.iter().any(|id| id == "headscale"), "the mesh would become unjoinable: {ids:?}");
        assert!(ids.iter().any(|id| id == "homepage"), "the rest of the list must still be honoured");
        let yaml = configuration_yaml(&input, &services);
        assert!(!yaml.contains("mesh.example.com"), "no rule may name the control server");
    }
}
