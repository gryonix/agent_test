//! Passbolt's declarative install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/PassboltService.swift`,
//! declarative half only. The imperative half (directories, the readiness
//! wait, the one-time admin invitation, pull/up) lives in `execute.rs` next
//! to the other services'.
//!
//! **Third product on the `passwords` shelf**, closing it alongside
//! Vaultwarden and Psono: same `preferOne` shelf, own hostname, no conflict
//! in the catalog.
//!
//! **Two containers, GPG-based, and no administrator secret to generate at
//! all.** Passbolt plus its own MariaDB, same shape as PhotoPrism's compose
//! file. Unlike every other service in this port, `envTemplate` carries no
//! administrator credential — only the two database passwords — because
//! Passbolt's server holds no key that could set one: every account's
//! private key is generated CLIENT-SIDE in the browser. The CLI can create a
//! PENDING invitation and nothing more (`cake passbolt register_user`
//! returns a one-time setup URL), which is why this module's imperative
//! sibling ends up narrating a URL instead of a password — see
//! `execute::provision_passbolt`'s own doc.
//!
//! **The server's own GPG keypair is generated automatically on first
//! start**, with no environment variable and nothing this service has to
//! drive — the image's entrypoint batch-generates it the moment
//! `PASSBOLT_GPG_SERVER_KEY_PRIVATE`'s bind-mounted path is empty. That
//! file's existence is both this service's readiness signal AND its
//! "already invited once" signal, exactly as `PassboltService.setupSteps`'s
//! own comment explains.

use super::caddy::{self, WebIngress};
use super::context::Input;

/// Exact patch tag (`<version>-<build>-ce`), never upstream's own
/// `latest-ce`. arm64 confirmed at the MANIFEST level only (Docker Hub's tags
/// API lists a real `arm64` record for this exact tag) — this sandbox has no
/// docker/skopeo to check the ELF header the way `seafileltd/seafile-mc` was
/// checked, so that stronger claim is not made here either.
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "passbolt";

pub const IMAGE: &str = "passbolt/passbolt:5.14.3-1-ce";
/// MariaDB 10.11 — the pin in Passbolt's own official
/// `docker-compose-ce.yaml`, and also what this catalog already runs for
/// Seafile.
pub const DATABASE_IMAGE: &str = "mariadb:10.11";
pub const COMPOSE_PROJECT: &str = "passbolt";
pub const CONTAINER: &str = "passbolt";
/// Loopback port Caddy proxies to — distinct from every other upstream in
/// the catalog (8089 Psono, 8090 here).
pub const WEB_UI_PORT: u16 = 8090;

/// A port of `PassboltService.hostname(_:)`. `passbolt.<domain>` by default;
/// Vaultwarden and Psono hold their own names on the same `preferOne` shelf.
pub fn hostname(input: &Input) -> String {
    if input.passbolt_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.passbolt_hostname.clone()
    }
}

/// A port of `PassboltService.adminLogin(_:)`. Passbolt has no bare-username
/// login of its own — the account name in its UI IS the email — so this is
/// built from the shared admin name for one consistent identity across
/// services, the same construction Seafile and Psono use.
pub fn admin_login(input: &Input) -> String {
    format!("{}@{}", input.admin_username, input.domain)
}

/// A port of `PassboltService.secretsPath(_:)` (private in Swift, exposed
/// here because the imperative half needs it too).
pub fn secrets_path(input: &Input) -> String {
    format!("{}/secrets", input.passbolt_path)
}

/// A port of `PassboltService.gpgPrivateKeyPath(_:)` — the file whose
/// existence is both "the server finished its first start" and "an earlier
/// run already sent the one-time invitation".
pub fn gpg_private_key_path(input: &Input) -> String {
    format!("{}/gpg/serverkey_private.asc", secrets_path(input))
}

/// A port of `PassboltService.registrationURLPath(_:)` — where the
/// imperative half leaves the one-time admin setup URL. The only secret this
/// service ever persists on the host outside the container's own volumes,
/// and not a password: see the module doc for why there is no password to
/// persist instead.
pub fn registration_url_path(input: &Input) -> String {
    format!("{}/.registration-url", input.passbolt_path)
}

/// A port of `PassboltService.composeFile(_:).composeContents`, comments
/// included — they are part of the file the Swift generator writes.
///
/// Two of those comments are load-bearing and stay verbatim: `MYSQL_ROOT_
/// PASSWORD` is explicit rather than upstream's own randomized-and-discarded
/// default (the shared backup wrapper always dumps as root, reading it out
/// of the container's OWN environment), and the `command:` override is
/// upstream's own `wait-for.sh` kept verbatim ahead of the entrypoint that
/// generates the GPG keypair and installs the schema.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.passbolt_path;
    let secrets = secrets_path(input);
    let host = hostname(input);
    format!(
        "services:\n  db:\n    image: {DATABASE_IMAGE}\n    restart: unless-stopped\n    environment:\n      # Explicit, NOT upstream's own MYSQL_RANDOM_ROOT_PASSWORD:\n      # the shared backup wrapper always dumps as root, reading\n      # MYSQL_ROOT_PASSWORD out of the container's OWN\n      # environment — a randomized-and-discarded root password\n      # would make this service's own backups impossible.\n      MYSQL_ROOT_PASSWORD: ${{PASSBOLT_DB_ROOT_PASSWORD}}\n      MYSQL_DATABASE: passbolt\n      MYSQL_USER: passbolt\n      MYSQL_PASSWORD: ${{PASSBOLT_DB_PASSWORD}}\n    volumes:\n      - {path}/db:/var/lib/mysql\n  passbolt:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    depends_on:\n      - db\n    environment:\n      APP_FULL_BASE_URL: https://{host}\n      DATASOURCES_DEFAULT_HOST: db\n      DATASOURCES_DEFAULT_USERNAME: passbolt\n      DATASOURCES_DEFAULT_PASSWORD: ${{PASSBOLT_DB_PASSWORD}}\n      DATASOURCES_DEFAULT_DATABASE: passbolt\n    volumes:\n      - {secrets}/gpg:/etc/passbolt/gpg\n      - {secrets}/jwt:/etc/passbolt/jwt\n    # `depends_on` only waits for the db CONTAINER to start, not\n    # for MariaDB to accept connections — this is upstream's own\n    # wait, kept verbatim, ahead of the entrypoint that generates\n    # the GPG keypair and installs the schema.\n    command:\n      [\n        \"/usr/bin/wait-for.sh\",\n        \"-t\",\n        \"0\",\n        \"db:3306\",\n        \"--\",\n        \"/docker-entrypoint.sh\",\n      ]\n    ports:\n      # Caddy terminates TLS and speaks plain HTTP to this port —\n      # the community has documented this exact shape (nginx or\n      # Caddy in front on 80, Passbolt never sees the TLS layer);\n      # unlike mailcow's nginx, nothing here redirects 80 to 443\n      # on its own. Port 443 is never published: this catalog's\n      # own self-signed listener has no certificate anyone trusts\n      # and Caddy already owns the public 443.\n      - \"127.0.0.1:{WEB_UI_PORT}:80\""
    )
}

/// A port of `PassboltService.composeFile(_:).envTemplate`: the two database
/// secrets only. Deliberately no administrator password here — see the
/// module doc for why the server holds nothing that could set one.
pub fn env_template() -> String {
    "PASSBOLT_DB_ROOT_PASSWORD=__RANDOM__\nPASSBOLT_DB_PASSWORD=__RANDOM__".to_string()
}

/// A port of `PassboltService.dnsHostnames(_:)`. Unreached in the binary for
/// the same reason AdGuard's is.
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `PassboltService.webIngress(_:)`.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
}

/// The Caddy site NAMES this ingress publishes — see
/// `adguard::caddy_site_names`.
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// A port of the Passbolt slice of `ServiceInfraSections.writeCaddyfile`.
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

    #[test]
    fn hostname_defaults_to_the_plain_vault_name_when_it_is_alone() {
        assert_eq!(hostname(&base("example.com")), "vault.example.com");
        let mut crowded = base("example.com");
        crowded.installed_services = vec![SERVICE_ID.to_string(), "vaultwarden".to_string()];
        assert_eq!(hostname(&crowded), "passbolt.example.com");
    }

    #[test]
    fn the_administrator_carries_the_domain_the_server_appends_itself() {
        let mut input = base("example.com");
        input.admin_username = "operator".to_string();
        assert_eq!(admin_login(&input), "operator@example.com");
    }

    /// Two secrets, not three — see the module doc for why there is no
    /// administrator password to generate for this service.
    #[test]
    fn the_env_template_asks_for_exactly_the_two_database_secrets() {
        assert_eq!(env_template().lines().filter(|l| l.ends_with("=__RANDOM__")).count(), 2);
        assert!(!env_template().contains("ADMIN"));
    }

    /// The backup wrapper reads this out of the container's own environment;
    /// the explicit value is what makes the dump possible at all (upstream's
    /// own default discards the root password after first start). Whether
    /// `MYSQL_RANDOM_ROOT_PASSWORD` appears ELSEWHERE (it legitimately does,
    /// in the comment explaining why it is not used) is covered byte-exactly
    /// by `fixture_parity` below — this test is only about the actual key.
    #[test]
    fn the_database_root_password_is_explicit_not_discarded() {
        let compose = compose_contents(&base("example.com"));
        assert!(compose.contains("MYSQL_ROOT_PASSWORD: ${PASSBOLT_DB_ROOT_PASSWORD}"));
    }

    /// The GPG/JWT volumes and the path the imperative half polls for must
    /// name the exact same file — a mismatch would mean the readiness signal
    /// this service polls for never appears where the container writes it.
    #[test]
    fn the_secrets_volumes_and_the_gpg_key_path_agree() {
        let input = base("example.com");
        assert_eq!(secrets_path(&input), "/opt/passbolt/secrets");
        assert_eq!(gpg_private_key_path(&input), "/opt/passbolt/secrets/gpg/serverkey_private.asc");
        let compose = compose_contents(&input);
        assert!(compose.contains("- /opt/passbolt/secrets/gpg:/etc/passbolt/gpg"));
        assert!(compose.contains("- /opt/passbolt/secrets/jwt:/etc/passbolt/jwt"));
    }

    #[test]
    fn the_hostname_reaches_the_app_url() {
        let mut input = base("example.com");
        input.passbolt_hostname = "secrets.example.com".to_string();
        assert!(compose_contents(&input).contains("APP_FULL_BASE_URL: https://secrets.example.com"));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — same
/// discipline as `adguard::fixture_parity`.
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
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

    fn assert_parity(input: &Input, scenario: &str) {
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
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base("example.com"), "pb-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "pb-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "pb-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.passbolt_hostname = "secrets2.example.com".to_string();
        assert_parity(&input, "pb-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.passbolt_path = "/srv/passbolt".to_string();
        assert_parity(&input, "pb-custompath-public-en");
    }

    /// The mirroring GUARD — see `adguard::fixture_parity`. Passbolt's
    /// compose file DOES carry the hostname (`APP_FULL_BASE_URL`), unlike
    /// Psono's, so this scenario proves the guard through all three
    /// artifacts that would otherwise carry a name nobody owns.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.passbolt_hostname = "passbolt.other-company.net".to_string();
        assert_parity(&input, "pb-foreignhost-mirrored-public-en");
    }
}
