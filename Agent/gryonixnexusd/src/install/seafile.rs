//! Seafile's declarative install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/SeafileService.swift`,
//! declarative half only. The imperative half (directories, pull/up, the
//! CSRF origins rewrite) lives in `execute.rs` next to the other services'.
//!
//! **Three containers**: the server, its own MariaDB and a small Redis used
//! purely as a cache. Nothing new for the executor — `docker compose up -d`
//! brings up whatever the file declares — and four independent `__RANDOM__`
//! secrets, one more than PhotoPrism's three.
//!
//! **The administrator is created BY US, from the environment.** Seafile has
//! no setup wizard to lose a race against: it reads
//! `INIT_SEAFILE_ADMIN_EMAIL`/`INIT_SEAFILE_ADMIN_PASSWORD` on the first
//! start. That is worse than a wizard rather than better — upstream's own
//! compose defaults them to `me@example.com`/`asecret`, so an instance
//! brought up without both set is a public URL with a documented password on
//! it. The login is an EMAIL (`<admin>@<domain>`, `admin_login` below)
//! because Seafile rejects the account otherwise.
//!
//! **`csrf_trusted_origins_line` is declarative content the IMPERATIVE half
//! writes**, which is why it lives here with the rest of the file contents
//! rather than in `execute.rs`. Every name the Caddy site answers on has to
//! appear in it: Caddy terminates TLS and speaks plain HTTP to the
//! container, whose internal nginx never forwards `X-Forwarded-Proto`, so
//! Django sees `http://` while the browser says `https://` and refuses every
//! sign-in POST with a CSRF error that reads exactly like a wrong password.
//! No fixture covers it (`setupSteps` was never dumped), so it is unit
//! tested here instead — and it is the one place in this module where the
//! MIRRORED names matter, not just the canonical one.

use super::caddy::{self, WebIngress};
use super::context::Input;

/// Exact patch tag — `13.0-latest` floats, and this catalog pins what it
/// ran. arm64 verified by ELF header inside the layer rather than by the
/// index's promise (the repository also publishes `-arm-testing` tags, which
/// is what a fake multi-arch index usually looks like).
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "seafile";

pub const IMAGE: &str = "seafileltd/seafile-mc:13.0.25";
/// MariaDB 10.11 — the version upstream's own compose pins, deliberately NOT
/// the `mariadb:11` the Nextcloud and PhotoPrism stacks share: Seafile builds
/// its three schemas on the first start, and a failure there is a dead
/// install rather than a degraded one.
pub const DATABASE_IMAGE: &str = "mariadb:10.11";
/// Cache only. Seafile 13 defaults `CACHE_PROVIDER` to redis and looks for a
/// host literally called `redis`; the image name still says "mc" (memcached),
/// which it was up to version 12, so the wrong companion leaves seahub
/// pointing at a host that does not exist.
pub const CACHE_IMAGE: &str = "redis:7-alpine";
pub const COMPOSE_PROJECT: &str = "seafile";
pub const CONTAINER: &str = "seafile";
/// The compose SERVICE key of the server itself — `db` and `redis` are the
/// other two. It happens to spell the same as `CONTAINER`, but the two are
/// addressed by different commands (`compose restart <service>` versus
/// `docker restart <container>`), and a service that ever renamed one of
/// them would need the other left alone.
pub const SERVER_SERVICE: &str = "seafile";
/// Loopback port Caddy proxies to — the container's own nginx on 80 fronts
/// seahub, the file server and WebDAV together.
pub const WEB_UI_PORT: u16 = 8088;

/// The settings file Seafile writes on its FIRST start, relative to the
/// `/shared` mount — the imperative half waits for it to appear and then
/// rewrites its CSRF line.
pub const SEAHUB_SETTINGS_RELATIVE_PATH: &str = "conf/seahub_settings.py";

/// The key the CSRF line is written under. Also the deletion anchor: the
/// bash version's `sed -i '/^CSRF_TRUSTED_ORIGINS = /d'` matches this exact
/// prefix, TRAILING SPACE INCLUDED, before appending the fresh line.
pub const CSRF_SETTING_PREFIX: &str = "CSRF_TRUSTED_ORIGINS = ";

/// A port of `SeafileService.hostname(_:)`. The default is
/// `files.<domain>`, NOT the `cloud.<domain>` Nextcloud already owns: the
/// `files` shelf is `preferOne`, so both products can stand side by side in
/// the advanced form, and two services on one Caddy site name would be one
/// certificate request with two upstreams.
pub fn hostname(input: &Input) -> String {
    if input.seafile_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.seafile_hostname.clone()
    }
}

/// A port of `SeafileService.adminLogin(_:)`: Seafile's login is an email
/// address, built from the shared admin name so the deployment still has ONE
/// administrator identity.
pub fn admin_login(input: &Input) -> String {
    format!("{}@{}", input.admin_username, input.domain)
}

/// A port of `SeafileService.dataPath(_:)` — where the container's `/shared`
/// bind mount lands: conf, ccnet, seafile-data, seahub-data and logs all
/// live under it.
pub fn data_path(input: &Input) -> String {
    format!("{}/data", input.seafile_path)
}

/// A port of `SeafileService.composeFile(_:).composeContents`, comments
/// included — they are part of the file the Swift generator writes.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.seafile_path;
    let data = data_path(input);
    let admin = admin_login(input);
    let host = hostname(input);
    format!(
        "services:\n  db:\n    image: {DATABASE_IMAGE}\n    restart: unless-stopped\n    environment:\n      # The shared backup wrapper dumps through this variable, read\n      # out of the container's OWN environment — a password passed\n      # from the host would sit in the argv of docker exec, where\n      # /proc hands it to every account. There is deliberately no\n      # MYSQL_DATABASE: Seafile owns three, and the backup plan\n      # names each one instead.\n      MYSQL_ROOT_PASSWORD: ${{SEAFILE_DB_ROOT_PASSWORD}}\n      MARIADB_AUTO_UPGRADE: \"1\"\n    volumes:\n      - {path}/db:/var/lib/mysql\n  redis:\n    image: {CACHE_IMAGE}\n    restart: unless-stopped\n    # Cache only, so persistence is off: an appendonly file here\n    # would be disk traffic for data that is rebuilt on demand.\n    # No password either — redis takes it as a command-line\n    # argument, which puts it in the process table where the host\n    # can read it, and it buys nothing over a port that is never\n    # published outside this project's own network.\n    command: [\"redis-server\", \"--save\", \"\", \"--appendonly\", \"no\"]\n  seafile:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    depends_on:\n      - db\n      - redis\n    environment:\n      SEAFILE_MYSQL_DB_HOST: db\n      SEAFILE_MYSQL_DB_PORT: \"3306\"\n      SEAFILE_MYSQL_DB_USER: seafile\n      SEAFILE_MYSQL_DB_PASSWORD: ${{SEAFILE_DB_PASSWORD}}\n      # Only used on the first start, to create the three schemas\n      # and the unprivileged user above.\n      INIT_SEAFILE_MYSQL_ROOT_PASSWORD: ${{SEAFILE_DB_ROOT_PASSWORD}}\n      SEAFILE_MYSQL_DB_CCNET_DB_NAME: ccnet_db\n      SEAFILE_MYSQL_DB_SEAFILE_DB_NAME: seafile_db\n      SEAFILE_MYSQL_DB_SEAHUB_DB_NAME: seahub_db\n      # The administrator, created on the first start. Left unset,\n      # Seafile creates me@example.com with the password `asecret`\n      # — a documented credential on a public hostname.\n      INIT_SEAFILE_ADMIN_EMAIL: {admin}\n      INIT_SEAFILE_ADMIN_PASSWORD: ${{SEAFILE_ADMIN_PASSWORD}}\n      # SERVICE_URL and FILE_SERVER_ROOT are derived from these two\n      # on every start, so they stay SINGLE-valued at the canonical\n      # name even though the Caddy site answers on the aliases too.\n      # The protocol must be https: it is what the browser speaks,\n      # and an http value here makes every download link a\n      # mixed-content block.\n      SEAFILE_SERVER_HOSTNAME: {host}\n      SEAFILE_SERVER_PROTOCOL: https\n      SITE_ROOT: /\n      NON_ROOT: \"false\"\n      TIME_ZONE: Etc/UTC\n      JWT_PRIVATE_KEY: ${{SEAFILE_JWT_PRIVATE_KEY}}\n      # SeaDoc is a SEPARATE container upstream ships in its own\n      # compose file. Left at its default (true) the server\n      # advertises a /sdoc-server endpoint that nothing answers, so\n      # opening a document fails with no explanation — off is the\n      # honest state of an install that does not include it.\n      ENABLE_SEADOC: \"false\"\n      CACHE_PROVIDER: redis\n      REDIS_HOST: redis\n      REDIS_PORT: \"6379\"\n    volumes:\n      - {data}:/shared\n    ports:\n      # The container runs its own nginx on 80, which fronts\n      # seahub, the file server and WebDAV on one port.\n      - \"127.0.0.1:{WEB_UI_PORT}:80\""
    )
}

/// A port of `SeafileService.composeFile(_:).envTemplate`: four independent
/// secrets, all generated on the server. `SEAFILE_JWT_PRIVATE_KEY` has to be
/// at least 32 characters and the generator emits 48 hex, so the shared
/// `__RANDOM__` expansion already satisfies it.
pub fn env_template() -> String {
    "SEAFILE_DB_ROOT_PASSWORD=__RANDOM__\nSEAFILE_DB_PASSWORD=__RANDOM__\nSEAFILE_JWT_PRIVATE_KEY=__RANDOM__\nSEAFILE_ADMIN_PASSWORD=__RANDOM__".to_string()
}

/// A port of `SeafileService.dnsHostnames(_:)`. Unreached in the binary for
/// the same reason AdGuard's is.
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `SeafileService.webIngress(_:)`.
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

/// A port of the Seafile slice of `ServiceInfraSections.writeCaddyfile`.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

/// A port of the `trustedOrigins` expression in `SeafileService.setupSteps`:
/// EVERY served name (the hostname plus its mirror on each additional
/// domain), as a Python list literal of `https://` origins.
///
/// The alias half is the whole point — Caddy holds a certificate for those
/// names, and a name the proxy serves but Django refuses is precisely the
/// bug this catalog has already paid for once (Nextcloud's "Access through
/// untrusted domain").
pub fn csrf_trusted_origins_line(input: &Input) -> String {
    let origins: Vec<String> =
        input.served_hostnames(&hostname(input)).iter().map(|name| format!("'https://{name}'")).collect();
    format!("{CSRF_SETTING_PREFIX}[{}]", origins.join(", "))
}

/// A port of the `sed`/`printf` pair that rewrites the CSRF line in
/// `seahub_settings.py`: every existing `CSRF_TRUSTED_ORIGINS = ` line is
/// dropped and the fresh one appended.
///
/// Rewritten on EVERY run rather than appended once, because the served name
/// list changes the moment the owner adds a domain and Seafile reads this
/// file only at start — the same reason Nextcloud re-applies its trusted
/// domains instead of trusting the first install. Everything else in the
/// file is preserved byte for byte, including whether it ended with a
/// newline: `sed -i` only deletes lines, and `printf '%s\n' >>` appends
/// exactly where the file happened to end.
pub fn rewritten_seahub_settings(existing: &str, csrf_line: &str) -> String {
    let mut out = String::with_capacity(existing.len() + csrf_line.len() + 1);
    for line in existing.split_inclusive('\n') {
        if line.trim_end_matches(['\n', '\r']).starts_with(CSRF_SETTING_PREFIX) {
            continue;
        }
        out.push_str(line);
    }
    out.push_str(csrf_line);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_defaults_to_files_not_cloud() {
        // `cloud.<domain>` belongs to Nextcloud; sharing it would mean one
        // certificate request with two upstreams.
        assert_eq!(hostname(&base("example.com")), "files.example.com");
    }

    /// Seafile rejects an administrator that is not an email address, and
    /// the local part is the deployment's ONE shared admin name.
    #[test]
    fn the_administrator_is_an_email_built_from_the_shared_admin_name() {
        let mut input = base("example.com");
        input.admin_username = "operator".to_string();
        assert_eq!(admin_login(&input), "operator@example.com");
        assert!(compose_contents(&input).contains("INIT_SEAFILE_ADMIN_EMAIL: operator@example.com"));
    }

    /// The backup wrapper reads this out of the container's own environment;
    /// and there must be no `MYSQL_DATABASE` at all — Seafile owns three
    /// schemas and the backup plan names each one instead, so a dump driven
    /// by a single database variable would carry a fraction of the service
    /// and still report success.
    #[test]
    fn the_database_names_no_single_schema_of_its_own() {
        let compose = compose_contents(&base("example.com"));
        assert!(compose.contains("MYSQL_ROOT_PASSWORD: ${SEAFILE_DB_ROOT_PASSWORD}"));
        // The KEY, not the word: the compose file's own comment explains
        // why the variable is absent, so a substring search would pass on
        // the explanation and prove nothing.
        assert!(
            !compose.lines().any(|line| line.trim_start().starts_with("MYSQL_DATABASE:")),
            "no MYSQL_DATABASE key may be set — the backup plan names all three schemas instead"
        );
    }

    #[test]
    fn the_env_template_asks_for_four_separate_secrets() {
        assert_eq!(env_template().lines().filter(|l| l.ends_with("=__RANDOM__")).count(), 4);
    }

    /// The mirrored names are the reason this line exists at all: Caddy
    /// serves them, so Django has to trust them.
    #[test]
    fn every_mirrored_name_reaches_the_trusted_origins() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert_eq!(
            csrf_trusted_origins_line(&input),
            "CSRF_TRUSTED_ORIGINS = ['https://files.example.com', 'https://files.example.org']"
        );
    }

    /// A hostname outside the primary domain mirrors nowhere — the same
    /// guard the `foreignhost` fixture scenario pins for the Caddy site.
    #[test]
    fn a_foreign_hostname_contributes_only_itself() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.seafile_hostname = "files.other-company.net".to_string();
        assert_eq!(
            csrf_trusted_origins_line(&input),
            "CSRF_TRUSTED_ORIGINS = ['https://files.other-company.net']"
        );
    }

    #[test]
    fn the_csrf_rewrite_replaces_the_old_line_and_keeps_everything_else() {
        let existing = "SECRET_KEY = 'x'\nCSRF_TRUSTED_ORIGINS = ['https://old.example.com']\nDEBUG = False\n";
        let rewritten = rewritten_seahub_settings(existing, "CSRF_TRUSTED_ORIGINS = ['https://files.example.com']");
        assert_eq!(
            rewritten,
            "SECRET_KEY = 'x'\nDEBUG = False\nCSRF_TRUSTED_ORIGINS = ['https://files.example.com']\n"
        );
    }

    /// Repeating the rewrite must not accumulate lines — the file Seafile
    /// reads at start has to hold exactly one of them.
    #[test]
    fn rewriting_twice_leaves_exactly_one_csrf_line() {
        let line = "CSRF_TRUSTED_ORIGINS = ['https://files.example.com']";
        let once = rewritten_seahub_settings("SECRET_KEY = 'x'\n", line);
        let twice = rewritten_seahub_settings(&once, line);
        assert_eq!(once, twice);
        assert_eq!(twice.matches(CSRF_SETTING_PREFIX).count(), 1);
    }

    /// A file that did not end in a newline is appended to exactly where it
    /// ended, which is what `>>` does — no invented separator.
    #[test]
    fn a_file_without_a_trailing_newline_is_left_as_it_was() {
        let rewritten = rewritten_seahub_settings("DEBUG = False", "CSRF_TRUSTED_ORIGINS = []");
        assert_eq!(rewritten, "DEBUG = FalseCSRF_TRUSTED_ORIGINS = []\n");
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
        assert_parity(&base("example.com"), "sf-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "sf-mirrored-public-en");
    }

    /// The only scenario whose compose file differs in the ADMIN LOGIN as
    /// well as the hostname — the login carries the domain, so a local-only
    /// deployment names `admin@home.local`.
    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "sf-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.seafile_hostname = "share.example.com".to_string();
        assert_parity(&input, "sf-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.seafile_path = "/srv/seafile".to_string();
        assert_parity(&input, "sf-custompath-public-en");
    }

    /// The mirroring GUARD — see `adguard::fixture_parity`.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.seafile_hostname = "files.other-company.net".to_string();
        assert_parity(&input, "sf-foreignhost-mirrored-public-en");
    }
}
