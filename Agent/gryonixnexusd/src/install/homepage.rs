//! Homepage's declarative install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/HomepageService.swift`.
//!
//! **The one service here whose configuration is about its NEIGHBOURS.**
//! `services.yaml` is generated from the list of services on the host, which is
//! the whole reason this product ships a start page at all: a page somebody
//! fills in by hand is a page they could have made without the app. On this
//! side the list comes from `host_service_ids` (discovery plus what is being
//! installed), on the Swift side from `ServiceContext.installedServices` — two
//! ways of answering the same question, which is exactly why the fixtures
//! compare the rendered file rather than the two code paths.
//!
//! **`HOMEPAGE_ALLOWED_HOSTS` is not optional.** Read out of the pinned
//! image's own middleware, not its docs: the allow-list is `localhost:3000`
//! and `127.0.0.1:3000` plus whatever that variable names, and a request whose
//! Host is not in it is answered with HTTP 400. Caddy forwards the real Host,
//! so every name of the site — mirrors included — has to be in the list.

use super::caddy::{self, WebIngress};
use super::context::Input;

/// Exact pinned tag. arm64 verified by the ELF header inside the layer:
/// `usr/local/bin/node` in the linux/arm64 manifest is a real AArch64 binary
/// (e_machine 0xB7).
/// The catalog id this module installs — the one written into its Caddy
/// block so a second service asking for the same names is refused rather
/// than silently replacing it. Held to the catalog by
/// `every_site_owner_is_a_catalog_id`, and to the Swift generator by the
/// byte-exact fixtures.
pub const SERVICE_ID: &str = "homepage";

pub const IMAGE: &str = "ghcr.io/gethomepage/homepage:v1.4.5";
pub const COMPOSE_PROJECT: &str = "homepage";
pub const CONTAINER: &str = "homepage";
/// Loopback port Caddy proxies to (8092 is Pi-hole's, 8091 headscale's).
pub const WEB_UI_PORT: u16 = 8093;
/// Port the app binds INSIDE the container — its own `PORT` default, which the
/// host-validation list is also keyed on.
pub const CONTAINER_WEB_PORT: u16 = 3000;

pub fn hostname(input: &Input) -> String {
    if input.homepage_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.homepage_hostname.clone()
    }
}

/// Every name the Caddy site answers on — the value `HOMEPAGE_ALLOWED_HOSTS`
/// has to carry. A port of `ServiceContext.servedHostnames(of:)` applied to
/// this service's hostname.
fn served_hostnames(input: &Input) -> Vec<String> {
    let host = hostname(input);
    let mut names = vec![host.clone()];
    names.extend(input.mirrored_hostnames(&host));
    names
}

pub fn compose_contents(input: &Input) -> String {
    let path = &input.homepage_path;
    let allowed = served_hostnames(input).join(",");
    format!(
        "services:\n  homepage:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      # Read out of the image's own middleware, not its docs: a\n      # request whose Host is not in this list is answered with\n      # HTTP 400 and nothing else. Caddy forwards the real Host,\n      # so every name of the site belongs here.\n      HOMEPAGE_ALLOWED_HOSTS: {allowed}\n    volumes:\n      - {path}/config:/app/config\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_WEB_PORT}\""
    )
}

/// A YAML scalar that cannot be read as anything else — single quotes with
/// doubling, YAML's own literal form. A port of `HomepageService.yamlScalar`.
fn yaml_scalar(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// One group per catalog category, one row per installed service, each
/// pointing at the hostname that service actually answers on.
///
/// `services` is the host's catalog ids; the ORDER of the groups is the
/// catalog's own (`CATALOG_ORDER` mirrors `ServiceRegistry`), not the order
/// they were passed in — the Swift side walks `ServiceRegistry.categories`,
/// and a page whose sections reshuffle between installs would be a different
/// file every run for no reason.
pub fn services_yaml(input: &Input, services: &[String]) -> String {
    let mut lines = vec!["---".to_string()];
    for (category_title, category_summary, members) in super::catalog::categories() {
        // Only what Caddy actually publishes, and the emptiness check runs
        // AFTER that filter — a group header with no rows under it is a YAML
        // key with a null value, which draws as an empty box (Cloudflare
        // Tunnel publishes its names in Cloudflare, not here).
        let present: Vec<(&str, String)> = members
            .iter()
            // Itself excluded: a start page whose first row is the start page
            // is a joke the second time somebody sees it.
            .filter(|(id, _)| *id != "homepage" && services.iter().any(|s| s == id))
            .filter_map(|(id, display)| super::catalog::web_hostname(id, input).map(|host| (*display, host)))
            .collect();
        if present.is_empty() {
            continue;
        }
        lines.push(format!("- {}:", yaml_scalar(category_title)));
        for (display, host) in present {
            lines.push(format!("    - {}:", yaml_scalar(display)));
            lines.push(format!("        href: https://{host}"));
            lines.push(format!("        description: {}", yaml_scalar(category_summary)));
        }
    }
    lines.join("\n")
}

pub fn settings_yaml(input: &Input, services: &[String]) -> String {
    let used: Vec<String> = super::catalog::categories()
        .into_iter()
        .filter(|(_, _, members)| {
            members.iter().any(|(id, _)| {
                *id != "homepage"
                    && services.iter().any(|s| s == id)
                    // Same rule as the page: a layout entry for a group the
                    // page does not draw is a name Homepage cannot place.
                    && super::catalog::web_hostname(id, input).is_some()
            })
        })
        .map(|(title, _, _)| format!("{}:\n    style: row\n    columns: 3", yaml_scalar(title)))
        .collect();
    format!(
        "---\ntitle: {}\nheaderStyle: boxed\nlayout:\n  {}",
        yaml_scalar(&input.domain),
        used.join("\n  ")
    )
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
}

pub fn caddy_site_names(input: &Input) -> Vec<String> {
    served_hostnames(input)
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

    /// The line that decides whether the page works behind the proxy at all.
    #[test]
    fn allowed_hosts_carries_every_name_the_site_answers_on() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        let compose = compose_contents(&input);
        assert!(
            compose.contains("HOMEPAGE_ALLOWED_HOSTS: start.example.com,start.example.org"),
            "a missing mirror is a page that loads and then answers 400 on every call: {compose}"
        );
    }

    /// A service pointed at a hostname of its own is NOT mirrored onto the
    /// deployment's other domains — Caddy would ask for a certificate for a
    /// name nobody owns, and the allow-list would advertise it.
    #[test]
    fn a_foreign_hostname_is_not_mirrored() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.homepage_hostname = "start.other-company.net".to_string();
        assert_eq!(served_hostnames(&input), vec!["start.other-company.net".to_string()]);
    }

    /// The page never lists itself, and lists nothing for a host with nothing
    /// on it — the empty page is a working answer, not an error.
    #[test]
    fn the_page_never_lists_itself() {
        let input = base("example.com");
        let only_itself = services_yaml(&input, &["homepage".to_string()]);
        assert_eq!(only_itself, "---");
        let with_others = services_yaml(&input, &["homepage".to_string(), "vaultwarden".to_string()]);
        assert!(with_others.contains("https://vault.example.com"), "{with_others}");
        assert!(!with_others.contains("start.example.com"), "{with_others}");
    }

    /// A service with no web face has no row: a link that leads nowhere is
    /// worse than no link.
    #[test]
    fn a_service_without_a_web_face_gets_no_row() {
        let input = base("example.com");
        let yaml = services_yaml(&input, &["shadowsocks".to_string(), "vaultwarden".to_string()]);
        assert!(yaml.contains("https://vault.example.com"), "{yaml}");
        assert!(!yaml.to_lowercase().contains("shadowsocks"), "{yaml}");
    }
}

/// Byte-for-byte parity against REAL Swift-generated output.
///
/// **This one carries more weight than the other ports' parity tests.** The
/// two sides derive the page from DIFFERENT sources — Swift from
/// `ServiceContext.installedServices`, this crate from `host_service_ids`
/// (discovery plus what is being installed) — so nothing but the rendered file
/// can say they agree. The service list itself comes out of a fixture too, so
/// the Rust half is driven by the same set the Swift half was, rather than by
/// one retyped into this test.
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
        let ids: Vec<String> = fixture(&format!("{scenario}__service-ids.txt"))
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        assert!(!ids.is_empty(), "{scenario}: the id fixture is empty — the test would prove nothing");
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
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
            services_yaml(input, &ids),
            fixture(&format!("{scenario}__services.yaml")),
            "{scenario}: services.yaml"
        );
        assert_eq!(
            settings_yaml(input, &ids),
            fixture(&format!("{scenario}__settings.yaml")),
            "{scenario}: settings.yaml"
        );
    }

    #[test]
    fn alone_public_en() {
        assert_parity(&base("example.com"), "homepage-alone-public-en");
    }

    /// The scenario that exercises the whole table: several shelves, both
    /// engines of one shelf, a VPN whose protocols have no web face and whose
    /// PANEL is the only row its group can have, and a service with no web
    /// face at all whose group must therefore not appear.
    #[test]
    fn full_public_en() {
        assert_parity(&base("example.com"), "homepage-full-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "homepage-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "homepage-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.homepage_hostname = "hub.example.com".to_string();
        assert_parity(&input, "homepage-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.homepage_path = "/srv/homepage".to_string();
        assert_parity(&input, "homepage-custompath-public-en");
    }

    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.homepage_hostname = "start.other-company.net".to_string();
        assert_parity(&input, "homepage-foreignhost-mirrored-public-en");
    }
}
