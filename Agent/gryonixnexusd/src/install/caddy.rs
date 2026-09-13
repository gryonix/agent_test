//! Caddy site rendering — a port of `ServiceInfraSections.caddySite`/the join
//! `writeCaddyfile` performs once every service's site is rendered
//! (`Packages/gryonixNexus/Sources/MailRecipe/Scripts/ServiceInfraSections.swift`).
//! Byte-exact, including the indentation Swift's multi-line string literals
//! bake in — `install::adguard`'s `fixture_parity` test diffs `site()`'s
//! output against REAL Caddyfile text the Swift generator produced, not a
//! re-reading of the Swift source.
//!
//! Shared infrastructure, not AdGuard-specific — every future install slice
//! that publishes a web UI needs the same site shape, which is why this
//! lives in its own module rather than folded into `adguard`.

/// A port of `WebIngress` (`ManagedService.swift`), reduced to the fields a
/// Caddy site actually needs. `admin_guard` DEFAULTS TO TRUE on the Swift
/// side (`ManagedService.swift`'s own doc: "the switch must cover EVERY web
/// page — per-service opt-out is a planned follow-up") — which is why
/// `AdGuardHomeService.webIngress` passes no argument for it at all and
/// still gets the guard imported into its site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebIngress {
    pub hostname: String,
    pub upstream_port: u16,
    pub admin_guard: bool,
    pub upstream_https: bool,
    /// URL path prefixes that answer the public internet even on a site the
    /// admin guard or single sign-on closes. Empty for every service but n8n
    /// — see `WebIngress.publicPaths` on the Swift side, and `site_with_sso`
    /// below for the shape it renders.
    pub public_paths: Vec<String>,
}

/// `VPNPanelService.adminGuardPath` on the Swift side — a contract with the
/// generated Caddyfile, not a value this module invents:
/// `ServiceInfraSections.writeCaddyfile` seeds this exact path with an empty
/// file before rendering any site, so every site's `import` always has
/// something to read. Also the THIRD path the agent's systemd unit needed
/// under `ReadWritePaths`/`ProtectSystem=full` (GOTCHAS.md, "Ф2 срез 7",
/// `SetLockdown` writing here is what surfaced it) — unrelated to this
/// slice, but the same literal, and a reminder that this path is read by
/// more than one part of the system.
pub const ADMIN_GUARD_PATH: &str = "/etc/caddy/gryonixnexus-admin-guard";

/// The `reverse_proxy` block — plain one-liner, or the nested TLS-skip form
/// an HTTPS-speaking upstream (mailcow's nginx) needs so Caddy does not loop
/// forever proxying plain HTTP into a redirect-to-HTTPS backend. AdGuard's
/// web UI is always plain HTTP, so its fixtures never exercise the `true`
/// branch — `site()` stays general because the next service slice needs it.
fn proxy_block(upstream_port: u16, upstream_https: bool, overwrite_forwarded_for: bool) -> String {
    if upstream_https {
        format!(
            "reverse_proxy https://127.0.0.1:{upstream_port} {{\n        transport http {{\n            tls_insecure_skip_verify\n        }}\n    }}"
        )
    } else if overwrite_forwarded_for {
        format!(
            "reverse_proxy 127.0.0.1:{upstream_port} {{\n        header_up X-Forwarded-For {{remote_host}}\n    }}"
        )
    } else {
        format!("reverse_proxy 127.0.0.1:{upstream_port}")
    }
}

/// **The line that says whose block this is.**
///
/// A Caddy site block is a list of names and nothing else, so until now the
/// file recorded no owner — and a second service asking for exactly the name
/// set another already served was indistinguishable from the first service
/// reinstalling. `merge_site` replaced the block, and the first service lost
/// its site with no error anywhere (owner, 2026-09-04, answering the question
/// this comment used to defer).
///
/// A comment rather than anything Caddy reads: it must not change what the
/// server does, only what the file says about itself. Inside the braces rather
/// than above the header, so the header stays the first line — `merge_site`,
/// `served_hostnames` and the uninstall wrapper's `awk` all key on it, and a
/// line before it would have moved all three.
fn owner_line(owner: &str) -> String {
    format!("# {OWNER_TAG} {owner}")
}

/// The prefix an owner line begins with. One literal, because the writer and
/// the reader below must agree and a second spelling is how they stop.
const OWNER_TAG: &str = "gryonixnexus:";

/// Name of the matcher the public-path branch is selected by, matching
/// `ServiceInfraSections.caddyPublicPathsMatcher`.
///
/// Deliberately NOT `gryonixnexus_public`: the admin guard's own file already
/// defines a matcher by that name. The two live in different scopes — the
/// guard is imported inside a `handle`, which Caddy gives its own matcher
/// namespace — but one name meaning "everyone may reach this" in one file and
/// "this request is from outside, refuse it" in the other is a trap for
/// whoever reads the rendered site next.
const PUBLIC_PATHS_MATCHER: &str = "gryonixnexus_open";

/// Whose block this is, or `None` when it does not say.
///
/// **`None` is not "nobody", it is "written before blocks said".** Every
/// Caddyfile already on a host predates this, and reading an unmarked block as
/// somebody else's would make every install on every existing host refuse a
/// site it has served for months. So an unmarked block belongs to whoever asks
/// — which is exactly the behaviour that shipped, kept deliberately rather
/// than by omission.
pub fn owner_of(block: &str) -> Option<String> {
    block.lines().skip(1).find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix('#')?.trim_start();
        rest.strip_prefix(OWNER_TAG)
            .map(|owner| owner.trim().to_string())
            .filter(|owner| !owner.is_empty())
    })
}

/// A byte-exact port of `ServiceInfraSections.caddySite`.
pub fn site(owner: &str, hostname: &str, upstream_port: u16, admin_guard: bool, upstream_https: bool, tls_internal: bool) -> String {
    site_with_sso(owner, hostname, upstream_port, admin_guard, upstream_https, tls_internal, false)
}

/// The same site, with Authelia's forward-auth check in front of it.
///
/// **`sso == false` returns exactly the bytes `site` always returned**, which
/// is what keeps every existing fixture valid and makes "nobody opted in"
/// indistinguishable from "this feature does not exist". The block goes AFTER
/// the admin guard and BEFORE the proxy: the guard decides whether the request
/// may reach this server at all, and asking somebody to log in to a site their
/// network is not allowed to open would be the wrong order.
pub fn site_with_sso(
    owner: &str,
    hostname: &str,
    upstream_port: u16,
    admin_guard: bool,
    upstream_https: bool,
    tls_internal: bool,
    sso: bool,
) -> String {
    site_with_public_paths(owner, hostname, upstream_port, admin_guard, upstream_https, tls_internal, sso, &[], false)
}

/// The same site again, with a list of path prefixes that stay reachable from
/// the public internet whatever the guard says. A port of the `publicPaths`
/// branch of `ServiceInfraSections.caddySite`.
///
/// **The split has to be `handle` blocks, and the guard has to move INSIDE one
/// of them — measured with `caddy adapt`, not reasoned about.** Caddy sorts
/// directives by its own table, and [`GLOBAL_OPTIONS`] moves `respond` ahead
/// of `forward_auth`, which puts it ahead of `handle` too. With the guard left
/// at the top of the site, the compiled route list begins with the guard's two
/// `static_response` 403s and the path matcher is not reached at all — the
/// webhook is refused and the file reads exactly as if it were not. Inside the
/// second `handle`, the same ordering is what makes it right: `respond` still
/// sorts before `reverse_proxy`, so the guard runs first in the branch it
/// belongs to and not at all in the branch it does not. Both shapes were run
/// through `caddy adapt` on Caddy 2.11.4 (2026-09-07): both adapt with no
/// error, and they differ only in the order of the compiled handlers.
///
/// An EMPTY list renders exactly the bytes `site_with_sso` always rendered,
/// which is what keeps every existing fixture valid. So does a non-empty list
/// on a site with neither guard nor sign-on: there is nothing to be exempt
/// from, and a second shape of an unrestricted site is only something for a
/// reader to reconcile.
pub fn site_with_public_paths(
    owner: &str,
    hostname: &str,
    upstream_port: u16,
    admin_guard: bool,
    upstream_https: bool,
    tls_internal: bool,
    sso: bool,
    public_paths: &[String],
    overwrite_forwarded_for: bool,
) -> String {
    let proxy = proxy_block(upstream_port, upstream_https, overwrite_forwarded_for);
    // Caddy obtains and renews the TLS certificate itself — unless
    // `tls_internal`, where the deployment has no public domain to run ACME
    // against and Caddy mints its own self-signed certificate instead (the
    // browser is trusted to accept it once, by hand).
    let tls_line = if tls_internal { "tls internal\n    " } else { "" };
    let sso_line = if sso {
        format!("{}\n    ", super::authelia::forward_auth_block())
    } else {
        String::new()
    };
    // FIRST inside the block, before anything Caddy acts on: a reader looking
    // at a strange site should learn whose it is from the same line every time.
    let owner = format!("{}\n    ", owner_line(owner));
    if !public_paths.is_empty() && (admin_guard || sso) {
        let guard_line =
            if admin_guard { format!("import {ADMIN_GUARD_PATH}\n        ") } else { String::new() };
        // Both pieces were rendered for a site block; one more level of braces
        // is one more level of indent on every line after the first.
        let nested = |block: &str| block.replace('\n', "\n    ");
        let proxy = nested(&proxy);
        let sso_line = nested(&sso_line);
        let paths = public_paths.join(" ");
        return format!(
            "{hostname} {{\n    {owner}{tls_line}@{PUBLIC_PATHS_MATCHER} path {paths}\n    handle @{PUBLIC_PATHS_MATCHER} {{\n        {proxy}\n    }}\n    handle {{\n        {guard_line}{sso_line}{proxy}\n    }}\n}}"
        );
    }
    if !admin_guard {
        format!("{hostname} {{\n    {owner}{tls_line}{sso_line}{proxy}\n}}")
    } else {
        format!("{hostname} {{\n    {owner}{tls_line}import {ADMIN_GUARD_PATH}\n    {sso_line}{proxy}\n}}")
    }
}

/// The same site, with Caddy overwriting `X-Forwarded-For` instead of
/// appending to it.
///
/// **One service needs this, and without it that service serves nothing.**
/// OpenClaw's gateway attributes every request to a client and refuses the
/// ones it cannot attribute — behind a proxy it does not trust, that is the
/// whole site, answered 403 `proxy_attribution`. Trusting the proxy is the
/// service's half (`openclaw::SEEDED_CONFIG`); overwriting the header is the
/// proxy's half, and its own documentation asks for exactly it: a proxy that
/// APPENDS lets a client put a forged address first in the list.
pub fn site_overwriting_forwarded_for(
    owner: &str,
    hostname: &str,
    upstream_port: u16,
    admin_guard: bool,
    upstream_https: bool,
    tls_internal: bool,
) -> String {
    site_with_public_paths(owner, hostname, upstream_port, admin_guard, upstream_https, tls_internal, false, &[], true)
}

/// A port of the join `ServiceInfraSections.writeCaddyfile` performs once
/// every service's site is rendered: `sites.joined(separator: "\n\n")`.
pub fn caddyfile(sites: &[String]) -> String {
    sites.join("\n\n")
}

/// Fold ONE service's site into an existing Caddyfile's text, touching only
/// that service's OWN previously-written block (if any) and leaving every
/// other site untouched.
///
/// `writeCaddyfile` on the Swift side always re-renders the WHOLE file from
/// every installed service's `Input` — this crate cannot do that yet (most
/// catalog services have no declarative port at all), so an install-time
/// executor that just wrote `caddyfile(&[this_one_site])` unconditionally
/// would delete every other site on the host the moment it reloaded Caddy.
/// This is the merge that avoids that: `existing` may be empty (no file
/// yet) or written by either this path or the SSH-script setup path — both
/// already join blocks the same way (this function's own `"\n\n"`), so
/// splitting on it reverses that join reliably regardless of which one
/// wrote the file, AS LONG AS no site's own body ever contains a blank
/// line — true of every `site()` output today (single-`\n` formatting
/// throughout, including the nested HTTPS-upstream branch).
///
/// `new_site_names` identifies the block to replace: the exact header a
/// PREVIOUS run of the SAME service would have written (its hostname plus
/// every domain it mirrors onto, in `site()`'s own join order) — an install
/// whose hostname or mirror list changed since the last run correctly drops
/// the stale block instead of leaving an orphaned one behind.
pub fn merge_site(existing: &str, new_site_names: &[String], new_site: &str) -> String {
    let header_prefix = format!("{} {{", new_site_names.join(", "));
    let mut blocks: Vec<String> = existing
        .split("\n\n")
        .map(str::trim)
        .filter(|block| !block.is_empty())
        .map(str::to_string)
        .collect();
    blocks.retain(|block| !block.starts_with(&header_prefix));
    blocks.push(new_site.to_string());
    // The global block, always first and exactly once — see GLOBAL_OPTIONS.
    // Added here rather than at file creation because a host may already have
    // a Caddyfile from the SSH route, from an older agent, or from a run that
    // predates this: every one of them needs the ordering, and every install
    // passes through this function.
    blocks.retain(|block| block != GLOBAL_OPTIONS);
    blocks.insert(0, GLOBAL_OPTIONS.to_string());
    caddyfile(&blocks)
}

/// Names this service wants that some OTHER block on the host already serves.
///
/// **Two blocks naming one host is not a duplicate line, it is the whole
/// file.** Caddy answers `ambiguous site definition` and refuses to adapt the
/// Caddyfile at all — measured against a live host's real file (vps-middle,
/// 2026-08-26). On a reload the previous config simply stays, so the service
/// that was installed silently never gets its site; on the next restart Caddy
/// has nothing valid to load and EVERY site on the machine is gone.
///
/// [`merge_site`] cannot see this, and should not: it replaces this service's
/// own block and leaves every other one alone, which is exactly right. What it
/// leaves alone is precisely where the collision lives, so the question is
/// asked here instead, before anything is written.
///
/// This service's OWN previous block is excluded by the same header rule
/// `merge_site` replaces on, so a reinstall never collides with itself — the
/// same rule the port preflight follows for a port held by its own project.
///
/// **The hole this used to leave, and how it is closed** (owner, 2026-09-04).
/// A block whose header was EXACTLY this service's was treated as this
/// service's own, because the Caddyfile recorded no owner — a site block is a
/// list of names and nothing else. So a second service asking for precisely
/// the name set another already served was not refused; `merge_site` replaced
/// the block and the first service quietly lost its site. Blocks now carry
/// `# gryonixnexus: <id>` and this asks it.
///
/// **Three answers, and only two of them existed before.** For a block whose
/// header matches ours:
/// * it names US — our own previous block, replaced, exactly as before. A
///   reinstall must never collide with itself, the same rule the port
///   preflight follows for a port held by its own project;
/// * it names NOBODY — written before blocks said whose they were, which is
///   every Caddyfile already on a host. Also ours, and deliberately: reading
///   an unmarked block as a stranger's would make the next install on every
///   existing host refuse a site it has been serving for months. That is the
///   difference the owner asked for in as many words;
/// * it names SOMEBODY ELSE — the case that used to be silent, now a refusal
///   before anything is written.
pub fn conflicting_names(existing: &str, new_site_names: &[String], owner: &str) -> Vec<String> {
    let own_header = format!("{} {{", new_site_names.join(", "));
    let others: String = existing
        .split("\n\n")
        .map(str::trim)
        .filter(|block| !block.is_empty())
        .filter(|block| {
            if !block.starts_with(&own_header) {
                return true;
            }
            // Same names: ours unless it says otherwise, in so many words.
            matches!(owner_of(block), Some(other) if other != owner)
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    let taken = served_hostnames(&others);
    new_site_names
        .iter()
        .filter(|name| taken.iter().any(|held| held.eq_ignore_ascii_case(name)))
        .cloned()
        .collect()
}

/// The Caddyfile's global block, byte-identical to
/// `ServiceInfraSections.caddyGlobalOptions`.
///
/// **`order respond before forward_auth` is what makes the admin guard work
/// at all on a site single sign-on protects.** Caddy sorts DIRECTIVES by its
/// own table rather than by the order they are written, and `forward_auth`
/// sorts ahead of `respond` — so a guarded site with SSO compiled to "ask the
/// portal first, refuse second", leaving the lockdown 403 unreachable while
/// the Caddyfile read exactly as though it applied. Measured on the production
/// host 2026-08-19 with `caddy adapt`: the guarded+SSO route began with
/// forward_auth's `reverse_proxy`; the guarded route WITHOUT SSO began with
/// the guard's `static_response`, which is the intended shape and the reason
/// it went unnoticed. Ordering against `reverse_proxy` instead changes
/// nothing — also measured.
pub const GLOBAL_OPTIONS: &str = "{\n\torder respond before forward_auth\n}";

/// The names this host actually serves, read back out of a Caddyfile.
///
/// **The file is the authority, and that is the point.** Every site block's
/// header IS the list of hostnames Caddy answers on — this module wrote them
/// (`site()` joins a service's hostname with the domains it mirrors onto), and
/// Caddy obtained a certificate for each. Nothing else on the box knows the
/// deployment's names: `state.db` stores services, not addresses, and the
/// host's own `hostname` is the machine's name (`nukki`), which is not a
/// domain at all.
///
/// Parses the same shape `merge_site` writes and `caddyfile` joins: blocks
/// separated by a blank line, each beginning `<names> {`. The global options
/// block has no names before its brace and falls out on its own.
pub fn served_hostnames(caddyfile: &str) -> Vec<String> {
    let mut names = Vec::new();
    for block in caddyfile.split("\n\n") {
        let Some(header) = block.trim().lines().next() else { continue };
        let Some(names_part) = header.trim().strip_suffix('{') else { continue };
        for name in names_part.split(',') {
            let name = name.trim();
            // The global block is `{` with nothing before it, and a site never
            // serves a name with a space or a scheme in it — anything that odd
            // is not a hostname we can hand to the app as one.
            if name.is_empty() || name.contains(char::is_whitespace) || name.contains("://") {
                continue;
            }
            if !names.iter().any(|existing| existing == name) {
                names.push(name.to_string());
            }
        }
    }
    names
}

/// The deployment's domains, worked out from the names it serves.
///
/// Returns the primary domain first, then the others. Every service name is
/// `<prefix>.<domain>`, so stripping one label off each served name gives a
/// candidate, and the candidate that the most names agree on is the primary
/// domain — the same reasoning a person applies reading the list.
///
/// **This is a derivation, not a record, and the app is told to treat it as
/// one.** A service pointed at a hostname of its own (which the catalog
/// explicitly allows — a name outside the deployment's domains is never
/// mirrored) contributes a candidate nobody else shares, and a host serving
/// exactly one service cannot be told apart from that case at all. So the
/// answer goes into the form as a PREFILLED FIELD the owner confirms, never
/// as a value saved behind their back: wrong here is a wrong address on every
/// service, and the person adding the server is the one who knows.
///
/// Ties are broken by name so two runs on one host answer identically —
/// a domain that changes between refreshes would be worse than none.
pub fn domains(served: &[String]) -> Vec<String> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for name in served {
        // A bare `example.com` (no prefix) is already a domain; anything with
        // one dot or fewer has no label to strip.
        let Some((_, rest)) = name.split_once('.') else { continue };
        if !rest.contains('.') {
            continue;
        }
        match counts.iter_mut().find(|(candidate, _)| candidate == rest) {
            Some((_, count)) => *count += 1,
            None => counts.push((rest.to_string(), 1)),
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    counts.into_iter().map(|(domain, _)| domain).collect()
}

#[cfg(test)]
mod tests {

    // ------------------------------------------------- one name, one service

    /// A host already serving two services, each under its own single name,
    /// each block saying whose it is.
    fn two_site_file() -> String {
        merge_site(
            &merge_site("", &["dns.example.com".to_string()],
                        &site("adguard-home", "dns.example.com", 8080, false, false, false)),
            &["cloud.example.com".to_string()],
            &site("nextcloud", "cloud.example.com", 8081, false, false, false),
        )
    }

    /// The same host as it looked before blocks carried an owner — which is
    /// every host this product has already installed on.
    fn two_site_file_without_owners() -> String {
        merge_site(
            &merge_site("", &["dns.example.com".to_string()], "dns.example.com {\n\treverse_proxy 127.0.0.1:8080\n}"),
            &["cloud.example.com".to_string()],
            "cloud.example.com {\n\treverse_proxy 127.0.0.1:8081\n}",
        )
    }

    /// **The catastrophe, caught before it is written.** A service that mirrors
    /// onto several domains has a header of its own, so its block replaces
    /// nobody's — both blocks stay, they name one host between them, and Caddy
    /// refuses to adapt the WHOLE file. The cost of one misconfigured service
    /// is every other site on the machine.
    #[test]
    fn a_name_another_block_already_serves_is_a_conflict() {
        let taken = conflicting_names(
            &two_site_file(),
            &["dns.example.com".to_string(), "dns.example.org".to_string()],
            "immich",
        );
        assert_eq!(taken, vec!["dns.example.com".to_string()]);
    }

    /// Case is not a difference to a hostname, and must not be one here: Caddy
    /// would still call the pair ambiguous.
    #[test]
    fn the_conflict_is_found_regardless_of_case() {
        let taken = conflicting_names(
            &two_site_file(),
            &["DNS.Example.COM".to_string(), "extra.example.org".to_string()],
            "immich",
        );
        assert_eq!(taken, vec!["DNS.Example.COM".to_string()]);
    }

    /// **A reinstall is not a conflict with itself.** The same rule the port
    /// preflight follows for a port held by its own project — without this the
    /// second install of any service would be refused.
    #[test]
    fn a_service_does_not_conflict_with_its_own_previous_block() {
        assert!(conflicting_names(&two_site_file(), &["cloud.example.com".to_string()], "nextcloud").is_empty());
    }

    /// **The hole this change closes: a DIFFERENT service asking for exactly
    /// the names another already serves.** It used to be indistinguishable
    /// from the first service reinstalling — same header, and the file said
    /// nothing about whose block it was — so `merge_site` replaced it and the
    /// first service lost its site with no error anywhere.
    #[test]
    fn another_service_asking_for_the_same_names_is_a_conflict() {
        let taken = conflicting_names(&two_site_file(), &["cloud.example.com".to_string()], "immich");
        assert_eq!(taken, vec!["cloud.example.com".to_string()],
                   "a stranger's block with our exact names was taken for our own");
    }

    /// **And the half that must NOT change: an UNMARKED block belongs to
    /// whoever asks.** Every Caddyfile already on a host was written before
    /// blocks said whose they were. Reading those as a stranger's would refuse
    /// the next install of a site the deployment has been serving for months —
    /// the difference the owner asked for in as many words.
    #[test]
    fn a_block_from_before_owners_existed_is_never_somebody_elses() {
        assert!(
            conflicting_names(&two_site_file_without_owners(),
                              &["cloud.example.com".to_string()], "nextcloud").is_empty(),
            "an install was refused a site it has been serving since before blocks said whose they were"
        );
        // Even for a service that is NOT the one which wrote it: nothing on
        // the host can tell, and refusing on a guess is the expensive answer.
        assert!(
            conflicting_names(&two_site_file_without_owners(),
                              &["cloud.example.com".to_string()], "immich").is_empty()
        );
    }

    /// A service bringing a name nobody serves is what the ordinary case looks
    /// like — the negative half, so the check above is not simply refusing.
    #[test]
    fn a_fresh_name_is_not_a_conflict() {
        assert!(conflicting_names(&two_site_file(), &["mc.example.com".to_string()], "crafty-controller").is_empty());
    }

    /// Only the taken names are named, so the message can say which one to
    /// change rather than which service to give up on.
    #[test]
    fn only_the_names_that_are_taken_are_reported() {
        let taken = conflicting_names(
            &two_site_file(),
            &["mc.example.com".to_string(), "dns.example.com".to_string()],
            "crafty-controller",
        );
        assert_eq!(taken, vec!["dns.example.com".to_string()]);
    }
    use super::*;

    #[test]
    fn served_names_come_back_out_of_a_file_this_module_wrote() {
        let file = merge_site(
            &merge_site("", &["vault.example.com".into()],
                        &site("vaultwarden", "vault.example.com", 8080, false, false, false)),
            &["mail.example.com".into(), "mail.alias.com".into()],
            // Mirrors ride in the header as one joined string — that is how
            // every caller builds a site (`caddy_site_names(...).join(", ")`),
            // and therefore the shape this has to read back.
            &site("mailcow", "mail.example.com, mail.alias.com", 8443, false, true, false),
        );
        let names = served_hostnames(&file);
        assert!(names.contains(&"vault.example.com".to_string()), "{names:?}");
        assert!(names.contains(&"mail.example.com".to_string()), "{names:?}");
        assert!(names.contains(&"mail.alias.com".to_string()), "{names:?}");
        // The global options block has no names before its brace.
        assert!(!names.iter().any(|n| n.contains('{')), "{names:?}");
    }

    #[test]
    fn the_domain_most_names_agree_on_comes_first() {
        let served = vec![
            "mail.example.com".to_string(),
            "vault.example.com".to_string(),
            "cloud.example.com".to_string(),
            "mail.alias.net".to_string(),
        ];
        assert_eq!(domains(&served), vec!["example.com", "alias.net"]);
    }

    #[test]
    fn a_service_on_its_own_hostname_does_not_outvote_the_deployment() {
        // The catalog allows a service aimed at a name outside the
        // deployment's domains; it must not become the primary domain.
        let served = vec![
            "mail.example.com".to_string(),
            "vault.example.com".to_string(),
            "status.someones-other-domain.org".to_string(),
        ];
        assert_eq!(domains(&served).first().map(String::as_str), Some("example.com"));
    }

    #[test]
    fn a_local_only_host_still_yields_its_name() {
        let served = vec!["dns.home.local".to_string(), "cloud.home.local".to_string()];
        assert_eq!(domains(&served), vec!["home.local"]);
    }

    #[test]
    fn nothing_to_derive_from_answers_nothing_rather_than_guessing() {
        assert!(domains(&[]).is_empty());
        // One label deep: there is no domain under it to report.
        assert!(domains(&["localhost".to_string()]).is_empty());
    }

    #[test]
    fn no_guard_no_tls_internal_is_the_plain_two_line_block() {
        assert_eq!(
            site("vaultwarden", "vault.example.com", 8080, false, false, false),
            "vault.example.com {\n    # gryonixnexus: vaultwarden\n    reverse_proxy 127.0.0.1:8080\n}"
        );
    }

    #[test]
    fn guard_and_tls_internal_both_land_before_the_proxy_line() {
        assert_eq!(
            site("adguard-home", "dns.home.local", 8087, true, false, true),
            "dns.home.local {\n    # gryonixnexus: adguard-home\n    tls internal\n    import /etc/caddy/gryonixnexus-admin-guard\n    reverse_proxy 127.0.0.1:8087\n}"
        );
    }

    // ─────────────────────────── the owner line ───────────────────────────

    /// **The owner is the FIRST line inside the block, on every shape.** Two
    /// shapes exist (guarded and not) and the line has to land in both — a
    /// block written without it is one this file cannot tell from a stranger's,
    /// which is the whole hole being closed.
    #[test]
    fn every_shape_of_block_says_whose_it_is() {
        for guard in [false, true] {
            for tls in [false, true] {
                for https in [false, true] {
                    let block = site("nextcloud", "cloud.example.com", 8080, guard, https, tls);
                    assert_eq!(
                        owner_of(&block).as_deref(),
                        Some("nextcloud"),
                        "guard={guard} tls={tls} https={https}"
                    );
                    let second = block.lines().nth(1).unwrap_or_default();
                    assert_eq!(second.trim(), "# gryonixnexus: nextcloud",
                               "the owner is not the first line inside the block");
                }
            }
        }
    }

    /// **A block written before blocks said whose they were has NO owner, and
    /// that is not "nobody".** Every Caddyfile already on a host looks like
    /// this, and reading them as a stranger's would refuse a site the
    /// deployment has served for months.
    #[test]
    fn a_block_from_before_this_existed_names_nobody() {
        assert_eq!(owner_of("cloud.example.com {\n    reverse_proxy 127.0.0.1:8080\n}"), None);
    }

    /// The HEADER is never read as an owner, however it is spelled. A site
    /// genuinely named `# gryonixnexus: x` is not a thing, but a reader that
    /// looked at line one would answer for the global options block — which
    /// has no names at all — and hand every install a stranger to collide with.
    #[test]
    fn the_header_line_is_not_an_owner() {
        assert_eq!(owner_of("# gryonixnexus: forged {\n    reverse_proxy 127.0.0.1:1\n}"), None);
        assert_eq!(owner_of(GLOBAL_OPTIONS), None);
    }

    /// **Every module's owner is a CATALOG id, and that is what stops the
    /// fixtures being circular.**
    ///
    /// The 114 `__caddy-site.txt` fixtures were Swift's own bytes and were
    /// patched with one line each when blocks gained an owner — a mechanical
    /// edit, so on its own it proves only that this port agrees with an edit
    /// this port's author made. What makes it more than that is the id: it is
    /// the same string the app sends in `InstallServiceRequest`, so a module
    /// carrying a wrong one would be carrying a service id no install can even
    /// resolve. The Swift generator writes `service.id.rawValue` into the same
    /// place, and the Kotlin port is held to Swift's bytes by the recipe
    /// golden — so all three name a service the same way or none of them
    /// installs it.
    #[test]
    fn every_site_owner_is_a_catalog_id() {
        use crate::install::*;
        let known = crate::install::execute::implemented_service_ids();
        let owners = [
            adguard::SERVICE_ID, authelia::SERVICE_ID, crafty::SERVICE_ID,
            forgejo::SERVICE_ID, gitlab::SERVICE_ID, headscale::SERVICE_ID,
            homepage::SERVICE_ID, immich::SERVICE_ID, jellyfin::SERVICE_ID,
            nextcloud::SERVICE_ID, passbolt::SERVICE_ID, photoprism::SERVICE_ID,
            pihole::SERVICE_ID, psono::SERVICE_ID, seafile::SERVICE_ID,
            vaultwarden::SERVICE_ID, mail::mailcow::SERVICE_ID, mail::mailu::SERVICE_ID,
            mail::dockermailserver::SERVICE_ID, vpn::panel::SERVICE_ID,
        ];
        for owner in owners {
            assert!(known.contains(&owner), "{owner} is not a service this agent installs");
        }
        // And no two modules claim the same id, which would put one service's
        // name on another's block and make the collision check answer for the
        // wrong pair.
        let mut sorted = owners.to_vec();
        sorted.sort_unstable();
        let count = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), count, "two modules claim one catalog id");
    }

    /// An owner line with nothing after the tag says nothing. Reading it as an
    /// empty-named owner would make every unmarked block collide with it.
    #[test]
    fn an_empty_owner_line_says_nothing() {
        assert_eq!(owner_of("a.example.com {\n    # gryonixnexus:\n    x\n}"), None);
        assert_eq!(owner_of("a.example.com {\n    # gryonixnexus:   \n    x\n}"), None);
    }

    /// The HTTPS-upstream branch against a fixture dumped from the REAL Swift
    /// `caddySite`, not against an expectation typed out here. No AdGuard
    /// scenario can reach this branch (its web UI is plain HTTP), so without
    /// this the only thing standing behind the nested block's indentation
    /// would be a careful reading of Swift's multi-line-literal stripping
    /// rules — exactly the kind of "verified by reading" the project keeps
    /// getting burned by (GOTCHAS.md: the DMS DKIM glob, the authorized_keys
    /// test). mailcow is proxied over TLS on 18443, so the next service slice
    /// depends on these bytes.
    #[test]
    fn https_upstream_matches_the_swift_generators_own_output() {
        let path = format!(
            "{}/tests/fixtures/install/caddy-https-upstream__caddy-site.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        let expected = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"));
        assert_eq!(site("mailcow", "mail.example.com, mail.example.org", 18443, true, true, false), expected);
    }

    #[test]
    fn caddyfile_joins_sites_with_a_blank_line() {
        assert_eq!(caddyfile(&["a {\n}".to_string(), "b {\n}".to_string()]), "a {\n}\n\nb {\n}");
    }

    // ─────────────────────────── merge_site ───────────────────────────

    /// `merge_site`'s output with the global block stripped, so the merge
    /// tests keep asserting on the SITES — the thing they are about. The block
    /// itself is asserted separately, and by its own test, so that dropping it
    /// cannot hide behind a helper that tolerates its absence.
    fn sites_only(merged: &str) -> String {
        let prefix = format!("{GLOBAL_OPTIONS}\n\n");
        assert!(
            merged.starts_with(&prefix) || merged == GLOBAL_OPTIONS,
            "every Caddyfile this writes must open with the global block"
        );
        merged.strip_prefix(&prefix).unwrap_or("").to_string()
    }

    #[test]
    fn merging_into_an_empty_or_missing_file_yields_just_the_new_site() {
        assert_eq!(sites_only(&merge_site("", &["dns.example.com".to_string()], "dns.example.com {\n    x\n}")), "dns.example.com {\n    x\n}");
        assert_eq!(
            sites_only(&merge_site("   \n  ", &["dns.example.com".to_string()], "dns.example.com {\n    x\n}")),
            "dns.example.com {\n    x\n}"
        );
    }

    #[test]
    fn merging_appends_without_disturbing_an_unrelated_existing_site() {
        let existing = "vault.example.com {\n    reverse_proxy 127.0.0.1:8080\n}";
        let merged = sites_only(&merge_site(existing, &["dns.example.com".to_string()], "dns.example.com {\n    x\n}"));
        assert_eq!(merged, "vault.example.com {\n    reverse_proxy 127.0.0.1:8080\n}\n\ndns.example.com {\n    x\n}");
    }

    #[test]
    fn a_rerun_replaces_only_its_own_stale_block_and_leaves_the_rest() {
        let existing = "vault.example.com {\n    a\n}\n\ndns.example.com {\n    OLD\n}\n\nother.example.com {\n    b\n}";
        let merged = sites_only(&merge_site(existing, &["dns.example.com".to_string()], "dns.example.com {\n    NEW\n}"));
        assert_eq!(
            merged,
            "vault.example.com {\n    a\n}\n\nother.example.com {\n    b\n}\n\ndns.example.com {\n    NEW\n}"
        );
        assert!(!merged.contains("OLD"));
    }

    #[test]
    fn a_multi_name_header_is_matched_and_replaced_as_one_block() {
        let existing = "dns.example.com, dns.example.org {\n    OLD\n}";
        let merged = sites_only(&merge_site(
            existing,
            &["dns.example.com".to_string(), "dns.example.org".to_string()],
            "dns.example.com, dns.example.org {\n    NEW\n}",
        ));
        assert_eq!(merged, "dns.example.com, dns.example.org {\n    NEW\n}");
    }

    /// The global block is present, first, and never duplicated.
    ///
    /// Its absence is not cosmetic: without `order respond before
    /// forward_auth` the admin guard is compiled AFTER single sign-on and can
    /// never refuse anything on a protected site — the lockdown reads as
    /// applied and is inert. Duplicating it is not cosmetic either: Caddy
    /// refuses a Caddyfile with two global blocks outright, which would take
    /// every site on the host down on the next reload.
    #[test]
    fn the_global_block_is_present_once_and_first() {
        let first = merge_site("", &["a.example.com".to_string()], "a.example.com {\n    x\n}");
        assert!(first.starts_with(GLOBAL_OPTIONS), "a fresh file must open with it");
        assert_eq!(first.matches("order respond before forward_auth").count(), 1);

        // Merging into a file that ALREADY has it (every re-run, and every
        // host the SSH route wrote) must not add a second one.
        let again = merge_site(&first, &["b.example.com".to_string()], "b.example.com {\n    y\n}");
        assert!(again.starts_with(GLOBAL_OPTIONS));
        assert_eq!(again.matches("order respond before forward_auth").count(), 1);
        assert!(again.contains("a.example.com {\n    x\n}"), "the earlier site survives");

        // And a host whose file predates this gains it rather than keeping an
        // ordering that silently disables its own guard.
        let legacy = merge_site("old.example.com {\n    z\n}",
                                &["c.example.com".to_string()],
                                "c.example.com {\n    w\n}");
        assert!(legacy.starts_with(GLOBAL_OPTIONS));
        assert!(legacy.contains("old.example.com {\n    z\n}"));
    }

    #[test]
    fn a_hostname_that_is_a_prefix_of_another_sites_header_is_not_confused_with_it() {
        // "dns.example.com" must not match a stale block headed
        // "dns.example.com.evil.net { ... }" — the header check anchors on
        // the exact "<names> {" prefix, not a bare substring.
        let existing = "dns.example.com.evil.net {\n    untouched\n}";
        let merged = merge_site(existing, &["dns.example.com".to_string()], "dns.example.com {\n    NEW\n}");
        assert!(merged.contains("dns.example.com.evil.net {\n    untouched\n}"), "unrelated lookalike header must survive");
        assert!(merged.contains("dns.example.com {\n    NEW\n}"));
    }
}
