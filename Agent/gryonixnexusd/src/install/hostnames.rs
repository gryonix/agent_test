//! The name a service answers on when nobody typed one.
//!
//! A port of Swift's `ServiceDefaultHostnames`, and the same rule: a shelf
//! carrying ONE published service gives it the plain name (`photos.<domain>`,
//! `files.<domain>`, `ai.<domain>`), and a shelf carrying two or more makes
//! each say which service it is (`immich.<domain>`, `photoprism.<domain>`).
//! The plain name is the one a person would guess, and it is only guessable
//! while exactly one thing could answer it.
//!
//! **Two things this replaces.** Every service module held its default as a
//! literal, so nothing could see a pair: AdGuard Home and Pi-hole both said
//! `dns.<domain>`, which is one Caddy site named twice and a whole Caddyfile
//! that stops loading; and OpenClaw held `agent.<domain>`, a name the owner
//! never gave it (owner, 2026-09-12 — the standard address of an assistant is
//! `ai.<domain>`, and `agent.` belongs to nobody).
//!
//! **Why the neighbours are an input at all.** Unlike the app, which has the
//! whole selection in front of it, the agent installs one service per request
//! — so the list comes from what the host already carries plus the service
//! being installed (`Input::installed_services`, filled from the same union
//! `HostInput::services` uses). A blank list therefore means "nothing else is
//! here", which is exactly what the plain name is for.

/// A set of services that would compete for one plain name: the name the
/// single member takes, and the name each takes once two or more are present.
struct Group {
    shared: &'static str,
    own: &'static [(&'static str, &'static str)],
}

/// Explicit membership, not "everything on the shelf": the AI shelf also
/// carries Ollama, Qdrant and SearXNG, and none of the three is published
/// under any name at all. A group is the set of things that would ANSWER on
/// the name, which is smaller than a shelf.
const GROUPS: &[Group] = &[
    Group {
        shared: "vault",
        own: &[
            ("vaultwarden", "vaultwarden"),
            ("psono", "psono"),
            ("passbolt", "passbolt"),
        ],
    },
    Group {
        shared: "files",
        own: &[("nextcloud", "nextcloud"), ("seafile", "seafile")],
    },
    Group {
        shared: "photos",
        own: &[("immich", "immich"), ("photoprism", "photoprism")],
    },
    Group {
        shared: "dns",
        own: &[("adguard-home", "adguard"), ("pihole", "pihole")],
    },
    Group {
        shared: "git",
        own: &[("forgejo", "forgejo"), ("gitlab", "gitlab")],
    },
    Group {
        shared: "ai",
        own: &[
            ("open-webui", "openwebui"),
            ("anythingllm", "anythingllm"),
            ("litellm", "litellm"),
            ("openclaw", "openclaw"),
        ],
    },
];

/// Services that share their plain name with nobody.
const SOLE: &[(&str, &str)] = &[
    ("jellyfin", "media"),
    ("authelia", "auth"),
    ("homepage", "start"),
    ("headscale", "mesh"),
    ("crafty-controller", "mc"),
    ("n8n", "flows"),
];

/// The label this service answers on, without the domain.
///
/// The service itself counts as present whether or not `installed` lists it:
/// the name is asked for while the install is still being planned as often as
/// afterwards, and a service that could not see itself would call itself the
/// only one on a shelf it is about to share.
pub fn label(service_id: &str, installed: &[String]) -> String {
    let group = GROUPS
        .iter()
        .find(|group| group.own.iter().any(|(id, _)| *id == service_id));
    let Some(group) = group else {
        return SOLE
            .iter()
            .find(|(id, _)| *id == service_id)
            .map(|(_, label)| (*label).to_string())
            // Neither grouped nor sole means a nameable service somebody added
            // without saying what it is called. The id is a working, visible
            // name: a wrong site name is noticed, a panic at install time is
            // not.
            .unwrap_or_else(|| service_id.to_string());
    };
    let present = group
        .own
        .iter()
        .filter(|(id, _)| *id == service_id || installed.iter().any(|other| other == id))
        .count();
    if present <= 1 {
        return group.shared.to_string();
    }
    group
        .own
        .iter()
        .find(|(id, _)| *id == service_id)
        .map(|(_, label)| (*label).to_string())
        .unwrap_or_else(|| service_id.to_string())
}

/// The label plus the deployment's domain — what every service module's
/// `hostname` returns when its own setting is blank.
pub fn default_hostname(service_id: &str, domain: &str, installed: &[String]) -> String {
    format!("{}.{}", label(service_id, installed), domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|id| (*id).to_string()).collect()
    }

    #[test]
    fn one_service_on_a_shelf_takes_the_plain_name() {
        assert_eq!(label("immich", &ids(&["immich"])), "photos");
        assert_eq!(label("nextcloud", &[]), "files");
        assert_eq!(label("open-webui", &ids(&["open-webui", "ollama", "qdrant"])), "ai");
        assert_eq!(label("openclaw", &ids(&["openclaw"])), "ai");
    }

    #[test]
    fn two_on_a_shelf_each_say_which_one_they_are() {
        let photos = ids(&["immich", "photoprism"]);
        assert_eq!(label("immich", &photos), "immich");
        assert_eq!(label("photoprism", &photos), "photoprism");

        let dns = ids(&["adguard-home", "pihole"]);
        assert_eq!(label("adguard-home", &dns), "adguard");
        assert_eq!(label("pihole", &dns), "pihole");
    }

    /// The collision the literals used to produce: both filters claimed
    /// `dns.<domain>`, which is one Caddyfile that stops loading.
    #[test]
    fn the_two_dns_filters_never_share_a_name() {
        let both = ids(&["adguard-home", "pihole"]);
        assert_ne!(
            default_hostname("adguard-home", "example.com", &both),
            default_hostname("pihole", "example.com", &both)
        );
    }

    /// The name the owner freed: no service may produce it, alone or crowded.
    #[test]
    fn nothing_claims_the_agent_name() {
        let everything: Vec<String> = GROUPS
            .iter()
            .flat_map(|group| group.own.iter().map(|(id, _)| (*id).to_string()))
            .chain(SOLE.iter().map(|(id, _)| (*id).to_string()))
            .collect();
        for id in &everything {
            assert_ne!(label(id, &[]), "agent", "{id} alone");
            assert_ne!(label(id, &everything), "agent", "{id} crowded");
        }
    }

    #[test]
    fn services_with_no_shelf_mate_keep_their_own_name() {
        assert_eq!(label("jellyfin", &ids(&["jellyfin", "immich"])), "media");
        assert_eq!(label("n8n", &[]), "flows");
    }
}
