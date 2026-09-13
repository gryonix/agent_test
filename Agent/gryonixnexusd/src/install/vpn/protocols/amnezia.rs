//! AmneziaWG — a DPI-resistant WireGuard variant behind the `amnezia-wg-easy`
//! panel, on its own subnet and its own compose project.
//!
//! **What the user actually manages is the unified panel, not this one.** The
//! stock web UI binds loopback only and nothing proxies it; clients are added
//! through `vpn.<domain>`. That is why a failure to hash the panel password is
//! DEGRADED rather than fatal (see [`env_contents`]), and why this protocol
//! contributes no Caddy site.
//!
//! **The password hash comes from the image, and getting it can hang.** The
//! bcrypt hash is produced by the image's own `wgpw` tool, and when the
//! entrypoint does not recognise a sub-command it falls through to STARTING
//! the panel — a long-running server — which wedged a real installation at
//! "AmneziaWG VPN: starting" with no output. Both routes therefore try the
//! explicit `--entrypoint wgpw` form first, the bare sub-command second, and
//! put a hard timeout on each. The agent gets the timeout for free (every
//! `docker` call it makes is bounded), but the ORDER and the fallback are
//! ported as they are.
//!
//! **`$` in the hash must be doubled before compose sees it.** `docker
//! compose` interpolates `$` inside `.env` values, so a raw bcrypt hash
//! reaches the container mangled behind a flood of "variable is not set"
//! warnings. [`escape_hash`] is the port of the generator's `sed`, including
//! its idempotence: a run of `$`s collapses to exactly `$$`, so an already
//! escaped hash is left alone.

use crate::install::context::Input;

/// `AmneziaWGVPNService.composeProject`.
pub const COMPOSE_PROJECT: &str = "awgvpn";

/// `AmneziaWGVPNService.containerName`, pinned for the dashboard's restart
/// literal.
pub const CONTAINER: &str = "awgvpn";

/// DeckerSU's build, NOT w0rng's original: the latter's "multi-arch" tag ships
/// amd64 binaries inside its arm variants, so every exec on an ARM host dies
/// with "exec format error" (GOTCHAS.md's rule about fake multi-arch tags).
pub const IMAGE: &str = "ghcr.io/deckersu/amnezia-wg-easy:14";

/// The panel's own web port inside the container. Differs from the unified
/// panel's so both can bind loopback at once.
const WEB_UI_PORT: u16 = 51823;

/// The host directory, from settings.
pub fn dir(input: &Input) -> &str {
    &input.amnezia_wg_path
}

/// The `.env` holding the plain password (for the report) and the hash (for
/// the container).
pub fn env_path(input: &Input) -> String {
    format!("{}/.env", dir(input))
}

/// A port of `AmneziaWGVPNService.composeFile`.
pub fn compose_contents(input: &Input) -> String {
    let path = dir(input);
    let port = input.amnezia_wg_port;
    let host = super::super::panel::hostname(input);
    format!(
        "services:
  amnezia-wg-easy:
    image: {IMAGE}
    container_name: {CONTAINER}
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    # Most kernels have no AmneziaWG module, so awg-quick falls back
    # to the userspace amneziawg-go, which needs a TUN device to
    # bring wg0 up. Without it the container crashlooped with
    # \"RTNETLINK: Not supported\" / \"Protocol not supported\".
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
    environment:
      WG_HOST: {host}
      WG_PORT: \"{port}\"
      # 10.10.0.x: clear of the relay tunnel (10.8.0.0/24) and the
      # plain WireGuard VPN (10.9.0.0/24).
      WG_DEFAULT_ADDRESS: 10.10.0.x
      PASSWORD_HASH: ${{PASSWORD_HASH}}
      PORT: \"{WEB_UI_PORT}\"
    volumes:
      # The deckersu fork stores its config under
      # /etc/amnezia/amneziawg (NOT wg-easy's /etc/wireguard) — the
      # container ENOENT-crashlooped saving wg0.json when mounted at
      # the wrong path, and the panel (which reads <path>/data/
      # wg0.json) saw nothing. Mount at the path the fork uses.
      - {path}/data:/etc/amnezia/amneziawg
    ports:
      # The wg-easy fork sets the wg0 interface's ListenPort to
      # WG_PORT (the same value advertised to clients), so the
      # container listens on `port` INTERNALLY — not on a fixed
      # 51820. Publishing host:port onto a different container port
      # (the old 51820) sent every UDP packet to a port nothing
      # listened on: clients handshook into a black hole. The
      # container port must equal WG_PORT. (The unified VPN panel's
      # own wgpanel already does this right — host:wgPort→wgPort.)
      - \"{port}:{port}/udp\"
      - \"127.0.0.1:{WEB_UI_PORT}:{WEB_UI_PORT}\""
    )
}

/// The `.env`, in the generator's own two `printf` shapes.
///
/// `hash` is `None` when the image would not produce one. That is a DEGRADED
/// but working VPN — the panel then starts with no password, on loopback, with
/// nothing proxying it — and both routes prefer it to an install that never
/// finishes. The empty `PASSWORD_HASH=` line is kept, not dropped: compose
/// warns loudly about an undefined variable, and the file is also the record
/// that this host went through the degraded path.
pub fn env_contents(password: &str, hash: Option<&str>) -> String {
    match hash {
        Some(hash) => format!("ADMIN_PASSWORD={password}\nPASSWORD_HASH={}\n", escape_hash(hash)),
        None => format!("ADMIN_PASSWORD={password}\nPASSWORD_HASH=\n"),
    }
}

/// A port of `sed -i '/^PASSWORD_HASH=/s/\$\{1,\}/$$/g'` — every RUN of `$`
/// becomes exactly `$$`.
///
/// Idempotent by construction, which is the property that matters: the
/// generator applies it on every run, including to a hash it escaped last
/// time, and a port that simply doubled each `$` would grow the hash by a
/// factor of two per install.
pub fn escape_hash(hash: &str) -> String {
    let mut out = String::with_capacity(hash.len() + 4);
    let mut chars = hash.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        while chars.peek() == Some(&'$') {
            chars.next();
        }
        out.push_str("$$");
    }
    out
}

/// Whether `wgpw`'s output is an answer at all, and the hash if so.
///
/// A port of the generator's three-step reduction: take the FIRST line, strip
/// a leading `PASSWORD_HASH=`, drop every `'`, and accept the result only if
/// it looks like a bcrypt hash (`$2…`). Anything else — a usage message, the
/// panel's own startup banner, an empty string — is not an answer, and the
/// caller falls through to the next form and then to the degraded path.
pub fn parse_hash(output: &str) -> Option<String> {
    let first = output.lines().next().unwrap_or("");
    let hash: String = first
        .strip_prefix("PASSWORD_HASH=")
        .unwrap_or(first)
        .chars()
        .filter(|c| *c != '\'')
        .collect();
    if hash.starts_with("$2") {
        Some(hash)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both shapes the tool has printed, plus the three non-answers.
    #[test]
    fn only_a_bcrypt_hash_counts_as_an_answer() {
        assert_eq!(
            parse_hash("PASSWORD_HASH='$2b$12$abc'\n"),
            Some("$2b$12$abc".to_string())
        );
        assert_eq!(parse_hash("$2y$10$xyz\n"), Some("$2y$10$xyz".to_string()));
        assert_eq!(parse_hash(""), None);
        assert_eq!(parse_hash("Usage: wgpw <password>\n"), None);
        // The failure that wedged a real install: the panel started instead of
        // hashing, so its banner is what came back.
        assert_eq!(parse_hash("Listening on port 51823\n"), None);
    }

    /// `head -n1` — later lines are not consulted.
    #[test]
    fn only_the_first_line_is_read() {
        assert_eq!(parse_hash("$2b$1\n$2b$2\n").unwrap(), "$2b$1");
    }

    /// The property the generator's `\$\{1,\}` gives and a naive double would
    /// not: applying it twice changes nothing.
    #[test]
    fn escaping_a_hash_is_idempotent() {
        let raw = "$2b$12$Kix4Cl/pw";
        let once = escape_hash(raw);
        assert_eq!(once, "$$2b$$12$$Kix4Cl/pw");
        assert_eq!(escape_hash(&once), once, "a second pass must not grow it");
        assert_eq!(escape_hash("$$$$a"), "$$a", "a run of any length collapses to $$");
        assert_eq!(escape_hash("plain"), "plain");
    }

    /// The degraded path writes the password and an EMPTY hash — never a
    /// missing line.
    #[test]
    fn the_degraded_env_still_names_both_keys() {
        assert_eq!(env_contents("pw", None), "ADMIN_PASSWORD=pw\nPASSWORD_HASH=\n");
        assert_eq!(
            env_contents("pw", Some("$2b$x")),
            "ADMIN_PASSWORD=pw\nPASSWORD_HASH=$$2b$$x\n"
        );
    }
}

#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::install::vpn::protocols::tests_support::{fixture, scenario_input};

    /// The `.env` is written by `printf`, not a heredoc, so the fixture
    /// carries the FORMAT (`ADMIN_PASSWORD=%s\nPASSWORD_HASH=%s\n`) and its
    /// arguments. This reads that format out of the fixture and substitutes,
    /// rather than re-deriving the expectation from the Swift source.
    fn env_from_fixture(steps: &str, degraded: bool, password: &str, hash: &str) -> String {
        let needle = if degraded { "PASSWORD_HASH=\\n'" } else { "PASSWORD_HASH=%s\\n'" };
        let line = steps
            .lines()
            .find(|line| line.trim_start().starts_with("printf 'ADMIN_PASSWORD=") && line.contains(needle))
            .unwrap_or_else(|| panic!("no printf for the {} .env", if degraded { "degraded" } else { "hashed" }));
        let format = line
            .trim_start()
            .trim_start_matches("printf '")
            .split_once("' ")
            .expect("a quoted format followed by arguments")
            .0;
        let mut out = String::new();
        let mut values = [password, hash].into_iter();
        let mut rest = format;
        while let Some(at) = rest.find("%s") {
            out.push_str(&rest[..at]);
            out.push_str(values.next().expect("one value per %s"));
            rest = &rest[at + 2..];
        }
        out.push_str(rest);
        out.replace("\\n", "\n")
    }

    fn assert_parity(scenario: &str) {
        let input = scenario_input(scenario);
        let steps = fixture(&format!("awg-{scenario}__setup-steps.txt"));
        assert_eq!(
            compose_contents(&input),
            fixture(&format!("awg-{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            dir(&input),
            fixture(&format!("awg-{scenario}__compose-directory.txt")),
            "{scenario}: compose directory"
        );
        // `$2b$x` rather than a placeholder: the escaping happens on the shell
        // side AFTER the printf, so the comparison is against the UNESCAPED
        // value and this module's own escaping is pinned by its unit test.
        assert_eq!(
            env_contents("PW", Some("HASH")),
            env_from_fixture(&steps, false, "PW", "HASH"),
            "{scenario}: .env (hashed)"
        );
        assert_eq!(
            env_contents("PW", None),
            env_from_fixture(&steps, true, "PW", ""),
            "{scenario}: .env (degraded)"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity("default-public-en");
    }

    #[test]
    fn custompaths_public_en() {
        assert_parity("custompaths-public-en");
    }

    /// The endpoint hostname is baked into the container's `WG_HOST`, so this
    /// is the one protocol whose COMPOSE file moves with it.
    #[test]
    fn customhost_public_en() {
        assert_parity("customhost-public-en");
        assert!(compose_contents(&scenario_input("customhost-public-en"))
            .contains("WG_HOST: tunnel.example.com"));
    }

    #[test]
    fn default_public_ru() {
        assert_parity("default-public-ru");
        let en = scenario_input("default-public-en");
        let ru = scenario_input("default-public-ru");
        assert_eq!(compose_contents(&en), compose_contents(&ru));
    }
}
