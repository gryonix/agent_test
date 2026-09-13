//! Parity harness for `install-report.txt` — see this module's parent doc
//! for why source-text comparison (what every other `install::host` file
//! uses) cannot verify this one: the fixtures are shell SOURCE, but what has
//! to match is shell OUTPUT. Every `fixture_parity` test below therefore
//! RUNS the real generated block through a real `bash` in a throwaway
//! sandbox and diffs its stdout against [`render`] byte-for-byte, given a
//! [`Facts`] impl reading the same seeded files bash reads.
//!
//! ## The sandbox
//!
//! Every fixture's literal `/opt/...` paths are rewritten to
//! `<tmpdir>/opt/...` in BOTH the fixture text (see [`Sandbox::rewrite`])
//! and the [`Input`] path fields the tests build ([`base_input`]) — the one
//! sandboxing design the task specified up front. [`Sandbox::reroot`] is
//! the matching rule on the [`Facts`] side: a path already under the
//! sandbox is used as-is (every `Input` field the tests hand to `render`
//! already went through the rewrite), anything else — the two hardcoded
//! `/opt` constants ([`VAULTWARDEN_ENV`], [`VPN_PANEL_PATH`]) and the two
//! DKIM wrapper paths — gets re-rooted. That is what keeps a hardcoded
//! constant pointing at the same seeded file on both routes without this
//! module needing to know which paths are hardcoded and which are settings.
//!
//! `bash` runs each block under the EXACT shell options the generated setup
//! script runs it under: `set -euo pipefail` for the whole script, `set +e`
//! around the report section only — pipefail stays ON. That distinction is
//! load-bearing for the DKIM branch (see `dkim_wrapper_lines`'s doc on
//! [`super::dkim_wrapper_lines`]): verified by hand against a real bash
//! before touching the port (this file's own module doc records the
//! transcript in spirit; the porting report has the literal one).
//!
//! `PATH` is prefixed with a directory of stub executables for the four
//! external binaries a report block shells out to (`systemctl`, `curl`,
//! `jq`, `wg`) — everything else (`grep`, `cut`, `tail`, `sed`, `cat`,
//! `printf`) is the real system tool, reading the real seeded files.
//!
//! ## What is NOT covered
//!
//! Local-only deployments drop both the PTR line and the DNS reminder
//! (`render_services_host`'s two `if` guards on `ptr_ip`/`!local_only`), but
//! no fixture in `GeneratedScriptLintTests.makeVariants()` ever sets
//! `DeploymentScope.localOnly` for a variant this extraction pulled from —
//! every dumped scenario is scenario A or B, both of which always carry a
//! public PTR. That branch is therefore read, not run: `local_only_drops_the_ptr_and_dns_reminder_lines`
//! below exercises it directly against `render`, not against a fixture.

use super::*;
use crate::dns_records::Language;
use crate::install::context::Input;
use crate::install::host::HostRole;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

// ============================================================================
// Sandbox
// ============================================================================

/// A throwaway directory standing in for the server's filesystem, plus a
/// `PATH` prefix of stub executables. One per test function (fixture text
/// does not vary per case within a test, so one sandbox is seeded once and
/// reused across every case in that test's loop).
struct Sandbox {
    root: PathBuf,
    root_str: String,
    bin: PathBuf,
    /// The mailcow API key the stub `curl` treats as authorized — chosen by
    /// the test, planted as the LAST line of a two-line `mailcow.conf`, so a
    /// port that read the FIRST `API_KEY=` line instead of the last would
    /// send the wrong key and get the "not ready" response instead of the
    /// seeded one.
    mailcow_key: String,
    /// `<domain>.txt` under here holds the raw DKIM value the stub `curl`
    /// returns for that domain, when the key matches. Absent file = mailcow
    /// itself would report "not ready".
    mailcow_dkim_dir: PathBuf,
    /// Appended to (one line per call) by any DKIM wrapper stub that opts
    /// in — see `dkim_wrapper_lines_calls_the_wrapper_at_most_once`.
    dkim_call_log: PathBuf,
    script_counter: AtomicU32,
}

impl Sandbox {
    fn new() -> Self {
        let out = Command::new("mktemp").arg("-d").output().expect("mktemp must be on PATH");
        assert!(out.status.success(), "mktemp failed: {out:?}");
        let root = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim().to_string());
        let bin = root.join("stub-bin");
        std::fs::create_dir_all(&bin).unwrap();
        let mailcow_dkim_dir = root.join("mailcow-dkim-seed");
        std::fs::create_dir_all(&mailcow_dkim_dir).unwrap();
        let dkim_call_log = root.join("dkim-call-log.txt");
        std::fs::write(&dkim_call_log, "").unwrap();
        let root_str = root.to_str().expect("mktemp path must be utf8").to_string();
        let sandbox = Sandbox {
            root,
            root_str,
            bin,
            mailcow_key: "REAL-mailcow-key-9f8e7d".to_string(),
            mailcow_dkim_dir,
            dkim_call_log,
            script_counter: AtomicU32::new(0),
        };
        sandbox.install_stub_binaries();
        sandbox
    }

    /// The task's re-rooting rule: a path already under this sandbox is used
    /// verbatim, anything else gets the sandbox root prepended.
    fn reroot(&self, path: &str) -> PathBuf {
        if path.starts_with(&self.root_str) {
            PathBuf::from(path)
        } else {
            self.root.join(path.trim_start_matches('/'))
        }
    }

    /// The same transform applied to fixture TEXT — every literal `/opt/`
    /// baked into the generated script becomes a path under the sandbox, so
    /// the running script and the files this test seeds agree on where
    /// things live.
    fn rewrite(&self, text: &str) -> String {
        // `/etc/gryonixnexus/` as well as `/opt/`: the report reads the host's
        // backup passphrase from there, and a path left unrewritten reads the
        // REAL machine — which on a developer's Mac is simply absent, so the
        // fixture printed an empty value while the renderer printed the seeded
        // one. That looked like a renderer bug and was a harness one.
        text.replace("/opt/", &format!("{}/opt/", self.root.display()))
            .replace("/etc/gryonixnexus/", &format!("{}/etc/gryonixnexus/", self.root.display()))
    }

    fn write_file(&self, path: &str, contents: &str) {
        let full = self.reroot(path);
        std::fs::create_dir_all(full.parent().expect("path must have a parent")).unwrap();
        std::fs::write(&full, contents).unwrap();
    }

    fn write_executable(&self, path: &str, script: &str) {
        self.write_file(path, script);
        Self::chmod_x(&self.reroot(path));
    }

    fn install_stub(&self, name: &str, script: &str) {
        let full = self.bin.join(name);
        std::fs::write(&full, script).unwrap();
        Self::chmod_x(&full);
    }

    fn chmod_x(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    /// `systemctl is-active <unit>` — one status per unit, deliberately NOT
    /// all identical (a column-formatting bug in `unit_status_block` could
    /// otherwise hide behind three copies of "active"). The table is the
    /// SINGLE source of truth for both the stub script text and
    /// [`TestFacts::systemctl_is_active`] — see `install_stub_binaries`.
    const UNIT_STATUSES: &'static [(&'static str, &'static str, i32)] = &[
        ("nftables", "active", 0),
        ("docker", "active", 0),
        ("caddy", "inactive", 3),
        ("wg-quick@wg0", "failed", 1),
    ];

    /// `wg show wg0` — one interface block, no peers. Shared verbatim between
    /// the stub script and [`TestFacts::wg_show`] so the two cannot drift;
    /// `render_relay` appends its OWN trailing `\n` after this (mirroring the
    /// generated script's blank `echo` right after `wg show wg0 || true`), so
    /// this text carries no extra blank line of its own.
    const WG_SHOW_TEXT: &'static str =
        "interface: wg0\n  public key: TESTPUBKEY0000000000000000000000000000000=\n  listening port: 51820\n";

    fn install_stub_binaries(&self) {
        let mut systemctl = String::from("#!/bin/bash\nif [ \"$1\" != \"is-active\" ]; then exit 1; fi\ncase \"$2\" in\n");
        for (unit, status, code) in Self::UNIT_STATUSES {
            systemctl.push_str(&format!("  {unit}) echo {status}; exit {code} ;;\n"));
        }
        systemctl.push_str("  *) echo unknown; exit 4 ;;\nesac\n");
        self.install_stub("systemctl", &systemctl);

        // Stub `curl`: finds the request URL and the `X-API-Key` header
        // among its args, and — if the key matches what this sandbox
        // considers correct — prints the RAW seeded DKIM value for that
        // domain. No JSON: the report block's own `jq -r '.dkim_txt //
        // empty'` is stubbed as a pass-through (below), so there is nothing
        // for this stub to wrap a value in. Testing jq's own JSON semantics
        // is out of scope — what is under test is `mod.rs`'s control flow
        // around the captured value, not the wire format between two
        // upstream tools neither side of this port re-implements.
        let curl = format!(
            "#!/bin/bash\n\
             key=\"\"\n\
             url=\"\"\n\
             prev=\"\"\n\
             for a in \"$@\"; do\n\
             \x20 if [ \"$prev\" = \"-H\" ]; then\n\
             \x20   case \"$a\" in\n\
             \x20     \"X-API-Key: \"*) key=\"${{a#X-API-Key: }}\" ;;\n\
             \x20   esac\n\
             \x20 fi\n\
             \x20 case \"$a\" in\n\
             \x20   https://*) url=\"$a\" ;;\n\
             \x20 esac\n\
             \x20 prev=\"$a\"\n\
             done\n\
             domain=\"${{url##*/}}\"\n\
             if [ \"$key\" = \"{key}\" ]; then\n\
             \x20 seed=\"{dir}/$domain.txt\"\n\
             \x20 [ -f \"$seed\" ] && cat \"$seed\"\n\
             fi\n\
             exit 0\n",
            key = self.mailcow_key,
            dir = self.mailcow_dkim_dir.display(),
        );
        self.install_stub("curl", &curl);
        self.install_stub("jq", "#!/bin/bash\ncat\nexit 0\n");

        let wg = format!("#!/bin/bash\nif [ \"$1\" = \"show\" ]; then\n  printf '%s' '{}'\nfi\n", Self::WG_SHOW_TEXT);
        self.install_stub("wg", &wg);
    }

    /// Runs a report BODY through a real bash under the exact shell options
    /// the generated setup script runs it under, and returns raw stdout.
    fn run(&self, body: &str) -> String {
        let n = self.script_counter.fetch_add(1, Ordering::Relaxed);
        let prelude = format!(
            "set -euo pipefail\nset +e\nlog() {{ printf '\\n==> %s\\n' \"$*\"; }}\nexport PATH=\"{}:$PATH\"\n",
            self.bin.display()
        );
        let full_script = format!("{prelude}{body}");
        let script_path = self.root.join(format!("report-{n}.sh"));
        std::fs::write(&script_path, &full_script).unwrap();
        let out = Command::new("bash")
            .arg(&script_path)
            .output()
            .unwrap_or_else(|e| panic!("could not run bash: {e}"));
        String::from_utf8(out.stdout).unwrap_or_else(|e| {
            panic!("report block wrote non-utf8 stdout: {e}\nscript:\n{full_script}")
        })
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ============================================================================
// Facts
// ============================================================================

/// **Every id the wrapper table knows must render a report block.** The arm
/// for an unknown id is `unreachable!()`, so a service added to
/// `CATALOG_ORDER` without a block here does not degrade — it PANICS the
/// whole call, and `ProvisionHost` answers "could not render the install
/// report". That is exactly how it was found: on a live host, after the
/// service worked. Cheap to assert, and it fails the moment a shelf is
/// added without its report lines.
#[test]
fn every_catalogued_service_renders_a_report_block() {
    let sandbox = Sandbox::new();
    let facts = TestFacts::new(&sandbox);
    for id in crate::install::host::CATALOG_ORDER {
        let input = host_input(&[id], HostRole::SingleHost, Language::En, Input::default());
        // Panicking here is the failure; the text itself is pinned by the
        // fixture tests that execute the real script.
        let _ = service_block(id, &input, &facts);
    }
}

/// **The line that says the game version floats, and the condition it hangs
/// on.**
///
/// With no `VERSION` the image resolves the LATEST release, so the jar beside
/// an existing world changes on the next restart after one — which is exactly
/// what the service's own comment on `image` says must not happen. A report
/// that stayed silent left the owner to discover it from a world that would not
/// load.
///
/// Both halves are asserted, because a line that is always printed says as
/// little as one that never is: an owner who pinned a version must not be told
/// their world will move.
#[test]
fn an_unpinned_minecraft_version_is_named_in_the_report() {
    let sandbox = Sandbox::new();
    let facts = TestFacts::new(&sandbox);

    let floating = host_input(&["minecraft-java"], HostRole::SingleHost, Language::En,
                              Input::default());
    let text = service_block("minecraft-java", &floating, &facts);
    assert!(
        text.contains(&l10n::minecraft_version_follows_latest(Language::En)),
        "an unpinned version is not named: {text}"
    );

    let pinned = host_input(
        &["minecraft-java"],
        HostRole::SingleHost,
        Language::En,
        Input { minecraft_java_version: "1.21.4".to_string(), ..Input::default() },
    );
    let text = service_block("minecraft-java", &pinned, &facts);
    assert!(
        !text.contains(&l10n::minecraft_version_follows_latest(Language::En)),
        "a pinned version was told its world will move: {text}"
    );
}

struct TestFacts<'a> {
    sandbox: &'a Sandbox,
}

impl<'a> TestFacts<'a> {
    fn new(sandbox: &'a Sandbox) -> Self {
        TestFacts { sandbox }
    }
}

impl Facts for TestFacts<'_> {
    fn systemctl_is_active(&self, unit: &str) -> String {
        Sandbox::UNIT_STATUSES
            .iter()
            .find(|(u, _, _)| *u == unit)
            .map(|(_, status, _)| status.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn read_file(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(self.sandbox.reroot(path)).ok()
    }

    fn dkim_wrapper(&self, path: &str) -> String {
        match Command::new(self.sandbox.reroot(path)).output() {
            Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
            Err(_) => String::new(),
        }
    }

    /// Reuses the SAME stub `curl` binary the bash side runs, rather than
    /// re-implementing the "does the key match" decision a second time in
    /// Rust — a second implementation is exactly how the two routes end up
    /// disagreeing (the class of bug this whole harness exists to catch).
    fn mailcow_dkim(&self, api_key: &str, domain: &str, https_port: u16) -> String {
        let curl = self.sandbox.bin.join("curl");
        let out = Command::new(&curl)
            .args([
                "-fsSk",
                "--max-time",
                "20",
                "-H",
                &format!("X-API-Key: {api_key}"),
                &format!("https://127.0.0.1:{https_port}/api/v1/get/dkim/{domain}"),
            ])
            .output()
            .expect("stub curl must run");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn wg_show(&self, _interface: &str) -> String {
        Sandbox::WG_SHOW_TEXT.to_string()
    }
}

// ============================================================================
// Seeding — the files every fixture MIGHT read. Seeded unconditionally
// whether or not the given case actually selects that service: the file
// simply goes unread otherwise, and seeding it once for every case is
// simpler than tracking which of 24 service sets needs which of 15 files.
// ============================================================================

fn seed_common_files(sandbox: &Sandbox) {
    // Two API_KEY lines on purpose (mandated by the task): the wrapper takes
    // `tail -n1`, and a port that took the first line instead would send the
    // WRONG key to the stub `curl`, which only answers the one this sandbox
    // calls correct.
    sandbox.write_file(
        "/opt/mailcow-dockerized/mailcow.conf",
        &format!("API_KEY=decoy-key-from-first-boot\nAPI_KEY={}\n", sandbox.mailcow_key),
    );
    sandbox.write_file("/opt/vaultwarden/.env", "ADMIN_TOKEN=VW-TOKEN-1\n");
    // The host's backup passphrase, seeded with a RECOGNISABLE value rather
    // than left absent: with no file both sides would print the label followed
    // by nothing and agree on emptiness, which proves the label and not the
    // value. NO trailing newline — the install writes the bare secret, and a
    // stray newline would reach gpg.
    sandbox.write_file("/etc/gryonixnexus/autobackup.pass", "AUTOBACKUP-PASS-1");
    sandbox.write_file("/opt/psono/.env", "PSONO_ADMIN_PASSWORD=PSONO-PW-1\n");
    // An embedded `=` in the value: `cut -d= -f2-`/the port's prefix-strip
    // both have to keep everything after the FIRST `=`, not split on every
    // one.
    sandbox.write_file("/opt/nextcloud/.env", "NEXTCLOUD_ADMIN_PASSWORD=NC-PW=1\n");
    sandbox.write_file("/opt/seafile/.env", "SEAFILE_ADMIN_PASSWORD=SEAFILE-PW-1\n");
    sandbox.write_file("/opt/photoprism/.env", "PHOTOPRISM_ADMIN_PASSWORD=PP-PW-1\n");
    sandbox.write_file("/opt/gitlab-ce/.env", "GITLAB_ROOT_PASSWORD=GITLAB-PW-1\n");
    sandbox.write_file("/opt/forgejo/.env", "FORGEJO_ADMIN_PASSWORD=FORGEJO-PW-1\n");
    sandbox.write_file("/opt/adguardhome/.env", "ADGUARD_ADMIN_PASSWORD=ADGUARD-PW-1\n");
    sandbox.write_file("/opt/mailu/.env", "INITIAL_ADMIN_PW=MAILU-PW-1\n");
    sandbox.write_file("/opt/docker-mailserver/.env", "FIRST_MAILBOX_PASSWORD=DMS-PW-1\n");
    sandbox.write_file("/opt/gryonix-vpn-panel/.env", "ADMIN_USER=vpnadmin\nADMIN_PASSWORD=VPNPANEL-PW-1\n");
    // A password containing all three SIP002-escaped characters at once.
    sandbox.write_file(
        "/opt/shadowsocks/config.json",
        "{\n  \"server\": \"0.0.0.0\",\n  \"server_port\": 8388,\n  \"password\": \"abcDEF123+/=\",\n  \"method\": \"2022-blake3-aes-256-gcm\"\n}\n",
    );
    sandbox.write_file("/opt/xray/link.txt", "vless://uuid@vpn.example.com:8443?security=reality#gryonixNexus\n");
    // Deliberately NO trailing newline — the openvpn arm uses a bare `cat`,
    // not `$(cat …)`, precisely because it must NOT normalize this away.
    sandbox.write_file(
        "/opt/openvpn/gryonixnexus.ovpn",
        "client\ndev tun\nremote vpn.example.com 1194 udp\n<ca>\nTESTCERT\n</ca>",
    );
    // Passbolt's `.registration-url` and the two DKIM wrapper scripts are
    // deliberately NOT seeded here — their default state (absent) is what
    // the bulk fixture_parity loop below exercises; the other states are
    // each their own dedicated test.
}

// ============================================================================
// HostInput / Topology builders
// ============================================================================

fn base_input() -> Input {
    Input {
        domain: "example.com".to_string(),
        wireguard_vpn_port: 51821,
        xray_reality_port: 8443,
        ..Input::default()
    }
}

fn multidomain_input() -> Input {
    Input {
        domain: "example.com".to_string(),
        additional_domains: vec!["example.org".to_string(), "example.net".to_string()],
        wireguard_vpn_port: 51821,
        xray_reality_port: 8443,
        ..Input::default()
    }
}

fn host_input(services: &[&str], role: HostRole, language: Language, install: Input) -> HostInput {
    HostInput {
        services: services.iter().map(|s| s.to_string()).collect(),
        install,
        language,
        ssh_user: Some("admin".to_string()),
        role,
    }
}

/// Scenario A / scenario B home-half topology. Both roles print the SAME
/// PTR (the relay's own address/hostname — mail leaves through it either
/// way); only `tunnel_endpoint` tells them apart.
fn services_host_topology(tunnel_endpoint: Option<&str>) -> Topology {
    Topology::ServicesHost {
        ptr_ip: Some("203.0.113.10".to_string()),
        ptr_hostname: "relay.example.com".to_string(),
        tunnel_endpoint: tunnel_endpoint.map(|s| s.to_string()),
    }
}

/// Rewrites a fixture's literal `/opt/` occurrences AND rewrites `input`'s
/// path fields the same way, per this module's own sandboxing rule — the
/// two hardcoded `/opt` constants and the two DKIM wrapper paths are handled
/// on the [`Facts`] side instead ([`Sandbox::reroot`]), since they are not
/// reachable through any `Input` field.
fn reroot_input(sandbox: &Sandbox, mut input: Input) -> Input {
    let r = |s: &str| -> String { format!("{}{s}", sandbox.root.display()) };
    input.adguard_path = r(&input.adguard_path);
    input.jellyfin_path = r(&input.jellyfin_path);
    input.photoprism_path = r(&input.photoprism_path);
    input.immich_path = r(&input.immich_path);
    input.nextcloud_path = r(&input.nextcloud_path);
    input.forgejo_path = r(&input.forgejo_path);
    input.gitlab_path = r(&input.gitlab_path);
    input.seafile_path = r(&input.seafile_path);
    input.psono_path = r(&input.psono_path);
    input.passbolt_path = r(&input.passbolt_path);
    input.amnezia_wg_path = r(&input.amnezia_wg_path);
    input.shadowsocks_path = r(&input.shadowsocks_path);
    input.xray_reality_path = r(&input.xray_reality_path);
    input.openvpn_path = r(&input.openvpn_path);
    input.mailcow_path = r(&input.mailcow_path);
    input.docker_mailserver_path = r(&input.docker_mailserver_path);
    input.mailu_path = r(&input.mailu_path);
    input
}

fn fixture(subdir: &str, name: &str) -> String {
    let path = format!("{}/tests/fixtures/install/host/{subdir}/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

// ============================================================================
// The service-set manifest — the same 24 named sets `uninstall.rs`'s
// `fixture_parity` reads from `GeneratedScriptLintTests.makeVariants()`,
// reused rather than re-derived (this module's own instruction).
// ============================================================================

const SERVICE_SETS: &[(&str, &[&str])] = &[
    ("bare", &[]),
    ("mailcow", &["mailcow"]),
    ("nomail", &["vaultwarden", "nextcloud", "immich", "forgejo", "gitlab"]),
    ("mailcow-wg", &["mailcow", "vaultwarden", "nextcloud", "immich", "wireguard-vpn"]),
    ("mailcow-awg", &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "amnezia-wg"]),
    ("nomail-ss", &["vaultwarden", "shadowsocks"]),
    ("mailcow-xray", &["mailcow", "vaultwarden", "xray-reality"]),
    ("nomail-ovpn", &["vaultwarden", "openvpn"]),
    ("mailu", &["mailu"]),
    ("dms", &["docker-mailserver"]),
    ("dms-full", &["docker-mailserver", "vaultwarden", "forgejo", "wireguard-vpn"]),
    ("mailu-full", &["mailu", "vaultwarden", "nextcloud", "immich", "forgejo", "wireguard-vpn"]),
    ("jellyfin", &["jellyfin"]),
    ("jellyfin-full", &["jellyfin", "vaultwarden", "nextcloud", "wireguard-vpn"]),
    ("adguard", &["adguard-home"]),
    ("adguard-full", &["adguard-home", "vaultwarden", "nextcloud", "wireguard-vpn"]),
    ("photoprism", &["photoprism"]),
    ("photoprism-immich", &["photoprism", "immich", "vaultwarden"]),
    ("seafile", &["seafile"]),
    ("seafile-nextcloud", &["seafile", "nextcloud", "vaultwarden"]),
    ("psono", &["psono"]),
    ("psono-vaultwarden", &["psono", "vaultwarden"]),
    ("passbolt", &["passbolt"]),
    ("passwords-shelf", &["passbolt", "psono", "vaultwarden"]),
];

/// Runs every `(set-name, services)` row in [`SERVICE_SETS`], both
/// languages, plus the multidomain row, against fixtures under `subdir` with
/// names built as `<prefix>-<set>-access-<lang>` / `<prefix>-multidomain` —
/// shared by the scenario-A and scenario-B-home tests, which differ only in
/// the fixture prefix, the [`HostRole`], and whether a tunnel line prints.
fn run_services_host_fixture_parity(subdir: &str, prefix: &str, role: HostRole, tunnel: Option<&str>) {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let topology = services_host_topology(tunnel);

    for (set_name, services) in SERVICE_SETS {
        for (lang_suffix, language) in [("en", Language::En), ("ru", Language::Ru)] {
            let install = reroot_input(&sandbox, base_input());
            let input = host_input(services, role, language, install);
            let actual = render(&input, &topology, &TestFacts::new(&sandbox));

            let fixture_name = format!("{prefix}-{set_name}-access-{lang_suffix}");
            let body = sandbox.rewrite(&fixture(subdir, &fixture_name));
            let expected = sandbox.run(&body);

            assert_eq!(actual, expected, "fixture {fixture_name} ({subdir})");
        }
    }

    // Multidomain: a different Input (two additional domains, so the mailcow
    // DKIM loop and every mirrored-hostname-adjacent line get exercised),
    // same topology, English only — matching the one multidomain row every
    // other host-half fixture set carries.
    let services: &[&str] =
        &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "gitlab", "amnezia-wg"];
    let install = reroot_input(&sandbox, multidomain_input());
    let input = host_input(services, role, Language::En, install);
    let actual = render(&input, &topology, &TestFacts::new(&sandbox));
    let fixture_name = format!("{prefix}-multidomain");
    let body = sandbox.rewrite(&fixture(subdir, &fixture_name));
    let expected = sandbox.run(&body);
    assert_eq!(actual, expected, "fixture {fixture_name} ({subdir})");
}

#[test]
fn fixture_parity_single_host() {
    run_services_host_fixture_parity("report_single", "A", HostRole::SingleHost, None);
}

#[test]
fn fixture_parity_home_backend() {
    run_services_host_fixture_parity("report_home", "B", HostRole::HomeBackend, Some("203.0.113.10:51820"));
}

// ============================================================================
// Scenario B relay — a DIFFERENT document (render_relay), independent of
// HostInput.services entirely; only wg_port/forwarded_ports/home_wg_address
// vary per case, read off each fixture's own text rather than re-derived
// (this module owns no firewall-port logic to derive them from).
// ============================================================================

const VPS_CASES: &[(&str, &[u16])] = &[
    ("B-adguard-access", &[80, 443]),
    ("B-bare-access", &[80]),
    ("B-dms-access", &[25, 80, 143, 443, 465, 587, 993, 4190]),
    ("B-dms-full-access", &[25, 80, 143, 443, 465, 587, 993, 2222, 4190]),
    ("B-mailcow-xray-access", &[25, 80, 143, 443, 465, 587, 993, 4190, 8443]),
    ("B-mailu-access", &[25, 80, 443, 465, 993, 4190]),
    ("B-mailu-full-access", &[25, 80, 443, 465, 993, 2222, 4190]),
    ("B-nomail-access", &[80, 443, 2222, 2223]),
    ("B-nomail-ss-access", &[80, 443, 8388]),
];

#[test]
fn fixture_parity_vps_relay() {
    let sandbox = Sandbox::new();

    for (base_name, ports) in VPS_CASES {
        for (lang_suffix, language) in [("en", Language::En), ("ru", Language::Ru)] {
            let topology = Topology::Relay {
                wg_port: 51820,
                forwarded_ports: ports.to_vec(),
                home_wg_address: "10.8.0.2".to_string(),
                ptr_hostname: "relay.example.com".to_string(),
            };
            let input = host_input(&[], HostRole::VpsRelay, language, base_input());
            let actual = render(&input, &topology, &TestFacts::new(&sandbox));

            let fixture_name = format!("{base_name}-{lang_suffix}");
            let body = sandbox.rewrite(&fixture("report_vps", &fixture_name));
            let expected = sandbox.run(&body);
            assert_eq!(actual, expected, "fixture {fixture_name}");
        }
    }

    // Multidomain: same relay document (it carries no per-domain content at
    // all), the widest forwarded-port set in the catalog.
    let topology = Topology::Relay {
        wg_port: 51820,
        forwarded_ports: vec![25, 80, 143, 443, 465, 587, 993, 2222, 2223, 4190],
        home_wg_address: "10.8.0.2".to_string(),
        ptr_hostname: "relay.example.com".to_string(),
    };
    let input = host_input(&[], HostRole::VpsRelay, Language::En, base_input());
    let actual = render(&input, &topology, &TestFacts::new(&sandbox));
    let body = sandbox.rewrite(&fixture("report_vps", "B-multidomain"));
    let expected = sandbox.run(&body);
    assert_eq!(actual, expected, "fixture B-multidomain");
}

// ============================================================================
// Branch coverage the fixtures alone do not give — each of these needs its
// own case because the fixture set only ever exercises ONE side.
// ============================================================================

/// mailcow DKIM ready vs. not ready — the SAME real fixture body run twice,
/// once with no seeded DKIM value (the state every fixture_parity case
/// above uses) and once with one, proving the "if -n" branch both ways
/// through the real `curl`/`jq` stubs rather than just through `render`.
#[test]
fn mailcow_dkim_ready_vs_not_ready() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let install = reroot_input(&sandbox, base_input());
    let input = host_input(&["mailcow"], HostRole::SingleHost, Language::En, install);
    let topology = services_host_topology(None);
    let body = sandbox.rewrite(&fixture("report_single", "A-mailcow-access-en"));

    // Not ready (no seed file for example.com): this is the default state
    // seed_common_files leaves the mailcow_dkim_dir in.
    let actual_not_ready = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_not_ready = sandbox.run(&body);
    assert_eq!(actual_not_ready, expected_not_ready, "not-ready branch");
    assert!(actual_not_ready.contains("DKIM is not ready yet"));
    assert!(!actual_not_ready.contains("GRYONIXNEXUS_DKIM"));

    // Ready: seed a value for example.com and re-run the SAME fixture body.
    std::fs::write(sandbox.mailcow_dkim_dir.join("example.com.txt"), "v=DKIM1; k=rsa; p=TESTVALUE123").unwrap();
    let actual_ready = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_ready = sandbox.run(&body);
    assert_eq!(actual_ready, expected_ready, "ready branch");
    assert!(actual_ready.contains("GRYONIXNEXUS_DKIM dkim._domainkey.example.com v=DKIM1; k=rsa; p=TESTVALUE123"));
}

/// The DMS/Mailu DKIM wrapper's three real states, all run through the SAME
/// generated pipeline (`<wrapper> | grep … | while read …; done || echo
/// …`): missing, present-and-printing, and — the regression this harness
/// exists to catch — present but printing nothing that matches. All three
/// collapse to the SAME "not ready" line under `pipefail` (see
/// `dkim_wrapper_lines`'s doc); this proves it against real bash, not just
/// against the port's own reasoning about real bash.
#[test]
fn dkim_wrapper_missing_vs_printing_vs_printing_nothing() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let install = reroot_input(&sandbox, base_input());
    let input = host_input(&["docker-mailserver"], HostRole::SingleHost, Language::En, install);
    let topology = services_host_topology(None);
    let body = sandbox.rewrite(&fixture("report_single", "A-dms-access-en"));

    // Missing: no file at all (seed_common_files never writes it) — the
    // default state the bulk fixture_parity loop already exercises.
    let actual_missing = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_missing = sandbox.run(&body);
    assert_eq!(actual_missing, expected_missing, "missing wrapper");
    assert!(actual_missing.contains("not ready yet — run the DKIM setup again on the server"));

    // Present and printing a real record.
    sandbox.write_executable(
        "/opt/gryonixnexus-dms-dkim.sh",
        "#!/bin/bash\nprintf 'GRYONIXNEXUS_DKIM dkim._domainkey.example.com v=DKIM1; k=rsa; p=ABC\\n'\n",
    );
    let actual_printing = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_printing = sandbox.run(&body);
    assert_eq!(actual_printing, expected_printing, "printing wrapper");
    assert!(actual_printing.contains("dkim._domainkey.example.com TXT v=DKIM1; k=rsa; p=ABC"));
    assert!(!actual_printing.contains("not ready yet"));

    // Present, exits 0, prints text with no GRYONIXNEXUS_DKIM line in it — the
    // realistic "key not minted yet" state on a live DMS host, and the case
    // the earlier port got wrong (it printed nothing at all here instead of
    // the pending note).
    sandbox.write_executable("/opt/gryonixnexus-dms-dkim.sh", "#!/bin/bash\necho 'no keys yet'\nexit 0\n");
    let actual_empty = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_empty = sandbox.run(&body);
    assert_eq!(actual_empty, expected_empty, "wrapper ran, printed nothing matching");
    assert!(actual_empty.contains("not ready yet — run the DKIM setup again on the server"));
}

/// The regression class the coordinator flagged separately from the text
/// itself: an earlier version of `dkim_wrapper_lines` consulted
/// `Facts::dkim_wrapper` a second time (a helper re-ran the same wrapper
/// just to ask "was it missing"), which on a real host means running the
/// DKIM dumper twice per report for identical output — invisible in the
/// rendered text, visible only by counting the wrapper's own invocations.
#[test]
fn dkim_wrapper_lines_calls_the_wrapper_at_most_once() {
    let sandbox = Sandbox::new();
    sandbox.write_executable(
        "/opt/gryonixnexus-dms-dkim.sh",
        &format!(
            "#!/bin/bash\necho x >> \"{}\"\nprintf 'GRYONIXNEXUS_DKIM dkim._domainkey.example.com v=DKIM1; k=rsa; p=ABC\\n'\n",
            sandbox.dkim_call_log.display()
        ),
    );
    let facts = TestFacts::new(&sandbox);
    let out = dkim_wrapper_lines(&facts, DMS_DKIM_WRAPPER, "pending note");
    assert!(out.contains("dkim._domainkey.example.com TXT v=DKIM1; k=rsa; p=ABC"));

    let calls = std::fs::read_to_string(&sandbox.dkim_call_log).unwrap_or_default();
    let call_count = calls.lines().count();
    assert_eq!(call_count, 1, "dkim wrapper invoked {call_count} times, expected exactly 1: {calls:?}");
}

/// Passbolt's `.registration-url`: `[ -s file ]` treats an ABSENT file and
/// an EMPTY file the same way (both take the "already configured" branch);
/// only a non-empty file takes the setup-link branch. The bulk
/// fixture_parity loop above only ever exercises "absent" (seed_common_files
/// never creates it) — the other two states are exercised here, against the
/// same real fixture body.
#[test]
fn passbolt_registration_url_absent_vs_empty_vs_present() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let install = reroot_input(&sandbox, base_input());
    let input = host_input(&["passbolt"], HostRole::SingleHost, Language::En, install);
    let topology = services_host_topology(None);
    let body = sandbox.rewrite(&fixture("report_single", "A-passbolt-access-en"));

    // Absent (the default — nothing written).
    let actual_absent = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_absent = sandbox.run(&body);
    assert_eq!(actual_absent, expected_absent, "absent");
    assert!(actual_absent.contains("No setup link available here"));

    // Empty file.
    sandbox.write_file("/opt/passbolt/.registration-url", "");
    let actual_empty = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_empty = sandbox.run(&body);
    assert_eq!(actual_empty, expected_empty, "empty");
    assert!(actual_empty.contains("No setup link available here"));

    // Non-empty — the real setup link, with a trailing newline the way a
    // shell-written file would have one; `$(cat …)` on the bash side strips
    // it, so the port must too (`strip_trailing_newlines`).
    sandbox.write_file(
        "/opt/passbolt/.registration-url",
        "https://passbolt.example.com/setup/install/00000000-0000-0000-0000-000000000000/TOKEN\n",
    );
    let actual_present = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_present = sandbox.run(&body);
    assert_eq!(actual_present, expected_present, "present");
    assert!(actual_present.contains("https://passbolt.example.com/setup/install/"));
    assert!(!actual_present.contains("No setup link available here"));
}

/// Forgejo and GitLab's SSH port: 0 means "switched off", printed as a
/// different sentence entirely rather than "port 0". No fixture covers 0
/// (`GeneratedScriptLintTests.makeVariants()` never sets it — see
/// `ServiceInstallationTests.swift`), so this is a direct `render` check
/// against the `l10n` functions themselves, the same "read, not run" caveat
/// `restore.rs`'s `vps_wrapper` test carries for its own uncovered branch.
#[test]
fn forgejo_and_gitlab_ssh_port_zero_disables_the_git_over_ssh_line() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let mut install = reroot_input(&sandbox, base_input());
    install.forgejo_ssh_port = 0;
    install.gitlab_ssh_port = 0;
    let input = host_input(&["forgejo", "gitlab"], HostRole::SingleHost, Language::En, install);
    let topology = services_host_topology(None);
    let out = render(&input, &topology, &TestFacts::new(&sandbox));

    assert!(out.contains("Git over SSH is off — clone and push over HTTPS with an access token."));
    assert!(!out.contains("Git over SSH: port"));

    // The non-zero case is already exercised by every fixture (defaults are
    // 2222/2223) — this asserts the SAME input with a non-zero port takes
    // the other branch, so the test is proven to see the difference.
    let mut install_nonzero = reroot_input(&sandbox, base_input());
    install_nonzero.forgejo_ssh_port = 2222;
    install_nonzero.gitlab_ssh_port = 2223;
    let input_nonzero = host_input(&["forgejo", "gitlab"], HostRole::SingleHost, Language::En, install_nonzero);
    let out_nonzero = render(&input_nonzero, &topology, &TestFacts::new(&sandbox));
    assert!(out_nonzero.contains("Git over SSH: port 2222"));
    assert!(out_nonzero.contains("Git over SSH: port 2223"));
    assert!(!out_nonzero.contains("Git over SSH is off"));
}

/// Vaultwarden signups open vs. closed — every fixture_parity case above
/// uses the default (`vaultwarden_allow_signups: true`, "open"); the closed
/// branch is exercised here against the same real fixture body run with the
/// setting flipped, so both the SOURCE TEXT for "closed" and the branch
/// itself are proven, not just read off `l10n.rs`.
#[test]
fn vaultwarden_signups_open_vs_closed() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let topology = services_host_topology(None);

    let mut install_closed = reroot_input(&sandbox, base_input());
    install_closed.vaultwarden_allow_signups = false;
    let input_closed = host_input(&["vaultwarden"], HostRole::SingleHost, Language::En, install_closed);
    let out_closed = render(&input_closed, &topology, &TestFacts::new(&sandbox));
    assert!(out_closed.contains("Signups: closed — invite users from the admin panel"));
    assert!(!out_closed.contains("Signups: open"));

    let install_open = reroot_input(&sandbox, base_input());
    let input_open = host_input(&["vaultwarden"], HostRole::SingleHost, Language::En, install_open);
    let out_open = render(&input_open, &topology, &TestFacts::new(&sandbox));
    assert!(out_open.contains("Signups: open"));
}

/// Local-only drops BOTH the PTR line and the DNS reminder — no fixture
/// covers this (see this module's own doc), so it is checked directly
/// against `render` rather than against a bash execution.
#[test]
fn local_only_drops_the_ptr_and_dns_reminder_lines() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let mut install = reroot_input(&sandbox, base_input());
    install.local_only = true;
    let input = host_input(&["vaultwarden"], HostRole::SingleHost, Language::En, install);
    // A local-only deployment has no public address to publish a PTR for,
    // and no DNS artifact was ever generated for it — `ptr_ip: None` is what
    // a real caller would pass here.
    let topology = Topology::ServicesHost {
        ptr_ip: None,
        ptr_hostname: "irrelevant".to_string(),
        tunnel_endpoint: None,
    };
    let out = render(&input, &topology, &TestFacts::new(&sandbox));
    assert!(!out.contains("PTR at your provider"));
    assert!(!out.contains("Remember the DNS records"));
}

// ============================================================================
// Small structural pins — cheap to state directly, expensive to lose.
// ============================================================================

/// `CommandCatalog.installReport` cats this exact literal, without sudo — a
/// contract with already-installed machines.
#[test]
fn the_report_path_is_the_one_the_app_reads() {
    assert_eq!(REPORT_PATH, "/var/lib/gryonixnexus/install-report.txt");
}

/// `DKIMRecordParser` on the app side parses this exact shape out of the
/// report's prose; it must stay ASCII and identically shaped in every
/// language, unlike every human-readable line around it.
#[test]
fn the_dkim_marker_line_is_ascii_and_identically_shaped_in_every_language() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    std::fs::write(sandbox.mailcow_dkim_dir.join("example.com.txt"), "v=DKIM1; k=rsa; p=TESTVALUE123").unwrap();
    let topology = services_host_topology(None);

    for language in [
        Language::En,
        Language::De,
        Language::Fr,
        Language::Es,
        Language::Ru,
        Language::Uk,
        Language::It,
        Language::Ja,
        Language::Zh,
    ] {
        let install = reroot_input(&sandbox, base_input());
        let input = host_input(&["mailcow"], HostRole::SingleHost, language, install);
        let out = render(&input, &topology, &TestFacts::new(&sandbox));
        let marker_line = out
            .lines()
            .find(|l| l.starts_with("GRYONIXNEXUS_DKIM "))
            .unwrap_or_else(|| panic!("no marker line for {language:?} in:\n{out}"));
        assert_eq!(
            marker_line, "GRYONIXNEXUS_DKIM dkim._domainkey.example.com v=DKIM1; k=rsa; p=TESTVALUE123",
            "marker line differs by language ({language:?}), which DKIMRecordParser cannot cope with"
        );
        assert!(marker_line.is_ascii(), "marker line is not ASCII for {language:?}: {marker_line}");
    }
}

/// `render` panics rather than silently producing a report about the wrong
/// machine when the role and the topology variant disagree — the report is
/// the one place a deployment's passwords are written down.
#[test]
#[should_panic(expected = "report topology does not match the host role")]
fn render_panics_when_role_and_topology_disagree() {
    let sandbox = Sandbox::new();
    let install = reroot_input(&sandbox, base_input());
    let input = host_input(&[], HostRole::SingleHost, Language::En, install);
    let topology = Topology::Relay {
        wg_port: 51820,
        forwarded_ports: vec![80],
        home_wg_address: "10.8.0.2".to_string(),
        ptr_hostname: "relay.example.com".to_string(),
    };
    let _ = render(&input, &topology, &TestFacts::new(&sandbox));
}
