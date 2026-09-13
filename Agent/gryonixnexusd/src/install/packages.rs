//! The two packages every install stands on: docker and Caddy.
//!
//! **Why this module exists at all.** Ф4's goal is to replace the setup
//! scripts, and until 2026-08-13 it did not reach it: measured live, the agent
//! refused on a host with no `/etc/caddy` and NOTHING in it ever installed
//! Caddy, so a "bare host" still needed the very script the agent was meant to
//! replace. Docker was the same story one step earlier — every executor shells
//! out to `docker` and none of them put it there. The refusal was honest, but
//! honest about a hole.
//!
//! **The sandbox is the whole difficulty, and it is not worked around by
//! relaxing it.** `gryonixnexusd.service` runs `ProtectSystem=full`, so `/usr` is
//! read-only inside the agent's mount namespace and `apt`/`dpkg` cannot install
//! anything there — measured, not assumed: `touch /usr/x` inside such a unit
//! returns `Read-only file system`. The escape is `systemd-run`, which is not a
//! fork of this process but a REQUEST TO PID 1 to start a transient unit; that
//! unit gets a fresh namespace and can write `/usr` normally (measured the same
//! way, on the same host, in the same minute — the inner command wrote where
//! the outer one could not). So the hardening stays exactly as it is, and the
//! package work happens outside it.
//!
//! That escape is also the reason this module is deliberately SMALL and its
//! commands are fixed strings. A transient unit runs as root with no sandbox
//! at all, so nothing from a request may ever reach it: every argument below is
//! a `&'static str`, the same rule the service-id gate follows for argv.

use std::path::Path;
use std::time::Duration;

use super::execute::EventSink;

/// Caddy's official apt repository — the same two URLs
/// `ServiceInfraSections.caddyRepository` declares on the SSH path, kept
/// byte-identical on purpose: two ways of installing the same server that
/// disagree about where it comes from would be two different products.
const CADDY_GPG_KEY_URL: &str = "https://dl.cloudsmith.io/public/caddy/stable/gpg.key";
const CADDY_SOURCE_LIST_URL: &str = "https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt";
/// Docker's own convenience script, as `ServiceInfraSections.installDocker`
/// uses it.
const DOCKER_INSTALL_URL: &str = "https://get.docker.com";

/// The one option every `apt-get` this agent runs carries — a port of Swift's
/// `Apt.lockWait`.
///
/// **Bought by a live run on 2026-09-08.** Installing the NVIDIA container
/// toolkit on the owner's machine died on `Could not get lock
/// /var/lib/dpkg/lock-frontend — it is held by process 11273 (unattended-upgr)`.
/// Nothing was wrong with the script: `apt-get` refuses rather than waits, and
/// `unattended-upgrades` fires on a timer shortly after boot, which is exactly
/// when somebody sets a fresh server up. Ten minutes, because a security
/// upgrade that lands mid-install can take several.
pub(crate) const APT_LOCK_WAIT: &str = "-o DPkg::Lock::Timeout=600";

/// Installing a package can take minutes on a small VPS (docker's script pulls
/// a repository and several megabytes of packages), and a deadline that fires
/// mid-`dpkg` leaves the package manager half configured — worse than waiting.
const PACKAGE_TIMEOUT: Duration = Duration::from_secs(900);

/// Is this binary already on the host?
///
/// `command -v` semantics without a shell: walk `PATH` ourselves. A shell would
/// mean quoting a name into a command line, and this is called with fixed names
/// only, so there is nothing to gain and a habit to lose.
// `pub(crate)`, not `pub(super)`: `uninstall` asks the same question about
// `systemd-run` before it decides whether the wrapper can escape the sandbox.
pub(crate) fn have_binary(name: &str) -> bool {
    let Some(path) = search_path() else { return false };
    path.split(':').filter(|dir| !dir.is_empty()).any(|dir| {
        let candidate = Path::new(dir).join(name);
        std::fs::metadata(&candidate).map(|meta| meta.is_file()).unwrap_or(false)
    })
}

/// Where to look for binaries: `PATH`, unless a test has named its own
/// directory of stubs.
///
/// **Tests get their own variable instead of narrowing `PATH` itself**, and
/// that is not squeamishness — it was tried and it broke five unrelated tests
/// at once. `PATH` is process-wide, and the report fixtures EXECUTE real bash;
/// a test that points `PATH` at a directory holding two stubs tells every
/// concurrently running test that this machine has no shell. A lock would only
/// help if every reader took it, and the readers here are `Command::spawn`
/// calls that read `PATH` through the OS. The variable below has exactly one
/// reader — this function — which is the property that makes it safe, and it is
/// checked rather than assumed (`grep` for the name).
fn search_path() -> Option<String> {
    if cfg!(test) {
        if let Ok(stubbed) = std::env::var(BIN_PATH_OVERRIDE) {
            return Some(stubbed);
        }
    }
    std::env::var("PATH").ok()
}

/// Test-only override for the binary search path. Never set on a server.
const BIN_PATH_OVERRIDE: &str = "GRYONIXNEXUSD_INSTALL_BIN_PATH";

/// Make sure docker and Caddy are present, installing them if they are not.
///
/// Both failures are FATAL, and for the same reason a failed Caddy reload is:
/// every step after this one assumes them. A host that reached the end of an
/// install without docker did not install anything.
pub(super) async fn ensure_present(sink: &EventSink) -> Result<(), String> {
    ensure_docker(sink).await?;
    ensure_caddy(sink).await
}

async fn ensure_docker(sink: &EventSink) -> Result<(), String> {
    if have_binary("docker") {
        return Ok(());
    }
    let _ = sink.step("docker is not installed on this host — installing it").await;
    require_apt()?;
    // Piped through `sh` exactly as the setup script does. The URL is fixed and
    // the pipeline is fixed; nothing here is built from a request.
    run_outside_sandbox(
        &format!("curl -fsSL {DOCKER_INSTALL_URL} | sh"),
        "installing docker",
        sink,
    )
    .await?;
    // `enable --now` and not just `start`: a docker that does not come back
    // after a reboot takes every service on the host with it — the same lesson
    // the Caddy unit taught on 2026-08-13, paid once.
    run_outside_sandbox("systemctl enable --now docker", "enabling docker", sink).await?;
    if !have_binary("docker") {
        return Err("docker still is not on PATH after installing it".to_string());
    }
    let _ = sink.step("docker is installed and running").await;
    Ok(())
}

/// NVIDIA's container toolkit — the userspace half of running a model on a
/// card, and the ONLY half this crate installs.
///
/// **The driver is never installed here, and that is a deliberate line.** This
/// package teaches docker to hand an existing device to a container. The driver
/// underneath it is a kernel module — DKMS, kernel headers, secure boot, and a
/// reboot on the far side — and an agent that puts kernel modules on somebody's
/// server can leave a machine that does not come back. The caller checks that a
/// driver ALREADY answers before reaching this function; if none does, the
/// engine runs on the processor and the report says so.
///
/// Idempotent by the same rule as the two above: it is skipped entirely when
/// docker already knows the runtime, which is every re-install after the first.
pub(in crate::install) async fn ensure_nvidia_container_toolkit(sink: &EventSink) -> Result<(), String> {
    let _ = sink
        .step("teaching docker about the graphics card (NVIDIA container toolkit)")
        .await;
    require_apt()?;
    // One transient unit for the whole thing, exactly as Caddy's is: a
    // repository without the install that follows leaves a host with a dangling
    // source list, and the runtime configuration without the package is a
    // docker daemon pointed at a binary that is not there.
    let script = format!(
        "set -e\n\
         export DEBIAN_FRONTEND=noninteractive\n\
         apt-get {APT_LOCK_WAIT} install -y ca-certificates curl gnupg\n\
         curl -fsSL {GPU_KEY_URL} | gpg --batch --yes --dearmor -o {GPU_KEYRING_PATH}\n\
         curl -fsSL {GPU_SOURCE_LIST_URL} | sed 's#deb https://#deb [signed-by={GPU_KEYRING_PATH}] https://#g' > {GPU_SOURCE_LIST_PATH}\n\
         apt-get {APT_LOCK_WAIT} update\n\
         apt-get {APT_LOCK_WAIT} install -y nvidia-container-toolkit\n\
         nvidia-ctk runtime configure --runtime=docker\n\
         systemctl restart docker\n",
        GPU_KEY_URL = crate::install::ollama::GPU_KEY_URL,
        GPU_KEYRING_PATH = crate::install::ollama::GPU_KEYRING_PATH,
        GPU_SOURCE_LIST_URL = crate::install::ollama::GPU_SOURCE_LIST_URL,
        GPU_SOURCE_LIST_PATH = crate::install::ollama::GPU_SOURCE_LIST_PATH,
    );
    run_outside_sandbox(&script, "installing the NVIDIA container toolkit", sink).await
}

async fn ensure_caddy(sink: &EventSink) -> Result<(), String> {
    if have_binary("caddy") {
        return Ok(());
    }
    let _ = sink.step("Caddy is not installed on this host — installing it").await;
    require_apt()?;
    // One transient unit for the whole thing: the repository is useless without
    // the install that follows it, and splitting them would leave a host with a
    // dangling source list when the second half failed.
    let script = format!(
        "set -e\n\
         export DEBIAN_FRONTEND=noninteractive\n\
         apt-get {APT_LOCK_WAIT} install -y debian-keyring debian-archive-keyring \
         apt-transport-https curl gnupg\n\
         curl -fsSL {CADDY_GPG_KEY_URL} | gpg --batch --yes --dearmor \
             -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg\n\
         curl -fsSL {CADDY_SOURCE_LIST_URL} > /etc/apt/sources.list.d/caddy-stable.list\n\
         apt-get {APT_LOCK_WAIT} update\n\
         apt-get {APT_LOCK_WAIT} install -y caddy\n"
    );
    run_outside_sandbox(&script, "installing Caddy", sink).await?;
    run_outside_sandbox("systemctl enable --now caddy", "enabling Caddy", sink).await?;
    if !have_binary("caddy") {
        return Err("caddy still is not on PATH after installing it".to_string());
    }
    let _ = sink.step("Caddy is installed and running").await;
    Ok(())
}

/// Both installers are apt-shaped, which mirrors `DistributionProfile`'s only
/// implementations (Debian and Ubuntu). Say so plainly rather than running
/// apt commands on a host that has none and reporting whatever error that
/// produces — the operator can act on "this build only knows apt".
fn require_apt() -> Result<(), String> {
    if have_binary("apt-get") {
        return Ok(());
    }
    Err("this host has no apt-get, and the agent only knows how to install packages on \
         Debian/Ubuntu — install docker and Caddy by hand, or run the setup script"
        .to_string())
}

/// Run a shell script as a TRANSIENT SYSTEMD UNIT, outside this process's
/// sandbox, streaming its output.
///
/// `systemd-run --wait --pipe` hands the work to PID 1, so the child does not
/// inherit `ProtectSystem=full` and can write `/usr`. `--collect` removes the
/// unit afterwards even when it failed, so a host does not accumulate failed
/// units nobody will read.
///
/// **The reader is the executor's, not a second one.** The first version of
/// this function grew its own `select!` loop over stdout/stderr/`wait()`, and
/// on the first bare-host run it hung: the transient unit finished, its
/// `systemd-run` went `<defunct>`, and the install sat there — a child that had
/// exited and was never reaped, because two instantly-ready pipe branches can
/// starve the branch that reaps. `run_child_streaming` already solves exactly
/// this, and duplicating a solved problem is how a fixed bug comes back.
pub(super) async fn run_outside_sandbox(script: &str, what: &str, sink: &EventSink) -> Result<(), String> {
    let args: Vec<String> = vec![
        "--quiet".into(),
        "--collect".into(),
        "--wait".into(),
        "--pipe".into(),
        "--service-type=oneshot".into(),
        "/bin/sh".into(),
        "-c".into(),
        script.to_string(),
    ];
    super::execute::run_child_streaming(
        Path::new(&systemd_run_bin()),
        &args,
        None,
        &[],
        None,
        PACKAGE_TIMEOUT,
        sink,
    )
    .await
    .map_err(|err| format!("{what} failed: {err}"))
}

/// Run a script outside the sandbox the way [`run_outside_sandbox`] does, but
/// with the script on DISK instead of on the transient unit's command line.
///
/// **Found live on `vps-middle` 2026-09-01, installing CrowdSec.** Its
/// post-installation script calls `cscli setup unattended`, which enumerates
/// the host's units with `systemctl show <unit> --all` and parses the result as
/// `key=value` lines. The unit it was looking at was OURS — the transient one
/// running the install — and its `ExecStart` carried our whole multi-line shell
/// script, so `systemctl show` emitted a property whose value spans lines and
/// cscli died on `unexpected line: "curl -fsSL https://install.crowdsec.net |
/// sh"`. dpkg then failed the package, and the agent reported an install that
/// had genuinely not happened.
///
/// A script on disk makes the command line one short argument, so no child
/// process can be handed our newlines through systemd's own properties. That is
/// a property worth having for anything whose packaging inspects the system it
/// is being installed on, which is not a small class.
///
/// `/run` rather than `/tmp`: it is a tmpfs that does not survive a reboot, the
/// agent's unit can write it, and a leftover install script under a
/// world-readable /tmp is a file nobody meant to publish. 0700 and removed
/// afterwards either way.
pub(super) async fn run_outside_sandbox_from_file(
    script: &str,
    what: &str,
    sink: &EventSink,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::path::PathBuf::from(format!("/run/gryonixnexusd-install-{}.sh", std::process::id()));
    std::fs::write(&path, script).map_err(|err| format!("{what} failed: could not stage the script: {err}"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("{what} failed: could not stage the script: {err}"))?;
    let outcome = run_outside_sandbox(&format!("/bin/sh {}", path.display()), what, sink).await;
    let _ = std::fs::remove_file(&path);
    outcome
}

/// Overridable for tests, the same technique `docker_bin`/`systemctl_bin` use:
/// a stub records argv and exits how the test wants. A server never sets it.
fn systemd_run_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN").unwrap_or_else(|_| "systemd-run".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One lock for the one variable these tests set and REMOVE, per the rule
    /// two separate incidents already bought (`util::STATE_DIR_ENV_LOCK`'s doc).
    /// It lives here because this module holds its only reader — checked, not
    /// assumed.
    static BIN_PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn a_binary_that_exists_is_found_and_a_made_up_one_is_not() {
        // `sh` is on PATH on every host this ever runs on, including the mac
        // this test runs on; the second name is not a binary anywhere.
        assert!(have_binary("sh"));
        assert!(!have_binary("gryonixnexus-definitely-not-a-binary"));
    }

    /// Build a directory of stub binaries and point `PATH` at it alone, so the
    /// test decides what this "host" has instead of inheriting whatever the
    /// developer's machine happens to carry — the same lesson as faking
    /// "docker is absent" with the system PATH, which passed on a mac and
    /// accused the product on every Linux box (GOTCHAS.md).
    fn stub_host(name: &str, stubs: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-pkg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("stub dir");
        for (binary, body) in stubs {
            let path = dir.join(binary);
            std::fs::write(&path, body).expect("stub");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        dir
    }

    /// The whole point of the module, end to end: a host with neither binary
    /// gets both, and the work goes through `systemd-run` rather than being
    /// attempted inside the agent's own read-only `/usr`.
    ///
    /// The stub does not merely exit 0 — it CREATES the binaries it claims to
    /// install, so the post-install `have_binary` check is exercised for real.
    /// A stub that only recorded argv would pass while the product forgot to
    /// verify anything, which is the failure this project keeps paying for.
    #[tokio::test]
    async fn a_host_with_neither_binary_gets_both_through_systemd_run() {
        let _guard = BIN_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let log = std::env::temp_dir().join(format!("gryonixnexusd-pkg-log-{}", std::process::id()));
        let _ = std::fs::remove_file(&log);
        let dir = stub_host(
            "bare",
            &[
                ("apt-get", "#!/bin/sh\nexit 0\n"),
                // Records what it was asked to run, then "installs" by creating
                // the binary the caller is about to look for.
                (
                    "systemd-run",
                    &format!(
                        "#!/bin/sh\necho \"$@\" >> '{}'\ncase \"$*\" in\n  *get.docker.com*) : > \"$(dirname \"$0\")/docker\"; chmod 755 \"$(dirname \"$0\")/docker\" ;;\n  *caddy*) : > \"$(dirname \"$0\")/caddy\"; chmod 755 \"$(dirname \"$0\")/caddy\" ;;\nesac\nexit 0\n",
                        log.display()
                    ),
                ),
            ],
        );
        std::env::set_var(BIN_PATH_OVERRIDE, &dir);
        // `have_binary` looks in the stub directory, but spawning still goes
        // through the real PATH — so the binary that is actually EXECUTED has
        // to be pointed at the stub explicitly. Missing this made the test fail
        // with "No such file or directory" on a mac, which reads like a product
        // bug and is not one.
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN", dir.join("systemd-run"));

        let (tx, _rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);
        let sink = crate::install::execute::EventSink::for_test(tx, "vaultwarden");
        let result = ensure_present(&sink).await;

        std::env::remove_var(BIN_PATH_OVERRIDE);
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN");
        assert_eq!(result, Ok(()), "both packages must be installable on a bare host");
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(calls.contains("get.docker.com"), "docker must be installed: {calls}");
        assert!(calls.contains("caddy"), "caddy must be installed: {calls}");
        assert!(calls.contains("--pipe"), "the work must go through a transient unit: {calls}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&log);
    }

    /// A host that already has both is left completely alone — no apt, no
    /// transient unit, nothing. Installing on every run would reconfigure a
    /// working machine on a repair.
    #[tokio::test]
    async fn a_host_that_already_has_both_runs_nothing() {
        let _guard = BIN_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let log = std::env::temp_dir().join(format!("gryonixnexusd-pkg-log2-{}", std::process::id()));
        let _ = std::fs::remove_file(&log);
        let dir = stub_host(
            "ready",
            &[
                ("docker", "#!/bin/sh\nexit 0\n"),
                ("caddy", "#!/bin/sh\nexit 0\n"),
                ("apt-get", "#!/bin/sh\nexit 0\n"),
                ("systemd-run", &format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 0\n", log.display())),
            ],
        );
        std::env::set_var(BIN_PATH_OVERRIDE, &dir);
        // `have_binary` looks in the stub directory, but spawning still goes
        // through the real PATH — so the binary that is actually EXECUTED has
        // to be pointed at the stub explicitly. Missing this made the test fail
        // with "No such file or directory" on a mac, which reads like a product
        // bug and is not one.
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN", dir.join("systemd-run"));

        let (tx, _rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);
        let sink = crate::install::execute::EventSink::for_test(tx, "vaultwarden");
        let result = ensure_present(&sink).await;

        std::env::remove_var(BIN_PATH_OVERRIDE);
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN");
        assert_eq!(result, Ok(()));
        assert!(!log.exists(), "nothing should have been run: {:?}", std::fs::read_to_string(&log));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A host with no apt is refused in its own words rather than being handed
    /// apt commands to fail on.
    #[tokio::test]
    async fn a_host_without_apt_is_told_so_instead_of_being_guessed_at() {
        let _guard = BIN_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = stub_host("noapt", &[("systemd-run", "#!/bin/sh\nexit 0\n")]);
        std::env::set_var(BIN_PATH_OVERRIDE, &dir);
        // `have_binary` looks in the stub directory, but spawning still goes
        // through the real PATH — so the binary that is actually EXECUTED has
        // to be pointed at the stub explicitly. Missing this made the test fail
        // with "No such file or directory" on a mac, which reads like a product
        // bug and is not one.
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN", dir.join("systemd-run"));

        let (tx, _rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);
        let sink = crate::install::execute::EventSink::for_test(tx, "vaultwarden");
        let result = ensure_present(&sink).await;

        std::env::remove_var(BIN_PATH_OVERRIDE);
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN");
        let err = result.expect_err("no apt means no automatic install");
        assert!(err.contains("apt-get"), "the refusal must name what is missing: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_caddy_repository_matches_the_one_the_setup_script_uses() {
        // Pinned as literals because the SSH path declares the same two URLs in
        // Swift (`ServiceInfraSections.caddyRepository`) and the two cannot
        // share a type — the same duplication the GRYONIXNEXUS_* markers have,
        // caught the same way: a test on each side.
        assert_eq!(CADDY_GPG_KEY_URL, "https://dl.cloudsmith.io/public/caddy/stable/gpg.key");
        assert_eq!(CADDY_SOURCE_LIST_URL, "https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt");
        assert_eq!(DOCKER_INSTALL_URL, "https://get.docker.com");
    }
}
