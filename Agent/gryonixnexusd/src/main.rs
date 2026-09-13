//! gryonixnexusd — control-plane agent for a single gryonixNexus deployment.
//!
//! Listens on a local Unix socket ONLY (`/run/gryonixnexusd.sock`); the app reaches
//! it through an SSH tunnel, so there is no network-facing control surface. The
//! SSH transport already authenticates the device — the pairing registry (see
//! `state`) exists on top so multiple devices can be listed and revoked, not to
//! gate the transport.
//!
//! Phase 1 (read-only + adoption) is complete: GetState, Discover, Pairing and
//! both streams (HostMetrics, Logs) are live. Mutating RPCs arrive in Phase 2
//! and reuse this same server.
//!
//! State lives in `/var/lib/gryonixnexus/agent` — a subdirectory of the shared
//! product directory, see STATE_DIR. Socket and state dir are overridable via
//! GRYONIXNEXUSD_SOCKET / GRYONIXNEXUSD_STATE_DIR for local runs (binding /run
//! needs root).

mod agent_update;
mod api;
mod backup;
mod container_backup;
mod container_backup_run;
mod container_ops;
mod container_removal;
mod container_schedule;
mod container_update;
mod containers;
mod control;
mod discover;
mod dkim;
// Ф4 слайс 4.0: standing alone in the crate on purpose — no RPC, no `api.rs`
// route yet (see the module doc in dns_records.rs for why). `#[allow(dead_code)]`
// comes off the moment a later slice wires this into `route()`.
#[allow(dead_code)]
mod dns_l10n;
#[allow(dead_code)]
mod dns_records;
mod history;
// Ф4 срез 4.1 ported AdGuard Home's declarative install artifacts (compose
// file, env template, hostname, DNS hostnames, Caddy ingress); срез 4.2
// wired the imperative executor behind it into `Install/InstallService` in
// api.rs::route(), so this module is reachable now. dns_records/dns_l10n
// keep their own `#[allow(dead_code)]` — install-time DNS generation is not
// wired to any RPC yet (see ROADMAP.md).
mod install;
mod jobs;
mod lockdown;
mod mailbox;
/// Read-only status of the host's own intrusion defence (CrowdSec + the
/// nftables bouncer). Installs nothing — `install::crowdsec` from
/// `ProvisionHost` does that; this shows the owner it is working.
mod security;
/// Dynamic DNS — the host keeps its own A records current. The updater is a
/// wrapper and a timer; this module writes them and reports what they did.
mod ddns;
mod mesh;
mod metrics;
mod models;
mod mods;
mod restore;
mod state;
mod uninstall;
/// VPN client devices, driven through the panel's own API — the engine stays in
/// the panel, which owns every protocol's client format AND the lock that keeps
/// two writers from handing one address to two clients.
mod vpn_clients;
mod update;
mod util;
/// The deployment's own service passwords, sealed at rest. The rows live in
/// `state.db`; this module owns the key and the sealing.
mod vault;

/// Types generated from ../proto/gryonixnexusd/v1/gryonixnexusd.proto at build time.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/gryonixnexusd.v1.rs"));
}

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

const SOCKET_PATH: &str = "/run/gryonixnexusd.sock";
/// The agent lives in a SUBDIRECTORY of the product state dir, never in it.
/// `/var/lib/gryonixnexus` is shared with the setup scripts: they write
/// install-report.txt there and the app reads it without sudo (it is the only
/// copy of the credentials generated on the server), so that directory has to
/// stay 0755. The agent's own directory is root-only — state.db holds the
/// paired-device registry.
const STATE_DIR: &str = "/var/lib/gryonixnexus/agent";
const PAIRING_CODE_TTL_SECS: i64 = 600;

/// Binds the control socket at 0700, explicitly — never left to whatever mode
/// `bind` and the process umask would otherwise produce.
///
/// `bind` alone creates the socket at `0777 & ~umask` — 0755 under systemd's
/// default `UMask=0022`, reachable for a `connect()` by every local account,
/// not just root. The unauthenticated RPC policy's only real boundary is this
/// file (`api.rs::session_refusal` lets an unpaired caller through on
/// `never`, the policy's own default), so it must not depend on the umask the
/// service happens to start with. Explicit rather than `RuntimeDirectoryMode`
/// on the systemd unit: `GRYONIXNEXUSD_SOCKET` lets a caller point the agent
/// at an arbitrary path outside that directory, and this covers that case
/// too. See the 2026-09-13 security audit, finding F3.
fn bind_socket(path: &str) -> std::io::Result<tokio::net::UnixListener> {
    // A stale socket from a crashed run would refuse the bind; clear it first.
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(listener)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let socket_path = std::env::var("GRYONIXNEXUSD_SOCKET").unwrap_or_else(|_| SOCKET_PATH.to_string());
    let state_dir = std::env::var("GRYONIXNEXUSD_STATE_DIR").unwrap_or_else(|_| STATE_DIR.to_string());

    // `gryonixnexusd bridge`: splice stdin/stdout to the local API socket. The app
    // runs this over an SSH exec channel to reach the agent — the socket stays
    // private (no TCP port, no streamlocal needed), and SSH already authenticates
    // the device. This is the transport the thin client speaks Connect over.
    //
    // Dispatched BEFORE the state store is opened: the bridge only splices
    // bytes, and it is the app's ONLY way in. Opening state.db first made the
    // single entry point fail on anything wrong with the database — and made
    // every non-root invocation die with "unable to open database file"
    // instead of doing its job.
    if std::env::args().nth(1).as_deref() == Some("bridge") {
        return run_bridge(&socket_path).await;
    }

    // `gryonixnexusd version`: what the bootstrap script asks the installed binary
    // before deciding whether to rebuild. Without it an upgrade cannot tell a
    // current binary from a stale one and either rebuilds every run (minutes of
    // cargo on a Pi) or silently keeps the old agent.
    //
    // Dispatched beside `bridge` and for the same reason: it must answer without
    // root and without a usable state.db.
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("version") | Some("--version") | Some("-V")
    ) {
        println!("gryonixnexusd {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Agent-owned, root-only state. Created here so a fresh install has a home
    // for state.db before the first RPC lands (running outside systemd, or
    // before the unit's StateDirectory= has ever applied).
    //
    // create_dir_all gives every missing component the default 0755, which is
    // right for the SHARED parent and wrong for this leaf: 0700 is set on the
    // leaf ALONE, so the product directory keeps letting the managing user read
    // install-report.txt. Same split systemd applies for us, see the unit.
    std::fs::create_dir_all(&state_dir)?;
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))?;
    let store = state::Store::open(Path::new(&state_dir).join("state.db"))?;

    // **Said out loud here because an unfinished journal is otherwise
    // indistinguishable from a running install.** Nothing this process did not
    // start is running, so every open journal on disk belongs to a previous
    // life — a reboot mid-install, or a crash. Without this the host looks, to
    // anyone reading the log, like a machine still working on something.
    install::journal::sweep_abandoned();
    // Same sweep for every other kind of long run — see `jobs`, which is the
    // install slice's record generalised.
    jobs::sweep_abandoned();

    // `gryonixnexusd pair-code`: mint a one-time code and print it, then exit. The
    // operator runs this over SSH and types the code into the app to enroll a
    // device — the code is deliberately NOT reachable over the API.
    if std::env::args().nth(1).as_deref() == Some("pair-code") {
        let code = store.issue_pairing_code(PAIRING_CODE_TTL_SECS)?;
        println!("Pairing code (valid 10 minutes): {}-{}", &code[..4], &code[4..]);
        return Ok(());
    }

    let store = Arc::new(Mutex::new(store));

    // The agent's own backup timer for container groups the configurator never
    // installed. In-process rather than a systemd unit on purpose — see
    // `container_schedule`'s own note; the short version is that a per-group
    // unit would be a root-owned file no erase wrapper removes.
    container_schedule::spawn(store.clone());
    // Closes the loop on whatever the PREVIOUS process attempted before it
    // triggered its own restart — must run before `spawn` below, which reads
    // the state this leaves behind for `GetAgentUpdateStatus`.
    agent_update::reconcile_on_startup();
    agent_update::spawn();

    let listener = bind_socket(&socket_path)?;
    tracing::info!(socket = %socket_path, "gryonixnexusd listening");

    // Second half of F3: the socket mode keeps out every OTHER account, but a
    // peer that already runs as this process's own user is still let through
    // by the mode alone (e.g. the control user, if the agent were ever
    // started as one). SO_PEERCRED is the actual trust boundary — checked
    // per-connection because a mode is a property of the file, not proof
    // about who is on the other end of any given accept().
    let allowed_uid = unsafe { libc::geteuid() };
    loop {
        let (stream, _addr) = listener.accept().await?;
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == allowed_uid => {}
            Ok(cred) => {
                tracing::warn!(uid = cred.uid(), "rejected connection from an unexpected local uid");
                continue;
            }
            Err(err) => {
                tracing::warn!(?err, "could not read the peer's credentials — rejecting the connection");
                continue;
            }
        }
        let io = TokioIo::new(stream);
        let store = store.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| api::serve(req, store.clone()));
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                tracing::warn!(?err, "connection error");
            }
        });
    }
}

/// Splice this process's stdin/stdout onto the API socket: bytes from stdin go
/// to the agent, the agent's replies go to stdout. The SOCKET side drives the
/// lifetime — the bridge exits when the agent closes the connection (a unary
/// response finishing) or when stdout breaks (a stream the client cancelled by
/// dropping the SSH channel).
///
/// The stdin→socket copy runs in the background and, crucially, does NOT
/// half-close the socket at stdin EOF: every request carries a Content-Length,
/// so the agent never needs a write-EOF to know the body is complete, and
/// half-closing early makes hyper treat the peer as gone and drop the response
/// before sending it (`connection error err=hyper::Error(IncompleteMessage)`).
///
/// Keeping it open takes an explicit `forget()`. Dropping tokio's
/// `OwnedWriteHalf` SHUTS THE WRITE SIDE DOWN — that is its documented
/// behaviour, and letting the copy task end was doing exactly that. The bug hid
/// because it is a race: a reply the agent already wrote wins, so `GetState`
/// looked fine, while `Discover` — which shells out to docker first — lost its
/// response every time. It hid completely over the app's own transport, where
/// stdin is an SSH channel that stays open for the whole call and never reaches
/// EOF; only a piped stdin (a script, a triage one-liner) sees it.
async fn run_bridge(socket_path: &str) -> anyhow::Result<()> {
    bridge(socket_path, tokio::io::stdin(), tokio::io::stdout()).await
}

/// The splice itself, over any byte streams, so the EOF behaviour above can be
/// tested without a process.
async fn bridge<R, W>(socket_path: &str, mut input: R, mut output: W) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let stream = tokio::net::UnixStream::connect(socket_path).await?;
    let (mut socket_read, mut socket_write) = stream.into_split();

    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut input, &mut socket_write).await;
        // Leave the write side OPEN — see the note above. The socket is closed
        // for real when the read half drops, i.e. when this process exits.
        socket_write.forget();
    });

    tokio::io::copy(&mut socket_read, &mut output).await?;
    output.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The bridge must not tell the agent "the client is gone" when the client
    /// has merely finished SENDING. The agent answers slow calls (Discover
    /// shells out to docker) long after the request bytes are in, and a write
    /// shutdown at that moment makes hyper abandon the response — the reply
    /// simply never arrives, with a warning in the journal and nothing on the
    /// client side to explain it. Live-found 2026-08-06.
    #[tokio::test]
    async fn stdin_reaching_eof_does_not_close_the_agent_side_of_the_socket() {
        let path = std::env::temp_dir().join(format!("gryonixnexusd-bridge-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();

        // Stands in for the agent: read the request, take a while (as a real
        // handler does), then report whether the peer closed its write side in
        // the meantime.
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let mut probe = [0u8; 1];
            let peer_hung_up = matches!(stream.try_read(&mut probe), Ok(0));
            stream
                .write_all(if peer_hung_up { b"GONE" } else { b"HERE" })
                .await
                .unwrap();
        });

        // The client sends its request and its stdin ends immediately — a piped
        // stdin, the shape that broke.
        let mut reply = Vec::new();
        super::bridge(path.to_str().unwrap(), std::io::Cursor::new(b"PING".to_vec()), &mut reply)
            .await
            .unwrap();
        server.await.unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            String::from_utf8_lossy(&reply),
            "HERE",
            "the agent saw the bridge hang up while it was still working"
        );
    }

    /// Pins the mode `bind_socket` sets, not the umask the test happens to
    /// run under — the whole point of setting it explicitly (2026-09-13
    /// security audit, finding F3) is that the mode must NOT be a function of
    /// the caller's umask.
    #[tokio::test]
    async fn the_socket_is_locked_to_owner_only_regardless_of_umask() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("gryonixnexusd-mode-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let wide_umask = unsafe { libc::umask(0o000) };
        let listener = super::bind_socket(path.to_str().unwrap()).unwrap();
        unsafe {
            libc::umask(wide_umask);
        }
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        drop(listener);
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode, 0o700, "the socket must be owner-only no matter the process umask");
    }

    /// Cargo.lock has to carry the SAME version as Cargo.toml, because the
    /// bootstrap builds `--locked` (the committed lock file is the pin: an
    /// install must not resolve a different dependency graph than the tests ran
    /// against). A version bump that forgets the lock file leaves both files
    /// looking fine and fails at the only place it shows — on every server, with
    /// "cannot update the lock file … because --locked was passed", after the
    /// toolchain image has already been pulled.
    ///
    /// And the version bump is not optional: it is the upgrade signal the
    /// bootstrap compares against `gryonixnexusd version`, so every change to what
    /// the daemon does to a host goes through here.
    #[test]
    fn cargo_lock_records_the_crate_version_the_manifest_declares() {
        let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
            .expect("Cargo.lock sits beside Cargo.toml");
        let locked = lock
            .split("[[package]]")
            .find(|block| block.contains("name = \"gryonixnexusd\""))
            .and_then(|block| {
                block
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("version = "))
            })
            .map(|value| value.trim().trim_matches('"').to_string())
            .expect("Cargo.lock has an entry for this crate");
        assert_eq!(
            locked,
            env!("CARGO_PKG_VERSION"),
            "Cargo.lock says {locked}, Cargo.toml says {} — run `cargo update -p gryonixnexusd`",
            env!("CARGO_PKG_VERSION")
        );
    }
}
