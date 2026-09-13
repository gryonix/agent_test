//! The root-owned wrapper the APP calls to install or update the agent.
//!
//! **The grant and the script must arrive together.** The app connects as the
//! control user, whose sudoers whitelist is the whole of what it may ask root
//! for; the bootstrap needs root, so "install the agent" is a command
//! the SERVER offers, not one the app composes. `access.rs` emits the
//! whitelist line — and a host provisioned by the agent used to get that line
//! with no script behind it, which is a dangling grant on one side and a
//! button that fails on the other.
//!
//! A byte-for-byte port of `AgentBootstrapSections.wrapper` on the Swift side,
//! pinned by the same parity fixtures as every other wrapper here.

/// The archive the app uploads — always in the control user's own home, the
/// one directory it can always write.
pub fn archive_path(user: &str) -> String {
    if user == "root" {
        "/root/gryonixnexus-agent-src.tar.gz".to_string()
    } else {
        format!("/home/{user}/gryonixnexus-agent-src.tar.gz")
    }
}

pub const UNPACK_ROOT: &str = "/opt/gryonixnexus-agent-src";

/// The wrapper body, exactly as it lands on disk.
pub fn script(user: &str) -> String {
    format!(
        r#"#!/bin/bash
# Managed by gryonixNexus — installs or updates the control-plane agent
# from the archive the app uploaded into the control user's home.
#
# No arguments, deliberately: this runs under sudo, and an argument is
# an argument that reached root. Both paths below are fixed at
# generation time.
set -euo pipefail
ARCHIVE='{archive}'
UNPACK='{unpack}'

[ -s "$ARCHIVE" ] || {{ echo "no agent sources uploaded ($ARCHIVE)" >&2; exit 1; }}

# --no-same-owner: the archive is written on a Mac, so its uids mean
# nothing here, and tar honouring them fails in ways that read like a
# corrupt archive.
rm -rf "$UNPACK"
install -d -m 700 "$UNPACK"
tar -xzf "$ARCHIVE" -C "$UNPACK" --no-same-owner
rm -f "$ARCHIVE"

[ -x "$UNPACK/Agent/bootstrap/install-agent.sh" ] \
  || {{ echo "the uploaded archive carries no bootstrap script" >&2; exit 1; }}
cd "$UNPACK/Agent"
exec bash bootstrap/install-agent.sh
"#,
        archive = archive_path(user),
        unpack = UNPACK_ROOT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte against the generator's own output, lifted out of a real
    /// generated setup script — the same rule every other wrapper here follows:
    /// a port checked against a reading of the generator only proves the port
    /// matches how somebody read it.
    #[test]
    fn matches_the_generators_wrapper() {
        let fixture = include_str!("../../../tests/fixtures/install/host/agent_bootstrap/admin.txt");
        assert_eq!(script("admin"), fixture);
    }

    /// root has no `/home/root`, and a wrapper that looked there would refuse
    /// every upload on a deployment that connects as root.
    #[test]
    fn root_reads_its_own_home() {
        assert_eq!(archive_path("root"), "/root/gryonixnexus-agent-src.tar.gz");
        assert_eq!(archive_path("server-user"), "/home/server-user/gryonixnexus-agent-src.tar.gz");
    }

    /// No arguments anywhere: the sudoers line that authorises this carries
    /// none either, and that pairing is the only thing making it safe.
    #[test]
    fn the_wrapper_takes_no_arguments() {
        let body = script("admin");
        assert!(!body.contains("$1"), "an argument here is an argument that reached root");
        assert!(!body.contains("\"$@\""));
    }
}
