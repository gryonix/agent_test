//! Port of `LockSections` — per-service locking shared by the backup and
//! update wrappers.
//!
//! The reasoning behind every constant here lives in the Swift original
//! (`Packages/gryonixNexus/Sources/MailRecipe/Scripts/LockSections.swift`) and
//! is not repeated: non-blocking `flock`, one lock file PER SERVICE, and two
//! separate NAMESPACES because an update's critical section runs the backup
//! wrapper as a child process — `flock` is per open file description, so the
//! child would be a genuinely different holder of the same path and every
//! update with a backup step would refuse itself.
//!
//! **One thing this port must not "improve": `exec {fd}>` needs bash 4.1.**
//! The dynamic file-descriptor form is what the live host runs (bash 5.x) and
//! it is deliberate, but it is also invisible to `bash -n` under macOS's bash
//! 3.2, which parses `{fd}` as an ordinary word (GOTCHAS.md — it cost two
//! harnesses a day of false failures). Emit it exactly as the generator does.

/// Where per-service lock files live — NOT under `/etc`, which is what keeps
/// it writable from inside the agent's `ProtectSystem=full` sandbox.
pub const DIRECTORY: &str = "/var/lib/gryonixnexus/locks";

/// `sysexits.h`'s `EX_TEMPFAIL`. Nothing else in either wrapper returns it, so
/// one comparison tells "a lock was held" apart from "the operation failed".
pub const BUSY_EXIT_CODE: &str = "75";

/// The `gd_with_lock` helper, byte-identical to `LockSections.helper`.
///
/// Runs its command in the SAME shell rather than a subshell: callers set
/// globals first (`gd_load_service`'s PROJECT/DIR/BACKUP_TARGET/IMAGES,
/// `gd_default_encrypt`'s GD_ENCRYPT) and those must stay visible under the
/// lock.
pub fn helper() -> String {
    format!(
        "GD_LOCK_BUSY={busy}\n\
         \n\
         gd_with_lock() {{\n\
         \x20 local id=\"$1\"\n\
         \x20 shift\n\
         \x20 install -d -m 700 '{dir}'\n\
         \x20 local fd\n\
         \x20 exec {{fd}}>\"{dir}/$id.lock\"\n\
         \x20 if ! flock -n \"$fd\"; then\n\
         \x20   echo \"$id: another backup or update for this service is already running, skipping\" >&2\n\
         \x20   return \"$GD_LOCK_BUSY\"\n\
         \x20 fi\n\
         \x20 \"$@\"\n\
         }}",
        busy = BUSY_EXIT_CODE,
        dir = DIRECTORY
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parity method every file in `install::host` uses, worked once here
    /// so it does not have to be re-derived: the fixture is the heredoc body
    /// of a REAL generated setup script (extracted with
    /// `scratchpad/extract-heredoc-from-generated-script.sh`), which is
    /// literally the bytes `cat` writes on the server — not a transcription of
    /// the Swift source, which would only prove the port matches how the
    /// generator was READ.
    #[test]
    fn the_helper_matches_the_real_generated_script_byte_for_byte() {
        let path = format!(
            "{}/tests/fixtures/install/host/lock-helper.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        let expected = std::fs::read_to_string(&path).expect("fixture");
        assert_eq!(helper(), expected.trim_end_matches('\n'));
    }

    /// The one form `bash -n` on this machine cannot vouch for, so it is
    /// pinned as text instead: the live host parses `exec {fd}>` as a dynamic
    /// descriptor, macOS's bash 3.2 parses it as a word, and a port that
    /// "fixed" it into `exec 9>` would silently stop being the generator's
    /// output.
    #[test]
    fn the_dynamic_descriptor_form_survives_the_port() {
        let helper = helper();
        assert!(helper.contains("exec {fd}>\"/var/lib/gryonixnexus/locks/$id.lock\""));
        assert!(helper.contains("flock -n \"$fd\""));
        assert!(!helper.contains("exec 9>"));
    }

    /// `flock -n`, never a bare `flock`: a scheduled run that hangs on a lock
    /// is worse than one that skips with a reason.
    #[test]
    fn the_lock_is_never_blocking_and_reports_ex_tempfail() {
        assert_eq!(BUSY_EXIT_CODE, "75");
        assert!(helper().contains("GD_LOCK_BUSY=75"));
    }
}
