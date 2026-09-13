//! The shared machinery behind the Containers section's destructive verbs.
//!
//! Backup, removal and update each stream a different event type, but
//! underneath they all do the same two things: run a child process and forward
//! its output line by line, or run one and keep its output. Writing that select
//! loop a third time is how a fixed bug comes back — the crate has already paid
//! for exactly that once, when a new module grew its own reader over
//! stdout/stderr/`wait()` and the two always-ready branches starved the branch
//! that reaps, leaving `systemd-run` as `<defunct>` and the install hung.
//!
//! So there is ONE loop here, and the callers differ only in how they encode a
//! progress line. The encoder is a plain synchronous closure rather than a
//! trait with an async method: an async trait would mean a new dependency, and
//! bootstrap builds the agent `--locked` on the target host, where a lockfile
//! that disagrees with the manifest breaks EVERY server.

use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::Sender;

/// Output of a command whose result is read rather than watched.
pub(crate) struct Captured {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

/// Run a child and forward every line to the client as it arrives.
///
/// `encode` turns one line into a wire frame, which is the only part that
/// differs between the verbs. A send that fails means the client is gone; that
/// is "stop talking", never an error, so it does not fail the run.
///
/// **One deadline for the whole run, never one per line.** `docker compose
/// pull` on a twenty-container stack is silent for long stretches while it
/// moves gigabytes, and a quiet minute is not a hung command. Dropping the
/// future drops the child, and `kill_on_drop` reaps it.
pub(crate) async fn run_streaming(
    bin: &str,
    args: &[String],
    timeout_secs: u64,
    tx: &Sender<Bytes>,
    encode: &(dyn Fn(&'static str, String) -> Bytes + Sync),
) -> Result<(), String> {
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run {bin}: {err}"))?;

    let mut out = child.stdout.take().map(|s| BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| BufReader::new(s).lines());

    let outcome = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = tx.send(encode("stdout", text)).await; }
                        _ => out = None,
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        // docker narrates on stderr ("Pulling 3/3"), so an
                        // stderr line is progress and the exit status is the
                        // only proof of failure.
                        Ok(Some(text)) => { let _ = tx.send(encode("stderr", text)).await; }
                        _ => err = None,
                    }
                }
                else => break,
            }
        }
        child.wait().await
    })
    .await;

    match outcome {
        Err(_) => Err(format!("timed out after {timeout_secs}s")),
        Ok(Err(io)) => Err(format!("{bin} did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(match status.code() {
            Some(code) => format!("{bin} exited {code}"),
            None => format!("{bin} was killed by a signal"),
        }),
    }
}

/// Run a child and keep its output.
///
/// **stdout and stderr stay SEPARATE, and that is not tidiness.** The SSH path
/// once read a password hash out of a stream that also carried docker's own
/// `Digest: sha256:…` line from an image pull, wrote the wrong one into
/// Authelia's user database and left a portal that refused to start — for ever,
/// because the step only wrote the file when it was missing. Merging the two
/// here would re-import that bug into every caller at once.
pub(crate) async fn capture(bin: &str, args: &[String], timeout_secs: u64) -> Result<Captured, String> {
    let child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run {bin}: {err}"))?;

    let output = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
        .await
        .map_err(|_| format!("{bin} timed out after {timeout_secs}s"))?
        .map_err(|err| format!("{bin} did not finish: {err}"))?;

    Ok(Captured {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        success: output.status.success(),
    })
}

/// Run a child, keep stdout, and write it to `dest` only once the command has
/// SUCCEEDED.
///
/// **`docker … > file` in a shell creates the file before the command runs**,
/// so a failed dump leaves an empty file behind — and an empty file is
/// indistinguishable from a real one to the next step that guards on existence.
/// Psono's key generator cost this project exactly that, and the answer there
/// was the same: capture, check, then write.
pub(crate) async fn capture_to_file(
    bin: &str,
    args: &[String],
    dest: &std::path::Path,
    timeout_secs: u64,
) -> Result<u64, String> {
    let out = capture(bin, args, timeout_secs).await?;
    if !out.success {
        let why = out.stderr.trim();
        let why = if why.is_empty() { "no output" } else { why };
        return Err(first_lines(why, 3));
    }
    std::fs::write(dest, out.stdout.as_bytes())
        .map_err(|err| format!("could not write {}: {err}", dest.display()))?;
    Ok(out.stdout.len() as u64)
}

/// The first `n` lines of a message, for an error that has to fit in one event.
/// A dump client's real complaint is on its first line; the rest is a stack of
/// context nobody reads in a progress stream.
pub(crate) fn first_lines(text: &str, n: usize) -> String {
    text.lines().take(n).collect::<Vec<_>>().join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capture_keeps_the_two_streams_apart() {
        let out = capture("sh", &["-c".into(), "echo mine; echo theirs 1>&2".into()], 10)
            .await
            .expect("sh runs");
        assert!(out.success);
        assert_eq!(out.stdout.trim(), "mine");
        assert_eq!(out.stderr.trim(), "theirs");
    }

    /// The Psono lesson, as a test: a failing command must leave NO file, so
    /// the next run's "does it exist" guard cannot read a failure as a result.
    #[tokio::test]
    async fn a_failed_capture_writes_no_file() {
        let dir = std::env::temp_dir().join(format!("gdc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dump.sql");
        let _ = std::fs::remove_file(&dest);

        let err = capture_to_file("sh", &["-c".into(), "echo boom 1>&2; exit 1".into()], &dest, 10)
            .await
            .expect_err("a failing command is an error");
        assert!(err.contains("boom"), "{err}");
        assert!(!dest.exists(), "a failed dump must not leave a file behind");

        // ...and a succeeding one does write.
        capture_to_file("sh", &["-c".into(), "echo rows".into()], &dest, 10).await.expect("writes");
        assert_eq!(std::fs::read_to_string(&dest).unwrap().trim(), "rows");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn streaming_forwards_both_pipes_and_reports_the_exit_status() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        let encode = |stream: &'static str, text: String| Bytes::from(format!("{stream}:{text}"));
        let err = run_streaming("sh", &["-c".into(), "echo a; echo b 1>&2; exit 3".into()], 10, &tx, &encode)
            .await
            .expect_err("exit 3 is a failure");
        assert!(err.contains("exited 3"), "{err}");
        drop(tx);

        let mut seen = Vec::new();
        while let Some(frame) = rx.recv().await {
            seen.push(String::from_utf8_lossy(&frame).into_owned());
        }
        assert!(seen.contains(&"stdout:a".to_string()), "{seen:?}");
        assert!(seen.contains(&"stderr:b".to_string()), "{seen:?}");
    }
}
