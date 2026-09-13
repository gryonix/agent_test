//! Small shared helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock time in Unix milliseconds — the timestamp unit every
/// proto message uses. Falls back to 0 if the clock is before the epoch.
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Remove terminal control noise from an engine's output — a port of the app's
/// ANSIStripper, kept behaviour-for-behaviour identical.
///
/// This is not cosmetics. docker-mailserver colours its OWN error prefix, and
/// that error is the only explanation a user ever gets when a mailbox action
/// fails; the app once put a literal `\e[1;31mERROR\e[0m` into an alert. Text
/// that leaves the agent has to be readable as-is, because the client is not
/// always a terminal and must not have to know that.
pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1B}' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            // CSI: parameters/intermediates until a final byte 0x40–0x7E.
            Some('[') => {
                for byte in chars.by_ref() {
                    if ('\u{40}'..='\u{7E}').contains(&byte) {
                        break;
                    }
                }
            }
            // OSC: terminated by BEL or ESC \.
            Some(']') => {
                while let Some(byte) = chars.next() {
                    if byte == '\u{07}' {
                        break;
                    }
                    if byte == '\u{1B}' {
                        if chars.peek() == Some(&'\\') {
                            chars.next();
                        }
                        break;
                    }
                }
            }
            // Any other two-byte escape: both bytes are consumed already.
            _ => {}
        }
    }
    // Progress bars redraw a line with bare CRs; keep only the final state, the
    // same collapse the app does.
    out.split('\n')
        .map(|line| match line.rfind('\r') {
            Some(index) => &line[index + '\r'.len_utf8()..],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colour_codes_are_removed_and_the_words_are_kept() {
        // The exact shape docker-mailserver prints, and the exact shape that
        // reached an alert as literal escape bytes before the app started
        // stripping on the error path too.
        assert_eq!(
            strip_ansi("\u{1B}[1;31mERROR\u{1B}[0m  Mailbox data directory does not exist"),
            "ERROR  Mailbox data directory does not exist"
        );
        assert_eq!(strip_ansi("plain text"), "plain text");
    }

    #[test]
    fn an_osc_sequence_and_a_redrawn_progress_line_collapse() {
        assert_eq!(strip_ansi("\u{1B}]0;title\u{07}done"), "done");
        assert_eq!(strip_ansi("\u{1B}]0;title\u{1B}\\done"), "done");
        // A progress bar redraws its line with bare CRs: only the final state
        // is text anyone meant to be read.
        assert_eq!(strip_ansi("10%\r50%\r100%\nnext"), "100%\nnext");
    }

    #[test]
    fn a_truncated_escape_does_not_eat_the_rest_of_the_output() {
        // Output cut mid-sequence still has to produce something readable
        // rather than swallowing every following line.
        assert_eq!(strip_ansi("head\u{1B}"), "head");
        assert_eq!(strip_ansi("a\u{1B}[31"), "a");
    }
}

/// One process-wide lock for tests that touch the ENVIRONMENT.
///
/// Every module here has its own `ENV_LOCK`, which is enough while only one
/// module reads a given variable — and `GRYONIXNEXUSD_STATE_DIR` broke that
/// assumption the moment a second one did. `backup`, `update` and
/// `install::execute` all set and REMOVE it, each under a different mutex, so
/// one test's `remove_var` lands in the middle of another's run: the observed
/// failure was `install::execute`'s docker config directory falling back to
/// the real `/var/lib/gryonixnexus` mid-test and failing on permissions, once in
/// every few full runs.
///
/// A shared lock rather than "stop using env vars": the variable is how the
/// binary itself is redirected (`main.rs` reads it), so a test that wants a
/// state directory of its own has no other seam.
#[cfg(test)]
pub static STATE_DIR_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());


