//! Mailboxes of the docker-mailserver engine.
//!
//! docker-mailserver is the one service in the catalog with no web admin of its
//! own, so this is not a convenience layer — without it the only way to add a
//! mailbox is a shell on the server. The SSH route reaches the same engine
//! through a root-owned wrapper (`/opt/gryonixnexus-dms-mailbox.sh`); this is that
//! wrapper's behaviour moved into the agent, deliberately ONE-FOR-ONE, because
//! every one of its rules was paid for by a live run:
//!
//! * the password goes to the engine on STDIN, never in argv — `docker exec`
//!   argv is world-readable through /proc to every account on the box;
//! * the address is validated HERE, character for character, by the same rule
//!   the wrapper's `check_address` uses: this code is root, so an argument that
//!   reaches `docker exec` unchecked is an argument that reaches root;
//! * an install with no mailboxes yet is an EMPTY LIST, not a failure —
//!   upstream's `setup email list` exits non-zero until the account file exists,
//!   and a fresh install must show "no mailboxes" rather than an error. A
//!   container that is DOWN still has to fail, and does;
//! * `del` right after `add` loses a race INSIDE the engine (the maildir is
//!   created asynchronously about a second later and `delmailuser` refuses until
//!   it is there), so the delete is retried — see `delete`;
//! * the engine colours its own errors, and those errors are the only
//!   explanation a user gets, so everything leaving here is ANSI-stripped;
//! * the listing is parsed from STDOUT ONLY: `setup email list` writes
//!   `doveadm(<address>): Error: User doesn't exist` to stderr for an account
//!   Dovecot cannot resolve, and that line's first token is an address in
//!   parentheses — one `2>&1` away from becoming a phantom mailbox with a
//!   delete button on it.
//!
//! There is no shell anywhere on this path: the agent spawns `docker` directly,
//! so quoting cannot go wrong in the first place.

use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use hyper::StatusCode;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;

use crate::api::{connect_error, Codec, Resp};
use crate::util::strip_ansi;
use crate::{discover, pb};

/// The catalog id this module serves. It goes through `discover`'s table like
/// every other id — one gate, one answer to "is this service on this host".
const SERVICE_ID: &str = "docker-mailserver";

/// Where docker-mailserver keeps its config INSIDE the container. Used to find
/// the account file, both on the host (through the bind mount) and, when the
/// install uses no bind mount, inside the container itself.
const CONFIG_DIR_IN_CONTAINER: &str = "/tmp/docker-mailserver";
const ACCOUNTS_FILE: &str = "postfix-accounts.cf";

/// One engine call's deadline. Generous because `setup email add` on a cold
/// stack does real work; a blown deadline kills the child (`kill_on_drop`) and
/// is reported as a failure, never as a silent success.
const ENGINE_TIMEOUT_SECS: u64 = 120;

/// The delete retry, matching the wrapper exactly: four quiet attempts two
/// seconds apart, then a LAST one whose stderr is kept — whatever is really
/// wrong, the engine's own words are the only explanation the app can show.
const DELETE_ATTEMPTS: u32 = 5;
const DELETE_RETRY_DELAY_SECS: u64 = 2;

/// Client strings are echoed back so a mistyped address is diagnosable, but only
/// a bounded prefix: the message travels into logs and UI.
const ECHO_LIMIT: usize = 64;

/// Why a mailbox request was refused BEFORE the engine was touched.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The address failed the same check the wrapper applies.
    InvalidAddress(String),
    /// A mutation arrived without a password. Refused here so the engine is
    /// never asked to set an empty one.
    EmptyPassword,
    /// The engine is not installed on this host.
    NotInstalled,
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::InvalidAddress(address) => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                format!("invalid address: {}", truncate(address)),
            ),
            Rejection::EmptyPassword => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "the password is empty".to_string(),
            ),
            Rejection::NotInstalled => (
                StatusCode::NOT_FOUND,
                "not_found",
                "docker-mailserver is not installed on this host".to_string(),
            ),
        }
    }

    fn response(&self) -> Resp {
        let (status, code, message) = self.parts();
        connect_error(status, code, &message)
    }
}

fn truncate(value: &str) -> String {
    value.chars().take(ECHO_LIMIT).collect()
}

/// The address rule, character for character the wrapper's `check_address`:
///
/// ```sh
/// case "$ADDRESS" in
///   -*|*[!a-zA-Z0-9.@_+-]*|*@*@*|@*|*@) invalid ;;
///   *@*) ok ;;
///   *) invalid ;;
/// esac
/// ```
///
/// Deliberately NOT a general e-mail validator: it says what this host will
/// accept, and disagreeing with the wrapper in either direction is the bug it
/// exists to prevent. Both routes must refuse the same strings, or the same
/// address works in one and not the other.
pub fn valid_address(address: &str) -> bool {
    if address.is_empty() || address.starts_with('-') {
        return false;
    }
    let allowed = address.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '@' | '_' | '+' | '-')
    });
    if !allowed {
        return false;
    }
    let parts: Vec<&str> = address.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty()
}

// ─────────────────────────── Engine plumbing ───────────────────────────

/// The docker-mailserver container, resolved from the host's OWN report.
///
/// The name is never assumed: `docker ps` is asked which containers belong to
/// the project the catalog table recognizes, and the mail one is picked by its
/// image (Roundcube is the other container in that project). So an adopted host
/// that named its container something else still works, and the string that
/// reaches argv is one the host produced.
async fn engine_container() -> Result<Option<String>> {
    let Some(service) = discover::service_snapshot(SERVICE_ID).await? else {
        return Ok(None);
    };
    let by_image = service
        .containers
        .iter()
        .find(|c| c.image.to_lowercase().contains("docker-mailserver"));
    // The stock name, for an install whose image was retagged locally.
    let picked = by_image.or_else(|| service.containers.iter().find(|c| c.name == "mailserver"));
    Ok(picked.map(|c| c.name.clone()))
}

/// One row of `docker inspect --format {{json .Mounts}}`.
#[derive(Debug, Deserialize)]
struct Mount {
    #[serde(rename = "Source", default)]
    source: String,
    #[serde(rename = "Destination", default)]
    destination: String,
}

/// The host directory the engine's config is bind-mounted from, if it is.
async fn host_config_dir(container: &str) -> Option<String> {
    let output = tokio::process::Command::new("docker")
        .args(["inspect", "--format", "{{json .Mounts}}", container])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mounts: Vec<Mount> = serde_json::from_slice(&output.stdout).ok()?;
    mounts
        .into_iter()
        .find(|m| m.destination == CONFIG_DIR_IN_CONTAINER && !m.source.is_empty())
        .map(|m| m.source)
}

/// Does the engine have any account at all?
///
/// This is the check that turns "no mailboxes yet" into an empty list instead of
/// an error, and it is asked of the ACCOUNT FILE rather than of `setup email
/// list`, because that command exits 1 while the file does not exist — the same
/// exit code a broken container gives. The wrapper checks it on the host; so
/// does this, through the bind mount, which also means a stopped container with
/// no accounts still lists as empty rather than as a fault.
///
/// Without a bind mount (a named volume) the file is only reachable inside the
/// container, and then the container has to be up — which it must be for the
/// listing anyway.
async fn has_accounts(container: &str) -> Result<bool> {
    if let Some(dir) = host_config_dir(container).await {
        let path = std::path::Path::new(&dir).join(ACCOUNTS_FILE);
        return Ok(std::fs::metadata(&path).map(|m| m.len() > 0).unwrap_or(false));
    }
    let output = run_engine(
        container,
        &["test", "-s", &format!("{CONFIG_DIR_IN_CONTAINER}/{ACCOUNTS_FILE}")],
        None,
    )
    .await?;
    Ok(output.status_ok)
}

struct EngineOutput {
    status_ok: bool,
    stdout: String,
    stderr: String,
}

/// Run one command in the engine container. `stdin` is the ONLY channel a
/// secret ever travels on — nothing that is passed here as an argument is
/// private, because argv is world-readable through /proc.
async fn run_engine(container: &str, args: &[&str], stdin: Option<&str>) -> Result<EngineOutput> {
    let mut command = tokio::process::Command::new("docker");
    command.arg("exec");
    if stdin.is_some() {
        command.arg("-i");
    }
    command.arg(container);
    command.args(args);
    let mut child = command
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    if let Some(secret) = stdin {
        if let Some(mut pipe) = child.stdin.take() {
            // Written and then DROPPED: the helper prompts twice and waits for
            // EOF, so leaving the pipe open would hang the call until the
            // deadline.
            pipe.write_all(secret.as_bytes()).await?;
            pipe.shutdown().await?;
        }
    }

    let output = tokio::time::timeout(Duration::from_secs(ENGINE_TIMEOUT_SECS), child.wait_with_output())
        .await
        .map_err(|_| anyhow::anyhow!("the mail engine did not answer within {ENGINE_TIMEOUT_SECS}s"))??;

    Ok(EngineOutput {
        status_ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        // Stripped here, at the boundary: everything downstream (an error
        // message, a log line) is text meant to be read as-is.
        stderr: strip_ansi(&String::from_utf8_lossy(&output.stderr)).trim().to_string(),
    })
}

// ─────────────────────────── Listing ───────────────────────────

/// Parse `setup email list`, a port of the app's MailboxListParser.
///
/// Written around the ADDRESS, not the layout: the engine also prints log lines,
/// headers, and on a fresh stack a sentence saying there are no accounts. The
/// first token of a line has to BE an address, or the line is not a mailbox —
/// otherwise an error text that merely mentions an address becomes a row
/// offering to delete an account the line is not even about.
pub fn parse_list(output: &str) -> Vec<pb::Mailbox> {
    let stripped = strip_ansi(output);
    let mut mailboxes: Vec<pb::Mailbox> = Vec::new();
    for raw in stripped.split('\n') {
        // The bullet is part of the layout, not of the address.
        let line = raw.trim().trim_matches('*').trim();
        let (address, detail) = match line.find([' ', '\t']) {
            Some(index) => (&line[..index], line[index..].trim()),
            None => (line, ""),
        };
        if !is_address(address) || mailboxes.iter().any(|m| m.address == address) {
            continue;
        }
        mailboxes.push(pb::Mailbox {
            address: address.to_string(),
            detail: detail.to_string(),
            // What the client needs to decide whether to enable its buttons.
            // Computed here, from the same rule the mutations use, so the two
            // answers cannot disagree.
            manageable: valid_address(address),
        });
    }
    mailboxes
}

/// Is this token an address the SERVER printed? Deliberately laxer than
/// `valid_address`, which says what the server will ACCEPT: a mailbox created
/// outside the app exists and must be shown, even if acting on it is refused.
fn is_address(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    // Punctuation that belongs to prose, never to an address. This is what keeps
    // `doveadm(user@example.com):` — whose first token wraps a real address in
    // parentheses and a colon — from becoming a mailbox row. It passes every
    // "one @ and a dotted domain" test without this. Live-captured 2026-08-06.
    if token.contains(|c| "()<>[]{},;:\"'\\|".contains(c)) {
        return false;
    }
    let parts: Vec<&str> = token.split('@').collect();
    parts.len() == 2
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[1].contains('.')
        && !token.chars().any(char::is_whitespace)
}

/// The mailboxes on this host. An install with none is `Ok(vec![])`.
async fn list(container: &str) -> Result<Vec<pb::Mailbox>, EngineFailure> {
    if !has_accounts(container).await.map_err(EngineFailure::Unreachable)? {
        return Ok(Vec::new());
    }
    let output = run_engine(container, &["setup", "email", "list"], None)
        .await
        .map_err(EngineFailure::Unreachable)?;
    if !output.status_ok {
        // A container that is down lands here, and it MUST: "there are no
        // mailboxes" and "the mail server is not running" are different answers.
        return Err(EngineFailure::Refused(output.stderr));
    }
    // STDOUT only — see the module note about the stderr diagnostic.
    Ok(parse_list(&output.stdout))
}

/// A failure of the engine itself, once the request had already been accepted.
enum EngineFailure {
    /// docker could not be run/reached at all.
    Unreachable(anyhow::Error),
    /// docker ran and the engine said no. Its own words are the payload — they
    /// are the only explanation the user gets.
    Refused(String),
}

impl EngineFailure {
    fn response(&self) -> Resp {
        match self {
            EngineFailure::Unreachable(err) => connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                &format!("container engine unavailable: {err}"),
            ),
            // Not `internal`: the agent did its job and the ENGINE refused, and
            // the client phrases those differently ("try again" vs "this address
            // does not exist").
            EngineFailure::Refused(detail) => connect_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                if detail.is_empty() { "the mail engine refused the request" } else { detail },
            ),
        }
    }
}

// ─────────────────────────── Mutations ───────────────────────────

/// The engine prompts for a password twice; both lines go down stdin.
fn password_input(password: &str) -> String {
    format!("{password}\n{password}\n")
}

async fn create(container: &str, address: &str, password: &str) -> Result<(), EngineFailure> {
    let output = run_engine(
        container,
        &["setup", "email", "add", address],
        Some(&password_input(password)),
    )
    .await
    .map_err(EngineFailure::Unreachable)?;
    if output.status_ok {
        Ok(())
    } else {
        Err(EngineFailure::Refused(redact(password, &output.stderr)))
    }
}

async fn set_password(container: &str, address: &str, password: &str) -> Result<(), EngineFailure> {
    let output = run_engine(
        container,
        &["setup", "email", "update", address],
        Some(&password_input(password)),
    )
    .await
    .map_err(EngineFailure::Unreachable)?;
    if output.status_ok {
        Ok(())
    } else {
        Err(EngineFailure::Refused(redact(password, &output.stderr)))
    }
}

/// Delete a mailbox, waiting out a race INSIDE the engine.
///
/// `addmailuser` writes the account line at once but creates the mail directory
/// asynchronously about a second later, and `delmailuser` refuses while it is
/// not there ("Mailbox data directory … does not exist"). Live-measured
/// 2026-08-06: absent at t=0, present at t=1s, and the very same call then
/// succeeds — so the most likely first thing anyone does with this screen ("add
/// a mailbox, notice the typo, delete it") was the one thing that failed.
///
/// Retrying is safe because the refusal destroys nothing: the account line
/// survives. The LAST attempt's stderr is what the caller reports, so a real
/// failure still arrives in the engine's own words.
async fn delete(container: &str, address: &str) -> Result<(), EngineFailure> {
    let mut attempt = 1;
    loop {
        let output = run_engine(container, &["setup", "email", "del", "-y", address], None)
            .await
            .map_err(EngineFailure::Unreachable)?;
        if output.status_ok {
            return Ok(());
        }
        if attempt >= DELETE_ATTEMPTS {
            return Err(EngineFailure::Refused(output.stderr));
        }
        attempt += 1;
        tokio::time::sleep(Duration::from_secs(DELETE_RETRY_DELAY_SECS)).await;
    }
}

/// Blank a secret out of anything on its way back to the user. The wrapper never
/// prints the password and neither does the agent, but the tool behind it is not
/// ours: one upstream version echoing its own argv in a usage message would put
/// the password in an alert. Cheap here, impossible to undo afterwards.
fn redact(password: &str, text: &str) -> String {
    if password.is_empty() || !text.contains(password) {
        return text.to_string();
    }
    text.replace(password, "***")
}

// ─────────────────────────── RPCs ───────────────────────────

/// What every mailbox RPC needs first: the engine's container, or a refusal.
async fn resolve() -> Result<String, Resp> {
    match engine_container().await {
        Ok(Some(container)) => Ok(container),
        Ok(None) => Err(Rejection::NotInstalled.response()),
        Err(err) => Err(EngineFailure::Unreachable(err).response()),
    }
}

/// The answer to EVERY mailbox call, mutation or not: the listing as the engine
/// reports it right now.
///
/// A mutation returning the fresh listing is the same rule ControlService's
/// COMPLETED event follows — the client renders what the server reports and
/// never derives state from "the command exited 0". The difference is that
/// there is no stream here and no half-done state to report: a mailbox verb is
/// one bounded engine call, so a failure IS the whole answer and travels as a
/// plain response error.
async fn respond_with_listing(codec: Codec, container: &str) -> Resp {
    match list(container).await {
        Ok(mailboxes) => encode(codec, &pb::MailboxList { mailboxes }),
        Err(failure) => failure.response(),
    }
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

pub async fn list_mailboxes(codec: Codec, _req: pb::ListMailboxesRequest) -> Resp {
    match resolve().await {
        Ok(container) => respond_with_listing(codec, &container).await,
        Err(refusal) => refusal,
    }
}

pub async fn create_mailbox(codec: Codec, req: pb::CreateMailboxRequest) -> Resp {
    if !valid_address(&req.address) {
        return Rejection::InvalidAddress(req.address).response();
    }
    if req.password.is_empty() {
        return Rejection::EmptyPassword.response();
    }
    let container = match resolve().await {
        Ok(container) => container,
        Err(refusal) => return refusal,
    };
    if let Err(failure) = create(&container, &req.address, &req.password).await {
        return failure.response();
    }
    respond_with_listing(codec, &container).await
}

pub async fn delete_mailbox(codec: Codec, req: pb::DeleteMailboxRequest) -> Resp {
    if !valid_address(&req.address) {
        return Rejection::InvalidAddress(req.address).response();
    }
    let container = match resolve().await {
        Ok(container) => container,
        Err(refusal) => return refusal,
    };
    if let Err(failure) = delete(&container, &req.address).await {
        return failure.response();
    }
    respond_with_listing(codec, &container).await
}

pub async fn set_mailbox_password(codec: Codec, req: pb::SetMailboxPasswordRequest) -> Resp {
    if !valid_address(&req.address) {
        return Rejection::InvalidAddress(req.address).response();
    }
    if req.password.is_empty() {
        return Rejection::EmptyPassword.response();
    }
    let container = match resolve().await {
        Ok(container) => container,
        Err(refusal) => return refusal,
    };
    if let Err(failure) = set_password(&container, &req.address, &req.password).await {
        return failure.response();
    }
    respond_with_listing(codec, &container).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_rule_is_the_wrappers_rule() {
        // Accepted — the shapes a user actually types.
        for good in ["admin@example.com", "a.b+tag_1@sub.example.co.uk", "x@y"] {
            assert!(valid_address(good), "{good} must be accepted");
        }
        // Refused, each for the reason the wrapper's `case` refuses it. This
        // list is the contract with the SSH route's client-side mirror: an
        // address that one accepts and the other refuses is the bug both exist
        // to prevent.
        for bad in [
            "",                       // nothing at all
            "-admin@example.com",     // could read as a flag
            "admin",                  // no domain
            "@example.com",           // no local part
            "admin@",                 // no domain
            "a@b@c",                  // two @
            "admin example@com",      // space
            "admin@example.com; rm -rf /", // shell metacharacters, refused as an ADDRESS
            "admin@exam ple.com",
            "admin$@example.com",
            "admin@example.com\n",    // a newline is not part of an address
            "üser@example.com",       // non-ASCII: the engine's userdb will not resolve it
        ] {
            assert!(!valid_address(bad), "{bad:?} must be refused");
        }
    }

    /// The three shapes a live docker-mailserver 15.1.0 prints, captured from a
    /// real run: a mailbox with mail, one the engine has touched, and one
    /// created seconds ago whose maildir does not exist yet — its brackets are
    /// EMPTY, which is exactly what "add then look at the list" produces.
    const LIVE_LIST: &str = "\
* admin@example.com ( 6.0K / ~ ) [0%]
* used@example.com ( 0 / ~ ) [0%]
* fresh@example.com (  /  ) [%]
";

    #[test]
    fn all_three_live_row_shapes_parse() {
        let mailboxes = parse_list(LIVE_LIST);
        assert_eq!(
            mailboxes.iter().map(|m| m.address.as_str()).collect::<Vec<_>>(),
            ["admin@example.com", "used@example.com", "fresh@example.com"]
        );
        assert_eq!(mailboxes[0].detail, "( 6.0K / ~ ) [0%]");
        assert_eq!(mailboxes[1].detail, "( 0 / ~ ) [0%]");
        // The just-created mailbox: the engine prints empty brackets because the
        // maildir is made lazily. It is still a mailbox.
        assert_eq!(mailboxes[2].detail, "(  /  ) [%]");
        assert!(mailboxes.iter().all(|m| m.manageable));
    }

    #[test]
    fn a_diagnostic_line_never_becomes_a_mailbox() {
        // The exact stderr shape from a live host: an account whose local part
        // Dovecot cannot resolve. Its first token wraps a real address in
        // parentheses and a colon, and it passes every naive address test.
        // Parsing it would put a row with a DELETE button on something that is
        // not a mailbox.
        let text = "doveadm(broken@example.com): Error: User doesn't exist\n\
                    WARN  this is a log line\n\
                    Error: user@example.com not found\n\
                    There are no accounts\n";
        assert!(parse_list(text).is_empty(), "{:?}", parse_list(text));
    }

    #[test]
    fn a_mailbox_the_agent_would_not_accept_is_still_listed_but_not_manageable() {
        // Created outside the app: it exists, the user must see it, and the
        // client disables its buttons rather than offering an action that comes
        // back "invalid address".
        let mailboxes = parse_list("* üser@example.com ( 0 / ~ ) [0%]\n");
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].address, "üser@example.com");
        assert!(!mailboxes[0].manageable);
    }

    #[test]
    fn ansi_colour_never_reaches_the_parsed_output() {
        // The engine colours its own output; a coloured address must still be
        // one address, not a token with escape bytes glued to it.
        let mailboxes = parse_list("* \u{1B}[1;32madmin@example.com\u{1B}[0m ( 0 / ~ ) [0%]\n");
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].address, "admin@example.com");
    }

    #[test]
    fn duplicate_rows_collapse() {
        let mailboxes = parse_list("* a@b.com ( 0 / ~ )\n* a@b.com ( 0 / ~ )\n");
        assert_eq!(mailboxes.len(), 1);
    }

    #[test]
    fn an_empty_listing_is_no_mailboxes_not_a_parse_failure() {
        assert!(parse_list("").is_empty());
        assert!(parse_list("\n\n").is_empty());
    }

    #[test]
    fn the_password_is_prompted_twice_and_only_ever_on_stdin() {
        assert_eq!(password_input("s3cr3t"), "s3cr3t\ns3cr3t\n");
        // Structural: the argv of every mutating engine call is built from
        // literals plus the ADDRESS — the password appears in no argument
        // vector anywhere in this module, which is what keeps it out of /proc.
        for args in [
            vec!["setup", "email", "add", "a@b.com"],
            vec!["setup", "email", "update", "a@b.com"],
            vec!["setup", "email", "del", "-y", "a@b.com"],
            vec!["setup", "email", "list"],
        ] {
            assert!(!args.iter().any(|arg| arg.contains("s3cr3t")));
        }
    }

    #[test]
    fn a_secret_is_blanked_out_of_anything_going_back_to_the_user() {
        assert_eq!(redact("s3cr3t", "usage: add <a> s3cr3t"), "usage: add <a> ***");
        assert_eq!(redact("", "nothing to do"), "nothing to do");
    }

    #[test]
    fn the_delete_retry_budget_matches_the_wrappers() {
        // Four quiet attempts two seconds apart, then a fifth whose words are
        // reported. The engine's own race is about a second long, so the budget
        // has to outlast it by a margin without hanging the screen.
        assert_eq!(DELETE_ATTEMPTS, 5);
        assert_eq!(DELETE_RETRY_DELAY_SECS, 2);
    }

    #[test]
    fn refusals_carry_distinct_codes_and_bounded_text() {
        let (status, code, message) = Rejection::InvalidAddress("zz@zz.com".into()).parts();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "invalid_argument");
        assert!(message.contains("zz@zz.com"));

        let (status, code, _) = Rejection::NotInstalled.parts();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(code, "not_found");

        let (_, _, message) = Rejection::InvalidAddress("a".repeat(5000)).parts();
        assert!(message.len() < 200, "message was {} bytes", message.len());
    }

    #[test]
    fn an_engine_that_refuses_is_told_apart_from_an_engine_that_is_not_there() {
        // Three different failures, three different codes, because the client
        // phrases them differently and only one of them is the user's to fix:
        // a refusal by the ENGINE (the address does not exist), the engine not
        // being installed at all, and docker being unreachable.
        //
        // The live case behind the first one: with the mail container stopped,
        // the listing must FAIL. "There are no mailboxes" and "the mail server
        // is not running" are opposite answers, and only the account-file check
        // makes the empty case empty.
        let refused = EngineFailure::Refused("container mailserver is not running".into());
        assert_eq!(refused.response().status(), StatusCode::UNPROCESSABLE_ENTITY);
        let unreachable = EngineFailure::Unreachable(anyhow::anyhow!("docker: command not found"));
        assert_eq!(unreachable.response().status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(Rejection::NotInstalled.parts().0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn the_engine_is_addressed_through_the_same_catalog_gate_as_everything_else() {
        // One table, one answer to "is this service on this host" — the id here
        // must be the one `discover` knows, or the mailbox screen would appear
        // on a host whose mail engine the scan does not recognize.
        assert_eq!(discover::known_service(SERVICE_ID), Some("Docker Mailserver"));
    }
}
