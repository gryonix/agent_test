//! Close SSH password login on a host this product provisions.
//!
//! **What paid for this.** The same measurement that bought [`super::crowdsec`]:
//! 10 097 failed root password attempts against `vps-middle` over three days,
//! 2026-09-01. CrowdSec answers "who is knocking"; this answers "is the door
//! openable at all". Owner's decision 2026-09-02 — write it AND turn it on.
//!
//! ## The three facts this module exists to get right
//!
//! **1. The guard is THE APP'S key in `authorized_keys`, not merely a key.** A
//! host whose password login is switched off and whose dashboard has no key is
//! a host nobody can reach again, and the operator finds out at the worst
//! possible moment. "Some key is present" is not enough to prevent that, and
//! the difference is a shipped configuration rather than a hypothetical:
//! **existing-user mode** (`DashboardAccessInput.createUser == false`) leaves
//! the owner's account completely untouched — no `useradd`, no key installed,
//! deliberately no `passwd -l`, "which is exactly how the app will connect".
//! That account's `authorized_keys` can be full of the OWNER's keys while the
//! app itself authenticates with a password, so a non-empty-file guard would
//! pass and lock the dashboard out of every host set up that way. What is
//! asked instead is `grep -qxF` for the key this deployment actually uses, and
//! when that key is not known here at all, nothing is closed.
//!
//! **2. The check cannot happen in this process.** `gryonixnexusd.service`
//! runs with `ProtectHome=true`, which makes `/home`, `/root` and `/run/user`
//! inaccessible AND EMPTY inside the agent's mount namespace — so
//! `authorized_keys` is not merely unreadable here, it does not appear to
//! exist, and a Rust-side guard would read "no key" on every host in the fleet
//! and correctly refuse for ever. The same unit's `ProtectSystem=full` makes
//! `/etc` read-only, and `/etc/ssh/sshd_config.d` is not in its
//! `ReadWritePaths`, so the file cannot be written from here either. Both
//! halves therefore run in a transient systemd unit —
//! [`super::packages::run_outside_sandbox_from_file`], PID 1's namespace, the
//! route `crowdsec` and the package installers already take. Adding the path
//! to `ReadWritePaths` was the alternative and it is worse: the unit file is
//! only rewritten when the agent is reinstalled, so every host already in the
//! fleet would silently skip this until someone upgraded it.
//!
//! **3. The file has to sort BEFORE cloud-init's.** `sshd_config` takes the
//! FIRST value it obtains for a keyword, `Include /etc/ssh/sshd_config.d/*.conf`
//! is the first line of Debian's and Ubuntu's `sshd_config`, and `glob(3)`
//! returns that directory sorted. Ubuntu's cloud images ship
//! `50-cloud-init.conf` containing `PasswordAuthentication yes`. A drop-in
//! numbered above 50 — `60-`, matching this product's existing
//! `60-gryonixnexus-tunnel.conf` — would be written, would pass `sshd -t`,
//! would reload cleanly, and would change nothing at all, which is the exact
//! shape of failure this codebase keeps paying for. Hence [`DROP_IN_PATH`]'s
//! `10-`, and [`the_drop_in_outranks_cloud_inits`] pins it.
//!
//! ## Two callers, one policy
//!
//! Everything above was bought by the INSTALL, which closes the door once, at
//! the end of a provision, around the control user it just created. The app's
//! Security card asks for the same thing on demand, about the account IT signs
//! in with — see "The on-demand half" further down. The policy does not fork:
//! the drop-in, its number, the `sshd -t` rollback and the key guard are these
//! bytes for both callers, and the on-demand half adds only a READ (is the door
//! open, is the key there) and a way BACK.
//!
//! ## Fail closed to the OLD behaviour
//!
//! A configuration `sshd` refuses to parse takes the daemon down on the next
//! restart, and "the machine has no sshd" is a far worse outcome than "the
//! machine still takes passwords". So the drop-in is moved into place, `sshd
//! -t` is run against the MERGED config (the only way to test a drop-in — the
//! file has to be in the directory for the include to reach it), and a
//! rejection REMOVES it again before anything is reloaded. And it is a
//! `reload`, never a `restart`: a restart drops the session the provision is
//! running over.

use super::execute::EventSink;
use super::packages::{have_binary, run_outside_sandbox_from_file};

/// Where the drop-in lives.
///
/// `10-`, not `60-`: see fact 3 in the module doc. The number is the whole
/// point of the name and it is asserted, not trusted.
pub const DROP_IN_PATH: &str = "/etc/ssh/sshd_config.d/10-gryonixnexus-no-password.conf";

/// The staging name, which deliberately does NOT end in `.conf`.
///
/// `Include` globs `*.conf`, so a half-written or not-yet-validated file in
/// that directory is invisible to sshd — the same reasoning that makes the
/// sudoers whitelist stage under a dotted name (`execute::sudoers_staged_path`).
/// Staging is what makes "is this already what we would write" answerable
/// without ever having two authors of the live file.
const STAGED_SUFFIX: &str = ".staged";

/// Where the script leaves its one-word verdict for the agent to read.
///
/// `/run`, because it is the one directory both sides can reach: the transient
/// unit writes it as root outside the sandbox, and the agent's own namespace
/// leaves `/run` writable (`packages::run_outside_sandbox_from_file` stages its
/// script there for the same reason). The alternative was parsing an exit code
/// out of the error string `run_child_streaming` formats, which is a contract
/// nobody declared.
const VERDICT_PATH: &str = "/run/gryonixnexusd-sshd-password.verdict";

/// The drop-in itself.
///
/// Both keywords, because closing one leaves the other open: on a stock Debian
/// `KbdInteractiveAuthentication` is what PAM answers a password prompt
/// through, and a host with `PasswordAuthentication no` alone still lets the
/// whole internet type passwords at it via keyboard-interactive.
pub fn drop_in() -> String {
    // NO APOSTROPHE anywhere in this text, and that is load-bearing rather
    // than style: the SSH install path writes the same bytes from a
    // single-quoted shell literal (`DashboardAccessSections.passwordAuthClose`),
    // and one apostrophe there ends the literal mid-file. Byte-equality between
    // the two routes is what makes a provision after an SSH install a no-op
    // instead of a rewrite-and-reload, so the constraint belongs to both.
    "# Managed by gryonixNexus.\n\
     #\n\
     # Written only after the app key was proven present on the control user of\n\
     # this host. Numbered 10 so it is obtained BEFORE 50-cloud-init.conf: sshd\n\
     # keeps the FIRST value it sees for a keyword, and cloud images ship\n\
     # PasswordAuthentication yes in that file.\n\
     #\n\
     # Remove this file and reload ssh to take passwords again.\n\
     PasswordAuthentication no\n\
     KbdInteractiveAuthentication no\n"
        .to_string()
}

/// What the script can conclude, and what the operator is told about each.
///
/// Spelled as a type rather than as strings compared at the call site, so the
/// one thing that must never happen — an unrecognised verdict read as success —
/// is a compile-time shape instead of a forgotten `else`.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The drop-in was written and sshd reloaded: passwords are refused now.
    Closed,
    /// The drop-in was written but neither `ssh` nor `sshd` would reload. The
    /// file is on disk and applies at the next start; said out loud because
    /// "closed" would be a lie until then.
    ClosedNotReloaded,
    /// Written and reloaded, but `sshd -T` said nothing at all, so the merged
    /// configuration could not be read back. Almost certainly closed; not
    /// claimed as closed, because the whole point of the check is that a file
    /// on disk is not an answer about a running daemon.
    ClosedUnverified,
    /// Nothing landed on disk. The step before this one failed silently —
    /// there is no `set -e` here, and `sshd -t` PASSES when nothing was added,
    /// so without this verdict the run would have reported success.
    NotWritten,
    /// The file is there, sshd parsed and reloaded it, and sshd still accepts
    /// passwords: something obtained earlier in the merged configuration wins.
    /// The reason this exists at all — Ubuntu's `50-cloud-init.conf`.
    NotEffective,
    /// Already exactly this file. Nothing written, nothing reloaded.
    AlreadyClosed,
    /// No proven key. Nothing written — this is the guard doing its job.
    NoKey,
    /// `sshd -t` rejected the merged configuration; the drop-in was removed
    /// again and the host still takes passwords.
    InvalidConfig,
    /// No `sshd` on this host at all.
    NoSshd,
    /// The drop-in was removed and sshd now accepts passwords again.
    Opened,
    /// There was no drop-in of ours to remove. Nothing written, nothing
    /// reloaded — and deliberately NOT reported as "opened": this product only
    /// ever takes back its own file, and a host whose passwords are refused by
    /// somebody else's configuration is one the owner has to be told about
    /// rather than one this call quietly claims to have opened.
    AlreadyOpen,
    /// Removed, but neither `ssh` nor `sshd` would reload: passwords come back
    /// at the next start of the daemon and not before.
    OpenedNotReloaded,
    /// Removed and reloaded, and sshd STILL refuses passwords — something else
    /// in the merged configuration says so, and this call cannot reach it.
    OpenedNotEffective,
    /// `sshd -t` rejected the configuration WITHOUT our drop-in, which means
    /// the rejection was never ours. The file is put back, so the host keeps
    /// the configuration it was actually running.
    OpenInvalidConfig,
}

impl Verdict {
    fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "closed" => Some(Self::Closed),
            "closed-not-reloaded" => Some(Self::ClosedNotReloaded),
            "closed-unverified" => Some(Self::ClosedUnverified),
            "not-written" => Some(Self::NotWritten),
            "not-effective" => Some(Self::NotEffective),
            "already-closed" => Some(Self::AlreadyClosed),
            "no-key" => Some(Self::NoKey),
            "invalid-config" => Some(Self::InvalidConfig),
            "no-sshd" => Some(Self::NoSshd),
            "opened" => Some(Self::Opened),
            "already-open" => Some(Self::AlreadyOpen),
            "opened-not-reloaded" => Some(Self::OpenedNotReloaded),
            "opened-not-effective" => Some(Self::OpenedNotEffective),
            "open-invalid-config" => Some(Self::OpenInvalidConfig),
            _ => None,
        }
    }

    /// The operator-facing sentence. Every one of them says what the host's
    /// SSH accepts NOW, because that is the only fact anyone reading an
    /// install log about this actually needs.
    fn step(&self, user: &str) -> String {
        match self {
            Self::Closed => "SSH password login is closed on this host — key login only".to_string(),
            Self::ClosedNotReloaded => {
                "SSH password login is closed in the configuration, but sshd would not reload — \
                 it takes effect the next time sshd starts"
                    .to_string()
            }
            Self::ClosedUnverified => {
                "SSH password login is closed in the configuration, but sshd would not say what it \
                 resolved — check it by hand before relying on it"
                    .to_string()
            }
            Self::NotWritten => {
                "leaving SSH password login ON: the drop-in could not be written to this host at all"
                    .to_string()
            }
            Self::NotEffective => {
                "leaving SSH password login ON: sshd still accepts passwords with the drop-in in \
                 place, so something obtained earlier in its configuration wins — a cloud image's \
                 own sshd_config.d file is the usual one"
                    .to_string()
            }
            Self::AlreadyClosed => "SSH password login was already closed on this host".to_string(),
            Self::NoKey => format!(
                "leaving SSH password login ON: no login key is present for '{user}', and closing \
                 the door before the key is proven is how a host is lost"
            ),
            Self::InvalidConfig => {
                "leaving SSH password login ON: sshd rejected the configuration with the drop-in \
                 in place, so it was removed again"
                    .to_string()
            }
            Self::NoSshd => "not closing SSH password login: this host has no sshd".to_string(),
            Self::Opened => "SSH password login is open again on this host".to_string(),
            Self::AlreadyOpen => {
                "nothing to remove: this product has not closed SSH password login on this host"
                    .to_string()
            }
            Self::OpenedNotReloaded => {
                "SSH password login is open again in the configuration, but sshd would not reload \
                 — it takes effect the next time sshd starts"
                    .to_string()
            }
            Self::OpenedNotEffective => {
                "the drop-in is gone and sshd still refuses passwords: something else in this \
                 host's SSH configuration closes them, and it was not written by this app"
                    .to_string()
            }
            Self::OpenInvalidConfig => {
                "leaving SSH password login CLOSED: sshd rejected the configuration without the \
                 drop-in, so it was put back"
                    .to_string()
            }
        }
    }
}

/// The script that does the work, outside this process's sandbox.
///
/// `set -u` and not `set -e`: every exit here is deliberate and each one has to
/// leave a verdict behind, and under `set -e` a failing `cmp` or `grep` would
/// end the script silently with no verdict file — which the reader below would
/// then have to interpret, and "no verdict" is exactly the ambiguity this file
/// exists to remove.
fn script(control_user: &str, app_public_key: &str) -> String {
    // `verdict_path()`, never the constant: the reader below honours the test
    // override, and a script interpolating the hard-coded path would write one
    // file while the agent read another — every run then falls into the "no
    // verdict" arm and reports that it could not tell, on a successful close.
    let verdict = verdict_path();
    format!(
        "set -u\n\
         VERDICT='{verdict}'\n\
         DROP_IN='{DROP_IN_PATH}'\n\
         STAGED=\"$DROP_IN{STAGED_SUFFIX}\"\n\
         CONTROL_USER='{control_user}'\n\
         APP_KEY='{app_public_key}'\n\
         rm -f \"$VERDICT\"\n\
         say() {{ printf '%s\\n' \"$1\" > \"$VERDICT\"; }}\n\
         \n\
         if ! command -v sshd >/dev/null 2>&1; then say no-sshd; exit 0; fi\n\
         \n\
         # The guard asks for THE APP KEY, not for any key: an existing-user\n\
         # install leaves the account untouched, so this file can be full of\n\
         # keys that belong to somebody else while the app itself signs in with\n\
         # a password. A home directory that does not resolve, a missing file\n\
         # and a file without our line are one answer: no proven way back in.\n\
         HOME_DIR=\"$(getent passwd \"$CONTROL_USER\" | cut -d: -f6)\"\n\
         if [ -z \"$HOME_DIR\" ]; then say no-key; exit 0; fi\n\
         KEYS=\"$HOME_DIR/.ssh/authorized_keys\"\n\
         if [ ! -s \"$KEYS\" ]; then say no-key; exit 0; fi\n\
         if ! grep -qxF \"$APP_KEY\" \"$KEYS\"; then say no-key; exit 0; fi\n\
         \n\
         install -d -m 755 /etc/ssh/sshd_config.d\n\
         cat > \"$STAGED\" <<'GRYONIXNEXUS_SSHD_DROP_IN'\n\
         {body}\
         GRYONIXNEXUS_SSHD_DROP_IN\n\
         chmod 644 \"$STAGED\"\n\
         if [ -f \"$DROP_IN\" ] && cmp -s \"$STAGED\" \"$DROP_IN\"; then\n\
         \x20 rm -f \"$STAGED\"\n\
         \x20 say already-closed\n\
         \x20 exit 0\n\
         fi\n\
         mv \"$STAGED\" \"$DROP_IN\"\n\
         \n\
         # **Did the file actually land?** There is no `set -e` here on purpose\n\
         # (every exit has to leave a verdict), which means a failed install -d,\n\
         # a full disk or a read-only /etc would fall straight through to the\n\
         # test below — and that test PASSES when nothing was added, because the\n\
         # configuration is then exactly what it was. Without this line the\n\
         # agent reports the door closed on a host where it is wide open.\n\
         if [ ! -f \"$DROP_IN\" ]; then\n\
         \x20 rm -f \"$STAGED\"\n\
         \x20 say not-written\n\
         \x20 exit 0\n\
         fi\n\
         \n\
         # Tested with the file IN PLACE, because an include is the only way\n\
         # sshd ever sees it — and removed again on rejection, so a host that\n\
         # cannot parse this keeps the behaviour it had instead of losing sshd.\n\
         if ! sshd -t; then\n\
         \x20 rm -f \"$DROP_IN\"\n\
         \x20 say invalid-config\n\
         \x20 exit 0\n\
         fi\n\
         if ! systemctl reload ssh 2>/dev/null && ! systemctl reload sshd 2>/dev/null; then\n\
         \x20 say closed-not-reloaded\n\
         \x20 exit 0\n\
         fi\n\
         \n\
         # **The only proof that survives contact with a real host: ask sshd.**\n\
         # A file on disk says nothing about the MERGED configuration, and this\n\
         # is the one place the numbering can be checked against a machine\n\
         # rather than against a unit test: a cloud image that ships\n\
         # 50-cloud-init.conf with PasswordAuthentication yes would leave every\n\
         # step above successful and the door open. sshd -T prints what sshd\n\
         # itself resolved.\n\
         EFFECTIVE=\"$(sshd -T 2>/dev/null | tr 'A-Z' 'a-z')\"\n\
         if [ -z \"$EFFECTIVE\" ]; then say closed-unverified; exit 0; fi\n\
         case \"$EFFECTIVE\" in\n\
         \x20 *\"passwordauthentication no\"*) ;;\n\
         \x20 *) say not-effective; exit 0 ;;\n\
         esac\n\
         case \"$EFFECTIVE\" in\n\
         \x20 *\"kbdinteractiveauthentication no\"*) ;;\n\
         \x20 *) say not-effective; exit 0 ;;\n\
         esac\n\
         say closed\n",
        body = drop_in(),
    )
}

/// Close password login on this host, if and only if a key is proven present.
///
/// **Never fatal**, the call [`super::crowdsec::ensure_present`] and
/// `ensure_autobackup_passphrase` both make: the services are up by the time
/// this runs, and refusing a whole install because sshd would not reload is the
/// wrong trade. Every exit announces itself through the sink instead, so a host
/// that still takes passwords says so rather than looking provisioned.
pub(super) async fn close_password_login(
    control_user: Option<&str>,
    app_public_key: Option<&str>,
    sink: &EventSink,
) {
    // No control user means no account whose key could be proven, and this is
    // not an error: an agent-only host the owner reaches by their own key on
    // their own account is a supported shape, and the agent has no way to see
    // that key (`ProtectHome`). Closing the door on it would be the guard
    // failing in the one direction it must not.
    let (user, key) = match subject(control_user, app_public_key) {
        Ok(pair) => pair,
        Err(why) => {
            let _ = sink.step(why).await;
            return;
        }
    };
    if !have_binary("systemd-run") {
        let _ = sink
            .step("not closing SSH password login: this build can only reach sshd through systemd-run")
            .await;
        return;
    }

    let _ = std::fs::remove_file(verdict_path());
    if let Err(why) =
        run_outside_sandbox_from_file(&script(user, key), "closing SSH password login", sink).await
    {
        let _ = sink.step(&format!("could not close SSH password login: {why}")).await;
        return;
    }

    // A run that succeeded and left no verdict is not a success — it is a
    // script that took a path nobody wrote. Reported as itself rather than
    // rounded up to "closed", which is the only rounding here that could cost
    // somebody their host.
    let verdict = std::fs::read_to_string(verdict_path()).ok().and_then(|text| Verdict::parse(&text));
    let _ = std::fs::remove_file(verdict_path());
    match verdict {
        Some(verdict) => {
            let _ = sink.step(verdict.step(user)).await;
        }
        None => {
            let _ = sink
                .step("could not tell whether SSH password login was closed — assume it is still open")
                .await;
        }
    }
}

/// The two facts the caller has to supply, checked before anything runs.
///
/// A separate function because each refusal is a DECISION with a cost, and a
/// decision buried inside an async body next to a sink is one no test ever
/// asks about. Every `Err` here means the host keeps password login, which is
/// the safe direction and the one worth being able to pin.
fn subject<'a>(
    control_user: Option<&'a str>,
    app_public_key: Option<&'a str>,
) -> Result<(&'a str, &'a str), &'static str> {
    // No control user means no account whose key could be proven, and this is
    // not an error: an agent-only host the owner reaches by their own key on
    // their own account is a supported shape, and the agent has no way to see
    // that key (`ProtectHome`). Closing the door on it would be the guard
    // failing in the one direction it must not.
    let user = control_user
        .map(str::trim)
        .filter(|user| !user.is_empty())
        .ok_or("not closing SSH password login: this host has no gryonixNexus control user whose key could be proven")?;
    // No known app key means the guard has nothing to look for. Refusing is the
    // honest answer rather than falling back to "is there any key at all":
    // `execute::dashboard_access` returns `None` exactly when neither the
    // wrapper on disk nor the caller could name the key this deployment signs
    // in with, and a host whose dashboard key is unknown here is a host whose
    // dashboard might be signing in with a password.
    let key = app_public_key
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .ok_or("not closing SSH password login: this host does not know which key the app signs in with")?;
    // The key is interpolated into a single-quoted shell literal.
    // `execute::dashboard_access` already refuses a quote or a newline for the
    // same reason, and this is the SECOND reader of that value — the rule
    // belongs with each reader, not with whoever happened to fetch it.
    if key.contains('\'') || key.contains('\n') {
        return Err("not closing SSH password login: this host's recorded app key is not a single line");
    }
    Ok((user, key))
}

/// Overridable for tests, the same technique `systemd_run_bin` uses. A server
/// never sets it.
fn verdict_path() -> String {
    std::env::var("GRYONIXNEXUSD_SSHD_VERDICT_PATH").unwrap_or_else(|_| VERDICT_PATH.to_string())
}

// ─────────────────── The on-demand half: the app's own switch ──────────────
//
// **Everything above runs once, inside a provision. This runs when somebody
// taps a button**, and that difference is what the code below is for rather
// than a second copy of it (owner's decision 2026-09-07: the Security card gets
// the switch). Three things change and nothing else does:
//
//  1. **The account is the app's, not the recipe's.** The install knows the
//     control user it just created. A server ADOPTED by the app may have no
//     control user at all — it is reached as somebody's own account, very often
//     with a password, which is exactly the host this switch exists for. So the
//     account and the key come from the request, and the same guard is asked
//     about them: is THE APP'S key on THE ACCOUNT the app signs in with.
//  2. **There is a read.** A button that cannot say what the host currently
//     does is a button nobody dares press, and the one fact it must not get
//     wrong — "would this lock me out" — is invisible from the client side.
//  3. **There is a way back.** See [`open_password_login`].
//
// What does NOT change is where the work happens: `ProtectHome` still makes
// `authorized_keys` invisible in this process and `ProtectSystem=full` still
// makes `/etc` read-only, so all three scripts go out through PID 1 exactly as
// the install's does. See this module's own doc for why that is not negotiable.

/// What this host's SSH accepts right now, and whether the app could still get
/// in without a password.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct State {
    /// sshd accepts passwords. `None` — it could not be asked, which is not the
    /// same as "no" and is never rounded to it: the whole point of the reading
    /// is that a file on disk is not an answer about a running daemon.
    pub password_open: Option<bool>,
    /// The app's key is on the account it signs in with. The one condition
    /// under which closing is allowed at all.
    pub app_key_present: bool,
    /// This product's drop-in is on disk. Deliberately separate from
    /// `password_open`: present-and-still-open is the cloud-init failure this
    /// module's numbering exists to prevent, and it shows only as these two
    /// disagreeing.
    pub drop_in_present: bool,
    pub sshd_present: bool,
    /// The account that was actually asked about — resolved here when the
    /// caller named none, because "which account" is the one thing that cannot
    /// be checked from the client side.
    pub login_user: String,
}

/// Where the probe leaves its line. Beside the close verdict and not the same
/// file: a read must never be able to consume the answer a write is waiting
/// for, and the two are reached by different callers at unrelated times.
fn probe_verdict_path() -> String {
    format!("{}.probe", verdict_path())
}

/// The account to ask about: the caller's, or the control user this host was
/// provisioned with when the caller named none.
fn resolve_login_user(login_user: &str) -> Option<String> {
    let named = login_user.trim();
    if !named.is_empty() {
        return Some(named.to_string());
    }
    super::execute::existing_control_user()
}

/// Refuse anything that could not survive the single-quoted shell literal the
/// scripts embed it in. The same rule [`subject`] applies to the install's key,
/// stated again here because this is a SECOND reader of values that now arrive
/// from a request rather than from the host's own files.
fn shell_safe(value: &str) -> bool {
    !value.contains('\'') && !value.contains('\n') && !value.contains('\r')
}

/// The read, outside the sandbox.
///
/// One line of `key=value` pairs rather than a verdict word, because this
/// answers four questions and a reader that had to enumerate their combinations
/// as words would be a parser nobody could extend.
fn probe_script(login_user: &str, app_public_key: &str) -> String {
    let verdict = probe_verdict_path();
    format!(
        "set -u\n\
         VERDICT='{verdict}'\n\
         DROP_IN='{DROP_IN_PATH}'\n\
         LOGIN_USER='{login_user}'\n\
         APP_KEY='{app_public_key}'\n\
         OPEN=unknown\n\
         KEY=no\n\
         DROPIN=no\n\
         SSHD=no\n\
         [ -f \"$DROP_IN\" ] && DROPIN=yes\n\
         \n\
         # The same grep the guard uses, for the same reason: an adopted host's\n\
         # authorized_keys is usually full of the OWNER's keys, and \"some key is\n\
         # present\" is the answer that would lock the app out.\n\
         if [ -n \"$APP_KEY\" ]; then\n\
         \x20 HOME_DIR=\"$(getent passwd \"$LOGIN_USER\" | cut -d: -f6)\"\n\
         \x20 if [ -n \"$HOME_DIR\" ] && [ -s \"$HOME_DIR/.ssh/authorized_keys\" ]; then\n\
         \x20   if grep -qxF \"$APP_KEY\" \"$HOME_DIR/.ssh/authorized_keys\"; then KEY=yes; fi\n\
         \x20 fi\n\
         fi\n\
         \n\
         # `sshd -T` and nothing else. Reading the files would mean\n\
         # reimplementing sshd's own first-value-wins merge over a glob, which\n\
         # is the exact thing this module was written after getting wrong.\n\
         if command -v sshd >/dev/null 2>&1; then\n\
         \x20 SSHD=yes\n\
         \x20 EFFECTIVE=\"$(sshd -T 2>/dev/null | tr 'A-Z' 'a-z')\"\n\
         \x20 if [ -n \"$EFFECTIVE\" ]; then\n\
         \x20   OPEN=yes\n\
         \x20   case \"$EFFECTIVE\" in\n\
         \x20     *\"passwordauthentication no\"*)\n\
         \x20       case \"$EFFECTIVE\" in\n\
         \x20         *\"kbdinteractiveauthentication no\"*) OPEN=no ;;\n\
         \x20       esac\n\
         \x20       ;;\n\
         \x20   esac\n\
         \x20 fi\n\
         fi\n\
         printf 'open=%s key=%s dropin=%s sshd=%s\\n' \"$OPEN\" \"$KEY\" \"$DROPIN\" \"$SSHD\" > \"$VERDICT\"\n",
    )
}

/// Read the probe's line back. Anything it does not recognise leaves the field
/// at its safe value — `password_open: None` and `app_key_present: false`, the
/// two answers that make the app offer nothing rather than offer a lockout.
fn parse_state(text: &str) -> State {
    let mut state = State::default();
    for field in text.split_whitespace() {
        match field.split_once('=') {
            Some(("open", "yes")) => state.password_open = Some(true),
            Some(("open", "no")) => state.password_open = Some(false),
            Some(("key", "yes")) => state.app_key_present = true,
            Some(("dropin", "yes")) => state.drop_in_present = true,
            Some(("sshd", "yes")) => state.sshd_present = true,
            _ => {}
        }
    }
    state
}

/// Taking this product's drop-in back off, outside the sandbox.
///
/// **Symmetrical with the close, including the part that undoes itself.** The
/// removal is validated with `sshd -t` before anything is reloaded, and a
/// configuration that does not parse WITHOUT our file puts the file back: the
/// rejection was then never ours to fix, and a host left with an sshd that
/// refuses to start is worse than one that refuses passwords.
fn open_script() -> String {
    let verdict = verdict_path();
    format!(
        "set -u\n\
         VERDICT='{verdict}'\n\
         DROP_IN='{DROP_IN_PATH}'\n\
         BACKUP=\"$DROP_IN{STAGED_SUFFIX}\"\n\
         rm -f \"$VERDICT\"\n\
         say() {{ printf '%s\\n' \"$1\" > \"$VERDICT\"; }}\n\
         \n\
         if ! command -v sshd >/dev/null 2>&1; then say no-sshd; exit 0; fi\n\
         if [ ! -f \"$DROP_IN\" ]; then say already-open; exit 0; fi\n\
         \n\
         # Moved aside under the staging name, which the include glob does not\n\
         # match, so the file is out of the configuration and still on disk for\n\
         # the one path that has to put it back.\n\
         mv \"$DROP_IN\" \"$BACKUP\"\n\
         if [ -f \"$DROP_IN\" ]; then say not-written; exit 0; fi\n\
         if ! sshd -t; then\n\
         \x20 mv \"$BACKUP\" \"$DROP_IN\"\n\
         \x20 say open-invalid-config\n\
         \x20 exit 0\n\
         fi\n\
         rm -f \"$BACKUP\"\n\
         if ! systemctl reload ssh 2>/dev/null && ! systemctl reload sshd 2>/dev/null; then\n\
         \x20 say opened-not-reloaded\n\
         \x20 exit 0\n\
         fi\n\
         EFFECTIVE=\"$(sshd -T 2>/dev/null | tr 'A-Z' 'a-z')\"\n\
         if [ -z \"$EFFECTIVE\" ]; then say opened; exit 0; fi\n\
         case \"$EFFECTIVE\" in\n\
         \x20 *\"passwordauthentication yes\"*) say opened ;;\n\
         \x20 *) say opened-not-effective ;;\n\
         esac\n",
    )
}

/// Run one of the scripts above through PID 1 and hand back what it wrote.
///
/// The verdict file is removed before AND after: a stale line from an earlier
/// run read as this run's answer is the one failure mode that would report a
/// door closed on a host where nothing happened.
async fn run_and_read(script: &str, what: &str, verdict: &str) -> Result<String, String> {
    if !have_binary("systemd-run") {
        return Err("this build can only reach sshd through systemd-run, and this host has none"
            .to_string());
    }
    let _ = std::fs::remove_file(verdict);
    let sink = EventSink::detached();
    run_outside_sandbox_from_file(script, what, &sink).await?;
    let text = std::fs::read_to_string(verdict).map_err(|err| {
        format!("{what} left no answer behind, so what the host now accepts is unknown: {err}")
    })?;
    let _ = std::fs::remove_file(verdict);
    Ok(text)
}

/// What this host's SSH accepts, and whether `login_user` carries the app's
/// key. Nothing is written and nothing is reloaded.
pub async fn read_state(login_user: &str, app_public_key: &str) -> Result<State, String> {
    let user = resolve_login_user(login_user).ok_or_else(|| {
        "no account to ask about: name the account the app signs in with — this host has no \
         gryonixNexus control user to fall back to"
            .to_string()
    })?;
    if !shell_safe(&user) || !shell_safe(app_public_key) {
        return Err("the account name or the key is not a single plain line".to_string());
    }
    let text =
        run_and_read(&probe_script(&user, app_public_key), "reading the SSH login policy", &probe_verdict_path())
            .await?;
    let mut state = parse_state(&text);
    state.login_user = user;
    Ok(state)
}

/// Close password login on demand, guarded by the app's own key on the app's
/// own account.
///
/// The guard is the install path's, asked about the account from the request —
/// see this section's doc for why that is the same rule and not a weaker one.
pub async fn close_password_login_now(
    login_user: &str,
    app_public_key: &str,
) -> Result<Verdict, String> {
    let user = resolve_login_user(login_user).ok_or_else(|| {
        "not closing SSH password login: name the account the app signs in with — this host has \
         no gryonixNexus control user to fall back to"
            .to_string()
    })?;
    let (user, key) = subject(Some(user.as_str()), Some(app_public_key))
        .map_err(str::to_string)
        .map(|(user, key)| (user.to_string(), key.to_string()))?;
    if !shell_safe(&user) {
        return Err("not closing SSH password login: that account name is not a single plain line"
            .to_string());
    }
    let text = run_and_read(&script(&user, &key), "closing SSH password login", &verdict_path()).await?;
    // The same refusal the install path makes, and for the same reason: a run
    // that succeeded and left a word nobody wrote is not a close.
    Verdict::parse(&text).ok_or_else(|| {
        "could not tell whether SSH password login was closed — assume it is still open".to_string()
    })
}

/// Take this product's drop-in back off, so the host accepts passwords again.
///
/// **No guard, and that is not an oversight.** Every refusal in this module
/// exists to stop a host becoming unreachable; this direction can only make one
/// MORE reachable, and the owner asking for it is the whole authority it needs.
pub async fn open_password_login_now() -> Result<Verdict, String> {
    let text = run_and_read(&open_script(), "opening SSH password login", &verdict_path()).await?;
    Verdict::parse(&text).ok_or_else(|| {
        "could not tell whether SSH password login was opened — assume it is still closed"
            .to_string()
    })
}

/// The operator-facing sentence for a verdict, for the callers outside this
/// module. `step` is private because it is the install's narration; this is the
/// same words for a client that has no stream to narrate into.
pub fn verdict_sentence(verdict: &Verdict, login_user: &str) -> String {
    verdict.step(login_user)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key shaped like the real thing — the same fake `uninstall`'s fixtures
    /// use, so the two modules' tests read as one story.
    const FAKE_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake gryonixnexus-app";

    /// **The fact a reader would get wrong, and the only one that makes this
    /// module a no-op when wrong.** sshd keeps the FIRST value obtained for a
    /// keyword and `Include` globs the directory in sorted order, so a drop-in
    /// numbered above Ubuntu's `50-cloud-init.conf` — which says
    /// `PasswordAuthentication yes` — is written, validated, reloaded and
    /// completely ignored.
    #[test]
    fn the_drop_in_outranks_cloud_inits() {
        let name = DROP_IN_PATH.rsplit('/').next().expect("a file name");
        assert!(name < "50-cloud-init.conf", "{name} is obtained after cloud-init's drop-in");
        // The sibling this product already writes is numbered 60 and must NOT
        // be taken as the pattern to copy: it sets a keyword no cloud image
        // touches, so its number never mattered.
        assert!(name < "60-gryonixnexus-tunnel.conf", "{name}");
        assert!(DROP_IN_PATH.starts_with("/etc/ssh/sshd_config.d/"), "{DROP_IN_PATH}");
        assert!(DROP_IN_PATH.ends_with(".conf"), "{DROP_IN_PATH} would not be included at all");
    }

    /// Closing one keyword and not the other leaves the door open: on a stock
    /// Debian, keyboard-interactive is how PAM asks for the password.
    #[test]
    fn both_password_keywords_are_closed() {
        let text = drop_in();
        let directives: Vec<&str> =
            text.lines().filter(|line| !line.trim_start().starts_with('#')).filter(|line| !line.trim().is_empty()).collect();
        assert!(directives.contains(&"PasswordAuthentication no"), "{text}");
        assert!(directives.contains(&"KbdInteractiveAuthentication no"), "{text}");
        assert_eq!(directives.len(), 2, "nothing else belongs in this file: {text}");
    }

    /// **The body must survive a single-quoted shell literal**, because the SSH
    /// install path writes it from one. An apostrophe would end that literal
    /// mid-file and leave the rest of the setup script as shell to execute —
    /// and the failure would appear on the OTHER route, in a language this
    /// crate does not compile.
    #[test]
    fn the_drop_in_body_carries_nothing_a_shell_literal_could_not_hold() {
        let text = drop_in();
        assert!(!text.contains('\''), "an apostrophe ends the other route's literal: {text}");
        assert!(text.is_ascii(), "the other route embeds this verbatim: {text}");
    }

    /// The staging name must not be included, or a half-written file is live
    /// configuration for however long the write takes.
    #[test]
    fn the_staged_file_is_invisible_to_the_include_glob() {
        assert!(!STAGED_SUFFIX.is_empty());
        assert!(
            !format!("{DROP_IN_PATH}{STAGED_SUFFIX}").ends_with(".conf"),
            "the staged file would be included while it is being written"
        );
    }

    /// The rejection path must UNDO itself. A host that keeps a drop-in sshd
    /// refuses to parse loses its sshd at the next restart, which is strictly
    /// worse than the password login this was trying to close.
    #[test]
    fn a_rejected_configuration_removes_the_drop_in_again() {
        let text = script("gryonixnexus", FAKE_KEY);
        let test_at = text.find("if ! sshd -t; then").expect("the merged config is tested");
        let removal_at = text[test_at..].find("rm -f \"$DROP_IN\"").expect("a rejection removes the file");
        let verdict_at = text[test_at..].find("say invalid-config").expect("a rejection is reported");
        assert!(removal_at < verdict_at, "the file is removed before the verdict is written:\n{text}");
    }

    /// **A write that did not land must not be reported as a closed door.**
    ///
    /// There is no `set -e` here — every exit has to leave a verdict — so a
    /// failed `install -d`, a full disk or a read-only `/etc` falls straight
    /// through to `sshd -t`. And that test PASSES when nothing was added,
    /// because the configuration is then exactly what it already was. Without
    /// the existence check the run reports success on a host whose password
    /// login is wide open, which is the worst outcome this module has: not a
    /// failure, a false report of safety.
    #[test]
    fn a_write_that_did_not_land_is_not_reported_as_closed() {
        let text = script("gryonixnexus", FAKE_KEY);
        let landed = text
            .find("if [ ! -f \"$DROP_IN\" ]; then")
            .expect("nothing checks that the drop-in reached the disk");
        let tested = text.find("if ! sshd -t; then").expect("the merged config is tested");
        assert!(landed < tested, "the existence check runs after the test that cannot fail:\n{text}");
        assert!(text[landed..tested].contains("say not-written"), "{text}");
    }

    /// **The only proof that survives contact with a real host.**
    ///
    /// A file on disk says nothing about the MERGED configuration, and the
    /// `10-` numbering is the one decision here a unit test can only check
    /// against a FILENAME. `sshd -T` prints what sshd itself resolved, so a
    /// cloud image whose own `50-cloud-init.conf` says
    /// `PasswordAuthentication yes` is caught on the machine rather than
    /// reasoned about here.
    ///
    /// Both keywords are read back, and by then both are safe to expect:
    /// `KbdInteractiveAuthentication` arrived in OpenSSH 8.7, and an sshd too
    /// old to know it would have failed `sshd -t` above and taken the
    /// `invalid-config` exit long before this line.
    #[test]
    fn the_host_itself_is_asked_whether_passwords_are_still_taken() {
        let text = script("gryonixnexus", FAKE_KEY);
        let reload = text.find("systemctl reload").expect("sshd is reloaded");
        let asked = text.find("sshd -T").expect("sshd is never asked what it resolved");
        assert!(reload < asked, "asked before the reload, so it reads the OLD answer:\n{text}");
        assert!(text[asked..].contains("passwordauthentication no"), "{text}");
        assert!(text[asked..].contains("kbdinteractiveauthentication no"), "{text}");
        // Case-folded first: sshd -T prints lower case today, and a check that
        // depends on that is a check that breaks on a version nobody has yet.
        assert!(text.contains("tr 'A-Z' 'a-z'"), "{text}");
        // A daemon that would not answer is not evidence of anything.
        assert!(text[asked..].contains("say closed-unverified"), "{text}");
    }

    /// `reload`, never `restart`: a restart drops the SSH session the provision
    /// is running over, which turns a successful install into a lost one.
    #[test]
    fn sshd_is_reloaded_and_never_restarted() {
        let text = script("gryonixnexus", FAKE_KEY);
        assert!(text.contains("systemctl reload ssh"), "{text}");
        assert!(text.contains("systemctl reload sshd"), "{text}");
        assert!(!text.contains("systemctl restart ssh"), "a restart drops the install's own session:\n{text}");
        assert!(!text.contains("reboot"), "{text}");
    }

    /// The reload only ever happens AFTER the test passes. Ordering is the
    /// whole safety property here, so it is asserted on positions rather than
    /// on presence.
    #[test]
    fn nothing_is_reloaded_before_the_configuration_is_tested() {
        let text = script("gryonixnexus", FAKE_KEY);
        let test_at = text.find("sshd -t").expect("the config is tested");
        let reload_at = text.find("systemctl reload").expect("sshd is reloaded");
        assert!(test_at < reload_at, "{text}");
    }

    /// The guard, all three of its exits, and every one of them BEFORE the
    /// write. A home directory that does not resolve, a missing file, and a
    /// file that does not carry our key are one answer: no proven way back in.
    #[test]
    fn every_way_of_having_no_key_refuses_to_write_the_drop_in() {
        let text = script("gryonixnexus", FAKE_KEY);
        let write_at = text.find("mv \"$STAGED\" \"$DROP_IN\"").expect("the drop-in is installed");
        for guard in [
            "if [ -z \"$HOME_DIR\" ]; then say no-key; exit 0; fi",
            "if [ ! -s \"$KEYS\" ]; then say no-key; exit 0; fi",
            "if ! grep -qxF \"$APP_KEY\" \"$KEYS\"; then say no-key; exit 0; fi",
        ] {
            let at = text.find(guard).unwrap_or_else(|| panic!("missing guard {guard}:\n{text}"));
            assert!(at < write_at, "this guard runs after the file is written:\n{guard}");
        }
    }

    /// **The distinction the whole guard turns on.** `grep -qxF "$APP_KEY"`
    /// asks whether the key THIS deployment signs in with is on that account.
    /// A test for "the file is not empty" would pass on an existing-user host
    /// whose `authorized_keys` holds only the owner's own keys — and that host
    /// is precisely the one whose app authenticates with a password.
    #[test]
    fn the_guard_looks_for_the_apps_own_key_and_not_merely_a_key() {
        let text = script("gryonixnexus", FAKE_KEY);
        assert!(text.contains(&format!("APP_KEY='{FAKE_KEY}'")), "{text}");
        assert!(text.contains("grep -qxF \"$APP_KEY\" \"$KEYS\""), "{text}");
        // -x and -F together, or a key that is a PREFIX of a line already on
        // the account would answer for it: `grep -F` alone matches a substring.
        assert!(!text.contains("grep -q \"$APP_KEY\""), "a substring match is not a key: {text}");
    }

    /// The control user is interpolated into a shell script, so it goes in
    /// single quotes — the same discipline every generated wrapper in this
    /// crate follows.
    #[test]
    fn the_control_user_is_quoted_into_the_script() {
        assert!(script("admin", FAKE_KEY).contains("CONTROL_USER='admin'"), "{}", script("admin", FAKE_KEY));
    }

    /// The file the script writes has to be the file this module publishes;
    /// two authors of that text is the drift the whole crate is built to
    /// avoid.
    #[test]
    fn the_script_writes_exactly_the_published_drop_in() {
        let text = script("gryonixnexus", FAKE_KEY);
        assert!(text.contains(&drop_in()), "{text}");
        // Quoted heredoc: nothing inside it is expanded, so a `#` comment or a
        // `$` in a future revision cannot become a shell substitution.
        assert!(text.contains("<<'GRYONIXNEXUS_SSHD_DROP_IN'"), "{text}");
    }

    #[test]
    fn every_verdict_the_script_can_write_is_understood() {
        let text = script("gryonixnexus", FAKE_KEY);
        let mut said = Vec::new();
        let mut rest = text.as_str();
        while let Some(at) = rest.find("say ") {
            let tail = &rest[at + 4..];
            let end = tail.find(|c: char| !(c.is_ascii_alphanumeric() || c == '-')).unwrap_or(tail.len());
            if end > 0 {
                said.push(tail[..end].to_string());
            }
            rest = &tail[end.max(1)..];
        }
        // `say() {` itself is not a verdict; every other occurrence is.
        said.retain(|word| word != "say");
        assert!(!said.is_empty(), "{text}");
        for word in &said {
            assert!(Verdict::parse(word).is_some(), "the agent would not understand the verdict {word:?}");
        }
        // And the other direction: a verdict the agent knows but the script
        // never writes is a step line no host can ever produce.
        for word in [
            "closed",
            "closed-not-reloaded",
            "closed-unverified",
            "already-closed",
            "no-key",
            "invalid-config",
            "no-sshd",
            "not-written",
            "not-effective",
        ] {
            assert!(said.iter().any(|said| said == word), "the script never writes {word:?}");
        }
    }

    /// An unknown word is NOT rounded up to success. This is the single place
    /// where a lenient parse would cost somebody their host.
    #[test]
    fn an_unrecognised_verdict_is_not_a_success() {
        assert_eq!(Verdict::parse("probably fine"), None);
        assert_eq!(Verdict::parse(""), None);
        assert_eq!(Verdict::parse(" closed \n"), Some(Verdict::Closed));
    }

    /// Every verdict has to say what the host accepts now. The two that leave
    /// passwords on must SAY so — a step line that merely reports an internal
    /// state is one the operator cannot act on.
    #[test]
    fn the_verdicts_that_leave_passwords_on_say_which_they_are() {
        for verdict in [Verdict::NoKey, Verdict::InvalidConfig, Verdict::NotWritten, Verdict::NotEffective] {
            let line = verdict.step("gryonixnexus");
            assert!(line.contains("leaving SSH password login ON"), "{line}");
        }
        assert!(Verdict::NoKey.step("bot").contains("'bot'"), "the account is named: {}", Verdict::NoKey.step("bot"));
    }

    /// Every refusal, and each of them is a host that KEEPS password login.
    /// Pinned as a set, because the failure this guards against is a future
    /// edit that turns one of them into a fallback.
    #[test]
    fn nothing_is_closed_without_both_a_control_user_and_a_known_app_key() {
        assert!(subject(None, Some(FAKE_KEY)).is_err(), "no control user");
        assert!(subject(Some(""), Some(FAKE_KEY)).is_err(), "blank control user");
        assert!(subject(Some("gryonixnexus"), None).is_err(), "no known app key");
        assert!(subject(Some("gryonixnexus"), Some("   ")).is_err(), "blank app key");
        assert_eq!(subject(Some("gryonixnexus"), Some(FAKE_KEY)), Ok(("gryonixnexus", FAKE_KEY)));
    }

    /// A key carrying a quote or a newline would break out of the shell literal
    /// it is written into. Refused here as well as at the place it is read
    /// from, because this is a second reader and a rule enforced in one place
    /// is a rule the next reader does not have.
    #[test]
    fn a_key_that_could_break_out_of_the_shell_literal_is_refused() {
        assert!(subject(Some("gryonixnexus"), Some("ssh-ed25519 AAA' ; rm -rf / #")).is_err());
        assert!(subject(Some("gryonixnexus"), Some("ssh-ed25519 AAA\nssh-rsa BBB")).is_err());
    }

    /// The script must be runnable by `sh`, not just by bash: the transient
    /// unit runs `/bin/sh`.
    #[test]
    fn the_script_parses_under_plain_sh() {
        let out = std::process::Command::new("sh")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().expect("a stdin pipe").write_all(script("gryonixnexus", FAKE_KEY).as_bytes())?;
                child.wait_with_output()
            })
            .expect("sh runs");
        assert!(
            out.status.success(),
            "sh -n rejected the script: {}\n{}",
            String::from_utf8_lossy(&out.stderr),
            script("gryonixnexus", FAKE_KEY)
        );
    }
}

/// **The script, RUN.**
///
/// Everything above asks the generated text questions. This runs it — under a
/// fake root, with `sshd`, `systemctl` and `getent` stubbed — because a test
/// that greps a script for a guard says nothing about whether the guard fires,
/// and this file's whole job is to decide, on a live machine, whether that
/// machine can still be logged into. GOTCHAS states the rule twice over: an
/// assertion about server behaviour is checked by running it, and absence is
/// BUILT rather than taken from the environment.
#[cfg(test)]
mod execution {
    use std::path::{Path, PathBuf};

    const FAKE_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake gryonixnexus-app";

    /// One run of the real script against a sandbox.
    struct Run {
        root: PathBuf,
        verdict: String,
        drop_in: PathBuf,
    }

    /// Where the two absolute paths the script carries are redirected to.
    ///
    /// Rewritten in the TEXT rather than parameterised in the product: the
    /// point is to run the bytes a server would run, and a script with a
    /// test-only root would be a different script.
    fn sandbox(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sshd-close-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).expect("a sandbox");
        dir
    }

    fn stub(root: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("bin").join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("a stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("a stub");
    }

    /// `authorized_keys` for the control user, as the stubbed `getent` will
    /// point at it. `None` writes no file at all.
    fn with_keys(root: &Path, keys: Option<&str>) {
        let home = root.join("home/gryonixnexus");
        std::fs::create_dir_all(home.join(".ssh")).expect("a home");
        stub(root, "getent", &format!("printf 'gryonixnexus:x:1000:1000::{}:/bin/bash\\n'", home.display()));
        match keys {
            Some(text) => std::fs::write(home.join(".ssh/authorized_keys"), text).expect("keys"),
            None => {
                let _ = std::fs::remove_file(home.join(".ssh/authorized_keys"));
            }
        }
    }

    fn run(root: &Path) -> Run {
        let drop_in = root.join("etc/ssh/sshd_config.d/10-gryonixnexus-no-password.conf");
        let verdict_path = root.join("verdict");
        let text = super::script("gryonixnexus", FAKE_KEY)
            .replace("/etc/ssh/sshd_config.d", &root.join("etc/ssh/sshd_config.d").display().to_string())
            .replace(super::VERDICT_PATH, &verdict_path.display().to_string());

        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&text)
            // The stub directory FIRST, so `command -v sshd` finds ours and the
            // coreutils the script needs still come from the system.
            // **The whole environment is BUILT, never inherited.** Taking the
            // process PATH would mean "this host has no sshd" was tested
            // against a mac that has one in /usr/sbin — the exact mistake
            // GOTCHAS records about faking a missing docker. The stub
            // directory plus the two coreutils directories is everything the
            // script may find.
            .env("PATH", format!("{}:/usr/bin:/bin", root.join("bin").display()))
            .output()
            .expect("sh runs");
        assert!(
            out.status.success(),
            "the script exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        Run {
            root: root.to_path_buf(),
            verdict: std::fs::read_to_string(&verdict_path).unwrap_or_default().trim().to_string(),
            drop_in,
        }
    }

    impl Run {
        fn wrote_drop_in(&self) -> bool {
            self.drop_in.exists()
        }
        fn staged_left_behind(&self) -> bool {
            self.root.join("etc/ssh/sshd_config.d").read_dir().map(|entries| {
                entries.flatten().any(|e| e.file_name().to_string_lossy().ends_with(".staged"))
            }).unwrap_or(false)
        }
    }

    /// A host where everything works: the key is there, sshd accepts the
    /// configuration and reports it resolved.
    fn healthy(root: &Path) {
        stub(root, "sshd", "case \"$1\" in\n  -t) exit 0 ;;\n  -T) printf 'passwordauthentication no\\nkbdinteractiveauthentication no\\n' ;;\nesac");
        stub(root, "systemctl", "exit 0");
    }

    #[test]
    fn a_host_with_the_app_key_ends_up_closed_and_says_so() {
        let root = sandbox("closed");
        with_keys(&root, Some(&format!("# a comment\n\n{FAKE_KEY}\n")));
        healthy(&root);
        let run = run(&root);
        assert_eq!(run.verdict, "closed");
        assert!(run.wrote_drop_in(), "nothing was written");
        assert_eq!(std::fs::read_to_string(&run.drop_in).unwrap(), super::drop_in());
        assert!(!run.staged_left_behind(), "the staged file was left in the include directory");
    }

    /// The second run changes nothing and reloads nothing — a provision that
    /// bounced sshd on every unrelated service install would be its own defect.
    #[test]
    fn a_second_run_is_a_no_op() {
        let root = sandbox("idempotent");
        with_keys(&root, Some(FAKE_KEY));
        healthy(&root);
        assert_eq!(run(&root).verdict, "closed");
        // A systemctl that fails from now on: if the second run reloads, the
        // verdict cannot be `already-closed`.
        stub(&root, "systemctl", "exit 1");
        let again = run(&root);
        assert_eq!(again.verdict, "already-closed");
        assert!(again.wrote_drop_in());
    }

    /// **The guard, fired.** Every one of these is a host with no proven way
    /// back in, and on every one of them nothing may be written.
    #[test]
    fn no_proven_key_writes_nothing_at_all() {
        for (name, keys) in [
            ("missing", None),
            ("empty", Some("")),
            ("comments-only", Some("# nothing but a comment\n\n")),
            ("somebody-elses-key", Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsomeoneElse owner\n")),
            // A PREFIX of our line, which is what `grep -F` alone would accept.
            ("prefix-of-ours", Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake\n")),
        ] {
            let root = sandbox(&format!("nokey-{name}"));
            with_keys(&root, keys);
            healthy(&root);
            let run = run(&root);
            assert_eq!(run.verdict, "no-key", "{name}");
            assert!(!run.wrote_drop_in(), "{name}: a file was written with no proven key");
        }
    }

    /// A configuration sshd refuses takes the daemon down at the next restart,
    /// which is worse than the password login this was closing. The file has to
    /// come off again, and nothing may be reloaded.
    #[test]
    fn a_rejected_configuration_is_undone_on_the_disk() {
        let root = sandbox("rejected");
        with_keys(&root, Some(FAKE_KEY));
        stub(&root, "sshd", "case \"$1\" in\n  -t) exit 1 ;;\nesac");
        // Loud if it is called at all: nothing may be reloaded on this path.
        stub(&root, "systemctl", "echo 'reloaded a rejected configuration' >&2; exit 0");
        let run = run(&root);
        assert_eq!(run.verdict, "invalid-config");
        assert!(!run.wrote_drop_in(), "the host keeps a configuration sshd will not parse");
    }

    /// **The defect this module shipped with for one commit.** Without
    /// `set -e`, a write that cannot happen falls through to `sshd -t` — which
    /// PASSES, because nothing was added — and the run reports a closed door on
    /// a host that is wide open. Built rather than imagined: the include
    /// directory is a FILE, so `install -d` cannot create it.
    #[test]
    fn a_write_that_cannot_happen_is_reported_as_open() {
        let root = sandbox("unwritable");
        with_keys(&root, Some(FAKE_KEY));
        healthy(&root);
        std::fs::create_dir_all(root.join("etc/ssh")).expect("etc/ssh");
        std::fs::write(root.join("etc/ssh/sshd_config.d"), "not a directory").expect("a blocker");
        let run = run(&root);
        assert_eq!(run.verdict, "not-written", "a failed write was reported as success");
    }

    /// **The cloud-init trap, on a machine rather than in a filename.** Every
    /// step succeeds and sshd still takes passwords, because something obtained
    /// earlier in the merged configuration won. Only asking sshd finds it.
    #[test]
    fn a_drop_in_that_is_outranked_is_reported_as_open() {
        let root = sandbox("outranked");
        with_keys(&root, Some(FAKE_KEY));
        stub(&root, "sshd", "case \"$1\" in\n  -t) exit 0 ;;\n  -T) printf 'passwordauthentication yes\\nkbdinteractiveauthentication no\\n' ;;\nesac");
        stub(&root, "systemctl", "exit 0");
        let run = run(&root);
        assert_eq!(run.verdict, "not-effective");
        // The file stays: it is valid and inert, and removing it would hide the
        // reason the next reader needs.
        assert!(run.wrote_drop_in());
    }

    /// Keyboard-interactive left open is the same host with a different door,
    /// and `sshd -T` is where that shows.
    #[test]
    fn keyboard_interactive_left_open_is_reported_as_open() {
        let root = sandbox("kbd");
        with_keys(&root, Some(FAKE_KEY));
        stub(&root, "sshd", "case \"$1\" in\n  -t) exit 0 ;;\n  -T) printf 'passwordauthentication no\\nkbdinteractiveauthentication yes\\n' ;;\nesac");
        stub(&root, "systemctl", "exit 0");
        assert_eq!(run(&root).verdict, "not-effective");
    }

    /// A host with no sshd at all is not a failure and not a success.
    #[test]
    fn a_host_without_sshd_says_so() {
        let root = sandbox("no-sshd");
        with_keys(&root, Some(FAKE_KEY));
        stub(&root, "systemctl", "exit 0");
        let run = run(&root);
        assert_eq!(run.verdict, "no-sshd");
        assert!(!run.wrote_drop_in());
    }

    /// The configuration is on disk and applies at the next start, which is not
    /// the same sentence as "this host refuses passwords now".
    #[test]
    fn a_daemon_that_will_not_reload_is_not_called_closed() {
        let root = sandbox("no-reload");
        with_keys(&root, Some(FAKE_KEY));
        stub(&root, "sshd", "case \"$1\" in\n  -t) exit 0 ;;\n  -T) printf 'passwordauthentication no\\nkbdinteractiveauthentication no\\n' ;;\nesac");
        stub(&root, "systemctl", "exit 1");
        let run = run(&root);
        assert_eq!(run.verdict, "closed-not-reloaded");
        assert!(run.wrote_drop_in());
    }
}

/// **The two scripts the app's button runs, RUN.**
///
/// Same discipline as [`execution`] above and for the same reason: the read
/// decides whether a switch is offered at all, and the open path is the only
/// way back from a door this product closed. Both are asserted against a built
/// environment — a fake root with `sshd`, `systemctl` and `getent` stubbed —
/// because "the script contains a guard" is not a claim about a machine.
#[cfg(test)]
mod on_demand {
    use std::path::{Path, PathBuf};

    const FAKE_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake gryonixnexus-app";

    fn sandbox(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sshd-ondemand-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).expect("a sandbox");
        std::fs::create_dir_all(dir.join("etc/ssh/sshd_config.d")).expect("a sandbox");
        dir
    }

    fn stub(root: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("bin").join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("a stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("a stub");
    }

    fn with_keys(root: &Path, keys: Option<&str>) {
        let home = root.join("home/owner");
        std::fs::create_dir_all(home.join(".ssh")).expect("a home");
        stub(root, "getent", &format!("printf 'owner:x:1000:1000::{}:/bin/bash\\n'", home.display()));
        match keys {
            Some(text) => std::fs::write(home.join(".ssh/authorized_keys"), text).expect("keys"),
            None => {
                let _ = std::fs::remove_file(home.join(".ssh/authorized_keys"));
            }
        }
    }

    /// An sshd that parses, and answers `-T` with what the test says it
    /// resolved. `None` — it prints nothing, the case where the merged
    /// configuration cannot be read back at all.
    fn sshd_saying(root: &Path, effective: Option<&str>) {
        let answer = match effective {
            Some(text) => format!("printf '{text}'"),
            None => String::new(),
        };
        stub(root, "sshd", &format!("case \"$1\" in\n  -t) exit 0 ;;\n  -T) {answer} ;;\nesac"));
    }

    fn drop_in_path(root: &Path) -> PathBuf {
        root.join("etc/ssh/sshd_config.d/10-gryonixnexus-no-password.conf")
    }

    /// Run one of the real scripts with its two absolute paths redirected into
    /// the sandbox, and hand back what it left in the verdict file.
    fn run(root: &Path, text: &str, verdict_name: &str) -> String {
        let verdict = root.join(verdict_name);
        let script = text
            .replace("/etc/ssh/sshd_config.d", &root.join("etc/ssh/sshd_config.d").display().to_string())
            .replace(&super::probe_verdict_path(), &verdict.display().to_string())
            .replace(super::VERDICT_PATH, &verdict.display().to_string());
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            // Built, never inherited — the mac this runs on HAS an sshd, and a
            // test for "this host has none" that found it would prove nothing.
            .env("PATH", format!("{}:/usr/bin:/bin", root.join("bin").display()))
            .output()
            .expect("sh runs");
        assert!(
            out.status.success(),
            "the script exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        std::fs::read_to_string(&verdict).unwrap_or_default().trim().to_string()
    }

    fn probe(root: &Path) -> super::State {
        let line = run(root, &super::probe_script("owner", FAKE_KEY), "probe");
        super::parse_state(&line)
    }

    fn open(root: &Path) -> String {
        run(root, &super::open_script(), "verdict")
    }

    // ── The read ────────────────────────────────────────────────────────────

    /// A host that still takes passwords and does not carry the app's key —
    /// the shape of every server adopted with a password, and the one where
    /// the app must offer to add the key BEFORE it offers the switch.
    #[test]
    fn an_open_host_without_the_app_key_reads_as_both() {
        let root = sandbox("open-nokey");
        with_keys(&root, Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsomeoneElse owner\n"));
        sshd_saying(&root, Some("passwordauthentication yes\\nkbdinteractiveauthentication yes\\n"));
        let state = probe(&root);
        assert_eq!(state.password_open, Some(true));
        assert!(!state.app_key_present, "somebody else's key was taken for ours");
        assert!(!state.drop_in_present);
        assert!(state.sshd_present);
    }

    /// The same guard the close path uses, asked as a question rather than as
    /// a decision: only OUR line counts, and a prefix of it does not.
    #[test]
    fn the_key_is_found_only_when_the_whole_line_is_there() {
        for (name, keys, expected) in [
            ("exactly-ours", Some(format!("# a comment\n\n{FAKE_KEY}\n")), true),
            ("prefix-of-ours", Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake\n".to_string()), false),
            ("empty", Some(String::new()), false),
            ("missing", None, false),
        ] {
            let root = sandbox(&format!("key-{name}"));
            with_keys(&root, keys.as_deref());
            sshd_saying(&root, Some("passwordauthentication yes\\n"));
            assert_eq!(probe(&root).app_key_present, expected, "{name}");
        }
    }

    /// **The cloud-init trap as the CARD would draw it.** The drop-in is on
    /// disk and sshd still takes passwords; the two fields must disagree,
    /// because a reader that trusted the file would tell the owner the host is
    /// closed when it is open.
    #[test]
    fn a_drop_in_that_is_outranked_reads_as_present_and_still_open() {
        let root = sandbox("outranked");
        with_keys(&root, Some(FAKE_KEY));
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication yes\\nkbdinteractiveauthentication no\\n"));
        let state = probe(&root);
        assert!(state.drop_in_present);
        assert_eq!(state.password_open, Some(true), "the file was believed over sshd");
    }

    /// Keyboard-interactive alone is a password prompt with another name, and
    /// a host that leaves it open is open.
    #[test]
    fn keyboard_interactive_alone_still_reads_as_open() {
        let root = sandbox("kbd");
        with_keys(&root, Some(FAKE_KEY));
        sshd_saying(&root, Some("passwordauthentication no\\nkbdinteractiveauthentication yes\\n"));
        assert_eq!(probe(&root).password_open, Some(true));
    }

    /// A closed host, read back as closed.
    #[test]
    fn a_closed_host_reads_as_closed() {
        let root = sandbox("closed");
        with_keys(&root, Some(FAKE_KEY));
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication no\\nkbdinteractiveauthentication no\\n"));
        let state = probe(&root);
        assert_eq!(state.password_open, Some(false));
        assert!(state.app_key_present);
        assert!(state.drop_in_present);
    }

    /// **"Could not tell" is never rounded to "closed".** An sshd that prints
    /// nothing leaves the reading unknown, and the card draws no switch off an
    /// unknown — the alternative is offering to close a door on a host whose
    /// state nobody established.
    #[test]
    fn an_sshd_that_says_nothing_leaves_the_reading_unknown() {
        let root = sandbox("silent");
        with_keys(&root, Some(FAKE_KEY));
        sshd_saying(&root, None);
        let state = probe(&root);
        assert_eq!(state.password_open, None);
        assert!(state.sshd_present);
    }

    /// A host with no sshd: present false, and still no guess about passwords.
    #[test]
    fn a_host_without_sshd_reads_as_neither() {
        let root = sandbox("no-sshd");
        with_keys(&root, Some(FAKE_KEY));
        let state = probe(&root);
        assert!(!state.sshd_present);
        assert_eq!(state.password_open, None);
    }

    /// The probe writes NOTHING. It is the read behind a card that refreshes
    /// on every appearance, and a read that reloaded sshd would be a defect
    /// nobody would attribute to a read.
    #[test]
    fn the_read_changes_nothing_on_the_host() {
        let root = sandbox("read-only");
        with_keys(&root, Some(FAKE_KEY));
        sshd_saying(&root, Some("passwordauthentication yes\\n"));
        // Loud if anything reloads: the stub fails, and a script that depended
        // on it would not come back clean.
        stub(&root, "systemctl", "echo 'the read reloaded sshd' >&2; exit 1");
        probe(&root);
        assert!(!drop_in_path(&root).exists(), "the read wrote the drop-in");
        assert!(
            std::fs::read_dir(root.join("etc/ssh/sshd_config.d")).unwrap().flatten().next().is_none(),
            "the read left something in the include directory"
        );
    }

    // ── The way back ────────────────────────────────────────────────────────

    /// The ordinary open: our file is taken off, sshd parses and reloads, and
    /// it says it takes passwords again.
    #[test]
    fn removing_the_drop_in_opens_the_host_again() {
        let root = sandbox("open");
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication yes\\n"));
        stub(&root, "systemctl", "exit 0");
        assert_eq!(open(&root), "opened");
        assert!(!drop_in_path(&root).exists());
    }

    /// **Only ever this product's own file.** A host whose passwords are
    /// refused by somebody else's configuration is not one this call may claim
    /// to have opened, and nothing is written to make it so.
    #[test]
    fn a_host_this_product_never_closed_is_left_exactly_as_it_is() {
        let root = sandbox("already-open");
        std::fs::write(root.join("etc/ssh/sshd_config.d/50-cloud-init.conf"), "PasswordAuthentication no\n")
            .expect("somebody else's file");
        sshd_saying(&root, Some("passwordauthentication no\\n"));
        stub(&root, "systemctl", "echo 'reloaded for nothing' >&2; exit 1");
        assert_eq!(open(&root), "already-open");
        assert!(root.join("etc/ssh/sshd_config.d/50-cloud-init.conf").exists(),
                "a file this product did not write was removed");
    }

    /// **The rollback, in the direction nobody thinks about.** If sshd refuses
    /// the configuration WITHOUT our drop-in, the rejection was never ours —
    /// and a host left with an sshd that will not start is worse than one that
    /// refuses passwords. The file goes back and nothing is reloaded.
    #[test]
    fn a_configuration_that_is_broken_without_our_file_puts_it_back() {
        let root = sandbox("open-rejected");
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        stub(&root, "sshd", "case \"$1\" in\n  -t) exit 1 ;;\nesac");
        stub(&root, "systemctl", "echo 'reloaded a rejected configuration' >&2; exit 0");
        assert_eq!(open(&root), "open-invalid-config");
        assert_eq!(std::fs::read_to_string(drop_in_path(&root)).unwrap(), super::drop_in());
    }

    /// Removed and reloaded, and sshd still refuses passwords: something else
    /// says so, and this call must not report an open door.
    #[test]
    fn a_host_closed_by_something_else_is_not_reported_open() {
        let root = sandbox("open-not-effective");
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication no\\n"));
        stub(&root, "systemctl", "exit 0");
        assert_eq!(open(&root), "opened-not-effective");
        assert!(!drop_in_path(&root).exists());
    }

    /// A daemon that will not reload has not opened anything yet, and the
    /// sentence has to say so.
    #[test]
    fn a_daemon_that_will_not_reload_is_not_called_open() {
        let root = sandbox("open-no-reload");
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication yes\\n"));
        stub(&root, "systemctl", "exit 1");
        assert_eq!(open(&root), "opened-not-reloaded");
    }

    /// Nothing is left under the include glob on the way out — the backup the
    /// rollback needs is named so sshd cannot see it, and it is removed once
    /// the configuration is known good.
    #[test]
    fn the_backup_is_invisible_to_sshd_and_does_not_survive_a_success() {
        let root = sandbox("open-clean");
        std::fs::write(drop_in_path(&root), super::drop_in()).expect("a drop-in");
        sshd_saying(&root, Some("passwordauthentication yes\\n"));
        stub(&root, "systemctl", "exit 0");
        assert_eq!(open(&root), "opened");
        let left: Vec<String> = std::fs::read_dir(root.join("etc/ssh/sshd_config.d"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(left.is_empty(), "left behind: {left:?}");
        assert!(!format!("{}{}", super::DROP_IN_PATH, super::STAGED_SUFFIX).ends_with(".conf"));
    }

    // ── The parsing and the guards around the scripts ───────────────────────

    /// A line the probe did not write leaves every field at the answer that
    /// makes the app offer nothing.
    #[test]
    fn an_unreadable_probe_line_is_not_an_answer() {
        for text in ["", "open=maybe", "garbage", "open= key= dropin= sshd="] {
            let state = super::parse_state(text);
            assert_eq!(state.password_open, None, "{text:?}");
            assert!(!state.app_key_present, "{text:?}");
            assert!(!state.sshd_present, "{text:?}");
        }
    }

    /// Both scripts embed the account and the key in single-quoted shell
    /// literals, and these arrive from a REQUEST rather than from the host's
    /// own files — so the refusal belongs here as well as in `subject`.
    #[test]
    fn anything_that_could_break_out_of_the_shell_literal_is_refused() {
        assert!(super::shell_safe("owner"));
        assert!(super::shell_safe(FAKE_KEY));
        assert!(!super::shell_safe("own'er"));
        assert!(!super::shell_safe("owner\nrm -rf /"));
        assert!(!super::shell_safe("owner\rrm -rf /"));
    }

    /// The read's answer file is not the write's. A card refreshing while a
    /// close is in flight must not be able to consume the verdict that close
    /// is waiting for.
    #[test]
    fn the_read_and_the_write_do_not_share_an_answer_file() {
        assert_ne!(super::probe_verdict_path(), super::verdict_path());
        assert!(super::probe_verdict_path().starts_with(&super::verdict_path()));
    }

    /// Every verdict the two on-demand paths can produce has a sentence of its
    /// own, and none of them is empty — the app shows this text verbatim.
    #[test]
    fn every_verdict_the_button_can_produce_says_something() {
        for word in [
            "closed", "closed-not-reloaded", "closed-unverified", "not-written", "not-effective",
            "already-closed", "no-key", "invalid-config", "no-sshd", "opened", "already-open",
            "opened-not-reloaded", "opened-not-effective", "open-invalid-config",
        ] {
            let verdict = super::Verdict::parse(word).unwrap_or_else(|| panic!("{word} parses"));
            let sentence = super::verdict_sentence(&verdict, "owner");
            assert!(!sentence.trim().is_empty(), "{word}");
        }
    }
}
