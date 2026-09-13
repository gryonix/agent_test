//! Dynamic DNS: the server keeps its own A records pointing at the address it
//! actually has.
//!
//! **Written by the AGENT ONLY, unlike almost everything else in this
//! directory.** The SSH generator writes wrappers for the whole host half, and
//! this one is the exception for the same reason `dkim.rs`'s wrapper is the
//! rule: it is useless without a credential, and the credential belongs to the
//! app. A generated setup script has no Cloudflare token and no way to get one,
//! so writing this there would put a root-owned script and a systemd timer on
//! every host that could never run — bytes with no caller, which
//! `install/host/mod.rs`'s third rule exists to prevent.
//!
//! **Why the server and not the app.** The owner's decision, and the reason
//! stands on its own: an updater that only runs while a phone is unlocked is
//! not dynamic DNS. The cost is stated rather than hidden — a zone-scoped
//! token now lives on the machine, in a 0600 file, and it can edit DNS for
//! that zone and nothing else.
//!
//! **`curl -f` is banned here, as everywhere in this project.** It throws away
//! the response body, and Cloudflare's body is the only thing that says WHY a
//! call was refused — the lesson the mailcow API calls are annotated with.

/// The updater itself.
pub const SCRIPT_PATH: &str = "/opt/gryonixnexus-ddns.sh";
/// Its configuration, including the token: 0600, root-only.
pub const CONF_PATH: &str = "/etc/gryonixnexus/ddns.conf";
/// What the last run did, for the app to read without sudo.
pub const STATUS_PATH: &str = "/var/lib/gryonixnexus/ddns-status.txt";
pub const SERVICE_UNIT_PATH: &str = "/etc/systemd/system/gryonixnexus-ddns.service";
pub const TIMER_UNIT_PATH: &str = "/etc/systemd/system/gryonixnexus-ddns.timer";
pub const TIMER_UNIT: &str = "gryonixnexus-ddns.timer";

/// Pull the FIRST `"<key>":"<value>"` out of a Cloudflare response.
///
/// Its own constant because a test runs it through a real bash against a real
/// captured response body — a claim about parsing that is only asserted against
/// the script's TEXT is the "green on nothing" pattern this project keeps
/// paying for.
///
/// **Why first-match and never `sed`.** The obvious `sed -n
/// 's/.*"id":"\(...\)".*/\1/p'` is GREEDY: `.*` runs to the end of the line and
/// backtracks, so it yields the LAST id in the document, not the first.
/// Measured against the live API 2026-08-15: a zone response carries the zone's
/// id, then the account's, then a tenant placeholder, and the greedy form
/// returned the third. Cloudflare answers a call for a zone the token cannot
/// touch with a bare `Authentication error`, so the symptom accused the
/// CREDENTIAL. On the records call the same bug is worse and silent: it would
/// have returned the last record's id, and the updater would have pointed
/// someone else's name at this host. Every Cloudflare response puts `"result"`
/// first, so the first match is the first result's field.
const FIRST_FIELD_HELPER: &str = r#"gd_first() {
  # $1 = key. First match in document order; see the module doc for why a
  # greedy sed is wrong here.
  grep -o "\"$1\":\"[^\"]*\"" | head -n1 | cut -d'"' -f4
}"#;

/// How often the address is checked.
///
/// Five minutes is the trade this project can defend: a residential address
/// changes on a reconnect, and a name that resolves to the previous tenant of
/// that address for an hour is worse than five requests an hour to an API that
/// is answering anyway. Cloudflare's own trace endpoint is the source, so the
/// check costs one request even when nothing changed.
pub const INTERVAL: &str = "5min";

/// `/opt/gryonixnexus-ddns.sh`.
///
/// The address is read from Cloudflare's own trace endpoint rather than a
/// third-party "what is my IP" service: we are already trusting Cloudflare
/// with the record, so trusting it for the address adds nobody new — and one
/// fewer host to depend on is one fewer host to be broken by.
pub fn script() -> String {
    format!(
        r#"#!/bin/bash
# Managed by gryonixNexus — keep this host's A records pointing at its address.
# Runs from {TIMER_UNIT}; reads its token from {CONF_PATH} (0600).
set -euo pipefail

CONF='{CONF_PATH}'
STATUS='{STATUS_PATH}'
API='https://api.cloudflare.com/client/v4'

{FIRST_FIELD_HELPER}

gd_record() {{
  # The status file is the ONLY channel a scheduled run has: nobody is
  # watching stderr at four in the morning.
  printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >> "$STATUS"
  tail -n 50 "$STATUS" > "$STATUS.trim" 2>/dev/null && mv "$STATUS.trim" "$STATUS"
  echo "$*"
}}

[ -r "$CONF" ] || {{ gd_record 'GRYONIXNEXUS_DDNS_FAILED no-config'; exit 1; }}
# shellcheck source=/dev/null
. "$CONF"

: "${{DDNS_TOKEN:=}}"
: "${{DDNS_ZONE:=}}"
: "${{DDNS_NAMES:=}}"
if [ -z "$DDNS_TOKEN" ] || [ -z "$DDNS_ZONE" ] || [ -z "$DDNS_NAMES" ]; then
  gd_record 'GRYONIXNEXUS_DDNS_FAILED incomplete-config'
  exit 1
fi

# `-f` is deliberately NOT used anywhere here: it discards the body, and the
# body is the only place Cloudflare says why it refused.
gd_api() {{
  local method="$1" path="$2" body="${{3:-}}"
  if [ -n "$body" ]; then
    curl -sS --max-time 20 -X "$method" "$API$path" \
      -H "Authorization: Bearer $DDNS_TOKEN" -H 'Content-Type: application/json' \
      --data "$body"
  else
    curl -sS --max-time 20 -X "$method" "$API$path" \
      -H "Authorization: Bearer $DDNS_TOKEN" -H 'Content-Type: application/json'
  fi
}}

# The address as the INTERNET sees it, from the party that will serve the
# record anyway — asked for BOTH families.
#
# A home connection is normally dual-stack, and the record type has to match
# the family: an A record cannot hold an IPv6 address. Measured on a live home
# host 2026-08-15 — its DEFAULT egress was IPv6, so a single unqualified ask
# returned a v6 address, and the numeric check below rejected it as "no
# address". The host had a perfectly good IPv4 address the whole time; it just
# had to be asked for by name.
IP4="$( {{ curl -4 -sS --max-time 15 https://cloudflare.com/cdn-cgi/trace || true; }} | sed -n 's/^ip=//p' | head -n1 )"
IP6="$( {{ curl -6 -sS --max-time 15 https://cloudflare.com/cdn-cgi/trace || true; }} | sed -n 's/^ip=//p' | head -n1 )"
case "$IP4" in *[!0-9.]*) IP4='' ;; esac
case "$IP6" in *[!0-9a-fA-F:]*) IP6='' ;; esac
if [ -z "$IP4" ] && [ -z "$IP6" ]; then
  gd_record 'GRYONIXNEXUS_DDNS_FAILED no-address'
  exit 1
fi

ZONE_ID="$(gd_api GET "/zones?name=$DDNS_ZONE" | gd_first id)"
if [ -z "$ZONE_ID" ]; then
  gd_record "GRYONIXNEXUS_DDNS_FAILED no-zone $DDNS_ZONE"
  exit 1
fi

changed=0
for name in $DDNS_NAMES; do
  # Only record types that ALREADY exist are touched. The updater never
  # creates: which names this host should answer for is the owner's decision,
  # made in the zone, and a v6 address invented for a name that only has an A
  # record would be a new promise nobody asked for.
  seen=0
  for family in 4 6; do
    if [ "$family" = 4 ]; then ip="$IP4"; type=A; else ip="$IP6"; type=AAAA; fi
    if [ -z "$ip" ]; then continue; fi
    record="$(gd_api GET "/zones/$ZONE_ID/dns_records?type=$type&name=$name")"
    rec_id="$(printf '%s' "$record" | gd_first id)"
    if [ -z "$rec_id" ]; then continue; fi
    seen=1
    current="$(printf '%s' "$record" | gd_first content)"
    if [ "$current" = "$ip" ]; then continue; fi
    # PATCH, not PUT: the record's other fields (proxied, ttl, comment) are the
    # owner's and must survive an address change.
    answer="$(gd_api PATCH "/zones/$ZONE_ID/dns_records/$rec_id" "{{\"content\":\"$ip\"}}")"
    case "$answer" in
      *'"success":true'*) gd_record "GRYONIXNEXUS_DDNS_UPDATED $name $type $current -> $ip"; changed=1 ;;
      *) gd_record "GRYONIXNEXUS_DDNS_FAILED update $name $type $(printf '%s' "$answer" | tail -c 160)" ;;
    esac
  done
  # Said once per NAME, not per family: a name with only an A record is normal,
  # and complaining about its missing AAAA every five minutes would fill the
  # status file with something that reads like breakage.
  if [ "$seen" -eq 0 ]; then
    gd_record "GRYONIXNEXUS_DDNS_FAILED no-record $name"
  fi
done

if [ "$changed" -eq 0 ]; then
  gd_record "GRYONIXNEXUS_DDNS_UNCHANGED ${{IP4:-}} ${{IP6:-}}"
fi
"#
    )
}

/// The service unit the timer starts. `Type=oneshot`: it runs, records what it
/// did and exits — nothing here is long-lived.
pub fn service_unit() -> String {
    format!(
        "[Unit]\nDescription=gryonixNexus dynamic DNS update\nAfter=network-online.target\n\
         Wants=network-online.target\n\n[Service]\nType=oneshot\nExecStart={SCRIPT_PATH}\n"
    )
}

/// The timer.
///
/// `Persistent=true` so a machine that was asleep or off updates as soon as it
/// is back rather than waiting out the interval — the address it has after a
/// reconnect is exactly the one that has just gone stale.
pub fn timer_unit() -> String {
    format!(
        "[Unit]\nDescription=gryonixNexus dynamic DNS timer\n\n[Timer]\n\
         OnBootSec=2min\nOnUnitActiveSec={INTERVAL}\nPersistent=true\n\n\
         [Install]\nWantedBy=timers.target\n"
    )
}

/// `/etc/gryonixnexus/ddns.conf` — 0600, because line one is a credential.
///
/// Shell-quoted with single quotes and a refusal to carry one: the file is
/// SOURCED by the updater, so a value that closed the quote would run as a
/// command. The caller validates too; this is the second layer.
pub fn conf(token: &str, zone: &str, names: &[String]) -> Result<String, String> {
    for value in [token, zone] {
        if value.contains('\'') || value.contains('\n') {
            return Err("a quote or newline in a value that is sourced by the shell".to_string());
        }
    }
    for name in names {
        if name.contains('\'') || name.contains('\n') || name.contains(' ') {
            return Err(format!("{name} is not a hostname"));
        }
    }
    Ok(format!(
        "# Managed by gryonixNexus — dynamic DNS. Contains a credential; keep 0600.\n\
         DDNS_TOKEN='{token}'\nDDNS_ZONE='{zone}'\nDDNS_NAMES='{}'\n",
        names.join(" ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The body is the only thing that says why Cloudflare refused, and `-f`
    /// throws it away — the lesson this project paid for on the mailcow API.
    #[test]
    fn the_updater_never_uses_curls_fail_flag() {
        let text = script();
        for line in text.lines().filter(|line| line.contains("curl")) {
            assert!(!line.contains("-f "), "curl -f discards the body: {line}");
            assert!(!line.contains("-sf"), "curl -f discards the body: {line}");
        }
    }

    /// An unchanged address must still be recorded. A scheduled run nobody
    /// watches is only visible through this file, and silence would read the
    /// same as a host that stopped updating months ago.
    #[test]
    fn every_outcome_reaches_the_status_file() {
        let text = script();
        for marker in ["GRYONIXNEXUS_DDNS_UPDATED", "GRYONIXNEXUS_DDNS_UNCHANGED", "GRYONIXNEXUS_DDNS_FAILED"] {
            assert!(text.contains(marker), "{marker} is never recorded");
        }
    }

    /// PATCH, not PUT: an address change must not silently drop the record's
    /// proxied flag or its TTL, which belong to the owner.
    #[test]
    fn the_address_is_patched_so_the_owners_other_fields_survive() {
        assert!(script().contains("gd_api PATCH"));
        assert!(!script().contains("gd_api PUT"));
    }

    /// The file is SOURCED, so a quote in a value would be a command.
    #[test]
    fn a_value_that_could_break_out_of_the_config_is_refused() {
        assert!(conf("tok'en", "example.com", &["a.example.com".to_string()]).is_err());
        assert!(conf("token", "exam'ple.com", &["a.example.com".to_string()]).is_err());
        assert!(conf("token", "example.com", &["a b".to_string()]).is_err());
        let good = conf("token", "example.com", &["a.example.com".to_string(), "b.example.com".to_string()])
            .expect("a plain configuration is accepted");
        assert!(good.contains("DDNS_NAMES='a.example.com b.example.com'"), "{good}");
    }

    /// A real Cloudflare zone response, captured from the live API on
    /// 2026-08-15 and shortened only by cutting fields — the ORDER of the three
    /// ids is the whole point and is untouched. The zone's own id comes first,
    /// the account's second, a tenant placeholder third.
    const ZONE_RESPONSE: &str = r#"{"result":[{"id":"c6f4a209c9350a2dc8ab4ade10128a35","name":"gryonix.com","status":"active","account":{"id":"8676b863fb4dedce800974346975c54f","name":"an account"},"tenant":{"id":"0feeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}}],"success":true}"#;

    /// A records response for a zone holding TWO names. The wrapper asks with a
    /// name filter so it normally sees one, but a parse that reaches for the
    /// last match would point the WRONG name at this host — which is why the
    /// fixture deliberately carries a second record.
    const RECORDS_RESPONSE: &str = r#"{"result":[{"id":"47ab4f764589867571b50c6f826b025f","name":"home.gryonix.com","type":"A","content":"192.0.2.1","meta":{},"comment":"first"},{"id":"99999999999999999999999999999999","name":"other.gryonix.com","type":"A","content":"203.0.113.9","meta":{}}],"success":true}"#;

    fn extract(body: &str, key: &str) -> String {
        let script = format!("{FIRST_FIELD_HELPER}\nprintf '%s' \"$BODY\" | gd_first {key}");
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .env("BODY", body)
            .output()
            .expect("bash runs");
        assert!(out.status.success(), "helper failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// The defect this test exists for was live: a greedy `sed` returned the
    /// THIRD id in the zone response, every later call was for a zone the token
    /// could not touch, and Cloudflare's answer (`Authentication error`) blamed
    /// the credential. Asserted by RUNNING the extraction, not by reading it.
    #[test]
    fn the_first_id_is_taken_and_not_the_last() {
        assert_eq!(extract(ZONE_RESPONSE, "id"), "c6f4a209c9350a2dc8ab4ade10128a35");
        assert_eq!(extract(RECORDS_RESPONSE, "id"), "47ab4f764589867571b50c6f826b025f");
        assert_eq!(extract(RECORDS_RESPONSE, "content"), "192.0.2.1");
    }

    /// `"zone_id"` must not be mistaken for `"id"` — the record carries both,
    /// and pointing the update at the zone's id would address a record that
    /// does not exist.
    #[test]
    fn a_key_that_merely_ends_in_id_is_not_matched() {
        let body = r#"{"result":[{"zone_id":"aaaa","id":"bbbb","content":"1.2.3.4"}]}"#;
        assert_eq!(extract(body, "id"), "bbbb");
    }

    /// The extraction the script actually ships must be the tested one. A
    /// helper that is correct in a constant and bypassed in the script is the
    /// same nothing as a test that never ran.
    #[test]
    fn the_script_parses_through_the_helper_only() {
        let text = script();
        assert!(text.contains(FIRST_FIELD_HELPER), "the tested helper is not in the script");
        assert!(
            !text.contains(r#"sed -n 's/.*"id""#),
            "a greedy id extraction is back in the script"
        );
        for line in text.lines().filter(|line| line.contains(r#""id""#) || line.contains(r#""content""#)) {
            assert!(
                line.contains("gd_first") || line.trim_start().starts_with('#'),
                "this line parses a field without the helper: {line}"
            );
        }
    }

    /// A home connection is dual-stack and its DEFAULT egress may be IPv6.
    /// Measured on a live home host: an unqualified ask returned a v6 address
    /// and the updater rejected it as "no address" while a perfectly good IPv4
    /// address sat there unasked for.
    #[test]
    fn both_address_families_are_asked_for_by_name() {
        let text = script();
        assert!(text.contains("curl -4 -sS"), "the IPv4 address is never asked for by family");
        assert!(text.contains("curl -6 -sS"), "the IPv6 address is never asked for by family");
    }

    /// An A record cannot hold an IPv6 address. The type has to follow the
    /// family, or the update is refused by the API for a reason that reads like
    /// a broken token.
    #[test]
    fn the_record_type_follows_the_address_family() {
        let text = script();
        assert!(
            text.contains(r#"if [ "$family" = 4 ]; then ip="$IP4"; type=A; else ip="$IP6"; type=AAAA; fi"#),
            "the record type is not tied to the family"
        );
        assert!(text.contains("dns_records?type=$type&name=$name"), "the query does not carry the type");
    }

    /// A name with only an A record is normal. Complaining about its missing
    /// AAAA every five minutes would fill the only channel a scheduled run has
    /// with something that reads like breakage.
    #[test]
    fn a_missing_record_is_reported_once_per_name_not_once_per_family() {
        let text = script();
        let marker = text
            .lines()
            .filter(|line| line.contains("GRYONIXNEXUS_DDNS_FAILED no-record"))
            .count();
        assert_eq!(marker, 1, "no-record is recorded more than once");
        assert!(text.contains(r#"if [ "$seen" -eq 0 ]; then"#), "no-record is not guarded by the per-name flag");
    }

    /// The v6 check must accept hex and colons — the v4 charset would throw
    /// every IPv6 address away, which is exactly the defect this pass fixed.
    #[test]
    fn each_family_is_validated_with_its_own_charset() {
        let text = script();
        assert!(text.contains(r#"case "$IP4" in *[!0-9.]*)"#), "IPv4 is not validated");
        assert!(text.contains(r#"case "$IP6" in *[!0-9a-fA-F:]*)"#), "IPv6 is not validated as hex and colons");
    }

    /// A timer that only fires on its interval leaves a machine that was off
    /// pointing at an address it no longer has.
    #[test]
    fn the_timer_catches_up_after_downtime() {
        assert!(timer_unit().contains("Persistent=true"));
        assert!(timer_unit().contains("OnBootSec="));
    }
}
