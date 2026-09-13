//! The nftables ruleset itself, for a host that has none.
//!
//! `install/firewall.rs` writes per-service DROP-INS into `/etc/nftables.d` and
//! flushes the chain `gryonixnexus_services` in `table inet filter`. Both are
//! written by the SETUP script — so on a host the agent built alone, neither
//! exists, the drop-in path answers "ports are not open, re-run setup", and the
//! machine ends up with whatever firewall the distribution left behind. On
//! Ubuntu 26.04 that is: a sample `/etc/nftables.conf` and `nftables.service`
//! **disabled**, i.e. nothing in force at all. This module closes that.
//!
//! **What it writes is deliberately the smallest thing that works**: the base
//! chain with SSH/HTTP/HTTPS, the empty `gryonixnexus_services` chain, the jump
//! into it and the include of the drop-in directory. Ports for individual
//! services keep coming from `firewall.rs`, unchanged — this only creates the
//! surface those drop-ins land on.
//!
//! Three rules it must not break, each paid for elsewhere:
//! - **Never `flush ruleset`.** It erases docker's NAT rules and takes every
//!   container's networking with it (GOTCHAS.md). The distro's own sample file
//!   starts with exactly that, which is one more reason not to keep it.
//! - **No forward chain on a docker host.** docker sets its own FORWARD policy
//!   and per-container accepts; ours would kill them.
//! - **Replace only a ruleset that is NOT IN FORCE.** A host whose
//!   `nftables.service` is active with someone else's rules gets a refusal, not
//!   a rewrite.


use super::execute::EventSink;
use super::firewall;

/// Where the ruleset lives. Redirectable for tests, like every other path in
/// this crate that a test needs to point somewhere harmless.
pub fn conf_path() -> String {
    std::env::var("GRYONIXNEXUSD_NFTABLES_CONF").unwrap_or_else(|_| "/etc/nftables.conf".to_string())
}

/// The ports the BASE ruleset opens, as opposed to the per-service drop-ins.
///
/// All three are terminated by a HOST process, never by docker: sshd, and Caddy
/// for 80/443. That distinction is the whole reason this list is short — a
/// docker-published port is not controlled by the input chain at all (measured
/// 2026-08-13: an explicit `drop` does not close one), so listing it here would
/// be theatre. Caddy is the exception that makes the file worth writing: it is
/// a host process, so its two ports genuinely need an accept.
pub const BASE_TCP_PORTS: [u16; 3] = [22, 80, 443];

/// The ruleset this writes.
///
/// `table inet filter` and the chain name are `firewall::TABLE`/`CHAIN` — the
/// drop-in half looks them up there, and a base file that spelled them
/// differently would produce drop-ins nothing ever reaches.
pub fn ruleset(drop_in_dir: &str) -> String {
    let ports = BASE_TCP_PORTS.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
    format!(
        "#!/usr/sbin/nft -f\n\
         # Managed by gryonixNexus — written by the control-plane agent.\n\
         #\n\
         # No `flush ruleset` here on purpose: it would erase docker's own NAT\n\
         # table and cut every container off the network. Only OUR table is\n\
         # replaced, which is what makes re-applying this safe.\n\
         #\n\
         # No forward chain either — docker manages forwarding on this host, and\n\
         # a policy of ours would drop its per-container accepts.\n\
         #\n\
         # The relay's NAT table is destroyed too, and it has to be: a host that\n\
         # STOPPED being a relay keeps its DNAT otherwise, and a live rule that\n\
         # forwards 80/443 to a tunnel address nobody answers on is worse than\n\
         # a closed port — measured on lab-bare 2026-08-13, where 443 stayed\n\
         # unreachable after the role was rolled back and the filter table alone\n\
         # was replaced. `destroy` is idempotent, so this costs nothing on a host\n\
         # that never had one.\n\
         destroy table inet filter\n\
         destroy table ip {nat_table}\n\
         \n\
         table inet filter {{\n\
         \x20   # Ports of services live in {drop_in_dir}, not here: they are\n\
         \x20   # written per service and flushed as a group.\n\
         \x20   chain {chain} {{\n\
         \x20   }}\n\
         \n\
         \x20   chain input {{\n\
         \x20       type filter hook input priority filter; policy drop;\n\
         \x20       iif \"lo\" accept\n\
         \x20       ct state established,related accept\n\
         \x20       ct state invalid drop\n\
         \x20       icmp type {{ destination-unreachable, echo-request, time-exceeded, parameter-problem }} limit rate 10/second burst 5 packets accept\n\
         \x20       meta l4proto ipv6-icmp accept\n\
         \x20       tcp dport {{ {ports} }} accept comment \"SSH + HTTP/HTTPS for ACME\"\n\
         \x20       jump {chain}\n\
         \x20   }}\n\
         }}\n\
         \n\
         include \"{drop_in_dir}/{glob}\"\n",
        chain = firewall::CHAIN,
        glob = firewall::DROP_IN_GLOB,
        nat_table = super::firewall_relay::NAT_TABLE,
    )
}

/// Does this host already carry a gryonixNexus ruleset?
///
/// **Two markers, because one of them is version-dependent.** The chain name
/// only appears in rulesets written after the drop-in contract existed, and the
/// fleet has hosts older than that: the production home half (`nukki`,
/// 2026-08-13) carries a generated ruleset with no `gryonixnexus_services` chain at
/// all, so a check on the chain alone called it SOMEBODY ELSE'S and left it
/// untouched — meaning the one host that most needed the home half's connection
/// marks could never be given them.
///
/// The header is matched case-insensitively on purpose: the generator's own
/// wording changed from `Managed by GryonixNexus` to `Managed by gryonixNexus`, and
/// files with the old spelling are still on live hosts (`ProvisionHost`'s diffs
/// showed exactly that pair on both halves of the production deployment).
pub fn already_ours(conf: &str) -> bool {
    conf.contains(firewall::CHAIN) || conf.to_ascii_lowercase().contains("managed by gryonixnexus")
}

/// Which ruleset this host needs, which is a function of its ROLE.
///
/// A single host and either half of scenario B need genuinely different files —
/// see `firewall_relay` for what and why — and the role is something only the
/// client knows (the proto's comment on `host_role` explains why a live `wg0` is
/// not evidence).
pub enum Plan {
    /// Scenario A, and the services host of a local-only deployment.
    SingleHost,
    /// Scenario B's private half: the base ruleset plus the connection marks
    /// that send a relayed reply back through the tunnel, plus the deployment's
    /// forwarded ports accepted from the tunnel when the request named them.
    HomeBackend(Option<super::firewall_relay::Topology>),
    /// Scenario B's public half: forward chain, DNAT into the tunnel, SNAT.
    Relay(super::firewall_relay::Topology),
}

/// The marker every file THIS module writes carries.
///
/// It distinguishes our own output from a setup script's, which matters for
/// exactly one decision: a file the agent wrote is ours to keep CURRENT (a newer
/// agent that adds a rule must be able to land it), while a setup-generated file
/// of the right shape is left alone — it is richer than ours on purpose (tighter
/// accepts, its own NAT table), and replacing it would be a downgrade dressed up
/// as an upgrade.
const AGENT_MARKER: &str = "written by the control-plane agent";

/// Does this file already carry the shape its role needs?
///
/// **Being "ours" is not enough on either half of scenario B.** Measured on the
/// production relay 2026-08-13: its `/etc/nftables.conf` was ours, and
/// single-host shaped — no forward chain, no DNAT, and no accept for the tunnel
/// port, so the tunnel survived only on a conntrack entry a keepalive kept
/// renewing and a NEW peer could not hand-shake at all. A check that stopped at
/// "ours" would leave that mine in place forever.
///
/// The other direction matters just as much: a host whose file ALREADY has the
/// role's shape is left alone, so a setup-built relay or home half keeps its own
/// file — including the tighter tunnel-only accepts `NftablesConfig.homeRuleset`
/// writes and this module deliberately does not.
fn has_role_shape(conf: &str, plan: &Plan) -> bool {
    match plan {
        // A single host's file is right unless it is a RELAY's: a host that
        // stopped being one would otherwise keep forwarding rules aimed at a
        // tunnel that no longer exists. The condition is deliberately narrow
        // (a DNAT into the tunnel, which no single-host ruleset this project
        // generates has ever contained) so an operator's own additions to an
        // otherwise ordinary file are not treated as the wrong shape.
        Plan::SingleHost => !conf.contains("dnat to"),
        Plan::HomeBackend(_) => conf.contains("ct mark set"),
        Plan::Relay(_) => conf.contains("hook forward") && conf.contains("dnat to"),
    }
}

/// Make sure this host has a working ruleset with the drop-in surface on it.
///
/// Not fatal on failure, and that is a judgement rather than an oversight: the
/// services are up and published by this point, and refusing the whole install
/// over a firewall would leave the operator with a machine that works but is
/// reported as failed. It is announced loudly instead — the same shape as the
/// Caddy-enable step.
pub(super) async fn ensure_ruleset(sink: &EventSink) {
    ensure(&Plan::SingleHost, sink).await
}

/// Does this file already play a role that an INSTALL must not take away?
///
/// **Installing a service is not the verb that decides what a host is.**
/// `ProvisionHost` is; this one is called from every install with
/// `Plan::SingleHost`, because an install request does not carry the
/// deployment's topology. That was fine while the only question was "does a
/// ruleset exist", and it became a live outage the moment the staleness
/// refresh was added: a home half's file is ours, is NOT equal to the
/// single-host text, and was therefore judged stale and rewritten as a single
/// host — losing the tunnel accepts for the mail ports and the connection mark
/// that carries relayed replies back through the tunnel.
///
/// Measured on the production pair 2026-08-18: after one install, IMAPS,
/// submission, SMTP and Sieve were all refused ON THE HOME HALF'S OWN
/// FIREWALL, while the host itself looked perfectly healthy — local requests
/// worked, the tunnel was up, and the only symptom was that mail from outside
/// stopped arriving. Exactly the silence ARCHITECTURE warns about.
fn plays_a_relay_pair_role(conf: &str) -> bool {
    // The two markers the relay halves are detected by elsewhere in this file,
    // read together: either one means this host is half of a pair.
    conf.contains("ct mark set") || conf.contains("dnat to")
}

/// The role-aware entry point.
pub(super) async fn ensure(plan: &Plan, sink: &EventSink) {
    let conf = conf_path();
    let existing = std::fs::read_to_string(&conf).unwrap_or_default();
    // An install may create a ruleset where there is none; it may never take a
    // host OUT of the role it is already playing — see
    // `plays_a_relay_pair_role`. Only `ProvisionHost`, which is told the
    // topology, changes a role.
    if matches!(plan, Plan::SingleHost) && already_ours(&existing) && plays_a_relay_pair_role(&existing) {
        let _ = sink
            .step(
                concat!(
                    "left this host's firewall as it is: it is half of a relay pair, ",
                    "and installing a service does not change that — re-provision ",
                    "the server to rewrite its ruleset",
                ),
            )
            .await;
        return;
    }
    // A file this agent wrote gets refreshed when a newer agent would write
    // something different — measured 2026-08-13, when MSS clamping was added to
    // the relay ruleset and the shape check happily reported the OLD file as
    // correct, so the fix could not reach the host that had just proved it was
    // needed. Only our own output is treated this way; a setup script's file of
    // the right shape stays untouched.
    let ours_and_stale = existing.contains(AGENT_MARKER) && !existing.is_empty() && {
        let dir = firewall::drop_in_dir_display();
        match plan {
            Plan::SingleHost => existing != ruleset(&dir),
            Plan::HomeBackend(topology) => {
                existing != super::firewall_relay::home_ruleset(&dir, topology.as_ref().filter(|t| !t.all_tcp_ports().is_empty()))
            }
            // The relay's file names the detected interface, so comparing it
            // needs that answer; asking for it here would mean running `ip` on
            // every call. The cheap proxy is the rule set MINUS the interface:
            // any difference in the rules themselves shows up in it.
            Plan::Relay(topology) => match topology.is_complete() {
                false => false,
                true => {
                    let ours = super::firewall_relay::relay_ruleset(topology, "", &dir);
                    rules_without_interface(&existing) != rules_without_interface(&ours)
                }
            },
        }
    };
    if already_ours(&existing) && has_role_shape(&existing, plan) && !ours_and_stale {
        // The FILE is right for this role. The LIVE ruleset can still carry a
        // table from a role this host no longer plays: measured on lab-bare
        // 2026-08-13, rolling a relay back to a single host left
        // `ip gryonixnexus_nat` in force, so every inbound 443 was still DNATed
        // to a tunnel address nobody answered on — and because the file was by
        // then correct, the next call returned right here and never fixed it.
        // Re-applying our own file is what removes it, and re-applying is safe:
        // the file destroys and rebuilds only our own tables and re-includes the
        // drop-ins.
        if !matches!(plan, Plan::Relay(_)) && live_relay_nat_present().await {
            let _ = sink.step("removing the NAT table left over from this host's previous role").await;
            if let Err(why) = destroy_relay_nat().await {
                let _ = sink.step(format!("WARNING: could not remove it: {why}")).await;
            }
        }
        return;
    }
    // Someone else's rules, and they are LIVE: never overwrite those. A host
    // whose firewall is actually in force is a host whose firewall someone
    // chose.
    //
    // **`!already_ours` is load-bearing, and its absence was a real defect.**
    // Before roles existed, the check above returned for ANY file of ours, so
    // this one only ever saw foreign files and the guard was implicit. The moment
    // a file of ours could be the WRONG SHAPE for its role, it started arriving
    // here — and since our own ruleset is of course active, the relay refused to
    // fix itself and reported the host's firewall as "someone else's". Caught on
    // the first live run (lab-bare, 2026-08-13); no unit test could see it,
    // because the branch needs a host with an active nftables.
    if !already_ours(&existing) && !existing.trim().is_empty() && service_is_active().await {
        let _ = sink
            .step("this host has its own active nftables ruleset — leaving it alone; \
                   service ports will not be opened automatically")
            .await;
        return;
    }
    // **A home half must not lose its tunnel accepts to a request that simply
    // forgot them.** Those lines are the relayed services — the live pair
    // carries eight — and a rewrite without them kills relayed mail at the home
    // firewall, silently, which is exactly the mine `home_ruleset`'s own
    // comment describes. The narrow case is the dangerous one: the file HAS
    // such ports and the request names NONE. A request that names ports is
    // free to shorten the list (that is a real change), and a host that never
    // had any is untouched by this.
    if let Plan::HomeBackend(topology) = plan {
        let asked_for_none = topology
            .as_ref()
            .map_or(true, |topo| topo.all_tcp_ports().is_empty() && topo.all_udp_ports().is_empty());
        let already = super::firewall_relay::tunnel_accepted_ports(&existing);
        if asked_for_none && !already.is_empty() {
            let ports =
                already.iter().map(|port| port.to_string()).collect::<Vec<_>>().join(", ");
            let _ = sink
                .step(format!(
                    "the firewall was left alone: this host accepts {ports} from the tunnel and                      this request names no forwarded ports, so rewriting it would stop everything                      the relay sends here — send the deployment's forwarded ports"
                ))
                .await;
            return;
        }
    }

    let dir = firewall::drop_in_dir_display();
    let contents = match plan {
        Plan::SingleHost => {
            let _ = sink.step("writing the base nftables ruleset").await;
            ruleset(&dir)
        }
        Plan::HomeBackend(topology) => {
            let _ = sink
                .step("writing the home-half nftables ruleset (relayed replies need a connection mark)")
                .await;
            // The topology is OPTIONAL here, unlike on the relay: a home half
            // whose request carries the deployment's forwarded ports accepts
            // them from the tunnel, and one that carries none still gets a
            // working firewall rather than a refusal.
            super::firewall_relay::home_ruleset(&dir, topology.as_ref().filter(|t| !t.all_tcp_ports().is_empty()))
        }
        Plan::Relay(topology) => {
            // **A relay never gets the base ruleset as a fallback.** The base
            // opens 22/80/443 and nothing else, so on a relay it would close the
            // tunnel port and cut the deployment in half — strictly worse than
            // leaving the host's firewall exactly as it is and saying so.
            if !topology.is_complete() {
                let _ = sink
                    .step(
                        "this request carries no tunnel topology, so the relay's firewall was left \
                         untouched — a relay needs its tunnel port and DNAT rules, and the base \
                         ruleset would close them",
                    )
                    .await;
                return;
            }
            let public_interface = match super::firewall_relay::public_interface().await {
                Some(name) => name,
                None => {
                    let _ = sink
                        .step(
                            "could not work out this host's public interface, so the relay's \
                             firewall was left untouched",
                        )
                        .await;
                    return;
                }
            };
            let _ = sink
                .step(format!("writing the relay nftables ruleset (public interface {public_interface})"))
                .await;
            super::firewall_relay::relay_ruleset(topology, &public_interface, &dir)
        }
    };
    if let Err(why) = write_conf(&conf, &contents, sink).await {
        let _ = sink.step(format!("WARNING: could not write the firewall ruleset: {why}")).await;
        return;
    }
    if let Err(why) = enable_service(sink).await {
        let _ = sink.step(format!("WARNING: the firewall ruleset was written but not applied: {why}")).await;
        return;
    }
    // `destroy table inet filter` replaced OUR table only, so docker's NAT
    // survived and there is nothing to restart — unlike the setup script, which
    // flushes everything and has to bounce docker afterwards.
    let _ = sink
        .step(match plan {
            Plan::SingleHost => "the base firewall is in force",
            Plan::HomeBackend(_) => "the home-half firewall is in force",
            Plan::Relay(_) => "the relay firewall is in force",
        })
        .await;
}

/// The rule lines of a ruleset, with the `define pub_if = …` line dropped.
///
/// Comparing two relay rulesets means ignoring the one value that is discovered
/// per host: everything else about the file — every rule that decides where a
/// packet goes — still has to match.
fn rules_without_interface(conf: &str) -> Vec<String> {
    conf.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.is_empty() && !line.starts_with("define pub_if"))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

/// Is the relay's NAT table live on this host right now?
///
/// A question about the RULESET, not the file — the two disagree exactly when a
/// host changes role, which is the case this exists for. Read-only, so it runs
/// inside the sandbox; a failure to ask answers "no", because re-applying a
/// firewall on a guess is worse than leaving one stale table for the next call.
async fn live_relay_nat_present() -> bool {
    let output = tokio::process::Command::new(super::firewall::nft_bin())
        .args(["list", "tables"])
        .output()
        .await;
    match output {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.split_whitespace().last() == Some(super::firewall_relay::NAT_TABLE)),
        _ => false,
    }
}

/// Drop the relay's NAT table from the LIVE ruleset.
///
/// A direct `nft` call, not a re-apply of `/etc/nftables.conf`: the file on a
/// host that changed role may well be an older agent's, without the `destroy`
/// line, and re-applying it would then report success and change nothing —
/// measured exactly that way on lab-bare 2026-08-13. This asks the kernel for
/// the one thing that has to happen. No filesystem write, so no transient unit.
async fn destroy_relay_nat() -> Result<(), String> {
    let output = tokio::process::Command::new(super::firewall::nft_bin())
        .args(["destroy", "table", "ip", super::firewall_relay::NAT_TABLE])
        .output()
        .await
        .map_err(|err| err.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

/// Is `nftables.service` actually running?
async fn service_is_active() -> bool {
    super::execute::run_quiet_public(&super::execute::systemctl_bin_public(), &["is-active", "nftables"])
        .await
        .is_ok()
}

/// Both writes go through a transient unit for the same reason package
/// installation does: `/etc/nftables.conf` sits directly in `/etc`, which
/// `ProtectSystem=full` holds read-only for this process. See
/// `install/packages.rs` for the measurement.
async fn write_conf(path: &str, contents: &str, sink: &EventSink) -> Result<(), String> {
    // The heredoc delimiter is quoted, so nothing inside the ruleset is
    // expanded by the shell — the file lands byte for byte.
    let script = format!(
        "set -e\numask 022\ncat > '{path}' <<'GRYONIXNEXUS_NFT_EOF'\n{contents}GRYONIXNEXUS_NFT_EOF\nchmod 0755 '{path}'\n"
    );
    super::packages::run_outside_sandbox(&script, "writing the firewall ruleset", sink).await
}

async fn enable_service(sink: &EventSink) -> Result<(), String> {
    super::packages::run_outside_sandbox(
        "systemctl enable --now nftables && systemctl reload nftables 2>/dev/null || systemctl restart nftables",
        "applying the firewall ruleset",
        sink,
    )
    .await
}

#[cfg(test)]
mod relay_pair_guard_tests {
    use super::*;

    /// **The outage this guard exists to prevent, stated as a test.** A home
    /// half's ruleset carries the connection mark; a relay's carries the DNAT.
    /// An install — which always asks for `SingleHost`, because an install
    /// request does not know the topology — must leave both alone.
    #[test]
    fn a_home_halfs_ruleset_is_recognised_as_a_role_an_install_must_not_take_away() {
        let home = "# Managed by gryonixNexus\n  ct state new iifname \"wg0\" ct mark set 0x00000001\n";
        assert!(plays_a_relay_pair_role(home));
    }

    #[test]
    fn a_relays_ruleset_is_too() {
        let relay = "# Managed by gryonixNexus\n  iifname \"ens6\" tcp dport 443 dnat to 10.8.0.2\n";
        assert!(plays_a_relay_pair_role(relay));
    }

    /// And an ordinary single host is NOT — otherwise the guard would stop the
    /// agent from ever writing or refreshing a plain ruleset, which is the
    /// thing it is normally for.
    #[test]
    fn an_ordinary_single_host_is_not_locked_by_the_guard() {
        let dir = firewall::drop_in_dir_display();
        assert!(!plays_a_relay_pair_role(&ruleset(&dir)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RULES, without the comments — the first version of this checked the
    /// whole file and failed on the comment that explains why `flush ruleset`
    /// is absent. A firewall check has to read what nft reads.
    fn rules_only(text: &str) -> String {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_ruleset_never_flushes_everything() {
        let rules = rules_only(&ruleset("/etc/nftables.d"));
        assert!(!rules.contains("flush ruleset"), "flushing everything erases docker's NAT");
        assert!(rules.contains("destroy table inet filter"), "only our own table may be replaced");
    }

    /// **A host that stopped being a relay must lose the relay's NAT too.**
    ///
    /// Measured on lab-bare 2026-08-13: rolling the role back to single host
    /// rewrote the filter table and left `ip gryonixnexus_nat` live, so every
    /// inbound 443 was still DNATed to a tunnel address nobody answered on —
    /// a port that looks closed for a reason nothing on the host explains.
    #[test]
    fn the_base_ruleset_also_removes_a_relays_nat_table() {
        let rules = rules_only(&ruleset("/etc/nftables.d"));
        assert!(rules.contains(&format!("destroy table ip {}", super::super::firewall_relay::NAT_TABLE)));
        // The home half inherits the same removal, for the same reason.
        assert!(rules_only(&super::super::firewall_relay::home_ruleset("/etc/nftables.d", None))
            .contains(&format!("destroy table ip {}", super::super::firewall_relay::NAT_TABLE)));
        // And docker's own table is never named.
        assert!(!rules.contains("destroy table ip nat"), "that table is docker's");
    }

    #[test]
    fn the_ruleset_declares_no_forward_chain() {
        // docker owns forwarding on these hosts; ours would drop its
        // per-container accepts (GOTCHAS.md).
        let rules = rules_only(&ruleset("/etc/nftables.d"));
        assert!(!rules.contains("hook forward"), "a forward chain would break docker networking");
    }

    #[test]
    fn the_chain_and_include_match_what_the_drop_in_half_expects() {
        let text = ruleset("/etc/nftables.d");
        // The drop-in half flushes THIS chain and includes THIS glob; a base
        // file that spelled either differently would produce drop-ins nothing
        // reaches.
        assert!(text.contains(&format!("chain {} {{", firewall::CHAIN)));
        assert!(text.contains(&format!("jump {}", firewall::CHAIN)));
        assert!(text.contains(&format!("include \"/etc/nftables.d/{}\"", firewall::DROP_IN_GLOB)));
    }

    #[test]
    fn the_base_opens_only_ports_a_host_process_terminates() {
        let text = ruleset("/etc/nftables.d");
        assert!(text.contains("tcp dport { 22, 80, 443 } accept"));
        // Nothing docker-published belongs here: the input chain does not
        // control those at all (measured 2026-08-13).
        assert!(!text.contains("8388"));
        assert!(!text.contains("51820"));
    }

    /// **"Ours" is not enough on either half of scenario B — and this is the
    /// test the harness was missing.**
    ///
    /// Measured on the production relay 2026-08-13: its `/etc/nftables.conf` was
    /// ours and SINGLE-HOST shaped — no forward chain, no DNAT, and no accept for
    /// the tunnel port. The tunnel survived only because a keepalive kept
    /// renewing a conntrack entry; a new peer could not hand-shake at all. A
    /// check that stopped at `already_ours` would leave that mine in place
    /// forever, and a negative control proved nothing else caught it.
    ///
    /// The opposite direction is pinned too, because it is what keeps a
    /// setup-built host's own file: a ruleset that already HAS the role's shape is
    /// never rewritten, so the tighter tunnel-only accepts `NftablesConfig
    /// .homeRuleset` writes survive contact with the agent.
    #[test]
    fn being_ours_is_not_being_the_right_shape_for_the_role() {
        let single_host = ruleset("/etc/nftables.d");
        assert!(already_ours(&single_host));
        assert!(has_role_shape(&single_host, &Plan::SingleHost));
        // The exact state of the live relay: ours, and useless as a relay.
        assert!(
            !has_role_shape(&single_host, &Plan::Relay(super::super::firewall_relay::Topology::single("10.8.0.2".into(), "203.0.113.10".into(), 51820, vec![80, 443], vec![]))),
            "a single-host ruleset must never pass as a relay's"
        );
        assert!(!has_role_shape(&single_host, &Plan::HomeBackend(None)), "the base ruleset marks nothing");

        // The real generated artifacts DO carry their shapes.
        let swift_relay = include_str!("../../tests/fixtures/relay/vps.nft");
        let swift_home = include_str!("../../tests/fixtures/relay/home.nft");
        let topology = super::super::firewall_relay::Topology::single("10.8.0.2".into(), "203.0.113.10".into(), 51820, vec![80, 443], vec![51821]);
        assert!(has_role_shape(swift_relay, &Plan::Relay(topology.clone())));
        assert!(has_role_shape(swift_home, &Plan::HomeBackend(None)));
        // And so do the agent's own.
        assert!(has_role_shape(
            &super::super::firewall_relay::relay_ruleset(&topology, "ens6", "/etc/nftables.d"),
            &Plan::Relay(topology)
        ));
        assert!(has_role_shape(&super::super::firewall_relay::home_ruleset("/etc/nftables.d", None), &Plan::HomeBackend(None)));

        // And the reverse direction: a host that STOPPED being a relay must not
        // keep forwarding rules aimed at a tunnel nobody terminates any more.
        assert!(!has_role_shape(swift_relay, &Plan::SingleHost));
        assert!(has_role_shape(swift_home, &Plan::SingleHost), "marks alone are not a relay's DNAT");
    }

    /// **A file the AGENT wrote is kept current; a setup script's is not
    /// touched.** The distinction was paid for the day MSS clamping was added to
    /// the relay ruleset: the shape check reported the old file as correct, so
    /// the fix could not reach the very host that had just proved it was needed
    /// (2026-08-13). Refreshing every file of ours would be the wrong cure — a
    /// setup-generated relay file is richer than this module's on purpose.
    #[test]
    fn an_agent_written_ruleset_is_refreshed_and_a_setup_written_one_is_left_alone() {
        let ours = ruleset("/etc/nftables.d");
        assert!(ours.contains(AGENT_MARKER), "our own output must be identifiable");
        // A setup script's single-host ruleset says "Managed by gryonixNexus" and
        // never carries this marker.
        let setup_written = "#!/usr/sbin/nft -f\n\
                             # Managed by gryonixNexus — single-server firewall (default-deny).\n\
                             table inet filter {\n  chain gryonixnexus_services {\n  }\n}\n";
        assert!(already_ours(setup_written));
        assert!(!setup_written.contains(AGENT_MARKER));

        // The interface is the one value a relay's file gets per host, and
        // comparing two of them has to ignore it — while still comparing every
        // rule.
        let topology = super::super::firewall_relay::Topology::single("10.8.0.2".into(), "203.0.113.10".into(), 51820, vec![80, 443], vec![]);
        let with_ens6 = super::super::firewall_relay::relay_ruleset(&topology, "ens6", "/etc/nftables.d");
        let with_eth0 = super::super::firewall_relay::relay_ruleset(&topology, "eth0", "/etc/nftables.d");
        assert_eq!(rules_without_interface(&with_ens6), rules_without_interface(&with_eth0));
        // But a real difference in the rules is seen: drop the clamp and the
        // comparison must notice.
        let without_clamp: String = with_ens6.lines().filter(|line| !line.contains("maxseg")).collect();
        assert_ne!(rules_without_interface(&with_ens6), rules_without_interface(&without_clamp));
    }

    #[test]
    fn a_ruleset_we_already_wrote_is_recognised_and_a_foreign_one_is_not() {
        assert!(already_ours(&ruleset("/etc/nftables.d")));
        assert!(!already_ours("table inet filter {\n  chain input {\n  }\n}\n"));
        assert!(!already_ours(""));
        // A ruleset OLDER than the drop-in chain is still ours, and the header's
        // capitalisation changed once: `nukki` runs a file that says
        // `Managed by GryonixNexus` and has no chain, and reading it as a
        // stranger's is what kept the agent from ever fixing that host.
        let old_generated = "#!/usr/sbin/nft -f\n\
                             # Managed by GryonixNexus — home-server firewall (default-deny).\n\
                             table inet filter {\n  chain input {\n  }\n}\n";
        assert!(already_ours(old_generated));
        assert!(!has_role_shape(old_generated, &Plan::HomeBackend(None)), "it has no marks");
        // Current spelling, same answer.
        assert!(already_ours("# Managed by gryonixNexus — single-server firewall (default-deny).\n"));
    }
}
