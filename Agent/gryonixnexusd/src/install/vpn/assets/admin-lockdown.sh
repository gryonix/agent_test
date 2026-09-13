#!/bin/bash
# Managed by gryonixNexus — VPN-only access switch for admin web panels.
# on = every site; only host... = just those sites (per-service
# selection); off = public again. Every Caddy site imports the guard,
# so a host matcher inside it narrows which vhosts actually block.
set -euo pipefail
GUARD=/etc/caddy/gryonixnexus-admin-guard
# Shown to blocked visitors so a locked panel is a clear "denied"
# page, not an empty-bodied 403 that browsers render as a blank
# white screen. It names WireGuard specifically: whoever reads this
# page is most often already connected to the VPN — on AmneziaWG or
# one of the proxy protocols, which do not carry admin traffic — so
# "connect to the VPN" would be advice they already followed.
# ASCII only and no quotes: it rides through a Caddyfile heredoc and
# lands inside a double-quoted respond argument.
DENY='Access denied. The admin panels are reachable only over WireGuard. Add a WireGuard client in your VPN panel and connect with it. AmneziaWG, OpenVPN, Shadowsocks and XRay carry internet traffic but do not reach the admin panels.'
reload_caddy() { systemctl reload caddy 2>/dev/null || systemctl restart caddy || true; }
write_guard() {
  hosts="$1"
  # Scenario-A hairpin allow-source. VPN clients on the containerised
  # protocols (amneziaWG / OpenVPN / shadowsocks / xray) that open an
  # admin panel served on THIS host's own public IP loop back through
  # the protocol/host NAT and reach Caddy SNAT'd to that public IP — a
  # source private_ranges does not cover, so the guard used to 403 a
  # genuinely VPN-side client (only the panel's own WireGuard, which
  # arrives from a private address, got through). No off-box client can
  # forge our own public IP as its source — the TCP return path comes
  # straight back to us — so our own global addresses are a safe allow.
  # This is the scenario-A counterpart to the 10.8.0.254 relay hairpin.
  selfip=$(
    { ip -4 -o addr show scope global; ip -6 -o addr show scope global; } 2>/dev/null \
      | awk '{ split($4, a, "/"); ip = a[1]; print ip (index(ip, ":") ? "/128" : "/32") }' \
      | paste -sd' ' -
  )
  {
    if [ -n "$hosts" ]; then
      printf '@gryonixnexus_relay {\n'
      printf '    host %s\n' "$hosts"
      printf '    remote_ip 10.8.0.0/24\n'
      printf '    not remote_ip 10.8.0.254/32\n'
      printf '}\n'
      printf 'respond @gryonixnexus_relay "%s" 403\n' "$DENY"
      printf '@gryonixnexus_public {\n'
      printf '    host %s\n' "$hosts"
      printf '    not remote_ip private_ranges %s\n' "$selfip"
      printf '}\n'
      printf 'respond @gryonixnexus_public "%s" 403\n' "$DENY"
    else
      printf '@gryonixnexus_relay {\n'
      printf '    remote_ip 10.8.0.0/24\n'
      printf '    not remote_ip 10.8.0.254/32\n'
      printf '}\n'
      printf 'respond @gryonixnexus_relay "%s" 403\n' "$DENY"
      printf '@gryonixnexus_public not remote_ip private_ranges %s\n' "$selfip"
      printf 'respond @gryonixnexus_public "%s" 403\n' "$DENY"
    fi
  } > "$GUARD"
  reload_caddy
}
case "${1:-status}" in
  on)
    write_guard ""
    echo on ;;
  only)
    shift
    [ "$#" -ge 1 ] || { echo "usage: $0 only host..." >&2; exit 64; }
    for h in "$@"; do
      case "$h" in
        *[!A-Za-z0-9.-]*|"") echo "invalid host: $h" >&2; exit 64 ;;
      esac
    done
    write_guard "$*"
    echo "only $*" ;;
  off)
    : > "$GUARD"
    reload_caddy
    echo off ;;
  status)
    if [ ! -s "$GUARD" ]; then
      echo off
    elif grep -q 'host ' "$GUARD"; then
      echo "only $(grep -m1 'host ' "$GUARD" | sed 's/^ *host //')"
    else
      echo on
    fi ;;
  *)
    echo "usage: $0 on|off|only host...|status" >&2; exit 64 ;;
esac
