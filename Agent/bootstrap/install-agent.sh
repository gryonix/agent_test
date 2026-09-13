#!/usr/bin/env bash
# Bootstrap the gryonixNexus control-plane agent on a server. This is the ONE
# fixed script the app still sends over SSH: it installs/updates gryonixnexusd and
# its systemd unit, then everything else goes through the agent's API. Over
# time it replaces the two large setup scripts.
#
# Self-contained, idempotent, non-interactive — same rules as the setup scripts.
# It expects the Agent/ tree beside it (../gryonixnexusd, ../proto, ../systemd):
# the agent is built ON the server, like gryonix-vpn-panel:local.
#
# Env knobs:
#   GRYONIXNEXUSD_PREFIX          install under a prefix (tests; default "")
#   GRYONIXNEXUSD_FORCE_BUILD=1   rebuild even when the installed version matches
#   GRYONIXNEXUSD_RUST_IMAGE      toolchain image for the container build
#   GRYONIXNEXUSD_KEEP_BUILD_IMAGE=1  keep that image instead of removing it
set -euo pipefail

PREFIX="${GRYONIXNEXUSD_PREFIX:-}"
BIN_DEST="$PREFIX/usr/local/bin/gryonixnexusd"
UNIT_DEST="$PREFIX/etc/systemd/system/gryonixnexusd.service"
# /var/lib/gryonixnexus is the SHARED product directory (setup writes
# install-report.txt there); the agent owns only the `agent` subdirectory below
# it. See the state layout block further down.
PRODUCT_STATE_DIR="$PREFIX/var/lib/gryonixnexus"
STATE_DIR="$PRODUCT_STATE_DIR/agent"
# Build-time only, never runs in production, so it is NOT pinned the way the
# service images are: a fixed old toolchain rots against the crates' minimum
# Rust versions, and nothing about the resulting binary depends on which patch
# release built it. Overridable for an air-gapped mirror.
RUST_IMAGE="${GRYONIXNEXUSD_RUST_IMAGE:-rust:1-alpine}"

log() { printf 'gryonixnexusd-bootstrap: %s\n' "$*" >&2; }
fail() { log "$*"; exit 1; }

# musl target so the binary is a single static file per arch.
case "$(uname -m)" in
  aarch64|arm64) ARCH="aarch64" ;;
  x86_64|amd64)  ARCH="x86_64" ;;
  *) fail "unsupported arch: $(uname -m)" ;;
esac

AGENT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CRATE_DIR="$AGENT_DIR/gryonixnexusd"
UNIT_SRC="$AGENT_DIR/systemd/gryonixnexusd.service"
[ -f "$CRATE_DIR/Cargo.toml" ] || fail "agent sources not found next to this script ($CRATE_DIR)"
[ -f "$UNIT_SRC" ] || fail "systemd unit not found ($UNIT_SRC)"

# The version to install comes from the sources being installed — a second
# hardcoded copy here would drift from Cargo.toml the first time it bumps.
VERSION="$(awk -F'"' '/^version = "/ {print $2; exit}' "$CRATE_DIR/Cargo.toml")"
[ -n "$VERSION" ] || fail "could not read the version from $CRATE_DIR/Cargo.toml"

# The daemon used to be called `gryonixd` (unit gryonixnexus.service, socket
# /run/gryonixd.sock). Its unit has Restart=always, so a host that ran the old
# build keeps a second agent alive on the old socket forever — invisible to the
# app, still root, still holding the docker socket. Remove it before installing
# the new one — and before the state block below, which moves the database that
# predecessor may still have open. Its state is deliberately kept, never wiped.
if [ -f "$PREFIX/etc/systemd/system/gryonixnexus.service" ]; then
  log "removing the predecessor unit (gryonixd)"
  systemctl disable --now gryonixnexus.service >/dev/null 2>&1 || true
  rm -f "$PREFIX/etc/systemd/system/gryonixnexus.service" "$PREFIX/usr/local/bin/gryonixd" \
        "$PREFIX/run/gryonixd.sock"
  systemctl daemon-reload
fi

# ------------------------------------------------------------- state layout
# The product directory is SHARED with the setup scripts: they create it
# `install -d -m 755` and write install-report.txt into it, and the app reads
# that report WITHOUT sudo — it is the only place the credentials generated on
# the server are written down. The first agent claimed the whole directory
# (StateDirectory=gryonixnexus, StateDirectoryMode=0700, re-applied by systemd on
# every start) and the report became unreadable. The agent now owns only
# `agent/` below it.
#
# mkdir + explicit chmod rather than `install -d -m`: the mode has to be
# re-asserted on a directory that ALREADY exists (that is exactly the host this
# fix has to reach — the one the broken version left at 0700), and whether
# `install -d` touches an existing directory's mode is not worth depending on.
mkdir -p "$PRODUCT_STATE_DIR"
chmod 0755 "$PRODUCT_STATE_DIR"
mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"

# /etc/gryonixnexus has to exist BEFORE the unit starts, not when something first
# writes to it. The unit lists it in ReadWritePaths (the wrappers' schedule and
# passphrase files live there) and `ProtectSystem=full` punches that hole once,
# while the mount namespace is built — so a directory created afterwards is
# still read-only to the running agent, because its parent /etc is. On a host
# that setup has never touched, which is exactly the host Ф4 is meant to be
# able to build alone, nothing else would have created it.
# Same mode setup uses (0755): the directory is shared, only the passphrase
# file inside it is 0600.
mkdir -p "$PREFIX/etc/gryonixnexus"
chmod 0755 "$PREFIX/etc/gryonixnexus"

# /etc/caddy, for EXACTLY the same reason and a sharper one. The agent can now
# install Caddy itself (install/packages.rs), but installing it does NOT make
# its config directory writable: the hole is punched once, when the namespace is
# built, so a directory the package manager creates minutes later is still
# read-only to the running agent, and the install would die on
# `could not create /etc/caddy: Read-only file system` AFTER doing all the real
# work. Creating it here, before the unit starts, is what makes "the agent
# builds a bare host alone" actually true rather than nearly true.
# The Caddy package is happy to adopt an existing directory; the mode is the one
# setup uses, and caddy reads its Caddyfile as root.
mkdir -p "$PREFIX/etc/caddy"
chmod 0755 "$PREFIX/etc/caddy"

# /etc/nftables.d, third of the same kind. The agent writes per-service drop-ins
# here and the base ruleset it may write includes this directory by glob; both
# need it writable, which means it has to exist before the namespace is built.
# It used to be deliberately absent — "better an honest 'ports are not open'
# than drop-ins in a directory nobody includes" — and that reasoning expired the
# moment the agent started writing the ruleset that DOES include it.
mkdir -p "$PREFIX/etc/nftables.d"
chmod 0755 "$PREFIX/etc/nftables.d"

# /etc/crowdsec/acquis.d, fourth of the same kind and for the sharpest version
# of the reason. The agent installs CrowdSec itself and then has to write its
# own acquisition file — and the package creating /etc/crowdsec a minute later
# does not make it writable, because the hole is punched once, when the mount
# namespace is built. Without this the intrusion defence installs cleanly,
# starts cleanly, and reads nothing at all.
mkdir -p "$PREFIX/etc/crowdsec/acquis.d"
chmod 0755 "$PREFIX/etc/crowdsec" "$PREFIX/etc/crowdsec/acquis.d"

# A host that ran an earlier agent has state.db one level up. Move it instead of
# orphaning it: it holds the paired devices, and an agent that silently starts
# on an empty database looks to every paired device like a server that forgot
# them. The -wal/-shm sidecars are part of the database, not scratch files.
if [ -f "$PRODUCT_STATE_DIR/state.db" ]; then
  if [ -f "$STATE_DIR/state.db" ]; then
    log "both $STATE_DIR/state.db and the old $PRODUCT_STATE_DIR/state.db exist — keeping the new one, leaving the old untouched"
  else
    log "migrating state.db into $STATE_DIR"
    # Stop first: renaming the file out from under a running agent keeps it
    # writing to the moved inode while its WAL sidecars are moved separately.
    systemctl stop gryonixnexusd.service >/dev/null 2>&1 || true
    for f in state.db state.db-wal state.db-shm; do
      if [ -e "$PRODUCT_STATE_DIR/$f" ]; then
        mv -f "$PRODUCT_STATE_DIR/$f" "$STATE_DIR/$f"
      fi
    done
  fi
fi

# ------------------------------------------- the gryonixDom → gryonixNexus rename
# The product used to be called gryonixDom, and EVERY path on a server carried
# that name: the agent's unit and binary, the six wrappers under /opt, the
# metrics collector's unit, the autobackup/autoupdate units, /var/lib and /etc.
# The rename changed all of them in the sources at once and NOTHING on the
# machines already installed, so such a host ends up running both installations
# side by side.
#
# Measured on vps-middle 2026-08-31, not deduced: two agents alive at the same
# time, two autobackup units, and a metrics collector still appending two days
# of history to /var/lib/gryonixdom/metrics while the app read the new directory
# and drew "no history yet" over a host that had been sampling itself all along.
#
# The rule is one sentence: the NEW name wins wherever both exist, the old name
# is ADOPTED wherever only it exists, and when this returns the old installation
# has nothing running and nothing scheduled. Adoption rewrites the name INSIDE
# the text it moves, because a wrapper and a unit spell out their own paths —
# moving the file without rewriting it would leave a script under the new name
# still writing to the old directory, which is the bug this block exists to end.
#
# Why here and not in the agent: this is the one code path that reaches a host
# BEFORE the new agent runs, and the two installations must not overlap for even
# one tick of the collector.
LEGACY_UNIT_DIR="$PREFIX/etc/systemd/system"
LEGACY_STATE_DIR="$PREFIX/var/lib/gryonixdom"
LEGACY_ETC_DIR="$PREFIX/etc/gryonixdom"
LEGACY_SUDOERS="$PREFIX/etc/sudoers.d/gryonixdom-control"

# Rewrite the product name while copying. Deliberately NOT `sed -i`: this same
# script is exercised by Tools/test-install-agent.sh on macOS, where in-place
# editing needs an argument GNU sed rejects. Both spellings, because units carry
# the display name (Description=gryonixDom …) and paths carry the lowercase one.
rename_into() {
  sed -e 's/gryonixdom/gryonixnexus/g' -e 's/gryonixDom/gryonixNexus/g' "$1" > "$2"
}

# Move what only the old name has, keep what the new name already has, and walk
# INTO a directory that exists on both sides instead of calling it occupied.
# That last part is the whole reason this is a function: `agent/` exists on
# every host by the time this runs, `metrics/` exists on every host a current
# install has touched, and treating either as a taken name would silently
# abandon a database or two days of history one level below it.
# What could not be adopted, because the new name already had it, is moved out
# of the way rather than left where it lies. Two reasons, both measured:
#
#   - the old directory surviving is what makes this whole block run again on
#     every future bootstrap of the host, printing a paragraph about files it is
#     never going to move. One-shot is a property worth having.
#   - what stays behind is not junk. On vps-middle the two backup passphrases
#     differ (9e92494d vs 20385ba6): the wrapper generated a fresh one when it
#     found nothing at the new path, so every ENCRYPTED archive made before the
#     rename is keyed to the file being left behind. Deleting it would make
#     those archives unrecoverable; leaving it in an orphaned directory nothing
#     names is how it gets deleted by the next person to tidy up.
#
# 0700 on the way in: this holds a backup passphrase.
quarantine() {
  [ -d "$1" ] || return 0
  dest="$PRODUCT_STATE_DIR/pre-rename"
  mkdir -p "$dest"
  chmod 0700 "$dest"
  if [ -e "$dest/$2" ]; then
    # A second migration on a host that already has one. Nothing here is worth
    # a collision policy of its own — the first copy is the one the archives
    # were encrypted with.
    log "$1 left in place: $dest/$2 already holds a copy"
    return 0
  fi
  log "moving what exists under both names to $dest/$2"
  mv -f "$1" "$dest/$2"
}

adopt_into() {
  if [ -d "$1" ] && [ ! -L "$1" ] && [ -d "$2" ]; then
    for nested in "$1"/* "$1"/.[!.]*; do
      [ -e "$nested" ] || continue
      adopt_into "$nested" "$2/$(basename "$nested")"
    done
    # Fails while anything is left, which is exactly the report wanted: what
    # stayed behind is what exists under both names.
    rmdir "$1" 2>/dev/null || log "$1 exists under both names — keeping the current one"
  elif [ -e "$2" ]; then
    log "$1 exists under both names — keeping the current one"
  else
    mv -f "$1" "$2"
  fi
}

legacy_units="$(cd "$LEGACY_UNIT_DIR" 2>/dev/null && ls 2>/dev/null | grep '^gryonixdom' || true)"
legacy_wrappers="$(cd "$PREFIX/opt" 2>/dev/null && ls 2>/dev/null | grep '^gryonixdom' || true)"

if [ -n "$legacy_units" ] || [ -n "$legacy_wrappers" ] || [ -d "$LEGACY_STATE_DIR" ] \
   || [ -d "$LEGACY_ETC_DIR" ] || [ -f "$LEGACY_SUDOERS" ]; then
  log "adopting the pre-rename installation (gryonixDom)"

  # Stop the old name's units FIRST, and the new collector with them: the merge
  # below rewrites bucket files, and a collector appending to one while it is
  # being sorted would either lose a sample or write a half-merged file. Every
  # `|| true` here is deliberate — a unit that is already gone, masked or was
  # never enabled is a normal state on a partially migrated host, not a fault.
  #
  # What was RUNNING is recorded before it is stopped, because that is the only
  # moment it can be: after `disable --now` the answer is gone. Migration
  # restores a host to the state it was in under a different name; it must not
  # start work of its own. See the re-arm block at the end for the live incident
  # that made this a recorded fact rather than a preference.
  legacy_active=""
  for unit in $legacy_units; do
    # `if`, never `cmd && assignment`: under `set -e` an AND-list whose last
    # command does not run is a failed statement, so the first unit that was
    # NOT active would end the bootstrap right here, mid-migration.
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      legacy_active="$legacy_active $unit"
    fi
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
  done
  metrics_was_running=0
  if systemctl is-active --quiet gryonixnexus-metrics.service 2>/dev/null; then
    metrics_was_running=1
    systemctl stop gryonixnexus-metrics.service >/dev/null 2>&1 || true
  fi

  # --- units. The agent's own predecessor is REMOVED, not adopted: this script
  # installs the current agent a few lines below, so adopting gryonixdomd.service
  # would mean writing a unit only to overwrite it. Everything else (the metrics
  # collector, the two schedule units) has no other installer in this code path,
  # so it is adopted or it stops existing.
  adopted_units=""
  for unit in $legacy_units; do
    new_unit="$(printf '%s' "$unit" | sed 's/^gryonixdom/gryonixnexus/')"
    case "$unit" in
      gryonixdomd.service)
        rm -f "$LEGACY_UNIT_DIR/$unit" "$PREFIX/usr/local/bin/gryonixdomd" "$PREFIX/run/gryonixdomd.sock"
        ;;
      *)
        if [ -f "$LEGACY_UNIT_DIR/$new_unit" ]; then
          rm -f "$LEGACY_UNIT_DIR/$unit"
        else
          log "adopting $unit as $new_unit"
          rename_into "$LEGACY_UNIT_DIR/$unit" "$LEGACY_UNIT_DIR/$new_unit"
          chmod 0644 "$LEGACY_UNIT_DIR/$new_unit"
          rm -f "$LEGACY_UNIT_DIR/$unit"
          adopted_units="$adopted_units $unit>$new_unit"
        fi
        ;;
    esac
  done

  # --- wrappers under /opt. Same rule, and the mode is carried over rather than
  # assumed: five of the six are 0750 and the collector is 0755, and a wrapper
  # that comes back readable by everyone would be a quiet downgrade.
  for wrapper in $legacy_wrappers; do
    new_wrapper="$(printf '%s' "$wrapper" | sed 's/^gryonixdom/gryonixnexus/')"
    if [ -f "$PREFIX/opt/$new_wrapper" ]; then
      rm -f "$PREFIX/opt/$wrapper"
    else
      log "adopting /opt/$wrapper as /opt/$new_wrapper"
      old_mode="$(stat -c '%a' "$PREFIX/opt/$wrapper" 2>/dev/null || stat -f '%Lp' "$PREFIX/opt/$wrapper")"
      rename_into "$PREFIX/opt/$wrapper" "$PREFIX/opt/$new_wrapper"
      chmod "$old_mode" "$PREFIX/opt/$new_wrapper"
      rm -f "$PREFIX/opt/$wrapper"
    fi
  done

  # --- the sudoers drop-in, the one file where a bad line costs the machine its
  # `sudo`. Validated with visudo BEFORE it is installed, and on any doubt the
  # old file is left exactly where it is: a host that keeps a stale-but-valid
  # whitelist still works, a host with a broken one cannot even be repaired
  # over the same channel that broke it.
  if [ -f "$LEGACY_SUDOERS" ]; then
    new_sudoers="$PREFIX/etc/sudoers.d/gryonixnexus-control"
    if [ -f "$new_sudoers" ]; then
      rm -f "$LEGACY_SUDOERS"
    else
      staged="$PREFIX/etc/sudoers.d/.gryonixnexus-control.staged"
      rename_into "$LEGACY_SUDOERS" "$staged"
      chmod 0440 "$staged"
      if visudo -cf "$staged" >/dev/null 2>&1; then
        log "adopting the sudoers whitelist"
        mv -f "$staged" "$new_sudoers"
        rm -f "$LEGACY_SUDOERS"
      else
        rm -f "$staged"
        log "the rewritten sudoers whitelist did not validate — leaving $LEGACY_SUDOERS in place"
      fi
    fi
  fi

  # --- state. The metrics buckets are MERGED rather than picked, because both
  # sides can hold real rows: the old collector wrote until this minute, and the
  # new one starts the moment a current install touches the host. A bucket the
  # collector has never seen has to come out looking exactly like one it wrote:
  # one row per epoch, oldest first. It trims each bucket to its retention on
  # the next tick, so a merged file that is momentarily too long corrects itself.
  #
  # `awk` first and `sort` second, rather than one `sort -u`: which of two rows
  # with the same epoch survives is UNSPECIFIED for `sort -u`, and the two
  # collectors overlap by exactly the seconds between the current install and
  # this run. Reading the new file first makes the CURRENT collector's sample
  # win that overlap, which is the one whose columns match the daemon now
  # running. Caught by the harness, which had both sides holding a row at the
  # same second and got the stale one.
  if [ -d "$LEGACY_STATE_DIR" ]; then
    if [ -d "$LEGACY_STATE_DIR/metrics" ]; then
      mkdir -p "$PRODUCT_STATE_DIR/metrics"
      chmod 0755 "$PRODUCT_STATE_DIR/metrics"
      for old_bucket in "$LEGACY_STATE_DIR/metrics"/*.csv; do
        [ -e "$old_bucket" ] || continue
        new_bucket="$PRODUCT_STATE_DIR/metrics/$(basename "$old_bucket")"
        if [ -f "$new_bucket" ]; then
          if cat "$new_bucket" "$old_bucket" | awk -F, '!seen[$1]++' | sort -t, -k1,1n \
               > "$new_bucket.merged" 2>/dev/null; then
            mv -f "$new_bucket.merged" "$new_bucket"
            chmod 0644 "$new_bucket"
          else
            rm -f "$new_bucket.merged"
            log "could not merge $(basename "$old_bucket") — keeping the current file"
          fi
        else
          mv -f "$old_bucket" "$new_bucket"
        fi
      done
      rm -f "$LEGACY_STATE_DIR/metrics"/*.csv
      rmdir "$LEGACY_STATE_DIR/metrics" 2>/dev/null || true
    fi

    # Everything else under the old state directory moves only into a gap. The
    # agent's own database is the one that matters: it holds the paired devices,
    # and a phone that has to pair again is a migration the owner FEELS. Where
    # both exist the new one wins and the old is left on disk, the same answer
    # the state.db block above gives for the same collision.
    #
    # Depth-first, because a collision between two DIRECTORIES is not a
    # collision: the state layout block above unconditionally creates `agent/`,
    # so comparing whole entries would find it occupied on every host alive and
    # adopt nobody's database — every migrated phone would have to pair again.
    # Caught by the harness; the first version of this loop did exactly that.
    adopt_into "$LEGACY_STATE_DIR" "$PRODUCT_STATE_DIR"
    quarantine "$LEGACY_STATE_DIR" var-lib
  fi

  # --- /etc, where the wrappers keep their schedules and backup passphrase.
  # Same rule, file by file rather than directory at a time: a host can easily
  # have a schedule under one name and a passphrase under the other.
  if [ -d "$LEGACY_ETC_DIR" ]; then
    adopt_into "$LEGACY_ETC_DIR" "$PREFIX/etc/gryonixnexus"
    quarantine "$LEGACY_ETC_DIR" etc
  fi

  systemctl daemon-reload >/dev/null 2>&1 || true

  # Re-arm ONLY what this run adopted, and start only what was already running.
  #
  # The first version enabled `--now` every unit whose new name existed, and the
  # live run on vps-middle showed what that costs: gryonixnexus-autobackup.service
  # is a `static` oneshot a TIMER drives, so `enable` is a no-op on it and
  # `--now` is the whole command — the migration ran a full backup of every
  # service on the host, and reported itself failed because one of them had
  # nothing to archive. A migration restores the state a host was already in.
  # It does not start work, and it does not touch what it did not move.
  #
  # `enable` is still unconditional for what WAS adopted: a unit enabled under
  # the old name has to survive a reboot under the new one, and a host that
  # quietly stops collecting after its next reboot is the failure nobody
  # notices for a week.
  for pair in $adopted_units; do
    old_unit="${pair%%>*}"
    new_unit="${pair##*>}"
    systemctl enable "$new_unit" >/dev/null 2>&1 || true
    case " $legacy_active " in
      *" $old_unit "*) systemctl start "$new_unit" >/dev/null 2>&1 || true ;;
    esac
  done
  if [ "$metrics_was_running" = "1" ]; then
    systemctl start gryonixnexus-metrics.service >/dev/null 2>&1 || true
  fi
fi

# Ask the installed binary what it is. Anything unexpected (missing, corrupt,
# a build too old to know the subcommand) reads as "not current" and rebuilds —
# the failure mode of guessing wrong here is a silent no-op upgrade.
installed_version() {
  [ -x "$BIN_DEST" ] || return 0
  "$BIN_DEST" version 2>/dev/null | awk '/^gryonixnexusd /{print $2; exit}' || true
}

CURRENT="$(installed_version)"
if [ "$CURRENT" = "$VERSION" ] && [ -z "${GRYONIXNEXUSD_FORCE_BUILD:-}" ]; then
  log "gryonixnexusd $VERSION already installed"
  NEEDS_BUILD=0
else
  log "installed version is ${CURRENT:-none}, want $VERSION"
  NEEDS_BUILD=1
fi

# Build in a throwaway toolchain container: every target host runs docker (the
# whole catalog is docker-only), and this keeps a compiler, protoc and a crate
# registry off the server itself. The native path below is the fallback for a
# host that has cargo but no docker.
#
# The mount is the Agent/ ROOT, not the crate: build.rs compiles ../proto, so a
# crate-only mount fails at the proto path with nothing to explain it.
# The exact command line the toolchain container runs. Emitted by a function
# rather than inlined so the harness can execute the real string against stubbed
# apk/cargo — the interesting failures live INSIDE this string, where a stubbed
# `docker run` can never reach them.
#
# build-base: rusqlite is bundled, so a C compiler is required.
# protoc: prost-build shells out to it; there is no vendored copy.
# --locked: the committed Cargo.lock is the pin, an install must not resolve a
# different dependency graph than the one the tests ran against.
#
# apk's output is kept out of the way on success and PRINTED on failure. It used
# to be dropped unconditionally (`>/dev/null 2>&1 &&`), which meant a toolchain
# install that failed produced not one word and the script still said "see the
# output above" — there was nothing above. Found live on 2026-08-06: the host's
# firewall blocked container egress, apk could not reach any mirror, and the
# only symptom was a bootstrap that stopped. Same lesson as the mailcow API and
# nextcloud occ calls: the body of the error IS the explanation.
container_build_command() {
  cat <<'CMD'
if ! apk add --no-cache build-base protoc protobuf-dev >/tmp/apk.log 2>&1; then
  echo "installing the build toolchain in the container failed:" >&2
  cat /tmp/apk.log >&2
  exit 1
fi
cargo build --release --locked
CMD
}

build_in_docker() {
  local pulled=0 status=0
  if ! docker image inspect "$RUST_IMAGE" >/dev/null 2>&1; then
    log "pulling $RUST_IMAGE (build toolchain, removed afterwards)"
    docker pull -q "$RUST_IMAGE" >/dev/null || return 1
    pulled=1
  fi
  log "building gryonixnexusd $VERSION from source ($ARCH, in $RUST_IMAGE)"
  docker run --rm -v "$AGENT_DIR":/src -w /src/gryonixnexusd "$RUST_IMAGE" \
    sh -c "$(container_build_command)" || status=1
  # A ~700 MB toolchain image is a real cost on a Pi, and nothing needs it once
  # the binary exists. Only remove what this run pulled, and remove it on the
  # failing path too — a broken build must not leave the disk full as well.
  if [ "$pulled" = 1 ] && [ -z "${GRYONIXNEXUSD_KEEP_BUILD_IMAGE:-}" ]; then
    docker image rm "$RUST_IMAGE" >/dev/null 2>&1 || true
  fi
  return "$status"
}

build_natively() {
  command -v protoc >/dev/null 2>&1 ||
    fail "cargo is present but protoc is not — prost-build needs it (apt-get install -y protobuf-compiler)"
  log "building gryonixnexusd $VERSION from source ($ARCH, host toolchain)"
  ( cd "$CRATE_DIR" && cargo build --release --locked )
}

# A BARE host has no docker, and the container build is the only path most
# hosts have — so this script installs it rather than refusing. That is not
# scope creep: docker is a hard requirement of the product (the whole catalog is
# docker-only), this script already runs as root outside any sandbox, and the
# alternative is telling the operator to run one command by hand before the
# script that exists to spare them exactly that. Found the obvious way, on a
# genuinely empty VM: the agent could install docker for its SERVICES
# (install/packages.rs) but could not be installed itself without it.
install_docker() {
  command -v curl >/dev/null 2>&1 || {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null 2>&1 || true
    apt-get install -y curl >/dev/null 2>&1 || true
  }
  command -v curl >/dev/null 2>&1 || return 1
  log "docker is not installed — installing it (needed to build the agent)"
  curl -fsSL https://get.docker.com | sh || return 1
  systemctl enable --now docker >/dev/null 2>&1 || true
  command -v docker >/dev/null 2>&1
}

if [ "$NEEDS_BUILD" = 1 ]; then
  if ! command -v docker >/dev/null 2>&1 && ! command -v cargo >/dev/null 2>&1; then
    install_docker || fail "no way to build the agent: installing docker failed, and this host has no Rust toolchain either"
  fi
  if command -v docker >/dev/null 2>&1; then
    build_in_docker || fail "the container build failed — see the output above"
  elif command -v cargo >/dev/null 2>&1; then
    build_natively
  else
    fail "no way to build the agent: install docker (preferred) or a Rust toolchain with protoc"
  fi
  ARTIFACT="$CRATE_DIR/target/release/gryonixnexusd"
  [ -x "$ARTIFACT" ] || fail "the build produced no binary at $ARTIFACT"

  # Stop before replacing: writing over the file of a running process fails with
  # "Text file busy", and a half-installed agent is worse than a stopped one.
  systemctl stop gryonixnexusd.service >/dev/null 2>&1 || true
  install -d -m 0755 "$(dirname "$BIN_DEST")"
  install -m 0755 "$ARTIFACT" "$BIN_DEST"
fi

# The unit is installed on every run, not just after a build: it is the one
# piece a host can drift on (hand edits, a partial older install) and rewriting
# it costs nothing.
install -d -m 0755 "$(dirname "$UNIT_DEST")"
install -m 0644 "$UNIT_SRC" "$UNIT_DEST"

systemctl daemon-reload
systemctl enable --now gryonixnexusd.service
# `enable --now` starts a stopped unit but leaves a running one alone — after a
# rebuild that would keep the OLD binary serving until the next reboot.
if [ "$NEEDS_BUILD" = 1 ]; then
  systemctl restart gryonixnexusd.service
fi

# Verify rather than assume: `enable --now` succeeds on a unit whose binary dies
# immediately, and the app's only entry point is the socket. Bounded wait — the
# agent opens it right after start, so anything slower is a real failure.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  systemctl is-active --quiet gryonixnexusd.service && [ -S "$PREFIX/run/gryonixnexusd.sock" ] && break
  sleep 1
done
systemctl is-active --quiet gryonixnexusd.service ||
  fail "gryonixnexusd.service did not stay up — journalctl -u gryonixnexusd.service"
[ -S "$PREFIX/run/gryonixnexusd.sock" ] || fail "gryonixnexusd is running but never opened its socket"

FINAL="$(installed_version)"
[ "$FINAL" = "$VERSION" ] ||
  fail "installed binary reports '${FINAL:-nothing}', expected $VERSION"
log "gryonixnexusd $VERSION installed and started"
