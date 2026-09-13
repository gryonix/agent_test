//! Port of `MetricsHistorySections` — `/opt/gryonixnexus-metrics-collector.sh`
//! and its `gryonixnexus-metrics.service` unit.
//!
//! See `install/host/mod.rs` for the three rules that apply to everything in
//! this module. Like `lockdown.rs`, this wrapper carries NO per-host content
//! — no service list, no hostnames, no `ssh_user` — which is exactly what
//! `tests/fixtures/install/host/README.md` measures ("1 distinct body" across
//! all 97 generated variants): every host samples the same `/proc` sources
//! and keeps the same six downsampled buckets, regardless of which services
//! are installed on it. [`collector_script`] and [`unit`] therefore take no
//! [`super::HostInput`], the same reasoning `lockdown.rs`'s doc gives for its
//! own `render()`.
//!
//! **What the daemon encodes, and why it is pinned as data, not prose.** The
//! six buckets in [`BUCKETS`] are the one fact this whole file exists to get
//! right — ARCHITECTURE.md records that buckets no `HistoryRange` can select
//! were rolled up on every ten-second tick and then read by nothing, on hosts
//! as small as a Pi, and states the invariant that came out of it: every
//! bucket here must be reachable from some range the app offers. (Which spans
//! were the unreachable ones is not written down anywhere this port could
//! check, so it is not claimed here.) `BUCKETS` is declared independently of the literal
//! script text below and cross-checked against it by
//! [`every_bucket_appears_with_its_period_and_retention`] — the central trap
//! this slice was warned about (`README.md`'s last paragraph) is a port that
//! hardcodes the script text and calls that coverage; a corrupted bucket
//! period in the SCRIPT would still pass a test that only re-reads
//! substrings of that same script. See the porting report for the negative
//! control that proves this actually catches a planted defect.
//!
//! **The daemon degrades, it does not block.** Every sampler function ends in
//! `|| true` or an `awk` that falls through to an empty field on a `/proc`
//! source that does not exist (no thermal zone, a VPS with no `/proc/diskstats`
//! entry matching the device regex) — this is the same "never fatal, never
//! glossed over" discipline GOTCHAS.md records for the mailcow/`occ` engines,
//! applied to a daemon that runs forever under `Restart=always`: one sampler
//! throwing under `set -euo pipefail` would kill collection for the rest of
//! the host's life until someone notices the gap in the app's history graphs.

/// Where the collector script lives on disk.
pub const COLLECTOR_PATH: &str = "/opt/gryonixnexus-metrics-collector.sh";
/// Where its unit lives — `install/host` writes units directly under
/// `/etc/systemd/system`, matching every other timer/service this crate
/// installs (`backup_ctl::TIMER_NAME`, `update_ctl`'s own unit).
pub const UNIT_PATH: &str = "/etc/systemd/system/gryonixnexus-metrics.service";
/// The systemd unit NAME (`systemctl enable/disable/restart` argument,
/// without `.service`) — what `uninstall.rs`'s own `uninstall_all` already
/// stops by this literal name, spelled out here so the two cannot drift
/// silently if this module is ever wired into that removal path.
pub const UNIT_NAME: &str = "gryonixnexus-metrics";
/// Directory the collector writes its CSV buckets into. Duplicated in Swift
/// across `MetricsHistorySections` and `ServerControl/Commands/CommandCatalog`
/// deliberately (that module's own doc: the two do not depend on each
/// other) — this is the Rust side of the same duplicated literal, not a new
/// one.
pub const DATA_DIRECTORY: &str = "/var/lib/gryonixnexus/metrics";
/// Sampling interval in seconds — the collector's own `STEP` variable and the
/// unit the finest bucket, `10s`, on.
pub const STEP_SECONDS: u32 = 10;

/// Bucket name → (seconds per point, rows kept). Declared independently of
/// [`collector_script`]'s literal text — see this module's doc for why that
/// separation is the point, not an accident. Mirrors
/// `MetricsHistorySections.buckets` field for field, including the comment
/// about the two buckets ("10h", "1mo") that used to exist and were removed
/// for being unreachable by any `HistoryRange`.
pub const BUCKETS: &[(&str, u32, u32)] = &[
    ("10s", 10, 720),        // 2 hours
    ("1m", 60, 720),         // 12 hours
    ("10m", 600, 432),       // 3 days
    ("1h", 3_600, 336),      // 2 weeks
    ("1d", 86_400, 400),     // ~13 months
    ("1w", 604_800, 260),    // 5 years
];

/// The 12 CSV columns every row (raw or aggregated) carries, in order — the
/// collector's own header comment and `HostMetricsParser`'s field order on
/// the Swift side must agree on this, which is why it is spelled out here
/// rather than left implicit in the literal script text below.
pub const COLUMNS: &[&str] = &[
    "epoch", "cpu%", "memUsed", "memTotal", "diskUsed", "diskTotal", "netRx/s", "netTx/s", "ioRead/s", "ioWrite/s",
    "load1", "tempC",
];

/// The daemon itself — byte-identical to
/// `tests/fixtures/install/host/metrics/*.txt`, a heredoc BODY lifted out of
/// a real generated setup script (see that directory's `README.md`), not a
/// transcription of `MetricsHistorySections.swift`. Takes no
/// [`super::HostInput`]: see this module's doc for why there is nothing here
/// for one to supply.
pub fn collector_script() -> String {
    r#"#!/usr/bin/env bash
# Managed by gryonixNexus — samples host metrics every 10 seconds and keeps
# downsampled history buckets as CSV files under /var/lib/gryonixnexus/metrics.
# Columns: epoch,cpu%,memUsed,memTotal,diskUsed,diskTotal,netRx/s,netTx/s,
# ioRead/s,ioWrite/s,load1,tempC. Empty field = no data for that sample.
set -euo pipefail

DIR=/var/lib/gryonixnexus/metrics
STEP=10
install -d -m 755 /var/lib/gryonixnexus "$DIR"

cpu_ticks() { awk '$1=="cpu"{t=0; for(i=2;i<=9;i++) t+=$i; print t, $5+$6; exit}' /proc/stat; }
mem_bytes() { awk '/^MemTotal:/{t=$2*1024} /^MemAvailable:/{a=$2*1024} END{print t-a, t}' /proc/meminfo; }
disk_bytes() {
  { df -B1 --output=target,size,used -x tmpfs -x devtmpfs -x overlay 2>/dev/null || true; } \
    | awk 'NR>1 { if ($1=="/") {s=$2; u=$3; f=1} else if (!f && $2+0>s+0) {s=$2; u=$3} } END{print u+0, s+0}'
}
net_bytes() {
  awk -F: 'NF==2 {name=$1; gsub(/[ \t]/,"",name); if (name=="lo") next;
                  split($2,a," "); rx+=a[1]; tx+=a[9]} END{print rx+0, tx+0}' /proc/net/dev
}
io_bytes() {
  awk '$3 ~ /^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)$/ \
         {r+=$6*512; w+=$10*512} END{print r+0, w+0}' /proc/diskstats
}
load_one() { awk '{print $1}' /proc/loadavg; }
temp_c() {
  { cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null || true; } \
    | awk '$1>0 && $1<150000 { if ($1>m) m=$1 } END{ if (m>0) printf "%.1f", m/1000 }'
}
rate() { awk -v c="$1" -v p="$2" -v s="$STEP" 'BEGIN{d=c-p; if (d<0) d=0; printf "%d", d/s}'; }

# Keep only the newest <max> rows of <file>.
trim() {
  local file=$1 max=$2 lines tmp
  [ -f "$file" ] || return 0
  lines=$(wc -l < "$file")
  if [ "$lines" -gt "$max" ]; then
    tmp=$(mktemp "$DIR/.trim.XXXXXX")
    tail -n "$max" "$file" > "$tmp"
    mv "$tmp" "$file"
    chmod 644 "$file"
  fi
}

# Average the source rows inside the just-closed <period> window and
# append one row to <target>. No-op while the window is still open, when
# it was already written, or when the source has no rows in it (gap).
aggregate() {
  local target=$1 source=$2 period=$3 keep=$4 now start last row
  [ -f "$source" ] || return 0
  now=$(date +%s)
  start=$(( now / period * period - period ))
  last=-1
  if [ -f "$target" ]; then
    last=$(tail -n 1 "$target" | cut -d, -f1)
    case "$last" in ''|*[!0-9]*) last=-1 ;; esac
  fi
  [ "$last" -lt "$start" ] || return 0
  row=$(awk -F, -v s="$start" -v e=$(( start + period )) '
    $1>=s && $1<e {
      n++
      if ($2!="") {c+=$2; cn++}
      mu+=$3; mt=$4; du+=$5; dt=$6
      if ($7!="") {rx+=$7; rxn++}
      if ($8!="") {tx+=$8; txn++}
      if ($9!="") {ir+=$9; irn++}
      if ($10!="") {iw+=$10; iwn++}
      l+=$11
      if ($12!="") {tp+=$12; tn++}
    }
    END {
      if (!n) exit 0
      printf "%d,", s
      if (cn) printf "%.1f", c/cn
      printf ",%d,%d,%d,%d,", mu/n, mt, du/n, dt
      if (rxn) printf "%d", rx/rxn
      printf ","
      if (txn) printf "%d", tx/txn
      printf ","
      if (irn) printf "%d", ir/irn
      printf ","
      if (iwn) printf "%d", iw/iwn
      printf ",%.2f,", l/n
      if (tn) printf "%.1f", tp/tn
      printf "\n"
    }' "$source")
  [ -n "$row" ] || return 0
  printf '%s\n' "$row" >> "$target"
  chmod 644 "$target"
  trim "$target" "$keep"
}

prev_total=0 prev_idle=0 prev_rx=0 prev_tx=0 prev_ir=0 prev_iw=0 have_prev=0

while :; do
  now=$(date +%s)
  read -r total idle < <(cpu_ticks)
  read -r mem_used mem_total < <(mem_bytes)
  read -r disk_used disk_total < <(disk_bytes)
  read -r rx tx < <(net_bytes)
  read -r io_r io_w < <(io_bytes)
  load=$(load_one)
  temp=$(temp_c)

  cpu="" rx_rate="" tx_rate="" ir_rate="" iw_rate=""
  if [ "$have_prev" -eq 1 ]; then
    cpu=$(awk -v t=$((total - prev_total)) -v i=$((idle - prev_idle)) \
      'BEGIN{ if (t>0) { p=(t-i)*100/t; if (p<0) p=0; if (p>100) p=100; printf "%.1f", p } }')
    rx_rate=$(rate "$rx" "$prev_rx")
    tx_rate=$(rate "$tx" "$prev_tx")
    ir_rate=$(rate "$io_r" "$prev_ir")
    iw_rate=$(rate "$io_w" "$prev_iw")
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$now" "$cpu" "$mem_used" "$mem_total" "$disk_used" "$disk_total" \
    "$rx_rate" "$tx_rate" "$ir_rate" "$iw_rate" "$load" "$temp" >> "$DIR/10s.csv"
  chmod 644 "$DIR/10s.csv"
  trim "$DIR/10s.csv" 720

  aggregate "$DIR/1m.csv"  "$DIR/10s.csv" 60      720
  aggregate "$DIR/10m.csv" "$DIR/1m.csv"  600     432
  aggregate "$DIR/1h.csv"  "$DIR/10m.csv" 3600    336
  aggregate "$DIR/1d.csv"  "$DIR/1h.csv"  86400   400
  aggregate "$DIR/1w.csv"  "$DIR/1d.csv"  604800  260

  prev_total=$total prev_idle=$idle prev_rx=$rx prev_tx=$tx prev_ir=$io_r prev_iw=$io_w
  have_prev=1
  sleep "$STEP"
done"#
        .to_string()
}

/// The unit `UNIT_PATH` installs — byte-identical to
/// `tests/fixtures/install/host/metrics_unit/*.txt`. `Restart=always` is what
/// makes the daemon a permanent fixture of the host (the same reason
/// `uninstall.rs`'s `agent_removal` has to stop the agent's OWN unit before
/// deleting its state directory); `Nice=10`/`IOSchedulingClass=idle` keep a
/// sampler that runs forever from ever competing with the services it is
/// measuring.
pub fn unit() -> String {
    "[Unit]\nDescription=gryonixNexus metrics history collector\nAfter=local-fs.target\n\n[Service]\nExecStart=/opt/gryonixnexus-metrics-collector.sh\nRestart=always\nRestartSec=5\nNice=10\nIOSchedulingClass=idle\n\n[Install]\nWantedBy=multi-user.target"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(dir: &str, name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/host/{dir}/{name}.txt", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    /// Byte-for-byte parity against a real generated script. The one fixture
    /// under `metrics/` stands for all 97 script variants — `README.md`
    /// documents that this wrapper's body is the SAME across every one of
    /// them.
    #[test]
    fn collector_fixture_parity() {
        let expected = fixture("metrics", "A-adguard-access-en");
        assert_eq!(collector_script(), expected.trim_end_matches('\n'));
    }

    #[test]
    fn unit_fixture_parity() {
        let expected = fixture("metrics_unit", "A-adguard-access-en");
        assert_eq!(unit(), expected.trim_end_matches('\n'));
    }

    /// The central trap this slice was warned about: `collector_fixture_parity`
    /// alone would pass even if [`BUCKETS`] and the script text disagreed,
    /// because both a hardcoded blob and its "coverage" would be reading the
    /// same wrong string. This check derives its expectation from `BUCKETS`
    /// — declared separately, above — and only THEN looks for it inside the
    /// rendered script, so the two can genuinely disagree. See the porting
    /// report for the negative control that proves it.
    #[test]
    fn every_bucket_appears_with_its_period_and_retention() {
        let script = collector_script();
        // The raw 10s bucket is written directly (`$DIR/10s.csv`, `STEP=10`,
        // `trim … 720`), not through an `aggregate` call — the other five are
        // each one `aggregate` line naming the finer source bucket.
        let (name, period, keep) = BUCKETS[0];
        assert_eq!(name, "10s");
        assert_eq!(period, STEP_SECONDS);
        assert!(script.contains(&format!("trim \"$DIR/{name}.csv\" {keep}")));

        let sources = ["10s", "1m", "10m", "1h", "1d"];
        for (i, (name, period, keep)) in BUCKETS.iter().enumerate().skip(1) {
            let source = sources[i - 1];
            let line = format!("aggregate \"$DIR/{name}.csv\"");
            assert!(script.contains(&line), "no aggregate call writes {name}.csv:\n{script}");
            // Same aggregate call, further checked for the source it reads
            // and the exact period/retention BUCKETS claims for it — not
            // just that a call for this bucket name exists somewhere.
            let call_start = script.find(&line).unwrap();
            let call_line = script[call_start..].lines().next().unwrap();
            assert!(
                call_line.contains(&format!("\"$DIR/{source}.csv\"")),
                "{name}'s aggregate call does not read from {source}.csv: {call_line}"
            );
            assert!(
                call_line.contains(&period.to_string()),
                "{name}'s aggregate call is missing its period {period}: {call_line}"
            );
            assert!(
                call_line.contains(&keep.to_string()),
                "{name}'s aggregate call is missing its retention {keep}: {call_line}"
            );
        }
    }

    /// Exactly six buckets — a seventh silently added (or one of the two
    /// historical unreachable buckets silently restored) would not be caught
    /// by the loop above, which only checks that each of `BUCKETS`' entries
    /// is present, not that nothing extra is.
    #[test]
    fn there_are_exactly_six_buckets() {
        assert_eq!(BUCKETS.len(), 6);
        let script = collector_script();
        assert_eq!(script.matches("aggregate \"$DIR/").count(), 5, "expected 5 aggregate calls (6 buckets minus the raw one)");
    }

    /// The 12-column CSV header comment and the `printf` that actually writes
    /// a raw row must agree on the column count — declared once as
    /// [`COLUMNS`] and checked against the literal `printf` format string
    /// rather than assumed from the header comment alone (a stale comment
    /// would not be caught by `collector_fixture_parity` if BOTH texts
    /// happened to be equally stale).
    #[test]
    fn the_column_count_matches_the_raw_row_printf() {
        assert_eq!(COLUMNS.len(), 12);
        let script = collector_script();
        let placeholders = "%s,".repeat(COLUMNS.len() - 1) + "%s\\n";
        assert!(
            script.contains(&format!("printf '{placeholders}' \\\n")),
            "raw-row printf does not have {} fields:\n{script}",
            COLUMNS.len()
        );
    }

    /// The daemon is a permanent, low-priority fixture of the host, not a
    /// one-shot — `Restart=always` is what makes a crash self-heal instead
    /// of silently ending metrics collection until someone notices a gap in
    /// the app's history graphs.
    #[test]
    fn the_unit_restarts_forever_at_low_priority() {
        let u = unit();
        assert!(u.contains("Restart=always"));
        assert!(u.contains(&format!("ExecStart={COLLECTOR_PATH}")));
        assert!(u.contains("Nice=10"));
        assert!(u.contains("IOSchedulingClass=idle"));
    }

    /// The unit's `ExecStart` must name the SAME path this module installs
    /// the script at — checked against `COLLECTOR_PATH`, not a second
    /// hand-typed literal, so the two cannot drift from each other silently.
    #[test]
    fn unit_execstart_matches_the_collector_path() {
        assert!(unit().contains(&format!("ExecStart={COLLECTOR_PATH}\n")));
    }

    /// The data directory the collector writes into, checked against
    /// `DATA_DIRECTORY` rather than only appearing inside the larger
    /// fixture-parity comparison — this is the path `AgentClient`'s history
    /// RPCs and every SSH-path reader of these buckets both depend on.
    #[test]
    fn the_collector_writes_under_the_declared_data_directory() {
        assert!(collector_script().contains(&format!("DIR={DATA_DIRECTORY}\n")));
    }
}
