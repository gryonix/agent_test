//! Host metrics sampled from /proc, mirroring the Swift engine's
//! HostMetricsSample so the app's existing cards render an agent-sourced stream
//! unchanged. The parsers are pure and unit-tested against fixture text; the
//! file reads degrade to zero/absent on a non-Linux dev box, so the crate still
//! builds and tests everywhere.
//!
//! CPU% needs two readings: the `Sampler` seeds a baseline at construction and
//! every subsequent sample() diffs against the previous one, so each emitted
//! sample carries a valid utilisation figure rather than a meaningless first
//! reading against zero.

use std::collections::HashSet;

use crate::pb;
use crate::util::now_millis;

/// Cumulative CPU jiffies from /proc/stat's aggregate `cpu` line.
#[derive(Clone, Copy, Default)]
pub struct CpuTimes {
    pub total: u64,
    pub idle: u64,
}

/// The aggregate `cpu` line: `cpu user nice system idle iowait irq softirq
/// steal …`. idle-all is idle + iowait (the CPU is doing no useful work in
/// either), everything summed is the total.
pub fn parse_stat_cpu(stat: &str) -> Option<CpuTimes> {
    let line = stat.lines().next()?;
    let mut fields = line.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let vals: Vec<u64> = fields.filter_map(|t| t.parse().ok()).collect();
    if vals.len() < 4 {
        return None;
    }
    let idle = vals[3] + vals.get(4).copied().unwrap_or(0);
    let total: u64 = vals.iter().sum();
    Some(CpuTimes { total, idle })
}

/// Busy fraction over the interval between two cumulative readings, as a
/// percentage. A zero (or backwards) delta reads as 0 rather than dividing by
/// zero.
pub fn cpu_percent(prev: CpuTimes, cur: CpuTimes) -> f64 {
    let total = cur.total.saturating_sub(prev.total);
    if total == 0 {
        return 0.0;
    }
    let idle = cur.idle.saturating_sub(prev.idle);
    let busy = total.saturating_sub(idle);
    (100.0 * busy as f64 / total as f64).clamp(0.0, 100.0)
}

/// Physical/logical core count = the number of per-core `cpuN` lines.
pub fn count_cpu_cores(stat: &str) -> u32 {
    stat.lines()
        .filter(|l| l.starts_with("cpu") && l.as_bytes().get(3).is_some_and(u8::is_ascii_digit))
        .count() as u32
}

pub struct MemInfo {
    pub total: i64,
    pub used: i64,
    pub swap_total: i64,
    pub swap_used: i64,
}

/// /proc/meminfo reports kB; we return bytes. "Used" is total minus available
/// (available, not free — free ignores reclaimable cache and wildly overstates
/// pressure). Swap used is total minus free.
pub fn parse_meminfo(text: &str) -> MemInfo {
    let kb = |key: &str| -> i64 {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix(key) {
                let rest = rest.trim_start_matches(':').trim();
                if let Some(num) = rest.split_whitespace().next() {
                    return num.parse().unwrap_or(0);
                }
            }
        }
        0
    };
    let total = kb("MemTotal");
    let available = kb("MemAvailable");
    let swap_total = kb("SwapTotal");
    let swap_free = kb("SwapFree");
    MemInfo {
        total: total * 1024,
        used: (total - available).max(0) * 1024,
        swap_total: swap_total * 1024,
        swap_used: (swap_total - swap_free).max(0) * 1024,
    }
}

/// /proc/loadavg: `load1 load5 load15 running/total lastpid`.
pub fn parse_loadavg(text: &str) -> (f64, f64, f64) {
    let mut it = text.split_whitespace();
    let one = it.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let five = it.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let fifteen = it.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    (one, five, fifteen)
}

/// /proc/uptime: `uptime_seconds idle_seconds`; we want the first.
pub fn parse_uptime(text: &str) -> f64 {
    text.split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0)
}

/// Sum received/transmitted bytes across interfaces from /proc/net/dev, minus
/// loopback. Columns after the `iface:` label are rx: bytes packets … (16
/// fields); byte totals are column 0 (rx) and column 8 (tx).
pub fn parse_net_dev(text: &str) -> (i64, i64) {
    let mut rx = 0i64;
    let mut tx = 0i64;
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name.trim() == "lo" {
            continue;
        }
        let cols: Vec<i64> = rest.split_whitespace().filter_map(|t| t.parse().ok()).collect();
        if cols.len() >= 9 {
            rx += cols[0];
            tx += cols[8];
        }
    }
    (rx, tx)
}

/// Sum sectors read/written (×512 → bytes) from /proc/diskstats, counting ONLY
/// whole disks (`disks`), never their partitions — otherwise a disk and each of
/// its partitions would be added together and the figure would multiply. Fields
/// are `major minor name reads readsMerged sectorsRead … sectorsWritten …`;
/// sectors read is field 5, sectors written field 9 (0-indexed).
pub fn parse_diskstats(text: &str, disks: &HashSet<String>) -> (i64, i64) {
    let mut read = 0i64;
    let mut written = 0i64;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || !disks.contains(f[2]) {
            continue;
        }
        read += f[5].parse::<i64>().unwrap_or(0) * 512;
        written += f[9].parse::<i64>().unwrap_or(0) * 512;
    }
    (read, written)
}

/// /sys/class/thermal/<zone>/temp reports milli-degrees Celsius.
pub fn parse_temp(millidegrees: &str) -> Option<f64> {
    millidegrees.trim().parse::<f64>().ok().map(|m| m / 1000.0)
}

/// Samples the host once per call, carrying the previous CPU reading so each
/// sample reports utilisation over the gap since the last one.
pub struct Sampler {
    prev_cpu: CpuTimes,
}

impl Sampler {
    /// Seed the CPU baseline now, so the first sample() a tick later has a real
    /// interval to diff against.
    pub fn new() -> Self {
        Self {
            prev_cpu: parse_stat_cpu(&read("/proc/stat")).unwrap_or_default(),
        }
    }

    pub fn sample(&mut self) -> pb::MetricsSample {
        let stat = read("/proc/stat");
        let cur_cpu = parse_stat_cpu(&stat).unwrap_or_default();
        let cpu_percent = cpu_percent(self.prev_cpu, cur_cpu);
        self.prev_cpu = cur_cpu;

        let mem = parse_meminfo(&read("/proc/meminfo"));
        let (load1, load5, load15) = parse_loadavg(&read("/proc/loadavg"));
        let (net_received_bytes, net_sent_bytes) = parse_net_dev(&read("/proc/net/dev"));
        let (disk_read_bytes, disk_written_bytes) =
            parse_diskstats(&read("/proc/diskstats"), &whole_disks());

        pb::MetricsSample {
            sampled_at: now_millis(),
            cpu_cores: count_cpu_cores(&stat),
            cpu_percent,
            mem_total_bytes: mem.total,
            mem_used_bytes: mem.used,
            swap_total_bytes: mem.swap_total,
            swap_used_bytes: mem.swap_used,
            uptime_seconds: parse_uptime(&read("/proc/uptime")),
            load1,
            load5,
            load15,
            net_received_bytes,
            net_sent_bytes,
            disk_read_bytes,
            disk_written_bytes,
            mounts: read_mounts(),
            temperature_celsius: read_temp(),
        }
    }
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Whole block devices from /sys/block, minus the virtual ones (loop, ram,
/// device-mapper) that either aren't real I/O or would double-count their
/// backing disk. Used to keep partitions out of the diskstats sum.
fn whole_disks() -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(entries) = std::fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") {
                continue;
            }
            set.insert(name);
        }
    }
    set
}

fn read_temp() -> Option<f64> {
    parse_temp(&read("/sys/class/thermal/thermal_zone0/temp")).filter(|t| *t > 0.0)
}

/// Real filesystem mount points from /proc/mounts: those backed by an actual
/// block device (`/dev/…`), which excludes tmpfs/overlay/proc/sys and the other
/// pseudo filesystems. Deduplicated by SOURCE DEVICE — a device bind-mounted at
/// several points (systemd sandboxing, `ProtectSystem=`, re-exports /etc, /usr,
/// /boot off the root device) must report ONCE, not once per bind — and the
/// shortest target is kept, so the root device shows as "/" rather than "/etc".
fn parse_mounts(proc_mounts: &str) -> Vec<String> {
    // (source device, chosen target) in first-seen device order.
    let mut by_device: Vec<(String, String)> = Vec::new();
    for line in proc_mounts.lines() {
        let mut fields = line.split_whitespace();
        let (Some(source), Some(target)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !source.starts_with("/dev/") {
            continue;
        }
        match by_device.iter_mut().find(|(dev, _)| dev == source) {
            Some((_, chosen)) if target.len() < chosen.len() => *chosen = target.to_string(),
            Some(_) => {}
            None => by_device.push((source.to_string(), target.to_string())),
        }
    }
    by_device.into_iter().map(|(_, target)| target).collect()
}

fn read_mounts() -> Vec<pb::DiskMount> {
    parse_mounts(&read("/proc/mounts"))
        .into_iter()
        .filter_map(|target| {
            statvfs_usage(&target).map(|(size, used)| pb::DiskMount {
                target,
                size_bytes: size,
                used_bytes: used,
            })
        })
        .collect()
}

/// size/used bytes for a mount via statvfs(3). There is no /proc equivalent, so
/// this is the agent's one FFI call. `None` when the path can't be stat'd.
pub(crate) fn statvfs_usage(path: &str) -> Option<(i64, i64)> {
    let cpath = std::ffi::CString::new(path).ok()?;
    // SAFETY: statvfs writes into a caller-owned struct. A zeroed statvfs is a
    // valid starting state, the path is a valid NUL-terminated C string, and the
    // fields are read only after the return code confirms success.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(cpath.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let frsize = stat.f_frsize as i64;
    let size = stat.f_blocks as i64 * frsize;
    let used = (stat.f_blocks as i64 - stat.f_bfree as i64) * frsize;
    Some((size, used.max(0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str = "cpu  100 0 50 800 50 0 0 0 0 0
cpu0 50 0 25 400 25 0 0 0 0 0
cpu1 50 0 25 400 25 0 0 0 0 0
intr 12345";

    #[test]
    fn cpu_times_and_cores() {
        let cur = parse_stat_cpu(STAT).unwrap();
        assert_eq!(cur.total, 1000);
        assert_eq!(cur.idle, 850); // idle 800 + iowait 50
        assert_eq!(count_cpu_cores(STAT), 2);
    }

    #[test]
    fn cpu_percent_over_interval() {
        let prev = CpuTimes { total: 1000, idle: 850 };
        // 200 more jiffies, 100 of them idle → 50% busy.
        let cur = CpuTimes { total: 1200, idle: 950 };
        assert!((cpu_percent(prev, cur) - 50.0).abs() < 1e-9);
    }

    #[test]
    fn cpu_percent_zero_delta_is_zero_not_nan() {
        let same = CpuTimes { total: 1000, idle: 850 };
        assert_eq!(cpu_percent(same, same), 0.0);
    }

    #[test]
    fn meminfo_uses_available_not_free() {
        let text = "MemTotal:       16384 kB
MemFree:         1024 kB
MemAvailable:    8192 kB
SwapTotal:       2048 kB
SwapFree:        2048 kB";
        let mem = parse_meminfo(text);
        assert_eq!(mem.total, 16384 * 1024);
        assert_eq!(mem.used, (16384 - 8192) * 1024);
        assert_eq!(mem.swap_total, 2048 * 1024);
        assert_eq!(mem.swap_used, 0);
    }

    #[test]
    fn loadavg_and_uptime() {
        assert_eq!(parse_loadavg("0.15 0.25 0.35 1/234 5678"), (0.15, 0.25, 0.35));
        assert_eq!(parse_uptime("12345.67 89012.34"), 12345.67);
    }

    #[test]
    fn net_dev_sums_and_skips_loopback() {
        let text = "Inter-|   Receive                    |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets
    lo:  500       5    0    0    0     0          0         0     500       5
  eth0: 1000      10    0    0    0     0          0         0    2000      20";
        assert_eq!(parse_net_dev(text), (1000, 2000));
    }

    #[test]
    fn diskstats_counts_whole_disks_only() {
        let text = "   8       0 sda 100 0 200 0 50 0 400 0 0 0 0
   8       1 sda1 90 0 180 0 40 0 300 0 0 0 0
 253       0 dm-0 10 0 20 0 5 0 40 0 0 0 0";
        let disks: HashSet<String> = ["sda".to_string()].into_iter().collect();
        // Only sda counts: sectorsRead 200, sectorsWritten 400 → ×512.
        assert_eq!(parse_diskstats(text, &disks), (200 * 512, 400 * 512));
    }

    #[test]
    fn temp_millidegrees_to_celsius() {
        assert_eq!(parse_temp("42000"), Some(42.0));
        assert_eq!(parse_temp("bogus"), None);
    }

    #[test]
    fn mounts_dedupe_by_device_keeping_root_path() {
        // Mirrors the systemd sandbox seen live: the root device (/dev/sda2) is
        // bind-mounted at /, /boot, /etc, /usr by ProtectSystem=; it must collapse
        // to a single "/" entry, while the genuinely separate /boot/firmware
        // device survives. Pseudo filesystems are ignored.
        let text = "sysfs /sys sysfs rw 0 0
/dev/sda2 / ext4 rw 0 0
/dev/sda1 /boot/firmware vfat rw 0 0
/dev/sda2 /boot ext4 rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/sda2 /etc ext4 rw 0 0
/dev/sda2 /usr ext4 rw 0 0";
        assert_eq!(parse_mounts(text), ["/", "/boot/firmware"]);
    }

    #[test]
    fn statvfs_reads_the_root_filesystem() {
        // Runs on the dev box too: "/" always exists and reports a nonzero size.
        let (size, used) = statvfs_usage("/").expect("root is stat-able");
        assert!(size > 0);
        assert!(used <= size);
    }
}
