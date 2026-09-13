//! Metrics history: the downsampled CSV buckets the on-host collector daemon
//! writes under /var/lib/gryonixnexus/metrics.
//!
//! The agent does not sample anything here and does not own the schedule — the
//! collector (a bash daemon installed by the setup scripts) is still the writer,
//! and this only serves what is on disk. That is on purpose: the collector runs
//! on hosts that have no agent, and two writers of the same buckets would be two
//! sources of truth for the same chart.
//!
//! What moves here is the READING, which until now was an SSH `cat` of a path
//! the client composed. The gate is the same shape as management's: a client
//! sends a bucket NAME, it is looked up in the table below, and the path is
//! built from the table's own static string. A client string never reaches the
//! filesystem, so "10s/../../etc/shadow" is refused as an unknown bucket rather
//! than escaped.

use std::path::{Path, PathBuf};

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

/// Where the collector keeps its buckets. Overridable for tests only; the
/// literal must match MetricsHistorySections.dataDirectory on the Swift side
/// (the modules deliberately do not depend on each other, so both sides pin it).
const DEFAULT_DIR: &str = "/var/lib/gryonixnexus/metrics";

/// The buckets the collector maintains, and the ONLY names that resolve to a
/// file. Must match `MetricsHistoryBucket` in ServerControl and the aggregate
/// steps in MetricsHistorySections — pinned by tests on both sides.
///
/// Deliberately not derived from what is on disk: a stray file in the directory
/// must not become a servable "bucket", and a bucket that stopped being written
/// has to fail as an empty read, not silently pick up a neighbour's data.
const BUCKETS: &[&str] = &["10s", "1m", "10m", "1h", "1d", "1w"];

/// A CSV row: 12 fields, in the order the collector writes them.
/// epoch,cpu%,memUsed,memTotal,diskUsed,diskTotal,netRx/s,netTx/s,
/// ioRead/s,ioWrite/s,load1,tempC
const COLUMNS: usize = 12;

/// Resolve a client-supplied bucket name to the table's OWN string, or `None`.
///
/// The return value is `&'static str` on purpose: everything downstream builds
/// the file name from THIS, never from the caller's `&str`, so there is no path
/// on this module's happy path that a client can influence beyond choosing one
/// of six constants.
pub fn known_bucket(name: &str) -> Option<&'static str> {
    BUCKETS.iter().copied().find(|bucket| *bucket == name)
}

fn directory() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_METRICS_DIR").unwrap_or_else(|_| DEFAULT_DIR.to_string()))
}

/// The file one bucket lives in. Takes the table's string, not a client's.
fn bucket_path(dir: &Path, bucket: &'static str) -> PathBuf {
    dir.join(format!("{bucket}.csv"))
}

/// Read one bucket. A MISSING file is an empty history, not an error: a server
/// whose collector has not written its first row yet (or was installed before
/// the collector existed) has no history, and the app shows its empty state.
/// The SSH path said the same thing with `cat … 2>/dev/null; true`, and turning
/// it into an error now would paint a red banner on every fresh install.
///
/// A file that exists but cannot be read IS an error — that one is a real fault
/// on the host (permissions, I/O), and hiding it as "no data yet" is how a
/// broken collector stays invisible for a week.
pub fn read_bucket(bucket: &'static str) -> std::io::Result<Vec<pb::MetricsHistoryPoint>> {
    let path = bucket_path(&directory(), bucket);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(parse(&text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

/// Apply the request's window: `since` first (a lower bound in Unix ms), then
/// `limit` as the most RECENT N. Order matters — limiting first would hand back
/// the oldest rows of a bucket and call them the last hour.
pub fn window(points: Vec<pb::MetricsHistoryPoint>, since: i64, limit: u32) -> Vec<pb::MetricsHistoryPoint> {
    let mut points: Vec<_> = if since > 0 {
        points.into_iter().filter(|p| p.at >= since).collect()
    } else {
        points
    };
    if limit > 0 && points.len() > limit as usize {
        points.drain(..points.len() - limit as usize);
    }
    points
}

/// The RPC. Refusals happen before any file is touched and carry the bucket
/// back (bounded), because "1min" vs "1m" is the whole bug in that case.
pub fn metrics_history(codec: Codec, req: pb::MetricsHistoryRequest) -> Resp {
    let Some(bucket) = known_bucket(&req.bucket) else {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            &format!(
                "unknown metrics bucket '{}' (expected one of {})",
                req.bucket.chars().take(32).collect::<String>(),
                BUCKETS.join(", ")
            ),
        );
    };
    let points = match read_bucket(bucket) {
        Ok(points) => points,
        Err(err) => {
            return connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                &format!("could not read the {bucket} history bucket: {err}"),
            )
        }
    };
    let response = pb::MetricsHistoryResponse {
        // The table's string, never the request's: a client that asked with
        // odd whitespace must not see its own text echoed back as the answer.
        bucket: bucket.to_string(),
        points: window(points, req.since, req.limit),
    };
    codec.encode(&response).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

/// Parse a bucket file. A malformed line is SKIPPED, never fatal: the collector
/// may be appending the newest row at this very moment and it can arrive
/// truncated, and one bad row must not hide two weeks of good history. This
/// mirrors MetricsHistoryParser in ServerControl field for field — the app's
/// chart has to look identical on either route.
fn parse(text: &str) -> Vec<pb::MetricsHistoryPoint> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<pb::MetricsHistoryPoint> {
    let fields: Vec<&str> = line.split(',').collect();
    if fields.len() != COLUMNS {
        return None;
    }
    // Epoch SECONDS on disk (the collector's `date +%s`), Unix ms on the wire —
    // the rest of this API is milliseconds and one unit per schema is worth the
    // multiplication here.
    let seconds: f64 = fields[0].trim().parse().ok()?;
    Some(pb::MetricsHistoryPoint {
        at: (seconds * 1000.0) as i64,
        cpu_percent: optional(fields[1]),
        mem_used_bytes: required_int(fields[2])?,
        mem_total_bytes: required_int(fields[3])?,
        disk_used_bytes: required_int(fields[4])?,
        disk_total_bytes: required_int(fields[5])?,
        net_received_per_second: optional(fields[6]),
        net_sent_per_second: optional(fields[7]),
        disk_read_per_second: optional(fields[8]),
        disk_written_per_second: optional(fields[9]),
        load1: fields[10].trim().parse().ok()?,
        temperature_celsius: optional(fields[11]),
    })
}

fn required_int(field: &str) -> Option<i64> {
    field.trim().parse().ok()
}

/// An empty CSV field means "the collector had nothing to write here", which is
/// NOT zero: no rate yet on the first sample after a start, no thermal zone on
/// most VPSes. Sending 0 would draw a flat line that reads as measured.
fn optional(field: &str) -> Option<f64> {
    let field = field.trim();
    if field.is_empty() {
        return None;
    }
    field.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One real-shaped bucket: a full row, a row with no rates and no
    /// temperature (the collector's first sample after a start), and junk.
    const SAMPLE: &str = "\
1754400000,12.5,1073741824,4294967296,5368709120,107374182400,1024.5,2048.5,100.5,200.5,0.42,41.2
1754400010,,1073741824,4294967296,5368709120,107374182400,,,,,0.10,
this is not a row
1754400020,7.5,1173741824,4294967296,5368709120,107374182400,10,20,30,40,1.00,39.0
";

    #[test]
    fn only_the_collectors_six_buckets_resolve() {
        for bucket in ["10s", "1m", "10m", "1h", "1d", "1w"] {
            assert_eq!(known_bucket(bucket), Some(bucket));
        }
        // The whole gate in one line: the client picks among constants, it does
        // not supply a name. Traversal, an absolute path and a plausible-looking
        // bucket are all the SAME refusal.
        for hostile in ["10s.csv", "../../etc/shadow", "/etc/shadow", "10s/../1m", "30s", ""] {
            assert_eq!(known_bucket(hostile), None, "{hostile} must not resolve");
        }
    }

    #[test]
    fn the_path_is_built_from_the_table_not_from_the_request() {
        // Structural: every servable path is <dir>/<one of the six>.csv, and the
        // table's strings carry nothing a path could be traversed with.
        let dir = Path::new("/var/lib/gryonixnexus/metrics");
        for bucket in BUCKETS {
            let path = bucket_path(dir, bucket);
            assert_eq!(path.parent(), Some(dir));
            assert_eq!(path.file_name().unwrap().to_str().unwrap(), format!("{bucket}.csv"));
            assert!(!bucket.contains('/') && !bucket.contains('.'));
        }
    }

    #[test]
    fn parses_the_twelve_columns_in_the_collectors_order() {
        let points = parse(SAMPLE);
        assert_eq!(points.len(), 3, "the junk line is skipped, not fatal");
        let first = &points[0];
        assert_eq!(first.at, 1_754_400_000_000, "epoch seconds become Unix ms");
        assert_eq!(first.cpu_percent, Some(12.5));
        assert_eq!(first.mem_used_bytes, 1_073_741_824);
        assert_eq!(first.mem_total_bytes, 4_294_967_296);
        assert_eq!(first.disk_used_bytes, 5_368_709_120);
        assert_eq!(first.disk_total_bytes, 107_374_182_400);
        assert_eq!(first.net_received_per_second, Some(1024.5));
        assert_eq!(first.net_sent_per_second, Some(2048.5));
        assert_eq!(first.disk_read_per_second, Some(100.5));
        assert_eq!(first.disk_written_per_second, Some(200.5));
        assert_eq!(first.load1, 0.42);
        assert_eq!(first.temperature_celsius, Some(41.2));
    }

    #[test]
    fn an_empty_field_stays_absent_and_never_becomes_zero() {
        // The collector leaves rates empty on its first sample and temperature
        // empty on a host with no thermal zone. A 0 here would draw a measured
        // flat line at zero — the app's optionals exist for exactly this.
        let point = &parse(SAMPLE)[1];
        assert_eq!(point.cpu_percent, None);
        assert_eq!(point.net_received_per_second, None);
        assert_eq!(point.net_sent_per_second, None);
        assert_eq!(point.disk_read_per_second, None);
        assert_eq!(point.disk_written_per_second, None);
        assert_eq!(point.temperature_celsius, None);
        // …while the gauges on the same row are real values.
        assert_eq!(point.mem_used_bytes, 1_073_741_824);
        assert_eq!(point.load1, 0.10);
    }

    #[test]
    fn a_row_with_the_wrong_column_count_is_skipped() {
        assert!(parse("1754400000,1,2,3\n").is_empty());
        // Truncated mid-write: the trailing row is dropped, the good one stays.
        let text = "1754400000,1,2,3,4,5,6,7,8,9,0.5,\n1754400010,1,2,3,4,5";
        assert_eq!(parse(text).len(), 1);
    }

    #[test]
    fn window_takes_the_newest_points_after_filtering_by_time() {
        let points = parse(SAMPLE);
        let recent = window(points.clone(), 0, 2);
        assert_eq!(recent.len(), 2);
        // The NEWEST two, not the first two: limiting before the window would
        // hand back the oldest rows and label them "the last hour".
        assert_eq!(recent[0].at, 1_754_400_010_000);
        assert_eq!(recent[1].at, 1_754_400_020_000);

        let since = window(points.clone(), 1_754_400_010_000, 0);
        assert_eq!(since.len(), 2);
        assert_eq!(since[0].at, 1_754_400_010_000);

        // Both together: the window first, then the newest N inside it.
        let both = window(points, 1_754_400_010_000, 1);
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].at, 1_754_400_020_000);
    }

    #[test]
    fn a_bucket_file_that_does_not_exist_is_empty_history_not_an_error() {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-history-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("GRYONIXNEXUSD_METRICS_DIR", &dir);
        // Nothing written yet: a fresh install, before the collector's first row.
        assert_eq!(read_bucket("10s").unwrap().len(), 0);

        std::fs::write(bucket_path(&dir, "10s"), SAMPLE).unwrap();
        assert_eq!(read_bucket("10s").unwrap().len(), 3);
        std::env::remove_var("GRYONIXNEXUSD_METRICS_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
