//! Auth audit log (JSONL). Transfers are not logged, only auth decisions.

use serde::Serialize;
use std::io::Write;

#[derive(Serialize)]
struct Line<'a> {
    ts: String,
    epoch: u64,
    event: &'a str,
    result: &'a str,
    method: &'a str,
    device: Option<&'a str>,
    addr: &'a str,
    reason: Option<&'a str>,
}

/// Keep two generations; an always-on daemon must not grow one file forever.
const MAX_BYTES: u64 = 1 << 20;

pub fn log(
    event: &str,
    result: &str,
    method: &str,
    device: Option<&str>,
    addr: &str,
    reason: Option<&str>,
) {
    let epoch = crate::identity::now();
    let line = Line { ts: iso(epoch), epoch, event, result, method, device, addr, reason };
    let path = crate::cfg::file("auth.log");
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    rotate_if_big(&path);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        if let Ok(s) = serde_json::to_string(&line) {
            let _ = writeln!(f, "{s}");
        }
    }
}

fn rotate_if_big(path: &std::path::Path) {
    let big = std::fs::metadata(path).map(|m| m.len() > MAX_BYTES).unwrap_or(false);
    if big {
        let _ = std::fs::rename(path, path.with_extension("log.1"));
    }
}

/// Free-form diagnostic line (panics, fatal startup errors) in the same log.
pub fn note(text: &str) {
    log("diag", "-", "-", None, "-", Some(text));
}

pub fn tail(n: usize) -> Vec<String> {
    let path = crate::cfg::file("auth.log");
    let mut body = std::fs::read_to_string(path.with_extension("log.1")).unwrap_or_default();
    body.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
    let mut lines: Vec<String> = body.lines().map(|s| s.to_string()).collect();
    let cut = lines.len().saturating_sub(n);
    lines.split_off(cut)
}

/// unix seconds -> ISO8601 UTC, hand-rolled (civil_from_days).
pub fn iso(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe as i64 + era * 400 + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::iso;

    #[test]
    fn iso_conversion() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(iso(1_791_000_000), "2026-10-03T04:00:00Z");
    }
}
