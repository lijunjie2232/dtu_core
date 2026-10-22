//! Audit log (JSONL): who authenticated, and which files moved over that connection.
//! Contents are never logged — only the path, the size and the peer (id + address).

use serde::Serialize;
use std::io::Write;

#[derive(Serialize)]
struct Line<'a> {
    ts: String,
    epoch: u64,
    /// auth | invite | file | diag
    event: &'a str,
    /// ok | deny | pending | timeout | error
    result: &'a str,
    /// how the connection authenticated (jwt/code/session/unlimit), or the file
    /// operation (put/get/del) for `event = file`
    method: &'a str,
    device: Option<&'a str>,
    addr: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
    reason: Option<&'a str>,
}

/// Keep two generations; an always-on app must not grow one file forever.
const MAX_BYTES: u64 = 1 << 20;

pub fn log(
    event: &str,
    result: &str,
    method: &str,
    device: Option<&str>,
    addr: &str,
    reason: Option<&str>,
) {
    write(Line {
        ts: String::new(),
        epoch: 0,
        event,
        result,
        method,
        device,
        addr,
        path: None,
        bytes: None,
        reason,
    });
}

/// One transferred file (or one downloaded range) with the peer that moved it.
/// `op` is `put`, `get` or `del`.
pub fn file(
    op: &str,
    result: &str,
    device: &str,
    addr: &str,
    path: &str,
    bytes: u64,
    reason: Option<&str>,
) {
    write(Line {
        ts: String::new(),
        epoch: 0,
        event: "file",
        result,
        method: op,
        device: Some(device),
        addr,
        path: Some(path),
        bytes: Some(bytes),
        reason,
    });
}

fn write(mut line: Line<'_>) {
    let epoch = crate::identity::now();
    line.ts = iso(epoch);
    line.epoch = epoch;
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

/// One parsed log line, so frontends can render instead of grepping JSON.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Entry {
    pub ts: String,
    pub epoch: u64,
    pub event: String,
    pub result: String,
    pub method: String,
    #[serde(default)]
    pub device: Option<String>,
    pub addr: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

impl Entry {
    /// "12:34:56  file  ok  put  device…  192.168.1.24:54712  in/a.bin  1.2 MB"
    pub fn line(&self) -> String {
        let time = self.ts.split('T').nth(1).unwrap_or(&self.ts).trim_end_matches('Z');
        let who = match &self.device {
            Some(d) if d.len() > 12 => format!("{}…", &d[..12]),
            Some(d) => d.clone(),
            None => "-".to_string(),
        };
        let mut out = format!("{time}  {:<6} {:<5} {:<7} {:<13} {:<21}", self.event, self.result, self.method, who, self.addr);
        if let Some(p) = &self.path {
            out.push_str(&format!(" {p}"));
        }
        if let Some(b) = self.bytes {
            if b > 0 {
                out.push_str(&format!("  {}", human_bytes(b)));
            }
        }
        if let Some(r) = &self.reason {
            out.push_str(&format!("  — {r}"));
        }
        out
    }
}

/// Parsed tail of the log, newest last. Unparsable lines are skipped.
pub fn entries(event: Option<&str>, n: usize) -> Vec<Entry> {
    tail_of(event, n)
        .iter()
        .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
        .collect()
}

pub fn human_bytes(bytes: u64) -> String {
    let b = bytes as f64;
    const K: f64 = 1024.0;
    if b >= K * K * K {
        format!("{:.1} GiB", b / (K * K * K))
    } else if b >= K * K {
        format!("{:.1} MiB", b / (K * K))
    } else if b >= K {
        format!("{:.1} KiB", b / K)
    } else {
        format!("{bytes} B")
    }
}

pub fn tail(n: usize) -> Vec<String> {
    tail_of(None, n)
}

/// Last `n` lines, optionally only those with `event == kind` (`auth`, `file`, …).
pub fn tail_of(event: Option<&str>, n: usize) -> Vec<String> {
    let path = crate::cfg::file("auth.log");
    let mut body = std::fs::read_to_string(path.with_extension("log.1")).unwrap_or_default();
    body.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
    let needle = event.map(|k| format!("\"event\":\"{k}\""));
    let mut lines: Vec<String> = body
        .lines()
        .filter(|l| !l.is_empty())
        .filter(|l| match &needle {
            Some(needle) => l.contains(needle.as_str()),
            None => true,
        })
        .map(|s| s.to_string())
        .collect();
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
