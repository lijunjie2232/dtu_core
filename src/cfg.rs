//! Paths, config file, atomic JSON read/write.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// `%APPDATA%\dtu`, overridable with `DTU_HOME` (tests use this).
pub fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("DTU_HOME") {
        return PathBuf::from(d);
    }
    match std::env::var_os("APPDATA") {
        Some(a) => PathBuf::from(a).join("dtu"),
        None => PathBuf::from(".dtu"),
    }
}

pub fn file(name: &str) -> PathBuf {
    data_dir().join(name)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// TCP (and UDP discovery) port.
    pub port: u16,
    /// Root directory this app serves; every remote path resolves under it.
    pub root: String,
    /// Parallel TCP streams per file.
    pub parallel: usize,
    /// DANGEROUS: accept any device, any invite, skip trust checks.
    pub unlimit: bool,
    /// In unlimit mode, still record devices into the trust store.
    pub unlimit_store_trust: bool,
    /// One-time pairing code is consumed by the first successful auth.
    pub code_one_shot: bool,
    /// Rotate the pairing code whenever a connection is established.
    pub code_rotate_on_connect: bool,
    /// Optional extra password on top of the pairing code.
    pub code_password: Option<String>,
    /// Seconds an invitation waits for a human decision.
    pub invite_timeout: u64,
    /// Seconds a session token stays valid. Covers the extra TCP connections one
    /// transfer opens; must be generous for very large files.
    pub session_ttl: u64,
    /// Seconds an established connection may stay silent before it is dropped.
    /// 0 disables the watchdog.
    pub idle_timeout: u64,
    /// Concurrent connections accepted from one source address. Must stay above
    /// `parallel` * 2 + 2, since one `push` opens that many sockets itself.
    pub max_conn_per_ip: u32,
    /// Seconds an app waits for in-flight transfers when it stops.
    pub drain_timeout: u64,
    /// Loopback port for the REST surface. 0 = port + 1.
    pub api_port: u16,
    /// How often a UI repaints itself, in seconds. 0 = the client's default.
    pub ui_refresh_secs: u64,
    /// How many log lines a UI keeps on screen. 0 = the client's default.
    pub ui_log_lines: usize,
    /// Close the main window to the tray instead of quitting.
    pub ui_close_to_tray: bool,
}

/// How a settings field is edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Number,
    Bool,
    Text,
    /// Text that can be unset: an empty value clears it.
    #[serde(rename = "optional_text")]
    OptionalText,
}

/// One editable setting, so every frontend can render the same form.
#[derive(Debug, Clone, Serialize)]
pub struct Field {
    pub key: &'static str,
    pub kind: Kind,
    /// `true` when the running app cannot adopt the change (it reads the value
    /// once at startup).
    pub restart: bool,
    pub help: &'static str,
}

/// Every key of `Config`, in the order a settings form shows them.
pub fn fields() -> &'static [Field] {
    &[
        Field { key: "port", kind: Kind::Number, restart: true, help: "LAN port for transfers and discovery" },
        Field { key: "api_port", kind: Kind::Number, restart: true, help: "Loopback REST port (0 = port + 1)" },
        Field { key: "root", kind: Kind::Text, restart: true, help: "Directory served to peers" },
        Field { key: "parallel", kind: Kind::Number, restart: false, help: "Parallel TCP streams per file" },
        Field { key: "unlimit", kind: Kind::Bool, restart: true, help: "DANGEROUS: accept any device, skip trust" },
        Field { key: "unlimit_store_trust", kind: Kind::Bool, restart: true, help: "In unlimit mode, still record devices" },
        Field { key: "code_one_shot", kind: Kind::Bool, restart: true, help: "The pairing code is consumed by the first auth" },
        Field { key: "code_rotate_on_connect", kind: Kind::Bool, restart: true, help: "Rotate the pairing code on every connection" },
        Field { key: "code_password", kind: Kind::OptionalText, restart: false, help: "Extra password on top of the code (empty clears)" },
        Field { key: "invite_timeout", kind: Kind::Number, restart: true, help: "Seconds an invitation waits for a human" },
        Field { key: "session_ttl", kind: Kind::Number, restart: true, help: "Seconds a session token stays valid" },
        Field { key: "idle_timeout", kind: Kind::Number, restart: true, help: "Silent seconds before a connection is dropped (0 = off)" },
        Field { key: "max_conn_per_ip", kind: Kind::Number, restart: true, help: "Concurrent connections per source address" },
        Field { key: "drain_timeout", kind: Kind::Number, restart: true, help: "Seconds a stop waits for in-flight transfers" },
        Field { key: "ui_refresh_secs", kind: Kind::Number, restart: true, help: "UI refresh interval in seconds (0 = client default)" },
        Field { key: "ui_log_lines", kind: Kind::Number, restart: true, help: "Log lines a UI keeps (0 = client default)" },
        Field { key: "ui_close_to_tray", kind: Kind::Bool, restart: false, help: "Closing the window hides it to the tray instead of quitting" },
    ]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 47000,
            root: String::new(),
            parallel: 4,
            unlimit: false,
            unlimit_store_trust: false,
            code_one_shot: true,
            code_rotate_on_connect: false,
            code_password: None,
            invite_timeout: 600,
            session_ttl: 600,
            idle_timeout: 600,
            max_conn_per_ip: 32,
            drain_timeout: 5,
            api_port: 0,
            ui_refresh_secs: 0,
            ui_log_lines: 0,
            ui_close_to_tray: true,
        }
    }
}

impl Config {
    pub fn load() -> Self {
        let mut c: Config = read_json(&file("config.json")).unwrap_or_default();
        if c.root.trim().is_empty() {
            c.root = data_dir().join("share").to_string_lossy().into_owned();
            let _ = c.save();
        }
        c
    }

    pub fn save(&self) -> io::Result<()> {
        write_json(&file("config.json"), self)
    }

    pub fn root_path(&self) -> PathBuf {
        PathBuf::from(&self.root)
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let v = serde_json::to_value(self).ok()?;
        v.get(key).map(|x| match x {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        let mut v = serde_json::to_value(&*self).map_err(|e| e.to_string())?;
        let obj = v.as_object_mut().ok_or("config is not an object")?;
        let slot = obj.get_mut(key).ok_or_else(|| format!("unknown key: {key}"))?;
        *slot = match slot {
            serde_json::Value::Number(_) => serde_json::Value::from(
                value.parse::<u64>().map_err(|_| format!("{key} expects a number"))?,
            ),
            serde_json::Value::Bool(_) => serde_json::Value::from(parse_bool(value)?),
            _ => {
                if value.is_empty() || value == "none" {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::from(value)
                }
            }
        };
        *self = serde_json::from_value(v).map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn parse_bool(v: &str) -> Result<bool, String> {
    match v {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("not a boolean: {v}")),
    }
}

pub fn read_json<T: serde::de::DeserializeOwned>(p: &Path) -> Option<T> {
    let b = std::fs::read(p).ok()?;
    serde_json::from_slice(&b).ok()
}

pub fn write_json<T: Serialize>(p: &Path, v: &T) -> io::Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension("tmp");
    let body = serde_json::to_vec_pretty(v).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, p)
}

/// Parse "30d" / "12h" / "45m" / "90s" / "never" into epoch seconds.
pub fn parse_expiry(spec: &str) -> Result<u64, String> {
    let s = spec.trim().to_ascii_lowercase();
    if s.is_empty() || s == "never" || s == "none" || s == "0" {
        return Ok(0);
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: u64 = num.parse().map_err(|_| format!("bad duration: {spec}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        "w" => n * 7 * 86400,
        _ => return Err(format!("bad duration unit in {spec} (use s/m/h/d/w)")),
    };
    Ok(crate::identity::now() + secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_specs() {
        let now = crate::identity::now();
        assert_eq!(parse_expiry("never").unwrap(), 0);
        let d = parse_expiry("2d").unwrap();
        assert!(d >= now + 2 * 86400 && d <= now + 2 * 86400 + 5);
        assert!(parse_expiry("3x").is_err());
    }

    #[test]
    fn config_set_types() {
        let mut c = Config::default();
        c.set("port", "5000").unwrap();
        assert_eq!(c.port, 5000);
        c.set("unlimit", "yes").unwrap();
        assert!(c.unlimit);
        c.set("code_password", "hunter2").unwrap();
        assert_eq!(c.code_password.as_deref(), Some("hunter2"));
        c.set("code_password", "none").unwrap();
        assert!(c.code_password.is_none());
        assert!(c.set("port", "abc").is_err());
        assert!(c.set("nope", "1").is_err());
    }
}

