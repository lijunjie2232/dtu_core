//! Daemon: TCP listener with per-connection auth, file operations, control port.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::cfg::{self, Config};
use crate::discover;
use crate::guard;
use crate::identity::{self, Identity};
use crate::invite;
use crate::jwt;
use crate::proto::{self, Cred, Ctrl, Msg};
use crate::state::{Decision, State};
use crate::trust::Store;

const HANDSHAKE: Duration = Duration::from_secs(10);
const BUF: usize = 256 * 1024;
const MAX_CODE_FAILS: u32 = 5;
/// Entries per `Entries` frame: keeps one JSON frame well under `MAX_CTRL`.
const LIST_CHUNK: usize = 1000;

/// A failed operation, with a stable machine-readable kind so callers (scripts, a GUI)
/// do not have to parse prose. `Msg::Err.code` carries it.
#[derive(Debug)]
pub struct OpError {
    pub kind: &'static str,
    pub msg: String,
}

impl OpError {
    pub fn new(kind: &'static str, msg: impl Into<String>) -> Self {
        Self { kind, msg: msg.into() }
    }

    pub fn path(msg: impl Into<String>) -> Self {
        Self::new("path", msg)
    }

    pub fn io(msg: impl Into<String>) -> Self {
        Self::new("io", msg)
    }
}

impl From<String> for OpError {
    fn from(msg: String) -> Self {
        Self::new("op", msg)
    }
}

impl From<&str> for OpError {
    fn from(msg: &str) -> Self {
        Self::new("op", msg)
    }
}

/// Everything a hosted core needs before any loop runs: the data-dir lock, the
/// identity, the trust store, the served root and the local REST key.
pub struct Prepared {
    pub state: Arc<State>,
    pub key: String,
    /// Held for as long as the services run: one process per data directory.
    lock: std::fs::File,
}

pub fn prepare(cfg: Config) -> Result<Prepared, String> {
    let lock = acquire_data_lock()?;
    install_panic_hook();
    let id = Identity::load_or_create()?;
    let trust = Store::load();
    let root = cfg.root_path();
    std::fs::create_dir_all(&root).map_err(|e| format!("create root {}: {e}", root.display()))?;
    let st = State::new(cfg, id, trust);
    let key = control_token()?;
    let _ = std::fs::write(cfg::file("daemon.pid"), std::process::id().to_string());
    Ok(Prepared { state: st, key, lock })
}

