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

/// Bind the LAN listener, discovery and the REST surface, then accept until `stop`
/// fires. `ready` reports once the TCP listener is up, so the host can tell
/// "serving" from "still starting" (and shows the reason if binding failed).
pub async fn serve(
    prepared: Prepared,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
    stop: Arc<tokio::sync::Notify>,
) -> Result<(), String> {
    let Prepared { state: st, key, lock: _lock } = prepared;
    let port = st.cfg.port;

    {
        let st = st.clone();
        tokio::spawn(async move { discover::serve(st).await });
    }
    {
        let st = st.clone();
        tokio::spawn(async move { crate::api::serve(st, key).await });
    }

    let listeners = match bind_dual(port).await {
        Ok(l) => l,
        Err(e) => {
            let _ = ready.send(Err(e.clone()));
            return Err(e);
        }
    };
    let _ = ready.send(Ok(()));

    let mut rest = listeners.into_iter();
    let first = rest.next().expect("at least one listener");
    for l in rest {
        let st = st.clone();
        tokio::spawn(async move {
            let _ = accept_loop(l, st).await;
        });
    }
    let mut accepting = std::pin::pin!(accept_loop(first, st.clone()));
    tokio::select! {
        _ = stop.notified() => {
            drain(&st).await;
            Ok(())
        }
        r = &mut accepting => r,
    }
}

/// Give in-flight transfers a chance to finish instead of truncating them.
async fn drain(st: &State) {
    let budget = Duration::from_secs(st.cfg.drain_timeout);
    if budget.is_zero() {
        return;
    }
    let deadline = std::time::Instant::now() + budget;
    while st.active_conns().await > 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn install_panic_hook() {
    #[cfg(not(test))]
    {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // A background daemon has nobody watching stderr unless we say so.
            crate::audit::note(&format!("panic: {info}"));
            eprintln!("dtu panic: {info}");
            previous(info);
        }));
    }
}

/// Accept forever, one task per connection.
pub async fn accept_loop(listener: TcpListener, st: Arc<State>) -> Result<(), String> {
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let ip = peer.ip().to_canonical();
        if !st.adopt_conn(ip).await {
            eprintln!("conn {peer}: too many connections from this address");
            drop(sock);
            continue;
        }
        let st = st.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, peer, st.clone()).await {
                eprintln!("conn {peer}: {e}");
            }
            st.release_conn(ip).await;
        });
    }
}

/// The local key for the control port and the REST surface: minted on first start
/// and kept in the user data dir, so a frontend can be configured once.
pub fn control_token() -> Result<String, String> {
    let path = cfg::file("control.token");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let text = text.trim();
        if text.len() >= 16 {
            return Ok(text.to_string());
        }
    }
    let token = identity::random_code(32);
    std::fs::write(&path, &token).map_err(|e| format!("write control.token: {e}"))?;
    Ok(token)
}

/// Holds an OS-level lock on `daemon.lock` for the lifetime of the process.
pub fn acquire_data_lock() -> Result<std::fs::File, String> {
    let path = cfg::file("daemon.lock");
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create data dir: {e}"))?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| format!("open daemon.lock: {e}"))?;
    file.try_lock()
        .map_err(|_| format!("another dtu daemon already owns {}", cfg::data_dir().display()))?;
    Ok(file)
}

/// Windows does not always give dual-stack `[::]` sockets, so bind both families.
async fn bind_dual(port: u16) -> Result<Vec<TcpListener>, String> {
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for addr in [
        std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)),
        std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)),
    ] {
        match TcpListener::bind(addr).await {
            Ok(l) => out.push(l),
            Err(e) => errs.push(format!("{addr}: {e}")),
        }
    }
    if out.is_empty() {
        return Err(format!("bind port {port}: {}", errs.join("; ")));
    }
    Ok(out)
}

