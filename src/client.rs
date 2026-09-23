//! Client side: connect + auth, push/pull with resume and parallel streams, diff, sync.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::cfg::Config;
use crate::guard;
use crate::identity::{self, Identity};
use crate::jwt;
use crate::proto::{self, Cred, Entry, Msg};
use crate::trust::Store;

pub const CHUNK_MIN: u64 = 8 << 20;
const BUF: usize = 256 * 1024;
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub struct Conn {
    pub s: TcpStream,
}

/// A peer we are about to talk to.
#[derive(Clone, Debug)]
pub struct Target {
    pub addr: String,
    pub cred: Cred,
    /// Set when the peer is trusted: pinned (id, pubkey), checked after handshake.
    pub pin: Option<(String, String)>,
    /// Session token handed back by the peer, reused by the rest of the transfer.
    session: Arc<tokio::sync::Mutex<Option<String>>>,
    /// Identity the peer proved during the handshake: (id, pubkey).
    peer: Arc<tokio::sync::Mutex<Option<(String, String)>>>,
}

impl Target {
    pub fn new(addr: impl Into<String>, cred: Cred, pin: Option<(String, String)>) -> Self {
        Self {
            addr: addr.into(),
            cred,
            pin,
            session: Arc::new(tokio::sync::Mutex::new(None)),
            peer: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Authenticated peer identity, known after the first successful connection.
    pub async fn peer_id(&self) -> Option<String> {
        self.peer.lock().await.as_ref().map(|(id, _)| id.clone())
    }

    pub fn is_trusted(&self) -> bool {
        self.pin.is_some()
    }
    /// `<peer>` is either a trusted device id, its alias, or `host[:port]` / url.
    pub fn resolve(cfg: &Config, trust: &Store, peer: &str, code: Option<&str>, password: Option<&str>) -> Result<Self, String> {
        if let Some((id, dev)) = trust.resolve(peer) {
            if dev.expires_at != 0 && dev.expires_at <= identity::now() {
                return Err(format!("authorization for {id} expired, pair it again"));
            }
            let addr = dev
                .addr
                .clone()
                .ok_or("trusted device has no known address; pass host[:port] instead")?;
            return Ok(Target::new(
                addr,
                Cred::Token { token: dev.token.clone() },
                Some((id.to_string(), dev.pubkey.clone())),
            ));
        }
        let code = code.ok_or("peer is not trusted: pass --code <pairing code> (or --invite it first)")?;
        Ok(Target::new(
            normalize_addr(peer, cfg.port),
            Cred::Code { code: code.to_string(), password: password.map(|s| s.to_string()) },
            None,
        ))
    }
}

/// `host`, `host:port`, `[v6]:port`, `1.2.3.4`, `http://host:port`.
pub fn normalize_addr(spec: &str, default_port: u16) -> String {
    let s = spec.trim();
    let s = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")).unwrap_or(s);
    let s = s.trim_end_matches('/');
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail.trim_start_matches(':').parse().unwrap_or(default_port);
            return format!("[{host}]:{port}");
        }
    }
    if s.matches(':').count() > 1 {
        return format!("[{s}]:{default_port}");
    }
    match s.rsplit_once(':') {
        Some((host, p)) if p.parse::<u16>().is_ok() => format!("{host}:{p}"),
        _ => format!("{s}:{default_port}"),
    }
}

pub async fn connect(t: &Target, me: &Identity) -> Result<Conn, String> {
    let cached = t.session.lock().await.clone();
    let used_session = cached.is_some();
    let err = match connect_once(t, me, cached).await {
        Ok(c) => return Ok(c),
        Err(e) => e,
    };
    // A session token lives for `session_ttl`; long syncs outlive it, but the
    // long-lived credential behind it (a trusted JWT) still works.
    if used_session && err.starts_with("auth failed") {
        *t.session.lock().await = None;
        return connect_once(t, me, None).await;
    }
    Err(err)
}

async fn connect_once(t: &Target, me: &Identity, session: Option<String>) -> Result<Conn, String> {
    let mut s = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&t.addr))
        .await
        .map_err(|_| format!("connect {}: timeout", t.addr))?
        .map_err(|e| format!("connect {}: {e}", t.addr))?;
    let _ = s.set_nodelay(true);
    // Once the peer gave us a session token, use it: a pairing code is single-use
    // but a parallel transfer needs several connections.
    let cred = match session {
        Some(tok) => Cred::Session { token: tok },
        None => t.cred.clone(),
    };
    let hello = Msg::Hello { proto: proto::PROTO, id: me.id.clone(), pubkey: me.pubkey(), cred, nonce: 0 };
    proto::write_msg(&mut s, &hello).await.map_err(|e| e.to_string())?;

    let reply = tokio::time::timeout(CONNECT_TIMEOUT, proto::read_msg(&mut s))
        .await
        .map_err(|_| "handshake timeout".to_string())?
        .map_err(|e| e.to_string())?;
    match reply {
        Msg::HelloOk { proto: peer_proto, id, pubkey, token } => {
            if peer_proto != proto::PROTO {
                return Err(format!(
                    "protocol mismatch: peer speaks v{peer_proto}, this build speaks v{} — upgrade the older side",
                    proto::PROTO
                ));
            }
            // The peer proves it holds the key behind its advertised id.
            jwt::verify(&pubkey, &token, &id, &me.id, identity::now())?;
            if let Some((pin_id, pin_pub)) = &t.pin {
                if pin_id != &id {
                    return Err(format!("peer id {id} is not the trusted device {pin_id}"));
                }
                if pin_pub != &pubkey {
                    return Err("peer key changed since pairing, re-pair this device".into());
                }
            }
            *t.session.lock().await = Some(token);
            *t.peer.lock().await = Some((id, pubkey));
            Ok(Conn { s })
        }
        Msg::AuthFail { reason } => Err(format!("auth failed: {reason}")),
        other => Err(format!("unexpected handshake reply: {other:?}")),
    }
}

/// Establish the session token before parallel connections race for the same code.
pub async fn warm(t: &Target, me: &Identity) -> Result<(), String> {
    if t.session.lock().await.is_some() {
        return Ok(());
    }
    match t.cred {
        Cred::Code { .. } | Cred::Any => {
            connect(t, me).await?;
        }
        _ => {}
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct Plan {
    pub parallel: usize,
    pub resume: bool,
    /// End-to-end sha256 check. Costs one extra sequential read on each side.
    pub verify: bool,
}

/// Split `size` into at most `parallel` ranges, each at least CHUNK_MIN when possible.
pub fn ranges(size: u64, parallel: usize) -> Vec<(u64, u64)> {
    if size == 0 {
        return vec![(0, 0)];
    }
    let chunks = size.div_ceil(CHUNK_MIN) as usize;
    let k = parallel.max(1).min(chunks.max(1));
    let step = size.div_ceil(k as u64);
    let mut out = Vec::with_capacity(k);
    let mut start = 0;
    while start < size {
        let end = (start + step).min(size);
        out.push((start, end));
        start = end;
    }
    out
}

fn join_rel(base: &str, rel: &str) -> String {
    let base = base.replace('\\', "/").trim_matches('/').to_string();
    if base.is_empty() {
        rel.to_string()
    } else {
        format!("{base}/{rel}")
    }
}

async fn expect_ok(s: &mut TcpStream, what: &str) -> Result<(), String> {
    match proto::read_msg(s).await.map_err(|e| format!("{what}: {e}"))? {
        Msg::Ok => Ok(()),
        Msg::Err { code, msg } => Err(format!("{what}: {code}: {msg}")),
        other => Err(format!("{what}: unexpected {other:?}")),
    }
}

async fn expect_resume(s: &mut TcpStream) -> Result<(u64, u64), String> {
    match proto::read_msg(s).await.map_err(|e| e.to_string())? {
        Msg::Resume { offset, size, .. } => Ok((offset, size)),
        Msg::Err { code, msg } => Err(format!("{code}: {msg}")),
        other => Err(format!("expected resume, got {other:?}")),
    }
}

/// (local path, path relative to the pushed directory, is a directory)
fn expand_locals(locals: &[String]) -> Result<Vec<(PathBuf, String, bool)>, String> {
    let mut out = Vec::new();
    for spec in locals {
        let p = PathBuf::from(spec);
        let md = std::fs::metadata(&p).map_err(|e| format!("{spec}: {e}"))?;
        if md.is_file() {
            let name = p
                .file_name()
                .ok_or_else(|| format!("{spec}: not a file name"))?
                .to_string_lossy()
                .into_owned();
            out.push((p, name, false));
        } else {
            let base = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            for e in guard::walk(&p).map_err(|e| format!("{spec}: {e}"))? {
                out.push((p.join(&e.path), join_rel(&base, &e.path), e.dir));
            }
        }
    }
    Ok(out)
}

/// Create a remote directory (and its parents).
pub async fn mkdir(t: &Target, me: &Identity, remote: &str) -> Result<(), String> {
    warm(t, me).await?;
    let mut c = connect(t, me).await?;
    proto::write_msg(&mut c.s, &Msg::Mkdir { path: remote.into() })
        .await
        .map_err(|e| e.to_string())?;
    expect_ok(&mut c.s, "mkdir").await
}

fn strip_base(spec: &str, entries: Vec<Entry>) -> Vec<(String, Entry)> {
    let base = spec.replace('\\', "/").trim_matches('/').to_string();
    let single_file = entries.len() == 1 && entries[0].path == base;
    entries
        .into_iter()
        .map(|e| {
            let rel = if single_file {
                Path::new(&base)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| base.clone())
            } else {
                let prefix = if base.is_empty() { String::new() } else { format!("{base}/") };
                e.path.strip_prefix(&prefix).unwrap_or(&e.path).to_string()
            };
            (rel, e)
        })
        .collect()
}

pub async fn list(t: &Target, me: &Identity, path: &str) -> Result<Vec<Entry>, String> {
    warm(t, me).await?;
    let mut c = connect(t, me).await?;
    proto::write_msg(&mut c.s, &Msg::List { path: path.to_string() })
        .await
        .map_err(|e| e.to_string())?;
    let mut all = Vec::new();
    loop {
        match proto::read_msg(&mut c.s).await.map_err(|e| e.to_string())? {
            Msg::Entries { items, more } => {
                all.extend(items);
                if !more {
                    return Ok(all);
                }
            }
            Msg::Err { code, msg } => return Err(format!("list {path}: {code}: {msg}")),
            other => return Err(format!("list {path}: unexpected {other:?}")),
        }
    }
}

/// What a `push` would do, without moving any bytes.
#[derive(Debug, Clone)]
pub struct PushRow {
    pub remote: String,
    pub local_size: u64,
    /// Bytes already on the peer, 0 when the file is absent.
    pub remote_size: u64,
}

impl PushRow {
    pub fn up_to_date(&self) -> bool {
        self.remote_size == self.local_size
    }
}

/// Read-only size probe of a peer file (0 when absent).
pub async fn stat(t: &Target, me: &Identity, remote: &str) -> Result<u64, String> {
    warm(t, me).await?;
    let mut c = connect(t, me).await?;
    proto::write_msg(&mut c.s, &Msg::Stat { path: remote.into() })
        .await
        .map_err(|e| e.to_string())?;
    match proto::read_msg(&mut c.s).await.map_err(|e| e.to_string())? {
        Msg::Resume { size, .. } => Ok(size),
        Msg::Err { code, msg } => Err(format!("stat {remote}: {code}: {msg}")),
        other => Err(format!("stat {remote}: unexpected {other:?}")),
    }
}

/// Probe the peer for each file without transferring anything.
pub async fn plan_push(
    t: &Target,
    me: Arc<Identity>,
    locals: &[String],
    remote_dir: &str,
) -> Result<Vec<PushRow>, String> {
    warm(t, &me).await?;
    let mut rows = Vec::new();
    for (local, rel, is_dir) in expand_locals(locals)? {
        if is_dir {
            // directories carry no bytes: dry-run only reports files
            continue;
        }
        let remote = join_rel(remote_dir, &rel);
        let local_size = std::fs::metadata(&local).map_err(|e| format!("{}: {e}", local.display()))?.len();
        let remote_size = stat(t, &me, &remote).await?;
        rows.push(PushRow { remote, local_size, remote_size });
    }
    Ok(rows)
}

/// Which byte ranges of an in-progress upload the peer already holds, plus the part
/// file size. The connection is handed back so it can carry the first range.
pub async fn ranges_done(t: &Target, me: &Identity, remote: &str) -> Result<(Vec<(u64, u64)>, u64, Conn), String> {
    let mut c = connect(t, me).await?;
    proto::write_msg(&mut c.s, &Msg::Map { path: remote.into() })
        .await
        .map_err(|e| e.to_string())?;
    match proto::read_msg(&mut c.s).await.map_err(|e| e.to_string())? {
        Msg::Ranges { done, size } => Ok((done, size, c)),
        Msg::Err { code, msg } => Err(format!("map {remote}: {code}: {msg}")),
        other => Err(format!("map {remote}: unexpected {other:?}")),
    }
}

