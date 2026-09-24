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

pub async fn push(t: &Target, me: Arc<Identity>, locals: &[String], remote_dir: &str, plan: Plan) -> Result<Vec<String>, String> {
    let mut done = Vec::new();
    for (local, rel, is_dir) in expand_locals(locals)? {
        let remote = join_rel(remote_dir, &rel);
        if is_dir {
            mkdir(t, &me, &remote).await?;
        } else {
            put_one(t, me.clone(), &local, &remote, plan).await?;
        }
        done.push(remote);
    }
    Ok(done)
}

pub async fn pull(t: &Target, me: Arc<Identity>, remotes: &[String], local_dir: &str, plan: Plan) -> Result<Vec<String>, String> {
    let mut done = Vec::new();
    for spec in remotes {
        let items = strip_base(spec, list(t, &me, spec).await?);
        for (rel, e) in items {
            let local = PathBuf::from(local_dir).join(&rel);
            get_one(t, me.clone(), &e, &local, plan).await?;
            done.push(local.display().to_string());
        }
    }
    Ok(done)
}

async fn put_one(t: &Target, me: Arc<Identity>, local: &Path, remote: &str, plan: Plan) -> Result<(), String> {
    warm(t, &me).await?;
    let md = std::fs::metadata(local).map_err(|e| format!("{}: {e}", local.display()))?;
    let size = md.len();
    let mtime = guard::mtime(&md);

    // Pre-flight: ask which ranges the peer already holds. A middle hole is now
    // resumable, and a *longer* part file is still not a prefix of this one.
    let (mut done, spare) = if plan.resume {
        let (done, part, conn) = ranges_done(t, &me, remote).await?;
        if part > size {
            let begin = Msg::PutBegin { path: remote.into(), size, offset: 0, len: 0, truncate: true };
            let mut c = conn;
            proto::write_msg(&mut c.s, &begin).await.map_err(|e| e.to_string())?;
            expect_resume(&mut c.s).await?;
            proto::send_data(&mut c.s, &[]).await.map_err(|e| e.to_string())?;
            expect_ok(&mut c.s, "truncate").await?;
            (Vec::new(), c)
        } else {
            (done, conn)
        }
    } else {
        let mut c = connect(t, &me).await?;
        let begin = Msg::PutBegin { path: remote.into(), size, offset: 0, len: 0, truncate: true };
        proto::write_msg(&mut c.s, &begin).await.map_err(|e| e.to_string())?;
        expect_resume(&mut c.s).await?;
        proto::send_data(&mut c.s, &[]).await.map_err(|e| e.to_string())?;
        expect_ok(&mut c.s, "truncate").await?;
        (Vec::new(), c)
    };
    done.sort_unstable();

    let mut tasks = Vec::new();
    let mut spare = Some(spare);
    for (start, end) in ranges(size, plan.parallel) {
        // skip ranges the peer already completed
        if done.iter().any(|(ds, de)| *ds <= start && end <= *de) {
            continue;
        }
        let (t, me, local, remote) = (t.clone(), me.clone(), local.to_path_buf(), remote.to_string());
        // the probe connection is already authenticated: use it for the first range
        let conn = spare.take();
        tasks.push(tokio::spawn(async move {
            put_range(&t, &me, &local, &remote, size, (start, end), conn).await
        }));
    }
    // Hash the local file in parallel with the transfer when verification is on: it
    // only costs wall-clock time when the network is faster than a sequential read.
    let hashing = plan.verify.then(|| {
        let src = local.to_path_buf();
        tokio::task::spawn_blocking(move || guard::sha256_file(&src))
    });
    for task in tasks {
        task.await.map_err(|e| e.to_string())??;
    }
    let digest = match hashing {
        None => None,
        Some(job) => Some(job.await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?),
    };
    let mut c = connect(t, &me).await?;
    let end = Msg::PutEnd { path: remote.into(), size, mtime, sha256: digest };
    proto::write_msg(&mut c.s, &end).await.map_err(|e| e.to_string())?;
    expect_ok(&mut c.s, "put end").await
}

async fn put_range(
    t: &Target,
    me: &Identity,
    local: &Path,
    remote: &str,
    size: u64,
    range: (u64, u64),
    conn: Option<Conn>,
) -> Result<(), String> {
    let (start, end) = range;
    let mut c = match conn {
        Some(c) => c,
        None => connect(t, me).await?,
    };
    let begins = Msg::PutBegin { path: remote.into(), size, offset: start, len: end - start, truncate: false };
    proto::write_msg(&mut c.s, &begins).await.map_err(|e| e.to_string())?;
    let (offset, _) = expect_resume(&mut c.s).await?;

    let mut f = tokio::fs::File::open(local).await.map_err(|e| format!("{}: {e}", local.display()))?;
    let mut pos = offset.max(start);
    if pos < end {
        f.seek(std::io::SeekFrom::Start(pos)).await.map_err(|e| e.to_string())?;
    }
    let mut buf = vec![0u8; BUF];
    while pos < end {
        let take = ((end - pos) as usize).min(buf.len());
        f.read_exact(&mut buf[..take])
            .await
            .map_err(|e| format!("read {}: {e}", local.display()))?;
        proto::send_data(&mut c.s, &buf[..take]).await.map_err(|e| e.to_string())?;
        pos += take as u64;
    }
    proto::send_data(&mut c.s, &[]).await.map_err(|e| e.to_string())?;
    expect_ok(&mut c.s, "put range").await
}

async fn get_one(t: &Target, me: Arc<Identity>, e: &Entry, local: &Path, plan: Plan) -> Result<(), String> {
    warm(t, &me).await?;
    if e.dir {
        return tokio::fs::create_dir_all(local)
            .await
            .map_err(|err| format!("mkdir {}: {err}", local.display()));
    }
    if let Some(dir) = local.parent() {
        if !dir.as_os_str().is_empty() {
            tokio::fs::create_dir_all(dir).await.map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        }
    }
    // Same staging rule as the daemon: download into `<name>.dtu-part`, land it only
    // once it is complete, so a partial pull is resumable and never visible.
    let part = guard::part_path(local);
    // A staged file longer than the remote one cannot be a prefix of it; keeping it
    // would leave old bytes behind after the final truncate.
    if let Ok(md) = tokio::fs::metadata(&part).await {
        if md.len() > e.size {
            let f = tokio::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&part)
                .await
                .map_err(|e| format!("{}: {e}", part.display()))?;
            drop(f);
        }
    }
    if !plan.resume {
        let f = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&part)
            .await
            .map_err(|e| format!("{}: {e}", part.display()))?;
        drop(f);
    }

    let mut tasks = Vec::new();
    for (start, end) in ranges(e.size, plan.parallel) {
        let (t, me, part, remote) = (t.clone(), me.clone(), part.clone(), e.path.clone());
        let expected = e.size;
        tasks.push(tokio::spawn(async move { pull_range(&t, &me, &remote, &part, start, end, expected).await }));
    }
    for task in tasks {
        task.await.map_err(|e| e.to_string())??;
    }

    let f = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&part)
        .await
        .map_err(|e| format!("{}: {e}", part.display()))?;
    f.set_len(e.size).await.map_err(|e| e.to_string())?;
    drop(f);
    if e.mtime > 0 {
        let (part, mtime) = (part.clone(), e.mtime);
        let _ = tokio::task::spawn_blocking(move || {
            let f = std::fs::OpenOptions::new().write(true).open(&part)?;
            f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime))
        })
        .await;
    }
    tokio::fs::rename(&part, local)
        .await
        .map_err(|e| format!("move into place {}: {e}", local.display()))?;
    Ok(())
}

async fn pull_range(
    t: &Target,
    me: &Identity,
    remote: &str,
    local: &Path,
    start: u64,
    end: u64,
    expected: u64,
) -> Result<(), String> {
    // Resume from what the local partial already holds, clamped into this range.
    let have = tokio::fs::metadata(local).await.map(|m| m.len()).unwrap_or(0);
    let from = have.clamp(start, end);
    if from >= end {
        return Ok(());
    }
    let mut c = connect(t, me).await?;
    proto::write_msg(&mut c.s, &Msg::GetBegin { path: remote.into(), offset: from, len: end - from })
        .await
        .map_err(|e| e.to_string())?;
    let (offset, size) = expect_resume(&mut c.s).await?;
    // The size came from a listing snapshot; if the peer rewrote the file since,
    // writing what we fetch would leave a torn file. Refuse instead.
    if size != expected {
        return Err(format!("{remote} changed size while transferring ({size} != {expected}), re-run the command"));
    }

    let mut f = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(local)
        .await
        .map_err(|e| format!("{}: {e}", local.display()))?;
    let mut pos = offset.max(start);
    if pos < end {
        f.seek(std::io::SeekFrom::Start(pos)).await.map_err(|e| e.to_string())?;
    }
    let mut buf = vec![0u8; BUF];
    loop {
        let n = match proto::read_msg(&mut c.s).await.map_err(|e| e.to_string())? {
            Msg::Data { len } => len,
            Msg::Err { code, msg } => return Err(format!("{code}: {msg}")),
            other => return Err(format!("expected data, got {other:?}")),
        };
        if n == 0 {
            break;
        }
        if n > end.saturating_sub(pos) {
            return Err("server sent more bytes than requested".into());
        }
        let mut left = n;
        while left > 0 {
            let take = left.min(buf.len() as u64) as usize;
            c.s.read_exact(&mut buf[..take]).await.map_err(|e| e.to_string())?;
            f.write_all(&buf[..take]).await.map_err(|e| e.to_string())?;
            left -= take as u64;
        }
        pos += n;
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Row {
    pub rel: String,
    /// '+' local only, '-' remote only, '~' differs
    pub kind: char,
    pub local: u64,
    pub remote: u64,
    pub local_mtime: u64,
    pub remote_mtime: u64,
    /// Directories are compared by existence only.
    pub dir: bool,
}

pub async fn diff(t: &Target, me: &Identity, local_root: &str, remote: &str) -> Result<Vec<Row>, String> {
    // A destination that does not exist yet is simply empty: the first `async` into a
    // fresh directory should push everything instead of failing with "no such path".
    let remote_entries = match list(t, me, remote).await {
        Ok(items) => items,
        Err(e) if e.contains("no such path") => Vec::new(),
        Err(e) => return Err(e),
    };
    let rmap: BTreeMap<String, Entry> = strip_base(remote, remote_entries).into_iter().collect();
    let lmap: BTreeMap<String, Entry> = guard::walk(&PathBuf::from(local_root))
        .map_err(|e| format!("{local_root}: {e}"))?
        .into_iter()
        .map(|e| (e.path.clone(), e))
        .collect();

    let mut rows = Vec::new();
    for (rel, r) in &rmap {
        match lmap.get(rel) {
            None => rows.push(Row {
                rel: rel.clone(),
                kind: '-',
                local: 0,
                remote: r.size,
                local_mtime: 0,
                remote_mtime: r.mtime,
                dir: r.dir,
            }),
            Some(l) => {
                // a directory is either there on both sides or it is a one-sided row
                let differs = if l.dir || r.dir {
                    l.dir != r.dir
                } else {
                    l.size != r.size || l.mtime.abs_diff(r.mtime) > 1
                };
                if differs {
                    rows.push(Row {
                        rel: rel.clone(),
                        kind: '~',
                        local: l.size,
                        remote: r.size,
                        local_mtime: l.mtime,
                        remote_mtime: r.mtime,
                        dir: l.dir,
                    });
                }
            }
        }
    }
    for (rel, l) in &lmap {
        if !rmap.contains_key(rel) {
            rows.push(Row {
                rel: rel.clone(),
                kind: '+',
                local: l.size,
                remote: 0,
                local_mtime: l.mtime,
                remote_mtime: 0,
                dir: l.dir,
            });
        }
    }
    rows.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(rows)
}

/// Remove one file on the peer.
pub async fn del(t: &Target, me: &Identity, path: &str) -> Result<(), String> {
    warm(t, me).await?;
    let mut c = connect(t, me).await?;
    proto::write_msg(&mut c.s, &Msg::Del { path: path.to_string() })
        .await
        .map_err(|e| e.to_string())?;
    expect_ok(&mut c.s, "delete").await
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Prefer {
    Newer,
    Local,
    Remote,
}

impl Prefer {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "newer" | "mtime" => Ok(Prefer::Newer),
            "local" => Ok(Prefer::Local),
            "remote" => Ok(Prefer::Remote),
            other => Err(format!("unknown prefer mode {other:?} (newer|local|remote)")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DeleteSide {
    None,
    Local,
    Remote,
}

impl DeleteSide {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "none" | "off" => Ok(DeleteSide::None),
            "local" => Ok(DeleteSide::Local),
            "remote" => Ok(DeleteSide::Remote),
            other => Err(format!("unknown delete side {other:?} (none|local|remote)")),
        }
    }
}

/// How `sync` resolves a difference and what it does with one-sided files.
#[derive(Clone, Copy, Debug)]
pub struct SyncOpts {
    pub prefer: Prefer,
    pub dry_run: bool,
    pub delete: DeleteSide,
}

/// One-way-per-file reconciliation of local and remote trees.
pub async fn sync(
    t: &Target,
    me: Arc<Identity>,
    local_root: &str,
    remote: &str,
    opts: SyncOpts,
    plan: Plan,
) -> Result<Vec<String>, String> {
    let (prefer, dry, delete) = (opts.prefer, opts.dry_run, opts.delete);
    let mut log = Vec::new();
    let rows = diff(t, &me, local_root, remote).await?;
    for row in &rows {
        let pull_side = match row.kind {
            '+' => false,
            '-' => true,
            _ => match prefer {
                Prefer::Local => false,
                Prefer::Remote => true,
                Prefer::Newer => row.remote_mtime > row.local_mtime,
            },
        };
        let line = format!(
            "{}\t{}\tlocal={} remote={}",
            if pull_side { "pull" } else { "push" },
            row.rel,
            row.local,
            row.remote
        );
        if dry {
            log.push(format!("{line}  (dry run)"));
            continue;
        }
        let local = PathBuf::from(local_root).join(&row.rel);
        if row.dir {
            if pull_side {
                tokio::fs::create_dir_all(&local)
                    .await
                    .map_err(|e| format!("mkdir {}: {e}", local.display()))?;
            } else {
                mkdir(t, &me, &join_rel(remote, &row.rel)).await?;
            }
            log.push(format!("{}\tdir\t{}", if pull_side { "pull" } else { "push" }, row.rel));
            continue;
        }
        if pull_side {
            let entry = Entry {
                path: join_rel(remote, &row.rel),
                size: row.remote,
                mtime: row.remote_mtime,
                dir: false,
            };
            get_one(t, me.clone(), &entry, &local, plan).await?;
        } else {
            put_one(t, me.clone(), &local, &join_rel(remote, &row.rel), plan).await?;
        }
        log.push(line);
    }

    // Deletions run after the transfers, so a half-finished sync never removes the
    // only copy of something.
    if delete == DeleteSide::None || dry {
        return Ok(log);
    }
    for row in &rows {
        // only files are removed; directory rows are left to the operator
        if row.dir {
            continue;
        }
        let doomed_local = delete == DeleteSide::Local && row.kind == '+';
        let doomed_remote = delete == DeleteSide::Remote && row.kind == '-';
        if doomed_local {
            let local = PathBuf::from(local_root).join(&row.rel);
            tokio::fs::remove_file(&local).await.map_err(|e| format!("delete {}: {e}", local.display()))?;
            log.push(format!("del(remote side wins)\t{}", row.rel));
        } else if doomed_remote {
            del(t, &me, &join_rel(remote, &row.rel)).await?;
            log.push(format!("del(remote)\t{}", row.rel));
        }
    }
    Ok(log)
}

/// Send an invitation and wait for the peer's decision, then store mutual trust.
/// `listen_port` is our own listening port, sent so the peer can keep a dialable
/// address for us instead of the ephemeral port this connection uses.
pub async fn invite_send(
    addr: &str,
    expires_at: u64,
    note: Option<String>,
    me: &Identity,
    trust: &mut Store,
    listen_port: u16,
    on_pending: impl FnOnce(&str, &str),
) -> Result<String, String> {
    let mut s = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("connect {addr}: timeout"))?
        .map_err(|e| format!("connect {addr}: {e}"))?;
    let inv = Msg::Invite { proto: proto::PROTO, from: me.id.clone(), pubkey: me.pubkey(), expires_at, note, port: listen_port };
    proto::write_msg(&mut s, &inv).await.map_err(|e| e.to_string())?;

    let (peer, peer_pub) = match proto::read_msg(&mut s).await.map_err(|e| e.to_string())? {
        Msg::InvitePending { proto: peer_proto, id, peer, pubkey } => {
            if peer_proto != proto::PROTO {
                return Err(format!(
                    "protocol mismatch: peer speaks v{peer_proto}, this build speaks v{} — upgrade the older side",
                    proto::PROTO
                ));
            }
            on_pending(&id, &peer);
            (peer, pubkey)
        }
        Msg::Err { code, msg } => return Err(format!("{code}: {msg}")),
        other => return Err(format!("unexpected reply: {other:?}")),
    };

    match proto::read_msg(&mut s).await.map_err(|e| e.to_string())? {
        Msg::Accept { token } => {
            let claims = jwt::verify(&peer_pub, &token, &peer, &me.id, identity::now())?;
            let mine = jwt::sign(me, &peer, expires_at.max(claims.exp));
            proto::write_msg(&mut s, &Msg::InviteDone { token: mine }).await.map_err(|e| e.to_string())?;
            expect_ok(&mut s, "invite").await?;
            trust.insert(&peer, &peer_pub, &token, claims.exp, Some(addr.to_string()));
            trust.save()?;
            Ok(peer)
        }
        Msg::Deny { reason } => Err(format!("denied: {}", reason.unwrap_or_default())),
        Msg::Err { code, msg } => Err(format!("{code}: {msg}")),
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_splitting() {
        assert_eq!(ranges(0, 4), vec![(0, 0)]);
        assert_eq!(ranges(100, 4), vec![(0, 100)]);
        let r = ranges(100 * CHUNK_MIN, 4);
        assert_eq!(r.len(), 4);
        assert_eq!(r[0].0, 0);
        assert_eq!(r[3].1, 100 * CHUNK_MIN);
        assert!(r.windows(2).all(|w| w[0].1 == w[1].0), "ranges must tile: {r:?}");
        // 12 chunks worth of data over 4 streams -> 4 equal ranges
        let r = ranges(12 * CHUNK_MIN, 4);
        assert_eq!(r.len(), 4);
        assert!(r.iter().all(|(s, e)| e - s == 3 * CHUNK_MIN));
    }

    #[test]
    fn addr_normalization() {
        assert_eq!(normalize_addr("host", 47000), "host:47000");
        assert_eq!(normalize_addr("host:1234", 47000), "host:1234");
        assert_eq!(normalize_addr("http://host:1234/", 47000), "host:1234");
        assert_eq!(normalize_addr("1.2.3.4", 47000), "1.2.3.4:47000");
        assert_eq!(normalize_addr("::1", 47000), "[::1]:47000");
        assert_eq!(normalize_addr("[::1]:99", 47000), "[::1]:99");
        assert_eq!(normalize_addr("[fe80::1%12]", 47000), "[fe80::1%12]:47000");
    }
}



