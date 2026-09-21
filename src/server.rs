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

async fn handle(mut s: TcpStream, peer: SocketAddr, st: Arc<State>) -> Result<(), String> {
    let addr = peer.to_string();
    let ip = peer.ip().to_canonical();
    let _ = s.set_nodelay(true);
    let hello = tokio::time::timeout(HANDSHAKE, proto::read_msg(&mut s))
        .await
        .map_err(|_| "handshake timeout".to_string())?
        .map_err(|e| e.to_string())?;
    // Invitations are the one unauthenticated entry point: they *create* trust.
    // They still have to speak our wire version, or the pair would be unusable.
    if let Msg::Invite { proto: peer_proto, from, pubkey, expires_at, note, port } = hello {
        if peer_proto != proto::PROTO {
            let reason = format!(
                "protocol mismatch: peer speaks v{peer_proto}, this device speaks v{} — upgrade the older side",
                proto::PROTO
            );
            crate::audit::log("invite", "deny", "proto", Some(&from), &addr, Some(&reason));
            let reply = Msg::Err { code: "protocol".into(), msg: reason };
            let _ = proto::write_msg(&mut s, &reply).await;
            return Ok(());
        }
        let inv = invite::Invite {
            from,
            pubkey,
            expires_at,
            note,
            // The socket address is ephemeral; keep the port the peer advertised.
            dial: invite::dialable(&addr, port),
        };
        return invite::handle(st, &mut s, addr, inv).await;
    }
    let Msg::Hello { proto: peer_proto, id, pubkey, cred, .. } = hello else {
        return Err("expected hello".into());
    };
    if peer_proto != proto::PROTO {
        let reason = format!(
            "protocol mismatch: peer speaks v{peer_proto}, this device speaks v{} — upgrade the older side",
            proto::PROTO
        );
        crate::audit::log("auth", "deny", "proto", Some(&id), &addr, Some(&reason));
        let _ = proto::write_msg(&mut s, &Msg::AuthFail { reason }).await;
        return Ok(());
    }
    let method = cred_method(&cred);

    if let Err(reason) = authenticate(&st, &id, &pubkey, &cred, ip).await {
        crate::audit::log("auth", "deny", method, Some(&id), &addr, Some(&reason));
        let _ = proto::write_msg(&mut s, &Msg::AuthFail { reason }).await;
        return Ok(());
    }
    crate::audit::log("auth", "ok", method, Some(&id), &addr, None);

    if st.cfg.code_rotate_on_connect && !st.cfg.unlimit {
        st.rotate_code(None).await;
    }

    // Proof of *our* identity for the client to pin, and reusable for the other
    // connections of the same transfer (see Cred::Session).
    let ttl = if st.cfg.session_ttl > 0 { st.cfg.session_ttl } else { 60 };
    let token = jwt::sign(&st.id, &id, identity::now() + ttl);
    let ok = Msg::HelloOk { proto: proto::PROTO, id: st.id.id.clone(), pubkey: st.id.pubkey(), token };
    proto::write_msg(&mut s, &ok).await.map_err(|e| e.to_string())?;

    let idle = idle_of(&st);
    loop {
        let msg = match next_msg(&mut s, idle, "op").await {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        let res = match msg {
            Msg::PutBegin { path, size, offset, len, truncate } => {
                put(&mut s, &st, &path, size, offset, len, truncate).await
            }
            Msg::PutEnd { path, size, mtime, sha256 } => {
                put_end(&mut s, &st, &path, size, mtime, sha256).await
            }
            Msg::GetBegin { path, offset, len } => get(&mut s, &st, &path, offset, len).await,
            Msg::List { path } => list(&mut s, &st, &path).await,
            Msg::Map { path } => map_ranges(&mut s, &st, &path).await,
            Msg::Mkdir { path } => mkdir(&mut s, &st, &path).await,
            Msg::Stat { path } => stat(&mut s, &st, &path).await,
            Msg::Del { path } => del(&mut s, &st, &path).await,
            other => Err(format!("unexpected frame: {other:?}").into()),
        };
        if let Err(e) = res {
            let reply = Msg::Err { code: e.kind.to_string(), msg: e.msg };
            proto::write_msg(&mut s, &reply).await.map_err(|e| e.to_string())?;
        }
    }
}

fn cred_method(cred: &Cred) -> &'static str {
    match cred {
        Cred::Token { .. } => "jwt",
        Cred::Code { .. } => "code",
        Cred::Session { .. } => "session",
        Cred::Any => "unlimit",
    }
}

/// Watchdog for established connections: a peer that goes silent is dropped
/// instead of pinning a task forever. `0` disables it.
fn idle_of(st: &State) -> Option<Duration> {
    (st.cfg.idle_timeout > 0).then(|| Duration::from_secs(st.cfg.idle_timeout))
}

async fn next_msg(s: &mut TcpStream, idle: Option<Duration>, what: &str) -> Result<Msg, String> {
    let read = proto::read_msg(s);
    match idle {
        None => read.await.map_err(|e| e.to_string()),
        Some(d) => match tokio::time::timeout(d, read).await {
            Ok(r) => r.map_err(|e| e.to_string()),
            Err(_) => Err(format!("{what}: no traffic for {}s", d.as_secs())),
        },
    }
}

async fn authenticate(st: &State, id: &str, pubkey: &str, cred: &Cred, ip: IpAddr) -> Result<(), String> {
    if st.cfg.unlimit {
        return Ok(());
    }
    match cred {
        Cred::Any => Err("unlimit mode is disabled on this device".into()),
        Cred::Token { token } => {
            // Reload from disk: `dtu device rm` edits trust.json from another process,
            // and a revoked device must lose access immediately, not on restart.
            let snapshot = trust_snapshot(st).await;
            let pinned = match snapshot.get(id) {
                Some(d) => d.clone(),
                None if snapshot.get_raw(id).is_some() => {
                    return Err(format!("authorization for {id} expired, pair again"))
                }
                None => return Err("unknown device, pair first".into()),
            };
            if pinned.pubkey != pubkey {
                return Err("pinned public key mismatch".into());
            }
            // The token we present is one *this* server issued, so it verifies with our own key.
            jwt::verify(&st.id.pubkey(), token, &st.id.id, id, identity::now())?;
            Ok(())
        }
        Cred::Session { token } => {
            jwt::verify(&st.id.pubkey(), token, &st.id.id, id, identity::now())?;
            // A session hangs off an authenticated device: it must still be trusted,
            // or it must belong to a code-auth session (code devices are not trusted).
            if trust_snapshot(st).await.get(id).is_some() {
                return Ok(());
            }
            let from_code = {
                let mut sessions = st.code_sessions.lock().await;
                let now = identity::now();
                sessions.retain(|_, exp| *exp > now);
                sessions.contains_key(id)
            };
            if from_code {
                Ok(())
            } else {
                Err("session belongs to a device that is no longer trusted".into())
            }
        }
        Cred::Code { code, password } => {
            {
                let mut fails = st.fails.lock().await;
                // drop ancient entries so the map cannot grow forever
                fails.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(120));
                let e = fails.entry(ip).or_insert((0, std::time::Instant::now()));
                if e.1.elapsed() > Duration::from_secs(60) {
                    *e = (0, std::time::Instant::now());
                }
                if e.0 >= MAX_CODE_FAILS {
                    return Err("too many failed attempts, wait a minute".into());
                }
            }
            let ok = {
                let c = st.code.lock().await;
                if c.code.is_empty() || (st.cfg.code_one_shot && c.consumed) {
                    return Err("no active pairing code".into());
                }
                let code_ok = identity::ct_eq(&c.code, &code.trim().to_ascii_uppercase());
                let pass_ok = match (&c.password, password) {
                    (None, _) => true,
                    (Some(p), Some(given)) => identity::ct_eq(p, given),
                    (Some(_), None) => false,
                };
                code_ok && pass_ok
            };
            if !ok {
                let mut fails = st.fails.lock().await;
                let e = fails.entry(ip).or_insert((0, std::time::Instant::now()));
                e.0 += 1;
                return Err("wrong pairing code".into());
            }
            if st.cfg.code_one_shot {
                st.code.lock().await.consumed = true;
            }
            // Remember the code-auth session so it keeps working without a trust entry.
            let exp = identity::now() + st.cfg.session_ttl.max(60);
            st.code_sessions.lock().await.insert(id.to_string(), exp);
            Ok(())
        }
    }
}

/// Trust store as another process currently sees it on disk.
async fn trust_snapshot(st: &State) -> Store {
    let mut guard = st.trust.lock().await;
    if let Some(fresh) = crate::cfg::read_json::<Store>(&cfg::file("trust.json")) {
        *guard = fresh;
    }
    guard.clone()
}

async fn put(
    s: &mut TcpStream,
    st: &State,
    path: &str,
    size: u64,
    offset: u64,
    len: u64,
    truncate: bool,
) -> Result<(), OpError> {
    let end = offset.checked_add(len).ok_or_else(|| OpError::new("range", "range overflow"))?;
    if end > size {
        return Err(OpError::new("range", format!("range {offset}..{end} outside file size {size}")));
    }
    // Bytes land in `<name>.dtu-part`; `put_end` verifies and renames into place, so
    // a reader of the served tree never sees a half-written file.
    let target = guard::part_path(&guard::resolve(&st.root, path).map_err(OpError::path)?);
    if let Some(dir) = target.parent() {
        tokio::fs::create_dir_all(dir).await.map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    let mut f = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&target)
        .await
        .map_err(|e| OpError::io(format!("open {}: {e}", target.display())))?;
    // ponytail: no cross-connection lock, so two clients pushing the same path
    // interleave per range. Add a per-path lock if that ever matters.
    if truncate {
        f.set_len(0).await.map_err(|e| e.to_string())?;
        // a fresh start invalidates whatever we remembered about this path
        st.ranges.lock().await.remove(path);
    }
    let cur = f.metadata().await.map_err(|e| e.to_string())?.len();
    // Trust the ranges this path recorded, and nothing else: the part file's *length*
    // is not a prefix. A parallel push opens its ranges at the same time, so a higher
    // range can have written past this one's start before this range begins — reading
    // the length as "already sent" would skip these bytes and silently corrupt the file.
    let start = match st.ranges.lock().await.get(path) {
        Some(done) if done.iter().any(|(ds, de)| *ds <= offset && end <= *de) => end,
        _ => offset,
    };

    proto::write_msg(s, &Msg::Resume { offset: start, size: cur, mtime: 0 }).await.map_err(|e| e.to_string())?;

    f.seek(std::io::SeekFrom::Start(start)).await.map_err(|e| e.to_string())?;
    let mut remaining = end - start;
    let mut buf = vec![0u8; BUF];
    let idle = idle_of(st);
    loop {
        let n = match next_msg(s, idle, "put").await? {
            Msg::Data { len: n } => n,
            other => return Err(OpError::new("op", format!("expected data frame, got {other:?}"))),
        };
        if n == 0 {
            break;
        }
        if n > remaining {
            // Drain exactly what the frame declared, then refuse: the connection
            // stays framed instead of re-interpreting the payload as a frame.
            let mut left = n;
            while left > 0 {
                let chunk = left.min(buf.len() as u64) as usize;
                s.read_exact(&mut buf[..chunk]).await.map_err(|e| e.to_string())?;
                left -= chunk as u64;
            }
            return Err(OpError::new("range", "client sent more bytes than the range allows"));
        }
        remaining -= n;
        let mut left = n;
        while left > 0 {
            let chunk = left.min(buf.len() as u64) as usize;
            s.read_exact(&mut buf[..chunk]).await.map_err(|e| e.to_string())?;
            f.write_all(&buf[..chunk]).await.map_err(|e| e.to_string())?;
            left -= chunk as u64;
        }
    }
    if remaining > 0 {
        return Err(OpError::new("range", format!("range ended {remaining} bytes short")));
    }
    f.flush().await.map_err(|e| e.to_string())?;
    st.ranges
        .lock()
        .await
        .entry(path.to_string())
        .or_default()
        .push((start, end));
    proto::write_msg(s, &Msg::Ok).await.map_err(|e| OpError::io(e.to_string()))
}

async fn put_end(
    s: &mut TcpStream,
    st: &State,
    path: &str,
    size: u64,
    mtime: u64,
    sha256: Option<String>,
) -> Result<(), OpError> {
    let final_path = guard::resolve(&st.root, path).map_err(OpError::path)?;
    let part = guard::part_path(&final_path);
    {
        let f = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&part)
            .await
            .map_err(|e| OpError::io(format!("open {}: {e}", guard::for_display(&part))))?;
        let cur = f.metadata().await.map_err(|e| e.to_string())?.len();
        if cur < size {
            return Err(OpError::new("incomplete", format!("incomplete upload: have {cur} of {size}")));
        }
        f.set_len(size).await.map_err(|e| e.to_string())?;
        // ponytail: no fsync here. Flushing synchronously costs ~20x on ordinary disks
        // (measured 47 MB/s vs 1.1 GB/s), and every copy tool trusts the page cache.
        // Add `.sync_all()` back if a crash within seconds must never lose a byte.
    }

    if let Some(expected) = sha256 {
        let probe = part.clone();
        let got = tokio::task::spawn_blocking(move || guard::sha256_file(&probe))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        if got != expected {
            let _ = tokio::fs::remove_file(&part).await;
            return Err(OpError::new("checksum", format!("got {got}, expected {expected} — partial discarded, retry")));
        }
    }

    tokio::fs::rename(&part, &final_path)
        .await
        .map_err(|e| OpError::io(format!("move into place {}: {e}", guard::for_display(&final_path))))?;
    st.ranges.lock().await.remove(path);
    if mtime > 0 {
        let landed = final_path.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let f = std::fs::OpenOptions::new().write(true).open(&landed)?;
            f.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(mtime))
        })
        .await;
    }
    proto::write_msg(s, &Msg::Ok).await.map_err(|e| OpError::io(e.to_string()))
}

async fn get(s: &mut TcpStream, st: &State, path: &str, offset: u64, len: u64) -> Result<(), OpError> {
    let target = guard::resolve(&st.root, path).map_err(OpError::path)?;
    let md = tokio::fs::metadata(&target).await.map_err(|e| format!("stat {}: {e}", target.display()))?;
    if md.is_dir() {
        return Err(OpError::new("isdir", "path is a directory"));
    }
    let size = md.len();
    let mtime = guard::mtime_of(md.modified().ok());
    let start = offset.min(size);
    let end = offset.saturating_add(len).min(size);

    proto::write_msg(s, &Msg::Resume { offset: start, size, mtime }).await.map_err(|e| e.to_string())?;
    let mut f = tokio::fs::File::open(&target).await.map_err(|e| e.to_string())?;
    f.seek(std::io::SeekFrom::Start(start)).await.map_err(|e| e.to_string())?;
    let mut remaining = end - start;
    let mut buf = vec![0u8; BUF];
    while remaining > 0 {
        let take = remaining.min(buf.len() as u64) as usize;
        let n = f.read(&mut buf[..take]).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        proto::send_data(s, &buf[..n]).await.map_err(|e| e.to_string())?;
        remaining -= n as u64;
    }
    proto::send_data(s, &[]).await.map_err(|e| OpError::io(e.to_string()))
}

async fn list(s: &mut TcpStream, st: &State, path: &str) -> Result<(), OpError> {
    let base = guard::resolve(&st.root, path).map_err(OpError::path)?;
    if !base.exists() {
        return Err(OpError::new("notfound", format!("no such path: {path}")));
    }
    let is_file = base.is_file();
    let rel = path.replace('\\', "/").trim_matches('/').to_string();
    let items = tokio::task::spawn_blocking(move || guard::walk(&base))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let items = items
        .into_iter()
        .map(|mut e| {
            if is_file {
                e.path = rel.clone();
            } else if !rel.is_empty() {
                e.path = format!("{rel}/{}", e.path);
            }
            e
        })
        .collect::<Vec<_>>();
    // Chunk: a big tree used to overflow MAX_CTRL and break diff/async entirely.
    let mut rest = items;
    loop {
        let tail = if rest.len() > LIST_CHUNK { rest.split_off(LIST_CHUNK) } else { Vec::new() };
        let more = !tail.is_empty();
        proto::write_msg(s, &Msg::Entries { items: rest, more })
            .await
            .map_err(|e| e.to_string())?;
        if !more {
            return Ok(());
        }
        rest = tail;
    }
}

/// Which ranges of an in-progress upload are already on disk, plus the part file size.
async fn map_ranges(s: &mut TcpStream, st: &State, path: &str) -> Result<(), OpError> {
    let target = guard::part_path(&guard::resolve(&st.root, path).map_err(OpError::path)?);
    let size = tokio::fs::metadata(&target).await.map(|m| m.len()).unwrap_or(0);
    let done = st.ranges.lock().await.get(path).cloned().unwrap_or_default();
    proto::write_msg(s, &Msg::Ranges { done, size }).await.map_err(|e| OpError::io(e.to_string()))
}

async fn mkdir(s: &mut TcpStream, st: &State, path: &str) -> Result<(), OpError> {
    let target = guard::resolve(&st.root, path).map_err(OpError::path)?;
    tokio::fs::create_dir_all(&target)
        .await
        .map_err(|e| OpError::io(format!("mkdir {}: {e}", guard::for_display(&target))))?;
    proto::write_msg(s, &Msg::Ok).await.map_err(|e| OpError::io(e.to_string()))
}

/// Read-only probe used by `--dry-run`: never creates or truncates anything.
async fn stat(s: &mut TcpStream, st: &State, path: &str) -> Result<(), OpError> {
    let target = guard::resolve(&st.root, path).map_err(OpError::path)?;
    let reply = match tokio::fs::metadata(&target).await {
        Ok(md) if md.is_file() => Msg::Resume {
            offset: 0,
            size: md.len(),
            mtime: guard::mtime_of(md.modified().ok()),
        },
        Ok(_) => Msg::Err { code: "isdir".into(), msg: "path is a directory".into() },
        Err(_) => Msg::Resume { offset: 0, size: 0, mtime: 0 },
    };
    proto::write_msg(s, &reply).await.map_err(|e| OpError::io(e.to_string()))
}

async fn del(s: &mut TcpStream, st: &State, path: &str) -> Result<(), OpError> {
    let target = guard::resolve(&st.root, path).map_err(OpError::path)?;
    if target == st.root {
        return Err(OpError::new("path", "refusing to delete the served root"));
    }
    let md = tokio::fs::symlink_metadata(&target)
        .await
        .map_err(|e| OpError::io(format!("stat {}: {e}", guard::for_display(&target))))?;
    if md.is_dir() {
        return Err(OpError::new("isdir", "path is a directory (only files can be removed)"));
    }
    tokio::fs::remove_file(&target)
        .await
        .map_err(|e| OpError::io(format!("delete {}: {e}", guard::for_display(&target))))?;
    proto::write_msg(s, &Msg::Ok).await.map_err(|e| OpError::io(e.to_string()))
}

/// The one dispatch table behind the REST surface: a frontend that links the crate
/// calls the same functions directly instead.
pub(crate) async fn control_handle(st: &Arc<State>, req: Ctrl) -> Ctrl {
    match req {
        Ctrl::Status => {
            let trusted = st.trust.lock().await.devices.len();
            let pending = st.invites.lock().await.len();
            Ctrl::StatusOk {
                id: st.id.id.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                proto: proto::PROTO,
                port: st.cfg.port,
                root: guard::for_display(&st.root),
                unlimit: st.cfg.unlimit,
                trusted,
                pending,
                uptime: identity::now().saturating_sub(st.started),
            }
        }
        Ctrl::CodeShow => code_reply(st).await,
        Ctrl::CodeRefresh { password } => {
            // Refresh only rotates the code: the password survives unless explicitly
            // cleared with an empty string.
            let update = match password {
                None => None,
                Some(p) if p.is_empty() => Some(None),
                Some(p) => Some(Some(p)),
            };
            st.rotate_code(update).await;
            code_reply(st).await
        }
        Ctrl::Invites => Ctrl::InvitesOk { items: invite::list(st).await },
        Ctrl::InviteAccept { id, expires_at } => match invite::decide(st, &id, Decision::Accept { expires_at }).await {
            Ok(()) => Ctrl::Ok { msg: format!("accepted invite {id}") },
            Err(e) => Ctrl::Err { msg: e },
        },
        Ctrl::InviteDeny { id } => match invite::decide(st, &id, Decision::Deny).await {
            Ok(()) => Ctrl::Ok { msg: format!("denied invite {id}") },
            Err(e) => Ctrl::Err { msg: e },
        },
        Ctrl::Scan { wait_ms } => {
            let trust = st.trust.lock().await.clone();
            let items = discover::scan(st.cfg.port, wait_ms, &st.id.id, &trust).await;
            Ctrl::ScanOk { items }
        }
        other => Ctrl::Err { msg: format!("unexpected request: {other:?}") },
    }
}

async fn code_reply(st: &State) -> Ctrl {
    let c = st.code.lock().await;
    Ctrl::Code { code: c.code.clone(), password: c.password.is_some(), consumed: c.consumed }
}

#[cfg(test)]
mod tests {
    // see src/core_tests.rs: the env lock is held across awaits on purpose
    #![allow(clippy::await_holding_lock)]

    use super::*;
    use crate::client::{self, Plan, Prefer, Target};
    use crate::state::Decision;

    struct Daemon {
        st: Arc<State>,
        addr: String,
    }

    fn home() -> std::path::PathBuf {
        crate::core_tests::sweep_temp();
        let dir = std::env::temp_dir().join(format!("dtu-e2e-{}", identity::random_id()));
        std::fs::create_dir_all(&dir).unwrap();
        // audit log, trust.json and default config resolve under DTU_HOME.
        std::env::set_var("DTU_HOME", &dir);
        dir
    }

    async fn spawn_daemon(home: &std::path::Path, root: &std::path::Path, code: &str) -> Daemon {
        std::fs::create_dir_all(root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = Config {
            root: root.to_string_lossy().into_owned(),
            port,
            ..Default::default()
        };
        let id = Identity::load_or_create_at(&home.join(format!("id-{port}.json"))).unwrap();
        let st = State::new(cfg, id, Store::default());
        set_code(&st, code).await;
        let serving = st.clone();
        tokio::spawn(async move { let _ = accept_loop(listener, serving).await; });
        Daemon { st, addr: format!("127.0.0.1:{port}") }
    }

    async fn set_code(st: &Arc<State>, code: &str) {
        let mut c = st.code.lock().await;
        c.code = code.to_string();
        c.consumed = false;
    }

    #[tokio::test]
    async fn end_to_end() {
        let _g = crate::core_tests::env_lock();
        let home = home();
        let root = home.join("daemon-root");
        let work = home.join("work");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(work.join("sub")).unwrap();

        let d = spawn_daemon(&home, &root, "TESTCODE").await;
        let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
        let plan = Plan { parallel: 4, resume: true , verify: true};
        let code_target = |code: &str| {
            Target::new(d.addr.clone(), Cred::Code { code: code.to_string(), password: None }, None)
        };

        // 1. pairing-code auth + push of a file and a directory
        std::fs::write(work.join("hello.txt"), b"hello world").unwrap();
        std::fs::write(work.join("sub/nested.txt"), b"nested").unwrap();
        let locals = vec![
            work.join("hello.txt").display().to_string(),
            work.join("sub").display().to_string(),
        ];
        let pushed = client::push(&code_target("TESTCODE"), me.clone(), &locals, "in", plan).await.unwrap();
        assert_eq!(pushed, vec!["in/hello.txt".to_string(), "in/sub/nested.txt".to_string()]);
        assert_eq!(std::fs::read(root.join("in/hello.txt")).unwrap(), b"hello world");
        assert_eq!(std::fs::read(root.join("in/sub/nested.txt")).unwrap(), b"nested");

        // the code is single-use: a fresh client with the same code must be rejected
        let replay = Target::new(d.addr.clone(), Cred::Code { code: "TESTCODE".into(), password: None }, None);
        assert!(client::list(&replay, &me, "in").await.is_err(), "code must be consumed");

        // 2. unknown / wrong credential is refused
        let stranger = Identity::load_or_create_at(&home.join("stranger.json")).unwrap();
        let wrong = Target::new(d.addr.clone(), Cred::Code { code: "WRONG".into(), password: None }, None);
        assert!(client::list(&wrong, &stranger, "in").await.is_err());
        let anon = Target::new(d.addr.clone(), Cred::Any, None);
        assert!(client::list(&anon, &stranger, "in").await.is_err());

        // 3. path traversal and absolute paths are rejected server side
        set_code(&d.st, "ESC").await;
        let mut c = client::connect(&code_target("ESC"), &me).await.unwrap();
        for bad in ["../../..", "/etc/passwd", "C:\\Windows"] {
            proto::write_msg(&mut c.s, &Msg::List { path: bad.into() }).await.unwrap();
            match proto::read_msg(&mut c.s).await.unwrap() {
                Msg::Err { msg, .. } => assert!(msg.contains("illegal path"), "{bad}: {msg}"),
                other => panic!("expected error for {bad}, got {other:?}"),
            }
        }
        drop(c);

        // 4. parallel push of a large file, then resume from a partial remote copy
        let payload: Vec<u8> = (0..40 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let big = work.join("big.bin");
        std::fs::write(&big, &payload).unwrap();
        set_code(&d.st, "BIG").await;
        let t = code_target("BIG");
        client::push(&t, me.clone(), &[big.display().to_string()], "in", plan).await.unwrap();
        assert_eq!(std::fs::read(root.join("in/big.bin")).unwrap().len(), payload.len());
        assert!(std::fs::read(root.join("in/big.bin")).unwrap() == payload, "parallel push corrupted the file");

        let cut = payload.len() * 2 / 5;
        std::fs::write(root.join("in/big.bin"), &payload[..cut]).unwrap();
        client::push(&t, me.clone(), &[big.display().to_string()], "in", plan).await.unwrap();
        assert!(std::fs::read(root.join("in/big.bin")).unwrap() == payload, "resume produced wrong bytes");

        // 4c. --no-resume truncates the stale remote copy first
        let short = work.join("short.txt");
        std::fs::write(&short, b"tiny").unwrap();
        let fresh = Plan { parallel: 4, resume: false , verify: true};
        client::push(&t, me.clone(), &[short.display().to_string()], "in", fresh).await.unwrap();
        std::fs::write(root.join("in/short.txt"), b"0123456789").unwrap();
        client::push(&t, me.clone(), &[short.display().to_string()], "in", fresh).await.unwrap();
        assert_eq!(std::fs::read(root.join("in/short.txt")).unwrap(), b"tiny", "--no-resume must truncate");

        // 5. pull back and compare
        let back = home.join("back");
        std::fs::create_dir_all(&back).unwrap();
        client::pull(&t, me.clone(), &["in/big.bin".to_string()], &back.display().to_string(), plan).await.unwrap();
        assert!(std::fs::read(back.join("big.bin")).unwrap() == payload, "pull produced wrong bytes");

        // 6. diff sees only the local-only file, sync pushes it
        std::fs::write(work.join("only-local.txt"), b"L").unwrap();
        let rows = client::diff(&t, &me, &work.display().to_string(), "in").await.unwrap();
        assert_eq!(rows.len(), 1, "unexpected diff: {rows:?}");
        assert_eq!(rows[0].rel, "only-local.txt");
        assert_eq!(rows[0].kind, '+');
        let log = client::sync(&t, me.clone(), &work.display().to_string(), "in", client::SyncOpts { prefer: Prefer::Newer, dry_run: false, delete: client::DeleteSide::None }, plan)
            .await
            .unwrap();
        assert_eq!(log.len(), 1, "sync: {log:?}");
        assert_eq!(std::fs::read(root.join("in/only-local.txt")).unwrap(), b"L");

        // 7. refusals are audited
        let log = std::fs::read_to_string(home.join("auth.log")).unwrap();
        assert!(log.contains("\"result\":\"deny\""), "auth log missing refusal: {log}");
        assert!(log.contains("\"result\":\"ok\""), "auth log missing success: {log}");

        // 8. invitation yields mutual trust, then plain JWT auth works
        let b_root = home.join("b-root");
        let b = spawn_daemon(&home, &b_root, "unused").await;
        let acceptor = b.st.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let pending = acceptor.invites.lock().await.first().map(|p| p.id.clone());
                if let Some(id) = pending {
                    let exp = identity::now() + 3600;
                    let _ = crate::invite::decide(&acceptor, &id, Decision::Accept { expires_at: exp }).await;
                    return;
                }
            }
        });
        let mut trust = Store::default();
        let our_port: u16 = d.addr.rsplit(':').next().and_then(|p| p.parse().ok()).expect("daemon port");
        let peer = client::invite_send(&b.addr, identity::now() + 3600, None, &me, &mut trust, our_port, |_, _| {})
            .await
            .unwrap();
        assert_eq!(peer, b.st.id.id);
        let dev = trust.get(&peer).unwrap().clone();
        assert!(!dev.token.is_empty());
        let recorded = b.st.trust.lock().await.get_raw(&me.id).cloned().expect("peer did not record us");
        assert_eq!(recorded.addr.as_deref(), Some(d.addr.as_str()), "peer must keep our dialable address, not the invite's ephemeral port");
        // Both daemons in this test share one DTU_HOME, so the caller's own save above
        // overwrote the peer's file. Real machines have separate data dirs; restore
        // this side's view so the trust reload on the next auth sees it.
        b.st.trust.lock().await.save().expect("restore trust file");

        let trusted = Target::new(b.addr.clone(), Cred::Token { token: dev.token.clone() }, Some((peer.clone(), dev.pubkey.clone())));
        let items = client::list(&trusted, &me, "").await.unwrap();
        assert!(items.is_empty(), "unexpected entries: {items:?}");
        assert!(client::push(&trusted, me.clone(), &[work.join("hello.txt").display().to_string()], "got", plan)
            .await
            .is_ok());
        assert_eq!(std::fs::read(b_root.join("got/hello.txt")).unwrap(), b"hello world");

        // a token meant for another device does not authenticate us
        let stolen = Target::new(d.addr.clone(), Cred::Token { token: dev.token.clone() }, None);
        assert!(client::list(&stolen, &me, "in").await.is_err(), "token accepted by the wrong server");

        let _ = std::fs::remove_dir_all(&home);
    }
}










