//! Deep tests for the core: framing, auth bypass attempts, path escapes,
//! transfer edge cases, protocol abuse, IPv6, control port, diff/sync semantics.
//!
//! `an_on_path_observer_cannot_read_the_wire` is the acceptance gate for transport
//! encryption (C1). It is `#[ignore]`d while the transport is plaintext; run it with
//! `cargo test -- --ignored an_on_path_observer` and it must pass once ciphertext
//! lands. The same `Relay` doubles as a tamper harness: mutate bytes in `pump` to
//! check that AEAD rejects them.
//!
//! Every test that touches `DTU_HOME` takes `env_lock()` first, because the
//! process environment is shared between parallel test threads.
//!
//! The guard is deliberately a std mutex held across awaits: each `#[tokio::test]`
//! runs on its own single-threaded runtime, so blocking a sibling test thread is
//! exactly the serialization wanted, and the holder always makes progress.
#![allow(clippy::await_holding_lock)]

use std::net::{Ipv6Addr, TcpListener as StdListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::cfg::Config;
use crate::client::{self, Plan, Prefer, Target};
use crate::guard;
use crate::identity::{self, Identity};
use crate::jwt;
use crate::proto::{self, Cred, Ctrl, Msg};
use crate::server;
use crate::state::{Decision, State};
use crate::trust::Store;

static ENV: OnceLock<Mutex<()>> = OnceLock::new();
/// Data dir of the test that held the lock last; deleted when the next one starts.
static LAST_HOME: Mutex<Option<PathBuf>> = Mutex::new(None);

#[cfg(windows)]
fn symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[cfg(unix)]
fn symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

/// `remove_dir_all` trips over files named CON/NUL unless the path is verbatim.
fn rm_dir(p: &Path) {
    #[cfg(windows)]
    {
        let _ = std::fs::remove_dir_all(format!(r"\\?\{}", p.display()));
    }
    #[cfg(not(windows))]
    {
        let _ = std::fs::remove_dir_all(p);
    }
}

pub fn env_lock() -> MutexGuard<'static, ()> {
    // Poisoning is irrelevant here: one panicking test must not wedge the rest.
    let guard = ENV.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner());
    // The previous test has released the lock, so its data dir is garbage now.
    let stale = LAST_HOME.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(dir) = stale {
        rm_dir(&dir);
    }
    guard
}

/// Remove leftovers from earlier runs, once per test process. Only touches our own
/// prefixes and only if they are older than an hour, so parallel runs are safe.
pub fn sweep_temp() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let Ok(dir) = std::env::temp_dir().read_dir() else {
            return;
        };
        let now = std::time::SystemTime::now();
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !(name.starts_with("dtu-deep-") || name.starts_with("dtu-e2e-")) {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .map(|age| age.as_secs() > 3600)
                .unwrap_or(false);
            if stale {
                rm_dir(&entry.path());
            }
        }
    });
}

fn home(tag: &str) -> PathBuf {
    sweep_temp();
    let dir = std::env::temp_dir().join(format!("dtu-deep-{tag}-{}", identity::random_id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("DTU_HOME", &dir);
    *LAST_HOME.lock().unwrap_or_else(|e| e.into_inner()) = Some(dir.clone());
    dir
}

struct Daemon {
    st: Arc<State>,
    addr: String,
}

async fn daemon_on(
    listener: TcpListener,
    home: &Path,
    root: &Path,
    code: &str,
    tune: impl FnOnce(&mut Config),
) -> Daemon {
    std::fs::create_dir_all(root).unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = Config {
        root: root.to_string_lossy().into_owned(),
        port,
        ..Default::default()
    };
    tune(&mut cfg);
    let id = Identity::load_or_create_at(&home.join(format!("d-{port}.json"))).unwrap();
    let st = State::new(cfg, id, Store::default());
    set_code(&st, code).await;
    let serving = st.clone();
    tokio::spawn(async move { let _ = server::accept_loop(listener, serving).await; });
    Daemon { st, addr: format!("127.0.0.1:{port}") }
}

async fn daemon(home: &Path, root: &Path, code: &str, tune: impl FnOnce(&mut Config)) -> Daemon {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    daemon_on(listener, home, root, code, tune).await
}

async fn set_code(st: &Arc<State>, code: &str) {
    let mut c = st.code.lock().await;
    c.code = code.to_string();
    c.consumed = false;
}

fn target(d: &Daemon, code: &str) -> Target {
    Target::new(d.addr.clone(), Cred::Code { code: code.to_string(), password: None }, None)
}

/// Authenticated connection driven by hand, so tests can send illegal frames.
async fn raw(addr: &str, cred: Cred, me: &Identity) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let hello = Msg::Hello { proto: proto::PROTO, id: me.id.clone(), pubkey: me.pubkey(), cred, nonce: 0 };
    proto::write_msg(&mut s, &hello).await.unwrap();
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::HelloOk { .. } => s,
        other => panic!("handshake should succeed, got {other:?}"),
    }
}

async fn raw_denied(addr: &str, cred: Cred, me: &Identity) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let hello = Msg::Hello { proto: proto::PROTO, id: me.id.clone(), pubkey: me.pubkey(), cred, nonce: 0 };
    proto::write_msg(&mut s, &hello).await.unwrap();
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::AuthFail { reason } => reason,
        other => panic!("expected auth failure, got {other:?}"),
    }
}

/// Push a large payload through the wire format (one frame per 4 MB at most).
async fn send_bulk(s: &mut TcpStream, data: &[u8]) {
    for piece in data.chunks((proto::MAX_DATA as usize).max(1)) {
        proto::send_data(s, piece).await.unwrap();
    }
}

/// Open one authenticated connection and keep the session token it was given.
async fn mint_session(addr: &str, cred: Cred, me: &Identity) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let hello = Msg::Hello { proto: proto::PROTO, id: me.id.clone(), pubkey: me.pubkey(), cred, nonce: 0 };
    proto::write_msg(&mut s, &hello).await.unwrap();
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::HelloOk { token, .. } => token,
        other => panic!("handshake should succeed, got {other:?}"),
    }
}

async fn expect_ok(s: &mut TcpStream) {
    match proto::read_msg(s).await.unwrap() {
        Msg::Ok => {}
        other => panic!("expected Ok, got {other:?}"),
    }
}

async fn expect_resume(s: &mut TcpStream) -> (u64, u64) {
    match proto::read_msg(s).await.unwrap() {
        Msg::Resume { offset, size, .. } => (offset, size),
        other => panic!("expected Resume, got {other:?}"),
    }
}

async fn expect_err(s: &mut TcpStream) -> String {
    expect_err_coded(s).await.1
}

/// Error kind + message, so tests can assert the machine-readable code.
async fn expect_err_coded(s: &mut TcpStream) -> (String, String) {
    match proto::read_msg(s).await.unwrap() {
        Msg::Err { code, msg } => (code, msg),
        other => panic!("expected Err, got {other:?}"),
    }
}

// ---------------------------------------------------------------- framing

#[tokio::test]
async fn framing_rejects_bad_frames() {
    use std::io::ErrorKind;

    // zero-length frame: JSON parse error, never a hang
    let (mut a, mut b) = tokio::io::duplex(64);
    a.write_all(&0u32.to_le_bytes()).await.unwrap();
    assert_eq!(proto::read_msg(&mut b).await.unwrap_err().kind(), ErrorKind::InvalidData);

    // header promises more bytes than arrive
    let (mut a, mut b) = tokio::io::duplex(64);
    a.write_all(&50u32.to_le_bytes()).await.unwrap();
    a.write_all(b"{\"t\":\"Ok\"}").await.unwrap();
    drop(a);
    assert_eq!(proto::read_msg(&mut b).await.unwrap_err().kind(), ErrorKind::UnexpectedEof);

    // outgoing chunk above the cap is refused before touching the socket
    let (mut a, _b) = tokio::io::duplex(16);
    let big = vec![0u8; (proto::MAX_DATA + 1) as usize];
    assert_eq!(proto::send_data(&mut a, &big).await.unwrap_err().kind(), ErrorKind::InvalidInput);

    // a frame right at the cap still round-trips
    let (mut a, mut b) = tokio::io::duplex(proto::MAX_DATA as usize + 1024);
    let payload = "x".repeat(proto::MAX_CTRL - 32);
    let writing = tokio::spawn(async move {
        proto::write_msg(&mut a, &Msg::List { path: payload }).await
    });
    match proto::read_msg(&mut b).await.unwrap() {
        Msg::List { path } => assert_eq!(path.len(), proto::MAX_CTRL - 32),
        other => panic!("unexpected {other:?}"),
    }
    writing.await.unwrap().unwrap();
}

// ------------------------------------------------------------------- auth

#[tokio::test]
async fn auth_code_password_and_rate_limit() {
    let _g = env_lock();
    let home = home("code");
    let d = daemon(&home, &home.join("root"), "GOODCODE", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    d.st.code.lock().await.password = Some("pw".into());

    let no_pw = raw_denied(&d.addr, Cred::Code { code: "GOODCODE".into(), password: None }, &me).await;
    assert!(no_pw.contains("wrong pairing code"), "{no_pw}");
    let bad_pw = raw_denied(&d.addr, Cred::Code { code: "GOODCODE".into(), password: Some("nope".into()) }, &me).await;
    assert!(bad_pw.contains("wrong pairing code"), "{bad_pw}");

    // correct code + password, lower case accepted
    let s = raw(&d.addr, Cred::Code { code: "goodcode".into(), password: Some("pw".into()) }, &me).await;
    drop(s);

    // one-shot: the code is gone even with the right password
    let replay = raw_denied(&d.addr, Cred::Code { code: "GOODCODE".into(), password: Some("pw".into()) }, &me).await;
    assert!(replay.contains("no active pairing code"), "{replay}");

    // per-IP throttle: five misses, then even the right code is refused
    {
        let mut c = d.st.code.lock().await;
        c.code = "RATE".into();
        c.consumed = false;
        c.password = None;
    }
    d.st.fails.lock().await.clear();
    for i in 0..5 {
        let r = raw_denied(&d.addr, Cred::Code { code: "WRONG".into(), password: None }, &me).await;
        assert!(r.contains("wrong pairing code"), "attempt {i}: {r}");
    }
    let locked = raw_denied(&d.addr, Cred::Code { code: "RATE".into(), password: None }, &me).await;
    assert!(locked.contains("too many failed attempts"), "{locked}");

    // every refusal landed in the audit log with its method
    let log = std::fs::read_to_string(home.join("auth.log")).unwrap();
    assert!(log.contains("\"result\":\"deny\""), "{log}");
    assert!(log.contains("\"method\":\"code\""), "{log}");
}

#[tokio::test]
async fn auth_tokens_are_bound_to_issuer_and_audience() {
    let _g = env_lock();
    let home = home("token");
    let d = daemon(&home, &home.join("root"), "unused", |_| {}).await;
    let a = Identity::load_or_create_at(&home.join("a.json")).unwrap();
    let c = Identity::load_or_create_at(&home.join("c.json")).unwrap();
    let now = identity::now();

    // d trusts a, using a token d itself issued for a
    let good = jwt::sign(&d.st.id, &a.id, now + 3600);
    {
        let mut t = d.st.trust.lock().await;
        t.insert(&a.id, &a.pubkey(), &good, now + 3600, None);
        t.insert(&c.id, &c.pubkey(), &jwt::sign(&d.st.id, &c.id, now + 3600), now + 3600, None);
    }
    drop(raw(&d.addr, Cred::Token { token: good.clone() }, &a).await);

    // a's token presented under c's identity: trust exists, but the audience is wrong
    let cross = raw_denied(&d.addr, Cred::Token { token: good.clone() }, &c).await;
    assert!(cross.contains("not for this device"), "{cross}");

    // claim someone else's pinned key
    let mut s = TcpStream::connect(&d.addr).await.unwrap();
    let hello = Msg::Hello { proto: proto::PROTO, id: a.id.clone(), pubkey: c.pubkey(), cred: Cred::Token { token: good.clone() }, nonce: 0 };
    proto::write_msg(&mut s, &hello).await.unwrap();
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::AuthFail { reason } => assert!(reason.contains("pinned public key"), "{reason}"),
        other => panic!("expected rejection, got {other:?}"),
    }

    // token signed by a third party: signature check fails
    let foreign = jwt::sign(&c, &a.id, now + 3600);
    let bad_sig = raw_denied(&d.addr, Cred::Token { token: foreign }, &a).await;
    assert!(bad_sig.contains("bad signature"), "{bad_sig}");

    // expired token
    let stale = jwt::sign(&d.st.id, &a.id, now - 5);
    let expired = raw_denied(&d.addr, Cred::Token { token: stale }, &a).await;
    assert!(expired.contains("expired"), "{expired}");

    // unknown device gets no detail about the token
    let stranger = Identity::load_or_create_at(&home.join("stranger.json")).unwrap();
    let unknown = raw_denied(&d.addr, Cred::Token { token: good.clone() }, &stranger).await;
    assert!(unknown.contains("unknown device"), "{unknown}");

    // a session token is not usable by another identity
    let session = jwt::sign(&d.st.id, &a.id, now + 600);
    let stolen = raw_denied(&d.addr, Cred::Session { token: session }, &stranger).await;
    assert!(stolen.contains("not for this device"), "{stolen}");
}

#[tokio::test]
async fn auth_rejects_expired_trust_records() {
    let _g = env_lock();
    let home = home("expired");
    let d = daemon(&home, &home.join("root"), "unused", |_| {}).await;
    let a = Identity::load_or_create_at(&home.join("a.json")).unwrap();
    let now = identity::now();

    let token = jwt::sign(&d.st.id, &a.id, now + 3600);
    {
        let mut t = d.st.trust.lock().await;
        t.insert(&a.id, &a.pubkey(), &token.clone(), now - 1, None);
    }
    let reason = raw_denied(&d.addr, Cred::Token { token }, &a).await;
    assert!(reason.contains("expired"), "{reason}");
    assert!(d.st.trust.lock().await.get(&a.id).is_none(), "expired device must not be usable");
}

#[tokio::test]
async fn unlimit_mode_accepts_anything_and_is_opt_in() {
    let _g = env_lock();
    let home = home("unlimit");
    let open = daemon(&home, &home.join("open"), "unused", |c| c.unlimit = true).await;
    let closed = daemon(&home, &home.join("closed"), "unused", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    // no credential at all, wrong code, all accepted while unlimit is on
    drop(raw(&open.addr, Cred::Any, &me).await);
    drop(raw(&open.addr, Cred::Code { code: "NONSENSE".into(), password: None }, &me).await);
    assert!(open.st.trust.lock().await.devices.is_empty(), "unlimit must not persist trust");

    // and nothing is accepted when it is off
    let r = raw_denied(&closed.addr, Cred::Any, &me).await;
    assert!(r.contains("unlimit mode is disabled"), "{r}");

    // unlimit invites auto-accept
    let mut trust = Store::default();
    let peer = client::invite_send(&open.addr, identity::now() + 600, None, &me, &mut trust, 47000, |_, _| {})
        .await
        .unwrap();
    assert_eq!(peer, open.st.id.id);
    assert!(open.st.trust.lock().await.devices.is_empty(), "store disabled by default");
    drop(raw(&open.addr, Cred::Token { token: trust.get(&peer).unwrap().token.clone() }, &me).await);

    // with unlimit_store_trust the peer records the device
    let keeping = daemon(&home, &home.join("keeping"), "unused", |c| {
        c.unlimit = true;
        c.unlimit_store_trust = true;
    })
    .await;
    let mut trust2 = Store::default();
    let _p2 = client::invite_send(&keeping.addr, identity::now() + 600, None, &me, &mut trust2, 47000, |_, _| {})
        .await
        .unwrap();
    let recorded = keeping.st.trust.lock().await.get_raw(&me.id).cloned().expect("peer should have recorded us");
    assert_eq!(
        recorded.addr.as_deref(),
        Some("127.0.0.1:47000"),
        "accept must keep the advertised listen port, not the invite's ephemeral one"
    );
}

// ------------------------------------------------------------- path guard

