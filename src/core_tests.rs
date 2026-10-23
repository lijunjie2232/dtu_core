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

#[tokio::test]
async fn path_guard_blocks_every_escape_it_can() {
    let _g = env_lock();
    let home = home("paths");
    let root = home.join("root");
    std::fs::create_dir_all(root.join("ok")).unwrap();
    let d = daemon(&home, &root, "PATHS", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    let mut s = raw(&d.addr, Cred::Code { code: "PATHS".into(), password: None }, &me).await;

    for bad in [
        "../secret",
        "a/../../secret",
        "..",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "\\\\?\\C:\\Windows",
        "\\\\.\\pipe\\x",
        "//server/share/x",
        "..\\..\\secret",
    ] {
        proto::write_msg(&mut s, &Msg::List { path: bad.into() }).await.unwrap();
        let msg = expect_err(&mut s).await;
        assert!(msg.contains("path"), "{bad:?} gave {msg}");
    }

    // normal relative paths still work through the same connection
    proto::write_msg(&mut s, &Msg::List { path: "ok".into() }).await.unwrap();
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::Entries { items, .. } => assert!(items.is_empty()),
        other => panic!("expected entries, got {other:?}"),
    }

    // write attempts through traversal are refused too
    let begin = Msg::PutBegin { path: "../outside.bin".into(), size: 1, offset: 0, len: 1, truncate: true };
    proto::write_msg(&mut s, &begin).await.unwrap();
    assert!(expect_err(&mut s).await.contains("path"));
    assert!(!home.join("outside.bin").exists(), "traversal must not write outside the root");
}

#[tokio::test]
async fn path_guard_rejects_symlink_escape_when_available() {
    let _g = env_lock();
    let home = home("link");
    let root = home.join("root");
    let outside = home.join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"secret").unwrap();

    // creating links needs privileges on Windows; skip when unavailable
    let linked = symlink_dir(&outside, &root.join("link")).is_ok();
    if !linked {
        eprintln!("skipping: cannot create symlinks in this environment");
        return;
    }

    assert!(guard::resolve(&root, "link/secret.txt").is_err(), "symlink escape must be refused");
    // walk never follows links out of the tree
    let entries = guard::walk(&root).unwrap();
    assert!(entries.iter().all(|e| !e.path.contains("secret")), "{entries:?}");
}

// -------------------------------------------------------- transfer edges

#[tokio::test]
async fn transfer_edge_cases() {
    let _g = env_lock();
    let home = home("edge");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "EDGE", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "EDGE");
    let plan = Plan { parallel: 4, resume: true , verify: false};

    // empty file over stale remote content must end up empty
    std::fs::create_dir_all(root.join("e")).unwrap();
    std::fs::write(root.join("e/empty.bin"), b"stale bytes here").unwrap();
    std::fs::write(work.join("empty.bin"), b"").unwrap();
    client::push(&t, me.clone(), &[work.join("empty.bin").display().to_string()], "e", plan)
        .await
        .unwrap();
    assert_eq!(std::fs::read(root.join("e/empty.bin")).unwrap().len(), 0);

    // one byte, and a non-ASCII name
    std::fs::write(work.join("one.bin"), b"x").unwrap();
    std::fs::write(work.join("报告 α.txt"), b"unicode payload").unwrap();
    let locals = vec![
        work.join("one.bin").display().to_string(),
        work.join("报告 α.txt").display().to_string(),
    ];
    client::push(&t, me.clone(), &locals, "e", plan).await.unwrap();
    assert_eq!(std::fs::read(root.join("e/one.bin")).unwrap(), b"x");
    assert_eq!(std::fs::read(root.join("e/报告 α.txt")).unwrap(), b"unicode payload");

    // a tree: 5 dirs x 6 files, nested three levels deep
    let tree = work.join("tree");
    let mut expected = Vec::new();
    for i in 0..5 {
        for j in 0..6 {
            let dir = tree.join(format!("d{i}/n{j}/leaf"));
            std::fs::create_dir_all(&dir).unwrap();
            let body = format!("file {i}-{j}");
            std::fs::write(dir.join("f.txt"), &body).unwrap();
            expected.push((format!("d{i}/n{j}/leaf/f.txt"), body));
        }
    }
    client::push(&t, me.clone(), &[tree.display().to_string()], "deep", plan).await.unwrap();
    assert_eq!(
        guard::walk(&root.join("deep/tree")).unwrap().iter().filter(|e| !e.dir).count(),
        expected.len()
    );
    for (rel, body) in &expected {
        let got = std::fs::read_to_string(root.join("deep/tree").join(rel)).unwrap();
        assert_eq!(&got, body, "{rel}");
    }

    // pulling into a directory that does not exist yet
    let out = home.join("out/nested");
    client::pull(&t, me.clone(), &["e/报告 α.txt".to_string()], &out.display().to_string(), plan)
        .await
        .unwrap();
    assert_eq!(std::fs::read(out.join("报告 α.txt")).unwrap(), b"unicode payload");
}

#[tokio::test]
async fn resume_survives_a_real_disconnect() {
    let _g = env_lock();
    let home = home("resume");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "RESUME", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let me_raw = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    let payload: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 253) as u8).collect();
    let local = work.join("big.bin");
    std::fs::write(&local, &payload).unwrap();

    // hand-driven upload that dies halfway (no end-of-stream marker)
    let mut s = raw(&d.addr, Cred::Code { code: "RESUME".into(), password: None }, &me_raw).await;
    let size = payload.len() as u64;
    let begin = Msg::PutBegin { path: "big.bin".into(), size, offset: 0, len: size, truncate: true };
    proto::write_msg(&mut s, &begin).await.unwrap();
    assert_eq!(expect_resume(&mut s).await.0, 0);
    proto::send_data(&mut s, &payload[..1024 * 1024]).await.unwrap();
    drop(s); // abrupt disconnect
    tokio::time::sleep(Duration::from_millis(100)).await;

    let partial = std::fs::metadata(guard::part_path(&root.join("big.bin"))).unwrap().len();
    assert!(partial >= 1024 * 1024 && partial < size, "partial file expected, got {partial}");

    // a normal push resumes from wherever the bytes stopped
    set_code(&d.st, "RESUME2").await;
    let t = Target::new(d.addr.clone(), Cred::Code { code: "RESUME2".into(), password: None }, None);
    client::push(&t, me, &[local.display().to_string()], "", Plan { parallel: 4, resume: true , verify: false})
        .await
        .unwrap();
    assert!(std::fs::read(root.join("big.bin")).unwrap() == payload, "resume corrupted the file");
}

#[tokio::test]
async fn protocol_abuse_is_answered_with_errors() {
    let _g = env_lock();
    let home = home("abuse");
    let root = home.join("root");
    let d = daemon(&home, &root, "ABUSE", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    // byte ranges are validated, no overflow/panic
    let mut s = raw(&d.addr, Cred::Code { code: "ABUSE".into(), password: None }, &me).await;
    let overflow = Msg::PutBegin { path: "o.bin".into(), size: 10, offset: u64::MAX, len: 10, truncate: false };
    proto::write_msg(&mut s, &overflow).await.unwrap();
    assert!(expect_err(&mut s).await.contains("overflow"));

    // declaring a range of zero bytes over a stale file, then lying about the size
    let begin = Msg::PutBegin { path: "p.bin".into(), size: 100, offset: 0, len: 4, truncate: true };
    proto::write_msg(&mut s, &begin).await.unwrap();
    assert_eq!(expect_resume(&mut s).await.0, 0);
    proto::send_data(&mut s, b"abcd").await.unwrap();
    proto::send_data(&mut s, &[]).await.unwrap();
    expect_ok(&mut s).await;
    proto::write_msg(&mut s, &Msg::PutEnd { path: "p.bin".into(), size: 100, mtime: 0, sha256: None }).await.unwrap();
    assert!(expect_err(&mut s).await.contains("incomplete"));
    assert_eq!(std::fs::metadata(guard::part_path(&root.join("p.bin"))).unwrap().len(), 4);

    // listing a non-existent path
    proto::write_msg(&mut s, &Msg::List { path: "nope".into() }).await.unwrap();
    assert!(expect_err(&mut s).await.contains("no such path"));

    // reading past EOF returns an empty stream, not an error or a hang
    std::fs::write(root.join("small.txt"), b"12345").unwrap();
    let get = Msg::GetBegin { path: "small.txt".into(), offset: 1000, len: 10 };
    proto::write_msg(&mut s, &get).await.unwrap();
    let (offset, size) = expect_resume(&mut s).await;
    assert_eq!((offset, size), (5, 5));
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::Data { len } => assert_eq!(len, 0),
        other => panic!("expected end of stream, got {other:?}"),
    }

    // writing more bytes than the declared range is refused
    let begin = Msg::PutBegin { path: "q.bin".into(), size: 4, offset: 0, len: 4, truncate: true };
    proto::write_msg(&mut s, &begin).await.unwrap();
    expect_resume(&mut s).await;
    proto::send_data(&mut s, b"0123456789").await.unwrap();
    assert!(expect_err(&mut s).await.contains("more bytes"));

    // the stream stayed framed: the same connection keeps working
    proto::write_msg(&mut s, &Msg::List { path: String::new() }).await.unwrap();
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::Entries { items, .. } => assert!(items.iter().any(|e| e.path == "small.txt"), "{items:?}"),
        other => panic!("connection desynced after an overrun: {other:?}"),
    }

    // unknown frames and bare garbage close the connection instead of wedging it
    set_code(&d.st, "ABUSE2").await;
    let session = mint_session(&d.addr, Cred::Code { code: "ABUSE2".into(), password: None }, &me).await;
    let mut t = raw(&d.addr, Cred::Session { token: session }, &me).await;
    t.write_all(&5u32.to_le_bytes()).await.unwrap();
    t.write_all(b"garba").await.unwrap();
    assert!(proto::read_msg(&mut t).await.is_err(), "garbage must close the connection");
}

// ------------------------------------------------------------------ ipv6

#[tokio::test]
async fn ipv6_end_to_end() {
    let _g = env_lock();
    let home = home("v6");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();

    let listener = match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("skipping: no IPv6 loopback ({e})");
            return;
        }
    };
    let port = listener.local_addr().unwrap().port();
    let d = daemon_on(listener, &home, &root, "V6", |_| {}).await;
    let addr = format!("[::1]:{port}");
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let plan = Plan { parallel: 2, resume: true , verify: false};

    std::fs::write(work.join("v6.txt"), b"over ipv6").unwrap();
    let t = Target::new(addr.clone(), Cred::Code { code: "V6".into(), password: None }, None);
    client::push(&t, me.clone(), &[work.join("v6.txt").display().to_string()], "in", plan)
        .await
        .unwrap();
    assert_eq!(std::fs::read(root.join("in/v6.txt")).unwrap(), b"over ipv6");

    let items = client::list(&t, &me, "in").await.unwrap();
    assert_eq!(items.len(), 1);

    let back = home.join("back");
    client::pull(&t, me, &["in/v6.txt".to_string()], &back.display().to_string(), plan)
        .await
        .unwrap();
    assert_eq!(std::fs::read(back.join("v6.txt")).unwrap(), b"over ipv6");
    assert_eq!(d.st.cfg.port, port);
}

// ------------------------------------------------------- in-process core

#[tokio::test]
async fn the_core_answers_requests_in_process() {
    let _g = env_lock();
    let home = home("reqs");
    let cfg = Config {
        root: home.join("root").to_string_lossy().into_owned(),
        ..Default::default()
    };
    let id = Identity::load_or_create_at(&home.join("d.json")).unwrap();
    let st = State::new(cfg, id, Store::default());

    match server::control_handle(&st, Ctrl::Status).await {
        Ctrl::StatusOk { id: got, version, proto, trusted, pending, .. } => {
            assert_eq!(got, st.id.id);
            assert_eq!((trusted, pending), (0, 0));
            assert_eq!(proto, proto::PROTO);
            assert!(!version.is_empty(), "status should report the build version");
        }
        other => panic!("unexpected {other:?}"),
    }
    // a refresh rotates the code and keeps the password it was given
    match server::control_handle(&st, Ctrl::CodeRefresh { password: Some("pw".into()) }).await {
        Ctrl::Code { password, consumed, code } => {
            assert!(password);
            assert!(!consumed);
            assert_eq!(code.len(), 8);
        }
        other => panic!("unexpected {other:?}"),
    }
    match server::control_handle(&st, Ctrl::Invites).await {
        Ctrl::InvitesOk { items } => assert!(items.is_empty()),
        other => panic!("unexpected {other:?}"),
    }
}

// --------------------------------------------------------- diff and sync

#[tokio::test]
async fn diff_and_sync_resolve_conflicts_predictably() {
    let _g = env_lock();
    let home = home("sync");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(work.join("sub")).unwrap();
    let d = daemon(&home, &root, "SYNC", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "SYNC");
    let plan = Plan { parallel: 4, resume: true , verify: false};

    std::fs::write(work.join("same.txt"), b"identical").unwrap();
    std::fs::write(work.join("conflict.txt"), b"local-side").unwrap();
    std::fs::write(work.join("sub/local-only.txt"), b"only here").unwrap();
    let locals = vec![work.join("same.txt").display().to_string(), work.join("sub").display().to_string()];
    client::push(&t, me.clone(), &locals, "s", plan).await.unwrap();

    // remote gets a different, explicitly newer version of conflict.txt
    std::fs::write(root.join("s/conflict.txt"), b"remote-side-newer").unwrap();
    let f = std::fs::OpenOptions::new().write(true).open(root.join("s/conflict.txt")).unwrap();
    f.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(identity::now() + 500)).unwrap();
    drop(f);

    // remote-only file shows up as '-', a file created after the push shows up as '+'
    std::fs::write(root.join("s/remote-only.txt"), b"remote").unwrap();
    std::fs::write(work.join("late.txt"), b"appeared later").unwrap();

    let rows = client::diff(&t, &me, &work.display().to_string(), "s").await.unwrap();
    let kinds: Vec<(char, &str)> = rows.iter().map(|r| (r.kind, r.rel.as_str())).collect();
    assert!(kinds.contains(&('~', "conflict.txt")), "{kinds:?}");
    assert!(kinds.contains(&('-', "remote-only.txt")), "{kinds:?}");
    assert!(kinds.contains(&('+', "late.txt")), "{kinds:?}");
    assert!(!kinds.iter().any(|(_, r)| *r == "same.txt"), "identical files must not be listed");
    assert!(!kinds.iter().any(|(_, r)| *r == "sub/local-only.txt"), "synced files must not be listed");

    // newest wins: the remote copy is newer, so it is pulled
    let act = client::sync(&t, me.clone(), &work.display().to_string(), "s", client::SyncOpts { prefer: Prefer::Newer, dry_run: true, delete: client::DeleteSide::None }, plan)
        .await
        .unwrap();
    assert!(act.iter().any(|l| l.starts_with("pull") && l.contains("conflict.txt")), "{act:?}");

    client::sync(&t, me.clone(), &work.display().to_string(), "s", client::SyncOpts { prefer: Prefer::Newer, dry_run: false, delete: client::DeleteSide::None }, plan)
        .await
        .unwrap();
    assert_eq!(std::fs::read(work.join("conflict.txt")).unwrap(), b"remote-side-newer");
    assert_eq!(std::fs::read(work.join("remote-only.txt")).unwrap(), b"remote");
    assert_eq!(std::fs::read(root.join("s/late.txt")).unwrap(), b"appeared later");
    assert_eq!(std::fs::read(root.join("s/sub/local-only.txt")).unwrap(), b"only here");
    assert!(client::diff(&t, &me, &work.display().to_string(), "s").await.unwrap().is_empty());

    // Prefer::Local forces a push even when the remote is newer
    std::fs::write(work.join("conflict.txt"), b"forced-local").unwrap();
    client::sync(&t, me.clone(), &work.display().to_string(), "s", client::SyncOpts { prefer: Prefer::Local, dry_run: false, delete: client::DeleteSide::None }, plan)
        .await
        .unwrap();
    assert_eq!(std::fs::read(root.join("s/conflict.txt")).unwrap(), b"forced-local");

    // Prefer::Remote forces a pull
    std::fs::write(work.join("conflict.txt"), b"local-again").unwrap();
    client::sync(&t, me.clone(), &work.display().to_string(), "s", client::SyncOpts { prefer: Prefer::Remote, dry_run: false, delete: client::DeleteSide::None }, plan)
        .await
        .unwrap();
    assert_eq!(std::fs::read(work.join("conflict.txt")).unwrap(), b"forced-local");
}

// --------------------------------------------------------- client helpers

#[tokio::test]
async fn client_helpers_behave_on_edges() {
    let _g = env_lock();

    // range splitting must tile the file exactly, for any size and width
    for size in [0u64, 1, 7, client::CHUNK_MIN - 1, client::CHUNK_MIN, client::CHUNK_MIN + 1, 3 * client::CHUNK_MIN, 10 * client::CHUNK_MIN + 123] {
        for parallel in [0usize, 1, 2, 4, 16] {
            let r = client::ranges(size, parallel);
            assert!(!r.is_empty(), "size={size} p={parallel}");
            if size == 0 {
                assert_eq!(r, vec![(0, 0)]);
                continue;
            }
            assert_eq!(r[0].0, 0, "size={size} p={parallel}");
            assert_eq!(r.last().unwrap().1, size, "size={size} p={parallel}");
            assert!(r.windows(2).all(|w| w[0].1 == w[1].0), "gap at {r:?}");
            assert!(r.len() <= parallel.max(1), "too many streams: {r:?}");
        }
    }

    // address forms a human might type
    for (input, expected) in [
        ("host", 47000),
        ("host:99", 99),
        ("1.2.3.4", 47000),
        ("http://host:1234/", 1234),
        ("https://host", 47000),
        ("::1", 47000),
        ("[::1]", 47000),
        ("[::1]:88", 88),
        ("[fe80::1%12]", 47000),
    ] {
        let got = client::normalize_addr(input, 47000);
        assert_eq!(got, format!("{}:{}", got.rsplit_once(':').map(|(h, _)| h).unwrap_or(&got), expected), "{input} -> {got}");
        assert!(got.ends_with(&format!(":{expected}")), "{input} -> {got}");
    }

    // peer resolution: trusted, expired, unknown, trusted-without-address
    let cfg = Config::default();
    let now = identity::now();
    let mut trust = Store::default();
    trust.insert("dev1", "key1", "tok1", now + 600, Some("1.2.3.4:47000".into()));
    trust.insert("old", "key2", "tok2", now - 10, Some("1.2.3.5:47000".into()));
    trust.insert("noaddr", "key3", "tok3", 0, None);

    let ok = Target::resolve(&cfg, &trust, "dev1", None, None).unwrap();
    assert_eq!(ok.addr, "1.2.3.4:47000");
    assert_eq!(ok.pin, Some(("dev1".to_string(), "key1".to_string())));
    assert!(matches!(ok.cred, Cred::Token { .. }));

    assert!(Target::resolve(&cfg, &trust, "old", None, None).unwrap_err().contains("expired"));
    assert!(Target::resolve(&cfg, &trust, "ghost", None, None).unwrap_err().contains("not trusted"));
    assert!(Target::resolve(&cfg, &trust, "noaddr", None, None).unwrap_err().contains("no known address"));
    let by_addr = Target::resolve(&cfg, &trust, "10.0.0.9:5000", Some("ABCD"), None).unwrap();
    assert_eq!(by_addr.addr, "10.0.0.9:5000");
    assert!(by_addr.pin.is_none());

    // an alias stands in for the id everywhere a peer is named
    trust.set_alias("dev1", Some("laptop")).unwrap();
    let by_alias = Target::resolve(&cfg, &trust, "LAPTOP", None, None).unwrap();
    assert_eq!(by_alias.addr, "1.2.3.4:47000");
    assert_eq!(by_alias.pin, Some(("dev1".to_string(), "key1".to_string())));
    assert_eq!(trust.resolve("laptop").map(|(id, _)| id), Some("dev1"));
    // unique: neither another device's alias nor any device id is allowed
    assert!(trust.set_alias("noaddr", Some("Laptop")).unwrap_err().contains("already used"));
    assert!(trust.set_alias("noaddr", Some("old")).unwrap_err().contains("device id"));
    // re-pairing keeps our name, and an empty name clears it
    trust.insert("dev1", "key1b", "tok1b", now + 600, None);
    assert_eq!(trust.devices["dev1"].alias.as_deref(), Some("laptop"));
    trust.set_alias("dev1", Some("")).unwrap();
    assert!(trust.devices["dev1"].alias.is_none());

    // preference parsing
    assert_eq!(Prefer::parse("newer").unwrap(), Prefer::Newer);
    assert_eq!(Prefer::parse("LOCAL").unwrap(), Prefer::Local);
    assert!(Prefer::parse("whatever").is_err());
}

// -------------------------------------------------------- code rotation

#[tokio::test]
async fn rotating_the_code_invalidates_the_old_one() {
    let _g = env_lock();
    let home = home("rotate");
    let d = daemon(&home, &home.join("root"), "FIRST", |c| c.code_rotate_on_connect = true).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    drop(raw(&d.addr, Cred::Code { code: "FIRST".into(), password: None }, &me).await);
    let fresh = d.st.code.lock().await.code.clone();
    assert_ne!(fresh, "FIRST", "code should have rotated");

    let r = raw_denied(&d.addr, Cred::Code { code: "FIRST".into(), password: None }, &me).await;
    assert!(r.contains("wrong pairing code"), "{r}");
    drop(raw(&d.addr, Cred::Code { code: fresh, password: None }, &me).await);
}

// --------------------------------------------------------- invitations

#[tokio::test]
async fn invite_deny_timeout_and_mixed_versions() {
    let _g = env_lock();
    let home = home("invite-paths");
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    // deny: the peer answers Deny
    let b = daemon(&home, &home.join("b-deny"), "unused", |_| {}).await;
    let decider = b.st.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let pending = decider.invites.lock().await.first().map(|p| p.id.clone());
            if let Some(id) = pending {
                let _ = crate::invite::decide(&decider, &id, Decision::Deny).await;
                return;
            }
        }
    });
    let err = client::invite_send(&b.addr, identity::now() + 600, None, &me, &mut Store::default(), 47000, |_, _| {})
        .await
        .unwrap_err();
    assert!(err.contains("denied"), "{err}");
    assert!(crate::invite::list(&b.st).await.is_empty(), "answered invites must not linger");
    assert!(b.st.trust.lock().await.devices.is_empty(), "a denied invite must not create trust");

    // timeout: nobody answers within invite_timeout
    let slow = daemon(&home, &home.join("b-slow"), "unused", |c| c.invite_timeout = 1).await;
    let err = client::invite_send(&slow.addr, identity::now() + 600, None, &me, &mut Store::default(), 47000, |_, _| {})
        .await
        .unwrap_err();
    assert!(err.contains("timeout"), "{err}");
    assert!(crate::invite::list(&slow.st).await.is_empty());

    // a mixed-version invitation is refused before it can create trust
    let mut s = TcpStream::connect(&b.addr).await.unwrap();
    let inv = Msg::Invite {
        proto: 99,
        from: me.id.clone(),
        pubkey: me.pubkey(),
        expires_at: identity::now() + 600,
        note: None,
        port: 0,
    };
    proto::write_msg(&mut s, &inv).await.unwrap();
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::Err { code, msg } => {
            assert_eq!(code, "protocol", "{msg}");
            assert!(msg.contains("protocol mismatch"), "{msg}");
        }
        other => panic!("expected a version refusal, got {other:?}"),
    }
    assert!(crate::invite::list(&b.st).await.is_empty(), "no pending entry for a bad version");
    let log = std::fs::read_to_string(home.join("auth.log")).unwrap();
    assert!(log.contains("\"method\":\"proto\""), "{log}");
}

// ------------------------------------------------------- hostile input

#[tokio::test]
async fn malformed_hellos_are_rejected_without_panic() {
    let _g = env_lock();
    let home = home("hello");
    let d = daemon(&home, &home.join("root"), "REAL", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    let cases: Vec<(&str, String, String, Cred)> = vec![
        ("empty id", String::new(), me.pubkey(), Cred::Any),
        ("id only", "id".into(), me.pubkey(), Cred::Any),
        ("pubkey not base64", me.id.clone(), "!!!not base64!!!".into(), Cred::Any),
        ("pubkey wrong length", me.id.clone(), "c2hvcnQ".into(), Cred::Any),
        ("empty token", me.id.clone(), me.pubkey(), Cred::Token { token: String::new() }),
        ("token garbage", me.id.clone(), me.pubkey(), Cred::Token { token: "a.b.c".into() }),
        ("session garbage", me.id.clone(), me.pubkey(), Cred::Session { token: "nope".into() }),
        ("empty code", me.id.clone(), me.pubkey(), Cred::Code { code: String::new(), password: None }),
    ];
    for (label, id, pubkey, cred) in cases {
        let mut s = TcpStream::connect(&d.addr).await.unwrap();
        proto::write_msg(&mut s, &Msg::Hello { proto: proto::PROTO, id, pubkey, cred, nonce: 0 }).await.unwrap();
        match proto::read_msg(&mut s).await {
            Ok(Msg::AuthFail { .. }) | Err(_) => {}
            Ok(other) => panic!("{label}: expected rejection, got {other:?}"),
        }
    }

    // still serving after all that
    d.st.fails.lock().await.clear();
    drop(raw(&d.addr, Cred::Code { code: "REAL".into(), password: None }, &me).await);
}

#[tokio::test]
async fn wrong_targets_and_frames_are_reported() {
    let _g = env_lock();
    let home = home("targets");
    let root = home.join("root");
    let d = daemon(&home, &root, "TGT", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    let mut s = raw(&d.addr, Cred::Code { code: "TGT".into(), password: None }, &me).await;

    // finishing a transfer that never started
    proto::write_msg(&mut s, &Msg::PutEnd { path: "missing.bin".into(), size: 1, mtime: 0, sha256: None }).await.unwrap();
    assert!(expect_err(&mut s).await.contains("open"));

    // reading a directory, listing a missing path
    std::fs::create_dir_all(root.join("adir")).unwrap();
    let get = Msg::GetBegin { path: "adir".into(), offset: 0, len: 10 };
    proto::write_msg(&mut s, &get).await.unwrap();
    assert!(expect_err(&mut s).await.contains("directory"));
    proto::write_msg(&mut s, &Msg::List { path: "missing".into() }).await.unwrap();
    assert!(expect_err(&mut s).await.contains("no such path"));

    // unknown frame type
    proto::write_msg(&mut s, &Msg::Accept { token: "x".into() }).await.unwrap();
    assert!(expect_err(&mut s).await.contains("unexpected frame"));

    // nested directories are created on demand, and the connection survives all of it
    let begin = Msg::PutBegin { path: "a/b/c/new.bin".into(), size: 2, offset: 0, len: 2, truncate: true };
    proto::write_msg(&mut s, &begin).await.unwrap();
    assert_eq!(expect_resume(&mut s).await.0, 0);
    proto::send_data(&mut s, b"hi").await.unwrap();
    proto::send_data(&mut s, &[]).await.unwrap();
    expect_ok(&mut s).await;
    proto::write_msg(&mut s, &Msg::PutEnd { path: "a/b/c/new.bin".into(), size: 2, mtime: 0, sha256: None })
        .await
        .unwrap();
    expect_ok(&mut s).await;
    assert_eq!(std::fs::read(root.join("a/b/c/new.bin")).unwrap(), b"hi");

    proto::write_msg(&mut s, &Msg::List { path: String::new() }).await.unwrap();
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::Entries { items, .. } => {
            assert_eq!(items.iter().filter(|e| !e.dir).count(), 1, "{items:?}");
            // the nested directories created for a/b/c/new.bin are listed too
            assert!(items.iter().any(|e| e.dir && e.path == "a/b/c"), "{items:?}");
        }
        other => panic!("expected entries, got {other:?}"),
    }
}

#[tokio::test]
async fn random_frames_never_wedge_the_daemon() {
    let _g = env_lock();
    let home = home("fuzz");
    let d = daemon(&home, &home.join("root"), "unused", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    // a real session: code auth, then reuse the token it hands back
    set_code(&d.st, "FUZZ").await;
    let session = mint_session(&d.addr, Cred::Code { code: "FUZZ".into(), password: None }, &me).await;

    for round in 0..40 {
        let mut s = TcpStream::connect(&d.addr).await.unwrap();
        let hello = Msg::Hello {
            proto: proto::PROTO,
            id: me.id.clone(),
            pubkey: me.pubkey(),
            cred: Cred::Session { token: session.clone() },
            nonce: round,
        };
        proto::write_msg(&mut s, &hello).await.unwrap();
        assert!(matches!(proto::read_msg(&mut s).await.unwrap(), Msg::HelloOk { .. }));

        // a well-framed but meaningless payload, then silence
        let junk = identity::random_code(16 + round as usize);
        s.write_all(&(junk.len() as u32).to_le_bytes()).await.unwrap();
        s.write_all(junk.as_bytes()).await.unwrap();
        s.flush().await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), proto::read_msg(&mut s)).await;
    }

    // the daemon is unharmed
    set_code(&d.st, "STILL").await;
    let items = client::list(&target(&d, "STILL"), &me, "").await.unwrap();
    assert!(items.is_empty());
}

#[tokio::test]
async fn dry_run_never_touches_files() {
    let _g = env_lock();
    let home = home("dry");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "DRY", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "DRY");
    let plan = Plan { parallel: 2, resume: true , verify: false};

    std::fs::write(work.join("mine.txt"), b"local").unwrap();
    client::push(&t, me.clone(), &[work.join("mine.txt").display().to_string()], "d", plan)
        .await
        .unwrap();
    std::fs::write(root.join("d/theirs.txt"), b"remote").unwrap();
    std::fs::write(work.join("new-local.txt"), b"fresh").unwrap();

    let log = client::sync(&t, me.clone(), &work.display().to_string(), "d", client::SyncOpts { prefer: Prefer::Newer, dry_run: true, delete: client::DeleteSide::None }, plan)
        .await
        .unwrap();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(log.iter().all(|l| l.contains("dry run")), "{log:?}");

    assert!(!root.join("d/new-local.txt").exists(), "dry run pushed a file");
    assert!(!work.join("theirs.txt").exists(), "dry run pulled a file");
    assert_eq!(std::fs::read(root.join("d/mine.txt")).unwrap(), b"local");
}

// ------------------------------------------------------------- config

#[tokio::test]
async fn protocol_version_mismatch_is_explained() {
    let _g = env_lock();
    let home = home("proto");
    let d = daemon(&home, &home.join("root"), "unused", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    for bogus in [0u32, 99] {
        let mut s = TcpStream::connect(&d.addr).await.unwrap();
        let hello = Msg::Hello { proto: bogus, id: me.id.clone(), pubkey: me.pubkey(), cred: Cred::Any, nonce: 0 };
        proto::write_msg(&mut s, &hello).await.unwrap();
        match proto::read_msg(&mut s).await.unwrap() {
            Msg::AuthFail { reason } => {
                assert!(reason.contains("protocol mismatch"), "{reason}");
                assert!(reason.contains(&format!("v{bogus}")), "{reason}");
            }
            other => panic!("expected a version refusal, got {other:?}"),
        }
    }
    let log = std::fs::read_to_string(home.join("auth.log")).unwrap();
    assert!(log.contains("\"method\":\"proto\""), "{log}");

    // the current version still works
    set_code(&d.st, "OK").await;
    drop(raw(&d.addr, Cred::Code { code: "OK".into(), password: None }, &me).await);
}

#[tokio::test]
async fn expired_session_falls_back_to_the_trusted_token() {
    let _g = env_lock();
    let home = home("session");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    // sessions expire after a second, so a second push must fall back
    let d = daemon(&home, &root, "unused", |c| c.session_ttl = 1).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());

    let token = jwt::sign(&d.st.id, &me.id, identity::now() + 86_400);
    {
        let mut t = d.st.trust.lock().await;
        t.insert(&me.id, &me.pubkey(), &token.clone(), identity::now() + 86_400, None);
    }
    let t = Target::new(
        d.addr.clone(),
        Cred::Token { token },
        // the pin is the *peer's* identity, checked after the handshake
        Some((d.st.id.id.clone(), d.st.id.pubkey())),
    );
    let plan = Plan { parallel: 2, resume: true , verify: false};

    std::fs::write(work.join("a.txt"), b"first").unwrap();
    client::push(&t, me.clone(), &[work.join("a.txt").display().to_string()], "s", plan)
        .await
        .unwrap();
    assert_eq!(std::fs::read(root.join("s/a.txt")).unwrap(), b"first");

    tokio::time::sleep(Duration::from_millis(1200)).await; // the cached session is now stale

    std::fs::write(work.join("b.txt"), b"second").unwrap();
    client::push(&t, me.clone(), &[work.join("b.txt").display().to_string()], "s", plan)
        .await
        .expect("stale session must fall back to the trusted token");
    assert_eq!(std::fs::read(root.join("s/b.txt")).unwrap(), b"second");
}

#[tokio::test]
async fn silent_connections_are_dropped_by_the_watchdog() {
    let _g = env_lock();
    let home = home("idle");
    let d = daemon(&home, &home.join("root"), "IDLE", |c| c.idle_timeout = 1).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    let mut s = raw(&d.addr, Cred::Code { code: "IDLE".into(), password: None }, &me).await;
    let started = std::time::Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(5), proto::read_msg(&mut s)).await;
    assert!(matches!(r, Ok(Err(_))), "silent connection must be closed, got {r:?}");
    assert!(started.elapsed() < Duration::from_secs(4), "watchdog too slow: {:?}", started.elapsed());
}

#[tokio::test]
async fn audit_log_rotates_and_keeps_the_newest_lines() {
    let _g = env_lock();
    let home = home("rotate-log");
    let path = crate::cfg::file("auth.log");
    assert!(path.starts_with(&home));
    std::fs::write(&path, vec![b'x'; (1 << 20) + 16]).unwrap();

    crate::audit::log("t", "ok", "test", None, "-", None);

    assert!(crate::cfg::file("auth.log.1").exists(), "old log should be rotated");
    let current = std::fs::metadata(&path).unwrap().len();
    assert!(current < 4096, "fresh log should be small, got {current}");
    let tail = crate::audit::tail(1);
    assert_eq!(tail.len(), 1);
    assert!(tail[0].contains("\"event\":\"t\""), "{tail:?}");

    // the diagnostic helper shares the same sink
    crate::audit::note("panic: synthetic");
    let tail = crate::audit::tail(1);
    assert!(tail[0].contains("synthetic"), "{tail:?}");
}

#[tokio::test]
async fn transfers_are_logged_with_the_peer_and_its_address() {
    let _g = env_lock();
    let home = home("file-log");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "LOG", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let plan = Plan { parallel: 2, resume: true, verify: false };

    std::fs::write(work.join("note.txt"), b"logged bytes").unwrap();
    let t = target(&d, "LOG");
    client::push(&t, me.clone(), &[work.join("note.txt").display().to_string()], "in", plan)
        .await
        .unwrap();

    // pull logs one line per downloaded range
    let back = home.join("back");
    std::fs::create_dir_all(&back).unwrap();
    client::pull(&t, me.clone(), &["in/note.txt".to_string()], &back.display().to_string(), plan)
        .await
        .unwrap();

    let files = crate::audit::tail_of(Some("file"), 50);
    assert!(!files.is_empty(), "no file lines logged");
    let put = files
        .iter()
        .find(|l| l.contains("\"method\":\"put\""))
        .unwrap_or_else(|| panic!("no put line: {files:?}"));
    assert!(put.contains(&me.id), "put line must name the peer: {put}");
    assert!(put.contains("127.0.0.1:"), "put line must keep the peer address: {put}");
    assert!(put.contains("\"path\":\"in/note.txt\""), "{put}");
    assert!(put.contains("\"bytes\":12"), "{put}");
    assert!(put.contains("\"result\":\"ok\""), "{put}");

    let get = files
        .iter()
        .find(|l| l.contains("\"method\":\"get\""))
        .unwrap_or_else(|| panic!("no get line: {files:?}"));
    assert!(get.contains(&me.id) && get.contains("in/note.txt"), "{get}");

    // the auth that carried them is in the same log, keyed by the same peer
    let auth = crate::audit::tail_of(Some("auth"), 50);
    assert!(auth.iter().any(|l| l.contains(&me.id) && l.contains("127.0.0.1:")), "{auth:?}");
}

#[tokio::test]
async fn a_code_peer_without_a_usable_identity_is_refused() {
    let _g = env_lock();
    let home = home("bad-id");
    let d = daemon(&home, &home.join("root"), "ID", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    // a random connection that claims a one-character id
    let mut s = TcpStream::connect(&d.addr).await.unwrap();
    let hello = Msg::Hello {
        proto: proto::PROTO,
        id: "x".into(),
        pubkey: me.pubkey(),
        cred: Cred::Code { code: "ID".into(), password: None },
        nonce: 0,
    };
    proto::write_msg(&mut s, &hello).await.unwrap();
    let reason = match proto::read_msg(&mut s).await.unwrap() {
        Msg::AuthFail { reason } => reason,
        other => panic!("expected AuthFail, got {other:?}"),
    };
    assert!(reason.contains("malformed device id"), "{reason}");

    let denies = crate::audit::tail_of(Some("auth"), 10);
    assert!(denies.iter().any(|l| l.contains("\"deny\"") && l.contains("\"device\":\"x\"")), "{denies:?}");
}

#[tokio::test]
async fn a_trusted_id_cannot_be_claimed_with_another_key() {
    let _g = env_lock();
    let home = home("impersonate");
    let d = daemon(&home, &home.join("root"), "IM", |c| c.code_one_shot = false).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    // the device vouches for `me` from another key, so claiming that id is impersonation
    {
        let mut trust = d.st.trust.lock().await;
        let other = Identity::load_or_create_at(&home.join("other.json")).unwrap();
        trust.insert(&me.id, &other.pubkey(), "token", 0, None);
    }
    let reason = raw_denied(&d.addr, Cred::Code { code: "IM".into(), password: None }, &me).await;
    assert!(reason.contains("already trusted with another key"), "{reason}");
}

#[tokio::test]
async fn paths_past_the_windows_limit_still_work() {
    let _g = env_lock();
    let home = home("long");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "LONG", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());

    let seg = "d".repeat(110);
    let remote_dir = format!("{seg}/{seg}");
    let absolute = d.st.root.join(&seg).join(&seg).join("deep.txt");
    assert!(
        absolute.to_string_lossy().len() > 260,
        "test is pointless below MAX_PATH: {}",
        absolute.to_string_lossy().len()
    );

    std::fs::write(work.join("deep.txt"), b"deep file").unwrap();
    let t = target(&d, "LONG");
    client::push(&t, me.clone(), &[work.join("deep.txt").display().to_string()], &remote_dir, Plan { parallel: 2, resume: true , verify: false})
        .await
        .expect("long remote path must be writable");
    assert_eq!(std::fs::read(&absolute).unwrap(), b"deep file");

    // and it can be listed and pulled back
    let items = client::list(&t, &me, &seg).await.unwrap();
    assert!(items.iter().any(|e| e.path.ends_with("deep.txt")), "{items:?}");
    let back = home.join("back");
    client::pull(&t, me, &[format!("{seg}/{seg}/deep.txt")], &back.to_string_lossy(), Plan { parallel: 2, resume: true , verify: false})
        .await
        .unwrap();
    assert_eq!(std::fs::read(back.join("deep.txt")).unwrap(), b"deep file");
}

// ------------------------------------------------------------ stress

#[tokio::test]
async fn watchdog_kills_a_stalled_upload_and_resume_finishes_it() {
    let _g = env_lock();
    let home = home("stall");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "W1", |c| c.idle_timeout = 1).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let me_raw = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 247) as u8).collect();
    let size = payload.len() as u64;

    // start an upload, send one chunk, then go silent
    let mut s = raw(&d.addr, Cred::Code { code: "W1".into(), password: None }, &me_raw).await;
    let begin = Msg::PutBegin { path: "stall.bin".into(), size, offset: 0, len: size, truncate: true };
    proto::write_msg(&mut s, &begin).await.unwrap();
    assert_eq!(expect_resume(&mut s).await.0, 0);
    proto::send_data(&mut s, &payload[..256 * 1024]).await.unwrap();

    // the daemon must give up on us instead of holding the task forever
    let r = tokio::time::timeout(Duration::from_secs(5), proto::read_msg(&mut s)).await;
    match r {
        Ok(Ok(Msg::Err { msg, .. })) => assert!(msg.contains("no traffic"), "{msg}"),
        Ok(Err(_)) => {}
        other => panic!("stalled upload should be dropped, got {other:?}"),
    }
    drop(s);

    let partial = std::fs::metadata(guard::part_path(&root.join("stall.bin"))).unwrap().len();
    assert_eq!(partial, 256 * 1024, "bytes received before the stall must be kept");

    // a normal client resumes from there
    set_code(&d.st, "W2").await;
    std::fs::write(work.join("stall.bin"), &payload).unwrap();
    let t = target(&d, "W2");
    client::push(&t, me, &[work.join("stall.bin").display().to_string()], "", Plan { parallel: 2, resume: true , verify: false})
        .await
        .expect("resume after a watchdog kill");
    assert!(std::fs::read(root.join("stall.bin")).unwrap() == payload, "resume produced wrong bytes");
}

#[tokio::test]
async fn parallel_clients_are_isolated() {
    let _g = env_lock();
    let home = home("parallel");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "unused", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());

    // eight clients, each with its own session token, pushing its own file
    d.st.code_sessions.lock().await.insert(me.id.clone(), identity::now() + 600);
    let mut tasks = Vec::new();
    let mut expected = Vec::new();
    for i in 0..8u64 {
        let addr = d.addr.clone();
        let me = me.clone();
        let token = jwt::sign(&d.st.id, &me.id, identity::now() + 600 + i);
        let local = work.join(format!("c{i}.bin"));
        let body: Vec<u8> = (0..128 * 1024).map(|b| (b % 241) as u8 + i as u8).collect();
        std::fs::write(&local, &body).unwrap();
        expected.push((format!("p{i}/c{i}.bin"), body));
        tasks.push(tokio::spawn(async move {
            let t = Target::new(addr, Cred::Session { token }, None);
            let plan = Plan { parallel: 2, resume: true , verify: false};
            client::push(&t, me, &[local.display().to_string()], &format!("p{i}"), plan).await
        }));
    }
    for (i, task) in tasks.into_iter().enumerate() {
        task.await.unwrap().unwrap_or_else(|e| panic!("client {i} failed: {e}"));
    }
    for (rel, body) in expected {
        let got = std::fs::read(root.join(&rel)).unwrap();
        assert!(got == body, "{rel} was corrupted by a concurrent client");
    }
}

#[tokio::test]
async fn sync_operates_on_the_root_itself() {
    let _g = env_lock();
    let home = home("root-sync");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(work.join("sub")).unwrap();
    let d = daemon(&home, &root, "ROOT", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "ROOT");
    let plan = Plan { parallel: 2, resume: true , verify: false};

    std::fs::write(work.join("top.txt"), b"top").unwrap();
    std::fs::write(work.join("sub/nested.txt"), b"nested").unwrap();
    let locals = vec![work.join("top.txt").display().to_string(), work.join("sub").display().to_string()];
    client::push(&t, me.clone(), &locals, "", plan).await.unwrap();
    assert_eq!(std::fs::read(root.join("top.txt")).unwrap(), b"top");
    assert_eq!(std::fs::read(root.join("sub/nested.txt")).unwrap(), b"nested");

    // remote "" means the served root
    assert!(client::diff(&t, &me, &work.display().to_string(), "").await.unwrap().is_empty());
    assert!(client::sync(&t, me.clone(), &work.display().to_string(), "", client::SyncOpts { prefer: Prefer::Newer, dry_run: false, delete: client::DeleteSide::None }, plan)
        .await
        .unwrap()
        .is_empty());

    let out = home.join("out");
    client::pull(&t, me, &["top.txt".to_string()], &out.display().to_string(), plan)
        .await
        .unwrap();
    assert_eq!(std::fs::read(out.join("top.txt")).unwrap(), b"top");
}

// ------------------------------------------- windows quirks and promises

#[tokio::test]
async fn empty_directories_survive_a_sync() {
    let _g = env_lock();
    let home = home("empty-dirs");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(work.join("parent/empty")).unwrap();
    std::fs::create_dir_all(work.join("only-empty/leaf")).unwrap();
    std::fs::write(work.join("parent/keep.txt"), b"x").unwrap();
    std::fs::write(work.join("only-empty/leaf/note.txt"), b"n").unwrap();
    let d = daemon(&home, &root, "ED", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "ED");
    let plan = Plan { parallel: 2, resume: true, verify: false };

    // push recreates the empty directories, not just the files
    let trees = vec![
        work.join("parent").display().to_string(),
        work.join("only-empty").display().to_string(),
    ];
    client::push(&t, me.clone(), &trees, "", plan).await.unwrap();
    assert!(root.join("parent/empty").is_dir(), "empty directory was dropped by push");
    assert!(root.join("only-empty/leaf").is_dir(), "directory-only tree was dropped");
    assert_eq!(std::fs::read(root.join("parent/keep.txt")).unwrap(), b"x");

    // directories round-trip exactly: no spurious rows, no missing ones
    assert!(
        client::diff(&t, &me, &work.display().to_string(), "").await.unwrap().is_empty(),
        "a pushed tree must compare equal, directories included"
    );

    // pulling a remote-only empty directory creates it locally
    std::fs::create_dir_all(root.join("remote-empty/inner")).unwrap();
    let out = home.join("out");
    std::fs::create_dir_all(&out).unwrap();
    client::pull(&t, me.clone(), &["remote-empty".to_string()], &out.display().to_string(), plan)
        .await
        .unwrap();
    // same flattening rule as files: the pulled path's own name is dropped
    assert!(out.join("inner").is_dir(), "pull dropped an empty directory");

    // sync copies it, and is idempotent afterwards
    let log = client::sync(
        &t,
        me.clone(),
        &work.display().to_string(),
        "",
        client::SyncOpts { prefer: Prefer::Newer, dry_run: false, delete: client::DeleteSide::None },
        plan,
    )
    .await
    .unwrap();
    assert!(log.iter().any(|l| l.starts_with("pull") && l.contains("remote-empty")), "{log:?}");
    assert!(work.join("remote-empty/inner").is_dir());
    assert!(client::diff(&t, &me, &work.display().to_string(), "").await.unwrap().is_empty());
}

#[tokio::test]
async fn pull_overwrites_a_longer_local_file() {
    let _g = env_lock();
    let home = home("pull-longer");
    let root = home.join("root");
    let out = home.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "PL", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "PL");
    let plan = Plan { parallel: 2, resume: true , verify: false};

    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 239) as u8).collect();
    std::fs::write(work.join("x.bin"), &payload).unwrap();
    client::push(&t, me.clone(), &[work.join("x.bin").display().to_string()], "", plan)
        .await
        .unwrap();

    // a longer, staler local copy must end up byte-identical to the remote
    std::fs::write(out.join("x.bin"), vec![b'Z'; 200 * 1024]).unwrap();
    client::pull(&t, me, &["x.bin".to_string()], &out.display().to_string(), plan)
        .await
        .unwrap();
    let got = std::fs::read(out.join("x.bin")).unwrap();
    assert_eq!(got.len(), payload.len(), "stale tail must be truncated");
    assert!(got == payload, "pull produced wrong bytes");
}

#[tokio::test]
async fn windows_reserved_names_are_plain_files() {
    let _g = env_lock();
    let home = home("reserved");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    // the local side needs verbatim paths to create such names at all
    let vwork = work.canonicalize().unwrap();
    let d = daemon(&home, &root, "RES", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "RES");

    for name in ["con.txt", "nul.txt", "aux.txt", "prn.txt", "com1.txt"] {
        std::fs::write(vwork.join(name), name.as_bytes()).unwrap();
        client::push(&t, me.clone(), &[vwork.join(name).display().to_string()], "res", Plan { parallel: 1, resume: true , verify: false})
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        // the daemon must have created a regular file, not written to the device
        let stored = std::fs::read(d.st.root.join("res").join(name)).unwrap();
        assert_eq!(stored, name.as_bytes(), "{name} was not stored as a regular file");
    }
}

#[tokio::test]
async fn absurdly_long_remote_names_fail_cleanly() {
    let _g = env_lock();
    let home = home("toolong");
    let d = daemon(&home, &home.join("root"), "TL", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    let mut s = raw(&d.addr, Cred::Code { code: "TL".into(), password: None }, &me).await;

    // one component longer than the filesystem allows
    let name = format!("{}.bin", "n".repeat(300));
    let begin = Msg::PutBegin { path: name, size: 2, offset: 0, len: 2, truncate: true };
    proto::write_msg(&mut s, &begin).await.unwrap();
    let msg = expect_err(&mut s).await;
    assert!(msg.contains("open"), "{msg}");

    // the daemon is unharmed and still framed
    proto::write_msg(&mut s, &Msg::List { path: String::new() }).await.unwrap();
    assert!(matches!(proto::read_msg(&mut s).await.unwrap(), Msg::Entries { .. }));
}

#[tokio::test]
async fn refreshing_the_code_does_not_break_running_transfers() {
    let _g = env_lock();
    let home = home("refresh");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "C1", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "C1");
    let plan = Plan { parallel: 2, resume: true , verify: false};

    std::fs::write(work.join("a.txt"), b"first").unwrap();
    client::push(&t, me.clone(), &[work.join("a.txt").display().to_string()], "m", plan)
        .await
        .unwrap();

    // the operator refreshes the code mid-session
    d.st.rotate_code(None).await;

    // the established session keeps working...
    std::fs::write(work.join("b.txt"), b"second").unwrap();
    client::push(&t, me.clone(), &[work.join("b.txt").display().to_string()], "m", plan)
        .await
        .expect("a refreshed code must not kill the running session");
    assert_eq!(std::fs::read(root.join("m/b.txt")).unwrap(), b"second");

    // ...while the old code is useless for a newcomer
    let other = Identity::load_or_create_at(&home.join("other.json")).unwrap();
    let fresh = Target::new(d.addr.clone(), Cred::Code { code: "C1".into(), password: None }, None);
    assert!(client::list(&fresh, &other, "m").await.is_err(), "old code must be dead");
}

// ------------------------------------------------ staging and integrity

#[tokio::test]
async fn partial_uploads_are_staged_then_landed() {
    let _g = env_lock();
    let home = home("stage");
    let root = home.join("root");
    let d = daemon(&home, &root, "STG", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    let final_path = root.join("stage.bin");
    let part = guard::part_path(&final_path);

    // leave an upload half done
    let mut s = raw(&d.addr, Cred::Code { code: "STG".into(), password: None }, &me).await;
    let begin = Msg::PutBegin { path: "stage.bin".into(), size: 10, offset: 0, len: 10, truncate: true };
    proto::write_msg(&mut s, &begin).await.unwrap();
    assert_eq!(expect_resume(&mut s).await.0, 0);
    proto::send_data(&mut s, b"abcd").await.unwrap();
    drop(s);
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert!(!final_path.exists(), "a partial upload must not appear under its final name");
    assert_eq!(std::fs::metadata(&part).unwrap().len(), 4, "the partial must be kept for resume");

    // the in-progress file is invisible to listing/diff
    set_code(&d.st, "STG1").await;
    let items = client::list(&target(&d, "STG1"), &me, "").await.unwrap();
    assert!(items.is_empty(), "partials leaked into the listing: {items:?}");

    // finishing lands it under the final name and removes the staging file
    set_code(&d.st, "STG2").await;
    let mut s = raw(&d.addr, Cred::Code { code: "STG2".into(), password: None }, &me).await;
    let begin = Msg::PutBegin { path: "stage.bin".into(), size: 10, offset: 4, len: 6, truncate: false };
    proto::write_msg(&mut s, &begin).await.unwrap();
    assert_eq!(expect_resume(&mut s).await.0, 4, "resume must pick up the staged bytes");
    proto::send_data(&mut s, b"efghij").await.unwrap();
    proto::send_data(&mut s, &[]).await.unwrap();
    expect_ok(&mut s).await;
    let end = Msg::PutEnd { path: "stage.bin".into(), size: 10, mtime: 0, sha256: None };
    proto::write_msg(&mut s, &end).await.unwrap();
    expect_ok(&mut s).await;

    assert_eq!(std::fs::read(&final_path).unwrap(), b"abcdefghij");
    assert!(!part.exists(), "staging file must be gone after landing");
}

#[tokio::test]
async fn checksum_mismatch_discards_the_upload() {
    let _g = env_lock();
    let home = home("checksum");
    let root = home.join("root");
    let d = daemon(&home, &root, "SUM", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    let mut s = raw(&d.addr, Cred::Code { code: "SUM".into(), password: None }, &me).await;

    let begin = Msg::PutBegin { path: "bad.bin".into(), size: 4, offset: 0, len: 4, truncate: true };
    proto::write_msg(&mut s, &begin).await.unwrap();
    expect_resume(&mut s).await;
    proto::send_data(&mut s, b"abcd").await.unwrap();
    proto::send_data(&mut s, &[]).await.unwrap();
    expect_ok(&mut s).await;

    let end = Msg::PutEnd {
        path: "bad.bin".into(),
        size: 4,
        mtime: 0,
        sha256: Some(identity::b64e(&[0u8; 32])),
    };
    proto::write_msg(&mut s, &end).await.unwrap();
    let (code, msg) = expect_err_coded(&mut s).await;
    assert_eq!(code, "checksum", "{msg}");
    assert!(!root.join("bad.bin").exists(), "a corrupt file must not land");
    assert!(!guard::part_path(&root.join("bad.bin")).exists(), "corrupt staging file must be discarded");

    // and a correct digest does land
    set_code(&d.st, "SUM2").await;
    let session = mint_session(&d.addr, Cred::Code { code: "SUM2".into(), password: None }, &me).await;
    let mut s = raw(&d.addr, Cred::Session { token: session }, &me).await;
    let begin = Msg::PutBegin { path: "good.bin".into(), size: 4, offset: 0, len: 4, truncate: true };
    proto::write_msg(&mut s, &begin).await.unwrap();
    expect_resume(&mut s).await;
    proto::send_data(&mut s, b"abcd").await.unwrap();
    proto::send_data(&mut s, &[]).await.unwrap();
    expect_ok(&mut s).await;
    std::fs::write(root.join("local-src"), b"abcd").unwrap();
    let digest = guard::sha256_file(&root.join("local-src")).unwrap();
    let end = Msg::PutEnd { path: "good.bin".into(), size: 4, mtime: 0, sha256: Some(digest) };
    proto::write_msg(&mut s, &end).await.unwrap();
    expect_ok(&mut s).await;
    assert_eq!(std::fs::read(root.join("good.bin")).unwrap(), b"abcd");
}

#[tokio::test]
async fn pull_resumes_from_the_local_partial() {
    let _g = env_lock();
    let home = home("pull-resume");
    let root = home.join("root");
    let work = home.join("work");
    let out = home.join("out");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    let d = daemon(&home, &root, "PR", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "PR");
    let plan = Plan { parallel: 2, resume: true , verify: false};

    let payload: Vec<u8> = (0..96 * 1024).map(|i| (i % 233) as u8).collect();
    std::fs::write(work.join("p.bin"), &payload).unwrap();
    client::push(&t, me.clone(), &[work.join("p.bin").display().to_string()], "", plan)
        .await
        .unwrap();

    // half the file already downloaded: the rest must be fetched, then landed
    let local = out.join("p.bin");
    let part = guard::part_path(&local);
    std::fs::write(&part, &payload[..payload.len() / 2]).unwrap();
    client::pull(&t, me, &["p.bin".to_string()], &out.display().to_string(), plan)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), payload);
    assert!(!part.exists(), "staging file must be gone after landing");
}

#[tokio::test]
async fn large_listings_are_chunked() {
    let _g = env_lock();
    let home = home("biglist");
    let root = home.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let d = daemon(&home, &root, "BL", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    // more than one LIST_CHUNK (1000) worth of entries
    for i in 0..2500 {
        std::fs::write(root.join(format!("f{i:04}.txt")), b"x").unwrap();
    }
    let items = client::list(&target(&d, "BL"), &me, "").await.unwrap();
    assert_eq!(items.len(), 2500, "chunked listing must be reassembled");
    assert!(items.iter().any(|e| e.path == "f2499.txt"));
}

// ------------------------------------------------- guards and limits

#[tokio::test]
async fn one_data_dir_one_daemon() {
    let _g = env_lock();
    let _home = home("lock");
    let first = server::acquire_data_lock().expect("first lock");
    assert!(server::acquire_data_lock().is_err(), "a second daemon must be refused");
    drop(first);
    assert!(server::acquire_data_lock().is_ok(), "lock must be released with the handle");
}

#[tokio::test]
async fn connections_per_ip_are_capped() {
    let _g = env_lock();
    let home = home("ipcap");
    let d = daemon(&home, &home.join("root"), "CAP", |c| c.max_conn_per_ip = 2).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    let first = TcpStream::connect(&d.addr).await.unwrap();
    let second = TcpStream::connect(&d.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // this one is accepted by the OS and then dropped by the daemon
    let mut third = TcpStream::connect(&d.addr).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(3), proto::read_msg(&mut third)).await;
    assert!(matches!(r, Ok(Err(_))), "connection over the cap must be dropped, got {r:?}");

    // freeing a slot lets the same address back in
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(second);
    drop(raw(&d.addr, Cred::Code { code: "CAP".into(), password: None }, &me).await);
}

#[tokio::test]
async fn revoking_a_device_takes_effect_immediately() {
    let _g = env_lock();
    let home = home("revoke");
    let d = daemon(&home, &home.join("root"), "unused", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    let now = identity::now();
    let token = jwt::sign(&d.st.id, &me.id, now + 3600);
    {
        let mut trust = d.st.trust.lock().await;
        trust.insert(&me.id, &me.pubkey(), &token.clone(), now + 3600, None);
        trust.save().unwrap();
    }
    drop(raw(&d.addr, Cred::Token { token: token.clone() }, &me).await);

    // `dtu device rm` rewrites trust.json from another process
    Store::default().save().unwrap();
    let reason = raw_denied(&d.addr, Cred::Token { token }, &me).await;
    assert!(reason.contains("unknown device"), "revocation must not wait for a restart: {reason}");
}

// ------------------------------------------------------ daemon lifecycle

fn free_port() -> u16 {
    let l = StdListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test]
async fn the_hosted_core_serves_and_stops() {
    let _g = env_lock();
    let home = home("hosted");
    let root = home.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let cfg = Config {
        port: free_port(),
        root: root.to_string_lossy().into_owned(),
        ..Default::default()
    };
    crate::cfg::write_json(&crate::cfg::file("config.json"), &cfg).unwrap();

    let daemon = crate::embed::host(cfg.clone()).expect("host the core");
    daemon.wait_ready().expect("services must come up");
    assert!(crate::cfg::file("daemon.lock").exists(), "data dir lock file missing");
    assert!(crate::cfg::file("control.token").exists(), "local key missing");

    // one owner per data dir, checked through the real entry point
    let dup = crate::embed::host(cfg.clone()).err().expect("a second owner must be refused");
    assert!(dup.contains("already owns"), "{dup}");

    // it actually serves transfers with the code it is showing
    let code = daemon.state.code.lock().await.code.clone();
    let me = Arc::new(Identity::load_or_create_at(&home.join("client.json")).unwrap());
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("hello.txt"), b"through the hosted core").unwrap();
    let t = Target::new(
        format!("127.0.0.1:{}", cfg.port),
        Cred::Code { code, password: None },
        None,
    );
    client::push(
        &t,
        me.clone(),
        &[work.join("hello.txt").display().to_string()],
        "in",
        Plan { parallel: 2, resume: true, verify: true },
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(root.join("in/hello.txt")).unwrap(), b"through the hosted core");
    assert!(!std::fs::read_dir(root.join("in")).unwrap().any(|e| {
        e.map(|e| e.file_name().to_string_lossy().ends_with(".dtu-part")).unwrap_or(false)
    }));

    // stopping hands the data dir back
    daemon.stop();
    let again = crate::embed::host(cfg).expect("host again after stop");
    again.wait_ready().expect("services must come back");
    again.stop();
}

#[tokio::test]
async fn revoking_a_device_kills_its_session_too() {
    let _g = env_lock();
    let home = home("revoke-session");
    let d = daemon(&home, &home.join("root"), "unused", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    let now = identity::now();
    let token = jwt::sign(&d.st.id, &me.id, now + 3600);
    {
        let mut trust = d.st.trust.lock().await;
        trust.insert(&me.id, &me.pubkey(), &token.clone(), now + 3600, None);
        trust.save().unwrap();
    }

    // a trusted device gets a session from its JWT, and that session works
    let session = mint_session(&d.addr, Cred::Token { token }, &me).await;
    drop(raw(&d.addr, Cred::Session { token: session.clone() }, &me).await);

    // `dtu device rm` rewrites trust.json from another process
    Store::default().save().unwrap();
    let reason = raw_denied(&d.addr, Cred::Session { token: session }, &me).await;
    assert!(
        reason.contains("no longer trusted"),
        "a revoked device must lose its live session immediately: {reason}"
    );
}

#[tokio::test]
async fn code_auth_sessions_survive_an_empty_trust_store() {
    let _g = env_lock();
    let home = home("code-session");
    let d = daemon(&home, &home.join("root"), "CS", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    // a code-auth device is never in the trust store, but its session must keep
    // working for the rest of the transfer
    let session = mint_session(&d.addr, Cred::Code { code: "CS".into(), password: None }, &me).await;
    Store::default().save().unwrap();
    drop(raw(&d.addr, Cred::Session { token: session.clone() }, &me).await);

    // once the code session forgets the device, the token is dead
    d.st.code_sessions.lock().await.clear();
    let reason = raw_denied(&d.addr, Cred::Session { token: session }, &me).await;
    assert!(reason.contains("no longer trusted"), "{reason}");
}

// -------------------------------------------- staging, integrity, framing

#[tokio::test]
async fn reserved_suffix_is_refused_in_both_directions() {
    let _g = env_lock();
    let home = home("reserved-suffix");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "SFX", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "SFX");

    // a local file that would land under the reserved name
    std::fs::write(work.join("data.bin.dtu-part"), b"x").unwrap();
    let err = client::push(
        &t,
        me.clone(),
        &[work.join("data.bin.dtu-part").display().to_string()],
        "r",
        Plan { parallel: 1, resume: true, verify: false },
    )
    .await
    .unwrap_err();
    assert!(err.contains("reserved suffix"), "{err}");

    // and pulling such a name is refused too
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("real.bin"), b"data").unwrap();
    let out = home.join("out");
    std::fs::create_dir_all(&out).unwrap();
    set_code(&d.st, "SFX2").await;
    let mut s = raw(&d.addr, Cred::Code { code: "SFX2".into(), password: None }, &me).await;
    let get = Msg::GetBegin { path: "real.bin.dtu-part".into(), offset: 0, len: 4 };
    proto::write_msg(&mut s, &get).await.unwrap();
    assert!(expect_err(&mut s).await.contains("reserved suffix"));
}

#[tokio::test]
async fn pull_discards_an_oversized_staged_file() {
    let _g = env_lock();
    let home = home("oversized-part");
    let root = home.join("root");
    let work = home.join("work");
    let out = home.join("out");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    let d = daemon(&home, &root, "OVR", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "OVR");
    let plan = Plan { parallel: 2, resume: true, verify: false };

    let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 227) as u8).collect();
    std::fs::write(work.join("o.bin"), &payload).unwrap();
    client::push(&t, me.clone(), &[work.join("o.bin").display().to_string()], "", plan)
        .await
        .unwrap();

    // a stale staging file from some larger transfer must not survive as a prefix
    let part = guard::part_path(&out.join("o.bin"));
    std::fs::write(&part, vec![b'Z'; 200 * 1024]).unwrap();
    client::pull(&t, me, &["o.bin".to_string()], &out.display().to_string(), plan)
        .await
        .unwrap();
    assert!(std::fs::read(out.join("o.bin")).unwrap() == payload, "oversized staging leaked into the file");
}

#[tokio::test]
async fn verification_handles_empty_files_and_keeps_good_versions() {
    let _g = env_lock();
    let home = home("verify-cases");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "VF", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "VF");
    let plan = Plan { parallel: 2, resume: true, verify: true };

    // empty file: the digest of nothing must still verify
    std::fs::write(work.join("empty.bin"), b"").unwrap();
    client::push(&t, me.clone(), &[work.join("empty.bin").display().to_string()], "", plan)
        .await
        .unwrap();
    assert_eq!(std::fs::metadata(root.join("empty.bin")).unwrap().len(), 0);

    // a bad upload must not destroy the version already in place
    std::fs::write(work.join("keep.bin"), b"v1").unwrap();
    client::push(&t, me.clone(), &[work.join("keep.bin").display().to_string()], "", plan)
        .await
        .unwrap();
    assert_eq!(std::fs::read(root.join("keep.bin")).unwrap(), b"v1");

    set_code(&d.st, "VF2").await;
    let mut s = raw(&d.addr, Cred::Code { code: "VF2".into(), password: None }, &me).await;
    let begin = Msg::PutBegin { path: "keep.bin".into(), size: 3, offset: 0, len: 3, truncate: true };
    proto::write_msg(&mut s, &begin).await.unwrap();
    expect_resume(&mut s).await;
    proto::send_data(&mut s, b"bad").await.unwrap();
    proto::send_data(&mut s, &[]).await.unwrap();
    expect_ok(&mut s).await;
    let end = Msg::PutEnd { path: "keep.bin".into(), size: 3, mtime: 0, sha256: Some(identity::b64e(&[7u8; 32])) };
    proto::write_msg(&mut s, &end).await.unwrap();
    let (code, msg) = expect_err_coded(&mut s).await;
    assert_eq!(code, "checksum", "{msg}");
    assert_eq!(
        std::fs::read(root.join("keep.bin")).unwrap(),
        b"v1",
        "a rejected upload must leave the previous file untouched"
    );
}

#[tokio::test]
async fn list_chunk_boundary_is_exact() {
    let _g = env_lock();
    let home = home("chunk-edge");
    let root = home.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let d = daemon(&home, &root, "CE", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    // one more than a chunk: first frame must be full and flagged `more`
    for i in 0..1001 {
        std::fs::write(root.join(format!("e{i:04}.txt")), b"x").unwrap();
    }
    let mut s = raw(&d.addr, Cred::Code { code: "CE".into(), password: None }, &me).await;
    proto::write_msg(&mut s, &Msg::List { path: String::new() }).await.unwrap();
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::Entries { items, more } => {
            assert_eq!(items.len(), 1000, "first frame should be exactly one chunk");
            assert!(more, "a second frame should follow");
        }
        other => panic!("unexpected {other:?}"),
    }
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::Entries { items, more } => {
            assert_eq!(items.len(), 1);
            assert!(!more);
        }
        other => panic!("unexpected {other:?}"),
    }

    // the client reassembles the same set
    set_code(&d.st, "CE2").await;
    let all = client::list(&target(&d, "CE2"), &me, "").await.unwrap();
    assert_eq!(all.len(), 1001);
}

#[tokio::test]
async fn a_corrupt_trust_file_does_not_wipe_access() {
    let _g = env_lock();
    let home = home("badtrust");
    let d = daemon(&home, &home.join("root"), "unused", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    let now = identity::now();
    let token = jwt::sign(&d.st.id, &me.id, now + 3600);
    {
        let mut trust = d.st.trust.lock().await;
        trust.insert(&me.id, &me.pubkey(), &token.clone(), now + 3600, None);
        trust.save().unwrap();
    }
    drop(raw(&d.addr, Cred::Token { token: token.clone() }, &me).await);

    // a half-written file must be ignored, not treated as "everything revoked"
    std::fs::write(crate::cfg::file("trust.json"), b"{ truncated").unwrap();
    drop(raw(&d.addr, Cred::Token { token }, &me).await);
}

// ---------------------------------------------- peripheral: dry run, delete

#[tokio::test]
async fn dry_run_reports_without_touching_the_peer() {
    let _g = env_lock();
    let home = home("dryplan");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "DP", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "DP");

    std::fs::write(work.join("a.txt"), b"0123456789").unwrap();
    std::fs::write(work.join("b.txt"), b"bb").unwrap();
    let locals = vec![work.join("a.txt").display().to_string(), work.join("b.txt").display().to_string()];

    // nothing exists yet: the plan says so, and nothing is created
    let rows = client::plan_push(&t, me.clone(), &locals, "plan").await.unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.remote_size == 0 && !r.up_to_date()));
    assert!(!root.join("plan").exists(), "a dry run must not create directories");

    // transfer for real, then the plan reports it as up to date
    client::push(&t, me.clone(), &locals, "plan", Plan { parallel: 2, resume: true, verify: false })
        .await
        .unwrap();
    let rows = client::plan_push(&t, me.clone(), &locals, "plan").await.unwrap();
    assert!(rows.iter().all(|r| r.up_to_date()), "{rows:?}");
    assert_eq!(rows[0].remote, "plan/a.txt");

    // stat is read-only for a missing path too
    assert_eq!(client::stat(&t, &me, "plan/absent.bin").await.unwrap(), 0);
    assert!(!root.join("plan/absent.bin").exists());
}

#[tokio::test]
async fn sync_creates_a_missing_remote_directory() {
    let _g = env_lock();
    let home = home("fresh-remote");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(work.join("deep")).unwrap();
    let d = daemon(&home, &root, "FR", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "FR");
    let plan = Plan { parallel: 2, resume: true, verify: false };

    std::fs::write(work.join("one.txt"), b"1").unwrap();
    std::fs::write(work.join("deep/two.txt"), b"2").unwrap();

    // the destination does not exist at all
    let rows = client::diff(&t, &me, &work.display().to_string(), "fresh/dir").await.unwrap();
    assert_eq!(rows.len(), 3, "two files plus the deep directory: {rows:?}");
    assert!(rows.iter().any(|r| r.dir && r.rel == "deep"), "{rows:?}");
    let log = client::sync(&t, me.clone(), &work.display().to_string(), "fresh/dir", client::SyncOpts { prefer: Prefer::Newer, dry_run: false, delete: client::DeleteSide::None }, plan)
        .await
        .unwrap();
    assert_eq!(log.len(), 3, "{log:?}");
    assert_eq!(std::fs::read(root.join("fresh/dir/deep/two.txt")).unwrap(), b"2");
}

#[tokio::test]
async fn delete_mirrors_either_side() {
    let _g = env_lock();
    let home = home("delete");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "DL", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());
    let t = target(&d, "DL");
    let plan = Plan { parallel: 2, resume: true, verify: false };

    std::fs::write(work.join("keep.txt"), b"keep").unwrap();
    client::push(&t, me.clone(), &[work.join("keep.txt").display().to_string()], "s", plan)
        .await
        .unwrap();

    // `--delete remote` removes what only the peer has
    std::fs::write(root.join("s/theirs.txt"), b"peer only").unwrap();
    let log = client::sync(&t, me.clone(), &work.display().to_string(), "s", client::SyncOpts { prefer: Prefer::Newer, dry_run: false, delete: client::DeleteSide::Remote }, plan)
        .await
        .unwrap();
    assert!(log.iter().any(|l| l.starts_with("del(remote)")), "{log:?}");
    assert!(!root.join("s/theirs.txt").exists(), "peer-only file should be removed");
    assert_eq!(std::fs::read(work.join("theirs.txt")).unwrap(), b"peer only", "it must be pulled first");

    // `--delete local` removes what only this side has
    std::fs::write(work.join("mine.txt"), b"local only").unwrap();
    let log = client::sync(&t, me.clone(), &work.display().to_string(), "s", client::SyncOpts { prefer: Prefer::Newer, dry_run: false, delete: client::DeleteSide::Local }, plan)
        .await
        .unwrap();
    assert!(log.iter().any(|l| l.contains("del(remote side wins)")), "{log:?}");
    assert!(!work.join("mine.txt").exists(), "local-only file should be removed");
    assert_eq!(std::fs::read(root.join("s/mine.txt")).unwrap(), b"local only", "it must be pushed first");

    // dry runs never delete
    std::fs::write(work.join("spare.txt"), b"x").unwrap();
    client::sync(&t, me.clone(), &work.display().to_string(), "s", client::SyncOpts { prefer: Prefer::Newer, dry_run: true, delete: client::DeleteSide::Local }, plan)
        .await
        .unwrap();
    assert!(work.join("spare.txt").exists(), "dry run deleted a file");
}

#[tokio::test]
async fn remote_delete_is_guarded() {
    let _g = env_lock();
    let home = home("delguard");
    let root = home.join("root");
    let d = daemon(&home, &root, "DG", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    std::fs::create_dir_all(root.join("dir")).unwrap();
    std::fs::write(root.join("dir/inside.txt"), b"x").unwrap();
    std::fs::write(root.join("gone.txt"), b"x").unwrap();
    let mut s = raw(&d.addr, Cred::Code { code: "DG".into(), password: None }, &me).await;

    // a directory is not deleted
    proto::write_msg(&mut s, &Msg::Del { path: "dir".into() }).await.unwrap();
    assert!(expect_err(&mut s).await.contains("directory"));
    assert!(root.join("dir/inside.txt").exists());

    // traversal is refused
    proto::write_msg(&mut s, &Msg::Del { path: "../escape.txt".into() }).await.unwrap();
    assert!(expect_err(&mut s).await.contains("path"));

    // a missing file reports a stat failure
    proto::write_msg(&mut s, &Msg::Del { path: "nope.txt".into() }).await.unwrap();
    assert!(expect_err(&mut s).await.contains("stat"));

    // the happy path, then listing no longer shows it
    proto::write_msg(&mut s, &Msg::Del { path: "gone.txt".into() }).await.unwrap();
    expect_ok(&mut s).await;
    assert!(!root.join("gone.txt").exists());
}

#[tokio::test]
async fn stopping_the_core_drains_live_connections() {
    let _g = env_lock();
    let home = home("drain");
    let root = home.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let cfg = Config {
        port: free_port(),
        root: root.to_string_lossy().into_owned(),
        drain_timeout: 1,
        ..Default::default()
    };
    crate::cfg::write_json(&crate::cfg::file("config.json"), &cfg).unwrap();
    let daemon = crate::embed::host(cfg.clone()).expect("host the core");
    daemon.wait_ready().expect("services must come up");

    // a connection that never finishes must not be cut mid-flight
    let held = TcpStream::connect(format!("127.0.0.1:{}", cfg.port)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let started = std::time::Instant::now();
    daemon.stop();
    let took = started.elapsed();
    drop(held);
    assert!(took >= Duration::from_millis(800), "drain budget was not honoured: {took:?}");
    assert!(took < Duration::from_secs(5), "drain overran: {took:?}");
}

#[tokio::test]
async fn an_invitation_can_be_abandoned_by_the_caller() {
    let _g = env_lock();
    let home = home("invite-wait");
    let b = daemon(&home, &home.join("b"), "unused", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();

    let pending = tokio::time::timeout(
        Duration::from_millis(300),
        client::invite_send(&b.addr, identity::now() + 600, None, &me, &mut Store::default(), 47000, |_, _| {}),
    )
    .await;
    assert!(pending.is_err(), "the caller should be able to stop waiting");

    // the peer keeps the invitation queued, and it can still be answered
    let queued = crate::invite::list(&b.st).await;
    assert_eq!(queued.len(), 1, "{queued:?}");
    let _ = crate::invite::decide(&b.st, &queued[0].id, Decision::Deny).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(crate::invite::list(&b.st).await.is_empty());
}

// ------------------------------------------------------ on-the-wire harness

/// A recording TCP relay. Windows does not let you sniff loopback, so the only way
/// to see what really crosses the wire on one machine is to be an on-path proxy.
/// It also doubles as a tamper harness: mutating bytes here is exactly what an
/// active attacker would do.
struct Relay {
    addr: String,
    wire: Arc<Mutex<Vec<u8>>>,
}

impl Relay {
    async fn start(upstream: &str) -> Relay {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let wire = Arc::new(Mutex::new(Vec::new()));
        let up = upstream.to_string();
        let sink = wire.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let up = up.clone();
                let sink = sink.clone();
                tokio::spawn(async move {
                    let Ok(server) = TcpStream::connect(&up).await else {
                        return;
                    };
                    let (mut cr, mut cw) = client.into_split();
                    let (mut sr, mut sw) = server.into_split();
                    let a = tokio::spawn({
                        let sink = sink.clone();
                        async move { pump(&mut cr, &mut sw, &sink).await }
                    });
                    let b = tokio::spawn(async move { pump(&mut sr, &mut cw, &sink).await });
                    let _ = tokio::join!(a, b);
                });
            }
        });
        Relay { addr: format!("127.0.0.1:{port}"), wire }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.wire.lock().unwrap()).to_string()
    }
}

async fn pump<R, W>(r: &mut R, w: &mut W, sink: &Arc<Mutex<Vec<u8>>>)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut chunk = vec![0u8; 32 * 1024];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                sink.lock().unwrap().extend_from_slice(&chunk[..n]);
                if w.write_all(&chunk[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[tokio::test]
async fn the_relay_harness_sees_both_directions() {
    // self-check: an echo target must show up twice in the capture
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("127.0.0.1:{}", echo.local_addr().unwrap().port());
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut buf = [0u8; 64];
        while let Ok(n) = s.read(&mut buf).await {
            if n == 0 {
                break;
            }
            let _ = s.write_all(&buf[..n]).await;
        }
    });

    let relay = Relay::start(&target).await;
    let mut c = TcpStream::connect(&relay.addr).await.unwrap();
    c.write_all(b"ping-marker").await.unwrap();
    let mut back = [0u8; 11];
    c.read_exact(&mut back).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let wire = relay.text();
    assert!(wire.contains("ping-marker"), "relay captured nothing: {wire:?}");
    assert_eq!(wire.matches("ping-marker").count(), 2, "both directions should be teed: {wire:?}");
}

/// C1 gate: once the transport is encrypted, neither the pairing code nor file
/// contents may be readable by an on-path observer. Enable with
/// `cargo test -- --ignored` after transport encryption lands.
#[ignore = "C1: expected to fail while the transport is plaintext"]
#[tokio::test]
async fn an_on_path_observer_cannot_read_the_wire() {
    let _g = env_lock();
    let home = home("wire");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "WIRECODE", |_| {}).await;
    let relay = Relay::start(&d.addr).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());

    let marker = "SECRET-MARKER-9182";
    std::fs::write(work.join("secret.txt"), marker.as_bytes()).unwrap();
    let t = Target::new(
        relay.addr.clone(),
        Cred::Code { code: "WIRECODE".into(), password: None },
        None,
    );
    client::push(
        &t,
        me,
        &[work.join("secret.txt").display().to_string()],
        "",
        Plan { parallel: 1, resume: true, verify: false },
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(root.join("secret.txt")).unwrap(), marker.as_bytes());

    let wire = relay.text();
    assert!(wire.len() > 1024, "the relay should have seen real traffic: {} bytes", wire.len());
    assert!(!wire.contains("WIRECODE"), "the pairing code crossed the wire in the clear");
    assert!(!wire.contains(marker), "file contents crossed the wire in the clear");
}

// -------------------------------------------------- gap resume (B4)

#[tokio::test]
async fn the_peer_records_completed_ranges() {
    let _g = env_lock();
    let home = home("gapmap");
    let root = home.join("root");
    let d = daemon(&home, &root, "GM", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    let mut s = raw(&d.addr, Cred::Code { code: "GM".into(), password: None }, &me).await;

    // three ranges of 4 bytes; write the first and the last, leave the middle empty
    for (range, body) in [((0u64, 4u64), b"aaaa"), ((8, 12), b"cccc")] {
        let begin = Msg::PutBegin { path: "gap.bin".into(), size: 12, offset: range.0, len: 4, truncate: false };
        proto::write_msg(&mut s, &begin).await.unwrap();
        assert_eq!(expect_resume(&mut s).await.0, range.0, "a gap must not be skipped");
        proto::send_data(&mut s, body).await.unwrap();
        proto::send_data(&mut s, &[]).await.unwrap();
        expect_ok(&mut s).await;
    }

    proto::write_msg(&mut s, &Msg::Map { path: "gap.bin".into() }).await.unwrap();
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::Ranges { done, size } => {
            assert_eq!(size, 12, "the part file spans the highest written byte");
            assert_eq!(done, vec![(0, 4), (8, 12)], "only real ranges are recorded");
        }
        other => panic!("unexpected {other:?}"),
    }

    // landing the file clears the record
    set_code(&d.st, "GM2").await;
    let mut s = raw(&d.addr, Cred::Code { code: "GM2".into(), password: None }, &me).await;
    let end = Msg::PutEnd { path: "gap.bin".into(), size: 12, mtime: 0, sha256: None };
    proto::write_msg(&mut s, &end).await.unwrap();
    expect_ok(&mut s).await;
    proto::write_msg(&mut s, &Msg::Map { path: "gap.bin".into() }).await.unwrap();
    match proto::read_msg(&mut s).await.unwrap() {
        Msg::Ranges { done, size } => {
            assert!(done.is_empty(), "landing must forget the ranges: {done:?}");
            assert_eq!(size, 0, "the staging file is gone");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn a_middle_gap_is_resumed_without_resending_the_rest() {
    let _g = env_lock();
    let home = home("gapresume");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "GR", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());

    // 24 MB over 3 streams -> three 8 MB ranges
    let payload: Vec<u8> = (0..24 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let local = work.join("gap.bin");
    std::fs::write(&local, &payload).unwrap();
    let size = payload.len() as u64;
    let grid = client::ranges(size, 3);
    assert_eq!(grid.len(), 3, "the test needs three ranges: {grid:?}");

    // simulate an interrupted attempt: first and last range already written
    let me_raw = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    let mut s = raw(&d.addr, Cred::Code { code: "GR".into(), password: None }, &me_raw).await;
    for (from, to) in [grid[0], grid[2]] {
        let begin = Msg::PutBegin { path: "gap.bin".into(), size, offset: from, len: to - from, truncate: false };
        proto::write_msg(&mut s, &begin).await.unwrap();
        assert_eq!(expect_resume(&mut s).await.0, from);
        send_bulk(&mut s, &payload[from as usize..to as usize]).await;
        proto::send_data(&mut s, &[]).await.unwrap();
        expect_ok(&mut s).await;
    }
    drop(s);

    // a normal push only has to fill the hole and land the file
    set_code(&d.st, "GR2").await;
    let t = target(&d, "GR2");
    client::push(&t, me.clone(), &[local.display().to_string()], "", Plan { parallel: 3, resume: true, verify: true })
        .await
        .expect("gap resume");
    assert!(std::fs::read(root.join("gap.bin")).unwrap() == payload, "gap resume produced wrong bytes");

    // the record is gone now
    let (done, staged, _) = client::ranges_done(&t, &me, "gap.bin").await.unwrap();
    assert!(done.is_empty() && staged == 0, "{done:?} {staged}");
}

#[tokio::test]
async fn gap_resume_trusts_the_record_instead_of_the_bytes() {
    let _g = env_lock();
    let home = home("gaptrust");
    let root = home.join("root");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let d = daemon(&home, &root, "GT", |_| {}).await;
    let me = Arc::new(Identity::load_or_create_at(&home.join("me.json")).unwrap());

    // 24 MB, three ranges; the first range on the peer holds *different* bytes
    let payload: Vec<u8> = (0..24 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let local = work.join("gap.bin");
    std::fs::write(&local, &payload).unwrap();
    let size = payload.len() as u64;
    let grid = client::ranges(size, 3);
    assert_eq!(grid.len(), 3, "{grid:?}");
    let first = grid[0];

    let me_raw = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    let mut s = raw(&d.addr, Cred::Code { code: "GT".into(), password: None }, &me_raw).await;
    let begin = Msg::PutBegin { path: "gap.bin".into(), size, offset: first.0, len: first.1 - first.0, truncate: false };
    proto::write_msg(&mut s, &begin).await.unwrap();
    expect_resume(&mut s).await;
    send_bulk(&mut s, &vec![b'X'; (first.1 - first.0) as usize]).await;
    proto::send_data(&mut s, &[]).await.unwrap();
    expect_ok(&mut s).await;
    drop(s);

    // a completed range is not re-sent, so verification is the only thing that can
    // notice the mismatch — which is exactly why --verify exists.
    set_code(&d.st, "GT2").await;
    let t = target(&d, "GT2");
    let err = client::push(&t, me, &[local.display().to_string()], "", Plan { parallel: 3, resume: true, verify: true })
        .await
        .unwrap_err();
    assert!(err.contains("checksum"), "{err}");
    assert!(!root.join("gap.bin").exists(), "a rejected upload must not land");
}

/// A parallel push opens its ranges concurrently, so a higher range can fill the part
/// file past a lower range's start before that range connects. The part file's length
/// is not a prefix: the lower range still has to send its own bytes.
#[tokio::test]
async fn a_late_range_never_skips_bytes_written_by_a_higher_one() {
    let _g = env_lock();
    let home = home("late-range");
    let root = home.join("root");
    let d = daemon(&home, &root, "LR", |c| c.code_one_shot = false).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    const M8: u64 = 8 * 1024 * 1024;
    let size = 3 * M8;

    // the *last* range goes first and grows the part file to 24 MB
    let mut high = raw(&d.addr, Cred::Code { code: "LR".into(), password: None }, &me).await;
    let begin = Msg::PutBegin { path: "p.bin".into(), size, offset: 2 * M8, len: M8, truncate: false };
    proto::write_msg(&mut high, &begin).await.unwrap();
    assert_eq!(expect_resume(&mut high).await.0, 2 * M8);
    send_bulk(&mut high, &vec![1u8; M8 as usize]).await;

    // the first range must start at 0, not at the length the peer already holds
    let mut low = raw(&d.addr, Cred::Code { code: "LR".into(), password: None }, &me).await;
    let begin = Msg::PutBegin { path: "p.bin".into(), size, offset: 0, len: M8, truncate: false };
    proto::write_msg(&mut low, &begin).await.unwrap();
    let (start, _) = expect_resume(&mut low).await;
    assert_eq!(start, 0, "range 0 skipped bytes that the last range had written");
}

// -------------------------------------------------- structured errors (G6)

#[tokio::test]
async fn failures_carry_a_machine_readable_kind() {
    let _g = env_lock();
    let home = home("errkind");
    let root = home.join("root");
    let d = daemon(&home, &root, "EK", |_| {}).await;
    let me = Identity::load_or_create_at(&home.join("me.json")).unwrap();
    std::fs::create_dir_all(root.join("adir")).unwrap();
    std::fs::write(root.join("tiny.bin"), b"abcd").unwrap();
    let mut s = raw(&d.addr, Cred::Code { code: "EK".into(), password: None }, &me).await;

    // a part file that is too short for the declared size
    let begin = Msg::PutBegin { path: "tiny.bin".into(), size: 4, offset: 0, len: 4, truncate: false };
    proto::write_msg(&mut s, &begin).await.unwrap();
    expect_resume(&mut s).await;
    proto::send_data(&mut s, b"abcd").await.unwrap();
    proto::send_data(&mut s, &[]).await.unwrap();
    expect_ok(&mut s).await;

    let cases: Vec<(Msg, &str)> = vec![
        (Msg::List { path: "../escape".into() }, "path"),
        (Msg::List { path: "missing".into() }, "notfound"),
        (Msg::GetBegin { path: "adir".into(), offset: 0, len: 4 }, "isdir"),
        (Msg::Del { path: "adir".into() }, "isdir"),
        (
            Msg::PutBegin { path: "x.bin".into(), size: 4, offset: u64::MAX, len: 4, truncate: false },
            "range",
        ),
        (Msg::PutEnd { path: "tiny.bin".into(), size: 99, mtime: 0, sha256: None }, "incomplete"),
    ];
    for (frame, want) in cases {
        let label = format!("{frame:?}");
        proto::write_msg(&mut s, &frame).await.unwrap();
        let (code, msg) = expect_err_coded(&mut s).await;
        assert_eq!(code, want, "{label} gave {code}: {msg}");
        assert!(!msg.is_empty(), "{label} lost its message");
    }
}

// --------------------------------------------------------------- rest api

/// Minimal HTTP client for the loopback REST surface: returns (status line, body).
async fn http_get(addr: &str, path: &str) -> (String, String) {
    http_with(addr, &format!("GET {path} HTTP/1.1\r\n")).await
}

async fn http_bearer(addr: &str, path: &str, token: &str) -> (String, String) {
    http_with(addr, &format!("GET {path} HTTP/1.1\r\nAuthorization: Bearer {token}\r\n")).await
}

async fn http_with(addr: &str, first: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!("{first}Host: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    match text.split_once("\r\n\r\n") {
        Some((head, body)) => (head.lines().next().unwrap_or_default().to_string(), body.to_string()),
        None => (text, String::new()),
    }
}

#[tokio::test]
async fn the_rest_api_needs_the_key_and_serves_the_live_state() {
    let _g = env_lock();
    let home = home("restapi");
    let root = home.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let d = daemon(&home, &root, "UI", |c| c.api_port = free_port()).await;
    let addr = format!("127.0.0.1:{}", crate::api::api_port(&d.st));
    tokio::spawn(crate::api::serve(d.st.clone(), "webtok".into()));
    for _ in 0..40 {
        if TcpStream::connect(&addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // no key, wrong key: both refused before touching state
    let (status, _) = http_get(&addr, "/api/status").await;
    assert!(status.contains("403"), "{status}");
    let (status, body) = http_get(&addr, "/api/status?t=guess").await;
    assert!(status.contains("403") && !body.contains(&d.st.id.id), "{status} {body}");

    // the key opens it, from the query string or the header
    let (_, body) = http_get(&addr, "/api/status?t=webtok").await;
    assert!(body.contains(&d.st.id.id), "{body}");
    assert!(body.contains("\"proto\":"), "{body}");
    let (status, body) = http_bearer(&addr, "/api/status", "webtok").await;
    assert!(status.contains("200") && body.contains(&d.st.id.id), "{status} {body}");

    let (_, body) = http_get(&addr, "/api/code?t=webtok").await;
    let before = d.st.code.lock().await.code.clone();
    assert!(body.contains(&before), "{body}");

    let (_, body) = http_get(&addr, "/api/devices?t=webtok").await;
    assert!(body.contains("\"items\""), "{body}");
    let (_, body) = http_get(&addr, "/api/invites?t=webtok").await;
    assert_eq!(body.trim(), "{\"items\":[]}", "{body}");

    // no page is served: a frontend of your own is expected
    let (status, _) = http_get(&addr, "/?t=webtok").await;
    assert!(status.contains("404"), "{status}");
    // an unknown endpoint is a clean 404, not a panic
    let (status, _) = http_get(&addr, "/api/nope?t=webtok").await;
    assert!(status.contains("404"), "{status}");
}


// ------------------------------------------------------------- config

#[tokio::test]
async fn config_handles_corruption_and_durations() {
    let _g = env_lock();
    let home = home("cfg");
    std::fs::write(home.join("config.json"), b"{ not json").unwrap();
    let cfg = Config::load();
    assert!(cfg.port > 0);
    assert!(cfg.root.contains("share"), "{}", cfg.root);

    let now = identity::now();
    assert_eq!(crate::cfg::parse_expiry("never").unwrap(), 0);
    assert!(crate::cfg::parse_expiry("1w").unwrap() >= now + 7 * 86400);
    assert!(crate::cfg::parse_expiry("15m").unwrap() >= now + 900);
    assert_eq!(crate::cfg::parse_expiry("").unwrap(), 0);
    assert!(crate::cfg::parse_expiry("5y").is_err());

    // guard: empty remote path means "the root itself"
    let root = home.join("share");
    std::fs::create_dir_all(&root).unwrap();
    assert_eq!(guard::resolve(&root, "").unwrap(), root);
}







