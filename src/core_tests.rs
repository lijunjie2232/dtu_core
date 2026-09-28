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

