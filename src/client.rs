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

