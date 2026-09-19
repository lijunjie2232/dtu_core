//! Invitation handshake (the "trust this device" flow) and its pending queue.
//!
//! A -> B : Invite{from, pubkey, expires_at, port}
//! B -> A : InvitePending{id, peer=B, pubkey=B}      (B waits for a human)
//! B -> A : Accept{token issued by B for A} | Deny
//! A -> B : InviteDone{token issued by A for B}
//! B -> A : Ok                                        (both sides now trust each other)
//!
//! Accept also records a dialable address for A: A's IP (from the socket) plus the
//! listening port it advertised in the invite, because the socket's own source port
//! is ephemeral and useless once this connection closes.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::oneshot;

use crate::proto::{self, InviteView, Msg};
use crate::state::{Decision, Pending, State};

/// One invitation, already version-checked.
pub struct Invite {
    pub from: String,
    pub pubkey: String,
    pub expires_at: u64,
    pub note: Option<String>,
    /// Where the peer can be dialled afterwards, from `dialable`.
    pub dial: Option<String>,
}

pub async fn handle(st: Arc<State>, s: &mut TcpStream, addr: String, inv: Invite) -> Result<(), String> {
    let Invite { from, pubkey, expires_at, note, dial } = inv;
    let id = crate::identity::random_code(6);
    let (tx, rx) = oneshot::channel();
    if !st.cfg.unlimit {
        let mut q = st.invites.lock().await;
        q.push(Pending {
            id: id.clone(),
            from: from.clone(),
            addr: addr.clone(),
            expires_at,
            created: crate::identity::now(),
            tx: Some(tx),
        });
    }
    crate::audit::log(
        "invite",
        "pending",
        "invite",
        Some(&from),
        &addr,
        note.as_deref(),
    );
    proto::write_msg(
        s,
        &Msg::InvitePending {
            proto: proto::PROTO,
            id: id.clone(),
            peer: st.id.id.clone(),
            pubkey: st.id.pubkey(),
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    let decision = if st.cfg.unlimit {
        Some(Decision::Accept { expires_at })
    } else {
        match tokio::time::timeout(Duration::from_secs(st.cfg.invite_timeout.max(1)), rx).await {
            Ok(Ok(d)) => Some(d),
            Ok(Err(_)) => None,
            Err(_) => None,
        }
    };

    let result = match decision {
        Some(Decision::Accept { expires_at }) => accept(st.clone(), s, &from, &pubkey, expires_at, dial).await,
        Some(Decision::Deny) => {
            crate::audit::log("invite", "deny", "invite", Some(&from), &addr, None);
            proto::write_msg(s, &Msg::Deny { reason: Some("denied by user".into()) })
                .await
                .map_err(|e| e.to_string())
        }
        None => {
            crate::audit::log("invite", "timeout", "invite", Some(&from), &addr, None);
            proto::write_msg(s, &Msg::Err { code: "invite_timeout".into(), msg: "no decision".into() })
                .await
                .map_err(|e| e.to_string())
        }
    };
    st.drop_invite(&id).await;
    result
}

/// The invite arrives from an ephemeral source port, so the address worth keeping is
/// the sender's IP plus the listening port it advertised (0 = older build, keep none).
pub fn dialable(peer: &str, listen_port: u16) -> Option<String> {
    if listen_port == 0 {
        return None;
    }
    let ip = peer.parse::<std::net::SocketAddr>().ok()?.ip();
    Some(std::net::SocketAddr::new(ip, listen_port).to_string())
}

async fn accept(
    st: Arc<State>,
    s: &mut TcpStream,
    from: &str,
    pubkey: &str,
    expires_at: u64,
    dial: Option<String>,
) -> Result<(), String> {
    // Our half of the pair: a token we sign, granting the peer access to us.
    let mine = crate::jwt::sign(&st.id, from, expires_at);
    proto::write_msg(s, &Msg::Accept { token: mine }).await.map_err(|e| e.to_string())?;

    let back = match proto::read_msg(s).await.map_err(|e| e.to_string())? {
        Msg::InviteDone { token } => token,
        _ => return Err("expected invite completion".into()),
    };
    // Their half: signed by them, made out to us.
    let claims = crate::jwt::verify(pubkey, &back, from, &st.id.id, crate::identity::now())?;

    if !st.cfg.unlimit || st.cfg.unlimit_store_trust {
        let mut trust = st.trust.lock().await;
        trust.insert(from, pubkey, &back, claims.exp, dial);
        trust.save()?;
    }
    crate::audit::log("invite", "ok", "invite", Some(from), "-", None);
    proto::write_msg(s, &Msg::Ok).await.map_err(|e| e.to_string())
}

/// Called from the control port: resolve a pending invitation.
pub async fn decide(st: &State, id: &str, decision: Decision) -> Result<(), String> {
    let mut q = st.invites.lock().await;
    let p = q.iter_mut().find(|p| p.id == id).ok_or("no such invite")?;
    match p.tx.take() {
        Some(tx) => tx.send(decision).map_err(|_| "invite connection is gone".to_string()),
        None => Err("invite already answered".into()),
    }
}

pub async fn list(st: &State) -> Vec<InviteView> {
    st.prune_invites().await;
    let q = st.invites.lock().await;
    q.iter()
        .map(|p| InviteView {
            id: p.id.clone(),
            from: p.from.clone(),
            addr: p.addr.clone(),
            expires_at: p.expires_at,
            created: p.created,
        })
        .collect()
}
