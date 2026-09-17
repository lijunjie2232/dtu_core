//! Wire protocol: `[u32 LE len][JSON]` control frames, raw bytes for file data.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Wire-format version. Bumped only on incompatible frame changes; peers refuse
/// each other instead of half-working across mixed versions.
pub const PROTO: u32 = 1;

/// Max size of one JSON control frame.
pub const MAX_CTRL: usize = 1 << 20;
/// Max size of one raw data chunk.
pub const MAX_DATA: u64 = 4 << 20;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    /// Path relative to the served root, `/` separated.
    pub path: String,
    pub size: u64,
    pub mtime: u64,
    /// Directories carry no bytes; they exist so empty ones survive a sync.
    pub dir: bool,
}

/// How a client proves who it is. One auth per TCP connection.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind")]
pub enum Cred {
    /// JWT the peer issued for us (permanent trust).
    Token { token: String },
    /// Ephemeral one-time pairing code.
    Code { code: String, password: Option<String> },
    /// Short-lived token the peer handed us in `HelloOk`, so one pairing code can
    /// authorize the several TCP connections a parallel transfer needs.
    Session { token: String },
    /// Unlimit mode probe (accepted only if the server enabled it).
    Any,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t")]
pub enum Msg {
    Hello { proto: u32, id: String, pubkey: String, cred: Cred, nonce: u64 },
    HelloOk { proto: u32, id: String, pubkey: String, token: String },
    AuthFail { reason: String },
    /// Client -> server: I am about to write bytes [offset, offset+len) of `path`.
    PutBegin { path: String, size: u64, offset: u64, len: u64, truncate: bool },
    /// Server -> client: resume cursor (clamped into the requested range).
    Resume { offset: u64, size: u64, mtime: u64 },
    /// Followed by exactly `len` raw bytes. len == 0 ends the stream.
    Data { len: u64 },
    PutEnd { path: String, size: u64, mtime: u64, sha256: Option<String> },
    GetBegin { path: String, offset: u64, len: u64 },
    List { path: String },
    /// Create one directory (and any missing parents).
    Mkdir { path: String },
    /// Which byte ranges of an in-progress upload the peer already holds.
    Map { path: String },
    Ranges { done: Vec<(u64, u64)>, size: u64 },
    /// Read-only size/mtime probe: answers `Resume` without touching anything.
    Stat { path: String },
    Del { path: String },
    /// Entries are chunked: `more` means another frame follows on this connection.
    Entries { items: Vec<Entry>, more: bool },
    Ok,
    /// `port` is the inviter's listening TCP port. The connection itself arrives
    /// from an ephemeral source port, so a receiver that wants a dialable address
    /// for the new device needs this. 0 means an older build that did not send it.
    Invite { proto: u32, from: String, pubkey: String, expires_at: u64, note: Option<String>, #[serde(default)] port: u16 },
    InvitePending { proto: u32, id: String, peer: String, pubkey: String },
    Accept { token: String },
    InviteDone { token: String },
    Deny { reason: Option<String> },
    Err { code: String, msg: String },
}

/// Requests behind the REST surface. The bundled UIs call the same handlers
/// in-process; there is no network control port.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t")]
pub enum Ctrl {
    Status,
    CodeShow,
    CodeRefresh { password: Option<String> },
    Invites,
    InviteAccept { id: String, expires_at: u64 },
    InviteDeny { id: String },
    Scan { wait_ms: u64 },
    StatusOk { id: String, version: String, proto: u32, port: u16, root: String, unlimit: bool, trusted: usize, pending: usize, uptime: u64 },
    Code { code: String, password: bool, consumed: bool },
    InvitesOk { items: Vec<InviteView> },
    ScanOk { items: Vec<Seen> },
    Ok { msg: String },
    Err { msg: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteView {
    pub id: String,
    pub from: String,
    pub addr: String,
    pub expires_at: u64,
    pub created: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Seen {
    pub id: String,
    pub addr: String,
    pub trusted: bool,
}

pub async fn write_json<W, T>(w: &mut W, v: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(v).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if body.len() > MAX_CTRL {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "control frame too large"));
    }
    w.write_all(&(body.len() as u32).to_le_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}

pub async fn read_json<R, T>(r: &mut R) -> std::io::Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut head = [0u8; 4];
    r.read_exact(&mut head).await?;
    let n = u32::from_le_bytes(head) as usize;
    if n > MAX_CTRL {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "control frame too large"));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, m: &Msg) -> std::io::Result<()> {
    write_json(w, m).await
}

pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Msg> {
    read_json(r).await
}

/// Send one data chunk (`Data{len}` + bytes). Empty slice = end-of-stream marker.
pub async fn send_data<W: AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> std::io::Result<()> {
    if buf.len() as u64 > MAX_DATA {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "chunk too large"));
    }
    write_msg(w, &Msg::Data { len: buf.len() as u64 }).await?;
    if !buf.is_empty() {
        w.write_all(buf).await?;
        w.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_survive_partial_and_batched_reads() {
        let (mut a, mut b) = tokio::io::duplex(16);
        let writer = tokio::spawn(async move {
            write_msg(&mut a, &Msg::Ok).await.unwrap();
            write_msg(&mut a, &Msg::List { path: "dir".into() }).await.unwrap();
            write_msg(&mut a, &Msg::PutBegin { path: "x".into(), size: 10, offset: 0, len: 10, truncate: false })
                .await
                .unwrap();
            send_data(&mut a, b"hello").await.unwrap();
        });
        assert!(matches!(read_msg(&mut b).await.unwrap(), Msg::Ok));
        assert!(matches!(read_msg(&mut b).await.unwrap(), Msg::List { .. }));
        assert!(matches!(read_msg(&mut b).await.unwrap(), Msg::PutBegin { size: 10, .. }));
        match read_msg(&mut b).await.unwrap() {
            Msg::Data { len } => {
                assert_eq!(len, 5);
                let mut buf = vec![0u8; 5];
                b.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"hello");
            }
            other => panic!("expected Data, got {other:?}"),
        }
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = a.write_all(&((MAX_CTRL as u32) + 1).to_le_bytes()).await;
        });
        let err = read_msg(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}

