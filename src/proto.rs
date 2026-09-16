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

