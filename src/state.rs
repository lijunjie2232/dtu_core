//! Daemon state shared by the TCP listener, the control port and discovery.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::{oneshot, Mutex};

use crate::cfg::Config;
use crate::identity::Identity;
use crate::trust::Store;

pub enum Decision {
    Accept { expires_at: u64 },
    Deny,
}

pub struct Pending {
    pub id: String,
    pub from: String,
    pub addr: String,
    pub expires_at: u64,
    pub created: u64,
    pub tx: Option<oneshot::Sender<Decision>>,
}

pub struct CodeState {
    pub code: String,
    pub password: Option<String>,
    pub consumed: bool,
}

/// One transfer started through the REST surface, polled by its id.
#[derive(Serialize)]
pub struct Job {
    pub kind: String,
    /// running | done | error
    pub state: String,
    pub lines: Vec<String>,
    pub error: Option<String>,
}

pub struct State {
    pub cfg: Config,
    pub id: Identity,
    /// Canonical served root. Canonicalizing once makes every joined path a verbatim
    /// path on Windows, which is what allows trees deeper than MAX_PATH.
    pub root: std::path::PathBuf,
    pub trust: Mutex<Store>,
    pub code: Mutex<CodeState>,
    /// Failed pairing-code attempts per source address.
    pub fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    /// Inbound invitations waiting for a human decision.
    pub invites: Mutex<Vec<Pending>>,
    /// Live connections per source address, so one peer cannot exhaust the runtime.
    pub conns: Mutex<HashMap<IpAddr, u32>>,
    /// Devices that authenticated with a one-time code, and until when their session
    /// stays valid. They are never in the trust store, so this is what keeps their
    /// session tokens working (bounded by the same TTL).
    pub code_sessions: Mutex<HashMap<String, u64>>,
    /// Byte ranges already written for an in-progress upload, keyed by wire path.
    /// Kept in memory: it only has to survive one failed attempt, and losing it falls
    /// back to plain prefix resume.
    pub ranges: Mutex<HashMap<String, Vec<(u64, u64)>>>,
    /// Transfers started over the REST surface, keyed by job id.
    pub jobs: Mutex<BTreeMap<String, Job>>,
    pub started: u64,
}

impl State {
    pub fn new(cfg: Config, id: Identity, trust: Store) -> Arc<Self> {
        let code = CodeState {
            code: crate::identity::random_code(8),
            password: cfg.code_password.clone(),
            consumed: false,
        };
        let root = cfg.root_path();
        let root = root.canonicalize().unwrap_or(root);
        Arc::new(Self {
            cfg,
            id,
            root,
            trust: Mutex::new(trust),
            code: Mutex::new(code),
            fails: Mutex::new(HashMap::new()),
            invites: Mutex::new(Vec::new()),
            conns: Mutex::new(HashMap::new()),
            code_sessions: Mutex::new(HashMap::new()),
            ranges: Mutex::new(HashMap::new()),
            jobs: Mutex::new(BTreeMap::new()),
            started: crate::identity::now(),
        })
    }

    /// `None` keeps the current password, `Some(None)` clears it.
    pub async fn rotate_code(&self, password: Option<Option<String>>) {
        let mut c = self.code.lock().await;
        c.code = crate::identity::random_code(8);
        c.consumed = false;
        if let Some(p) = password {
            c.password = p;
        }
    }

    /// Adopt the settings a running app can take without a restart; everything else
    /// is read from `config.json` at startup.
    pub async fn apply_live(&self, cfg: &Config) {
        self.code.lock().await.password = cfg.code_password.clone();
    }

    pub async fn drop_invite(&self, id: &str) {
        let mut q = self.invites.lock().await;
        q.retain(|p| p.id != id);
    }

    /// Count a new connection; `false` when this source is already at its limit.
    pub async fn adopt_conn(&self, ip: IpAddr) -> bool {
        let mut conns = self.conns.lock().await;
        let slot = conns.entry(ip).or_insert(0);
        if *slot >= self.cfg.max_conn_per_ip.max(1) {
            return false;
        }
        *slot += 1;
        true
    }

    pub async fn release_conn(&self, ip: IpAddr) {
        let mut conns = self.conns.lock().await;
        if let Some(n) = conns.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                conns.remove(&ip);
            }
        }
    }

    /// Total live data connections, used to drain before shutting down.
    pub async fn active_conns(&self) -> u32 {
        self.conns.lock().await.values().copied().sum()
    }

    pub async fn prune_invites(&self) {
        let timeout = Duration::from_secs(self.cfg.invite_timeout.max(1));
        let mut q = self.invites.lock().await;
        q.retain(|p| p.tx.is_some() && p.created + timeout.as_secs() > crate::identity::now());
    }
}
