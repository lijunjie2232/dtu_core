//! LAN discovery over UDP broadcast. Replies expose nothing but the device id.
//!
//! Both ends are assumed to listen on the same port (the probe targets ours).
//! IPv6 peers and non-default ports are reached by explicit address
//! (`dtu device add [fe80::1%12]:47000`); transfers themselves are dual-stack.
//! On Windows, an inbound firewall rule for the port is required for scanning.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::proto::Seen;
use crate::state::State;
use crate::trust::Store;

const PROBE: &[u8] = b"DTU1?";
const REPLY: &str = "DTU1:";

pub async fn serve(st: Arc<State>) {
    let port = st.cfg.port;
    let sock = match UdpSocket::bind(("0.0.0.0", port)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("discovery disabled (udp {port}: {e})");
            return;
        }
    };
    let mut buf = [0u8; 64];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, from)) if &buf[..n] == PROBE => {
                let reply = format!("{REPLY}{}", st.id.id);
                let _ = sock.send_to(reply.as_bytes(), from).await;
            }
            _ => {}
        }
    }
}

/// Broadcast a probe and collect answers for `wait_ms`.
pub async fn scan(port: u16, wait_ms: u64, me: &str, trust: &Store) -> Vec<Seen> {
    let sock = match UdpSocket::bind(("0.0.0.0", 0)).await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let _ = sock.set_broadcast(true);
    let _ = sock.send_to(PROBE, ("255.255.255.255", port)).await;

    let deadline = Instant::now() + Duration::from_millis(wait_ms.clamp(100, 10_000));
    let mut found: BTreeMap<String, Seen> = BTreeMap::new();
    let mut buf = [0u8; 64];
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let Ok(Ok((n, from))) = tokio::time::timeout(left, sock.recv_from(&mut buf)).await else {
            break;
        };
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        if let Some(id) = text.strip_prefix(REPLY) {
            if id.is_empty() || id == me {
                continue;
            }
            found.insert(
                id.to_string(),
                Seen {
                    id: id.to_string(),
                    addr: format!("{}:{}", from.ip(), port),
                    trusted: trust.get_raw(id).is_some(),
                },
            );
        }
    }
    found.into_values().collect()
}
