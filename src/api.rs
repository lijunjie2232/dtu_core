//! Loopback REST control surface: every daemon capability over HTTP, guarded by
//! the local key written at init (`control.token`, in the user data dir).
//!
//! No page is served here — a web frontend lives where its author wants it and
//! talks to this API. The bundled UIs (`dtu_cli`, `dtu_tui`, `dtu_gui`) do not:
//! they call the crate directly.
//!
//! Authenticate with `Authorization: Bearer <key>`, or `?t=<key>` for a quick
//! curl. Prefer the header: a key in the URL leaks into history and referrers.

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::client::{self, Plan, Target};
use crate::proto::Ctrl;
use crate::state::{Job, State};

/// Keep a bounded history: a frontend polling transfers must not grow the daemon.
const MAX_JOBS: usize = 32;

pub async fn serve(st: Arc<State>, token: String) {
    let port = api_port(&st);
    let listener = match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("dtu: REST surface disabled (127.0.0.1:{port}: {e})");
            return;
        }
    };
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                let st = st.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    let _ = one(sock, st, token).await;
                });
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
        }
    }
}

/// Loopback port for the REST surface. `api_port` wins; otherwise one above the
/// LAN port, which is what frontends document.
pub fn api_port(st: &State) -> u16 {
    if st.cfg.api_port != 0 {
        st.cfg.api_port
    } else {
        st.cfg.port.saturating_add(1)
    }
}

async fn one(mut sock: TcpStream, st: Arc<State>, token: String) -> Result<(), String> {
    let mut buf = vec![0u8; 16 * 1024];
    let n = sock.read(&mut buf).await.map_err(|e| e.to_string())?;
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or("/").to_string();
    let bearer = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("authorization"))
        .and_then(|(_, v)| v.trim().strip_prefix("Bearer ").map(|t| t.trim().to_string()))
        .unwrap_or_default();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };

    if method == "OPTIONS" {
        return respond(&mut sock, 204, "").await;
    }
    let given = param(&query, "t").unwrap_or_default();
    if !crate::identity::ct_eq(&given, &token) && !crate::identity::ct_eq(&bearer, &token) {
        return respond(&mut sock, 403, "{\"error\":\"forbidden: Authorization: Bearer <control.token>\"}").await;
    }
    let (status, body) = route(&st, &method, &path, &query).await;
    respond(&mut sock, status, &body).await
}

async fn route(st: &Arc<State>, method: &str, path: &str, query: &str) -> (u16, String) {
    match (method, path) {
        ("GET", "/api/status") => ctrl_json(st, Ctrl::Status).await,
        ("GET", "/api/code") => ctrl_json(st, Ctrl::CodeShow).await,
        ("POST", "/api/code/refresh") => ctrl_json(st, Ctrl::CodeRefresh { password: param(query, "password") }).await,
        ("GET", "/api/invites") => ctrl_json(st, Ctrl::Invites).await,
        ("GET", "/api/scan") => {
            let wait_ms = param(query, "wait").and_then(|v| v.parse().ok()).unwrap_or(1500);
            ctrl_json(st, Ctrl::Scan { wait_ms }).await
        }
        ("POST", "/api/shutdown") => (
            400,
            "{\"error\":\"the client app owns its lifetime; shutdown is not a remote operation\"}".to_string(),
        ),
        ("GET", "/api/devices") => (200, json!({ "items": devices(st).await }).to_string()),
        ("GET", "/api/log") => {
            let n = param(query, "n").and_then(|v| v.parse().ok()).unwrap_or(20);
            (200, json!({ "lines": crate::audit::tail(n) }).to_string())
        }
        // Read from disk: a PUT lands in config.json, and reporting the running
        // daemon's snapshot instead would just show the value before the write.
        ("GET", "/api/config") => (200, serde_json::to_string(&crate::cfg::Config::load()).unwrap_or_default()),
        ("PUT", "/api/config") => put_config(query).await,
        ("POST", "/api/transfer") => start_job(st, query).await,
        _ if path.starts_with("/api/invites/") => invite_action(st, path, query).await,
        _ if path.starts_with("/api/devices/") => device_action(st, method, path, query).await,
        _ if path.starts_with("/api/transfer/") => job_view(st, path).await,
        _ => (404, "{\"error\":\"no such endpoint\"}".to_string()),
    }
}

async fn ctrl_json(st: &Arc<State>, req: Ctrl) -> (u16, String) {
    match crate::server::control_handle(st, req).await {
        Ctrl::Err { msg } => (400, json!({ "error": msg }).to_string()),
        other => (200, untagged(&other)),
    }
}

/// The control replies carry a `t` discriminator for the binary protocol; JSON
/// clients get the payload without it.
fn untagged(reply: &Ctrl) -> String {
    match serde_json::to_value(reply) {
        Ok(Value::Object(mut map)) => {
            map.remove("t");
            Value::Object(map).to_string()
        }
        Ok(other) => other.to_string(),
        Err(e) => json!({ "error": e.to_string() }).to_string(),
    }
}

async fn devices(st: &State) -> Vec<Value> {
    let store = st.trust.lock().await.clone();
    store
        .devices
        .iter()
        .map(|(id, d)| {
            json!({
                "id": id,
                "alias": d.alias,
                "addr": d.addr,
                "expires_at": d.expires_at,
                "expired": store.get(id).is_none(),
                "pubkey": d.pubkey.chars().take(12).collect::<String>(),
            })
        })
        .collect()
}

async fn device_action(st: &Arc<State>, method: &str, path: &str, query: &str) -> (u16, String) {
    let rest = path.trim_start_matches("/api/devices/");
    let (name, action) = match rest.split_once('/') {
        Some((n, a)) => (n, Some(a)),
        None => (rest, None),
    };
    let mut store = st.trust.lock().await;
    let id = store.resolve(name).map(|(id, _)| id.to_string()).unwrap_or_else(|| name.to_string());
    match (method, action) {
        ("DELETE", None) => {
            if !store.remove(&id) {
                return (404, json!({ "error": format!("no such device: {id}") }).to_string());
            }
            let saved = store.save().map_err(|e| json!({ "error": e }).to_string());
            saved.map_or_else(|e| (500, e), |_| (200, json!({ "removed": id }).to_string()))
        }
        ("POST", Some("alias")) => {
            let alias = param(query, "name").unwrap_or_default();
            match store.set_alias(&id, Some(&alias)).and_then(|_| store.save()) {
                Ok(()) => (200, json!({ "id": id, "alias": alias }).to_string()),
                Err(e) => (400, json!({ "error": e }).to_string()),
            }
        }
        _ => (404, "{\"error\":\"no such action\"}".to_string()),
    }
}

async fn invite_action(st: &Arc<State>, path: &str, query: &str) -> (u16, String) {
    let Some((id, action)) = path.trim_start_matches("/api/invites/").split_once('/') else {
        return (404, "{\"error\":\"no such endpoint\"}".to_string());
    };
    match action {
        "accept" => {
            let exp = param(query, "expires").unwrap_or_else(|| "30d".into());
            match crate::cfg::parse_expiry(&exp) {
                Ok(expires_at) => ctrl_json(st, Ctrl::InviteAccept { id: id.to_string(), expires_at }).await,
                Err(e) => (400, json!({ "error": format!("expires: {e}") }).to_string()),
            }
        }
        "deny" => ctrl_json(st, Ctrl::InviteDeny { id: id.to_string() }).await,
        _ => (404, "{\"error\":\"no such action\"}".to_string()),
    }
}

