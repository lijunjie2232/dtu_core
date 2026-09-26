//! Host the core inside a frontend process.
//!
//! `dtu_core` has no daemon of its own: whoever wants one hosts it. `dtu_cli`,
//! `dtu_tui`, `dtu_gui` and any third-party client all start with [`host`], get
//! back the live [`State`], drive it in-process, and call [`Daemon::stop`] when
//! the app exits. Only one process may own a data directory at a time.

use std::sync::Arc;

use crate::cfg::Config;
use crate::state::State;

pub struct Daemon {
    /// Live state the services mutate: read it (and call the crate) directly.
    pub state: Arc<State>,
    /// Local key for the REST surface (also in `control.token`).
    pub key: String,
    stop: Arc<tokio::sync::Notify>,
    ready: std::sync::mpsc::Receiver<Result<(), String>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Daemon {
    /// REST port the services listen on (loopback).
    pub fn api_port(&self) -> u16 {
        crate::api::api_port(&self.state)
    }

    /// Block until the LAN listener is bound. Errors carry the bind failure.
    pub fn wait_ready(&self) -> Result<(), String> {
        match self.ready.recv() {
            Ok(r) => r,
            Err(_) => Err("services stopped before they were ready".into()),
        }
    }

    /// Stop the services, letting in-flight transfers drain, and wait for them.
    pub fn stop(mut self) {
        self.stop.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Start the core here: listener, discovery and the REST surface, all owned by
/// this process. Fails when another dtu app already owns the data directory.
pub fn host(cfg: Config) -> Result<Daemon, String> {
    let prepared = crate::server::prepare(cfg)?;
    let state = prepared.state.clone();
    let key = prepared.key.clone();
    let stop = Arc::new(tokio::sync::Notify::new());
    let (ready_tx, ready) = std::sync::mpsc::channel();

    let thread_stop = stop.clone();
    let thread = std::thread::Builder::new()
        .name("dtu-core".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("core runtime: {e}")));
                    return;
                }
            };
            if let Err(e) = rt.block_on(crate::server::serve(prepared, ready_tx, thread_stop)) {
                eprintln!("dtu: {e}");
            }
        })
        .map_err(|e| format!("spawn core thread: {e}"))?;

    Ok(Daemon { state, key, stop, ready, thread: Some(thread) })
}
