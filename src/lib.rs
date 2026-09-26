//! dtu core: everything except a UI.
//!
//! `dtu_cli`, `dtu_tui` and `dtu_gui` link this crate and call it in process; each
//! one hosts the daemon itself through [`embed`], so any of them alone is a full
//! client *and* server. Third-party frontends (web, mobile, scripts) go through
//! [`api`], the loopback REST surface guarded by the local key in `control.token`.

pub mod api;
pub mod audit;
pub mod cfg;
pub mod client;
pub mod discover;
pub mod embed;
pub mod guard;
pub mod identity;
pub mod invite;
pub mod jwt;
pub mod proto;
pub mod server;
pub mod state;
pub mod trust;

#[cfg(test)]
mod core_tests;

pub use cfg::Config;
pub use embed::Daemon;
pub use identity::Identity;
pub use state::State;
pub use trust::Store;

/// Core version, shown by every frontend.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
