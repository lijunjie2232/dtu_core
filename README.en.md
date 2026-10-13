[![日本語](https://img.shields.io/badge/lang-日本語-868e96?style=flat-square)](README.md)
[![English](https://img.shields.io/badge/lang-English-1c7ed6?style=flat-square)](README.en.md)
[![繁體中文](https://img.shields.io/badge/lang-繁體中文-868e96?style=flat-square)](README.zh-TW.md)

# dtu_core

The **core library** for authenticated, fast, resumable file transfer between two machines on a LAN.
It has no binary and no daemon of its own: `dtu_cli`, `dtu_tui`, `dtu_gui` — or your own client — **host it in process**.

[Docs](docs/index.en.md) · [dtu_cli](../dtu_cli) · [dtu_tui](../dtu_tui) · [dtu_gui](../dtu_gui)

## Features

- **Device auth** — Ed25519 keypair plus a 22-character device id. Permanent trust (JWT) and one-time pairing codes.
- **Fast** — one file split across several TCP streams (measured ~700 MiB/s on loopback, ~70 MiB/s with `--verify`).
- **Resumable** — the receiver writes `<name>.dtu-part`, records completed ranges, checks sha256, then lands the file.
- **Discovery** — UDP broadcast lists peers on the same LAN (the reply carries nothing but the device id).
- **REST surface** — loopback only, so a third-party frontend can drive every feature. No page is served.

## Usage

```toml
[dependencies]
dtu_core = { path = "../dtu_core" }
```

```rust
use dtu_core::{cfg, embed};

// listener, discovery and the REST surface, in this process
let daemon = embed::host(cfg::Config::load())?;
daemon.wait_ready()?;

println!("listen {} api {}", daemon.state.cfg.port, daemon.api_port());
// read/write daemon.state and call the crate directly — no IPC needed
let code = daemon.state.code.lock().await.code.clone();
println!("pairing code {code}");

daemon.stop(); // services stop with the app
```

Because it never runs on its own, it always lives **inside a client**. One process owns a data directory; a second app is refused with `another dtu daemon already owns …`.

## Modules

| Module | Responsibility |
| --- | --- |
| `identity` | keypair and device id (`identity.json`) |
| `trust` | trust store (`trust.json`, pinned key + JWT) |
| `proto` / `server` / `client` | wire protocol, receiver, sender |
| `guard` | path safety, part files, sha256 |
| `discover` | UDP broadcast |
| `invite` / `jwt` | mutual-trust handshake |
| `api` | loopback REST (`127.0.0.1:<port+1>`) |
| `embed` | the entry point clients host the core with |

## Tests

```bash
cargo test                      # 78 cases, incl. real TCP both ways, resume, watchdog
cargo clippy --all-targets
pwsh ./deep-test.ps1            # integration test that runs two real apps
```

## Docs

`docs/` is MkDocs (Material + static-i18n) in Japanese / English / 繁體中文.
`.github/workflows/docs.yml` publishes it to GitHub Pages on every push to `main`.

```bash
pip install -r requirements-docs.txt
mkdocs serve     # http://127.0.0.1:8000
mkdocs build     # site/
```
