# dtu_core

The **core library** for authenticated, fast, resumable file transfer between two machines on a LAN.
It ships no binary and no daemon: `dtu_cli`, `dtu_tui`, `dtu_gui` — or your own client — **host it in process**.

!!! note "It cannot be started on its own"
    There is no `dtu_core` command. The client that calls `embed::host()` is the app, and its services stop when it exits.

## What it gives you

| Piece | What it does |
| --- | --- |
| Device identity | Ed25519 keypair + 22-character id in `identity.json` |
| Auth | Permanent trust (JWT issued by the peer) and one-time pairing codes |
| Transfer | One file split across several TCP streams, staged as `<name>.dtu-part` |
| Resume | Completed ranges are remembered and asked for with `Map` |
| Discovery | UDP broadcast (the reply carries nothing but the device id) |
| REST | Loopback-only control surface. No page is served |

## Hosting it

```rust
use dtu_core::{cfg, embed};

let daemon = embed::host(cfg::Config::load())?; // listener + discovery + REST
daemon.wait_ready()?;                           // blocks until the TCP ports are bound

// from here on, drive daemon.state directly (REST is for third parties)
let st = &daemon.state;
println!("{} listening on {}", st.id.id, st.cfg.port);

daemon.stop(); // drains in-flight transfers, then stops
```

Two processes cannot share one data directory: the second `embed::host()` fails with
`another dtu daemon already owns …`.

## Data directory

`DTU_HOME` (default `%APPDATA%\dtu` on Windows, `./.dtu` elsewhere).

| File | Content |
| --- | --- |
| `identity.json` | this device's id and ed25519 secret |
| `trust.json` | trusted devices, pinned public keys, the JWT each peer issued |
| `config.json` | port, served root, parallelism, … |
| `control.token` | local key for the REST surface (minted once, then reused) |
| `auth.log` | auth decisions as JSON Lines (transfers are not logged) |
| `daemon.lock` / `daemon.pid` | marks the single owner of the data directory |

## Security model

- One auth per TCP connection (not per file), done in the `Hello` frame with a JWT, a one-time code, or a session token.
- Trusted devices are **pinned by public key**; a changed key is refused with `peer key changed since pairing`.
- Revocation (`device rm`) applies immediately: the next auth reloads `trust.json`.
- Every remote path goes through `guard::resolve`, which rejects `..`, absolute paths and `<name>.dtu-part`.
- REST needs `Authorization: Bearer <control.token>` (or `?t=`). Since no page is served, there is no browser-facing surface.

## How a transfer runs

1. The sender asks `Map` for the ranges the peer already holds.
2. Remaining ranges are sent in parallel: `PutBegin` → `Data` → end marker.
3. The receiver writes at the right offset of the part file and records the range.
4. `PutEnd` fixes the length, verifies `sha256` when given, then renames into place.
5. `--verify` reads the whole file on both sides, so it is markedly slower (700 → 70 MiB/s on loopback).

## Tests

```bash
cargo test                    # 78 cases: real TCP both ways, resume, watchdog, REST
cargo clippy --all-targets
pwsh ./deep-test.ps1          # integration test that starts two real apps
```

## About this site

Built with MkDocs (Material theme + static-i18n) and published to GitHub Pages on every push to `main`.
Set **Settings → Pages → Source** to **GitHub Actions** once.

```bash
pip install -r requirements-docs.txt
mkdocs serve     # http://127.0.0.1:8000
```
