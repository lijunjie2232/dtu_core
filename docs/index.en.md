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
| `auth.log` | auth decisions **and** transferred files (JSON Lines): who (device id), from where (IP:port), what (path, bytes) |
| `daemon.lock` / `daemon.pid` | marks the single owner of the data directory |

## Security model

- One auth per TCP connection (not per file), done in the `Hello` frame with a JWT, a one-time code, or a session token.
- Trusted devices are **pinned by public key**; a changed key is refused with `peer key changed since pairing`.
- Revocation (`device rm`) applies immediately: the next auth reloads `trust.json`.
- Every remote path goes through `guard::resolve`, which rejects `..`, absolute paths and `<name>.dtu-part`.
- A one-time code still needs an identity: a 22-character base64url id, a parsable key, and no claiming an id that is already pinned with another key. Anything else is refused before it can write to the log (and is logged as `deny` with its address).
- REST needs `Authorization: Bearer <control.token>` (or `?t=`). Since no page is served, there is no browser-facing surface.

## Audit log

One line per event: the auth of a connection, and every file that actually moved (JSON Lines, two generations rotated at 1 MiB).

| event | method | Records |
| --- | --- | --- |
| `auth` | `jwt` / `code` / `session` / `unlimit` | who (device) got in from where (addr), or why not |
| `file` | `put` / `get` / `del` | the peer's device and addr, `path`, `bytes`, result |
| `invite` | `invite` | pending / ok / deny / timeout |
| `diag` | `-` | panics and fatal startup errors |

```json
{"ts":"2026-10-30T09:12:03Z","epoch":1793351523,"event":"file","result":"ok","method":"put","device":"0tZr635ykNqC3_eYOsNnPQ","addr":"192.168.1.24:54712","path":"in/report.pdf","bytes":24117248,"reason":null}
```

Read it with `dtu log --event file` (CLI), `GET /api/log?event=file` (REST), or the log tab in the TUI / GUI.
It is a record of who moved what — not a file inventory.

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
