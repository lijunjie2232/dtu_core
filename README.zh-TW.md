[![日本語](https://img.shields.io/badge/lang-日本語-868e96?style=flat-square)](README.md)
[![English](https://img.shields.io/badge/lang-English-868e96?style=flat-square)](README.en.md)
[![繁體中文](https://img.shields.io/badge/lang-繁體中文-1c7ed6?style=flat-square)](README.zh-TW.md)

# dtu_core

在 LAN 的兩台機器之間，做「有認證、高速、可續傳」檔案傳輸的**核心程式庫**。
它沒有執行檔、也沒有自己的常駐程式：`dtu_cli` / `dtu_tui` / `dtu_gui` 或你自己寫的客戶端，會把這個 crate **載入自己的行程裡**執行。

[文件](docs/index.zh-TW.md) · [dtu_cli](../dtu_cli) · [dtu_tui](../dtu_tui) · [dtu_gui](../dtu_gui)

## 特色

- **裝置認證** — Ed25519 金鑰對加上 22 字元裝置 ID；永久信任（JWT）與一次性配對碼兩種方式
- **高速** — 單一檔案切成多條 TCP 連線傳送（loopback 實測約 700 MiB/s；加 `--verify` 約 70 MiB/s）
- **可續傳** — 接收端先寫入 `<name>.dtu-part`，記錄已完成區間、核對 sha256 後才落地
- **區網探索** — UDP 廣播列出同網段裝置（回覆只帶裝置 ID）
- **REST 介面** — 只綁 loopback，第三方前端可透過它操作全部功能；不提供任何網頁

## 用法

```toml
[dependencies]
dtu_core = { path = "../dtu_core" }
```

```rust
use dtu_core::{cfg, embed};

// 在這個行程裡啟動監聽、區網探索與 REST 介面
let daemon = embed::host(cfg::Config::load())?;
daemon.wait_ready()?;

println!("listen {} api {}", daemon.state.cfg.port, daemon.api_port());
// 直接讀寫 daemon.state、直接呼叫 crate 的函式（不需要任何 IPC）
let code = daemon.state.code.lock().await.code.clone();
println!("pairing code {code}");

daemon.stop(); // 應用程式結束，服務也一起停
```

因為它無法單獨執行，所以永遠活在**某個客戶端裡面**。一個資料目錄同時只允許一個行程，第二個應用會收到 `another dtu daemon already owns …`。

## 模組

| 模組 | 職責 |
| --- | --- |
| `identity` | 金鑰對與裝置 ID（`identity.json`） |
| `trust` | 信任清單（`trust.json`，釘選公鑰 + JWT） |
| `proto` / `server` / `client` | 線路協定、接收端、傳送端 |
| `guard` | 路徑安全、part 檔、sha256 |
| `discover` | UDP 廣播 |
| `invite` / `jwt` | 互相建立信任的握手 |
| `api` | loopback REST（`127.0.0.1:<port+1>`） |
| `embed` | 客戶端載入核心的入口 |

## 測試

```bash
cargo test                      # 78 個案例（含真實 TCP 雙向、續傳、watchdog）
cargo clippy --all-targets
pwsh ./deep-test.ps1            # 真的啟動兩個應用程式的整合測試
```

## 文件

`docs/` 用 MkDocs（Material + static-i18n），三種語言：日本語 / English / 繁體中文。
`.github/workflows/docs.yml` 會在 push 到 `main` 時發佈到 GitHub Pages。

```bash
pip install -r requirements-docs.txt
mkdocs serve     # http://127.0.0.1:8000
mkdocs build     # site/
```
