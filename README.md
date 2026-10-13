[![日本語](https://img.shields.io/badge/lang-日本語-1c7ed6?style=flat-square)](README.md)
[![English](https://img.shields.io/badge/lang-English-868e96?style=flat-square)](README.en.md)
[![繁體中文](https://img.shields.io/badge/lang-繁體中文-868e96?style=flat-square)](README.zh-TW.md)

# dtu_core

LAN 内の 2 台のマシン間で、認証付き・高速・レジューム可能なファイル転送を行うための**コアライブラリ**です。
実行ファイルもデーモンも持ちません。`dtu_cli` / `dtu_tui` / `dtu_gui`、または自作のクライアントがこのクレートを**プロセス内にホスト**して初めて動作します。

[ドキュメント](docs/index.md) · [dtu_cli](../dtu_cli) · [dtu_tui](../dtu_tui) · [dtu_gui](../dtu_gui)

## 特長

- **デバイス認証** — Ed25519 の鍵ペアと 22 文字のデバイス ID。恒久信頼（JWT）とワンタイムコードの 2 方式
- **高速転送** — 1 ファイルを複数の TCP ストリームに分割（ループバック実測 約 700 MiB/s、`--verify` 時 約 70 MiB/s）
- **レジューム** — 受信側は `<name>.dtu-part` に書き、範囲記録と sha256 を確認してから確定。途中で切れても続きから
- **ディスカバリ** — UDP ブロードキャストで同一 LAN の端末を列挙（返答はデバイス ID のみ）
- **REST 面** — ループバック限定。第三者のフロントエンドはここから全機能を操作できる（ページは持たない）

## 使い方

```toml
[dependencies]
dtu_core = { path = "../dtu_core" }
```

```rust
use dtu_core::{cfg, embed};

// リスナー・ディスカバリ・REST 面をこのプロセスで起動する
let daemon = embed::host(cfg::Config::load())?;
daemon.wait_ready()?;

println!("listen {} api {}", daemon.state.cfg.port, daemon.api_port());
// daemon.state を直接読み書きし、dtu_core の関数を直接呼ぶ（REST は不要）
let code = daemon.state.code.lock().await.code.clone();
println!("pairing code {code}");

daemon.stop(); // アプリ終了時にサービスも止まる
```

`dtu_core` は単体で走らないため、**必ずどれかのクライアントの中で**動きます。データディレクトリは 1 プロセスが占有し、2 つ目のアプリは `another dtu daemon already owns …` で拒否されます。

## 構成

| モジュール | 役割 |
| --- | --- |
| `identity` | 鍵ペアとデバイス ID（`identity.json`） |
| `trust` | 信頼ストア（`trust.json`、ピン留め公開鍵 + JWT） |
| `proto` / `server` / `client` | ワイヤプロトコル、受信側、送信側 |
| `guard` | パスの安全性、part ファイル、sha256 |
| `discover` | UDP ブロードキャスト |
| `invite` / `jwt` | 相互信頼のハンドシェイク |
| `api` | ループバック REST（`127.0.0.1:<port+1>`） |
| `embed` | クライアントがコアをホストするための入口 |

## テスト

```bash
cargo test                      # 78 ケース（実 TCP 双方向・レジューム・watchdog を含む）
cargo clippy --all-targets
pwsh ./deep-test.ps1            # 2 アプリを実際に起動する統合テスト
```

## ドキュメント

`docs/` は MkDocs（Material + static-i18n）で、日本語 / English / 繁體中文の 3 言語。
`.github/workflows/docs.yml` が `main` への push で GitHub Pages に公開します。

```bash
pip install -r requirements-docs.txt
mkdocs serve     # http://127.0.0.1:8000
mkdocs build     # site/
```
