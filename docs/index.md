# dtu_core

LAN 内の 2 台のマシン間で、認証付き・高速・レジューム可能なファイル転送を行う**コアライブラリ**です。
実行ファイルもデーモンも持たず、`dtu_cli` / `dtu_tui` / `dtu_gui`、または自作のクライアントが**プロセス内にホスト**して動きます。

!!! note "単体では起動できません"
    `dtu_core` を起動するコマンドはありません。`embed::host()` を呼ぶクライアントが本体で、そのクライアントが終了すればサービスも止まります。

## 何を提供するか

| 機能 | 説明 |
| --- | --- |
| デバイス識別 | Ed25519 の鍵ペア + 22 文字の ID を `identity.json` に保存 |
| 認証 | 恒久信頼（相手が発行した JWT）とワンタイムのペアリングコード |
| 転送 | 1 ファイルを複数の TCP ストリームに分割。`<name>.dtu-part` に書いてから確定 |
| レジューム | 完了した範囲をメモリに記録し、`Map` で相手に問い合わせる |
| ディスカバリ | UDP ブロードキャスト（返答はデバイス ID のみ） |
| REST | ループバック限定の操作面。ページは持たない |

## ホストする

```rust
use dtu_core::{cfg, embed};

let daemon = embed::host(cfg::Config::load())?; // 監聴 + 探索 + REST を起動
daemon.wait_ready()?;                            // TCP バインド完了まで待つ

// ここから先は daemon.state を直接読み書きする（REST は第三者用）
let st = &daemon.state;
println!("{} listening on {}", st.id.id, st.cfg.port);

daemon.stop(); // 進行中の転送を drain してから停止
```

同じデータディレクトリを 2 つのプロセスが同時に使うことはできません。
2 つ目の `embed::host()` は `another dtu daemon already owns …` で失敗します。

## データディレクトリ

`DTU_HOME`（未設定なら Windows は `%APPDATA%\dtu`、Linux/macOS は `./.dtu`）。

| ファイル | 内容 |
| --- | --- |
| `identity.json` | 自デバイスの ID と秘密鍵（ed25519） |
| `trust.json` | 信頼したデバイス、ピン留め公開鍵、相手が発行した JWT |
| `config.json` | ポート、公開ルート、並列数など |
| `control.token` | REST 用のローカル鍵（初回起動時に生成、以後は再利用） |
| `auth.log` | 認証と転送の記録（JSON Lines）。誰が（デバイス ID）、どこから（IP:port）、何を（パス・バイト数） |
| `daemon.lock` / `daemon.pid` | 1 プロセスだけがデータディレクトリを所有するための目印 |

## セキュリティモデル

- 接続ごとに 1 回認証します（ファイルごとではありません）。認証は `Hello` フレームで行い、`Cred` は JWT / ワンタイムコード / セッションのいずれか。
- 信頼済みデバイスは**公開鍵をピン留め**します。相手の鍵が変われば `peer key changed since pairing` で拒否。
- 取り消し（`device rm`）は即時有効。次の認証で `trust.json` を読み直します。
- パスは `guard::resolve` を通し、`..` や絶対パス、`<name>.dtu-part` を拒否します。ドライブ（`C:` / `C:/…`）や UNC（`\\host\…`）の前置きは、サーバーの OS に関係なく拒否します。
- ワンタイムコードでも**デバイス ID と公開鍵は必須**です。22 文字の base64url でない ID、壊れた鍵、払い出し済みの ID を別の鍵で名乗る接続は、ログに書く前に拒否します（第三者 IP 付きで deny として残ります）。
- REST は `Authorization: Bearer <control.token>`（または `?t=`）。ページを配信しないので、ブラウザから直接叩かれる面はありません。

## 監査ログ

接続の認証と、実際に動いたファイルを 1 行 1 イベントで残します（JSON Lines、1 MiB で 2 世代ローテーション）。

| event | method | 記録内容 |
| --- | --- | --- |
| `auth` | `jwt` / `code` / `session` / `unlimit` | 誰が（device）どこから（addr）通ったか、拒否理由 |
| `file` | `put` / `get` / `del` | 相手の device と addr、`path`、`bytes`、結果 |
| `invite` | `invite` | 招待の pending / ok / deny / timeout |
| `diag` | `-` | パニックなど |

```json
{"ts":"2026-10-30T09:12:03Z","epoch":1793351523,"event":"file","result":"ok","method":"put","device":"0tZr635ykNqC3_eYOsNnPQ","addr":"192.168.1.24:54712","path":"in/report.pdf","bytes":24117248,"reason":null}
```

取得方法は 3 通り: `dtu log --event file`（CLI）、`GET /api/log?event=file`（REST）、TUI / GUI の log タブ。
「どのファイルがあったか」の一覧は持ちません。あくまで「誰が何を動かしたか」の記録です。

## 転送の流れ

1. 送信側が `Map` で「どこまで受信済みか」を問い合わせる
2. 未完了の範囲を並列に `PutBegin` → `Data` →（終端）で送る
3. 受信側は part ファイルの該当オフセットに書き、範囲を記録
4. `PutEnd` で長さを確定し、`sha256` が付いていれば検証してから rename
5. `--verify` は両側で 1 回ずつ全読みするため、明確に遅くなる（ループバックで 700 → 70 MiB/s 程度）

## テスト

```bash
cargo test                    # 78 ケース（実 TCP、レジューム、watchdog、REST）
cargo clippy --all-targets
pwsh ./deep-test.ps1          # 2 つのアプリを実際に起動する統合テスト
```

## このサイトについて

MkDocs（Material テーマ + static-i18n）で生成し、`main` への push で GitHub Pages に公開します。
初回だけ、リポジトリの **Settings → Pages → Source** を **GitHub Actions** に設定してください。

```bash
pip install -r requirements-docs.txt
mkdocs serve     # http://127.0.0.1:8000
```
