# dtu_core

在 LAN 的兩台機器之間，負責「有認證、高速、可續傳」檔案傳輸的**核心程式庫**。
它沒有執行檔、也沒有常駐程式：`dtu_cli` / `dtu_tui` / `dtu_gui` 或你自己寫的客戶端，會把它**載入自己的行程**裡執行。

!!! note "它無法單獨啟動"
    沒有 `dtu_core` 這個指令。呼叫 `embed::host()` 的客戶端才是應用本體，應用結束，服務也跟著停。

## 提供什麼

| 項目 | 內容 |
| --- | --- |
| 裝置身分 | Ed25519 金鑰對 + 22 字元 ID，存在 `identity.json` |
| 認證 | 永久信任（對端簽發的 JWT）與一次性配對碼 |
| 傳輸 | 單一檔案切成多條 TCP 連線，先寫 `<name>.dtu-part` 再落地 |
| 續傳 | 記住已完成的區間，用 `Map` 向對端確認 |
| 探索 | UDP 廣播（回覆只帶裝置 ID） |
| REST | 只綁 loopback 的操作介面，不提供網頁 |

## 如何載入核心

```rust
use dtu_core::{cfg, embed};

let daemon = embed::host(cfg::Config::load())?; // 監聽 + 探索 + REST
daemon.wait_ready()?;                           // 等到 TCP 埠綁定完成

// 之後直接操作 daemon.state（REST 是給第三方用的）
let st = &daemon.state;
println!("{} listening on {}", st.id.id, st.cfg.port);

daemon.stop(); // 先把進行中的傳輸 drain 完，再停止
```

同一個資料目錄不能同時被兩個行程使用，第二個 `embed::host()` 會失敗：
`another dtu daemon already owns …`。

## 資料目錄

`DTU_HOME`（Windows 預設 `%APPDATA%\dtu`，其他平台 `./.dtu`）。

| 檔案 | 內容 |
| --- | --- |
| `identity.json` | 本機裝置 ID 與 ed25519 私鑰 |
| `trust.json` | 已信任裝置、釘選公鑰、對端簽發的 JWT |
| `config.json` | 埠、分享根目錄、平行數… |
| `control.token` | REST 用的本機金鑰（第一次啟動產生，之後重用） |
| `auth.log` | 認證與傳輸紀錄（JSON Lines）：誰（裝置 ID）、從哪（IP:port）、動了什麼（路徑、位元組數） |
| `daemon.lock` / `daemon.pid` | 標記資料目錄的唯一擁有者 |

## 安全模型

- 每條 TCP 連線認證一次（不是每個檔案），在 `Hello` 訊框裡帶 JWT、一次性配對碼或 session token。
- 信任的裝置**釘選公鑰**；公鑰換了就以 `peer key changed since pairing` 拒絕。
- 取消信任（`device rm`）立即生效：下一次認證會重新讀 `trust.json`。
- 所有遠端路徑都經過 `guard::resolve`，拒絕 `..`、絕對路徑與 `<name>.dtu-part`。
- 一次性配對碼也必須帶身分：22 字元 base64url 的 ID、可解析的公鑰，且不得冒用已被釘選成其他公鑰的 ID。不合格的連線在寫日誌前就被拒絕（並以 `deny` 連同位址記錄）。
- REST 需要 `Authorization: Bearer <control.token>`（或 `?t=`）。因為不提供任何頁面，瀏覽器沒有可直接攻擊的介面。

## 稽核日誌

每個事件一行：連線的認證，以及真正搬動過的檔案（JSON Lines，1 MiB 兩代輪替）。

| event | method | 記錄內容 |
| --- | --- | --- |
| `auth` | `jwt` / `code` / `session` / `unlimit` | 誰（device）從哪（addr）通過，或為何被拒 |
| `file` | `put` / `get` / `del` | 對端的 device 與 addr、`path`、`bytes`、結果 |
| `invite` | `invite` | pending / ok / deny / timeout |
| `diag` | `-` | panic 等致命錯誤 |

```json
{"ts":"2026-10-30T09:12:03Z","epoch":1793351523,"event":"file","result":"ok","method":"put","device":"0tZr635ykNqC3_eYOsNnPQ","addr":"192.168.1.24:54712","path":"in/report.pdf","bytes":24117248,"reason":null}
```

三種讀法：`dtu log --event file`（CLI）、`GET /api/log?event=file`（REST）、TUI / GUI 的 log 分頁。
它記錄的是「誰搬動了什麼」，不是檔案清單。

## 傳輸流程

1. 傳送端用 `Map` 問對端「已經有哪幾段」
2. 沒完成的區間以平行方式送出：`PutBegin` → `Data` → 結束標記
3. 接收端寫入 part 檔對應位移，並記錄區間
4. `PutEnd` 確定長度，有 `sha256` 就驗證，然後 rename 落地
5. `--verify` 兩邊各多讀一次全檔，明顯較慢（loopback 700 → 70 MiB/s）

## 測試

```bash
cargo test                    # 78 個案例：真實 TCP 雙向、續傳、watchdog、REST
cargo clippy --all-targets
pwsh ./deep-test.ps1          # 真的啟動兩個應用程式的整合測試
```

## 關於本網站

用 MkDocs（Material 主題 + static-i18n）產生，push 到 `main` 時自動發佈到 GitHub Pages。
第一次請把 repo 的 **Settings → Pages → Source** 設成 **GitHub Actions**。

```bash
pip install -r requirements-docs.txt
mkdocs serve     # http://127.0.0.1:8000
```
