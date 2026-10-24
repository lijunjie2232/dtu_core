# REST API

給第三方使用的操作介面。載入核心的應用（`dtu_cli` / `dtu_tui` / `dtu_gui` 或自寫客戶端）會在
`127.0.0.1:<port + 1>` 上等待；可用 `config.json` 的 `api_port` 固定埠號。

!!! tip "認證"
    本機金鑰在第一次啟動時產生到 `control.token`，之後重複使用。

    ```bash
    KEY=$(cat "$DTU_HOME/control.token")
    curl -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/status
    ```

    也可以用 `?t=<key>`，但 URL 會留在歷史與 Referer，請盡量用標頭。
    沒有金鑰或金鑰錯誤一律 **403**。

## 端點

| 方法 | 路徑 | 用途 |
| --- | --- | --- |
| GET | `/api/status` | 裝置 ID、版本、埠、根目錄、運行秒數 |
| GET | `/api/devices` | 已信任裝置（`items[]`） |
| DELETE | `/api/devices/<id\|alias>` | 取消信任 |
| POST | `/api/devices/<id\|alias>/alias?name=` | 設定別名 |
| GET | `/api/invites` | 待批准的邀請（`items[]`） |
| POST | `/api/invites/<id>/accept?expires=30d` | 批准邀請 |
| POST | `/api/invites/<id>/deny` | 拒絕邀請 |
| GET | `/api/code` | 目前的配對碼 |
| POST | `/api/code/refresh?password=` | 重新產生（空字串代表清除密碼） |
| GET | `/api/scan?wait=1500` | 掃描區網（預設 1500 ms） |
| GET | `/api/config` | 已儲存的設定 |
| GET | `/api/config/fields` | 設定表單定義（key、kind、restart、help） |
| PUT | `/api/config?key=&value=` | 改一個設定（`note` 回報是否即時生效） |
| GET | `/api/log?n=20&event=auth\|file\|invite\|diag` | 稽核日誌尾端（`event` 可篩選） |
| POST | `/api/transfer?op=...` | 開始一次傳輸（見下） |
| GET | `/api/transfer/<id>` | 查詢傳輸工作狀態 |

`POST /api/shutdown` 固定回 **400**：應用程式的壽命由應用程式自己決定。

## 傳輸工作

```
POST /api/transfer?op=push&peer=<id|alias|host:port>&paths=<a,b>&to=<remote-dir>
POST /api/transfer?op=pull&peer=...&paths=<a,b>&to=<local-dir>
POST /api/transfer?op=diff&peer=...&local=<dir>&remote=<dir>
POST /api/transfer?op=sync&peer=...&local=<dir>&remote=<dir>&prefer=newer&delete=none
```

額外參數：`verify=1`（等同 `--verify`）、`no_resume=1`、`dry_run=1`、`parallel=`（未指定則用設定值），
以及對尚未信任的對象使用的 `code=` / `password=`。

回應為 `202 {"id": "<job>"}`，用同一個 id 輪詢進度。

```bash
curl -s -H "Authorization: Bearer $KEY" \
  -X POST "http://127.0.0.1:47001/api/transfer?op=push&peer=living-room-nas&paths=C:/work/a.bin&to=in&verify=1"

curl -s -H "Authorization: Bearer $KEY" \
  http://127.0.0.1:47001/api/transfer/<job>
# {"kind":"push","state":"done","lines":["pushed in/a.bin"],"error":null}
```

`state` 由 `running` 變成 `done` / `error`，最多保留 32 筆工作。

## 回應格式

成功時是乾淨的 JSON 物件，線路上的 `t` 標籤會被移除。

```json
{ "id": "0tZr635ykNqC3…", "version": "0.1.0", "proto": 1,
  "port": 47000, "root": "C:\\Users\\me\\dtu\\share",
  "unlimit": false, "trusted": 2, "pending": 0, "uptime": 42 }
```

失敗為 4xx 加 `{"error": "..."}`。路徑會做 percent 解碼，但 `paths` 以逗號分隔，
檔名含逗號時請改用 CLI 傳送。

## 設定

`GET /api/config/fields` 回傳每個鍵的定義，前端可直接拿它渲染表單。

```bash
curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/config/fields
# {"fields":[{"key":"port","kind":"number","restart":true,"help":"LAN port for transfers and discovery"},
#            {"key":"code_password","kind":"optional_text","restart":false,...}]}
```

PUT 回應的 `note` 為 `applied` 表示執行中的應用已立即採用；
為 `takes effect on the next daemon start` 則要等下次啟動。

## 稽核日誌

不只認證：真正搬動過的檔案也會一行一筆。用 `event=file` 只看傳輸。

```bash
curl -s -H "Authorization: Bearer $KEY" "http://127.0.0.1:47001/api/log?n=50&event=file"
# {"lines":["{\"ts\":\"…\",\"event\":\"file\",\"result\":\"ok\",\"method\":\"put\",
#   \"device\":\"0tZr…\",\"addr\":\"192.168.1.24:54712\",\"path\":\"in/a.bin\",\"bytes\":24117248}"]}
```

| event | method | 意義 |
| --- | --- | --- |
| `auth` | jwt / code / session / unlimit | 連線認證結果（被拒時附原因） |
| `file` | put / get / del | 收到一個檔案、送出一段區間、或刪除 |
| `invite` | invite | pending / ok / deny / timeout |
| `diag` | - | panic 等致命錯誤 |

`get` 是「每段區間（每條連線）一行」；把同一路徑的行加總，就是一次傳輸。

## 常用片段

```bash
# 看本機的配對碼
curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/code

# 一次批准所有待處理邀請
for id in $(curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/invites \
            | python -c 'import json,sys; print(" ".join(i["id"] for i in json.load(sys.stdin)["items"]))'); do
  curl -s -X POST -H "Authorization: Bearer $KEY" "http://127.0.0.1:47001/api/invites/$id/accept?expires=30d"
done
```
