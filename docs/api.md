# REST API

第三者向けの操作面です。コアをホストしているアプリ（`dtu_cli` / `dtu_tui` / `dtu_gui`、自作クライアント）が
`127.0.0.1:<port + 1>` で待ち受けます。ポートは `config.json` の `api_port` で固定できます。

!!! tip "認証"
    ローカル鍵は初回起動時に `control.token` に作られ、以後は再利用されます。

    ```bash
    KEY=$(cat "$DTU_HOME/control.token")
    curl -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/status
    ```

    `?t=<key>` でも通りますが、URL は履歴や Referer に残るのでヘッダを使ってください。
    鍵が無い／違う場合は **403**。

## エンドポイント

| メソッド | パス | 説明 |
| --- | --- | --- |
| GET | `/api/status` | デバイス ID、バージョン、ポート、ルート、稼働秒数 |
| GET | `/api/devices` | 信頼済みデバイス（`items[]`） |
| DELETE | `/api/devices/<id\|alias>` | 信頼を取り消す |
| POST | `/api/devices/<id>\|alias>/alias?name=` | 別名を付ける |
| GET | `/api/invites` | 承認待ちの招待（`items[]`） |
| POST | `/api/invites/<id>/accept?expires=30d` | 招待を承認 |
| POST | `/api/invites/<id>/deny` | 招待を拒否 |
| GET | `/api/code` | 現在のペアリングコード |
| POST | `/api/code/refresh?password=` | コードを再生成（空文字でパスワード解除） |
| GET | `/api/scan?wait=1500` | LAN を探索（既定 1500 ms） |
| GET | `/api/config` | 保存されている設定 |
| GET | `/api/config/fields` | 設定フォームの定義（key・kind・restart・help） |
| PUT | `/api/config?key=&value=` | 設定を 1 項目書き換える（`note` で即時反映か次回起動かを返す） |
| GET | `/api/log?n=20&event=auth\|file\|invite\|diag` | 監査ログの末尾（`event` で絞り込み） |
| POST | `/api/transfer?op=...` | 転送を開始（下記） |
| GET | `/api/transfer/<id>` | 転送ジョブの状態 |

`POST /api/shutdown` は **400** を返します。アプリの寿命はアプリが持ちます。

## 転送ジョブ

```
POST /api/transfer?op=push&peer=<id|alias|host:port>&paths=<a,b>&to=<remote-dir>
POST /api/transfer?op=pull&peer=...&paths=<a,b>&to=<local-dir>
POST /api/transfer?op=diff&peer=...&local=<dir>&remote=<dir>
POST /api/transfer?op=sync&peer=...&local=<dir>&remote=<dir>&prefer=newer&delete=none
```

追加のクエリ: `--verify` 相当の `verify=1`、`no_resume=1`、`dry_run=1`、`parallel=`（未指定は設定値）、
信頼していない相手には `code=` / `password=`。

応答は `202 {"id": "<job>"}`。進捗は同じ ID をポーリングします。

```bash
curl -s -H "Authorization: Bearer $KEY" \
  -X POST "http://127.0.0.1:47001/api/transfer?op=push&peer=living-room-nas&paths=C:/work/a.bin&to=in&verify=1"

curl -s -H "Authorization: Bearer $KEY" \
  http://127.0.0.1:47001/api/transfer/<job>
# {"kind":"push","state":"done","lines":["pushed in/a.bin"],"error":null}
```

`state` は `running` → `done` / `error`。ジョブは 32 件まで保持されます。

## 形

成功時は JSON オブジェクト。ワイヤ用の `t` タグは取り除いて返します。

```json
{ "id": "0tZr635ykNqC3…", "version": "0.1.0", "proto": 1,
  "port": 47000, "root": "C:\\Users\\me\\dtu\\share",
  "unlimit": false, "trusted": 2, "pending": 0, "uptime": 42 }
```

失敗時は 4xx と `{"error": "..."}`。パスは `%20` などをデコードして受け取りますが、
`paths` はカンマ区切りなので、名前にカンマを含むファイルは CLI から送ってください。

## 設定

`GET /api/config/fields` が全キーの定義を返すので、フロントエンドはそれをそのままフォームにできます。

```bash
curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/config/fields
# {"fields":[{"key":"port","kind":"number","restart":true,"help":"LAN port for transfers and discovery"},
#            {"key":"code_password","kind":"optional_text","restart":false,...}]}
```

`PUT` の応答の `note` が `applied` なら実行中のアプリがその場で採用済み、
`takes effect on the next daemon start` なら次回起動からです。

## 監査ログ

認証だけでなく、実際に動いたファイルも 1 行ずつ入ります。`event=file` で転送だけを取り出せます。

```bash
curl -s -H "Authorization: Bearer $KEY" "http://127.0.0.1:47001/api/log?n=50&event=file"
# {"lines":["{\"ts\":\"…\",\"event\":\"file\",\"result\":\"ok\",\"method\":\"put\",\
#   \"device\":\"0tZr…\",\"addr\":\"192.168.1.24:54712\",\"path\":\"in/a.bin\",\"bytes\":24117248}"]}
```

| event | method | 意味 |
| --- | --- | --- |
| `auth` | jwt / code / session / unlimit | 接続の認証結果（拒否理由付き） |
| `file` | put / get / del | 1 ファイルの受信、1 レンジの送信、削除 |
| `invite` | invite | 招待の pending / ok / deny / timeout |
| `diag` | - | パニックなど |

`get` は 1 レンジ（接続）ごとに 1 行です。同じパスの行を合計すると 1 回の転送になります。

## 便利な使い方

```bash
# 相手のコードを見る
curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/code

# 承認待ちの招待を全部承認
for id in $(curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/invites \
            | python -c 'import json,sys; print(" ".join(i["id"] for i in json.load(sys.stdin)["items"]))'); do
  curl -s -X POST -H "Authorization: Bearer $KEY" "http://127.0.0.1:47001/api/invites/$id/accept?expires=30d"
done
```
