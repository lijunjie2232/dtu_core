# REST API

The control surface for third parties. Whichever app hosts the core — `dtu_cli`, `dtu_tui`, `dtu_gui`,
or your own client — listens on `127.0.0.1:<port + 1>`. Pin it with `api_port` in `config.json`.

!!! tip "Authenticate"
    The local key is minted into `control.token` on first start and reused afterwards.

    ```bash
    KEY=$(cat "$DTU_HOME/control.token")
    curl -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/status
    ```

    `?t=<key>` also works, but URLs leak into history and referrers — prefer the header.
    A missing or wrong key answers **403**.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/status` | device id, version, port, root, uptime |
| GET | `/api/devices` | trusted devices (`items[]`) |
| DELETE | `/api/devices/<id\|alias>` | revoke trust |
| POST | `/api/devices/<id\|alias>/alias?name=` | set an alias |
| GET | `/api/invites` | pending invitations (`items[]`) |
| POST | `/api/invites/<id>/accept?expires=30d` | accept one |
| POST | `/api/invites/<id>/deny` | deny one |
| GET | `/api/code` | the current pairing code |
| POST | `/api/code/refresh?password=` | rotate it (empty string clears the password) |
| GET | `/api/scan?wait=1500` | probe the LAN (default 1500 ms) |
| GET | `/api/config` | the stored configuration |
| GET | `/api/config/fields` | the settings form (key, kind, restart, help) |
| PUT | `/api/config?key=&value=` | change one setting (`note` says whether it applied now or next start) |
| GET | `/api/log?n=20&event=auth\|file\|invite\|diag` | tail of the audit log (`event` filters) |
| POST | `/api/transfer?op=...` | start a transfer (below) |
| GET | `/api/transfer/<id>` | poll a transfer job |

`POST /api/shutdown` answers **400**: the app owns its own lifetime.

## Transfer jobs

```
POST /api/transfer?op=push&peer=<id|alias|host:port>&paths=<a,b>&to=<remote-dir>
POST /api/transfer?op=pull&peer=...&paths=<a,b>&to=<local-dir>
POST /api/transfer?op=diff&peer=...&local=<dir>&remote=<dir>
POST /api/transfer?op=sync&peer=...&local=<dir>&remote=<dir>&prefer=newer&delete=none
```

Extra query parameters: `verify=1` (like `--verify`), `no_resume=1`, `dry_run=1`, `parallel=`
(defaults to the config value), and `code=` / `password=` for a peer you do not trust yet.

The reply is `202 {"id": "<job>"}`; poll that id for the log.

```bash
curl -s -H "Authorization: Bearer $KEY" \
  -X POST "http://127.0.0.1:47001/api/transfer?op=push&peer=living-room-nas&paths=C:/work/a.bin&to=in&verify=1"

curl -s -H "Authorization: Bearer $KEY" \
  http://127.0.0.1:47001/api/transfer/<job>
# {"kind":"push","state":"done","lines":["pushed in/a.bin"],"error":null}
```

`state` goes `running` → `done` / `error`. The last 32 jobs are kept.

## Shapes

Successful replies are plain JSON objects; the `t` discriminator used on the wire is stripped.

```json
{ "id": "0tZr635ykNqC3…", "version": "0.1.0", "proto": 1,
  "port": 47000, "root": "C:\\Users\\me\\dtu\\share",
  "unlimit": false, "trusted": 2, "pending": 0, "uptime": 42 }
```

Failures are 4xx with `{"error": "..."}`. Paths are percent-decoded, but `paths` is comma
separated — send a file whose name contains a comma from the CLI instead.

## Settings

`GET /api/config/fields` describes every key, so a frontend can render the form without hardcoding it.

```bash
curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/config/fields
# {"fields":[{"key":"port","kind":"number","restart":true,"help":"LAN port for transfers and discovery"},
#            {"key":"code_password","kind":"optional_text","restart":false,...}]}
```

`note` in the PUT reply is `applied` when the running app took the change immediately, and
`takes effect on the next daemon start` otherwise.

## Audit log

Not just auth: every file that actually moved is a line too. `event=file` narrows it down.

```bash
curl -s -H "Authorization: Bearer $KEY" "http://127.0.0.1:47001/api/log?n=50&event=file"
# {"lines":["{\"ts\":\"…\",\"event\":\"file\",\"result\":\"ok\",\"method\":\"put\",
#   \"device\":\"0tZr…\",\"addr\":\"192.168.1.24:54712\",\"path\":\"in/a.bin\",\"bytes\":24117248}"]}
```

| event | method | Meaning |
| --- | --- | --- |
| `auth` | jwt / code / session / unlimit | connection auth result, with the reason when refused |
| `file` | put / get / del | one received file, one sent range, or a delete |
| `invite` | invite | pending / ok / deny / timeout |
| `diag` | - | panics and fatal startup errors |

`get` is one line per range (per connection); summing the lines for a path gives one transfer.

## Recipes

```bash
# show this device's pairing code
curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/code

# accept every pending invitation
for id in $(curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:47001/api/invites \
            | python -c 'import json,sys; print(" ".join(i["id"] for i in json.load(sys.stdin)["items"]))'); do
  curl -s -X POST -H "Authorization: Bearer $KEY" "http://127.0.0.1:47001/api/invites/$id/accept?expires=30d"
done
```
