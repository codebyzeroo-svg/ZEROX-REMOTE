"""In-memory signaling and consent-gated message relay for ZEROX REMOTE."""

from __future__ import annotations

import eventlet

eventlet.monkey_patch()

import hashlib
import ntpath
import os
import re
import secrets
import time
from collections import defaultdict, deque
from threading import RLock
from typing import Any

from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit


APP_ENV = os.environ.get("APP_ENV", "production").lower()
SECRET_KEY = os.environ.get("SECRET_KEY")
if APP_ENV == "production" and not SECRET_KEY:
    raise RuntimeError("SECRET_KEY must be configured in production.")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)
socketio = SocketIO(
    app,
    async_mode="eventlet",
    cors_allowed_origins=[
        origin.strip()
        for origin in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    ],
    max_http_buffer_size=2 * 1024 * 1024,
    ping_interval=25,
    ping_timeout=40,
    logger=False,
    engineio_logger=False,
)

LOCK = RLock()
DEVICES: dict[str, dict[str, Any]] = {}
SID_DEVICE: dict[str, str] = {}
SESSIONS: dict[str, dict[str, Any]] = {}
SESSION_CODES: dict[str, str] = {}
REQUESTS: dict[str, dict[str, Any]] = {}
SID_SESSION: dict[str, str] = {}
RATE_LIMITS: dict[str, deque[float]] = defaultdict(deque)
SESSION_TTL = 300
MAX_SCREEN_BYTES = 1_000_000
MAX_FILE_CHUNK = 64 * 1024
BLOCKED_FILE_EXTENSIONS = {
    ".appx", ".bash", ".bat", ".cpl", ".csh", ".cmd", ".com", ".command",
    ".dll", ".exe", ".gadget", ".hta", ".jar", ".js", ".jse", ".lnk",
    ".msi", ".msix", ".ocx", ".pif", ".ps1", ".psm1", ".py", ".pyw",
    ".reg", ".scr", ".sh", ".sys", ".vbe", ".vbs", ".wsf", ".wsh", ".zsh",
}


def _code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _valid_device_id(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-F0-9-]{36}", value))


def _data(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _rate_limit(key: str, limit: int, window: int) -> bool:
    now = time.monotonic()
    queue = RATE_LIMITS[key]
    while queue and now - queue[0] > window:
        queue.popleft()
    if len(queue) >= limit:
        return False
    queue.append(now)
    return True


def _deny(message: str) -> dict[str, Any]:
    emit("server_error", {"message": message})
    return {"ok": False, "error": message}


def _session_for(sid: str, data: dict[str, Any]) -> dict[str, Any] | None:
    session_id = data.get("session_id")
    if not isinstance(session_id, str):
        return None
    session = SESSIONS.get(session_id)
    if not session or sid not in {session.get("host_sid"), session.get("viewer_sid")}:
        return None
    if time.time() >= session["expires_at"]:
        _end_session(session_id, "Session expired")
        return None
    return session


def _end_session(session_id: str, reason: str) -> None:
    session = SESSIONS.pop(session_id, None)
    if not session:
        return
    SESSION_CODES.pop(session["code_hash"], None)
    for sid in (session.get("host_sid"), session.get("viewer_sid")):
        if sid:
            SID_SESSION.pop(sid, None)
            socketio.emit("session_ended", {"reason": reason}, to=sid)


def _peer(session: dict[str, Any], sid: str) -> str | None:
    if sid == session["host_sid"]:
        return session.get("viewer_sid")
    if sid == session.get("viewer_sid"):
        return session["host_sid"]
    return None


@app.get("/")
def index():
    return jsonify({"service": "ZEROX REMOTE signaling", "status": "ok", "transport": "Socket.IO"})


@app.get("/health")
def health():
    return jsonify({"status": "ok", "active_devices": len(DEVICES), "active_sessions": len(SESSIONS)})


@socketio.on("connect")
def on_connect(auth=None):
    if not _rate_limit(f"connect:{request.remote_addr}", 30, 60):
        return False


@socketio.on("register")
def register_device(payload):
    data = _data(payload)
    if not data or not _valid_device_id(data.get("device_id")):
        return _deny("Invalid device ID.")
    device_id = data["device_id"]
    sid = request.sid
    with LOCK:
        previous = DEVICES.get(device_id)
        if previous and previous["sid"] != sid:
            socketio.emit("server_error", {"message": "This device ID has an active connection elsewhere."}, to=sid)
            return {"ok": False}
        DEVICES[device_id] = {"sid": sid, "last_seen": time.time()}
        SID_DEVICE[sid] = device_id
    emit("registered", {"device_id": device_id})
    return {"ok": True}


@socketio.on("create_session")
def create_session(payload=None):
    sid = request.sid
    device_id = SID_DEVICE.get(sid)
    if not device_id:
        return _deny("Register this device before creating a session.")
    with LOCK:
        if SID_SESSION.get(sid):
            return _deny("End the active session before creating a new invitation.")
        for session_id, session in list(SESSIONS.items()):
            if session.get("host_sid") == sid:
                _end_session(session_id, "Replaced by a new session")
        code = secrets.token_urlsafe(12).replace("-", "A").replace("_", "B").upper()
        code_hash = _code_hash(code)
        SESSIONS["pending:" + code_hash] = {
            "host_sid": sid,
            "host_device": device_id,
            "viewer_sid": None,
            "viewer_device": None,
            "code_hash": code_hash,
            "created_at": time.time(),
            "expires_at": time.time() + SESSION_TTL,
            "permissions": {},
        }
        SESSION_CODES[code_hash] = "pending:" + code_hash
    emit("session_code", {"code": code, "expires_in": SESSION_TTL})
    return {"ok": True}


@socketio.on("request_session")
def request_session(payload):
    data = _data(payload)
    sid = request.sid
    if not data or not isinstance(data.get("code"), str):
        return _deny("Invalid session code.")
    if not _rate_limit(f"request:{request.remote_addr}", 10, 60):
        return _deny("Too many connection attempts; wait a minute and try again.")
    viewer_device = SID_DEVICE.get(sid)
    if not viewer_device:
        return _deny("Register this device before requesting a session.")
    code = data["code"].strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{12,24}", code):
        return _deny("Invalid session code.")
    with LOCK:
        code_hash = _code_hash(code)
        session_id = SESSION_CODES.get(code_hash)
        session = SESSIONS.get(session_id or "")
        if not session or session.get("viewer_sid") or time.time() >= session["expires_at"]:
            SESSION_CODES.pop(code_hash, None)
            SESSIONS.pop(session_id or "", None)
            return _deny("Session code is expired, used, or unavailable.")
        if sid == session["host_sid"] or SID_SESSION.get(sid):
            return _deny("This device cannot join another session right now.")
        request_id = secrets.token_urlsafe(18)
        requested = data.get("permissions", {})
        if not isinstance(requested, dict):
            requested = {}
        requested_permissions = {
            key: requested.get(key) is True for key in ("screen", "control", "files", "clipboard")
        }
        REQUESTS[request_id] = {
            "session_key": session_id,
            "viewer_sid": sid,
            "viewer_device": viewer_device,
            "permissions": requested_permissions,
            "expires_at": time.time() + 60,
        }
        host_sid = session["host_sid"]
    socketio.emit(
        "incoming_request",
        {"request_id": request_id, "device_id": viewer_device, "permissions": requested_permissions},
        to=host_sid,
    )
    return {"ok": True, "message": "Request sent to device owner."}


@socketio.on("respond_session")
def respond_session(payload):
    data = _data(payload)
    if not data or not isinstance(data.get("request_id"), str):
        return _deny("Invalid consent response.")
    request_id = data["request_id"]
    with LOCK:
        pending = REQUESTS.pop(request_id, None)
        if not pending or pending["expires_at"] < time.time():
            return _deny("Connection request expired.")
        session = SESSIONS.get(pending["session_key"])
        if (
            not session
            or request.sid != session["host_sid"]
            or session.get("viewer_sid")
            or SID_SESSION.get(pending["viewer_sid"])
        ):
            return _deny("This request is no longer available.")
        if data.get("accepted") is not True:
            SESSION_CODES.pop(session["code_hash"], None)
            SESSIONS.pop(pending["session_key"], None)
            for other_id, other in list(REQUESTS.items()):
                if other["session_key"] == pending["session_key"]:
                    REQUESTS.pop(other_id, None)
                    socketio.emit("session_ended", {"reason": "Request denied by device owner"}, to=other["viewer_sid"])
            socketio.emit("session_ended", {"reason": "Request denied by device owner"}, to=pending["viewer_sid"])
            return {"ok": True, "accepted": False}
        requested = pending["permissions"]
        selected = data.get("permissions", {})
        if not isinstance(selected, dict):
            selected = {}
        permissions = {
            name: bool(selected.get(name) is True and requested.get(name) is True)
            for name in ("screen", "control", "files", "clipboard")
        }
        if not any(permissions.values()):
            return _deny("At least one permission must be granted.")
        session_id = secrets.token_urlsafe(24)
        session["id"] = session_id
        session["viewer_sid"] = pending["viewer_sid"]
        session["viewer_device"] = pending["viewer_device"]
        session["permissions"] = permissions
        session["expires_at"] = time.time() + 4 * 60 * 60
        SESSION_CODES.pop(session["code_hash"], None)
        SESSIONS.pop(pending["session_key"], None)
        for other_id, other in list(REQUESTS.items()):
            if other["session_key"] == pending["session_key"]:
                REQUESTS.pop(other_id, None)
                socketio.emit("session_ended", {"reason": "This temporary code has already been used"}, to=other["viewer_sid"])
        SESSIONS[session_id] = session
        SID_SESSION[session["host_sid"]] = session_id
        SID_SESSION[session["viewer_sid"]] = session_id
    for sid, role, peer_device_id in (
        (session["host_sid"], "host", session["viewer_device"]),
        (session["viewer_sid"], "viewer", session["host_device"]),
    ):
        socketio.emit(
            "session_started",
            {
                "session_id": session_id,
                "role": role,
                "permissions": permissions,
                "peer_device_id": peer_device_id,
            },
            to=sid,
        )
    return {"ok": True, "accepted": True}


@socketio.on("list_devices")
def list_devices(payload=None):
    if request.sid not in SID_DEVICE:
        return _deny("Register this device before listing devices.")
    current = SID_DEVICE[request.sid]
    devices = [{"device_id": key} for key in DEVICES if key != current]
    emit("device_list", {"devices": devices})
    return {"ok": True}


@socketio.on("ping_probe")
def ping_probe(payload=None):
    if request.sid not in SID_DEVICE:
        return {"ok": False}
    return {"ok": True}


@socketio.on("end_session")
def end_session(payload):
    data = _data(payload)
    if not data:
        return _deny("Invalid session request.")
    with LOCK:
        session = _session_for(request.sid, data)
        if not session:
            return _deny("Session not found.")
        session_id = session["id"]
        _end_session(session_id, "Disconnected by a participant")
    return {"ok": True}


def _relay(event: str, payload: Any, permission: str | None, allowed_senders: set[str] | None = None, max_size: int = 16_000):
    data = _data(payload)
    if not data:
        return _deny("Invalid message.")
    sid = request.sid
    relay_limits = {
        "screen_frame": (20, 1),
        "remote_input": (100, 1),
        "chat_message": (30, 60),
        "clipboard_text": (10, 10),
        "file_offer": (20, 60),
        "file_response": (40, 60),
        "file_chunk": (400, 1),
        "file_complete": (40, 60),
        "file_cancel": (40, 60),
    }
    limit, window = relay_limits[event]
    if not _rate_limit(f"relay:{sid}:{event}", limit, window):
        return _deny("Message rate limit reached.")
    with LOCK:
        session = _session_for(sid, data)
        if not session:
            return _deny("Session is not active.")
        role = "host" if sid == session["host_sid"] else "viewer"
        if allowed_senders and role not in allowed_senders:
            return _deny("This participant cannot send that message.")
        if permission == "screen" and (role != "host" or not session["permissions"].get("screen")):
            return _deny("Screen sharing was not approved.")
        if permission == "control" and (role != "viewer" or not session["permissions"].get("control")):
            return _deny("Remote input was not approved.")
        if permission in {"files", "clipboard"} and not session["permissions"].get(permission):
            return _deny(f"{permission.title()} sharing was not approved.")
        peer_sid = _peer(session, sid)
    if peer_sid is None:
        return _deny("Session peer is unavailable.")
    if event == "screen_frame":
        image = data.get("jpeg")
        if not isinstance(image, str) or len(image) > MAX_SCREEN_BYTES:
            return _deny("Screen frame is invalid or too large.")
        if not isinstance(data.get("width"), int) or not isinstance(data.get("height"), int):
            return _deny("Screen dimensions are invalid.")
        monitor = data.get("monitor")
        if not isinstance(monitor, int) or monitor < 1:
            return _deny("Screen monitor is invalid.")
        forwarded = {"jpeg": image, "width": data["width"], "height": data["height"], "monitor": monitor}
    elif event == "file_chunk":
        chunk = data.get("data")
        if not isinstance(chunk, str) or len(chunk) > MAX_FILE_CHUNK * 2:
            return _deny("File chunk is invalid or too large.")
        forwarded = {"transfer_id": data.get("transfer_id"), "data": chunk}
    else:
        forwarded = {key: value for key, value in data.items() if key != "session_id"}
        if len(str(forwarded)) > max_size:
            return _deny("Message is too large.")
    if event == "chat_message":
        forwarded["sender"] = SID_DEVICE.get(sid, "peer")
    socketio.emit(event, forwarded, to=peer_sid)
    return {"ok": True}


@socketio.on("screen_frame")
def screen_frame(payload):
    return _relay("screen_frame", payload, "screen", {"host"}, MAX_SCREEN_BYTES)


@socketio.on("remote_input")
def remote_input(payload):
    return _relay("remote_input", payload, "control", {"viewer"})


@socketio.on("chat_message")
def chat_message(payload):
    data = _data(payload)
    if data and (not isinstance(data.get("text"), str) or len(data["text"]) > 2000):
        return _deny("Chat message is invalid.")
    return _relay("chat_message", payload, None, max_size=4000)


@socketio.on("clipboard_text")
def clipboard_text(payload):
    data = _data(payload)
    if data and (not isinstance(data.get("text"), str) or len(data["text"]) > 10000):
        return _deny("Clipboard text is invalid.")
    return _relay("clipboard_text", payload, "clipboard", max_size=12000)


@socketio.on("file_offer")
def file_offer(payload):
    data = _data(payload)
    if not data or not isinstance(data.get("name"), str) or len(data["name"]) > 255:
        return _deny("Invalid file offer.")
    name = data["name"]
    if (
        name in {"", ".", ".."}
        or ntpath.basename(name) != name
        or any(ord(char) < 32 for char in name)
        or os.path.splitext(name)[1].lower() in BLOCKED_FILE_EXTENSIONS
    ):
        return _deny("This file name or type is not allowed.")
    if not isinstance(data.get("size"), int) or data["size"] < 0 or data["size"] > 100 * 1024 * 1024:
        return _deny("File exceeds the 100 MB size limit.")
    if not isinstance(data.get("sha256"), str) or not re.fullmatch(r"[a-fA-F0-9]{64}", data["sha256"]):
        return _deny("Invalid file checksum.")
    return _relay("file_offer", payload, "files", max_size=2000)


@socketio.on("file_response")
def file_response(payload):
    data = _data(payload)
    if not data or not isinstance(data.get("transfer_id"), str) or data.get("accepted") not in {True, False}:
        return _deny("Invalid file response.")
    return _relay("file_response", payload, "files", max_size=1000)


@socketio.on("file_chunk")
def file_chunk(payload):
    return _relay("file_chunk", payload, "files", max_size=MAX_FILE_CHUNK * 2)


@socketio.on("file_complete")
def file_complete(payload):
    return _relay("file_complete", payload, "files", max_size=500)


@socketio.on("file_cancel")
def file_cancel(payload):
    return _relay("file_cancel", payload, "files", max_size=1000)


@socketio.on("disconnect")
def on_disconnect(reason=None):
    sid = request.sid
    with LOCK:
        device_id = SID_DEVICE.pop(sid, None)
        if device_id and DEVICES.get(device_id, {}).get("sid") == sid:
            DEVICES.pop(device_id, None)
        for request_id, pending in list(REQUESTS.items()):
            if pending["viewer_sid"] == sid:
                REQUESTS.pop(request_id, None)
            elif SESSIONS.get(pending["session_key"], {}).get("host_sid") == sid:
                REQUESTS.pop(request_id, None)
        session_id = SID_SESSION.get(sid)
        if session_id:
            _end_session(session_id, "Participant disconnected")
        for session_key, session in list(SESSIONS.items()):
            if session.get("host_sid") == sid:
                SESSION_CODES.pop(session["code_hash"], None)
                SESSIONS.pop(session_key, None)
        for key in list(RATE_LIMITS):
            if key.startswith(f"relay:{sid}:"):
                RATE_LIMITS.pop(key, None)
    return None


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
