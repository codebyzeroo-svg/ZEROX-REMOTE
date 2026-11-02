"""ZEROX REMOTE - consent-based Windows remote support client."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import platform
import re
import secrets
import socket
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import customtkinter as ctk
import mss
import pyautogui
import socketio
from PIL import Image
from tkinter import TclError, filedialog, messagebox


APP_NAME = "ZEROX REMOTE"
DEFAULT_SERVER = "http://127.0.0.1:5000"
CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "ZEROX-REMOTE"
CONFIG_FILE = CONFIG_DIR / "settings.json"
MAX_FILE_SIZE = 100 * 1024 * 1024
FILE_CHUNK_SIZE = 48 * 1024
BLOCKED_FILE_EXTENSIONS = {
    ".appx", ".bash", ".bat", ".cpl", ".csh", ".cmd", ".com", ".command",
    ".dll", ".exe", ".gadget", ".hta", ".jar", ".js", ".jse", ".lnk",
    ".msi", ".msix", ".ocx", ".pif", ".ps1", ".psm1", ".py", ".pyw",
    ".reg", ".scr", ".sh", ".sys", ".vbe", ".vbs", ".wsf", ".wsh", ".zsh",
}
pyautogui.FAILSAFE = True
pyautogui.PAUSE = 0


def load_settings() -> dict[str, Any]:
    try:
        settings = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if not isinstance(settings, dict):
            raise ValueError("Invalid settings format")
    except FileNotFoundError:
        settings = {}
    except (OSError, json.JSONDecodeError, ValueError):
        settings = {}
    device_id = settings.get("device_id")
    if not isinstance(device_id, str) or not re.fullmatch(r"[A-F0-9-]{36}", device_id):
        settings["device_id"] = str(uuid.uuid4()).upper()
    if not isinstance(settings.get("server_url"), str):
        settings["server_url"] = os.environ.get("ZEROX_SERVER_URL", DEFAULT_SERVER)
    if not isinstance(settings.get("receive_folder"), str):
        settings["receive_folder"] = str(Path.home() / "Downloads")
    if not isinstance(settings.get("history"), list):
        settings["history"] = []
    else:
        settings["history"] = [row for row in settings["history"] if isinstance(row, dict)][-100:]
    return settings


def save_settings(settings: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    temporary = CONFIG_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    os.replace(temporary, CONFIG_FILE)


def clean_server_url(value: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ValueError("أدخل عنوانًا صالحًا يبدأ بـ https:// أو http://")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("عنوان السيرفر لا يجب أن يتضمن بيانات دخول أو query string.")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
        raise ValueError("الاتصال عبر الإنترنت يتطلب HTTPS/WSS.")
    return value


class RemoteClient:
    """Socket.IO transport and session state; all UI updates are scheduled on Tk."""

    def __init__(self, app: "ZeroXRemote") -> None:
        self.app = app
        self.sio = socketio.Client(
            reconnection=True,
            reconnection_attempts=0,
            reconnection_delay=1,
            reconnection_delay_max=20,
            logger=False,
            engineio_logger=False,
        )
        self.connected = False
        self.registered = False
        self.session_id: str | None = None
        self.role: str | None = None
        self.permissions: dict[str, bool] = {}
        self.peer_device_id = ""
        self.stop_stream = threading.Event()
        self.incoming_files: dict[str, dict[str, Any]] = {}
        self.screen_bounds = (0, 0, 1, 1)
        self.pressed_remote_keys: set[str] = set()
        self.pressed_mouse_buttons: set[str] = set()
        self._wire_events()

    def _wire_events(self) -> None:
        self.sio.on("connect", self._on_connect)
        self.sio.on("disconnect", self._on_disconnect)
        self.sio.on("connect_error", self._on_connect_error)
        self.sio.on("registered", self._on_registered)
        self.sio.on("session_code", self._on_session_code)
        self.sio.on("incoming_request", self._on_incoming_request)
        self.sio.on("session_started", self._on_session_started)
        self.sio.on("session_ended", self._on_session_ended)
        self.sio.on("screen_frame", self._on_screen_frame)
        self.sio.on("remote_input", self._on_remote_input)
        self.sio.on("chat_message", self._on_chat_message)
        self.sio.on("file_offer", self._on_file_offer)
        self.sio.on("file_response", self._on_file_response)
        self.sio.on("file_chunk", self._on_file_chunk)
        self.sio.on("file_complete", self._on_file_complete)
        self.sio.on("file_cancel", self._on_file_cancel)
        self.sio.on("clipboard_text", self._on_clipboard_text)
        self.sio.on("device_list", self._on_device_list)
        self.sio.on("server_error", self._on_server_error)

    def connect(self, address: str) -> None:
        try:
            address = clean_server_url(address)
            if self.sio.connected:
                self.sio.disconnect()
            self.app.settings["server_url"] = address
            save_settings(self.app.settings)
            self.app.ui(self.app.set_status, "Connecting", "yellow")
            while not self.sio.connected and not self.app.closing:
                try:
                    self.sio.connect(address, wait_timeout=18, transports=["websocket", "polling"])
                except (ValueError, OSError, socketio.exceptions.ConnectionError) as exc:
                    self.app.ui(self.app.set_status, f"Server offline: retrying ({str(exc)[:80]})", "red")
                    time.sleep(3)
        except (ValueError, OSError) as exc:
            self.app.ui(self.app.set_status, f"Could not save server settings: {exc}", "red")

    def disconnect(self) -> None:
        if self.sio.connected:
            try:
                self.sio.disconnect()
            except socketio.exceptions.SocketIOError as exc:
                self.app.ui(self.app.log, f"Disconnect error: {exc}")

    def emit(self, event: str, data: dict[str, Any] | None = None) -> None:
        if not self.sio.connected:
            self.app.ui(self.app.log, "Not connected to the signaling server.")
            return
        try:
            self.sio.emit(event, data or {})
        except socketio.exceptions.SocketIOError as exc:
            self.app.ui(self.app.log, f"Network error: {exc}")

    def _on_connect(self) -> None:
        self.connected = True
        self.registered = False
        self.emit("register", {"device_id": self.app.settings["device_id"]})
        self.app.ui(self.app.set_status, "Connected · registering device", "green")

    def _on_disconnect(self, *_: Any) -> None:
        self._release_remote_inputs()
        self._cleanup_incoming_files()
        self.app.pending_transfers.clear()
        self.connected = False
        self.registered = False
        self.session_id = None
        self.role = None
        self.stop_stream.set()
        self.app.ui(self.app.on_network_lost)

    def _on_connect_error(self, details: Any) -> None:
        self.app.ui(self.app.set_status, f"Server unavailable: {str(details)[:120]}", "red")

    def _on_registered(self, data: dict[str, Any]) -> None:
        self.registered = True
        self.app.ui(self.app.set_status, "Connected · online", "green")
        self.app.ui(self.app.refresh_device_id)

    def _on_session_code(self, data: dict[str, Any]) -> None:
        code = str(data.get("code", ""))
        expires = int(data.get("expires_in", 0))
        self.app.ui(self.app.show_session_code, code, expires)

    def _on_incoming_request(self, data: dict[str, Any]) -> None:
        self.app.ui(self.app.ask_incoming_consent, data)

    def _on_session_started(self, data: dict[str, Any]) -> None:
        self.session_id = str(data["session_id"])
        self.role = str(data["role"])
        self.permissions = {k: bool(v) for k, v in data.get("permissions", {}).items()}
        self.peer_device_id = str(data.get("peer_device_id", ""))
        self.stop_stream.clear()
        self.app.ui(self.app.on_session_started, self.role, self.permissions, self.peer_device_id)
        if self.role == "host":
            threading.Thread(target=self._stream_screen, daemon=True).start()

    def _on_session_ended(self, data: dict[str, Any] | None = None) -> None:
        self.stop_stream.set()
        self._release_remote_inputs()
        self._cleanup_incoming_files()
        self.session_id = None
        self.role = None
        self.permissions = {}
        self.app.pending_transfers.clear()
        self.app.ui(self.app.on_session_ended, (data or {}).get("reason", "Session ended"))

    def _on_screen_frame(self, data: dict[str, Any]) -> None:
        try:
            raw = base64.b64decode(data["jpeg"], validate=True)
            self.app.ui(
                self.app.display_frame,
                raw,
                int(data["width"]),
                int(data["height"]),
                int(data.get("monitor", 1)),
            )
        except (KeyError, ValueError, TypeError):
            self.app.ui(self.app.log, "Received an invalid screen frame.")

    def _on_remote_input(self, data: dict[str, Any]) -> None:
        if self.role != "host" or not self.permissions.get("control"):
            return
        try:
            kind = data.get("kind")
            if kind == "move":
                if int(data.get("monitor", -1)) != self.app.monitor_index:
                    return
                x = max(0.0, min(1.0, float(data["x"])))
                y = max(0.0, min(1.0, float(data["y"])))
                left, top, width, height = self.screen_bounds
                pyautogui.moveTo(
                    left + round(x * (width - 1)),
                    top + round(y * (height - 1)),
                )
            elif kind in {"mouse_down", "mouse_up"} and data.get("button") in {"left", "right", "middle"}:
                getattr(pyautogui, "mouseDown" if kind == "mouse_down" else "mouseUp")(button=data["button"])
                if kind == "mouse_down":
                    self.pressed_mouse_buttons.add(data["button"])
                else:
                    self.pressed_mouse_buttons.discard(data["button"])
            elif kind in {"key_down", "key_up"}:
                key = str(data.get("key", ""))
                if key in pyautogui.KEYBOARD_KEYS:
                    getattr(pyautogui, "keyDown" if kind == "key_down" else "keyUp")(key)
                    if kind == "key_down":
                        self.pressed_remote_keys.add(key)
                    else:
                        self.pressed_remote_keys.discard(key)
        except pyautogui.FailSafeException as exc:
            self.app.ui(self.app.log, f"Local mouse failsafe stopped remote control: {exc}")
            if self.session_id:
                self.emit("end_session", {"session_id": self.session_id})
        except (KeyError, ValueError, OSError) as exc:
            self.app.ui(self.app.log, f"Input was not applied: {exc}")

    def _release_remote_inputs(self) -> None:
        for key in self.pressed_remote_keys:
            try:
                pyautogui.keyUp(key)
            except (OSError, ValueError, pyautogui.FailSafeException) as exc:
                self.app.ui(self.app.log, f"Could not release remote key: {exc}")
        for button in self.pressed_mouse_buttons:
            try:
                pyautogui.mouseUp(button=button)
            except (OSError, ValueError, pyautogui.FailSafeException) as exc:
                self.app.ui(self.app.log, f"Could not release remote mouse button: {exc}")
        self.pressed_remote_keys.clear()
        self.pressed_mouse_buttons.clear()

    def _cleanup_incoming_files(self) -> None:
        for transfer in self.incoming_files.values():
            try:
                transfer["file"].close()
                transfer["temp"].unlink(missing_ok=True)
            except OSError as exc:
                self.app.ui(self.app.log, f"Could not clean up partial file: {exc}")
        self.incoming_files.clear()

    def _on_chat_message(self, data: dict[str, Any]) -> None:
        text = str(data.get("text", ""))[:2000]
        self.app.ui(self.app.append_chat, str(data.get("sender", "Peer")), text)

    def _on_file_offer(self, data: dict[str, Any]) -> None:
        self.app.ui(self.app.confirm_file_offer, data)

    def _on_file_response(self, data: dict[str, Any]) -> None:
        transfer_id = str(data.get("transfer_id", ""))
        self.app.ui(self.app.file_response, transfer_id, bool(data.get("accepted")), str(data.get("reason", "")))

    def _on_file_chunk(self, data: dict[str, Any]) -> None:
        transfer_id = str(data.get("transfer_id", ""))
        transfer = self.incoming_files.get(transfer_id)
        if not transfer:
            return
        try:
            chunk = base64.b64decode(data["data"], validate=True)
            if len(chunk) > FILE_CHUNK_SIZE or transfer["received"] + len(chunk) > transfer["size"]:
                raise ValueError("Unexpected file chunk size")
            transfer["file"].write(chunk)
            transfer["hash"].update(chunk)
            transfer["received"] += len(chunk)
            self.app.ui(
                self.app.update_transfer,
                transfer["name"],
                transfer["received"],
                transfer["size"],
            )
        except (KeyError, ValueError, OSError) as exc:
            self._abort_receive(transfer_id, str(exc))

    def _on_file_complete(self, data: dict[str, Any]) -> None:
        transfer_id = str(data.get("transfer_id", ""))
        transfer = self.incoming_files.pop(transfer_id, None)
        if not transfer:
            return
        try:
            transfer["file"].close()
            valid = (
                transfer["received"] == transfer["size"]
                and secrets.compare_digest(transfer["hash"].hexdigest(), transfer["sha256"])
            )
            if not valid:
                transfer["temp"].unlink(missing_ok=True)
                self.emit("file_cancel", {"transfer_id": transfer_id, "reason": "Integrity check failed"})
                self.app.ui(self.app.log, f"Rejected corrupted transfer: {transfer['name']}")
                return
            if transfer["destination"].exists():
                transfer["temp"].unlink(missing_ok=True)
                self.app.ui(self.app.log, "Destination file now exists; transfer discarded.")
                return
            os.rename(transfer["temp"], transfer["destination"])
            self.app.ui(self.app.log, f"Received file: {transfer['destination'].name}")
            self.app.ui(self.app.update_transfer, "Complete", transfer["size"], transfer["size"])
        except OSError as exc:
            self.app.ui(self.app.log, f"Could not finish file: {exc}")

    def _on_file_cancel(self, data: dict[str, Any]) -> None:
        transfer_id = str(data.get("transfer_id", ""))
        self.app.pending_transfers.pop(transfer_id, None)
        transfer = self.incoming_files.pop(transfer_id, None)
        if transfer:
            try:
                transfer["file"].close()
                transfer["temp"].unlink(missing_ok=True)
            except OSError as exc:
                self.app.ui(self.app.log, f"Could not remove partial transfer: {exc}")
        self.app.ui(self.app.log, f"File transfer cancelled: {str(data.get('reason', 'peer cancelled'))[:120]}")

    def _on_clipboard_text(self, data: dict[str, Any]) -> None:
        text = str(data.get("text", ""))[:10000]
        self.app.ui(self.app.receive_clipboard, text)

    def _on_device_list(self, data: dict[str, Any]) -> None:
        self.app.ui(self.app.show_devices, data.get("devices", []))

    def _on_server_error(self, data: dict[str, Any]) -> None:
        self.app.ui(self.app.log, f"Server: {str(data.get('message', 'Request failed'))[:200]}")

    def measure_latency(self) -> None:
        if not self.sio.connected or not self.registered:
            self.app.show_latency(None)
            self.app.log("Connect to the signaling server before measuring latency.")
            return

        def measure() -> None:
            started = time.perf_counter()
            try:
                result = self.sio.call("ping_probe", {}, timeout=4)
                if not isinstance(result, dict) or result.get("ok") is not True:
                    raise ValueError("The signaling server returned an invalid response.")
                milliseconds = round((time.perf_counter() - started) * 1000)
                self.app.ui(self.app.show_latency, milliseconds)
            except (TimeoutError, ValueError, RuntimeError, socketio.exceptions.SocketIOError) as exc:
                self.app.ui(self.app.show_latency, None)
                self.app.ui(self.app.log, f"Latency check failed: {exc}")

        threading.Thread(target=measure, daemon=True).start()

    def _stream_screen(self) -> None:
        while not self.stop_stream.is_set() and self.session_id:
            if self.role == "host" and self.permissions.get("screen"):
                try:
                    quality = self.app.capture_quality
                    interval = 1 / self.app.capture_fps
                    with mss.mss() as capture:
                        monitor_index = min(self.app.monitor_index, len(capture.monitors) - 1)
                        monitor = capture.monitors[monitor_index]
                        grabbed = capture.grab(monitor)
                        self.screen_bounds = (monitor["left"], monitor["top"], monitor["width"], monitor["height"])
                        screen_width = monitor["width"]
                        screen_height = monitor["height"]
                        shot = Image.frombytes("RGB", grabbed.size, grabbed.rgb)
                    max_width = {"Low": 800, "Medium": 1280, "High": 1920}[quality]
                    if shot.width > max_width:
                        height = round(shot.height * max_width / shot.width)
                        shot = shot.resize((max_width, height), Image.Resampling.BILINEAR)
                    output = io.BytesIO()
                    shot.save(output, format="JPEG", quality={"Low": 35, "Medium": 55, "High": 72}[quality], optimize=True)
                    encoded = base64.b64encode(output.getvalue()).decode("ascii")
                    self.emit(
                        "screen_frame",
                        {
                            "session_id": self.session_id,
                            "jpeg": encoded,
                            "width": screen_width,
                            "height": screen_height,
                            "monitor": monitor_index,
                        },
                    )
                    time.sleep(max(0.04, interval))
                except (OSError, ValueError, RuntimeError) as exc:
                    self.app.ui(self.app.log, f"Screen sharing paused: {exc}")
                    time.sleep(1)
            else:
                time.sleep(0.2)

    def send_file(self, path: Path) -> None:
        if not self.session_id or not self.permissions.get("files"):
            self.app.log("File transfer is not permitted for this session.")
            return
        try:
            size = path.stat().st_size
        except OSError as exc:
            self.app.log(f"Could not inspect the selected file: {exc}")
            return
        if size > MAX_FILE_SIZE:
            self.app.log("Files must be 100 MB or smaller.")
            return
        if path.suffix.lower() in BLOCKED_FILE_EXTENSIONS:
            self.app.log("Executable, script, shortcut, and driver files are blocked.")
            return
        transfer_id = secrets.token_hex(16)
        session_id = self.session_id
        self.app.pending_transfers[transfer_id] = {"path": path, "status": "hashing"}

        def prepare_offer() -> None:
            try:
                digest = hashlib.sha256()
                with path.open("rb") as source:
                    while block := source.read(FILE_CHUNK_SIZE):
                        digest.update(block)
                if self.session_id != session_id or transfer_id not in self.app.pending_transfers:
                    return
                self.app.pending_transfers[transfer_id]["status"] = "offered"
                self.emit(
                    "file_offer",
                    {
                        "session_id": session_id,
                        "transfer_id": transfer_id,
                        "name": path.name,
                        "size": size,
                        "sha256": digest.hexdigest(),
                    },
                )
                self.app.ui(self.app.log, f"Waiting for the peer to approve {path.name}.")
            except OSError as exc:
                self.app.pending_transfers.pop(transfer_id, None)
                self.app.ui(self.app.log, f"Could not prepare file transfer: {exc}")

        threading.Thread(target=prepare_offer, daemon=True).start()

    def start_file_send(self, transfer_id: str) -> None:
        item = self.app.pending_transfers.get(transfer_id)
        if not item:
            return
        path: Path = item["path"]

        def send() -> None:
            try:
                total = path.stat().st_size
                sent = 0
                with path.open("rb") as source:
                    while block := source.read(FILE_CHUNK_SIZE):
                        if not self.session_id or transfer_id not in self.app.pending_transfers:
                            return
                        self.emit(
                            "file_chunk",
                            {"session_id": self.session_id, "transfer_id": transfer_id, "data": base64.b64encode(block).decode("ascii")},
                        )
                        sent += len(block)
                        self.app.ui(self.app.update_transfer, path.name, sent, total)
                        time.sleep(0.003)
                self.emit("file_complete", {"session_id": self.session_id, "transfer_id": transfer_id})
                self.app.ui(self.app.log, f"Sent file: {path.name}")
            except OSError as exc:
                self.emit("file_cancel", {"session_id": self.session_id, "transfer_id": transfer_id, "reason": str(exc)[:100]})
                self.app.ui(self.app.log, f"File send failed: {exc}")
            finally:
                self.app.pending_transfers.pop(transfer_id, None)

        threading.Thread(target=send, daemon=True).start()

    def accept_file(self, data: dict[str, Any], destination: Path) -> None:
        transfer_id = str(data["transfer_id"])
        temp = destination.with_name(destination.name + ".zerox-part")
        if destination.exists() or temp.exists():
            raise FileExistsError("The destination or a partial transfer already exists.")
        file_obj = temp.open("xb")
        self.incoming_files[transfer_id] = {
            "name": destination.name,
            "destination": destination,
            "temp": temp,
            "file": file_obj,
            "size": int(data["size"]),
            "received": 0,
            "sha256": str(data["sha256"]),
            "hash": hashlib.sha256(),
        }
        self.emit("file_response", {"session_id": self.session_id, "transfer_id": transfer_id, "accepted": True})

    def _abort_receive(self, transfer_id: str, reason: str) -> None:
        transfer = self.incoming_files.pop(transfer_id, None)
        if transfer:
            try:
                transfer["file"].close()
                transfer["temp"].unlink(missing_ok=True)
            except OSError as exc:
                self.app.ui(self.app.log, f"Could not remove partial file: {exc}")
        self.emit("file_cancel", {"session_id": self.session_id, "transfer_id": transfer_id, "reason": reason[:100]})
        self.app.ui(self.app.log, f"File transfer aborted: {reason}")


class ZeroXRemote(ctk.CTk):
    COLORS = {"bg": "#080D1C", "panel": "#111A2E", "panel2": "#17243D", "blue": "#3478F6", "purple": "#8957E5", "text": "#F1F5FF", "muted": "#91A0BB", "green": "#28C98A", "red": "#F16C7A"}

    def __init__(self) -> None:
        super().__init__()
        self.settings = load_settings()
        self.client = RemoteClient(self)
        self.active_session_started: float | None = None
        self.current_peer_id = ""
        self.pending_transfers: dict[str, dict[str, Any]] = {}
        self.capture_quality = "Medium"
        self.capture_fps = 8
        self.monitor_index = 1
        self.frame_size = (1, 1)
        self.displayed_size = (1, 1)
        self.frame_monitor = 1
        self.frame_bytes: bytes | None = None
        self.last_pointer_at = 0.0
        self.closing = False
        self.frame_image: ctk.CTkImage | None = None
        self._mouse_down = False
        self.title(f"{APP_NAME} | REMOTE DESKTOP CONTROL")
        self.geometry("1180x760")
        self.minsize(940, 640)
        self.configure(fg_color=self.COLORS["bg"])
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self._build_shell()
        self._build_pages()
        self.show_page("Dashboard")
        self.refresh_device_id()
        self.bind("<Escape>", self._exit_fullscreen)
        threading.Thread(target=self.client.connect, args=(self.settings["server_url"],), daemon=True).start()
        self.after(1000, self._tick_session_timer)

    def ui(self, callback: Any, *args: Any) -> None:
        try:
            self.after(0, callback, *args)
        except (RuntimeError, TclError):
            pass

    def _build_shell(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#0D1426")
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        ctk.CTkLabel(sidebar, text="ZEROX", font=ctk.CTkFont(size=26, weight="bold"), text_color="#65A0FF").pack(anchor="w", padx=22, pady=(26, 0))
        ctk.CTkLabel(sidebar, text="REMOTE DESKTOP CONTROL", font=ctk.CTkFont(size=9, weight="bold"), text_color=self.COLORS["muted"]).pack(anchor="w", padx=23, pady=(0, 24))
        self.nav_buttons: dict[str, ctk.CTkButton] = {}
        for title in ("Dashboard", "Remote Connection", "My Devices", "File Transfer", "Chat", "Session History", "Security Center", "Settings", "About"):
            button = ctk.CTkButton(
                sidebar, text=title, anchor="w", height=38, corner_radius=10,
                fg_color="transparent", hover_color="#1C2A45",
                text_color="#C5D0E5", command=lambda name=title: self.show_page(name),
            )
            button.pack(fill="x", padx=12, pady=2)
            self.nav_buttons[title] = button
        ctk.CTkFrame(sidebar, height=2, fg_color="#202B43").pack(fill="x", padx=16, pady=(18, 12))
        self.status_dot = ctk.CTkLabel(sidebar, text="●  Connecting", anchor="w", text_color="#F2C45E")
        self.status_dot.pack(fill="x", padx=20, pady=4)
        ctk.CTkLabel(sidebar, text="Consent-first remote support", text_color="#64728B", font=ctk.CTkFont(size=10)).pack(side="bottom", anchor="w", padx=18, pady=18)
        self.content = ctk.CTkFrame(self, fg_color=self.COLORS["bg"], corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew", padx=22, pady=20)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

    def _build_pages(self) -> None:
        self.pages: dict[str, ctk.CTkFrame] = {}
        for name in self.nav_buttons:
            page = ctk.CTkFrame(self.content, fg_color="transparent")
            page.grid(row=0, column=0, sticky="nsew")
            page.grid_columnconfigure(0, weight=1)
            self.pages[name] = page
        self._build_dashboard()
        self._build_remote()
        self._build_devices()
        self._build_files()
        self._build_chat()
        self._build_history()
        self._build_security()
        self._build_settings()
        self._build_about()

    def _heading(self, parent: ctk.CTkFrame, title: str, subtitle: str) -> None:
        ctk.CTkLabel(parent, text=title, font=ctk.CTkFont(size=25, weight="bold"), text_color=self.COLORS["text"]).pack(anchor="w", pady=(4, 2))
        ctk.CTkLabel(parent, text=subtitle, font=ctk.CTkFont(size=12), text_color=self.COLORS["muted"]).pack(anchor="w", pady=(0, 18))

    def _card(self, parent: ctk.CTkFrame, **kwargs: Any) -> ctk.CTkFrame:
        card = ctk.CTkFrame(parent, fg_color=self.COLORS["panel"], corner_radius=16, **kwargs)
        return card

    def _button(self, parent: ctk.CTkFrame, text: str, command: Any, color: str | None = None, **kwargs: Any) -> ctk.CTkButton:
        return ctk.CTkButton(parent, text=text, command=command, height=38, corner_radius=11, fg_color=color or self.COLORS["blue"], hover_color="#2765D3", **kwargs)

    def _build_dashboard(self) -> None:
        page = self.pages["Dashboard"]
        self._heading(page, "Dashboard", "Secure, visible remote support — every session requires local approval.")
        card = self._card(page)
        card.pack(fill="x", pady=(0, 14))
        ctk.CTkLabel(card, text="Your device ID", text_color=self.COLORS["muted"]).pack(anchor="w", padx=20, pady=(16, 2))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=(0, 16))
        self.device_id_label = ctk.CTkLabel(row, text="", font=ctk.CTkFont(size=21, weight="bold"), text_color="#8DB8FF")
        self.device_id_label.pack(side="left", padx=(0, 14))
        self._button(row, "Copy ID", self.copy_device_id, color=self.COLORS["panel2"]).pack(side="left")
        cards = ctk.CTkFrame(page, fg_color="transparent")
        cards.pack(fill="x", pady=6)
        cards.grid_columnconfigure((0, 1), weight=1)
        for col, title, detail, action, callback in (
            (0, "Host a session", "Generate a one-time code and approve each incoming request.", "Create access code", self.create_session),
            (1, "Connect to a device", "Enter a temporary code shared by the device owner.", "Open connection", lambda: self.show_page("Remote Connection")),
        ):
            card = self._card(cards)
            card.grid(row=0, column=col, sticky="nsew", padx=(0, 8) if col == 0 else (8, 0))
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=17, weight="bold")).pack(anchor="w", padx=18, pady=(18, 5))
            ctk.CTkLabel(card, text=detail, wraplength=360, justify="left", text_color=self.COLORS["muted"]).pack(anchor="w", padx=18, pady=(0, 16))
            self._button(card, action, callback).pack(anchor="w", padx=18, pady=(0, 18))
        self.home_code = ctk.CTkLabel(page, text="", font=ctk.CTkFont(size=17, weight="bold"), text_color="#B99AFF")
        self.home_code.pack(anchor="w", pady=12)
        self.home_status = ctk.CTkLabel(page, text="No active session", text_color=self.COLORS["muted"])
        self.home_status.pack(anchor="w")

    def _build_remote(self) -> None:
        page = self.pages["Remote Connection"]
        self._heading(page, "Remote Connection", "The host must approve the request and its permissions before anything is shared.")
        card = self._card(page)
        card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(card, text="Temporary session code", text_color=self.COLORS["muted"]).grid(row=0, column=0, sticky="w", padx=16, pady=(15, 5))
        self.code_entry = ctk.CTkEntry(card, placeholder_text="Paste code shared by the device owner", width=340, height=38)
        self.code_entry.grid(row=1, column=0, padx=16, pady=(0, 15), sticky="w")
        self._button(card, "Request connection", self.request_connection).grid(row=1, column=1, padx=12, pady=(0, 15))
        self.video_frame = ctk.CTkFrame(page, fg_color="#050811", corner_radius=14, height=350)
        self.video_frame.pack(fill="both", expand=True, pady=8)
        self.video_frame.pack_propagate(False)
        self.video_label = ctk.CTkLabel(self.video_frame, text="Screen sharing begins only after the host grants permission.", text_color=self.COLORS["muted"])
        self.video_label.pack(fill="both", expand=True, padx=12, pady=12)
        self.video_label.bind("<Motion>", self._mouse_motion)
        self.video_label.bind("<ButtonPress-1>", lambda e: self._mouse_button(e, "left", True))
        self.video_label.bind("<ButtonRelease-1>", lambda e: self._mouse_button(e, "left", False))
        self.video_label.bind("<ButtonPress-3>", lambda e: self._mouse_button(e, "right", True))
        self.video_label.bind("<ButtonRelease-3>", lambda e: self._mouse_button(e, "right", False))
        self.video_label.bind("<KeyPress>", self._key_down)
        self.video_label.bind("<KeyRelease>", self._key_up)
        bar = ctk.CTkFrame(page, fg_color="transparent")
        bar.pack(fill="x", pady=8)
        self.quality_menu = ctk.CTkOptionMenu(bar, values=["Low", "Medium", "High"], command=self._set_quality, width=120)
        self.quality_menu.set("Medium")
        self.quality_menu.pack(side="left", padx=(0, 8))
        self.fps_menu = ctk.CTkOptionMenu(bar, values=["5", "8", "12", "15"], command=lambda value: setattr(self, "capture_fps", int(value)), width=90)
        self.fps_menu.set("8")
        self.fps_menu.pack(side="left")
        self._button(bar, "Disconnect", self.end_session, color="#A83A50").pack(side="right")
        self._button(bar, "Save screenshot", self.save_screenshot, color=self.COLORS["panel2"]).pack(side="right", padx=8)
        self._button(bar, "Measure latency", self.client.measure_latency, color=self.COLORS["panel2"]).pack(side="right", padx=8)
        self._button(bar, "Fullscreen", self._toggle_fullscreen, color=self.COLORS["panel2"]).pack(side="right", padx=8)
        try:
            with mss.mss() as capture:
                monitor_count = max(1, len(capture.monitors) - 1)
        except OSError:
            monitor_count = 1
        monitor_values = [f"Monitor {index}" for index in range(1, monitor_count + 1)]
        self.monitor_menu = ctk.CTkOptionMenu(bar, values=monitor_values, command=self._set_monitor, width=120)
        self.monitor_menu.set(monitor_values[0])
        self.monitor_menu.pack(side="left", padx=8)
        self.screen_info = ctk.CTkLabel(page, text="Screen: waiting for an approved stream", text_color=self.COLORS["muted"])
        self.screen_info.pack(anchor="w", pady=(2, 0))
        self.latency_label = ctk.CTkLabel(page, text="Latency: —", text_color=self.COLORS["muted"])
        self.latency_label.pack(anchor="w", pady=(0, 4))

    def _build_devices(self) -> None:
        page = self.pages["My Devices"]
        self._heading(page, "My Devices", "Only devices currently registered with the signaling server are shown.")
        self._button(page, "Refresh online devices", lambda: self.client.emit("list_devices")).pack(anchor="w", pady=(0, 12))
        self.device_list = ctk.CTkTextbox(page, height=380, fg_color=self.COLORS["panel"], corner_radius=14)
        self.device_list.pack(fill="both", expand=True)
        self.device_list.insert("end", f"This device: {self.settings['device_id']}\n\n")

    def _build_files(self) -> None:
        page = self.pages["File Transfer"]
        self._heading(page, "File Transfer", "Transfers are peer-approved, size-limited, integrity-checked, and never opened automatically.")
        card = self._card(page)
        card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(card, text=f"Maximum file size: {MAX_FILE_SIZE // (1024 * 1024)} MB · SHA-256 verification", text_color=self.COLORS["muted"]).pack(anchor="w", padx=18, pady=(16, 8))
        self._button(card, "Choose file and request transfer", self.choose_file).pack(anchor="w", padx=18, pady=(0, 16))
        self.transfer_name = ctk.CTkLabel(page, text="No active transfer", text_color=self.COLORS["muted"])
        self.transfer_name.pack(anchor="w", pady=(14, 4))
        self.transfer_bar = ctk.CTkProgressBar(page, progress_color=self.COLORS["purple"])
        self.transfer_bar.pack(fill="x", pady=8)
        self.transfer_bar.set(0)
        self.transfer_size = ctk.CTkLabel(page, text="")
        self.transfer_size.pack(anchor="w")
        self.transfer_speed = ctk.CTkLabel(page, text="Speed: —", text_color=self.COLORS["muted"])
        self.transfer_speed.pack(anchor="w", pady=(2, 0))
        self._button(page, "Cancel active transfer", self.cancel_transfer, color="#A83A50").pack(anchor="w", pady=8)
        ctk.CTkLabel(page, text=f"Receive folder: {self.settings['receive_folder']}", text_color=self.COLORS["muted"], wraplength=700).pack(anchor="w", pady=12)
        self._button(page, "Choose receive folder", self.choose_receive_folder, color=self.COLORS["panel2"]).pack(anchor="w")

    def _build_chat(self) -> None:
        page = self.pages["Chat"]
        self._heading(page, "Session Chat", "Text messages are relayed only to your currently paired session.")
        self.chat_log = ctk.CTkTextbox(page, fg_color=self.COLORS["panel"], corner_radius=14)
        self.chat_log.pack(fill="both", expand=True, pady=(0, 12))
        row = ctk.CTkFrame(page, fg_color="transparent")
        row.pack(fill="x")
        self.chat_entry = ctk.CTkEntry(row, placeholder_text="Write a message…", height=40)
        self.chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.chat_entry.bind("<Return>", lambda _: self.send_chat())
        self._button(row, "Send", self.send_chat).pack(side="right")
        self._button(row, "Share clipboard", self.share_clipboard, color=self.COLORS["panel2"]).pack(side="right", padx=8)

    def _build_history(self) -> None:
        page = self.pages["Session History"]
        self._heading(page, "Session History", "History is stored locally; it contains device IDs and times, not passwords or session codes.")
        self.history_box = ctk.CTkTextbox(page, fg_color=self.COLORS["panel"], corner_radius=14)
        self.history_box.pack(fill="both", expand=True)
        self._render_history()

    def _build_security(self) -> None:
        page = self.pages["Security Center"]
        self._heading(page, "Security Center", "Session access is temporary, visible, and controlled by the receiving device.")
        for title, body in (
            ("Explicit consent", "An incoming connection displays an approval dialog on the host. Denial ends the request."),
            ("Permission controls", "Screen sharing, remote input, clipboard, and file transfer are separately enabled for each session."),
            ("Transport security", "Use HTTPS/WSS for public servers. Render terminates TLS; use a trusted certificate for self-hosting."),
            ("No unattended access", "There is no stealth mode, persistence mechanism, UAC bypass, or background auto-approval."),
            ("Safety limits", "The client includes a local mouse-corner failsafe, a 100 MB transfer cap, and SHA-256 file verification."),
        ):
            card = self._card(page)
            card.pack(fill="x", pady=6)
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=16, pady=(12, 3))
            ctk.CTkLabel(card, text=body, text_color=self.COLORS["muted"], wraplength=770, justify="left").pack(anchor="w", padx=16, pady=(0, 12))

    def _build_settings(self) -> None:
        page = self.pages["Settings"]
        self._heading(page, "Settings", "Connection settings are saved in your user profile, not in the project folder.")
        card = self._card(page)
        card.pack(fill="x")
        ctk.CTkLabel(card, text="Signaling server URL", text_color=self.COLORS["muted"]).pack(anchor="w", padx=18, pady=(18, 4))
        self.server_entry = ctk.CTkEntry(card, height=38)
        self.server_entry.insert(0, self.settings["server_url"])
        self.server_entry.pack(fill="x", padx=18, pady=(0, 8))
        ctk.CTkLabel(card, text="Public server addresses must use HTTPS. For local development, use http://127.0.0.1:5000.", text_color=self.COLORS["muted"], wraplength=700, justify="left").pack(anchor="w", padx=18, pady=(0, 12))
        self._button(card, "Save and reconnect", self.save_server_settings).pack(anchor="w", padx=18, pady=(0, 18))
        ctk.CTkLabel(page, text=f"Device ID: {self.settings['device_id']}", text_color=self.COLORS["muted"]).pack(anchor="w", pady=18)

    def _build_about(self) -> None:
        page = self.pages["About"]
        self._heading(page, "About ZEROX REMOTE", "REMOTE DESKTOP CONTROL")
        card = self._card(page)
        card.pack(fill="x")
        for line in (
            "Consent-based remote support client for Windows 10/11.",
            f"Device: {platform.system()} {platform.release()} · Python {platform.python_version()}",
            f"Local network: {socket.gethostname()}",
            "",
            "This is an early relay-based build. The Render free tier is not suitable for sustained high-FPS screen relay.",
            "For production use, deploy a durable signaling service and a properly secured WebRTC SFU/TURN or direct P2P transport.",
        ):
            ctk.CTkLabel(card, text=line, text_color=self.COLORS["muted"], justify="left", wraplength=800).pack(anchor="w", padx=18, pady=5)

    def show_page(self, name: str) -> None:
        for page in self.pages.values():
            page.grid_remove()
        self.pages[name].grid()
        for title, button in self.nav_buttons.items():
            button.configure(fg_color="#1C2F52" if title == name else "transparent")

    def set_status(self, text: str, color: str) -> None:
        colors = {"green": "#34D399", "red": "#F16C7A", "yellow": "#F2C45E"}
        self.status_dot.configure(text=f"●  {text}", text_color=colors.get(color, self.COLORS["muted"]))

    def refresh_device_id(self) -> None:
        self.device_id_label.configure(text=self.settings["device_id"])

    def copy_device_id(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self.settings["device_id"])
        self.log("Device ID copied.")

    def create_session(self) -> None:
        if not self.client.registered:
            self.log("Wait for the signaling server connection before creating a session.")
            return
        self.client.emit("create_session")

    def show_session_code(self, code: str, expires: int) -> None:
        self.home_code.configure(text=f"Share this temporary code:  {code}  ·  expires in {expires // 60} min")
        self.log(f"Temporary session code created; expires in {expires // 60} minutes.")

    def request_connection(self) -> None:
        code = self.code_entry.get().strip().upper()
        if not re.fullmatch(r"[A-Z0-9_-]{10,30}", code):
            messagebox.showwarning(APP_NAME, "Enter a valid temporary session code.")
            return
        self.client.emit(
            "request_session",
            {"code": code, "permissions": {"screen": True, "control": True, "files": True, "clipboard": True}},
        )
        self.log("Connection request sent. The host must approve it.")

    def ask_incoming_consent(self, data: dict[str, Any]) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Incoming connection request")
        dialog.geometry("440x390")
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="Incoming remote support request", font=ctk.CTkFont(size=19, weight="bold")).pack(anchor="w", padx=20, pady=(20, 6))
        ctk.CTkLabel(dialog, text=f"Device ID: {str(data.get('device_id', 'unknown'))}", text_color=self.COLORS["muted"]).pack(anchor="w", padx=20, pady=(0, 12))
        ctk.CTkLabel(dialog, text="Choose exactly which permissions to grant:", text_color=self.COLORS["muted"]).pack(anchor="w", padx=20, pady=(0, 8))
        permissions: dict[str, ctk.CTkCheckBox] = {}
        for key, label, default in (
            ("screen", "Share my screen", True),
            ("control", "Allow mouse and keyboard", False),
            ("files", "Allow file transfer", False),
            ("clipboard", "Allow clipboard sharing", False),
        ):
            check = ctk.CTkCheckBox(dialog, text=label)
            check.pack(anchor="w", padx=22, pady=5)
            if default and data.get("permissions", {}).get(key, False):
                check.select()
            permissions[key] = check

        def respond(accepted: bool) -> None:
            values = {key: bool(check.get()) for key, check in permissions.items()}
            if accepted and not any(values.values()):
                messagebox.showwarning(APP_NAME, "Grant at least one permission, or deny the request.")
                return
            self.client.emit("respond_session", {"request_id": data.get("request_id"), "accepted": accepted, "permissions": values})
            dialog.destroy()
            if not accepted:
                self.log("Incoming request denied.")

        buttons = ctk.CTkFrame(dialog, fg_color="transparent")
        buttons.pack(side="bottom", fill="x", padx=18, pady=18)
        self._button(buttons, "Deny", lambda: respond(False), color="#A83A50").pack(side="left")
        self._button(buttons, "Approve selected", lambda: respond(True)).pack(side="right")

    def on_session_started(self, role: str, permissions: dict[str, bool], peer_device_id: str) -> None:
        self.active_session_started = time.monotonic()
        self.current_peer_id = peer_device_id
        self.home_status.configure(text=f"ACTIVE SESSION · {role.upper()} · {', '.join(k for k, v in permissions.items() if v) or 'chat'}", text_color="#34D399")
        self.set_status("Session active · visible", "green")
        self.show_page("Remote Connection")
        self._record_history("Connected", self.current_peer_id or "peer")
        if role == "viewer":
            self.video_label.focus_set()
        self.log(f"Session started as {role}; permissions: {permissions}")

    def on_session_ended(self, reason: str) -> None:
        duration = int(time.monotonic() - self.active_session_started) if self.active_session_started else 0
        self.active_session_started = None
        self.home_status.configure(text="No active session", text_color=self.COLORS["muted"])
        self.set_status("Connected · online", "green" if self.client.connected else "red")
        self.video_label.configure(image=None, text="Screen sharing begins only after the host grants permission.")
        self.frame_image = None
        self.frame_bytes = None
        self.screen_info.configure(text="Screen: waiting for an approved stream")
        self._record_history(f"Disconnected ({duration}s)", self.current_peer_id or "peer")
        self.current_peer_id = ""
        self.log(reason)

    def end_session(self) -> None:
        if self.client.session_id:
            self.client.emit("end_session", {"session_id": self.client.session_id})

    def on_network_lost(self) -> None:
        if self.active_session_started is not None:
            self.active_session_started = None
            self.home_status.configure(text="Session interrupted · reconnecting", text_color="#F2C45E")
            self._record_history("Connection interrupted", self.current_peer_id or "peer")
            self.current_peer_id = ""
        self.set_status("Offline · reconnecting", "red")
        self.video_label.configure(image=None, text="Server offline. Reconnecting automatically…")

    def _tick_session_timer(self) -> None:
        if self.active_session_started is not None:
            seconds = int(time.monotonic() - self.active_session_started)
            self.home_status.configure(text=f"ACTIVE SESSION · {seconds // 60:02}:{seconds % 60:02}")
        self.after(1000, self._tick_session_timer)

    def display_frame(self, data: bytes, width: int, height: int, monitor: int) -> None:
        try:
            with Image.open(io.BytesIO(data)) as incoming:
                if (
                    incoming.format != "JPEG"
                    or incoming.width > 7680
                    or incoming.height > 7680
                    or incoming.width * incoming.height > 33_554_432
                ):
                    raise ValueError("Screen frame dimensions or format are not allowed.")
                incoming.load()
                image = incoming.convert("RGB")
            bound_w = max(300, self.video_frame.winfo_width() - 24)
            bound_h = max(200, self.video_frame.winfo_height() - 24)
            image.thumbnail((bound_w, bound_h), Image.Resampling.BILINEAR)
            self.frame_size = (width, height)
            self.frame_monitor = monitor
            self.displayed_size = image.size
            self.frame_bytes = data
            self.frame_image = ctk.CTkImage(light_image=image, dark_image=image, size=image.size)
            self.video_label.configure(image=self.frame_image, text="")
            self.screen_info.configure(text=f"Screen: {width} × {height} · Monitor {monitor}")
        except (OSError, ValueError, Image.DecompressionBombError) as exc:
            self.log(f"Could not display screen frame: {exc}")

    def _mouse_motion(self, event: Any) -> None:
        if self.client.role != "viewer" or not self.client.permissions.get("control"):
            return
        self._send_pointer(event)

    def _send_pointer(self, event: Any, force: bool = False) -> bool:
        display_w, display_h = self.displayed_size
        widget_w, widget_h = self.video_label.winfo_width(), self.video_label.winfo_height()
        if display_w <= 1 or display_h <= 1 or widget_w <= 1 or widget_h <= 1:
            return False
        now = time.monotonic()
        if not force and now - self.last_pointer_at < 1 / 30:
            return False
        self.last_pointer_at = now
        offset_x = (widget_w - display_w) / 2
        offset_y = (widget_h - display_h) / 2
        x = (event.x - offset_x) / display_w
        y = (event.y - offset_y) / display_h
        if not 0 <= x <= 1 or not 0 <= y <= 1:
            return False
        self.client.emit("remote_input", {"session_id": self.client.session_id, "kind": "move", "x": x, "y": y, "monitor": self.frame_monitor})
        return True

    def _mouse_button(self, event: Any, button: str, down: bool) -> None:
        if self.client.role == "viewer" and self.client.permissions.get("control"):
            self.video_label.focus_set()
            if not self._send_pointer(event, force=True):
                return
            self.client.emit("remote_input", {"session_id": self.client.session_id, "kind": "mouse_down" if down else "mouse_up", "button": button})

    def _key_name(self, event: Any) -> str | None:
        key = str(getattr(event, "keysym", "")).lower()
        mapping = {"return": "enter", "escape": "esc", "prior": "pageup", "next": "pagedown", "control_l": "ctrl", "control_r": "ctrl", "alt_l": "alt", "alt_r": "alt", "shift_l": "shift", "shift_r": "shift", "meta_l": "win", "meta_r": "win"}
        key = mapping.get(key, key)
        return key if re.fullmatch(r"[a-z0-9_+\-]{1,24}", key) else None

    def _key_down(self, event: Any) -> str | None:
        key = self._key_name(event)
        if key and self.client.permissions.get("control"):
            self.client.emit("remote_input", {"session_id": self.client.session_id, "kind": "key_down", "key": key})
        return "break"

    def _key_up(self, event: Any) -> str | None:
        key = self._key_name(event)
        if key and self.client.permissions.get("control"):
            self.client.emit("remote_input", {"session_id": self.client.session_id, "kind": "key_up", "key": key})
        return "break"

    def _toggle_fullscreen(self, _: Any = None) -> None:
        self.attributes("-fullscreen", not self.attributes("-fullscreen"))

    def _exit_fullscreen(self, _: Any) -> None:
        if self.attributes("-fullscreen"):
            self.attributes("-fullscreen", False)

    def _set_quality(self, value: str) -> None:
        self.capture_quality = value

    def _set_monitor(self, value: str) -> None:
        self.monitor_index = int(value.rsplit(" ", 1)[1])

    def choose_file(self) -> None:
        if not self.client.session_id:
            self.log("Start an approved session before transferring files.")
            return
        paths = filedialog.askopenfilenames()
        for path in paths:
            try:
                self.client.send_file(Path(path))
            except OSError as exc:
                self.log(f"Could not read the selected file: {exc}")

    def cancel_transfer(self) -> None:
        for transfer_id in list(self.pending_transfers):
            self.client.emit("file_cancel", {"session_id": self.client.session_id, "transfer_id": transfer_id, "reason": "Cancelled locally"})
            self.pending_transfers.pop(transfer_id, None)
        for transfer_id, transfer in list(self.client.incoming_files.items()):
            try:
                transfer["file"].close()
                transfer["temp"].unlink(missing_ok=True)
            except OSError as exc:
                self.log(f"Could not remove partial transfer: {exc}")
            self.client.incoming_files.pop(transfer_id, None)
            self.client.emit("file_cancel", {"session_id": self.client.session_id, "transfer_id": transfer_id, "reason": "Cancelled locally"})
        self.transfer_name.configure(text="Transfer cancelled")
        self.transfer_bar.set(0)

    def choose_receive_folder(self) -> None:
        folder = filedialog.askdirectory(initialdir=self.settings["receive_folder"])
        if folder:
            self.settings["receive_folder"] = folder
            try:
                save_settings(self.settings)
            except OSError as exc:
                self.log(f"Could not save receive folder: {exc}")
                return
            self.log(f"Receive folder set to {folder}")

    def save_screenshot(self) -> None:
        if not self.frame_bytes:
            self.log("No remote screen frame is available yet.")
            return
        destination = filedialog.asksaveasfilename(
            defaultextension=".jpg",
            filetypes=[("JPEG image", "*.jpg"), ("PNG image", "*.png")],
            initialfile="zerox-screenshot.jpg",
        )
        if not destination:
            return
        try:
            image = Image.open(io.BytesIO(self.frame_bytes))
            image.save(destination)
            self.log(f"Screenshot saved to {destination}")
        except (OSError, ValueError) as exc:
            self.log(f"Could not save screenshot: {exc}")

    def confirm_file_offer(self, data: dict[str, Any]) -> None:
        name = Path(str(data.get("name", "file"))).name
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .") or "received-file"
        try:
            size = int(data["size"])
            digest = str(data["sha256"])
            transfer_id = str(data["transfer_id"])
            if (
                size < 0
                or size > MAX_FILE_SIZE
                or Path(name).suffix.lower() in BLOCKED_FILE_EXTENSIONS
                or not re.fullmatch(r"[a-fA-F0-9]{64}", digest)
            ):
                raise ValueError("File metadata is invalid or exceeds the size limit.")
        except (KeyError, ValueError, TypeError) as exc:
            self.client.emit("file_response", {"session_id": self.client.session_id, "transfer_id": str(data.get("transfer_id", "")), "accepted": False, "reason": str(exc)})
            self.log(f"Rejected file offer: {exc}")
            return
        accepted = messagebox.askyesno(APP_NAME, f"Receive this file?\n\n{name}\n{size:,} bytes\n\nIt will not be opened automatically.")
        if not accepted:
            self.client.emit("file_response", {"session_id": self.client.session_id, "transfer_id": transfer_id, "accepted": False, "reason": "Recipient declined"})
            return
        folder = Path(self.settings["receive_folder"])
        folder.mkdir(parents=True, exist_ok=True)
        destination_value = filedialog.asksaveasfilename(initialdir=str(folder), initialfile=name, title="Save received file")
        if not destination_value:
            self.client.emit("file_response", {"session_id": self.client.session_id, "transfer_id": transfer_id, "accepted": False, "reason": "No destination selected"})
            return
        try:
            self.client.accept_file(data, Path(destination_value))
            self.log(f"Receiving {name}…")
        except (OSError, KeyError, ValueError) as exc:
            self.client.emit("file_response", {"session_id": self.client.session_id, "transfer_id": transfer_id, "accepted": False, "reason": str(exc)})
            self.log(f"Could not start receiving file: {exc}")

    def file_response(self, transfer_id: str, accepted: bool, reason: str) -> None:
        if accepted:
            self.client.start_file_send(transfer_id)
        else:
            self.pending_transfers.pop(transfer_id, None)
            self.log(f"File transfer declined: {reason or 'peer declined'}")

    def update_transfer(self, name: str, done: int, total: int) -> None:
        now = time.monotonic()
        previous_name, previous_done, previous_time = getattr(
            self, "_transfer_speed_sample", ("", 0, now)
        )
        if name != previous_name or done < previous_done:
            rate = 0.0
        else:
            elapsed = now - previous_time
            rate = (done - previous_done) / elapsed if elapsed > 0 else 0.0
        self._transfer_speed_sample = (name, done, now)
        self.transfer_name.configure(text=name)
        self.transfer_bar.set(done / total if total else 1)
        self.transfer_size.configure(text=f"{done:,} / {total:,} bytes")
        self.transfer_speed.configure(text=f"Speed: {rate / (1024 * 1024):.2f} MB/s")

    def send_chat(self) -> None:
        text = self.chat_entry.get().strip()
        if not text:
            return
        if not self.client.session_id:
            self.log("Chat requires an active session.")
            return
        self.client.emit("chat_message", {"session_id": self.client.session_id, "text": text[:2000]})
        self.append_chat("You", text[:2000])
        self.chat_entry.delete(0, "end")

    def append_chat(self, sender: str, text: str) -> None:
        self.chat_log.insert("end", f"{datetime.now().strftime('%H:%M:%S')}  {sender}: {text}\n")
        self.chat_log.see("end")

    def share_clipboard(self) -> None:
        if not self.client.session_id or not self.client.permissions.get("clipboard"):
            self.log("Clipboard sharing is not enabled for this session.")
            return
        try:
            text = self.clipboard_get()
        except TclError as exc:
            self.log(f"Clipboard is unavailable: {exc}")
            return
        self.client.emit("clipboard_text", {"session_id": self.client.session_id, "text": text[:10000]})

    def receive_clipboard(self, text: str) -> None:
        if self.client.permissions.get("clipboard") and messagebox.askyesno(APP_NAME, "The peer shared clipboard text. Copy it to your clipboard?"):
            self.clipboard_clear()
            self.clipboard_append(text)
            self.log("Peer clipboard text copied with your approval.")

    def save_server_settings(self) -> None:
        try:
            address = clean_server_url(self.server_entry.get())
            self.settings["server_url"] = address
            save_settings(self.settings)
        except (ValueError, OSError) as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        threading.Thread(target=self.client.connect, args=(address,), daemon=True).start()

    def show_devices(self, devices: list[dict[str, Any]]) -> None:
        self.device_list.delete("1.0", "end")
        self.device_list.insert("end", f"This device: {self.settings['device_id']}\n\n")
        for item in devices:
            self.device_list.insert("end", f"● {item.get('device_id', 'unknown')}  · online\n")

    def show_latency(self, milliseconds: int | None) -> None:
        self.latency_label.configure(
            text=f"Signaling RTT: {milliseconds} ms" if milliseconds is not None else "Signaling RTT: unavailable"
        )

    def _record_history(self, event: str, peer: str) -> None:
        history = self.settings.setdefault("history", [])
        history.insert(0, {"time": datetime.now().isoformat(timespec="seconds"), "event": event, "peer": peer})
        del history[100:]
        try:
            save_settings(self.settings)
            self._render_history()
        except OSError as exc:
            self.log(f"Could not save session history: {exc}")

    def _render_history(self) -> None:
        if not hasattr(self, "history_box"):
            return
        self.history_box.delete("1.0", "end")
        for row in self.settings.get("history", []):
            self.history_box.insert("end", f"{row.get('time', '')}  ·  {row.get('event', '')}  ·  {row.get('peer', '')}\n")

    def log(self, text: str) -> None:
        if hasattr(self, "home_status"):
            current = self.home_status.cget("text")
            if "ACTIVE SESSION" not in current and "No active session" in current and "code" not in text.lower():
                self.home_status.configure(text=text[:130])
        if hasattr(self, "chat_log"):
            self.chat_log.insert("end", f"{datetime.now().strftime('%H:%M:%S')}  System: {text}\n")
            self.chat_log.see("end")

    def close_app(self) -> None:
        if self.client.session_id and not messagebox.askyesno(APP_NAME, "End the active remote session and close ZEROX REMOTE?"):
            return
        self.closing = True
        self.end_session()
        self.client.disconnect()
        self.destroy()


if __name__ == "__main__":
    if platform.system() != "Windows":
        print("ZEROX REMOTE is designed for Windows 10/11.")
    ZeroXRemote().mainloop()
