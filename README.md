# ZEROX REMOTE

**REMOTE DESKTOP CONTROL** — consent-based remote support for Windows 10/11. The repository contains a single-file Windows client (`zerox_remote.py`) and a small Flask-SocketIO signaling/relay service (`server/app.py`).

## What works in this build

- Random per-install device ID, live device list, temporary single-use session code, and server-side expiry.
- A visible approval prompt on the receiving device before session start. The owner selects screen, input, file, and clipboard permissions separately.
- Compressed JPEG screen relay, remote mouse/keyboard input when approved, chat, and peer-approved file transfers up to 100 MB each with SHA-256 verification. Executables, scripts, shortcuts, and drivers are blocked.
- Reconnect attempts, status and signaling-server RTT display, local session history, adjustable image quality/FPS, multi-monitor selection, screenshot, fullscreen preview, and configurable signaling URL.
- No unattended access, hidden operation, keylogging, UAC bypass, or automatic opening of received files.

The UI is dark and responsive, but this is an early functional implementation rather than a production-certified AnyDesk replacement. Clipboard transfer is permission-gated; the recipient must also confirm before shared text is copied.

## Architecture and important limitations

Render is used as a signaling server **and currently relays the screen/input/chat/file traffic**. The included relay makes an end-to-end demo possible, but is not a scalable media transport. Free Render services can sleep, have limited CPU/bandwidth, and do not provide durable in-memory state. Device registrations, codes, and sessions disappear on restart/sleep. Sustained screen sharing may be slow or disconnect; do not use this free-tier configuration for production or sensitive high-volume file transfer.

This version does **not** implement WebRTC/P2P. A production design should use WebRTC with an appropriate STUN service and TURN fallback; TURN requires a reachable relay and may incur costs. STUN alone does not work through every NAT/firewall. For a reliable production service, use a durable signaling deployment, per-device authentication/rotation, monitoring, stronger account/device pairing, and a reviewed media transport. The server relays media in this initial version, so it is not end-to-end encrypted beyond TLS transport; only use it with data appropriate for a TLS-terminated relay. Do not expose it as a production service without an independent security review. The latency indicator measures round-trip time to the signaling server, not a direct peer path.

For a no-cost development experiment, a future WebRTC direct-P2P transport could use a public STUN server and avoid relaying screen media through Render. This is not included here and will fail on some NAT/firewall combinations; reliable TURN capacity is not guaranteed to be free. Do not treat public STUN/TURN services as a production availability or privacy guarantee.

## Requirements

- Windows 10/11 for the client and remote input/screen capture.
- Python 3.11 recommended for both client and Render.
- A network-accessible signaling server. The client default is local development (`http://127.0.0.1:5000`); set the deployed HTTPS URL in **Settings**.

## Install and run the client

From the project root in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python .\zerox_remote.py
```

The client saves its device ID, server URL, receive-folder preference, and short local history under `%APPDATA%\ZEROX-REMOTE\settings.json`. No passwords or session secrets are stored there.

### Run the signaling server locally

In another PowerShell window:

```powershell
py -3.11 -m venv .venv-server
.\.venv-server\Scripts\Activate.ps1
pip install -r .\server\requirements.txt
$env:APP_ENV = "development"
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
python .\server\app.py
```

Use `http://127.0.0.1:5000` in the client for a local test. For a second computer, a local development server is not internet-accessible unless you deliberately configure a secure public endpoint. Do not expose plain HTTP over the internet.

## Deploy on Render Free

1. Push the repository to your GitHub account.
2. In Render, choose **New → Blueprint** and select the repository. `render.yaml` defines a Python web service rooted at `server/`.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn --worker-class eventlet -w 1 app:app`
5. Ensure `APP_ENV=production` and a unique `SECRET_KEY` are set in Render Environment. The blueprint generates a `SECRET_KEY`; do not commit secrets.
6. Wait for `/health` to pass. Copy the service's `https://....onrender.com` URL into **Settings** in each client.

Render terminates TLS for its HTTPS endpoint. The service uses one Eventlet worker because in-memory Socket.IO state cannot be shared across workers. Increasing worker count breaks this design. A free service can sleep, and all in-memory sessions are lost when it restarts. WebSocket connections may be interrupted by sleep/redeploy.

## Use

1. Install and start the same client on both Windows devices. Configure both to use the same server URL.
2. On the receiving device, click **Create access code** and share the temporary code with the person you intend to support. Codes expire after five minutes and are single-use.
3. On the connecting device, enter the code under **Remote Connection** and send a request. A device ID is an identifier only; it is not an invitation or a substitute for the temporary session code.
4. The receiving device shows an approval dialog. Review the device ID and select only the permissions needed. Denying the prompt ends the request.
5. The host can disconnect at any time. File recipients confirm each transfer and choose a destination. Received files are never executed by the app.

The viewer must focus the screen preview for keyboard control. Use **Fullscreen** to expand the view; press Escape to exit. PyAutoGUI's corner failsafe remains enabled; move the local host mouse to the top-left corner to interrupt remote control. A reconnect restores signaling only; if a connection drops, the session ends and the host must generate a new code and approve again.

## Build a Windows executable

With the client dependencies installed on Windows:

```powershell
pyinstaller --onefile --windowed --name ZEROX-REMOTE zerox_remote.py
```

The result is `dist\ZEROX-REMOTE.exe`. Build the executable on Windows for Windows; test it on a clean Windows 10/11 machine before distribution. The client is not code-signed by this command, so Windows SmartScreen may show a warning.

## Security notes

- Always use HTTPS/WSS for public deployments. The server rejects non-local HTTP URLs in the client.
- The temporary session code is a bearer invitation; share it only with the intended peer. Local approval remains required.
- Screen, input, file, and clipboard relays are authorized per session by the server, not just hidden in the UI.
- This initial server keeps state in memory and has no user account/password system, durable device ownership, or end-to-end encryption against the relay server.
- Keep the server private to intended users. Add authenticated device enrollment, invite revocation, audit/abuse controls, deployment monitoring, and an independent security review before real-world use.
- Internet connectivity, two physical Windows devices, Render deployment credentials, and external services were not available during this implementation. The two-device and Render integration tests are therefore not claimed as passed.

## Project layout

```text
ZEROX-REMOTE/
├── zerox_remote.py
├── requirements.txt
├── README.md
├── .gitignore
├── render.yaml
└── server/
    ├── app.py
    └── requirements.txt
```
