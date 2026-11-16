# StreapRous — Stream-based HTTP Server & Hybrid P2P Chat (CO3093/CO3094)

A pure Python standard-library HTTP server framework (`StreapRous`), reverse proxy (`start_proxy.py`), HTTP authentication/cookie session layer (RFC 2617 / 7235 / 6265), raw TCP socket transport (`streaprous_socket`), and encrypted hybrid Client-Server/P2P chat & file-transfer application.

---

## 1. Project Structure

| Path | Purpose |
| :--- | :--- |
| `start_tracker.py` | Entry point for the centralized P2P Tracker server (`apps/tracker_app.py`). |
| `start_peer.py` | Entry point for each Hybrid P2P Peer node (`apps/peer_app.py`). |
| `start_proxy.py` | Entry point for the Reverse Proxy & Round-Robin load balancer (`daemon/proxy.py`). |
| `start_backend.py` | Entry point for the standalone HTTP Backend server (`daemon/backend.py`). |
| `start_sampleapp.py` | Entry point for the minimal RESTful sample app (`apps/sampleapp.py`). |
| `config/proxy.conf` | Virtual-host routing, `proxy_pass`, `proxy_set_header`, and `dist_policy` rules. |
| `daemon/` | Core HTTP server (`backend.py`, `httpadapter.py`, `request.py`, `response.py`, `proxy.py`, `streaprous.py`, `crypto_utils.py`). |
| `streaprous_socket/` | Raw socket TCP 3-way handshake, MSS segmentation, and packet dispatcher. |
| `www/` & `static/` | Vanilla HTML/CSS/JS frontend (`login.html`, `index.html`, `styles.css`, `chat.js`). |

---

## 2. Step 1 — Prerequisites & Installing Dependencies

### Mode A: Standard Socket Mode (Windows, Localhost, or Non-Root Linux/macOS)
1. Install **Python 3.8+** (verified on Python 3.12 on Windows and Python 3.14 on Ubuntu 26.04 WSL2).
2. **No third-party Python packages are required.** All HTTP, Tracker, Peer, Proxy, Cookie Auth, Encryption (`hashlib`/`hmac`), and File Transfer modules run strictly on the Python standard library.
3. Verify Python is available from the project root:
   ```bash
   python --version        # Windows
   python3 --version       # Linux / WSL2 / macOS
   ```

### Mode B: Raw Socket Mode (Linux / WSL2 Ubuntu / macOS with `sudo`)
Raw socket mode (`AF_INET`, `SOCK_RAW`, `IPPROTO_TCP`) requires Unix root privileges, `iptables` (Linux) or `pfctl` (macOS) to block kernel `RST` packets, and `netifaces` for interface IP lookup.

1. On **Ubuntu / Debian / WSL2**, install `python3`, `iptables`, and `python3-netifaces`:
   ```bash
   sudo apt update
   sudo apt install -y python3 iptables python3-netifaces
   ```
   *(If `python3-netifaces` is unavailable on your distro, install via pip: `pip install netifaces`.)*
2. Verify `iptables` is installed:
   ```bash
   iptables --version
   ```
3. Identify your non-loopback network interface and IP address (for example `eth0`):
   ```bash
   ip addr show eth0
   ```

---

## 3. Step 2 — Running the Servers

### Scenario A: Hybrid P2P Chat + Cookie Auth + Encrypted File Transfer (Recommended)

Open **3 separate terminals** in the project root directory. *(Use `python3` instead of `python` on Linux/WSL2/macOS.)*

1. **Terminal 1 — Start the Tracker Server (port `8000`):**
   ```bash
   python start_tracker.py --server-ip 127.0.0.1 --server-port 8000
   ```
2. **Terminal 2 — Start Peer Node 1 (`alice` — Web UI `8081`, P2P TCP `9001`):**
   ```bash
   python start_peer.py --web-ip 127.0.0.1 --web-port 8081 --p2p-ip 127.0.0.1 --p2p-port 9001 --tracker-url http://127.0.0.1:8000
   ```
3. **Terminal 3 — Start Peer Node 2 (`bob` — Web UI `8082`, P2P TCP `9002`):**
   ```bash
   python start_peer.py --web-ip 127.0.0.1 --web-port 8082 --p2p-ip 127.0.0.1 --p2p-port 9002 --tracker-url http://127.0.0.1:8000
   ```
   *(To add a 3rd peer, run another `start_peer.py` instance with unused `--web-port` and `--p2p-port`, e.g. `8083` and `9003`.)*

---

### Scenario B: Reverse Proxy (`8080`) + Backend (`9000`)

#### Option B1 — Standard Socket Mode (Localhost / Windows)
1. **Terminal 1 — Start the Backend Server (port `9000`):**
   ```bash
   python start_backend.py --server-ip 127.0.0.1 --server-port 9000
   ```
2. **Terminal 2 — Start the Reverse Proxy (port `8080`, reads `config/proxy.conf`):**
   ```bash
   python start_proxy.py --server-ip 127.0.0.1 --server-port 8080
   ```
3. *(Optional)* To test `round-robin` load balancing for `app2.local` in `config/proxy.conf`, start two backends on ports `9001` and `9002`:
   ```bash
   python start_backend.py --server-ip 127.0.0.1 --server-port 9001
   python start_backend.py --server-ip 127.0.0.1 --server-port 9002
   ```

#### Option B2 — Raw Socket Mode (Linux / WSL2 with `sudo`)
1. Replace `<EXTERNAL_IP>` with your non-loopback IP from `ip addr show eth0` (e.g. `172.30.103.216`):
   ```bash
   sudo python3 start_backend.py --server-ip <EXTERNAL_IP> --server-port 9000 --interface eth0
   ```
2. `start_backend.py` automatically runs `iptables -A OUTPUT -p tcp --sport 9000 --tcp-flags RST RST -j DROP` so the Linux kernel does not abort the userspace 3-way handshake, and `run_conn_send` segments payloads larger than `1400` bytes (MSS) to avoid `Errno 90: Message too long`.
3. When finished testing Raw Socket mode, remove the temporary `iptables` rule:
   ```bash
   sudo iptables -D OUTPUT -p tcp --sport 9000 --tcp-flags RST RST -j DROP
   ```

---

## 4. Step 3 — Connecting Clients & Using the System

### A. Connecting Browser Clients to the Hybrid P2P Chat

1. Open **two separate Incognito / Private browser windows** (recommended so cookies and `sessionStorage` stay isolated per peer and HTTP caching is bypassed):
   - **Window 1 (Peer 1):** `http://127.0.0.1:8081`
   - **Window 2 (Peer 2):** `http://127.0.0.1:8082`
2. Unauthenticated requests to `/` or `/index.html` automatically receive `302 Found` (`Location: /login.html`), and unauthenticated API calls return `401 Unauthorized`.
3. Log in on each window using one of the built-in accounts from `USERS_DB` (`apps/tracker_app.py`):

   | Username | Password |
   | :--- | :--- |
   | `alice` | `123` |
   | `bob` | `123` |
   | `charlie` | `123` |
   | `tan` | `123` |
   | `admin` | `admin` |

   - Example: Log in as `alice` / `123` in Window 1 (port `9001`) and `bob` / `123` in Window 2 (port `9002`).
   - Upon success, the server issues `Set-Cookie: session_id=...; Path=/` and `Set-Cookie: username=...; Path=/`, registers the peer on the Tracker (`POST /submit-info/`), and redirects to `/index.html`.
4. **Discover & Connect to Peers:**
   - The left sidebar polls `GET /get-list/` every 3 seconds to display online peers.
   - Click **Connect** next to `bob` (`POST /connect-peer/`) to verify direct P2P TCP reachability.
5. **Send Encrypted P2P Messages:**
   - Select **# Global Broadcast** to send to all active peers (`POST /broadcast-peer/`), or click `@ bob` for direct 1-on-1 chat (`POST /send-peer/`).
   - Outgoing JSON payloads are encrypted with SHA-256 CTR + HMAC-SHA256 (`daemon/crypto_utils.py`). Check the peer terminals for:
     - `[P2P Security] Encrypted outgoing payload: ...`
     - `[P2P Security] Decrypted incoming payload verified via HMAC-SHA256`
6. **Send & Download Verified Files:**
   - Select a file using the **Choose File** input (`#fileInput`) beside the message box and click **Gửi** (`POST /send-file/`).
   - Watch the **File Transfer Progress Bar** advance from `0%` to `100% • Verified SHA-256`.
   - On the receiving peer, click **Tải xuống** on the attachment card (`GET /download-file/?file_id=...`) to download the SHA-256 verified file.
7. **Logout:**
   - Click **Thoát** (`POST /logout/`) to invalidate the server-side session and revoke browser cookies (`Max-Age=0`).

### B. Connecting CLI Clients (`curl`) to Proxy / Backend

- **Verify Reverse Proxy forwarding (`config/proxy.conf`):**
  ```bash
  curl -i http://127.0.0.1:8080/
  ```
- **Verify `round-robin` routing & `proxy_set_header` for `app2.local`:**
  ```bash
  curl -i -H "Host: app2.local" http://127.0.0.1:8080/
  ```
- **Verify Raw Socket server from another host / Windows client (replace `<EXTERNAL_IP>`):**
  ```bash
  curl -i http://<EXTERNAL_IP>:9000/
  ```
- **Verify Cookie Auth guard on Peer API (`401` without cookie vs `200` with cookie):**
  ```bash
  curl -i http://127.0.0.1:8081/get-list/
  curl -i -c cookies.txt -X POST http://127.0.0.1:8081/login/ -H "Content-Type: application/json" -d "{\"username\":\"alice\",\"password\":\"123\"}"
  curl -i -b cookies.txt http://127.0.0.1:8081/get-list/
  ```

---

## License

See [LICENSE](LICENSE) — educational use only for CO3093/CO3094.
