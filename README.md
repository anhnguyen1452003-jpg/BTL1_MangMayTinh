# StreapRous — Stream-based HTTP Server & Hybrid P2P Chat (Linux Guide)

A pure Python standard-library HTTP server framework (`StreapRous`), reverse proxy (`start_proxy.py`), HTTP authentication/cookie session layer (RFC 2617 / 7235 / 6265), raw TCP socket transport (`streaprous_socket`), and encrypted hybrid Client-Server/P2P chat & file-transfer application designed for **Linux** (Ubuntu / Debian / WSL2).

---

## 1. Project Structure

| Path | Purpose |
| :--- | :--- |
| `start_tracker.py` | Entry point for the centralized P2P Tracker server (`apps/tracker_app.py`). |
| `start_peer.py` | Entry point for each Hybrid P2P Peer node (`apps/peer_app.py`). |
| `start_proxy.py` | Entry point for the Reverse Proxy & Round-Robin load balancer (`daemon/proxy.py`). |
| `start_backend.py` | Entry point for the HTTP Backend server (`daemon/backend.py`). |
| `start_sampleapp.py` | Entry point for the minimal RESTful sample app (`apps/sampleapp.py`). |
| `config/proxy.conf` | Virtual-host routing, `proxy_pass`, `proxy_set_header`, and `dist_policy` rules. |
| `daemon/` | Core HTTP server (`backend.py`, `httpadapter.py`, `request.py`, `response.py`, `proxy.py`, `streaprous.py`, `crypto_utils.py`). |
| `streaprous_socket/` | Raw socket TCP 3-way handshake, MSS segmentation, and packet dispatcher. |
| `www/` & `static/` | Vanilla HTML/CSS/JS frontend (`login.html`, `index.html`, `styles.css`, `chat.js`). |

---

## 2. Step 1 — Prerequisites & Installing Dependencies on Linux

### Mode A: Standard Socket Mode (`127.0.0.1` / Non-Root)
1. Ensure **Python 3.8+** is installed (tested on Ubuntu 26.04 with Python 3.14):
   ```bash
   python3 --version
   ```
2. **No third-party Python packages are required.** All HTTP, Tracker, Peer, Proxy, Cookie Auth, Encryption (`hashlib`/`hmac`), and File Transfer modules run strictly on the Python standard library.

### Mode B: Raw Socket Mode (`sudo` + External/LAN IP)
Raw socket mode (`AF_INET`, `SOCK_RAW`, `IPPROTO_TCP`) on Linux requires `root` (`sudo`) privileges, `iptables` to drop kernel-generated `RST` packets, and `netifaces` to resolve the network interface IP.

1. Install `python3`, `iptables`, and `python3-netifaces` (Ubuntu / Debian / WSL2):
   ```bash
   sudo apt update
   sudo apt install -y python3 iptables python3-netifaces
   ```
   *(If `python3-netifaces` is not packaged on your distribution, install it with `pip3 install netifaces`.)*
2. Verify `iptables` and `netifaces` are available:
   ```bash
   iptables --version
   python3 -c "import netifaces; print(netifaces.interfaces())"
   ```
3. Identify your active network interface and non-loopback IPv4 address (for example `eth0`, `enp0s8`, or `wlan0`):
   ```bash
   ip -4 addr show
   ```

---

## 3. Step 2 — Running the Servers

Open separate terminal tabs/windows in the project root directory (for example, `cd ~/BTL1_MangMayTinh` or `cd /mnt/d/MangMayTinh/BTL1_MangMayTinh`).

### Scenario A: Hybrid P2P Chat + Cookie Auth + Encrypted File Transfer

Open **3 separate terminals**:

1. **Terminal 1 — Start the Tracker Server (port `8000`):**
   ```bash
   python3 start_tracker.py --server-ip 127.0.0.1 --server-port 8000
   ```
2. **Terminal 2 — Start Peer Node 1 (`alice` — Web UI `8081`, P2P TCP `9001`):**
   ```bash
   python3 start_peer.py --web-ip 127.0.0.1 --web-port 8081 --p2p-ip 127.0.0.1 --p2p-port 9001 --tracker-url http://127.0.0.1:8000
   ```
3. **Terminal 3 — Start Peer Node 2 (`bob` — Web UI `8082`, P2P TCP `9002`):**
   ```bash
   python3 start_peer.py --web-ip 127.0.0.1 --web-port 8082 --p2p-ip 127.0.0.1 --p2p-port 9002 --tracker-url http://127.0.0.1:8000
   ```
   *(To run across multiple Linux machines on the same LAN, replace `127.0.0.1` with each host's LAN IPv4 address from `ip -4 addr show`.)*

---

### Scenario B: Reverse Proxy (`8080`) + Backend (`9000`)

#### Option B1 — Standard Socket Mode (Localhost, No `sudo` Required)
1. **Terminal 1 — Start the Backend Server (port `9000`):**
   ```bash
   python3 start_backend.py --server-ip 127.0.0.1 --server-port 9000
   ```
2. **Terminal 2 — Start the Reverse Proxy (port `8080`, reads `config/proxy.conf`):**
   ```bash
   python3 start_proxy.py --server-ip 127.0.0.1 --server-port 8080
   ```
3. *(Optional)* To test `round-robin` load balancing for `app2.local` in `config/proxy.conf`, also start backends on ports `9001` and `9002`:
   ```bash
   python3 start_backend.py --server-ip 127.0.0.1 --server-port 9001
   python3 start_backend.py --server-ip 127.0.0.1 --server-port 9002
   ```

#### Option B2 — Raw Socket Mode (External/LAN IP with `sudo` + `iptables`)
1. Replace `<LINUX_IP>` and `<IFACE>` with your interface IP and name from `ip -4 addr show` (e.g., `172.30.103.216` and `eth0`):
   ```bash
   sudo python3 start_backend.py --server-ip <LINUX_IP> --server-port 9000 --interface <IFACE>
   ```
2. What happens automatically:
   - `start_backend.py` inserts an `iptables` rule to prevent the Linux kernel from sending `RST` packets during the userspace 3-way handshake:
     ```bash
     sudo iptables -A OUTPUT -p tcp --sport 9000 --tcp-flags RST RST -j DROP
     ```
   - `daemon/backend.py` runs `run_backend()` using `streaprous_socket` (`SOCK_RAW`).
   - `run_conn_send()` segments payloads larger than `1400` bytes (MSS) so large HTML/CSS/JS files transmit without `Errno 90: Message too long`.
3. After stopping the raw socket backend (`Ctrl+C`), inspect and remove the temporary `iptables` rule:
   ```bash
   sudo iptables -L OUTPUT -n --line-numbers
   sudo iptables -D OUTPUT -p tcp --sport 9000 --tcp-flags RST RST -j DROP
   ```

---

## 4. Step 3 — Connecting Clients & Using the System

### A. Browser Clients (Hybrid P2P Chat)

1. Open **two separate Incognito / Private browser windows** (recommended to isolate session cookies and `sessionStorage` per peer and prevent HTTP caching):
   - **Window 1 (Peer 1):** `http://127.0.0.1:8081`
   - **Window 2 (Peer 2):** `http://127.0.0.1:8082`
2. Unauthenticated requests to `/` or `/index.html` return `302 Found` (`Location: /login.html`), and unauthenticated API calls return `401 Unauthorized`.
3. Sign in on each window using any account from `USERS_DB` (`apps/tracker_app.py`):

   | Username | Password |
   | :--- | :--- |
   | `alice` | `123` |
   | `bob` | `123` |
   | `charlie` | `123` |
   | `tan` | `123` |
   | `admin` | `admin` |

   - Example: Log in as `alice` / `123` in Window 1 and `bob` / `123` in Window 2.
   - Upon login, the server issues `Set-Cookie: session_id=...; Path=/` and `Set-Cookie: username=...; Path=/`, registers the peer with the Tracker (`POST /submit-info/`), and redirects to `/index.html`.
4. **Discover & Connect:**
   - The sidebar polls `GET /get-list/` every 3 seconds. Click **Connect** next to `bob` (`POST /connect-peer/`) to verify direct P2P TCP reachability.
5. **Encrypted P2P Messaging:**
   - Use **# Global Broadcast** (`POST /broadcast-peer/`) or click `@ bob` (`POST /send-peer/`).
   - All P2P payloads are encrypted with SHA-256 CTR + HMAC-SHA256 (`daemon/crypto_utils.py`). Peer terminals print:
     - `[P2P Security] Encrypted outgoing payload: ...`
     - `[P2P Security] Decrypted incoming payload verified via HMAC-SHA256`
6. **Reliable Chunked File Transfer:**
   - Choose a file with `#fileInput` next to the message box and click **Gửi** (`POST /send-file/`).
   - Monitor the **File Transfer Progress Bar** (`0% -> 100% • Verified SHA-256`).
   - On the receiving peer, click **Tải xuống** (`GET /download-file/?file_id=...`) to download the SHA-256 verified file (stored under `downloads/<username>/`).
7. **Logout:**
   - Click **Thoát** (`POST /logout/`) to clear the server session and expire browser cookies (`Max-Age=0`).

### B. CLI Verification (`curl`)

- **Test Reverse Proxy (`8080` -> `9000`):**
  ```bash
  curl -i http://127.0.0.1:8080/
  ```
- **Test `round-robin` & `proxy_set_header` for `app2.local`:**
  ```bash
  curl -i -H "Host: app2.local" http://127.0.0.1:8080/
  ```
- **Test Raw Socket Backend (run from another host or Windows client against `<LINUX_IP>`):**
  ```bash
  curl -i http://<LINUX_IP>:9000/
  ```
- **Test Cookie Session Guard on Peer API (`401` without cookie vs `200` with cookie):**
  ```bash
  curl -i http://127.0.0.1:8081/get-list/
  curl -i -c /tmp/cookies.txt -X POST http://127.0.0.1:8081/login/ \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"123"}'
  curl -i -b /tmp/cookies.txt http://127.0.0.1:8081/get-list/
  ```

---
   - **Tìm chunk file**
   ```bash
   Tìm chunk file
   (tcp.port == 9001 or tcp.port == 9002) and tcp.len > 1000
   ```

   - **Chỉ bắt đúng các sự kiện chính**
   ```bash
   tcp.port == 8000 and http and (http.request.uri contains "/login/" or http.request.uri contains "/global-message/" or http.request.uri contains "/global-file/")
   ```

   - **Lọc cổng Web UI (8081 / 8082) bỏ qua polling của trình duyệt**
   ```bash
   (tcp.port == 8081 or tcp.port == 8082) and http and (http.request.uri contains "/login/" or http.request.uri contains "/connect-peer/" or http.request.uri contains "/send-peer/" or http.request.uri contains "/broadcast-peer/" or http.request.uri contains "/send-file/" or http.request.uri contains "/download-file/" or http.request.uri contains "/logout/")
   ```

## License

See [LICENSE](LICENSE) — educational use only for CO3093/CO3094.
