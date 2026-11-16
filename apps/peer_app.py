#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course.
#
# StreapRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#

"""
apps.peer_app
~~~~~~~~~~~~~

Hybrid P2P Peer Node application combining:
1. A TCP P2P listener thread and a 20-second tracker heartbeat thread.
2. A StreapRous local Web API for serving UI assets and handling peer actions.
"""

import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from daemon import StreapRous
from daemon.crypto_utils import decrypt_payload, encrypt_payload

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOWNLOADS_ROOT = os.path.join(BASE_DIR, "downloads")
SOCKET_TIMEOUT_SECONDS = 3.0
FILE_SOCKET_TIMEOUT_SECONDS = 15.0
HEARTBEAT_INTERVAL_SECONDS = 20.0
FILE_CHUNK_SIZE = 16384
MAX_P2P_PAYLOAD_BYTES = 1048576

app = StreapRous()

# Runtime peer configuration (populated by create_peer_app)
_config = {
    "web_ip": "0.0.0.0",
    "web_port": 8081,
    "p2p_ip": "0.0.0.0",
    "p2p_port": 9001,
    "advertise_ip": "127.0.0.1",
    "tracker_url": "http://127.0.0.1:8000",
}

# Thread-safe state and append-only (immutable) message store
_state_lock = threading.Lock()
_current_user = None
_peer_sessions = {}  # {session_id: username}
_has_unread = False
_connected_peers = {}  # {"ip:port": {"ip": str, "port": int, "username": str}}
_known_peers_cache = {}  # {username: {"ip": str, "port": int}}
_messages_store = {
    "global": [],   # Append-only list of global messages
    "private": {},  # {peer_key: append-only list of 1-1 messages}
}
_incoming_files = {}     # {file_id: {"meta": dict, "chunks": {idx: bytes}}}
_transfer_progress = {}  # {file_id: {"file_id": str, "filename": str, ...}}
_downloaded_files = {}   # {file_id: {"filename": str, "filepath": str, ...}}

_stop_event = threading.Event()
_listener_stop_event = threading.Event()
_listener_lock = threading.Lock()
_listener_sock = None
_listener_thread = None
_heartbeat_thread = None


def _utc_timestamp():
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _json_response(payload):
    """Serialize a Python dict into UTF-8 encoded JSON bytes."""
    return json.dumps(payload).encode("utf-8")


def _error_response(message):
    """Return a standardized JSON error payload."""
    return _json_response({"status": "error", "message": message})


def _parse_json_body(body):
    """
    Safely parse a request body into a JSON object (dict).

    Raises ``ValueError`` if the body is empty, invalid UTF-8, invalid JSON,
    or not a JSON object.
    """
    if isinstance(body, dict):
        return body

    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Request body is not valid UTF-8") from exc

    if not isinstance(body, str) or not body.strip():
        raise ValueError("Request body is empty")

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("Invalid JSON payload") from exc

    if not isinstance(data, dict):
        raise ValueError("JSON payload must be an object")

    return data


def _validate_port(port):
    """Validate and convert a TCP port value to an integer in 1..65535."""
    if isinstance(port, bool):
        raise ValueError("Invalid 'port'")
    try:
        port_int = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid 'port'") from exc

    if port_int < 1 or port_int > 65535:
        raise ValueError("'port' must be between 1 and 65535")
    return port_int


def _detect_local_ip(tracker_url):
    """Determine the local IP address used to reach the tracker."""
    try:
        parsed = urllib.parse.urlparse(tracker_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8000
        if host in ("127.0.0.1", "localhost", "::1"):
            return "127.0.0.1"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((host, port))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _extract_cookie_dict(headers):
    """Parse HTTP Cookie header from a request headers dict."""
    if not isinstance(headers, dict):
        return {}
    cookie_header = ""
    for key, val in headers.items():
        if str(key).lower() == "cookie":
            cookie_header = val
            break
    cookies = {}
    if cookie_header:
        for pair in str(cookie_header).split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies


def _get_session_username(headers):
    """Return the authenticated username for the request cookie, or None."""
    cookies = _extract_cookie_dict(headers)
    session_id = cookies.get("session_id", "").strip()
    if not session_id:
        return None
    with _state_lock:
        return _peer_sessions.get(session_id)


def _is_session_valid(headers):
    """Return True if the request carries a valid active session_id cookie."""
    return _get_session_username(headers) is not None


def _unauthorized_response():
    """Build a 401 Unauthorized JSON response for unauthenticated chat APIs."""
    return (
        401,
        {"Content-Type": "application/json"},
        _json_response({
            "status": "unauthorized",
            "message": "Please login first",
        }),
    )


def _extract_session_id_from_set_cookie(set_cookie_headers):
    """Extract session_id value from Set-Cookie header strings returned by Tracker."""
    for header_val in set_cookie_headers:
        first_part = str(header_val).split(";", 1)[0].strip()
        if "=" in first_part:
            k, v = first_part.split("=", 1)
            if k.strip() == "session_id" and v.strip():
                return v.strip()
    return None


def _tracker_request_with_headers(path, method="GET", payload=None):
    """Send an HTTP JSON request to the Tracker and return (data, set_cookie_list)."""
    base_url = _config["tracker_url"].rstrip("/")
    url = f"{base_url}{path}"
    headers = {"Accept": "application/json"}
    data = None

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(
            req,
            timeout=SOCKET_TIMEOUT_SECONDS,
        ) as resp:
            raw = resp.read().decode("utf-8")
            set_cookies = resp.headers.get_all("Set-Cookie") or []
            parsed = json.loads(raw) if raw else {"status": "success"}
            return parsed, set_cookies
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        set_cookies = exc.headers.get_all("Set-Cookie") or [] if exc.headers else []
        try:
            return json.loads(err_body), set_cookies
        except json.JSONDecodeError:
            return {
                "status": "error",
                "message": f"Tracker HTTP {exc.code}: {exc.reason}",
            }, set_cookies
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "status": "error",
            "message": f"Tracker unreachable: {exc}",
        }, []
    except json.JSONDecodeError:
        return {
            "status": "error",
            "message": "Tracker returned invalid JSON",
        }, []


def _tracker_request(path, method="GET", payload=None):
    """Send an HTTP JSON request to the Tracker Server using urllib."""
    data, _ = _tracker_request_with_headers(path, method=method, payload=payload)
    return data


def _extract_peers_map(tracker_data):
    """Normalize tracker /get-list/ response into {username: {ip, port}}."""
    peers_raw = tracker_data.get("peers", {})
    normalized = {}

    if isinstance(peers_raw, dict):
        for username, info in peers_raw.items():
            if isinstance(info, dict) and "ip" in info and "port" in info:
                try:
                    normalized[str(username)] = {
                        "ip": str(info["ip"]),
                        "port": _validate_port(info["port"]),
                        "last_seen": info.get("last_seen"),
                    }
                except ValueError:
                    continue
    elif isinstance(peers_raw, list):
        for item in peers_raw:
            if not isinstance(item, dict):
                continue
            username = item.get("username")
            if username and "ip" in item and "port" in item:
                try:
                    normalized[str(username)] = {
                        "ip": str(item["ip"]),
                        "port": _validate_port(item["port"]),
                        "last_seen": item.get("last_seen"),
                    }
                except ValueError:
                    continue

    return normalized


def _resolve_peer_label(target_ip, target_port, fallback_name=None):
    """Resolve a human-readable peer key from cached or connected peers."""
    if isinstance(fallback_name, str) and fallback_name.strip():
        return fallback_name.strip()

    with _state_lock:
        for username, info in _known_peers_cache.items():
            if info.get("ip") == target_ip and info.get("port") == target_port:
                return username
        addr_key = f"{target_ip}:{target_port}"
        conn_info = _connected_peers.get(addr_key)
        if conn_info and conn_info.get("username"):
            return conn_info["username"]

    return f"{target_ip}:{target_port}"


def _append_message(channel, sender, content, timestamp, peer_key=None,
                    mark_unread=False, extra=None):
    """
    Append an immutable message record into ``_messages_store``.

    Existing entries are never modified or deleted.
    """
    global _has_unread

    entry = {
        "type": "text",
        "sender": str(sender),
        "channel": channel,
        "content": str(content),
        "timestamp": str(timestamp),
    }
    if isinstance(extra, dict):
        entry.update(extra)

    with _state_lock:
        if channel == "private":
            bucket_key = peer_key or str(sender)
            bucket = _messages_store["private"].setdefault(bucket_key, [])
            bucket.append(entry)
        else:
            _messages_store["global"].append(entry)

        if mark_unread:
            _has_unread = True


def _safe_filename(raw_name):
    """Sanitize a filename so it cannot escape the downloads directory."""
    base = os.path.basename(str(raw_name or "").strip())
    cleaned = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", base)
    return cleaned or "unnamed_file.bin"


def _save_file_for_user(owner_name, file_id, filename, raw_bytes, sha256_hex):
    """Persist verified file bytes under ``downloads/<owner_name>/``."""
    safe_owner = re.sub(r"[^A-Za-z0-9_.-]", "_", str(owner_name or "peer"))
    safe_name = _safe_filename(filename)
    user_dir = os.path.join(DOWNLOADS_ROOT, safe_owner)
    os.makedirs(user_dir, exist_ok=True)
    disk_name = f"{file_id[:8]}_{safe_name}"
    filepath = os.path.join(user_dir, disk_name)
    with open(filepath, "wb") as file_obj:
        file_obj.write(raw_bytes)

    record = {
        "file_id": file_id,
        "filename": safe_name,
        "filepath": filepath,
        "file_size": len(raw_bytes),
        "sha256": sha256_hex,
        "verified": True,
    }
    with _state_lock:
        _downloaded_files[file_id] = record
    return record


def _update_transfer_progress(file_id, filename, direction, percent, status,
                              verified=False, file_size=0):
    """Update thread-safe transfer progress snapshot for UI polling."""
    with _state_lock:
        _transfer_progress[file_id] = {
            "file_id": file_id,
            "filename": filename,
            "direction": direction,
            "percent": max(0, min(100, int(percent))),
            "status": status,
            "verified": bool(verified),
            "file_size": int(file_size),
            "updated_at": time.time(),
        }


def _parse_query_params(headers):
    """Extract query parameters from ``x-query-string`` or ``x-request-path``."""
    if not isinstance(headers, dict):
        return {}
    query = headers.get("x-query-string", "")
    if not query:
        req_path = headers.get("x-request-path", "")
        if "?" in req_path:
            query = req_path.split("?", 1)[1]
    return urllib.parse.parse_qs(query, keep_blank_values=False)


def _send_p2p_frames(target_ip, target_port, packets, on_progress=None):
    """
    Encrypt and stream one or more JSON packets sequentially over a single
    P2P TCP connection.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(FILE_SOCKET_TIMEOUT_SECONDS)
    try:
        sock.connect((target_ip, target_port))
        total = len(packets)
        for idx, packet in enumerate(packets):
            raw_json = json.dumps(packet).encode("utf-8")
            encrypted = encrypt_payload(raw_json)
            if idx == 0:
                preview = encrypted.decode("ascii", errors="replace").strip()[:30]
                print(f"[P2P Security] Encrypted outgoing payload: {preview}...")
            sock.sendall(encrypted)
            if on_progress is not None:
                on_progress(idx + 1, total)
        return True, None
    except (socket.timeout, OSError) as exc:
        return False, str(exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _send_p2p_packet(target_ip, target_port, packet):
    """
    Encrypt and send a single JSON packet directly to a peer over TCP.

    Returns ``(True, None)`` on success or ``(False, error_message)`` on error.
    """
    return _send_p2p_frames(target_ip, target_port, [packet])


def _handle_incoming_file_packet(packet, addr):
    """Process ``file_meta``, ``file_chunk``, and ``file_end`` P2P packets."""
    pkt_type = packet.get("type")
    file_id = str(packet.get("file_id") or "").strip()
    if not file_id:
        return

    if pkt_type == "file_meta":
        filename = _safe_filename(packet.get("filename", "file.bin"))
        file_size = int(packet.get("file_size") or 0)
        total_chunks = int(packet.get("total_chunks") or 0)
        sha256_hex = str(packet.get("sha256") or "").strip().lower()
        sender = packet.get("sender") or f"{addr[0]}:{addr[1]}"
        channel = packet.get("channel", "private")
        if channel not in ("global", "private"):
            channel = "private"

        with _state_lock:
            _incoming_files[file_id] = {
                "meta": {
                    "file_id": file_id,
                    "filename": filename,
                    "file_size": file_size,
                    "total_chunks": total_chunks,
                    "sha256": sha256_hex,
                    "sender": sender,
                    "channel": channel,
                    "timestamp": packet.get("timestamp") or _utc_timestamp(),
                },
                "chunks": {},
            }
        _update_transfer_progress(
            file_id, filename, "receive", 0, "receiving", False, file_size
        )

    elif pkt_type == "file_chunk":
        chunk_index = packet.get("chunk_index")
        data_b64 = packet.get("data_b64", "")
        try:
            chunk_idx_int = int(chunk_index)
            chunk_bytes = base64.b64decode(data_b64.encode("ascii"), validate=True)
        except (TypeError, ValueError, binascii.Error):
            print(f"[PeerFile] Invalid file chunk for {file_id}")
            return

        with _state_lock:
            entry = _incoming_files.get(file_id)
            if not entry:
                return
            entry["chunks"][chunk_idx_int] = chunk_bytes
            total_chunks = max(1, entry["meta"]["total_chunks"])
            received = len(entry["chunks"])
            filename = entry["meta"]["filename"]
            file_size = entry["meta"]["file_size"]

        percent = min(99, int((received * 100) / total_chunks))
        _update_transfer_progress(
            file_id, filename, "receive", percent, "receiving", False, file_size
        )

    elif pkt_type == "file_end":
        with _state_lock:
            entry = _incoming_files.pop(file_id, None)
            owner = _current_user or f"peer_{_config['p2p_port']}"
        if not entry:
            return

        meta = entry["meta"]
        chunks = entry["chunks"]
        total_chunks = meta["total_chunks"]
        filename = meta["filename"]
        expected_sha = meta["sha256"]

        if len(chunks) != total_chunks or any(i not in chunks for i in range(total_chunks)):
            _update_transfer_progress(
                file_id, filename, "receive", 0, "error", False, meta["file_size"]
            )
            print(f"[PeerFile] Missing chunks for {filename} ({len(chunks)}/{total_chunks})")
            return

        assembled = b"".join(chunks[i] for i in range(total_chunks))
        actual_sha = hashlib.sha256(assembled).hexdigest()
        if expected_sha and actual_sha != expected_sha:
            _update_transfer_progress(
                file_id, filename, "receive", 0, "checksum_mismatch", False, len(assembled)
            )
            print(f"[PeerFile] SHA-256 mismatch for {filename}: expected={expected_sha} actual={actual_sha}")
            return

        _save_file_for_user(owner, file_id, filename, assembled, actual_sha)
        _update_transfer_progress(
            file_id, filename, "receive", 100, "completed", True, len(assembled)
        )
        print(f"[PeerFile] Verified SHA-256 and saved {filename} ({len(assembled)} bytes)")

        sender = meta["sender"]
        channel = meta["channel"]
        _append_message(
            channel=channel,
            sender=sender,
            content=f"[File] {filename} ({len(assembled)} bytes)",
            timestamp=meta["timestamp"],
            peer_key=str(sender),
            mark_unread=True,
            extra={
                "type": "file",
                "file_id": file_id,
                "filename": filename,
                "file_size": len(assembled),
                "sha256": actual_sha,
                "download_url": f"/download-file/?file_id={file_id}",
                "verified": True,
            },
        )


def _process_decrypted_packet(packet, addr):
    """Route a decrypted P2P JSON packet to file transfer or chat message store."""
    if not isinstance(packet, dict):
        return

    pkt_type = packet.get("type", "chat")
    if pkt_type in ("file_meta", "file_chunk", "file_end"):
        _handle_incoming_file_packet(packet, addr)
        return

    sender = packet.get("sender") or f"{addr[0]}:{addr[1]}"
    channel = packet.get("channel", "global")
    if channel not in ("global", "private"):
        channel = "global"
    content = packet.get("content", "")
    timestamp = packet.get("timestamp") or _utc_timestamp()

    _append_message(
        channel=channel,
        sender=sender,
        content=content,
        timestamp=timestamp,
        peer_key=str(sender),
        mark_unread=True,
    )


def _handle_p2p_client(conn, addr):
    """Receive, verify, decrypt, and dispatch P2P frames from a connected peer."""
    conn.settimeout(FILE_SOCKET_TIMEOUT_SECONDS)
    byte_buffer = b""

    try:
        while True:
            try:
                data = conn.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            byte_buffer += data
            if len(byte_buffer) > MAX_P2P_PAYLOAD_BYTES and b"\n" not in byte_buffer:
                print(f"[PeerP2P] Oversized unframed line from {addr}")
                return

            while b"\n" in byte_buffer:
                raw_line, byte_buffer = byte_buffer.split(b"\n", 1)
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    decrypted_bytes = decrypt_payload(line)
                    print("[P2P Security] Decrypted incoming payload verified via HMAC-SHA256")
                except ValueError as exc:
                    print(f"[P2P Security] Rejected invalid/tampered payload from {addr}: {exc}")
                    continue

                try:
                    packet = json.loads(decrypted_bytes.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    print(f"[PeerP2P] Ignored invalid JSON from {addr}")
                    continue
                _process_decrypted_packet(packet, addr)

        # Process trailing line if sender closed socket without trailing newline
        trailing = byte_buffer.strip()
        if trailing:
            try:
                decrypted_bytes = decrypt_payload(trailing)
                print("[P2P Security] Decrypted incoming payload verified via HMAC-SHA256")
                packet = json.loads(decrypted_bytes.decode("utf-8"))
                _process_decrypted_packet(packet, addr)
            except ValueError as exc:
                print(f"[P2P Security] Rejected invalid/tampered payload from {addr}: {exc}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                print(f"[PeerP2P] Ignored invalid JSON from {addr}")
    except OSError as exc:
        print(f"[PeerP2P] Connection error from {addr}: {exc}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _p2p_listener_loop(stop_event=None, ready_event=None, error_holder=None):
    """Run the P2P TCP listener server in a background daemon thread."""
    global _listener_sock
    if stop_event is None:
        stop_event = _listener_stop_event

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.settimeout(1.0)

    try:
        server_sock.bind((_config["p2p_ip"], _config["p2p_port"]))
        server_sock.listen(50)
        _listener_sock = server_sock
        if ready_event is not None:
            ready_event.set()
        print(
            f"[PeerP2P] Listening on "
            f"{_config['p2p_ip']}:{_config['p2p_port']}"
        )

        while not _stop_event.is_set() and not stop_event.is_set():
            try:
                conn, addr = server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if _stop_event.is_set() or stop_event.is_set():
                    break
                continue

            worker = threading.Thread(
                target=_handle_p2p_client,
                args=(conn, addr),
                daemon=True,
            )
            worker.start()
    except OSError as exc:
        if error_holder is not None:
            error_holder.append(exc)
        if ready_event is not None:
            ready_event.set()
        print(f"[PeerP2P] Listener stopped due to socket error: {exc}")
    finally:
        if _listener_sock is server_sock:
            _listener_sock = None
        try:
            server_sock.close()
        except OSError:
            pass


def _restart_p2p_listener(new_port):
    """Stop the current P2P listener and bind a fresh one on ``new_port``."""
    global _listener_stop_event, _listener_sock, _listener_thread

    with _listener_lock:
        if _config["p2p_port"] == new_port and _listener_thread and _listener_thread.is_alive():
            return

        _listener_stop_event.set()
        old_sock = _listener_sock
        if old_sock is not None:
            try:
                old_sock.close()
            except OSError:
                pass

        if _listener_thread is not None and _listener_thread.is_alive():
            _listener_thread.join(timeout=2.0)

        _config["p2p_port"] = new_port
        _listener_stop_event = threading.Event()
        ready_event = threading.Event()
        error_holder = []
        _listener_thread = threading.Thread(
            target=_p2p_listener_loop,
            args=(_listener_stop_event, ready_event, error_holder),
            daemon=True,
        )
        _listener_thread.start()
        ready_event.wait(timeout=3.0)
        if error_holder:
            raise ValueError(f"Cannot bind P2P port {new_port}: {error_holder[0]}")


def _heartbeat_loop():
    """Periodically send POST /submit-info/ heartbeat every 20 seconds."""
    while not _stop_event.wait(HEARTBEAT_INTERVAL_SECONDS):
        with _state_lock:
            username = _current_user

        if not username:
            continue

        payload = {
            "username": username,
            "ip": _config["advertise_ip"],
            "port": _config["p2p_port"],
        }
        result = _tracker_request("/submit-info/", method="POST",
                                  payload=payload)
        if result.get("status") != "success":
            print(f"[PeerHeartbeat] Failed to refresh info: {result}")


def _start_background_services():
    """Start P2P TCP listener and tracker heartbeat daemon threads once."""
    global _listener_thread, _heartbeat_thread

    if _listener_thread is None or not _listener_thread.is_alive():
        _listener_thread = threading.Thread(
            target=_p2p_listener_loop,
            daemon=True,
        )
        _listener_thread.start()

    if _heartbeat_thread is None or not _heartbeat_thread.is_alive():
        _heartbeat_thread = threading.Thread(
            target=_heartbeat_loop,
            daemon=True,
        )
        _heartbeat_thread.start()


def _read_static_asset(relative_paths, fallback_content=b""):
    """Load the first matching static asset under BASE_DIR safely."""
    for rel_path in relative_paths:
        full_path = os.path.join(BASE_DIR, rel_path)
        if os.path.isfile(full_path):
            try:
                with open(full_path, "rb") as file_obj:
                    return file_obj.read()
            except OSError:
                continue
    return fallback_content


# ---------------------------------------------------------------------------
# Static Web UI Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def serve_index(headers="guest", body="anonymous"):
    """Serve the main peer chat HTML page, or redirect if unauthenticated."""
    if not _is_session_valid(headers):
        return (
            302,
            {
                "Location": "/login.html",
                "Content-Type": "text/html; charset=utf-8",
            },
            b"",
        )
    return _read_static_asset(
        ["www/index.html", "static/index.html"],
        fallback_content=b"<h1>StreapRous P2P Peer</h1>",
    )


@app.route("/login.html", methods=["GET"])
def serve_login_page(headers="guest", body="anonymous"):
    """Serve the standalone peer login HTML page."""
    return _read_static_asset(
        ["www/login.html", "static/login.html"],
        fallback_content=b"<h1>Login</h1>",
    )


@app.route("/peer-info/", methods=["GET"])
def get_peer_info(headers="guest", body="anonymous"):
    """Return local peer node configuration and current login session."""
    username = _get_session_username(headers)
    return _json_response({
        "status": "success",
        "authenticated": bool(username),
        "username": username,
        "p2p_ip": _config["advertise_ip"],
        "p2p_port": _config["p2p_port"],
    })


@app.route("/styles.css", methods=["GET"])
@app.route("/static/css/styles.css", methods=["GET"])
def serve_styles(headers="guest", body="anonymous"):
    """Serve the stylesheet for the peer chat UI."""
    return _read_static_asset(
        ["static/css/styles.css", "www/styles.css"],
        fallback_content=b"",
    )


@app.route("/chat.js", methods=["GET"])
@app.route("/static/js/chat.js", methods=["GET"])
def serve_chat_js(headers="guest", body="anonymous"):
    """Serve the client-side JavaScript for the peer chat UI."""
    return _read_static_asset(
        ["static/js/chat.js", "www/chat.js"],
        fallback_content=b"// chat.js not found\n",
    )


# ---------------------------------------------------------------------------
# Local Peer RESTful API Routes
# ---------------------------------------------------------------------------

@app.route("/login/", methods=["POST"])
def login(headers="guest", body="anonymous"):
    """Authenticate with Tracker, update P2P port if provided, and issue cookies."""
    global _current_user

    try:
        data = _parse_json_body(body)
        username = data.get("username")
        password = data.get("password")

        if not isinstance(username, str) or not username.strip():
            return _error_response("Missing or invalid 'username'")
        if not isinstance(password, str) or not password:
            return _error_response("Missing or invalid 'password'")

        username = username.strip()
        login_res, tracker_set_cookies = _tracker_request_with_headers(
            "/login/",
            method="POST",
            payload={"username": username, "password": password},
        )
        if login_res.get("status") != "success":
            return (
                401,
                {"Content-Type": "application/json"},
                _json_response(login_res),
            )

        advertise_ip = data.get("ip")
        if isinstance(advertise_ip, str) and advertise_ip.strip():
            _config["advertise_ip"] = advertise_ip.strip()

        requested_port = data.get("p2p_port")
        if requested_port is not None and str(requested_port).strip() != "":
            new_port = _validate_port(requested_port)
            if new_port != _config["p2p_port"]:
                _restart_p2p_listener(new_port)

        submit_payload = {
            "username": username,
            "ip": _config["advertise_ip"],
            "port": _config["p2p_port"],
        }
        submit_res = _tracker_request(
            "/submit-info/",
            method="POST",
            payload=submit_payload,
        )
        if submit_res.get("status") != "success":
            return _error_response(
                f"Login succeeded but submit-info failed: "
                f"{submit_res.get('message', 'unknown error')}"
            )

        session_id = (
            _extract_session_id_from_set_cookie(tracker_set_cookies)
            or login_res.get("session_id")
            or uuid.uuid4().hex
        )
        with _state_lock:
            _current_user = username
            _peer_sessions[session_id] = username

        set_cookies = list(tracker_set_cookies)
        if not any("session_id=" in c for c in set_cookies):
            set_cookies.append(f"session_id={session_id}; Path=/")
        set_cookies.append(f"username={username}; Path=/")

        return (
            200,
            {
                "Set-Cookie": set_cookies,
                "Content-Type": "application/json",
            },
            _json_response({
                "status": "success",
                "message": "Logged in and peer info registered",
                "username": username,
                "session_id": session_id,
                "p2p_ip": _config["advertise_ip"],
                "p2p_port": _config["p2p_port"],
                "tracker_response": submit_res,
            }),
        )
    except ValueError as exc:
        return _error_response(str(exc))
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/logout/", methods=["POST", "GET"])
def logout(headers="guest", body="anonymous"):
    """Invalidate the current session cookie and clear browser session cookies."""
    global _current_user

    cookies = _extract_cookie_dict(headers)
    session_id = cookies.get("session_id", "").strip()

    with _state_lock:
        removed_user = _peer_sessions.pop(session_id, None) if session_id else None
        if removed_user and _current_user == removed_user:
            _current_user = None
        elif not _peer_sessions:
            _current_user = None

    return (
        200,
        {
            "Set-Cookie": [
                "session_id=; Path=/; Max-Age=0",
                "username=; Path=/; Max-Age=0",
            ],
            "Content-Type": "application/json",
        },
        _json_response({
            "status": "success",
            "message": "Logged out successfully",
        }),
    )


@app.route("/get-list/", methods=["GET"])
def get_list(headers="guest", body="anonymous"):
    """Fetch active peers from Tracker and cache address mappings."""
    if not _is_session_valid(headers):
        return _unauthorized_response()

    try:
        tracker_res = _tracker_request("/get-list/", method="GET")
        if tracker_res.get("status") != "success":
            return _json_response(tracker_res)

        peers_map = _extract_peers_map(tracker_res)
        with _state_lock:
            _known_peers_cache.clear()
            _known_peers_cache.update(peers_map)

        return _json_response(tracker_res)
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/connect-peer/", methods=["POST"])
def connect_peer(headers="guest", body="anonymous"):
    """Verify TCP reachability to a peer and save it in connected_peers."""
    if not _is_session_valid(headers):
        return _unauthorized_response()

    try:
        data = _parse_json_body(body)
        target_ip = data.get("target_ip")
        if not isinstance(target_ip, str) or not target_ip.strip():
            return _error_response("Missing or invalid 'target_ip'")
        target_ip = target_ip.strip()
        target_port = _validate_port(data.get("target_port"))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT_SECONDS)
        try:
            sock.connect((target_ip, target_port))
        except (socket.timeout, OSError) as exc:
            return _error_response(
                f"Cannot connect to peer {target_ip}:{target_port}: {exc}"
            )
        finally:
            try:
                sock.close()
            except OSError:
                pass

        peer_username = _resolve_peer_label(
            target_ip,
            target_port,
            data.get("username"),
        )
        addr_key = f"{target_ip}:{target_port}"
        peer_record = {
            "ip": target_ip,
            "port": target_port,
            "username": peer_username,
            "connected_at": _utc_timestamp(),
        }

        with _state_lock:
            _connected_peers[addr_key] = peer_record

        return _json_response({
            "status": "success",
            "message": f"Connected to {addr_key}",
            "peer": peer_record,
        })
    except ValueError as exc:
        return _error_response(str(exc))
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/send-peer/", methods=["POST"])
def send_peer(headers="guest", body="anonymous"):
    """Send a unicast P2P message over TCP and record it locally."""
    session_user = _get_session_username(headers)
    if session_user is None:
        return _unauthorized_response()

    try:
        data = _parse_json_body(body)
        target_ip = data.get("target_ip")
        if not isinstance(target_ip, str) or not target_ip.strip():
            return _error_response("Missing or invalid 'target_ip'")
        target_ip = target_ip.strip()
        target_port = _validate_port(data.get("target_port"))

        content = data.get("content", data.get("message"))
        if not isinstance(content, str) or not content.strip():
            return _error_response("Missing or invalid 'content'")

        with _state_lock:
            sender = session_user or _current_user or data.get("sender") or "anonymous"

        timestamp = _utc_timestamp()
        packet = {
            "sender": sender,
            "channel": "private",
            "content": content,
            "timestamp": timestamp,
        }

        ok, err = _send_p2p_packet(target_ip, target_port, packet)
        if not ok:
            return _error_response(
                f"Failed to send message to {target_ip}:{target_port}: {err}"
            )

        peer_key = _resolve_peer_label(
            target_ip,
            target_port,
            data.get("target_username"),
        )
        _append_message(
            channel="private",
            sender=sender,
            content=content,
            timestamp=timestamp,
            peer_key=peer_key,
            mark_unread=False,
        )

        return _json_response({
            "status": "success",
            "message": "Unicast message sent",
            "target": f"{target_ip}:{target_port}",
            "packet": packet,
        })
    except ValueError as exc:
        return _error_response(str(exc))
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/broadcast-peer/", methods=["POST"])
def broadcast_peer(headers="guest", body="anonymous"):
    """Broadcast a P2P message concurrently to all known/connected peers."""
    session_user = _get_session_username(headers)
    if session_user is None:
        return _unauthorized_response()

    try:
        data = _parse_json_body(body)
        content = data.get("content", data.get("message"))
        if not isinstance(content, str) or not content.strip():
            return _error_response("Missing or invalid 'content'")

        with _state_lock:
            sender = session_user or _current_user or data.get("sender") or "anonymous"

        # Refresh online list from tracker (best-effort)
        tracker_res = _tracker_request("/get-list/", method="GET")
        if tracker_res.get("status") == "success":
            peers_map = _extract_peers_map(tracker_res)
            with _state_lock:
                _known_peers_cache.clear()
                _known_peers_cache.update(peers_map)

        # Deduplicate target endpoints from online cache and connected_peers
        targets = {}
        with _state_lock:
            for uname, info in _known_peers_cache.items():
                if uname == _current_user:
                    continue
                if (info["ip"] == _config["advertise_ip"]
                        and info["port"] == _config["p2p_port"]):
                    continue
                targets[f"{info['ip']}:{info['port']}"] = (
                    info["ip"],
                    info["port"],
                )
            for addr_key, info in _connected_peers.items():
                if (info["ip"] == _config["advertise_ip"]
                        and info["port"] == _config["p2p_port"]):
                    continue
                targets[addr_key] = (info["ip"], info["port"])

        timestamp = _utc_timestamp()
        packet = {
            "sender": sender,
            "channel": "global",
            "content": content,
            "timestamp": timestamp,
        }

        _append_message(
            channel="global",
            sender=sender,
            content=content,
            timestamp=timestamp,
            mark_unread=False,
        )

        # Send to all target peers in parallel so one dead peer never blocks
        results_lock = threading.Lock()
        sent = []
        failed = []

        def _worker(addr_key, ip, port):
            ok, err = _send_p2p_packet(ip, port, packet)
            with results_lock:
                if ok:
                    sent.append(addr_key)
                else:
                    failed.append({"target": addr_key, "error": err})

        threads = []
        for addr_key, (ip, port) in targets.items():
            thread = threading.Thread(
                target=_worker,
                args=(addr_key, ip, port),
                daemon=True,
            )
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join(timeout=SOCKET_TIMEOUT_SECONDS + 0.5)

        return _json_response({
            "status": "success",
            "message": "Broadcast completed",
            "sent_count": len(sent),
            "failed_count": len(failed),
            "sent": sent,
            "failed": failed,
            "packet": packet,
        })
    except ValueError as exc:
        return _error_response(str(exc))
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/messages/", methods=["GET"])
def get_messages(headers="guest", body="anonymous"):
    """Return all global/private messages and unread status for UI polling."""
    global _has_unread
    if not _is_session_valid(headers):
        return _unauthorized_response()

    try:
        with _state_lock:
            unread_flag = _has_unread
            _has_unread = False
            global_msgs = [dict(msg) for msg in _messages_store["global"]]
            private_msgs = {
                peer: [dict(msg) for msg in msgs]
                for peer, msgs in _messages_store["private"].items()
            }

        return _json_response({
            "status": "success",
            "has_unread": unread_flag,
            "channels": {
                "global": global_msgs,
                "private": private_msgs,
            },
            "global": global_msgs,
            "private": private_msgs,
        })
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/send-file/", methods=["POST"])
def send_file(headers="guest", body="anonymous"):
    """Chunk, checksum, encrypt, and send a file over P2P TCP sockets."""
    session_user = _get_session_username(headers)
    if session_user is None:
        return _unauthorized_response()

    try:
        data = _parse_json_body(body)
        target = data.get("target", "global")
        if not isinstance(target, str) or not target.strip():
            target = "global"
        target = target.strip()

        raw_filename = data.get("filename")
        if not isinstance(raw_filename, str) or not raw_filename.strip():
            return _error_response("Missing or invalid 'filename'")
        filename = _safe_filename(raw_filename)

        raw_b64 = data.get("file_data_b64")
        if not isinstance(raw_b64, str) or raw_b64 is None:
            return _error_response("Missing or invalid 'file_data_b64'")
        if raw_b64.startswith("data:") and "," in raw_b64:
            raw_b64 = raw_b64.split(",", 1)[1]

        try:
            file_bytes = base64.b64decode(raw_b64.strip().encode("ascii"), validate=True)
        except (ValueError, binascii.Error) as exc:
            return _error_response(f"Invalid base64 file payload: {exc}")

        with _state_lock:
            sender = session_user or _current_user or "anonymous"

        file_id = uuid.uuid4().hex
        file_size = len(file_bytes)
        sha256_hex = hashlib.sha256(file_bytes).hexdigest()
        total_chunks = max(1, (file_size + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE) if file_size > 0 else 0
        timestamp = _utc_timestamp()
        channel = "global" if target == "global" else "private"

        _save_file_for_user(sender, file_id, filename, file_bytes, sha256_hex)
        _update_transfer_progress(
            file_id, filename, "send", 0, "sending", True, file_size
        )

        # Build protocol frames: file_meta -> file_chunk(s) -> file_end
        frames = [{
            "type": "file_meta",
            "file_id": file_id,
            "filename": filename,
            "file_size": file_size,
            "total_chunks": total_chunks,
            "sha256": sha256_hex,
            "sender": sender,
            "channel": channel,
            "timestamp": timestamp,
        }]
        for idx in range(total_chunks):
            chunk = file_bytes[idx * FILE_CHUNK_SIZE:(idx + 1) * FILE_CHUNK_SIZE]
            frames.append({
                "type": "file_chunk",
                "file_id": file_id,
                "chunk_index": idx,
                "data_b64": base64.b64encode(chunk).decode("ascii"),
            })
        frames.append({
            "type": "file_end",
            "file_id": file_id,
        })

        # Refresh online peer list from Tracker (best-effort)
        tracker_res = _tracker_request("/get-list/", method="GET")
        if tracker_res.get("status") == "success":
            peers_map = _extract_peers_map(tracker_res)
            with _state_lock:
                _known_peers_cache.clear()
                _known_peers_cache.update(peers_map)

        targets = {}
        if channel == "global":
            with _state_lock:
                for uname, info in _known_peers_cache.items():
                    if uname == sender:
                        continue
                    if (info["ip"] == _config["advertise_ip"]
                            and info["port"] == _config["p2p_port"]):
                        continue
                    targets[f"{info['ip']}:{info['port']}"] = (info["ip"], info["port"])
                for addr_key, info in _connected_peers.items():
                    if (info["ip"] == _config["advertise_ip"]
                            and info["port"] == _config["p2p_port"]):
                        continue
                    targets[addr_key] = (info["ip"], info["port"])
        else:
            target_ip = data.get("target_ip")
            target_port = data.get("target_port")
            if target_ip and target_port is not None:
                port_int = _validate_port(target_port)
                targets[f"{target_ip}:{port_int}"] = (str(target_ip).strip(), port_int)
            else:
                with _state_lock:
                    info = _known_peers_cache.get(target)
                    if info:
                        targets[f"{info['ip']}:{info['port']}"] = (info["ip"], info["port"])
                    else:
                        for addr_key, conn_info in _connected_peers.items():
                            if conn_info.get("username") == target or addr_key == target:
                                targets[addr_key] = (conn_info["ip"], conn_info["port"])
                                break
            if not targets:
                _update_transfer_progress(
                    file_id, filename, "send", 0, "error", False, file_size
                )
                return _error_response(f"Peer '{target}' not found or offline")

        sent = []
        failed = []
        results_lock = threading.Lock()
        total_frames = len(frames)

        def _send_to_peer(addr_key, ip, port):
            def _progress_cb(sent_idx, frame_count):
                pct = int((sent_idx * 100) / max(1, frame_count))
                _update_transfer_progress(
                    file_id, filename, "send", pct, "sending", True, file_size
                )

            ok, err = _send_p2p_frames(ip, port, frames, on_progress=_progress_cb)
            with results_lock:
                if ok:
                    sent.append(addr_key)
                else:
                    failed.append({"target": addr_key, "error": err})

        threads = []
        for addr_key, (ip, port) in targets.items():
            t = threading.Thread(
                target=_send_to_peer,
                args=(addr_key, ip, port),
                daemon=True,
            )
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=FILE_SOCKET_TIMEOUT_SECONDS + 1.0)

        if channel == "private" and not sent:
            err_msg = failed[0]["error"] if failed else "Failed to send file"
            _update_transfer_progress(
                file_id, filename, "send", 0, "error", False, file_size
            )
            return _error_response(err_msg)

        _update_transfer_progress(
            file_id, filename, "send", 100, "completed", True, file_size
        )

        peer_key = None if channel == "global" else target
        _append_message(
            channel=channel,
            sender=sender,
            content=f"[File] {filename} ({file_size} bytes)",
            timestamp=timestamp,
            peer_key=peer_key,
            mark_unread=False,
            extra={
                "type": "file",
                "file_id": file_id,
                "filename": filename,
                "file_size": file_size,
                "sha256": sha256_hex,
                "download_url": f"/download-file/?file_id={file_id}",
                "verified": True,
            },
        )

        return _json_response({
            "status": "success",
            "message": "File transfer completed",
            "file_id": file_id,
            "filename": filename,
            "file_size": file_size,
            "total_chunks": total_chunks,
            "total_frames": total_frames,
            "sha256": sha256_hex,
            "verified": True,
            "sent_count": len(sent),
            "failed_count": len(failed),
            "sent": sent,
            "failed": failed,
        })
    except ValueError as exc:
        return _error_response(str(exc))
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/transfer-status/", methods=["GET"])
def get_transfer_status(headers="guest", body="anonymous"):
    """Return file transfer progress records for UI polling."""
    if not _is_session_valid(headers):
        return _unauthorized_response()

    params = _parse_query_params(headers)
    file_id = (params.get("file_id") or [""])[0].strip()

    with _state_lock:
        if file_id:
            rec = _transfer_progress.get(file_id)
            return _json_response({
                "status": "success",
                "transfer": dict(rec) if rec else None,
            })
        snapshot = {k: dict(v) for k, v in _transfer_progress.items()}

    return _json_response({
        "status": "success",
        "transfers": snapshot,
    })


@app.route("/download-file/", methods=["GET"])
def download_file(headers="guest", body="anonymous"):
    """Download a verified received/sent file by ``file_id``."""
    if not _is_session_valid(headers):
        return _unauthorized_response()

    params = _parse_query_params(headers)
    file_id = (params.get("file_id") or [""])[0].strip()
    if not file_id:
        return (
            400,
            {"Content-Type": "application/json"},
            _json_response({"status": "error", "message": "Missing file_id"}),
        )

    with _state_lock:
        record = _downloaded_files.get(file_id)

    if not record or not os.path.isfile(record["filepath"]):
        return (
            404,
            {"Content-Type": "application/json"},
            _json_response({"status": "error", "message": "File not found"}),
        )

    try:
        with open(record["filepath"], "rb") as file_obj:
            file_bytes = file_obj.read()
    except OSError as exc:
        return (
            500,
            {"Content-Type": "application/json"},
            _json_response({"status": "error", "message": f"Read error: {exc}"}),
        )

    safe_name = _safe_filename(record["filename"])
    return (
        200,
        {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": f'attachment; filename="{safe_name}"',
        },
        file_bytes,
    )


def create_peer_app(web_port, p2p_port, tracker_url="http://127.0.0.1:8000",
                    web_ip="0.0.0.0", p2p_ip="0.0.0.0"):
    """Configure and launch the Peer Node (P2P threads + StreapRous API)."""
    _config["web_ip"] = web_ip
    _config["web_port"] = int(web_port)
    _config["p2p_ip"] = p2p_ip
    _config["p2p_port"] = int(p2p_port)
    _config["tracker_url"] = tracker_url.rstrip("/")
    _config["advertise_ip"] = _detect_local_ip(_config["tracker_url"])

    _start_background_services()
    app.prepare_address(_config["web_ip"], _config["web_port"])
    app.run()
