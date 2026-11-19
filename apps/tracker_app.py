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
apps.tracker_app
~~~~~~~~~~~~~~~~

Tracker RESTful application for peer discovery and registration built on
the StreapRous framework using only the Python standard library.
"""

import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
import threading
import time
import urllib.parse
import uuid

from daemon import StreapRous

PEER_TIMEOUT_SECONDS = 5.0

app = StreapRous()

# Demo user accounts database
USERS_DB = {
    "alice": "123",
    "bob": "123",
    "charlie": "123",
    "tan": "123",
    "admin": "admin",
}

# Active session store: {session_token: username}
ACTIVE_SESSIONS = {}
_sessions_lock = threading.Lock()

# Thread-safe in-memory store for active peers:
# {username: {"ip": str, "port": int, "last_seen": float}}
_peers_lock = threading.Lock()
_active_peers = {}

# Thread-safe in-memory store for global chat messages & global files
_global_lock = threading.Lock()
_global_messages = []
_global_msg_ids = set()
_global_files = {}  # {file_id: {"file_id": str, "filename": str, ...}}


def _utc_timestamp():
    """Return current UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _json_response(payload):
    """Serialize a dictionary payload to UTF-8 encoded JSON bytes."""
    return json.dumps(payload).encode("utf-8")


def _error_response(message):
    """Build a standardized JSON error response."""
    return _json_response({"status": "error", "message": message})


def _parse_json_body(body):
    """
    Safely parse the incoming request body into a JSON object (dict).

    Supports ``bytes``, ``str``, and ``dict`` inputs and raises ``ValueError``
    when the payload is empty, malformed JSON, or not a JSON object.
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


def _validate_peer_payload(data):
    """
    Validate and normalize peer registration fields from a parsed JSON dict.

    Returns a tuple ``(username, ip, port)`` or raises ``ValueError``.
    """
    username = data.get("username")
    ip = data.get("ip")
    port = data.get("port")

    if not isinstance(username, str) or not username.strip():
        raise ValueError("Missing or invalid 'username'")
    if not isinstance(ip, str) or not ip.strip():
        raise ValueError("Missing or invalid 'ip'")
    if isinstance(port, bool):
        raise ValueError("Missing or invalid 'port'")

    try:
        port_int = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("Missing or invalid 'port'") from exc

    if port_int < 1 or port_int > 65535:
        raise ValueError("'port' must be between 1 and 65535")

    return username.strip(), ip.strip(), port_int


def _prune_expired_peers_locked(now):
    """Remove peers inactive longer than ``PEER_TIMEOUT_SECONDS``."""
    expired = [
        username
        for username, info in _active_peers.items()
        if now - info["last_seen"] > PEER_TIMEOUT_SECONDS
    ]
    for username in expired:
        del _active_peers[username]


@app.route("/login/", methods=["POST"])
def login(headers="guest", body="anonymous"):
    """Authenticate a peer using JSON credentials and issue a session cookie."""
    try:
        data = _parse_json_body(body)
        username = data.get("username")
        password = data.get("password")

        if not isinstance(username, str) or not username.strip():
            return (
                401,
                {"Content-Type": "application/json"},
                _json_response({"status": "error", "message": "Invalid credentials"}),
            )
        if not isinstance(password, str) or not password:
            return (
                401,
                {"Content-Type": "application/json"},
                _json_response({"status": "error", "message": "Invalid credentials"}),
            )

        clean_username = username.strip()
        if USERS_DB.get(clean_username) != password:
            return (
                401,
                {"Content-Type": "application/json"},
                _json_response({"status": "error", "message": "Invalid credentials"}),
            )

        session_token = uuid.uuid4().hex
        with _sessions_lock:
            ACTIVE_SESSIONS[session_token] = clean_username

        return (
            200,
            {
                "Set-Cookie": f"session_id={session_token}; Path=/",
                "Content-Type": "application/json",
            },
            _json_response({
                "status": "success",
                "message": "Login successful",
                "username": clean_username,
                "session_id": session_token,
            }),
        )
    except ValueError as exc:
        return _error_response(str(exc))
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/logout/", methods=["POST"])
def logout(headers="guest", body="anonymous"):
    """Remove an active peer and session immediately when a user logs out."""
    try:
        data = _parse_json_body(body)
        username = data.get("username")
        session_id = data.get("session_id")

        removed_user = None
        if isinstance(session_id, str) and session_id.strip():
            with _sessions_lock:
                removed_user = ACTIVE_SESSIONS.pop(session_id.strip(), None)

        target_user = (
            username.strip()
            if isinstance(username, str) and username.strip()
            else removed_user
        )
        if target_user:
            with _peers_lock:
                _active_peers.pop(target_user, None)
            with _sessions_lock:
                stale_tokens = [
                    tok for tok, uname in ACTIVE_SESSIONS.items()
                    if uname == target_user
                ]
                for tok in stale_tokens:
                    ACTIVE_SESSIONS.pop(tok, None)

        return _json_response({
            "status": "success",
            "message": f"Logged out {target_user or 'guest'}",
            "username": target_user,
        })
    except ValueError as exc:
        return _error_response(str(exc))
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/submit-info/", methods=["POST"])
def submit_info(headers="guest", body="anonymous"):
    """Register a new peer or refresh an existing peer's active info."""
    try:
        data = _parse_json_body(body)
        username, ip, port = _validate_peer_payload(data)
        now = time.time()

        with _peers_lock:
            _prune_expired_peers_locked(now)
            _active_peers[username] = {
                "ip": ip,
                "port": port,
                "last_seen": now,
            }

        return _json_response({
            "status": "success",
            "message": "Peer info updated",
            "peer": {
                "username": username,
                "ip": ip,
                "port": port,
                "last_seen": now,
            },
        })
    except ValueError as exc:
        return _error_response(str(exc))
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/get-list/", methods=["GET"])
def get_list(headers="guest", body="anonymous"):
    """Return all currently online peers after pruning timed-out entries."""
    try:
        now = time.time()
        with _peers_lock:
            _prune_expired_peers_locked(now)
            peers_snapshot = {
                username: {
                    "ip": info["ip"],
                    "port": info["port"],
                    "last_seen": info["last_seen"],
                }
                for username, info in _active_peers.items()
            }

        return _json_response({
            "status": "success",
            "count": len(peers_snapshot),
            "peers": peers_snapshot,
        })
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/add-list/", methods=["POST"])
def add_list(headers="guest", body="anonymous"):
    """Add a peer to the active tracking list."""
    try:
        data = _parse_json_body(body)
        username, ip, port = _validate_peer_payload(data)
        now = time.time()

        with _peers_lock:
            _prune_expired_peers_locked(now)
            existed = username in _active_peers
            _active_peers[username] = {
                "ip": ip,
                "port": port,
                "last_seen": now,
            }

        action = "updated" if existed else "added"
        return _json_response({
            "status": "success",
            "message": f"Peer {action} in tracking list",
            "peer": {
                "username": username,
                "ip": ip,
                "port": port,
                "last_seen": now,
            },
        })
    except ValueError as exc:
        return _error_response(str(exc))
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/global-message/", methods=["POST"])
def post_global_message(headers="guest", body="anonymous"):
    """Store a global chat text message in the Tracker's memory cache."""
    try:
        data = _parse_json_body(body)
        sender = data.get("sender")
        content = data.get("content")
        if not isinstance(sender, str) or not sender.strip():
            return _error_response("Missing or invalid 'sender'")
        if not isinstance(content, str) or not content.strip():
            return _error_response("Missing or invalid 'content'")

        msg_id = str(data.get("msg_id") or uuid.uuid4().hex).strip()
        timestamp = str(data.get("timestamp") or _utc_timestamp())
        entry = {
            "msg_id": msg_id,
            "type": "text",
            "sender": sender.strip(),
            "channel": "global",
            "content": content,
            "timestamp": timestamp,
        }

        with _global_lock:
            if msg_id not in _global_msg_ids:
                _global_msg_ids.add(msg_id)
                _global_messages.append(entry)

        return _json_response({
            "status": "success",
            "message": "Global message stored",
            "message_entry": entry,
        })
    except ValueError as exc:
        return _error_response(str(exc))
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/global-file/", methods=["POST"])
def post_global_file(headers="guest", body="anonymous"):
    """Store a global chat file and its metadata entry in the Tracker cache."""
    try:
        data = _parse_json_body(body)
        sender = data.get("sender")
        filename = data.get("filename")
        raw_b64 = data.get("file_data_b64")
        if not isinstance(sender, str) or not sender.strip():
            return _error_response("Missing or invalid 'sender'")
        if not isinstance(filename, str) or not filename.strip():
            return _error_response("Missing or invalid 'filename'")
        if not isinstance(raw_b64, str):
            return _error_response("Missing or invalid 'file_data_b64'")

        clean_b64 = raw_b64.split(",", 1)[1] if raw_b64.startswith("data:") and "," in raw_b64 else raw_b64
        try:
            raw_bytes = base64.b64decode(clean_b64.strip().encode("ascii"), validate=True)
        except (ValueError, binascii.Error) as exc:
            return _error_response(f"Invalid base64 payload: {exc}")

        actual_sha = hashlib.sha256(raw_bytes).hexdigest()
        expected_sha = str(data.get("sha256") or "").strip().lower()
        if expected_sha and expected_sha != actual_sha:
            return _error_response("Global file SHA-256 checksum mismatch")

        file_id = str(data.get("file_id") or uuid.uuid4().hex).strip()
        msg_id = str(data.get("msg_id") or f"file:{file_id}").strip()
        clean_name = os.path.basename(filename.strip()) or "file.bin"
        timestamp = str(data.get("timestamp") or _utc_timestamp())

        file_record = {
            "file_id": file_id,
            "filename": clean_name,
            "file_size": len(raw_bytes),
            "sha256": actual_sha,
            "sender": sender.strip(),
            "timestamp": timestamp,
            "file_data_b64": base64.b64encode(raw_bytes).decode("ascii"),
        }
        entry = {
            "msg_id": msg_id,
            "type": "file",
            "sender": sender.strip(),
            "channel": "global",
            "content": f"[File] {clean_name} ({len(raw_bytes)} bytes)",
            "file_id": file_id,
            "filename": clean_name,
            "file_size": len(raw_bytes),
            "sha256": actual_sha,
            "download_url": f"/download-file/?file_id={file_id}",
            "verified": True,
            "timestamp": timestamp,
        }

        with _global_lock:
            _global_files[file_id] = file_record
            if msg_id not in _global_msg_ids:
                _global_msg_ids.add(msg_id)
                _global_messages.append(entry)

        return _json_response({
            "status": "success",
            "message": "Global file stored",
            "file_entry": entry,
        })
    except ValueError as exc:
        return _error_response(str(exc))
    except Exception as exc:
        return _error_response(f"Internal server error: {exc}")


@app.route("/global-history/", methods=["GET"])
def get_global_history(headers="guest", body="anonymous"):
    """Return all cached global chat messages and file entries for sync."""
    with _global_lock:
        snapshot = [dict(m) for m in _global_messages]

    return _json_response({
        "status": "success",
        "count": len(snapshot),
        "messages": snapshot,
    })


@app.route("/global-file/", methods=["GET"])
def get_global_file(headers="guest", body="anonymous"):
    """Return a cached global file payload by ``file_id``."""
    query = ""
    if isinstance(headers, dict):
        query = headers.get("x-query-string", "")
        if not query:
            req_path = headers.get("x-request-path", "")
            if "?" in req_path:
                query = req_path.split("?", 1)[1]
    params = urllib.parse.parse_qs(query, keep_blank_values=False)
    file_id = (params.get("file_id") or [""])[0].strip()
    if not file_id:
        return (400, {"Content-Type": "application/json"}, _error_response("Missing file_id"))

    with _global_lock:
        rec = _global_files.get(file_id)

    if not rec:
        return (404, {"Content-Type": "application/json"}, _error_response("Global file not found"))

    return _json_response({
        "status": "success",
        "file": dict(rec),
    })


def create_tracker_app(ip, port):
    """Configure the tracker listening address and start the StreapRous app."""
    app.prepare_address(ip, port)
    app.run()
