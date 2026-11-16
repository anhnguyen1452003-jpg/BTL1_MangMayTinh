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
daemon.crypto_utils
~~~~~~~~~~~~~~~~~~~

Pure Python standard-library encryption and integrity verification utilities
for P2P message framing (SHA-256 CTR stream cipher + HMAC-SHA256 + Base64).
"""

import base64
import binascii
import hashlib
import hmac
import json
import os

SHARED_SECRET = b"CO3094_STREAPROUS_SECRET_KEY_2026"
_IV_LEN = 16
_MAC_LEN = 32


def _xor_keystream(data: bytes, iv: bytes, secret: bytes = SHARED_SECRET) -> bytes:
    """Apply SHA-256 counter-mode keystream XOR over ``data``."""
    out = bytearray(len(data))
    offset = 0
    counter = 0
    total = len(data)

    while offset < total:
        block = hashlib.sha256(
            secret + iv + counter.to_bytes(4, "big")
        ).digest()
        chunk_len = min(len(block), total - offset)
        for i in range(chunk_len):
            out[offset + i] = data[offset + i] ^ block[i]
        offset += chunk_len
        counter += 1

    return bytes(out)


def encrypt_payload(raw_bytes: bytes) -> bytes:
    """
    Encrypt ``raw_bytes`` using SHA-256 CTR + HMAC-SHA256 and return a
    newline-delimited Base64 frame ``base64(iv + mac + ciphertext) + b'\\n'``.
    """
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode("utf-8")
    elif not isinstance(raw_bytes, (bytes, bytearray)):
        raise TypeError("raw_bytes must be bytes or str")

    iv = os.urandom(_IV_LEN)
    ciphertext = _xor_keystream(bytes(raw_bytes), iv)
    mac = hmac.new(SHARED_SECRET, iv + ciphertext, hashlib.sha256).digest()
    encoded = base64.b64encode(iv + mac + ciphertext)
    return encoded + b"\n"


def decrypt_payload(encrypted_bytes: bytes) -> bytes:
    """
    Verify HMAC-SHA256 integrity and decrypt a Base64-encoded (or JSON ``{"enc": ...}``)
    encrypted P2P frame back to original raw bytes.
    """
    if isinstance(encrypted_bytes, str):
        frame = encrypted_bytes.strip().encode("ascii", errors="strict")
    elif isinstance(encrypted_bytes, (bytes, bytearray)):
        frame = bytes(encrypted_bytes).strip()
    else:
        raise ValueError("Integrity check failed / Invalid key")

    if not frame:
        raise ValueError("Integrity check failed / Invalid key")

    if frame.startswith(b"{"):
        try:
            obj = json.loads(frame.decode("utf-8"))
            enc_val = obj.get("enc") if isinstance(obj, dict) else None
            if not isinstance(enc_val, str):
                raise ValueError("Integrity check failed / Invalid key")
            frame = enc_val.strip().encode("ascii")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Integrity check failed / Invalid key") from exc

    try:
        decoded = base64.b64decode(frame, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Integrity check failed / Invalid key") from exc

    if len(decoded) < _IV_LEN + _MAC_LEN:
        raise ValueError("Integrity check failed / Invalid key")

    iv = decoded[:_IV_LEN]
    mac = decoded[_IV_LEN:_IV_LEN + _MAC_LEN]
    ciphertext = decoded[_IV_LEN + _MAC_LEN:]

    expected_mac = hmac.new(
        SHARED_SECRET,
        iv + ciphertext,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected_mac, mac):
        raise ValueError("Integrity check failed / Invalid key")

    return _xor_keystream(ciphertext, iv)
