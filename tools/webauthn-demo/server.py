"""Tiny localhost WebAuthn demo for the ESP32 Passkey.

Serves a page at http://localhost:8787 and verifies registrations/assertions
server-side with python-fido2's CBOR/COSE helpers.

    python tools/webauthn-demo/server.py
"""

from __future__ import annotations

import base64
import json
import os
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fido2 import cbor
from fido2.cose import ES256
from fido2.utils import sha256

HERE = os.path.dirname(os.path.abspath(__file__))
RP_ID = "localhost"
ORIGIN = "http://localhost:8787"


def b64d(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.challenge = None
        self.cred_id = None
        self.public_key = None
        self.sign_count = 0
        self.user = None


STATE = State()


def parse_auth_data(auth_data: bytes):
    if len(auth_data) < 37:
        raise ValueError("short authData")
    rp_hash = auth_data[:32]
    flags = auth_data[32]
    counter = struct.unpack(">I", auth_data[33:37])[0]
    rest = auth_data[37:]
    cred_id = None
    cose = None
    if flags & 0x40:
        cred_len = struct.unpack(">H", rest[16:18])[0]
        cred_id = rest[18:18 + cred_len]
        cose = cbor.decode(rest[18 + cred_len:])
    return rp_hash, flags, counter, cred_id, cose


def verify_client_data(client_data_json: bytes, typ: str, challenge: bytes, origin: str):
    data = json.loads(client_data_json)
    if data.get("type") != typ:
        raise ValueError(f"bad clientData type {data.get('type')}")
    if b64d(data["challenge"]) != challenge:
        raise ValueError("challenge mismatch")
    if data.get("origin") != origin:
        raise ValueError(f"origin mismatch: {data.get('origin')}")
    return sha256(client_data_json)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif path == "/api/status":
            self._send(200, {
                "registered": STATE.cred_id is not None,
                "user": STATE.user,
                "signCount": STATE.sign_count,
                "credId": b64e(STATE.cred_id) if STATE.cred_id else None,
            })
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        path = self.path.split("?")[0]
        try:
            if path == "/api/register/options":
                with STATE.lock:
                    STATE.challenge = os.urandom(32)
                    challenge = STATE.challenge
                self._send(200, {"publicKey": {
                    "challenge": b64e(challenge),
                    "rp": {"id": RP_ID, "name": "ESP32 Passkey Demo"},
                    "user": {"id": b64e(os.urandom(16)), "name": "demo@localhost",
                             "displayName": "Demo User"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 120000,
                    "attestation": "none",
                    "authenticatorSelection": {
                        "authenticatorAttachment": "cross-platform",
                        "residentKey": "required",
                        "requireResidentKey": True,
                        "userVerification": "preferred",
                    },
                    "excludeCredentials": [],
                }})
                return

            if path == "/api/register/verify":
                with STATE.lock:
                    challenge = STATE.challenge
                resp = body["response"]
                cdh = verify_client_data(b64d(resp["clientDataJSON"]), "webauthn.create",
                                         challenge, ORIGIN)
                att_obj = cbor.decode(b64d(resp["attestationObject"]))
                auth_data = att_obj["authData"]
                rp_hash, flags, counter, cred_id, cose = parse_auth_data(auth_data)
                if rp_hash != sha256(RP_ID.encode()):
                    raise ValueError("rpIdHash mismatch")
                if not (flags & 0x01) or not (flags & 0x40):
                    raise ValueError("missing UP/AT flags")
                if att_obj["fmt"] not in ("none", "packed"):
                    raise ValueError("unexpected attestation format")
                with STATE.lock:
                    STATE.cred_id = cred_id
                    STATE.public_key = cose
                    STATE.sign_count = counter
                    STATE.user = body.get("user", "demo@localhost")
                    STATE.challenge = None
                self._send(200, {"ok": True, "credId": b64e(cred_id),
                                 "fmt": att_obj["fmt"], "flags": flags,
                                 "signCount": counter})
                return

            if path == "/api/login/options":
                with STATE.lock:
                    STATE.challenge = os.urandom(32)
                    challenge = STATE.challenge
                    cred_id = STATE.cred_id
                allow = [{"type": "public-key", "id": b64e(cred_id)}] if cred_id else []
                self._send(200, {"publicKey": {
                    "challenge": b64e(challenge),
                    "rpId": RP_ID,
                    "timeout": 120000,
                    "userVerification": "preferred",
                    "allowCredentials": allow,
                }})
                return

            if path == "/api/login/verify":
                with STATE.lock:
                    challenge = STATE.challenge
                    cose = STATE.public_key
                    stored_counter = STATE.sign_count
                if not cose:
                    raise ValueError("no credential registered")
                resp = body["response"]
                cdh = verify_client_data(b64d(resp["clientDataJSON"]), "webauthn.get",
                                         challenge, ORIGIN)
                auth_data = b64d(resp["authenticatorData"])
                rp_hash, flags, counter, _, _ = parse_auth_data(auth_data)
                if rp_hash != sha256(RP_ID.encode()):
                    raise ValueError("rpIdHash mismatch")
                if not (flags & 0x01):
                    raise ValueError("missing UP flag")
                ES256(cose).verify(auth_data + cdh, b64d(resp["signature"]))
                if counter < stored_counter:
                    raise ValueError("signature counter went backwards")
                with STATE.lock:
                    STATE.sign_count = counter
                    STATE.challenge = None
                self._send(200, {"ok": True, "signCount": counter, "flags": flags})
                return

            self._send(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            self._send(400, {"error": str(e)})


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"WebAuthn demo: http://localhost:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
