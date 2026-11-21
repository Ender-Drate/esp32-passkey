"""TechXPassKey Manager — local HTTP backend.

Serves the Apple-style web UI and bridges it to the ESP32 Passkey over its CDC
management channel (plus CTAP2 for PIN management and the WebAuthn demo).

    python apps/passkey-manager/server.py
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import pkdev  # noqa: E402
from core import importers, totp  # noqa: E402
from core.vault import Vault, VaultError, generate_password  # noqa: E402

from fido2 import cbor  # noqa: E402
from fido2.cose import ES256  # noqa: E402
from fido2.ctap2 import Ctap2  # noqa: E402
from fido2.ctap2.pin import ClientPin, PinProtocolV2  # noqa: E402
from fido2.utils import sha256  # noqa: E402

DATA = BASE / "data"
DATA.mkdir(exist_ok=True)
WEB = BASE / "web"
VAULT = Vault(str(DATA / "vault.enc"))

VERSION = "0.1.0"
DEVICE_LOCK = threading.RLock()
DEVICE: pkdev.Device | None = None
DEVICE_PORT: str | None = None


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------------------
# Device helpers
# ---------------------------------------------------------------------------
def device() -> pkdev.Device:
    global DEVICE, DEVICE_PORT
    with DEVICE_LOCK:
        if DEVICE is not None:
            try:
                DEVICE.info(timeout=0.6)
                return DEVICE
            except Exception:
                DEVICE = None
        try:
            DEVICE = pkdev.find_device()
            DEVICE_PORT = DEVICE.port
            try:
                DEVICE.set_time()
            except Exception:
                pass
            return DEVICE
        except Exception as e:  # noqa: BLE001
            DEVICE = None
            raise ApiError(f"未找到设备：{e}", 503)


def device_info() -> dict:
    with DEVICE_LOCK:
        d = device()
        info = d.info()
        info["port"] = d.port
        return info


def connect(port: str | None) -> dict:
    global DEVICE, DEVICE_PORT
    with DEVICE_LOCK:
        if DEVICE:
            DEVICE.close()
            DEVICE = None
        try:
            DEVICE = pkdev.find_device([port] if port else None)
            DEVICE_PORT = DEVICE.port
            DEVICE.set_time()
        except Exception as e:  # noqa: BLE001
            raise ApiError(str(e), 503)
        return device_info()


def require_pin_for_delete(pin: str, item_id_b64: str):
    d = device()
    import base64
    raw = base64.urlsafe_b64decode(item_id_b64 + "=" * (-len(item_id_b64) % 4))
    try:
        d.delete_credential(raw, pin or "")
    except pkdev.PasskeyError as e:
        raise ApiError(str(e), 401)


# ---------------------------------------------------------------------------
# WebAuthn demo state
# ---------------------------------------------------------------------------
DEMO = {
    "challenge": None,
    "cred_id": None,
    "public_key": None,
    "sign_count": 0,
    "user": None,
}
DEMO_LOCK = threading.Lock()
DEMO_RP = "localhost"


def b64d(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    import base64
    return base64.b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def parse_auth_data(auth_data: bytes):
    if len(auth_data) < 37:
        raise ValueError("short authData")
    rp_hash = auth_data[:32]
    flags = auth_data[32]
    counter = int.from_bytes(auth_data[33:37], "big")
    rest = auth_data[37:]
    cred_id = None
    cose = None
    if flags & 0x40:
        cred_len = int.from_bytes(rest[16:18], "big")
        cred_id = rest[18:18 + cred_len]
        cose = cbor.decode(rest[18 + cred_len:])
    return rp_hash, flags, counter, cred_id, cose


def verify_client_data(client_data_json: bytes, typ: str, challenge: bytes):
    data = json.loads(client_data_json)
    if data.get("type") != typ:
        raise ValueError(f"clientData type {data.get('type')}")
    if b64d(data["challenge"]) != challenge:
        raise ValueError("challenge 不匹配")
    origin = data.get("origin", "")
    if not (origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1")):
        raise ValueError(f"origin 不匹配: {origin}")
    return sha256(client_data_json)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
ROUTES = []


def route(method: str, pattern: str):
    def deco(fn):
        ROUTES.append((method, re.compile(f"^{pattern}$"), fn))
        return fn
    return deco


@route("GET", r"/api/state")
def api_state(body, m):
    out = {
        "version": VERSION,
        "vault": {"exists": VAULT.exists, "locked": not VAULT.unlocked,
                  "count": len(VAULT.items) if VAULT.unlocked else None},
        "device": None,
    }
    try:
        out["device"] = device_info()
    except ApiError as e:
        out["deviceError"] = str(e)
    return out


@route("POST", r"/api/device/connect")
def api_connect(body, m):
    return {"device": connect(body.get("port"))}


@route("GET", r"/api/device/passkeys")
def api_passkeys(body, m):
    global DEVICE
    with DEVICE_LOCK:
        d = device()
        return {"items": d.list_credentials(), "info": d.info()}


@route("POST", r"/api/device/passkeys/delete")
def api_passkey_delete(body, m):
    require_pin_for_delete(body.get("pin", ""), body["id"])
    return {"ok": True}


@route("POST", r"/api/device/pin")
def api_device_pin(body, m):
    action = body.get("action")
    pin = body.get("pin", "")
    new_pin = body.get("newPin", "")
    with DEVICE_LOCK:
        d = device()
        try:
            ctap = Ctap2(pkdev.CtapCdc(d))
            cp = ClientPin(ctap, PinProtocolV2())
            if action == "set":
                if len(new_pin) < 4:
                    raise ApiError("PIN 至少 4 位")
                cp.set_pin(new_pin)
            elif action == "change":
                cp.change_pin(pin, new_pin)
            else:
                raise ApiError("未知操作")
        except ApiError:
            raise
        except Exception as e:  # noqa: BLE001
            raise ApiError(f"PIN 操作失败：{e}")
        return {"ok": True, "info": d.info()}


@route("POST", r"/api/device/upmode")
def api_upmode(body, m):
    mode = body.get("mode")
    with DEVICE_LOCK:
        d = device()
        d.set_up_mode(mode == "auto")
        return {"ok": True, "info": d.info()}


@route("POST", r"/api/device/reset")
def api_reset(body, m):
    with DEVICE_LOCK:
        d = device()
        try:
            d.factory_reset(body.get("pin", ""))
        except pkdev.PasskeyError as e:
            raise ApiError(str(e), 401)
        return {"ok": True, "info": d.info()}


@route("POST", r"/api/device/reboot")
def api_reboot(body, m):
    with DEVICE_LOCK:
        d = device()
        d.reboot()
    return {"ok": True}


@route("POST", r"/api/device/ota")
def api_ota(body, m):
    raw = body.get("_raw", b"")
    if len(raw) < 1024:
        raise ApiError("固件文件太小")
    fd, path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    try:
        with DEVICE_LOCK:
            d = device()
            d.ota(path)
        return {"ok": True, "bytes": len(raw)}
    except Exception as e:  # noqa: BLE001
        raise ApiError(f"OTA 失败：{e}")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


@route("GET", r"/api/vault/items")
def api_vault_items(body, m):
    if not VAULT.unlocked:
        raise ApiError("密码库未解锁", 401)
    return {"items": VAULT.items}


@route("POST", r"/api/vault/create")
def api_vault_create(body, m):
    try:
        VAULT.create(body.get("password", ""))
    except VaultError as e:
        raise ApiError(str(e))
    return {"ok": True}


@route("POST", r"/api/vault/unlock")
def api_vault_unlock(body, m):
    try:
        VAULT.unlock(body.get("password", ""))
    except VaultError as e:
        raise ApiError(str(e), 401)
    return {"ok": True, "count": len(VAULT.items)}


@route("POST", r"/api/vault/lock")
def api_vault_lock(body, m):
    VAULT.lock()
    return {"ok": True}


@route("POST", r"/api/vault/items")
def api_vault_add(body, m):
    if not VAULT.unlocked:
        raise ApiError("密码库未解锁", 401)
    try:
        return {"item": VAULT.add(body.get("item", {}))}
    except VaultError as e:
        raise ApiError(str(e))


@route("PUT", r"/api/vault/items/([0-9a-f]+)")
def api_vault_update(body, m):
    if not VAULT.unlocked:
        raise ApiError("密码库未解锁", 401)
    try:
        return {"item": VAULT.update(m.group(1), body.get("item", {}))}
    except VaultError as e:
        raise ApiError(str(e))


@route("DELETE", r"/api/vault/items/([0-9a-f]+)")
def api_vault_delete(body, m):
    if not VAULT.unlocked:
        raise ApiError("密码库未解锁", 401)
    try:
        VAULT.delete(m.group(1))
    except VaultError as e:
        raise ApiError(str(e))
    return {"ok": True}


@route("POST", r"/api/vault/generate")
def api_generate(body, m):
    try:
        return {"password": generate_password(
            int(body.get("length", 20)), body.get("upper", True), body.get("lower", True),
            body.get("digits", True), body.get("symbols", True))}
    except VaultError as e:
        raise ApiError(str(e))


@route("POST", r"/api/vault/import")
def api_import(body, m):
    if not VAULT.unlocked:
        raise ApiError("密码库未解锁", 401)
    try:
        items, fmt = importers.detect_and_parse(body.get("text", ""), body.get("format", "auto"))
    except Exception as e:  # noqa: BLE001
        raise ApiError(f"解析失败：{e}")
    n = VAULT.import_items(items)
    return {"ok": True, "count": n, "format": fmt}


@route("POST", r"/api/vault/export")
def api_export(body, m):
    if not VAULT.unlocked:
        raise ApiError("密码库未解锁", 401)
    fmt = body.get("format", "chrome")
    if fmt == "bitwarden-json":
        content = importers.export_bitwarden_json(VAULT.items)
        name = "techxpasskey-bitwarden.json"
    elif fmt in ("chrome", "keepass", "bitwarden-csv"):
        content = importers.export_csv(VAULT.items, fmt)
        name = f"techxpasskey-{fmt}.csv"
    else:
        raise ApiError("未知导出格式")
    return {"filename": name, "content": content}


@route("GET", r"/api/totp/([0-9a-f]+)")
def api_totp(body, m):
    if not VAULT.unlocked:
        raise ApiError("密码库未解锁", 401)
    item = VAULT.find(m.group(1))
    if not item or not item.get("totp"):
        raise ApiError("该条目没有 TOTP", 404)
    secret = item["totp"]
    if secret.startswith("otpauth://"):
        secret = totp.parse_otpauth(secret)["secret"]
    return {"code": totp.totp(secret), "remaining": totp.totp_remaining()}


# -- WebAuthn demo ----------------------------------------------------------
@route("GET", r"/api/webauthn/status")
def api_wa_status(body, m):
    return {"registered": DEMO["cred_id"] is not None, "user": DEMO["user"],
            "signCount": DEMO["sign_count"],
            "credId": b64e(DEMO["cred_id"]) if DEMO["cred_id"] else None}


@route("POST", r"/api/webauthn/register/options")
def api_wa_reg_options(body, m):
    with DEMO_LOCK:
        DEMO["challenge"] = secrets.token_bytes(32)
        challenge = DEMO["challenge"]
    return {"publicKey": {
        "challenge": b64e(challenge),
        "rp": {"id": DEMO_RP, "name": "TechXPassKey"},
        "user": {"id": b64e(secrets.token_bytes(16)), "name": "demo@localhost",
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
    }}


@route("POST", r"/api/webauthn/register/verify")
def api_wa_reg_verify(body, m):
    with DEMO_LOCK:
        challenge = DEMO["challenge"]
    resp = body["response"]
    cdh = verify_client_data(b64d(resp["clientDataJSON"]), "webauthn.create", challenge)
    del cdh
    att = cbor.decode(b64d(resp["attestationObject"]))
    rp_hash, flags, counter, cred_id, cose = parse_auth_data(att["authData"])
    if rp_hash != sha256(DEMO_RP.encode()):
        raise ValueError("rpIdHash 不匹配")
    if not (flags & 0x01) or not (flags & 0x40):
        raise ValueError("缺少 UP/AT 标志")
    with DEMO_LOCK:
        DEMO.update(cred_id=cred_id, public_key=cose, sign_count=counter,
                    user="demo@localhost", challenge=None)
    return {"ok": True, "credId": b64e(cred_id), "fmt": att["fmt"], "flags": flags,
            "signCount": counter}


@route("POST", r"/api/webauthn/login/options")
def api_wa_login_options(body, m):
    with DEMO_LOCK:
        DEMO["challenge"] = secrets.token_bytes(32)
        challenge = DEMO["challenge"]
        cred_id = DEMO["cred_id"]
    allow = [{"type": "public-key", "id": b64e(cred_id)}] if cred_id else []
    return {"publicKey": {"challenge": b64e(challenge), "rpId": DEMO_RP, "timeout": 120000,
                          "userVerification": "preferred", "allowCredentials": allow}}


@route("POST", r"/api/webauthn/login/verify")
def api_wa_login_verify(body, m):
    with DEMO_LOCK:
        challenge = DEMO["challenge"]
        cose = DEMO["public_key"]
        stored = DEMO["sign_count"]
    if not cose:
        raise ValueError("还没有注册凭据")
    resp = body["response"]
    cdh = verify_client_data(b64d(resp["clientDataJSON"]), "webauthn.get", challenge)
    auth_data = b64d(resp["authenticatorData"])
    rp_hash, flags, counter, _, _ = parse_auth_data(auth_data)
    if rp_hash != sha256(DEMO_RP.encode()):
        raise ValueError("rpIdHash 不匹配")
    ES256(cose).verify(auth_data + cdh, b64d(resp["signature"]))
    if counter < stored:
        raise ValueError("签名计数器回退")
    with DEMO_LOCK:
        DEMO["sign_count"] = counter
        DEMO["challenge"] = None
    return {"ok": True, "signCount": counter, "flags": flags}


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data):
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        ctype = self.headers.get("Content-Type", "")
        if ctype.startswith("application/octet-stream"):
            return {"_raw": raw}
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw}

    def _dispatch(self, method: str):
        path = urlparse(self.path).path
        if method == "GET" and not path.startswith("/api/"):
            return self._static(path)
        body = self._body() if method in ("POST", "PUT", "PATCH") else {}
        for m_method, pattern, fn in ROUTES:
            if m_method != method:
                continue
            match = pattern.match(path)
            if match:
                try:
                    result = fn(body, match)
                    if isinstance(result, bytes):
                        return self._send(200, result, "application/octet-stream")
                    return self._json(200, result)
                except ApiError as e:
                    return self._json(e.status, {"error": str(e)})
                except Exception as e:  # noqa: BLE001
                    traceback.print_exc()
                    return self._json(500, {"error": str(e)})
        return self._json(404, {"error": "not found"})

    def _static(self, path: str):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        target = (WEB / rel).resolve()
        if not str(target).startswith(str(WEB.resolve())) or not target.is_file():
            return self._json(404, {"error": "not found"})
        ctype = MIME.get(target.suffix.lower(), "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    port = int(args[0]) if args else 8787
    try:
        device_info()
        print(f"device: {DEVICE.port}")
    except Exception as e:  # noqa: BLE001
        print(f"device: not connected ({e})")
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://localhost:{port}/"
    print(f"TechXPassKey Manager: {url}")
    if "--no-browser" not in sys.argv:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
