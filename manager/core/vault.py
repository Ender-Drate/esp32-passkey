"""Encrypted local vault (AES-256-GCM + scrypt)."""

from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
import time
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VAULT_VERSION = 1
KDF_N = 2 ** 15
KDF_R = 8
KDF_P = 1


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def new_item(**kw) -> dict:
    now = int(time.time())
    item = {
        "id": uuid.uuid4().hex,
        "type": "login",
        "title": "",
        "username": "",
        "password": "",
        "url": "",
        "notes": "",
        "totp": "",
        "tags": [],
        "created": now,
        "updated": now,
    }
    item.update({k: v for k, v in kw.items() if v is not None})
    return item


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, path: str):
        self.path = path
        self.items: list[dict] = []
        self.key: bytes | None = None
        self.salt: bytes | None = None

    # -- state ---------------------------------------------------------------
    @property
    def exists(self) -> bool:
        return os.path.exists(self.path)

    @property
    def unlocked(self) -> bool:
        return self.key is not None

    def create(self, password: str):
        if self.exists:
            raise VaultError("vault already exists")
        if len(password) < 8:
            raise VaultError("主密码至少 8 位")
        self.salt = secrets.token_bytes(16)
        self.key = self._derive(password, self.salt)
        self.items = []
        self.save()

    def unlock(self, password: str):
        if not self.exists:
            raise VaultError("密码库尚未创建")
        data = json.loads(open(self.path, "r", encoding="utf-8").read())
        salt = _b64d(data["salt"])
        key = self._derive(password, salt, data["n"], data["r"], data["p"])
        try:
            plain = AESGCM(key).decrypt(_b64d(data["nonce"]), _b64d(data["ct"]), None)
        except Exception:
            raise VaultError("主密码不正确")
        payload = json.loads(plain.decode("utf-8"))
        self.items = payload.get("items", [])
        self.salt = salt
        self.key = key

    def lock(self):
        self.key = None
        self.items = []

    def _derive(self, password: str, salt: bytes, n=KDF_N, r=KDF_R, p=KDF_P) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
        return kdf.derive(password.encode("utf-8"))

    def save(self):
        if not self.key:
            raise VaultError("vault is locked")
        payload = json.dumps({"items": self.items, "saved": int(time.time())},
                             ensure_ascii=False).encode("utf-8")
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self.key).encrypt(nonce, payload, None)
        doc = {
            "v": VAULT_VERSION,
            "salt": _b64e(self.salt or b""),
            "n": KDF_N, "r": KDF_R, "p": KDF_P,
            "nonce": _b64e(nonce),
            "ct": _b64e(ct),
        }
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), prefix=".vault-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        os.replace(tmp, self.path)

    # -- items ---------------------------------------------------------------
    def find(self, item_id: str) -> dict | None:
        return next((i for i in self.items if i["id"] == item_id), None)

    def add(self, item: dict) -> dict:
        item = new_item(**item)
        self.items.append(item)
        self.save()
        return item

    def update(self, item_id: str, patch: dict) -> dict:
        item = self.find(item_id)
        if not item:
            raise VaultError("条目不存在")
        for k in ("type", "title", "username", "password", "url", "notes", "totp", "tags"):
            if k in patch:
                item[k] = patch[k]
        item["updated"] = int(time.time())
        self.save()
        return item

    def delete(self, item_id: str):
        before = len(self.items)
        self.items = [i for i in self.items if i["id"] != item_id]
        if len(self.items) == before:
            raise VaultError("条目不存在")
        self.save()

    def import_items(self, items: list[dict]) -> int:
        for it in items:
            self.items.append(new_item(**it))
        self.save()
        return len(items)


def generate_password(length=20, upper=True, lower=True, digits=True, symbols=True) -> str:
    pools = []
    if upper: pools.append("ABCDEFGHJKLMNPQRSTUVWXYZ")
    if lower: pools.append("abcdefghijkmnopqrstuvwxyz")
    if digits: pools.append("23456789")
    if symbols: pools.append("!@#$%^&*-_=+?")
    if not pools:
        raise VaultError("至少选择一种字符类型")
    chars = [secrets.choice(p) for p in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(max(0, length - len(chars)))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars[:length])
