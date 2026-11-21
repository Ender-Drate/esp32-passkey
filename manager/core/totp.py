"""TOTP / HOTP (RFC 4226 / 6238), stdlib only."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time


def normalize_secret(secret: str) -> str:
    return "".join(secret.split()).replace("-", "").upper().rstrip("=")


def decode_secret(secret: str) -> bytes:
    s = normalize_secret(secret)
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s, casefold=True)


def hotp(secret: str, counter: int, digits: int = 6) -> str:
    key = decode_secret(secret)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: str, period: int = 30, digits: int = 6, at: float | None = None) -> str:
    now = time.time() if at is None else at
    return hotp(secret, int(now // period), digits)


def totp_remaining(period: int = 30, at: float | None = None) -> int:
    now = time.time() if at is None else at
    return int(period - (now % period))


def parse_otpauth(uri: str) -> dict:
    """otpauth://totp/Issuer:account?secret=...&issuer=...&digits=6&period=30"""
    from urllib.parse import urlparse, parse_qs, unquote

    u = urlparse(uri)
    if u.scheme != "otpauth":
        raise ValueError("not an otpauth URI")
    kind = u.netloc.lower()
    label = unquote(u.path.lstrip("/"))
    issuer, _, account = label.partition(":")
    q = parse_qs(u.query)
    return {
        "type": kind,
        "secret": (q.get("secret") or [""])[0],
        "issuer": (q.get("issuer") or [issuer])[0],
        "account": account or issuer,
        "digits": int((q.get("digits") or ["6"])[0]),
        "period": int((q.get("period") or ["30"])[0]),
    }
