"""Import/export for common password managers (CSV / JSON)."""

from __future__ import annotations

import csv
import io
import json
import re


def _rows(text: str):
    text = text.lstrip("\ufeff")
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    rows = [{(k or "").strip(): (v or "").strip() for k, v in r.items()} for r in reader]
    return reader.fieldnames or [], rows


def _mk(title="", username="", password="", url="", notes="", totp="", tags=None):
    return {
        "title": title.strip(),
        "username": username.strip(),
        "password": password,
        "url": url.strip(),
        "notes": notes.strip(),
        "totp": totp.strip(),
        "tags": tags or [],
    }


def parse_chrome(text: str) -> list[dict]:
    fields, rows = _rows(text)
    low = [f.lower() for f in fields]
    if not {"name", "password"} <= set(low):
        raise ValueError("不是 Chrome/Edge 导出的 CSV")
    out = []
    for r in rows:
        d = {k.lower(): v for k, v in r.items()}
        out.append(_mk(d.get("name", ""), d.get("username", ""), d.get("password", ""),
                       d.get("url", ""), d.get("note", "") or d.get("notes", "")))
    return out


def parse_bitwarden_json(text: str) -> list[dict]:
    doc = json.loads(text)
    items = doc.get("items", doc if isinstance(doc, list) else [])
    out = []
    for it in items:
        if it.get("type", 1) != 1:
            continue
        login = it.get("login") or {}
        uris = login.get("uris") or []
        url = uris[0].get("uri", "") if uris else ""
        out.append(_mk(it.get("name", ""), login.get("username", ""), login.get("password", ""),
                       url, it.get("notes", ""), login.get("totp", ""), it.get("collectionIds", [])))
    return out


def parse_bitwarden_csv(text: str) -> list[dict]:
    fields, rows = _rows(text)
    out = []
    for r in rows:
        if r.get("type", "login").lower() not in ("login", "1", ""):
            continue
        out.append(_mk(r.get("name", ""), r.get("login_username", ""), r.get("login_password", ""),
                       r.get("login_uri", ""), r.get("notes", ""), r.get("login_totp", "")))
    return out


def parse_1password_csv(text: str) -> list[dict]:
    fields, rows = _rows(text)
    low = {f.lower() for f in fields}
    if "title" not in low:
        raise ValueError("不是 1Password CSV")
    out = []
    for r in rows:
        d = {k.lower(): v for k, v in r.items()}
        out.append(_mk(d.get("title", ""), d.get("username", ""), d.get("password", ""),
                       d.get("url", "") or d.get("website", ""), d.get("notes", ""),
                       d.get("otpauth", "")))
    return out


def parse_keepass_csv(text: str) -> list[dict]:
    fields, rows = _rows(text)
    low = {f.lower() for f in fields}
    if "login name" not in low and "account" not in low:
        raise ValueError("不是 KeePass CSV")
    out = []
    for r in rows:
        d = {k.lower(): v for k, v in r.items()}
        out.append(_mk(d.get("account", ""), d.get("login name", ""), d.get("password", ""),
                       d.get("web site", ""), d.get("comments", "")))
    return out


def parse_lastpass_csv(text: str) -> list[dict]:
    fields, rows = _rows(text)
    low = {f.lower() for f in fields}
    if "grouping" not in low:
        raise ValueError("不是 LastPass CSV")
    out = []
    for r in rows:
        d = {k.lower(): v for k, v in r.items()}
        out.append(_mk(d.get("name", ""), d.get("username", ""), d.get("password", ""),
                       d.get("url", ""), d.get("extra", ""), d.get("totp", ""),
                       [d["grouping"]] if d.get("grouping") else []))
    return out


def parse_generic_csv(text: str) -> list[dict]:
    fields, rows = _rows(text)
    low = {f.lower(): f for f in fields}

    def pick(*names):
        for n in names:
            if n in low:
                return low[n]
        return None

    k_title = pick("name", "title", "account", "site")
    k_user = pick("username", "login", "login name", "user", "email")
    k_pass = pick("password", "pass")
    k_url = pick("url", "website", "web site", "login_uri")
    k_note = pick("note", "notes", "comments", "extra")
    k_totp = pick("totp", "otp", "otpauth", "login_totp")
    if not k_pass:
        raise ValueError("CSV 里没有密码列")
    out = []
    for r in rows:
        out.append(_mk(r.get(k_title, "") if k_title else "",
                       r.get(k_user, "") if k_user else "",
                       r.get(k_pass, ""),
                       r.get(k_url, "") if k_url else "",
                       r.get(k_note, "") if k_note else "",
                       r.get(k_totp, "") if k_totp else ""))
    return out


PARSERS = {
    "chrome": parse_chrome,
    "bitwarden-json": parse_bitwarden_json,
    "bitwarden-csv": parse_bitwarden_csv,
    "1password": parse_1password_csv,
    "keepass": parse_keepass_csv,
    "lastpass": parse_lastpass_csv,
    "generic": parse_generic_csv,
}


def detect_and_parse(text: str, fmt: str = "auto") -> tuple[list[dict], str]:
    text = text.lstrip("\ufeff")
    if fmt == "auto":
        if text.lstrip().startswith("{"):
            return parse_bitwarden_json(text), "bitwarden-json"
        head = text.splitlines()[0].lower() if text.splitlines() else ""
        if "grouping" in head:
            return parse_lastpass_csv(text), "lastpass"
        if "login_uri" in head:
            return parse_bitwarden_csv(text), "bitwarden-csv"
        if "otpauth" in head or "title" in head:
            return parse_1password_csv(text), "1password"
        if "login name" in head or head.startswith('"account"'):
            return parse_keepass_csv(text), "keepass"
        try:
            return parse_chrome(text), "chrome"
        except Exception:
            return parse_generic_csv(text), "generic"
    if fmt not in PARSERS:
        raise ValueError(f"unknown format {fmt}")
    return PARSERS[fmt](text), fmt


def export_csv(items: list[dict], kind: str) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    if kind == "keepass":
        w.writerow(["Account", "Login Name", "Password", "Web Site", "Comments"])
        for it in items:
            w.writerow([it.get("title", ""), it.get("username", ""), it.get("password", ""),
                        it.get("url", ""), it.get("notes", "")])
    elif kind == "bitwarden-csv":
        w.writerow(["folder", "favorite", "type", "name", "notes", "fields", "reprompt",
                    "login_uri", "login_username", "login_password", "login_totp"])
        for it in items:
            w.writerow(["", "0", "login", it.get("title", ""), it.get("notes", ""), "", "0",
                        it.get("url", ""), it.get("username", ""), it.get("password", ""),
                        it.get("totp", "")])
    else:  # chrome
        w.writerow(["name", "url", "username", "password", "note"])
        for it in items:
            w.writerow([it.get("title", ""), it.get("url", ""), it.get("username", ""),
                        it.get("password", ""), it.get("notes", "")])
    return buf.getvalue()


def export_bitwarden_json(items: list[dict]) -> str:
    doc = {
        "encrypted": False,
        "folders": [],
        "items": [
            {
                "id": it.get("id"),
                "type": 1,
                "name": it.get("title", ""),
                "notes": it.get("notes", ""),
                "login": {
                    "username": it.get("username", ""),
                    "password": it.get("password", ""),
                    "totp": it.get("totp", ""),
                    "uris": [{"uri": it.get("url", "")}] if it.get("url") else [],
                },
            }
            for it in items
        ],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)
