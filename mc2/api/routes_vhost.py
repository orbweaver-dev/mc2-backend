"""
Virtualmin vhost (virtual server) management — the per-domain view that
backs the new WebOps `/webops/vhost/[domain]/*` UI.

Wraps the Virtualmin CLI for:
  - listing domains
  - per-domain info (template, plan, quotas, features)
  - per-domain mailbox CRUD (list / create / modify / delete)

Other per-domain resources (aliases, mail-quotas, autoresponder, databases,
DNS, etc.) already have dedicated route modules (`routes_mail_aliases`,
`routes_mail_quotas`, `routes_autoresponder`, ...). The UI calls those
directly with a `?domain=` filter — no need to re-wrap them here.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from mc2.auth import TokenPayload, require_super_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vhost", tags=["vhost"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def _vmin(*args: str, timeout: int = 30) -> tuple[int, str, str]:
    return _run(["sudo", "virtualmin", *args], timeout=timeout)


# Domain names that Virtualmin accepts — lowercase ASCII letters, digits,
# dots, hyphens. Validated server-side so we never interpolate arbitrary
# strings into a shell argument.
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_USERNAME_RE = re.compile(r"^[a-z0-9._-]{1,64}$")


def _check_domain(domain: str) -> str:
    if not _DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail=f"Invalid domain name: {domain!r}")
    return domain


def _check_username(name: str) -> str:
    if not _USERNAME_RE.match(name):
        raise HTTPException(status_code=400, detail=f"Invalid mailbox name: {name!r}")
    return name


# ---------------------------------------------------------------------------
# Domain listing + info
# ---------------------------------------------------------------------------

@router.get("/domains")
def list_domains(_: Auth) -> dict:
    """
    Return every virtual server (top-level + sub-servers) as a flat list.

    The UI's vhost picker (`/webops/vhost`) consumes this directly. Output
    is `virtualmin list-domains --json` projected to only the fields the UI
    actually renders so we don't ship 30+ KB per call.
    """
    rc, out, err = _vmin("list-domains", "--json")
    if rc != 0:
        raise HTTPException(status_code=502, detail=err.strip() or "virtualmin list-domains failed")

    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="virtualmin returned non-JSON")

    domains: list[dict] = []
    # `list-domains --json` returns: {"data": [{"name": "...", "values": {...}}, ...]}
    for entry in (raw.get("data") or []):
        name = entry.get("name", "")
        v = entry.get("values", {}) or {}
        domains.append({
            "domain":       name,
            "type":         (v.get("type") or ["server"])[0],
            "user":         (v.get("username") or [""])[0],
            "ip":           (v.get("ip_address") or [""])[0],
            "ip6":          (v.get("ip6_address") or [""])[0],
            "home":         (v.get("home_directory") or [""])[0],
            "template":     (v.get("template") or [""])[0],
            "plan":         (v.get("plan") or [""])[0],
            "parent":       (v.get("parent_domain") or [""])[0],
            "quota_mb":     _parse_quota_mb(v),
            "features":     _flatten_features(v),
        })

    domains.sort(key=lambda d: (d["parent"] or d["domain"], d["domain"]))
    return {"domains": domains, "count": len(domains)}


def _parse_quota_mb(values: dict) -> int | None:
    """`list-domains --json` reports quota in 1KiB blocks under `server_quota`."""
    q = (values.get("server_quota") or [""])[0]
    if not q or q.lower() in ("unlimited", "none", ""):
        return None
    try:
        return int(int(q) / 1024)
    except (ValueError, TypeError):
        return None


def _flatten_features(values: dict) -> list[str]:
    """Booleans like `mail`, `web`, `dns`, `mysql` projected to a list."""
    feats = []
    for k in ("web", "ssl", "mail", "dns", "mysql", "postgres", "logrotate", "spam", "virus", "webmin"):
        v = values.get(k)
        if v and (v[0] or "").lower() in ("1", "true", "yes"):
            feats.append(k)
    return feats


@router.get("/domains/{domain}")
def domain_info(_: Auth, domain: str) -> dict:
    """Detailed info for a single domain. Backs the vhost dashboard."""
    _check_domain(domain)
    rc, out, err = _vmin("list-domains", "--domain", domain, "--json")
    if rc != 0:
        raise HTTPException(status_code=502, detail=err.strip() or "virtualmin list-domains failed")
    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="virtualmin returned non-JSON")
    data = (raw.get("data") or [])
    if not data:
        raise HTTPException(status_code=404, detail=f"Domain not found: {domain}")
    entry = data[0]
    v = entry.get("values") or {}
    return {
        "domain":          entry.get("name", domain),
        "user":            (v.get("username") or [""])[0],
        "type":            (v.get("type") or ["server"])[0],
        "ip":              (v.get("ip_address") or [""])[0],
        "ip6":             (v.get("ip6_address") or [""])[0],
        "home":            (v.get("home_directory") or [""])[0],
        "template":        (v.get("template") or [""])[0],
        "plan":            (v.get("plan") or [""])[0],
        "parent":          (v.get("parent_domain") or [""])[0],
        "creation_time":   (v.get("creation_time_human") or [""])[0],
        "quota_mb":        _parse_quota_mb(v),
        "used_quota_mb":   _parse_used_quota_mb(v),
        "bandwidth_used_mb": _parse_bandwidth_mb(v),
        "features":        _flatten_features(v),
        "ssl_expiry":      (v.get("ssl_certificate_expiry") or [""])[0],
    }


def _parse_used_quota_mb(values: dict) -> int | None:
    q = (values.get("server_quota_used") or [""])[0]
    if not q:
        return None
    try:
        return int(int(q) / 1024)
    except (ValueError, TypeError):
        return None


def _parse_bandwidth_mb(values: dict) -> int | None:
    b = (values.get("bandwidth_used") or [""])[0]
    if not b:
        return None
    try:
        return int(int(b) / (1024 * 1024))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Per-domain mailbox CRUD
# ---------------------------------------------------------------------------

@router.get("/domains/{domain}/users")
def list_users(_: Auth, domain: str) -> dict:
    """List every mailbox / FTP user under this virtual server."""
    _check_domain(domain)
    rc, out, err = _vmin("list-users", "--domain", domain, "--multiline")
    if rc != 0:
        raise HTTPException(status_code=502, detail=err.strip() or "virtualmin list-users failed")

    users = _parse_users_multiline(out)
    return {"domain": domain, "users": users, "count": len(users)}


def _parse_users_multiline(text: str) -> list[dict]:
    """
    Parse `virtualmin list-users --multiline` output. Each user block is a
    header line containing the username followed by indented `Key: value`
    lines until the next blank line / header.
    """
    users: list[dict] = []
    current: dict | None = None
    for raw in text.splitlines():
        if not raw.strip():
            if current is not None:
                users.append(_project_user(current))
                current = None
            continue
        if not raw.startswith(" ") and not raw.startswith("\t"):
            if current is not None:
                users.append(_project_user(current))
            current = {"_username": raw.strip(), "_raw": {}}
        else:
            line = raw.strip()
            if ":" in line and current is not None:
                k, _, v = line.partition(":")
                current["_raw"][k.strip()] = v.strip()
    if current is not None:
        users.append(_project_user(current))
    return users


def _project_user(u: dict) -> dict:
    raw = u.get("_raw", {})
    quota = raw.get("Mail quota") or raw.get("Quota") or ""
    return {
        "username":   u.get("_username", ""),
        "email":      raw.get("Email address") or raw.get("Email") or "",
        "real_name":  raw.get("Real name") or "",
        "mail":       (raw.get("Mail enabled") or "").lower() in ("yes", "1", "true"),
        "ftp":        (raw.get("FTP enabled") or "").lower() in ("yes", "1", "true"),
        "databases":  raw.get("Database access") or "",
        "quota":      quota,
        "uid":        raw.get("Unix UID") or raw.get("UID") or "",
        "shell":      raw.get("Login shell") or "",
        "home":       raw.get("Home directory") or "",
        "extra_aliases": _split_aliases(raw.get("Extra email addresses") or ""),
    }


def _split_aliases(s: str) -> list[str]:
    s = s.strip()
    if not s or s.lower() in ("none", "-"):
        return []
    return [a.strip() for a in s.replace(",", " ").split() if a.strip()]


class CreateMailbox(BaseModel):
    username:   str = Field(..., min_length=1, max_length=64)
    password:   str = Field(..., min_length=4)
    real_name:  str = Field("", max_length=128)
    quota_mb:   int | None = Field(None, ge=0, description="Mail quota in MB; null = unlimited")
    enable_ftp: bool = False


@router.post("/domains/{domain}/users", status_code=201)
def create_mailbox(_: Auth, domain: str, body: CreateMailbox) -> dict:
    """Create a new mailbox under this virtual server. `virtualmin create-user`."""
    _check_domain(domain)
    _check_username(body.username)

    args = [
        "create-user",
        "--domain",   domain,
        "--user",     body.username,
        "--pass",     body.password,
        "--mail-only" if not body.enable_ftp else "--mail",
    ]
    if body.real_name:
        args.extend(["--real", body.real_name])
    if body.quota_mb is not None and body.quota_mb > 0:
        args.extend(["--quota", str(body.quota_mb * 1024)])  # blocks (1KiB)

    rc, out, err = _vmin(*args, timeout=60)
    if rc != 0:
        detail = (err or out).strip() or "virtualmin create-user failed"
        raise HTTPException(status_code=502, detail=detail)
    return {"ok": True, "username": body.username, "domain": domain}


class ModifyMailbox(BaseModel):
    password:   str | None = Field(None, min_length=4)
    real_name:  str | None = Field(None, max_length=128)
    quota_mb:   int | None = Field(None, ge=0)
    enable_mail: bool | None = None
    enable_ftp:  bool | None = None


@router.put("/domains/{domain}/users/{username}")
def modify_mailbox(_: Auth, domain: str, username: str, body: ModifyMailbox) -> dict:
    """Update an existing mailbox. Only fields actually supplied are sent."""
    _check_domain(domain)
    _check_username(username)

    args = ["modify-user", "--domain", domain, "--user", username]
    if body.password is not None:
        args.extend(["--pass", body.password])
    if body.real_name is not None:
        args.extend(["--real", body.real_name])
    if body.quota_mb is not None:
        args.extend(["--quota", str(body.quota_mb * 1024)])
    if body.enable_mail is True:
        args.append("--mail")
    elif body.enable_mail is False:
        args.append("--no-mail")
    if body.enable_ftp is True:
        args.append("--ftp")
    elif body.enable_ftp is False:
        args.append("--no-ftp")

    if len(args) == 4:  # base args only — nothing to change
        return {"ok": True, "username": username, "domain": domain, "noop": True}

    rc, out, err = _vmin(*args, timeout=60)
    if rc != 0:
        detail = (err or out).strip() or "virtualmin modify-user failed"
        raise HTTPException(status_code=502, detail=detail)
    return {"ok": True, "username": username, "domain": domain}


@router.delete("/domains/{domain}/users/{username}")
def delete_mailbox(_: Auth, domain: str, username: str) -> dict:
    """Remove a mailbox. `virtualmin delete-user`."""
    _check_domain(domain)
    _check_username(username)

    rc, out, err = _vmin(
        "delete-user", "--domain", domain, "--user", username, timeout=60,
    )
    if rc != 0:
        detail = (err or out).strip() or "virtualmin delete-user failed"
        raise HTTPException(status_code=502, detail=detail)
    return {"ok": True, "username": username, "domain": domain}


# ---------------------------------------------------------------------------
# Per-domain databases (read-only — list only; create/delete is a follow-up)
# ---------------------------------------------------------------------------

@router.get("/domains/{domain}/databases")
def list_databases(_: Auth, domain: str) -> dict:
    """List databases owned by this virtual server."""
    _check_domain(domain)
    rc, out, err = _vmin("list-databases", "--domain", domain, "--multiline")
    if rc != 0:
        raise HTTPException(status_code=502, detail=err.strip() or "virtualmin list-databases failed")

    dbs: list[dict] = []
    current: dict | None = None
    for raw in out.splitlines():
        if not raw.strip():
            if current is not None:
                dbs.append(current); current = None
            continue
        if not raw.startswith(" ") and not raw.startswith("\t"):
            if current is not None:
                dbs.append(current)
            current = {"name": raw.strip(), "raw": {}}
        elif current is not None and ":" in raw:
            k, _, v = raw.strip().partition(":")
            current["raw"][k.strip()] = v.strip()
    if current is not None:
        dbs.append(current)

    projected = [{
        "name":  d["name"],
        "type":  d["raw"].get("Type") or d["raw"].get("Database type") or "",
        "size_mb": _to_mb(d["raw"].get("Size") or d["raw"].get("Disk usage") or ""),
        "user":  d["raw"].get("Owner") or d["raw"].get("Username") or "",
    } for d in dbs]
    return {"domain": domain, "databases": projected, "count": len(projected)}


def _to_mb(s: str) -> int | None:
    s = (s or "").strip().lower()
    if not s or s in ("none", "—", "-"):
        return None
    m = re.match(r"([0-9.]+)\s*(kb|mb|gb|tb|b)?", s)
    if not m:
        return None
    try:
        v = float(m.group(1))
        unit = (m.group(2) or "b")
        mult = {"b": 1/(1024*1024), "kb": 1/1024, "mb": 1, "gb": 1024, "tb": 1024*1024}[unit]
        return int(v * mult)
    except (ValueError, KeyError):
        return None


# ---------------------------------------------------------------------------
# Per-domain DNS records
# ---------------------------------------------------------------------------

@router.get("/domains/{domain}/dns")
def get_dns(_: Auth, domain: str) -> dict:
    """Return the DNS zone for this domain as parsed records."""
    _check_domain(domain)
    rc, out, err = _vmin("get-dns", "--domain", domain, "--multiline")
    if rc != 0:
        raise HTTPException(status_code=502, detail=err.strip() or "virtualmin get-dns failed")

    records: list[dict] = []
    for raw in out.splitlines():
        line = raw.strip()
        if not line or line.startswith(";") or line.startswith("$"):
            continue
        # Standard BIND record: NAME [TTL] CLASS TYPE RDATA
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        # Heuristic: if second token is a number it's TTL; class is usually 'IN'
        name = parts[0]
        idx = 1
        ttl = None
        if parts[idx].isdigit():
            ttl = int(parts[idx]); idx += 1
        cls = parts[idx] if idx < len(parts) else ""; idx += 1
        rtype = parts[idx] if idx < len(parts) else ""; idx += 1
        rdata = " ".join(parts[idx:]) if idx < len(parts) else ""
        if not rtype:
            continue
        records.append({"name": name, "ttl": ttl, "class": cls, "type": rtype, "value": rdata})

    return {"domain": domain, "records": records, "count": len(records)}
