"""
Virtual server (vhost) routes for the WebOps `/webops/vhost/[domain]/*` UI.

**No virtualmin / webmin shellouts.** Every read comes from the underlying
system directly — Apache configs, /etc/passwd, MariaDB, Postfix maps, BIND
zones. See `feedback_mc2_replaces_webmin_virtualmin` for the architecture
rule and `services/system_state.py` for the readers.

Mutations (create/modify/delete mailbox) still use the canonical OS tools
(`useradd`, `usermod`, `setquota`, `postmap`) — those interfaces are stable
and OS-native, not Virtualmin-specific.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from mc2.auth import TokenPayload, require_super_admin
from mc2.services import system_state as state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vhost", tags=["vhost"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

_DOMAIN_RE   = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_USERNAME_RE = re.compile(r"^[a-z0-9._-]{1,64}$")


def _check_domain(domain: str) -> str:
    if not _DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail=f"Invalid domain name: {domain!r}")
    return domain


def _check_username(name: str) -> str:
    if not _USERNAME_RE.match(name):
        raise HTTPException(status_code=400, detail=f"Invalid mailbox name: {name!r}")
    return name


def _cheap_features_for(d: state.DomainRecord) -> list[str]:
    """
    Per-row feature chips for the vhost picker.

    Only emits flags that are free from already-parsed Apache config —
    `web` (any port) and `ssl` (port 443 / SSLEngine on). Mail / DNS /
    MariaDB probes were each costing a sudo+CLI shellout per domain
    (~1.5s × 30 domains × 3 sources ≈ 100s wall), turning the picker
    back into a multi-second page. The per-domain dashboard runs the
    expensive probes once when the operator drills in.
    """
    feats = []
    if d.has_http or d.has_https:
        feats.append("web")
    if d.ssl_enabled:
        feats.append("ssl")
    return feats


def _full_features_for(d: state.DomainRecord) -> list[str]:
    """
    Comprehensive feature list — used by the per-domain dashboard, never
    by the picker. Each probe wrapped in try/except so a single
    unreadable source can't 500 the request.
    """
    feats = _cheap_features_for(d)
    try:
        if state.list_postfix_aliases(d.domain) or _has_mailboxes(d.owner_user, d.domain):
            feats.append("mail")
    except Exception as exc:
        logger.warning("features mail check failed for %s: %s", d.domain, exc)
    try:
        if state._find_zone_file(d.domain) is not None:
            feats.append("dns")
    except Exception as exc:
        logger.warning("features dns check failed for %s: %s", d.domain, exc)
    try:
        if state.list_mariadb_databases_for(d.owner_user):
            feats.append("mysql")
    except Exception as exc:
        logger.warning("features mysql check failed for %s: %s", d.domain, exc)
    return feats


def _has_mailboxes(owner: str, domain: str) -> bool:
    return any(u.username != owner for u in state.list_users_for_domain(owner, domain))


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------

@router.get("/domains")
def list_domains(_: Auth) -> dict:
    """List every virtual server by parsing Apache vhost configs directly."""
    rows = state.list_domains()
    domains = [{
        "domain":    d.domain,
        "type":      "alias" if d.parent else "server",
        "user":      d.owner_user,
        "ip":        d.ip,
        "ip6":       d.ip6,
        "home":      d.docroot,
        "template":  "",
        "plan":      "",
        "parent":    d.parent,
        "quota_mb":  None,
        "features":  _cheap_features_for(d),
    } for d in rows]
    return {"domains": domains, "count": len(domains)}


@router.get("/domains/{domain}")
def domain_info(_: Auth, domain: str) -> dict:
    """Detailed info for one domain. Backs the vhost dashboard."""
    _check_domain(domain)
    d = state.get_domain(domain)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Domain not found: {domain}")
    return {
        "domain":          d.domain,
        "user":            d.owner_user,
        "type":            "alias" if d.parent else "server",
        "ip":              d.ip,
        "ip6":             d.ip6,
        "home":            d.docroot,
        "template":        "",
        "plan":            "",
        "parent":          d.parent,
        "creation_time":   "",
        "quota_mb":        None,
        "used_quota_mb":   None,
        "bandwidth_used_mb": None,
        "features":        _full_features_for(d),
        "ssl_expiry":      "",
        "config_file":     d.config_file,
        "access_log":      d.access_log,
        "error_log":       d.error_log,
        "aliases":         d.aliases,
    }


# ---------------------------------------------------------------------------
# Mailbox / system users
# ---------------------------------------------------------------------------

@router.get("/domains/{domain}/users")
def list_users(_: Auth, domain: str) -> dict:
    """List system users associated with this domain (mailbox-style accounts)."""
    _check_domain(domain)
    d = state.get_domain(domain)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Domain not found: {domain}")

    users = []
    for u in state.list_users_for_domain(d.owner_user, d.domain):
        users.append({
            "username":      u.username,
            "email":         state.email_address_for(u.username, d.owner_user, d.domain),
            "real_name":     u.real_name,
            "mail":          True,   # presence of an account under the owner = mail-capable
            "ftp":           u.shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", ""),
            "databases":     "",
            "quota":         "",
            "uid":           str(u.uid),
            "shell":         u.shell,
            "home":          u.home,
            "extra_aliases": [],
        })
    return {"domain": domain, "users": users, "count": len(users)}


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def _mailbox_username(domain_owner: str, local: str) -> str:
    """Mailbox login = `<owner>.<local>` — virtualmin's convention preserved
    so existing mailboxes stay addressable. The mailbox at adinflux@adinflux.com
    is the owner itself; everything else gets `adinflux.<local>`."""
    if local == "admin":
        return domain_owner
    return f"{domain_owner}.{local}"


class CreateMailbox(BaseModel):
    username:   str = Field(..., min_length=1, max_length=64)
    password:   str = Field(..., min_length=4)
    real_name:  str = Field("", max_length=128)
    quota_mb:   int | None = Field(None, ge=0)
    enable_ftp: bool = False


@router.post("/domains/{domain}/users", status_code=201)
def create_mailbox(_: Auth, domain: str, body: CreateMailbox) -> dict:
    """Create a system user serving as a mailbox under this domain."""
    _check_domain(domain)
    _check_username(body.username)
    d = state.get_domain(domain)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Domain not found: {domain}")
    if not d.owner_user:
        raise HTTPException(status_code=502, detail="Could not determine domain owner from docroot")

    login = _mailbox_username(d.owner_user, body.username)
    home  = f"{d.docroot.rstrip('/')}/homes/{body.username}"
    shell = "/usr/sbin/nologin" if not body.enable_ftp else "/bin/bash"

    args = ["sudo", "useradd",
            "-m", "-d", home,
            "-g", d.owner_user,
            "-s", shell,
            "-c", body.real_name.strip(),
            login]
    rc, out, err = _run(args)
    if rc != 0:
        detail = (err or out).strip() or "useradd failed"
        raise HTTPException(status_code=502, detail=detail)

    # Set password via `chpasswd` (more script-friendly than `passwd`)
    rc, _o, err = _run(["sudo", "chpasswd"], timeout=10)
    # Re-run with stdin since _run doesn't pipe — fall back to a direct stream:
    try:
        r = subprocess.run(["sudo", "chpasswd"], input=f"{login}:{body.password}\n",
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise HTTPException(status_code=502, detail=(r.stderr or "chpasswd failed").strip())
    except subprocess.SubprocessError as exc:
        raise HTTPException(status_code=502, detail=f"chpasswd error: {exc}")

    # Set mail quota (block quota in MB → 1KiB blocks)
    if body.quota_mb is not None and body.quota_mb > 0:
        blocks = body.quota_mb * 1024
        rc, _o, err = _run(["sudo", "setquota", "-u", login,
                            str(blocks), str(blocks), "0", "0", "/"])
        if rc != 0:
            logger.warning("setquota failed for %s: %s", login, err.strip())

    return {"ok": True, "username": body.username, "login": login, "domain": domain}


class ModifyMailbox(BaseModel):
    password:    str | None = Field(None, min_length=4)
    real_name:   str | None = Field(None, max_length=128)
    quota_mb:    int | None = Field(None, ge=0)
    enable_mail: bool | None = None
    enable_ftp:  bool | None = None


@router.put("/domains/{domain}/users/{username}")
def modify_mailbox(_: Auth, domain: str, username: str, body: ModifyMailbox) -> dict:
    """Update mailbox attributes via usermod / chpasswd / setquota."""
    _check_domain(domain)
    _check_username(username)
    d = state.get_domain(domain)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Domain not found: {domain}")

    login = username if username == d.owner_user or username.startswith(f"{d.owner_user}.") \
            else _mailbox_username(d.owner_user, username)

    if body.real_name is not None:
        rc, _o, err = _run(["sudo", "usermod", "-c", body.real_name.strip(), login])
        if rc != 0:
            raise HTTPException(status_code=502, detail=(err or "usermod failed").strip())

    if body.enable_ftp is not None:
        shell = "/bin/bash" if body.enable_ftp else "/usr/sbin/nologin"
        rc, _o, err = _run(["sudo", "usermod", "-s", shell, login])
        if rc != 0:
            raise HTTPException(status_code=502, detail=(err or "usermod -s failed").strip())

    if body.password:
        r = subprocess.run(["sudo", "chpasswd"], input=f"{login}:{body.password}\n",
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise HTTPException(status_code=502, detail=(r.stderr or "chpasswd failed").strip())

    if body.quota_mb is not None:
        blocks = body.quota_mb * 1024
        rc, _o, err = _run(["sudo", "setquota", "-u", login,
                            str(blocks), str(blocks), "0", "0", "/"])
        if rc != 0:
            raise HTTPException(status_code=502, detail=(err or "setquota failed").strip())

    return {"ok": True, "username": username, "login": login, "domain": domain}


@router.delete("/domains/{domain}/users/{username}")
def delete_mailbox(_: Auth, domain: str, username: str) -> dict:
    """Remove the system user backing this mailbox (`userdel -r`)."""
    _check_domain(domain)
    _check_username(username)
    d = state.get_domain(domain)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Domain not found: {domain}")
    if username == d.owner_user:
        raise HTTPException(status_code=400, detail="Cannot delete the domain owner via this endpoint")

    login = username if username.startswith(f"{d.owner_user}.") \
            else _mailbox_username(d.owner_user, username)

    rc, out, err = _run(["sudo", "userdel", "-r", login], timeout=60)
    if rc != 0:
        detail = (err or out).strip() or "userdel failed"
        raise HTTPException(status_code=502, detail=detail)
    return {"ok": True, "username": username, "login": login, "domain": domain}


# ---------------------------------------------------------------------------
# Databases (read directly from MariaDB; no virtualmin)
# ---------------------------------------------------------------------------

@router.get("/domains/{domain}/databases")
def list_databases(_: Auth, domain: str) -> dict:
    """List MariaDB databases owned by this virtual server's Unix user."""
    _check_domain(domain)
    d = state.get_domain(domain)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Domain not found: {domain}")
    rows = state.list_mariadb_databases_for(d.owner_user)
    # `tables` / `files` / `used_by` aren't cheap to derive from raw SQL on every
    # call and weren't always populated by the old virtualmin path either —
    # leave them as None until a follow-up adds the queries.
    for r in rows:
        r.setdefault("tables", None)
        r.setdefault("files", None)
        r.setdefault("used_by", "")
    return {"domain": domain, "databases": rows, "count": len(rows)}


# ---------------------------------------------------------------------------
# DNS (read directly from BIND zone files; no virtualmin)
# ---------------------------------------------------------------------------

@router.get("/domains/{domain}/dns")
def get_dns(_: Auth, domain: str) -> dict:
    """Return the BIND zone for this domain as parsed records."""
    _check_domain(domain)
    if state.get_domain(domain) is None:
        raise HTTPException(status_code=404, detail=f"Domain not found: {domain}")
    records = state.list_dns_records(domain)
    return {"domain": domain, "records": records, "count": len(records)}
