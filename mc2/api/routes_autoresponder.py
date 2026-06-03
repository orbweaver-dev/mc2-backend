"""
Email Autoresponder / Vacation Manager — Dovecot Sieve backend.

Owns per-mailbox vacation behaviour by managing `~/sieve/vacation.sieve`
files and the `~/.dovecot.sieve` active symlink. Delivery is performed by
`dovecot-lda` (Postfix mailbox_command), which loads the sieve plugin and
runs the active script at delivery time.

No virtualmin shellouts — direct system-state reads/writes per
[mc2#80](https://github.com/orbweaver-dev/mc2-backend/issues/80).

Closes TASK-2026-00341.
"""

from __future__ import annotations

import math
import os
import pwd
import re
import subprocess
import tempfile
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from mc2.auth import TokenPayload, require_super_admin
from mc2.services import system_state as state

router = APIRouter(prefix="/autoresponder", tags=["autoresponder"])

Auth = Annotated[TokenPayload, Depends(require_super_admin)]


# ── shell helpers ────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def _sudo_readlink(path: str) -> str | None:
    rc, out, _ = _run(["sudo", "readlink", path])
    return out.strip() if rc == 0 and out.strip() else None


def _sudo_cat(path: str) -> str | None:
    rc, out, _ = _run(["sudo", "cat", path])
    return out if rc == 0 else None


# ── Sieve render / parse ─────────────────────────────────────────────────────

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?$")


def _sieve_escape(s: str) -> str:
    """Sieve string literal — backslash-escape `\\` and `"`."""
    return s.replace("\\", "\\\\").replace("\"", "\\\"")


def _iso_z(s: str) -> str:
    """Normalise an operator-supplied date(time) to ISO 8601 UTC for currentdate."""
    if "T" in s or " " in s:
        return s.replace(" ", "T").rstrip("Z") + "Z"
    return f"{s}T00:00:00Z"


def _render_vacation_sieve(
    *,
    email: str,
    message: str,
    days: int,
    subject: str | None,
    start: str | None,
    end: str | None,
) -> str:
    body = _sieve_escape(message)
    addr = _sieve_escape(email)
    days = max(1, int(days))

    parts = ["require [\"vacation\""]
    if start or end:
        parts[0] += ", \"date\", \"relational\""
    parts[0] += "];\n"

    vacation = (
        "vacation\n"
        f"  :days {days}\n"
    )
    if subject:
        vacation += f'  :subject "{_sieve_escape(subject)}"\n'
    vacation += f'  :addresses ["{addr}"]\n'
    vacation += f'  "{body}";\n'

    if start or end:
        conds = []
        if start:
            conds.append(f'currentdate :value "ge" "iso8601" "{_iso_z(start)}"')
        if end:
            conds.append(f'currentdate :value "le" "iso8601" "{_iso_z(end)}"')
        joined = ",\n    ".join(conds)
        guard = f"if allof (\n    {joined}\n) {{\n  {vacation.rstrip()}\n}}\n"
        return parts[0] + guard

    return parts[0] + vacation


_VAC_DAYS_RE = re.compile(r":days\s+(\d+)")
_VAC_SUBJ_RE = re.compile(r':subject\s+"((?:[^"\\]|\\.)*)"')
_VAC_BODY_RE = re.compile(r'\]\s*"((?:[^"\\]|\\.)*)"\s*;', re.DOTALL)
_DATE_GE_RE = re.compile(r'currentdate\s+:value\s+"ge"\s+"iso8601"\s+"([^"]+)"')
_DATE_LE_RE = re.compile(r'currentdate\s+:value\s+"le"\s+"iso8601"\s+"([^"]+)"')


def _parse_vacation_sieve(text: str) -> dict:
    def unesc(s: str) -> str:
        return s.replace('\\"', '"').replace("\\\\", "\\")

    days_m = _VAC_DAYS_RE.search(text)
    subj_m = _VAC_SUBJ_RE.search(text)
    body_m = _VAC_BODY_RE.search(text)
    start_m = _DATE_GE_RE.search(text)
    end_m = _DATE_LE_RE.search(text)
    return {
        "message": unesc(body_m.group(1)) if body_m else "",
        "subject": unesc(subj_m.group(1)) if subj_m else None,
        "period_seconds": int(days_m.group(1)) * 86400 if days_m else None,
        "start": start_m.group(1) if start_m else None,
        "end": end_m.group(1) if end_m else None,
    }


# ── mailbox enumeration ──────────────────────────────────────────────────────

def _mailboxes() -> list[dict]:
    """Yield every per-domain mailbox (Virtualmin layout: `<user>@<domain>` Unix
    accounts whose home is under `/home/<domain>/homes/<user>`)."""
    out: list[dict] = []
    for d in state.list_domains():
        for u in state.list_users_for_domain(d.owner, d.domain):
            home = u.home or ""
            if not home.startswith(f"/home/{d.domain}/homes/"):
                continue
            email = u.username if "@" in u.username else f"{u.username}@{d.domain}"
            out.append({
                "email": email,
                "user": u.username,
                "domain": d.domain,
                "home": home,
                "real_name": u.gecos or None,
            })
    return out


def _autoreply_state_for(mailbox: dict) -> dict:
    """Inspect ~/.dovecot.sieve symlink. Returns enabled + body details."""
    home = mailbox["home"]
    active = _sudo_readlink(f"{home}/.dovecot.sieve")
    if not active or not active.endswith("/sieve/vacation.sieve"):
        return {"enabled": False, "message": "", "subject": None,
                "start": None, "end": None, "period_seconds": None}
    body = _sudo_cat(f"{home}/sieve/vacation.sieve")
    if not body:
        return {"enabled": False, "message": "", "subject": None,
                "start": None, "end": None, "period_seconds": None}
    return {"enabled": True, **_parse_vacation_sieve(body)}


def _resolve(email: str) -> dict:
    """Look up a mailbox by `<user>@<domain>` email."""
    user, _, domain = email.partition("@")
    if not user or not domain:
        raise HTTPException(status_code=400, detail="invalid email")
    try:
        pw = pwd.getpwnam(email)
    except KeyError as e:
        raise HTTPException(status_code=404, detail="mailbox not found") from e
    home = pw.pw_dir
    if not home.startswith(f"/home/{domain}/homes/"):
        raise HTTPException(status_code=404, detail="mailbox not in expected layout")
    return {
        "email": email,
        "user": user,
        "domain": domain,
        "home": home,
        "uid": pw.pw_uid,
        "gid": pw.pw_gid,
        "real_name": pw.pw_gecos or None,
    }


# ── sieve write / activate / clear ───────────────────────────────────────────

def _ensure_sieve_dir(mailbox: dict) -> str:
    sieve_dir = f"{mailbox['home']}/sieve"
    rc, _, err = _run(["sudo", "mkdir", "-p", sieve_dir])
    if rc != 0:
        raise HTTPException(status_code=500, detail=f"mkdir sieve: {err[:200]}")
    rc, _, err = _run(["sudo", "chown", f"{mailbox['email']}:{mailbox['email'].split('@')[1]}", sieve_dir])
    if rc != 0:
        raise HTTPException(status_code=500, detail=f"chown sieve: {err[:200]}")
    return sieve_dir


def _install_vacation(mailbox: dict, sieve_text: str) -> None:
    sieve_dir = _ensure_sieve_dir(mailbox)
    sieve_path = f"{sieve_dir}/vacation.sieve"
    group = mailbox["email"].split("@", 1)[1]

    tf = tempfile.NamedTemporaryFile(
        mode="w", dir="/tmp", prefix="mc2-sieve-", suffix=".sieve", delete=False
    )
    try:
        tf.write(sieve_text)
        tf.flush()
        tmp = tf.name
    finally:
        tf.close()
    try:
        os.chmod(tmp, 0o644)
        rc, _, err = _run([
            "sudo", "install", "-m", "0644",
            "-o", mailbox["email"], "-g", group,
            tmp, sieve_path,
        ])
        if rc != 0:
            raise HTTPException(status_code=500, detail=f"install vacation.sieve: {err[:200]}")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    # Stale compiled binary — let Dovecot recompile on next delivery
    _run(["sudo", "rm", "-f", f"{mailbox['home']}/.dovecot.sieve.bin"])

    # Activate
    active = f"{mailbox['home']}/.dovecot.sieve"
    rc, _, err = _run(["sudo", "ln", "-sfn", sieve_path, active])
    if rc != 0:
        raise HTTPException(status_code=500, detail=f"activate .dovecot.sieve: {err[:200]}")


def _clear_vacation(mailbox: dict) -> None:
    home = mailbox["home"]
    for p in (f"{home}/.dovecot.sieve", f"{home}/.dovecot.sieve.bin",
              f"{home}/sieve/vacation.sieve"):
        _run(["sudo", "rm", "-f", p])


# ── routes ───────────────────────────────────────────────────────────────────

@router.get("")
def autoresponder_index(_: Auth):
    boxes = _mailboxes()
    out: list[dict] = []
    for mb in boxes:
        st = _autoreply_state_for(mb)
        out.append({
            "email": mb["email"],
            "user": mb["user"],
            "domain": mb["domain"],
            "real_name": mb["real_name"],
            **st,
        })
    out.sort(key=lambda u: (u["domain"], u["email"]))
    return {
        "users": out,
        "summary": {
            "total": len(out),
            "active": sum(1 for u in out if u["enabled"]),
        },
        "errors": [],
    }


@router.get("/{email}")
def autoresponder_show(email: str, _: Auth):
    mb = _resolve(email)
    st = _autoreply_state_for(mb)
    return {"email": email, "real_name": mb["real_name"], **st}


class AutoreplyUpdate(BaseModel):
    enabled: bool
    message: str | None = None
    subject: str | None = None
    start: str | None = None       # yyyy-mm-dd[Thh:mm[:ss]]
    end: str | None = None
    period_seconds: int | None = None  # mapped to :days (rounded up, min 1)


@router.put("/{email}")
def autoresponder_update(email: str, body: AutoreplyUpdate, _: Auth):
    mb = _resolve(email)

    if not body.enabled:
        _clear_vacation(mb)
        return autoresponder_show(email, _)  # type: ignore[arg-type]

    if not (body.message and body.message.strip()):
        raise HTTPException(status_code=400, detail="message is required when enabling")
    for f, v in (("start", body.start), ("end", body.end)):
        if v and not _DATE_RE.match(v):
            raise HTTPException(status_code=400, detail=f"{f} must be yyyy-mm-dd[Thh:mm[:ss]]")

    days = math.ceil((body.period_seconds or 86400) / 86400)
    sieve_text = _render_vacation_sieve(
        email=email,
        message=body.message,
        days=days,
        subject=body.subject,
        start=body.start,
        end=body.end,
    )
    _install_vacation(mb, sieve_text)
    return autoresponder_show(email, _)  # type: ignore[arg-type]
