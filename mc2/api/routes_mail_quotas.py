"""
Per-mailbox disk quota management.

**No virtualmin shellouts.** Mailbox users come from `pwd.getpwall()`
filtered to each domain owner (`system_state.list_users_for_domain`).
Quota usage is read from `repquota` and written with `setquota` — both
operate on the kernel quota subsystem directly.
"""
from __future__ import annotations

import csv
import io
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from mc2.auth import TokenPayload, require_super_admin
from mc2.services import system_state as state

router = APIRouter(prefix="/mail-quotas", tags=["mail-quotas"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

BLOCKS_PER_MB = 1024  # 1 quota block = 1 KiB


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _repquota_csv() -> list[dict[str, int]]:
    """Parse `repquota -a -u --output=csv` once and return per-user rows."""
    rc, out, _err = _run(["sudo", "repquota", "-a", "-u", "--output=csv"])
    if rc != 0 or not out:
        return []
    reader = csv.DictReader(io.StringIO(out))
    rows: list[dict[str, int]] = []
    for row in reader:
        name = list(row.values())[0]  # first column is username
        try:
            rows.append({
                "username":   name,
                "block_used": int(row.get("BlockUsed", 0) or 0),
                "block_soft": int(row.get("BlockSoftLimit", 0) or 0),
                "block_hard": int(row.get("BlockHardLimit", 0) or 0),
            })
        except ValueError:
            continue
    return rows


@router.get("")
def list_quotas(_: Auth, domain: str | None = None):
    """List mailbox users for one or every domain with their quota usage."""
    domains = (
        [state.get_domain(domain)] if domain else state.list_domains()
    )
    domains = [d for d in domains if d is not None]

    rep_index = {r["username"]: r for r in _repquota_csv()}

    users: list[dict] = []
    for d in domains:
        for su in state.list_users_for_domain(d.owner_user, d.domain):
            r = rep_index.get(su.username)
            block_used = (r or {}).get("block_used", 0)
            block_hard = (r or {}).get("block_hard", 0)
            quota_mb = None if block_hard == 0 else round(block_hard / BLOCKS_PER_MB, 2)
            used_mb  = round(block_used / BLOCKS_PER_MB, 2)
            users.append({
                "username":       su.username,
                "email":          state.email_address_for(su.username, d.owner_user, d.domain),
                "domain":         d.domain,
                "quota_mb":       quota_mb,
                "used_mb":        used_mb,
                "used_bytes":     block_used * 1024,
                "unlimited":      block_hard == 0,
                "home_directory": su.home,
                "user_type":      "",
                "disabled":       su.shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"),
            })

    users.sort(key=lambda u: (u["domain"], u["username"]))
    return {"users": users, "total": len(users)}


class QuotaUpdate(BaseModel):
    domain: str
    username: str
    quota_mb: float | None = None  # None = unlimited (0 blocks)


@router.put("")
def set_quota(payload: QuotaUpdate, _: Auth):
    """Set or remove the kernel disk quota for a mailbox user (`setquota`)."""
    if payload.quota_mb is not None and payload.quota_mb < 0:
        raise HTTPException(400, "quota_mb must be >= 0 (use null for unlimited)")
    blocks = 0 if payload.quota_mb is None else int(payload.quota_mb * BLOCKS_PER_MB)

    rc, _out, err = _run(["sudo", "setquota", "-u", payload.username,
                          str(blocks), str(blocks), "0", "0", "/"])
    if rc != 0:
        raise HTTPException(500, err or "setquota failed")
    return {
        "ok": True,
        "username": payload.username,
        "quota_mb": payload.quota_mb,
        "unlimited": payload.quota_mb is None,
    }
