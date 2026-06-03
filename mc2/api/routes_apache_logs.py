"""
Per-domain Apache log viewer.

**No virtualmin shellouts.** Domain list comes from Apache vhost files via
`system_state.list_domains()`. Log file paths are taken from the parsed
`ErrorLog` / `CustomLog` directives in each vhost (so we follow whatever
the operator actually configured — typically `/var/log/virtualmin/<domain>_access_log`,
but it could be anything).
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from mc2.auth import TokenPayload, require_super_admin
from mc2.services import system_state as state

router = APIRouter(prefix="/apache-logs", tags=["apache-logs"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _log_pair_for(domain: str) -> tuple[Path | None, Path | None]:
    """Return (access_log_path, error_log_path) from the parsed vhost."""
    d = state.get_domain(domain)
    if d is None:
        return None, None
    return (Path(d.access_log) if d.access_log else None,
            Path(d.error_log)  if d.error_log  else None)


def _size_mb(p: Path | None) -> float:
    if not p or not p.exists():
        return 0
    try:
        return round(p.stat().st_size / (1024 * 1024), 2)
    except OSError:
        return 0


@router.get("/domains")
def list_log_domains(_: Auth):
    """One row per domain with its access / error log paths and sizes."""
    out = []
    for d in state.list_domains():
        access = Path(d.access_log) if d.access_log else None
        error  = Path(d.error_log)  if d.error_log  else None
        out.append({
            "domain":         d.domain,
            "access_log":     str(access) if access else "",
            "error_log":      str(error)  if error  else "",
            "access_exists":  bool(access and access.exists()),
            "error_exists":   bool(error  and error.exists()),
            "access_size_mb": _size_mb(access),
            "error_size_mb":  _size_mb(error),
        })
    return {"domains": out}


@router.get("/tail")
def tail_log(
    _: Auth,
    domain: str = Query(...),
    log_type: str = Query("access", pattern="^(access|error)$"),
    lines: int = Query(100, ge=10, le=2000),
    search: str | None = Query(None),
):
    """Tail the last N lines of the chosen domain's log, optional grep filter."""
    access, error = _log_pair_for(domain)
    log_file = access if log_type == "access" else error
    if log_file is None:
        raise HTTPException(404, f"Domain {domain!r} not found")
    if not log_file.exists():
        raise HTTPException(404, f"Log file not found: {log_file}")

    rc, out, err = _run(
        ["sudo", "tail", f"-{lines * 3 if search else lines}", str(log_file)],
        timeout=20,
    )
    if rc != 0:
        raise HTTPException(500, err or "Failed to read log")

    raw_lines = out.splitlines()
    if search:
        raw_lines = [ln for ln in raw_lines if search.lower() in ln.lower()]
    raw_lines = raw_lines[-lines:]
    raw_lines.reverse()

    return {
        "domain":   domain,
        "log_type": log_type,
        "log_file": str(log_file),
        "lines":    raw_lines,
        "count":    len(raw_lines),
    }
