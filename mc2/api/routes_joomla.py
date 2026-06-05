"""
Joomla Fleet Manager — auto-discovers every Joomla install on this host
and surfaces version / extensions / per-type counts to the
`/webops/joomla` UI.

Backs `mc2-backend#85`. Implementation is a thin wrapper around the
`mc2-joomla-scan` helper script (from frothiq-infra:bin/), installed at
/usr/local/sbin/mc2-joomla-scan with a single sudoers grant in
/etc/sudoers.d/mc2-sysops.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/joomla", tags=["joomla"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

_SCAN_BIN = "/usr/local/sbin/mc2-joomla-scan"
_TIMEOUT_S = 60


def _run_scan_sync() -> dict:
    r = subprocess.run(
        ["sudo", "-n", _SCAN_BIN],
        capture_output=True, text=True, timeout=_TIMEOUT_S,
    )
    if r.returncode != 0:
        raise HTTPException(
            status_code=502,
            detail=f"mc2-joomla-scan failed (rc={r.returncode}): {(r.stderr or r.stdout)[:300]}"
        )
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=502,
            detail=f"mc2-joomla-scan returned invalid JSON: {e}; first 200 bytes: {r.stdout[:200]!r}"
        )


def _summarize(installs: list[dict]) -> dict:
    versions: dict[str, int] = {}
    for i in installs:
        v = i.get("version") or "unknown"
        versions[v] = versions.get(v, 0) + 1
    return {
        "total":             len(installs),
        "by_version":        versions,
        "total_components":  sum(i.get("component_count", 0) for i in installs),
        "total_modules":     sum(i.get("module_count", 0) for i in installs),
        "total_plugins":     sum(i.get("plugin_count", 0) for i in installs),
        "total_templates":   sum(i.get("template_count", 0) for i in installs),
        "with_errors":       sum(1 for i in installs if i.get("error") or i.get("db_error")),
        "with_debug":        sum(1 for i in installs if i.get("debug")),
        "with_offline":      sum(1 for i in installs if i.get("offline")),
    }


@router.get("")
async def list_joomla_installs(_: Auth) -> dict:
    """Discover every Joomla install on this host."""
    data = await asyncio.to_thread(_run_scan_sync)
    installs = data.get("installs", [])
    return {"installs": installs, "summary": _summarize(installs)}
