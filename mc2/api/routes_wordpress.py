"""
WordPress Fleet Manager — auto-discovers every WP install on this host and
surfaces version / active theme / plugin counts / active plugins to the
`/webops/wordpress` UI.

Backs `mc2-backend#84`. Implementation is a thin wrapper around the
`mc2-wp-scan` helper script (from frothiq-infra:bin/) which does the
actual file + MariaDB inspection. The scanner ships in frothiq-infra and
is installed at /usr/local/sbin/mc2-wp-scan with a single sudoers grant
in /etc/sudoers.d/mc2-sysops.

No WP-CLI dependency — pure file + SQL reads.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/wordpress", tags=["wordpress"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

_SCAN_BIN = "/usr/local/sbin/mc2-wp-scan"
_TIMEOUT_S = 60


def _run_scan_sync() -> dict:
    r = subprocess.run(
        ["sudo", "-n", _SCAN_BIN],
        capture_output=True, text=True, timeout=_TIMEOUT_S,
    )
    if r.returncode != 0:
        raise HTTPException(
            status_code=502,
            detail=f"mc2-wp-scan failed (rc={r.returncode}): {(r.stderr or r.stdout)[:300]}"
        )
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=502,
            detail=f"mc2-wp-scan returned invalid JSON: {e}; first 200 bytes: {r.stdout[:200]!r}"
        )


def _summarize(installs: list[dict]) -> dict:
    versions: dict[str, int] = {}
    for i in installs:
        v = i.get("version") or "unknown"
        versions[v] = versions.get(v, 0) + 1
    return {
        "total":         len(installs),
        "by_version":    versions,
        "total_plugins": sum(i.get("plugin_count", 0) for i in installs),
        "total_themes":  sum(i.get("theme_count", 0) for i in installs),
        "with_errors":   sum(1 for i in installs if i.get("error") or i.get("db_error")),
        "with_multisite": sum(1 for i in installs if i.get("is_multisite")),
        "with_wp_debug":  sum(1 for i in installs if i.get("wp_debug")),
    }


@router.get("")
async def list_wp_installs(_: Auth) -> dict:
    """Discover every WordPress install on this host. Reads filesystem +
    options table for each; no WP-CLI required."""
    data = await asyncio.to_thread(_run_scan_sync)
    installs = data.get("installs", [])
    return {"installs": installs, "summary": _summarize(installs)}
