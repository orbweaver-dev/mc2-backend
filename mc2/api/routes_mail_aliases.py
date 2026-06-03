"""
Email alias / forwarding manager.

**No virtualmin shellouts.** Reads `/etc/postfix/virtual` directly and
mutates it with `postmap` after each change. See
`feedback_mc2_replaces_webmin_virtualmin`.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from mc2.auth import TokenPayload, require_super_admin
from mc2.services import system_state as state

router = APIRouter(prefix="/mail-aliases", tags=["mail-aliases"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

POSTFIX_VIRTUAL = Path("/etc/postfix/virtual")


# ---------------------------------------------------------------------------
# Postfix virtual-map mutator
# ---------------------------------------------------------------------------

_ENTRY_RE = re.compile(r"^\s*([^#\s][^\s]*)\s+(.+?)\s*$")


def _rewrite_virtual_map(mutate) -> None:
    """
    Read /etc/postfix/virtual, hand the line list to a mutator, write back
    atomically, then run `postmap` to rebuild the hash.

    The mutator receives the existing list of lines (strings, no trailing
    newline) and must return the new list. Comments and blank lines are
    preserved by callers — the mutator should pass them through unchanged.
    """
    try:
        original = POSTFIX_VIRTUAL.read_text(errors="replace")
    except OSError as exc:
        raise HTTPException(502, f"Cannot read {POSTFIX_VIRTUAL}: {exc}")

    new_lines = mutate(original.splitlines())
    new_text = "\n".join(new_lines)
    if not new_text.endswith("\n"):
        new_text += "\n"

    # Atomic replace via tempfile in the same dir
    parent = POSTFIX_VIRTUAL.parent
    with tempfile.NamedTemporaryFile("w", dir=parent, delete=False,
                                     prefix=".virtual.tmp.") as tmp:
        tmp.write(new_text)
        tmp_path = Path(tmp.name)

    # The Postfix dir is root-owned; use sudo install for the move + chown
    rc = subprocess.run(
        ["sudo", "install", "-m", "0644", "-o", "root", "-g", "root",
         str(tmp_path), str(POSTFIX_VIRTUAL)],
        capture_output=True, text=True, timeout=10,
    )
    try:
        tmp_path.unlink(missing_ok=True)
    except OSError:
        pass
    if rc.returncode != 0:
        raise HTTPException(502,
            f"Failed to install new {POSTFIX_VIRTUAL}: {rc.stderr.strip() or rc.stdout.strip()}")

    pm = subprocess.run(["sudo", "postmap", str(POSTFIX_VIRTUAL)],
                        capture_output=True, text=True, timeout=15)
    if pm.returncode != 0:
        raise HTTPException(502,
            f"postmap failed: {pm.stderr.strip() or pm.stdout.strip()}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
def list_aliases(_: Auth, domain: str | None = None):
    """List every mail alias, optionally filtered to one domain."""
    aliases = state.list_postfix_aliases(domain)
    # Strip the internal from_local field — UI only needs domain, from_address, to_addresses.
    out = [{"domain": a["domain"], "from_address": a["from_address"], "to_addresses": a["to_addresses"]}
           for a in aliases]
    return {"aliases": out, "total": len(out)}


@router.get("/domains")
def list_domains(_: Auth):
    """List every domain MC² knows about (from Apache configs, not virtualmin)."""
    return {"domains": [d.domain for d in state.list_domains()]}


class AliasCreate(BaseModel):
    domain: str
    from_local: str          # local-part only (before @)
    to_addresses: list[str]  # full email addresses


@router.post("", status_code=201)
def create_alias(payload: AliasCreate, _: Auth):
    """Append a new alias to /etc/postfix/virtual."""
    from_local = payload.from_local.strip().lower()
    if not from_local or not payload.domain:
        raise HTTPException(400, "from_local and domain are required")
    if not payload.to_addresses:
        raise HTTPException(400, "at least one to_address required")

    from_addr = f"{from_local}@{payload.domain}"
    targets = ", ".join(t.strip() for t in payload.to_addresses if t.strip())

    def mutate(lines):
        # Refuse duplicates — if from_addr already exists, fail.
        for ln in lines:
            m = _ENTRY_RE.match(ln)
            if m and m.group(1) == from_addr:
                raise HTTPException(409, f"Alias {from_addr!r} already exists")
        return lines + [f"{from_addr}\t{targets}"]

    _rewrite_virtual_map(mutate)
    return {"ok": True, "from_address": from_addr}


class ForwardingUpdate(BaseModel):
    domain: str
    from_local: str
    to_addresses: list[str]


@router.put("")
def update_alias(payload: ForwardingUpdate, _: Auth):
    """Replace an alias's destination list in-place."""
    from_local = payload.from_local.strip().lower()
    from_addr = f"{from_local}@{payload.domain}"
    targets = ", ".join(t.strip() for t in payload.to_addresses if t.strip())

    def mutate(lines):
        found = False
        out = []
        for ln in lines:
            m = _ENTRY_RE.match(ln)
            if m and m.group(1) == from_addr:
                out.append(f"{from_addr}\t{targets}")
                found = True
            else:
                out.append(ln)
        if not found:
            raise HTTPException(404, f"Alias {from_addr!r} not found")
        return out

    _rewrite_virtual_map(mutate)
    return {"ok": True}


@router.delete("/{domain}/{from_local}")
def delete_alias(domain: str, from_local: str, _: Auth):
    """Remove the matching line from /etc/postfix/virtual."""
    from_addr = f"{from_local}@{domain}"

    def mutate(lines):
        found = False
        out = []
        for ln in lines:
            m = _ENTRY_RE.match(ln)
            if m and m.group(1) == from_addr:
                found = True
                continue
            out.append(ln)
        if not found:
            raise HTTPException(404, f"Alias {from_addr!r} not found")
        return out

    _rewrite_virtual_map(mutate)
    return {"ok": True}
