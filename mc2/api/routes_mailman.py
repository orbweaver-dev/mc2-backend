"""
MailMan — operator-visible inventory of all mail accounts across all
Virtualmin domains on this server. Read-only enumeration; for actually
reading messages, operators use webmail (Roundcube) or an IMAP client.

Closes TASK-2026-00413: "Add MailMan menu item to MC² WebOps for checking
email for all users".
"""

from __future__ import annotations

import re
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from mc2.auth import require_super_admin, TokenPayload


router = APIRouter(prefix="/mailman", tags=["mailman"])

Auth = Annotated[TokenPayload, Depends(require_super_admin)]


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
	r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
	return r.returncode, r.stdout, r.stderr


def _vmin(*args: str) -> tuple[int, str, str]:
	return _run(["sudo", "virtualmin", *args])


def _list_domains() -> list[str]:
	# Reads from Apache vhost files via system_state — no virtualmin shellout.
	from mc2.services import system_state
	return [d.domain for d in system_state.list_domains()]


_SIZE_RE = re.compile(r"^([\d.]+)\s*([KMGT]?i?B)?$", re.I)


def _parse_size_to_bytes(s: str | None) -> int | None:
	if not s:
		return None
	m = _SIZE_RE.match(s.strip())
	if not m:
		return None
	n = float(m.group(1))
	unit = (m.group(2) or "").upper()
	mult = {"": 1, "B": 1, "KB": 1024, "KIB": 1024,
			"MB": 1024**2, "MIB": 1024**2,
			"GB": 1024**3, "GIB": 1024**3,
			"TB": 1024**4, "TIB": 1024**4}.get(unit, 1)
	return int(n * mult)


def _parse_mailbox_users(text: str) -> list[dict]:
	"""Parse multiline output of `virtualmin list-users --multiline`."""
	users: list[dict] = []
	current: dict | None = None
	for raw in text.splitlines():
		if not raw:
			continue
		if not raw.startswith("    "):
			# New record — top-level "user@domain"
			if current:
				users.append(current)
			current = {"key": raw.strip(), "raw": {}}
		else:
			# Indented attribute "    Field: Value"
			line = raw.strip()
			if ":" in line and current is not None:
				k, _, v = line.partition(":")
				current["raw"][k.strip()] = v.strip()
	if current:
		users.append(current)

	out: list[dict] = []
	for u in users:
		r = u["raw"]
		email = r.get("Email address") or u["key"]
		if not email or "@" not in email:
			continue  # FTP/db-only users
		quota_used_str = r.get("Home quota used") or ""
		quota_total_str = r.get("Home quota") or ""
		out.append({
			"email": email,
			"user": r.get("User"),
			"domain": r.get("Domain"),
			"real_name": r.get("Real name") or None,
			"disabled": (r.get("Disabled") or "").lower() == "yes",
			"mail_location": r.get("Mail location"),
			"home_dir": r.get("Home directory"),
			"quota_used": quota_used_str or None,
			"quota_used_bytes": _parse_size_to_bytes(quota_used_str),
			"quota_total": quota_total_str or None,
			"quota_total_bytes": _parse_size_to_bytes(quota_total_str),
			"spam_check": (r.get("Check spam and viruses") or "").lower() == "yes",
		})
	return out


@router.get("")
def mailman_index(_: Auth) -> dict:
	"""Enumerate every mail account across every Virtualmin domain.

	Single shelled-out call per domain — slow on large servers; client paginates.
	"""
	domains = _list_domains()
	all_users: list[dict] = []
	domain_counts: dict[str, int] = {}
	errors: list[str] = []

	for d in domains:
		rc, out, err = _vmin("list-users", "--domain", d, "--multiline")
		if rc != 0:
			errors.append(f"{d}: virtualmin rc={rc} {err[:120]}")
			continue
		users = _parse_mailbox_users(out)
		domain_counts[d] = len(users)
		all_users.extend(users)

	all_users.sort(key=lambda u: (u.get("domain") or "", u.get("email") or ""))
	totals = {
		"domains": len(domains),
		"mailboxes": len(all_users),
		"quota_used_bytes": sum((u.get("quota_used_bytes") or 0) for u in all_users),
	}
	return {
		"totals": totals,
		"domain_counts": domain_counts,
		"users": all_users,
		"errors": errors,
	}


@router.get("/domains")
def mailman_domains(_: Auth) -> dict:
	"""Just the domain list — cheap; useful for a domain selector before
	loading the full enumeration."""
	return {"domains": _list_domains()}


@router.get("/domain/{domain}")
def mailman_domain(domain: Annotated[str, ...], _: Auth) -> dict:
	rc, out, err = _vmin("list-users", "--domain", domain, "--multiline")
	if rc != 0:
		raise HTTPException(status_code=502, detail=f"virtualmin rc={rc}: {err[:200]}")
	users = _parse_mailbox_users(out)
	return {"domain": domain, "users": users, "count": len(users)}
