"""
DMARC Analyzer — per-vhost (per-domain) email-authentication posture.

Read-only analysis of a domain's DMARC / SPF / DKIM DNS records plus
parsing of any collected DMARC aggregate (RUA) reports. Passive DNS via
`dig`; no virtualmin shellouts (mc2 reads system state directly).

Lives under WebOps because DMARC is scoped to an individual virtual host.
"""

from __future__ import annotations

import glob
import gzip
import os
import re
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/dmarc", tags=["dmarc"])

Auth = Annotated[TokenPayload, Depends(require_super_admin)]

# Where a collector may deposit aggregate (rua) reports, per-domain or flat.
REPORT_DIRS = ["/var/lib/mc2/dmarc-reports", "/var/lib/frothiq/dmarc-reports"]

COMMON_SELECTORS = [
    "default", "mail", "google", "selector1", "selector2", "dkim",
    "smtp", "k1", "s1", "mx", "mandrill", "sig1", "fm1", "pic",
]

_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")


# ── DNS helpers ───────────────────────────────────────────────────────────────

def _dig_txt(name: str) -> list[str]:
    try:
        r = subprocess.run(["dig", "+short", "TXT", name],
                           capture_output=True, text=True, timeout=8)
    except Exception:
        return []
    out = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = re.findall(r'"([^"]*)"', line)   # dig quotes + may split long TXT
        out.append("".join(parts) if parts else line.strip('"'))
    return out


def _parse_tags(record: str) -> dict:
    tags: dict[str, str] = {}
    for kv in record.split(";"):
        kv = kv.strip()
        if "=" in kv:
            k, v = kv.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


# ── Analyzers ─────────────────────────────────────────────────────────────────

def _analyze_dmarc(domain: str) -> dict:
    records = [t for t in _dig_txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not records:
        return {"present": False, "record": None, "tags": {}, "policy": None,
                "rua": [], "ruf": [],
                "warnings": [f"No DMARC record at _dmarc.{domain} — the domain is "
                             "unprotected against spoofing."]}
    warnings: list[str] = []
    if len(records) > 1:
        warnings.append("Multiple DMARC records found — only one is allowed; the rest are ignored.")
    tags = _parse_tags(records[0])
    p = tags.get("p")
    if not p:
        warnings.append("No policy tag (p=) — the record is invalid.")
    elif p == "none":
        warnings.append("Policy is p=none (monitor only) — spoofed mail is not quarantined or rejected.")
    if "rua" not in tags:
        warnings.append("No rua= address — you will not receive aggregate reports.")
    pct = tags.get("pct")
    if pct and pct != "100":
        warnings.append(f"pct={pct} — the policy is only applied to {pct}% of mail.")
    return {
        "present": True, "record": records[0], "tags": tags,
        "policy": p, "subdomain_policy": tags.get("sp"),
        "pct": pct or "100", "adkim": tags.get("adkim", "r"),
        "aspf": tags.get("aspf", "r"),
        "rua": [a.strip() for a in tags.get("rua", "").split(",") if a.strip()],
        "ruf": [a.strip() for a in tags.get("ruf", "").split(",") if a.strip()],
        "warnings": warnings,
    }


def _analyze_spf(domain: str) -> dict:
    records = [t for t in _dig_txt(domain) if t.lower().startswith("v=spf1")]
    if not records:
        return {"present": False, "record": None, "mechanisms": [],
                "warnings": ["No SPF record — add `v=spf1 … -all` to authorize your senders."]}
    warnings: list[str] = []
    if len(records) > 1:
        warnings.append("Multiple SPF records — only one is allowed; SPF will permerror.")
    rec = records[0]
    if "+all" in rec:
        warnings.append("+all lets anyone send as your domain — remove it.")
    elif "?all" in rec:
        warnings.append("?all (neutral) gives no protection — use -all or ~all.")
    elif not re.search(r"[~\-]all", rec):
        warnings.append("No `all` mechanism — SPF is incomplete.")
    return {"present": True, "record": rec, "mechanisms": rec.split()[1:], "warnings": warnings}


def _analyze_dkim(domain: str) -> dict:
    found = []
    for sel in COMMON_SELECTORS:
        for r in _dig_txt(f"{sel}._domainkey.{domain}"):
            if "v=dkim1" in r.lower() or "p=" in r:
                found.append({"selector": sel,
                              "record": r[:120] + ("…" if len(r) > 120 else "")})
                break
    return {
        "present": bool(found), "selectors": found, "checked": COMMON_SELECTORS,
        "warnings": [] if found else
        [f"No DKIM key found for {len(COMMON_SELECTORS)} common selectors. "
         "If you sign with a custom selector it won't be detected here."],
    }


def _parse_aggregate(xml_bytes: bytes) -> list[dict]:
    try:
        root = ET.fromstring(xml_bytes)
    except Exception:
        return []
    rows = []
    for rec in root.findall(".//record"):
        row = rec.find("row")
        if row is None:
            continue
        pe = row.find("policy_evaluated")
        rows.append({
            "source_ip": (row.findtext("source_ip") or "").strip(),
            "count": int((row.findtext("count") or "0") or 0),
            "disposition": (pe.findtext("disposition") if pe is not None else "") or "none",
            "dkim": (pe.findtext("dkim") if pe is not None else "") or "",
            "spf": (pe.findtext("spf") if pe is not None else "") or "",
        })
    return rows


def _load_reports(domain: str) -> dict:
    files: list[str] = []
    for base in REPORT_DIRS:
        for d in (os.path.join(base, domain), base):
            if os.path.isdir(d):
                for ext in ("*.xml", "*.xml.gz", "*.zip"):
                    files += glob.glob(os.path.join(d, ext))
    agg: dict[str, dict] = {}
    total = 0
    report_count = 0
    for f in sorted(set(files))[:500]:
        try:
            if f.endswith(".gz"):
                xml = gzip.open(f, "rb").read()
            elif f.endswith(".zip"):
                z = zipfile.ZipFile(f)
                xml = z.read(z.namelist()[0])
            else:
                xml = open(f, "rb").read()
        except Exception:
            continue
        rows = _parse_aggregate(xml)
        if not rows:
            continue
        report_count += 1
        for r in rows:
            total += r["count"]
            a = agg.setdefault(r["source_ip"],
                               {"source_ip": r["source_ip"], "count": 0, "pass": 0, "fail": 0})
            a["count"] += r["count"]
            if r["dkim"] == "pass" or r["spf"] == "pass":
                a["pass"] += r["count"]
            else:
                a["fail"] += r["count"]
    return {
        "report_count": report_count,
        "message_count": total,
        "sources": sorted(agg.values(), key=lambda x: -x["count"])[:100],
    }


# ── Route ─────────────────────────────────────────────────────────────────────

@router.get("")  # GET /api/v1/cc/dmarc?domain=example.com
def dmarc_analyze(_: Auth, domain: str = Query(...)):
    domain = domain.strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(domain) or "." not in domain:
        raise HTTPException(status_code=400, detail="invalid domain")

    dmarc = _analyze_dmarc(domain)
    spf = _analyze_spf(domain)
    dkim = _analyze_dkim(domain)
    reports = _load_reports(domain)

    score = 0
    if dmarc["present"]:
        score += 40
        if dmarc.get("policy") in ("quarantine", "reject"):
            score += 20
    if spf["present"]:
        score += 20
    if dkim["present"]:
        score += 20

    grade = "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
    return {
        "domain": domain, "score": score, "grade": grade,
        "dmarc": dmarc, "spf": spf, "dkim": dkim,
        "reports": reports, "report_dirs": REPORT_DIRS,
    }


# ── Cross-domain overview + health (visibility + notifications) ─────────────────
import subprocess as _sp
from datetime import datetime, timezone


def _domain_report_stat(domain: str) -> dict:
    d = os.path.join(REPORT_DIRS[0], domain)
    files = glob.glob(os.path.join(d, "*.xml")) if os.path.isdir(d) else []
    if not files:
        return {"count": 0, "last_report": None, "age_days": None}
    last = max(os.path.getmtime(f) for f in files)
    age = (datetime.now(timezone.utc).timestamp() - last) / 86400.0
    return {"count": len(files),
            "last_report": datetime.fromtimestamp(last, timezone.utc).isoformat(),
            "age_days": round(age, 1)}


def _collector_health() -> dict:
    """systemd timer state + overall report freshness."""
    out = {"timer_active": None, "total_reports": 0, "newest_age_days": None,
           "state_path": os.path.join(REPORT_DIRS[0], ".collector-state.json")}
    try:
        r = _sp.run(["systemctl", "is-active", "mc2-dmarc-collector.timer"],
                    capture_output=True, text=True, timeout=5)
        out["timer_active"] = r.stdout.strip() == "active"
    except Exception:
        pass
    newest = 0.0
    for f in glob.glob(os.path.join(REPORT_DIRS[0], "*", "*.xml")):
        out["total_reports"] += 1
        m = os.path.getmtime(f)
        if m > newest:
            newest = m
    if newest:
        out["newest_age_days"] = round(
            (datetime.now(timezone.utc).timestamp() - newest) / 86400.0, 1)
    return out


@router.get("/overview")  # GET /api/v1/cc/dmarc/overview
def email_auth_overview(_: Auth):
    """Cross-domain DMARC/SPF posture + collector health + computed issues.
    Powers the WebOps Email Authentication page and the MC² notifications."""
    # Non-sending service subdomains never need DMARC — exclude them as noise.
    _SKIP = ("autoconfig.", "autodiscover.", "mail.", "www.", "webmail.",
             "cpanel.", "webdisk.", "mta-sts.", "smtp.", "imap.", "pop.", "ns.")
    try:
        from mc2.services import system_state as state
        domains = sorted({
            d.domain for d in state.list_domains()
            if not getattr(d, "parent", "")
            and not d.domain.startswith(_SKIP)
        })
    except Exception:
        domains = []

    rows, issues = [], []
    for dom in domains:
        dmarc = _analyze_dmarc(dom)
        spf = _analyze_spf(dom)
        rep = _domain_report_stat(dom)
        score = 0
        if dmarc["present"]:
            score += 50
            if dmarc.get("policy") in ("quarantine", "reject"):
                score += 20
        if spf["present"]:
            score += 30
        rows.append({
            "domain": dom, "dmarc": dmarc["present"], "policy": dmarc.get("policy"),
            "spf": spf["present"], "score": score, "rua": dmarc.get("rua", []),
            "reports": rep["count"], "last_report": rep["last_report"],
            "report_age_days": rep["age_days"],
        })

        def add(sev, msg):
            issues.append({"domain": dom, "severity": sev, "message": msg,
                           "key": f"emailauth:{dom}:{msg[:24]}"})

        if not dmarc["present"]:
            add("warning", "No DMARC record — domain is unprotected against spoofing.")
        elif dmarc.get("policy") == "none":
            add("info", "DMARC is p=none (monitor only) — not enforcing.")
        if dmarc["present"] and not dmarc.get("rua"):
            add("info", "DMARC has no rua= — aggregate reports won't be delivered.")
        if not spf["present"]:
            add("warning", "No SPF record published.")
        if dmarc["present"] and dmarc.get("rua") and rep["count"] == 0:
            add("warning", "DMARC rua is set but no aggregate reports collected yet.")
        elif rep["count"] and (rep["age_days"] or 0) > 14:
            add("warning", f"No new DMARC reports in {int(rep['age_days'])} days — collection may be broken.")

    coll = _collector_health()
    if coll["timer_active"] is False:
        issues.append({"domain": "(collector)", "severity": "critical",
                       "message": "DMARC collector timer is not active.",
                       "key": "emailauth:collector:timer"})

    sev_rank = {"critical": 0, "warning": 1, "info": 2}
    issues.sort(key=lambda i: sev_rank.get(i["severity"], 9))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domains": rows, "issues": issues, "collector": coll,
        "summary": {
            "domains": len(rows),
            "protected": sum(1 for r in rows if r["dmarc"] and r["policy"] in ("quarantine", "reject")),
            "issues": len(issues),
            "critical": sum(1 for i in issues if i["severity"] == "critical"),
        },
    }
