#!/usr/bin/env python3
"""DMARC aggregate-report collector.

Scans configured Dovecot Maildir(s) for DMARC rua (aggregate) reports,
extracts the report XML (plain / .gz / .zip attachments), and files it
under <output_dir>/<published-domain>/ for the MC² DMARC Analyzer to read.

Non-destructive: never modifies, flags, or deletes mail. Processed
messages are tracked in a state file (keyed by the Maildir unique id, so
new/→cur/ moves don't cause re-imports). Safe to point at a shared inbox —
non-DMARC mail is simply ignored.

Run on a timer:  python3 dmarc_collector.py --config /etc/mc2/dmarc-collector.json
"""

from __future__ import annotations

import argparse
import email
import glob
import gzip
import io
import json
import os
import re
import zipfile
import xml.etree.ElementTree as ET
from email import policy

DEFAULT_CONFIG = "/etc/mc2/dmarc-collector.json"
DEFAULT_OUTPUT = "/var/lib/mc2/dmarc-reports"


def load_config(path: str) -> dict:
    cfg = {"maildirs": [], "output_dir": DEFAULT_OUTPUT,
           "state_file": os.path.join(DEFAULT_OUTPUT, ".collector-state.json")}
    if os.path.exists(path):
        try:
            cfg.update(json.load(open(path)))
        except Exception as e:
            print(f"dmarc-collector: bad config {path}: {e}")
    cfg.setdefault("state_file", os.path.join(cfg["output_dir"], ".collector-state.json"))
    return cfg


def maildir_messages(maildir: str):
    for sub in ("new", "cur"):
        d = os.path.join(maildir, sub)
        if os.path.isdir(d):
            for f in glob.glob(os.path.join(d, "*")):
                if os.path.isfile(f):
                    yield f


def extract_reports(raw: bytes) -> list[bytes]:
    """Return DMARC aggregate XML blobs found in an email's attachments."""
    out: list[bytes] = []
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
    except Exception:
        return out
    for part in msg.walk():
        fn = (part.get_filename() or "").lower()
        ctype = (part.get_content_type() or "").lower()
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            continue
        if not payload:
            continue
        if fn.endswith(".xml.gz") or ctype in ("application/gzip", "application/x-gzip"):
            try:
                out.append(gzip.decompress(payload))
            except Exception:
                pass
        elif fn.endswith(".zip") or ctype == "application/zip":
            try:
                z = zipfile.ZipFile(io.BytesIO(payload))
                for n in z.namelist():
                    if n.lower().endswith(".xml"):
                        out.append(z.read(n))
            except Exception:
                pass
        elif fn.endswith(".xml") or ctype in ("text/xml", "application/xml"):
            out.append(payload)
    return out


def report_meta(xml_bytes: bytes) -> dict | None:
    try:
        root = ET.fromstring(xml_bytes)
    except Exception:
        return None
    dom = (root.findtext(".//policy_published/domain") or "").lower().strip()
    if not dom:
        return None
    rng = root.find(".//report_metadata/date_range")
    return {
        "domain": dom,
        "org": (root.findtext(".//report_metadata/org_name") or "unknown").strip(),
        "report_id": (root.findtext(".//report_metadata/report_id") or "").strip(),
        "begin": (rng.findtext("begin") if rng is not None else "") or "",
        "end": (rng.findtext("end") if rng is not None else "") or "",
    }


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)[:120] or "x"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    args = ap.parse_args()
    cfg = load_config(args.config)

    out_root = cfg["output_dir"]
    os.makedirs(out_root, exist_ok=True)
    state_path = cfg["state_file"]
    state: set[str] = set()
    if os.path.exists(state_path):
        try:
            state = set(json.load(open(state_path)))
        except Exception:
            state = set()

    scanned = imported = 0
    for md in cfg.get("maildirs", []):
        for msgfile in maildir_messages(md):
            key = os.path.basename(msgfile).split(":")[0]   # stable Maildir id
            if key in state:
                continue
            state.add(key)
            scanned += 1
            try:
                raw = open(msgfile, "rb").read()
            except Exception:
                continue
            for xml in extract_reports(raw):
                meta = report_meta(xml)
                if not meta:
                    continue
                ddir = os.path.join(out_root, _safe(meta["domain"]))
                os.makedirs(ddir, exist_ok=True)
                name = _safe("!".join([meta["org"], meta["domain"], meta["begin"],
                                       meta["end"], meta["report_id"]])) + ".xml"
                with open(os.path.join(ddir, name), "wb") as fh:
                    fh.write(xml)
                imported += 1

    tmp = state_path + ".tmp"
    json.dump(sorted(state), open(tmp, "w"))
    os.replace(tmp, state_path)
    print(f"dmarc-collector: {scanned} new message(s) scanned, {imported} report(s) imported")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
