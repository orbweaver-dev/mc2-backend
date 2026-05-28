"""
IP Traffic Monitor — live gateway request feed, traffic statistics, and active blocks.

Data source: gw:audit Redis stream written by the gateway's AuditLoggerMiddleware.
Both the gateway and CC backend share Redis DB 2, so CC can read gateway telemetry directly.
Block data is read directly from the live nftables sets (blacklist + temp_ban).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request

from mc2.auth import TokenPayload, require_security_analyst

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/traffic", tags=["traffic"])

_GW_AUDIT_STREAM = "gw:audit"
_PROC_NET_DEV = "/proc/net/dev"
_NFT_TABLE = "inet frothiq"
_APACHE_LOG_DIR = Path("/var/log/virtualmin")

# ---------------------------------------------------------------------------
# Apache log cache — shared across all endpoints; refreshed at most every
# _APACHE_CACHE_TTL seconds to prevent subprocess explosion under fast polls.
# ---------------------------------------------------------------------------
_APACHE_CACHE_TTL = 10.0          # seconds before re-reading logs
_APACHE_MAX_CONCURRENT = 6        # max simultaneous sudo tail subprocesses
_apache_cache: dict = {"data": [], "ts": 0.0}
_apache_cache_lock: asyncio.Lock | None = None
_apache_semaphore: asyncio.Semaphore | None = None


def _get_apache_lock() -> asyncio.Lock:
    global _apache_cache_lock
    if _apache_cache_lock is None:
        _apache_cache_lock = asyncio.Lock()
    return _apache_cache_lock


def _get_apache_semaphore() -> asyncio.Semaphore:
    global _apache_semaphore
    if _apache_semaphore is None:
        _apache_semaphore = asyncio.Semaphore(_APACHE_MAX_CONCURRENT)
    return _apache_semaphore


# ---------------------------------------------------------------------------
# nftables helpers
# ---------------------------------------------------------------------------

def _nft_list_set(set_name: str) -> list[str]:
    """Return the list of IPs/CIDRs in a named nftables set."""
    try:
        result = subprocess.run(
            ["/usr/sbin/nft", "list", "set", "inet", "frothiq", set_name],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return []
        # Extract IPs/CIDRs from the elements block
        elements_match = re.search(r"elements\s*=\s*\{([^}]+)\}", result.stdout, re.DOTALL)
        if not elements_match:
            return []
        raw = elements_match.group(1)
        # Each element may have a "timeout X expires Y" annotation — strip those
        entries = []
        for token in re.split(r",", raw):
            token = token.strip()
            # nftables temp_ban elements look like: "1.2.3.4 timeout 1h expires 59m30s"
            ip_part = token.split()[0] if token else ""
            if ip_part and re.match(r"^[\d./a-fA-F:]+$", ip_part):
                entries.append(ip_part)
        return entries
    except Exception:
        return []


def _build_block_sets() -> tuple[set[str], list, set[str]]:
    """
    Return (blacklist_exact, blacklist_networks, temp_ban_exact).

    blacklist_exact: plain IPs as strings for O(1) lookup
    blacklist_networks: parsed ip_network objects for CIDR membership checks
    temp_ban_exact: temp-banned IPs (nftables dynamic set — always individual IPs)
    """
    raw_bl   = _nft_list_set("blacklist")
    temp_ban = set(_nft_list_set("temp_ban"))

    exact_bl: set[str] = set()
    networks: list = []
    for entry in raw_bl:
        if "/" in entry:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass
        else:
            exact_bl.add(entry)

    return exact_bl, networks, temp_ban


def _ip_in_blacklist(ip: str, exact: set[str], networks: list) -> bool:
    """Check if an IP is in the blacklist (exact match or CIDR membership)."""
    if ip in exact:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False


def _classify_ip(ip: str, blacklist: set[str], temp_ban: set[str]) -> str:
    """Return the enforcement status for a single IP (legacy call-site shim)."""
    if ip in blacklist:
        return "blocked"
    if ip in temp_ban:
        return "temp_banned"
    return "allowed"


# ---------------------------------------------------------------------------
# Audit stream helpers
# ---------------------------------------------------------------------------

def _parse_proc_net_dev() -> list[dict]:
    """Read /proc/net/dev and return per-interface byte/packet counters."""
    results = []
    try:
        with open(_PROC_NET_DEV) as f:
            lines = f.readlines()[2:]
        for line in lines:
            parts = line.split()
            if len(parts) < 11:
                continue
            iface = parts[0].rstrip(":")
            if iface == "lo":
                continue
            results.append({
                "interface": iface,
                "rx_bytes": int(parts[1]),
                "rx_packets": int(parts[2]),
                "rx_errors": int(parts[3]),
                "tx_bytes": int(parts[9]),
                "tx_packets": int(parts[10]),
                "tx_errors": int(parts[11]),
            })
    except Exception:
        pass
    return results


async def _read_audit_entries(redis, count: int = 500) -> list[dict]:
    """Read the most recent entries from the gateway audit stream."""
    try:
        raw = await redis.xrevrange(_GW_AUDIT_STREAM, count=count)
    except Exception:
        return []
    entries = []
    for stream_id, fields in raw:
        entry: dict = dict(fields)
        entry["_id"] = stream_id
        try:
            entry["ts"] = int(entry.get("ts", 0))
        except (ValueError, TypeError):
            entry["ts"] = 0
        try:
            entry["status"] = int(entry.get("status", 0))
        except (ValueError, TypeError):
            entry["status"] = 0
        try:
            entry["latency_ms"] = int(entry.get("latency_ms", 0))
        except (ValueError, TypeError):
            entry["latency_ms"] = 0
        entries.append(entry)
    return entries


def _security_action(
    ip: str,
    status: int,
    bl_exact: set[str],
    bl_networks: list,
    temp_ban: set[str],
    ip_error_rates: dict[str, float],
) -> str:
    """Determine security action for one request entry (CIDR-aware)."""
    if _ip_in_blacklist(ip, bl_exact, bl_networks):
        return "blocked"
    if ip in temp_ban:
        return "temp_banned"
    if ip_error_rates.get(ip, 0.0) >= 0.5 and ip_error_rates.get(ip + ":n", 0) >= 3:
        return "suspicious"
    if status in (401, 403):
        return "suspicious"
    return "allowed"


# ---------------------------------------------------------------------------
# Nginx log parser (whole-server traffic)
# ---------------------------------------------------------------------------

_NGINX_LOG = "/var/log/nginx/access.log"

# Regex for new format: $host $remote_addr ... (host prepended after our change)
_RE_NEW = re.compile(
    r'^(\S+) (\S+) - \S+ \[([^\]]+)\] "(\w+) (\S+) [^"]+" (\d+) \d+ "[^"]*" "([^"]*)"'
)
# Regex for old format: $remote_addr ... (no host)
_RE_OLD = re.compile(
    r'^(\S+) - \S+ \[([^\]]+)\] "(\w+) (\S+) [^"]+" (\d+) \d+ "[^"]*" "([^"]*)"'
)

_NGINX_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_nginx_log(n_lines: int = 500) -> list[dict]:
    """Tail the nginx access log and return structured entries, newest first."""
    try:
        with open(_NGINX_LOG, "rb") as fh:
            # Efficient tail: seek from end
            fh.seek(0, 2)
            size = fh.tell()
            chunk = min(size, 256 * 1024)  # read up to 256 KB
            fh.seek(max(0, size - chunk))
            raw_lines = fh.read().decode("utf-8", errors="replace").splitlines()
    except Exception:
        return []

    entries = []
    for line in reversed(raw_lines[-n_lines:]):
        line = line.strip()
        if not line:
            continue
        m = _RE_NEW.match(line)
        if m:
            host, ip, ts_str, method, path, status, ua = m.groups()
        else:
            m = _RE_OLD.match(line)
            if m:
                ip, ts_str, method, path, status, ua = m.groups()
                host = "unknown"
            else:
                continue
        try:
            ts = int(datetime.strptime(ts_str, _NGINX_TS_FMT).timestamp())
        except Exception:
            ts = 0
        entries.append({
            "_id": f"nginx-{hash(line) & 0xFFFFFFFF:08x}",
            "ts": ts,
            "method": method,
            "path": path,
            "upstream": "nginx",
            "host": host,
            "status": int(status),
            "latency_ms": 0,
            "client_ip": ip,
            "user_agent": ua,
            "tenant_id": "",
            "cc_role": "",
        })
        if len(entries) >= n_lines:
            break

    return entries


# ---------------------------------------------------------------------------
# Apache / Virtualmin log parser (second IP stack — .77.105)
# ---------------------------------------------------------------------------

# Apache "combined" format: IP - - [DD/Mon/YYYY:HH:MM:SS -TZ] "METHOD path HTTP/ver" status bytes "ref" "ua"
_RE_APACHE = re.compile(
    r'^(\S+) - \S+ \[([^\]]+)\] "(\w+) (\S+) [^"]+" (\d+) \d+ "[^"]*" "([^"]*)"'
)
_APACHE_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_single_apache_log(domain: str, log_path: str, max_bytes: int = 32768) -> list[dict]:
    """Parse one Apache combined-format access log. Returns entries newest first."""
    try:
        result = subprocess.run(
            ["sudo", "tail", "-c", str(max_bytes), log_path],
            capture_output=True, text=True, timeout=6,
        )
        text = result.stdout
    except Exception:
        return []

    entries = []
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        m = _RE_APACHE.match(line)
        if not m:
            continue
        ip, ts_str, method, path, status, ua = m.groups()
        try:
            ts = int(datetime.strptime(ts_str, _APACHE_TS_FMT).timestamp())
        except ValueError:
            ts = 0
        entries.append({
            "_id": f"apache-{hash(line) & 0xFFFFFFFF:08x}",
            "ts": ts,
            "method": method,
            "path": path,
            "upstream": "apache",
            "host": domain,
            "status": int(status),
            "latency_ms": 0,
            "client_ip": ip,
            "user_agent": ua,
            "tenant_id": "",
            "cc_role": "",
        })
    return entries


async def _parse_single_apache_log_throttled(domain: str, log_path: str) -> list[dict]:
    """Parse one Apache log, rate-limited by the shared semaphore."""
    async with _get_apache_semaphore():
        return await asyncio.to_thread(_parse_single_apache_log, domain, log_path)


async def _parse_apache_logs_async(n_per_file: int = 200) -> list[dict]:
    """
    Read all Virtualmin access logs in parallel and return parsed entries.
    Results are cached for _APACHE_CACHE_TTL seconds to prevent subprocess
    explosion when multiple endpoints poll simultaneously.
    """
    now = time.monotonic()
    lock = _get_apache_lock()

    async with lock:
        if now - _apache_cache["ts"] < _APACHE_CACHE_TTL:
            return list(_apache_cache["data"])

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["sudo", "ls", str(_APACHE_LOG_DIR)],
                capture_output=True, text=True, timeout=5,
            )
            filenames = [
                f for f in result.stdout.strip().splitlines()
                if f.endswith("_access_log") and not f.endswith(".gz")
            ]
        except Exception:
            return []

        tasks = [
            _parse_single_apache_log_throttled(
                fname.replace("_access_log", ""),
                str(_APACHE_LOG_DIR / fname),
            )
            for fname in filenames
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_entries: list[dict] = []
        for r in results:
            if isinstance(r, list):
                all_entries.extend(r)

        _apache_cache["data"] = all_entries
        _apache_cache["ts"] = time.monotonic()
        return list(all_entries)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/live")
async def get_live_traffic(
    request: Request,
    limit: int = Query(100, ge=10, le=500),
    _: TokenPayload = Depends(require_security_analyst),
):
    """Most recent gateway requests annotated with security_action."""
    redis = request.state.redis
    entries, (bl_exact, bl_nets, temp_ban) = await asyncio.gather(
        _read_audit_entries(redis, count=limit),
        asyncio.to_thread(_build_block_sets),
    )

    # Compute per-IP error rates across visible window
    ip_total: Counter = Counter()
    ip_errors: Counter = Counter()
    for e in entries:
        ip = e.get("client_ip", "")
        st = e.get("status", 0)
        ip_total[ip] += 1
        if 400 <= st < 600:
            ip_errors[ip] += 1
    ip_error_rates: dict[str, float] = {
        ip: ip_errors[ip] / ip_total[ip] for ip in ip_total
    }
    # Stash count under a sentinel key so _security_action can read it
    for ip in ip_total:
        ip_error_rates[ip + ":n"] = ip_total[ip]

    for e in entries:
        ip = e.get("client_ip", "")
        e["security_action"] = _security_action(
            ip, e.get("status", 0), bl_exact, bl_nets, temp_ban, ip_error_rates
        )

    return {"entries": entries, "count": len(entries), "stream": _GW_AUDIT_STREAM}


@router.get("/server-feed")
async def get_server_feed(
    request: Request,
    limit: int = Query(200, ge=50, le=1000),
    _: TokenPayload = Depends(require_security_analyst),
):
    """
    Combined whole-server traffic feed: gateway audit stream (mc2) + nginx access log
    (all Frappe sites). Entries sorted newest first. Annotated with security_action.
    """
    redis = request.state.redis
    gw_entries, nginx_entries, apache_entries, (bl_exact, bl_nets, temp_ban) = await asyncio.gather(
        _read_audit_entries(redis, count=limit),
        asyncio.to_thread(_parse_nginx_log, limit),
        _parse_apache_logs_async(),
        asyncio.to_thread(_build_block_sets),
    )

    # Compute per-IP error rates across all sources
    ip_total: Counter = Counter()
    ip_errors: Counter = Counter()
    for e in [*gw_entries, *nginx_entries, *apache_entries]:
        ip = e.get("client_ip", "")
        st = e.get("status", 0)
        ip_total[ip] += 1
        if 400 <= st < 600:
            ip_errors[ip] += 1

    ip_error_rates: dict[str, float] = {
        ip: ip_errors[ip] / ip_total[ip] for ip in ip_total
    }
    for ip in ip_total:
        ip_error_rates[ip + ":n"] = ip_total[ip]

    all_entries = [*gw_entries, *nginx_entries, *apache_entries]
    for e in all_entries:
        ip = e.get("client_ip", "")
        e["security_action"] = _security_action(
            ip, e.get("status", 0), bl_exact, bl_nets, temp_ban, ip_error_rates
        )

    # Sort newest first, cap at limit
    all_entries.sort(key=lambda e: e.get("ts", 0), reverse=True)
    all_entries = all_entries[:limit]

    return {"entries": all_entries, "count": len(all_entries), "sources": ["gateway", "nginx", "apache"]}


@router.get("/ip-sessions")
async def get_ip_sessions(
    request: Request,
    limit: int = Query(200, ge=50, le=1000),
    _: TokenPayload = Depends(require_security_analyst),
):
    """
    Consolidated per-IP session view: one row per source IP with worst-case
    security status, request count, last path, and time range.
    This is the WordFence-style live view — aggregated, not per-request.
    """
    redis = request.state.redis
    gw_entries, nginx_entries, apache_entries, (bl_exact, bl_nets, temp_ban) = await asyncio.gather(
        _read_audit_entries(redis, count=limit),
        asyncio.to_thread(_parse_nginx_log, limit),
        _parse_apache_logs_async(),
        asyncio.to_thread(_build_block_sets),
    )
    entries = [*gw_entries, *nginx_entries, *apache_entries]

    # First pass: per-IP totals for suspicious detection
    ip_total: Counter = Counter()
    ip_errors: Counter = Counter()
    for e in entries:
        ip = e.get("client_ip", "")
        st = e.get("status", 0)
        ip_total[ip] += 1
        if 400 <= st < 600:
            ip_errors[ip] += 1

    # Second pass: build per-IP session rows
    sessions: dict[str, dict] = {}
    for e in entries:
        ip = e.get("client_ip", "")
        if not ip:
            continue
        ts  = e.get("ts", 0)
        st  = e.get("status", 0)
        ip_blocked = _ip_in_blacklist(ip, bl_exact, bl_nets)
        if ip not in sessions:
            sessions[ip] = {
                "ip": ip,
                "first_seen": ts,
                "last_seen": ts,
                "request_count": 0,
                "error_count": 0,
                "last_method": e.get("method", ""),
                "last_path": e.get("path", ""),
                "last_status": st,
                "paths_seen": [],
                "upstreams_seen": [],
                "is_blocked": ip_blocked,
                "is_temp_banned": ip in temp_ban,
                "security_action": "allowed",
            }
        s = sessions[ip]
        s["request_count"] += 1
        if 400 <= st < 600:
            s["error_count"] += 1
        # Keep chronologically latest request details
        if ts >= s["last_seen"]:
            s["last_seen"]   = ts
            s["last_method"] = e.get("method", s["last_method"])
            s["last_path"]   = e.get("path", s["last_path"])
            s["last_status"] = st
        if ts < s["first_seen"]:
            s["first_seen"] = ts
        path = e.get("path", "")
        if path and path not in s["paths_seen"] and len(s["paths_seen"]) < 5:
            s["paths_seen"].append(path)
        upstream = e.get("upstream", "")
        if upstream and upstream not in s["upstreams_seen"] and len(s["upstreams_seen"]) < 10:
            s["upstreams_seen"].append(upstream)

    # Third pass: assign worst-case security_action (CIDR-aware)
    _ACTION_RANK = {"blocked": 3, "temp_banned": 2, "suspicious": 1, "allowed": 0}
    for ip, s in sessions.items():
        if _ip_in_blacklist(ip, bl_exact, bl_nets):
            s["security_action"] = "blocked"
        elif ip in temp_ban:
            s["security_action"] = "temp_banned"
        elif ip_total[ip] >= 3 and ip_errors[ip] / ip_total[ip] >= 0.5:
            s["security_action"] = "suspicious"
        else:
            s["security_action"] = "allowed"

    # Sort: blocked first, then temp_banned, then suspicious, then by last_seen desc
    ranked = sorted(
        sessions.values(),
        key=lambda s: (-_ACTION_RANK[s["security_action"]], -s["last_seen"]),
    )
    return {"sessions": ranked, "count": len(ranked)}


@router.get("/active-blocks")
async def get_active_blocks(
    _: TokenPayload = Depends(require_security_analyst),
):
    """
    Return the full Defense Mesh blocklist surface — the union of every IP the
    mesh would deny on contact:

      - nft `blacklist` (IPv4) + `blacklist6` (IPv6) on this host
      - nft `temp_ban` (short-term dynamic bans)
      - `frothiq_ip_list` DB rows (canonical mirror of what should be in nft;
        may include entries that drifted off nft after a restart)
      - `threat_reports` community pool (IPs reported by any edge tenant)

    Minus any operator whitelist entries.

    Counts the union, deduplicated by IP — the same address present in multiple
    sources counts once. Previous version returned only nft v4 + temp_ban,
    underreporting by ~10x once the community pool had accumulated entries.
    """
    from sqlalchemy import text as _sql
    from mc2.integrations.database import get_session_factory

    (bl_exact, bl_nets, temp_ban), bl6_raw, whitelist_v4, whitelist_v6 = await asyncio.gather(
        asyncio.to_thread(_build_block_sets),
        asyncio.to_thread(lambda: _nft_list_set("blacklist6")),
        asyncio.to_thread(lambda: _nft_list_set("whitelist")),
        asyncio.to_thread(lambda: _nft_list_set("whitelist6")),
    )

    nft_v4_exact: set[str] = set(bl_exact)
    nft_v4_nets:  list[str] = [str(n) for n in bl_nets]
    nft_v6:       set[str] = set(bl6_raw)
    temp_ban_set: set[str] = set(temp_ban)
    whitelist_set: set[str] = set(whitelist_v4) | set(whitelist_v6)

    # Pull DB blacklist + community pool concurrently.
    db_bl_ips: set[str] = set()
    community_ips: set[str] = set()
    try:
        async with get_session_factory()() as session:
            db_rows = (await session.execute(_sql(
                "SELECT DISTINCT ip FROM frothiq_ip_list WHERE list_type='blacklist'"
            ))).all()
            db_bl_ips = {r[0] for r in db_rows}

            community_rows = (await session.execute(_sql(
                "SELECT DISTINCT ip FROM threat_reports"
            ))).all()
            community_ips = {r[0] for r in community_rows}
    except Exception as exc:
        logger.warning("get_active_blocks: DB read failed: %s", exc)

    union: set[str] = nft_v4_exact | nft_v6 | temp_ban_set | db_bl_ips | community_ips
    union -= whitelist_set

    return {
        "blacklist":         sorted(nft_v4_exact | set(nft_v4_nets) | nft_v6),
        "blacklist_count":   len(nft_v4_exact) + len(nft_v4_nets) + len(nft_v6),
        "temp_ban":          sorted(temp_ban_set),
        "temp_ban_count":    len(temp_ban_set),
        "db_blacklist_count":  len(db_bl_ips),
        "community_count":     len(community_ips),
        # total_blocked = unique IPs across every blocklist source minus whitelist.
        # This is what the dashboard "X blocked" tile should read against.
        "total_blocked":     len(union),
        "whitelist":         sorted(whitelist_set),
        "whitelist_count":   len(whitelist_set),
    }


@router.get("/stats")
async def get_traffic_stats(
    request: Request,
    window_seconds: int = Query(300, ge=60, le=3600),
    _: TokenPayload = Depends(require_security_analyst),
):
    """Aggregated traffic statistics over a rolling time window, including block counts."""
    redis = request.state.redis
    gw_entries, nginx_entries, apache_entries, (bl_exact, bl_nets, temp_ban) = await asyncio.gather(
        _read_audit_entries(redis, count=2000),
        asyncio.to_thread(_parse_nginx_log, 500),
        _parse_apache_logs_async(),
        asyncio.to_thread(_build_block_sets),
    )
    entries = [*gw_entries, *nginx_entries, *apache_entries]

    now = int(time.time())
    cutoff = now - window_seconds
    recent = [e for e in entries if e.get("ts", 0) >= cutoff]

    ip_counts: Counter = Counter()
    status_counts: Counter = Counter()
    upstream_counts: Counter = Counter()
    path_counts: Counter = Counter()
    latencies: list[int] = []

    for e in recent:
        ip = e.get("client_ip", "unknown")
        status = e.get("status", 0)
        upstream = e.get("upstream", "unknown")
        path = e.get("path", "")
        lat = e.get("latency_ms", 0)

        ip_counts[ip] += 1

        status_class = f"{status // 100}xx" if 100 <= status < 600 else "other"
        status_counts[status_class] += 1

        upstream_counts[upstream] += 1

        if path:
            segments = path.strip("/").split("/")
            root = "/" + segments[0] if segments[0] else "/"
            path_counts[root] += 1

        if isinstance(lat, int) and lat > 0:
            latencies.append(lat)

    avg_latency = int(sum(latencies) / len(latencies)) if latencies else 0
    p95_latency = 0
    if latencies:
        sorted_lats = sorted(latencies)
        p95_latency = sorted_lats[int(len(sorted_lats) * 0.95)]

    req_per_sec = round(len(recent) / window_seconds, 2) if recent else 0.0
    error_count = sum(v for k, v in status_counts.items() if k in ("4xx", "5xx"))
    error_rate = round(error_count / len(recent) * 100, 1) if recent else 0.0

    return {
        "window_seconds": window_seconds,
        "total_requests": len(recent),
        "requests_per_second": req_per_sec,
        "error_rate_pct": error_rate,
        "avg_latency_ms": avg_latency,
        "p95_latency_ms": p95_latency,
        "top_ips": [{"ip": ip, "count": c} for ip, c in ip_counts.most_common(15)],
        "status_breakdown": dict(status_counts),
        "upstream_breakdown": dict(upstream_counts),
        "top_paths": [{"path": p, "count": c} for p, c in path_counts.most_common(10)],
        "network_interfaces": _parse_proc_net_dev(),
        "blocked_ips": len(bl_exact) + len(bl_nets),
        "temp_banned_ips": len(temp_ban),
        "total_blocked": len(bl_exact) + len(bl_nets) + len(temp_ban),
        "ts": now,
    }


@router.get("/enforcement-log")
async def get_enforcement_log(
    request: Request,
    limit: int = Query(100, ge=10, le=500),
    _: TokenPayload = Depends(require_security_analyst),
):
    """
    Recent automatic enforcement actions taken by the policy enforcement engine.
    Returns newest-first list of temp-ban events with IP, reason, and timestamp.
    """
    from mc2.services.enforcement_engine import (
        LOG_STREAM, SCAN_INTERVAL, WINDOW_SECONDS, RATE_THRESHOLD, ERROR_RATE_THRESHOLD,
    )
    redis = request.state.redis
    try:
        raw = await redis.xrevrange(LOG_STREAM, count=limit)
    except Exception:
        raw = []

    entries = []
    for stream_id, fields in raw:
        try:
            ts = int(fields.get("ts", 0))
        except (ValueError, TypeError):
            ts = 0
        entries.append({
            "id":     stream_id,
            "ts":     ts,
            "ip":     fields.get("ip", ""),
            "action": fields.get("action", ""),
            "reason": fields.get("reason", ""),
            "reqs":   int(fields.get("reqs", 0) or 0),
            "errors": int(fields.get("errors", 0) or 0),
        })

    return {
        "entries": entries,
        "count":   len(entries),
        "engine": {
            "scan_interval_s":       SCAN_INTERVAL,
            "window_s":              WINDOW_SECONDS,
            "rate_threshold":        RATE_THRESHOLD,
            "error_rate_threshold":  ERROR_RATE_THRESHOLD,
        },
    }


@router.get("/my-ip")
async def get_my_ip(
    request: Request,
    _: TokenPayload = Depends(require_security_analyst),
):
    """
    Return the caller's IP address(es) as seen by the backend.
    Returns both the observed IP and its dual-stack counterpart so that
    traffic logged under either IPv4 or IPv6 can be matched.
    """
    import ipaddress
    ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    ips: set[str] = {ip}
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            ips.add(str(addr.ipv4_mapped))
        elif isinstance(addr, ipaddress.IPv4Address):
            ips.add(f"::ffff:{ip}")
    except ValueError:
        pass
    return {"ip": ip, "ips": sorted(ips)}


@router.get("/ip-info")
async def get_ip_info(
    request: Request,
    ips: str = Query(..., description="Comma-separated list of IPs (max 50)"),
    _: TokenPayload = Depends(require_security_analyst),
):
    """
    Return geolocation, hostname, ISP, and bot/human classification for a list of IPs.
    Results are cached in Redis for 24 hours to minimise external API calls.
    """
    from mc2.services.ip_enrichment import enrich_ips
    ip_list = [ip.strip() for ip in ips.split(",") if ip.strip()][:50]
    if not ip_list:
        return {}
    redis = request.state.redis
    return await enrich_ips(ip_list, redis)
