"""
ServOps — system information + management endpoints (super_admin only).
"""

from __future__ import annotations

import grp
import json
import os
import platform
import pwd
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

import psutil

from .routes_auth import require_super_admin

router = APIRouter(prefix="/sysinfo", tags=["sysinfo"])

# ---------------------------------------------------------------------------
# Constants / validation
# ---------------------------------------------------------------------------

SERVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9._@:-]+$")
ALLOWED_SERVICE_ACTIONS = {"start", "stop", "restart", "enable", "disable", "reload"}
ALLOWED_KILL_SIGNALS = {1, 9, 15}  # SIGHUP, SIGKILL, SIGTERM

# Kernel pseudo-filesystems — they have no real "disk usage" (psutil reports
# 0/0 or the wrapping FS's stats). Listing them as rows with numeric used/total
# values implies they consume storage, which is misleading and produces
# duplicate-looking "Disk Usage" amounts across many rows. Mark these so the
# UI can render usage as "—" instead of a fake number.
_VIRTUAL_FSTYPES: frozenset[str] = frozenset({
    "sysfs", "proc", "devpts", "devtmpfs", "cgroup", "cgroup2", "configfs",
    "securityfs", "bpf", "debugfs", "tracefs", "fusectl", "autofs", "pstore",
    "efivarfs", "hugetlbfs", "mqueue", "binfmt_misc", "ramfs", "rpc_pipefs",
    "nsfs", "selinuxfs", "fuse.gvfsd-fuse", "fuse.portal",
})


def _classify_mount(part: psutil._common.sdiskpart) -> tuple[bool, dict | None]:
    """
    Compute (is_virtual, usage_dict_or_None) for a psutil partition.

    - is_virtual: True if fstype is a kernel pseudo-FS — caller should suppress
      numeric usage display for these.
    - usage_dict: psutil.disk_usage(mountpoint) result rounded to GB, or None
      if the lookup failed (permission denied) or is_virtual is True.
    """
    is_virtual = part.fstype in _VIRTUAL_FSTYPES
    if is_virtual:
        return True, None
    try:
        u = psutil.disk_usage(part.mountpoint)
    except (PermissionError, OSError):
        return False, None
    return False, {
        "total_gb": round(u.total / 1e9, 2),
        "used_gb":  round(u.used  / 1e9, 2),
        "free_gb":  round(u.free  / 1e9, 2),
        "percent":  u.percent,
    }

LOG_FILES = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/kern.log",
    "/var/log/dpkg.log",
    "/var/log/apt/history.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/mysql/error.log",
    "/var/log/fail2ban.log",
    "/var/log/mail.log",
]

KNOWN_SERVERS: dict[str, dict] = {
    "nginx": {
        "label": "Nginx",
        "service": "nginx",
        "binaries": ["nginx"],
        "config_paths": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled"],
        "log_paths": ["/var/log/nginx/error.log", "/var/log/nginx/access.log"],
        "category": "web",
    },
    "apache2": {
        "label": "Apache2",
        "service": "apache2",
        "binaries": ["apache2", "httpd"],
        "config_paths": ["/etc/apache2/apache2.conf"],
        "log_paths": ["/var/log/apache2/error.log", "/var/log/apache2/access.log"],
        "category": "web",
    },
    "mysql": {
        "label": "MySQL",
        "service": "mysql",
        "binaries": ["mysql", "mysqld"],
        "config_paths": ["/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/mysqld.cnf"],
        "log_paths": ["/var/log/mysql/error.log"],
        "category": "database",
    },
    "mariadb": {
        "label": "MariaDB",
        "service": "mariadb",
        "binaries": ["mariadbd", "mysqld"],
        "config_paths": ["/etc/mysql/mariadb.conf.d/50-server.cnf"],
        "log_paths": ["/var/log/mysql/error.log"],
        "category": "database",
    },
    "postgresql": {
        "label": "PostgreSQL",
        "service": "postgresql",
        "binaries": ["psql", "postgres"],
        "config_paths": ["/etc/postgresql"],
        "log_paths": ["/var/log/postgresql"],
        "category": "database",
    },
    "redis": {
        "label": "Redis",
        "service": "redis-server",
        "binaries": ["redis-server", "redis-cli"],
        "config_paths": ["/etc/redis/redis.conf"],
        "log_paths": ["/var/log/redis/redis-server.log"],
        "category": "database",
    },
    "mongodb": {
        "label": "MongoDB",
        "service": "mongod",
        "binaries": ["mongod", "mongosh"],
        "config_paths": ["/etc/mongod.conf"],
        "log_paths": ["/var/log/mongodb/mongod.log"],
        "category": "database",
    },
    "postfix": {
        "label": "Postfix",
        "service": "postfix",
        "binaries": ["postfix", "postconf"],
        "config_paths": ["/etc/postfix/main.cf"],
        "log_paths": ["/var/log/mail.log"],
        "category": "mail",
    },
    "dovecot": {
        "label": "Dovecot",
        "service": "dovecot",
        "binaries": ["dovecot"],
        "config_paths": ["/etc/dovecot/dovecot.conf"],
        "log_paths": ["/var/log/mail.log"],
        "category": "mail",
    },
    "openssh": {
        "label": "OpenSSH",
        "service": "ssh",
        "binaries": ["sshd"],
        "config_paths": ["/etc/ssh/sshd_config"],
        "log_paths": ["/var/log/auth.log"],
        "category": "access",
    },
    "bind9": {
        "label": "BIND DNS",
        "service": "bind9",
        "binaries": ["named"],
        "config_paths": ["/etc/bind/named.conf"],
        "log_paths": ["/var/log/syslog"],
        "category": "dns",
    },
    "haproxy": {
        "label": "HAProxy",
        "service": "haproxy",
        "binaries": ["haproxy"],
        "config_paths": ["/etc/haproxy/haproxy.cfg"],
        "log_paths": ["/var/log/haproxy.log"],
        "category": "proxy",
    },
    "vsftpd": {
        "label": "FTP (vsftpd)",
        "service": "vsftpd",
        "binaries": ["vsftpd"],
        "config_paths": ["/etc/vsftpd.conf"],
        "log_paths": ["/var/log/vsftpd.log"],
        "category": "ftp",
    },
    "fail2ban": {
        "label": "Fail2ban",
        "service": "fail2ban",
        "binaries": ["fail2ban-client"],
        "config_paths": ["/etc/fail2ban/jail.conf", "/etc/fail2ban/jail.local"],
        "log_paths": ["/var/log/fail2ban.log"],
        "category": "security",
    },
}

# ---------------------------------------------------------------------------
# Per-IP nftables accounting (IPv4 + IPv6)
# ---------------------------------------------------------------------------

_ipacct_ips: set[str]  = set()
_ipacct6_ips: set[str] = set()
_ipacct_lock  = threading.Lock()
_ipacct6_lock = threading.Lock()

# Cache ipacct reads — dashboard polls every 2 s; cap nft reads at 1/10 s to avoid
# generating dozens of kernel netlink calls per minute.
_IPACCT_TTL = 10.0
_ipacct_cache:  dict = {"data": {}, "ts": 0.0}
_ipacct6_cache: dict = {"data": {}, "ts": 0.0}

def _nft(*args: str) -> subprocess.CompletedProcess:
    # Run nft directly — the service unit grants CAP_NET_ADMIN via AmbientCapabilities,
    # so no sudo is needed for nftables operations.
    return subprocess.run(["/usr/sbin/nft"] + list(args), capture_output=True, text=True)

def _parse_nft_counters(table: str, family: str, proto_fields: tuple[str, ...]) -> dict[str, dict[str, int]]:
    """Generic parser for nftables counter rules. Works for both ip and ip6 families."""
    import json as _json
    result = _nft("-j", "list", "table", family, table)
    if result.returncode != 0:
        return {}
    try:
        data = _json.loads(result.stdout)
    except Exception:
        return {}
    totals: dict[str, dict[str, int]] = {}
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        chain  = rule.get("chain")
        exprs  = rule.get("expr", [])
        ip_val: str | None = None
        bytes_v: int = 0
        for expr in exprs:
            match   = expr.get("match", {})
            payload = match.get("left", {}).get("payload", {})
            if payload.get("protocol") in proto_fields and payload.get("field") in ("daddr", "saddr"):
                ip_val = match.get("right")
            counter = expr.get("counter", {})
            if "bytes" in counter:
                bytes_v = counter["bytes"]
        if ip_val:
            if ip_val not in totals:
                totals[ip_val] = {"bytes_in": 0, "bytes_out": 0}
            if chain == "in":
                totals[ip_val]["bytes_in"] = bytes_v
            elif chain == "out":
                totals[ip_val]["bytes_out"] = bytes_v
    return totals

# --- IPv4 ---

def _setup_ipacct(ips: set[str]) -> None:
    _nft("delete", "table", "ip", "cc_ipacct")
    _nft("add", "table", "ip", "cc_ipacct")
    _nft("add", "chain", "ip", "cc_ipacct", "in",
         "{ type filter hook input priority -10 ; policy accept ; }")
    _nft("add", "chain", "ip", "cc_ipacct", "out",
         "{ type filter hook output priority -10 ; policy accept ; }")
    for ip in sorted(ips):
        _nft("add", "rule", "ip", "cc_ipacct", "in",  "ip", "daddr", ip, "counter")
        _nft("add", "rule", "ip", "cc_ipacct", "out", "ip", "saddr", ip, "counter")

def _get_ipacct(current_ips: set[str]) -> dict[str, dict[str, int]]:
    global _ipacct_ips
    with _ipacct_lock:
        if current_ips != _ipacct_ips:
            _setup_ipacct(current_ips)
            _ipacct_ips = current_ips.copy()
        now = time.monotonic()
        if now - _ipacct_cache["ts"] < _IPACCT_TTL:
            return dict(_ipacct_cache["data"])
        result = _parse_nft_counters("cc_ipacct", "ip", ("ip",))
        _ipacct_cache["data"] = result
        _ipacct_cache["ts"] = now
    return result

# --- IPv6 ---

def _setup_ipacct6(ips: set[str]) -> None:
    _nft("delete", "table", "ip6", "cc_ipacct6")
    _nft("add", "table", "ip6", "cc_ipacct6")
    _nft("add", "chain", "ip6", "cc_ipacct6", "in",
         "{ type filter hook input priority -10 ; policy accept ; }")
    _nft("add", "chain", "ip6", "cc_ipacct6", "out",
         "{ type filter hook output priority -10 ; policy accept ; }")
    for ip in sorted(ips):
        _nft("add", "rule", "ip6", "cc_ipacct6", "in",  "ip6", "daddr", ip, "counter")
        _nft("add", "rule", "ip6", "cc_ipacct6", "out", "ip6", "saddr", ip, "counter")

def _get_ipacct6(current_ips: set[str]) -> dict[str, dict[str, int]]:
    global _ipacct6_ips
    with _ipacct6_lock:
        if current_ips != _ipacct6_ips:
            _setup_ipacct6(current_ips)
            _ipacct6_ips = current_ips.copy()
        now = time.monotonic()
        if now - _ipacct6_cache["ts"] < _IPACCT_TTL:
            return dict(_ipacct6_cache["data"])
        result = _parse_nft_counters("cc_ipacct6", "ip6", ("ip6",))
        _ipacct6_cache["data"] = result
        _ipacct6_cache["ts"] = now
    return result

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uptime_str(boot_ts: float) -> str:
    secs = int(time.time() - boot_ts)
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{mins}m")
    return " ".join(parts)


def _run(cmd: list[str], timeout: int = 10) -> tuple[str, str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timed out", 1
    except Exception as e:
        return "", str(e), 1


def _run_out(cmd: list[str], timeout: int = 10) -> str:
    stdout, _, _ = _run(cmd, timeout)
    return stdout


def _service_active(service: str) -> str:
    out, _, _ = _run(["systemctl", "is-active", service], timeout=5)
    return out.strip()


def _service_enabled(service: str) -> str:
    out, _, _ = _run(["systemctl", "is-enabled", service], timeout=5)
    return out.strip()


def _system_users(shell_only: bool = False) -> list[str]:
    users = []
    for p in pwd.getpwall():
        if shell_only and p.pw_shell in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin"):
            continue
        users.append(p.pw_name)
    return users


def _parse_crontab_file(path: Path, source: str, jobs: list) -> None:
    try:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("@"):
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    jobs.append({"source": source, "schedule": parts[0], "user": parts[1] if len(parts) > 2 else "", "command": parts[-1]})
                continue
            parts = line.split(None, 6)
            if len(parts) >= 6:
                jobs.append({
                    "source": source,
                    "schedule": " ".join(parts[:5]),
                    "user": parts[5] if len(parts) > 6 else "",
                    "command": parts[-1],
                })
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@router.get("")
async def get_sysinfo(_: str = Depends(require_super_admin)) -> dict:
    boot_ts = psutil.boot_time()
    cpu_pct = psutil.cpu_percent(interval=0.2)
    cpu_per_core = psutil.cpu_percent(interval=0, percpu=True)
    load_avg = list(psutil.getloadavg())
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disks = []
    # Dedupe bind mounts by underlying device: only emit the primary mount per
    # device so the UI doesn't show the same used/total numbers across multiple
    # rows for the same physical filesystem.
    seen_devices: set[str] = set()
    for part in psutil.disk_partitions(all=False):
        is_virtual, usage = _classify_mount(part)
        if is_virtual or usage is None:
            continue
        if part.device in seen_devices:
            # Bind mount / alias of an already-emitted device — skip on dashboard
            # to keep the card focused on distinct filesystems.
            continue
        seen_devices.add(part.device)
        disks.append({
            "mountpoint": part.mountpoint,
            "device":     part.device,
            "fstype":     part.fstype,
            **usage,
        })
    net = psutil.net_io_counters()
    net_per_nic = psutil.net_io_counters(pernic=True)
    net_if_addrs = psutil.net_if_addrs()
    # Collect non-loopback IPv4 + global-scope IPv6 addresses for per-IP accounting
    _all_ips: set[str]  = set()
    _all_ip6s: set[str] = set()
    for iface, addrs in net_if_addrs.items():
        if iface == "lo":
            continue
        for a in addrs:
            if a.family == 2:    # AF_INET — IPv4
                _all_ips.add(a.address)
            elif a.family == 10: # AF_INET6 — IPv6, skip link-local (fe80::)
                addr = a.address.split("%")[0]  # strip interface suffix e.g. "fe80::1%eth0"
                if not addr.lower().startswith("fe80"):
                    _all_ip6s.add(addr)
    ip_acct  = _get_ipacct(_all_ips)
    ip6_acct = _get_ipacct6(_all_ip6s)
    uname = platform.uname()

    # Read the real OS distribution from /etc/os-release (freedesktop standard).
    # platform.uname().release is the kernel version, not the distro name.
    try:
        os_release = platform.freedesktop_os_release()
        os_name      = os_release.get("PRETTY_NAME", f"{uname.system} {uname.release}")
        os_id        = os_release.get("ID", "linux").lower()
        os_version   = os_release.get("VERSION_ID", "")
        os_codename  = os_release.get("VERSION_CODENAME", "")
    except (OSError, AttributeError):
        os_name     = f"{uname.system} {uname.release}"
        os_id       = "linux"
        os_version  = ""
        os_codename = ""

    return {
        "hostname": uname.node,
        "os": os_name,           # "Ubuntu 24.04.4 LTS" — human-readable distro name
        "os_id": os_id,          # "ubuntu" — machine-readable ID for logo matching
        "os_version": os_version,    # "24.04"
        "os_codename": os_codename,  # "noble"
        "kernel": uname.release,     # "6.8.0-107-generic" — kernel version
        "kernel_build": uname.version,  # "#107-Ubuntu SMP PREEMPT_DYNAMIC …" — build string
        "arch": uname.machine,
        "python": platform.python_version(),
        "uptime": _uptime_str(boot_ts),
        "boot_time": datetime.fromtimestamp(boot_ts, tz=UTC).isoformat(),
        "cpu": {
            "percent": cpu_pct,
            "per_core": cpu_per_core,
            "logical_cores": psutil.cpu_count(logical=True),
            "physical_cores": psutil.cpu_count(logical=False),
            "load_avg_1m": round(load_avg[0], 2),
            "load_avg_5m": round(load_avg[1], 2),
            "load_avg_15m": round(load_avg[2], 2),
        },
        "memory": {
            "total_gb": round(mem.total / 1e9, 2),
            "used_gb": round(mem.used / 1e9, 2),
            "available_gb": round(mem.available / 1e9, 2),
            "percent": mem.percent,
            "swap_total_gb": round(swap.total / 1e9, 2),
            "swap_used_gb": round(swap.used / 1e9, 2),
            "swap_percent": swap.percent,
        },
        "disks": disks,
        "network": {
            "bytes_sent_mb": round(net.bytes_sent / 1e6, 4),
            "bytes_recv_mb": round(net.bytes_recv / 1e6, 4),
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
            "interfaces": list(net_if_addrs.keys()),
            "per_interface": {
                iface: {
                    "bytes_sent": counters.bytes_sent,
                    "bytes_recv": counters.bytes_recv,
                    "ip": next(
                        (a.address for a in net_if_addrs.get(iface, []) if a.family == 2),  # AF_INET = 2
                        None,
                    ),
                    "all_ips": [
                        a.address for a in net_if_addrs.get(iface, []) if a.family == 2
                    ],
                    "all_ipv6s": [
                        a.address.split("%")[0] for a in net_if_addrs.get(iface, [])
                        if a.family == 10 and not a.address.lower().startswith("fe80")
                    ],
                }
                for iface, counters in net_per_nic.items()
            },
            "per_ip_bytes":  ip_acct,
            "per_ip6_bytes": ip6_acct,
        },
        "processes": len(psutil.pids()),
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------

@router.get("/processes")
async def get_processes(
    _: str = Depends(require_super_admin),
    limit: int = Query(100, ge=1, le=500),
    sort: str = Query("cpu", pattern="^(cpu|mem|pid|name)$"),
) -> dict:
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "status", "cpu_percent", "memory_percent", "create_time", "cmdline"]):
        try:
            info = p.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"] or "",
                "user": info["username"] or "",
                "status": info["status"] or "",
                "cpu_pct": round(info["cpu_percent"] or 0, 1),
                "mem_pct": round(info["memory_percent"] or 0, 2),
                "started": datetime.fromtimestamp(info["create_time"], tz=UTC).isoformat() if info["create_time"] else None,
                "cmd": " ".join(info["cmdline"] or [])[:120],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    key_map = {"cpu": "cpu_pct", "mem": "mem_pct", "pid": "pid", "name": "name"}
    procs.sort(key=lambda x: x[key_map[sort]], reverse=(sort in ("cpu", "mem")))
    return {"total": len(procs), "processes": procs[:limit], "checked_at": datetime.now(UTC).isoformat()}


class KillRequest(BaseModel):
    signal: int = 15


@router.post("/processes/{pid}/kill")
async def kill_process(pid: int, body: KillRequest, _: str = Depends(require_super_admin)) -> dict:
    if body.signal not in ALLOWED_KILL_SIGNALS:
        raise HTTPException(400, f"Signal must be one of {ALLOWED_KILL_SIGNALS}")
    try:
        proc = psutil.Process(pid)
        proc.send_signal(body.signal)
        return {"ok": True, "pid": pid, "signal": body.signal}
    except psutil.NoSuchProcess:
        raise HTTPException(404, "Process not found")
    except psutil.AccessDenied:
        raise HTTPException(403, "Access denied")


# ---------------------------------------------------------------------------
# Bootup / Systemd services
# ---------------------------------------------------------------------------

@router.get("/bootup")
async def get_bootup(_: str = Depends(require_super_admin)) -> dict:
    import json
    out, _, _ = _run([
        "systemctl", "list-units", "--type=service",
        "--all", "--no-pager", "--no-legend", "--output=json",
    ], timeout=10)
    services = []
    if out:
        try:
            for s in json.loads(out):
                services.append({
                    "unit": s.get("unit", ""),
                    "load": s.get("load", ""),
                    "active": s.get("active", ""),
                    "sub": s.get("sub", ""),
                    "description": s.get("description", ""),
                })
        except Exception:
            pass
    return {"services": services, "count": len(services), "checked_at": datetime.now(UTC).isoformat()}


class ServiceActionRequest(BaseModel):
    service: str
    action: str


@router.post("/bootup/action")
async def service_action(body: ServiceActionRequest, _: str = Depends(require_super_admin)) -> dict:
    if not SERVICE_NAME_RE.match(body.service):
        raise HTTPException(400, "Invalid service name")
    if body.action not in ALLOWED_SERVICE_ACTIONS:
        raise HTTPException(400, f"Action must be one of {ALLOWED_SERVICE_ACTIONS}")
    _, stderr, rc = _run(["sudo", "systemctl", body.action, body.service], timeout=30)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or f"systemctl {body.action} failed")
    return {"ok": True, "service": body.service, "action": body.action}


# Classification labels
_CLS_GHOST       = "ghost_record"
_CLS_SUPERSEDED  = "superseded"
_CLS_CRASHED     = "crashed"
_CLS_MISSING_DEP = "missing_dependency"
_CLS_UNKNOWN     = "unknown"


def _classify_failed_unit(unit: str, load_state: str) -> dict:
    """Inspect a failed systemd unit and return classification + recommended fix."""

    # ── Ghost record: unit file no longer exists ───────────────────────────
    if load_state == "not-found":
        return {
            "classification": _CLS_GHOST,
            "reason": "Unit file has been deleted but systemd still holds a failure record for it.",
            "recommended_action": "reset-failed",
            "recommended_label": "Clear record",
            "safe_to_autofix": True,
        }

    # ── Load the unit file for pattern inspection ──────────────────────────
    unit_path_out, _, _ = _run(["systemctl", "show", unit, "--property=FragmentPath"], timeout=5)
    unit_path = ""
    for line in unit_path_out.splitlines():
        if line.startswith("FragmentPath="):
            unit_path = line.split("=", 1)[1].strip()

    unit_content = ""
    if unit_path:
        try:
            unit_content = open(unit_path).read()
        except OSError:
            pass

    # ── fcgiwrap superseded by PHP-FPM ─────────────────────────────────────
    if unit.startswith("fcgiwrap-"):
        # Extract the socket ID from ExecStart to find matching PHP-FPM pool
        import re as _re
        sock_match = _re.search(r"/var/fcgiwrap/(\d+)\.sock", unit_content)
        fpm_running = False
        if sock_match:
            pool_id = sock_match.group(1)
            fpm_out, _, _ = _run(
                ["systemctl", "is-active", f"php8.3-fpm@{pool_id}.service"],
                timeout=5,
            )
            # Also check generic pool activity via ps
            ps_out, _, _ = _run(["pgrep", "-f", f"pool {pool_id}"], timeout=5)
            fpm_running = fpm_out.strip() == "active" or bool(ps_out.strip())

        if fpm_running:
            return {
                "classification": _CLS_SUPERSEDED,
                "reason": "fcgiwrap was replaced by PHP-FPM for this virtual host. "
                          "The PHP-FPM pool is active and serving PHP requests normally.",
                "recommended_action": "disable-and-reset",
                "recommended_label": "Disable & clear",
                "safe_to_autofix": True,
            }
        # fcgiwrap for a non-PHP site (no fpm pool found)
        return {
            "classification": _CLS_SUPERSEDED,
            "reason": "fcgiwrap is not needed — this virtual host does not serve PHP. "
                      "No PHP-FPM pool was found either.",
            "recommended_action": "disable-and-reset",
            "recommended_label": "Disable & clear",
            "safe_to_autofix": True,
        }

    # ── Check journal for dependency / exec errors ─────────────────────────
    journal_out, _, _ = _run(
        ["journalctl", "-u", unit, "-n", "20", "--no-pager", "--output=short"],
        timeout=8,
    )

    if "Dependency failed" in journal_out or "dependency" in journal_out.lower():
        dep_hint = ""
        for line in journal_out.splitlines():
            if "Dependency" in line or "Required" in line:
                dep_hint = line.strip()
                break
        return {
            "classification": _CLS_MISSING_DEP,
            "reason": f"Service failed due to an unmet dependency. Last log: {dep_hint or 'see journal'}",
            "recommended_action": "investigate",
            "recommended_label": "View logs",
            "safe_to_autofix": False,
        }

    # ── Legitimate crashed service ─────────────────────────────────────────
    last_error = ""
    for line in reversed(journal_out.splitlines()):
        if "error" in line.lower() or "failed" in line.lower() or "killed" in line.lower():
            last_error = line.strip()
            break

    return {
        "classification": _CLS_CRASHED,
        "reason": f"Service exited unexpectedly. {('Last error: ' + last_error) if last_error else 'Check journal for details.'}",
        "recommended_action": "restart",
        "recommended_label": "Restart",
        "safe_to_autofix": False,
    }


@router.get("/bootup/failed-analysis")
async def failed_service_analysis(_: str = Depends(require_super_admin)) -> dict:
    """Classify all failed systemd units and return per-service fix recommendations."""
    import json
    out, _, _ = _run([
        "systemctl", "list-units", "--state=failed",
        "--all", "--no-pager", "--no-legend", "--output=json",
    ], timeout=10)

    results = []
    if out:
        try:
            units = json.loads(out)
        except Exception:
            units = []
        for u in units:
            name = u.get("unit", "")
            load = u.get("load", "")
            if not name:
                continue
            classification = _classify_failed_unit(name, load)
            results.append({
                "unit": name,
                "load": load,
                "active": u.get("active", ""),
                "sub": u.get("sub", ""),
                "description": u.get("description", ""),
                **classification,
            })

    return {
        "failed": results,
        "count": len(results),
        "analyzed_at": datetime.now(UTC).isoformat(),
    }


class FailedFixRequest(BaseModel):
    service: str
    action: str  # "reset-failed" | "disable-and-reset"


@router.post("/bootup/failed-analysis/fix")
async def fix_failed_service(body: FailedFixRequest, _: str = Depends(require_super_admin)) -> dict:
    """Apply the recommended fix for a classified failed service."""
    if not SERVICE_NAME_RE.match(body.service):
        raise HTTPException(400, "Invalid service name")
    if body.action not in {"reset-failed", "disable-and-reset"}:
        raise HTTPException(400, "action must be reset-failed or disable-and-reset")

    if body.action == "disable-and-reset":
        _, err, rc = _run(["sudo", "systemctl", "disable", body.service], timeout=15)
        if rc != 0:
            # disable may fail if unit is not-found — proceed to reset anyway
            pass
        _, err2, rc2 = _run(["sudo", "systemctl", "reset-failed", body.service], timeout=10)
        if rc2 != 0:
            raise HTTPException(500, err2.strip() or "reset-failed failed")
    else:
        _, err, rc = _run(["sudo", "systemctl", "reset-failed", body.service], timeout=10)
        if rc != 0:
            raise HTTPException(500, err.strip() or "reset-failed failed")

    return {"ok": True, "service": body.service, "action": body.action}


# ---------------------------------------------------------------------------
# Cron Jobs
# ---------------------------------------------------------------------------

@router.get("/cron")
async def get_cron(_: str = Depends(require_super_admin)) -> dict:
    jobs: list[dict[str, Any]] = []
    system_crontab = Path("/etc/crontab")
    if system_crontab.exists():
        _parse_crontab_file(system_crontab, "system", jobs)
    cron_d = Path("/etc/cron.d")
    if cron_d.is_dir():
        for f in sorted(cron_d.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                _parse_crontab_file(f, f"cron.d/{f.name}", jobs)
    for user in _system_users(shell_only=True):
        out = _run_out(["crontab", "-l", "-u", user], timeout=5)
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 5)
            if len(parts) >= 6:
                jobs.append({"source": f"user:{user}", "schedule": " ".join(parts[:5]), "user": user, "command": parts[5]})
    return {"total": len(jobs), "jobs": jobs, "checked_at": datetime.now(UTC).isoformat()}


class CronAddRequest(BaseModel):
    user: str
    schedule: str
    command: str


@router.post("/cron/entry")
async def add_cron_entry(body: CronAddRequest, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", body.user):
        raise HTTPException(400, "Invalid username")
    if len(body.schedule) > 100 or len(body.command) > 500:
        raise HTTPException(400, "Schedule or command too long")
    # Read existing crontab
    existing, _, _ = _run(["crontab", "-l", "-u", body.user], timeout=5)
    new_entry = f"{body.schedule} {body.command}\n"
    new_crontab = existing.rstrip("\n") + ("\n" if existing.strip() else "") + new_entry
    proc = subprocess.run(
        ["crontab", "-u", body.user, "-"],
        input=new_crontab, capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        raise HTTPException(500, proc.stderr.strip() or "crontab write failed")
    return {"ok": True}


class CronDeleteRequest(BaseModel):
    user: str
    schedule: str
    command: str


@router.delete("/cron/entry")
async def delete_cron_entry(body: CronDeleteRequest, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", body.user):
        raise HTTPException(400, "Invalid username")
    existing, _, _ = _run(["crontab", "-l", "-u", body.user], timeout=5)
    target = f"{body.schedule} {body.command}"
    new_lines = [l for l in existing.splitlines() if l.strip() != target]
    new_crontab = "\n".join(new_lines) + "\n"
    proc = subprocess.run(
        ["crontab", "-u", body.user, "-"],
        input=new_crontab, capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        raise HTTPException(500, proc.stderr.strip() or "crontab write failed")
    return {"ok": True}


# ---------------------------------------------------------------------------
# System Logs
# ---------------------------------------------------------------------------

@router.get("/logs")
async def get_log_files(_: str = Depends(require_super_admin)) -> dict:
    files = []
    for path_str in LOG_FILES:
        try:
            p = Path(path_str)
            if p.exists() and p.is_file():
                stat = p.stat()
                files.append({"path": path_str, "size_kb": round(stat.st_size / 1024, 1), "modified": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat()})
        except (PermissionError, OSError):
            continue
    return {"files": files}


@router.get("/logs/tail")
async def tail_log(
    _: str = Depends(require_super_admin),
    path: str = Query(...),
    lines: int = Query(100, ge=10, le=1000),
) -> dict:
    if not path.startswith("/var/log/"):
        return {"error": "Path not allowed", "lines": []}
    try:
        out = _run_out(["tail", f"-n{lines}", path])
        return {"path": path, "lines": out.splitlines(), "checked_at": datetime.now(UTC).isoformat()}
    except Exception as e:
        return {"error": str(e), "lines": []}


# ---------------------------------------------------------------------------
# Software Packages
# ---------------------------------------------------------------------------

@router.get("/packages")
async def get_packages(
    _: str = Depends(require_super_admin),
    search: str = Query("", max_length=100),
) -> dict:
    out = _run_out(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\t${Architecture}\n"], timeout=15)
    pkgs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        name, version, status, arch = parts[0], parts[1], parts[2], parts[3]
        if "installed" not in status:
            continue
        if search and search.lower() not in name.lower():
            continue
        pkgs.append({"name": name, "version": version, "arch": arch})
    pkgs.sort(key=lambda x: x["name"])
    return {"total": len(pkgs), "packages": pkgs[:500], "checked_at": datetime.now(UTC).isoformat()}


@router.get("/packages/updates")
async def get_package_updates(_: str = Depends(require_super_admin)) -> dict:
    out = _run_out(["apt", "list", "--upgradable", "-q"], timeout=30)
    updates = []
    for line in out.splitlines():
        if "/" not in line or "Listing" in line:
            continue
        m = re.match(r"^(\S+)/\S+\s+(\S+)\s+(\S+)\s+\[upgradable from: (\S+)\]", line)
        if m:
            updates.append({"name": m.group(1), "new_version": m.group(2), "arch": m.group(3), "old_version": m.group(4)})
    return {"total": len(updates), "updates": updates, "checked_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# OS upgrade — background job tracker
# ---------------------------------------------------------------------------

_UPGRADE_JOB: dict = {
    "id": None,
    "status": "idle",      # idle | running | done | error
    "lines": [],
    "packages_upgraded": 0,
    "started_at": None,
    "finished_at": None,
    "error": "",
}
_UPGRADE_LOCK = threading.Lock()


def _run_upgrade() -> None:
    """Run apt-get update + apt-get upgrade in a background thread."""
    _UPGRADE_JOB["lines"] = []
    _UPGRADE_JOB["packages_upgraded"] = 0
    _UPGRADE_JOB["error"] = ""

    def _emit(line: str) -> None:
        _UPGRADE_JOB["lines"].append(line)
        if len(_UPGRADE_JOB["lines"]) > 500:
            _UPGRADE_JOB["lines"] = _UPGRADE_JOB["lines"][-500:]

    # env_keep in sudoers preserves these through sudo privilege escalation.
    # NEEDRESTART_MODE=a: auto-restart services without prompting.
    # DEBIAN_FRONTEND=noninteractive: suppresses debconf/whiptail TUI dialogs.
    apt_env = {
        **os.environ,
        "DEBIAN_FRONTEND": "noninteractive",
        "APT_LISTCHANGES_FRONTEND": "none",
        "NEEDRESTART_MODE": "a",
    }

    try:
        # Step 1: refresh package lists
        _emit("[apt] Refreshing package lists…")
        proc = subprocess.run(
            ["sudo", "apt-get", "update", "-q"],
            capture_output=True, text=True, env=apt_env, timeout=120,
        )
        for line in (proc.stdout + proc.stderr).splitlines():
            line = line.strip()
            # skip raw terminal escape sequences from whiptail
            if line and not line.startswith("\x1b[") and not line.startswith("[?"):
                _emit(line)

        if proc.returncode != 0:
            _UPGRADE_JOB["status"] = "error"
            _UPGRADE_JOB["error"] = "apt-get update failed (rc={})".format(proc.returncode)
            _UPGRADE_JOB["finished_at"] = datetime.now(UTC).isoformat()
            return

        # Step 2: upgrade all packages.
        # -o Dpkg::Options force-confdef/confold: handle config file conflicts without prompting.
        _emit("[apt] Starting package upgrade…")
        proc2 = subprocess.run(
            [
                "sudo", "apt-get", "upgrade", "-y", "-q",
                "--no-install-recommends",
                "-o", "Dpkg::Options::=--force-confdef",
                "-o", "Dpkg::Options::=--force-confold",
            ],
            capture_output=True, text=True, env=apt_env, timeout=600,
        )
        for line in (proc2.stdout + proc2.stderr).splitlines():
            line = line.strip()
            if line and not line.startswith("\x1b[") and not line.startswith("[?"):
                _emit(line)
            m = re.search(r"(\d+) upgraded", line)
            if m:
                _UPGRADE_JOB["packages_upgraded"] = int(m.group(1))

        _emit(f"[apt] Exit code: {proc2.returncode}")
        if proc2.returncode != 0:
            _UPGRADE_JOB["status"] = "error"
            err = "\n".join(
                l for l in (proc2.stderr or "").splitlines()
                if l.strip() and not l.startswith("\x1b[") and not l.startswith("[?")
            )
            _UPGRADE_JOB["error"] = (err or "apt-get upgrade failed")[-300:]
        else:
            _UPGRADE_JOB["status"] = "done"
            _emit("[apt] Upgrade complete.")

    except Exception as exc:
        _UPGRADE_JOB["status"] = "error"
        _UPGRADE_JOB["error"] = str(exc)[:300]
        _emit(f"[apt] Exception: {exc}")

    _UPGRADE_JOB["finished_at"] = datetime.now(UTC).isoformat()


@router.post("/os/upgrade")
async def start_os_upgrade(_: str = Depends(require_super_admin)) -> dict:
    with _UPGRADE_LOCK:
        if _UPGRADE_JOB["status"] == "running":
            return {"ok": False, "message": "Upgrade already in progress", "job_id": _UPGRADE_JOB["id"]}
        job_id = str(uuid.uuid4())
        _UPGRADE_JOB.update({
            "id": job_id,
            "status": "running",
            "lines": [],
            "packages_upgraded": 0,
            "started_at": datetime.now(UTC).isoformat(),
            "finished_at": None,
            "error": "",
        })
    thread = threading.Thread(target=_run_upgrade, daemon=True)
    thread.start()
    return {"ok": True, "job_id": job_id}


@router.get("/os/upgrade/status")
async def get_upgrade_status(_: str = Depends(require_super_admin)) -> dict:
    return {
        "job_id": _UPGRADE_JOB["id"],
        "status": _UPGRADE_JOB["status"],
        "lines": _UPGRADE_JOB["lines"][-60:],   # last 60 lines
        "packages_upgraded": _UPGRADE_JOB["packages_upgraded"],
        "started_at": _UPGRADE_JOB["started_at"],
        "finished_at": _UPGRADE_JOB["finished_at"],
        "error": _UPGRADE_JOB["error"],
    }


class PackageActionRequest(BaseModel):
    name: str
    action: str  # remove | purge


@router.post("/packages/action")
async def package_action(body: PackageActionRequest, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z0-9][a-z0-9+\-.]{0,100}$", body.name):
        raise HTTPException(400, "Invalid package name")
    if body.action not in {"remove", "purge"}:
        raise HTTPException(400, "Action must be remove or purge")
    env = {"DEBIAN_FRONTEND": "noninteractive"}
    import os
    full_env = {**os.environ, **env}
    _, stderr, rc = _run(["apt-get", body.action, "-y", "--", body.name], timeout=120)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or "apt-get failed")
    return {"ok": True, "package": body.name, "action": body.action}


# ---------------------------------------------------------------------------
# Users and Groups
# ---------------------------------------------------------------------------

@router.get("/users")
async def get_users(_: str = Depends(require_super_admin)) -> dict:
    users = [
        {
            "username": p.pw_name, "uid": p.pw_uid, "gid": p.pw_gid,
            "gecos": p.pw_gecos, "home": p.pw_dir, "shell": p.pw_shell,
            "login_shell": p.pw_shell not in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin", ""),
        }
        for p in sorted(pwd.getpwall(), key=lambda x: x.pw_uid)
    ]
    groups = [
        {"name": g.gr_name, "gid": g.gr_gid, "members": list(g.gr_mem)}
        for g in sorted(grp.getgrall(), key=lambda x: x.gr_gid)
    ]
    return {"users": users, "groups": groups, "user_count": len(users), "group_count": len(groups), "checked_at": datetime.now(UTC).isoformat()}


class CreateUserRequest(BaseModel):
    username: str
    password: str
    shell: str = "/bin/bash"
    groups: list[str] = []
    comment: str = ""


@router.post("/users")
async def create_user(body: CreateUserRequest, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", body.username):
        raise HTTPException(400, "Invalid username")
    if body.shell not in ("/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/fish", "/bin/false", "/usr/sbin/nologin"):
        raise HTTPException(400, "Shell not allowed")
    cmd = ["useradd", "-m", "-s", body.shell]
    if body.comment:
        cmd += ["-c", body.comment[:64]]
    if body.groups:
        safe_groups = [g for g in body.groups if re.match(r"^[a-z_][a-z0-9_-]{0,31}$", g)]
        cmd += ["-G", ",".join(safe_groups)]
    cmd.append(body.username)
    _, stderr, rc = _run(cmd, timeout=10)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or "useradd failed")
    # Set password via chpasswd
    proc = subprocess.run(
        ["chpasswd"],
        input=f"{body.username}:{body.password}",
        capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        raise HTTPException(500, proc.stderr.strip() or "chpasswd failed")
    return {"ok": True, "username": body.username}


@router.delete("/users/{username}")
async def delete_user(username: str, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", username):
        raise HTTPException(400, "Invalid username")
    _, stderr, rc = _run(["userdel", "-r", username], timeout=15)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or "userdel failed")
    return {"ok": True, "username": username}


class CreateGroupRequest(BaseModel):
    name: str


@router.post("/groups")
async def create_group(body: CreateGroupRequest, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", body.name):
        raise HTTPException(400, "Invalid group name")
    _, stderr, rc = _run(["groupadd", body.name], timeout=10)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or "groupadd failed")
    return {"ok": True, "name": body.name}


@router.delete("/groups/{name}")
async def delete_group(name: str, _: str = Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", name):
        raise HTTPException(400, "Invalid group name")
    _, stderr, rc = _run(["groupdel", name], timeout=10)
    if rc != 0:
        raise HTTPException(500, stderr.strip() or "groupdel failed")
    return {"ok": True, "name": name}


# ---------------------------------------------------------------------------
# Filesystems
# ---------------------------------------------------------------------------

@router.get("/filesystems")
async def get_filesystems(_: str = Depends(require_super_admin)) -> dict:
    """
    List every mount on the host. Each mount is classified so the UI can
    decide whether numeric usage is meaningful:

      - is_virtual=True  → kernel pseudo-FS (proc, sysfs, cgroup, …).
        used/total/free/percent are all None — UI should render "—".

      - alias_of=<path>  → bind mount or duplicate mount of an already-listed
        underlying device. used/total/free/percent ARE included (psutil
        returns the wrapping FS stats), but the UI should de-emphasize them
        as a reminder that they share storage with the primary mount.

      - is_virtual=False, alias_of=None → distinct real filesystem; show
        normal df-style usage.
    """
    mounts: list[dict] = []
    primary_for_device: dict[str, str] = {}  # device → first mountpoint seen
    for part in psutil.disk_partitions(all=True):
        is_virtual, usage = _classify_mount(part)
        alias_of = primary_for_device.get(part.device) if not is_virtual else None
        if not is_virtual and alias_of is None:
            primary_for_device[part.device] = part.mountpoint
        row = {
            "device":     part.device,
            "mountpoint": part.mountpoint,
            "fstype":     part.fstype,
            "opts":       part.opts,
            "is_virtual": is_virtual,
            "alias_of":   alias_of,
            "total_gb":   (usage or {}).get("total_gb"),
            "used_gb":    (usage or {}).get("used_gb"),
            "free_gb":    (usage or {}).get("free_gb"),
            "percent":    (usage or {}).get("percent"),
        }
        mounts.append(row)
    return {"mounts": mounts, "count": len(mounts), "checked_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Servers — auto-detection
# ---------------------------------------------------------------------------

def _detect_server(key: str, meta: dict) -> dict | None:
    found = any(shutil.which(b) for b in meta["binaries"])
    if not found:
        # Also check if config path exists
        found = any(Path(p).exists() for p in meta["config_paths"])
    if not found:
        return None
    active = _service_active(meta["service"])
    enabled = _service_enabled(meta["service"])
    return {
        "key": key,
        "label": meta["label"],
        "service": meta["service"],
        "category": meta["category"],
        "active": active,
        "enabled": enabled,
        "running": active == "active",
    }


@router.get("/servers")
async def list_servers(_: str = Depends(require_super_admin)) -> dict:
    detected_keys: set[str] = set()
    servers = []
    for key, meta in KNOWN_SERVERS.items():
        srv = _detect_server(key, meta)
        if not srv:
            continue
        # If MariaDB is present, skip the MySQL entry (MariaDB ships a mysql compat binary)
        if key == "mysql" and "mariadb" in detected_keys:
            continue
        if key == "mariadb" and "mysql" in detected_keys:
            # Replace the mysql entry with mariadb
            servers = [s for s in servers if s["key"] != "mysql"]
        detected_keys.add(key)
        servers.append(srv)
    return {"servers": servers, "count": len(servers), "checked_at": datetime.now(UTC).isoformat()}


@router.get("/servers/{key}")
async def get_server(key: str, _: str = Depends(require_super_admin)) -> dict:
    if key not in KNOWN_SERVERS:
        raise HTTPException(404, "Unknown server")
    meta = KNOWN_SERVERS[key]
    detected = _detect_server(key, meta)
    if not detected:
        raise HTTPException(404, "Server not installed")

    # Read first existing config file (first 200 lines)
    config_content = None
    config_path = None
    for cp in meta["config_paths"]:
        p = Path(cp)
        if p.is_file():
            try:
                lines = p.read_text(errors="replace").splitlines()[:200]
                config_content = "\n".join(lines)
                config_path = cp
            except Exception:
                pass
            break

    # Tail first existing log file — use sudo to handle root-owned log dirs
    log_lines = []
    log_path = None
    for lp in meta["log_paths"]:
        out = _run_out(["sudo", "tail", "-n50", lp])
        if out.strip():
            log_lines = out.splitlines()
            log_path = lp
            break

    return {
        **detected,
        "config_path": config_path,
        "config_content": config_content,
        "log_path": log_path,
        "log_lines": log_lines,
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Network speed test
# ---------------------------------------------------------------------------

@router.post("/speedtest")
async def run_speedtest(_: str = Depends(require_super_admin)) -> dict:
    """Run a network speed test using the first available CLI tool."""
    import asyncio, json as _json, shutil

    async def _run(cmd: list[str], timeout: int = 60) -> dict | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            if proc.returncode != 0:
                return None
            return _json.loads(stdout.decode())
        except Exception:
            return None

    def _is_valid(dl: float, ul: float, ping: float) -> bool:
        # speedtest-cli returns ping=1800000 and speeds=0 when test servers are unreachable
        return ping < 10_000 and (dl > 0 or ul > 0)

    # --- Ookla official speedtest CLI (bytes/sec bandwidth) ---
    # Only attempt if it's actually the Ookla binary (not Python speedtest-cli)
    ookla_path = shutil.which("speedtest")
    if ookla_path:
        ver_proc = await _run([ookla_path, "--version"], timeout=5)
        # Ookla binary returns structured JSON for --version; Python speedtest-cli returns None (non-JSON stdout)
        ookla_available = ver_proc is not None
    else:
        ookla_available = False

    if ookla_available:
        data = await _run([ookla_path, "--accept-gdpr", "--accept-license", "-f", "json"])
        if data and "download" in data and isinstance(data["download"], dict):
            bw_dl = data["download"].get("bandwidth", 0)   # bytes/sec
            bw_ul = data["upload"].get("bandwidth", 0)
            ping  = data.get("ping", {}).get("latency", 0)
            dl_mbps = round(bw_dl * 8 / 1_000_000, 2)
            ul_mbps = round(bw_ul * 8 / 1_000_000, 2)
            if _is_valid(dl_mbps, ul_mbps, ping):
                srv = data.get("server", {})
                return {
                    "download_mbps": dl_mbps,
                    "upload_mbps":   ul_mbps,
                    "ping_ms":       round(ping, 1),
                    "server":        f"{srv.get('name', '')}, {srv.get('location', '')}".strip(", "),
                    "isp":           data.get("isp", ""),
                    "tested_at":     datetime.now(UTC).isoformat(),
                }

    # --- speedtest-cli Python package (bits/sec) ---
    # speedtest-cli exits 0 even on HTTP errors (403, network failures), returning
    # error text to stdout instead of JSON. We must distinguish:
    #   - tool not found (shutil.which returns None)
    #   - speedtest.net blocked/rate-limited (HTTP 4xx in stdout)
    #   - server unresponsive (ping=1800000, speeds=0)
    #   - success

    _BLOCK_PATTERNS = ("403", "Forbidden", "Cannot retrieve", "Unable to connect", "ERROR")

    async def _run_raw(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
        """Run command and return (returncode, stdout, stderr)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode, stdout.decode(), stderr.decode()
        except Exception as exc:
            return -1, "", str(exc)

    async def _get_nearest_server_id(binary: str) -> tuple[str | None, str | None]:
        """Return (server_id, error_detail). error_detail is set when blocked."""
        import re as _re
        rc, stdout, _ = await _run_raw([binary, "--list"], timeout=20)
        combined = stdout
        for pat in _BLOCK_PATTERNS:
            if pat in combined:
                return None, f"speedtest.net refused the connection ({combined.strip().splitlines()[-1]}). This is usually temporary rate-limiting — try again in a few minutes."
        for line in combined.splitlines():
            m = _re.match(r"^\s*(\d+)\)", line)
            if m:
                return m.group(1), None
        return None, None   # no servers found but no explicit error

    # Check tool is installed before attempting
    cli_binary = shutil.which("speedtest-cli")
    if not cli_binary:
        raise HTTPException(status_code=503, detail="speedtest-cli is not installed. Run: apt install speedtest-cli")

    server_id, block_error = await _get_nearest_server_id(cli_binary)
    if block_error:
        raise HTTPException(status_code=503, detail=block_error)

    cmd = [cli_binary, "--json"]
    if server_id:
        cmd += ["--server", server_id]
    rc, stdout, stderr = await _run_raw(cmd, timeout=90)

    # Check for blocking errors in the test output too
    for pat in _BLOCK_PATTERNS:
        if pat in stdout or pat in stderr:
            raise HTTPException(
                status_code=503,
                detail=f"speedtest.net blocked the test. This is usually temporary — try again in a few minutes.",
            )

    try:
        data = _json.loads(stdout)
    except Exception:
        raw = (stdout + stderr).strip().splitlines()
        last = raw[-1] if raw else "no output"
        raise HTTPException(status_code=503, detail=f"Speed test returned unexpected output: {last}")

    if "download" in data and isinstance(data["download"], (int, float)):
        dl_mbps = round(data["download"] / 1_000_000, 2)
        ul_mbps = round(data["upload"]   / 1_000_000, 2)
        ping    = data.get("ping", 0)
        if not _is_valid(dl_mbps, ul_mbps, ping):
            raise HTTPException(
                status_code=503,
                detail="Speed test completed but returned invalid measurements (ping>10s or zero speeds). Try again.",
            )
        srv = data.get("server", {})
        loc = ", ".join(filter(None, [srv.get("name"), srv.get("country")]))
        return {
            "download_mbps": dl_mbps,
            "upload_mbps":   ul_mbps,
            "ping_ms":       round(ping, 1),
            "server":        loc,
            "isp":           data.get("client", {}).get("isp", ""),
            "tested_at":     datetime.now(UTC).isoformat(),
        }


# ---------------------------------------------------------------------------
# Network Configuration
# ---------------------------------------------------------------------------

@router.get("/network-config")
async def get_network_config(_: str = Depends(require_super_admin)) -> dict:
    import socket
    import struct

    af_inet  = 2   # AF_INET  (IPv4)
    af_inet6 = 10  # AF_INET6 (IPv6)
    af_link  = 17  # AF_PACKET (MAC address on Linux)

    net_if_addrs  = psutil.net_if_addrs()
    net_if_stats  = psutil.net_if_stats()
    net_io        = psutil.net_io_counters(pernic=True)

    interfaces = []
    for iface, addrs in net_if_addrs.items():
        stats   = net_if_stats.get(iface)
        io      = net_io.get(iface)
        ipv4    = [a for a in addrs if a.family == af_inet]
        ipv6    = [a for a in addrs if a.family == af_inet6]
        mac_rec = next((a for a in addrs if a.family == af_link), None)

        def _cidr(netmask: str | None) -> str | None:
            if not netmask:
                return None
            try:
                return str(sum(bin(int(o)).count("1") for o in netmask.split(".")))
            except Exception:
                return None

        interfaces.append({
            "name":       iface,
            "is_up":      stats.isup if stats else False,
            "speed_mbps": stats.speed if stats else 0,
            "mtu":        stats.mtu if stats else 0,
            "mac":        mac_rec.address if mac_rec else None,
            "ipv4": [
                {
                    "address": a.address,
                    "netmask": a.netmask,
                    "cidr":    _cidr(a.netmask),
                    "broadcast": a.broadcast,
                }
                for a in ipv4
            ],
            "ipv6": [
                {
                    "address": a.address.split("%")[0],
                    "netmask": a.netmask,
                }
                for a in ipv6
                if not a.address.lower().startswith("fe80")
            ],
            "io": {
                "bytes_sent": io.bytes_sent if io else 0,
                "bytes_recv": io.bytes_recv if io else 0,
                "packets_sent": io.packets_sent if io else 0,
                "packets_recv": io.packets_recv if io else 0,
                "errin": io.errin if io else 0,
                "errout": io.errout if io else 0,
                "dropin": io.dropin if io else 0,
                "dropout": io.dropout if io else 0,
            } if io else None,
        })

    # DNS servers from /etc/resolv.conf
    dns_servers: list[str] = []
    dns_search: list[str] = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        dns_servers.append(parts[1])
                elif line.startswith("search") or line.startswith("domain"):
                    dns_search.extend(line.split()[1:])
    except OSError:
        pass

    # Routing table via `ip route show`
    routes: list[dict] = []
    try:
        out = _run_out(["ip", "route", "show"])
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            route: dict[str, str | None] = {
                "destination": parts[0] if parts else None,
                "gateway": None,
                "interface": None,
                "metric": None,
                "proto": None,
                "scope": None,
            }
            i = 1
            while i < len(parts):
                if parts[i] == "via" and i + 1 < len(parts):
                    route["gateway"] = parts[i + 1]; i += 2
                elif parts[i] == "dev" and i + 1 < len(parts):
                    route["interface"] = parts[i + 1]; i += 2
                elif parts[i] == "metric" and i + 1 < len(parts):
                    route["metric"] = parts[i + 1]; i += 2
                elif parts[i] == "proto" and i + 1 < len(parts):
                    route["proto"] = parts[i + 1]; i += 2
                elif parts[i] == "scope" and i + 1 < len(parts):
                    route["scope"] = parts[i + 1]; i += 2
                else:
                    i += 1
            routes.append(route)
    except Exception:
        pass

    # Default gateway
    default_gateway: str | None = next(
        (r["gateway"] for r in routes if r.get("destination") in ("default", "0.0.0.0/0") and r.get("gateway")),
        None,
    )

    # Firewall state — FrothIQ-nft preferred; fall back to ufw then nftables
    # CSF/LFD is intentionally excluded: it was decommissioned when FrothIQ took over.
    firewall: dict = {"tool": "unknown", "state": "unknown", "rules": []}

    frothiq_nft_out, _, frothiq_nft_rc = _run(["systemctl", "is-active", "frothiq-nft"])
    frothiq_nft_state = frothiq_nft_out.strip() if frothiq_nft_rc == 0 else "inactive"

    if frothiq_nft_state in ("active", "activating") or frothiq_nft_rc == 0:
        # --- FrothIQ nft firewall detected ---
        frothiq_lfd_out, _, frothiq_lfd_rc = _run(["systemctl", "is-active", "frothiq-lfd"])
        frothiq_lfd_state = frothiq_lfd_out.strip() if frothiq_lfd_rc == 0 else "inactive"

        # Count blacklisted IPs from the live nft set
        def _count_nft_set(set_name: str) -> int:
            try:
                import re as _re
                out, _, rc = _run(["nft", "list", "set", "inet", "frothiq", set_name])
                if rc != 0:
                    return 0
                m = _re.search(r"elements\s*=\s*\{([^}]+)\}", out, _re.DOTALL)
                if not m:
                    return 0
                return sum(1 for t in _re.split(r",", m.group(1)) if t.strip().split()[0:1] and _re.match(r"^[\d./a-fA-F:]+$", t.strip().split()[0]))
            except Exception:
                return 0

        blacklist_count = _count_nft_set("blacklist")
        temp_ban_count  = _count_nft_set("temp_ban")

        overall_state = "active" if frothiq_nft_state == "active" else "inactive"

        firewall = {
            "tool":               "frothiq",
            "state":              overall_state,
            "frothiq_nft_state":  frothiq_nft_state,
            "frothiq_lfd_state":  frothiq_lfd_state,
            "blacklist_count":    blacklist_count,
            "temp_ban_count":     temp_ban_count,
            "rules":              [],
        }
    else:
        ufw_out, _, ufw_rc = _run(["ufw", "status", "verbose"])
        if ufw_rc == 0:
            lines = ufw_out.splitlines()
            state_line = next((l for l in lines if l.lower().startswith("status:")), "")
            firewall = {
                "tool": "ufw",
                "state": state_line.replace("Status:", "").strip() if state_line else "unknown",
                "rules": [l for l in lines if l and not l.startswith("Status") and not l.startswith("Logging") and not l.startswith("Default") and not l.startswith("New profiles") and l.strip()],
            }
        else:
            nft_out, _, nft_rc = _run(["nft", "list", "ruleset"])
            if nft_rc == 0:
                firewall = {
                    "tool": "nftables",
                    "state": "active",
                    "rules": nft_out.splitlines()[:40],
                }

    # Open listening ports via ss
    ports: list[dict] = []
    try:
        ss_out = _run_out(["ss", "-tlnp"])
        for line in ss_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[3]
            process = parts[6] if len(parts) > 6 else ""
            addr, _, port = local.rpartition(":")
            ports.append({"local_address": addr or "*", "port": port, "process": process})
    except Exception:
        pass

    # DNS resolution check
    dns_ok = False
    try:
        socket.getaddrinfo("google.com", 80, proto=socket.IPPROTO_TCP)
        dns_ok = True
    except Exception:
        pass

    # Connectivity checks: ping 8.8.8.8 (external) and default gateway (internal)
    def _ping(host: str) -> dict:
        out, _, rc = _run(["ping", "-c", "3", "-W", "2", host])
        if rc == 0:
            rtt = None
            for l in out.splitlines():
                if "rtt" in l or "round-trip" in l:
                    parts = l.split("=")
                    if len(parts) > 1:
                        rtt = parts[1].strip().split("/")[1] + " ms" if "/" in parts[1] else parts[1].strip()
            return {"host": host, "reachable": True, "rtt_avg": rtt}
        return {"host": host, "reachable": False, "rtt_avg": None}

    ping_external = _ping("8.8.8.8")
    ping_gateway  = _ping(default_gateway) if default_gateway else {"host": default_gateway, "reachable": None, "rtt_avg": None}

    return {
        "interfaces":       interfaces,
        "dns_servers":      dns_servers,
        "dns_search":       dns_search,
        "dns_resolves":     dns_ok,
        "routes":           routes,
        "default_gateway":  default_gateway,
        "firewall":         firewall,
        "open_ports":       ports,
        "connectivity": {
            "external": ping_external,
            "gateway":  ping_gateway,
        },
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Hardware Info
# ---------------------------------------------------------------------------

@router.get("/hardware")
async def get_hardware(_: str = Depends(require_super_admin)) -> dict:
    uname = platform.uname()

    # CPU
    cpu_freq = psutil.cpu_freq()
    cpu_info: dict = {
        "logical_cores":  psutil.cpu_count(logical=True),
        "physical_cores": psutil.cpu_count(logical=False),
        "percent":        psutil.cpu_percent(interval=0.3),
        "per_core":       psutil.cpu_percent(interval=0, percpu=True),
        "freq_mhz":       round(cpu_freq.current, 1) if cpu_freq else None,
        "freq_max_mhz":   round(cpu_freq.max, 1) if cpu_freq else None,
        "model":          None,
        "arch":           uname.machine,
        "load_avg_1m":    round(psutil.getloadavg()[0], 2),
        "load_avg_5m":    round(psutil.getloadavg()[1], 2),
        "load_avg_15m":   round(psutil.getloadavg()[2], 2),
    }
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu_info["model"] = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass

    # Memory
    mem  = psutil.virtual_memory()
    swap = psutil.swap_memory()
    memory = {
        "total_gb":     round(mem.total / 1e9, 2),
        "used_gb":      round(mem.used / 1e9, 2),
        "available_gb": round(mem.available / 1e9, 2),
        "cached_gb":    round(getattr(mem, "cached", 0) / 1e9, 2),
        "buffers_gb":   round(getattr(mem, "buffers", 0) / 1e9, 2),
        "percent":      mem.percent,
        "swap_total_gb": round(swap.total / 1e9, 2),
        "swap_used_gb":  round(swap.used / 1e9, 2),
        "swap_percent":  swap.percent,
    }

    # Disks
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except PermissionError:
            continue
        disks.append({
            "device":     part.device,
            "mountpoint": part.mountpoint,
            "fstype":     part.fstype,
            "opts":       part.opts,
            "total_gb":   round(usage.total / 1e9, 2),
            "used_gb":    round(usage.used / 1e9, 2),
            "free_gb":    round(usage.free / 1e9, 2),
            "percent":    usage.percent,
        })

    # Block devices (lsblk)
    block_devices: list[dict] = []
    try:
        out = _run_out(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MODEL,ROTA,TRAN"])
        import json as _json
        lsblk = _json.loads(out)
        block_devices = lsblk.get("blockdevices", [])
    except Exception:
        pass

    # Temperature sensors
    temps: dict = {}
    try:
        raw = psutil.sensors_temperatures()
        for name, entries in raw.items():
            temps[name] = [
                {"label": e.label or name, "current": e.current, "high": e.high, "critical": e.critical}
                for e in entries
            ]
    except (AttributeError, Exception):
        pass

    # GPU (nvidia-smi if available)
    gpu: list[dict] = []
    try:
        out = _run_out(["nvidia-smi", "--query-gpu=name,memory.total,memory.used,utilization.gpu,temperature.gpu",
                        "--format=csv,noheader,nounits"])
        for line in out.strip().splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                gpu.append({
                    "name":         parts[0],
                    "memory_total": parts[1] + " MiB",
                    "memory_used":  parts[2] + " MiB",
                    "utilization":  parts[3] + "%",
                    "temperature":  parts[4] + "°C",
                })
    except Exception:
        pass

    # System / OS info
    try:
        os_release = platform.freedesktop_os_release()
        os_pretty = os_release.get("PRETTY_NAME", f"{uname.system} {uname.release}")
    except (OSError, AttributeError):
        os_pretty = f"{uname.system} {uname.release}"

    # DMI / hardware info (dmidecode — requires root; graceful fallback)
    dmi: dict = {}
    try:
        for dmi_type, key in [("system", "system"), ("baseboard", "baseboard"), ("bios", "bios")]:
            out, _, rc = _run(["dmidecode", "-t", dmi_type])
            if rc == 0:
                entry: dict = {}
                for line in out.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        k = k.strip(); v = v.strip()
                        if k and v and v not in ("Not Specified", "Not Present", "To Be Filled By O.E.M."):
                            entry[k] = v
                dmi[key] = entry
    except Exception:
        pass

    boot_ts = psutil.boot_time()

    return {
        "cpu":     cpu_info,
        "memory":  memory,
        "disks":   disks,
        "block_devices": block_devices,
        "temperatures": temps,
        "gpu":     gpu,
        "dmi":     dmi,
        "system": {
            "hostname": uname.node,
            "os":       os_pretty,
            "kernel":   uname.release,
            "arch":     uname.machine,
            "uptime":   _uptime_str(boot_ts),
            "boot_time": datetime.fromtimestamp(boot_ts, tz=UTC).isoformat(),
            "processes": len(psutil.pids()),
            "python":   platform.python_version(),
        },
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

import logging as _logging

_audit_log = _logging.getLogger("mc2.audit")
if not _audit_log.handlers:
    try:
        _h = _logging.FileHandler("/var/log/mc2-audit.log", delay=True)
        _h.setFormatter(_logging.Formatter("%(asctime)s  %(message)s"))
        _audit_log.addHandler(_h)
    except OSError:
        pass
    _audit_log.addHandler(_logging.StreamHandler())
    _audit_log.setLevel(_logging.INFO)


def _audit(user: str, action: str, detail: str, result: str) -> None:
    _audit_log.info("user=%s action=%s detail=%r result=%s", user, action, detail, result)


# ---------------------------------------------------------------------------
# Allowed network interfaces (validated against psutil at call time)
# ---------------------------------------------------------------------------

def _validate_iface(name: str) -> None:
    allowed = set(psutil.net_if_addrs().keys())
    if name not in allowed:
        raise HTTPException(status_code=400, detail=f"Unknown interface: {name!r}")


def _validate_ip(addr: str) -> None:
    import ipaddress
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {addr!r}")


def _validate_prefix(prefix: int) -> None:
    if not (0 <= prefix <= 128):
        raise HTTPException(status_code=400, detail=f"Invalid prefix length: {prefix}")


# ---------------------------------------------------------------------------
# Network: Interface link up/down
# ---------------------------------------------------------------------------

class IfaceLinkRequest(BaseModel):
    action: str  # "up" | "down"


@router.post("/network/interface/{name}/link")
async def iface_link(name: str, body: IfaceLinkRequest, user: str = Depends(require_super_admin)) -> dict:
    if body.action not in ("up", "down"):
        raise HTTPException(status_code=400, detail="action must be 'up' or 'down'")
    _validate_iface(name)
    out, err, rc = _run(["ip", "link", "set", name, body.action])
    result = "ok" if rc == 0 else "error"
    _audit(user, f"iface_link_{body.action}", name, result)
    if rc != 0:
        raise HTTPException(status_code=500, detail=err.strip() or f"ip link set {name} {body.action} failed")
    # Verify new state
    stats = psutil.net_if_stats().get(name)
    return {
        "ok": True,
        "interface": name,
        "action": body.action,
        "is_up": stats.isup if stats else None,
        "executed_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Network: IP configuration (static or DHCP)
# ---------------------------------------------------------------------------

class IfaceIPRequest(BaseModel):
    mode: str           # "static" | "dhcp"
    address: str = ""   # required for static
    prefix: int = 24    # CIDR prefix length
    gateway: str = ""   # optional for static


@router.post("/network/interface/{name}/ip")
async def iface_ip(name: str, body: IfaceIPRequest, user: str = Depends(require_super_admin)) -> dict:
    if body.mode not in ("static", "dhcp"):
        raise HTTPException(status_code=400, detail="mode must be 'static' or 'dhcp'")
    _validate_iface(name)

    if body.mode == "static":
        if not body.address:
            raise HTTPException(status_code=400, detail="address is required for static mode")
        _validate_ip(body.address)
        _validate_prefix(body.prefix)
        if body.gateway:
            _validate_ip(body.gateway)

        # Flush existing IPv4 addresses, assign new one
        _run(["ip", "addr", "flush", "dev", name])
        out, err, rc = _run(["ip", "addr", "add", f"{body.address}/{body.prefix}", "dev", name])
        if rc != 0:
            _audit(user, "iface_ip_static", f"{name} {body.address}/{body.prefix}", "error")
            raise HTTPException(status_code=500, detail=err.strip() or "ip addr add failed")

        if body.gateway:
            _run(["ip", "route", "replace", "default", "via", body.gateway, "dev", name])

        detail = f"{name} {body.address}/{body.prefix} gw={body.gateway or 'unchanged'}"
        _audit(user, "iface_ip_static", detail, "ok")
        return {"ok": True, "interface": name, "mode": "static", "address": body.address,
                "prefix": body.prefix, "gateway": body.gateway or None,
                "executed_at": datetime.now(UTC).isoformat()}

    else:  # dhcp
        # Release existing static config and request DHCP lease via dhclient
        _run(["ip", "addr", "flush", "dev", name])
        out, err, rc = _run(["dhclient", "-v", name], timeout=20)
        if rc != 0:
            # Try dhcpcd as fallback
            out2, err2, rc2 = _run(["dhcpcd", name], timeout=20)
            if rc2 != 0:
                _audit(user, "iface_ip_dhcp", name, "error")
                raise HTTPException(status_code=500, detail="dhclient and dhcpcd both failed — no DHCP client available")
        _audit(user, "iface_ip_dhcp", name, "ok")
        return {"ok": True, "interface": name, "mode": "dhcp",
                "executed_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Network: DNS configuration
# ---------------------------------------------------------------------------

class DNSRequest(BaseModel):
    servers: list[str]  # list of IP address strings


@router.put("/network/dns")
async def update_dns(body: DNSRequest, user: str = Depends(require_super_admin)) -> dict:
    if not body.servers:
        raise HTTPException(status_code=400, detail="At least one DNS server required")
    if len(body.servers) > 4:
        raise HTTPException(status_code=400, detail="Maximum 4 DNS servers allowed")
    for s in body.servers:
        _validate_ip(s)

    resolv = Path("/etc/resolv.conf")

    # Backup original
    backup_path = Path(f"/etc/resolv.conf.mc3bak.{int(time.time())}")
    try:
        if resolv.exists():
            import shutil as _shutil
            _shutil.copy2(str(resolv), str(backup_path))
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Could not create backup: {e}")

    # Preserve existing search/domain lines, replace nameserver lines
    existing_lines: list[str] = []
    try:
        with open(resolv) as f:
            existing_lines = f.readlines()
    except OSError:
        pass

    non_ns_lines = [l for l in existing_lines if not l.startswith("nameserver")]
    new_lines = non_ns_lines + [f"nameserver {s}\n" for s in body.servers]

    try:
        with open(resolv, "w") as f:
            f.writelines(new_lines)
    except OSError as e:
        _audit(user, "update_dns", str(body.servers), "error")
        raise HTTPException(status_code=500, detail=f"Could not write /etc/resolv.conf: {e}")

    _audit(user, "update_dns", f"servers={body.servers}", "ok")
    return {
        "ok": True,
        "servers": body.servers,
        "backup": str(backup_path),
        "executed_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Network: Restart networking
# ---------------------------------------------------------------------------

@router.post("/network/restart")
async def restart_networking(user: str = Depends(require_super_admin)) -> dict:
    # Try systemd-networkd first, then networking, then NetworkManager
    for service in ("systemd-networkd", "networking", "NetworkManager"):
        _, _, rc = _run(["systemctl", "is-active", service])
        if rc == 0:
            out, err, rc2 = _run(["systemctl", "restart", service], timeout=30)
            result = "ok" if rc2 == 0 else "error"
            _audit(user, "restart_networking", service, result)
            if rc2 != 0:
                raise HTTPException(status_code=500, detail=err.strip() or f"systemctl restart {service} failed")
            return {"ok": True, "service": service, "executed_at": datetime.now(UTC).isoformat()}

    _audit(user, "restart_networking", "none_found", "error")
    raise HTTPException(status_code=404, detail="No active network service found (systemd-networkd / networking / NetworkManager)")


# ---------------------------------------------------------------------------
# Disk: Mount / Unmount
# ---------------------------------------------------------------------------

# Allowed filesystem types for mounting
_ALLOWED_FSTYPES = {
    "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat",
    "ntfs", "tmpfs", "iso9660", "udf",
}

# Block device path must start with /dev/
_DEV_RE = re.compile(r"^/dev/[a-zA-Z0-9/_-]+$")
# Mountpoint must be an absolute path
_MP_RE  = re.compile(r"^/[a-zA-Z0-9_/.-]*$")


class MountRequest(BaseModel):
    device: str
    mountpoint: str
    fstype: str = "ext4"
    options: str = "defaults"


@router.post("/disk/mount")
async def disk_mount(body: MountRequest, user: str = Depends(require_super_admin)) -> dict:
    if not _DEV_RE.match(body.device):
        raise HTTPException(status_code=400, detail="Invalid device path")
    if not _MP_RE.match(body.mountpoint):
        raise HTTPException(status_code=400, detail="Invalid mountpoint path")
    if body.fstype not in _ALLOWED_FSTYPES:
        raise HTTPException(status_code=400, detail=f"Filesystem type not allowed: {body.fstype!r}")
    # options: allow only safe alphanumeric/comma/= chars
    if not re.match(r"^[a-zA-Z0-9,=_-]+$", body.options):
        raise HTTPException(status_code=400, detail="Invalid mount options")

    # Ensure mountpoint exists
    Path(body.mountpoint).mkdir(parents=True, exist_ok=True)

    cmd = ["mount", "-t", body.fstype, "-o", body.options, body.device, body.mountpoint]
    out, err, rc = _run(cmd, timeout=15)
    result = "ok" if rc == 0 else "error"
    _audit(user, "disk_mount", f"{body.device} → {body.mountpoint} ({body.fstype})", result)
    if rc != 0:
        raise HTTPException(status_code=500, detail=err.strip() or "mount failed")
    return {"ok": True, "device": body.device, "mountpoint": body.mountpoint,
            "fstype": body.fstype, "executed_at": datetime.now(UTC).isoformat()}


class UnmountRequest(BaseModel):
    mountpoint: str
    lazy: bool = False   # -l flag — unmount when no longer busy


@router.post("/disk/unmount")
async def disk_unmount(body: UnmountRequest, user: str = Depends(require_super_admin)) -> dict:
    if not _MP_RE.match(body.mountpoint):
        raise HTTPException(status_code=400, detail="Invalid mountpoint path")

    # Refuse to unmount critical system paths
    protected = {"/", "/boot", "/boot/efi", "/proc", "/sys", "/dev", "/run", "/tmp"}
    if body.mountpoint.rstrip("/") in protected:
        raise HTTPException(status_code=403, detail=f"Cannot unmount protected path: {body.mountpoint}")

    cmd = ["umount"]
    if body.lazy:
        cmd.append("-l")
    cmd.append(body.mountpoint)
    out, err, rc = _run(cmd, timeout=15)
    result = "ok" if rc == 0 else "error"
    _audit(user, "disk_unmount", body.mountpoint, result)
    if rc != 0:
        raise HTTPException(status_code=500, detail=err.strip() or "umount failed")
    return {"ok": True, "mountpoint": body.mountpoint, "executed_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# System: Reboot / Shutdown
# ---------------------------------------------------------------------------

class SystemPowerRequest(BaseModel):
    confirm: bool = False  # must be True to execute


@router.post("/system/reboot")
async def system_reboot(body: SystemPowerRequest, user: str = Depends(require_super_admin)) -> dict:
    if not body.confirm:
        raise HTTPException(status_code=400, detail="confirm must be true")
    _audit(user, "system_reboot", "requested", "executing")
    out, err, rc = _run(["shutdown", "-r", "+0"], timeout=10)
    result = "ok" if rc == 0 else "error"
    _audit(user, "system_reboot", "shutdown -r +0", result)
    if rc != 0:
        raise HTTPException(status_code=500, detail=err.strip() or "reboot failed")
    return {"ok": True, "action": "reboot", "executed_at": datetime.now(UTC).isoformat()}


@router.post("/system/shutdown")
async def system_shutdown(body: SystemPowerRequest, user: str = Depends(require_super_admin)) -> dict:
    if not body.confirm:
        raise HTTPException(status_code=400, detail="confirm must be true")
    _audit(user, "system_shutdown", "requested", "executing")
    out, err, rc = _run(["shutdown", "-h", "+0"], timeout=10)
    result = "ok" if rc == 0 else "error"
    _audit(user, "system_shutdown", "shutdown -h +0", result)
    if rc != 0:
        raise HTTPException(status_code=500, detail=err.strip() or "shutdown failed")
    return {"ok": True, "action": "shutdown", "executed_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Watchdog — critical service health check
# ---------------------------------------------------------------------------

_WATCHDOG_SERVICES = [
    "frothiq-control-center",
    "frothiq-ui",
    "frothiq-nft",
    "supervisor",
    "apache2",
    "mysql",
    "redis-server",
]


def _check_service_active(name: str) -> bool:
    try:
        out, _, rc = _run(["systemctl", "is-active", name], timeout=5)
        return rc == 0 and out.strip() == "active"
    except Exception:
        return False


@router.get("/watchdog")
async def get_watchdog(_: str = Depends(require_super_admin)) -> dict:
    """Check health of critical services."""
    import asyncio as _asyncio
    loop = _asyncio.get_event_loop()
    results = await _asyncio.gather(
        *[loop.run_in_executor(None, _check_service_active, svc) for svc in _WATCHDOG_SERVICES]
    )
    services = dict(zip(_WATCHDOG_SERVICES, results))
    return {
        "services": services,
        "all_healthy": all(results),
        "checked_at": datetime.now(UTC).isoformat(),
    }


@router.post("/watchdog/run")
async def run_watchdog(_: str = Depends(require_super_admin)) -> dict:
    """Trigger an immediate watchdog check and return results."""
    import asyncio as _asyncio
    loop = _asyncio.get_event_loop()
    results = await _asyncio.gather(
        *[loop.run_in_executor(None, _check_service_active, svc) for svc in _WATCHDOG_SERVICES]
    )
    services = dict(zip(_WATCHDOG_SERVICES, results))
    return {
        "ok": all(results),
        "services": services,
        "checked_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Audit log — tail /var/log/mc2-audit.log
# ---------------------------------------------------------------------------

import re as _re

_AUDIT_LOG_PATH = Path("/var/log/mc2-audit.log")
_AUDIT_PATTERN = _re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\s+"
    r"(?:user=(?P<user>\S+)\s+)?(?:action=(?P<action>\S+)\s+)?(?:detail=(?P<detail>.*?)\s+)?(?:result=(?P<result>\S+))?$"
)


def _parse_audit_line(line: str) -> dict:
    m = _AUDIT_PATTERN.match(line.strip())
    if m:
        return {
            "timestamp": m.group("ts"),
            "user": m.group("user") or "",
            "action": m.group("action") or "",
            "detail": (m.group("detail") or "").strip("'\""),
            "result": m.group("result") or "",
            "raw": line.strip(),
        }
    return {"raw": line.strip()}


@router.get("/audit-log")
async def get_audit_log(
    lines: int = Query(200, ge=1, le=5000),
    search: str | None = Query(None),
    _user=Depends(require_super_admin),
) -> dict:
    if not _AUDIT_LOG_PATH.exists():
        return {"entries": [], "total": 0, "path": str(_AUDIT_LOG_PATH)}

    try:
        out, _, _ = _run(["tail", "-n", str(lines), str(_AUDIT_LOG_PATH)], timeout=10)
    except Exception:
        return {"entries": [], "total": 0, "path": str(_AUDIT_LOG_PATH)}

    raw_lines = [ln for ln in out.splitlines() if ln.strip()]
    if search:
        raw_lines = [ln for ln in raw_lines if search.lower() in ln.lower()]

    entries = [_parse_audit_line(ln) for ln in reversed(raw_lines)]
    return {
        "entries": entries,
        "total": len(entries),
        "path": str(_AUDIT_LOG_PATH),
    }


# ---------------------------------------------------------------------------
# Filesystem Backup — job definitions + rsync/tar runner
# ---------------------------------------------------------------------------

import json as _json_backup
import uuid as _uuid
import subprocess as _subprocess_backup
import threading as _threading_backup
from pathlib import Path as _Path_backup

_BACKUP_JOBS_FILE = _Path_backup("/var/lib/mc2/backup-jobs.json")
_BACKUP_RUN_DIR = _Path_backup("/var/lib/mc2/backup-runs")


def _load_backup_jobs() -> list:
    try:
        if _BACKUP_JOBS_FILE.exists():
            return _json_backup.loads(_BACKUP_JOBS_FILE.read_text())
    except Exception:
        pass
    return []


def _save_backup_jobs(jobs: list) -> None:
    _BACKUP_JOBS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _BACKUP_JOBS_FILE.write_text(_json_backup.dumps(jobs, indent=2))


def _get_run_dir(job_id: str) -> _Path_backup:
    d = _BACKUP_RUN_DIR / job_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _run_backup_job(job: dict) -> None:
    run_dir = _get_run_dir(job["id"])
    status_file = run_dir / "status"
    log_file = run_dir / "log"
    status_file.write_text("running")
    log_file.write_text("")

    src = job["source"]
    dst = job["destination"]
    method = job.get("method", "rsync")
    exclude = job.get("exclude", [])

    try:
        if method == "tar":
            cmd = ["tar", "-czf", dst, src]
        else:
            cmd = ["rsync", "-a", "--delete", "--stats"]
            for ex in exclude:
                cmd += ["--exclude", ex]
            cmd += [src, dst]

        proc = _subprocess_backup.Popen(
            cmd, stdout=_subprocess_backup.PIPE, stderr=_subprocess_backup.STDOUT,
            text=True, bufsize=1
        )
        lines = []
        for line in proc.stdout:
            lines.append(line.rstrip())
            log_file.write_text("\n".join(lines))

        proc.wait()
        result = "ok" if proc.returncode == 0 else "error"
    except Exception as exc:
        result = "error"
        log_file.write_text(str(exc))

    status_file.write_text(result)
    # Update last_run / last_result on the job record
    jobs = _load_backup_jobs()
    for j in jobs:
        if j["id"] == job["id"]:
            j["last_run"] = datetime.now(UTC).isoformat()
            j["last_result"] = result
            break
    _save_backup_jobs(jobs)


class _BackupJobCreate(BaseModel):
    name: str
    source: str
    destination: str
    method: str = "rsync"
    exclude: list[str] = []


@router.get("/backup-jobs")
async def list_backup_jobs(_=Depends(require_super_admin)) -> dict:
    jobs = _load_backup_jobs()
    return {"jobs": jobs, "total": len(jobs)}


@router.post("/backup-jobs")
async def create_backup_job(body: _BackupJobCreate, _=Depends(require_super_admin)) -> dict:
    jobs = _load_backup_jobs()
    job = {
        "id": str(_uuid.uuid4()),
        "name": body.name,
        "source": body.source,
        "destination": body.destination,
        "method": body.method,
        "exclude": body.exclude,
        "created_at": datetime.now(UTC).isoformat(),
        "last_run": None,
        "last_result": None,
    }
    jobs.append(job)
    _save_backup_jobs(jobs)
    return {"ok": True, "job": job}


@router.post("/backup-jobs/{job_id}/run")
async def run_backup_job(job_id: str, _=Depends(require_super_admin)) -> dict:
    jobs = _load_backup_jobs()
    job = next((j for j in jobs if j["id"] == job_id), None)
    if not job:
        raise HTTPException(404, "Job not found")
    _threading_backup.Thread(target=_run_backup_job, args=(job,), daemon=True).start()
    return {"ok": True, "job_id": job_id}


@router.get("/backup-jobs/{job_id}/log")
async def get_backup_job_log(job_id: str, _=Depends(require_super_admin)) -> dict:
    run_dir = _BACKUP_RUN_DIR / job_id
    status_file = run_dir / "status"
    log_file = run_dir / "log"
    status = status_file.read_text().strip() if status_file.exists() else "never"
    log_lines = log_file.read_text().splitlines() if log_file.exists() else []
    return {"job_id": job_id, "status": status, "log": log_lines}


@router.delete("/backup-jobs/{job_id}")
async def delete_backup_job(job_id: str, _=Depends(require_super_admin)) -> dict:
    jobs = _load_backup_jobs()
    jobs = [j for j in jobs if j["id"] != job_id]
    _save_backup_jobs(jobs)
    return {"ok": True}


# ---------------------------------------------------------------------------
# SSH keys — manage authorized_keys for system users
# ---------------------------------------------------------------------------

import re as _re_ssh

_SSH_KEY_RE = _re_ssh.compile(r"^(ssh-\S+|ecdsa-\S+)\s+\S+(\s+\S+)?$")


def _authorized_keys_path(username: str) -> Path:
    pw = pwd.getpwnam(username)
    return Path(pw.pw_dir) / ".ssh" / "authorized_keys"


@router.get("/ssh-keys")
async def list_ssh_keys(username: str = Query("root"), _=Depends(require_super_admin)) -> dict:
    try:
        ak = _authorized_keys_path(username)
        lines = ak.read_text().splitlines() if ak.exists() else []
    except KeyError:
        raise HTTPException(404, f"User {username!r} not found")
    keys = []
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        keys.append({
            "index": i,
            "type": parts[0] if parts else "",
            "key": parts[1][:20] + "…" if len(parts) > 1 else "",
            "fingerprint": parts[1][:20] + "…" if len(parts) > 1 else "",
            "comment": parts[2] if len(parts) > 2 else "",
            "full": line,
            "raw": line,
        })
    return {"username": username, "keys": keys, "count": len(keys)}


@router.post("/ssh-keys")
async def add_ssh_key(
    username: str = Query("root"),
    key: str = Query(...),
    _=Depends(require_super_admin),
) -> dict:
    key = key.strip()
    if not _SSH_KEY_RE.match(key):
        raise HTTPException(400, "Invalid SSH public key format")
    try:
        ak = _authorized_keys_path(username)
    except KeyError:
        raise HTTPException(404, f"User {username!r} not found")
    ak.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    existing = ak.read_text() if ak.exists() else ""
    if not existing.endswith("\n") and existing:
        existing += "\n"
    ak.write_text(existing + key + "\n")
    ak.chmod(0o600)
    return {"ok": True}


@router.delete("/ssh-keys")
async def delete_ssh_key(
    username: str = Query("root"),
    key_prefix: str | None = Query(None),
    index: int | None = Query(None),
    _=Depends(require_super_admin),
) -> dict:
    try:
        ak = _authorized_keys_path(username)
    except KeyError:
        raise HTTPException(404, f"User {username!r} not found")
    lines = ak.read_text().splitlines(keepends=True) if ak.exists() else []
    if key_prefix is not None:
        # Remove by matching key prefix
        new_lines = [l for l in lines if not l.split()[1:2] or not l.split()[1].startswith(key_prefix)]
        ak.write_text("".join(new_lines))
    elif index is not None:
        content_lines = [(i, l) for i, l in enumerate(lines) if l.strip() and not l.strip().startswith("#")]
        if index >= len(content_lines):
            raise HTTPException(404, "Key index out of range")
        real_index = content_lines[index][0]
        lines.pop(real_index)
        ak.write_text("".join(lines))
    else:
        raise HTTPException(400, "Provide either key_prefix or index")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Alert thresholds — configurable CPU/mem/disk alert levels
# ---------------------------------------------------------------------------

_ALERT_THRESHOLDS_FILE = Path("/var/lib/mc2/alert-thresholds.json")
_DEFAULT_THRESHOLDS = {
    "cpu_warn": 80, "cpu_crit": 95,
    "mem_warn": 80, "mem_crit": 95,
    "disk_warn": 80, "disk_crit": 95,
    "load_warn": 4.0, "load_crit": 8.0,
}


def _load_thresholds() -> dict:
    try:
        if _ALERT_THRESHOLDS_FILE.exists():
            return {**_DEFAULT_THRESHOLDS, **json.loads(_ALERT_THRESHOLDS_FILE.read_text())}
    except Exception:
        pass
    return dict(_DEFAULT_THRESHOLDS)


@router.get("/alert-thresholds")
async def get_alert_thresholds(_=Depends(require_super_admin)) -> dict:
    t = _load_thresholds()
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    load1 = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0
    current = {"cpu_pct": cpu, "mem_pct": mem, "disk_root_pct": disk, "load_1m": load1}
    active_alerts = []
    if cpu > t.get("cpu_crit", 95):
        active_alerts.append({"metric": "cpu_pct", "level": "critical", "value": cpu})
    elif cpu > t.get("cpu_warn", 80):
        active_alerts.append({"metric": "cpu_pct", "level": "warning", "value": cpu})
    if mem > t.get("mem_crit", 95):
        active_alerts.append({"metric": "mem_pct", "level": "critical", "value": mem})
    elif mem > t.get("mem_warn", 80):
        active_alerts.append({"metric": "mem_pct", "level": "warning", "value": mem})
    if disk > t.get("disk_crit", 95):
        active_alerts.append({"metric": "disk_root_pct", "level": "critical", "value": disk})
    elif disk > t.get("disk_warn", 80):
        active_alerts.append({"metric": "disk_root_pct", "level": "warning", "value": disk})
    if load1 > t.get("load_crit", 8.0):
        active_alerts.append({"metric": "load_1m", "level": "critical", "value": load1})
    elif load1 > t.get("load_warn", 4.0):
        active_alerts.append({"metric": "load_1m", "level": "warning", "value": load1})
    return {"thresholds": t, "current": current, "active_alerts": active_alerts}


@router.post("/alert-thresholds")
async def update_alert_thresholds(body: dict, _=Depends(require_super_admin)) -> dict:
    thresholds = {**_DEFAULT_THRESHOLDS, **body}
    _ALERT_THRESHOLDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _ALERT_THRESHOLDS_FILE.write_text(json.dumps(thresholds, indent=2))
    return {"ok": True, "thresholds": thresholds}


# ---------------------------------------------------------------------------
# Log rotation — list logrotate configs + run logrotate
# ---------------------------------------------------------------------------

@router.get("/log-rotation")
async def list_log_rotation(_=Depends(require_super_admin)) -> dict:
    configs = []
    for conf_dir in [Path("/etc/logrotate.d"), Path("/etc/logrotate.conf").parent]:
        if conf_dir.exists() and conf_dir.is_dir():
            for f in sorted(conf_dir.iterdir()):
                if f.is_file():
                    configs.append({"name": f.name, "path": str(f), "size_kb": round(f.stat().st_size / 1024, 1)})
    # last_runs: parse logrotate status file — returns dict {path: last_rotated_date}
    last_runs: dict = {}
    for status_file in [Path("/var/lib/logrotate/status"), Path("/var/lib/logrotate/logrotate.status")]:
        if status_file.exists():
            try:
                for line in status_file.read_text().splitlines()[1:200]:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        last_runs[parts[0].strip('"')] = " ".join(parts[1:])
            except Exception:
                pass
            break
    return {"configs": configs, "total": len(configs), "last_runs": last_runs}


@router.post("/log-rotation/run")
async def run_logrotate(force: bool = Query(False), _=Depends(require_super_admin)) -> dict:
    cmd = ["logrotate", "-v"]
    if force:
        cmd.append("--force")
    cmd.append("/etc/logrotate.conf")
    out, err, rc = _run(cmd, timeout=60)
    return {"ok": rc == 0, "stdout": out.strip(), "stderr": err.strip(), "output": (out + err).strip()}


# ---------------------------------------------------------------------------
# Metrics history — store/retrieve per-minute system metrics
# ---------------------------------------------------------------------------

_METRICS_DB = Path("/var/lib/mc2/metrics-history.json")
_METRICS_MAX_ENTRIES = 1440  # 24 hours of per-minute data


def _load_metrics_history() -> list:
    try:
        if _METRICS_DB.exists():
            return json.loads(_METRICS_DB.read_text())
    except Exception:
        pass
    return []


@router.get("/metrics-history")
async def get_metrics_history(
    minutes: int = Query(60, ge=5, le=1440),
    resolution: int = Query(1, ge=1, le=60),
    _=Depends(require_super_admin),
) -> dict:
    history = _load_metrics_history()
    subset = history[-minutes:]
    if resolution > 1:
        subset = subset[::resolution]
    return {"entries": subset, "rows": subset, "total": len(subset)}


# ---------------------------------------------------------------------------
# Package holds — apt-mark hold/unhold
# ---------------------------------------------------------------------------

@router.get("/package-holds")
async def list_package_holds(_=Depends(require_super_admin)) -> dict:
    out, _, _ = _run(["apt-mark", "showhold"], timeout=10)
    holds = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return {"holds": holds, "held": holds, "total": len(holds)}


@router.post("/package-holds")
async def set_package_hold(package: str = Query(...), hold: bool = Query(True), _=Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-zA-Z0-9._+-]+$", package):
        raise HTTPException(400, "Invalid package name")
    action = "hold" if hold else "unhold"
    out, err, rc = _run(["apt-mark", action, package], timeout=15)
    return {"ok": rc == 0, "output": (out + err).strip()}


# ---------------------------------------------------------------------------
# PTY WebSocket URL — return the ws:// URL for the terminal
# ---------------------------------------------------------------------------

@router.get("/pty-ws-url")
async def get_pty_ws_url(request: Request, _=Depends(require_super_admin)) -> dict:
    host = request.headers.get("host", "localhost:8003")
    scheme = "wss" if request.url.scheme == "https" else "ws"
    ws_url = f"{scheme}://{host}/api/v1/cc/tools/pty"
    return {"ws_url": ws_url}


# ---------------------------------------------------------------------------
# OS upgrade stream URL — Server-Sent Events endpoint path
# ---------------------------------------------------------------------------

@router.get("/upgrade-stream-url")
async def get_upgrade_stream_url(request: Request, _=Depends(require_super_admin)) -> dict:
    host = request.headers.get("host", "localhost:8003")
    return {"stream_url": f"/api/v1/cc/sysinfo/os-upgrade/stream"}


# ---------------------------------------------------------------------------
# Database management — list, query, create, drop databases
# ---------------------------------------------------------------------------

def _mysql(*args: str, timeout: int = 10) -> tuple[str, str, int]:
    return _run(["mysql", "--batch", "--skip-column-names", "-e", *args], timeout=timeout)


@router.get("/databases")
async def list_databases(_=Depends(require_super_admin)) -> dict:
    out, err, rc = _mysql("SHOW DATABASES;")
    if rc != 0:
        raise HTTPException(500, f"MySQL error: {err.strip()}")
    dbs = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return {"databases": dbs, "total": len(dbs)}


@router.get("/databases/{db}/tables")
async def list_tables(db: str, _=Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-zA-Z0-9_]+$", db):
        raise HTTPException(400, "Invalid database name")
    out, err, rc = _mysql(f"SHOW TABLES FROM `{db}`;")
    if rc != 0:
        raise HTTPException(500, f"MySQL error: {err.strip()}")
    tables = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return {"database": db, "tables": tables, "total": len(tables)}


class _DBQuery(BaseModel):
    query: str


@router.post("/databases/{db}/query")
async def run_db_query(db: str, body: _DBQuery, _=Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-zA-Z0-9_]+$", db):
        raise HTTPException(400, "Invalid database name")
    q = body.query.strip()
    forbidden = _re.compile(r"\b(DROP\s+DATABASE|CREATE\s+DATABASE)\b", _re.IGNORECASE)
    if forbidden.search(q):
        raise HTTPException(400, "Use the dedicated create/drop endpoints for database-level operations")
    out, err, rc = _run(["mysql", "--batch", "--database", db, "-e", q], timeout=30)
    if rc != 0:
        raise HTTPException(400, f"Query error: {err.strip()}")
    rows = [ln.split("\t") for ln in out.splitlines()]
    return {"database": db, "rows": rows, "row_count": len(rows), "result": out.strip()}


@router.post("/databases")
async def create_database(name: str = Query(...), _=Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-zA-Z0-9_]+$", name):
        raise HTTPException(400, "Invalid database name (alphanumeric + underscore only)")
    _, err, rc = _mysql(f"CREATE DATABASE `{name}`;")
    if rc != 0:
        raise HTTPException(500, f"MySQL error: {err.strip()}")
    return {"ok": True, "database": name}


@router.delete("/databases/{db}")
async def drop_database(db: str, confirm: bool = Query(False), _=Depends(require_super_admin)) -> dict:
    if not re.match(r"^[a-zA-Z0-9_]+$", db):
        raise HTTPException(400, "Invalid database name")
    if not confirm:
        raise HTTPException(400, "Pass confirm=true to confirm drop")
    _, err, rc = _mysql(f"DROP DATABASE `{db}`;")
    if rc != 0:
        raise HTTPException(500, f"MySQL error: {err.strip()}")
    return {"ok": True, "database": db}
