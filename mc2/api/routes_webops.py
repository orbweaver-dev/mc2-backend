"""
WebOps — Virtual server inventory, connectivity monitoring, and controlled actions.

Server registry is stored in /etc/mc2/webops-servers.json.
Two server types:
  ssh      — remote server accessible via SSH (stop/restart only)
  libvirt  — local KVM/QEMU VM managed via virsh (start/stop/restart)

All actions are whitelisted. No arbitrary command execution.
Every action is audited to /var/log/mc2-audit.log.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .routes_auth import require_super_admin

router = APIRouter(prefix="/webops", tags=["webops"])

# ---------------------------------------------------------------------------
# Registry persistence
# ---------------------------------------------------------------------------

REGISTRY_FILE = Path("/var/lib/mc2/webops-servers.json")


def _load_registry() -> list[dict]:
    try:
        return json.loads(REGISTRY_FILE.read_text()) if REGISTRY_FILE.exists() else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_registry(servers: list[dict]) -> None:
    REGISTRY_FILE.write_text(json.dumps(servers, indent=2))


def _find_server(server_id: str) -> dict:
    if server_id == "self-mc2-host":
        return _self_server_entry()
    for s in _load_registry():
        if s.get("id") == server_id:
            return s
    raise HTTPException(status_code=404, detail=f"Server {server_id!r} not found in registry")


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

_audit_log = logging.getLogger("mc2.webops.audit")
if not _audit_log.handlers:
    try:
        _h = logging.FileHandler("/var/log/mc2-audit.log", delay=True)
        _h.setFormatter(logging.Formatter("%(asctime)s  %(message)s"))
        _audit_log.addHandler(_h)
    except OSError:
        pass
    _audit_log.addHandler(logging.StreamHandler())
    _audit_log.setLevel(logging.INFO)


def _audit(user: str, action: str, server_id: str, detail: str, result: str) -> None:
    _audit_log.info(
        "domain=webops user=%s action=%s server=%s detail=%r result=%s",
        user, action, server_id, detail, result,
    )


# ---------------------------------------------------------------------------
# Low-level helpers — all subprocess with explicit arg lists, no shell=True
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 10) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 124
    except FileNotFoundError:
        return "", f"{cmd[0]!r} not found", 127


def _run_out(cmd: list[str], timeout: int = 10) -> str:
    out, _, _ = _run(cmd, timeout)
    return out.strip()


# ---------------------------------------------------------------------------
# Ping connectivity
# ---------------------------------------------------------------------------

def _ping_check(host: str) -> dict:
    out, _, rc = _run(["ping", "-c", "3", "-W", "2", host], timeout=10)
    if rc != 0:
        return {"reachable": False, "latency_ms": None, "packet_loss": None}
    latency_ms: float | None = None
    loss: str | None = None
    for line in out.splitlines():
        if "rtt" in line or "round-trip" in line:
            parts = line.split("=")
            if len(parts) > 1:
                vals = parts[1].strip().split("/")
                if len(vals) >= 2:
                    try:
                        latency_ms = float(vals[1])
                    except ValueError:
                        pass
        if "packet loss" in line:
            m = re.search(r"(\d+)%\s+packet loss", line)
            if m:
                loss = m.group(1) + "%"
    return {"reachable": True, "latency_ms": latency_ms, "packet_loss": loss or "0%"}


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def _ssh_base(server: dict) -> list[str]:
    """Build the base ssh command for a server entry (no remote command yet)."""
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=8",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=1",
        "-p", str(server.get("ssh_port", 22)),
    ]
    key = server.get("ssh_key", "")
    if key and os.path.isfile(key):
        cmd += ["-i", key]
    cmd.append(f"{server.get('ssh_user', 'root')}@{server['ip']}")
    return cmd


def _ssh_check(server: dict) -> dict:
    """Test SSH reachability. Returns latency_ms or None on failure."""
    t0 = time.monotonic()
    out, err, rc = _run(_ssh_base(server) + ["echo ok"], timeout=12)
    elapsed = round((time.monotonic() - t0) * 1000, 1)
    if rc == 0 and "ok" in out:
        return {"reachable": True, "latency_ms": elapsed, "error": None}
    return {"reachable": False, "latency_ms": None, "error": err.strip() or "SSH failed"}


def _ssh_metrics(server: dict) -> dict:
    """Fetch resource metrics over SSH — single connection, hardcoded commands only."""
    script = (
        "echo LOAD:$(cat /proc/loadavg 2>/dev/null | awk '{print $1\",\"$2\",\"$3}');"
        "echo MEM:$(free -b 2>/dev/null | awk 'NR==2{print $2\",\"$3\",\"$4}');"
        "echo SWAP:$(free -b 2>/dev/null | awk 'NR==3{print $2\",\"$3\",\"$4}');"
        "echo UPTIME:$(awk '{print $1}' /proc/uptime 2>/dev/null);"
        "echo HOST:$(hostname -s 2>/dev/null);"
        "echo OS:$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"');"
        "echo PROCS:$(ps aux --no-headers 2>/dev/null | wc -l);"
        "echo CPU:$(grep -m1 'cpu ' /proc/stat | awk '{u=$2+$4; t=$2+$3+$4+$5; if(t>0) printf \"%.1f\", u*100/t; else print 0}');"
        # Multiple disk mounts — semicolon-delimited: mountpoint|size|used|avail|pct|fstype
        "echo DISKS:$(df -P -B1 2>/dev/null | awk 'NR>1 && $6!=\"\" {gsub(/%/,\"\",$5); printf \"%s|%s|%s|%s|%s|%s;\", $6,$2,$3,$4,$5,$1}' | grep -v 'tmpfs\\|devtmpfs\\|squashfs\\|loop\\|udev\\|sysfs\\|proc' | head -c 2000);"
        # Network IO — semicolon-delimited: iface|bytes_rx|bytes_tx (from /proc/net/dev)
        "echo NETIO:$(awk 'NR>2 && $1!~/lo:/{gsub(/:/,\"\",$1); printf \"%s|%s|%s;\", $1,$2,$10}' /proc/net/dev 2>/dev/null | head -c 500)"
    )
    out, _, rc = _run(_ssh_base(server) + [script], timeout=20)
    if rc != 0:
        return {}

    result: dict[str, Any] = {}
    for line in out.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip(); val = val.strip()

        if key == "LOAD":
            parts = val.split(",")
            result["load_avg"] = {"1m": _safe_float(parts, 0), "5m": _safe_float(parts, 1), "15m": _safe_float(parts, 2)}

        elif key == "MEM":
            parts = val.split(",")
            total = _safe_int(parts, 0); used = _safe_int(parts, 1); free = _safe_int(parts, 2)
            result["memory"] = {
                "total_gb": round(total / 1e9, 2),
                "used_gb":  round(used  / 1e9, 2),
                "free_gb":  round(free  / 1e9, 2),
                "percent":  round(used / total * 100, 1) if total else 0,
            }

        elif key == "SWAP":
            parts = val.split(",")
            total = _safe_int(parts, 0); used = _safe_int(parts, 1)
            if total > 0:
                result["swap"] = {
                    "total_gb": round(total / 1e9, 2),
                    "used_gb":  round(used  / 1e9, 2),
                    "percent":  round(used / total * 100, 1),
                }

        elif key == "DISKS":
            disks = []
            for entry in val.split(";"):
                entry = entry.strip()
                if not entry:
                    continue
                parts = entry.split("|")
                if len(parts) < 5:
                    continue
                mount = parts[0]; size_b = _safe_int(parts, 1)
                used_b = _safe_int(parts, 2); avail_b = _safe_int(parts, 3)
                pct = _safe_float(parts, 4); fstype = parts[5] if len(parts) > 5 else ""
                disks.append({
                    "mountpoint": mount,
                    "total_gb":   round(size_b  / 1e9, 2),
                    "used_gb":    round(used_b  / 1e9, 2),
                    "free_gb":    round(avail_b / 1e9, 2),
                    "percent":    pct,
                    "fstype":     fstype,
                })
            if disks:
                result["disks"] = disks
                # Keep legacy single-disk key pointing at root or first disk
                root = next((d for d in disks if d["mountpoint"] == "/"), disks[0])
                result["disk"] = {k: root[k] for k in ("total_gb", "used_gb", "free_gb", "percent")}

        elif key == "NETIO":
            ifaces = []
            for entry in val.split(";"):
                entry = entry.strip()
                if not entry:
                    continue
                parts = entry.split("|")
                if len(parts) < 3:
                    continue
                ifaces.append({
                    "iface":    parts[0],
                    "bytes_rx": _safe_int(parts, 1),
                    "bytes_tx": _safe_int(parts, 2),
                })
            if ifaces:
                result["network_io"] = ifaces

        elif key == "UPTIME":
            secs = _safe_float([val], 0)
            result["uptime_secs"] = secs
            result["uptime"] = _fmt_uptime(secs)

        elif key == "HOST":
            result["hostname_live"] = val

        elif key == "OS":
            result["os_live"] = val

        elif key == "PROCS":
            result["process_count"] = _safe_int([val], 0)

        elif key == "CPU":
            result["cpu_percent"] = _safe_float([val], 0)

    return result


def _ssh_vhosts(server: dict) -> list[dict]:
    """Read virtual host configs from Apache / Nginx over SSH. No user input embedded."""
    script = (
        # Apache (apache2ctl or apachectl or httpd)
        "if command -v apache2ctl >/dev/null 2>&1; then "
        "  echo 'WEB:apache'; apache2ctl -S 2>&1 | grep 'namevhost'; "
        "elif command -v apachectl >/dev/null 2>&1; then "
        "  echo 'WEB:apache'; apachectl -S 2>&1 | grep 'namevhost'; "
        "elif command -v httpd >/dev/null 2>&1; then "
        "  echo 'WEB:httpd'; httpd -S 2>&1 | grep 'namevhost'; "
        "fi; "
        # Nginx — iterate enabled site configs
        "if command -v nginx >/dev/null 2>&1; then "
        "  echo 'WEB:nginx'; "
        "  for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do "
        "    [ -f \"$f\" ] || continue; "
        "    sn=$(grep -m1 'server_name' \"$f\" 2>/dev/null | sed 's/.*server_name[[:space:]]*//' | tr -d ';' | awk '{print $1}'); "
        "    lt=$(grep -m1 'listen' \"$f\" 2>/dev/null | sed 's/.*listen[[:space:]]*//' | tr -d ';' | awk '{print $1}'); "
        "    ssl=$(grep -c 'ssl_certificate' \"$f\" 2>/dev/null || echo 0); "
        "    dr=$(grep -m1 'root ' \"$f\" 2>/dev/null | sed 's/.*root[[:space:]]*//' | tr -d ';' | awk '{print $1}'); "
        "    [ -n \"$sn\" ] && echo \"NGINX_VH:${sn}|${lt}|${ssl}|${dr}\"; "
        "  done; "
        "fi"
    )
    out, _, rc = _run(_ssh_base(server) + [script], timeout=25)
    if rc != 0:
        return []

    vhosts: list[dict] = []
    current_web = "apache"
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("WEB:"):
            current_web = line[4:].strip()
        elif "namevhost" in line:
            # Apache: "         port 80 namevhost example.com (/path/conf:1)"
            m = re.search(r"port\s+(\d+)\s+namevhost\s+(\S+)\s+\((.+?):\d+\)", line)
            if m:
                port = int(m.group(1)); domain = m.group(2); cfg = m.group(3)
                vhosts.append({
                    "domain": domain, "port": port,
                    "ssl": port == 443,
                    "server": current_web,
                    "doc_root": None,
                    "config_file": cfg,
                })
        elif line.startswith("NGINX_VH:"):
            parts = line[9:].split("|")
            domain   = parts[0] if parts else "_"
            raw_port = parts[1] if len(parts) > 1 else "80"
            ssl_cnt  = _safe_int(parts, 2)
            doc_root = (parts[3].strip() or None) if len(parts) > 3 else None
            m2 = re.search(r"(\d+)", raw_port)
            port_num = int(m2.group(1)) if m2 else 80
            vhosts.append({
                "domain": domain, "port": port_num,
                "ssl": ssl_cnt > 0 or port_num == 443,
                "server": "nginx",
                "doc_root": doc_root,
                "config_file": None,
            })

    # Deduplicate domain+port pairs
    seen: set[tuple] = set()
    unique: list[dict] = []
    for v in vhosts:
        key_t = (v["domain"], v["port"])
        if key_t not in seen:
            seen.add(key_t)
            unique.append(v)
    return sorted(unique, key=lambda v: (v["domain"], v["port"]))


def _ssh_services(server: dict) -> list[dict]:
    """List active systemd services over SSH."""
    cmd = (
        "systemctl list-units --type=service --state=running "
        "--no-pager --plain 2>/dev/null | head -30 | awk '{print $1}'"
    )
    out, _, rc = _run(_ssh_base(server) + [cmd], timeout=15)
    if rc != 0:
        return []
    return [{"name": line.strip()} for line in out.splitlines() if line.strip() and line.endswith(".service")]


def _ssh_ports(server: dict) -> list[dict]:
    """List listening ports on the remote server via SSH."""
    cmd = "ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | head -20"
    out, _, rc = _run(_ssh_base(server) + [cmd], timeout=12)
    if rc != 0:
        return []
    ports = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        _, _, port = line.rpartition(":")
        if port.isdigit():
            ports.append({"port": port, "address": line})
    return ports


# ---------------------------------------------------------------------------
# libvirt helpers
# ---------------------------------------------------------------------------

def _virsh_state(server: dict) -> str:
    """Get VM state from virsh: running, shut off, paused, etc."""
    name = server.get("libvirt_name", "")
    if not name:
        return "unknown"
    out = _run_out(["virsh", "domstate", name], timeout=8)
    return out.lower() or "unknown"


def _virsh_metrics(server: dict) -> dict:
    name = server.get("libvirt_name", "")
    if not name:
        return {}
    out = _run_out(["virsh", "dominfo", name], timeout=8)
    result: dict[str, Any] = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip(); v = v.strip()
            if k == "Max memory":
                result["memory_max_kb"] = _safe_int([v.split()[0]], 0)
            elif k == "Used memory":
                result["memory_used_kb"] = _safe_int([v.split()[0]], 0)
            elif k == "CPU(s)":
                result["vcpus"] = _safe_int([v], 0)
    mem_max = result.get("memory_max_kb", 0)
    mem_used = result.get("memory_used_kb", 0)
    if mem_max:
        result["memory"] = {
            "total_gb":  round(mem_max  / 1e6, 2),
            "used_gb":   round(mem_used / 1e6, 2),
            "percent":   round(mem_used / mem_max * 100, 1) if mem_max else 0,
        }
    return result


# ---------------------------------------------------------------------------
# Parsing utils
# ---------------------------------------------------------------------------

def _safe_float(parts: list[str], idx: int) -> float:
    try:
        return float(parts[idx])
    except (IndexError, ValueError):
        return 0.0


def _safe_int(parts: list[str], idx: int) -> int:
    try:
        return int(parts[idx])
    except (IndexError, ValueError):
        return 0


def _fmt_uptime(secs: float) -> str:
    s = int(secs)
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    mins, _  = divmod(s, 60)
    parts = []
    if days:  parts.append(f"{days}d")
    if hours: parts.append(f"{hours}h")
    parts.append(f"{mins}m")
    return " ".join(parts) or "0m"


# ---------------------------------------------------------------------------
# Server action execution (whitelisted)
# ---------------------------------------------------------------------------

_SSH_ACTIONS: dict[str, list[str]] = {
    "restart": ["sudo", "reboot"],
    "stop":    ["sudo", "poweroff"],
}

_VIRSH_ACTIONS: dict[str, str] = {
    "start":   "start",
    "stop":    "shutdown",
    "restart": "reboot",
}


def _execute_action(server: dict, action: str, user: str) -> dict:
    stype  = server.get("type", "ssh")
    sid    = server["id"]
    sname  = server.get("display_name", server.get("hostname", sid))

    if stype == "libvirt":
        virsh_cmd = _VIRSH_ACTIONS.get(action)
        if not virsh_cmd:
            raise HTTPException(status_code=400, detail=f"Action {action!r} not supported for libvirt servers")
        name = server.get("libvirt_name", "")
        if not name:
            raise HTTPException(status_code=400, detail="libvirt_name not configured for this server")
        out, err, rc = _run(["virsh", virsh_cmd, name], timeout=30)
        result = "ok" if rc == 0 else "error"
        _audit(user, f"virsh_{action}", sid, sname, result)
        if rc != 0:
            raise HTTPException(status_code=500, detail=err.strip() or f"virsh {virsh_cmd} {name} failed")
        return {"ok": True, "server": sname, "action": action, "output": out.strip(),
                "executed_at": datetime.now(UTC).isoformat()}

    else:  # ssh
        if action == "start":
            raise HTTPException(status_code=400, detail="Start is not available for SSH servers — server must be powered on externally")
        cmd_parts = _SSH_ACTIONS.get(action)
        if not cmd_parts:
            raise HTTPException(status_code=400, detail=f"Action {action!r} not supported for SSH servers")
        full_cmd = _ssh_base(server) + cmd_parts
        out, err, rc = _run(full_cmd, timeout=20)
        # SSH to a rebooting server may return non-zero; check if action was initiated
        result = "ok" if rc in (0, 255) else "error"
        _audit(user, f"ssh_{action}", sid, sname, result)
        if rc not in (0, 255):
            raise HTTPException(status_code=500, detail=err.strip() or f"SSH action {action} failed (rc={rc})")
        return {"ok": True, "server": sname, "action": action,
                "note": "Command sent — server may be unreachable briefly during restart" if action == "restart" else None,
                "executed_at": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AddServerRequest(BaseModel):
    display_name: str
    hostname: str
    ip: str
    type: str = "ssh"           # "ssh" | "libvirt"
    provider: str = ""
    os: str = ""
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_key: str = "/root/.ssh/id_rsa"
    libvirt_name: str = ""
    tags: list[str] = []
    notes: str = ""


class ServerActionRequest(BaseModel):
    action: str   # "start" | "stop" | "restart"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _self_server_entry() -> dict:
    """
    Synthetic 'self' server representing the host MC² runs on.

    MC² is a master control panel — the local host is always under its
    own management, so it should always appear in the WebOps server list
    without the operator needing to "add" it. Stable id "self-mc2-host"
    so subsequent calls (servers/{id}/vhosts, /status, etc.) recognise it
    as the local host and use direct CLI shellouts instead of SSH.
    """
    import socket
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "localhost"
    return {
        "id":           "self-mc2-host",
        "display_name": "This Host (MC²)",
        "hostname":     hostname,
        "ip":           "127.0.0.1",
        "type":         "local",
        "provider":     "self",
        "os":           "linux",
        "ssh_user":     "",
        "ssh_port":     0,
        "ssh_key":      "",
        "libvirt_name": "",
        "tags":         ["self", "primary"],
        "notes":        "Local host — auto-registered. Vhost / database / file operations execute directly via the mc2 service user's sudo grants.",
        "added_at":     "",
        "added_by":     "system",
        "is_self":      True,
    }


@router.get("/servers")
async def list_servers(_: str = Depends(require_super_admin)) -> dict:
    """
    Return the registered remote servers PLUS a synthetic 'self' entry for
    the local host so the WebOps UI never shows an empty server list on a
    single-host MC² deployment.
    """
    servers = [_self_server_entry()] + _load_registry()
    return {"servers": servers, "count": len(servers), "checked_at": datetime.now(UTC).isoformat()}


@router.post("/servers")
async def add_server(body: AddServerRequest, user: str = Depends(require_super_admin)) -> dict:
    if body.type not in ("ssh", "libvirt"):
        raise HTTPException(status_code=400, detail="type must be 'ssh' or 'libvirt'")
    # Basic IP validation
    if not re.match(r"^[\w.\-:]+$", body.ip):
        raise HTTPException(status_code=400, detail="Invalid IP/hostname")
    if body.ssh_port < 1 or body.ssh_port > 65535:
        raise HTTPException(status_code=400, detail="Invalid SSH port")

    servers = _load_registry()
    # Prevent duplicate IPs
    for s in servers:
        if s.get("ip") == body.ip and s.get("type") == body.type:
            raise HTTPException(status_code=409, detail=f"Server with IP {body.ip!r} already exists")

    entry = {
        "id": str(uuid.uuid4()),
        "display_name": body.display_name,
        "hostname": body.hostname,
        "ip": body.ip,
        "type": body.type,
        "provider": body.provider,
        "os": body.os,
        "ssh_user": body.ssh_user,
        "ssh_port": body.ssh_port,
        "ssh_key": body.ssh_key,
        "libvirt_name": body.libvirt_name,
        "tags": body.tags,
        "notes": body.notes,
        "added_at": datetime.now(UTC).isoformat(),
        "added_by": user,
    }
    servers.append(entry)
    _save_registry(servers)
    _audit(user, "add_server", entry["id"], body.display_name, "ok")
    return {"ok": True, "server": entry}


@router.delete("/servers/{server_id}")
async def remove_server(server_id: str, user: str = Depends(require_super_admin)) -> dict:
    servers = _load_registry()
    orig_count = len(servers)
    servers = [s for s in servers if s.get("id") != server_id]
    if len(servers) == orig_count:
        raise HTTPException(status_code=404, detail="Server not found")
    _save_registry(servers)
    _audit(user, "remove_server", server_id, "", "ok")
    return {"ok": True, "removed": server_id}


@router.get("/servers/{server_id}/status")
async def server_status(server_id: str, _: str = Depends(require_super_admin)) -> dict:
    server = _find_server(server_id)
    stype  = server.get("type", "ssh")
    result: dict[str, Any] = {
        "id": server["id"],
        "display_name": server.get("display_name", ""),
        "ip": server["ip"],
        "type": stype,
        "checked_at": datetime.now(UTC).isoformat(),
    }

    # Local self — read directly via psutil instead of pretending to SSH
    # into our own host. This is the synthetic server entry auto-included
    # in /webops/servers so the registry is never empty on single-host MC².
    if stype == "local":
        import psutil
        result["is_up"]  = True
        result["state"]  = "running"
        result["ping"]   = {"alive": True, "rtt_ms": 0}
        result["ssh"]    = {"reachable": None, "note": "local host — no SSH needed"}
        try:
            mem = psutil.virtual_memory()
            result["metrics"] = {
                "cpu_percent":   psutil.cpu_percent(interval=0.2),
                "load_avg_1m":   psutil.getloadavg()[0],
                "memory_used_gb":  round(mem.used / 1e9, 2),
                "memory_total_gb": round(mem.total / 1e9, 2),
                "uptime_seconds":  int(__import__("time").time() - psutil.boot_time()),
            }
        except Exception:
            result["metrics"] = {}
        result["services"] = []
        result["ports"]    = []
        return result

    # Ping check
    result["ping"] = _ping_check(server["ip"])

    if stype == "libvirt":
        state = _virsh_state(server)
        result["state"]   = state
        result["is_up"]   = state == "running"
        result["metrics"] = _virsh_metrics(server) if state == "running" else {}
        result["ssh"]     = {"reachable": None}   # ssh not primary for libvirt

    else:  # ssh
        ssh = _ssh_check(server)
        result["ssh"]   = ssh
        result["is_up"] = ssh["reachable"]
        result["state"] = "running" if ssh["reachable"] else "unreachable"
        if ssh["reachable"]:
            result["metrics"]  = _ssh_metrics(server)
            result["services"] = _ssh_services(server)
            result["ports"]    = _ssh_ports(server)
        else:
            result["metrics"]  = {}
            result["services"] = []
            result["ports"]    = []

    return result


@router.get("/servers/{server_id}/vhosts")
async def server_vhosts(server_id: str, _: str = Depends(require_super_admin)) -> dict:
    """Return virtual host configurations for the named server."""
    # Local "self" server: read the host's own Virtualmin domain list
    # directly via the CLI instead of pretending we'd SSH into ourselves.
    if server_id == "self-mc2-host":
        try:
            from mc2.api.routes_vhost import list_domains as _vhost_list_domains
            vd = _vhost_list_domains(_="ok")
        except Exception as exc:
            return {"vhosts": [], "web_servers": [], "count": 0,
                    "note": f"Failed to enumerate local vhosts: {exc}",
                    "checked_at": datetime.now(UTC).isoformat()}
        vhosts = [{
            "domain":     d["domain"],
            "server":     "apache2",
            "docroot":    d.get("home") or "",
            "owner":      d.get("user"),
            "ip":         d.get("ip"),
            "ssl":        "ssl" in (d.get("features") or []),
            "features":   d.get("features") or [],
        } for d in (vd.get("domains") or [])]
        return {
            "vhosts": vhosts,
            "web_servers": ["apache2"],
            "count": len(vhosts),
            "checked_at": datetime.now(UTC).isoformat(),
        }

    server = _find_server(server_id)
    if server.get("type") != "ssh":
        return {"vhosts": [], "web_servers": [], "note": "vhost scraping only available for SSH servers",
                "checked_at": datetime.now(UTC).isoformat()}
    ssh = _ssh_check(server)
    if not ssh["reachable"]:
        raise HTTPException(status_code=503, detail="Server is not reachable via SSH")
    vhosts = _ssh_vhosts(server)
    web_servers = list({v["server"] for v in vhosts})
    return {
        "vhosts": vhosts,
        "web_servers": web_servers,
        "count": len(vhosts),
        "checked_at": datetime.now(UTC).isoformat(),
    }


@router.post("/servers/{server_id}/action")
async def server_action(
    server_id: str,
    body: ServerActionRequest,
    user: str = Depends(require_super_admin),
) -> dict:
    if body.action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail="action must be 'start', 'stop', or 'restart'")
    server = _find_server(server_id)
    return _execute_action(server, body.action, user)


@router.get("/domains")
async def list_domains(_: str = Depends(require_super_admin)) -> dict:
    """Return list of Virtualmin domains on this server."""
    import subprocess
    try:
        result = subprocess.run(
            ["sudo", "virtualmin", "list-domains", "--name-only"],
            capture_output=True, text=True, timeout=15,
        )
        domains = [d.strip() for d in result.stdout.splitlines() if d.strip()]
    except Exception:
        # Fallback: parse /etc/apache2/sites-enabled or /etc/nginx/sites-enabled
        import glob
        domains = []
        for conf in glob.glob("/etc/apache2/sites-enabled/*.conf") + glob.glob("/etc/nginx/sites-enabled/*.conf"):
            name = conf.split("/")[-1].replace(".conf", "")
            if name not in ("000-default", "default"):
                domains.append(name)
    return {"domains": sorted(domains), "total": len(domains)}
