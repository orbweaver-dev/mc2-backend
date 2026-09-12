"""
ServOps — System Tools API (super_admin only).
Terminal command execution, permission-aware file manager, and network tools.
"""

from __future__ import annotations

import os
import pwd
import socket
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from .routes_auth import require_super_admin

router = APIRouter(prefix="/sysinfo/tools", tags=["tools"])

MAX_READ_BYTES = 1 * 1024 * 1024  # 1 MB
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 15, stdin: str | None = None) -> tuple[str, str, int]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            input=stdin,
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1


# ---------------------------------------------------------------------------
# Permission-aware helpers (Webmin pattern: detect owner → sudo -u owner)
# ---------------------------------------------------------------------------

def _path_owner(path: str | Path) -> str:
    """Return the username owning path (or nearest existing parent)."""
    p = Path(path).resolve()
    while True:
        try:
            return pwd.getpwuid(os.stat(p).st_uid).pw_name
        except (FileNotFoundError, KeyError, OSError):
            parent = p.parent
            if parent == p:  # reached filesystem root
                return "root"
            p = parent


def _sudo_as(owner: str, cmd: list[str], timeout: int = 15, stdin: str | None = None) -> tuple[str, str, int]:
    """Run a command as the file owner via sudo."""
    return _run(["sudo", "-u", owner] + cmd, timeout=timeout, stdin=stdin)


def _parse_find_line(base: str, line: str) -> dict | None:
    """Parse one line of find -printf output into a FileEntry dict."""
    # Format: type|size|mtime_unix|perms_octal|user|group|relative_name
    parts = line.split("|", 6)
    if len(parts) < 7:
        return None
    ftype, size_s, mtime_s, perms, user, group, relname = parts
    if not relname or relname == ".":
        return None  # skip the directory itself
    name = relname.rstrip("\n")
    full_path = os.path.join(base, name)
    is_dir = ftype.startswith("d") or ftype == "directory"
    is_link = ftype.startswith("l")
    try:
        mtime = datetime.fromtimestamp(float(mtime_s), UTC).isoformat()
    except (ValueError, OSError):
        mtime = None
    return {
        "name": name,
        "path": full_path,
        "type": "link" if is_link else ("dir" if is_dir else "file"),
        "size": None if is_dir else (int(size_s) if size_s.isdigit() else None),
        "modified": mtime,
        "permissions": perms,
        "owner": user,
        "group": group,
    }


# ---------------------------------------------------------------------------
# Terminal — command execution
# ---------------------------------------------------------------------------

class TerminalRequest(BaseModel):
    command: str
    cwd: str = "/"

    @field_validator("command")
    @classmethod
    def no_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("command cannot be empty")
        return v


@router.post("/exec")
async def execute_command(req: TerminalRequest, _: str = Depends(require_super_admin)) -> dict:
    """Execute a shell command as root and return combined output."""
    safe_cwd = req.cwd.replace("'", "\\'") if req.cwd.startswith("/") else "/"
    wrapped = f"cd '{safe_cwd}' 2>/dev/null; {req.command}"
    try:
        result = subprocess.run(
            ["sudo", "bash", "-c", wrapped],
            capture_output=True, text=True,
            timeout=30, cwd="/tmp",
            env={**os.environ, "TERM": "xterm-256color", "COLUMNS": "200"},
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "command": req.command,
            "cwd": safe_cwd,
            "executed_at": datetime.now(UTC).isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "", "stderr": "Command timed out after 30 seconds",
            "returncode": -1, "command": req.command, "cwd": safe_cwd,
            "executed_at": datetime.now(UTC).isoformat(),
        }
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# File Manager — list directory
# ---------------------------------------------------------------------------

@router.get("/files")
async def list_directory(path: str = "/", _: str = Depends(require_super_admin)) -> dict:
    """List directory contents, running as the directory owner."""
    try:
        p = Path(path).resolve()
        owner = _path_owner(p)

        # Check path exists + is a dir using the owner's permissions
        out, err, rc = _sudo_as(owner, ["stat", "-c", "%F", str(p)])
        if rc != 0:
            if "No such file" in err:
                raise HTTPException(404, f"Path not found: {path}")
            raise HTTPException(403, f"Permission denied: {path}")
        if "directory" not in out:
            raise HTTPException(400, f"Not a directory: {path}")

        # List with find — format: type|size|mtime_unix|perms_octal|user|group|relname
        find_fmt = "%y|%s|%T@|%#m|%u|%g|%P\\n"
        out, err, rc = _sudo_as(
            owner,
            ["find", str(p), "-maxdepth", "1", "-printf", find_fmt],
            timeout=20,
        )
        if rc != 0:
            raise HTTPException(403, f"Cannot read directory: {err.strip()}")

        entries = []
        for line in out.splitlines():
            entry = _parse_find_line(str(p), line)
            if entry:
                entries.append(entry)

        entries.sort(key=lambda e: (e["type"] != "dir", e["name"].lower()))
        parent = str(p.parent) if str(p) != "/" else None
        return {
            "path": str(p),
            "parent": parent,
            "entries": entries,
            "count": len(entries),
            "owner": owner,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# File Manager — read file content
# ---------------------------------------------------------------------------

@router.get("/files/content")
async def read_file_content(path: str, _: str = Depends(require_super_admin)) -> dict:
    """Read a text file (max 1 MB), running as the file owner."""
    try:
        p = Path(path).resolve()
        owner = _path_owner(p)

        # Get file size first
        out, err, rc = _sudo_as(owner, ["stat", "-c", "%s|%F", str(p)])
        if rc != 0:
            raise HTTPException(404, f"File not found: {path}")
        parts = out.strip().split("|")
        if len(parts) < 2:
            raise HTTPException(500, "stat parse error")
        size = int(parts[0]) if parts[0].isdigit() else 0
        if "directory" in parts[1]:
            raise HTTPException(400, f"Not a file: {path}")

        if size > MAX_READ_BYTES:
            return {
                "path": str(p), "content": None, "size": size,
                "truncated": True,
                "error": f"File too large ({size // 1024} KB). Use terminal to view.",
            }

        out, err, rc = _sudo_as(owner, ["cat", str(p)], timeout=10)
        if rc != 0:
            raise HTTPException(403, f"Permission denied reading: {path}")

        return {"path": str(p), "content": out, "size": size, "truncated": False, "error": None}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# File Manager — write file content
# ---------------------------------------------------------------------------

class WriteRequest(BaseModel):
    path: str
    content: str


@router.post("/files/write")
async def write_file(req: WriteRequest, _: str = Depends(require_super_admin)) -> dict:
    """Write text content to a file, preserving owner and permissions."""
    try:
        p = Path(req.path).resolve()
        owner = _path_owner(p)

        # Write to a temp file, then sudo cp as the owner
        with tempfile.NamedTemporaryFile(mode="w", suffix=".fmtmp", delete=False) as tf:
            tf.write(req.content)
            tmp_path = tf.name

        try:
            # Determine if file exists to preserve permissions
            out, _, rc = _sudo_as(owner, ["stat", "-c", "%a", str(p)])
            existing_perms = out.strip() if rc == 0 and out.strip() else "644"

            # Copy content into place as the owner
            _, err, rc = _run(["sudo", "-u", owner, "/usr/bin/cp", tmp_path, str(p)])
            if rc != 0:
                raise HTTPException(500, f"Write failed: {err.strip()}")
            _run(["sudo", "-u", owner, "/usr/bin/chmod", existing_perms, str(p)])
        finally:
            os.unlink(tmp_path)

        return {"path": str(p), "ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# File Manager — create directory
# ---------------------------------------------------------------------------

class MkdirRequest(BaseModel):
    path: str


@router.post("/files/mkdir")
async def make_directory(req: MkdirRequest, _: str = Depends(require_super_admin)) -> dict:
    """Create a directory, running as the parent directory owner."""
    try:
        p = Path(req.path).resolve()
        owner = _path_owner(p.parent)
        _, err, rc = _sudo_as(owner, ["mkdir", "-p", str(p)])
        if rc != 0:
            raise HTTPException(500, f"mkdir failed: {err.strip()}")
        return {"path": str(p), "ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# File Manager — delete
# ---------------------------------------------------------------------------

class DeleteRequest(BaseModel):
    path: str
    recursive: bool = False


@router.delete("/files/delete")
async def delete_path(req: DeleteRequest, _: str = Depends(require_super_admin)) -> dict:
    """Delete a file or directory, running as the path owner."""
    try:
        p = Path(req.path).resolve()
        if str(p) in ("/", "/etc", "/home", "/usr", "/var", "/bin", "/sbin"):
            raise HTTPException(400, "Refusing to delete protected system path")
        owner = _path_owner(p)
        cmd = ["rm", "-rf", str(p)] if req.recursive else ["rm", "-f", str(p)]
        _, err, rc = _sudo_as(owner, cmd)
        if rc != 0:
            raise HTTPException(500, f"delete failed: {err.strip()}")
        return {"path": str(p), "ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# File Manager — copy
# ---------------------------------------------------------------------------

class CopyRequest(BaseModel):
    source: str
    destination: str


@router.post("/files/copy")
async def copy_path(req: CopyRequest, _: str = Depends(require_super_admin)) -> dict:
    """Copy a file or directory. Runs as source owner."""
    try:
        src = Path(req.source).resolve()
        dst = Path(req.destination).resolve()
        owner = _path_owner(src)
        _, err, rc = _sudo_as(owner, ["cp", "-a", str(src), str(dst)])
        if rc != 0:
            raise HTTPException(500, f"copy failed: {err.strip()}")
        return {"source": str(src), "destination": str(dst), "ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# File Manager — move / rename
# ---------------------------------------------------------------------------

class MoveRequest(BaseModel):
    source: str
    destination: str


@router.post("/files/move")
async def move_path(req: MoveRequest, _: str = Depends(require_super_admin)) -> dict:
    """Move or rename a file or directory. Runs as source owner."""
    try:
        src = Path(req.source).resolve()
        dst = Path(req.destination).resolve()
        owner = _path_owner(src)
        _, err, rc = _sudo_as(owner, ["mv", str(src), str(dst)])
        if rc != 0:
            raise HTTPException(500, f"move failed: {err.strip()}")
        return {"source": str(src), "destination": str(dst), "ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# File Manager — download
# ---------------------------------------------------------------------------

@router.get("/files/download")
async def download_file(path: str, _: str = Depends(require_super_admin)):
    """Stream a file for download, reading as the file owner."""
    p = Path(path).resolve()
    owner = _path_owner(p)
    filename = p.name

    def _stream():
        proc = subprocess.Popen(
            ["sudo", "-u", owner, "cat", str(p)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            assert proc.stdout is not None
            while chunk := proc.stdout.read(65536):
                yield chunk
        finally:
            proc.wait()

    return StreamingResponse(
        _stream(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# File Manager — upload
# ---------------------------------------------------------------------------

@router.post("/files/upload")
async def upload_file(
    directory: str = Form(...),
    file: UploadFile = File(...),
    _: str = Depends(require_super_admin),
) -> dict:
    """Upload a file into a directory, creating it as the directory owner."""
    try:
        dest_dir = Path(directory).resolve()
        owner = _path_owner(dest_dir)
        filename = Path(file.filename or "upload").name  # strip any path components
        dest_path = dest_dir / filename

        content = await file.read()
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"File too large (max {MAX_UPLOAD_BYTES // 1048576} MB)")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".fmup") as tf:
            tf.write(content)
            tmp_path = tf.name

        try:
            # install preserves nothing from tmp; sets owner and mode explicitly
            _, err, rc = _run(
                ["sudo", "-u", owner, "/usr/bin/install",
                 "-m", "644", tmp_path, str(dest_path)]
            )
            if rc != 0:
                raise HTTPException(500, f"upload failed: {err.strip()}")
        finally:
            os.unlink(tmp_path)

        return {"path": str(dest_path), "name": filename, "size": len(content), "ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# Network Tools
# ---------------------------------------------------------------------------

@router.get("/network/ping")
async def ping(host: str, count: int = 4, _: str = Depends(require_super_admin)) -> dict:
    count = min(max(count, 1), 10)
    stdout, stderr, rc = _run(["ping", "-c", str(count), "-W", "3", host], timeout=20)
    return {"host": host, "output": stdout or stderr, "reachable": rc == 0}


@router.get("/network/traceroute")
async def traceroute(host: str, _: str = Depends(require_super_admin)) -> dict:
    stdout, stderr, _ = _run(["traceroute", "-n", "-m", "20", host], timeout=45)
    return {"host": host, "output": stdout or stderr}


@router.get("/network/dns")
async def dns_lookup(host: str, record_type: str = "A", _: str = Depends(require_super_admin)) -> dict:
    rtype = record_type.upper() if record_type.upper() in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "PTR", "SOA") else "A"
    stdout, stderr, _ = _run(["dig", "+short", "@8.8.8.8", host, rtype], timeout=10)
    return {"host": host, "type": rtype, "output": (stdout or stderr).strip()}


@router.get("/network/ports")
async def check_ports(
    host: str,
    ports: str = "22,80,443,3306,6379",
    _: str = Depends(require_super_admin),
) -> dict:
    results = []
    for port_str in ports.split(",")[:20]:
        try:
            port = int(port_str.strip())
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            sock.close()
            results.append({"port": port, "open": result == 0})
        except Exception:
            try:
                results.append({"port": int(port_str.strip()), "open": False})
            except ValueError:
                pass
    return {"host": host, "ports": results}
