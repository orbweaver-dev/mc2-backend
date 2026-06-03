"""
Direct system-state readers for ServOps / WebOps.

This module exists because MC² REPLACES Webmin/Virtualmin — it does not wrap
them. Every helper here pulls state from the underlying OS interfaces
(Apache configs, /etc/passwd, MariaDB, Postfix maps, BIND zones, etc.)
instead of shelling `sudo virtualmin <cmd>`. See
`feedback_mc2_replaces_webmin_virtualmin` for the architecture rule.

Profiling on wh1 (2026-06-03):
  sudo virtualmin list-domains --json   ~8 s   (forks Perl + miniserv)
  cat /etc/apache2/sites-available/*.conf  ~4 ms

Everything here is read-only. Mutations live in dedicated service modules
(see future system_users / system_postfix / system_mariadb services).
"""

from __future__ import annotations

import os
import pwd
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

APACHE_SITES_DIR     = Path("/etc/apache2/sites-available")
POSTFIX_VIRTUAL_FILE = Path("/etc/postfix/virtual")
POSTFIX_MAIN_CF      = Path("/etc/postfix/main.cf")
BIND_ZONES_CANDIDATES = [
    Path("/etc/bind/zones"),
    Path("/var/named"),
    Path("/var/lib/bind"),
]


# ---------------------------------------------------------------------------
# Apache vhost parser
# ---------------------------------------------------------------------------

# Captures a <VirtualHost ...> block — matches the literal opening up to the
# closing tag. Apache's vhost syntax is line-oriented and not nested, so this
# regex is sufficient (we never embed another <VirtualHost> inside one).
_VHOST_RE = re.compile(
    r"<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>",
    re.DOTALL | re.IGNORECASE,
)
_DIRECTIVE_RE = re.compile(r"^\s*(\S+)\s+(.+?)\s*$", re.MULTILINE)


@dataclass
class VhostBlock:
    """One parsed <VirtualHost> block."""
    server_name:    str = ""
    aliases:        list[str] = field(default_factory=list)
    docroot:        str = ""
    ip:             str = ""
    ip6:            str = ""
    ports:          set[int] = field(default_factory=set)
    ssl_enabled:    bool = False
    error_log:      str = ""
    access_log:     str = ""
    suexec_user:    str = ""
    config_file:    str = ""


def _parse_vhost_listen(listen: str) -> tuple[str, str, set[int]]:
    """
    Parse the `<VirtualHost host:port [host:port] ...>` value into
    (primary_ip, primary_ip6, ports). Accepts:
      - 144.202.77.105:80
      - [2001:19f0:...]:80
      - *:80
    """
    ip = ip6 = ""
    ports: set[int] = set()
    # Split on whitespace — each token is one host:port pair
    for tok in listen.split():
        m = re.match(r"^(?:\[([^\]]+)\]|([^:]+)):(\d+)$", tok)
        if not m:
            continue
        ip6_part, ip4_part, port = m.group(1), m.group(2), int(m.group(3))
        ports.add(port)
        if ip6_part and not ip6:
            ip6 = ip6_part
        elif ip4_part and not ip and ip4_part != "*":
            ip = ip4_part
    return ip, ip6, ports


def _parse_one_block(listen: str, body: str, source: Path) -> VhostBlock:
    ip, ip6, ports = _parse_vhost_listen(listen)
    block = VhostBlock(ip=ip, ip6=ip6, ports=ports, ssl_enabled=(443 in ports), config_file=source.name)

    for d in _DIRECTIVE_RE.finditer(body):
        key, val = d.group(1).lower(), d.group(2).strip().strip('"')
        if key == "servername" and not block.server_name:
            block.server_name = val
        elif key == "serveralias":
            block.aliases.extend(v for v in val.split() if v)
        elif key == "documentroot" and not block.docroot:
            block.docroot = val
        elif key == "errorlog" and not block.error_log:
            block.error_log = val
        elif key == "customlog" and not block.access_log:
            # CustomLog "<path>" <format>  — take just the path
            block.access_log = val.split()[0]
        elif key == "sslengine" and val.lower() in ("on", "true", "1"):
            block.ssl_enabled = True
        elif key == "suexecusergroup" and not block.suexec_user:
            block.suexec_user = val.split()[0]
    return block


def _read_apache_sites() -> list[VhostBlock]:
    """Parse every *.conf file under /etc/apache2/sites-available/."""
    blocks: list[VhostBlock] = []
    if not APACHE_SITES_DIR.is_dir():
        return blocks
    for conf in sorted(APACHE_SITES_DIR.glob("*.conf")):
        try:
            text = conf.read_text(errors="replace")
        except OSError:
            continue
        for m in _VHOST_RE.finditer(text):
            blocks.append(_parse_one_block(m.group(1), m.group(2), conf))
    return blocks


@dataclass
class DomainRecord:
    """Aggregated per-domain projection — what list_domains returns."""
    domain:        str
    aliases:       list[str]
    owner_user:    str
    owner_uid:     int
    docroot:       str
    ip:            str
    ip6:           str
    ssl_enabled:   bool
    has_http:      bool
    has_https:     bool
    error_log:     str
    access_log:    str
    config_file:   str
    parent:        str = ""    # filled later if we can detect sub-domain relationships


def _owner_of_path(path: str) -> tuple[str, int]:
    """Stat a docroot and return (username, uid). Empty on failure."""
    if not path:
        return "", -1
    try:
        st = os.stat(path)
    except OSError:
        return "", -1
    try:
        return pwd.getpwuid(st.st_uid).pw_name, st.st_uid
    except KeyError:
        return "", st.st_uid


def list_domains() -> list[DomainRecord]:
    """
    Aggregate vhost blocks by ServerName into one record per domain.

    On a Virtualmin-style host every domain typically has two blocks
    (:80 + :443). We merge them, take the union of aliases, prefer the
    :443 block's SSL info, and resolve the docroot's owner via stat()
    instead of asking Virtualmin who owns the domain.
    """
    by_domain: dict[str, list[VhostBlock]] = {}
    for b in _read_apache_sites():
        if not b.server_name:
            continue
        by_domain.setdefault(b.server_name, []).append(b)

    records: list[DomainRecord] = []
    for domain, blocks in by_domain.items():
        # Merge / aggregate
        aliases = sorted({a for b in blocks for a in b.aliases})
        docroot = next((b.docroot for b in blocks if b.docroot), "")
        ip      = next((b.ip      for b in blocks if b.ip),      "")
        ip6     = next((b.ip6     for b in blocks if b.ip6),     "")
        error_log  = next((b.error_log  for b in blocks if b.error_log),  "")
        access_log = next((b.access_log for b in blocks if b.access_log), "")
        config_file = blocks[0].config_file
        has_http  = any(80  in b.ports for b in blocks)
        has_https = any(443 in b.ports for b in blocks)
        ssl_enabled = any(b.ssl_enabled for b in blocks)

        owner_user, owner_uid = _owner_of_path(docroot)

        records.append(DomainRecord(
            domain=domain, aliases=aliases, owner_user=owner_user,
            owner_uid=owner_uid, docroot=docroot, ip=ip, ip6=ip6,
            ssl_enabled=ssl_enabled, has_http=has_http, has_https=has_https,
            error_log=error_log, access_log=access_log, config_file=config_file,
        ))

    # Sub-domain detection (best-effort): if "foo.bar.com" matches the
    # tail of an existing domain "bar.com" AND shares the same owner,
    # treat foo.bar.com as a child of bar.com.
    by_name = {r.domain: r for r in records}
    for r in records:
        parts = r.domain.split(".")
        for cut in range(1, len(parts) - 1):
            candidate = ".".join(parts[cut:])
            parent = by_name.get(candidate)
            if parent and parent.owner_user == r.owner_user:
                r.parent = candidate
                break

    records.sort(key=lambda r: (r.parent or r.domain, r.domain))
    return records


def get_domain(domain: str) -> DomainRecord | None:
    for r in list_domains():
        if r.domain == domain:
            return r
    return None


# ---------------------------------------------------------------------------
# Postfix virtual aliases
# ---------------------------------------------------------------------------

def list_postfix_aliases(domain: str | None = None) -> list[dict]:
    """
    Parse /etc/postfix/virtual into a list of alias records.

    File format (one rule per line):
        local@domain.tld   target1,target2

    Lines starting with '#' and blank lines are ignored. Targets are
    comma-separated; whitespace tolerated.
    """
    out: list[dict] = []
    if not POSTFIX_VIRTUAL_FILE.is_file():
        return out
    try:
        text = POSTFIX_VIRTUAL_FILE.read_text(errors="replace")
    except OSError:
        return out

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s+", line, maxsplit=1)
        if len(parts) != 2:
            continue
        from_addr, targets_raw = parts
        if "@" not in from_addr:
            continue
        local, dom = from_addr.split("@", 1)
        if domain and dom != domain:
            continue
        targets = [t.strip() for t in re.split(r"[,\s]+", targets_raw) if t.strip()]
        out.append({
            "domain":       dom,
            "from_address": from_addr,
            "from_local":   local,
            "to_addresses": targets,
        })
    return out


# ---------------------------------------------------------------------------
# System users
# ---------------------------------------------------------------------------

@dataclass
class SystemUser:
    username: str
    uid:      int
    gid:      int
    real_name: str
    home:     str
    shell:    str


def list_users_for_domain(domain_owner: str, domain: str) -> list[SystemUser]:
    """
    Return mailbox-like users belonging to a domain.

    Virtualmin's convention: the domain owner is a Unix user (e.g. `adinflux`),
    and additional mailbox users live under that owner's home directory
    namespace (e.g. `adinflux.someuser` or homedirs rooted at `/home/<owner>/homes/`).
    Without virtualmin we identify them as users whose home directory is
    under the domain owner's home OR whose login name starts with
    `<owner>.`.
    """
    out: list[SystemUser] = []
    try:
        owner_pw = pwd.getpwnam(domain_owner)
    except KeyError:
        return out
    owner_home = owner_pw.pw_dir.rstrip("/") + "/"

    seen: set[str] = set()
    for pw in pwd.getpwall():
        if pw.pw_name in seen:
            continue
        is_owner_dot = pw.pw_name.startswith(f"{domain_owner}.")
        is_under_home = pw.pw_dir.startswith(owner_home)
        is_owner_itself = pw.pw_name == domain_owner
        if not (is_owner_dot or is_under_home or is_owner_itself):
            continue
        seen.add(pw.pw_name)
        out.append(SystemUser(
            username=pw.pw_name,
            uid=pw.pw_uid,
            gid=pw.pw_gid,
            real_name=(pw.pw_gecos or "").split(",")[0],
            home=pw.pw_dir,
            shell=pw.pw_shell,
        ))
    out.sort(key=lambda u: u.username)
    return out


def email_address_for(username: str, domain_owner: str, domain: str) -> str:
    """Map a system username back to its likely email address."""
    if username == domain_owner:
        return f"admin@{domain}"
    if username.startswith(f"{domain_owner}."):
        return f"{username[len(domain_owner) + 1:]}@{domain}"
    return f"{username}@{domain}"


# ---------------------------------------------------------------------------
# MariaDB databases
# ---------------------------------------------------------------------------

_MYSQL_CLI       = "/usr/bin/mariadb"
_MYSQL_CREDS     = "/etc/mysql/debian.cnf"
_SYSTEM_DBS      = {"information_schema", "performance_schema", "mysql", "sys"}


def _mysql(cmd: str) -> str:
    """
    Run a single SQL statement via the local socket; return raw text. Empty
    on failure.

    The `root@localhost` MariaDB user isn't configured for unix_socket auth
    on this host, so we authenticate via `/etc/mysql/debian.cnf` (the
    debian-sys-maint-style credentials file shipped by the mariadb-server
    package). It's root-readable only; sudo runs the client as root so it
    can read it.
    """
    if not Path(_MYSQL_CLI).exists():
        return ""
    try:
        r = subprocess.run(
            ["sudo", _MYSQL_CLI,
             f"--defaults-file={_MYSQL_CREDS}",
             "--batch", "--skip-column-names",
             "-e", cmd],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return ""
        return r.stdout
    except (subprocess.SubprocessError, OSError):
        return ""


def _all_database_sizes_bytes() -> dict[str, int]:
    """One SQL pass over information_schema for size — keyed by database name.
    Not cached — operator wants development reads to always be live."""
    out = _mysql(
        "SELECT table_schema, SUM(data_length + index_length) "
        "FROM information_schema.tables GROUP BY table_schema;"
    )
    sizes: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            try:
                sizes[parts[0]] = int(parts[1] or 0)
            except ValueError:
                continue
    return sizes


def list_mariadb_databases_for(domain_owner: str) -> list[dict]:
    """
    List databases that belong to a domain owner.

    Without virtualmin's bookkeeping we infer ownership two ways:
      1. The DB name starts with the owner's login (Virtualmin's
         convention — `adinflux` and `adinflux_wordpress` for owner
         `adinflux`).
      2. The owner is a granted user on the DB (mysql.db.User column).
    """
    if not domain_owner:
        return []
    sizes = _all_database_sizes_bytes()
    db_names = _mysql("SHOW DATABASES;").splitlines()
    grants_text = _mysql(f"SELECT Db FROM mysql.db WHERE User = '{domain_owner}';")
    granted = {ln.strip() for ln in grants_text.splitlines() if ln.strip()}

    out: list[dict] = []
    for name in db_names:
        name = name.strip()
        if not name or name in _SYSTEM_DBS:
            continue
        if not (name == domain_owner
                or name.startswith(f"{domain_owner}_")
                or name in granted):
            continue
        sz = sizes.get(name, 0)
        out.append({
            "name":    name,
            "type":    "mariadb",
            "size_mb": round(sz / (1024 * 1024), 2),
            "user":    domain_owner,
        })
    return out


# ---------------------------------------------------------------------------
# BIND DNS zone reader
# ---------------------------------------------------------------------------

def _find_zone_file(domain: str) -> Path | None:
    """Search every BIND zone-dir candidate every time — no path memo."""
    for base in BIND_ZONES_CANDIDATES:
        if not base.is_dir():
            continue
        for p in (base / f"{domain}.hosts", base / f"{domain}.zone", base / domain):
            if p.is_file():
                return p
    return None


def list_dns_records(domain: str) -> list[dict]:
    """Parse the BIND zone for this domain into a flat record list."""
    p = _find_zone_file(domain)
    if p is None:
        return []
    try:
        text = p.read_text(errors="replace")
    except OSError:
        return []

    records: list[dict] = []
    for raw in text.splitlines():
        line = raw.split(";", 1)[0].rstrip()
        if not line or line.startswith("$"):
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        name = parts[0]
        idx = 1
        ttl: int | None = None
        if parts[idx].isdigit():
            ttl = int(parts[idx]); idx += 1
        cls = parts[idx] if idx < len(parts) else ""; idx += 1
        rtype = parts[idx] if idx < len(parts) else ""; idx += 1
        rdata = " ".join(parts[idx:]) if idx < len(parts) else ""
        if not rtype:
            continue
        records.append({"name": name, "ttl": ttl, "class": cls, "type": rtype, "value": rdata})
    return records


# No cache layer in this module — operator directive 2026-06-03: "I really
# don't want caching invoked until we are done developing." Every read here
# goes straight to the underlying file / database.
