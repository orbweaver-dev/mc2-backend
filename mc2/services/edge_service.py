"""
Edge Node service — self-registering edge node provisioning.

Flow:
  1. Plugin calls POST /api/v1/edge/register with domain + edge_id + platform
  2. get_or_create_tenant() finds or creates an EdgeTenant for the domain
  3. register_node() creates/upserts the EdgeNode record
  4. issue_license_token() signs a license envelope with the tenant binding
  5. Returns tenant_id, license_token, plan, feature_flags to the plugin

All new tenants receive plan="free" and PLAN_ENFORCEMENT_ENABLED is respected.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import HTTPException

from mc2.config import get_settings
from mc2.integrations.database import get_session_factory
from mc2.models.edge import AttackReport, EdgeEulaRecord, EdgeNode, EdgeTenant, EulaVersion, FeatureFlag, ThreatReport
from mc2.models.defense_settings import FrothiqIPEntry
from mc2.services import frappe_billing_client

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Canonical EULA text registry
#
# This is the authoritative source for each published EULA version.
# The sha256 of this text (UTF-8, stripped of leading/trailing whitespace)
# is stored in EdgeEulaRecord.eula_hash so every acceptance record proves
# exactly what the administrator agreed to, independent of the plugin source.
# ─────────────────────────────────────────────────────────────────────────────

_EULA_CANONICAL: dict[str, str] = {
    "1.1": """\
FROTHIQ DEFENSE — LICENSE & NO-LIABILITY AGREEMENT
Version 1.1

PLEASE READ THIS AGREEMENT CAREFULLY BEFORE ACTIVATING FROTHIQ DEFENSE.

1. No Warranty

FrothIQ Defense is provided "AS IS" without warranty of any kind, express or implied. OrbWeaver makes no warranty that the plugin will prevent all security threats, detect all intrusions, or be free of errors or defects. Security is inherently probabilistic — no tool guarantees complete protection.

2. Limitation of Liability

To the maximum extent permitted by applicable law, OrbWeaver and its contributors shall not be liable for any direct, indirect, incidental, special, consequential, or exemplary damages arising from your use of this plugin, including but not limited to:

- Security breaches that occur despite the plugin being active
- Legitimate traffic incorrectly blocked (false positives)
- Data loss, site downtime, or revenue loss
- Changes made to .htaccess rules

3. .htaccess Modifications

FrothIQ Defense may modify your .htaccess file to block IP addresses at the web-server layer. You accept full responsibility for reviewing and testing these changes in your environment. OrbWeaver is not responsible for access issues or downtime that may result from .htaccess modifications. A self-check is performed after every block rule is written; if the site becomes inaccessible the rule is automatically rolled back.

4. Your Responsibility

You are solely responsible for configuring the plugin appropriately for your site and environment, testing its behavior before enabling active blocking, and maintaining current backups of your data and firewall rules. You should monitor the Activity Log regularly and review blocked IPs to avoid extended false-positive blocking of legitimate users.

5. License

FrothIQ Defense is licensed under the GNU General Public License v2.0 or later (GPL-2.0+). FrothIQ Core and associated cloud intelligence services are separate, proprietary services governed by their own terms of service. Use of cloud features requires a separate agreement with OrbWeaver.

6. Governing Law

This agreement is governed by the laws of the State of Texas, United States, without regard to conflict of law provisions. Any disputes arising from your use of this plugin shall be resolved in the courts of Texas.

7. Data Sharing & Attack Reporting

When the Auto Attack Reporting setting is enabled (on by default), FrothIQ Defense transmits the following data to FrothIQ Core upon blocking a request:

- The blocked IP address
- Threat score assigned by this site
- Request path that triggered the block
- HTTP user-agent string from the request
- Server-side traceroute hops (run by FrothIQ Core, not your server)
- Your site's registered domain and Edge ID

This data is used solely to compile structured attack reports, maintain the community threat intelligence pool, and improve blocking accuracy across all FrothIQ-protected sites. Reports are deduplicated to one per attacker IP per 24 hours. You may disable Auto Attack Reporting at any time in Settings > Protection without affecting local blocking functionality.

Additionally, this plugin records your acceptance of this agreement, including the accepting administrator's email address, the timestamp, and the IP address of the administrator's browser, and transmits that record to FrothIQ Core for your site's compliance history.\
""",
}


def _canonical_hash(text: str) -> str:
    """SHA-256 of the canonical EULA text (UTF-8, stripped)."""
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


async def get_eula_version(version: str) -> dict[str, str] | None:
    """
    Return the canonical EULA record for a given version string.

    Looks up the in-memory registry first; if found and not yet persisted,
    upserts the row into eula_versions so the table stays consistent.
    Returns None when the version is unknown.
    """
    text = _EULA_CANONICAL.get(version)
    if text is None:
        return None

    authoritative_hash = _canonical_hash(text)

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EulaVersion).where(EulaVersion.version == version).limit(1)
        )
        row = result.scalar_one_or_none()
        if not row:
            row = EulaVersion(
                version=version,
                text=text,
                sha256_hash=authoritative_hash,
                published_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
            session.add(row)
            await session.commit()

    return {
        "version":      version,
        "text":         text,
        "sha256_hash":  authoritative_hash,
        "published_at": row.published_at.isoformat() if row.published_at else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def register_edge_node(
    domain: str,
    edge_id: str,
    plugin_version: str,
    platform: str,
    contact_email: str | None = None,
) -> dict[str, Any]:
    """
    Idempotent: safe to call multiple times (e.g. on every plugin boot).
    Returns a complete registration response with license token.
    """
    factory = get_session_factory()
    async with factory() as session:
        tenant = await _get_or_create_tenant(
            session, domain, contact_email=contact_email
        )
        node = await _upsert_node(session, tenant, edge_id, plugin_version, platform)
        await session.commit()

        # Refresh after commit to get DB-generated values
        await session.refresh(tenant)
        await session.refresh(node)

        enforcement_enabled = await _flag_value(session, "PLAN_ENFORCEMENT_ENABLED")
        feature_flags = _build_feature_flags(tenant.plan, enforcement_enabled)
        license_token = _issue_license_token(
            tenant_id=tenant.tenant_id,
            edge_id=edge_id,
            domain=domain,
            plan=tenant.plan,
        )

    is_new_tenant = node.registration_count == 1
    logger.info(
        "edge_service: %s node=%s tenant=%s plan=%s state=%s",
        "new" if is_new_tenant else "re-register",
        edge_id[:16], tenant.tenant_id[:8], tenant.plan, node.state,
    )

    # Fire-and-forget: sync new tenants to ERPNext for GAAP accounting.
    # Never blocks the registration response; failures are logged, not raised.
    if is_new_tenant:
        asyncio.create_task(frappe_billing_client.sync_new_tenant(
            tenant_id=tenant.tenant_id,
            domain=tenant.domain,
            contact_email=tenant.contact_email,
            plan=tenant.plan,
        ))

    return {
        "tenant_id": tenant.tenant_id,
        "domain": tenant.domain,
        "license_token": license_token,
        "plan": tenant.plan,
        "edge_id": edge_id,
        "node_state": node.state,
        "feature_flags": feature_flags,
        "enforcement_enabled": enforcement_enabled,
    }


async def deregister_edge_node(
    edge_id: str,
    license_token: str,
    reason: str = "uninstalled",
) -> bool:
    """
    Set node state to REMOVED. Returns True if the node was found and updated.
    The node record is kept for audit — never hard-deleted.
    """
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EdgeNode).where(EdgeNode.edge_id == edge_id)
        )
        node = result.scalar_one_or_none()
        if node is None or node.state == "REMOVED":
            return False

        node.state = "REMOVED"
        node.last_seen_at = datetime.now(timezone.utc).replace(tzinfo=None)
        await session.commit()

    logger.info("edge_service: deregistered edge_id=%s reason=%s", edge_id[:16], reason)
    return True


async def touch_edge_node(
    edge_id: str,
    requests_1m: int = 0,
    blocks_1m: int = 0,
    errors_1m: int = 0,
    protection_mode: str | None = None,
    plugin_version: str | None = None,
) -> dict[str, Any] | None:
    """
    Update last_seen_at and promote node state on heartbeat.
    Returns current plan and state, or None if node not found.
    """
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EdgeNode).where(EdgeNode.edge_id == edge_id)
        )
        node = result.scalar_one_or_none()
        if node is None:
            return None

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        node.last_seen_at = now
        if plugin_version:
            node.plugin_version = plugin_version
        if protection_mode in ("monitor", "protect", "block"):
            node.protection_mode = protection_mode
        # State promotions
        if node.state == "REGISTERED":
            node.state = "ACTIVE"
        elif node.state in ("ACTIVE", "DEGRADED"):
            node.state = "SYNCED"
        # Don't promote REMOVED nodes
        if node.state == "REMOVED":
            return None

        # Close any open heartbeat-miss outage windows — node is alive again.
        from mc2.services.edge_outage_service import close_open_windows_for_node
        await close_open_windows_for_node(session, edge_id)

        await session.commit()

    logger.debug(
        "edge_service: heartbeat edge_id=%s req=%d blk=%d err=%d",
        edge_id[:16], requests_1m, blocks_1m, errors_1m,
    )
    return {"plan": node.plan, "state": node.state}


async def _nft_add_element(ip: str) -> bool:
    """Run `nft add element inet frothiq blacklist { ip }`. Returns True on success."""
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                "/usr/sbin/nft", "add", "element", "inet", "frothiq", "blacklist", f"{{ {ip} }}",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            ),
            timeout=4,
        )
        rc = await asyncio.wait_for(proc.wait(), timeout=4)
        return rc == 0
    except Exception as exc:
        logger.debug("_nft_add_element: failed for %s: %s", ip, exc)
        return False


async def _auto_promote_to_blacklist(ip: str, reason: str) -> None:
    """
    Promote a community-corroborated IP to the frothiq_ip_list DB and live nft blacklist.

    Called fire-and-forget from report_edge_event() when threat_score crosses >= 65
    (2+ independent tenants have reported the same IP). This ensures the Defense Mesh
    grows the shared blocklist automatically — not just on manual admin action.

    Persistence: DB record survives reboots; sync_community_ips_to_nft() re-applies
    all DB entries to the live nft set on MC3 startup.

    Whitelist protection: if the IP is on the operator whitelist, the promotion is
    silently dropped and an audit entry is written. Without this, an operator IP
    that gets reported by tenants (curl tests, scanner-pattern UA, etc.) would
    land in the blacklist set despite kernel-level acceptance via the whitelist
    chain rule, and would be redistributed to every edge plugin until #67's
    subtraction filter caught it on the way out.
    """
    import ipaddress as _ipmod
    from mc2.models.defense_settings import FrothiqIPEntry
    from mc2.services import audit_service

    try:
        normalized = str(_ipmod.ip_address(ip))
    except ValueError:
        return

    factory = get_session_factory()
    async with factory() as session:
        on_whitelist = await session.scalar(
            select(FrothiqIPEntry.id).where(
                FrothiqIPEntry.ip == normalized,
                FrothiqIPEntry.list_type == "whitelist",
            )
        )
        if on_whitelist is not None:
            logger.warning(
                "community_promote: refusing to blacklist whitelisted IP %s (reason=%s)",
                normalized, reason[:80] if reason else "",
            )
            try:
                await audit_service.log_action(
                    action="whitelist_protect",
                    user_id=None,
                    user_email="system",
                    resource=f"ip:{normalized}",
                    detail=f"Defense Mesh blocked from blacklisting whitelisted IP. Reason: {reason[:200]}",
                    status="denied",
                    db=session,
                )
            except Exception as exc:
                logger.debug("audit log_action whitelist_protect failed: %s", exc)
            return

        existing = await session.execute(
            select(FrothiqIPEntry).where(
                FrothiqIPEntry.ip == normalized,
                FrothiqIPEntry.list_type == "blacklist",
            )
        )
        if existing.scalar_one_or_none() is None:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            entry = FrothiqIPEntry(
                id=str(uuid.uuid4()),
                ip=normalized,
                label=f"Defense Mesh: {reason[:100]}" if reason else "Defense Mesh: community report",
                list_type="blacklist",
                notes=f"Auto-promoted: 2+ edge nodes corroborated this IP. Reason: {reason}",
                created_at=now,
                created_by="system",
            )
            session.add(entry)
            await session.commit()

    ok = await _nft_add_element(normalized)
    logger.info(
        "community_promote: ip=%s reason=%s nft_applied=%s",
        normalized, reason[:60] if reason else "", ok,
    )


async def sync_community_ips_to_nft() -> None:
    """
    Re-apply all DB-tracked blacklist entries to the live nft set, and backfill
    any ThreatReport IPs with score >= 65 that haven't been promoted yet.

    Called at MC3 startup so community-promoted IPs survive service restarts.
    nft add element is idempotent for IPs already in the set from frothiq.nft;
    errors (duplicate elements) are silently ignored.
    """
    from mc2.models.defense_settings import FrothiqIPEntry

    factory = get_session_factory()

    # Step 1: backfill ThreatReport IPs that crossed the threshold before this
    # feature was deployed but were never added to frothiq_ip_list.
    try:
        async with factory() as session:
            # IPs in ThreatReport with score >= 65 that are NOT yet in frothiq_ip_list
            already_stmt = select(FrothiqIPEntry.ip).where(FrothiqIPEntry.list_type == "blacklist")
            already_result = await session.execute(already_stmt)
            already_tracked = {row[0] for row in already_result.fetchall()}

            backfill_stmt = (
                select(ThreatReport.ip, ThreatReport.reason)
                .where(ThreatReport.threat_score >= 65)
                .distinct()
            )
            backfill_result = await session.execute(backfill_stmt)
            to_backfill = [
                (row[0], row[1] or "community report")
                for row in backfill_result.fetchall()
                if row[0] not in already_tracked
            ]

        for ip, reason in to_backfill:
            await _auto_promote_to_blacklist(ip, f"backfill: {reason}")

        if to_backfill:
            logger.info("sync_community_ips_to_nft: backfilled %d pre-existing IPs", len(to_backfill))
    except Exception as exc:
        logger.warning("sync_community_ips_to_nft: backfill step failed: %s", exc)

    # Step 2: push all frothiq_ip_list blacklist entries to the live nft set
    try:
        async with factory() as session:
            result = await session.execute(
                select(FrothiqIPEntry.ip).where(FrothiqIPEntry.list_type == "blacklist")
            )
            ips = [row[0] for row in result.fetchall()]
    except Exception as exc:
        logger.warning("sync_community_ips_to_nft: DB read failed: %s", exc)
        return

    added = errors = 0
    for ip in ips:
        ok = await _nft_add_element(ip)
        if ok:
            added += 1
        else:
            errors += 1

    logger.info(
        "sync_community_ips_to_nft: applied=%d already_present_or_err=%d total=%d",
        added, errors, len(ips),
    )


async def _read_nft_set(set_name: str) -> list[str]:
    """
    Read the live nftables `inet frothiq <set_name>` set and return all IP/CIDR entries.

    Runs as a non-blocking asyncio subprocess (no event loop blocking).
    Returns empty list on any failure.
    """
    import re
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                "/usr/sbin/nft", "list", "set", "inet", "frothiq", set_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            ),
            timeout=5,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        text = (stdout or b"").decode("utf-8", errors="replace")
        elements_match = re.search(r"elements\s*=\s*\{([^}]+)\}", text, re.DOTALL)
        if not elements_match:
            return []
        entries: list[str] = []
        for token in re.split(r",", elements_match.group(1)):
            token = token.strip()
            ip_part = token.split()[0] if token else ""
            if ip_part and re.match(r"^[\d./a-fA-F:]+$", ip_part):
                entries.append(ip_part)
        return entries
    except Exception as exc:
        logger.debug("edge_service: _read_nft_set(%s) failed: %s", set_name, exc)
        return []


async def _read_nft_blacklist(set_name: str = "blacklist") -> list[str]:
    """
    Read the canonical MC3 blacklist set (same IPs the firewall enforces).
    Thin wrapper around _read_nft_set retained for call-site compatibility.
    """
    return await _read_nft_set(set_name)


async def _read_operator_whitelist() -> set[str]:
    """
    Return the operator whitelist as a set of IPs.

    Sourced from frothiq_ip_list (list_type='whitelist'). The DB row is the
    authoritative record — the nftables `inet frothiq whitelist` set is just
    its kernel-side mirror and isn't readable from an unprivileged service user.
    Whitelisted IPs must never be redistributed to edge nodes as blocked,
    even if they appear in the blacklist set or community threat pool.
    """
    try:
        async with get_session_factory()() as session:
            result = await session.execute(
                select(FrothiqIPEntry.ip).where(FrothiqIPEntry.list_type == "whitelist")
            )
            return {row[0] for row in result.fetchall()}
    except Exception as exc:
        logger.warning("edge_service: _read_operator_whitelist DB read failed: %s", exc)
        return set()


async def get_blocklist(
    edge_id: str,
    since: int = 0,
) -> dict[str, Any] | None:
    """
    Return the threat IP block list for this edge node's plan.

    Sources (merged and deduplicated in priority order):
      1. Live nftables `inet frothiq blacklist` — the canonical MC3-enforced list
      2. Community threat pool (ThreatReport table, score-filtered per plan)
      3. frothiq-core external threat feed (fail-open fallback)

    Block list tiers:
      free:       full feed — same as enterprise while plan enforcement is off
      pro:        extended feed (score ≥ 70)
      enterprise: full feed (score ≥ 50)
    """
    from mc2.services.core_client import core_client

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EdgeNode).where(EdgeNode.edge_id == edge_id)
        )
        node = result.scalar_one_or_none()

    if node is None or node.state == "REMOVED":
        return None

    plan = node.plan

    # Score threshold by plan — free matches enterprise while plan enforcement is off
    score_threshold = {"pro": 70, "enterprise": 50}.get(plan, 50)

    # Source 1 — live nftables blacklist (canonical MC3 firewall list)
    nft_ips = await _read_nft_blacklist("blacklist")

    # Source 2 — community threat pool (IPs reported as blocked by edge nodes)
    community_ips: list[str] = []
    try:
        async with get_session_factory()() as session:
            stmt = (
                select(ThreatReport.ip)
                .where(ThreatReport.threat_score >= score_threshold)
                .distinct()
            )
            if since:
                since_dt = datetime.fromtimestamp(since, tz=timezone.utc).replace(tzinfo=None)
                stmt = stmt.where(ThreatReport.last_seen >= since_dt)
            result = await session.execute(stmt)
            community_ips = [row[0] for row in result.fetchall()]
    except Exception as exc:
        logger.warning("edge_service: get_blocklist community query failed: %s", exc)

    # Source 3 — frothiq-core external threat feed (fail-open)
    core_ips: list[str] = []
    try:
        params: dict[str, Any] = {"min_score": score_threshold, "limit": 5000}
        if since:
            params["since"] = since
        data = await core_client.get("/api/v1/threats/feed", params=params)
        if isinstance(data, list):
            core_ips = [str(e["ip"]) for e in data if e.get("ip")]
        elif isinstance(data, dict):
            raw = data.get("ips") or data.get("threats") or []
            core_ips = [str(e["ip"] if isinstance(e, dict) else e) for e in raw if e]
    except Exception as exc:
        logger.debug("edge_service: get_blocklist core feed unavailable: %s", exc)

    # Operator whitelist — subtract from all three sources before redistribution.
    # The kernel firewall honors @whitelist before @blacklist drop (see frothiq.nft chain order),
    # but edge plugins enforce at the application layer using only this list, so they need the
    # already-filtered version. Without this step, a whitelisted operator IP that lands in
    # @blacklist (manual add, LFD escalation, etc.) is still pushed to every WP plugin as blocked.
    whitelist = await _read_operator_whitelist()
    if whitelist:
        nft_ips       = [ip for ip in nft_ips       if ip not in whitelist]
        community_ips = [ip for ip in community_ips if ip not in whitelist]
        core_ips      = [ip for ip in core_ips      if ip not in whitelist]

    # Merge: nft (canonical) first so it's never filtered out, then community, then core
    ips = list(dict.fromkeys(nft_ips + community_ips + core_ips))

    logger.info(
        "edge_service: blocklist plan=%s threshold=%d nft=%d community=%d core=%d whitelist=%d total=%d",
        plan, score_threshold, len(nft_ips), len(community_ips), len(core_ips), len(whitelist), len(ips),
    )
    return {"ips": ips, "plan": plan}


async def report_edge_event(
    edge_id: str,
    tenant_id: str,
    ip: str,
    event_type: str,
    severity: str = "high",
    reason: str = "",
) -> dict[str, Any]:
    """
    Ingest a threat event reported by an edge node.

    Upserts into ThreatReport (one row per ip+tenant). Recalculates
    threat_score based on cross-tenant confirmation count:
      1 tenant  → score 40   (single-source, low confidence)
      2 tenants → score 65   (corroborated)
      3 tenants → score 80   (multi-site confirmed)
      5+ tenants → score 95  (high confidence, enters free-tier blocklist)

    The updated IP becomes eligible for the global blocklist on the next pull.
    """
    factory = get_session_factory()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    async with factory() as session:
        # Load or create the per-(ip, tenant) row
        result = await session.execute(
            select(ThreatReport).where(
                ThreatReport.ip == ip,
                ThreatReport.tenant_id == tenant_id,
            )
        )
        row = result.scalar_one_or_none()

        if row is None:
            row = ThreatReport(
                id=str(uuid.uuid4()),
                ip=ip,
                tenant_id=tenant_id,
                edge_id=edge_id,
                event_type=event_type,
                severity=severity,
                reason=reason[:512],
                report_count=1,
                tenant_count=1,
                threat_score=0,
                first_seen=now,
                last_seen=now,
            )
            session.add(row)
        else:
            row.report_count += 1
            row.last_seen = now
            if severity in ("high", "critical") and row.severity not in ("high", "critical"):
                row.severity = severity

        await session.flush()

        # Count distinct tenants that have reported this IP
        from sqlalchemy import func
        count_result = await session.execute(
            select(func.count(ThreatReport.id)).where(ThreatReport.ip == ip)
        )
        distinct_tenants = count_result.scalar_one() or 1

        # Update tenant_count and recalculate threat_score on the current row
        row.tenant_count = distinct_tenants
        score_map = {1: 40, 2: 65, 3: 80, 4: 88}
        row.threat_score = score_map.get(distinct_tenants, 95 if distinct_tenants >= 5 else 40)

        await session.commit()

    logger.info(
        "threat_report: ip=%s tenants=%d score=%d event=%s edge=%s",
        ip, distinct_tenants, row.threat_score, event_type, edge_id[:16],
    )

    # Forward to frothiq-core intelligence pipeline (fire-and-forget).
    # This seeds the campaign correlator so Defense Mesh shows real data.
    asyncio.create_task(_forward_threat_to_core(ip, event_type, severity))

    # Auto-promote to live nft blacklist when corroborated by 2+ tenants.
    # Score 65 = 2 tenants agreed → sufficient to block at firewall level.
    if row.threat_score >= 65:
        asyncio.create_task(_auto_promote_to_blacklist(ip, reason))

    return {
        "ip": ip,
        "threat_score": row.threat_score,
        "tenant_count": distinct_tenants,
        "ingested": True,
    }


async def list_edge_nodes(
    limit: int = 100, offset: int = 0, platform: str | None = None
) -> dict[str, Any]:
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(EdgeNode).order_by(EdgeNode.registered_at.desc()).offset(offset).limit(limit)
        if platform:
            stmt = stmt.where(EdgeNode.platform == platform)
        result = await session.execute(stmt)
        nodes = result.scalars().all()

        count_result = await session.execute(select(EdgeNode))
        total = len(count_result.scalars().all())

    return {
        "total": total,
        "nodes": [_node_to_dict(n) for n in nodes],
    }


async def list_edge_tenants(limit: int = 100, offset: int = 0) -> dict[str, Any]:
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EdgeTenant).order_by(EdgeTenant.created_at.desc()).offset(offset).limit(limit)
        )
        tenants = result.scalars().all()
    return {
        "total": len(tenants),
        "tenants": [_tenant_to_dict(t) for t in tenants],
    }


async def get_feature_flags() -> dict[str, bool]:
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(FeatureFlag))
        flags = result.scalars().all()
    return {f.flag_key: f.flag_value for f in flags}


async def set_feature_flag(flag_key: str, value: bool, changed_by: str) -> dict[str, Any]:
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(FeatureFlag).where(FeatureFlag.flag_key == flag_key)
        )
        flag = result.scalar_one_or_none()
        if flag is None:
            flag = FeatureFlag(
                id=str(uuid.uuid4()),
                flag_key=flag_key,
                flag_value=value,
                description=_flag_description(flag_key),
                last_changed_by=changed_by,
            )
            session.add(flag)
        else:
            flag.flag_value = value
            flag.last_changed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            flag.last_changed_by = changed_by
        await session.commit()

    logger.info("feature_flag: %s set to %s by %s", flag_key, value, changed_by)
    return {"flag_key": flag_key, "flag_value": value, "changed_by": changed_by}


async def get_edge_endpoint(tenant_id: str) -> str | None:
    """
    Return the HTTP base URL of the most-recently-seen active edge node for *tenant_id*.
    Returns None if no active node is registered.
    The URL is derived from the node's domain field: https://<domain>
    """
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(EdgeNode)
            .where(EdgeNode.tenant_id == tenant_id)
            .where(EdgeNode.state.in_(["ACTIVE", "SYNCED"]))
            .order_by(EdgeNode.last_seen_at.desc())
        )
        node = result.scalars().first()

    if node is None:
        return None

    domain = node.domain.rstrip("/")
    if not domain.startswith("http"):
        domain = f"https://{domain}"
    return domain


async def get_registration_stats() -> dict[str, Any]:
    """Summary statistics for the MC3 dashboard."""
    factory = get_session_factory()
    async with factory() as session:
        nodes_result = await session.execute(select(EdgeNode))
        nodes = nodes_result.scalars().all()

        tenants_result = await session.execute(select(EdgeTenant))
        tenants = tenants_result.scalars().all()

    plan_dist: dict[str, int] = {}
    platform_dist: dict[str, int] = {}
    state_dist: dict[str, int] = {}

    for n in nodes:
        plan_dist[n.plan] = plan_dist.get(n.plan, 0) + 1
        platform_dist[n.platform] = platform_dist.get(n.platform, 0) + 1
        state_dist[n.state] = state_dist.get(n.state, 0) + 1

    return {
        "total_nodes": len(nodes),
        "total_tenants": len(tenants),
        "plan_distribution": plan_dist,
        "platform_distribution": platform_dist,
        "state_distribution": state_dist,
        "free_pct": round(
            plan_dist.get("free", 0) / max(len(nodes), 1) * 100, 1
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _get_or_create_tenant(
    session: AsyncSession,
    domain: str,
    contact_email: str | None = None,
) -> EdgeTenant:
    result = await session.execute(
        select(EdgeTenant).where(EdgeTenant.domain == domain)
    )
    tenant = result.scalar_one_or_none()

    if tenant is not None:
        # --- Gate: revoked domains may never re-register ---
        if tenant.registration_state == "revoked":
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "domain_revoked",
                    "message": (
                        "This domain has been permanently revoked. "
                        "Contact support if you believe this is an error."
                    ),
                },
            )

        # --- Gate: deregistered domains require email verification ---
        if tenant.registration_state == "deregistered":
            if not contact_email:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "email_required",
                        "message": (
                            "This domain was previously deregistered. "
                            "Provide the original contact email to restore your data."
                        ),
                        "archived": True,
                    },
                )
            if tenant.contact_email and tenant.contact_email.lower() != contact_email.lower():
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "email_mismatch",
                        "message": "Email does not match the archived registration record.",
                    },
                )

            # Email matched — restore archived data and reactive tenant
            archived = {}
            if tenant.archived_data:
                try:
                    archived = json.loads(tenant.archived_data)
                except Exception:
                    pass

            tenant.registration_state = "active"
            tenant.is_active = True
            tenant.deregistered_at = None
            tenant.archived_data = None
            if archived.get("plan"):
                tenant.plan = archived["plan"]
            if archived.get("notes"):
                tenant.notes = archived["notes"]

            logger.info(
                "edge_service: deregistered tenant RESTORED for domain=%s via email match", domain
            )
        else:
            # Active tenant — update contact_email if newly provided
            if contact_email and not tenant.contact_email:
                tenant.contact_email = contact_email

        return tenant

    # New tenant
    tenant = EdgeTenant(
        id=str(uuid.uuid4()),
        domain=domain,
        tenant_id=str(uuid.uuid4()),
        plan="free",
        registration_state="active",
        contact_email=contact_email,
    )
    session.add(tenant)
    logger.info("edge_service: new tenant created for domain=%s", domain)
    return tenant


async def _upsert_node(
    session: AsyncSession,
    tenant: EdgeTenant,
    edge_id: str,
    plugin_version: str,
    platform: str,
) -> EdgeNode:
    result = await session.execute(
        select(EdgeNode).where(EdgeNode.edge_id == edge_id)
    )
    node = result.scalar_one_or_none()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if node is None:
        node = EdgeNode(
            id=str(uuid.uuid4()),
            edge_id=edge_id,
            tenant_id=tenant.tenant_id,
            domain=tenant.domain,
            platform=platform,
            plugin_version=plugin_version,
            state="REGISTERED",
            plan=tenant.plan,
            registered_at=now,
            last_seen_at=now,
            registration_count=1,
        )
        session.add(node)
    else:
        node.last_seen_at = now
        node.plugin_version = plugin_version
        node.registration_count = (node.registration_count or 0) + 1
        # Promote state on re-registration
        if node.state == "REGISTERED":
            node.state = "ACTIVE"
        elif node.state in ("ACTIVE", "DEGRADED"):
            node.state = "SYNCED"

    return node


async def _flag_value(session: AsyncSession, flag_key: str) -> bool:
    result = await session.execute(
        select(FeatureFlag).where(FeatureFlag.flag_key == flag_key)
    )
    flag = result.scalar_one_or_none()
    return flag.flag_value if flag else False


def _issue_license_token(
    tenant_id: str, edge_id: str, domain: str, plan: str
) -> str:
    """
    Issue a signed license envelope.
    Payload is HMAC-SHA256 signed with gateway_signing_key for tamper detection.
    The token is a JSON payload with a detached HMAC signature.
    """
    settings = get_settings()
    payload = {
        "tenant_id": tenant_id,
        "edge_id": edge_id,
        "domain": domain,
        "plan": plan,
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = hmac.new(
        settings.gateway_signing_key.encode(),
        payload_json.encode(),
        hashlib.sha256,
    ).hexdigest()
    # Return a compact token: base64url(payload) + "." + sig
    import base64
    b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=").decode()
    return f"{b64}.{sig}"


def _build_feature_flags(plan: str, enforcement_enabled: bool) -> dict[str, bool]:
    """
    Return the feature flags the edge plugin should apply.
    When PLAN_ENFORCEMENT_ENABLED=false, all features behave as accessible (soft mode).
    """
    if not enforcement_enabled:
        # Soft mode: all features open regardless of plan
        return {
            "paywall_active": False,
            "upgrade_prompt": False,
            "advanced_scanning": True,
            "real_time_events": True,
            "threat_feeds": True,
            "audit_logs": True,
        }

    # Enforcement mode: all features open for now — free plan ungated
    return {
        "paywall_active": False,
        "upgrade_prompt": False,
        "advanced_scanning": True,
        "real_time_events": True,
        "threat_feeds": True,
        "audit_logs": True,
    }


def _flag_description(flag_key: str) -> str:
    descriptions = {
        "PLAN_ENFORCEMENT_ENABLED": (
            "When true, enforce plan limits and activate paywall injection. "
            "When false (default), all features are accessible regardless of plan."
        ),
        "UPGRADE_SYSTEM_ENABLED": "When true, show upgrade prompts and enable upgrade orchestration.",
        "REGISTRATION_ENABLED": "When false, new edge node registrations are rejected.",
    }
    return descriptions.get(flag_key, f"Feature flag: {flag_key}")


def _node_to_dict(n: EdgeNode) -> dict[str, Any]:
    return {
        "id": n.id,
        "edge_id": n.edge_id,
        "tenant_id": n.tenant_id,
        "domain": n.domain,
        "platform": n.platform,
        "plugin_version": n.plugin_version,
        "state": n.state,
        "plan": n.plan,
        "protection_mode": getattr(n, "protection_mode", None),
        "registered_at": n.registered_at.isoformat() if n.registered_at else None,
        "last_seen": n.last_seen_at.isoformat() if n.last_seen_at else None,
        "last_seen_at": n.last_seen_at.isoformat() if n.last_seen_at else None,
        "registration_count": n.registration_count,
    }


def _tenant_to_dict(t: EdgeTenant) -> dict[str, Any]:
    return {
        "id": t.id,
        "tenant_id": t.tenant_id,
        "domain": t.domain,
        "plan": t.plan,
        "is_active": t.is_active,
        "registration_state": getattr(t, "registration_state", "active"),
        "contact_email": getattr(t, "contact_email", None),
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


async def _forward_threat_to_core(ip: str, event_type: str, severity: str) -> None:
    """Fire-and-forget: push edge threat event into frothiq-core's campaign correlator."""
    try:
        from mc2.services.core_client import core_client
        await core_client.post(
            "/api/v2/internal/ingest-threat",
            body={"ip": ip, "severity": severity, "event_type": event_type, "attack_vectors": []},
        )
    except Exception as exc:
        logger.debug("_forward_threat_to_core: %s ip=%s: %s", event_type, ip, exc)


# ─────────────────────────────────────────────────────────────────────────────
# Attack Reports
# ─────────────────────────────────────────────────────────────────────────────

async def store_attack_report(data: dict[str, Any]) -> dict[str, Any]:
    """
    Persist a structured attack report submitted by an edge node.

    Also feeds the attacking IP into the community threat pool so it can
    be distributed to other edge nodes via the /blocklist feed.
    """
    factory = get_session_factory()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    def _parse_ts(val: Any) -> datetime | None:
        try:
            return datetime.fromtimestamp(int(val), tz=timezone.utc).replace(tzinfo=None)
        except (TypeError, ValueError, OSError):
            return None

    report_id = str(uuid.uuid4())
    async with factory() as session:
        report = AttackReport(
            id=report_id,
            edge_id=data.get("edge_id", ""),
            tenant_id=data.get("tenant_id", ""),
            domain=data.get("domain", "")[:255],
            attacking_ip=data.get("attacking_ip", ""),
            cidr=data.get("cidr", "")[:50],
            asn=data.get("asn", "")[:32],
            org=data.get("org", "")[:255],
            attack_type=data.get("attack_type", "credential_stuffing")[:64],
            attempt_count=int(data.get("attempt_count", 0)),
            usernames_targeted=json.dumps(data.get("usernames_targeted", [])),
            user_agents=json.dumps(data.get("user_agents", [])),
            attack_started_at=_parse_ts(data.get("attack_started_at")),
            attack_ended_at=_parse_ts(data.get("attack_ended_at")),
            ip_blocked=bool(data.get("ip_blocked", False)),
            cidr_blocked=bool(data.get("cidr_blocked", False)),
            enum_lockdown=bool(data.get("enum_lockdown", False)),
            notes=data.get("notes", "")[:2000],
            traceroute_hops=json.dumps(data.get("traceroute_hops", [])) if data.get("traceroute_hops") else None,
            reported_at=now,
        )
        session.add(report)
        await session.commit()

    logger.info(
        "attack_report: id=%s ip=%s type=%s attempts=%d domain=%s",
        report_id, data.get("attacking_ip"), data.get("attack_type"),
        data.get("attempt_count", 0), data.get("domain"),
    )

    # Feed IP into community threat pool
    await report_edge_event(
        edge_id=data.get("edge_id", ""),
        tenant_id=data.get("tenant_id", ""),
        ip=data.get("attacking_ip", ""),
        event_type=data.get("attack_type", "credential_stuffing"),
        severity="high",
        reason=(
            f"Attack report: {data.get('attack_type','credential_stuffing')} — "
            f"{data.get('attempt_count', 0)} attempts on {data.get('domain', '')}"
        ),
    )

    return {"report_id": report_id}


async def auto_compile_attack_report(
    edge_id: str,
    ip: str,
    score: int,
    reason: str,
    path: str,
    ip_blocked: bool,
) -> dict[str, Any]:
    """
    Compile a full AttackReport from a thin plugin trigger.

    The plugin supplies only the raw block context (IP, score, reason, path).
    MC3 handles everything else: tenant lookup, attempt count from stored threat
    reports, attack type inference, traceroute, deduplication, and storage.

    Rate-limited to one compiled report per (edge_id, IP) per 24 hours.
    """
    import asyncio
    import re as _re

    factory = get_session_factory()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff_24h = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)

    async with factory() as session:
        # Resolve edge node → tenant_id, domain
        node_result = await session.execute(
            select(EdgeNode).where(EdgeNode.edge_id == edge_id)
        )
        node = node_result.scalar_one_or_none()
        if node is None:
            return {"ok": False, "error": "unknown edge node"}

        tenant_id = node.tenant_id
        domain    = node.site_url or ""

        # Deduplication: skip if already reported this IP in the last 24 hours
        dup = await session.execute(
            select(AttackReport.id).where(
                AttackReport.edge_id      == edge_id,
                AttackReport.attacking_ip == ip,
                AttackReport.reported_at  >= cutoff_24h,
            ).limit(1)
        )
        if dup.scalar_one_or_none():
            return {"ok": False, "skipped": True, "reason": "rate_limited"}

        # Attempt count: total threat reports received from this edge for this IP
        count_result = await session.execute(
            select(ThreatReport).where(
                ThreatReport.edge_id == edge_id,
                ThreatReport.ip      == ip,
            )
        )
        tr = count_result.scalar_one_or_none()
        attempt_count = tr.report_count if tr else 1

    # Infer attack type from reason string
    reason_lc = reason.lower()
    if any(k in reason_lc for k in ("brute", "login", "credential")):
        attack_type = "brute_force"
    elif any(k in reason_lc for k in ("sql", "injection", "select", "union")):
        attack_type = "sql_injection"
    elif any(k in reason_lc for k in ("xss", "script", "javascript")):
        attack_type = "xss"
    elif any(k in reason_lc for k in ("traversal", "../", "%2e")):
        attack_type = "path_traversal"
    elif any(k in reason_lc for k in ("sensitive file", "file access")):
        attack_type = "file_access_attempt"
    elif any(k in reason_lc for k in ("scanner", "user agent", "nikto", "sqlmap")):
        attack_type = "scanner"
    else:
        attack_type = "suspicious_request"

    # Traceroute (runs on MC3 — no exec() on the WordPress server)
    hops: list[dict] = []
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                "traceroute", "-n", "-q", "1", "-w", "2", "-m", "20", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            ),
            timeout=5,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=65)
        for line in stdout.decode().splitlines():
            m = _re.match(
                r"^\s*(\d+)\s+(\*|\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)\s+(?:([\d.]+)\s+ms)?",
                line,
            )
            if m:
                hops.append({
                    "hop":    int(m.group(1)),
                    "ip":     None if m.group(2) == "*" else m.group(2),
                    "rtt_ms": float(m.group(3)) if m.group(3) else None,
                })
    except Exception:
        pass  # traceroute unavailable or timed out — report still stored without hops

    notes = (
        f"Auto-compiled by MC3. Block score: {score}. "
        f"Reason: {reason}. Path: {path}. "
        f"Attempt count from threat pool: {attempt_count}."
    )

    result = await store_attack_report({
        "edge_id":            edge_id,
        "tenant_id":          tenant_id,
        "domain":             domain,
        "attacking_ip":       ip,
        "cidr":               "",
        "asn":                "",
        "org":                "",
        "attack_type":        attack_type,
        "attempt_count":      attempt_count,
        "usernames_targeted": [],
        "user_agents":        [],
        "ip_blocked":         ip_blocked,
        "cidr_blocked":       False,
        "enum_lockdown":      True,
        "notes":              notes,
        "traceroute_hops":    hops,
    })
    return {"ok": True, **result}


async def list_attack_reports(
    limit: int = 50,
    offset: int = 0,
    tenant_id: str | None = None,
    edge_id: str | None = None,
) -> dict[str, Any]:
    """Return paginated attack reports for the Control Center UI or edge plugin."""
    from sqlalchemy import func

    factory = get_session_factory()
    async with factory() as session:
        stmt = select(AttackReport).order_by(AttackReport.reported_at.desc())
        if tenant_id:
            stmt = stmt.where(AttackReport.tenant_id == tenant_id)
        if edge_id:
            stmt = stmt.where(AttackReport.edge_id == edge_id)
        stmt = stmt.limit(min(limit, 200)).offset(offset)
        result = await session.execute(stmt)
        rows = result.scalars().all()

        count_stmt = select(func.count()).select_from(AttackReport)
        if tenant_id:
            count_stmt = count_stmt.where(AttackReport.tenant_id == tenant_id)
        if edge_id:
            count_stmt = count_stmt.where(AttackReport.edge_id == edge_id)
        total = (await session.execute(count_stmt)).scalar_one()

    return {"reports": [_attack_report_to_dict(r) for r in rows], "total": total}


def _attack_report_to_dict(r: AttackReport) -> dict[str, Any]:
    return {
        "id": r.id,
        "edge_id": r.edge_id,
        "tenant_id": r.tenant_id,
        "domain": r.domain,
        "attacking_ip": r.attacking_ip,
        "cidr": r.cidr,
        "asn": r.asn,
        "org": r.org,
        "attack_type": r.attack_type,
        "attempt_count": r.attempt_count,
        "usernames_targeted": json.loads(r.usernames_targeted or "[]"),
        "user_agents": json.loads(r.user_agents or "[]"),
        "attack_started_at": r.attack_started_at.isoformat() if r.attack_started_at else None,
        "attack_ended_at": r.attack_ended_at.isoformat() if r.attack_ended_at else None,
        "ip_blocked": r.ip_blocked,
        "cidr_blocked": r.cidr_blocked,
        "enum_lockdown": r.enum_lockdown,
        "notes": r.notes,
        "traceroute_hops": json.loads(r.traceroute_hops) if r.traceroute_hops else [],
        "reported_at": r.reported_at.isoformat() if r.reported_at else None,
    }


async def record_eula_acceptance(
    edge_id: str,
    eula_version: str,
    plugin_version: str = "",
    eula_hash: str = "",
    site_url: str = "",
    accepted_by_email: str = "",
    accepted_from_ip: str = "",
) -> dict[str, Any]:
    """
    Upsert a EULA acceptance record for this edge node + EULA version pair.

    Idempotent: if the same (edge_id, eula_version) already exists the call
    is a no-op and returns {"created": False}.  A new row is written only
    when the EULA version advances or when a node accepts for the first time.

    eula_hash is ALWAYS set to the server-authoritative SHA-256 of the
    canonical EULA text (from _EULA_CANONICAL), regardless of what the
    client sends.  The record therefore proves which text was in force —
    not merely which version string the client claimed.

    hash_verified in the return value indicates whether the client-supplied
    hash matched the authoritative one (useful for detecting modified UIs).
    """
    # Resolve authoritative hash from the canonical text registry
    canonical_text = _EULA_CANONICAL.get(eula_version)
    if canonical_text:
        authoritative_hash = _canonical_hash(canonical_text)
        hash_verified = (eula_hash == authoritative_hash)
    else:
        # Unknown future version — store client hash as-is, flag as unverified
        authoritative_hash = eula_hash
        hash_verified = False

    factory = get_session_factory()
    async with factory() as session:
        # Ensure the EulaVersion row exists (auto-seeds from _EULA_CANONICAL)
        if canonical_text:
            ev_result = await session.execute(
                select(EulaVersion).where(EulaVersion.version == eula_version).limit(1)
            )
            if not ev_result.scalar_one_or_none():
                session.add(EulaVersion(
                    version=eula_version,
                    text=canonical_text,
                    sha256_hash=authoritative_hash,
                    published_at=datetime.now(timezone.utc).replace(tzinfo=None),
                ))

        existing = await session.execute(
            select(EdgeEulaRecord).where(
                EdgeEulaRecord.edge_id      == edge_id,
                EdgeEulaRecord.eula_version == eula_version,
            ).limit(1)
        )
        if existing.scalar_one_or_none():
            await session.commit()
            return {"created": False, "eula_version": eula_version, "hash_verified": hash_verified}

        record = EdgeEulaRecord(
            edge_id=edge_id,
            eula_version=eula_version,
            plugin_version=plugin_version,
            eula_hash=authoritative_hash,   # always the server-authoritative hash
            site_url=site_url,
            accepted_by_email=accepted_by_email,
            accepted_from_ip=accepted_from_ip,
            accepted_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        session.add(record)
        await session.commit()

    if not hash_verified and eula_hash:
        logger.warning(
            "eula_acceptance: hash mismatch edge=%s version=%s client_hash=%s authoritative=%s",
            edge_id, eula_version, eula_hash, authoritative_hash,
        )
    logger.info(
        "eula_acceptance: edge=%s version=%s email=%s ip=%s hash_verified=%s",
        edge_id, eula_version, accepted_by_email, accepted_from_ip, hash_verified,
    )
    return {"created": True, "eula_version": eula_version, "hash_verified": hash_verified}
