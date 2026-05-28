"""
Threat Geo Service — geocodes IPs from threat_reports using ip-api.com (free, no key).
Results are cached in ip_geo_cache to avoid repeated lookups.
Batch endpoint: 100 IPs per request, ~45 req/min on free tier.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import text

from mc2.integrations.database import get_session_factory

logger = logging.getLogger(__name__)

_GEO_BATCH_URL = "http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,query"
_BATCH_SIZE = 100
_BATCH_DELAY = 1.5  # seconds between batches to stay under 45 req/min


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def _fetch_geo_batch(ips: list[str]) -> list[dict]:
    """POST up to 100 IPs to ip-api.com batch endpoint."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(_GEO_BATCH_URL, json=[{"query": ip} for ip in ips])
            if r.status_code == 200:
                return r.json()
    except Exception as exc:
        logger.warning("ip-api.com batch failed: %s", exc)
    return []


async def geocode_missing() -> int:
    """Geocode all IPs in threat_reports that are not yet in ip_geo_cache. Returns count cached."""
    factory = get_session_factory()
    async with factory() as session:
        rows = await session.execute(
            text("""
                SELECT DISTINCT t.ip FROM threat_reports t
                LEFT JOIN ip_geo_cache g ON g.ip = t.ip
                WHERE g.ip IS NULL
                LIMIT 5000
            """)
        )
        missing_ips = [r.ip for r in rows.all()]

    if not missing_ips:
        return 0

    logger.info("Geocoding %d uncached IPs from threat_reports", len(missing_ips))
    cached = 0

    for i in range(0, len(missing_ips), _BATCH_SIZE):
        batch = missing_ips[i : i + _BATCH_SIZE]
        results = await _fetch_geo_batch(batch)
        now = _utcnow()

        async with factory() as session:
            for result in results:
                ip = result.get("query", "")
                if not ip:
                    continue
                success = result.get("status") == "success"
                await session.execute(
                    text("""
                        INSERT INTO ip_geo_cache
                          (ip, country_code, country_name, city, lat, lon, cached_at, failed)
                        VALUES (:ip, :cc, :cn, :city, :lat, :lon, :ts, :fail)
                        ON DUPLICATE KEY UPDATE
                          country_code=VALUES(country_code), country_name=VALUES(country_name),
                          city=VALUES(city), lat=VALUES(lat), lon=VALUES(lon),
                          cached_at=VALUES(cached_at), failed=VALUES(failed)
                    """),
                    {
                        "ip": ip,
                        "cc":   result.get("countryCode", "") if success else "",
                        "cn":   result.get("country", "") if success else "",
                        "city": result.get("city", "") if success else "",
                        "lat":  result.get("lat", 0) if success else 0,
                        "lon":  result.get("lon", 0) if success else 0,
                        "ts":   now,
                        "fail": 0 if success else 1,
                    },
                )
                if success:
                    cached += 1
            await session.commit()

        if i + _BATCH_SIZE < len(missing_ips):
            await asyncio.sleep(_BATCH_DELAY)

    logger.info("Geocoded %d IPs successfully", cached)
    return cached


async def get_threat_overview() -> dict:
    """
    Aggregate threat data from threat_reports + attack_reports + anomaly_events + edge_nodes.
    Returns summary stats, geo-tagged points for maps, per-edge breakdown, and top attackers.
    """
    factory = get_session_factory()
    async with factory() as session:

        # ── Summary ──────────────────────────────────────────────────────────
        summary_row = (await session.execute(text("""
            SELECT
              COUNT(DISTINCT ip)        AS unique_ips,
              SUM(report_count)         AS total_events,
              COUNT(DISTINCT tenant_id) AS tenants_hit,
              COUNT(DISTINCT edge_id)   AS edges_hit,
              SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical_count,
              SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) AS high_count
            FROM threat_reports
        """))).one()

        anomaly_row = (await session.execute(text("""
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN acknowledged=0 THEN 1 ELSE 0 END) AS unacked
            FROM anomaly_events
        """))).one()

        # Active nft blocks from frothiq_ip_list
        block_row = (await session.execute(text("""
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN list_type='blacklist' THEN 1 ELSE 0 END) AS blacklisted,
              SUM(CASE WHEN list_type='whitelist' THEN 1 ELSE 0 END) AS whitelisted
            FROM frothiq_ip_list
        """))).one()

        edge_row = (await session.execute(text("""
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN state IN ('ACTIVE','ENROLLED') THEN 1 ELSE 0 END) AS active
            FROM edge_nodes
        """))).one()

        # ── Geo data (all time) ───────────────────────────────────────────────
        geo_rows = (await session.execute(text("""
            SELECT
              g.lat, g.lon, g.country_code, g.country_name,
              COUNT(DISTINCT t.ip)   AS unique_ips,
              SUM(t.report_count)    AS event_count,
              MAX(t.threat_score)    AS max_score,
              MAX(t.last_seen)       AS last_seen
            FROM threat_reports t
            JOIN ip_geo_cache g ON g.ip = t.ip AND g.failed = 0
            WHERE g.lat != 0 OR g.lon != 0
            GROUP BY g.lat, g.lon, g.country_code, g.country_name
            ORDER BY event_count DESC
            LIMIT 2000
        """))).all()

        # ── Active geo (last 24h) ─────────────────────────────────────────────
        active_geo_rows = (await session.execute(text("""
            SELECT
              g.lat, g.lon, g.country_code, g.country_name,
              COUNT(DISTINCT t.ip)   AS unique_ips,
              SUM(t.report_count)    AS event_count,
              MAX(t.threat_score)    AS max_score
            FROM threat_reports t
            JOIN ip_geo_cache g ON g.ip = t.ip AND g.failed = 0
            WHERE t.last_seen >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
              AND (g.lat != 0 OR g.lon != 0)
            GROUP BY g.lat, g.lon, g.country_code, g.country_name
            ORDER BY event_count DESC
            LIMIT 500
        """))).all()

        # ── Top countries ─────────────────────────────────────────────────────
        country_rows = (await session.execute(text("""
            SELECT
              g.country_code, g.country_name,
              COUNT(DISTINCT t.ip)  AS unique_ips,
              SUM(t.report_count)   AS events
            FROM threat_reports t
            JOIN ip_geo_cache g ON g.ip = t.ip AND g.failed = 0 AND g.country_code != ''
            GROUP BY g.country_code, g.country_name
            ORDER BY events DESC
            LIMIT 10
        """))).all()

        # ── Top attackers ────────────────────────────────────────────────────
        top_attacker_rows = (await session.execute(text("""
            SELECT t.ip, t.severity, t.event_type, t.threat_score,
                   t.report_count, t.tenant_count, t.last_seen,
                   g.country_code, g.city
            FROM threat_reports t
            LEFT JOIN ip_geo_cache g ON g.ip = t.ip AND g.failed = 0
            ORDER BY t.report_count DESC
            LIMIT 10
        """))).all()

        # ── Event type breakdown ──────────────────────────────────────────────
        type_rows = (await session.execute(text("""
            SELECT event_type, COUNT(*) AS ip_count, SUM(report_count) AS events
            FROM threat_reports
            GROUP BY event_type
            ORDER BY events DESC
        """))).all()

        # ── Per-edge breakdown ────────────────────────────────────────────────
        edge_rows = (await session.execute(text("""
            SELECT
              e.id AS edge_id, e.domain, e.state, e.protection_mode,
              e.last_heartbeat, e.tenant_id,
              COUNT(DISTINCT t.ip)  AS threat_ips,
              SUM(t.report_count)   AS events,
              MAX(t.threat_score)   AS max_score
            FROM edge_nodes e
            LEFT JOIN threat_reports t ON t.edge_id = e.id
            GROUP BY e.id, e.domain, e.state, e.protection_mode, e.last_heartbeat, e.tenant_id
            -- MariaDB doesn't support `NULLS LAST`; emulate it by sorting
            -- null rows after non-null rows, then by events DESC within each.
            ORDER BY events IS NULL, events DESC
        """))).all()

    def fmt_dt(v):
        return v.isoformat() if v and hasattr(v, "isoformat") else None

    return {
        "summary": {
            "unique_threat_ips":  int(summary_row.unique_ips or 0),
            "total_events":       int(summary_row.total_events or 0),
            "tenants_hit":        int(summary_row.tenants_hit or 0),
            "edges_hit":          int(summary_row.edges_hit or 0),
            "critical_threats":   int(summary_row.critical_count or 0),
            "high_threats":       int(summary_row.high_count or 0),
            "anomalies_total":    int(anomaly_row.total or 0),
            "anomalies_unacked":  int(anomaly_row.unacked or 0),
            "active_blocks":      int(block_row.blacklisted or 0),
            "whitelisted":        int(block_row.whitelisted or 0),
            "edge_nodes_total":   int(edge_row.total or 0),
            "edge_nodes_active":  int(edge_row.active or 0),
        },
        "geo_all": [
            {
                "lat":          float(r.lat),
                "lon":          float(r.lon),
                "country_code": r.country_code,
                "country_name": r.country_name,
                "unique_ips":   int(r.unique_ips),
                "event_count":  int(r.event_count or 0),
                "max_score":    int(r.max_score or 0),
                "last_seen":    fmt_dt(r.last_seen),
            }
            for r in geo_rows
        ],
        "geo_active": [
            {
                "lat":          float(r.lat),
                "lon":          float(r.lon),
                "country_code": r.country_code,
                "country_name": r.country_name,
                "unique_ips":   int(r.unique_ips),
                "event_count":  int(r.event_count or 0),
                "max_score":    int(r.max_score or 0),
            }
            for r in active_geo_rows
        ],
        "top_countries": [
            {
                "country_code": r.country_code,
                "country_name": r.country_name,
                "unique_ips":   int(r.unique_ips),
                "events":       int(r.events or 0),
            }
            for r in country_rows
        ],
        "top_attackers": [
            {
                "ip":           r.ip,
                "severity":     r.severity,
                "event_type":   r.event_type,
                "threat_score": int(r.threat_score or 0),
                "report_count": int(r.report_count or 0),
                "tenant_count": int(r.tenant_count or 0),
                "last_seen":    fmt_dt(r.last_seen),
                "country_code": r.country_code or "",
                "city":         r.city or "",
            }
            for r in top_attacker_rows
        ],
        "event_types": [
            {"type": r.event_type, "ip_count": int(r.ip_count), "events": int(r.events or 0)}
            for r in type_rows
        ],
        "per_edge": [
            {
                "edge_id":        r.edge_id,
                "domain":         r.domain,
                "state":          r.state,
                "protection_mode": r.protection_mode,
                "last_heartbeat": fmt_dt(r.last_heartbeat),
                "tenant_id":      r.tenant_id,
                "threat_ips":     int(r.threat_ips or 0),
                "events":         int(r.events or 0),
                "max_score":      int(r.max_score or 0),
            }
            for r in edge_rows
        ],
    }
