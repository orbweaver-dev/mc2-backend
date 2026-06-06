"""
Universe NAD API — queryable US address lookup (National Address Database r15).

NAD is ~76M point addresses — far too large for the pull-whole-dataset
/universe/v1/{slug} model. It is served from a lean read-only SQLite store
(nad_r15.db, built from the DOT/BTS NAD r15 part files) via *query* endpoints.

Consumer auth reuses the Universe X-Universe-Key scheme (virtual dataset slug
"nad"); a `nad` UniverseDataset row exists only so keys can be scoped + ETag'd.

  GET /api/v1/cc/universe/nad/lookup    structured/auto-complete address search
  GET /api/v1/cc/universe/nad/validate  resolve a full address -> canonical NAD form
  GET /api/v1/cc/universe/nad/reverse   nearest addresses to a lat/lon
  GET /api/v1/cc/universe/nad/meta      dataset version, row count, per-state counts

All results are advisory (source: US DOT/BTS NAD r15); NOT authoritative for
legal service-of-process. Consumers must surface that.
"""
from __future__ import annotations

import os
import sqlite3
from threading import Lock

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.concurrency import run_in_threadpool

from mc2.integrations.database import get_session_factory
from mc2.api.routes_universe import _authorize_consumer

router = APIRouter(prefix="/universe/nad", tags=["universe-nad"])

NAD_DB_PATH = os.environ.get("NAD_DB_PATH", "/usr/lib/mc2/backend/data/nad_r15.db")
SLUG = "nad"

_conn: sqlite3.Connection | None = None
_lock = Lock()

# columns returned to consumers (display order)
_FIELDS = ["uuid", "add_number", "addno_full", "stnam_full", "unit", "building",
           "floor", "city", "county", "state", "zip", "plus4", "lon", "lat"]


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        if not os.path.exists(NAD_DB_PATH):
            raise HTTPException(status_code=503, detail="NAD store not available")
        uri = f"file:{NAD_DB_PATH}?mode=ro&immutable=1"
        _conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
    return _conn


def _rows(sql: str, params: tuple) -> list[dict]:
    with _lock:
        cur = _db().execute(sql, params)
        out = [dict(r) for r in cur.fetchall()]
        cur.close()
    return out


def _fmt(r: dict) -> dict:
    return {k: r.get(k) for k in _FIELDS}


async def _auth(x_universe_key: str | None):
    factory = get_session_factory()
    async with factory() as session:
        await _authorize_consumer(session, x_universe_key, SLUG)


# --------------------------------------------------------------------------- #
@router.get("/meta")
async def nad_meta(x_universe_key: str | None = Header(default=None)):
    await _auth(x_universe_key)

    def work():
        c = _db()
        total = c.execute("SELECT COUNT(*) FROM address").fetchone()[0]
        states = [dict(r) for r in c.execute(
            "SELECT state, COUNT(*) n FROM address GROUP BY state ORDER BY n DESC").fetchall()]
        return {"dataset": SLUG, "source": "US DOT/BTS National Address Database r15",
                "advisory": True, "total_addresses": total, "states": states}

    return await run_in_threadpool(work)


@router.get("/lookup")
async def nad_lookup(
    x_universe_key: str | None = Header(default=None),
    state: str | None = Query(None, min_length=2, max_length=2),
    zip: str | None = Query(None, alias="zip"),
    city: str | None = None,
    county: str | None = None,
    street: str | None = Query(None, description="street name (prefix match)"),
    number: str | None = Query(None, description="house/primary number"),
    limit: int = Query(20, ge=1, le=100),
):
    """Structured + autocomplete lookup. At least one of zip/city/county/(state+street)
    is required to keep queries index-bound over 76M rows."""
    await _auth(x_universe_key)
    if not any([zip, city, county, (state and street)]):
        raise HTTPException(status_code=400,
                            detail="provide at least one of: zip, city, county, or state+street")

    where, params = [], []
    if state:
        where.append("state = ?"); params.append(state.upper())
    if zip:
        where.append("zip = ?"); params.append(zip.strip())
    if city:
        where.append("UPPER(city) = ?"); params.append(city.strip().upper())
    if county:
        where.append("UPPER(county) = ?"); params.append(county.strip().upper())
    if street:
        # NAD stores the full street name incl. pre-directional (e.g. "South MESA Street"),
        # so use a contains-match — the query is already narrowed by zip/city/county.
        where.append("UPPER(stnam_full) LIKE ?"); params.append("%" + street.strip().upper() + "%")
    if number:
        where.append("add_number = ?"); params.append(number.strip())

    sql = ("SELECT " + ",".join(_FIELDS) + " FROM address WHERE " + " AND ".join(where)
           + " ORDER BY add_number+0, stnam_full LIMIT ?")
    params.append(limit)
    rows = await run_in_threadpool(_rows, sql, tuple(params))
    return {"dataset": SLUG, "advisory": True, "count": len(rows),
            "matches": [_fmt(r) for r in rows]}


@router.get("/validate")
async def nad_validate(
    x_universe_key: str | None = Header(default=None),
    number: str = Query(..., description="house/primary number"),
    street: str = Query(..., description="full street name e.g. 'MAIN St'"),
    state: str = Query(..., min_length=2, max_length=2),
    zip: str | None = None,
    city: str | None = None,
):
    """Resolve a specific address to its canonical NAD record(s). Returns
    matched=True with the canonical form + UUID + lat/lon when found."""
    await _auth(x_universe_key)
    where = ["state = ?", "add_number = ?", "UPPER(stnam_full) = ?"]
    params = [state.upper(), number.strip(), street.strip().upper()]
    if zip:
        where.append("zip = ?"); params.append(zip.strip())
    if city:
        where.append("UPPER(city) = ?"); params.append(city.strip().upper())
    sql = "SELECT " + ",".join(_FIELDS) + " FROM address WHERE " + " AND ".join(where) + " LIMIT 10"
    rows = await run_in_threadpool(_rows, sql, tuple(params))
    return {"dataset": SLUG, "advisory": True, "matched": bool(rows),
            "count": len(rows), "matches": [_fmt(r) for r in rows]}


@router.get("/reverse")
async def nad_reverse(
    x_universe_key: str | None = Header(default=None),
    lat: float = Query(...),
    lon: float = Query(...),
    radius_m: int = Query(200, ge=10, le=5000),
    limit: int = Query(10, ge=1, le=50),
):
    """Nearest addresses to a coordinate (bounding-box prefilter + haversine sort)."""
    await _auth(x_universe_key)
    # ~deg per metre; latitude ~111320 m/deg, longitude scaled by cos(lat)
    import math
    dlat = radius_m / 111320.0
    dlon = radius_m / (111320.0 * max(0.05, math.cos(math.radians(lat))))
    sql = ("SELECT " + ",".join(_FIELDS) + " FROM address WHERE lat BETWEEN ? AND ? "
           "AND lon BETWEEN ? AND ?")
    params = (lat - dlat, lat + dlat, lon - dlon, lon + dlon)
    rows = await run_in_threadpool(_rows, sql, params)

    def dist(r):
        if r["lat"] is None or r["lon"] is None:
            return 9e9
        a = (math.radians(r["lat"] - lat)) ** 2 + math.cos(math.radians(lat)) * \
            math.cos(math.radians(r["lat"])) * (math.radians(r["lon"] - lon)) ** 2
        return 6371000 * 2 * math.asin(min(1, math.sqrt(a)))

    ranked = sorted(rows, key=dist)[:limit]
    return {"dataset": SLUG, "advisory": True, "count": len(ranked),
            "matches": [dict(_fmt(r), distance_m=round(dist(r), 1)) for r in ranked]}
