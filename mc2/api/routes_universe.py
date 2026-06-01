"""
Universe API — OrbWeaver shared reference-data authority.

Operator endpoints (JWT, under /api/v1/cc/universe/...):
  GET    /datasets                         list datasets (read_only)
  POST   /datasets                         create/update a dataset (super_admin)
  GET    /datasets/{slug}/records          list records in a dataset (read_only)
  PUT    /datasets/{slug}/records          bulk upsert records (super_admin)
  DELETE /datasets/{slug}/records/{key}    delete a record (super_admin)
  GET    /consumer-keys                    list issued keys (super_admin)
  POST   /consumer-keys                    issue a key — full key returned ONCE (super_admin)
  POST   /consumer-keys/{id}/revoke        revoke a key (super_admin)

Consumer endpoint (X-Universe-Key header, machine-to-machine):
  GET    /v1/{slug}                        fetch a dataset's active records (+ ETag = version)
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import delete, func, select

from mc2.auth import TokenPayload, require_read_only, require_super_admin
from mc2.integrations.database import get_session_factory
from mc2.models.universe import UniverseConsumerKey, UniverseDataset, UniverseRecord

router = APIRouter(prefix="/universe", tags=["universe"])


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _hash_key(full: str) -> str:
    return hashlib.sha256(full.encode()).hexdigest()


def _new_key() -> tuple[str, str, str]:
    """Returns (full_key, prefix, hash). Full key shown to the operator once."""
    full = "uvk_" + secrets.token_urlsafe(32)
    return full, full[:12], _hash_key(full)


def _now() -> datetime:
    return datetime.utcnow()


async def _bump_dataset_version(session, slug: str) -> int:
    ds = (await session.execute(select(UniverseDataset).where(UniverseDataset.slug == slug))).scalar_one_or_none()
    if ds is None:
        raise HTTPException(status_code=404, detail=f"Dataset '{slug}' not found")
    ds.version = (ds.version or 1) + 1
    ds.updated_at = _now()
    return ds.version


# --------------------------------------------------------------------------- #
# request models
# --------------------------------------------------------------------------- #
class DatasetIn(BaseModel):
    slug: str
    title: str
    description: str | None = None
    is_active: bool = True


class RecordIn(BaseModel):
    record_key: str
    data: dict
    is_active: bool = True


class RecordsBulkIn(BaseModel):
    records: list[RecordIn]
    replace: bool = False  # if true, deactivate records not present in this payload


class ConsumerKeyIn(BaseModel):
    consumer_name: str
    datasets: list[str] | None = None  # None/[] = all datasets


# --------------------------------------------------------------------------- #
# operator: datasets
# --------------------------------------------------------------------------- #
@router.get("/datasets")
async def list_datasets(_: TokenPayload = Depends(require_read_only)):
    factory = get_session_factory()
    async with factory() as session:
        rows = (await session.execute(select(UniverseDataset).order_by(UniverseDataset.slug))).scalars().all()
        out = []
        for d in rows:
            count = (await session.execute(
                select(func.count()).select_from(UniverseRecord).where(
                    UniverseRecord.dataset == d.slug, UniverseRecord.is_active == True))).scalar() or 0
            out.append({
                "slug": d.slug, "title": d.title, "description": d.description,
                "version": d.version, "is_active": d.is_active, "record_count": count,
                "updated_at": d.updated_at.isoformat() if d.updated_at else None,
            })
        return {"datasets": out}


@router.post("/datasets")
async def upsert_dataset(payload: DatasetIn, _: TokenPayload = Depends(require_super_admin)):
    factory = get_session_factory()
    async with factory() as session:
        ds = (await session.execute(select(UniverseDataset).where(UniverseDataset.slug == payload.slug))).scalar_one_or_none()
        if ds is None:
            ds = UniverseDataset(slug=payload.slug, title=payload.title,
                                 description=payload.description, is_active=payload.is_active, version=1)
            session.add(ds)
        else:
            ds.title = payload.title
            ds.description = payload.description
            ds.is_active = payload.is_active
            ds.updated_at = _now()
        await session.commit()
        return {"ok": True, "slug": payload.slug}


# --------------------------------------------------------------------------- #
# operator: records
# --------------------------------------------------------------------------- #
@router.get("/datasets/{slug}/records")
async def list_records(slug: str, limit: int = 500, offset: int = 0,
                       _: TokenPayload = Depends(require_read_only)):
    factory = get_session_factory()
    async with factory() as session:
        rows = (await session.execute(
            select(UniverseRecord).where(UniverseRecord.dataset == slug)
            .order_by(UniverseRecord.record_key).limit(limit).offset(offset))).scalars().all()
        return {"dataset": slug, "records": [
            {"record_key": r.record_key, "data": json.loads(r.data or "{}"),
             "is_active": r.is_active, "version": r.version} for r in rows]}


@router.put("/datasets/{slug}/records")
async def upsert_records(slug: str, payload: RecordsBulkIn, _: TokenPayload = Depends(require_super_admin)):
    factory = get_session_factory()
    async with factory() as session:
        ds = (await session.execute(select(UniverseDataset).where(UniverseDataset.slug == slug))).scalar_one_or_none()
        if ds is None:
            raise HTTPException(status_code=404, detail=f"Dataset '{slug}' not found")
        incoming_keys = set()
        for rec in payload.records:
            incoming_keys.add(rec.record_key)
            row = (await session.execute(select(UniverseRecord).where(
                UniverseRecord.dataset == slug, UniverseRecord.record_key == rec.record_key))).scalar_one_or_none()
            blob = json.dumps(rec.data, sort_keys=True, default=str)
            if row is None:
                session.add(UniverseRecord(dataset=slug, record_key=rec.record_key, data=blob,
                                           is_active=rec.is_active, version=1))
            else:
                row.data = blob
                row.is_active = rec.is_active
                row.version = (row.version or 1) + 1
                row.updated_at = _now()
        if payload.replace:
            existing = (await session.execute(select(UniverseRecord).where(UniverseRecord.dataset == slug))).scalars().all()
            for row in existing:
                if row.record_key not in incoming_keys and row.is_active:
                    row.is_active = False
                    row.updated_at = _now()
        new_version = await _bump_dataset_version(session, slug)
        await session.commit()
        return {"ok": True, "dataset": slug, "version": new_version, "written": len(payload.records)}


@router.delete("/datasets/{slug}/records/{record_key}")
async def delete_record(slug: str, record_key: str, _: TokenPayload = Depends(require_super_admin)):
    factory = get_session_factory()
    async with factory() as session:
        await session.execute(delete(UniverseRecord).where(
            UniverseRecord.dataset == slug, UniverseRecord.record_key == record_key))
        await _bump_dataset_version(session, slug)
        await session.commit()
        return {"ok": True}


# --------------------------------------------------------------------------- #
# operator: consumer keys
# --------------------------------------------------------------------------- #
@router.get("/consumer-keys")
async def list_keys(_: TokenPayload = Depends(require_super_admin)):
    factory = get_session_factory()
    async with factory() as session:
        rows = (await session.execute(select(UniverseConsumerKey).order_by(UniverseConsumerKey.created_at.desc()))).scalars().all()
        return {"keys": [{
            "id": k.id, "key_prefix": k.key_prefix, "consumer_name": k.consumer_name,
            "datasets": json.loads(k.datasets) if k.datasets else None,
            "is_active": k.is_active,
            "created_at": k.created_at.isoformat() if k.created_at else None,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
        } for k in rows]}


@router.post("/consumer-keys")
async def issue_key(payload: ConsumerKeyIn, _: TokenPayload = Depends(require_super_admin)):
    full, prefix, key_hash = _new_key()
    factory = get_session_factory()
    async with factory() as session:
        session.add(UniverseConsumerKey(
            key_prefix=prefix, key_hash=key_hash, consumer_name=payload.consumer_name,
            datasets=json.dumps(payload.datasets) if payload.datasets else None, is_active=True))
        await session.commit()
    # full key returned ONCE — never retrievable again
    return {"ok": True, "api_key": full, "key_prefix": prefix,
            "consumer_name": payload.consumer_name, "datasets": payload.datasets}


@router.post("/consumer-keys/{key_id}/revoke")
async def revoke_key(key_id: str, _: TokenPayload = Depends(require_super_admin)):
    factory = get_session_factory()
    async with factory() as session:
        k = await session.get(UniverseConsumerKey, key_id)
        if k is None:
            raise HTTPException(status_code=404, detail="Key not found")
        k.is_active = False
        await session.commit()
        return {"ok": True}


# --------------------------------------------------------------------------- #
# consumer: read API (X-Universe-Key)
# --------------------------------------------------------------------------- #
async def _authorize_consumer(session, x_universe_key: str | None, slug: str) -> UniverseConsumerKey:
    if not x_universe_key:
        raise HTTPException(status_code=401, detail="Missing X-Universe-Key header")
    prefix = x_universe_key[:12]
    key_hash = _hash_key(x_universe_key)
    k = (await session.execute(select(UniverseConsumerKey).where(
        UniverseConsumerKey.key_prefix == prefix, UniverseConsumerKey.is_active == True))).scalars().all()
    match = next((row for row in k if row.key_hash == key_hash), None)
    if match is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    if match.datasets:
        allowed = json.loads(match.datasets)
        if allowed and slug not in allowed:
            raise HTTPException(status_code=403, detail=f"Key not scoped for dataset '{slug}'")
    return match


@router.get("/v1/{slug}")
async def consumer_get_dataset(slug: str, response: Response, request: Request,
                               x_universe_key: str | None = Header(default=None),
                               if_none_match: str | None = Header(default=None)):
    factory = get_session_factory()
    async with factory() as session:
        match = await _authorize_consumer(session, x_universe_key, slug)
        ds = (await session.execute(select(UniverseDataset).where(
            UniverseDataset.slug == slug, UniverseDataset.is_active == True))).scalar_one_or_none()
        if ds is None:
            raise HTTPException(status_code=404, detail=f"Dataset '{slug}' not found")
        etag = f'"{slug}.v{ds.version}"'
        # touch last_used (best-effort)
        match.last_used_at = _now()
        await session.commit()
        response.headers["ETag"] = etag
        response.headers["Cache-Control"] = "private, max-age=300"
        if if_none_match and if_none_match == etag:
            response.status_code = status.HTTP_304_NOT_MODIFIED
            return Response(status_code=304)
        rows = (await session.execute(select(UniverseRecord).where(
            UniverseRecord.dataset == slug, UniverseRecord.is_active == True)
            .order_by(UniverseRecord.record_key))).scalars().all()
        return {
            "dataset": slug, "version": ds.version, "title": ds.title,
            "records": [{"key": r.record_key, "data": json.loads(r.data or "{}")} for r in rows],
        }
