"""
Database setup — SQLAlchemy async engine + session factory.
"""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from mc2.config import get_settings
from mc2.models.user import Base
# Import all models so Base.metadata has them registered before create_all()
import mc2.models.edge     # noqa: F401
import mc2.models.billing          # noqa: F401
import mc2.models.reconciliation   # noqa: F401
import mc2.models.predictive_sync  # noqa: F401
import mc2.models.enrollment       # noqa: F401
import mc2.models.defense_settings  # noqa: F401  (also registers FrothiqCidrRecommendation)
import mc2.models.outage           # noqa: F401
import mc2.models.teleops          # noqa: F401
import mc2.models.universe         # noqa: F401  (Universe reference-data authority)

logger = logging.getLogger(__name__)

_engine = None
_session_factory = None


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


async def create_tables() -> None:
    """Create all tables if they don't exist. Idempotent (uses checkfirst=True).

    Gated behind an fcntl exclusive file lock so when uvicorn starts multiple
    workers, only one runs the migrations at a time. Without this, the workers
    race on CREATE TABLE and the loser logs "Table already exists" errors on
    every new model added.
    """
    import fcntl
    import os

    lockfile = "/run/mc2/create-tables.lock" if os.path.isdir("/run/mc2") else "/tmp/mc2-create-tables.lock"
    fd = os.open(lockfile, os.O_CREAT | os.O_WRONLY, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: Base.metadata.create_all(c, checkfirst=True))
        await _migrate_totp_columns()
        await _migrate_threat_reports()
        await _migrate_outage_ticket_column()
        await _seed_admin_ip()
        logger.info("Database tables ready")
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


async def _migrate_totp_columns() -> None:
    """Add TOTP columns to cc_users if they don't already exist (idempotent)."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.execute(
            __import__("sqlalchemy").text(
                "ALTER TABLE cc_users "
                "ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(64) NULL, "
                "ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE"
            )
        )
    logger.info("TOTP columns ensured on cc_users")


async def _migrate_threat_reports() -> None:
    """Ensure threat_reports table exists (idempotent — create_all covers it, this is belt+suspenders)."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.execute(
            __import__("sqlalchemy").text(
                "CREATE TABLE IF NOT EXISTS threat_reports ("
                "  id VARCHAR(36) PRIMARY KEY,"
                "  ip VARCHAR(45) NOT NULL,"
                "  tenant_id VARCHAR(36) NOT NULL,"
                "  edge_id VARCHAR(128) NOT NULL,"
                "  event_type VARCHAR(64) NOT NULL DEFAULT 'blocked_local',"
                "  severity VARCHAR(16) NOT NULL DEFAULT 'high',"
                "  reason VARCHAR(512) NOT NULL DEFAULT '',"
                "  report_count INT NOT NULL DEFAULT 1,"
                "  tenant_count INT NOT NULL DEFAULT 1,"
                "  threat_score INT NOT NULL DEFAULT 0,"
                "  first_seen DATETIME NOT NULL,"
                "  last_seen DATETIME NOT NULL,"
                "  UNIQUE KEY uq_threat_ip_tenant (ip, tenant_id),"
                "  INDEX idx_threat_ip (ip),"
                "  INDEX idx_threat_tenant (tenant_id),"
                "  INDEX idx_threat_score (threat_score)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )
        )
    logger.info("threat_reports table ensured")


async def _migrate_outage_ticket_column() -> None:
    """Add frappe_ticket_id column to edge_outage_events if missing (idempotent)."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.execute(
            __import__("sqlalchemy").text(
                "ALTER TABLE edge_outage_events "
                "ADD COLUMN IF NOT EXISTS frappe_ticket_id VARCHAR(64) NULL"
            )
        )
    logger.info("frappe_ticket_id column ensured on edge_outage_events")


async def _seed_admin_ip() -> None:
    """Seed the bootstrap admin IP from CC_ADMIN_IP_SEED env var (idempotent)."""
    import os
    seed_ip = os.environ.get("CC_ADMIN_IP_SEED", "").strip()
    if not seed_ip:
        return
    import uuid as _uuid
    from datetime import datetime
    from sqlalchemy import select, text
    from mc2.models.enrollment import IPAllowlist

    engine = get_engine()
    async with async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)() as session:
        existing = await session.execute(select(IPAllowlist).where(IPAllowlist.ip == seed_ip))
        if existing.scalar_one_or_none() is None:
            session.add(IPAllowlist(
                id=str(_uuid.uuid4()),
                ip=seed_ip,
                user_email="admin@bootstrap",
                approved_at=datetime.utcnow(),
                notes="Bootstrap seed from CC_ADMIN_IP_SEED",
            ))
            await session.commit()
            logger.info("Seeded bootstrap admin IP: %s", seed_ip)


async def dispose_engine() -> None:
    engine = get_engine()
    await engine.dispose()
    logger.info("Database engine disposed")
