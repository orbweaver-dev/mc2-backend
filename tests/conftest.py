"""
Pytest configuration and shared fixtures for OrbWeaver MC² tests.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from mc2.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
)


# ---------------------------------------------------------------------------
# Event loop
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Database schema
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(autouse=True)
async def _database_schema():
    """Create the tables in the test database before each test.

    The `app` fixture wires a MOCK session factory into DBSessionMiddleware,
    but the service layer does not use it: license_service and the other
    edge-table services call get_session_factory() from mc2.integrations
    directly, which builds a real engine against CC_DATABASE_URL. With no
    schema behind it every one of those endpoints failed with
    "no such table: edge_tenants" — which read like an API bug and was really
    an empty database.

    create_all is idempotent, so running per test is cheap and keeps tests from
    inheriting rows another test wrote.
    """
    import os

    os.environ.setdefault("CC_SECRET_KEY", "test-secret-key-minimum-32-chars-long-yes")
    os.environ.setdefault("CC_DATABASE_URL", "sqlite+aiosqlite:///./test.db")

    from mc2.integrations.database import get_engine
    from mc2.models.user import Base
    import mc2.integrations.database  # noqa: F401  — registers every model on Base

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


# ---------------------------------------------------------------------------
# Mock frothiq-core client
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_core_client():
    """Mock CoreClient so tests don't need a live frothiq-core.

    Patches the METHODS of the shared singleton rather than rebinding the name
    in mc2.services.core_client.

    Every service does `from .core_client import core_client` at import time,
    which copies the object into its own module namespace. Replacing the
    attribute on the core_client module therefore reached none of them: they
    kept calling the real client, which raises "CoreClient not started"
    because nothing ran its startup() outside the app lifespan. Patching the
    object itself reaches every holder of the reference — the module-level
    importers and the ones that import it inside a function alike.
    """
    # NOT `from mc2.services import core_client` — mc2/services/__init__.py
    # re-exports the singleton under that name, so the package attribute is the
    # INSTANCE and shadows the submodule of the same name.
    from mc2.services.core_client import core_client as real
    with patch.object(real, "get", new=AsyncMock(return_value={})), \
         patch.object(real, "post", new=AsyncMock(return_value={})), \
         patch.object(real, "health_check",
                      new=AsyncMock(return_value={"status": "online", "version": "0.6.0"})), \
         patch.object(real, "is_healthy", new=MagicMock(return_value=True)):
        yield real


# ---------------------------------------------------------------------------
# Mock database
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    """Mock async database session."""
    db = AsyncMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.close = AsyncMock()
    db.add = MagicMock()
    db.refresh = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# Mock Redis
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock()
    redis.xadd = AsyncMock()
    redis.publish = AsyncMock()
    return redis


# ---------------------------------------------------------------------------
# Auth tokens for different roles
# ---------------------------------------------------------------------------

@pytest.fixture
def super_admin_token():
    return create_access_token("user-super-admin", "super_admin")


@pytest.fixture
def security_analyst_token():
    return create_access_token("user-security", "security_analyst")


@pytest.fixture
def billing_admin_token():
    return create_access_token("user-billing", "billing_admin")


@pytest.fixture
def read_only_token():
    return create_access_token("user-readonly", "read_only")


@pytest.fixture
def super_admin_headers(super_admin_token):
    return {"Authorization": f"Bearer {super_admin_token}"}


@pytest.fixture
def security_analyst_headers(security_analyst_token):
    return {"Authorization": f"Bearer {security_analyst_token}"}


@pytest.fixture
def billing_admin_headers(billing_admin_token):
    return {"Authorization": f"Bearer {billing_admin_token}"}


@pytest.fixture
def read_only_headers(read_only_token):
    return {"Authorization": f"Bearer {read_only_token}"}


# ---------------------------------------------------------------------------
# FastAPI test app
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_session_factory(mock_db):
    """Return a session factory that yields the mock db."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _factory():
        yield mock_db

    return _factory


@pytest.fixture
def app(mock_db, mock_redis, mock_session_factory):
    """Create a test FastAPI app with mocked dependencies."""
    import os
    os.environ.setdefault("CC_SECRET_KEY", "test-secret-key-minimum-32-chars-long-yes")
    os.environ.setdefault("CC_DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    os.environ.setdefault("CC_REDIS_URL", "redis://localhost:6379/15")
    os.environ.setdefault("CC_ENVIRONMENT", "development")
    os.environ.setdefault("CC_CORE_SERVICE_API_KEY", "test-service-key")

    from mc2.config.settings import get_settings
    get_settings.cache_clear()

    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from mc2.api import api_router
    from mc2.middleware import DBSessionMiddleware, IPAllowlistMiddleware
    from mc2.websocket import ws_router

    test_app = FastAPI()
    test_app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    test_app.add_middleware(IPAllowlistMiddleware)
    test_app.add_middleware(DBSessionMiddleware, session_factory=mock_session_factory, redis_client=mock_redis)
    test_app.include_router(api_router)
    test_app.include_router(ws_router)

    @test_app.get("/health")
    async def health():
        return {"status": "ok"}

    return test_app


@pytest_asyncio.fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP test client."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Sample data fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_cluster():
    return {
        "cluster_id": "cluster-abc123",
        "campaign_ids": ["camp-1", "camp-2", "camp-3"],
        "severity": "high",
        "action": "block_asn",
        "auto_apply_eligible": True,
        "campaign_count": 3,
        "tenant_hit_count": 5,
        "first_seen": "2024-01-01T00:00:00Z",
        "last_seen": "2024-01-15T12:00:00Z",
    }


@pytest.fixture
def sample_tenant():
    return {
        "tenant_id": "tenant-001",
        "plan": "pro",
        "rate_limit_rpm": 600,
        "max_sites": 10,
        "active_sites": 7,
        "block_score": 80,
        "features": {
            "defense_mesh": True,
            "policy_mesh": True,
            "simulation_engine": False,
        },
        "last_sync": "2024-01-15T10:00:00Z",
    }


@pytest.fixture
def sample_policy():
    return {
        "policy_id": "policy-xyz",
        "name": "Block High-Risk IPs",
        "version": 3,
        "status": "active",
        "tenant_count": 12,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-10T08:00:00Z",
    }


@pytest.fixture
def sample_envelope():
    return {
        "version": "v1.2.3",
        "signature": "sha256:abcdef1234567890",
        "sections": {
            "rules": {"block_score": 80, "threshold": 100},
            "features": {"defense_mesh": True},
            "license": {"plan": "pro", "expires": "2025-01-01"},
        },
    }
