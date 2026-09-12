"""
Tests for authentication and RBAC enforcement.
Covers JWT issuance, role hierarchy, endpoint access control.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from jose import jwt

from mc2.auth.jwt_handler import (
    ROLE_LEVEL,
    Role,
    create_access_token,
    create_refresh_token,
    decode_token,
    role_at_least,
)
from mc2.auth.password import hash_password, verify_password
from mc2.config import get_settings


# ---------------------------------------------------------------------------
# JWT handler unit tests
# ---------------------------------------------------------------------------

class TestJWTHandler:
    def test_create_access_token_returns_string(self):
        token = create_access_token("user-1", "super_admin")
        assert isinstance(token, str)
        assert len(token) > 0

    def test_decode_access_token(self):
        token = create_access_token("user-1", "security_analyst")
        payload = decode_token(token)
        assert payload.sub == "user-1"
        assert payload.role == "security_analyst"
        assert payload.type == "access"

    def test_decode_refresh_token(self):
        token = create_refresh_token("user-1", "super_admin")
        payload = decode_token(token)
        assert payload.sub == "user-1"
        assert payload.role == "super_admin"
        assert payload.type == "refresh"

    def test_expired_token_raises(self):
        from jose import JWTError
        settings = get_settings()
        past = datetime.now(UTC) - timedelta(hours=2)
        payload = {
            "sub": "user-1",
            "role": "read_only",
            "type": "access",
            "iat": past,
            "exp": past + timedelta(minutes=1),  # already expired
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
        with pytest.raises(JWTError):
            decode_token(token)

    def test_invalid_token_raises(self):
        from jose import JWTError
        with pytest.raises(JWTError):
            decode_token("not.a.valid.jwt")

    def test_tampered_token_raises(self):
        from jose import JWTError
        token = create_access_token("user-1", "read_only")
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(JWTError):
            decode_token(tampered)

    def test_access_token_expiry_is_correct(self):
        settings = get_settings()
        token = create_access_token("user-1", "super_admin")
        payload = decode_token(token)
        expected_exp = payload.iat + timedelta(minutes=settings.access_token_expire_minutes)
        # Allow 2 second tolerance
        assert abs((payload.exp - expected_exp).total_seconds()) < 2


# ---------------------------------------------------------------------------
# Role hierarchy tests
# ---------------------------------------------------------------------------

class TestRoleHierarchy:
    def test_super_admin_above_all(self):
        assert role_at_least("super_admin", "super_admin")
        assert role_at_least("super_admin", "security_analyst")
        assert role_at_least("super_admin", "billing_admin")
        assert role_at_least("super_admin", "read_only")

    def test_security_analyst_hierarchy(self):
        assert role_at_least("security_analyst", "security_analyst")
        assert role_at_least("security_analyst", "billing_admin")
        assert role_at_least("security_analyst", "read_only")
        assert not role_at_least("security_analyst", "super_admin")

    def test_billing_admin_hierarchy(self):
        assert role_at_least("billing_admin", "billing_admin")
        assert role_at_least("billing_admin", "read_only")
        assert not role_at_least("billing_admin", "security_analyst")
        assert not role_at_least("billing_admin", "super_admin")

    def test_read_only_lowest(self):
        assert role_at_least("read_only", "read_only")
        assert not role_at_least("read_only", "billing_admin")
        assert not role_at_least("read_only", "security_analyst")
        assert not role_at_least("read_only", "super_admin")

    def test_role_levels_are_ordered(self):
        assert ROLE_LEVEL["super_admin"] > ROLE_LEVEL["security_analyst"]
        assert ROLE_LEVEL["security_analyst"] > ROLE_LEVEL["billing_admin"]
        assert ROLE_LEVEL["billing_admin"] > ROLE_LEVEL["read_only"]

    def test_unknown_role_cannot_access_anything(self):
        assert not role_at_least("hacker", "read_only")
        assert not role_at_least("", "read_only")


# ---------------------------------------------------------------------------
# Password utilities
# ---------------------------------------------------------------------------

class TestPasswordUtils:
    def test_hash_is_not_plaintext(self):
        plain = "securepassword123!"
        hashed = hash_password(plain)
        assert hashed != plain
        assert len(hashed) > 20

    def test_verify_correct_password(self):
        plain = "mypassword!Secure99"
        hashed = hash_password(plain)
        assert verify_password(plain, hashed) is True

    def test_verify_wrong_password(self):
        plain = "mypassword!Secure99"
        hashed = hash_password(plain)
        assert verify_password("wrongpassword", hashed) is False

    def test_two_hashes_of_same_password_differ(self):
        plain = "samepassword"
        h1 = hash_password(plain)
        h2 = hash_password(plain)
        assert h1 != h2  # bcrypt uses random salt
        # But both verify correctly
        assert verify_password(plain, h1)
        assert verify_password(plain, h2)


# ---------------------------------------------------------------------------
# RBAC endpoint enforcement (integration-style via HTTP client)
# ---------------------------------------------------------------------------

class TestRBACEndpoints:
    """
    Test that endpoints correctly enforce role requirements.
    We use the mock app from conftest.py.
    """

    @pytest.mark.asyncio
    async def test_unauthenticated_request_rejected(self, client):
        resp = await client.get("/api/v1/cc/dashboard/health")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_read_only_can_access_dashboard(self, client, read_only_headers, mock_core_client):
        mock_core_client.health_check.return_value = {"status": "online"}
        mock_core_client.get.return_value = {"clusters": [], "total": 0, "tenants": []}
        resp = await client.get("/api/v1/cc/dashboard/health", headers=read_only_headers)
        # May return 200 or 502 depending on mock state; just not 401/403
        assert resp.status_code != 401
        assert resp.status_code != 403

    @pytest.mark.asyncio
    async def test_read_only_cannot_revoke_license(self, client, read_only_headers):
        resp = await client.post(
            "/api/v1/cc/license/tenant-001/revoke",
            headers=read_only_headers,
            json={"reason": "test"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_billing_admin_cannot_revoke_license(self, client, billing_admin_headers):
        resp = await client.post(
            "/api/v1/cc/license/tenant-001/revoke",
            headers=billing_admin_headers,
            json={"reason": "test"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_super_admin_can_revoke_license(self, client, super_admin_headers, mock_core_client):
        mock_core_client.post.return_value = {"success": True, "tenant_id": "tenant-001"}
        resp = await client.post(
            "/api/v1/cc/license/tenant-001/revoke",
            headers=super_admin_headers,
            json={"reason": "Non-payment"},
        )
        assert resp.status_code in (200, 502)  # 502 = core returned error in mock

    @pytest.mark.asyncio
    async def test_security_analyst_can_run_simulation(self, client, security_analyst_headers, mock_core_client):
        mock_core_client.post.return_value = {
            "sim_id": "sim-123",
            "status": "started",
            "started_at": "2024-01-01T00:00:00Z",
        }
        resp = await client.post(
            "/api/v1/cc/simulation/run",
            headers=security_analyst_headers,
            json={"scenario_id": "replay_sqli", "parameters": {}},
        )
        assert resp.status_code != 403

    @pytest.mark.asyncio
    async def test_read_only_cannot_run_simulation(self, client, read_only_headers):
        resp = await client.post(
            "/api/v1/cc/simulation/run",
            headers=read_only_headers,
            json={"scenario_id": "replay_sqli", "parameters": {}},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_billing_admin_can_access_monetization(self, client, billing_admin_headers, mock_core_client):
        mock_core_client.get.return_value = {"tenants": []}
        resp = await client.get("/api/v1/cc/monetization/overview", headers=billing_admin_headers)
        assert resp.status_code != 403

    @pytest.mark.asyncio
    async def test_read_only_cannot_access_monetization(self, client, read_only_headers):
        resp = await client.get("/api/v1/cc/monetization/overview", headers=read_only_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_super_admin_can_create_user(self, client, super_admin_headers, mock_db):
        from unittest.mock import AsyncMock, MagicMock
        from sqlalchemy.engine import Result

        # Mock: no existing user found
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = result_mock

        # The handler relies on db.refresh() to populate what the database
        # fills in — id, is_active, totp_enabled, created_at. On an AsyncMock
        # refresh does nothing, so those stayed None and UserResponse refused
        # to serialise the reply. Give the mock the one behaviour the handler
        # actually depends on.
        import uuid as _uuid
        from datetime import UTC as _UTC, datetime as _dt

        async def _refresh(obj, *_a, **_k):
            if getattr(obj, "id", None) is None:
                obj.id = str(_uuid.uuid4())
            if getattr(obj, "is_active", None) is None:
                obj.is_active = True
            if getattr(obj, "totp_enabled", None) is None:
                obj.totp_enabled = False
            if getattr(obj, "created_at", None) is None:
                obj.created_at = _dt.now(_UTC)

        mock_db.refresh = AsyncMock(side_effect=_refresh)

        resp = await client.post(
            "/api/v1/cc/auth/users",
            headers=super_admin_headers,
            json={
                "email": "newadmin@test.com",
                "password": "SecurePassword123!",
                "full_name": "New Admin",
                "role": "security_analyst",
            },
        )
        # 201 or 422 (validation); not 403
        assert resp.status_code != 403

    @pytest.mark.asyncio
    async def test_read_only_cannot_create_user(self, client, read_only_headers):
        resp = await client.post(
            "/api/v1/cc/auth/users",
            headers=read_only_headers,
            json={
                "email": "test@test.com",
                "password": "SecurePassword123!",
                "full_name": "Test",
                "role": "read_only",
            },
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_refresh_token_cannot_access_api(self, client):
        refresh_token = create_refresh_token("user-1", "super_admin")
        resp = await client.get(
            "/api/v1/cc/dashboard/health",
            headers={"Authorization": f"Bearer {refresh_token}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_malformed_bearer_rejected(self, client):
        resp = await client.get(
            "/api/v1/cc/dashboard/health",
            headers={"Authorization": "Bearer not-a-jwt"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_security_analyst_can_rollback_policy(self, client, security_analyst_headers, mock_core_client):
        mock_core_client.post.return_value = {"success": True}
        resp = await client.post(
            "/api/v1/cc/policy/policy-xyz/rollback",
            headers=security_analyst_headers,
            json={"version": 2},
        )
        assert resp.status_code != 403

    @pytest.mark.asyncio
    async def test_read_only_cannot_rollback_policy(self, client, read_only_headers):
        resp = await client.post(
            "/api/v1/cc/policy/policy-xyz/rollback",
            headers=read_only_headers,
            json={"version": 2},
        )
        assert resp.status_code == 403
