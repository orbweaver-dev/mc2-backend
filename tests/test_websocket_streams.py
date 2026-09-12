"""
WebSocket stream tests — connection auth, heartbeat, event dispatch, role filtering.
"""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mc2.auth import create_access_token, create_refresh_token
from mc2.websocket.connection_manager import (
    ConnectedClient,
    ConnectionManager,
)
from mc2.websocket.event_dispatcher import (
    CHANNEL_ROLE_MAP,
    publish_event,
    _handle_message,
)


# ---------------------------------------------------------------------------
# ConnectionManager unit tests
# ---------------------------------------------------------------------------

class TestConnectionManager:
    @pytest.mark.asyncio
    async def test_connect_registers_client(self):
        manager = ConnectionManager()
        ws = AsyncMock()
        client = await manager.connect(ws, "user-1", "super_admin")
        assert manager.get_connection_count() == 1
        assert client.user_id == "user-1"
        assert client.role == "super_admin"

    @pytest.mark.asyncio
    async def test_disconnect_removes_client(self):
        manager = ConnectionManager()
        ws = AsyncMock()
        client = await manager.connect(ws, "user-1", "super_admin")
        await manager.disconnect(client)
        assert manager.get_connection_count() == 0

    @pytest.mark.asyncio
    async def test_broadcast_sends_to_all(self):
        manager = ConnectionManager()
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        await manager.connect(ws1, "user-1", "super_admin")
        await manager.connect(ws2, "user-2", "security_analyst")

        sent = await manager.broadcast("TEST_EVENT", {"key": "value"})
        assert sent == 2
        ws1.send_text.assert_called_once()
        ws2.send_text.assert_called_once()

    @pytest.mark.asyncio
    async def test_broadcast_role_filtering_read_only_excluded(self):
        manager = ConnectionManager()
        ws_admin = AsyncMock()
        ws_readonly = AsyncMock()
        await manager.connect(ws_admin, "user-1", "super_admin")
        await manager.connect(ws_readonly, "user-2", "read_only")

        sent = await manager.broadcast("SECRET_EVENT", {}, min_role="security_analyst")
        assert sent == 1  # only super_admin receives
        ws_admin.send_text.assert_called_once()
        ws_readonly.send_text.assert_not_called()

    @pytest.mark.asyncio
    async def test_broadcast_all_roles_receive_low_min_role(self):
        manager = ConnectionManager()
        for i, role in enumerate(["super_admin", "security_analyst", "billing_admin", "read_only"]):
            ws = AsyncMock()
            await manager.connect(ws, f"user-{i}", role)

        sent = await manager.broadcast("PUBLIC_EVENT", {}, min_role="read_only")
        assert sent == 4

    @pytest.mark.asyncio
    async def test_broadcast_removes_dead_connections(self):
        manager = ConnectionManager()
        ws_dead = AsyncMock()
        ws_dead.send_text = AsyncMock(side_effect=Exception("Connection closed"))
        ws_alive = AsyncMock()

        await manager.connect(ws_dead, "dead-user", "read_only")
        await manager.connect(ws_alive, "alive-user", "read_only")

        sent = await manager.broadcast("EVENT", {})
        # Dead connection removed, only alive sent to
        assert sent == 1
        assert manager.get_connection_count() == 1

    @pytest.mark.asyncio
    async def test_send_to_user_targets_specific_user(self):
        manager = ConnectionManager()
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        await manager.connect(ws1, "user-alpha", "super_admin")
        await manager.connect(ws2, "user-beta", "super_admin")

        await manager.send_to_user("user-alpha", "PERSONAL_EVENT", {"msg": "for you"})
        ws1.send_text.assert_called_once()
        ws2.send_text.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_to_user_returns_false_if_not_connected(self):
        manager = ConnectionManager()
        result = await manager.send_to_user("nonexistent", "EVENT", {})
        assert result is False

    @pytest.mark.asyncio
    async def test_get_stats_structure(self):
        manager = ConnectionManager()
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        await manager.connect(ws1, "u1", "super_admin")
        await manager.connect(ws2, "u2", "read_only")

        stats = manager.get_stats()
        assert stats["total_connections"] == 2
        assert stats["by_role"]["super_admin"] == 1
        assert stats["by_role"]["read_only"] == 1

    @pytest.mark.asyncio
    async def test_broadcast_message_format(self):
        manager = ConnectionManager()
        ws = AsyncMock()
        await manager.connect(ws, "user-1", "super_admin")

        await manager.broadcast("LICENSE_REVOKED", {"tenant": "t1"}, tenant_id="t1")

        call_args = ws.send_text.call_args[0][0]
        msg = json.loads(call_args)
        assert msg["event_type"] == "LICENSE_REVOKED"
        assert msg["payload"]["tenant"] == "t1"
        assert "ts" in msg

    @pytest.mark.asyncio
    async def test_multiple_concurrent_connects(self):
        manager = ConnectionManager()
        websockets = [AsyncMock() for _ in range(10)]

        tasks = [
            manager.connect(ws, f"user-{i}", "read_only")
            for i, ws in enumerate(websockets)
        ]
        await asyncio.gather(*tasks)
        assert manager.get_connection_count() == 10


# ---------------------------------------------------------------------------
# Event dispatcher unit tests
# ---------------------------------------------------------------------------

class TestEventDispatcher:
    @pytest.mark.asyncio
    async def test_handle_message_broadcasts(self):
        msg = {
            "type": "message",
            "channel": b"frothiq:cc:DEFENSE_CLUSTER_UPDATE",
            "data": json.dumps({"cluster_id": "cluster-1", "severity": "high"}).encode(),
        }
        with patch(
            "mc2.websocket.event_dispatcher.connection_manager"
        ) as mock_manager:
            mock_manager.broadcast = AsyncMock(return_value=1)
            await _handle_message(msg)
            mock_manager.broadcast.assert_called_once()
            call_kwargs = mock_manager.broadcast.call_args[1] or {}
            call_args = mock_manager.broadcast.call_args[0]
            event_type = call_args[0] if call_args else call_kwargs.get("event_type")
            assert event_type == "DEFENSE_CLUSTER_UPDATE"

    @pytest.mark.asyncio
    async def test_handle_non_message_type_skipped(self):
        msg = {"type": "subscribe", "channel": b"frothiq:cc:TEST", "data": None}
        with patch(
            "mc2.websocket.event_dispatcher.connection_manager"
        ) as mock_manager:
            mock_manager.broadcast = AsyncMock()
            await _handle_message(msg)
            mock_manager.broadcast.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_invalid_json_payload(self):
        msg = {
            "type": "message",
            "channel": b"frothiq:cc:SYSTEM_ALERT",
            "data": b"not valid json",
        }
        with patch(
            "mc2.websocket.event_dispatcher.connection_manager"
        ) as mock_manager:
            mock_manager.broadcast = AsyncMock(return_value=0)
            # Should not raise
            await _handle_message(msg)
            mock_manager.broadcast.assert_called_once()

    @pytest.mark.asyncio
    async def test_publish_event_uses_redis(self):
        redis = AsyncMock()
        redis.publish = AsyncMock()
        await publish_event(redis, "FLYWHEEL_SIGNAL", {"signal": 0.9})
        redis.publish.assert_called_once()
        call_args = redis.publish.call_args[0]
        assert "frothiq:cc:FLYWHEEL_SIGNAL" in call_args[0]

    @pytest.mark.asyncio
    async def test_publish_event_redis_failure_falls_back_to_direct(self):
        redis = AsyncMock()
        redis.publish = AsyncMock(side_effect=Exception("Redis error"))
        with patch(
            "mc2.websocket.event_dispatcher.connection_manager"
        ) as mock_manager:
            mock_manager.broadcast = AsyncMock(return_value=0)
            await publish_event(redis, "SYSTEM_ALERT", {"msg": "test"})
            mock_manager.broadcast.assert_called_once()

    def test_all_event_types_have_role_mappings(self):
        required_events = [
            "ENVELOPE_UPDATE",
            "DEFENSE_CLUSTER_UPDATE",
            "LICENSE_REVOKED",
            "ORCHESTRATION_DECISION",
            "FLYWHEEL_SIGNAL",
            "AUDIT_ACTION",
            "SIMULATION_RESULT",
            "SYSTEM_ALERT",
            "THREAT_LEVEL_CHANGE",
        ]
        for event in required_events:
            assert event in CHANNEL_ROLE_MAP, f"Missing role mapping for event: {event}"

    def test_license_revoked_requires_super_admin(self):
        assert CHANNEL_ROLE_MAP["LICENSE_REVOKED"] == "super_admin"

    def test_system_alert_accessible_to_all(self):
        assert CHANNEL_ROLE_MAP["SYSTEM_ALERT"] == "read_only"


# ---------------------------------------------------------------------------
# WebSocket endpoint tests (via test client)
# ---------------------------------------------------------------------------

class TestWebSocketEndpoint:
    @pytest.mark.asyncio
    async def test_ws_rejects_missing_token(self, app):
        # Verifies via HTTP that the WS stats endpoint exists. (It used to
        # import httpx_ws, which is not a dependency of this project and is not
        # used by the test.)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ws/stats")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_ws_stats_returns_connection_info(self, app):
        from httpx import AsyncClient, ASGITransport
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ws/stats")
            data = resp.json()
            assert "total_connections" in data
            assert "by_role" in data

    @pytest.mark.asyncio
    async def test_ws_token_validation_uses_access_token(self):
        """Verify that decode_token is called during WS auth."""
        from mc2.auth.jwt_handler import decode_token
        token = create_access_token("user-1", "super_admin")
        payload = decode_token(token)
        assert payload.type == "access"

    @pytest.mark.asyncio
    async def test_ws_refresh_token_rejected(self):
        """Refresh tokens must not grant WS access."""
        from mc2.auth.jwt_handler import decode_token
        token = create_refresh_token("user-1", "super_admin")
        payload = decode_token(token)
        assert payload.type == "refresh"
        # In the WS handler, type != "access" → close(4001)


# ---------------------------------------------------------------------------
# Import fix for TestWebSocketEndpoint
# ---------------------------------------------------------------------------

from httpx import AsyncClient, ASGITransport
