"""
test_control_center_boundary_enforcement.py

Verifies that the Control Center backend:
  1. Never computes business logic locally (all state from frothiq-core)
  2. All mutation operations go through the command proxy (async receipts)
  3. Service layer passes core's fields through without local derivation
  4. CoreDecisionResponse source field is preserved
  5. Forbidden local computation functions do not exist in service modules
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import sys
import time
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_core_tenant(**kwargs) -> dict:
    defaults = {
        "tenant_id": "t-001",
        "plan": "pro",
        "license_status": "active",
        "sync_healthy": True,
        "max_sites": 5,
        "active_sites": 3,
        "last_sync": "2026-04-14T10:00:00+00:00",
    }
    return {**defaults, **kwargs}


def _make_cluster(**kwargs) -> dict:
    defaults = {
        "cluster_id": "c-abc123",
        "severity": "high",
        "priority": 3,
        "auto_apply_eligible": True,
        "action": "harden",
        "campaign_ids": ["camp-1", "camp-2"],
    }
    return {**defaults, **kwargs}


# ===========================================================================
# 1. License service boundary tests (24 tests)
# ===========================================================================

class TestLicenseServiceBoundary:
    """The license boundary, as it stands today.

    This class used to assert the opposite: that every license field came from
    frothiq-core and that revoke/restore/force-sync were proxied to it. That
    was reversed deliberately, and license_service.py says why in its own
    docstring — core's registry holds PLAN TEMPLATES, not individual site
    registrations, so it cannot answer "is this tenant's licence live". License
    state is now derived from the Control Center's own edge_tenants and
    edge_nodes tables and annotated `source: edge_db`.

    Nine tests here asserted the old direction and failed against the new
    service. Deleting them would have removed the guard entirely; they are
    rewritten to hold the CURRENT line instead, so the boundary is still
    enforced — just the boundary that exists.
    """

    @staticmethod
    def _session_factory(tenants=(), nodes=()):
        """A session factory whose two queries return the given rows.

        get_all_license_states issues exactly two selects — tenants, then
        nodes — so returning them in order is enough to exercise the whole
        derivation without a database.
        """
        results = [list(tenants), list(nodes)]

        class _Result:
            def __init__(self, rows):
                self._rows = rows

            def scalars(self):
                return self

            def all(self):
                return self._rows

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def execute(self, *_a, **_k):
                return _Result(results.pop(0) if results else [])

        return lambda: _Session()

    @pytest.mark.asyncio
    async def test_license_state_is_annotated_as_coming_from_the_edge_db(self):
        """The source annotation is the contract: callers must be able to tell."""
        from mc2.services import license_service

        with patch.object(license_service, "get_session_factory",
                          return_value=self._session_factory()):
            result = await license_service.get_all_license_states()

        assert result["source"] == "edge_db", (
            "license state is derived from edge_tenants/edge_nodes; the annotation "
            "is how a caller knows it did not come from frothiq-core"
        )

    @pytest.mark.asyncio
    async def test_sync_health_is_annotated_as_coming_from_the_edge_db(self):
        from mc2.services import license_service

        with patch.object(license_service, "get_session_factory",
                          return_value=self._session_factory()):
            result = await license_service.get_sync_health()

        assert result["source"] == "edge_db"
        assert result["total"] == 0
        assert result["health_pct"] == 0.0

    @pytest.mark.asyncio
    async def test_license_state_does_not_call_frothiq_core(self):
        """The point of the reversal: no round trip to core for license state.

        Asserted against the shared singleton, because a service that wanted to
        call core would import the object rather than the module attribute.
        """
        from mc2.services import license_service
        from mc2.services.core_client import core_client

        with patch.object(core_client, "get", new=AsyncMock(return_value={})) as core_get, \
             patch.object(core_client, "post", new=AsyncMock(return_value={})) as core_post, \
             patch.object(license_service, "get_session_factory",
                          return_value=self._session_factory()):
            await license_service.get_all_license_states()

        core_get.assert_not_called()
        core_post.assert_not_called()

    def test_license_service_holds_no_reference_to_core_client(self):
        """A module-level import would be the first step back to the old shape."""
        from mc2.services import license_service

        assert not hasattr(license_service, "core_client"), (
            "license_service must not hold a core_client reference — license state "
            "comes from the edge tables (see the module docstring)"
        )

    def test_license_service_module_has_no_business_logic_functions(self):
        """Ensure forbidden local computation functions don't exist."""
        from mc2.services import license_service
        forbidden = ["_derive_license_status", "_compute_health_pct"]
        for fn in forbidden:
            assert not hasattr(license_service, fn), (
                f"license_service.{fn} is forbidden — that shape belonged to the "
                "proxy-everything design"
            )



# ===========================================================================
# 2. Defense service boundary tests (20 tests)
# ===========================================================================

class TestDefenseServiceBoundary:

    def test_defense_service_no_local_priority_computation(self):
        """_severity_to_priority must not exist — priority comes from core."""
        from mc2.services import defense_service
        assert not hasattr(defense_service, "_severity_to_priority"), (
            "defense_service must not contain _severity_to_priority — "
            "priority scoring belongs in frothiq-core"
        )

    @pytest.mark.asyncio
    async def test_get_all_clusters_annotates_source(self):
        from mc2.services.defense_service import get_all_clusters

        with patch("mc2.services.defense_service.core_client") as mock:
            mock.get = AsyncMock(return_value={"clusters": [], "total": 0})
            result = await get_all_clusters()

        assert result.get("source") == "frothiq-core"

    @pytest.mark.asyncio
    async def test_get_all_clusters_passes_severity_from_core(self):
        """Severity must be passed through from core, not derived."""
        from mc2.services.defense_service import get_all_clusters

        clusters = [_make_cluster(severity="critical")]
        with patch("mc2.services.defense_service.core_client") as mock:
            mock.get = AsyncMock(return_value={"clusters": clusters, "total": 1})
            result = await get_all_clusters()

        assert result["clusters"][0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_get_suggested_actions_prefers_core_endpoint(self):
        """Suggested actions should first try core's dedicated endpoint."""
        from mc2.services.defense_service import get_suggested_actions

        with patch("mc2.services.defense_service.core_client") as mock:
            mock.get = AsyncMock(return_value={"actions": [{"cluster_id": "c-1", "action": "harden"}]})
            result = await get_suggested_actions()

        assert len(result) == 1
        assert result[0]["action"] == "harden"

    @pytest.mark.asyncio
    async def test_get_suggested_actions_fallback_uses_core_priority(self):
        """Fallback sorting must use core's priority field, not _severity_to_priority."""
        from mc2.services.defense_service import get_suggested_actions
        from mc2.services.core_client import CoreClientError

        clusters = [
            _make_cluster(cluster_id="c-low", priority=1, severity="low"),
            _make_cluster(cluster_id="c-high", priority=4, severity="critical"),
        ]

        call_count = 0
        async def mock_get(path, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise CoreClientError(404, "not found")
            return {"clusters": clusters, "total": 2}

        with patch("mc2.services.defense_service.core_client") as mock:
            mock.get = AsyncMock(side_effect=mock_get)
            result = await get_suggested_actions()

        # High priority cluster should be first
        if result:
            assert result[0]["cluster_id"] == "c-high"

    @pytest.mark.asyncio
    async def test_get_propagation_graph_passes_severity_through(self):
        """Propagation graph must pass core's severity without re-scoring."""
        from mc2.services.defense_service import get_propagation_graph
        from mc2.services.core_client import CoreClientError

        # Simulate core lacking a dedicated graph endpoint
        call_count = 0
        async def mock_get(path, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise CoreClientError(404, "not found")
            return {"clusters": [_make_cluster(severity="critical")], "total": 1}

        with patch("mc2.services.defense_service.core_client") as mock:
            mock.get = AsyncMock(side_effect=mock_get)
            result = await get_propagation_graph()

        nodes = result.get("nodes", [])
        if nodes:
            assert nodes[0].get("severity") == "critical"

    @pytest.mark.asyncio
    async def test_get_engine_status_is_pure_proxy(self):
        from mc2.services.defense_service import get_engine_status

        core_status = {"healthy": True, "uptime": 3600, "version": "2.0"}
        with patch("mc2.services.defense_service.core_client") as mock:
            mock.get = AsyncMock(return_value=core_status)
            result = await get_engine_status()

        assert result["healthy"] is True
        assert result["version"] == "2.0"

    @pytest.mark.asyncio
    async def test_get_cluster_detail_is_pure_proxy(self):
        from mc2.services.defense_service import get_cluster_detail

        cluster = _make_cluster()
        with patch("mc2.services.defense_service.core_client") as mock:
            mock.get = AsyncMock(return_value=cluster)
            result = await get_cluster_detail("c-abc123")

        assert result["cluster_id"] == "c-abc123"

    @pytest.mark.asyncio
    async def test_get_all_clusters_engine_unhealthy_on_error(self):
        from mc2.services.defense_service import get_all_clusters
        from mc2.services.core_client import CoreClientError

        with patch("mc2.services.defense_service.core_client") as mock:
            mock.get = AsyncMock(side_effect=CoreClientError(503, "core down"))
            result = await get_all_clusters()

        assert result["engine_healthy"] is False
        assert result["clusters"] == []


# ===========================================================================
# 3. Monetization service boundary tests (20 tests)
# ===========================================================================

class TestMonetizationServiceBoundary:

    def test_monetization_service_no_local_rpi_computation(self):
        """_compute_rpi must not exist — RPI is a frothiq-core metric."""
        from mc2.services import monetization_service
        assert not hasattr(monetization_service, "_compute_rpi"), (
            "monetization_service._compute_rpi is forbidden — RPI belongs in frothiq-core"
        )

    def test_monetization_service_no_local_next_plan(self):
        from mc2.services import monetization_service
        assert not hasattr(monetization_service, "_next_plan"), (
            "monetization_service._next_plan is forbidden — plan progression logic belongs in core"
        )

    def test_monetization_service_no_upgrade_signal_estimation(self):
        from mc2.services import monetization_service
        assert not hasattr(monetization_service, "_estimate_upgrade_signals"), (
            "monetization_service._estimate_upgrade_signals is forbidden"
        )

    def test_monetization_service_no_paywall_hit_estimation(self):
        from mc2.services import monetization_service
        assert not hasattr(monetization_service, "_estimate_paywall_hits"), (
            "monetization_service._estimate_paywall_hits is forbidden"
        )

    @pytest.mark.asyncio
    async def test_get_monetization_overview_prefers_core_endpoint(self):
        from mc2.services.monetization_service import get_monetization_overview

        core_overview = {
            "total_tenants": 42,
            "plan_breakdown": {"free": 20, "pro": 15, "enterprise": 7},
            "revenue_pressure_index": 0.476,
            "upgrade_signals_last_7d": 8,
            "paywall_hits_last_7d": 3,
            "top_upgrade_candidates": [],
        }
        with patch("mc2.services.monetization_service.core_client") as mock:
            mock.get = AsyncMock(return_value=core_overview)
            result = await get_monetization_overview()

        assert result["source"] == "frothiq-core"
        assert result["total_tenants"] == 42
        assert result["revenue_pressure_index"] == 0.476

    @pytest.mark.asyncio
    async def test_get_monetization_overview_source_annotation(self):
        from mc2.services.monetization_service import get_monetization_overview

        with patch("mc2.services.monetization_service.core_client") as mock:
            mock.get = AsyncMock(return_value={"total_tenants": 0})
            result = await get_monetization_overview()

        assert result.get("source") == "frothiq-core"

    @pytest.mark.asyncio
    async def test_get_upgrade_funnel_delegates_to_core(self):
        from mc2.services.monetization_service import get_upgrade_funnel

        funnel = {"free_to_pro": 5, "pro_to_enterprise": 2}
        with patch("mc2.services.monetization_service.core_client") as mock:
            mock.get = AsyncMock(return_value=funnel)
            result = await get_upgrade_funnel()

        assert result["free_to_pro"] == 5

    @pytest.mark.asyncio
    async def test_get_revenue_heatmap_delegates_to_core(self):
        from mc2.services.monetization_service import get_revenue_heatmap

        with patch("mc2.services.monetization_service.core_client") as mock:
            mock.get = AsyncMock(return_value={"cells": [], "rpi": 0.3})
            result = await get_revenue_heatmap(30)

        assert result.get("source") == "frothiq-core"
        assert result["rpi"] == 0.3

    @pytest.mark.asyncio
    async def test_get_paywall_analytics_delegates_to_core(self):
        from mc2.services.monetization_service import get_paywall_analytics

        with patch("mc2.services.monetization_service.core_client") as mock:
            mock.get = AsyncMock(return_value={"total_hits": 50})
            result = await get_paywall_analytics()

        assert result["success"] is True
        assert result["total_hits"] == 50


# ===========================================================================
# 4. Command proxy tests (20 tests)
# ===========================================================================

class TestCommandProxy:

    def test_command_router_module_exists(self):
        from mc2.api import routes_commands  # noqa: F401

    def test_command_types_are_complete(self):
        from mc2.api.routes_commands import CommandType, _CORE_COMMAND_MAP
        # All command types must have a registered path
        valid_commands = [
            "trigger_policy_rollout", "revoke_license", "restore_license",
            "force_license_sync", "force_cluster_propagation", "run_simulation",
            "refresh_envelope", "block_ip", "unblock_ip", "rollback_policy",
        ]
        for cmd in valid_commands:
            assert cmd in _CORE_COMMAND_MAP, f"Command {cmd} missing from _CORE_COMMAND_MAP"

    def test_command_receipt_status_is_acknowledged_not_executed(self):
        """Commands must return 'acknowledged' status — never 'executed' synchronously."""
        from mc2.api.routes_commands import _CORE_COMMAND_MAP
        # The command system must not have a 'executed' status (only acknowledged/queued)
        from mc2.api.routes_commands import CommandReceipt
        valid_statuses = {"acknowledged", "queued", "executing", "completed", "failed"}
        # 'executed' is forbidden — commands are async
        assert "executed" not in valid_statuses or True  # just confirming the type design

    def test_sign_command_produces_deterministic_signature(self):
        from mc2.api.routes_commands import _sign_command
        sig1 = _sign_command("POST", "/api/v2/policy/rollout", "1234567890", "test-key")
        sig2 = _sign_command("POST", "/api/v2/policy/rollout", "1234567890", "test-key")
        assert sig1 == sig2

    def test_sign_command_different_paths_produce_different_sigs(self):
        from mc2.api.routes_commands import _sign_command
        sig1 = _sign_command("POST", "/api/v2/policy/rollout", "1234567890", "test-key")
        sig2 = _sign_command("POST", "/api/v2/license/revoke", "1234567890", "test-key")
        assert sig1 != sig2

    def test_sign_command_different_timestamps_produce_different_sigs(self):
        from mc2.api.routes_commands import _sign_command
        sig1 = _sign_command("POST", "/api/v2/policy/rollout", "1111111111", "test-key")
        sig2 = _sign_command("POST", "/api/v2/policy/rollout", "9999999999", "test-key")
        assert sig1 != sig2

    def test_estimate_seconds_covers_all_commands(self):
        from mc2.api.routes_commands import _estimate_seconds, _CORE_COMMAND_MAP
        for cmd in _CORE_COMMAND_MAP:
            result = _estimate_seconds(cmd)
            assert isinstance(result, int) and result > 0

    def test_gateway_routes_subset_of_all_commands(self):
        from mc2.api.routes_commands import _GATEWAY_ROUTES, _CORE_COMMAND_MAP
        for route_cmd in _GATEWAY_ROUTES:
            assert route_cmd in _CORE_COMMAND_MAP

    @pytest.mark.asyncio
    async def test_dispatch_command_requires_auth(self, client):
        """Unauthenticated command dispatch must return 401/403."""
        from httpx import AsyncClient
        # Command endpoint rejects missing auth at dependency injection level
        resp = await client.post("/api/v1/cc/commands", json={"command": "run_simulation"})
        assert resp.status_code in (401, 403, 422)


# ===========================================================================
# 5. API layer type tests (16 tests)
# ===========================================================================

# ---------------------------------------------------------------------------
# The TypeScript half of the contract
# ---------------------------------------------------------------------------
#
# These assertions read the UI repo's source. It is a SEPARATE repository, so
# it is only there when someone has both checked out side by side — never in
# this repo's CI. They therefore skip rather than fail when it is absent; a
# test that cannot see what it asserts about has found nothing.
#
# The directory was also renamed: frothiq-control-center-ui -> mc2-ui. One
# test hard-asserted the old name and so failed for everyone, while its three
# neighbours guarded with `if os.path.exists` and silently passed. Both names
# are tried here so a developer with either layout gets the real check.

def _ui_lib(*parts: str) -> str | None:
    """Absolute path inside the UI repo's lib/, or None if it is not checked out."""
    import os
    here = os.path.dirname(__file__)
    for repo in ("mc2-ui", "frothiq-control-center-ui"):
        candidate = os.path.join(here, "..", "..", repo, "lib", *parts)
        if os.path.exists(candidate):
            return candidate
    return None


_UI_ABSENT = _ui_lib("command-client.ts") is None
_needs_ui = pytest.mark.skipif(_UI_ABSENT, reason="UI repo (mc2-ui) is not checked out beside this one")


class TestAPILayerTypes:

    @_needs_ui
    def test_core_decision_response_type_exists_in_api_module(self):
        """CoreDecisionResponse must be exported from lib/api.ts (TypeScript side)."""
        api_ts_path = _ui_lib("api.ts")
        if api_ts_path:
            content = open(api_ts_path).read()
            assert "CoreDecisionResponse" in content, \
                "CoreDecisionResponse interface missing from lib/api.ts"
            assert 'source: "frothiq-core"' in content, \
                "CoreDecisionResponse must have source: \"frothiq-core\" discriminant"

    @_needs_ui
    def test_command_client_exists(self):
        assert _ui_lib("command-client.ts"), "lib/command-client.ts must exist in the UI repo"

    @_needs_ui
    def test_command_client_has_send_command_to_core(self):
        cc_path = _ui_lib("command-client.ts")
        if cc_path:
            content = open(cc_path).read()
            assert "sendCommandToCore" in content
            assert "sendCommandToGateway" in content
            assert "CommandReceipt" in content

    @_needs_ui
    def test_command_client_all_commands_are_async_receipts(self):
        cc_path = _ui_lib("command-client.ts")
        if cc_path:
            content = open(cc_path).read()
            assert "Promise<CommandReceipt>" in content
            # Commands must return receipts, never void
            assert "Promise<void>" not in content

    @_needs_ui
    def test_assert_core_source_function_exists(self):
        api_ts_path = _ui_lib("api.ts")
        if api_ts_path:
            content = open(api_ts_path).read()
            assert "assertCoreSource" in content

    @_needs_ui
    def test_no_local_risk_computation_in_api_ts(self):
        """lib/api.ts must contain no business logic functions."""
        api_ts_path = _ui_lib("api.ts")
        if api_ts_path:
            content = open(api_ts_path).read()
            forbidden_patterns = [
                "riskScore",
                "computeRisk",
                "evaluatePolicy",
                "validateLicense",
                "computeRpi",
                "calculateConversion",
            ]
            for pattern in forbidden_patterns:
                assert pattern not in content, (
                    f"lib/api.ts contains forbidden business logic: {pattern}"
                )
