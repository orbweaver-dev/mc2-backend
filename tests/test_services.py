"""
Unit tests for all service modules.
Tests business logic, failover, and data transformation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mc2.services.core_client import CoreClientError
from mc2.services import (
    defense_service,
    envelope_service,
    flywheel_service,
    license_service,
    monetization_service,
    policy_service,
    simulation_service,
)
from mc2.services.envelope_service import (
    _compute_diff,
    _verify_envelope_signature,
)
from mc2.services.license_service import _state_to_status


# ---------------------------------------------------------------------------
# Defense service
# ---------------------------------------------------------------------------

class TestDefenseService:
    @pytest.mark.asyncio
    async def test_get_all_clusters_success(self, mock_core_client):
        mock_core_client.get.return_value = {"clusters": [{"severity": "high"}], "total": 1}
        with patch("mc2.services.defense_service.core_client", mock_core_client):
            result = await defense_service.get_all_clusters()
        assert result["success"] is True
        assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_get_all_clusters_core_offline(self, mock_core_client):
        mock_core_client.get.side_effect = CoreClientError(503, "Core offline")
        with patch("mc2.services.defense_service.core_client", mock_core_client):
            result = await defense_service.get_all_clusters()
        assert result["success"] is False
        assert result["engine_healthy"] is False

    @pytest.mark.asyncio
    async def test_suggested_actions_sorted_by_core_priority(self, mock_core_client):
        """The fallback orders by CORE's priority field, not by severity.

        This used to assert severity order, which only held while
        _severity_to_priority existed here. That function was deleted when
        priority became core's decision, so the ranking now follows the
        priority core sends — note c1 is "low" severity but outranks the
        "critical" c2, which is exactly the pass-through being asserted.

        The dedicated endpoint has to fail for the fallback to run at all; the
        old mock answered every URL with the cluster payload, so the preferred
        call "succeeded" with a shape it could not read and returned nothing.
        """
        def _by_url(url, *a, **k):
            if url == "/api/v2/defense/suggested-actions":
                raise CoreClientError(404, "core has no dedicated endpoint here")
            return {
                "clusters": [
                    {"cluster_id": "c1", "severity": "low", "action": "monitor",
                     "auto_apply_eligible": True, "campaign_ids": [], "priority": 90},
                    {"cluster_id": "c2", "severity": "critical", "action": "block_asn",
                     "auto_apply_eligible": True, "campaign_ids": ["a", "b"], "priority": 10},
                    {"cluster_id": "c3", "severity": "medium", "action": "rate_limit",
                     "auto_apply_eligible": True, "campaign_ids": ["x"], "priority": 50},
                ]
            }

        mock_core_client.get.side_effect = _by_url
        with patch("mc2.services.defense_service.core_client", mock_core_client):
            actions = await defense_service.get_suggested_actions()

        assert [a["cluster_id"] for a in actions] == ["c1", "c3", "c2"]
        assert [a["priority"] for a in actions] == [90, 50, 10]

    @pytest.mark.asyncio
    async def test_suggested_actions_excludes_non_eligible(self, mock_core_client):
        mock_core_client.get.return_value = {
            "clusters": [
                {"cluster_id": "c1", "severity": "high", "action": "block", "auto_apply_eligible": False, "campaign_ids": []},
            ]
        }
        with patch("mc2.services.defense_service.core_client", mock_core_client):
            actions = await defense_service.get_suggested_actions()
        assert len(actions) == 0

    @pytest.mark.asyncio
    async def test_propagation_graph_structure(self, mock_core_client):
        """The fallback builds cluster -> campaign topology from the cluster list.

        As above: the dedicated graph endpoint must fail for the fallback to be
        reached, otherwise its reply is returned verbatim and there are no
        nodes to count.
        """
        def _by_url(url, *a, **k):
            if url == "/api/v2/defense/propagation-graph":
                raise CoreClientError(404, "core has no dedicated endpoint here")
            return {
                "clusters": [
                    {"cluster_id": "cluster-1", "campaign_ids": ["camp-a", "camp-b"],
                     "severity": "high"},
                ]
            }

        mock_core_client.get.side_effect = _by_url
        with patch("mc2.services.defense_service.core_client", mock_core_client):
            graph = await defense_service.get_propagation_graph()

        cluster_nodes = [n for n in graph["nodes"] if n.get("type") == "cluster"]
        assert len(cluster_nodes) == 1
        assert cluster_nodes[0]["severity"] == "high"
        assert len(graph["edges"]) == 2

    # _severity_to_priority was deleted when defense_service became a pure
    # proxy — priority is frothiq-core's decision, and
    # test_control_center_boundary_enforcement asserts the function must not
    # reappear here.

# ---------------------------------------------------------------------------
# License service
# ---------------------------------------------------------------------------

class TestLicenseService:
    """License state comes from the edge tables, not from frothiq-core.

    Four tests here patched mc2.services.license_service.core_client and
    asserted revoke/list were proxied to core. license_service.py says in its
    own docstring why that was reversed: core's registry holds plan templates,
    not individual site registrations, so it cannot answer whether a tenant's
    licence is live. They are replaced with the same assertions against the
    implementation that exists.
    """

    @staticmethod
    def _session(tenants=(), nodes=(), captured=None):
        """Session factory whose selects return the given rows, in order."""
        results = [list(tenants), list(nodes)]

        class _Result:
            def __init__(self, rows):
                self._rows = rows

            def scalars(self):
                return self

            def all(self):
                return self._rows

            def scalar_one_or_none(self):
                return self._rows[0] if self._rows else None

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def execute(self, stmt, *a, **k):
                if captured is not None:
                    captured.append(stmt)
                return _Result(results.pop(0) if results else [])

            async def commit(self):
                if captured is not None:
                    captured.append("commit")

        return lambda: _Session()

    @pytest.mark.asyncio
    async def test_get_all_license_states_success(self):
        tenant = MagicMock(tenant_id="t1", plan="pro", is_active=True,
                           registration_state="REGISTERED", domain="a.example.com",
                           deregistered_at=None)
        with patch.object(license_service, "get_session_factory",
                          return_value=self._session([tenant], [])):
            result = await license_service.get_all_license_states()

        assert result["success"] is True
        assert result["total"] == 1
        assert result["source"] == "edge_db"

    @pytest.mark.asyncio
    async def test_revoke_license_marks_the_tenant_inactive(self):
        """Revocation is a write to the edge tables, not a POST to core."""
        tenant = MagicMock(tenant_id="t1", domain="a.example.com",
                           is_active=True, registration_state="REGISTERED")
        captured: list = []
        with patch.object(license_service, "get_session_factory",
                          return_value=self._session([tenant], captured=captured)):
            result = await license_service.revoke_license("t1", "Non-payment", "admin@cc.io")

        assert result["success"] is True
        assert result["status"] == "suspended"
        assert tenant.is_active is False
        assert tenant.registration_state == "revoked"
        assert "commit" in captured, "the revocation must be committed"

    @pytest.mark.asyncio
    async def test_revoke_license_unknown_tenant_reports_failure(self):
        with patch.object(license_service, "get_session_factory",
                          return_value=self._session([])):
            result = await license_service.revoke_license("nope", "test", "admin")

        assert result["success"] is False
        assert "error" in result

    # _derive_license_status(dict) became _state_to_status(is_active, state)
    # when license state moved to the edge tables: the inputs are now the two
    # columns that carry it rather than a dict from core. Same decisions, so
    # the coverage is kept against the function that exists.
    def test_state_to_status_inactive_is_suspended(self):
        assert _state_to_status(False, "ACTIVE") == "suspended"

    def test_state_to_status_revoked_is_suspended(self):
        assert _state_to_status(True, "REVOKED") == "suspended"

    def test_state_to_status_removed_is_expired(self):
        assert _state_to_status(True, "REMOVED") == "expired"

    def test_state_to_status_otherwise_active(self):
        assert _state_to_status(True, "REGISTERED") == "active"

    # _is_sync_healthy was dropped: sync health is no longer a pure function of
    # a core payload, it is derived inside get_all_license_states from each
    # node's last_seen against _SYNC_HEALTHY_WINDOW. The boundary suite covers
    # the result and its source annotation.

    @pytest.mark.asyncio
    async def test_sync_health_returns_pct(self):
        """health_pct is derived from the tenants the edge tables report."""
        tenant = MagicMock(tenant_id="t1", plan="pro", is_active=True,
                           registration_state="REGISTERED", domain="a.example.com",
                           deregistered_at=None)
        with patch.object(license_service, "get_session_factory",
                          return_value=self._session([tenant], [])):
            result = await license_service.get_sync_health()

        assert result["total"] == 1
        assert result["sync_healthy"] + result["sync_degraded"] == 1
        assert 0.0 <= result["health_pct"] <= 100.0
        assert result["source"] == "edge_db"


class TestEnvelopeService:
    def test_verify_envelope_with_signature(self):
        env = {"signature": "sha256:validhash12345678"}
        assert _verify_envelope_signature(env) is True

    def test_verify_envelope_without_signature_permissive(self):
        env = {"version": "v1", "sections": {}}
        assert _verify_envelope_signature(env) is True

    def test_compute_diff_added_key(self):
        old = {"a": 1}
        new = {"a": 1, "b": 2}
        changes = _compute_diff(old, new)
        assert any(c["op"] == "add" and c["path"] == "b" for c in changes)

    def test_compute_diff_removed_key(self):
        old = {"a": 1, "b": 2}
        new = {"a": 1}
        changes = _compute_diff(old, new)
        assert any(c["op"] == "remove" and c["path"] == "b" for c in changes)

    def test_compute_diff_changed_value(self):
        old = {"score": 80}
        new = {"score": 100}
        changes = _compute_diff(old, new)
        assert any(c["op"] == "change" and c["path"] == "score" for c in changes)

    def test_compute_diff_nested(self):
        old = {"rules": {"block_score": 80}}
        new = {"rules": {"block_score": 90}}
        changes = _compute_diff(old, new)
        assert any(c["path"] == "rules.block_score" for c in changes)

    def test_compute_diff_no_changes(self):
        d = {"a": 1, "b": {"c": 2}}
        changes = _compute_diff(d, d.copy())
        assert len(changes) == 0

    @pytest.mark.asyncio
    async def test_get_tenant_envelope_success(self, mock_core_client):
        mock_core_client.get.return_value = {
            "version": "v1.0", "signature": "sha256:abc123", "sections": {}
        }
        with patch("mc2.services.envelope_service.core_client", mock_core_client):
            result = await envelope_service.get_tenant_envelope("t1")
        assert result["success"] is True
        assert result["envelope_version"] == "v1.0"

    @pytest.mark.asyncio
    async def test_get_tenant_envelope_core_failure(self, mock_core_client):
        mock_core_client.get.side_effect = CoreClientError(503, "Offline")
        with patch("mc2.services.envelope_service.core_client", mock_core_client):
            result = await envelope_service.get_tenant_envelope("t1")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_verify_all_envelopes_batch(self, mock_core_client):
        mock_core_client.get.return_value = {"version": "v1", "signature": "abc123456789"}
        with patch("mc2.services.envelope_service.core_client", mock_core_client):
            result = await envelope_service.verify_all_envelopes(["t1", "t2", "t3"])
        assert result["summary"]["total"] == 3


# ---------------------------------------------------------------------------
# Monetization service
# ---------------------------------------------------------------------------

class TestMonetizationService:
    # _compute_rpi, _next_plan, _estimate_upgrade_signals and
    # _estimate_paywall_hits were deleted when monetization stopped computing
    # locally and became a proxy to frothiq-core. Their unit tests went with
    # them: test_control_center_boundary_enforcement asserts both that the
    # functions do not exist and that the service delegates, which is the
    # behaviour that is now true. What remains here exercises the proxy.

    @pytest.mark.asyncio
    async def test_monetization_overview_structure(self, mock_core_client):
        """plan_breakdown and friends are assembled by the FALLBACK path.

        The dedicated overview endpoint has to fail to reach it. The old mock
        answered every URL with the tenant list, so the preferred call
        "succeeded" and its payload was returned verbatim — without the fields
        this asserts.
        """
        def _by_url(url, *a, **k):
            if url == "/api/v2/intelligence/monetization/overview":
                raise CoreClientError(404, "no dedicated overview endpoint")
            return {
                "tenants": [
                    {"tenant_id": "t1", "plan": "free", "max_sites": 1, "active_sites": 1},
                    {"tenant_id": "t2", "plan": "pro", "max_sites": 10, "active_sites": 2},
                ]
            }

        mock_core_client.get.side_effect = _by_url
        with patch("mc2.services.monetization_service.core_client", mock_core_client):
            result = await monetization_service.get_monetization_overview()
        assert "plan_breakdown" in result
        assert "revenue_pressure_index" in result
        assert "top_upgrade_candidates" in result

    @pytest.mark.asyncio
    async def test_upgrade_candidates_sorted_by_utilization(self, mock_core_client):
        def _by_url(url, *a, **k):
            if url == "/api/v2/intelligence/monetization/overview":
                raise CoreClientError(404, "no dedicated overview endpoint")
            return {
                "tenants": [
                    {"tenant_id": "t1", "plan": "free", "max_sites": 1, "active_sites": 1},
                    {"tenant_id": "t2", "plan": "pro", "max_sites": 10, "active_sites": 9},
                ]
            }

        mock_core_client.get.side_effect = _by_url
        with patch("mc2.services.monetization_service.core_client", mock_core_client):
            result = await monetization_service.get_monetization_overview()
        candidates = result["top_upgrade_candidates"]
        if len(candidates) >= 2:
            assert candidates[0]["utilization"] >= candidates[1]["utilization"]


# ---------------------------------------------------------------------------
# Simulation service
# ---------------------------------------------------------------------------

class TestSimulationService:
    @pytest.mark.asyncio
    async def test_get_scenarios_list(self, mock_core_client):
        mock_core_client.get.return_value = {"scenarios": [{"id": "s1"}, {"id": "s2"}]}
        with patch("mc2.services.simulation_service.core_client", mock_core_client):
            scenarios = await simulation_service.get_scenarios()
        assert len(scenarios) == 2

    @pytest.mark.asyncio
    async def test_run_scenario_success(self, mock_core_client):
        mock_core_client.post.return_value = {"sim_id": "sim-001", "status": "started"}
        with patch("mc2.services.simulation_service.core_client", mock_core_client):
            result = await simulation_service.run_scenario("s1", "t1", {}, "admin")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_run_scenario_core_failure(self, mock_core_client):
        mock_core_client.post.side_effect = CoreClientError(500, "Error")
        with patch("mc2.services.simulation_service.core_client", mock_core_client):
            result = await simulation_service.run_scenario("s1", "t1", {}, "admin")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_get_metrics_returns_all_scores(self, mock_core_client):
        mock_core_client.get.return_value = {
            "das_avg": 0.7, "dei_avg": 0.6, "pps_avg": 0.8,
            "das_trend": [0.5, 0.7], "dei_trend": [], "pps_trend": [],
        }
        with patch("mc2.services.simulation_service.core_client", mock_core_client):
            result = await simulation_service.get_metrics(period_days=7)
        assert result["das_avg"] == 0.7
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_get_metrics_core_offline_graceful(self, mock_core_client):
        mock_core_client.get.side_effect = CoreClientError(503, "Offline")
        with patch("mc2.services.simulation_service.core_client", mock_core_client):
            result = await simulation_service.get_metrics()
        assert result["success"] is False
        assert result["das_avg"] == 0.0


# ---------------------------------------------------------------------------
# Flywheel service
# ---------------------------------------------------------------------------

class TestFlywheelService:
    @pytest.mark.asyncio
    async def test_get_flywheel_state_success(self, mock_core_client):
        mock_core_client.get.return_value = {"phase": "reinforcement", "velocity": 0.87}
        with patch("mc2.services.flywheel_service.core_client", mock_core_client):
            result = await flywheel_service.get_flywheel_state()
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_correlation_heatmap_fallback_on_error(self, mock_core_client):
        mock_core_client.get.side_effect = CoreClientError(503, "Offline")
        with patch("mc2.services.flywheel_service.core_client", mock_core_client):
            result = await flywheel_service.get_correlation_heatmap()
        assert result["success"] is False
        assert len(result["matrix"]) == len(result["dimensions"])
        # Matrix should be all zeros
        assert all(v == 0.0 for row in result["matrix"] for v in row)

    @pytest.mark.asyncio
    async def test_flywheel_dashboard_aggregates_all(self, mock_core_client):
        mock_core_client.get.return_value = {}
        with patch("mc2.services.flywheel_service.core_client", mock_core_client):
            result = await flywheel_service.get_flywheel_dashboard()
        assert "state" in result
        assert "correlation_heatmap" in result
        assert "reinforcement_vectors" in result
        assert "optimization_suggestions" in result

    @pytest.mark.asyncio
    async def test_flywheel_dashboard_handles_partial_failure(self, mock_core_client):
        """Flywheel dashboard should not crash if some sub-calls fail."""
        mock_core_client.get.side_effect = CoreClientError(503, "Offline")
        with patch("mc2.services.flywheel_service.core_client", mock_core_client):
            result = await flywheel_service.get_flywheel_dashboard()
        # Should return something, not raise
        assert isinstance(result, dict)
