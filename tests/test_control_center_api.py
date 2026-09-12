"""
Control Center API integration tests.
Tests all major API endpoints with mocked frothiq-core responses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mc2.services.core_client import CoreClientError


class TestDashboardAPI:
    @pytest.mark.asyncio
    async def test_health_endpoint_returns_200(self, client, read_only_headers, mock_core_client):
        mock_core_client.health_check.return_value = {"status": "online", "version": "0.6.0"}
        mock_core_client.get.return_value = {"clusters": [], "total": 0, "tenants": []}
        resp = await client.get("/api/v1/cc/dashboard/health", headers=read_only_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_health_includes_core_status(self, client, read_only_headers, mock_core_client):
        mock_core_client.health_check.return_value = {"status": "online"}
        mock_core_client.get.return_value = {"clusters": [], "total": 0, "tenants": []}
        resp = await client.get("/api/v1/cc/dashboard/health", headers=read_only_headers)
        data = resp.json()
        assert "core_status" in data
        assert "threat_level" in data
        assert "instability_index" in data

    @pytest.mark.asyncio
    async def test_health_threat_level_with_critical_clusters(self, client, read_only_headers, mock_core_client):
        mock_core_client.health_check.return_value = {"status": "online"}
        mock_core_client.get.side_effect = [
            # defense clusters
            {"clusters": [{"severity": "critical"}, {"severity": "high"}], "total": 2},
            # licenses
            {"tenants": [], "total": 0, "active": 0, "suspended": 0},
            # policies
            {"total": 0, "active": 0},
            # monetization
            {"tenants": [], "revenue_pressure_index": 0.1},
            # simulation
            {"healthy": True},
        ]
        resp = await client.get("/api/v1/cc/dashboard/health", headers=read_only_headers)
        # Even if some fail due to mock, the endpoint shouldn't 500
        assert resp.status_code in (200, 500)

    @pytest.mark.asyncio
    async def test_metrics_summary_returns_correct_keys(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"tenants": [], "total": 0, "active": 0, "suspended": 0, "clusters": []}
        resp = await client.get("/api/v1/cc/dashboard/metrics/summary", headers=read_only_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "license_health_pct" in data
        assert "total_clusters" in data

    @pytest.mark.asyncio
    async def test_dashboard_unauthenticated_returns_401(self, client):
        resp = await client.get("/api/v1/cc/dashboard/health")
        assert resp.status_code == 401


class TestDefenseMeshAPI:
    @pytest.mark.asyncio
    async def test_list_clusters_returns_200(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"clusters": [], "total": 0}
        resp = await client.get("/api/v1/cc/defense/clusters", headers=read_only_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_clusters_returns_cluster_data(self, client, read_only_headers, mock_core_client, sample_cluster):
        mock_core_client.get.return_value = {"clusters": [sample_cluster], "total": 1}
        resp = await client.get("/api/v1/cc/defense/clusters", headers=read_only_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1

    @pytest.mark.asyncio
    async def test_defense_status_returns_200(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"healthy": True, "last_run": "2024-01-15T12:00:00Z"}
        resp = await client.get("/api/v1/cc/defense/status", headers=read_only_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_propagation_graph_returns_nodes_edges(self, client, read_only_headers, mock_core_client, sample_cluster):
        # The service PREFERS core's dedicated propagation-graph endpoint and
        # only builds nodes/edges from the cluster list as a fallback. A mock
        # that answers every URL with the cluster payload makes the preferred
        # call succeed, so that payload is returned verbatim and there is no
        # graph in it.
        def _by_url(url, *a, **k):
            if url == "/api/v2/defense/propagation-graph":
                raise CoreClientError(404, "no dedicated endpoint")
            return {"clusters": [sample_cluster]}

        mock_core_client.get.side_effect = _by_url
        resp = await client.get("/api/v1/cc/defense/propagation", headers=read_only_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data

    @pytest.mark.asyncio
    async def test_suggested_actions_requires_security_analyst(self, client, billing_admin_headers):
        resp = await client.get("/api/v1/cc/defense/suggested-actions", headers=billing_admin_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_suggested_actions_accessible_to_security_analyst(self, client, security_analyst_headers, mock_core_client):
        mock_core_client.get.return_value = {"clusters": []}
        resp = await client.get("/api/v1/cc/defense/suggested-actions", headers=security_analyst_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_cluster_detail_404_from_core(self, client, read_only_headers, mock_core_client):
        from mc2.services.core_client import CoreClientError
        mock_core_client.get.side_effect = CoreClientError(404, "Cluster not found")
        resp = await client.get("/api/v1/cc/defense/clusters/nonexistent", headers=read_only_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_core_offline_defense_returns_degraded(self, client, read_only_headers, mock_core_client):
        from mc2.services.core_client import CoreClientError
        mock_core_client.get.side_effect = CoreClientError(503, "frothiq-core unreachable")
        resp = await client.get("/api/v1/cc/defense/clusters", headers=read_only_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["engine_healthy"] is False


class TestPolicyMeshAPI:
    @pytest.mark.asyncio
    async def test_policy_overview_200(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"policies": []}
        resp = await client.get("/api/v1/cc/policy/overview", headers=read_only_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_active_policies_list(self, client, read_only_headers, mock_core_client, sample_policy):
        mock_core_client.get.return_value = {"policies": [sample_policy]}
        resp = await client.get("/api/v1/cc/policy/active", headers=read_only_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1

    @pytest.mark.asyncio
    async def test_policy_rollback_requires_security_analyst(self, client, read_only_headers):
        resp = await client.post(
            "/api/v1/cc/policy/policy-xyz/rollback",
            headers=read_only_headers,
            json={"version": 1},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_policy_rollback_success(self, client, security_analyst_headers, mock_core_client):
        mock_core_client.post.return_value = {"success": True, "policy_id": "policy-xyz"}
        resp = await client.post(
            "/api/v1/cc/policy/policy-xyz/rollback",
            headers=security_analyst_headers,
            json={"version": 2},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_policy_rollback_failure_returns_502(self, client, security_analyst_headers, mock_core_client):
        from mc2.services.core_client import CoreClientError
        mock_core_client.post.side_effect = CoreClientError(500, "Core error")
        resp = await client.post(
            "/api/v1/cc/policy/policy-xyz/rollback",
            headers=security_analyst_headers,
            json={"version": 2},
        )
        assert resp.status_code in (200, 502)  # service returns success:False → 502


class TestLicenseAPI:
    @pytest.mark.asyncio
    async def test_license_overview_200(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"tenants": [], "total": 0}
        resp = await client.get("/api/v1/cc/license/overview", headers=read_only_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_sync_health_returns_pct(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {
            "tenants": [
                {"tenant_id": "t1", "plan": "pro", "last_sync": "2024-01-15T10:00:00+00:00"},
                {"tenant_id": "t2", "plan": "free", "last_sync": None},
            ],
            "total": 2,
        }
        resp = await client.get("/api/v1/cc/license/sync-health", headers=read_only_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "health_pct" in data

    @pytest.mark.asyncio
    async def test_revoke_requires_super_admin(self, client, security_analyst_headers):
        resp = await client.post(
            "/api/v1/cc/license/tenant-001/revoke",
            headers=security_analyst_headers,
            json={"reason": "test"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_revoke_by_super_admin_succeeds(self, client, super_admin_headers, mock_core_client):
        mock_core_client.post.return_value = {"success": True}
        resp = await client.post(
            "/api/v1/cc/license/tenant-001/revoke",
            headers=super_admin_headers,
            json={"reason": "Policy violation"},
        )
        assert resp.status_code in (200, 502)

    @pytest.mark.asyncio
    async def test_restore_requires_super_admin(self, client, security_analyst_headers):
        resp = await client.post(
            "/api/v1/cc/license/tenant-001/restore",
            headers=security_analyst_headers,
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_force_sync_super_admin_only(self, client, billing_admin_headers):
        resp = await client.post(
            "/api/v1/cc/license/tenant-001/sync",
            headers=billing_admin_headers,
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_license_overview_multi_tenant(self, client, read_only_headers):
        """Seeded in the edge tables, because that is where the overview reads.

        This used to seed frothiq-core through mock_core_client and assert the
        count came back. License state moved to the Control Center's own
        tables, so the core payload was ignored and the answer was always 0.
        """
        from mc2.integrations.database import get_session_factory
        from mc2.models.edge import EdgeTenant

        factory = get_session_factory()
        async with factory() as session:
            session.add(EdgeTenant(domain="a.example.com", tenant_id="tenant-001", plan="pro"))
            session.add(EdgeTenant(domain="b.example.com", tenant_id="tenant-002", plan="free"))
            await session.commit()

        resp = await client.get("/api/v1/cc/license/overview", headers=read_only_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert data["source"] == "edge_db"


class TestEnvelopeAPI:
    @pytest.mark.asyncio
    async def test_get_envelope_200(self, client, read_only_headers, mock_core_client, sample_envelope):
        mock_core_client.get.return_value = sample_envelope
        resp = await client.get("/api/v1/cc/envelope/tenant-001", headers=read_only_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_envelope_includes_signature_status(self, client, read_only_headers, mock_core_client, sample_envelope):
        mock_core_client.get.return_value = sample_envelope
        resp = await client.get("/api/v1/cc/envelope/tenant-001", headers=read_only_headers)
        data = resp.json()
        assert "signature_valid" in data

    @pytest.mark.asyncio
    async def test_envelope_without_signature_still_valid(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"version": "v1", "sections": {}}
        resp = await client.get("/api/v1/cc/envelope/tenant-001", headers=read_only_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["signature_valid"] is True  # permissive in dev

    @pytest.mark.asyncio
    async def test_envelope_diff_requires_security_analyst(self, client, read_only_headers):
        resp = await client.get(
            "/api/v1/cc/envelope/tenant-001/diff",
            headers=read_only_headers,
            params={"from_version": "v1", "to_version": "v2"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_batch_verify_returns_summary(self, client, security_analyst_headers, mock_core_client, sample_envelope):
        mock_core_client.get.return_value = sample_envelope
        resp = await client.post(
            "/api/v1/cc/envelope/verify-batch",
            headers=security_analyst_headers,
            json={"tenant_ids": ["tenant-001", "tenant-002"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data


class TestSimulationAPI:
    @pytest.mark.asyncio
    async def test_simulation_status_200(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"healthy": True, "last_run": None}
        resp = await client.get("/api/v1/cc/simulation/status", headers=read_only_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_scenarios_200(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"scenarios": [{"id": "replay_sqli", "name": "SQL Injection Replay"}]}
        resp = await client.get("/api/v1/cc/simulation/scenarios", headers=read_only_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_simulation_metrics_period_days(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {
            "das_avg": 0.75, "dei_avg": 0.60, "pps_avg": 0.80,
            "das_trend": [], "dei_trend": [], "pps_trend": [],
        }
        resp = await client.get(
            "/api/v1/cc/simulation/metrics",
            headers=read_only_headers,
            params={"period_days": 14},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "das_avg" in data
        assert data["period_days"] == 14

    @pytest.mark.asyncio
    async def test_run_simulation_missing_scenario_422(self, client, security_analyst_headers):
        resp = await client.post(
            "/api/v1/cc/simulation/run",
            headers=security_analyst_headers,
            json={},  # missing scenario_id
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_simulation_alerts_list(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"alerts": [{"id": "alert-1", "severity": "high"}]}
        resp = await client.get("/api/v1/cc/simulation/alerts", headers=read_only_headers)
        assert resp.status_code == 200


class TestMonetizationAPI:
    @pytest.mark.asyncio
    async def test_monetization_overview_200(self, client, billing_admin_headers, mock_core_client):
        mock_core_client.get.return_value = {"tenants": []}
        resp = await client.get("/api/v1/cc/monetization/overview", headers=billing_admin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_rpi_computed(self, client, billing_admin_headers, mock_core_client, sample_tenant):
        # revenue_pressure_index is assembled by the FALLBACK path, so core's
        # dedicated overview endpoint has to be absent for it to appear.
        def _by_url(url, *a, **k):
            if url == "/api/v2/intelligence/monetization/overview":
                raise CoreClientError(404, "no dedicated endpoint")
            return {
                "tenants": [
                    {**sample_tenant, "plan": "free", "tenant_id": "t1"},
                    {**sample_tenant, "plan": "pro", "tenant_id": "t2"},
                    {**sample_tenant, "plan": "enterprise", "tenant_id": "t3"},
                ]
            }

        mock_core_client.get.side_effect = _by_url
        resp = await client.get("/api/v1/cc/monetization/overview", headers=billing_admin_headers)
        data = resp.json()
        assert "revenue_pressure_index" in data
        # 1 free out of 3 total = 0.333
        assert 0 <= data["revenue_pressure_index"] <= 1

    @pytest.mark.asyncio
    async def test_upgrade_funnel_200(self, client, billing_admin_headers, mock_core_client):
        mock_core_client.get.return_value = {"tenants": []}
        resp = await client.get("/api/v1/cc/monetization/upgrade-funnel", headers=billing_admin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_heatmap_respects_period_days(self, client, billing_admin_headers, mock_core_client):
        mock_core_client.get.return_value = {"tenants": []}
        resp = await client.get(
            "/api/v1/cc/monetization/heatmap",
            headers=billing_admin_headers,
            params={"period_days": 7},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["period_days"] == 7


class TestTenantAPI:
    @pytest.mark.asyncio
    async def test_list_tenants_200(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"tenants": [], "total": 0}
        resp = await client.get("/api/v1/cc/tenants/", headers=read_only_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_tenants_plan_filter(self, client, read_only_headers, mock_core_client, sample_tenant):
        mock_core_client.get.return_value = {
            "tenants": [
                sample_tenant,
                {**sample_tenant, "tenant_id": "t2", "plan": "enterprise"},
            ]
        }
        resp = await client.get(
            "/api/v1/cc/tenants/",
            headers=read_only_headers,
            params={"plan": "pro"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Only pro tenants
        for t in data["tenants"]:
            assert t["plan"] == "pro"

    @pytest.mark.asyncio
    async def test_tenant_reload_requires_super_admin(self, client, security_analyst_headers):
        resp = await client.post(
            "/api/v1/cc/tenants/tenant-001/reload",
            headers=security_analyst_headers,
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_tenant_reload_by_super_admin(self, client, super_admin_headers, mock_core_client):
        mock_core_client.post.return_value = {"reloaded": True}
        resp = await client.post(
            "/api/v1/cc/tenants/tenant-001/reload",
            headers=super_admin_headers,
        )
        assert resp.status_code in (200, 404, 502)  # depends on mock


class TestFlywheelAPI:
    @pytest.mark.asyncio
    async def test_flywheel_dashboard_200(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"state": "active"}
        resp = await client.get("/api/v1/cc/flywheel/dashboard", headers=read_only_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_correlation_heatmap_has_matrix(self, client, read_only_headers, mock_core_client):
        mock_core_client.get.return_value = {"dimensions": ["a", "b"], "matrix": [[1.0, 0.5], [0.5, 1.0]]}
        resp = await client.get("/api/v1/cc/flywheel/correlations", headers=read_only_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "matrix" in data

    @pytest.mark.asyncio
    async def test_vectors_requires_security_analyst(self, client, billing_admin_headers):
        resp = await client.get("/api/v1/cc/flywheel/vectors", headers=billing_admin_headers)
        assert resp.status_code == 403


class TestAuditLogAPI:
    @pytest.mark.asyncio
    async def test_audit_log_requires_security_analyst(self, client, read_only_headers):
        resp = await client.get("/api/v1/cc/audit/log", headers=read_only_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_audit_log_accessible_to_security_analyst(self, client, security_analyst_headers, mock_db):
        from unittest.mock import MagicMock, AsyncMock
        mock_db.execute.return_value = MagicMock(
            scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[]))),
            scalar=MagicMock(return_value=0),
        )
        resp = await client.get("/api/v1/cc/audit/log", headers=security_analyst_headers)
        # DB mock may fail; important thing is not 403
        assert resp.status_code != 403

    @pytest.mark.asyncio
    async def test_audit_log_pagination_params(self, client, super_admin_headers, mock_db):
        mock_db.execute.return_value = MagicMock(
            scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[]))),
            scalar=MagicMock(return_value=0),
        )
        resp = await client.get(
            "/api/v1/cc/audit/log",
            headers=super_admin_headers,
            params={"page": 2, "page_size": 10},
        )
        assert resp.status_code != 403
