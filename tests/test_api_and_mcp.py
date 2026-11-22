"""
test_api_and_mcp.py — Tests for the FastAPI service and WorkBuddy MCP server.

Run: pytest backend/tests/test_api_and_mcp.py -v
"""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.main import app  # noqa: E402
from app import services  # noqa: E402

client = TestClient(app)


class TestFastAPI:
    """FastAPI HTTP service."""

    def test_root(self):
        response = client.get("/")
        assert response.status_code == 200
        assert response.json()["service"] == "customer-master-profiler"
        assert response.json()["docs"] == "/docs"

    def test_health_shape(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "database_configured" in data
        assert "database_connected" in data
        assert "profile_script" in data

    def test_all_routes_registered(self):
        paths = {route.path for route in app.routes if hasattr(route, "path")}
        required = {
            "/health", "/", "/profiler/ingest", "/profiler/pending",
            "/profiler/write", "/profiler/build-master",
            "/profiler/approve-staging", "/profiler/report", "/profiles",
            "/tickets/pending", "/tickets/publish", "/tickets/approve", "/tickets",
            "/auth/login", "/auth/me", "/auth/logout",
            "/mcp/{role}",
        }
        assert required <= paths

    def test_vercel_stateless_mcp_endpoints(self):
        """Stateless JSON-RPC MCP on Vercel exposes 3 tools for profiler and 4 for ticket_agent."""
        res_prof = client.post("/mcp/profiler", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert res_prof.status_code == 200
        prof_tools = {t["name"] for t in res_prof.json()["result"]["tools"]}
        assert len(prof_tools) == 3
        assert "sekre_publish_personalized_ticket" not in prof_tools

        res_tk = client.post("/mcp/ticket_agent", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert res_tk.status_code == 200
        tk_tools = {t["name"] for t in res_tk.json()["result"]["tools"]}
        assert len(tk_tools) == 4
        assert "sekre_publish_personalized_ticket" in tk_tools

    def test_auth_me_requires_token(self):
        response = client.get("/auth/me")
        assert response.status_code == 401

    def test_auth_me_with_valid_jwt(self):
        from app.core.security import create_access_token

        token = create_access_token("owner_rifat", "Rifat")
        response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert response.json()["owner"]["owner_id"] == "owner_rifat"

    def test_ticket_publish_validation(self):
        """Rejects invalid channel or out-of-range confidence via Pydantic."""
        response = client.post(
            "/tickets/publish",
            json={"body_draft": "Halo", "channel": "fax", "confidence": 1.5},
        )
        assert response.status_code == 422

    def test_ticket_approve_validation(self):
        """Rejects invalid decision value."""
        response = client.post(
            "/tickets/approve",
            json={"request_id": "req_001", "decision": "maybe"},
        )
        assert response.status_code == 422

    def test_pending_returns_list(self):
        """Pending returns a JSON list (messages if DB connected, or structured error dict if not)."""
        response = client.get("/profiler/pending?limit=1")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if data:
            assert "message_pk" in data[0] or "status" in data[0]

    def test_write_rejects_non_array(self):
        response = client.post("/profiler/write", json={"results": "not-an-array"})
        assert response.status_code == 422  # Pydantic validation

    def test_ingest_validation(self):
        response = client.post("/profiler/ingest", json={"source": "invalid"})
        assert response.status_code == 422

    def test_report_endpoint(self):
        response = client.get("/profiler/report?tz_group=WITA")
        assert response.status_code == 200
        assert "markdown" in response.json()


class TestServices:
    """Shared service layer used by both API and MCP."""

    def test_check_health(self):
        result = services.check_health()
        assert result["service"] == "customer-master-profiler"
        assert isinstance(result["database_configured"], bool)

    def test_write_rejects_bad_input(self):
        result = services.write_enrichment("not-a-list")  # type: ignore[arg-type]
        assert result["status"] == "error"

    def test_unknown_command_raises(self):
        with pytest.raises(ValueError):
            services._run_command("does-not-exist")


class TestMCPServer:
    """WorkBuddy MCP server tool definitions (Profiler + Friend's Ticket Bridge)."""

    def test_six_tools_registered(self):
        from app import mcp_server

        tools = mcp_server.mcp._tool_manager.list_tools()
        names = {tool.name for tool in tools}
        assert names == {
            "sekre_run_master_profiler",
            "sekre_query_master_profiles",
            "sekre_approve_master_profile_staging",
            "sekre_fetch_pending_tickets",
            "sekre_publish_personalized_ticket",
            "sekre_approve_ticket_to_outbox",
        }

    def test_tool_functions_callable(self):
        from app import mcp_server

        for name in (
            "sekre_run_master_profiler",
            "sekre_query_master_profiles",
            "sekre_approve_master_profile_staging",
            "sekre_fetch_pending_tickets",
            "sekre_publish_personalized_ticket",
            "sekre_approve_ticket_to_outbox",
        ):
            assert callable(getattr(mcp_server, name))

    def test_run_tool_rejects_unknown_subcommand(self):
        from app.mcp_server import sekre_run_master_profiler

        result = sekre_run_master_profiler(subcommand="bogus")
        assert "error" in result

    def test_write_tool_requires_payloads(self):
        from app.mcp_server import sekre_run_master_profiler

        result = sekre_run_master_profiler(subcommand="write")
        assert "error" in result

    def test_profiler_role_has_no_ticket_tools(self):
        """WorkBuddy #1 (MCP_AGENT_ROLE=profiler) physically cannot see or call ticket tools."""
        from app.mcp_server import build_mcp_server

        server = build_mcp_server("profiler")
        names = {t.name for t in server._tool_manager.list_tools()}
        assert names == {
            "sekre_run_master_profiler",
            "sekre_query_master_profiles",
            "sekre_approve_master_profile_staging",
        }
        assert "sekre_publish_personalized_ticket" not in names
        assert "sekre_approve_ticket_to_outbox" not in names

    def test_ticket_agent_role_has_lookup_and_ticket_tools(self):
        """Friend's WorkBuddy #2 (MCP_AGENT_ROLE=ticket_agent) gets profile lookup + ticket tools only."""
        from app.mcp_server import build_mcp_server

        server = build_mcp_server("ticket_agent")
        names = {t.name for t in server._tool_manager.list_tools()}
        assert names == {
            "sekre_query_master_profiles",
            "sekre_fetch_pending_tickets",
            "sekre_publish_personalized_ticket",
            "sekre_approve_ticket_to_outbox",
        }
        assert "sekre_run_master_profiler" not in names
