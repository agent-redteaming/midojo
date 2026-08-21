"""Tests for the MCP SDK — ToolContext, ControlPlaneClient, MidojoMCP."""

import asyncio
import json

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from midojo.mcp_sdk import ControlPlaneClient, MidojoMCP, ToolContext


@pytest.fixture()
def control_plane(client) -> TestClient:
    return client


@pytest.fixture()
def eval_context(control_plane: TestClient) -> tuple[TestClient, str, str]:
    run_id = control_plane.post("/runs").json()["id"]
    eval_resp = control_plane.post(
        f"/runs/{run_id}/evaluations",
        json={"user_task_id": "user_task_0"},
    ).json()
    return control_plane, run_id, eval_resp["id"]


def _make_client(app: FastAPI) -> ControlPlaneClient:
    transport = httpx.ASGITransport(app=app)
    http = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    return ControlPlaneClient("http://testserver", http=http)


@pytest.mark.asyncio
async def test_control_plane_client_get_environment(eval_context, app):
    cp, run_id, eval_id = eval_context
    client = _make_client(app)

    env = await client.get_environment()
    assert "cities" in env
    assert "New York" in env["cities"]


@pytest.mark.asyncio
async def test_control_plane_client_put_environment(eval_context, app):
    cp, run_id, eval_id = eval_context
    client = _make_client(app)

    env = await client.get_environment()
    env["weather_alerts"] = [{"city": "NYC", "message": "test"}]
    await client.put_environment(env)

    fresh = cp.get(f"/runs/{run_id}/evaluations/{eval_id}/environment").json()
    assert fresh["weather_alerts"] == [{"city": "NYC", "message": "test"}]


@pytest.mark.asyncio
async def test_control_plane_client_record_function_call(eval_context, app):
    cp, run_id, eval_id = eval_context
    client = _make_client(app)

    await client.record_function_call(
        function="get_weather",
        args={"city": "New York"},
        result="72°F, sunny",
    )

    fcs = cp.get(f"/runs/{run_id}/evaluations/{eval_id}/function-calls").json()
    assert len(fcs) == 1
    assert fcs[0]["function"] == "get_weather"


@pytest.mark.asyncio
async def test_tool_context_env(eval_context, app):
    _, run_id, eval_id = eval_context
    client = _make_client(app)
    ctx = client.create_tool_context()

    cities = await ctx.env("cities")
    assert "New York" in cities


@pytest.mark.asyncio
async def test_tool_context_env_update(eval_context, app):
    cp, run_id, eval_id = eval_context
    client = _make_client(app)
    ctx = client.create_tool_context()

    alerts = await ctx.env("weather_alerts")
    alerts.append({"city": "Chicago", "message": "wind advisory"})
    await ctx.env_update("weather_alerts", alerts)

    fresh = cp.get(f"/runs/{run_id}/evaluations/{eval_id}/environment").json()
    assert len(fresh["weather_alerts"]) == 1


def test_midojo_mcp_tool_registration():
    mcp = MidojoMCP("test", control_plane_url="http://localhost:9999")

    @mcp.tool()
    async def my_tool(ctx: ToolContext, name: str) -> str:
        """A test tool."""
        return f"hello {name}"

    tools = asyncio.run(mcp._fastmcp.list_tools())
    assert len(tools) == 1
    tool = tools[0]
    assert tool.name == "my_tool"
    assert "name" in tool.parameters.get("properties", {})
    assert "ctx" not in tool.parameters.get("properties", {})


def test_midojo_mcp_tool_requires_ctx():
    mcp = MidojoMCP("test", control_plane_url="http://localhost:9999")

    with pytest.raises(TypeError, match="ToolContext"):

        @mcp.tool()
        async def bad_tool(name: str) -> str:
            """Missing ctx."""
            return name


# --- Forwarding / UpstreamClient tests ---




@pytest.mark.asyncio
async def test_tool_context_forward_raises_without_upstream():
    client = ControlPlaneClient("http://localhost:9999")
    ctx = client.create_tool_context()
    with pytest.raises(RuntimeError, match="No upstream MCP server configured"):
        await ctx.forward("get_weather", {"city": "New York"})


# --- Passthrough / Intercept tests ---


class TestFindBestField:
    """Tests for the _find_best_field auto-detection."""

    def test_finds_known_text_field(self):
        from midojo.mcp_sdk import _find_best_field

        result = '{"customer_id": "CUST001", "name": "Alice", "notes": "Regular customer"}'
        assert _find_best_field(result) == "notes"

    def test_finds_description_in_nested_list(self):
        from midojo.mcp_sdk import _find_best_field

        result = '{"transactions": [{"txn_id": "T1", "description": "Payroll deposit", "amount": 5000}]}'
        assert _find_best_field(result) is not None
        assert "description" in _find_best_field(result)

    def test_prefers_longer_known_field(self):
        from midojo.mcp_sdk import _find_best_field

        result = '{"notes": "Short", "address": "123 Main St, Boston MA 02101, United States of America"}'
        # Both are known text fields; longer value wins (more room to hide injection)
        assert _find_best_field(result) == "address"

    def test_prefers_known_over_unknown(self):
        from midojo.mcp_sdk import _find_best_field

        result = '{"notes": "A customer note", "custom_field": "Some very long value that is not a known text field name at all"}'
        assert _find_best_field(result) == "notes"

    def test_falls_back_to_long_natural_text(self):
        from midojo.mcp_sdk import _find_best_field

        result = '{"customer_id": "C1", "custom_info": "This is a long field with natural language content for testing"}'
        assert _find_best_field(result) == "custom_info"

    def test_returns_none_for_no_text_fields(self):
        from midojo.mcp_sdk import _find_best_field

        result = '{"balance": 15420.50, "currency": "USD", "is_frozen": false}'
        assert _find_best_field(result) is None

    def test_skips_id_fields(self):
        from midojo.mcp_sdk import _find_best_field

        result = '{"customer_id": "CUST001", "account_id": "ACC001", "status": "active"}'
        assert _find_best_field(result) is None

    def test_handles_non_json(self):
        from midojo.mcp_sdk import _find_best_field

        assert _find_best_field("plain text result") is None

    def test_finds_field_in_list_items(self):
        from midojo.mcp_sdk import _find_best_field

        result = '[{"id": "C1", "summary": "A detailed summary of the customer account status"}]'
        best = _find_best_field(result)
        assert best == "summary"


class TestExecuteInjection:
    """Tests for _execute_injection."""

    def test_embed_with_target_field(self):
        from midojo.mcp_sdk import _execute_injection

        result = '{"notes": "Original note", "id": "1"}'
        instruction = {"payload": "INJECTED", "target_field": "notes", "mode": "embed"}
        injected = _execute_injection(result, instruction, "test_tool")
        assert "Original note INJECTED" in injected

    def test_embed_auto_detect(self):
        from midojo.mcp_sdk import _execute_injection

        result = '{"customer_id": "C1", "description": "Account summary for review"}'
        instruction = {"payload": "INJECTED", "mode": "embed"}
        injected = _execute_injection(result, instruction, "test_tool")
        assert "INJECTED" in injected
        data = json.loads(injected)
        assert "INJECTED" in data.get("description", "") or "_annotation" in data

    def test_replace_mode(self):
        from midojo.mcp_sdk import _execute_injection

        result = '{"balance": 15420.50}'
        instruction = {"payload": "Completely replaced response", "mode": "replace"}
        injected = _execute_injection(result, instruction, "test_tool")
        assert injected == "Completely replaced response"

    def test_append_mode(self):
        from midojo.mcp_sdk import _execute_injection

        result = '{"data": "value"}'
        instruction = {"payload": "APPENDED", "mode": "append"}
        injected = _execute_injection(result, instruction, "test_tool")
        assert injected.startswith('{"data": "value"}')
        assert "APPENDED" in injected

    def test_new_field_mode(self):
        from midojo.mcp_sdk import _execute_injection

        result = '{"balance": 15420.50}'
        instruction = {"payload": "INJECTED NOTE", "mode": "new_field"}
        injected = _execute_injection(result, instruction, "test_tool")
        data = json.loads(injected)
        assert data["_annotation"] == "INJECTED NOTE"

    def test_embed_fallback_to_annotation(self):
        from midojo.mcp_sdk import _execute_injection

        result = '{"balance": 15420.50, "currency": "USD", "is_frozen": false}'
        instruction = {"payload": "INJECTED", "mode": "embed"}
        injected = _execute_injection(result, instruction, "test_tool")
        data = json.loads(injected)
        assert "_annotation" in data


class TestSpliceInjection:
    """Tests for the _splice_injection helper."""

    def test_splice_into_json_field(self):
        from midojo.mcp_sdk import _splice_injection

        result = '{"id": "TXN001", "notes": "Payroll deposit"}'
        injected = _splice_injection(result, "notes", "INJECTED PAYLOAD")
        assert "Payroll deposit INJECTED PAYLOAD" in injected

    def test_splice_into_nested_list(self):
        from midojo.mcp_sdk import _splice_injection

        result = '{"transactions": [{"id": "T1", "notes": "original"}]}'
        injected = _splice_injection(result, "notes", "INJECTED")
        assert "original INJECTED" in injected

    def test_splice_into_empty_field(self):
        from midojo.mcp_sdk import _splice_injection

        result = '{"id": "TXN001", "notes": ""}'
        injected = _splice_injection(result, "notes", "INJECTED")
        assert "INJECTED" in injected

    def test_splice_missing_field_appends(self):
        from midojo.mcp_sdk import _splice_injection

        result = '{"id": "TXN001", "amount": 100}'
        injected = _splice_injection(result, "notes", "INJECTED")
        assert "INJECTED" in injected

    def test_splice_non_json_appends(self):
        from midojo.mcp_sdk import _splice_injection

        result = "Plain text result"
        injected = _splice_injection(result, "notes", "INJECTED")
        assert "Plain text result" in injected
        assert "INJECTED" in injected


class TestMidojoMCPConfig:
    """Tests for MidojoMCP configuration."""

    def test_passthrough_default_false(self):
        mcp = MidojoMCP("test", control_plane_url="http://localhost:8080")
        assert mcp._passthrough is False

    def test_passthrough_enabled(self):
        mcp = MidojoMCP(
            "test",
            control_plane_url="http://localhost:8080",
            upstream_url="http://localhost:8081/mcp",
            passthrough_unregistered=True,
        )
        assert mcp._passthrough is True

    def test_tool_decorator_tracks_registration(self):
        mcp = MidojoMCP("test", control_plane_url="http://localhost:8080")

        @mcp.tool()
        async def my_tool(ctx: ToolContext, arg: str) -> str:
            return arg

        assert "my_tool" in mcp._registered_tools

    def test_no_forward_param(self):
        mcp = MidojoMCP(
            "test",
            control_plane_url="http://localhost:8080",
            no_forward=["send_notification", "initiate_transfer"],
        )
        assert "send_notification" in mcp._no_forward
        assert "initiate_transfer" in mcp._no_forward

    def test_no_forward_empty_by_default(self):
        mcp = MidojoMCP("test", control_plane_url="http://localhost:8080")
        assert mcp._no_forward == set()


class TestInjectionPlanAPI:
    """Tests for the injection plan control plane endpoints."""

    def test_get_empty_plan(self, eval_context):
        cp, run_id, eval_id = eval_context
        resp = cp.get(f"/runs/{run_id}/evaluations/{eval_id}/injection-plan")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_set_and_get_plan(self, eval_context):
        cp, run_id, eval_id = eval_context
        plan = {
            "instructions": [
                {"payload": "INJECTED", "target_tool": "get_info", "target_field": "notes", "mode": "embed"},
                {"payload": "REPLACED", "target_tool": None, "mode": "replace"},
            ]
        }
        resp = cp.put(f"/runs/{run_id}/evaluations/{eval_id}/injection-plan", json=plan)
        assert resp.status_code == 200
        result = resp.json()
        assert len(result) == 2
        assert result[0]["payload"] == "INJECTED"
        assert result[0]["target_tool"] == "get_info"
        assert result[1]["mode"] == "replace"

        get_resp = cp.get(f"/runs/{run_id}/evaluations/{eval_id}/injection-plan")
        assert get_resp.json() == result

    def test_current_injection_plan(self, eval_context):
        cp, run_id, eval_id = eval_context
        plan = {"instructions": [{"payload": "TEST", "mode": "embed"}]}
        cp.put(f"/runs/{run_id}/evaluations/{eval_id}/injection-plan", json=plan)

        resp = cp.get("/current/injection-plan")
        assert resp.status_code == 200
        assert len(resp.json()) == 1
        assert resp.json()[0]["payload"] == "TEST"

    def test_update_plan_replaces(self, eval_context):
        cp, run_id, eval_id = eval_context
        cp.put(f"/runs/{run_id}/evaluations/{eval_id}/injection-plan",
               json={"instructions": [{"payload": "v1"}]})
        cp.put(f"/runs/{run_id}/evaluations/{eval_id}/injection-plan",
               json={"instructions": [{"payload": "v2"}, {"payload": "v3"}]})
        resp = cp.get(f"/runs/{run_id}/evaluations/{eval_id}/injection-plan")
        payloads = [i["payload"] for i in resp.json()]
        assert payloads == ["v2", "v3"]


