"""Tests for the MCP SDK — ToolContext, ControlPlaneClient, MidojoMCP."""

import asyncio

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


