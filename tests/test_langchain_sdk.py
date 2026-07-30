"""Tests for the LangChain SDK — MidojoToolkit, tool wrapping, recording."""

import httpx
import pytest
from fastapi import FastAPI
from langchain_core.tools import tool

from midojo.langchain_sdk import MidojoToolkit
from midojo.sdk import ControlPlaneClient, ToolContext

# --- Fixtures ---


@pytest.fixture()
def eval_context(client):
    run_id = client.post("/runs").json()["id"]
    eval_resp = client.post(
        f"/runs/{run_id}/evaluations",
        json={"user_task_id": "user_task_0"},
    ).json()
    return client, run_id, eval_resp["id"]


def _make_client(app: FastAPI) -> ControlPlaneClient:
    transport = httpx.ASGITransport(app=app)
    http = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    return ControlPlaneClient("http://testserver", http=http)


# --- Real tools for testing ---


@tool
def greet(name: str) -> str:
    """Say hello."""
    return f"Hello, {name}!"


@tool
def add(a: int, b: int) -> str:
    """Add two numbers."""
    return str(a + b)


# --- Registration tests ---


def test_toolkit_tool_registration():
    toolkit = MidojoToolkit(control_plane_url="http://localhost:9999")

    @toolkit.tool()
    async def my_tool(ctx: ToolContext, name: str) -> str:
        """A test tool."""
        return f"hello {name}"

    tools = toolkit.get_tools()
    assert len(tools) == 1
    t = tools[0]
    assert t.name == "my_tool"
    schema = t.args
    assert "name" in schema
    assert "ctx" not in schema


def test_toolkit_requires_ctx():
    toolkit = MidojoToolkit(control_plane_url="http://localhost:9999")

    with pytest.raises(TypeError, match="ToolContext"):

        @toolkit.tool()
        async def bad_tool(name: str) -> str:
            """Missing ctx."""
            return name


def test_toolkit_multiple_tools():
    toolkit = MidojoToolkit(control_plane_url="http://localhost:9999")

    @toolkit.tool()
    async def tool_a(ctx: ToolContext, x: int) -> str:
        """Tool A."""
        return str(x)

    @toolkit.tool()
    async def tool_b(ctx: ToolContext, y: str) -> str:
        """Tool B."""
        return y

    tools = toolkit.get_tools()
    assert len(tools) == 2
    names = {t.name for t in tools}
    assert names == {"tool_a", "tool_b"}


# --- Forward tests ---


@pytest.mark.asyncio
async def test_toolkit_forward_calls_real_tool():
    toolkit = MidojoToolkit(
        control_plane_url="http://localhost:9999",
        real_tools=[greet],
    )
    result = await toolkit._lc_forward("greet", {"name": "World"})
    assert result == "Hello, World!"


@pytest.mark.asyncio
async def test_toolkit_forward_raises_for_unknown_tool():
    toolkit = MidojoToolkit(
        control_plane_url="http://localhost:9999",
        real_tools=[greet],
    )
    with pytest.raises(RuntimeError, match="No real tool named 'unknown'"):
        await toolkit._lc_forward("unknown", {})


@pytest.mark.asyncio
async def test_toolkit_forward_raises_without_real_tools(eval_context, app):
    # A live control plane is required: recording now fails loudly, so a dead
    # URL would mask the RuntimeError we're actually asserting.
    client = _make_client(app)

    toolkit = MidojoToolkit.__new__(MidojoToolkit)
    toolkit._client = client
    toolkit._real_tools = {}
    toolkit._tools = []

    @toolkit.tool()
    async def my_tool(ctx: ToolContext, x: str) -> str:
        """Test."""
        return await ctx.forward("greet", {"name": x})

    tools = toolkit.get_tools()
    with pytest.raises(RuntimeError, match="No upstream configured"):
        await tools[0].ainvoke({"x": "test"})


# --- Recording tests ---


@pytest.mark.asyncio
async def test_toolkit_records_function_call(eval_context, app):
    cp, run_id, eval_id = eval_context
    client = _make_client(app)

    toolkit = MidojoToolkit.__new__(MidojoToolkit)
    toolkit._client = client
    toolkit._real_tools = {}
    toolkit._tools = []

    @toolkit.tool()
    async def my_tool(ctx: ToolContext, city: str) -> str:
        """Get info."""
        return f"info for {city}"

    tools = toolkit.get_tools()
    result = await tools[0].ainvoke({"city": "NYC"})
    assert result == "info for NYC"

    fcs = cp.get(f"/runs/{run_id}/evaluations/{eval_id}/function-calls").json()
    assert len(fcs) == 1
    assert fcs[0]["function"] == "my_tool"
    assert fcs[0]["args"] == {"city": "NYC"}
    assert fcs[0]["result"] == "info for NYC"
    assert fcs[0]["error"] is None


@pytest.mark.asyncio
async def test_toolkit_records_errors(eval_context, app):
    cp, run_id, eval_id = eval_context
    client = _make_client(app)

    toolkit = MidojoToolkit.__new__(MidojoToolkit)
    toolkit._client = client
    toolkit._real_tools = {}
    toolkit._tools = []

    @toolkit.tool()
    async def failing_tool(ctx: ToolContext, x: str) -> str:
        """Will fail."""
        raise ValueError("boom")

    tools = toolkit.get_tools()
    with pytest.raises(ValueError, match="boom"):
        await tools[0].ainvoke({"x": "test"})

    fcs = cp.get(f"/runs/{run_id}/evaluations/{eval_id}/function-calls").json()
    assert len(fcs) == 1
    assert fcs[0]["function"] == "failing_tool"
    assert fcs[0]["error"] == "boom"


# --- Integration with env ---


@pytest.mark.asyncio
async def test_toolkit_tool_reads_env(eval_context, app):
    cp, run_id, eval_id = eval_context
    client = _make_client(app)

    toolkit = MidojoToolkit.__new__(MidojoToolkit)
    toolkit._client = client
    toolkit._real_tools = {}
    toolkit._tools = []

    @toolkit.tool()
    async def read_env(ctx: ToolContext) -> str:
        """Read from env."""
        cities = await ctx.env("cities")
        return str(list(cities.keys()))

    tools = toolkit.get_tools()
    result = await tools[0].ainvoke({})
    assert "New York" in result
