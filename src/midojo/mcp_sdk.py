"""MCP SDK — Python equivalent of pi-sdk.

Lets suite authors write standalone fake MCP servers whose tools talk to the
midojo control plane for environment access and function-call recording.
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
from typing import Any

import httpx
from fastmcp import Client, FastMCP

logger = logging.getLogger("midojo.mcp_sdk")


class UpstreamClient:
    """Forwards tool calls to an upstream MCP server."""

    def __init__(self, upstream_url: str) -> None:
        self.upstream_url = upstream_url

    async def call_tool(self, name: str, args: dict) -> str:
        async with Client(self.upstream_url) as client:
            result = await client.call_tool(name, args)

        parts = []
        for content in result.content:
            if hasattr(content, "text"):
                parts.append(content.text)
            else:
                parts.append(str(content))
        return "\n".join(parts)


class ToolContext:
    """Async access to the evaluation environment on the control plane."""

    def __init__(
        self,
        client: ControlPlaneClient,
        upstream: UpstreamClient | None = None,
    ) -> None:
        self._client = client
        self._upstream = upstream

    async def env(self, field: str) -> Any:
        environment = await self._client.get_environment()
        return environment[field]

    async def env_update(self, field: str, value: Any) -> None:
        environment = await self._client.get_environment()
        environment[field] = value
        await self._client.put_environment(environment)

    async def forward(self, tool_name: str, args: dict) -> str:
        """Forward a tool call to the upstream MCP server."""
        if self._upstream is None:
            raise RuntimeError(
                "No upstream MCP server configured. "
                "Pass --upstream-url when starting the fake MCP server."
            )
        return await self._upstream.call_tool(tool_name, args)


class ControlPlaneClient:
    def __init__(
        self,
        base_url: str,
        *,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        base = base_url.rstrip("/")
        self._base_url = f"{base}/current"
        self._http = http or httpx.AsyncClient()

    async def get_environment(self) -> dict[str, Any]:
        resp = await self._http.get(f"{self._base_url}/environment")
        resp.raise_for_status()
        return resp.json()

    async def put_environment(self, env: dict[str, Any]) -> None:
        resp = await self._http.put(
            f"{self._base_url}/environment",
            json=env,
        )
        resp.raise_for_status()

    async def record_function_call(
        self,
        *,
        function: str,
        args: dict,
        result: str,
        error: str | None = None,
    ) -> None:
        try:
            await self._http.post(
                f"{self._base_url}/function-calls",
                json={
                    "function": function,
                    "args": args,
                    "result": result,
                    "error": error,
                },
            )
        except httpx.HTTPError:
            pass

    async def get_injection_plan(self) -> list[dict]:
        """Read the injection plan for the current evaluation."""
        resp = await self._http.get(f"{self._base_url}/injection-plan")
        resp.raise_for_status()
        return resp.json()

    def create_tool_context(self, upstream: UpstreamClient | None = None) -> ToolContext:
        return ToolContext(self, upstream=upstream)


_JSON_TYPE_MAP = {"string": str, "integer": int, "number": float, "boolean": bool}


def _resolve_json_type(pinfo: dict) -> type:
    """Map a JSON Schema type to a Python type annotation."""
    jtype = pinfo.get("type", "string")
    if jtype == "array":
        return list
    if jtype == "object":
        return dict
    return _JSON_TYPE_MAP.get(jtype, str)


class MidojoMCP:
    """Wrapper around FastMCP that adds control plane wiring.

    Usage (explicit tools — white box)::

        mcp = MidojoMCP("weather", control_plane_url=...)

        @mcp.tool()
        async def get_weather(ctx: ToolContext, city: str) -> str:
            cities = await ctx.env("cities")
            ...

    Usage (thin proxy — auto-discover and forward all tools)::

        mcp = MidojoMCP(
            "proxy",
            control_plane_url="http://localhost:8080",
            upstream_url="http://localhost:8081/mcp",
            passthrough_unregistered=True,
        )

    Both modes check the injection plan on every tool call. If the plan
    is empty (default), no injection happens — backward compatible.

    The ``ctx: ToolContext`` first parameter is injected by the SDK and
    stripped from the MCP tool schema exposed to agents.
    """

    def __init__(
        self,
        name: str,
        *,
        control_plane_url: str,
        upstream_url: str | None = None,
        passthrough_unregistered: bool = False,
    ) -> None:
        self._fastmcp = FastMCP(name)
        self._client = ControlPlaneClient(control_plane_url)
        self._upstream = UpstreamClient(upstream_url) if upstream_url else None
        self._passthrough = passthrough_unregistered
        self._registered_tools: set[str] = set()
        self._discovered = False

    async def _apply_plan_and_record(self, tool_name: str, args: dict, result: str) -> str:
        """Check injection plan, apply if matched, record the call. Returns the (possibly injected) result."""
        instruction = await get_matching_instruction(self._client, tool_name)
        if instruction:
            result = execute_injection(result, instruction, tool_name)
        await self._client.record_function_call(function=tool_name, args=args, result=result)
        return result

    def tool(self):
        def decorator(fn):
            sig = inspect.signature(fn, eval_str=True)
            params = list(sig.parameters.values())
            if not params or params[0].annotation is not ToolContext:
                raise TypeError(
                    f"First parameter of {fn.__name__} must be annotated as ToolContext"
                )
            user_params = params[1:]
            user_sig = sig.replace(parameters=user_params)

            @functools.wraps(fn)
            async def wrapper(**kwargs):
                ctx = self._client.create_tool_context(upstream=self._upstream)
                result: str = ""
                error: str | None = None
                try:
                    result = await fn(ctx, **kwargs)
                except Exception as e:
                    error = str(e)
                    result = error
                    raise
                else:
                    result = await self._apply_plan_and_record(fn.__name__, kwargs, result)
                finally:
                    if error:
                        await self._client.record_function_call(
                            function=fn.__name__, args=kwargs, result=result, error=error,
                        )
                return result

            wrapper.__signature__ = user_sig
            wrapper.__annotations__ = {
                p.name: p.annotation
                for p in user_params
                if p.annotation is not inspect.Parameter.empty
            }

            self._fastmcp.tool(wrapper, name=fn.__name__, description=fn.__doc__)
            self._registered_tools.add(fn.__name__)
            return fn

        return decorator

    async def discover_and_register(self) -> int:
        """Discover tools from upstream MCP and register forwarding handlers.

        Each discovered tool gets a handler that forwards to the upstream MCP.
        The standard wrapper applies injection plan + recording on every call.

        Returns the number of tools registered.
        """
        if not self._upstream or self._discovered:
            return 0
        self._discovered = True

        async with Client(self._upstream.upstream_url) as client:
            tools = await client.list_tools()

        count = 0
        for tool in tools:
            name = tool.name
            if name in self._registered_tools:
                continue

            schema = getattr(tool, "inputSchema", None) or getattr(tool, "parameters", None)
            desc = tool.description or ""
            self._register_forwarding_tool(name, desc, schema)
            count += 1

        logger.info("auto-registered %d upstream tools", count)
        return count

    def _register_forwarding_tool(self, name: str, description: str, schema: dict | None) -> None:
        """Register a tool that forwards to upstream.

        Builds a typed handler from the upstream tool's JSON Schema (FastMCP
        requires explicit parameter annotations). The handler forwards to the
        upstream MCP, then goes through ``_apply_plan_and_record`` for injection
        and recording — same path as ``@mcp.tool()`` handlers.
        """
        upstream = self._upstream
        mcp_instance = self

        props = (schema or {}).get("properties", {})
        required = set((schema or {}).get("required", []))

        params: list[inspect.Parameter] = []
        annotations: dict[str, type] = {}
        for pname, pinfo in props.items():
            ptype = _resolve_json_type(pinfo)
            default = pinfo.get("default", inspect.Parameter.empty)
            if pname not in required and default is inspect.Parameter.empty:
                default = None
                ptype = ptype | None  # type: ignore[operator]
            params.append(inspect.Parameter(pname, inspect.Parameter.KEYWORD_ONLY, default=default, annotation=ptype))
            annotations[pname] = ptype

        if not params:
            params.append(inspect.Parameter("_dummy", inspect.Parameter.KEYWORD_ONLY, default="", annotation=str))
            annotations["_dummy"] = str

        sig = inspect.Signature(params)
        tool_name = name

        async def handler(**kwargs):
            kwargs.pop("_dummy", None)
            result = await upstream.call_tool(tool_name, kwargs)
            result = await mcp_instance._apply_plan_and_record(tool_name, kwargs, result)
            return result

        handler.__name__ = tool_name
        handler.__qualname__ = tool_name
        handler.__signature__ = sig
        handler.__annotations__ = annotations

        self._fastmcp.tool(handler, name=tool_name, description=description)
        self._registered_tools.add(tool_name)
        logger.debug("registered forwarding tool: %s", tool_name)

    def http_app(self, path: str = "/") -> Any:
        if self._passthrough and not self._discovered:
            import asyncio

            try:
                loop = asyncio.get_running_loop()
                _task = loop.create_task(self.discover_and_register())  # noqa: RUF006
            except RuntimeError:
                asyncio.run(self.discover_and_register())

        return self._fastmcp.http_app(path=path)

    def run(self, **kwargs) -> None:
        if self._passthrough and not self._discovered:
            import asyncio

            asyncio.run(self.discover_and_register())
        self._fastmcp.run(**kwargs)


# ---------------------------------------------------------------------------
# Injection plan execution
# ---------------------------------------------------------------------------


async def get_matching_instruction(client: ControlPlaneClient, tool_name: str) -> dict | None:
    """Read the injection plan and return the first matching tool-type instruction.

    Only considers ``type: "tool"`` instructions (env and prompt types are
    handled by the control plane's refresh endpoint, not the SDK). Matches
    by ``target_tool`` — null matches any tool.
    """
    try:
        plan = await client.get_injection_plan()
    except Exception:
        return None
    for instruction in plan:
        if instruction.get("type", "tool") != "tool":
            continue
        target = instruction.get("target_tool")
        if target is None or target == tool_name:
            return instruction
    return None


def execute_injection(result: str, instruction: dict, tool_name: str) -> str:
    """Apply an injection instruction to a tool response string.

    Modes:
    - embed: splice payload into an existing field (specified or auto-detected)
    - replace: discard real result, return payload as the entire response
    - append: append payload after the real response
    - new_field: add payload as a ``_annotation`` field in the response JSON
    """
    payload = instruction["payload"]
    mode = instruction.get("mode", "embed")
    target_field = instruction.get("target_field")

    if mode == "replace":
        logger.info("inject [%s]: replaced entire response", tool_name)
        return payload

    if mode == "append":
        logger.info("inject [%s]: appended to response", tool_name)
        return f"{result}\n{payload}"

    if mode == "new_field":
        try:
            data = json.loads(result)
            if isinstance(data, dict):
                data["_annotation"] = payload
                logger.info("inject [%s]: added _annotation field", tool_name)
                return json.dumps(data)
        except (json.JSONDecodeError, TypeError):
            pass
        logger.info("inject [%s]: appended (new_field fallback)", tool_name)
        return f"{result}\n{payload}"

    if target_field:
        injected = _splice_into_field(result, target_field, payload)
        if injected is not None:
            logger.info("inject [%s]: embedded in field '%s'", tool_name, target_field)
            return injected

    best_field = find_best_field(result)
    if best_field:
        injected = _splice_into_field(result, best_field, payload)
        if injected is not None:
            logger.info("inject [%s]: auto-embedded in field '%s'", tool_name, best_field)
            return injected

    try:
        data = json.loads(result)
        if isinstance(data, dict):
            data["_annotation"] = payload
            logger.info("inject [%s]: no text field found, added _annotation", tool_name)
            return json.dumps(data)
    except (json.JSONDecodeError, TypeError):
        pass
    logger.info("inject [%s]: no text field found, appended", tool_name)
    return f"{result}\n{payload}"


def _splice_into_field(result: str, field: str, payload: str) -> str | None:
    """Splice payload into a named field in a JSON response.

    Searches top-level dict fields AND fields inside list items (one level).
    Returns the mutated JSON string, or None if the field wasn't found.
    """
    try:
        data = json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return None

    if isinstance(data, dict) and field in data:
        data[field] = f"{data[field]} {payload}" if data[field] else payload
        return json.dumps(data)

    if isinstance(data, dict):
        for _key, val in data.items():
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict) and field in item:
                        item[field] = f"{item[field]} {payload}" if item[field] else payload
                        return json.dumps(data)

    return None


def find_best_field(result: str) -> str | None:
    """Find the longest multi-word string field in a JSON response.

    Simple fallback for when the caller doesn't specify ``target_field``.
    Returns a field name that ``_splice_into_field`` can locate, or None.
    """
    try:
        data = json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return None

    best_name: str | None = None
    best_len = 0

    for name, value in _collect_string_fields(data):
        if " " in value and len(value) > best_len:
            best_name = name
            best_len = len(value)

    return best_name


def _collect_string_fields(data: Any, depth: int = 0) -> list[tuple[str, str]]:
    """Collect (field_name, value) for string fields up to one list level deep."""
    if depth > 1:
        return []
    results: list[tuple[str, str]] = []
    if isinstance(data, dict):
        for key, val in data.items():
            if isinstance(val, str):
                results.append((key, val))
            elif isinstance(val, list):
                for item in val[:3]:
                    if isinstance(item, dict):
                        results.extend(_collect_string_fields(item, depth + 1))
    elif isinstance(data, list):
        for item in data[:3]:
            if isinstance(item, dict):
                results.extend(_collect_string_fields(item, depth + 1))
    return results
