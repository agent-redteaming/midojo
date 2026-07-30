"""Shared SDK core for midojo framework integrations.

Provides ``ControlPlaneClient`` and ``ToolContext`` — the framework-agnostic
primitives that every midojo SDK (MCP, LangChain, …) builds on.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx

ForwardFn = Callable[[str, dict[str, Any]], Awaitable[str]]


class ToolContext:
    """Async access to the evaluation environment on the control plane."""

    def __init__(
        self,
        client: ControlPlaneClient,
        *,
        forward_fn: ForwardFn | None = None,
    ) -> None:
        self._client = client
        self._forward_fn = forward_fn

    async def env(self, field: str) -> Any:
        environment = await self._client.get_environment()
        return environment[field]

    async def env_update(self, field: str, value: Any) -> None:
        environment = await self._client.get_environment()
        environment[field] = value
        await self._client.put_environment(environment)

    async def forward(self, tool_name: str, args: dict[str, Any]) -> str:
        """Forward a tool call to the upstream implementation."""
        if self._forward_fn is None:
            raise RuntimeError(
                "No upstream configured. Pass real_tools (LangChain) or --upstream-url (MCP) to enable forwarding."
            )
        return await self._forward_fn(tool_name, args)


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

    def create_tool_context(self, *, forward_fn: ForwardFn | None = None) -> ToolContext:
        return ToolContext(self, forward_fn=forward_fn)
