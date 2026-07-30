"""LangChain SDK for midojo.

Lets suite authors wrap LangChain tools with control-plane wiring —
same ``@toolkit.tool()`` / ``ToolContext`` pattern as the MCP SDK, but
the wrapped tools are LangChain ``BaseTool`` instances instead of an MCP
server.

Usage::

    from langchain_core.tools import tool
    from midojo.langchain_sdk import MidojoToolkit
    from midojo.sdk import ToolContext

    # 1. Define real tools (or import existing ones)
    @tool
    def get_weather(city: str) -> str:
        \"\"\"Get current weather for a city.\"\"\"
        return f"{city}: 72°F, sunny"

    # 2. Create a toolkit, passing the real tools
    toolkit = MidojoToolkit(
        control_plane_url="http://localhost:8080",
        real_tools=[get_weather],
    )

    # 3. Define fake (intercepted) tools — same shape as MCP SDK
    @toolkit.tool()
    async def get_weather(ctx: ToolContext, city: str) -> str:
        \"\"\"Get current weather for a city.\"\"\"
        result = await ctx.forward("get_weather", {"city": city})
        cities = await ctx.env("cities")
        notes = cities.get(city, {}).get("notes", "")
        if notes:
            result += "\\n" + notes
        return result

    # 4. Hand the wrapped tools to your LangChain agent
    agent_tools = toolkit.get_tools()
"""

from __future__ import annotations

import functools
import inspect
from typing import Any

from langchain_core.tools import BaseTool, StructuredTool

from midojo.sdk import ControlPlaneClient, ToolContext

__all__ = ["MidojoToolkit"]


class MidojoToolkit:
    """Wraps LangChain tools with midojo control-plane wiring.

    Mirrors ``MidojoMCP``'s API: the ``@toolkit.tool()`` decorator takes
    an ``async def(ctx: ToolContext, ...)`` function, strips ``ctx`` from
    the schema, and wires up environment access + function-call recording.
    """

    def __init__(
        self,
        *,
        control_plane_url: str,
        real_tools: list[BaseTool] | None = None,
    ) -> None:
        self._client = ControlPlaneClient(control_plane_url)
        self._real_tools: dict[str, BaseTool] = {}
        if real_tools:
            for t in real_tools:
                self._real_tools[t.name] = t
        self._tools: list[BaseTool] = []

    async def _lc_forward(self, tool_name: str, args: dict[str, Any]) -> str:
        real_tool = self._real_tools.get(tool_name)
        if real_tool is None:
            raise RuntimeError(f"No real tool named '{tool_name}'. Available: {list(self._real_tools.keys())}")
        result = await real_tool.ainvoke(args)
        return str(result)

    def tool(self):
        """Decorator that registers a fake tool with control-plane wiring.

        The decorated function must have ``ctx: ToolContext`` as its first
        parameter.  That parameter is stripped from the tool schema exposed
        to the LangChain agent.
        """

        def decorator(fn):
            sig = inspect.signature(fn, eval_str=True)
            params = list(sig.parameters.values())
            if not params or params[0].annotation is not ToolContext:
                raise TypeError(f"First parameter of {fn.__name__} must be annotated as ToolContext")
            user_params = params[1:]
            user_sig = sig.replace(parameters=user_params)

            toolkit_ref = self

            @functools.wraps(fn)
            async def wrapper(**kwargs):
                forward_fn = toolkit_ref._lc_forward if toolkit_ref._real_tools else None
                ctx = toolkit_ref._client.create_tool_context(forward_fn=forward_fn)
                result: str = ""
                error: str | None = None
                try:
                    result = await fn(ctx, **kwargs)
                except Exception as e:
                    error = str(e)
                    result = error
                    raise
                finally:
                    await toolkit_ref._client.record_function_call(
                        function=fn.__name__,
                        args=kwargs,
                        result=result,
                        error=error,
                    )
                return result

            wrapper.__signature__ = user_sig
            wrapper.__annotations__ = {
                p.name: p.annotation for p in user_params if p.annotation is not inspect.Parameter.empty
            }

            lc_tool = StructuredTool.from_function(
                coroutine=wrapper,
                name=fn.__name__,
                description=fn.__doc__ or "",
            )
            self._tools.append(lc_tool)
            return fn

        return decorator

    def get_tools(self) -> list[BaseTool]:
        """Return the wrapped LangChain tools, ready for an agent."""
        return list(self._tools)
