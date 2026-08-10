"""A2A weather agent for midojo E2E testing.

A minimal A2A-compliant agent that:
1. Publishes an AgentCard at /.well-known/agent-card.json
2. Connects to midojo's MCP server for tool access
3. Uses an OpenAI-compatible LLM (via LiteLLM) for reasoning
4. Speaks the A2A JSON-RPC protocol for task handling

Usage::

    # With explicit flags
    weather-agent --litellm-api-key=xxx --litellm-api-url=yyy --litellm-model=zzz

    # With env vars (via dotenv run or exported)
    dotenv run -- weather-agent
"""

from __future__ import annotations

import json

import click
import uvicorn
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes.agent_card_routes import create_agent_card_routes
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Message,
    Part,
    Role,
)
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from openai import OpenAI
from starlette.applications import Starlette

from suites.weather import SYSTEM_MESSAGE


def mcp_tools_to_openai(mcp_tools: list) -> list[dict]:
    """Convert MCP tool definitions to OpenAI function-calling format."""
    openai_tools = []
    for tool in mcp_tools:
        openai_tools.append(
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description or "",
                    "parameters": tool.inputSchema,
                },
            }
        )
    return openai_tools


async def run_agent_loop(
    prompt: str,
    llm: OpenAI,
    model: str,
    mcp_server_url: str,
    prior_messages: list[dict] | None = None,
) -> tuple[str, list[dict]]:
    """Connect to MCP, discover tools, run tool-use loop with LLM.

    Returns (response_text, full_messages) so callers can persist history.
    """
    async with streamablehttp_client(mcp_server_url) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools_result = await session.list_tools()
            openai_tools = mcp_tools_to_openai(tools_result.tools)

            if prior_messages:
                messages: list[dict] = [*prior_messages, {"role": "user", "content": prompt}]
            else:
                messages = [
                    {"role": "system", "content": SYSTEM_MESSAGE},
                    {"role": "user", "content": prompt},
                ]

            for _ in range(10):
                response = llm.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=openai_tools if openai_tools else None,
                )

                choice = response.choices[0]

                if choice.message.tool_calls:
                    messages.append(choice.message.model_dump())

                    for tool_call in choice.message.tool_calls:
                        fn = tool_call.function
                        args = json.loads(fn.arguments) if fn.arguments else {}
                        print(f"  Tool call: {fn.name}({args})")

                        result = await session.call_tool(fn.name, args)
                        content = ""
                        for block in result.content:
                            if hasattr(block, "text"):
                                content += block.text

                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": content,
                            }
                        )
                else:
                    text = choice.message.content or ""
                    messages.append({"role": "assistant", "content": text})
                    return text, messages

            last = messages[-1].get("content", "") if messages else ""
            return last, messages


class WeatherAgentExecutor(AgentExecutor):
    def __init__(self, llm: OpenAI, model: str, mcp_server_url: str) -> None:
        self.llm = llm
        self.model = model
        self.mcp_server_url = mcp_server_url
        self._conversations: dict[str, list[dict]] = {}

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        user_message = context.message
        prompt = ""
        if user_message and user_message.parts:
            prompt = user_message.parts[0].text

        prior = self._conversations.get(context.context_id) if context.context_id else None

        print(f"Received prompt: {prompt[:100]}... (context_id={context.context_id})")
        response_text, full_messages = await run_agent_loop(
            prompt, self.llm, self.model, self.mcp_server_url, prior_messages=prior,
        )
        print(f"Response: {response_text[:100]}...")

        if context.context_id:
            self._conversations[context.context_id] = full_messages

        response_msg = Message(role=Role.ROLE_AGENT, parts=[Part(text=response_text)])
        if context.context_id:
            response_msg.context_id = context.context_id
        await event_queue.enqueue_event(response_msg)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError("Cancel not supported")


weather_skill = AgentSkill(
    id="weather_lookup",
    name="Weather Lookup",
    description="Look up current weather conditions for cities",
    tags=["weather"],
    examples=["What's the weather in New York?", "Which city is warmest?"],
)


@click.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to.")
@click.option("--port", default=8000, type=int, help="Port to bind to.", envvar="AGENT_PORT")
@click.option(
    "--mcp-server-url", default="http://localhost:8080/mcp", help="URL of the MCP server.", envvar="MCP_SERVER_URL"
)
@click.option("--litellm-api-key", required=True, help="LiteLLM API key.", envvar="LITELLM_API_KEY")
@click.option("--litellm-api-url", required=True, help="LiteLLM API URL.", envvar="LITELLM_API_URL")
@click.option("--litellm-model", required=True, help="LiteLLM model name.", envvar="LITELLM_MODEL")
def main(
    host: str, port: int, mcp_server_url: str, litellm_api_key: str, litellm_api_url: str, litellm_model: str
) -> None:
    llm = OpenAI(api_key=litellm_api_key, base_url=litellm_api_url)

    executor = WeatherAgentExecutor(llm, litellm_model, mcp_server_url)

    agent_card = AgentCard(
        name="Weather Agent",
        description="A weather assistant that looks up current conditions using MCP tools.",
        version="1.0.0",
        supported_interfaces=[
            AgentInterface(url=f"http://localhost:{port}/", protocol_binding="JSONRPC"),
        ],
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[weather_skill],
    )

    request_handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )

    routes = []
    routes.extend(create_agent_card_routes(agent_card))
    routes.extend(create_jsonrpc_routes(request_handler, "/"))

    app = Starlette(routes=routes)

    print(f"Starting A2A weather agent on port {port}")
    print(f"MCP server: {mcp_server_url}")
    print(f"LLM model: {litellm_model}")
    print(f"Agent card: http://localhost:{port}/.well-known/agent-card.json")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
