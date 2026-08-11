from __future__ import annotations

import abc
import asyncio
import os
import uuid
from typing import Any

import httpx


class AgentClient(abc.ABC):
    @abc.abstractmethod
    async def send_task(self, prompt: str) -> str:
        """Send a task prompt to the agent and return its final text output."""
        ...

    @property
    def supports_multi_turn(self) -> bool:
        """Whether this client supports stateful multi-turn conversations."""
        return type(self).send_message is not AgentClient.send_message

    async def send_message(self, message: str, state: Any = None) -> tuple[str, Any]:
        """Send a message in a multi-turn conversation.

        Returns ``(output_text, response_state)`` where ``response_state``
        can be passed to the next call to maintain conversation state.
        Default implementation falls back to ``send_task`` (no state).
        """
        output = await self.send_task(message)
        return output, None


class SimpleHTTPAgentClient(AgentClient):
    """Sends a prompt via HTTP POST and returns the response text.

    Expects the agent to accept ``{"prompt": "..."}`` and return
    ``{"response": "..."}``.
    """

    def __init__(self, agent_url: str, timeout: float = 120.0) -> None:
        self.agent_url = agent_url
        self.timeout = timeout

    async def send_task(self, prompt: str) -> str:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(self.agent_url, json={"prompt": prompt})
            resp.raise_for_status()
            data = resp.json()
            for key in ("response", "output", "text"):
                if key in data:
                    return data[key]
            raise ValueError(
                f"Agent response JSON has no recognized key (expected 'response', 'output', or 'text'). "
                f"Got keys: {list(data.keys())}. Is the agent using the expected protocol? "
                f"(Use --protocol a2a for A2A agents.)"
            )


class A2AAgentClient(AgentClient):
    """Sends a task via the A2A protocol and returns the agent's text output."""

    def __init__(self, agent_url: str, timeout: float = 120.0) -> None:
        self.agent_url = agent_url
        self.timeout = timeout

    async def send_task(self, prompt: str) -> str:
        from a2a.client import ClientConfig, create_client
        from a2a.types import Message, Part, Role, SendMessageRequest

        config = ClientConfig(
            httpx_client=httpx.AsyncClient(timeout=self.timeout),
        )
        client = await create_client(self.agent_url, client_config=config)
        try:
            request = SendMessageRequest(
                message=Message(
                    role=Role.ROLE_USER,
                    message_id=uuid.uuid4().hex,
                    parts=[Part(text=prompt)],
                ),
            )

            result_text = ""
            async for event in client.send_message(request):
                payload_type = event.WhichOneof("payload")
                if payload_type == "message":
                    for part in event.message.parts:
                        if part.text:
                            result_text += part.text
                elif payload_type == "task":
                    for artifact in event.task.artifacts:
                        for part in artifact.parts:
                            if part.text:
                                result_text += part.text
                elif payload_type == "artifact_update":
                    for part in event.artifact_update.artifact.parts:
                        if part.text:
                            result_text = part.text

            return result_text
        finally:
            await client.close()

    async def send_message(self, message: str, state: Any = None) -> tuple[str, Any]:
        from a2a.client import ClientConfig, create_client
        from a2a.types import Message, Part, Role, SendMessageRequest

        config = ClientConfig(
            httpx_client=httpx.AsyncClient(timeout=self.timeout),
        )
        client = await create_client(self.agent_url, client_config=config)
        try:
            msg = Message(
                role=Role.ROLE_USER,
                message_id=uuid.uuid4().hex,
                parts=[Part(text=message)],
            )
            if state:
                msg.context_id = state

            result_text = ""
            context_id = state
            async for event in client.send_message(SendMessageRequest(message=msg)):
                payload_type = event.WhichOneof("payload")
                if payload_type == "message":
                    for part in event.message.parts:
                        if part.text:
                            result_text += part.text
                    if event.message.context_id:
                        context_id = event.message.context_id
                elif payload_type == "task":
                    if event.task.context_id:
                        context_id = event.task.context_id
                    for artifact in event.task.artifacts:
                        for part in artifact.parts:
                            if part.text:
                                result_text += part.text
                elif payload_type == "artifact_update":
                    for part in event.artifact_update.artifact.parts:
                        if part.text:
                            result_text = part.text

            return result_text, context_id
        finally:
            await client.close()


class OpenAIResponsesAgentClient(AgentClient):
    """Calls any OpenAI Responses API endpoint (OpenAI cloud, Llama Stack, vLLM, etc.).

    Uses the standard ``openai`` SDK so it works with any server that implements
    the OpenAI Responses API spec — including local deployments. The tool loop
    runs server-side; the model discovers and calls MCP tools without client
    involvement.

    Unlike ``OGXResponsesClient``, this client is fully async and has no
    OGX-specific extensions (no ``guardrails``). Set ``OPENAI_API_KEY`` for
    cloud endpoints; local servers accept any non-empty string as the key.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        mcp_server_url: str,
        *,
        mcp_server_label: str = "midojo",
        instructions: str = "",
        api_key: str = "x",
        timeout: float = 120.0,
    ) -> None:
        self.base_url = base_url
        self.model = model
        self.mcp_server_url = mcp_server_url
        self.mcp_server_label = mcp_server_label
        self.instructions = instructions
        self.api_key = api_key
        self.timeout = timeout

    async def send_task(self, prompt: str) -> str:
        from openai import AsyncOpenAI  # openai is in the [suites] optional extras

        client = AsyncOpenAI(base_url=self.base_url, api_key=self.api_key, timeout=self.timeout)
        response = await client.responses.create(
            model=self.model,
            input=prompt,
            instructions=self.instructions,
            tools=[
                {
                    "type": "mcp",
                    "server_label": self.mcp_server_label,
                    "server_url": self.mcp_server_url,
                    "require_approval": "never",
                },
            ],
            stream=False,
        )
        return response.output_text

    async def send_message(self, message: str, state: Any = None) -> tuple[str, Any]:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(base_url=self.base_url, api_key=self.api_key, timeout=self.timeout)
        kwargs: dict = dict(
            model=self.model,
            input=message,
            instructions=self.instructions,
            tools=[
                {
                    "type": "mcp",
                    "server_label": self.mcp_server_label,
                    "server_url": self.mcp_server_url,
                    "require_approval": "never",
                },
            ],
            stream=False,
        )
        if state:
            kwargs["previous_response_id"] = state
        response = await client.responses.create(**kwargs)
        return response.output_text, response.id


class OGXResponsesClient(AgentClient):
    """Calls the OGX (Llama Stack) Responses API directly.

    The Responses API runs the tool loop server-side — the model discovers
    and calls MCP tools without client involvement. This is the vector
    tested by ogx-ai/ogx#5036: server-side tool results bypass guardrails.
    """

    def __init__(
        self,
        ogx_url: str,
        model: str,
        mcp_server_url: str,
        *,
        mcp_server_label: str = "midojo",
        instructions: str = "",
        shield_id: str | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.ogx_url = ogx_url
        self.model = model
        self.mcp_server_url = mcp_server_url
        self.mcp_server_label = mcp_server_label
        self.instructions = instructions
        self.shield_id = shield_id
        self.timeout = timeout

    async def send_task(self, prompt: str) -> str:
        from ogx_client import OgxClient

        client = OgxClient(base_url=self.ogx_url, timeout=self.timeout)
        kwargs: dict = dict(
            model=self.model,
            input=prompt,
            instructions=self.instructions,
            tools=[
                {
                    "type": "mcp",
                    "server_label": self.mcp_server_label,
                    "server_url": self.mcp_server_url,
                    "require_approval": "never",
                },
            ],
            stream=False,
        )
        if self.shield_id:
            kwargs["guardrails"] = [self.shield_id]

        response = client.responses.create(**kwargs)
        return response.output_text


class PIAgentClient(AgentClient):
    """Launches a PI coding agent as a subprocess for each task.

    The ``agent_dir`` should point to a directory containing a ``.pi/``
    configuration folder with extensions that use ``@midojo/pi-sdk``.
    """

    def __init__(
        self,
        agent_dir: str,
        control_url: str,
        *,
        timeout: float = 120.0,
    ) -> None:
        self.agent_dir = os.path.abspath(agent_dir)
        self.control_url = control_url
        self.timeout = timeout

    async def send_task(self, prompt: str) -> str:
        env = {
            **os.environ,
            "MIDOJO_URL": self.control_url,
        }

        proc = await asyncio.create_subprocess_exec(
            "pi", "-p", "--no-session", prompt,
            cwd=self.agent_dir,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise TimeoutError(f"PI agent timed out after {self.timeout}s")

        if proc.returncode != 0:
            raise RuntimeError(
                f"PI agent exited with code {proc.returncode}: {stderr.decode()}"
            )

        return stdout.decode().strip()
