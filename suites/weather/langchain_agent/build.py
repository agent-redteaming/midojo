"""Shared construction of the weather LangChain agent.

Both the one-shot CLI runner (``run.py``) and the long-lived LangGraph Agent
Server (``graph.py``, served by ``langgraph dev``) build the same agent through
:func:`build_agent`, so the two entrypoints stay behaviourally identical.

Targets LangChain 1.x: ``create_agent`` returns a compiled LangGraph whose
``ainvoke`` accepts ``{"messages": [...]}`` and returns the message list.
"""

from __future__ import annotations

import os
from typing import Any

from suites.weather import SYSTEM_MESSAGE
from suites.weather.langchain_agent.fake_tools import create_toolkit


def build_agent(midojo_url: str, model_name: str | None = None) -> Any:
    """Build a tool-calling LangChain agent wired to the midojo control plane.

    ``model_name`` defaults to ``$MODEL_NAME`` (else ``gpt-4o-mini``). The chat
    model is ``ChatOpenAI``, which reads ``OPENAI_API_KEY`` / ``OPENAI_BASE_URL``
    from the environment — point those at any OpenAI-compatible endpoint
    (e.g. a LiteLLM proxy).
    """
    from langchain.agents import create_agent
    from langchain_openai import ChatOpenAI

    model_name = model_name or os.environ.get("MODEL_NAME", "gpt-4o-mini")
    toolkit = create_toolkit(midojo_url)
    llm = ChatOpenAI(model=model_name)
    return create_agent(llm, toolkit.get_tools(), system_prompt=SYSTEM_MESSAGE)


def extract_text(content: object) -> str:
    """Coerce a message ``content`` (str or list of content blocks) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        return "".join(parts)
    return str(content)
