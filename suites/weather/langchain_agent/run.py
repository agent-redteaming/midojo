"""Local one-shot CLI for the weather LangChain agent.

Reads a prompt from argv, runs the agent once, and prints the output to
stdout.  Handy for a quick local smoke test without standing up the
LangGraph server; the cluster deployment instead serves ``graph.py`` via
``langgraph dev`` and is driven with ``midojo-run --protocol langgraph``.
"""

from __future__ import annotations

import asyncio
import os

import click

from suites.weather.langchain_agent.build import build_agent, extract_text


@click.command()
@click.argument("prompt")
def main(prompt: str) -> None:
    midojo_url = os.environ.get("MIDOJO_URL", "http://localhost:8080")
    agent = build_agent(midojo_url)
    result = asyncio.run(agent.ainvoke({"messages": [{"role": "user", "content": prompt}]}))
    print(extract_text(result["messages"][-1].content))


if __name__ == "__main__":
    main()
