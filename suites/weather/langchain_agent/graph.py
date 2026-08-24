"""Graph entrypoint for the LangGraph Agent Server.

``langgraph dev`` (and the production Agent Server) import this module and
serve the module-level ``graph`` — a compiled LangGraph produced by
``create_agent``.  The tools are wired to the midojo control plane via
``MIDOJO_URL`` at import time, so each pod serves one suite's agent.
"""

from __future__ import annotations

import os

from suites.weather.langchain_agent.build import build_agent

graph = build_agent(os.environ.get("MIDOJO_URL", "http://localhost:8080"))
