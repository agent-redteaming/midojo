"""Discover real tool names from a live MCP server.

When the user provides an MCP URL, we connect to the real server, list its
tools, and use the actual tool names + schemas in the generated artifacts.
This replaces the abstract tool names from the capability profile.

Usage::

    tools = await discover_tools("http://localhost:8081/mcp")
    # Returns: [{"name": "get_customer_info", "description": "...", "parameters": {...}}, ...]
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger("midojo.artifact_gen")


def discover_tools_sync(mcp_url: str) -> list[dict[str, Any]]:
    """Synchronously discover tools from a live MCP server."""
    return asyncio.run(discover_tools(mcp_url))


async def discover_tools(mcp_url: str) -> list[dict[str, Any]]:
    """Connect to an MCP server and list all available tools."""
    from fastmcp import Client

    tools: list[dict[str, Any]] = []
    async with Client(mcp_url) as client:
        raw_tools = await client.list_tools()
        for tool in raw_tools:
            schema = getattr(tool, "inputSchema", None) or getattr(tool, "parameters", None) or {}
            tools.append({
                "name": tool.name,
                "description": tool.description or "",
                "parameters": schema.get("properties", {}),
                "kind": _infer_tool_kind(tool.name, tool.description or ""),
            })

    logger.info("discovered %d tools from %s", len(tools), mcp_url)
    return tools


def _infer_tool_kind(name: str, description: str) -> str:
    """Infer tool kind (read/write/communicate/privileged) from name and description."""
    name_lower = name.lower()
    desc_lower = description.lower()

    write_indicators = ["transfer", "initiate", "create", "update", "modify", "process", "execute", "approve"]
    privileged_indicators = ["freeze", "flag", "suspend", "block", "delete", "remove", "revoke"]
    communicate_indicators = ["send", "notify", "email", "message", "alert"]

    for indicator in privileged_indicators:
        if indicator in name_lower or indicator in desc_lower:
            return "privileged"
    for indicator in communicate_indicators:
        if indicator in name_lower or indicator in desc_lower:
            return "communicate"
    for indicator in write_indicators:
        if indicator in name_lower or indicator in desc_lower:
            return "write"
    return "read"


def enrich_profile_with_real_tools(
    profile_tools: list[dict[str, Any]],
    real_tools: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map abstract profile tool names to real MCP tool names.

    Uses fuzzy matching on descriptions and names to find the best match.
    Returns the real tools enriched with kind information.
    """
    enriched = []
    for real in real_tools:
        kind = real.get("kind", "read")

        # Try to match against profile tools for better kind classification
        for profile_tool in profile_tools:
            if _tools_match(profile_tool, real):
                break

        enriched.append({
            "name": real["name"],
            "description": real["description"],
            "kind": kind,
            "parameters": real.get("parameters", {}),
        })

    return enriched


def _tools_match(profile_tool: dict, real_tool: dict) -> bool:
    """Check if a profile tool and a real tool refer to the same capability."""
    p_name = profile_tool.get("name", "").lower()
    r_name = real_tool["name"].lower()
    p_desc = profile_tool.get("description", "").lower()
    r_desc = real_tool["description"].lower()

    # Direct name overlap
    p_words = set(p_name.replace("_", " ").split())
    r_words = set(r_name.replace("_", " ").split())
    if len(p_words & r_words) >= 2:
        return True

    # Description keyword overlap
    p_desc_words = set(p_desc.split())
    r_desc_words = set(r_desc.split())
    overlap = len(p_desc_words & r_desc_words)
    if overlap >= 3:
        return True

    return False
