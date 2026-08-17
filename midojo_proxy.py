"""Generic MiDojo injection proxy — zero custom code per suite.

Uses passthrough_unregistered + intercept rules to MITM any agent's tools.

Usage:
    python midojo_proxy.py \
        --upstream-url http://localhost:8081/mcp \
        --control-url http://localhost:8080 \
        --intercept get_customer_info:notes:inject_0:main \
        --capture send_notification \
        --port 8082
"""

from __future__ import annotations

import click
import uvicorn

from midojo.mcp_sdk import MidojoMCP


@click.command()
@click.option("--upstream-url", required=True, help="Real MCP server URL")
@click.option("--control-url", default="http://localhost:8080", help="MiDojo control plane URL")
@click.option(
    "--intercept", "intercepts", multiple=True,
    help="Intercept rule: tool:field:probe (e.g., get_customer_info:notes:inject_0:main)",
)
@click.option(
    "--capture", "captures", multiple=True,
    help="Capture-only tools (record but don't forward, e.g., send_notification)",
)
@click.option("--port", default=8082, help="Port to run the proxy on")
def main(upstream_url: str, control_url: str, intercepts: tuple, captures: tuple, port: int):
    rules = []
    for spec in intercepts:
        parts = spec.split(":", 2)
        if len(parts) == 3:
            rules.append({"tool": parts[0], "field": parts[1], "probe": parts[2]})
        elif len(parts) == 2:
            rules.append({"tool": parts[0], "field": parts[1]})
        else:
            click.echo(f"Invalid intercept spec: {spec} (expected tool:field or tool:field:probe)")
            return

    for tool in captures:
        rules.append({"tool": tool, "capture": True})

    click.echo("MiDojo Generic Proxy")
    click.echo(f"  Upstream:  {upstream_url}")
    click.echo(f"  Control:   {control_url}")
    click.echo(f"  Rules:     {len(rules)} ({len(intercepts)} intercept, {len(captures)} capture)")
    for r in rules:
        if r.get("capture"):
            click.echo(f"    capture: {r['tool']}")
        else:
            click.echo(f"    intercept: {r['tool']} → field={r.get('field')} probe={r.get('probe', '*')}")

    mcp = MidojoMCP(
        "midojo-proxy",
        control_plane_url=control_url,
        upstream_url=upstream_url,
        passthrough_unregistered=True,
        intercept=rules,
    )

    import asyncio

    asyncio.run(mcp.discover_and_register())
    click.echo(f"  Registered tools: {sorted(mcp._registered_tools)}")

    app = mcp.http_app(path="/mcp")
    uvicorn.run(app, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
