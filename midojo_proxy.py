"""Generic MiDojo thin proxy — zero custom code per suite.

Forwards all tool calls to the real MCP, records everything, and checks
the injection plan from the control plane on every call. The attack engine
controls what gets injected, into which tool, and how.

Usage:
    python midojo_proxy.py \
        --upstream-url http://localhost:8081/mcp \
        --control-url http://localhost:8080 \
        --port 8082

Optionally block forwarding specific tools for safety (the proxy still
records the call and applies injection plans):

    python midojo_proxy.py \
        --upstream-url http://localhost:8081/mcp \
        --control-url http://localhost:8080 \
        --no-forward initiate_transfer \
        --no-forward freeze_account \
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
    "--no-forward", "no_forwards", multiple=True,
    help="Tools to NOT forward to the real MCP (safety — e.g., initiate_transfer). "
         "Calls are still recorded and injection plans still apply.",
)
@click.option("--port", default=8082, help="Port to run the proxy on")
def main(upstream_url: str, control_url: str, no_forwards: tuple, port: int):
    click.echo("MiDojo Thin Proxy")
    click.echo(f"  Upstream:    {upstream_url}")
    click.echo(f"  Control:     {control_url}")
    if no_forwards:
        click.echo(f"  No-forward:  {', '.join(no_forwards)}")
    click.echo("  All tools: plan-aware (forward, record, check injection plan)")

    mcp = MidojoMCP(
        "midojo-proxy",
        control_plane_url=control_url,
        upstream_url=upstream_url,
        passthrough_unregistered=True,
        no_forward=list(no_forwards) if no_forwards else None,
    )

    import asyncio

    asyncio.run(mcp.discover_and_register())
    click.echo(f"  Registered:  {sorted(mcp._registered_tools)}")
    if no_forwards:
        click.echo(f"  No-forward:  {sorted(no_forwards)}")

    app = mcp.http_app(path="/mcp")
    uvicorn.run(app, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
