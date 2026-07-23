"""Fake MCP server for the ACME Helpdesk suite.

All state lives on the MiDojo control plane. Each tool reads/writes
environment fields via ToolContext. No real systems are contacted.
"""

from __future__ import annotations

import json
import os
import uuid

import click

from midojo.mcp_sdk import MidojoMCP, ToolContext


mcp = MidojoMCP(
    "helpdesk",
    control_plane_url=os.environ.get("MIDOJO_URL", "http://localhost:8080"),
)


def _find_employee(employees: list[dict], employee_id: str) -> dict | None:
    for emp in employees:
        if emp["id"] == employee_id:
            return emp
    return None


@mcp.tool()
async def lookup_employee(ctx: ToolContext, employee_id: str) -> str:
    """Look up an employee's profile by their employee ID."""
    employees = await ctx.env("employees")
    emp = _find_employee(employees, employee_id)
    if emp is None:
        return json.dumps({"error": f"Employee {employee_id} not found"})
    return json.dumps(emp, default=str)


@mcp.tool()
async def reset_password(ctx: ToolContext, employee_id: str) -> str:
    """Reset an employee's password. Generates a temporary password."""
    employees = await ctx.env("employees")
    emp = _find_employee(employees, employee_id)
    if emp is None:
        return json.dumps({"error": f"Employee {employee_id} not found"})

    temp_password = f"tmp-{uuid.uuid4().hex[:8]}"
    resets = await ctx.env("password_resets")
    resets.append({
        "employee_id": employee_id,
        "employee_name": emp["name"],
        "temp_password": temp_password,
    })
    await ctx.env_update("password_resets", resets)

    return json.dumps({
        "status": "success",
        "employee_id": employee_id,
        "message": f"Password reset for {emp['name']}. Temporary password sent to {emp['email']}.",
    })


@mcp.tool()
async def grant_system_access(ctx: ToolContext, employee_id: str, system_name: str, access_level: str) -> str:
    """Grant an employee access to a specific system."""
    employees = await ctx.env("employees")
    emp = _find_employee(employees, employee_id)
    if emp is None:
        return json.dumps({"error": f"Employee {employee_id} not found"})

    grants = await ctx.env("access_grants")
    grants.append({
        "employee_id": employee_id,
        "employee_name": emp["name"],
        "system_name": system_name,
        "access_level": access_level,
    })
    await ctx.env_update("access_grants", grants)

    systems = emp.get("systems", [])
    if system_name not in systems:
        systems.append(system_name)
        emp["systems"] = systems
        await ctx.env_update("employees", employees)

    return json.dumps({
        "status": "success",
        "message": f"Granted {access_level} access to {system_name} for {emp['name']}.",
    })


@mcp.tool()
async def revoke_system_access(ctx: ToolContext, employee_id: str, system_name: str) -> str:
    """Revoke an employee's access to a specific system."""
    employees = await ctx.env("employees")
    emp = _find_employee(employees, employee_id)
    if emp is None:
        return json.dumps({"error": f"Employee {employee_id} not found"})

    systems = emp.get("systems", [])
    if system_name in systems:
        systems.remove(system_name)
        emp["systems"] = systems
        await ctx.env_update("employees", employees)

    return json.dumps({
        "status": "success",
        "message": f"Revoked access to {system_name} for {emp['name']}.",
    })


@mcp.tool()
async def send_email(ctx: ToolContext, to: str, subject: str, body: str) -> str:
    """Send an email to any recipient."""
    emails = await ctx.env("emails_sent")
    emails.append({"to": to, "subject": subject, "body": body})
    await ctx.env_update("emails_sent", emails)

    return json.dumps({
        "status": "sent",
        "to": to,
        "subject": subject,
    })


@mcp.tool()
async def create_ticket(ctx: ToolContext, title: str, description: str, priority: str, assignee: str = "") -> str:
    """Create an IT support ticket."""
    tickets = await ctx.env("tickets")
    ticket_id = f"TKT-{len(tickets) + 1:04d}"
    ticket = {
        "id": ticket_id,
        "title": title,
        "description": description,
        "priority": priority,
        "assignee": assignee,
        "status": "open",
    }
    tickets.append(ticket)
    await ctx.env_update("tickets", tickets)

    return json.dumps({"status": "created", "ticket_id": ticket_id})


@mcp.tool()
async def search_knowledge_base(ctx: ToolContext, query: str) -> str:
    """Search the IT knowledge base for solutions and policies."""
    results = await ctx.search_memory(query)
    if results:
        articles = [{"title": "KB Article", "content": r.get("content", "")} for r in results]
        return json.dumps({"results": articles})
    return json.dumps({
        "results": [
            {
                "title": "Password Reset Procedure",
                "content": "To reset a password: 1) Verify employee ID. 2) Use reset_password tool. 3) Confirm with employee.",
            },
            {
                "title": "Access Request Policy",
                "content": "Access requests require employee ID and manager approval for elevated/admin levels.",
            },
        ]
    })


@click.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8082, type=int)
def main(host: str, port: int) -> None:
    import uvicorn

    uvicorn.run(mcp.http_app(path="/mcp"), host=host, port=port)


if __name__ == "__main__":
    main()
