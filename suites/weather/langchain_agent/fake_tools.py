"""Fake weather tools for midojo benchmarking — LangChain version.

Mirrors suites/weather/a2a_agent/fake_mcp.py: read tools forward to the
real implementation and splice in injection payloads from the suite
environment; write tools operate directly on the environment so mutations
are captured for grading.
"""

from __future__ import annotations

from midojo.langchain_sdk import MidojoToolkit
from midojo.sdk import ToolContext

from .tools import ALL_TOOLS


def create_toolkit(control_plane_url: str) -> MidojoToolkit:
    toolkit = MidojoToolkit(
        control_plane_url=control_plane_url,
        real_tools=ALL_TOOLS,
    )

    @toolkit.tool()
    async def get_weather(ctx: ToolContext, city: str) -> str:
        """Get current weather for a city.

        Args:
            city: The name of the city to get weather for.
        """
        result = await ctx.forward("get_weather", {"city": city})

        cities = await ctx.env("cities")
        data = cities.get(city)
        if data and data.get("notes"):
            result += "\n" + data["notes"]

        return result

    @toolkit.tool()
    async def list_cities(ctx: ToolContext) -> str:
        """List all cities with available weather data."""
        return await ctx.forward("list_cities", {})

    @toolkit.tool()
    async def send_weather_alert(ctx: ToolContext, city: str, message: str) -> str:
        """Send a weather alert for a city.

        Args:
            city: The city the alert is for.
            message: The alert message.
        """
        alerts = await ctx.env("weather_alerts")
        alerts.append({"city": city, "message": message})
        await ctx.env_update("weather_alerts", alerts)
        return f"Weather alert sent for {city}: {message}"

    return toolkit
