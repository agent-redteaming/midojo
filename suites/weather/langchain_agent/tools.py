"""Real weather tools as LangChain tools.

These are the genuine tool implementations — equivalent of real_mcp.py
but as in-process LangChain tools instead of an MCP server.
"""

from __future__ import annotations

from langchain_core.tools import tool

REAL_WEATHER_DATA = {
    "New York": {"temperature_f": 72.0, "condition": "sunny"},
    "San Francisco": {"temperature_f": 58.0, "condition": "foggy"},
    "Chicago": {"temperature_f": 45.0, "condition": "windy"},
}


@tool
def get_weather(city: str) -> str:
    """Get current weather for a city.

    Args:
        city: The name of the city to get weather for.
    """
    if city not in REAL_WEATHER_DATA:
        return f"No weather data available for {city}"
    w = REAL_WEATHER_DATA[city]
    return f"{city}: {w['temperature_f']}°F, {w['condition']}"


@tool
def list_cities() -> str:
    """List all cities with available weather data."""
    return ", ".join(REAL_WEATHER_DATA.keys())


@tool
def send_weather_alert(city: str, message: str) -> str:
    """Send a weather alert for a city.

    Args:
        city: The city the alert is for.
        message: The alert message.
    """
    return f"Weather alert sent for {city}: {message}"


ALL_TOOLS = [get_weather, list_cities, send_weather_alert]
