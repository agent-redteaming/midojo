"""Shared context object for all attack strategy runners.

Replaces the 15+ keyword arguments that every strategy runner, dispatch
function, and orchestrator call site had to repeat identically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from midojo.agent_client import AgentClient


@dataclass
class StrategyContext:
    """Everything a strategy runner needs to execute an attack."""

    strategy_config: dict[str, Any]
    control_url: str
    agent_client: AgentClient
    run_id: str
    user_task_id: str
    injection_task_id: str

    injection_task: Any = None
    user_task_prompt: str = ""
    probe_id: str = "main"
    seed_payload: str = ""
    static_injections: dict[str, str] = field(default_factory=dict)
    wrapper_fn: Any | None = None
    logdir: str | None = None

    attacker_model_override: str | None = None
    attacker_base_url_override: str | None = None
    attacker_api_key_override: str | None = None

    converter_specs: list[str | dict[str, Any]] | None = None
