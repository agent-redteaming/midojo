"""Process-local application state.

Persistence is in-memory only (lost on restart). A db store may replace
this layer later.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from midojo.types import Environment, FunctionCallRecord
from midojo.yaml_task_suite import YAMLTaskSuite


def _new_id() -> str:
    return uuid.uuid4().hex[:8]


# --- State models ---


@dataclass
class Evaluation:
    """A single task execution within a Run. Captures the environment before and after tool execution, the function call trace, and grading results."""

    id: str
    user_task_id: str
    injection_task_id: str | None
    pre_environment: Environment
    environment: Environment
    function_calls: list[FunctionCallRecord] = field(default_factory=list)
    # Runtime evidence streams keyed by source (e.g. "openshell" -> OCSF events),
    # pushed by the backend/agent client and read by verifiers at grade time.
    observations: dict[str, Any] = field(default_factory=dict)
    agent_input: str | None = None
    agent_output: str | None = None
    completed: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    active_injections: dict[str, str] = field(default_factory=dict)
    utility: bool | None = None
    security: bool | None = None


class Run(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str
    evaluations: dict[str, Evaluation] = {}
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


# --- Module-level state ---

suite: YAMLTaskSuite = None  # type: ignore[assignment]
runs: dict[str, Run] = {}
# Only one eval is active at a time — the orchestrator runs tasks sequentially.
# Concurrent evals would clobber this; use explicit /runs/{id}/evaluations/{id}/* routes instead.
current_eval: Evaluation | None = None
