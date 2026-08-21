"""Process-local application state.

Run/evaluation state lives behind the :class:`~midojo.app.store.Store` seam
(see ``store.py``); this module holds only the process-global handles wired up
at startup — the loaded ``suite`` and the active ``store``. The default store is
in-memory (lost on restart); a db-backed store may replace it later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from midojo.types import Environment, FunctionCallRecord
from midojo.yaml_task_suite import YAMLTaskSuite

if TYPE_CHECKING:
    from .store import Store


# --- State models ---


@dataclass
class EnvInjection:
    """Inject payload into an environment field via placeholder substitution."""

    type: Literal["env"] = "env"
    payload: str = ""
    probe_key: str = ""


@dataclass
class PromptInjection:
    """Inject payload into the user task prompt via placeholder substitution."""

    type: Literal["prompt"] = "prompt"
    payload: str = ""
    probe_key: str = ""


@dataclass
class ToolInjection:
    """Inject payload into a tool response via the interception SDK."""

    type: Literal["tool"] = "tool"
    payload: str = ""
    target_tool: str | None = None
    target_field: str | None = None
    mode: Literal["embed", "replace", "append", "new_field"] = "embed"


InjectionInstruction = EnvInjection | PromptInjection | ToolInjection


@dataclass
class Evaluation:
    """A single task execution within a Run.

    Captures the environment before and after tool execution, the function
    call trace, and grading results.
    """

    id: str
    run_id: str
    user_task_id: str
    injection_task_id: str | None
    pre_environment: Environment
    environment: Environment
    function_calls: list[FunctionCallRecord] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)
    agent_input: str | None = None
    agent_output: str | None = None
    completed: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    active_injections: dict[str, str] = field(default_factory=dict)
    injection_plan: list[InjectionInstruction] = field(default_factory=list)
    env_template: dict | None = None
    utility: bool | None = None
    security: bool | None = None
    security_reason: str | None = None


class Run(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str
    evaluations: dict[str, Evaluation] = {}
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


# --- Module-level state ---
#
# Set by create_app() at startup. `store` is the seam through which all
# run/evaluation state is accessed; routers reach it via the get_store
# dependency rather than touching this module directly.

suite: YAMLTaskSuite = None  # type: ignore[assignment]
store: Store = None  # type: ignore[assignment]
