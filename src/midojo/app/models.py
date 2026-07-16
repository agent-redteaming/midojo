from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from midojo.types import Environment, MemoryEntry, OutputHook, ToolModification

# --- Run / Evaluation request/response models ---


class CreateFunctionCallRecord(BaseModel):
    """Request body for recording a function call (server fills in timestamp + env snapshots)."""

    function: str
    args: dict
    result: str
    error: str | None = None


class FunctionCallResponse(CreateFunctionCallRecord):
    """Public shape of a recorded function call.

    Excludes the internal pre/post environment snapshots that the domain
    ``FunctionCallRecord`` carries for grading — no API client consumes them.
    ``from_attributes`` lets it be built directly from a domain record.
    """

    model_config = ConfigDict(from_attributes=True)

    timestamp: str


class CreateEvaluationRequest(BaseModel):
    user_task_id: str
    injection_task_id: str | None = None
    injections: dict[str, str] = {}
    tool_modifications: list[ToolModification] = []
    output_hooks: list[OutputHook] = []
    memory_entries: list[MemoryEntry] = []


class CreateRunResponse(BaseModel):
    id: str


class CreateEvaluationResponse(BaseModel):
    id: str
    prompt: str


class CompleteRequest(BaseModel):
    agent_output: str


class RecordObservationsRequest(BaseModel):
    """Push a runtime evidence stream for the active evaluation, keyed by source.

    e.g. ``{"source": "openshell", "data": [<OCSF events>]}``. Verifiers read it
    from ``VerificationContext.observations[source]`` at grade time.
    """

    source: str
    data: Any


class GradeResponse(BaseModel):
    utility: bool
    security: bool


class EvaluationSummary(BaseModel):
    id: str
    user_task_id: str
    injection_task_id: str | None
    completed: bool
    utility: bool | None
    security: bool | None


class RunResponse(BaseModel):
    id: str
    created_at: str
    evaluations: list[EvaluationSummary]


class EvaluationResponse(BaseModel):
    id: str
    user_task_id: str
    injection_task_id: str | None
    completed: bool
    utility: bool | None
    security: bool | None
    agent_input: str | None
    agent_output: str | None
    function_calls: list[FunctionCallResponse]


# --- Suite / task / tool response models ---


class SuiteInfoResponse(BaseModel):
    user_tasks: list[str]
    injection_tasks: list[str]
    tools: list[str]
    environment: Environment


class TaskDetailResponse(BaseModel):
    id: str
    type: str
    prompt: str | None = None
    description: str | None = None


class ToolInfoResponse(BaseModel):
    name: str
    description: str
    parameters: dict
