from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from midojo.types import Environment

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


class EnvInjectionModel(BaseModel):
    """Inject payload into an environment field via placeholder substitution."""

    type: Literal["env"] = "env"
    payload: str
    probe_key: str


class PromptInjectionModel(BaseModel):
    """Inject payload into the user task prompt via placeholder substitution."""

    type: Literal["prompt"] = "prompt"
    payload: str
    probe_key: str


class ToolInjectionModel(BaseModel):
    """Inject payload into a tool response via the interception SDK."""

    type: Literal["tool"] = "tool"
    payload: str
    target_tool: str | None = None
    target_field: str | None = None
    mode: Literal["embed", "replace", "append", "new_field"] = "embed"


InjectionInstructionModel = EnvInjectionModel | PromptInjectionModel | ToolInjectionModel


class SetInjectionPlanRequest(BaseModel):
    instructions: list[InjectionInstructionModel]


class RefreshRequest(BaseModel):
    """Refresh the eval's environment and prompt with current mutable injections."""

    reset_state: bool = True


class RefreshResponse(BaseModel):
    prompt: str


class CreateEvaluationRequest(BaseModel):
    user_task_id: str
    injection_task_id: str | None = None
    injections: dict[str, str] = {}
    injection_plan: list[InjectionInstructionModel] | None = None


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
    security_reason: str | None = Field(
        default=None,
        description=(
            "When the attack succeeded, the criterion that graded it "
            "(e.g. the AnyOf branch that fired); None when the attack failed."
        ),
    )


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
    security_reason: str | None = None
    agent_input: str | None
    agent_output: str | None
    function_calls: list[FunctionCallResponse]


# --- Suite / task response models ---


class SuiteInfoResponse(BaseModel):
    user_tasks: list[str]
    injection_tasks: list[str]
    environment: Environment


class TaskDetailResponse(BaseModel):
    id: str
    type: str
    prompt: str | None = None
    description: str | None = None
