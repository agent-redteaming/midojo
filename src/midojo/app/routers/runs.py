from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from midojo.types import FunctionCallRecord
from midojo.yaml_task_suite import YAMLTaskSuite

from ..dependencies import (
    get_current_evaluation,
    get_current_ids,
    get_evaluation_by_id,
    get_run,
    get_store,
    get_suite,
)
from ..models import (
    CompleteRequest,
    CreateEvaluationRequest,
    CreateEvaluationResponse,
    CreateFunctionCallRecord,
    CreateRunResponse,
    EnvInjectionModel,
    EvaluationResponse,
    EvaluationSummary,
    FunctionCallResponse,
    GradeResponse,
    InjectionInstructionModel,
    PromptInjectionModel,
    RecordObservationsRequest,
    RefreshRequest,
    RefreshResponse,
    RunResponse,
    SetInjectionPlanRequest,
)
from ..state import EnvInjection, Evaluation, InjectionInstruction, PromptInjection, Run, ToolInjection
from ..store import Store

router = APIRouter(prefix="/runs")

# Mirrors of the per-eval environment + function-call endpoints that resolve the
# active eval from the store. Used by long-lived MCP servers / PI extensions that
# don't have a run/eval ID at construction time. See dependencies.get_current_evaluation.
current_router = APIRouter(prefix="/current")


def _require_eval(evaluation: Evaluation | None, eval_id: str) -> Evaluation:
    """404 when an ID-based store mutation reports the evaluation doesn't exist."""
    if evaluation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown evaluation: {eval_id}")
    return evaluation


def _require_current(evaluation: Evaluation | None) -> Evaluation:
    """400 when the current-eval pointer no longer resolves to a live evaluation."""
    if evaluation is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No evaluation in progress.")
    return evaluation


@router.post("", response_model=CreateRunResponse, status_code=status.HTTP_201_CREATED)
def create_run(store: Annotated[Store, Depends(get_store)]):
    run = store.create_run()
    return CreateRunResponse(id=run.id)


@router.get("/{run_id}", response_model=RunResponse, status_code=status.HTTP_200_OK)
def retrieve_run(run: Annotated[Run, Depends(get_run)]):
    return RunResponse(
        id=run.id,
        created_at=run.created_at,
        evaluations=[
            EvaluationSummary(
                id=e.id,
                user_task_id=e.user_task_id,
                injection_task_id=e.injection_task_id,
                completed=e.completed,
                utility=e.utility,
                security=e.security,
            )
            for e in run.evaluations.values()
        ],
    )


@router.post("/{run_id}/evaluations", response_model=CreateEvaluationResponse, status_code=status.HTTP_201_CREATED)
def create_evaluation(
    req: CreateEvaluationRequest,
    run: Annotated[Run, Depends(get_run)],
    suite: Annotated[YAMLTaskSuite, Depends(get_suite)],
    store: Annotated[Store, Depends(get_store)],
):
    if req.user_task_id not in suite.user_tasks:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown user task: {req.user_task_id}")
    if req.injection_task_id is not None and req.injection_task_id not in suite.injection_tasks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown injection task: {req.injection_task_id}"
        )

    environment = suite.provision_environment(req.injections)
    pre_environment = environment.model_copy(deep=True)
    prompt = suite.inject_user_task_prompt(req.user_task_id, req.injections)

    evaluation = store.create_evaluation(
        run.id,
        user_task_id=req.user_task_id,
        injection_task_id=req.injection_task_id,
        pre_environment=pre_environment,
        environment=environment,
        active_injections=req.injections,
        agent_input=prompt,
    )

    if req.injection_plan:
        plan = [_model_to_instruction(i) for i in req.injection_plan]
        store.set_injection_plan(run.id, evaluation.id, plan)
        evaluation.env_template = suite.get_env_template()

    return CreateEvaluationResponse(id=evaluation.id, prompt=prompt)


@router.get(
    "/{run_id}/evaluations/{eval_id}",
    response_model=EvaluationResponse,
    status_code=status.HTTP_200_OK,
)
def retrieve_evaluation(evaluation: Annotated[Evaluation, Depends(get_evaluation_by_id)]):
    return EvaluationResponse(
        id=evaluation.id,
        user_task_id=evaluation.user_task_id,
        injection_task_id=evaluation.injection_task_id,
        completed=evaluation.completed,
        utility=evaluation.utility,
        security=evaluation.security,
        security_reason=evaluation.security_reason,
        agent_input=evaluation.agent_input,
        agent_output=evaluation.agent_output,
        function_calls=[FunctionCallResponse.model_validate(fc) for fc in evaluation.function_calls],
    )


@router.post("/{run_id}/evaluations/{eval_id}/complete", status_code=status.HTTP_200_OK)
def complete_evaluation(
    eval_id: str,
    req: CompleteRequest,
    run: Annotated[Run, Depends(get_run)],
    store: Annotated[Store, Depends(get_store)],
):
    _require_eval(store.complete_evaluation(run.id, eval_id, req.agent_output), eval_id)
    return {"status": "completed"}


@router.post("/{run_id}/evaluations/{eval_id}/grade", response_model=GradeResponse, status_code=status.HTTP_200_OK)
def grade_evaluation(
    evaluation: Annotated[Evaluation, Depends(get_evaluation_by_id)],
    suite: Annotated[YAMLTaskSuite, Depends(get_suite)],
    store: Annotated[Store, Depends(get_store)],
):
    if not evaluation.completed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Evaluation not completed. Call complete first."
        )

    result = suite.grade(
        user_task_id=evaluation.user_task_id,
        injection_task_id=evaluation.injection_task_id,
        agent_output=evaluation.agent_output or "",
        pre_environment=evaluation.pre_environment,
        post_environment=evaluation.environment,
        function_calls=evaluation.function_calls,
        observations=evaluation.observations,
    )
    graded = GradeResponse.model_validate(result)
    store.set_grade(
        evaluation.run_id,
        evaluation.id,
        utility=graded.utility,
        security=graded.security,
        security_reason=graded.security_reason,
    )
    return graded


# --- Environment endpoints (nested under evaluation) ---


@router.get("/{run_id}/evaluations/{eval_id}/environment", status_code=status.HTTP_200_OK)
def get_environment(evaluation: Annotated[Evaluation, Depends(get_evaluation_by_id)]) -> dict:
    return evaluation.environment.model_dump()


def register_environment_update_route(env_type: type) -> None:
    """Register PUT routes for environment updates using the suite's concrete environment type.

    Each suite defines its own Pydantic environment model (e.g. WeatherEnvironment).
    FastAPI needs the concrete type annotation on the request body to validate and
    deserialize it, but the router module doesn't know which suite is loaded. So we
    register these routes at startup once the suite type is known, patching __annotations__
    on the handler to give FastAPI the right body type.
    """

    def update_environment(
        eval_id: str,
        body,
        run: Annotated[Run, Depends(get_run)],
        store: Annotated[Store, Depends(get_store)],
    ) -> dict:
        evaluation = _require_eval(store.set_environment(run.id, eval_id, body), eval_id)
        return evaluation.environment.model_dump()

    update_environment.__annotations__["body"] = env_type
    router.add_api_route("/{run_id}/evaluations/{eval_id}/environment", update_environment, methods=["PUT"])

    def update_current_environment(
        body,
        ids: Annotated[tuple[str, str], Depends(get_current_ids)],
        store: Annotated[Store, Depends(get_store)],
    ) -> dict:
        run_id, eval_id = ids
        evaluation = _require_current(store.set_environment(run_id, eval_id, body))
        return evaluation.environment.model_dump()

    update_current_environment.__annotations__["body"] = env_type
    current_router.add_api_route("/environment", update_current_environment, methods=["PUT"])


# --- Function call endpoints ---


@router.get(
    "/{run_id}/evaluations/{eval_id}/function-calls",
    response_model=list[FunctionCallResponse],
    status_code=status.HTTP_200_OK,
)
def list_function_calls(evaluation: Annotated[Evaluation, Depends(get_evaluation_by_id)]) -> list[FunctionCallRecord]:
    return evaluation.function_calls


@router.get(
    "/{run_id}/evaluations/{eval_id}/function-calls/{idx}",
    response_model=FunctionCallResponse,
    status_code=status.HTTP_200_OK,
)
def get_function_call(idx: int, evaluation: Annotated[Evaluation, Depends(get_evaluation_by_id)]) -> FunctionCallRecord:
    if idx < 0 or idx >= len(evaluation.function_calls):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Function call index out of range: {idx}")
    return evaluation.function_calls[idx]


@router.post(
    "/{run_id}/evaluations/{eval_id}/function-calls",
    response_model=FunctionCallResponse,
    status_code=status.HTTP_201_CREATED,
)
def record_function_call(
    eval_id: str,
    req: CreateFunctionCallRecord,
    run: Annotated[Run, Depends(get_run)],
    store: Annotated[Store, Depends(get_store)],
) -> FunctionCallRecord:
    evaluation = _require_eval(store.append_function_call(run.id, eval_id, req), eval_id)
    return evaluation.function_calls[-1]


# --- Observation endpoints ---
#
# Runtime evidence streams (e.g. OpenShell OCSF events) the runner reads from a
# source and records here, keyed by source — symmetric with PUT /environment.
# Verifiers read them from VerificationContext.observations at grade time.


@router.get("/{run_id}/evaluations/{eval_id}/observations", status_code=status.HTTP_200_OK)
def get_observations(evaluation: Annotated[Evaluation, Depends(get_evaluation_by_id)]) -> dict:
    return evaluation.observations


@router.post("/{run_id}/evaluations/{eval_id}/observations", status_code=status.HTTP_200_OK)
def record_observations(
    eval_id: str,
    req: RecordObservationsRequest,
    run: Annotated[Run, Depends(get_run)],
    store: Annotated[Store, Depends(get_store)],
) -> dict:
    evaluation = _require_eval(store.record_observations(run.id, eval_id, req.source, req.data), eval_id)
    return evaluation.observations


# --- /current mirrors ---


@current_router.get("/environment", status_code=status.HTTP_200_OK)
def get_current_environment(evaluation: Annotated[Evaluation, Depends(get_current_evaluation)]) -> dict:
    return evaluation.environment.model_dump()


@current_router.get(
    "/function-calls",
    response_model=list[FunctionCallResponse],
    status_code=status.HTTP_200_OK,
)
def list_current_function_calls(
    evaluation: Annotated[Evaluation, Depends(get_current_evaluation)],
) -> list[FunctionCallRecord]:
    return evaluation.function_calls


@current_router.get(
    "/function-calls/{idx}",
    response_model=FunctionCallResponse,
    status_code=status.HTTP_200_OK,
)
def get_current_function_call(
    idx: int, evaluation: Annotated[Evaluation, Depends(get_current_evaluation)]
) -> FunctionCallRecord:
    if idx < 0 or idx >= len(evaluation.function_calls):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Function call index out of range: {idx}")
    return evaluation.function_calls[idx]


@current_router.post(
    "/function-calls",
    response_model=FunctionCallResponse,
    status_code=status.HTTP_201_CREATED,
)
def record_current_function_call(
    req: CreateFunctionCallRecord,
    ids: Annotated[tuple[str, str], Depends(get_current_ids)],
    store: Annotated[Store, Depends(get_store)],
) -> FunctionCallRecord:
    run_id, eval_id = ids
    evaluation = _require_current(store.append_function_call(run_id, eval_id, req))
    return evaluation.function_calls[-1]


@current_router.get("/observations", status_code=status.HTTP_200_OK)
def get_current_observations(evaluation: Annotated[Evaluation, Depends(get_current_evaluation)]) -> dict:
    return evaluation.observations


@current_router.post("/observations", status_code=status.HTTP_200_OK)
def record_current_observations(
    req: RecordObservationsRequest,
    ids: Annotated[tuple[str, str], Depends(get_current_ids)],
    store: Annotated[Store, Depends(get_store)],
) -> dict:
    run_id, eval_id = ids
    evaluation = _require_current(store.record_observations(run_id, eval_id, req.source, req.data))
    return evaluation.observations


# --- Injection plan endpoints ---


def _instruction_to_dict(i: InjectionInstruction) -> dict:
    if isinstance(i, EnvInjection):
        return {"type": "env", "payload": i.payload, "probe_key": i.probe_key}
    if isinstance(i, PromptInjection):
        return {"type": "prompt", "payload": i.payload, "probe_key": i.probe_key}
    return {
        "type": "tool", "payload": i.payload,
        "target_tool": i.target_tool, "target_field": i.target_field, "mode": i.mode,
    }


def _plan_to_dicts(plan: list[InjectionInstruction]) -> list[dict]:
    return [_instruction_to_dict(i) for i in plan]


def _model_to_instruction(m: InjectionInstructionModel) -> InjectionInstruction:
    if isinstance(m, EnvInjectionModel):
        return EnvInjection(payload=m.payload, probe_key=m.probe_key)
    if isinstance(m, PromptInjectionModel):
        return PromptInjection(payload=m.payload, probe_key=m.probe_key)
    return ToolInjection(
        payload=m.payload, target_tool=m.target_tool,
        target_field=m.target_field, mode=m.mode,
    )


def _plan_from_request(req: SetInjectionPlanRequest) -> list[InjectionInstruction]:
    return [_model_to_instruction(i) for i in req.instructions]


@router.get(
    "/{run_id}/evaluations/{eval_id}/injection-plan",
    response_model=list[InjectionInstructionModel],
    status_code=status.HTTP_200_OK,
)
def get_injection_plan(
    evaluation: Annotated[Evaluation, Depends(get_evaluation_by_id)],
) -> list[dict]:
    return _plan_to_dicts(evaluation.injection_plan)


@router.put(
    "/{run_id}/evaluations/{eval_id}/injection-plan",
    response_model=list[InjectionInstructionModel],
    status_code=status.HTTP_200_OK,
)
def set_injection_plan(
    eval_id: str,
    req: SetInjectionPlanRequest,
    run: Annotated[Run, Depends(get_run)],
    store: Annotated[Store, Depends(get_store)],
) -> list[dict]:
    evaluation = _require_eval(store.set_injection_plan(run.id, eval_id, _plan_from_request(req)), eval_id)
    return _plan_to_dicts(evaluation.injection_plan)


@current_router.get(
    "/injection-plan",
    response_model=list[InjectionInstructionModel],
    status_code=status.HTTP_200_OK,
)
def get_current_injection_plan(
    evaluation: Annotated[Evaluation, Depends(get_current_evaluation)],
) -> list[dict]:
    return _plan_to_dicts(evaluation.injection_plan)


@current_router.put(
    "/injection-plan",
    response_model=list[InjectionInstructionModel],
    status_code=status.HTTP_200_OK,
)
def set_current_injection_plan(
    req: SetInjectionPlanRequest,
    ids: Annotated[tuple[str, str], Depends(get_current_ids)],
    store: Annotated[Store, Depends(get_store)],
) -> list[dict]:
    run_id, eval_id = ids
    evaluation = _require_current(store.set_injection_plan(run_id, eval_id, _plan_from_request(req)))
    return _plan_to_dicts(evaluation.injection_plan)


@current_router.post("/refresh", response_model=RefreshResponse, status_code=status.HTTP_200_OK)
def refresh_current_eval(
    req: RefreshRequest,
    evaluation: Annotated[Evaluation, Depends(get_current_evaluation)],
    suite: Annotated[YAMLTaskSuite, Depends(get_suite)],
    store: Annotated[Store, Depends(get_store)],
) -> RefreshResponse:
    """Refresh the eval's environment and prompt from current mutable injections.

    Reads the injection plan, builds an injections dict from env/prompt-type
    instructions, re-provisions the environment, and re-renders the prompt.
    If ``reset_state`` is true (default), resets env and clears function calls.
    """
    plan = evaluation.injection_plan
    mutable_injections = {
        i.probe_key: i.payload for i in plan if isinstance(i, EnvInjection | PromptInjection)
    }
    merged = {**evaluation.active_injections, **mutable_injections}

    if req.reset_state:
        environment = suite.provision_environment(merged)
        pre_environment = environment.model_copy(deep=True)
        store.set_environment(evaluation.run_id, evaluation.id, environment)
        evaluation.pre_environment = pre_environment
        evaluation.function_calls.clear()
    else:
        if mutable_injections and evaluation.env_template:
            environment = suite.provision_environment(merged)
            store.set_environment(evaluation.run_id, evaluation.id, environment)

    prompt = suite.inject_user_task_prompt(evaluation.user_task_id, merged)
    evaluation.agent_input = prompt

    return RefreshResponse(prompt=prompt)
