from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from midojo.types import FunctionCallRecord
from midojo.yaml_task_suite import YAMLTaskSuite

from ..dependencies import (
    get_current_evaluation,
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
    EvaluationResponse,
    EvaluationSummary,
    FunctionCallResponse,
    GradeResponse,
    RecordObservationsRequest,
    RunResponse,
)
from ..state import Evaluation, Run
from ..store import Store

router = APIRouter(prefix="/runs")

# Mirrors of the per-eval environment + function-call endpoints that resolve the
# active eval from the store. Used by long-lived MCP servers / PI extensions that
# don't have a run/eval ID at construction time. See dependencies.get_current_evaluation.
current_router = APIRouter(prefix="/current")


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
        agent_input=evaluation.agent_input,
        agent_output=evaluation.agent_output,
        function_calls=[FunctionCallResponse.model_validate(fc) for fc in evaluation.function_calls],
    )


@router.post("/{run_id}/evaluations/{eval_id}/complete", status_code=status.HTTP_200_OK)
def complete_evaluation(
    req: CompleteRequest,
    evaluation: Annotated[Evaluation, Depends(get_evaluation_by_id)],
    store: Annotated[Store, Depends(get_store)],
):
    store.complete_evaluation(evaluation, req.agent_output)
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
    store.set_grade(evaluation, utility=result["utility"], security=result["security"])
    return GradeResponse(**result)


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
        body,
        evaluation: Annotated[Evaluation, Depends(get_evaluation_by_id)],
        store: Annotated[Store, Depends(get_store)],
    ) -> dict:
        store.set_environment(evaluation, body)
        return evaluation.environment.model_dump()

    update_environment.__annotations__["body"] = env_type
    router.add_api_route("/{run_id}/evaluations/{eval_id}/environment", update_environment, methods=["PUT"])

    def update_current_environment(
        body,
        evaluation: Annotated[Evaluation, Depends(get_current_evaluation)],
        store: Annotated[Store, Depends(get_store)],
    ) -> dict:
        store.set_environment(evaluation, body)
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
    req: CreateFunctionCallRecord,
    evaluation: Annotated[Evaluation, Depends(get_evaluation_by_id)],
    store: Annotated[Store, Depends(get_store)],
) -> FunctionCallRecord:
    return store.append_function_call(evaluation, req)


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
    req: RecordObservationsRequest,
    evaluation: Annotated[Evaluation, Depends(get_evaluation_by_id)],
    store: Annotated[Store, Depends(get_store)],
) -> dict:
    return store.record_observations(evaluation, req.source, req.data)


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
    evaluation: Annotated[Evaluation, Depends(get_current_evaluation)],
    store: Annotated[Store, Depends(get_store)],
) -> FunctionCallRecord:
    return store.append_function_call(evaluation, req)


@current_router.get("/observations", status_code=status.HTTP_200_OK)
def get_current_observations(evaluation: Annotated[Evaluation, Depends(get_current_evaluation)]) -> dict:
    return evaluation.observations


@current_router.post("/observations", status_code=status.HTTP_200_OK)
def record_current_observations(
    req: RecordObservationsRequest,
    evaluation: Annotated[Evaluation, Depends(get_current_evaluation)],
    store: Annotated[Store, Depends(get_store)],
) -> dict:
    return store.record_observations(evaluation, req.source, req.data)
