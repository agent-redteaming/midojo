"""State persistence seam for the control plane.

All run/evaluation state is accessed through the :class:`Store` protocol so the
routers never touch process globals directly. :class:`InMemoryStore` is the
default, process-local implementation (state lost on restart); a Postgres-backed
store can be dropped in behind the same interface without changing the routers.

The store also owns identity (id generation) and tracks the single "current"
evaluation that backs the ``/current`` endpoints — behavior preserved from the
old module-global ``state.current_eval`` for now.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

from midojo.types import Environment, FunctionCallRecord

from .models import CreateFunctionCallRecord
from .state import Evaluation, Run, _new_id


class Store(Protocol):
    """Interface for run/evaluation persistence."""

    # --- runs ---
    def create_run(self) -> Run: ...
    def get_run(self, run_id: str) -> Run | None: ...
    def list_runs(self) -> list[Run]: ...

    # --- evaluations ---
    def create_evaluation(
        self,
        run_id: str,
        *,
        user_task_id: str,
        injection_task_id: str | None,
        pre_environment: Environment,
        environment: Environment,
        active_injections: dict[str, str],
        agent_input: str | None = None,
    ) -> Evaluation: ...
    def get_evaluation(self, run_id: str, eval_id: str) -> Evaluation | None: ...
    def get_current_evaluation(self) -> Evaluation | None: ...

    # --- per-evaluation mutations ---
    def append_function_call(self, evaluation: Evaluation, req: CreateFunctionCallRecord) -> FunctionCallRecord: ...
    def set_environment(self, evaluation: Evaluation, environment: Environment) -> None: ...
    def record_observations(self, evaluation: Evaluation, source: str, data: Any) -> dict[str, Any]: ...
    def set_grade(self, evaluation: Evaluation, *, utility: bool, security: bool) -> None: ...
    def complete_evaluation(self, evaluation: Evaluation, agent_output: str) -> None: ...


class InMemoryStore:
    """Process-local, in-memory :class:`Store`. State is lost on restart."""

    def __init__(self) -> None:
        self._runs: dict[str, Run] = {}
        # Only one eval is active at a time — the orchestrator runs tasks
        # sequentially. Tracked here to back the /current endpoints; concurrent
        # evals would clobber it (superseded by session-scoped resolution later).
        self._current_eval: Evaluation | None = None

    # --- runs ---

    def create_run(self) -> Run:
        run = Run(id=_new_id())
        self._runs[run.id] = run
        return run

    def get_run(self, run_id: str) -> Run | None:
        return self._runs.get(run_id)

    def list_runs(self) -> list[Run]:
        return list(self._runs.values())

    # --- evaluations ---

    def create_evaluation(
        self,
        run_id: str,
        *,
        user_task_id: str,
        injection_task_id: str | None,
        pre_environment: Environment,
        environment: Environment,
        active_injections: dict[str, str],
        agent_input: str | None = None,
    ) -> Evaluation:
        evaluation = Evaluation(
            id=_new_id(),
            user_task_id=user_task_id,
            injection_task_id=injection_task_id,
            pre_environment=pre_environment,
            environment=environment,
            active_injections=active_injections,
            agent_input=agent_input,
        )
        self._runs[run_id].evaluations[evaluation.id] = evaluation
        self._current_eval = evaluation
        return evaluation

    def get_evaluation(self, run_id: str, eval_id: str) -> Evaluation | None:
        run = self._runs.get(run_id)
        if run is None:
            return None
        return run.evaluations.get(eval_id)

    def get_current_evaluation(self) -> Evaluation | None:
        return self._current_eval

    # --- per-evaluation mutations ---

    def append_function_call(self, evaluation: Evaluation, req: CreateFunctionCallRecord) -> FunctionCallRecord:
        # Each call's pre-env is the previous call's post-env, chaining from the
        # eval's initial environment; post-env is a deep copy so later mutations
        # don't retroactively change the recorded snapshot.
        if evaluation.function_calls:
            pre_env = evaluation.function_calls[-1].post_environment
        else:
            pre_env = evaluation.pre_environment
        record = FunctionCallRecord(
            **req.model_dump(),
            timestamp=datetime.now(UTC).isoformat(),
            pre_environment=pre_env,
            post_environment=evaluation.environment.model_copy(deep=True),
        )
        evaluation.function_calls.append(record)
        return record

    def set_environment(self, evaluation: Evaluation, environment: Environment) -> None:
        evaluation.environment = environment

    def record_observations(self, evaluation: Evaluation, source: str, data: Any) -> dict[str, Any]:
        evaluation.observations[source] = data
        return evaluation.observations

    def set_grade(self, evaluation: Evaluation, *, utility: bool, security: bool) -> None:
        evaluation.utility = utility
        evaluation.security = security

    def complete_evaluation(self, evaluation: Evaluation, agent_output: str) -> None:
        evaluation.agent_output = agent_output
        evaluation.completed = True
