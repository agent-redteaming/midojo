"""State persistence seam for the control plane.

All run/evaluation state is accessed through the :class:`Store` protocol so the
routers never touch process globals directly. :class:`InMemoryStore` is the
default, process-local implementation (state lost on restart); a Postgres-backed
store can be dropped in behind the same interface without changing the routers.

Per-evaluation mutations are ID-based (``run_id``, ``eval_id``) so they map
directly to a future ``UPDATE … WHERE`` without relying on live Python objects.
Each returns the mutated :class:`Evaluation`, or ``None`` if no such evaluation
exists; the HTTP layer turns ``None`` into a 404 (a 400 on the ``/current`` routes).

The store also owns identity (id generation) and tracks the single "current"
evaluation that backs the ``/current`` endpoints — behavior preserved from the
old module-global ``state.current_eval`` for now.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from midojo.types import Environment, FunctionCallRecord

from .models import CreateFunctionCallRecord
from .state import Evaluation, InjectionInstruction, Run


def _new_id() -> str:
    return uuid.uuid4().hex[:8]


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
    def get_current_ids(self) -> tuple[str, str] | None: ...

    # --- per-evaluation mutations (ID-based) ---
    # Each returns the mutated evaluation, or None if (run_id, eval_id) is unknown.
    def append_function_call(self, run_id: str, eval_id: str, req: CreateFunctionCallRecord) -> Evaluation | None: ...
    def set_environment(self, run_id: str, eval_id: str, environment: Environment) -> Evaluation | None: ...
    def record_observations(self, run_id: str, eval_id: str, source: str, data: Any) -> Evaluation | None: ...
    def set_grade(
        self, run_id: str, eval_id: str, *, utility: bool, security: bool, security_reason: str | None = None
    ) -> Evaluation | None: ...
    def complete_evaluation(self, run_id: str, eval_id: str, agent_output: str) -> Evaluation | None: ...
    def set_injection_plan(
        self, run_id: str, eval_id: str, plan: list[InjectionInstruction],
    ) -> Evaluation | None: ...


class InMemoryStore:
    """Process-local, in-memory :class:`Store`. State is lost on restart."""

    def __init__(self) -> None:
        self._runs: dict[str, Run] = {}
        # Only one eval is active at a time — the orchestrator runs tasks
        # sequentially. Tracked as (run_id, eval_id) to back the /current
        # endpoints; concurrent evals would clobber it (superseded by
        # session-scoped resolution later).
        self._current_ids: tuple[str, str] | None = None

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
            run_id=run_id,
            user_task_id=user_task_id,
            injection_task_id=injection_task_id,
            pre_environment=pre_environment,
            environment=environment,
            active_injections=active_injections,
            agent_input=agent_input,
        )
        self._runs[run_id].evaluations[evaluation.id] = evaluation
        self._current_ids = (run_id, evaluation.id)
        return evaluation

    def get_evaluation(self, run_id: str, eval_id: str) -> Evaluation | None:
        run = self._runs.get(run_id)
        if run is None:
            return None
        return run.evaluations.get(eval_id)

    def get_current_evaluation(self) -> Evaluation | None:
        ids = self.get_current_ids()
        if ids is None:
            return None
        return self.get_evaluation(*ids)

    def get_current_ids(self) -> tuple[str, str] | None:
        return self._current_ids

    # --- per-evaluation mutations ---

    def append_function_call(self, run_id: str, eval_id: str, req: CreateFunctionCallRecord) -> Evaluation | None:
        evaluation = self.get_evaluation(run_id, eval_id)
        if evaluation is None:
            return None
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
        return evaluation

    def set_environment(self, run_id: str, eval_id: str, environment: Environment) -> Evaluation | None:
        evaluation = self.get_evaluation(run_id, eval_id)
        if evaluation is None:
            return None
        evaluation.environment = environment
        return evaluation

    def record_observations(self, run_id: str, eval_id: str, source: str, data: Any) -> Evaluation | None:
        evaluation = self.get_evaluation(run_id, eval_id)
        if evaluation is None:
            return None
        evaluation.observations[source] = data
        return evaluation

    def set_grade(
        self, run_id: str, eval_id: str, *, utility: bool, security: bool, security_reason: str | None = None
    ) -> Evaluation | None:
        evaluation = self.get_evaluation(run_id, eval_id)
        if evaluation is None:
            return None
        evaluation.utility = utility
        evaluation.security = security
        evaluation.security_reason = security_reason
        return evaluation

    def complete_evaluation(self, run_id: str, eval_id: str, agent_output: str) -> Evaluation | None:
        evaluation = self.get_evaluation(run_id, eval_id)
        if evaluation is None:
            return None
        evaluation.agent_output = agent_output
        evaluation.completed = True
        return evaluation

    def set_injection_plan(
        self, run_id: str, eval_id: str, plan: list[InjectionInstruction],
    ) -> Evaluation | None:
        evaluation = self.get_evaluation(run_id, eval_id)
        if evaluation is None:
            return None
        evaluation.injection_plan = plan
        return evaluation
