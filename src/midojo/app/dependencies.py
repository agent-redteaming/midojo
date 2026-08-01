from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status

from midojo.yaml_task_suite import YAMLTaskSuite

from . import state
from .state import Evaluation, Run
from .store import Store


def get_store() -> Store:
    return state.store


def get_suite() -> YAMLTaskSuite:
    return state.suite


def get_run(run_id: str, store: Annotated[Store, Depends(get_store)]) -> Run:
    run = store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown run: {run_id}")
    return run


def get_evaluation_by_id(
    eval_id: str,
    run: Annotated[Run, Depends(get_run)],
    store: Annotated[Store, Depends(get_store)],
) -> Evaluation:
    evaluation = store.get_evaluation(run.id, eval_id)
    if evaluation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown evaluation: {eval_id}")
    return evaluation


def get_current_evaluation(store: Annotated[Store, Depends(get_store)]) -> Evaluation:
    evaluation = store.get_current_evaluation()
    if evaluation is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No evaluation in progress.")
    return evaluation
