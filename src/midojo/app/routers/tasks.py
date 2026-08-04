from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from midojo.yaml_task_suite import YAMLTaskSuite

from ..dependencies import get_suite
from ..models import TaskDetailResponse

router = APIRouter(prefix="/tasks")


@router.get("/user", status_code=status.HTTP_200_OK)
def list_user_tasks(suite: Annotated[YAMLTaskSuite, Depends(get_suite)]) -> list[str]:
    return list(suite.user_tasks.keys())


@router.get("/user/{task_id}", response_model=TaskDetailResponse, status_code=status.HTTP_200_OK)
def get_user_task(task_id: str, suite: Annotated[YAMLTaskSuite, Depends(get_suite)]):
    if task_id not in suite.user_tasks:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown user task: {task_id}")
    task = suite.user_tasks[task_id]
    return TaskDetailResponse(
        id=task_id,
        type="user",
        prompt=task.prompt,
    )


@router.get("/injection", status_code=status.HTTP_200_OK)
def list_injection_tasks(suite: Annotated[YAMLTaskSuite, Depends(get_suite)]) -> list[str]:
    return list(suite.injection_tasks.keys())


@router.get("/injection/{task_id}", response_model=TaskDetailResponse, status_code=status.HTTP_200_OK)
def get_injection_task(task_id: str, suite: Annotated[YAMLTaskSuite, Depends(get_suite)]):
    if task_id not in suite.injection_tasks:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown injection task: {task_id}")
    task = suite.injection_tasks[task_id]
    return TaskDetailResponse(
        id=task_id,
        type="injection",
        description=task.description,
    )
