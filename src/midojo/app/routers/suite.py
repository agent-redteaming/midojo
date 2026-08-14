from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status

from midojo.yaml_task_suite import YAMLTaskSuite

from ..dependencies import get_suite
from ..models import SuiteInfoResponse

router = APIRouter(prefix="/suite")


@router.get("", response_model=SuiteInfoResponse, status_code=status.HTTP_200_OK)
def suite_info(suite: Annotated[YAMLTaskSuite, Depends(get_suite)]):
    return SuiteInfoResponse(
        user_tasks=list(suite.user_tasks.keys()),
        injection_tasks=list(suite.injection_tasks.keys()),
        environment=suite.provision_environment({}),
    )
