from __future__ import annotations

from fastapi import FastAPI

from midojo.yaml_task_suite import YAMLTaskSuite

from . import state
from .routers import runs, suite, tasks
from .store import InMemoryStore


def create_app(suite_instance: YAMLTaskSuite) -> FastAPI:
    state.suite = suite_instance
    state.store = InMemoryStore()

    app = FastAPI()
    app.include_router(suite.router)
    app.include_router(tasks.router)
    runs.register_environment_update_route(suite_instance.environment_type)
    app.include_router(runs.router)
    app.include_router(runs.current_router)
    return app
