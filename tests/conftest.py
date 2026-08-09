import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from midojo.app import state
from midojo.app.routers import runs, tasks
from midojo.app.routers import suite as suite_router
from midojo.app.store import InMemoryStore
from midojo.suites import get_suite

task_suite = get_suite("weather")


@pytest.fixture
def suite():
    return task_suite


@pytest.fixture
def environment():
    return task_suite.provision_environment({})


@pytest.fixture()
def app() -> FastAPI:
    state.suite = task_suite
    state.store = InMemoryStore()
    application = FastAPI()
    application.include_router(suite_router.router)
    application.include_router(tasks.router)
    runs.register_environment_update_route(task_suite.environment_type)
    application.include_router(runs.router)
    application.include_router(runs.current_router)
    return application


@pytest.fixture()
def client(app) -> TestClient:
    return TestClient(app)
