from fastapi.testclient import TestClient

from midojo.app import state
from midojo.app.state import Evaluation


def _current_eval() -> Evaluation:
    """The store's active eval, for asserting internal (non-API) server state."""
    evaluation = state.store.get_current_evaluation()
    assert evaluation is not None
    return evaluation


def _create_run(client: TestClient) -> str:
    resp = client.post("/runs")
    assert resp.status_code == 201
    return resp.json()["id"]


def _create_evaluation(client: TestClient, run_id: str, **kwargs) -> dict:
    payload = {"user_task_id": "user_task_0", **kwargs}
    resp = client.post(f"/runs/{run_id}/evaluations", json=payload)
    assert resp.status_code == 201
    return resp.json()


def test_create_run(client):
    run_id = _create_run(client)
    assert len(run_id) > 0


def test_get_run(client):
    run_id = _create_run(client)
    resp = client.get(f"/runs/{run_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == run_id
    assert data["evaluations"] == []


def test_get_run_not_found(client):
    resp = client.get("/runs/nonexistent")
    assert resp.status_code == 404


def test_create_evaluation(client):
    run_id = _create_run(client)
    data = _create_evaluation(client, run_id)
    assert "id" in data
    assert "prompt" in data
    assert "weather" in data["prompt"].lower()


def test_create_evaluation_unknown_task(client):
    run_id = _create_run(client)
    resp = client.post(f"/runs/{run_id}/evaluations", json={"user_task_id": "nonexistent"})
    assert resp.status_code == 400


def test_get_evaluation(client):
    run_id = _create_run(client)
    eval_data = _create_evaluation(client, run_id)
    eval_id = eval_data["id"]

    resp = client.get(f"/runs/{run_id}/evaluations/{eval_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == eval_id
    assert data["user_task_id"] == "user_task_0"
    assert data["completed"] is False
    assert "agent_input" in data
    assert "weather" in data["agent_input"].lower()


def test_complete_and_grade_utility_only(client):
    run_id = _create_run(client)
    eval_data = _create_evaluation(client, run_id)
    eval_id = eval_data["id"]

    resp = client.post(
        f"/runs/{run_id}/evaluations/{eval_id}/complete",
        json={"agent_output": "The weather in New York is 72°F and sunny."},
    )
    assert resp.status_code == 200

    resp = client.get(f"/runs/{run_id}/evaluations/{eval_id}")
    assert resp.json()["completed"] is True

    resp = client.post(f"/runs/{run_id}/evaluations/{eval_id}/grade")
    assert resp.status_code == 200
    data = resp.json()
    assert data["utility"] is True
    assert data["security"] is False


def test_grade_before_complete(client):
    run_id = _create_run(client)
    eval_data = _create_evaluation(client, run_id)
    eval_id = eval_data["id"]

    resp = client.post(f"/runs/{run_id}/evaluations/{eval_id}/grade")
    assert resp.status_code == 400


def test_record_function_call_via_post(client):
    run_id = _create_run(client)
    eval_data = _create_evaluation(client, run_id)
    eval_id = eval_data["id"]

    resp = client.post(
        f"/runs/{run_id}/evaluations/{eval_id}/function-calls",
        json={"function": "get_weather", "args": {"city": "New York"}, "result": "72°F, sunny", "error": None},
    )
    assert resp.status_code == 201
    record = resp.json()
    assert record["function"] == "get_weather"
    assert record["args"] == {"city": "New York"}
    assert record["result"] == "72°F, sunny"
    assert record["error"] is None
    assert "timestamp" in record
    # Env snapshots are internal server state, not part of the public response.
    assert "pre_environment" not in record
    assert "post_environment" not in record

    resp = client.get(f"/runs/{run_id}/evaluations/{eval_id}/function-calls")
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    # ...but they are still captured server-side for grading.
    recorded = _current_eval().function_calls[0]
    assert recorded.pre_environment is not None
    assert recorded.post_environment is not None


def test_record_function_call_pre_env_chain(client):
    """pre_environment of each call should match post_environment of the previous call.

    The chaining is an internal invariant (env snapshots aren't exposed over the
    API), so it's asserted against the recorded server-side state.
    """
    run_id = _create_run(client)
    eval_data = _create_evaluation(client, run_id)
    eval_id = eval_data["id"]

    initial_env = client.get(f"/runs/{run_id}/evaluations/{eval_id}/environment").json()

    client.post(
        f"/runs/{run_id}/evaluations/{eval_id}/function-calls",
        json={"function": "get_weather", "args": {"city": "New York"}, "result": "72°F, sunny"},
    )

    client.put(
        f"/runs/{run_id}/evaluations/{eval_id}/environment",
        json={**initial_env, "weather_alerts": [{"city": "New York", "message": "Storm warning"}]},
    )

    client.post(
        f"/runs/{run_id}/evaluations/{eval_id}/function-calls",
        json={
            "function": "send_weather_alert",
            "args": {"city": "New York", "message": "Storm warning"},
            "result": "ok",
        },
    )

    calls = _current_eval().function_calls
    assert calls[0].pre_environment.model_dump() == initial_env
    assert calls[1].pre_environment == calls[0].post_environment
    assert calls[1].post_environment.model_dump()["weather_alerts"] == [
        {"city": "New York", "message": "Storm warning"}
    ]


# --- /current/* endpoints ---


def test_current_environment_400_before_eval(client):
    resp = client.get("/current/environment")
    assert resp.status_code == 400


def test_current_environment_resolves_active_eval(client):
    run_id = _create_run(client)
    eval_data = _create_evaluation(client, run_id)
    eval_id = eval_data["id"]

    resp = client.get("/current/environment")
    assert resp.status_code == 200
    assert resp.json() == client.get(f"/runs/{run_id}/evaluations/{eval_id}/environment").json()


def test_current_environment_put(client):
    run_id = _create_run(client)
    eval_data = _create_evaluation(client, run_id)
    eval_id = eval_data["id"]

    env = client.get("/current/environment").json()
    env["weather_alerts"] = [{"city": "Boston", "message": "blizzard"}]
    resp = client.put("/current/environment", json=env)
    assert resp.status_code == 200
    # The PUT's own body is built from the mutated Evaluation, not re-fetched.
    assert resp.json()["weather_alerts"] == [{"city": "Boston", "message": "blizzard"}]

    fresh = client.get(f"/runs/{run_id}/evaluations/{eval_id}/environment").json()
    assert fresh["weather_alerts"] == [{"city": "Boston", "message": "blizzard"}]


def test_current_function_calls_post_and_list(client):
    run_id = _create_run(client)
    eval_data = _create_evaluation(client, run_id)
    eval_id = eval_data["id"]

    resp = client.post(
        "/current/function-calls",
        json={"function": "get_weather", "args": {"city": "New York"}, "result": "72°F"},
    )
    assert resp.status_code == 201

    listed = client.get("/current/function-calls").json()
    assert len(listed) == 1
    assert listed[0]["function"] == "get_weather"

    # Same record should be visible via the nested URL.
    nested = client.get(f"/runs/{run_id}/evaluations/{eval_id}/function-calls").json()
    assert len(nested) == 1


def test_current_follows_eval_switch(client):
    """Creating a new eval should make /current resolve to it, not the previous one."""
    run_id = _create_run(client)
    eval1 = _create_evaluation(client, run_id)["id"]

    client.post(
        "/current/function-calls",
        json={"function": "get_weather", "args": {"city": "NYC"}, "result": "first eval"},
    )

    eval2 = _create_evaluation(client, run_id)["id"]
    assert eval2 != eval1

    client.post(
        "/current/function-calls",
        json={"function": "get_weather", "args": {"city": "NYC"}, "result": "second eval"},
    )

    eval1_calls = client.get(f"/runs/{run_id}/evaluations/{eval1}/function-calls").json()
    eval2_calls = client.get(f"/runs/{run_id}/evaluations/{eval2}/function-calls").json()
    assert len(eval1_calls) == 1
    assert eval1_calls[0]["result"] == "first eval"
    assert len(eval2_calls) == 1
    assert eval2_calls[0]["result"] == "second eval"


def test_create_evaluation_substitutes_prompt_probe_placeholder(client):
    """When a user task's prompt contains {task:probe}, the substituted prompt is returned."""
    run_id = _create_run(client)
    data = _create_evaluation(
        client,
        run_id,
        user_task_id="user_task_3",
        injection_task_id="injection_task_3",
        injections={"injection_task_3:embedded": "POISONED CITY NAME"},
    )
    assert "POISONED CITY NAME" in data["prompt"]
    assert "{injection_task_3" not in data["prompt"]


def test_create_evaluation_prompt_placeholder_collapses_for_inactive_task(client):
    """user_task_3's prompt placeholder collapses to "" when paired with another task."""
    run_id = _create_run(client)
    data = _create_evaluation(
        client,
        run_id,
        user_task_id="user_task_3",
        injection_task_id="injection_task_0",
        injections={"injection_task_0:main": "anything"},
    )
    assert "{injection_task_3" not in data["prompt"]
    # The placeholder is gone; the surrounding template text remains.
    assert data["prompt"].startswith("Tell me the weather for this city:")


# --- Observations ---


def test_record_and_get_observations(client):
    run_id = _create_run(client)
    eval_id = _create_evaluation(client, run_id)["id"]

    events = ["NET:OPEN DENIED curl -> evil.com:443"]
    resp = client.post(
        f"/runs/{run_id}/evaluations/{eval_id}/observations",
        json={"source": "openshell", "data": events},
    )
    assert resp.status_code == 200
    # The POST's own body is built from the mutated Evaluation, not re-fetched.
    assert resp.json() == {"openshell": events}

    assert client.get(f"/runs/{run_id}/evaluations/{eval_id}/observations").json() == {"openshell": events}
    assert _current_eval().observations == {"openshell": events}


def test_current_observations_keyed_by_source(client):
    run_id = _create_run(client)
    _create_evaluation(client, run_id)

    client.post("/current/observations", json={"source": "openshell", "data": ["PROC:LAUNCH curl"]})
    client.post("/current/observations", json={"source": "acs", "data": {"processes": ["curl"]}})

    assert client.get("/current/observations").json() == {
        "openshell": ["PROC:LAUNCH curl"],
        "acs": {"processes": ["curl"]},
    }


# --- 404s on the nested mutation routes ---
#
# The mutation routes depend on get_run (validates the run) and turn a None store
# return into a 404 via _require_eval. These exercise both not-found branches --
# unknown eval under a known run, and unknown run -- across every mutation route,
# so a miswired handler (missing _require_eval, wrong status/detail) is caught.


def _mutation_requests(client: TestClient, run_id: str, eval_id: str, env: dict) -> dict:
    return {
        "complete": lambda: client.post(f"/runs/{run_id}/evaluations/{eval_id}/complete", json={"agent_output": "x"}),
        "function-calls": lambda: client.post(
            f"/runs/{run_id}/evaluations/{eval_id}/function-calls",
            json={"function": "f", "args": {}, "result": "r"},
        ),
        "observations": lambda: client.post(
            f"/runs/{run_id}/evaluations/{eval_id}/observations",
            json={"source": "s", "data": []},
        ),
        "environment": lambda: client.put(f"/runs/{run_id}/evaluations/{eval_id}/environment", json=env),
    }


def test_nested_mutation_routes_unknown_eval_404(client):
    """Known run + unknown eval -> 404 'Unknown evaluation' from _require_eval on every mutation route."""
    run_id = _create_run(client)
    _create_evaluation(client, run_id)  # a real eval, so a valid env body is available for the PUT
    env = client.get("/current/environment").json()

    for name, send in _mutation_requests(client, run_id, "BOGUS", env).items():
        resp = send()
        assert resp.status_code == 404, name
        assert resp.json()["detail"] == "Unknown evaluation: BOGUS", name


def test_nested_mutation_routes_unknown_run_404(client):
    """Unknown run -> 404 'Unknown run' from get_run, before the eval check runs."""
    run_id = _create_run(client)
    _create_evaluation(client, run_id)
    env = client.get("/current/environment").json()

    for name, send in _mutation_requests(client, "BOGUS", "E", env).items():
        resp = send()
        assert resp.status_code == 404, name
        assert resp.json()["detail"] == "Unknown run: BOGUS", name
