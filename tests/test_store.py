"""Unit tests for the in-memory Store implementation (PR1 store seam)."""

from __future__ import annotations

from midojo.app.models import CreateFunctionCallRecord
from midojo.app.store import InMemoryStore
from midojo.types import Environment


class _Env(Environment):
    counter: int = 0


def _fc(function: str, result: str) -> CreateFunctionCallRecord:
    return CreateFunctionCallRecord(function=function, args={}, result=result)


def _make_eval(
    store: InMemoryStore,
    run_id: str,
    *,
    environment: Environment | None = None,
    pre_environment: Environment | None = None,
    agent_input: str | None = None,
):
    return store.create_evaluation(
        run_id,
        user_task_id="ut",
        injection_task_id=None,
        pre_environment=pre_environment if pre_environment is not None else _Env(),
        environment=environment if environment is not None else _Env(),
        active_injections={},
        agent_input=agent_input,
    )


# --- runs ---


def test_create_run_round_trip():
    store = InMemoryStore()
    r1 = store.create_run()
    r2 = store.create_run()
    # Each run is retrievable by its own id: two creates coexist without clobbering
    # (if create_run reused an id, get_run(r1.id) would return r2).
    assert store.get_run(r1.id) is r1
    assert store.get_run(r2.id) is r2


def test_get_run_unknown_returns_none():
    # None (not a raise) is the contract the dependency layer turns into a 404.
    store = InMemoryStore()
    assert store.get_run("nope") is None


def test_list_runs():
    store = InMemoryStore()
    assert store.list_runs() == []
    r1 = store.create_run()
    r2 = store.create_run()
    assert {r.id for r in store.list_runs()} == {r1.id, r2.id}


# --- evaluations ---


def test_create_evaluation_stored_under_run_and_current():
    store = InMemoryStore()
    run = store.create_run()
    ev = _make_eval(store, run.id, agent_input="prompt")
    assert store.get_evaluation(run.id, ev.id) is ev
    assert store.get_current_evaluation() is ev
    assert ev.agent_input == "prompt"  # kwarg is plumbed through to the Evaluation


def test_get_evaluation_unknown_returns_none():
    store = InMemoryStore()
    run = store.create_run()
    # Two distinct not-found branches: known run/unknown eval, and unknown run.
    assert store.get_evaluation(run.id, "nope") is None
    assert store.get_evaluation("nope", "nope") is None


def test_get_current_evaluation_none_before_any():
    # Backs the "No evaluation in progress" 400 before anything is created.
    store = InMemoryStore()
    assert store.get_current_evaluation() is None


def test_current_evaluation_follows_latest():
    store = InMemoryStore()
    run = store.create_run()
    _make_eval(store, run.id)
    ev2 = _make_eval(store, run.id)
    # Creating a second eval switches /current onto it (the eval-switch semantics).
    assert store.get_current_evaluation() is ev2


# --- function calls ---


def test_append_function_call_first_call_chains_from_pre_environment():
    store = InMemoryStore()
    run = store.create_run()
    # pre_environment and the live environment differ so the assertion can tell
    # which one the first call's pre-env is taken from.
    ev = _make_eval(store, run.id, pre_environment=_Env(counter=7), environment=_Env(counter=9))
    rec = store.append_function_call(ev, _fc("a", "r0"))
    assert isinstance(rec.pre_environment, _Env)
    assert rec.pre_environment.counter == 7  # first call chains from pre_environment, not the live env
    assert isinstance(rec.post_environment, _Env)
    assert rec.post_environment.counter == 9
    assert ev.function_calls == [rec]


def test_append_function_call_chains_pre_env_across_environment_change():
    store = InMemoryStore()
    run = store.create_run()
    ev = _make_eval(store, run.id, environment=_Env(counter=0))
    r0 = store.append_function_call(ev, _fc("a", "r0"))
    store.set_environment(ev, _Env(counter=1))
    r1 = store.append_function_call(ev, _fc("b", "r1"))
    # Second call's pre-env is the first call's post-env...
    assert r1.pre_environment == r0.post_environment
    # ...and its post-env reflects the set_environment that happened in between.
    assert isinstance(r1.post_environment, _Env)
    assert r1.post_environment.counter == 1
    assert ev.function_calls == [r0, r1]


def test_append_function_call_post_env_is_deep_copy():
    store = InMemoryStore()
    run = store.create_run()
    env = _Env(counter=0)
    ev = _make_eval(store, run.id, environment=env)
    rec = store.append_function_call(ev, _fc("a", "r"))
    env.counter = 99  # mutate the live env in place after recording
    # The recorded snapshot is a deep copy, so it doesn't track later mutations.
    assert isinstance(rec.post_environment, _Env)
    assert rec.post_environment.counter == 0


# --- observations / grade / complete ---


def test_record_observations_keyed_by_source():
    store = InMemoryStore()
    run = store.create_run()
    ev = _make_eval(store, run.id)
    obs = store.record_observations(ev, "openshell", ["e1"])
    assert obs == {"openshell": ["e1"]}
    store.record_observations(ev, "acs", {"x": 1})
    assert ev.observations == {"openshell": ["e1"], "acs": {"x": 1}}
    # A second write to the same source replaces that source's value only.
    store.record_observations(ev, "openshell", ["e2"])
    assert ev.observations == {"openshell": ["e2"], "acs": {"x": 1}}


def test_set_grade():
    store = InMemoryStore()
    run = store.create_run()
    ev = _make_eval(store, run.id)
    # Distinct values guard against the two flags being swapped.
    store.set_grade(ev, utility=True, security=False)
    assert ev.utility is True
    assert ev.security is False


def test_complete_evaluation():
    store = InMemoryStore()
    run = store.create_run()
    ev = _make_eval(store, run.id)
    store.complete_evaluation(ev, "final answer")
    # Completing records both the flag and the agent's final output.
    assert ev.completed is True
    assert ev.agent_output == "final answer"
