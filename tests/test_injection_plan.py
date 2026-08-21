"""Tests for the injection plan mechanism — the foundation layer.

Covers:
1. Data model: typed instructions (env/prompt/tool)
2. Control plane API: CRUD on injection plan, typed validation
3. Eval creation with injection plan
4. Refresh endpoint: re-render env/prompt from updated plan
5. SDK integration: get_matching_instruction filters by type and tool name
6. Injection execution: all modes (embed/replace/append/new_field)
7. Field auto-detection: find_best_field
8. Suite placement: build_injection_inputs from probe definitions
9. Backward compatibility: legacy suites with no placement
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi import FastAPI

from midojo.mcp_sdk import (
    ControlPlaneClient,
    _collect_string_fields,
    _splice_into_field,
    execute_injection,
    find_best_field,
    get_matching_instruction,
)
from midojo.yaml_task_suite import YAMLTaskSuite


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def _make_suite(tmp_path):
    """Factory for creating test suites with custom YAML."""

    def _factory(suite_yaml: dict) -> YAMLTaskSuite:
        path = tmp_path / "suite.yaml"
        path.write_text(yaml.dump(suite_yaml))
        return YAMLTaskSuite("test", suite_yaml_path=path)

    return _factory


# ---------------------------------------------------------------------------
# 1. Control plane API — typed injection plan
# ---------------------------------------------------------------------------


class TestInjectionPlanAPI:
    def test_empty_plan_by_default(self, client):
        run_id = client.post("/runs").json()["id"]
        eval_id = client.post(
            f"/runs/{run_id}/evaluations",
            json={"user_task_id": "weather_new_york"},
        ).json()["id"]
        plan = client.get(f"/runs/{run_id}/evaluations/{eval_id}/injection-plan").json()
        assert plan == []

    def test_create_eval_with_typed_plan(self, client):
        run_id = client.post("/runs").json()["id"]
        eval_resp = client.post(
            f"/runs/{run_id}/evaluations",
            json={
                "user_task_id": "weather_new_york",
                "injection_plan": [
                    {"type": "env", "payload": "ENV", "probe_key": "t:main"},
                    {"type": "prompt", "payload": "PROMPT", "probe_key": "t:p"},
                    {"type": "tool", "payload": "TOOL", "target_tool": "get_weather", "mode": "embed"},
                ],
            },
        )
        assert eval_resp.status_code == 201
        eval_id = eval_resp.json()["id"]

        plan = client.get(f"/runs/{run_id}/evaluations/{eval_id}/injection-plan").json()
        assert len(plan) == 3
        assert plan[0]["type"] == "env"
        assert plan[0]["probe_key"] == "t:main"
        assert plan[1]["type"] == "prompt"
        assert plan[2]["type"] == "tool"
        assert plan[2]["target_tool"] == "get_weather"

    def test_put_replaces_plan(self, client):
        run_id = client.post("/runs").json()["id"]
        eval_id = client.post(
            f"/runs/{run_id}/evaluations", json={"user_task_id": "weather_new_york"},
        ).json()["id"]

        client.put(
            f"/runs/{run_id}/evaluations/{eval_id}/injection-plan",
            json={"instructions": [{"type": "tool", "payload": "v1"}]},
        )
        client.put(
            f"/runs/{run_id}/evaluations/{eval_id}/injection-plan",
            json={"instructions": [{"type": "tool", "payload": "v2"}, {"type": "tool", "payload": "v3"}]},
        )
        plan = client.get(f"/runs/{run_id}/evaluations/{eval_id}/injection-plan").json()
        assert [p["payload"] for p in plan] == ["v2", "v3"]

    def test_current_mirrors_latest_eval(self, client):
        run_id = client.post("/runs").json()["id"]
        client.post(
            f"/runs/{run_id}/evaluations",
            json={
                "user_task_id": "weather_new_york",
                "injection_plan": [{"type": "tool", "payload": "CURRENT"}],
            },
        )
        plan = client.get("/current/injection-plan").json()
        assert plan[0]["payload"] == "CURRENT"

    def test_eval_isolation(self, client):
        run_id = client.post("/runs").json()["id"]
        eval1 = client.post(
            f"/runs/{run_id}/evaluations",
            json={
                "user_task_id": "weather_new_york",
                "injection_plan": [{"type": "tool", "payload": "EVAL1"}],
            },
        ).json()["id"]
        client.post(
            f"/runs/{run_id}/evaluations",
            json={
                "user_task_id": "weather_new_york",
                "injection_plan": [{"type": "tool", "payload": "EVAL2"}],
            },
        )
        plan1 = client.get(f"/runs/{run_id}/evaluations/{eval1}/injection-plan").json()
        assert plan1[0]["payload"] == "EVAL1"


# ---------------------------------------------------------------------------
# 2. Validation — invalid mode, missing fields
# ---------------------------------------------------------------------------


class TestValidation:
    def test_invalid_mode_rejected(self, client):
        run_id = client.post("/runs").json()["id"]
        resp = client.post(
            f"/runs/{run_id}/evaluations",
            json={
                "user_task_id": "weather_new_york",
                "injection_plan": [{"type": "tool", "payload": "x", "mode": "INVALID"}],
            },
        )
        assert resp.status_code == 422

    def test_env_without_probe_key_rejected(self, client):
        run_id = client.post("/runs").json()["id"]
        resp = client.post(
            f"/runs/{run_id}/evaluations",
            json={
                "user_task_id": "weather_new_york",
                "injection_plan": [{"type": "env", "payload": "x"}],
            },
        )
        assert resp.status_code == 422

    def test_prompt_without_probe_key_rejected(self, client):
        run_id = client.post("/runs").json()["id"]
        resp = client.post(
            f"/runs/{run_id}/evaluations",
            json={
                "user_task_id": "weather_new_york",
                "injection_plan": [{"type": "prompt", "payload": "x"}],
            },
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 3. Refresh endpoint
# ---------------------------------------------------------------------------


class TestRefresh:
    def test_refresh_returns_prompt(self, client):
        run_id = client.post("/runs").json()["id"]
        client.post(
            f"/runs/{run_id}/evaluations",
            json={"user_task_id": "weather_new_york"},
        )
        resp = client.post("/current/refresh", json={"reset_state": True})
        assert resp.status_code == 200
        assert "prompt" in resp.json()

    def test_refresh_with_updated_prompt_injection(self, client):
        run_id = client.post("/runs").json()["id"]
        client.post(
            f"/runs/{run_id}/evaluations",
            json={
                "user_task_id": "weather_new_york",
                "injection_plan": [
                    {"type": "prompt", "payload": "INITIAL", "probe_key": "test:main"},
                ],
            },
        )
        # Update the plan with a new prompt payload
        client.put(
            "/current/injection-plan",
            json={"instructions": [
                {"type": "prompt", "payload": "REFINED", "probe_key": "test:main"},
            ]},
        )
        resp = client.post("/current/refresh", json={"reset_state": True})
        assert resp.status_code == 200

    def test_refresh_clears_function_calls_when_reset(self, client):
        run_id = client.post("/runs").json()["id"]
        eval_id = client.post(
            f"/runs/{run_id}/evaluations",
            json={"user_task_id": "weather_new_york"},
        ).json()["id"]
        # Record a function call
        client.post(
            f"/runs/{run_id}/evaluations/{eval_id}/function-calls",
            json={"function": "test", "args": {}, "result": "ok"},
        )
        calls = client.get(f"/runs/{run_id}/evaluations/{eval_id}/function-calls").json()
        assert len(calls) == 1

        # Refresh with reset
        client.post("/current/refresh", json={"reset_state": True})
        calls = client.get(f"/runs/{run_id}/evaluations/{eval_id}/function-calls").json()
        assert len(calls) == 0

    def test_refresh_preserves_function_calls_without_reset(self, client):
        run_id = client.post("/runs").json()["id"]
        eval_id = client.post(
            f"/runs/{run_id}/evaluations",
            json={"user_task_id": "weather_new_york"},
        ).json()["id"]
        client.post(
            f"/runs/{run_id}/evaluations/{eval_id}/function-calls",
            json={"function": "test", "args": {}, "result": "ok"},
        )
        client.post("/current/refresh", json={"reset_state": False})
        calls = client.get(f"/runs/{run_id}/evaluations/{eval_id}/function-calls").json()
        assert len(calls) == 1


# ---------------------------------------------------------------------------
# 4. SDK — get_matching_instruction
# ---------------------------------------------------------------------------


class TestGetMatchingInstruction:
    @pytest.fixture()
    def mock_client(self, app):
        transport = httpx.ASGITransport(app=app)
        http = httpx.AsyncClient(transport=transport, base_url="http://testserver")
        return ControlPlaneClient("http://testserver", http=http)

    @pytest.fixture()
    def setup_eval(self, client):
        run_id = client.post("/runs").json()["id"]
        eval_id = client.post(
            f"/runs/{run_id}/evaluations",
            json={
                "user_task_id": "weather_new_york",
                "injection_plan": [
                    {"type": "env", "payload": "ENV", "probe_key": "t:e"},
                    {"type": "tool", "payload": "TOOL1", "target_tool": "get_weather"},
                    {"type": "tool", "payload": "TOOL2", "target_tool": None},
                ],
            },
        ).json()["id"]
        return run_id, eval_id

    @pytest.mark.asyncio
    async def test_matches_specific_tool(self, setup_eval, mock_client):
        match = await get_matching_instruction(mock_client, "get_weather")
        assert match is not None
        assert match["payload"] == "TOOL1"

    @pytest.mark.asyncio
    async def test_wildcard_matches_unknown_tool(self, setup_eval, mock_client):
        match = await get_matching_instruction(mock_client, "some_other_tool")
        assert match is not None
        assert match["payload"] == "TOOL2"

    @pytest.mark.asyncio
    async def test_skips_env_type(self, setup_eval, client, mock_client):
        # Replace plan with env-only
        run_id, eval_id = setup_eval
        client.put(
            f"/runs/{run_id}/evaluations/{eval_id}/injection-plan",
            json={"instructions": [{"type": "env", "payload": "ENV", "probe_key": "t:e"}]},
        )
        match = await get_matching_instruction(mock_client, "get_weather")
        assert match is None

    @pytest.mark.asyncio
    async def test_empty_plan_returns_none(self, client, mock_client):
        client.post("/runs").json()["id"]
        run_id = client.post("/runs").json()["id"]
        client.post(f"/runs/{run_id}/evaluations", json={"user_task_id": "weather_new_york"})
        match = await get_matching_instruction(mock_client, "anything")
        assert match is None


# ---------------------------------------------------------------------------
# 5. Injection execution — all modes
# ---------------------------------------------------------------------------


SAMPLE_JSON = json.dumps({"city": "NYC", "temp": 72, "description": "Sunny and warm with clear skies"})
SAMPLE_NESTED = json.dumps({"items": [{"id": "T1", "description": "First item details here"}]})
SAMPLE_NUMERIC = json.dumps({"balance": 15420.50, "currency": "USD", "is_frozen": False})


class TestExecuteInjection:
    def test_embed_auto_detect(self):
        result = execute_injection(SAMPLE_JSON, {"payload": "INJECTED", "mode": "embed"}, "test")
        data = json.loads(result)
        assert "INJECTED" in data["description"]

    def test_embed_specific_field(self):
        result = execute_injection(SAMPLE_JSON, {"payload": "INJECTED", "target_field": "city", "mode": "embed"}, "test")
        data = json.loads(result)
        assert "INJECTED" in data["city"]

    def test_embed_nested_list(self):
        result = execute_injection(SAMPLE_NESTED, {"payload": "INJECTED", "mode": "embed"}, "test")
        data = json.loads(result)
        assert "INJECTED" in data["items"][0]["description"]

    def test_embed_no_text_field_adds_annotation(self):
        result = execute_injection(SAMPLE_NUMERIC, {"payload": "INJECTED", "mode": "embed"}, "test")
        data = json.loads(result)
        assert data["_annotation"] == "INJECTED"

    def test_replace(self):
        result = execute_injection(SAMPLE_JSON, {"payload": "REPLACED", "mode": "replace"}, "test")
        assert result == "REPLACED"

    def test_append(self):
        result = execute_injection(SAMPLE_JSON, {"payload": "APPENDED", "mode": "append"}, "test")
        assert result.startswith(SAMPLE_JSON)
        assert "APPENDED" in result

    def test_new_field(self):
        result = execute_injection(SAMPLE_JSON, {"payload": "NOTE", "mode": "new_field"}, "test")
        data = json.loads(result)
        assert data["_annotation"] == "NOTE"
        assert data["city"] == "NYC"

    def test_non_json_embed_appends(self):
        result = execute_injection("plain text", {"payload": "INJECTED", "mode": "embed"}, "test")
        assert "plain text" in result
        assert "INJECTED" in result


# ---------------------------------------------------------------------------
# 6. Field auto-detection
# ---------------------------------------------------------------------------


class TestFindBestField:
    def test_finds_longest_multiword_string(self):
        result = json.dumps({"id": "C1", "name": "Alice", "bio": "A long biography with many words"})
        assert find_best_field(result) == "bio"

    def test_returns_none_for_no_text(self):
        assert find_best_field(SAMPLE_NUMERIC) is None

    def test_finds_field_in_list_items(self):
        assert find_best_field(SAMPLE_NESTED) == "description"

    def test_non_json_returns_none(self):
        assert find_best_field("not json") is None

    def test_single_word_strings_skipped(self):
        result = json.dumps({"status": "active", "type": "checking"})
        assert find_best_field(result) is None


# ---------------------------------------------------------------------------
# 7. Splice into field
# ---------------------------------------------------------------------------


class TestSpliceIntoField:
    def test_top_level_field(self):
        result = _splice_into_field('{"notes": "original"}', "notes", "INJECTED")
        assert result is not None
        assert "original INJECTED" in result

    def test_field_in_list_item(self):
        result = _splice_into_field(
            '{"items": [{"desc": "original"}]}', "desc", "INJECTED"
        )
        assert result is not None
        data = json.loads(result)
        assert "original INJECTED" in data["items"][0]["desc"]

    def test_missing_field_returns_none(self):
        result = _splice_into_field('{"other": "value"}', "notes", "INJECTED")
        assert result is None

    def test_empty_field_gets_payload(self):
        result = _splice_into_field('{"notes": ""}', "notes", "INJECTED")
        assert result is not None
        data = json.loads(result)
        assert data["notes"] == "INJECTED"

    def test_non_json_returns_none(self):
        assert _splice_into_field("plain text", "notes", "INJECTED") is None


# ---------------------------------------------------------------------------
# 8. Suite placement — build_injection_inputs
# ---------------------------------------------------------------------------


class TestBuildInjectionInputs:
    def test_legacy_no_placement(self, _make_suite):
        suite = _make_suite({
            "environment": {"backend": "dict", "state": {"data": "{t:main}"}},
            "user_tasks": [{"id": "u", "prompt": "test", "utility": {"output_contains": "x"}}],
            "injection_tasks": [{
                "id": "t",
                "description": "test",
                "probes": {"main": {"payload": "PAYLOAD"}},
                "security": {"output_contains": "x"},
            }],
        })
        injections, plan = suite.build_injection_inputs("t")
        assert "t:main" in injections
        assert plan == []

    def test_env_placement(self, _make_suite):
        suite = _make_suite({
            "environment": {"backend": "dict", "state": {"data": "{t:main}"}},
            "user_tasks": [{"id": "u", "prompt": "test", "utility": {"output_contains": "x"}}],
            "injection_tasks": [{
                "id": "t",
                "description": "test",
                "probes": {"main": {"payload": "PAYLOAD", "placement": "env"}},
                "security": {"output_contains": "x"},
            }],
        })
        injections, plan = suite.build_injection_inputs("t")
        assert "t:main" in injections
        assert len(plan) == 1
        assert plan[0]["type"] == "env"
        assert plan[0]["probe_key"] == "t:main"

    def test_prompt_placement(self, _make_suite):
        suite = _make_suite({
            "environment": {"backend": "dict", "state": {}},
            "user_tasks": [{"id": "u", "prompt": "test {t:main}", "utility": {"output_contains": "x"}}],
            "injection_tasks": [{
                "id": "t",
                "description": "test",
                "probes": {"main": {"payload": "PAYLOAD", "placement": "prompt"}},
                "security": {"output_contains": "x"},
            }],
        })
        injections, plan = suite.build_injection_inputs("t")
        assert "t:main" in injections
        assert len(plan) == 1
        assert plan[0]["type"] == "prompt"

    def test_tool_placement(self, _make_suite):
        suite = _make_suite({
            "environment": {"backend": "dict", "state": {}},
            "user_tasks": [{"id": "u", "prompt": "test", "utility": {"output_contains": "x"}}],
            "injection_tasks": [{
                "id": "t",
                "description": "test",
                "probes": {"main": {
                    "payload": "PAYLOAD",
                    "placement": "tool",
                    "target_tool": "get_info",
                    "mode": "replace",
                }},
                "security": {"output_contains": "x"},
            }],
        })
        injections, plan = suite.build_injection_inputs("t")
        assert "t:main" not in injections
        assert len(plan) == 1
        assert plan[0]["type"] == "tool"
        assert plan[0]["target_tool"] == "get_info"
        assert plan[0]["mode"] == "replace"

    def test_mixed_placements(self, _make_suite):
        suite = _make_suite({
            "environment": {"backend": "dict", "state": {"d": "{t:e}"}},
            "user_tasks": [{"id": "u", "prompt": "test {t:p}", "utility": {"output_contains": "x"}}],
            "injection_tasks": [{
                "id": "t",
                "description": "test",
                "probes": {
                    "e": {"payload": "ENV", "placement": "env"},
                    "p": {"payload": "PROMPT", "placement": "prompt"},
                    "tool": {"payload": "TOOL", "placement": "tool"},
                    "legacy": {"payload": "LEGACY"},
                },
                "security": {"output_contains": "x"},
            }],
        })
        injections, plan = suite.build_injection_inputs("t")
        assert "t:e" in injections
        assert "t:p" in injections
        assert "t:tool" not in injections
        assert "t:legacy" in injections
        assert len(plan) == 3
        types = {p["type"] for p in plan}
        assert types == {"env", "prompt", "tool"}


# ---------------------------------------------------------------------------
# 9. Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    def test_existing_weather_suite_unchanged(self, suite):
        task_id = list(suite.injection_tasks.keys())[0]
        old = suite.get_probes_for_task(task_id)
        injections, plan = suite.build_injection_inputs(task_id)
        assert injections == old
        assert plan == []

    def test_eval_without_plan_works(self, client):
        run_id = client.post("/runs").json()["id"]
        resp = client.post(
            f"/runs/{run_id}/evaluations",
            json={"user_task_id": "weather_new_york"},
        )
        assert resp.status_code == 201
        plan = client.get("/current/injection-plan").json()
        assert plan == []
