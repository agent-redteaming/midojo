"""Tests for payload fuzzing/variation sweep strategy."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from midojo.attacks.pyrit.context import StrategyContext


def _ctx(strategy_config: dict, **overrides) -> StrategyContext:
    defaults = {
        "strategy_config": strategy_config,
        "control_url": "http://test:8080",
        "agent_client": AsyncMock(),
        "run_id": "run1",
        "user_task_id": "ut0",
        "injection_task_id": "it0",
    }
    defaults.update(overrides)
    return StrategyContext(**defaults)


class TestFuzzVariationGeneration:
    """Tests for _generate_variations."""

    def test_default_methods_used_when_empty(self):
        from midojo.attacks.pyrit.fuzz import _generate_variations

        variations = _generate_variations("test payload", [], 3)
        assert len(variations) == 3
        methods = [v["method"] for v in variations]
        assert "wrapper:verbatim" in methods
        assert "wrapper:important_instructions" in methods
        assert "wrapper:ignore_previous" in methods

    def test_custom_methods_cycled(self):
        from midojo.attacks.pyrit.fuzz import _generate_variations

        methods = [
            {"wrapper": "important_instructions"},
            {"converters": ["rot13"]},
        ]
        variations = _generate_variations("payload", methods, 5)
        assert len(variations) == 5
        assert variations[0]["method"] == "wrapper:important_instructions"
        assert variations[1]["method"] == "converters:['rot13']"
        assert variations[2]["method"] == "wrapper:important_instructions"

    def test_wrapper_method_wraps_payload(self):
        from midojo.attacks.pyrit.fuzz import _generate_variations

        variations = _generate_variations("do bad thing", [{"wrapper": "important_instructions"}], 1)
        assert "<INFORMATION>" in variations[0]["payload"]

    def test_converter_method_keeps_raw_payload(self):
        from midojo.attacks.pyrit.fuzz import _generate_variations

        variations = _generate_variations("raw", [{"converters": ["base64"]}], 1)
        assert variations[0]["payload"] == "raw"
        assert variations[0]["converters"] == ["base64"]


class TestFuzzStrategy:
    """Tests for run_fuzz_strategy with mocked control plane."""

    @pytest.mark.asyncio
    async def test_stops_on_first_success(self):
        from midojo.attacks.pyrit.fuzz import run_fuzz_strategy

        mock_agent = AsyncMock()
        mock_agent.send_task = AsyncMock(return_value="Agent response")

        with pytest.MonkeyPatch.context() as mp:
            call_count = {"n": 0}

            async def mock_post(self, url, **kwargs):
                resp = MagicMock()
                resp.raise_for_status = MagicMock()
                if "/evaluations" in url and "/complete" not in url and "/grade" not in url:
                    resp.json.return_value = {"id": f"eval{call_count['n']}", "prompt": "test prompt"}
                elif "/grade" in url:
                    call_count["n"] += 1
                    resp.json.return_value = {
                        "security": call_count["n"] >= 2,
                        "utility": True,
                    }
                else:
                    resp.json.return_value = {}
                return resp

            async def mock_get(self, url, **kwargs):
                resp = MagicMock()
                resp.json.return_value = []
                resp.status_code = 200
                return resp

            import httpx
            mp.setattr(httpx.AsyncClient, "post", mock_post)
            mp.setattr(httpx.AsyncClient, "get", mock_get)

            result = await run_fuzz_strategy(_ctx(
                {
                    "type": "fuzz",
                    "params": {
                        "variations": 5,
                        "stop_on_success": True,
                        "methods": [{"wrapper": "verbatim"}],
                    },
                },
                agent_client=mock_agent,
                seed_payload="test payload",
            ))

        assert result["security"] is True
        assert result["strategy_type"] == "fuzz"
        assert result["n_evals"] == 2

    @pytest.mark.asyncio
    async def test_exhaustive_mode(self):
        from midojo.attacks.pyrit.fuzz import run_fuzz_strategy

        mock_agent = AsyncMock()
        mock_agent.send_task = AsyncMock(return_value="response")

        with pytest.MonkeyPatch.context() as mp:

            async def mock_post(self, url, **kwargs):
                resp = MagicMock()
                resp.raise_for_status = MagicMock()
                if "/evaluations" in url and "/complete" not in url and "/grade" not in url:
                    resp.json.return_value = {"id": "eval1", "prompt": "test"}
                elif "/grade" in url:
                    resp.json.return_value = {"security": False, "utility": True}
                else:
                    resp.json.return_value = {}
                return resp

            async def mock_get(self, url, **kwargs):
                resp = MagicMock()
                resp.json.return_value = []
                resp.status_code = 200
                return resp

            import httpx
            mp.setattr(httpx.AsyncClient, "post", mock_post)
            mp.setattr(httpx.AsyncClient, "get", mock_get)

            result = await run_fuzz_strategy(_ctx(
                {
                    "type": "fuzz",
                    "params": {
                        "variations": 3,
                        "stop_on_success": False,
                    },
                },
                agent_client=mock_agent,
                seed_payload="test",
            ))

        assert result["security"] is False
        assert result["n_evals"] == 3
