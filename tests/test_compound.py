"""Tests for compound (sequential) attack strategies."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from midojo.attacks.pyrit.context import StrategyContext

_PATCH_TARGET = "midojo.attacks.pyrit.adapter.run_pyrit_strategy"


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


class TestSequentialStrategy:
    """Tests for run_sequential_strategy."""

    @pytest.mark.asyncio
    async def test_first_success_stops_early(self):
        from midojo.attacks.pyrit.compound import run_sequential_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.side_effect = [
                {"utility": True, "security": False, "eval_id": "e1", "prompt": "p1",
                 "agent_output": "o1", "strategy_type": "prompt_sending",
                 "n_evals": 1, "eval_ids": ["e1"], "eval_log": [{"iter": 1}]},
                {"utility": True, "security": True, "eval_id": "e2", "prompt": "p2",
                 "agent_output": "o2", "strategy_type": "pair",
                 "n_evals": 5, "eval_ids": ["e2"], "eval_log": [{"iter": 2}]},
                {"utility": True, "security": False, "eval_id": "e3", "prompt": "p3",
                 "agent_output": "o3", "strategy_type": "crescendo",
                 "n_evals": 10, "eval_ids": ["e3"], "eval_log": [{"iter": 3}]},
            ]

            result = await run_sequential_strategy(_ctx({
                "type": "sequential",
                "params": {
                    "completion_policy": "first_success",
                    "steps": [
                        {"type": "prompt_sending"},
                        {"type": "pair", "params": {"max_iterations": 5}},
                        {"type": "crescendo", "params": {"max_turns": 10}},
                    ],
                },
            }))

        assert result["security"] is True
        assert result["strategy_type"] == "sequential"
        assert result["steps_attempted"] == 2
        assert result["steps_total"] == 3
        assert result["n_evals"] == 6
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_exhaustive_runs_all_steps(self):
        from midojo.attacks.pyrit.compound import run_sequential_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.side_effect = [
                {"utility": True, "security": True, "eval_id": "e1", "prompt": "p1",
                 "agent_output": "o1", "strategy_type": "prompt_sending",
                 "n_evals": 1, "eval_ids": ["e1"], "eval_log": []},
                {"utility": True, "security": False, "eval_id": "e2", "prompt": "p2",
                 "agent_output": "o2", "strategy_type": "pair",
                 "n_evals": 5, "eval_ids": ["e2"], "eval_log": []},
            ]

            result = await run_sequential_strategy(_ctx({
                "type": "sequential",
                "params": {
                    "completion_policy": "exhaustive",
                    "steps": [
                        {"type": "prompt_sending"},
                        {"type": "pair"},
                    ],
                },
            }))

        assert result["security"] is True
        assert result["steps_attempted"] == 2
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_all_fail_returns_false(self):
        from midojo.attacks.pyrit.compound import run_sequential_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.return_value = {
                "utility": True, "security": False, "eval_id": "e1", "prompt": "p1",
                "agent_output": "o1", "strategy_type": "pair",
                "n_evals": 5, "eval_ids": ["e1"], "eval_log": [],
            }

            result = await run_sequential_strategy(_ctx({
                "type": "sequential",
                "params": {
                    "steps": [
                        {"type": "pair"},
                        {"type": "pair"},
                    ],
                },
            }))

        assert result["security"] is False
        assert result["steps_attempted"] == 2

    @pytest.mark.asyncio
    async def test_empty_steps_raises(self):
        from midojo.attacks.pyrit.compound import run_sequential_strategy

        with pytest.raises(ValueError, match="at least one step"):
            await run_sequential_strategy(_ctx(
                {"type": "sequential", "params": {"steps": []}},
            ))

    @pytest.mark.asyncio
    async def test_step_error_continues_in_first_success(self):
        from midojo.attacks.pyrit.compound import run_sequential_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.side_effect = [
                RuntimeError("LLM timeout"),
                {"utility": True, "security": True, "eval_id": "e2", "prompt": "p2",
                 "agent_output": "o2", "strategy_type": "pair",
                 "n_evals": 3, "eval_ids": ["e2"], "eval_log": []},
            ]

            result = await run_sequential_strategy(_ctx({
                "type": "sequential",
                "params": {
                    "steps": [
                        {"type": "crescendo"},
                        {"type": "pair"},
                    ],
                },
            }))

        assert result["security"] is True
        assert result["steps_attempted"] == 2

    @pytest.mark.asyncio
    async def test_converters_passed_per_step(self):
        from midojo.attacks.pyrit.compound import run_sequential_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.return_value = {
                "utility": True, "security": True, "eval_id": "e1", "prompt": "p1",
                "agent_output": "o1", "strategy_type": "pair",
                "n_evals": 1, "eval_ids": ["e1"], "eval_log": [],
            }

            await run_sequential_strategy(_ctx({
                "type": "sequential",
                "params": {
                    "steps": [
                        {"type": "pair", "converters": ["rot13", "base64"]},
                    ],
                },
            }))

        # The step's StrategyContext should have converter_specs set
        call_ctx = mock_run.call_args[0][0]
        assert call_ctx.converter_specs == ["rot13", "base64"]

    @pytest.mark.asyncio
    async def test_first_decisive_stops_on_error(self):
        from midojo.attacks.pyrit.compound import run_sequential_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.side_effect = RuntimeError("fatal error")

            result = await run_sequential_strategy(_ctx({
                "type": "sequential",
                "params": {
                    "completion_policy": "first_decisive",
                    "steps": [
                        {"type": "crescendo"},
                        {"type": "pair"},
                    ],
                },
            }))

        assert result["security"] is False
        assert result["steps_attempted"] == 1
        assert mock_run.call_count == 1

    @pytest.mark.asyncio
    async def test_first_decisive_continues_on_success(self):
        """first_decisive only stops on error, not success — unlike first_success."""
        from midojo.attacks.pyrit.compound import run_sequential_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.side_effect = [
                {"utility": True, "security": True, "eval_id": "e1", "prompt": "p1",
                 "agent_output": "o1", "strategy_type": "prompt_sending",
                 "n_evals": 1, "eval_ids": ["e1"], "eval_log": []},
                {"utility": True, "security": False, "eval_id": "e2", "prompt": "p2",
                 "agent_output": "o2", "strategy_type": "pair",
                 "n_evals": 1, "eval_ids": ["e2"], "eval_log": []},
            ]

            result = await run_sequential_strategy(_ctx({
                "type": "sequential",
                "params": {
                    "completion_policy": "first_decisive",
                    "steps": [
                        {"type": "prompt_sending"},
                        {"type": "pair"},
                    ],
                },
            }))

        assert result["security"] is True
        assert result["steps_attempted"] == 2
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_logdir_writes_trace(self, tmp_path):
        from midojo.attacks.pyrit.compound import run_sequential_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.return_value = {
                "utility": True, "security": False, "eval_id": "e1", "prompt": "p1",
                "agent_output": "o1", "strategy_type": "pair",
                "n_evals": 1, "eval_ids": ["e1"], "eval_log": [],
            }

            await run_sequential_strategy(_ctx(
                {
                    "type": "sequential",
                    "params": {"steps": [{"type": "pair"}]},
                },
                logdir=str(tmp_path),
            ))

        trace_files = list(tmp_path.glob("strategy_sequential_*.json"))
        assert len(trace_files) == 1

        import json
        trace = json.loads(trace_files[0].read_text())
        assert trace["strategy_type"] == "sequential"
        assert trace["steps_attempted"] == 1
