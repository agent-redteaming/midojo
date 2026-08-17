"""Tests for adaptive (epsilon-greedy) attack strategy selection."""

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


class TestAdaptiveStrategy:
    """Tests for run_adaptive_strategy."""

    @pytest.mark.asyncio
    async def test_stops_on_first_success(self):
        from midojo.attacks.pyrit.adaptive import run_adaptive_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.side_effect = [
                {"utility": True, "security": False, "eval_id": "e1", "prompt": "p",
                 "agent_output": "", "strategy_type": "prompt_sending",
                 "n_evals": 1, "eval_ids": ["e1"], "eval_log": []},
                {"utility": True, "security": True, "eval_id": "e2", "prompt": "p",
                 "agent_output": "got it", "strategy_type": "pair",
                 "n_evals": 3, "eval_ids": ["e2"], "eval_log": []},
            ]

            result = await run_adaptive_strategy(_ctx({
                "type": "adaptive",
                "params": {
                    "max_attempts": 5,
                    "epsilon": 0.0,
                    "random_seed": 42,
                    "techniques": [
                        {"type": "prompt_sending"},
                        {"type": "pair", "params": {"max_iterations": 5}},
                    ],
                },
            }))

        assert result["security"] is True
        assert result["strategy_type"] == "adaptive"
        assert result["attempts"] == 2
        assert result["n_evals"] == 4
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_all_attempts_exhausted(self):
        from midojo.attacks.pyrit.adaptive import run_adaptive_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.return_value = {
                "utility": True, "security": False, "eval_id": "e1", "prompt": "p",
                "agent_output": "", "strategy_type": "pair",
                "n_evals": 1, "eval_ids": ["e1"], "eval_log": [],
            }

            result = await run_adaptive_strategy(_ctx({
                "type": "adaptive",
                "params": {
                    "max_attempts": 3,
                    "techniques": [{"type": "pair"}],
                },
            }))

        assert result["security"] is False
        assert result["attempts"] == 3
        assert mock_run.call_count == 3

    @pytest.mark.asyncio
    async def test_technique_stats_tracked(self):
        from midojo.attacks.pyrit.adaptive import run_adaptive_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.side_effect = [
                {"utility": True, "security": False, "eval_id": "e1", "prompt": "p",
                 "agent_output": "", "strategy_type": "prompt_sending",
                 "n_evals": 1, "eval_ids": ["e1"], "eval_log": []},
                {"utility": True, "security": False, "eval_id": "e2", "prompt": "p",
                 "agent_output": "", "strategy_type": "pair",
                 "n_evals": 1, "eval_ids": ["e2"], "eval_log": []},
                {"utility": True, "security": True, "eval_id": "e3", "prompt": "p",
                 "agent_output": "", "strategy_type": "pair",
                 "n_evals": 1, "eval_ids": ["e3"], "eval_log": []},
            ]

            result = await run_adaptive_strategy(_ctx({
                "type": "adaptive",
                "params": {
                    "max_attempts": 5,
                    "epsilon": 0.0,
                    "random_seed": 42,
                    "techniques": [
                        {"type": "prompt_sending"},
                        {"type": "pair"},
                    ],
                },
            }))

        assert "technique_stats" in result
        stats = result["technique_stats"]
        assert len(stats) == 2

    @pytest.mark.asyncio
    async def test_empty_techniques_raises(self):
        from midojo.attacks.pyrit.adaptive import run_adaptive_strategy

        with pytest.raises(ValueError, match="at least one technique"):
            await run_adaptive_strategy(_ctx(
                {"type": "adaptive", "params": {"techniques": []}},
            ))

    @pytest.mark.asyncio
    async def test_error_handling_continues(self):
        from midojo.attacks.pyrit.adaptive import run_adaptive_strategy

        with patch(_PATCH_TARGET) as mock_run:
            mock_run.side_effect = [
                RuntimeError("timeout"),
                {"utility": True, "security": True, "eval_id": "e2", "prompt": "p",
                 "agent_output": "ok", "strategy_type": "pair",
                 "n_evals": 1, "eval_ids": ["e2"], "eval_log": []},
            ]

            result = await run_adaptive_strategy(_ctx({
                "type": "adaptive",
                "params": {
                    "max_attempts": 3,
                    "random_seed": 42,
                    "techniques": [
                        {"type": "crescendo"},
                        {"type": "pair"},
                    ],
                },
            }))

        assert result["security"] is True
        assert result["attempts"] == 2


class TestTechniqueStats:
    """Unit tests for the epsilon-greedy selector."""

    def test_unseen_prioritized(self):
        import random as rmod

        from midojo.attacks.pyrit.adaptive import _TechniqueStats

        stats = _TechniqueStats([{"type": "a"}, {"type": "b"}, {"type": "c"}])
        rng = rmod.Random(42)

        stats.record(0, False)
        selected = stats.select(epsilon=0.0, rng=rng)
        assert selected in [1, 2]

    def test_exploit_picks_best(self):
        import random as rmod

        from midojo.attacks.pyrit.adaptive import _TechniqueStats

        stats = _TechniqueStats([{"type": "a"}, {"type": "b"}])
        rng = rmod.Random(42)

        stats.record(0, False)
        stats.record(0, False)
        stats.record(1, True)
        stats.record(1, False)

        selected = stats.select(epsilon=0.0, rng=rng)
        assert selected == 1

    def test_explore_with_epsilon(self):
        import random as rmod

        from midojo.attacks.pyrit.adaptive import _TechniqueStats

        stats = _TechniqueStats([{"type": "a"}, {"type": "b"}])

        stats.record(0, True)
        stats.record(1, False)

        selections = set()
        for seed in range(100):
            rng = rmod.Random(seed)
            selections.add(stats.select(epsilon=1.0, rng=rng))

        assert 0 in selections and 1 in selections

    @pytest.mark.asyncio
    async def test_logdir_writes_trace(self):
        import tempfile
        from pathlib import Path

        from midojo.attacks.pyrit.adaptive import run_adaptive_strategy

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch(_PATCH_TARGET) as mock_run:
                mock_run.return_value = {
                    "utility": True, "security": False, "eval_id": "e1", "prompt": "p",
                    "agent_output": "", "strategy_type": "pair",
                    "n_evals": 1, "eval_ids": ["e1"], "eval_log": [],
                }

                await run_adaptive_strategy(_ctx(
                    {
                        "type": "adaptive",
                        "params": {
                            "max_attempts": 1,
                            "techniques": [{"type": "pair"}],
                        },
                    },
                    logdir=tmpdir,
                ))

            trace_files = list(Path(tmpdir).glob("strategy_adaptive_*.json"))
            assert len(trace_files) == 1

            import json
            trace = json.loads(trace_files[0].read_text())
            assert trace["strategy_type"] == "adaptive"
            assert trace["attempts"] == 1
