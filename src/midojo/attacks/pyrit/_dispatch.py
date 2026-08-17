"""Shared strategy dispatch for compound, adaptive, and orchestrator callers."""

from __future__ import annotations

import logging
from pathlib import Path

from midojo.attacks.pyrit.context import StrategyContext

logger = logging.getLogger("midojo.pyrit")

_file_logging_configured = False


def _ensure_file_logging(logdir: str, strategy_type: str, user_task_id: str, injection_task_id: str) -> None:
    """Set up file logging once per process for the strategy run."""
    global _file_logging_configured
    if _file_logging_configured:
        return
    _file_logging_configured = True

    log_path = Path(logdir)
    log_path.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_path / f"strategy_{strategy_type}_{user_task_id}_{injection_task_id}.log", mode="w")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    for name in ("midojo.pyrit", "midojo.fuzz", "midojo.gptfuzzer", "midojo.compound", "midojo.adaptive", "midojo.converters", "midojo.preseed", "midojo.llm_judge"):
        logging.getLogger(name).addHandler(file_handler)
        logging.getLogger(name).setLevel(logging.INFO)


async def dispatch_strategy(ctx: StrategyContext, *, step_type: str | None = None) -> dict:
    """Route a strategy to the correct runner based on type.

    ``step_type`` overrides ``ctx.strategy_config["type"]`` when the caller
    (compound/adaptive) supplies a per-step type that differs from the
    top-level strategy.
    """
    resolved_type = step_type or ctx.strategy_config["type"]

    if ctx.logdir:
        _ensure_file_logging(ctx.logdir, resolved_type, ctx.user_task_id, ctx.injection_task_id)

    logger.info(
        "dispatch: type=%s, user_task=%s, injection_task=%s, probe=%s, has_wrapper=%s, has_converters=%s",
        resolved_type, ctx.user_task_id, ctx.injection_task_id, ctx.probe_id,
        ctx.wrapper_fn is not None, ctx.converter_specs is not None,
    )

    if resolved_type == "fuzz":
        from midojo.attacks.pyrit.fuzz import run_fuzz_strategy

        return await run_fuzz_strategy(ctx)

    if resolved_type == "gptfuzzer":
        from midojo.attacks.pyrit.gptfuzzer import run_gptfuzzer_strategy

        return await run_gptfuzzer_strategy(ctx)

    if resolved_type == "sequential":
        from midojo.attacks.pyrit.compound import run_sequential_strategy

        return await run_sequential_strategy(ctx)

    if resolved_type == "adaptive":
        from midojo.attacks.pyrit.adaptive import run_adaptive_strategy

        return await run_adaptive_strategy(ctx)

    from midojo.attacks.pyrit.adapter import run_pyrit_strategy

    return await run_pyrit_strategy(ctx)
