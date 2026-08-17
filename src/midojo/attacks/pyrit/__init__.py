"""PyRIT integration layer for MiDojo.

This subpackage bridges PyRIT's attack algorithms with MiDojo's
agent-aware evaluation. It provides:

- ``MiDojoTarget`` — PyRIT PromptTarget that evaluates through MiDojo's control plane
- ``MiDojoScorer`` — PyRIT FloatScaleScorer using MiDojo's behavioral security predicates
- ``run_pyrit_strategy`` — unified dispatcher for all PyRIT attack strategies
- Converter integration, compound attacks, adaptive selection, fuzzing, pre-seeding

All imports from ``pyrit.*`` are isolated here so MiDojo's core modules
remain usable without PyRIT installed.
"""

from __future__ import annotations

from midojo.attacks.pyrit.adapter import (
    MiDojoScorer,
    MiDojoTarget,
    run_pyrit_strategy,
)
from midojo.attacks.pyrit.adaptive import run_adaptive_strategy
from midojo.attacks.pyrit.compound import run_sequential_strategy
from midojo.attacks.pyrit.context import StrategyContext
from midojo.attacks.pyrit.converters import (
    CONVERTER_REGISTRY,
    apply_converters,
    build_attack_converter_config,
    resolve_converter,
    resolve_converters,
)
from midojo.attacks.pyrit.fuzz import run_fuzz_strategy
from midojo.attacks.pyrit.gptfuzzer import run_gptfuzzer_strategy

__all__ = [
    "CONVERTER_REGISTRY",
    "MiDojoScorer",
    "MiDojoTarget",
    "StrategyContext",
    "apply_converters",
    "build_attack_converter_config",
    "resolve_converter",
    "resolve_converters",
    "run_adaptive_strategy",
    "run_fuzz_strategy",
    "run_gptfuzzer_strategy",
    "run_pyrit_strategy",
    "run_sequential_strategy",
]
