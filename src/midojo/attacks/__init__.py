"""MiDojo's attack library: the catalog of attack techniques that get
templated into suites at evaluation time.

It separates *what* you're testing (suite authoring) from *how* you're
attacking (this library), so suites stay stable while attacks evolve. See
issue #36 for the design.
"""

from __future__ import annotations

from midojo.attacks.protocols import (
    AttackContext,
    AttackResult,
    AttackStrategy,
    ConversationalAttackStrategy,
    EvalResult,
    Injection,
    IterativeAttackStrategy,
    PayloadTransform,
    StaticAttackStrategy,
    TargetContext,
)
from midojo.attacks.records import AttackTechnique, Origin, PayloadSet, PayloadWrapper
from midojo.attacks.registry import (
    DEFAULT_LIBRARY,
    AttackLibrary,
    load_payload_set_file,
    resolve_source,
    wrap_payload,
)
from midojo.attacks.taxonomy import ASI_DESCRIPTIONS, ASI_DETAILS, ASICategory, parse_asi_category

__all__ = [
    "ASI_DESCRIPTIONS",
    "ASI_DETAILS",
    "DEFAULT_LIBRARY",
    "ASICategory",
    "AttackContext",
    "AttackLibrary",
    "AttackResult",
    "AttackStrategy",
    "AttackTechnique",
    "ConversationalAttackStrategy",
    "EvalResult",
    "Injection",
    "IterativeAttackStrategy",
    "Origin",
    "PayloadSet",
    "PayloadTransform",
    "PayloadWrapper",
    "StaticAttackStrategy",
    "TargetContext",
    "load_payload_set_file",
    "parse_asi_category",
    "resolve_source",
    "wrap_payload",
]
