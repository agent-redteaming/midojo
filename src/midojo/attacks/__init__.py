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


def __getattr__(name: str):
    """Lazy-load converter functions to avoid importing PyRIT at module level."""
    converter_attrs = {
        "CONVERTER_REGISTRY",
        "apply_converters",
        "build_attack_converter_config",
        "resolve_converter",
        "resolve_converters",
    }
    if name in converter_attrs:
        from midojo.attacks.pyrit import converters

        return getattr(converters, name)
    raise AttributeError(f"module 'midojo.attacks' has no attribute {name!r}")

__all__ = [
    "ASI_DESCRIPTIONS",
    "ASI_DETAILS",
    "CONVERTER_REGISTRY",
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
    "apply_converters",
    "build_attack_converter_config",
    "load_payload_set_file",
    "parse_asi_category",
    "resolve_converter",
    "resolve_converters",
    "resolve_source",
    "wrap_payload",
]
