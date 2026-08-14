"""Built-in verifier — declarative predicates over agent output and env state.

This is MiDojo's default verifier: the predicate types that ship with the
engine (substring checks, field equality, list matching) plus the
:class:`BuiltinVerifier` that adapts them to the :class:`Verifier` protocol.
Suites whose grading fits these patterns need no Python code.

The predicate types are this verifier's private implementation — nothing
outside this module references them. The verifier framework
(:mod:`midojo.verifiers`) knows nothing about predicates; this module registers
itself as the *default* verifier on import.

Limitation: there is no "run arbitrary code" predicate. A suite needing custom
logic (regex, numeric ranges, fuzzy comparison) is the cue to add a new
predicate type here, or a whole new verifier under :mod:`midojo.verifiers`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from midojo.types import Environment
from midojo.verifiers import Predicate, VerificationContext, VerificationResult, register_verifier
from midojo.verifiers.combinators import AllOf, AnyOf, Not


def resolve_field(env: Environment, path: str) -> Any:
    """Walk a dotted path into a Pydantic model."""
    current: Any = env
    for key in path.split("."):
        if isinstance(current, dict):
            current = current[key]
        else:
            current = getattr(current, key)
    return current


# ---------------------------------------------------------------------------
# Predicate types
# ---------------------------------------------------------------------------


@dataclass
class OutputContains:
    value: str

    def assess(self, ctx: VerificationContext) -> VerificationResult:
        passed = self.value.lower() in ctx.agent_output.lower()
        return VerificationResult(passed, f'output contains "{self.value}"')

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.assess(ctx).passed


@dataclass
class OutputContainsAll:
    values: list[str]

    def assess(self, ctx: VerificationContext) -> VerificationResult:
        lower = ctx.agent_output.lower()
        passed = all(v.lower() in lower for v in self.values)
        return VerificationResult(passed, f"output contains all of {self.values}")

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.assess(ctx).passed


@dataclass
class OutputContainsAny:
    values: list[str]

    def assess(self, ctx: VerificationContext) -> VerificationResult:
        lower = ctx.agent_output.lower()
        passed = any(v.lower() in lower for v in self.values)
        return VerificationResult(passed, f"output contains any of {self.values}")

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.assess(ctx).passed


@dataclass
class EnvFieldEquals:
    field: str
    value: Any

    def assess(self, ctx: VerificationContext) -> VerificationResult:
        passed = resolve_field(ctx.post_environment, self.field) == self.value
        return VerificationResult(passed, f"{self.field} == {self.value!r}")

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.assess(ctx).passed


@dataclass
class EnvFieldContains:
    field: str
    value: str

    def assess(self, ctx: VerificationContext) -> VerificationResult:
        field_val = resolve_field(ctx.post_environment, self.field)
        passed = self.value.lower() in str(field_val).lower()
        return VerificationResult(passed, f'{self.field} contains "{self.value}"')

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.assess(ctx).passed


@dataclass
class EnvListAnyMatch:
    field: str
    match: dict[str, str]

    def assess(self, ctx: VerificationContext) -> VerificationResult:
        items = resolve_field(ctx.post_environment, self.field)
        passed = False
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    if all(k in item and self.match[k].lower() in str(item[k]).lower() for k in self.match):
                        passed = True
                        break
                elif all(
                    hasattr(item, k) and self.match[k].lower() in str(getattr(item, k)).lower() for k in self.match
                ):
                    passed = True
                    break
        match_str = ", ".join(f"{k}={v}" for k, v in self.match.items())
        return VerificationResult(passed, f"{self.field} matches {match_str}")

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.assess(ctx).passed


@dataclass
class EnvListCount:
    field: str
    count: int

    def assess(self, ctx: VerificationContext) -> VerificationResult:
        items = resolve_field(ctx.post_environment, self.field)
        passed = isinstance(items, list) and len(items) == self.count
        return VerificationResult(passed, f"{self.field} has {self.count} items")

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.assess(ctx).passed


@dataclass
class EnvFieldUnchanged:
    field: str

    def assess(self, ctx: VerificationContext) -> VerificationResult:
        passed = resolve_field(ctx.pre_environment, self.field) == resolve_field(ctx.post_environment, self.field)
        return VerificationResult(passed, f"{self.field} unchanged")

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.assess(ctx).passed


# ---------------------------------------------------------------------------
# Parser: raw YAML dict -> Predicate
# ---------------------------------------------------------------------------

_PARSERS: dict[str, type] = {
    "output_contains": OutputContains,
    "output_contains_all": OutputContainsAll,
    "output_contains_any": OutputContainsAny,
    "env_field_equals": EnvFieldEquals,
    "env_field_contains": EnvFieldContains,
    "env_list_any_match": EnvListAnyMatch,
    "env_list_count": EnvListCount,
    "env_field_unchanged": EnvFieldUnchanged,
    "all_of": AllOf,
    "any_of": AnyOf,
    "not": Not,
}

PREDICATE_TYPES: frozenset[str] = frozenset(_PARSERS)


def parse_predicate(raw: dict) -> Predicate:
    if not isinstance(raw, dict) or len(raw) != 1:
        raise ValueError(f"Predicate must be a dict with exactly one key, got: {raw!r}")

    key = next(iter(raw))
    value = raw[key]

    if key not in _PARSERS:
        raise ValueError(f"Unknown predicate type: {key!r}. Must be one of: {sorted(_PARSERS)}")

    if key == "output_contains":
        return OutputContains(value=value)
    elif key == "output_contains_all":
        return OutputContainsAll(values=value)
    elif key == "output_contains_any":
        return OutputContainsAny(values=value)
    elif key == "env_field_equals":
        return EnvFieldEquals(field=value["field"], value=value["value"])
    elif key == "env_field_contains":
        return EnvFieldContains(field=value["field"], value=value["value"])
    elif key == "env_list_any_match":
        return EnvListAnyMatch(field=value["field"], match=value["match"])
    elif key == "env_list_count":
        return EnvListCount(field=value["field"], count=value["count"])
    elif key == "env_field_unchanged":
        return EnvFieldUnchanged(field=value["field"] if isinstance(value, dict) else value)
    elif key == "all_of":
        return AllOf(predicates=[parse_predicate(p) for p in value])
    elif key == "any_of":
        return AnyOf(predicates=[parse_predicate(p) for p in value])
    elif key == "not":
        return Not(predicate=parse_predicate(value))

    raise ValueError(f"Unhandled predicate type: {key!r}")


# ---------------------------------------------------------------------------
# The verifier
# ---------------------------------------------------------------------------


class BuiltinVerifier:
    """Default verifier: declarative predicates over output + env snapshots.

    Its check object is a :data:`Predicate`. It is the fallback for any check
    block whose key is not a registered verifier; ``claims`` are the top-level
    predicate keys it owns in that role.
    """

    name = "builtin"
    claims = PREDICATE_TYPES

    def parse(self, check_spec: dict) -> Predicate:
        return parse_predicate(check_spec)

    def assess(self, check: Predicate, ctx: VerificationContext) -> VerificationResult:
        return check.assess(ctx)

    def evaluate(self, check: Predicate, ctx: VerificationContext) -> bool:
        return check.evaluate(ctx)


register_verifier(BuiltinVerifier(), default=True)
