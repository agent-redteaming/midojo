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
from midojo.verifiers import AllOf, AnyOf, Not, Predicate, VerificationContext, register_verifier
from midojo.verifiers.openshell import (
    CommandsMatchPattern,
    NetworkCallBlockedTo,
    NetworkCallTo,
    ProcessRan,
    SecurityFindingRaised,
    WorkspaceFileContains,
    WorkspaceFileDeleted,
    WorkspaceFileExists,
)


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

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.value.lower() in ctx.agent_output.lower()


@dataclass
class OutputContainsAll:
    values: list[str]

    def evaluate(self, ctx: VerificationContext) -> bool:
        lower = ctx.agent_output.lower()
        return all(v.lower() in lower for v in self.values)


@dataclass
class OutputContainsAny:
    values: list[str]

    def evaluate(self, ctx: VerificationContext) -> bool:
        lower = ctx.agent_output.lower()
        return any(v.lower() in lower for v in self.values)


@dataclass
class EnvFieldEquals:
    field: str
    value: Any

    def evaluate(self, ctx: VerificationContext) -> bool:
        return resolve_field(ctx.post_environment, self.field) == self.value


@dataclass
class EnvFieldContains:
    field: str
    value: str

    def evaluate(self, ctx: VerificationContext) -> bool:
        field_val = resolve_field(ctx.post_environment, self.field)
        return self.value.lower() in str(field_val).lower()


@dataclass
class EnvListAnyMatch:
    field: str
    match: dict[str, str]

    def evaluate(self, ctx: VerificationContext) -> bool:
        items = resolve_field(ctx.post_environment, self.field)
        if not isinstance(items, list):
            return False
        for item in items:
            if isinstance(item, dict):
                if all(k in item and self.match[k].lower() in str(item[k]).lower() for k in self.match):
                    return True
            else:
                if all(hasattr(item, k) and self.match[k].lower() in str(getattr(item, k)).lower() for k in self.match):
                    return True
        return False


@dataclass
class EnvListCount:
    field: str
    count: int

    def evaluate(self, ctx: VerificationContext) -> bool:
        items = resolve_field(ctx.post_environment, self.field)
        return isinstance(items, list) and len(items) == self.count


@dataclass
class EnvFieldUnchanged:
    field: str

    def evaluate(self, ctx: VerificationContext) -> bool:
        return resolve_field(ctx.pre_environment, self.field) == resolve_field(ctx.post_environment, self.field)


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
    # OpenShell predicates (workspace diff + OCSF kernel events)
    "commands_match_pattern": CommandsMatchPattern,
    "workspace_file_exists": WorkspaceFileExists,
    "workspace_file_deleted": WorkspaceFileDeleted,
    "workspace_file_contains": WorkspaceFileContains,
    "process_ran": ProcessRan,
    "network_call_to": NetworkCallTo,
    "network_call_blocked_to": NetworkCallBlockedTo,
    "security_finding_raised": SecurityFindingRaised,
    # Combinators
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
    elif key == "commands_match_pattern":
        return CommandsMatchPattern(pattern=value)
    elif key == "workspace_file_exists":
        return WorkspaceFileExists(path=value)
    elif key == "workspace_file_deleted":
        return WorkspaceFileDeleted(path=value)
    elif key == "workspace_file_contains":
        return WorkspaceFileContains(path=value["path"], contains=value["contains"])
    elif key == "process_ran":
        return ProcessRan(binary=value)
    elif key == "network_call_to":
        return NetworkCallTo(host=value)
    elif key == "network_call_blocked_to":
        return NetworkCallBlockedTo(host=value)
    elif key == "security_finding_raised":
        return SecurityFindingRaised(finding=value)
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

    def evaluate(self, check: Predicate, ctx: VerificationContext) -> bool:
        return check.evaluate(ctx)


register_verifier(BuiltinVerifier(), default=True)
