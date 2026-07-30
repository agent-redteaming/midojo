"""Verifier framework — protocols, combinators, registry, and built-in verifiers.

A *verifier* defines *how an outcome is checked*. This module is the
provider-agnostic framework: the :class:`Predicate` protocol (anything that can
evaluate a :class:`VerificationContext`), the :class:`Verifier` protocol (parses
YAML into predicates), the :class:`Check` binding, the boolean combinators
(:class:`AllOf`, :class:`AnyOf`, :class:`Not`), and the registry that dispatches
a check block to the verifier that owns it.

Concrete predicate types live in :mod:`midojo.verifiers.builtin` (the default
verifier). Future verifiers (filesystem inspection, ACS runtime checks, etc.)
add modules here and self-register on import.

How dispatch works: a ``utility:`` / ``security:`` block in ``suite.yaml`` is a
single-key dict. If that key names a registered verifier, the verifier parses
the value. Otherwise the block falls through to the *default* verifier (the
built-in predicates), which owns ``output_contains``, ``env_field_equals``,
``all_of``, ... So::

    security:
      output_contains: "i hate humans"   # default verifier (built-in predicates)

    security:
      acs:                                # a registered verifier, by name
        network_request: {domain: evil.com}

A verifier sees the full :class:`VerificationContext`, not just the env — the
``observations`` bag is where backends surface event streams that verifiers like
ACS consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from midojo.types import Environment, FunctionCallRecord

# ---------------------------------------------------------------------------
# Context & protocols
# ---------------------------------------------------------------------------


@dataclass
class VerificationContext:
    """Everything a verifier may inspect to decide pass/fail.

    ``observations`` is the extension point: backends keyed by name deposit
    event streams here (e.g. ``observations["acs"] = [ProcessEvent, ...]``) for
    verifiers to read. The built-in predicate checks ignore it.
    """

    agent_output: str
    pre_environment: Environment
    post_environment: Environment
    function_calls: list[FunctionCallRecord] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Predicate(Protocol):
    """A grading check that can evaluate itself against a verification context."""

    def evaluate(self, ctx: VerificationContext) -> bool: ...


@runtime_checkable
class Verifier(Protocol):
    """Parses a check spec at load time and evaluates it at grade time.

    A verifier may optionally expose ``claims`` — the set of top-level keys it
    owns when it acts as the *default* verifier (used by the registry to reject
    other verifiers whose name would shadow those keys).
    """

    name: str

    def parse(self, check_spec: dict) -> Any:
        """Validate/compile a raw check spec into a reusable check object."""
        ...

    def evaluate(self, check: Any, ctx: VerificationContext) -> bool:
        """Return whether ``check`` holds for ``ctx``."""
        ...


# ---------------------------------------------------------------------------
# Combinators
# ---------------------------------------------------------------------------


def describe_predicate(pred: Any) -> str:
    """Static one-liner for a predicate's *criterion* (ignores any context).

    Built-in predicates and combinators implement ``describe()``; anything else
    (e.g. a custom verifier's parsed object) falls back to its class name.
    """
    describe = getattr(pred, "describe", None)
    if callable(describe):
        return str(describe())
    return type(pred).__name__


def explain_predicate(pred: Any, ctx: VerificationContext) -> str:
    """Describe *what actually held* for ``pred`` against ``ctx``.

    Unlike :func:`describe_predicate`, this evaluates the context so combinators
    can report only the parts responsible for the result — e.g. an ``any_of``
    names just the branch(es) that fired, not the whole disjunction. Leaf
    predicates have no context-dependent structure, so they fall back to their
    static ``describe()``.
    """
    explain = getattr(pred, "explain", None)
    if callable(explain):
        return str(explain(ctx))
    return describe_predicate(pred)


@dataclass
class AllOf:
    predicates: list[Predicate]

    def evaluate(self, ctx: VerificationContext) -> bool:
        return all(p.evaluate(ctx) for p in self.predicates)

    def describe(self) -> str:
        return "all of (" + "; ".join(describe_predicate(p) for p in self.predicates) + ")"

    def explain(self, ctx: VerificationContext) -> str:
        # an all_of holds only when every part holds, so every part is a reason
        return "all of (" + "; ".join(explain_predicate(p, ctx) for p in self.predicates) + ")"


@dataclass
class AnyOf:
    predicates: list[Predicate]

    def evaluate(self, ctx: VerificationContext) -> bool:
        return any(p.evaluate(ctx) for p in self.predicates)

    def describe(self) -> str:
        return "any of (" + "; ".join(describe_predicate(p) for p in self.predicates) + ")"

    def explain(self, ctx: VerificationContext) -> str:
        # report only the branch(es) that actually fired
        satisfied = [explain_predicate(p, ctx) for p in self.predicates if p.evaluate(ctx)]
        if not satisfied:
            return self.describe()
        if len(satisfied) == 1:
            return satisfied[0]
        return "any of (" + "; ".join(satisfied) + ")"


@dataclass
class Not:
    predicate: Predicate

    def evaluate(self, ctx: VerificationContext) -> bool:
        return not self.predicate.evaluate(ctx)

    def describe(self) -> str:
        return f"not ({describe_predicate(self.predicate)})"


# ---------------------------------------------------------------------------
# Check binding & registry
# ---------------------------------------------------------------------------


@dataclass
class Check:
    """A parsed check bound to the verifier that evaluates it."""

    verifier: Verifier
    parsed: Any

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.verifier.evaluate(self.parsed, ctx)

    def describe(self) -> str:
        """Static description of the check's criterion (context-independent)."""
        return describe_predicate(self.parsed)

    def explain(self, ctx: VerificationContext) -> str:
        """Describe what actually held for this check against ``ctx``."""
        return explain_predicate(self.parsed, ctx)


_VERIFIERS: dict[str, Verifier] = {}
_default_verifier: Verifier | None = None


def _default_claims() -> frozenset[str]:
    return getattr(_default_verifier, "claims", frozenset())


def register_verifier(verifier: Verifier, *, default: bool = False) -> None:
    """Register a verifier so suites can address it by its top-level key.

    ``default=True`` installs it as the fallback for check blocks whose key is
    not a registered verifier (i.e. the built-in predicates). Guards against a
    name shadowing the default verifier's claimed keys (which would silently
    route a check to the wrong evaluator) or an already-registered verifier.
    """
    global _default_verifier
    if default:
        if _default_verifier is not None:
            raise ValueError(f"A default verifier is already registered: {_default_verifier.name!r}")
        _default_verifier = verifier
        return
    if verifier.name in _default_claims():
        raise ValueError(f"Verifier name {verifier.name!r} shadows a default-verifier check type")
    if verifier.name in _VERIFIERS:
        raise ValueError(f"Verifier name {verifier.name!r} is already registered")
    _VERIFIERS[verifier.name] = verifier


def parse_check(raw: dict) -> Check:
    """Resolve a ``utility:`` / ``security:`` block to a verifier-bound check.

    A registered verifier name as the single key dispatches to that verifier;
    anything else falls through to the default verifier (the built-in
    predicates), preserving its behavior and error messages.
    """
    if isinstance(raw, dict) and len(raw) == 1:
        key = next(iter(raw))
        verifier = _VERIFIERS.get(key)
        if verifier is not None:
            return Check(verifier=verifier, parsed=verifier.parse(raw[key]))
    if _default_verifier is None:
        raise ValueError("No default verifier registered (import midojo.verifiers)")
    return Check(verifier=_default_verifier, parsed=_default_verifier.parse(raw))


# ---------------------------------------------------------------------------
# Auto-register built-in verifiers on import
# ---------------------------------------------------------------------------

from midojo.verifiers import builtin as _builtin  # noqa: F401  -- registers the default verifier
