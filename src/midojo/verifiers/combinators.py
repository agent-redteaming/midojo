"""Boolean combinators over predicates.

These are concrete :class:`~midojo.verifiers.Predicate` implementations that
compose other predicates — the logical glue (``all_of``, ``any_of``, ``not``)
that suites use to build richer checks. They live alongside the built-in
predicates (:mod:`midojo.verifiers.builtin`) rather than in the framework core,
and are re-exported from :mod:`midojo.verifiers` for convenience.

Each combinator produces a :class:`~midojo.verifiers.VerificationResult` whose
``reason`` names only the criterion that decided the verdict — for an
:class:`AnyOf` the single branch that fired, for an :class:`AllOf` the
conjunction, for a :class:`Not` the negated reason.
"""

from __future__ import annotations

from dataclasses import dataclass

from midojo.verifiers import Predicate, VerificationContext, VerificationResult


@dataclass
class AllOf:
    predicates: list[Predicate]

    def assess(self, ctx: VerificationContext) -> VerificationResult:
        reasons: list[str] = []
        for p in self.predicates:
            r = p.assess(ctx)
            if not r.passed:
                return VerificationResult(False, r.reason)  # first failing conjunct — same short-circuit as all()
            reasons.append(r.reason)
        return VerificationResult(True, "all of (" + "; ".join(reasons) + ")")

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.assess(ctx).passed


@dataclass
class AnyOf:
    predicates: list[Predicate]

    def assess(self, ctx: VerificationContext) -> VerificationResult:
        reasons: list[str] = []
        for p in self.predicates:
            r = p.assess(ctx)
            if r.passed:
                return VerificationResult(True, r.reason)  # only the branch that fired — same short-circuit as any()
            reasons.append(r.reason)
        return VerificationResult(False, "any of (" + "; ".join(reasons) + ")")

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.assess(ctx).passed


@dataclass
class Not:
    predicate: Predicate

    def assess(self, ctx: VerificationContext) -> VerificationResult:
        r = self.predicate.assess(ctx)
        return VerificationResult(not r.passed, f"not ({r.reason})")

    def evaluate(self, ctx: VerificationContext) -> bool:
        return self.assess(ctx).passed
