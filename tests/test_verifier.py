"""Tests for the verifier framework (dispatch/registry machinery).

These exercise registration and dispatch, not predicate semantics (those live
in test_predicates.py). They prove a non-builtin verifier can be registered,
addressed from a check block, and handed the full context (including the
``observations`` bag a backend would populate).
"""

import pytest

from midojo.types import Environment
from midojo.verifier import VerificationContext, parse_check, register_verifier
from midojo.verifiers.builtin import BuiltinVerifier, OutputContains

EMPTY = Environment()


def _ctx(output="", *, observations=None):
    return VerificationContext(
        agent_output=output,
        pre_environment=EMPTY,
        post_environment=EMPTY,
        observations=observations or {},
    )


class TestDefaultFallback:
    def test_predicate_key_dispatches_to_builtin_verifier(self):
        check = parse_check({"output_contains": "sunny"})
        assert isinstance(check.verifier, BuiltinVerifier)
        assert isinstance(check.parsed, OutputContains)
        assert check.evaluate(_ctx("it is sunny")) is True
        assert check.evaluate(_ctx("it is rainy")) is False

    def test_unknown_key_still_raises_through_predicates(self):
        with pytest.raises(ValueError, match="Unknown predicate type"):
            parse_check({"bogus": "value"})


class _EventsVerifier:
    """Toy verifier standing in for an ACS-style check over an event stream."""

    name = "events"

    def parse(self, check_spec: dict) -> str:
        return check_spec["contains"]

    def evaluate(self, check: str, ctx: VerificationContext) -> bool:
        return any(check in e for e in ctx.observations.get("events", []))


# Registered once for the module — register_verifier rejects duplicates by design.
register_verifier(_EventsVerifier())


class TestRegisteredVerifier:
    def test_registered_verifier_dispatches_by_key(self):
        check = parse_check({"events": {"contains": "spawn:nc"}})
        assert isinstance(check.verifier, _EventsVerifier)
        assert check.parsed == "spawn:nc"

    def test_verifier_reads_observations(self):
        check = parse_check({"events": {"contains": "spawn:nc"}})
        assert check.evaluate(_ctx(observations={"events": ["spawn:nc -e /bin/sh"]})) is True
        assert check.evaluate(_ctx(observations={"events": ["spawn:ls"]})) is False

    def test_check_assess_falls_back_to_verifier_name(self):
        # _EventsVerifier implements only evaluate(); Check.assess must still run
        # it exactly once and label the outcome with the verifier's name.
        check = parse_check({"events": {"contains": "spawn:nc"}})
        hit = check.assess(_ctx(observations={"events": ["spawn:nc -e /bin/sh"]}))
        assert hit.passed is True
        assert hit.reason == "events"
        miss = check.assess(_ctx(observations={"events": ["spawn:ls"]}))
        assert miss.passed is False

    def test_duplicate_registration_rejected(self):
        with pytest.raises(ValueError, match="already registered"):
            register_verifier(_EventsVerifier())

    def test_shadowing_default_check_type_rejected(self):
        class _Bad:
            name = "output_contains"

            def parse(self, check_spec):
                return check_spec

            def evaluate(self, check, ctx):
                return False

        with pytest.raises(ValueError, match="shadows a default-verifier check type"):
            register_verifier(_Bad())
