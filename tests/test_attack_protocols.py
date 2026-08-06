# ruff: noqa: RUF012
"""Conformance tests for the attack strategy protocols.

These verify that the Protocol shapes work as intended — toy classes that
satisfy each protocol pass isinstance checks, and classes missing required
attributes don't. They do NOT test behavior (no real attack execution).
"""

from __future__ import annotations

from typing import Any

from midojo.attacks.protocols import (
    AttackContext,
    AttackResult,
    ConversationalAttackStrategy,
    EvalResult,
    Injection,
    IterativeAttackStrategy,
    PayloadTransform,
    StaticAttackStrategy,
    TargetContext,
)

# ---------------------------------------------------------------------------
# Toy implementations that satisfy each protocol
# ---------------------------------------------------------------------------


class _ToyInjection:
    probes: dict[str, str] = {}
    prompt_content: str | None = None
    prompt_mode: str = "append"


class _ToyEvalResult:
    agent_output: str = ""
    function_calls: list[dict[str, Any]] = []
    security_passed: bool = False
    utility_passed: bool = True
    security_score: float | None = None
    injection: Any = None


class _ToyAttackResult:
    success: bool = False
    evaluations: list[Any] = []
    strategy_metadata: dict[str, Any] = {}


class _ToyPayloadTransform:
    id: str = "rot13"

    def transform(self, payload: str) -> str:
        return payload[::-1]


class _ToyTargetContext:
    tools: list[dict[str, Any]] = []
    user_task_prompt: str = "What is the weather?"
    environment_summary: str = "{}"
    system_prompt: str | None = None
    dry_run_trace: list[dict[str, Any]] | None = None


class _ToyAttackContext:
    tool_names: list[str] = []
    target: Any = None
    attacker_model: str | None = None
    attacker_base_url: str | None = None
    attacker_api_key: str | None = None

    async def evaluate_injection(self, injection: Any) -> Any:
        return _ToyEvalResult()

    async def converse(self, message: str, state: Any) -> tuple[str, Any]:
        raise NotImplementedError


class _ToyStaticStrategy:
    id: str = "toy-static"
    strategy_type: str = "static"

    async def run(self, spec: Any, ctx: AttackContext) -> AttackResult:
        return _ToyAttackResult()


class _ToyIterativeStrategy:
    id: str = "toy-iterative"
    strategy_type: str = "iterative"

    async def run(self, spec: Any, ctx: AttackContext) -> AttackResult:
        return _ToyAttackResult()


class _ToyConversationalStrategy:
    id: str = "toy-conversational"
    strategy_type: str = "conversational"

    async def run(self, spec: Any, ctx: AttackContext) -> AttackResult:
        return _ToyAttackResult()


# ---------------------------------------------------------------------------
# Data protocol conformance
# ---------------------------------------------------------------------------


class TestDataProtocols:
    def test_injection_conforms(self):
        assert isinstance(_ToyInjection(), Injection)

    def test_eval_result_conforms(self):
        assert isinstance(_ToyEvalResult(), EvalResult)

    def test_attack_result_conforms(self):
        assert isinstance(_ToyAttackResult(), AttackResult)

    def test_payload_transform_conforms(self):
        assert isinstance(_ToyPayloadTransform(), PayloadTransform)


# ---------------------------------------------------------------------------
# Context protocol conformance
# ---------------------------------------------------------------------------


class TestContextProtocols:
    def test_target_context_conforms(self):
        assert isinstance(_ToyTargetContext(), TargetContext)

    def test_attack_context_conforms(self):
        assert isinstance(_ToyAttackContext(), AttackContext)

    def test_attack_context_requires_methods(self):
        class _Missing:
            tool_names: list[str] = []
            target: Any = None
            attacker_model: str | None = None
            attacker_base_url: str | None = None
            attacker_api_key: str | None = None

        assert not isinstance(_Missing(), AttackContext)


# ---------------------------------------------------------------------------
# Strategy protocol conformance
# ---------------------------------------------------------------------------


class TestStrategyProtocols:
    def test_static_strategy_conforms(self):
        assert isinstance(_ToyStaticStrategy(), StaticAttackStrategy)

    def test_iterative_strategy_conforms(self):
        assert isinstance(_ToyIterativeStrategy(), IterativeAttackStrategy)

    def test_conversational_strategy_conforms(self):
        assert isinstance(_ToyConversationalStrategy(), ConversationalAttackStrategy)

    def test_strategy_type_enables_runtime_dispatch(self):
        """strategy_type lets the orchestrator dispatch without isinstance.

        Literal types are enforced at type-check time (pyright/mypy) but
        runtime_checkable isinstance only checks attribute existence, not
        value. The intended dispatch pattern is:

            if strategy.strategy_type == "conversational": ...
        """
        assert _ToyStaticStrategy().strategy_type == "static"
        assert _ToyIterativeStrategy().strategy_type == "iterative"
        assert _ToyConversationalStrategy().strategy_type == "conversational"

    def test_missing_run_method_fails(self):
        class _NoRun:
            id: str = "bad"
            strategy_type: str = "static"

        assert not isinstance(_NoRun(), StaticAttackStrategy)

    def test_missing_strategy_type_fails(self):
        class _NoType:
            id: str = "bad"

            async def run(self, spec: Any, ctx: AttackContext) -> AttackResult:
                return _ToyAttackResult()

        assert not isinstance(_NoType(), StaticAttackStrategy)
