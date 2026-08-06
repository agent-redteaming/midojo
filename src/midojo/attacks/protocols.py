"""Attack strategy contracts.

MiDojo defines these protocols so any conforming attack library can be
plugged in.  The host provides an ``AttackContext``; the library returns
an ``AttackResult`` via one of three strategy types:

* **Static injection** — single-shot payload via any channel.
* **Iterative refinement** — payload evolves across attempts (PAIR, TAP,
  Best-of-N).  Requires attacker LLM config and target context.
* **Conversational** — exploit unfolds across conversation turns
  (Crescendo).  Uses ``converse`` to exchange messages with the agent.

Compound strategies (static + conversational) are theoretically possible
but currently blocked: injection state (tool overrides, output hooks) is
per-evaluation, so state set in one eval does not persist into a
subsequent multi-turn eval.  This is noted as a future design concern.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Data protocols — what flows between host and library
# ---------------------------------------------------------------------------


@runtime_checkable
class Injection(Protocol):
    """What an attack library produces to tell MiDojo what to modify."""

    probes: dict[str, str]
    prompt_content: str | None
    prompt_mode: str


@runtime_checkable
class EvalResult(Protocol):
    """What MiDojo returns after a single evaluation."""

    agent_output: str
    function_calls: list[dict[str, Any]]
    security_passed: bool
    utility_passed: bool
    security_score: float | None
    injection: Any


@runtime_checkable
class AttackResult(Protocol):
    """What the attack library returns after execution."""

    success: bool
    evaluations: list[Any]
    strategy_metadata: dict[str, Any]


@runtime_checkable
class PayloadTransform(Protocol):
    """A payload transformation (wrapper/converter/buff).

    Adapters for external libraries (PyRIT Converters, garak Buffs) can
    implement this protocol to register their transforms as MiDojo
    wrappers without wrapping them in ``AttackTechnique``.
    """

    id: str

    def transform(self, payload: str) -> str: ...


# ---------------------------------------------------------------------------
# Context protocols — what MiDojo provides to the library
# ---------------------------------------------------------------------------


@runtime_checkable
class TargetContext(Protocol):
    """What the attacker knows about the target agent."""

    tools: list[dict[str, Any]]
    user_task_prompt: str
    environment_summary: str
    system_prompt: str | None
    dry_run_trace: list[dict[str, Any]] | None


@runtime_checkable
class AttackContext(Protocol):
    """The execution environment MiDojo provides to attack strategies.

    Two levels of agent interaction:

    * ``evaluate_injection`` — atomic single-shot: set up environment
      with the injection, send the resulting prompt to the agent, grade,
      return.  Each call is independent — environment resets between
      calls.  Used by static and iterative strategies.

    * ``converse`` — send one conversational message to the agent and
      get a response.  Conversation state is maintained via an opaque
      token returned alongside the output.  The orchestrator manages
      the evaluation lifecycle (create / complete / grade) around the
      strategy execution; the library just talks to the agent.  Used
      by conversational strategies (Crescendo, social engineering) and
      external library adapters (PyRIT, garak).  Implementations that
      do not support conversational strategies should raise
      ``NotImplementedError``.
    """

    tool_names: list[str]
    target: Any
    attacker_model: str | None
    attacker_base_url: str | None
    attacker_api_key: str | None

    async def evaluate_injection(self, injection: Any) -> Any: ...

    async def converse(self, message: str, state: Any) -> tuple[str, Any]: ...


# ---------------------------------------------------------------------------
# Strategy protocols — what the library implements
# ---------------------------------------------------------------------------


@runtime_checkable
class StaticAttackStrategy(Protocol):
    """Single-shot injection via any channel.

    Calls ``ctx.evaluate_injection`` once with a pre-built injection.
    """

    id: str
    strategy_type: Literal["static"]

    async def run(self, spec: Any, ctx: AttackContext) -> AttackResult: ...


@runtime_checkable
class IterativeAttackStrategy(Protocol):
    """Refines payloads across multiple attempts.

    Calls ``ctx.evaluate_injection`` N times, using an attacker LLM
    (configured via ``ctx.attacker_model``) and target context
    (``ctx.target``) to refine payloads between attempts.
    """

    id: str
    strategy_type: Literal["iterative"]

    async def run(self, spec: Any, ctx: AttackContext) -> AttackResult: ...


@runtime_checkable
class ConversationalAttackStrategy(Protocol):
    """Multi-turn conversational exploitation.

    Uses ``ctx.converse`` to exchange messages with the agent across
    multiple turns, escalating toward the objective.  May combine
    with static injection in future compound strategies.
    """

    id: str
    strategy_type: Literal["conversational"]

    async def run(self, spec: Any, ctx: AttackContext) -> AttackResult: ...


AttackStrategy = StaticAttackStrategy | IterativeAttackStrategy | ConversationalAttackStrategy
