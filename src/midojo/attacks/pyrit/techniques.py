"""Register PyRIT's technique catalog into MiDojo's unified AttackLibrary.

This module bridges PyRIT's named attack techniques (role-play variants,
crescendo variants, TAP, PAIR, etc.) into MiDojo's registry so they can
be referenced in suite YAML via ``wrapper:`` or ``strategy.technique:``.

Call ``register_pyrit_techniques()`` to populate the default library.
This is done lazily (not at import time) since it requires PyRIT.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("midojo.pyrit.techniques")

_REGISTERED = False

PYRIT_TECHNIQUES = [
    {
        "id": "role_play_movie_script",
        "description": "Frames the objective as a movie scene via adversarial role-play.",
        "strategy_config": {"type": "prompt_sending", "technique": "role_play_movie_script"},
    },
    {
        "id": "role_play_video_game",
        "description": "Frames the objective as a video game mechanic via adversarial role-play.",
        "strategy_config": {"type": "prompt_sending", "technique": "role_play_video_game"},
    },
    {
        "id": "role_play_trivia_game",
        "description": "Frames the objective as a trivia quiz answer via adversarial role-play.",
        "strategy_config": {"type": "prompt_sending", "technique": "role_play_trivia_game"},
    },
    {
        "id": "role_play_persuasion",
        "description": "Frames a persuasion-resistance test so the target drafts a spoken script.",
        "strategy_config": {"type": "prompt_sending", "technique": "role_play_persuasion"},
    },
    {
        "id": "crescendo_simulated",
        "description": "Crescendo attack preceded by a simulated trust-building conversation.",
        "strategy_config": {"type": "crescendo", "technique": "crescendo_simulated"},
    },
    {
        "id": "crescendo_naive",
        "description": "Naive Crescendo: multi-turn escalation without simulated preamble.",
        "strategy_config": {"type": "crescendo", "technique": "crescendo_naive"},
    },
    {
        "id": "context_compliance",
        "description": "Tests whether the agent follows contextual compliance framing.",
        "strategy_config": {"type": "prompt_sending", "technique": "context_compliance"},
    },
    {
        "id": "many_shot_technique",
        "description": "Primes the target with many fake compliance examples before the real ask.",
        "strategy_config": {"type": "many_shot"},
    },
    {
        "id": "tap_technique",
        "description": "Tree-of-attacks with pruning: explores adversarial prompt tree.",
        "strategy_config": {"type": "tap", "params": {"tree_width": 3, "max_iterations": 5}},
    },
    {
        "id": "pair_technique",
        "description": "PAIR iterative refinement: attacker LLM refines payloads based on feedback.",
        "strategy_config": {"type": "pair", "params": {"max_iterations": 5, "num_streams": 1}},
    },
    {
        "id": "red_teaming_technique",
        "description": "Generic multi-turn red teaming with adversarial LLM.",
        "strategy_config": {"type": "red_team", "params": {"max_turns": 10}},
    },
    {
        "id": "skeleton_key_technique",
        "description": "Skeleton Key jailbreak: attempts to unlock model constraints.",
        "strategy_config": {"type": "skeleton_key"},
    },
    {
        "id": "chunked_request_technique",
        "description": "Chunked request: splits objective across turns by character range to evade single-message filters.",
        "strategy_config": {"type": "chunked_request", "params": {"chunk_size": 50, "total_length": 200}},
    },
    {
        "id": "multi_prompt_technique",
        "description": "Multi-prompt sending: sends a fixed sequence of pre-written prompts in one conversation.",
        "strategy_config": {"type": "multi_prompt"},
    },
    {
        "id": "flip_technique",
        "description": "Flip attack: reverses payload text with task framing to bypass content filters.",
        "strategy_config": {"type": "prompt_sending"},
    },
    {
        "id": "crescendo_movie_director",
        "description": "Crescendo as movie director: gradual escalation via film scene framing.",
        "strategy_config": {"type": "crescendo", "params": {"max_turns": 10}},
    },
    {
        "id": "crescendo_journalist",
        "description": "Crescendo as journalist interview: gradual escalation via investigative journalism framing.",
        "strategy_config": {"type": "crescendo", "params": {"max_turns": 10}},
    },
    {
        "id": "violent_durian",
        "description": "Violent Durian: criminal mastermind persona role-play (max_turns=3).",
        "strategy_config": {"type": "red_team", "params": {"max_turns": 3}},
    },
]


def register_pyrit_techniques() -> None:
    """Register PyRIT techniques into MiDojo's DEFAULT_LIBRARY.

    Safe to call multiple times — idempotent after first registration.
    """
    global _REGISTERED
    if _REGISTERED:
        return
    _REGISTERED = True

    from midojo.attacks.records import AttackTechnique, Origin
    from midojo.attacks.registry import DEFAULT_LIBRARY

    pyrit_origin = Origin(kind="pyrit")

    for spec in PYRIT_TECHNIQUES:
        technique = AttackTechnique(
            id=spec["id"],
            wrapper=lambda payload: payload,
            description=spec["description"],
            origin=pyrit_origin,
            strategy_config=spec["strategy_config"],
        )
        try:
            DEFAULT_LIBRARY.register(technique)
        except ValueError:
            pass

    logger.info("registered %d PyRIT techniques into MiDojo AttackLibrary", len(PYRIT_TECHNIQUES))
