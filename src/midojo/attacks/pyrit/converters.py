"""PyRIT converter integration for MiDojo.

Bridges PyRIT's converter ecosystem into MiDojo's attack pipeline. Converters
transform payloads before they reach the injection target — obfuscation,
encoding, language translation, semantic rephrasing, steganography, etc.

Two integration surfaces:

1. **Static converters** — declared in suite YAML ``probes.<id>.converters``
   list. Applied to the seed payload before injection. Works with both
   static (no strategy) and adaptive (PAIR/TAP/Crescendo) attacks.

2. **Strategy converters** — passed to PyRIT's ``AttackConverterConfig``
   so the attacker LLM's generated payloads are transformed before each
   evaluation attempt. Only applies to adaptive strategies.

Requires ``pyrit`` — install with ``pip install midojo[pyrit]``.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("midojo.converters")

__all__ = [
    "CONVERTER_REGISTRY",
    "apply_converters",
    "build_attack_converter_config",
    "resolve_converter",
    "resolve_converters",
]

# ---------------------------------------------------------------------------
# Converter registry — maps short names to PyRIT converter constructors
# This is pure data and does NOT import PyRIT.
# ---------------------------------------------------------------------------

CONVERTER_REGISTRY: dict[str, dict[str, Any]] = {
    # ── Encoding / ciphers (no LLM needed) ────────────────────────────────
    "base64": {"class": "Base64Converter", "description": "Base64-encode the payload"},
    "base2048": {"class": "Base2048Converter", "description": "Base2048-encode (compact Unicode encoding)"},
    "rot13": {"class": "ROT13Converter", "description": "ROT13 cipher"},
    "binary": {"class": "BinaryConverter", "description": "Binary representation"},
    "binascii": {"class": "BinAsciiConverter", "description": "Binary-to-ASCII hex encoding"},
    "morse": {"class": "MorseConverter", "description": "Morse code encoding"},
    "nato": {"class": "NatoConverter", "description": "NATO phonetic alphabet encoding"},
    "braille": {"class": "BrailleConverter", "description": "Braille Unicode representation"},
    "atbash": {"class": "AtbashConverter", "description": "Atbash cipher (reverse alphabet)"},
    "caesar": {"class": "CaesarConverter", "description": "Caesar cipher shift", "kwargs": {"caesar_offset": 3}},
    "ascii_art": {"class": "AsciiArtConverter", "description": "ASCII art representation"},
    "ecoji": {"class": "EcojiConverter", "description": "Emoji-based encoding (ecoji)"},
    "math_obfuscation": {"class": "MathObfuscationConverter", "description": "Replace words with math expressions"},
    "code_chameleon": {"class": "CodeChameleonConverter", "description": "Encrypt payload inside code blocks"},
    "ask_to_decode": {
        "class": "AskToDecodeConverter",
        "description": "Wrap encoded payload with decode instructions",
    },
    # ── Text obfuscation / perturbation (no LLM needed) ───────────────────
    "leetspeak": {"class": "LeetspeakConverter", "description": "Leetspeak transformation"},
    "flip": {"class": "FlipConverter", "description": "Reverse the text"},
    "charswap": {"class": "CharSwapConverter", "description": "Swap adjacent characters randomly"},
    "char_space": {"class": "CharacterSpaceConverter", "description": "Insert spaces between characters"},
    "string_join": {"class": "StringJoinConverter", "description": "Join characters with a separator", "kwargs": {"join_value": "-"}},
    "random_caps": {"class": "RandomCapitalLettersConverter", "description": "Randomly capitalize letters"},
    "insert_punctuation": {"class": "InsertPunctuationConverter", "description": "Insert random punctuation between words"},
    "repeat_token": {"class": "RepeatTokenConverter", "description": "Repeat a token to pad/confuse", "kwargs": {"token_to_repeat": " ", "times_to_repeat": 3}},
    "superscript": {"class": "SuperscriptConverter", "description": "Convert to Unicode superscript characters"},
    "zalgo": {"class": "ZalgoConverter", "description": "Add Zalgo combining characters for visual noise"},
    "diacritic": {"class": "DiacriticConverter", "description": "Add diacritical marks to characters"},
    "emoji": {"class": "EmojiConverter", "description": "Replace words with emoji equivalents"},
    "suffix_append": {"class": "SuffixAppendConverter", "description": "Append a suffix string to the payload"},
    "search_replace": {"class": "SearchReplaceConverter", "description": "Search-and-replace pattern in payload"},
    "negation_trap": {"class": "NegationTrapConverter", "description": "Add negation phrases to confuse the model"},
    # ── Steganography / token smuggling (no LLM needed) ───────────────────
    "unicode_confusable": {"class": "UnicodeConfusableConverter", "description": "Replace chars with visually-identical Unicode confusables"},
    "zero_width": {"class": "ZeroWidthConverter", "description": "Encode payload in zero-width Unicode characters"},
    "ascii_smuggler": {"class": "AsciiSmugglerConverter", "description": "Hide payload in Unicode tag characters (invisible ASCII smuggling)"},
    "sneaky_bits": {"class": "SneakyBitsSmugglerConverter", "description": "Hide payload in zero-width Unicode bit encoding"},
    "variation_selector": {"class": "VariationSelectorSmugglerConverter", "description": "Hide payload using Unicode variation selectors"},
    "bidi": {"class": "BidiConverter", "description": "Use Unicode bidirectional control characters to reorder text"},
    # ── Structural encoding (no LLM needed) ───────────────────────────────
    "first_letter": {"class": "FirstLetterConverter", "description": "Encode objective as first letter of each word"},
    "acrostic": {"class": "AcrosticConverter", "description": "Encode payload as an acrostic poem/message"},
    # ── Script / writing system (no LLM needed) ──────────────────────────
    "tatweel": {"class": "TatweelConverter", "description": "Insert Arabic kashida characters"},
    "arabic_presentation": {"class": "ArabicPresentationFormConverter", "description": "Replace Arabic with isolated presentation forms"},
    "arabizi": {"class": "ArabiziConverter", "description": "Arabic to Latin transliteration"},
    # ── Attack technique converters (no LLM needed) ───────────────────────
    "ansi_attack": {"class": "AnsiAttackConverter", "description": "Use ANSI escape sequences to manipulate terminal display"},
    "policy_puppetry": {"class": "PolicyPuppetryConverter", "description": "Frame payload as a policy/config document the model should follow"},
    "jailbreak_template": {"class": "TextJailbreakConverter", "description": "Apply a known jailbreak template (DAN, AIM, etc.)"},
    "template_segment": {"class": "TemplateSegmentConverter", "description": "Split prompt using a template pattern"},
    # ── LLM-based converters (require a converter_target) ─────────────────
    "variation": {"class": "VariationConverter", "description": "Generate a diverse rephrasing using an LLM", "requires_target": True},
    "translation": {"class": "TranslationConverter", "description": "Translate to a different language", "requires_target": True, "kwargs": {"language": "Spanish"}},
    "random_translation": {"class": "RandomTranslationConverter", "description": "Translate each word to a random language", "requires_target": True},
    "llm_rephrase": {"class": "LLMGenericTextConverter", "description": "Rephrase payload using a custom LLM prompt", "requires_target": True},
    "tone_formal": {"class": "ToneConverter", "description": "Rewrite in formal/professional tone", "requires_target": True, "kwargs": {"tone": "formal"}},
    "tone_casual": {"class": "ToneConverter", "description": "Rewrite in casual/friendly tone", "requires_target": True, "kwargs": {"tone": "casual"}},
    "tone_angry": {"class": "ToneConverter", "description": "Rewrite in angry/aggressive tone", "requires_target": True, "kwargs": {"tone": "angry"}},
    "persuasion": {"class": "PersuasionConverter", "description": "Reframe using persuasion techniques", "requires_target": True},
    "task_framing": {"class": "TaskFramingConverter", "description": "Wrap payload in a contextual task framing", "requires_target": True},
    "decomposition": {"class": "DecompositionConverter", "description": "Split objective into a reconstruction puzzle", "requires_target": True},
    "noise": {"class": "NoiseConverter", "description": "Add random noise/typos via LLM", "requires_target": True},
    "tense_past": {"class": "TenseConverter", "description": "Change verb tense to past", "requires_target": True, "kwargs": {"tense": "past"}},
    "tense_future": {"class": "TenseConverter", "description": "Change verb tense to future", "requires_target": True, "kwargs": {"tense": "future"}},
    "scientific": {"class": "ScientificTranslationConverter", "description": "Translate into scientific/academic language", "requires_target": True},
    "colloquial": {"class": "ColloquialWordswapConverter", "description": "Replace words with colloquial equivalents", "requires_target": True},
    "malicious_question": {"class": "MaliciousQuestionGeneratorConverter", "description": "Generate adversarial question variants", "requires_target": True},
    "toxic_sentence": {"class": "ToxicSentenceGeneratorConverter", "description": "Generate toxic sentence variants", "requires_target": True},
    "denylist": {"class": "DenylistConverter", "description": "Rephrase to avoid denylist terms", "requires_target": True},
}


def _require_pyrit_converters() -> None:
    try:
        import pyrit.converter  # noqa: F401
    except ImportError:
        raise ImportError(
            "PyRIT converters are required. Install with: pip install midojo[pyrit]"
        ) from None


def _get_converter_class(class_name: str) -> type:
    """Resolve a converter class by name from pyrit.converter."""
    _require_pyrit_converters()
    import pyrit.converter as conv_module

    cls = getattr(conv_module, class_name, None)
    if cls is None:
        raise ValueError(f"Unknown PyRIT converter class: {class_name}")
    return cls


def _build_converter_target(
    model: str | None = None,
    endpoint: str | None = None,
) -> Any:
    """Build a LiteLLMChatTarget for LLM-based converters.

    Uses the provided model/endpoint, or falls back to env vars
    CONVERTER_MODEL / ATTACKER_MODEL and CONVERTER_BASE_URL / ATTACKER_BASE_URL.
    """
    import os

    _require_pyrit_converters()
    from pyrit.prompt_target import LiteLLMChatTarget

    resolved_model = model or os.environ.get("CONVERTER_MODEL") or os.environ.get("ATTACKER_MODEL")
    resolved_endpoint = endpoint or os.environ.get("CONVERTER_BASE_URL") or os.environ.get("ATTACKER_BASE_URL")
    resolved_key = os.environ.get("CONVERTER_API_KEY") or os.environ.get("ATTACKER_API_KEY", "no-key")

    if not resolved_model:
        raise ValueError(
            "LLM-based converters require a model. Set converter_target_model in the spec, "
            "or CONVERTER_MODEL / ATTACKER_MODEL env var."
        )

    return LiteLLMChatTarget(
        model_name=resolved_model,
        endpoint=resolved_endpoint,
        api_key=resolved_key,
    )


def _build_selective_converter(spec: dict[str, Any]) -> Any:
    """Build a SelectiveTextConverter from a YAML spec.

    Spec format::

        name: selective
        sub_converter: rot13           # any registry name or dict spec
        strategy: keyword              # keyword, regex, index, proportion
        keywords: [SSN, password]      # strategy-specific params
    """
    _require_pyrit_converters()
    from pyrit.converter import SelectiveTextConverter
    from pyrit.converter.text_selection_strategy import (
        WordIndexSelectionStrategy,
        WordKeywordSelectionStrategy,
        WordProportionSelectionStrategy,
        WordRegexSelectionStrategy,
    )

    sub_spec = spec.get("sub_converter", "rot13")
    sub_conv = resolve_converter(sub_spec)

    strategy_type = spec.get("strategy", "keyword")
    if strategy_type == "keyword":
        strategy = WordKeywordSelectionStrategy(keywords=spec.get("keywords", []))
    elif strategy_type == "regex":
        strategy = WordRegexSelectionStrategy(regex=spec.get("regex", ".*"))
    elif strategy_type == "index":
        strategy = WordIndexSelectionStrategy(indices=spec.get("indices", [0]))
    elif strategy_type == "proportion":
        strategy = WordProportionSelectionStrategy(proportion=spec.get("proportion", 0.5))
    else:
        raise ValueError(f"Unknown selective strategy: {strategy_type}")

    return SelectiveTextConverter(
        sub_converter=sub_conv,
        selection_strategy=strategy,
        preserve_tokens=spec.get("preserve_tokens", False),
    )


def resolve_converter(spec: str | dict[str, Any]) -> Any:
    """Resolve a converter specification to a PyRIT Converter instance.

    Accepts either:
    - A string name from CONVERTER_REGISTRY (e.g., "base64", "rot13")
    - A dict with "name" key and optional kwargs (e.g., {"name": "caesar", "caesar_offset": 5})
    - A dict with "class" key for direct PyRIT class reference
    - ``{"name": "selective", "sub_converter": "rot13", "strategy": "keyword", "keywords": [...]}``
    - For LLM-based converters, include "converter_target_model" and optionally
      "converter_target_endpoint" in the dict spec.
    """
    if isinstance(spec, dict) and spec.get("name") == "selective":
        return _build_selective_converter(spec)

    if isinstance(spec, str):
        if spec not in CONVERTER_REGISTRY:
            cls = _get_converter_class(spec)
            return cls()
        entry = CONVERTER_REGISTRY[spec]
        if entry.get("requires_target"):
            cls = _get_converter_class(entry["class"])
            target = _build_converter_target()
            return cls(converter_target=target, **entry.get("kwargs", {}))
        cls = _get_converter_class(entry["class"])
        return cls(**entry.get("kwargs", {}))

    name = spec.get("name") or spec.get("class")
    if not name:
        raise ValueError(f"Converter spec must have 'name' or 'class' key: {spec}")

    kwargs = {k: v for k, v in spec.items() if k not in ("name", "class", "description", "converter_target_model", "converter_target_endpoint")}

    if name in CONVERTER_REGISTRY:
        entry = CONVERTER_REGISTRY[name]
        merged_kwargs = {**entry.get("kwargs", {}), **kwargs}
        cls = _get_converter_class(entry["class"])
        if entry.get("requires_target") or spec.get("converter_target_model"):
            target = _build_converter_target(
                model=spec.get("converter_target_model"),
                endpoint=spec.get("converter_target_endpoint"),
            )
            return cls(converter_target=target, **merged_kwargs)
        return cls(**merged_kwargs)

    cls = _get_converter_class(name)
    if spec.get("converter_target_model"):
        target = _build_converter_target(
            model=spec.get("converter_target_model"),
            endpoint=spec.get("converter_target_endpoint"),
        )
        return cls(converter_target=target, **kwargs)
    return cls(**kwargs)


def resolve_converters(specs: list[str | dict[str, Any]]) -> list[Any]:
    """Resolve a list of converter specifications."""
    return [resolve_converter(s) for s in specs]


async def apply_converters(payload: str, converters: list[Any]) -> str:
    """Apply a chain of PyRIT converters to a payload string.

    Converters are applied in order (pipeline-style). Each converter's
    output becomes the next converter's input. Logs before/after for audit.
    """
    result = payload
    for conv in converters:
        conv_name = type(conv).__name__
        before = result[:100]
        conv_result = await conv.convert_tokens_async(prompt=result)
        result = conv_result.output_text
        after = result[:100]
        logger.info("converter %s: %r -> %r", conv_name, before, after)
    return result


def build_attack_converter_config(
    converter_specs: list[str | dict[str, Any]],
) -> Any:
    """Build a PyRIT AttackConverterConfig from converter specifications.

    Used when passing converters to PyRIT attack strategies (PAIR, TAP, etc.)
    so the attacker LLM's generated payloads are transformed before each
    evaluation attempt.
    """
    _require_pyrit_converters()
    from pyrit.executor.attack import AttackConverterConfig
    from pyrit.prompt_normalizer import ConverterConfiguration

    converters = resolve_converters(converter_specs)
    converter_configs = ConverterConfiguration.from_converters(converters=converters)
    return AttackConverterConfig(request_converters=converter_configs)
