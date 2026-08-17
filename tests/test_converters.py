"""Tests for the converter integration module."""

from __future__ import annotations

import pytest


class TestConverterRegistry:
    """Tests for the converter registry and resolution."""

    def test_registry_has_expected_entries(self):
        from midojo.attacks.pyrit.converters import CONVERTER_REGISTRY

        original = {"base64", "rot13", "binary", "morse", "atbash", "caesar",
                     "leetspeak", "ascii_art", "flip", "unicode_confusable",
                     "zero_width", "char_space", "charswap", "string_join"}
        smuggling = {"ascii_smuggler", "sneaky_bits", "variation_selector", "bidi"}
        encoding = {"base2048", "binascii", "nato", "braille", "ecoji",
                     "math_obfuscation", "code_chameleon", "ask_to_decode"}
        perturbation = {"random_caps", "insert_punctuation", "repeat_token",
                         "superscript", "zalgo", "diacritic", "emoji",
                         "negation_trap", "suffix_append", "search_replace"}
        attack = {"ansi_attack", "policy_puppetry", "jailbreak_template",
                   "template_segment", "first_letter", "acrostic"}
        llm = {"decomposition", "noise", "scientific", "colloquial",
                "random_translation", "malicious_question", "toxic_sentence",
                "denylist", "tone_angry", "tense_past", "tense_future"}
        all_expected = original | smuggling | encoding | perturbation | attack | llm
        assert all_expected.issubset(set(CONVERTER_REGISTRY.keys()))
        assert len(CONVERTER_REGISTRY) >= 55


def _has_pyrit() -> bool:
    try:
        import pyrit  # noqa: F401

        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _has_pyrit(), reason="PyRIT not installed")
class TestConverterResolution:
    """Tests that require PyRIT to be installed."""

    def test_resolve_string_name(self):
        from midojo.attacks.pyrit.converters import resolve_converter

        conv = resolve_converter("rot13")
        assert conv is not None
        assert hasattr(conv, "convert_tokens_async")

    def test_resolve_dict_spec(self):
        from midojo.attacks.pyrit.converters import resolve_converter

        conv = resolve_converter({"name": "caesar", "caesar_offset": 7})
        assert conv is not None

    def test_resolve_unknown_raises(self):
        from midojo.attacks.pyrit.converters import resolve_converter

        with pytest.raises(ValueError, match="Unknown PyRIT converter"):
            resolve_converter("nonexistent_converter_xyz")

    def test_resolve_converters_list(self):
        from midojo.attacks.pyrit.converters import resolve_converters

        convs = resolve_converters(["rot13", "base64"])
        assert len(convs) == 2

    @pytest.mark.asyncio
    async def test_apply_converters_single(self):
        from midojo.attacks.pyrit.converters import apply_converters, resolve_converters

        convs = resolve_converters(["rot13"])
        result = await apply_converters("hello", convs)
        assert result == "uryyb"

    @pytest.mark.asyncio
    async def test_apply_converters_chain(self):
        from midojo.attacks.pyrit.converters import apply_converters, resolve_converters

        convs = resolve_converters(["rot13", "rot13"])
        result = await apply_converters("hello", convs)
        assert result == "hello"

    @pytest.mark.asyncio
    async def test_apply_converters_empty_list(self):
        from midojo.attacks.pyrit.converters import apply_converters

        result = await apply_converters("hello", [])
        assert result == "hello"

    @pytest.mark.asyncio
    async def test_selective_converter_keyword(self):
        from midojo.attacks.pyrit.converters import apply_converters, resolve_converter

        conv = resolve_converter({
            "name": "selective",
            "sub_converter": "rot13",
            "strategy": "keyword",
            "keywords": ["secret"],
        })
        result = await apply_converters("the secret is hidden", [conv])
        assert "frperg" in result
        assert "the" in result
        assert "hidden" in result

    def test_build_attack_converter_config(self):
        from midojo.attacks.pyrit.converters import build_attack_converter_config

        config = build_attack_converter_config(["rot13"])
        assert config is not None
        assert hasattr(config, "request_converters")
        assert len(config.request_converters) > 0


class TestRegisterPyritTechniques:
    """Tests for register_pyrit_techniques."""

    def test_techniques_registered_into_library(self):
        from midojo.attacks.pyrit.techniques import PYRIT_TECHNIQUES, register_pyrit_techniques
        from midojo.attacks.registry import DEFAULT_LIBRARY

        register_pyrit_techniques()
        for spec in PYRIT_TECHNIQUES:
            technique = DEFAULT_LIBRARY.get(spec["id"])
            assert technique is not None
            assert technique.origin.kind == "pyrit"
            assert technique.strategy_config is not None

    def test_idempotent_registration(self):
        from midojo.attacks.pyrit.techniques import register_pyrit_techniques

        register_pyrit_techniques()
        register_pyrit_techniques()

    def test_identity_wrapper(self):
        from midojo.attacks.pyrit.techniques import register_pyrit_techniques
        from midojo.attacks.registry import DEFAULT_LIBRARY

        register_pyrit_techniques()
        technique = DEFAULT_LIBRARY.get("pair_technique")
        assert technique.wrapper("test payload") == "test payload"


class TestConverterYAMLParsing:
    """Tests that converters declared in suite YAML are extracted correctly."""

    def test_converters_in_strategy_config(self, tmp_path):
        from midojo.yaml_task_suite import YAMLTaskSuite

        suite_yaml = tmp_path / "suite.yaml"
        suite_yaml.write_text("""
environment:
  backend: dict
  state:
    data: "{it0:main}"
user_tasks:
  - id: ut0
    prompt: "do something"
    utility:
      output_contains: "ok"
injection_tasks:
  - id: it0
    description: "test converters"
    probes:
      main:
        payload: "attack payload"
        converters:
          - rot13
          - base64
        strategy:
          type: pair
          params:
            max_iterations: 5
    security:
      output_contains: "hacked"
""")
        suite = YAMLTaskSuite("test", suite_yaml)
        cfg = suite.injection_tasks["it0"].strategy_config
        assert cfg is not None
        assert cfg["type"] == "pair"

        raw_probes = suite.get_raw_probes("it0")
        assert raw_probes is not None
        assert raw_probes["main"].get("converters") == ["rot13", "base64"]
