from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from midojo.attacks import resolve_source, wrap_payload
from midojo.backends import EnvironmentBackend, build_backend
from midojo.probes import substitute_probes
from midojo.types import Environment, FunctionCallRecord
from midojo.verifier import Check, VerificationContext, parse_check


@dataclass
class UserTask:
    id: str
    prompt: str
    check: Check


@dataclass
class InjectionTask:
    id: str
    description: str
    probes: dict[str, str] = field(default_factory=dict)
    check: Check | None = None
    attack_spec: dict | None = None


class YAMLTaskSuite:
    """Reads a suite definition from a single suite.yaml file."""

    def __init__(
        self,
        name: str,
        suite_yaml_path: Path,
        backend: EnvironmentBackend | None = None,
    ) -> None:
        self.name = name
        self._suite_yaml_path = suite_yaml_path
        self._suite_raw: dict = yaml.safe_load(suite_yaml_path.read_text())
        self.backend: EnvironmentBackend = backend or build_backend(name, self._suite_raw["environment"])
        self.user_tasks: dict[str, UserTask] = {}
        self.injection_tasks: dict[str, InjectionTask] = {}
        self._register_tasks()

    @property
    def environment_type(self) -> type[Environment]:
        return self.backend.environment_type

    def provision_environment(self, injections: dict[str, str]) -> Environment:
        return self.backend.provision(injections)

    def inject_user_task_prompt(self, user_task_id: str, injections: dict[str, str]) -> str:
        return substitute_probes(self.user_tasks[user_task_id].prompt, injections)

    def get_probes_for_task(self, task_id: str) -> dict[str, str]:
        probes = self.injection_tasks[task_id].probes
        return {f"{task_id}:{probe_id}": payload for probe_id, payload in probes.items()}

    def grade(
        self,
        user_task_id: str,
        injection_task_id: str | None,
        agent_output: str,
        pre_environment: Environment,
        post_environment: Environment,
        function_calls: list[FunctionCallRecord],
        observations: dict[str, Any] | None = None,
    ) -> dict[str, bool]:
        ctx = VerificationContext(
            agent_output=agent_output,
            pre_environment=pre_environment,
            post_environment=post_environment,
            function_calls=function_calls,
            observations=observations or {},
        )

        utility = self.user_tasks[user_task_id].check.evaluate(ctx)

        injection_check = self.injection_tasks[injection_task_id].check if injection_task_id is not None else None
        security = injection_check.evaluate(ctx) if injection_check is not None else False

        return {"utility": utility, "security": security}

    def _register_tasks(self) -> None:
        for task_raw in self._suite_raw.get("user_tasks", []):
            task_id = task_raw["id"]
            check = parse_check(task_raw["utility"])
            self.user_tasks[task_id] = UserTask(id=task_id, prompt=task_raw["prompt"], check=check)

        for task_raw in self._suite_raw.get("injection_tasks", []):
            task_id = task_raw["id"]
            check = parse_check(task_raw["security"])
            probes, attack_spec = self._parse_probes(task_id, task_raw.get("probes", {}))
            if not attack_spec:
                attack_spec = task_raw.get("attack")
                if attack_spec:
                    attack_spec = dict(attack_spec)
                    self._enrich_attack_spec(attack_spec, task_id, task_raw.get("probes", {}))
            self.injection_tasks[task_id] = InjectionTask(
                id=task_id,
                description=task_raw["description"],
                check=check,
                probes=probes,
                attack_spec=attack_spec,
            )

    def _enrich_attack_spec(self, attack_spec: dict, task_id: str, probes_raw: dict) -> None:
        """Extract channel config and seed payloads from probes into the attack spec.

        Legacy path: when ``attack:`` block is at the injection_task level
        rather than inside each probe.
        """
        if "channel_config" not in attack_spec:
            attack_spec["channel_config"] = {}
        if "seed_payloads" not in attack_spec:
            attack_spec["seed_payloads"] = []

        for probe_raw in probes_raw.values():
            if "payload" in probe_raw:
                attack_spec["seed_payloads"].append(probe_raw["payload"])
            elif "source" in probe_raw:
                try:
                    ps = resolve_source(probe_raw["source"], base_dir=self._suite_yaml_path.parent)
                    idx = probe_raw.get("index", 0)
                    if 0 <= idx < len(ps.payloads):
                        attack_spec["seed_payloads"].append(ps.payloads[idx])
                except ValueError:
                    pass

            if probe_raw.get("target_tool"):
                attack_spec["channel_config"]["target_tool"] = probe_raw["target_tool"]
            if probe_raw.get("inject_mode"):
                attack_spec["channel_config"]["inject_mode"] = probe_raw["inject_mode"]
            if probe_raw.get("prompt_mode"):
                attack_spec["channel_config"]["mode"] = probe_raw["prompt_mode"]

    def _parse_probes(self, task_id: str, raw: dict[str, dict]) -> tuple[dict[str, str], dict | None]:
        """Parse probe definitions, returning (probes_dict, attack_spec).

        Supports both legacy ``attack_type`` and new ``wrapper`` field names.
        If any probe has a ``strategy`` block, an attack_spec is built from it.
        """
        probes: dict[str, str] = {}
        attack_spec: dict | None = None
        for probe_id, probe_raw in raw.items():
            try:
                payload = self._resolve_probe_payload(probe_raw)

                wrapper = probe_raw.get("wrapper") or probe_raw.get("attack_type", "verbatim")
                if isinstance(wrapper, list):
                    wrapped = payload
                    for wrapper_id in wrapper:
                        wrapped = wrap_payload(wrapped, wrapper_id)
                else:
                    wrapped = wrap_payload(payload, wrapper)

                probes[probe_id] = wrapped

                strategy = probe_raw.get("strategy")
                if strategy and attack_spec is None:
                    attack_spec = self._build_attack_spec_from_probe(probe_raw, payload)
            except ValueError as e:
                raise ValueError(f"Probe '{task_id}:{probe_id}': {e}") from None
        return probes, attack_spec

    def _build_attack_spec_from_probe(self, probe_raw: dict, raw_payload: str) -> dict:
        """Build an attack spec from a probe's inline strategy config."""
        strategy = probe_raw["strategy"]
        wrapper = probe_raw.get("wrapper") or probe_raw.get("attack_type", "verbatim")
        if isinstance(wrapper, str):
            wrapper = [wrapper]

        spec: dict = {
            "wrappers": wrapper,
            "channel": probe_raw.get("channel", "environment_state"),
            "seed_payloads": [raw_payload],
        }

        if isinstance(strategy, dict):
            spec["strategy"] = strategy.get("type", "static")
            spec["strategy_params"] = {k: v for k, v in strategy.items() if k != "type"}
            if "attacker_llm_config" in strategy:
                spec["attacker_llm_config"] = strategy["attacker_llm_config"]
        else:
            spec["strategy"] = strategy

        channel_config = {}
        if probe_raw.get("target_tool"):
            channel_config["target_tool"] = probe_raw["target_tool"]
        if probe_raw.get("inject_mode"):
            channel_config["inject_mode"] = probe_raw["inject_mode"]
        if probe_raw.get("prompt_mode"):
            channel_config["mode"] = probe_raw["prompt_mode"]
        if channel_config:
            spec["channel_config"] = channel_config

        return spec

    def _resolve_probe_payload(self, probe_raw: dict) -> str:
        """A probe's cargo is either an inline ``payload`` or a library ``source``."""
        if ("payload" in probe_raw) == ("source" in probe_raw):
            raise ValueError("exactly one of 'payload' or 'source' is required")
        if "payload" in probe_raw:
            return probe_raw["payload"]
        payload_set = resolve_source(probe_raw["source"], base_dir=self._suite_yaml_path.parent)
        index = probe_raw.get("index", 0)
        if not 0 <= index < len(payload_set.payloads):
            raise ValueError(
                f"index {index} out of range for payload set '{payload_set.id}' "
                f"({len(payload_set.payloads)} payloads)"
            )
        return payload_set.payloads[index]
