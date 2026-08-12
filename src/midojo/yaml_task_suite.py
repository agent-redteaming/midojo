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
class ProbePlacement:
    """Where a probe placeholder was found in the suite."""

    probe_key: str
    field_path: str
    surrounding_text: str
    in_user_prompt: bool = False


@dataclass
class InjectionTask:
    id: str
    description: str
    probes: dict[str, str] = field(default_factory=dict)
    check: Check | None = None
    strategy_config: dict[str, Any] | None = None
    probe_placements: list[ProbePlacement] = field(default_factory=list)


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
            probes_raw = task_raw.get("probes", {})
            strategy_config = self._extract_strategy_config(probes_raw)
            probes = self._parse_probes(task_id, probes_raw)
            placements = self._detect_probe_placements(task_id, probes_raw)
            self.injection_tasks[task_id] = InjectionTask(
                id=task_id,
                description=task_raw["description"],
                check=check,
                probes=probes,
                strategy_config=strategy_config,
                probe_placements=placements,
            )

    def _parse_probes(self, task_id: str, raw: dict[str, dict]) -> dict[str, str]:
        probes: dict[str, str] = {}
        for probe_id, probe_raw in raw.items():
            try:
                payload = self._resolve_probe_payload(probe_raw)
                wrapper_id = probe_raw.get("wrapper") or probe_raw.get("attack_type", "verbatim")
                probes[probe_id] = wrap_payload(payload, wrapper_id)
            except ValueError as e:
                raise ValueError(f"Probe '{task_id}:{probe_id}': {e}") from None
        return probes

    @staticmethod
    def _extract_strategy_config(probes_raw: dict[str, dict]) -> dict[str, Any] | None:
        """Extract strategy config from the first probe that declares one.

        Convention: probes WITHOUT a strategy block are injection probes
        (placed in env data). Probes WITH a strategy block drive the attack.
        """
        for probe_raw in probes_raw.values():
            strategy = probe_raw.get("strategy")
            if strategy:
                return dict(strategy)
        return None

    @staticmethod
    def get_strategy_probe_id(probes_raw: dict[str, dict]) -> str | None:
        """Return the probe ID that carries the strategy config, if any."""
        for probe_id, probe_raw in probes_raw.items():
            if probe_raw.get("strategy"):
                return probe_id
        return None

    def _detect_probe_placements(self, task_id: str, probes_raw: dict[str, dict]) -> list[ProbePlacement]:
        """Walk the environment and user prompts to find where each probe placeholder appears."""
        placements: list[ProbePlacement] = []
        probe_ids = list(probes_raw.keys())

        env_state = self._suite_raw.get("environment", {}).get("state", {})
        for probe_id in probe_ids:
            key = f"{task_id}:{probe_id}"
            placeholder = "{" + key + "}"
            self._find_in_structure(env_state, placeholder, key, "", placements)

        for ut in self._suite_raw.get("user_tasks", []):
            prompt = ut.get("prompt", "")
            for probe_id in probe_ids:
                key = f"{task_id}:{probe_id}"
                placeholder = "{" + key + "}"
                if placeholder in prompt:
                    placements.append(ProbePlacement(
                        probe_key=key,
                        field_path=f"user_tasks.{ut['id']}.prompt",
                        surrounding_text=prompt,
                        in_user_prompt=True,
                    ))

        return placements

    @staticmethod
    def _find_in_structure(
        obj: Any, placeholder: str, probe_key: str, path: str, results: list[ProbePlacement],
    ) -> None:
        """Recursively search a nested dict/list for a probe placeholder string."""
        if isinstance(obj, str) and placeholder in obj:
            results.append(ProbePlacement(
                probe_key=probe_key,
                field_path=path,
                surrounding_text=obj,
                in_user_prompt=False,
            ))
        elif isinstance(obj, dict):
            for k, v in obj.items():
                child_path = f"{path}.{k}" if path else k
                YAMLTaskSuite._find_in_structure(v, placeholder, probe_key, child_path, results)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                child_path = f"{path}[{i}]"
                YAMLTaskSuite._find_in_structure(v, placeholder, probe_key, child_path, results)

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
