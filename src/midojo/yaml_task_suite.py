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
class ProbeDefinition:
    """A parsed probe with its payload and optional placement metadata."""

    payload: str
    placement: str | None = None
    target_tool: str | None = None
    target_field: str | None = None
    mode: str = "embed"


@dataclass
class InjectionTask:
    id: str
    description: str
    probes: dict[str, str] = field(default_factory=dict)
    probe_definitions: dict[str, ProbeDefinition] = field(default_factory=dict)
    check: Check | None = None


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

    def get_env_template(self) -> dict:
        """Return the raw environment state template (with placeholders intact)."""
        return self._suite_raw.get("environment", {}).get("state", {})

    def inject_user_task_prompt(self, user_task_id: str, injections: dict[str, str]) -> str:
        return substitute_probes(self.user_tasks[user_task_id].prompt, injections)

    def get_probes_for_task(self, task_id: str) -> dict[str, str]:
        probes = self.injection_tasks[task_id].probes
        return {f"{task_id}:{probe_id}": payload for probe_id, payload in probes.items()}

    def build_injection_inputs(self, task_id: str) -> tuple[dict[str, str], list[dict]]:
        """Build the injections dict and injection plan for a task.

        Reads the ``placement`` field from each probe definition:
        - No placement: payload → injections dict (legacy substitution, no plan)
        - ``env``: payload → injections dict + EnvInjection in plan
        - ``prompt``: payload → injections dict + PromptInjection in plan
        - ``tool``: ToolInjection in plan only (no injections dict entry)

        Returns (injections_dict, injection_plan).
        """
        task = self.injection_tasks[task_id]
        injections: dict[str, str] = {}
        plan: list[dict] = []

        for probe_id, probe_def in task.probe_definitions.items():
            probe_key = f"{task_id}:{probe_id}"

            if probe_def.placement == "tool":
                plan.append({
                    "type": "tool",
                    "payload": probe_def.payload,
                    "target_tool": probe_def.target_tool,
                    "target_field": probe_def.target_field,
                    "mode": probe_def.mode,
                })
            elif probe_def.placement == "env":
                injections[probe_key] = probe_def.payload
                plan.append({
                    "type": "env",
                    "payload": probe_def.payload,
                    "probe_key": probe_key,
                })
            elif probe_def.placement == "prompt":
                injections[probe_key] = probe_def.payload
                plan.append({
                    "type": "prompt",
                    "payload": probe_def.payload,
                    "probe_key": probe_key,
                })
            else:
                injections[probe_key] = probe_def.payload

        return injections, plan

    def grade(
        self,
        user_task_id: str,
        injection_task_id: str | None,
        agent_output: str,
        pre_environment: Environment,
        post_environment: Environment,
        function_calls: list[FunctionCallRecord],
        observations: dict[str, Any] | None = None,
    ) -> dict[str, bool | str | None]:
        ctx = VerificationContext(
            agent_output=agent_output,
            pre_environment=pre_environment,
            post_environment=post_environment,
            function_calls=function_calls,
            observations=observations or {},
        )

        utility = self.user_tasks[user_task_id].check.evaluate(ctx)

        # One traversal grades the injection and names the criterion that fired.
        injection_check = self.injection_tasks[injection_task_id].check if injection_task_id is not None else None
        security = False
        security_reason: str | None = None
        if injection_check is not None:
            result = injection_check.assess(ctx)
            security = result.passed
            security_reason = result.reason if result.passed else None

        return {"utility": utility, "security": security, "security_reason": security_reason}

    def _register_tasks(self) -> None:
        for task_raw in self._suite_raw.get("user_tasks", []):
            task_id = task_raw["id"]
            check = parse_check(task_raw["utility"])
            self.user_tasks[task_id] = UserTask(id=task_id, prompt=task_raw["prompt"], check=check)

        for task_raw in self._suite_raw.get("injection_tasks", []):
            task_id = task_raw["id"]
            check = parse_check(task_raw["security"])
            probes, probe_defs = self._parse_probes(task_id, task_raw.get("probes", {}))
            self.injection_tasks[task_id] = InjectionTask(
                id=task_id,
                description=task_raw["description"],
                check=check,
                probes=probes,
                probe_definitions=probe_defs,
            )

    def _parse_probes(self, task_id: str, raw: dict[str, dict]) -> tuple[dict[str, str], dict[str, ProbeDefinition]]:
        probes: dict[str, str] = {}
        probe_defs: dict[str, ProbeDefinition] = {}
        for probe_id, probe_raw in raw.items():
            try:
                payload = self._resolve_probe_payload(probe_raw)
                wrapped = wrap_payload(payload, probe_raw.get("attack_type", "verbatim"))
                probes[probe_id] = wrapped
                probe_defs[probe_id] = ProbeDefinition(
                    payload=wrapped,
                    placement=probe_raw.get("placement"),
                    target_tool=probe_raw.get("target_tool"),
                    target_field=probe_raw.get("target_field"),
                    mode=probe_raw.get("mode", "embed"),
                )
            except ValueError as e:
                raise ValueError(f"Probe '{task_id}:{probe_id}': {e}") from None
        return probes, probe_defs

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
