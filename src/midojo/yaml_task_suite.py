from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from midojo.app.models import ToolInfoResponse
from midojo.attacks import resolve_source, wrap_payload
from midojo.backends import EnvironmentBackend, build_backend
from midojo.probes import substitute_probes
from midojo.types import Environment, FunctionCallRecord, MemoryEntry, OutputHook, PromptModification, ToolModification
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
        self._prompt_injections: dict[str, PromptModification] = {}
        self._tool_modifications: dict[str, ToolModification] = {}
        self._output_hooks: dict[str, OutputHook] = {}
        self._memory_entries: dict[str, MemoryEntry] = {}
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

    def get_prompt_injections_for_task(self, task_id: str) -> list[PromptModification]:
        """Return prompt-channel injections for the given injection task."""
        prefix = f"{task_id}:"
        return [mod for key, mod in self._prompt_injections.items() if key.startswith(prefix)]

    def get_tool_modifications_for_task(self, task_id: str) -> list[ToolModification]:
        """Return tool-description-channel modifications for the given injection task."""
        prefix = f"{task_id}:"
        return [mod for key, mod in self._tool_modifications.items() if key.startswith(prefix)]

    def get_output_hooks_for_task(self, task_id: str) -> list[OutputHook]:
        """Return tool-output-channel hooks for the given injection task."""
        prefix = f"{task_id}:"
        return [hook for key, hook in self._output_hooks.items() if key.startswith(prefix)]

    def get_memory_entries_for_task(self, task_id: str) -> list[MemoryEntry]:
        """Return memory-channel entries for the given injection task."""
        prefix = f"{task_id}:"
        return [entry for key, entry in self._memory_entries.items() if key.startswith(prefix)]

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

    def get_tool_definitions(self) -> list[ToolInfoResponse]:
        return [
            ToolInfoResponse(
                name=t["name"],
                description=t.get("description", ""),
                parameters=t.get("parameters", {}),
            )
            for t in self._suite_raw.get("tools", [])
        ]

    def get_tool_names(self) -> list[str]:
        return [t["name"] for t in self._suite_raw.get("tools", [])]

    def _register_tasks(self) -> None:
        for task_raw in self._suite_raw.get("user_tasks", []):
            task_id = task_raw["id"]
            check = parse_check(task_raw["utility"])
            self.user_tasks[task_id] = UserTask(id=task_id, prompt=task_raw["prompt"], check=check)

        for task_raw in self._suite_raw.get("injection_tasks", []):
            task_id = task_raw["id"]
            check = parse_check(task_raw["security"])
            probes = self._parse_probes(task_id, task_raw.get("probes", {}))
            self.injection_tasks[task_id] = InjectionTask(
                id=task_id,
                description=task_raw["description"],
                check=check,
                probes=probes,
                attack_spec=task_raw.get("attack"),
            )

    def _parse_probes(self, task_id: str, raw: dict[str, dict]) -> dict[str, str]:
        probes: dict[str, str] = {}
        for probe_id, probe_raw in raw.items():
            try:
                payload = self._resolve_probe_payload(probe_raw)
                attack_type = probe_raw.get("attack_type", "verbatim")
                if isinstance(attack_type, list):
                    wrapped = payload
                    for wrapper_id in attack_type:
                        wrapped = wrap_payload(wrapped, wrapper_id)
                else:
                    wrapped = wrap_payload(payload, attack_type)

                channel = probe_raw.get("channel", "environment_state")
                if channel == "user_prompt":
                    mode = probe_raw.get("prompt_mode", "append")
                    self._prompt_injections[f"{task_id}:{probe_id}"] = PromptModification(
                        mode=mode,
                        content=wrapped,
                    )
                elif channel == "tool_description":
                    target_tool = probe_raw.get("target_tool")
                    if not target_tool:
                        raise ValueError("channel 'tool_description' requires 'target_tool'")
                    self._tool_modifications[f"{task_id}:{probe_id}"] = ToolModification(
                        tool_name=target_tool,
                        append_to_description=f"\n{wrapped}",
                    )
                elif channel == "tool_output":
                    target_tool = probe_raw.get("target_tool")
                    if not target_tool:
                        raise ValueError("channel 'tool_output' requires 'target_tool'")
                    self._output_hooks[f"{task_id}:{probe_id}"] = OutputHook(
                        tool_name=target_tool,
                        inject_in_response=wrapped,
                        inject_mode=probe_raw.get("inject_mode", "append"),
                    )
                elif channel == "memory":
                    self._memory_entries[f"{task_id}:{probe_id}"] = MemoryEntry(
                        content=wrapped,
                        source=probe_raw.get("memory_source", "system"),
                    )
                else:
                    probes[probe_id] = wrapped
            except ValueError as e:
                raise ValueError(f"Probe '{task_id}:{probe_id}': {e}") from None
        return probes

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
