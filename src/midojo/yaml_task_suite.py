from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from midojo.attacks import resolve_source, wrap_payload
from midojo.backends import EnvironmentBackend, build_backend
from midojo.probes import substitute_probes
from midojo.types import Environment, FunctionCallRecord
from midojo.verifier import Check, VerificationContext, parse_check

# ``${env.VAR}`` references (OGX-style), expanded from the process environment in
# the backend config only (see ``_expand_env_vars``). The ``env.`` namespace
# keeps these from colliding with the bare ``${...}`` shell tokens that appear in
# attack payloads, and mirrors the syntax OGX uses in its distribution configs.
_ENV_VAR_RE = re.compile(r"\$\{env\.([A-Za-z_][A-Za-z0-9_]*)(?:(:=|:\+)([^}]*))?\}")


def _expand_env_vars(value: Any) -> Any:
    """Recursively expand ``${env.VAR}`` references in string leaves.

    Deployment-specific settings (notably the sandbox network policy's control
    plane host, which differs between a local gateway and a cluster) can be
    parameterised from the environment instead of hard-coded. The syntax mirrors
    OGX's distribution configs, with an added bare (required) form:

    - ``${env.VAR:=default}`` — ``default`` when VAR is unset *or empty*
    - ``${env.VAR:+value}``   — ``value`` only when VAR is set and non-empty, else ""
    - ``${env.VAR}``          — required: raises when VAR is unset or empty

    This is applied to the ``environment.backend`` subtree only — never to attack
    payloads, which legitimately contain bare ``${...}`` (e.g. ``${IFS}`` shell
    obfuscation). The ``env.`` namespace means even a stray ``${env.X}`` in a
    payload would be out of scope here; nothing else looks like these tokens.
    """
    if isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env_vars(v) for v in value]
    if isinstance(value, str):
        return _ENV_VAR_RE.sub(_replace_env_match, value)
    return value


def _replace_env_match(match: re.Match[str]) -> str:
    name, op, arg = match.group(1), match.group(2), match.group(3)
    value = os.environ.get(name)
    if op == ":=":  # ${env.VAR:=default}
        return value or arg
    if op == ":+":  # ${env.VAR:+value}
        return arg if value else ""
    if value:  # bare ${env.VAR} — required
        return value
    raise ValueError(
        f"environment variable '{name}' referenced in suite backend config is unset "
        f"or empty (use '${{env.{name}:=default}}' to provide a default)"
    )


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
        environment = self._suite_raw.get("environment")
        if isinstance(environment, dict) and "backend" in environment:
            environment["backend"] = _expand_env_vars(environment["backend"])
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
            probes = self._parse_probes(task_id, task_raw.get("probes", {}))
            self.injection_tasks[task_id] = InjectionTask(
                id=task_id,
                description=task_raw["description"],
                check=check,
                probes=probes,
            )

    def _parse_probes(self, task_id: str, raw: dict[str, dict]) -> dict[str, str]:
        probes: dict[str, str] = {}
        for probe_id, probe_raw in raw.items():
            try:
                payload = self._resolve_probe_payload(probe_raw)
                probes[probe_id] = wrap_payload(payload, probe_raw.get("attack_type", "verbatim"))
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
                f"index {index} out of range for payload set '{payload_set.id}' ({len(payload_set.payloads)} payloads)"
            )
        return payload_set.payloads[index]
