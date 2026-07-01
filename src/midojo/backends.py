"""Environment backends — the first of the engine's two observability axes.

A backend defines *what the agent operates on*. Today there is one: a state
dict declared in ``suite.yaml`` and inferred into a Pydantic model
(:class:`DictEnvironmentBackend`). The protocol is the seam where richer
backends plug in later — a sandboxed container (e.g. NVIDIA OpenShell), or an
eventually a full cluster resource — without the suite, control plane, or
grading code needing to know which backend is in play.

A backend is responsible for:
  * the *type* of the observable state (so the control plane can validate
    env reads/writes against a concrete schema), and
  * *provisioning* a fresh instance of that state for an evaluation, with the
    active injection payloads templated in.

Future protocol extensions (Phase 2+): ``snapshot()`` for pre/post capture,
``observations()`` to surface event streams (process/network/k8s) that
verification providers consume, and ``teardown()`` for lifecycle cleanup.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable

from midojo.env_inference import infer_environment_type
from midojo.probes import substitute_probes
from midojo.types import Environment


@runtime_checkable
class EnvironmentBackend(Protocol):
    """Provisions and types the observable state an agent operates on."""

    @property
    def environment_type(self) -> type[Environment]:
        """Concrete Pydantic type of the observable state."""
        ...

    def provision(self, injections: dict[str, str]) -> Environment:
        """Build a fresh environment instance with ``injections`` templated in."""
        ...


class DictEnvironmentBackend:
    """Default backend: a declared state dict from ``suite.yaml``.

    The dict is inferred into a Pydantic model once at load time; each
    :meth:`provision` re-renders the declared state (substituting the active
    probe payloads) and validates it into a fresh instance.
    """

    def __init__(
        self,
        suite_name: str,
        env_raw: dict,
        environment_type: type[Environment] | None = None,
    ) -> None:
        self._env_raw = env_raw
        self._environment_type = environment_type or infer_environment_type(suite_name, env_raw)

    @property
    def environment_type(self) -> type[Environment]:
        return self._environment_type

    def provision(self, injections: dict[str, str]) -> Environment:
        state = _substitute_in_structure(self._env_raw, injections)
        return self._environment_type.model_validate(state)


def _substitute_in_structure(node: object, injections: dict[str, str]) -> object:
    """Substitute probe payloads into every string value of a parsed structure.

    Substituting structurally (rather than into serialized YAML text) keeps
    payload content — quotes, colons, newlines — from corrupting the document.
    """
    if isinstance(node, str):
        return substitute_probes(node, injections)
    if isinstance(node, dict):
        return {key: _substitute_in_structure(value, injections) for key, value in node.items()}
    if isinstance(node, list):
        return [_substitute_in_structure(item, injections) for item in node]
    return node


# --- Backend registry + dispatch ---
#
# Mirrors the verifier registry. A suite's ``environment.backend`` selects the
# backend; it is either a bare name (``backend: dict``) or an object carrying the
# backend's infra config (``backend: {type: openshell, image: pi, ...}``). The
# declared environment state stays a sibling key (``state``), parallel across
# backends. A factory receives the suite name, the full ``environment`` block,
# and the parsed backend infra config.

BackendFactory = Callable[[str, dict, dict], EnvironmentBackend]

_BACKENDS: dict[str, BackendFactory] = {}


def register_backend(name: str, factory: BackendFactory) -> None:
    if name in _BACKENDS:
        raise ValueError(f"Environment backend {name!r} is already registered")
    _BACKENDS[name] = factory


def _parse_backend(env_config: dict) -> tuple[str, dict]:
    """Resolve ``environment.backend`` into a (name, infra_config) pair."""
    spec = env_config.get("backend", "dict")
    if isinstance(spec, str):
        return spec, {}
    if isinstance(spec, dict):
        if "type" not in spec:
            raise ValueError("object form of 'backend' requires a 'type' field")
        return spec["type"], {k: v for k, v in spec.items() if k != "type"}
    raise ValueError(f"'backend' must be a name or an object with a 'type', got: {spec!r}")


def build_backend(suite_name: str, env_config: dict) -> EnvironmentBackend:
    """Construct the backend declared by ``env_config['backend']`` (default: dict)."""
    name, backend_config = _parse_backend(env_config)
    factory = _BACKENDS.get(name)
    if factory is None:
        raise ValueError(f"Unknown environment backend: {name!r}. Registered: {sorted(_BACKENDS)}")
    return factory(suite_name, env_config, backend_config)


def _build_dict_backend(suite_name: str, env_config: dict, backend_config: dict) -> EnvironmentBackend:
    if "state" not in env_config:
        raise ValueError("dict environment backend requires a 'state' field under 'environment'")
    return DictEnvironmentBackend(suite_name, env_config["state"])


def _build_openshell_backend(suite_name: str, env_config: dict, backend_config: dict) -> EnvironmentBackend:
    # Imported lazily so the openshell SDK is only needed when the backend runs.
    from midojo.openshell_backend import OpenShellBackend

    return OpenShellBackend(
        suite_name,
        image=backend_config.get("image"),
        policy=backend_config.get("policy"),
        agent_command=backend_config.get("agent_command"),
        workspace=env_config.get("state", {}),
    )


register_backend("dict", _build_dict_backend)
register_backend("openshell", _build_openshell_backend)
