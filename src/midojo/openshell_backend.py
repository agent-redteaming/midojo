"""OpenShell environment backend.

A container backend that provisions a sandboxed shell environment on NVIDIA
OpenShell (https://github.com/NVIDIA/OpenShell). Unlike the dict backend — whose
"environment" is an in-memory model — OpenShell's environment is a real Linux
sandbox: the agent runs *inside* it, governed by a policy, and the kernel audits
everything it does as OCSF events.

Two grading channels:
  * **workspace diff** — seeded ``/sandbox/workspace`` files before vs. after the session —
    is the pre/post environment (graded by workspace env predicates).
  * **OCSF events** — kernel-audited network/process/finding events — stored on the
    environment as typed fields (``network_calls_allowed``, ``processes_launched``, etc.)
    for predicate grading via the ``openshell`` predicates in
    :mod:`midojo.verifiers.openshell`.

Policy:
  Suite YAML can name a built-in policy (``policy: pi``) or supply an inline dict
  matching the proto JSON field names. ``_BUILTIN_POLICIES`` maps names to camelCase
  proto-JSON dicts. ``_resolve_policy`` fills ``SandboxSpec.policy`` in-place via
  ``ParseDict`` — no direct import of ``SandboxPolicy`` needed.

OCSF caching:
  ``_fetch_ocsf()`` fetches and caches the ``GetSandboxLogs`` response; subsequent
  calls within the same evaluation return the cache. The cache is cleared at the
  start of each ``setup()`` call.
"""

from __future__ import annotations

import time
from typing import Any

from pydantic import BaseModel, Field

from midojo.openshell_logs import OCSFEvents, parse_ocsf_lines
from midojo.probes import substitute_probes
from midojo.types import Environment


# ---------------------------------------------------------------------------
_COMMUNITY_REGISTRY = "ghcr.io/nvidia/openshell-community/sandboxes"


def _resolve_image(image: str) -> str:
    """Expand a community sandbox name to its full registry reference.

    The OpenShell CLI resolves bare names (e.g. ``pi``) to
    ``ghcr.io/nvidia/openshell-community/sandboxes/<name>:latest``.
    The SDK does not, so we replicate that logic here.  Names that
    already contain a ``/`` or ``:`` are passed through unchanged.
    Override the registry prefix with ``OPENSHELL_COMMUNITY_REGISTRY``.
    """
    import os
    if "/" in image or ":" in image:
        return image
    registry = os.environ.get("OPENSHELL_COMMUNITY_REGISTRY", _COMMUNITY_REGISTRY)
    return f"{registry}/{image}:latest"


def _resolve_policy(spec: dict | None, sandbox_spec: Any) -> None:
    """Populate ``sandbox_spec.policy`` in-place. ``spec=None`` is a no-op.

    Args:
        spec: ``None`` (no-op — image built-in policy applies) or a camelCase
              proto-JSON dict matching ``SandboxPolicy`` field names.
        sandbox_spec: A ``SandboxSpec`` proto message whose ``.policy`` field will
                      be populated in-place. ``SandboxPolicy`` is accessed via the
                      field directly — no direct import of its type needed.
    """
    if spec is None:
        return
    from google.protobuf.json_format import ParseDict  # protobuf is a required dep

    ParseDict(spec, sandbox_spec.policy)


# ---------------------------------------------------------------------------
# Environment model
# ---------------------------------------------------------------------------


class CommandRecord(BaseModel):
    """A shell command executed by the agent inside the sandbox."""

    command: str
    exit_code: int
    stdout: str
    stderr: str = ""


class OpenShellEnvironment(Environment):
    """Observable state of an OpenShell sandbox.

    ``workspace_files`` is populated by ``provision()`` (pre-session, injection
    payloads already substituted). All other fields are populated post-session by
    ``OpenShellBackend.snapshot()``.
    """

    # Pre-session: seeded file contents keyed by path relative to /sandbox/workspace
    workspace_files: dict[str, str] = Field(default_factory=dict)

    # Post-session workspace diff
    files_created: list[str] = Field(default_factory=list)
    files_modified: list[str] = Field(default_factory=list)
    files_deleted: list[str] = Field(default_factory=list)
    workspace_new_file_contents: dict[str, str] = Field(default_factory=dict)

    # Shell commands the agent executed (from PI tool trace — future)
    commands_executed: list[CommandRecord] = Field(default_factory=list)

    # OCSF-derived fields (kernel-verified; also in observations["openshell"])
    network_calls_allowed: list[str] = Field(default_factory=list)   # "host:port"
    network_calls_blocked: list[str] = Field(default_factory=list)
    processes_launched: list[str] = Field(default_factory=list)       # binary names
    security_findings: list[str] = Field(default_factory=list)        # finding titles


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


class OpenShellBackend:
    """Provisions and manages an OpenShell sandbox for a benchmark evaluation.

    Suite YAML::

        environment:
          backend:
            type: openshell
            image: pi              # OpenShell sandbox image
            policy: pi             # built-in name or inline dict; omit for no policy
          state:                   # seeded workspace files (probe placeholders allowed)
            customer_report.txt: "Q4 report ... {injection_task_0:main}"

    Lifecycle (called by the orchestrator for each evaluation):
      1. ``configure(endpoint=..., control_url=...)`` — inject deployment config
      2. ``provision(injections)`` — render workspace files (pure, no sandbox needed)
      3. ``setup(pre_env)`` — create sandbox, seed workspace, start timer
      4. agent executes (via ``exec_agent``)
      5. ``snapshot()`` — workspace diff + OCSF events → full ``OpenShellEnvironment``
      6. ``teardown()`` — delete sandbox, close client
    """

    def __init__(
        self,
        suite_name: str,
        *,
        image: str | None,
        policy: dict | None = None,
        agent_command: list[str] | None = None,
        workspace: dict[str, str] | None = None,
    ) -> None:
        if not image:
            raise ValueError("openshell backend requires an 'image' field under 'environment.backend'")
        self._suite_name = suite_name
        self._image: str = image
        self._policy_spec: dict | None = policy
        # Command used to invoke the agent inside the sandbox.
        # Analogous to --agent-url for other protocols: this is how midojo calls
        # the user's agent, expressed as a command inside the sandbox image.
        self._agent_command: list[str] | None = agent_command
        self._workspace: dict[str, str] = workspace or {}

        # Deployment config — set by configure() before setup()
        self._endpoint: str = ""
        self._control_url: str = ""

        # Live sandbox state — set by setup(), cleared by teardown()
        self._client: Any = None
        self._ref: Any = None
        self._pb2: Any = None   # openshell_pb2, stored at setup() to avoid repeated lazy imports
        self._start_ms: int = 0
        self._cached_ocsf: OCSFEvents | None = None
        self._seeded_workspace: dict[str, str] = {}  # injected file contents (pre_env.workspace_files)

    # --- Public read-only accessors (avoid direct private attribute access) ---

    @property
    def image(self) -> str:
        return self._image

    @property
    def policy(self) -> dict | None:
        return self._policy_spec

    @property
    def agent_command(self) -> list[str] | None:
        return self._agent_command

    # --- Deployment config ---

    def configure(self, *, endpoint: str, control_url: str = "") -> None:
        """Inject deployment config. Must be called before ``setup()``."""
        self._endpoint = endpoint
        self._control_url = control_url

    # --- EnvironmentBackend protocol ---

    @property
    def environment_type(self) -> type[Environment]:
        return OpenShellEnvironment

    def provision(self, injections: dict[str, str]) -> Environment:
        """Render seeded workspace with active injections substituted.

        Pure — no sandbox connection needed. Suites load without a gateway.
        """
        files = {path: substitute_probes(template, injections) for path, template in self._workspace.items()}
        return OpenShellEnvironment(workspace_files=files)

    # --- Live sandbox lifecycle ---

    def setup(self, pre_env: OpenShellEnvironment) -> None:  # type: ignore[override]
        """Create sandbox, seed workspace files, record baseline timestamp.

        If no endpoint was configured via ``configure()``, uses
        ``SandboxClient.from_active_cluster()`` which reads the mTLS bundle and
        gateway URL from ``~/.config/openshell/`` (set by the CLI or install script).
        """
        from openshell import SandboxClient  # pyright: ignore[reportMissingImports]
        from openshell._proto import openshell_pb2  # pyright: ignore[reportMissingImports]

        self._pb2 = openshell_pb2
        self._cached_ocsf = None
        self._seeded_workspace = dict(pre_env.workspace_files)

        if self._endpoint:
            self._client = SandboxClient(self._endpoint)
        else:
            self._client = SandboxClient.from_active_cluster()

        spec = openshell_pb2.SandboxSpec(
            template=openshell_pb2.SandboxTemplate(image=_resolve_image(self._image)),
            environment={"MIDOJO_URL": self._control_url} if self._control_url else {},
        )
        _resolve_policy(self._policy_spec, spec)

        self._ref = self._client.create(spec=spec)
        self._client.wait_ready(self._ref.name, timeout_seconds=120.0)

        # Seed workspace
        self._client.exec(self._ref.id, ["mkdir", "-p", "/sandbox/workspace"])
        for path, content in pre_env.workspace_files.items():
            self._client.exec(self._ref.id, ["tee", f"/sandbox/workspace/{path}"], stdin=content.encode())

        self._client.exec(self._ref.id, ["touch", "/tmp/.midojo_baseline"])
        self._start_ms = int(time.time() * 1000)

    def exec_agent(self, prompt: str, *, timeout_seconds: float) -> Any:
        """Execute the agent inside the sandbox. Returns an ``ExecResult``.

        Uses ``agent_command`` from the suite YAML if set, otherwise falls back
        to the image's default entrypoint by running the prompt as a positional
        argument. Suite authors should always set ``agent_command`` explicitly.
        """
        cmd = [*self._agent_command, prompt] if self._agent_command else [prompt]
        return self._client.exec(self._ref.id, cmd, timeout_seconds=timeout_seconds)

    def _fetch_ocsf(self) -> OCSFEvents:
        """Fetch OCSF events from the sandbox log stream, with caching.

        Uses ``client._stub.GetSandboxLogs`` directly — the high-level SDK has no
        public wrapper for log retrieval.
        """
        if self._cached_ocsf is not None:
            return self._cached_ocsf

        messages: list[str] = []
        try:
            logs_resp = self._client._stub.GetSandboxLogs(
                self._pb2.GetSandboxLogsRequest(
                    sandbox_id=self._ref.id,
                    since_ms=self._start_ms,
                    sources=["sandbox"],
                ),
                timeout=10.0,
            )
            messages = [
                log_line.message
                for log_line in logs_resp.logs
                if log_line.level.upper() == "OCSF"
            ]
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning(
                "OCSF log fetch failed — security predicates will degrade to False: %s", exc
            )

        self._cached_ocsf = parse_ocsf_lines(messages)
        return self._cached_ocsf

    def snapshot(self) -> OpenShellEnvironment:  # type: ignore[override]
        """Compute workspace diff and OCSF events, returning a fully-populated env."""
        seeded = {f"/sandbox/workspace/{p}" for p in self._seeded_workspace}

        diff_result = self._client.exec(
            self._ref.id,
            ["find", "/sandbox/workspace", "-type", "f", "-newer", "/tmp/.midojo_baseline"],
        )
        all_result = self._client.exec(self._ref.id, ["find", "/sandbox/workspace", "-type", "f"])

        current = {ln.strip() for ln in all_result.stdout.splitlines() if ln.strip()}

        files_created: list[str] = []
        files_modified: list[str] = []
        new_file_contents: dict[str, str] = {}

        for line in diff_result.stdout.splitlines():
            fpath = line.strip()
            if not fpath:
                continue
            if fpath in seeded:
                files_modified.append(fpath)
            else:
                files_created.append(fpath)
                cat = self._client.exec(self._ref.id, ["cat", fpath])
                if cat.exit_code == 0:
                    new_file_contents[fpath] = cat.stdout

        files_deleted = [p for p in seeded if p not in current]

        ocsf = self._fetch_ocsf()

        return OpenShellEnvironment(
            workspace_files=self._seeded_workspace,
            files_created=files_created,
            files_modified=files_modified,
            files_deleted=files_deleted,
            workspace_new_file_contents=new_file_contents,
            network_calls_allowed=ocsf.network_allowed_endpoints,
            network_calls_blocked=ocsf.network_blocked_endpoints,
            processes_launched=[p.binary for p in ocsf.processes_launched],
            security_findings=[f.title for f in ocsf.findings],
        )

    def teardown(self) -> None:
        """Delete the sandbox and close the gRPC client."""
        if self._ref is not None and self._client is not None:
            try:
                self._client.delete(self._ref.name)
                self._client.wait_deleted(self._ref.name, timeout_seconds=30.0)
            except Exception as exc:
                import logging
                logging.getLogger(__name__).warning("Sandbox teardown failed: %s", exc)
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None
        self._ref = None
        self._pb2 = None
        self._start_ms = 0
        self._cached_ocsf = None
        self._seeded_workspace = {}
