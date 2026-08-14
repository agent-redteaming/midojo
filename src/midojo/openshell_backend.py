"""OpenShell environment backend.

A container backend that provisions a sandboxed shell environment on NVIDIA
OpenShell (https://github.com/NVIDIA/OpenShell). Unlike the dict backend — whose
"environment" is an in-memory model — OpenShell's environment is a real Linux
sandbox: the agent runs *inside* it, governed by a policy, and the kernel audits
everything it does as OCSF events.

Two grading channels:
  * **workdir diff** — seeded ``/sandbox/workdir`` files before vs. after the session —
    is the pre/post environment (graded by workdir env predicates).
  * **OCSF events** — kernel-audited network/process/finding events — stored on the
    environment as typed fields (``network_calls_allowed``, ``processes_launched``, etc.)
    for predicate grading via the ``openshell`` predicates in
    :mod:`midojo.verifiers.openshell`.

The seed directory (``/sandbox/workdir``) is distinct from an OpenShell
*workspace*: a workspace is a gateway-side named scope that holds sandboxes and
their policies. midojo creates one workspace per orchestrator run and one
sandbox per evaluation inside it; ``workdir`` is a plain directory inside each
sandbox where the suite's files are seeded.

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

# Directory inside the sandbox where the suite's files are seeded and where the
# agent works. Relative paths in the suite's `state` are placed under it.
_WORKDIR = "/sandbox/workdir"

# The gateway's sandbox teardown can take longer than the SDK's 30s default
# per-call gRPC timeout: DeleteSandbox blocks server-side until the sandbox is
# gone, and each wait_deleted poll issues its own GetSandbox call. Use a larger
# per-call timeout so neither aborts early with DEADLINE_EXCEEDED.
_CLIENT_TIMEOUT_SECONDS = 120.0

# Total wall-clock budget for a teardown wait (sandbox delete, or waiting for a
# workspace to drain to empty). Polled in ~1s steps.
_TEARDOWN_BUDGET_SECONDS = 120.0


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

    ``workdir_files`` is populated by ``provision()`` (pre-session, injection
    payloads already substituted). All other fields are populated post-session by
    ``OpenShellBackend.snapshot()``.
    """

    # Pre-session: seeded file contents keyed by path relative to /sandbox/workdir
    workdir_files: dict[str, str] = Field(default_factory=dict)

    # Post-session workdir diff
    files_created: list[str] = Field(default_factory=list)
    files_modified: list[str] = Field(default_factory=list)
    files_deleted: list[str] = Field(default_factory=list)
    workdir_new_file_contents: dict[str, str] = Field(default_factory=dict)

    # Shell commands the agent executed (from PI tool trace — future)
    commands_executed: list[CommandRecord] = Field(default_factory=list)

    # OCSF-derived fields (kernel-verified; also in observations["openshell"])
    network_calls_allowed: list[str] = Field(default_factory=list)  # "host:port"
    network_calls_blocked: list[str] = Field(default_factory=list)
    processes_launched: list[str] = Field(default_factory=list)  # binary names
    security_findings: list[str] = Field(default_factory=list)  # finding titles


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


class OpenShellBackend:
    """Provisions and manages OpenShell sandboxes for a benchmark run.

    Suite YAML::

        environment:
          backend:
            type: openshell
            image: pi              # OpenShell sandbox image
            policy: pi             # built-in name or inline dict; omit for no policy
          state:                   # seeded workdir files (probe placeholders allowed)
            customer_report.txt: "Q4 report ... {injection_task_0:main}"

    Lifecycle (driven by the orchestrator):
      1. ``configure(cluster=..., control_url=...)`` — inject deployment config (once)
      2. ``start_run(run_id)`` — open the run's OpenShell workspace + client (once)
      3. ``provision(injections)`` — render workdir files (pure, no sandbox needed)
      4. ``setup(pre_env)`` — create sandbox, seed workdir, start timer (per evaluation)
      5. agent executes (via ``exec_agent``)
      6. ``snapshot()`` — workdir diff + OCSF events → full ``OpenShellEnvironment``
      7. ``teardown()`` — delete the sandbox (per evaluation)
      8. ``end_run()`` — delete the run's workspace, close the client (once)
    """

    def __init__(
        self,
        suite_name: str,
        *,
        image: str | None,
        policy: dict | None = None,
        providers: list[str] | None = None,
        env_vars: dict[str, str] | None = None,
        agent_command: list[str] | None = None,
        workdir_files: dict[str, str] | None = None,
    ) -> None:
        if not image:
            raise ValueError("openshell backend requires an 'image' field under 'environment.backend'")
        self._suite_name = suite_name
        self._image: str = image
        self._policy_spec: dict | None = policy
        # OpenShell provider names to inject into the sandbox as credentials.
        # These must be pre-registered with `openshell provider create`.
        # midojo does not manage the credentials — it only tells the gateway
        # which registered providers to activate for this sandbox. The gateway's
        # supervisor injects them as environment variables into the agent process.
        self._providers: list[str] = providers or []
        # Extra environment variables injected into the sandbox at creation.
        # Use this to configure inference endpoints (e.g. OPENAI_BASE_URL for
        # a local model server) without needing a registered provider.
        self._env_vars: dict[str, str] = env_vars or {}
        # Command used to invoke the agent inside the sandbox.
        # Analogous to --agent-uri for other protocols: this is how midojo calls
        # the user's agent, expressed as a command inside the sandbox image.
        self._agent_command: list[str] | None = agent_command
        # Seed-file templates from the suite's `state` (probe placeholders intact).
        self._workdir_files: dict[str, str] = workdir_files or {}

        # Deployment config — set by configure() before start_run()
        self._cluster: str = ""
        self._control_url: str = ""

        # Run-level state — set by start_run(), cleared by end_run()
        self._client: Any = None
        self._pb2: Any = None  # openshell_pb2, stored at start_run() to avoid repeated lazy imports
        # OpenShell workspace resource: a gateway-side named scope that holds the
        # run's sandboxes and their policies. One per orchestrator run; every
        # sandbox is created inside it. Distinct from ``_workdir_files`` (the
        # seed-file contents) and ``/sandbox/workdir`` (a directory in the sandbox).
        self._workspace_client: Any = None
        self._workspace_name: str = ""

        # Per-evaluation sandbox state — set by setup(), cleared by teardown()
        self._ref: Any = None
        self._start_ms: int = 0
        self._cached_ocsf: OCSFEvents | None = None
        self._seeded_workdir: dict[str, str] = {}  # rendered file contents (pre_env.workdir_files)

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

    def configure(self, *, cluster: str, control_url: str = "") -> None:
        """Inject deployment config. Must be called before ``start_run()``.

        ``cluster`` names an OpenShell gateway registered with the CLI. The
        gateway's gRPC endpoint and mTLS bundle are read from
        ``~/.config/openshell`` at ``start_run()``.
        """
        self._cluster = cluster
        self._control_url = control_url

    # --- EnvironmentBackend protocol ---

    @property
    def environment_type(self) -> type[Environment]:
        return OpenShellEnvironment

    def provision(self, injections: dict[str, str]) -> Environment:
        """Render seeded workdir files with active injections substituted.

        Pure — no sandbox connection needed. Suites load without a gateway.
        """
        files = {path: substitute_probes(template, injections) for path, template in self._workdir_files.items()}
        return OpenShellEnvironment(workdir_files=files)

    # --- Run-level lifecycle ---

    def start_run(self, run_id: str) -> None:
        """Open the run's OpenShell workspace and gRPC client.

        Called once per orchestrator run, before the first ``setup()``. Connects
        via ``SandboxClient.from_active_cluster(cluster=...)``, which reads the
        gateway's gRPC endpoint and mTLS bundle from ``~/.config/openshell/``
        (written by the CLI). The workspace is named after ``run_id`` so it maps
        back to the run in the orchestrator output and on the gateway.
        """
        from openshell import SandboxClient, WorkspaceClient  # pyright: ignore[reportMissingImports]
        from openshell._proto import openshell_pb2  # pyright: ignore[reportMissingImports]

        self._pb2 = openshell_pb2
        self._client = SandboxClient.from_active_cluster(cluster=self._cluster, timeout=_CLIENT_TIMEOUT_SECONDS)
        self._workspace_client = WorkspaceClient.from_sandbox_client(self._client)
        self._workspace_name = f"midojo-run-{run_id}"
        self._workspace_client.create(self._workspace_name)

    # --- Per-evaluation sandbox lifecycle ---

    def setup(self, pre_env: OpenShellEnvironment) -> None:  # type: ignore[override]
        """Create the sandbox in the run's workspace, seed the workdir, mark a baseline.

        Requires ``start_run()`` to have opened the client and workspace.
        """
        self._cached_ocsf = None
        self._seeded_workdir = dict(pre_env.workdir_files)

        env = {**self._env_vars}
        if self._control_url:
            env["MIDOJO_URL"] = self._control_url
        spec = self._pb2.SandboxSpec(
            template=self._pb2.SandboxTemplate(image=_resolve_image(self._image)),
            environment=env,
            providers=self._providers,
        )
        _resolve_policy(self._policy_spec, spec)

        self._ref = self._client.create(workspace=self._workspace_name, spec=spec)
        self._client.wait_ready(self._ref.name, workspace=self._workspace_name, timeout_seconds=120.0)

        # Seed workdir files.
        # Paths starting with "/" are seeded at the absolute path (e.g. config
        # files outside the workdir). All other paths are relative to
        # /sandbox/workdir/ (the agent's working directory).
        self._client.exec(self._ref.id, ["mkdir", "-p", _WORKDIR])
        for path, content in pre_env.workdir_files.items():
            if path.startswith("/"):
                dest = path
            else:
                dest = f"{_WORKDIR}/{path}"
            parent = dest.rsplit("/", 1)[0]
            self._client.exec(self._ref.id, ["mkdir", "-p", parent])
            self._client.exec(self._ref.id, ["tee", dest], stdin=content.encode())

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
                    workspace=self._workspace_name,
                    since_ms=self._start_ms,
                    sources=["sandbox"],
                ),
                timeout=10.0,
            )
            messages = [log_line.message for log_line in logs_resp.logs if log_line.level.upper() == "OCSF"]
        except Exception as exc:
            import logging

            logging.getLogger(__name__).warning(
                "OCSF log fetch failed — security predicates will degrade to False: %s", exc
            )

        self._cached_ocsf = parse_ocsf_lines(messages)
        return self._cached_ocsf

    def snapshot(self) -> OpenShellEnvironment:  # type: ignore[override]
        """Compute workdir diff and OCSF events, returning a fully-populated env."""
        seeded = {f"{_WORKDIR}/{p}" for p in self._seeded_workdir}

        diff_result = self._client.exec(
            self._ref.id,
            ["find", _WORKDIR, "-type", "f", "-newer", "/tmp/.midojo_baseline"],
        )
        all_result = self._client.exec(self._ref.id, ["find", _WORKDIR, "-type", "f"])

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
            workdir_files=self._seeded_workdir,
            files_created=files_created,
            files_modified=files_modified,
            files_deleted=files_deleted,
            workdir_new_file_contents=new_file_contents,
            network_calls_allowed=ocsf.network_allowed_endpoints,
            network_calls_blocked=ocsf.network_blocked_endpoints,
            processes_launched=[p.binary for p in ocsf.processes_launched],
            security_findings=[f.title for f in ocsf.findings],
        )

    def teardown(self) -> None:
        """Delete the evaluation's sandbox. The workspace is deleted in ``end_run()``."""
        if self._ref is not None and self._client is not None:
            try:
                self._client.delete(self._ref.name, workspace=self._workspace_name)
                self._client.wait_deleted(
                    self._ref.name, workspace=self._workspace_name, timeout_seconds=_TEARDOWN_BUDGET_SECONDS
                )
            except Exception as exc:
                import logging

                logging.getLogger(__name__).warning("Sandbox teardown failed: %s", exc)
        self._ref = None
        self._start_ms = 0
        self._cached_ocsf = None
        self._seeded_workdir = {}

    def end_run(self) -> None:
        """Wait for the run's workspace to drain, delete it, and close the client.

        Called once after the last ``teardown()``. Each evaluation's teardown
        deletes its sandbox, but the gateway removes a sandbox (and its policy)
        asynchronously, so the workspace can still report resources for a short
        window. Deleting a non-empty workspace is rejected (FAILED_PRECONDITION)
        and there is no cascade delete, so poll until the workspace is empty
        before deleting it.
        """
        import logging

        log = logging.getLogger(__name__)
        if self._client is not None and self._workspace_name:
            self._wait_workspace_empty()
        if self._workspace_client is not None and self._workspace_name:
            try:
                self._workspace_client.delete(self._workspace_name)
            except Exception as exc:
                log.warning("Workspace teardown failed: %s", exc)
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None
        self._pb2 = None
        self._workspace_client = None
        self._workspace_name = ""

    def _wait_workspace_empty(self) -> None:
        """Poll until the run's workspace has no sandboxes, or the budget elapses.

        ``list_ids`` may itself raise a transient RPC error mid-drain; that is
        tolerated and treated as "not yet empty". After ``_TEARDOWN_BUDGET_SECONDS``
        the loop gives up and ``end_run`` attempts the delete regardless.
        """
        import logging

        log = logging.getLogger(__name__)
        deadline = time.time() + _TEARDOWN_BUDGET_SECONDS
        while time.time() < deadline:
            try:
                remaining = self._client.list_ids(workspace=self._workspace_name)
            except Exception as exc:
                log.debug("workspace drain poll failed (treating as non-empty): %s", exc)
                remaining = ["<unknown>"]
            if not remaining:
                return
            time.sleep(1)
        log.warning(
            "workspace %s still not empty after %.0fs; attempting delete anyway",
            self._workspace_name,
            _TEARDOWN_BUDGET_SECONDS,
        )
