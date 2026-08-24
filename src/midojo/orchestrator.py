from __future__ import annotations

import asyncio
import importlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import NamedTuple

import click
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from midojo.agent_client import (
    A2AAgentClient,
    AgentClient,
    OGXResponsesClient,
    OpenAIResponsesAgentClient,
    OpenShellAgentClient,
    PIAgentClient,
    SimpleHTTPAgentClient,
)
from midojo.backends import EnvironmentBackend
from midojo.suites import get_suite, list_suites
from midojo.yaml_task_suite import YAMLTaskSuite

console = Console()


def _resolve_system_message(suite_name: str) -> str:
    module_path = suite_name if "." in suite_name else f"suites.{suite_name}"
    try:
        mod = importlib.import_module(module_path)
    except ImportError:
        mod = None
    msg = getattr(mod, "SYSTEM_MESSAGE", None)
    if not msg:
        console.print(f"[dim]No SYSTEM_MESSAGE in '{suite_name}' — running without a system prompt.[/dim]")
        return ""
    return msg


class TaskPair(NamedTuple):
    user_task_id: str
    injection_task_id: str


def _utility(value: bool) -> Text:
    return Text("✅ task completed", style="bold green") if value else Text("❌ task not completed", style="bold red")


def _print_agent_text(label: str, text: str, max_len: int = 200) -> None:
    text = (text or "").replace("\n", " ").strip()
    if len(text) > max_len:
        text = text[:max_len] + "…"
    line = Text(f"    {label}: ", style="dim")
    line.append(text, style="italic")
    console.print(line)


def _security(value: bool) -> Text:
    if value:
        return Text("💀 attack succeeded", style="bold red")
    return Text("🛡️ attack failed", style="bold green")


async def _fetch_suite_info(control_url: str) -> dict:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"{control_url}/suite")
        resp.raise_for_status()
        return resp.json()


async def _create_run(control_url: str) -> str:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(f"{control_url}/runs")
        resp.raise_for_status()
        return resp.json()["id"]


def _print_banner(
    suite_name: str,
    suite_info: dict,
    agent_uri: str,
    protocol: str,
    user_tasks_to_run: list[str],
    injection_tasks_to_run: list[str],
) -> None:
    lines = Text()
    lines.append("Suite       ", style="dim")
    lines.append(f"{suite_name}\n")
    lines.append("Agent       ", style="dim")
    lines.append(f"{agent_uri} ({protocol})\n")
    lines.append("Tasks       ", style="dim")
    if injection_tasks_to_run:
        lines.append(f"{len(user_tasks_to_run)} user x {len(injection_tasks_to_run)} injection\n")
    else:
        lines.append(f"{len(user_tasks_to_run)} user (no injections)\n")
    console.print(Panel(lines, title="midojo orchestrator", border_style="cyan", padding=(1, 2)))
    console.print()


def _print_results_table(
    utility_results: dict[TaskPair, bool],
    security_results: dict[TaskPair, bool],
    has_injections: bool,
    results_file: Path,
) -> None:
    table = Table(title="Results", border_style="cyan", show_lines=True)
    table.add_column("User Task", style="bold")
    if has_injections:
        table.add_column("Injection Task")
    table.add_column("Utility", justify="center")
    if has_injections:
        table.add_column("Security", justify="center")

    for pair, util in utility_results.items():
        sec = security_results.get(pair)
        if has_injections:
            sec_cell = _security(sec) if sec is not None else Text("N/A", style="dim")
            table.add_row(pair.user_task_id, pair.injection_task_id, _utility(util), sec_cell)
        else:
            table.add_row(pair.user_task_id, _utility(util))

    table.add_section()
    if utility_results:
        util_avg = f"{sum(utility_results.values()) / len(utility_results) * 100:.1f}%"
    else:
        util_avg = "-"
    if security_results:
        sec_avg = f"{sum(security_results.values()) / len(security_results) * 100:.1f}%"
    else:
        sec_avg = "-"

    if has_injections:
        table.add_row("", "", Text(util_avg, style="bold"), Text(sec_avg, style="bold"))
    else:
        table.add_row("", Text(util_avg, style="bold"))

    console.print(table)
    console.print(f"\nResults saved to [cyan]{results_file}[/cyan]")


async def _injection_reached_agent(
    control_url: str, run_id: str, eval_id: str, injections: dict[str, str]
) -> list[str]:
    """Return channels through which an injection payload reached the agent.

    Checks both the agent input (prompt) and function call results (tool output).
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        eval_resp, calls_resp = await asyncio.gather(
            client.get(f"{control_url}/runs/{run_id}/evaluations/{eval_id}"),
            client.get(f"{control_url}/runs/{run_id}/evaluations/{eval_id}/function-calls"),
        )
        eval_resp.raise_for_status()
        calls_resp.raise_for_status()
        eval_data = eval_resp.json()
        calls = calls_resp.json()
    payloads = [v for v in injections.values() if v]
    if not payloads:
        return []

    def _normalize(text: str) -> str:
        return " ".join(text.split()).lower()

    normalized_payloads = [_normalize(p) for p in payloads]
    hits: list[str] = []
    agent_input = eval_data.get("agent_input") or ""
    if agent_input and any(p in _normalize(agent_input) for p in normalized_payloads):
        hits.append("agent input")
    for call in calls:
        result = _normalize(call.get("result", "") or "")
        if any(p in result for p in normalized_payloads):
            hits.append(call["function"])
    return hits


async def _create_evaluation(
    client: httpx.AsyncClient,
    control_url: str,
    run_id: str,
    user_task_id: str,
    injection_task_id: str | None,
    injections: dict[str, str],
) -> tuple[str, str]:
    """POST /evaluations and return (eval_id, prompt)."""
    resp = await client.post(
        f"{control_url}/runs/{run_id}/evaluations",
        json={
            "user_task_id": user_task_id,
            "injection_task_id": injection_task_id,
            "injections": injections,
        },
    )
    resp.raise_for_status()
    data = resp.json()
    return data["id"], data["prompt"]


async def _complete_and_grade(
    client: httpx.AsyncClient,
    control_url: str,
    run_id: str,
    eval_id: str,
    agent_output: str,
) -> dict:
    """POST /complete + POST /grade and return the grading result dict."""
    complete_resp = await client.post(
        f"{control_url}/runs/{run_id}/evaluations/{eval_id}/complete",
        json={"agent_output": agent_output},
    )
    complete_resp.raise_for_status()

    grade_resp = await client.post(f"{control_url}/runs/{run_id}/evaluations/{eval_id}/grade")
    grade_resp.raise_for_status()
    result = grade_resp.json()
    result["eval_id"] = eval_id
    return result


async def run_task(
    control_url: str,
    agent_client: AgentClient,
    run_id: str,
    user_task_id: str,
    injection_task_id: str | None,
    injections: dict[str, str],
    *,
    backend: EnvironmentBackend | None = None,
) -> dict:
    """Run a single evaluation.

    If ``backend`` carries the OpenShell lifecycle (``setup``/``snapshot``/
    ``teardown``), those are called around the agent execution step.
    For dict-backed suites ``backend=None`` and the normal flow applies.
    """
    async with httpx.AsyncClient(timeout=300.0) as client:
        eval_id, prompt = await _create_evaluation(
            client, control_url, run_id, user_task_id, injection_task_id, injections
        )

        if backend is not None:
            # OpenShell provisioning (sandbox create/boot, seeding, teardown) is
            # slow and blocking; show a live spinner per phase so the run isn't
            # silent while it works. Label each with the task pair being run.
            pair = f"{user_task_id} x {injection_task_id}" if injection_task_id else user_task_id
            pre_env = backend.provision(injections)  # type: ignore[union-attr]
            with console.status(f"[dim]{pair} · creating sandbox (image pull + boot)…[/dim]", spinner="dots"):
                await asyncio.to_thread(backend.setup, pre_env)  # type: ignore[union-attr]
            try:
                with console.status(f"[dim]{pair} · running agent in sandbox…[/dim]", spinner="dots"):
                    agent_output = await agent_client.send_task(prompt)
                with console.status(f"[dim]{pair} · collecting sandbox observations…[/dim]", spinner="dots"):
                    post_env = await asyncio.to_thread(backend.snapshot)  # type: ignore[union-attr]
                env_resp = await client.put(
                    f"{control_url}/runs/{run_id}/evaluations/{eval_id}/environment",
                    json=post_env.model_dump(),  # type: ignore[union-attr]
                )
                env_resp.raise_for_status()
            finally:
                with console.status(f"[dim]{pair} · tearing down sandbox…[/dim]", spinner="dots"):
                    await asyncio.to_thread(backend.teardown)  # type: ignore[union-attr]
        else:
            agent_output = await agent_client.send_task(prompt)

        result = await _complete_and_grade(client, control_url, run_id, eval_id, agent_output)
        result["prompt"] = prompt
        result["agent_output"] = agent_output
        return result


async def run_benchmark(
    control_url: str,
    agent_client: AgentClient,
    agent_uri: str,
    protocol: str,
    suite: YAMLTaskSuite,
    suite_name: str,
    user_task_ids: list[str] | None,
    injection_task_ids: list[str] | None,
    logdir: Path,
    lifecycle_backend: EnvironmentBackend | None = None,
) -> None:
    user_tasks_to_run = user_task_ids or list(suite.user_tasks.keys())
    injection_tasks_to_run: list[str]
    if injection_task_ids is not None:
        injection_tasks_to_run = injection_task_ids
    elif user_task_ids is None:
        injection_tasks_to_run = list(suite.injection_tasks.keys())
    else:
        # -ut without -it: utility-only run
        injection_tasks_to_run = []

    suite_info = await _fetch_suite_info(control_url)
    _print_banner(suite_name, suite_info, agent_uri, protocol, user_tasks_to_run, injection_tasks_to_run)

    run_id = await _create_run(control_url)
    console.print(f"  [dim]run[/dim] [cyan underline]{run_id}[/cyan underline]\n")

    # openshell provisions one workspace per run (named after run_id) around the
    # eval loop; the sandbox itself is created/torn down per evaluation.
    if lifecycle_backend is not None:
        workspace_name = f"midojo-run-{run_id}"  # mirrors OpenShellBackend.start_run
        with console.status(
            f"[dim]opening workspace [cyan]{workspace_name}[/cyan] on the gateway…[/dim]", spinner="dots"
        ):
            await asyncio.to_thread(lifecycle_backend.start_run, run_id)  # type: ignore[attr-defined]
        console.print(
            f"  [magenta]openshell[/magenta] [dim]workspace[/dim] [cyan]{workspace_name}[/cyan] [green]ready[/green]\n"
        )

    utility_results: dict[TaskPair, bool] = {}
    security_results: dict[TaskPair, bool] = {}
    security_reasons: dict[TaskPair, str | None] = {}

    it_ids_to_run: list[str | None] = [*injection_tasks_to_run] if injection_tasks_to_run else [None]
    try:
        for ut_id in user_tasks_to_run:
            for it_id in it_ids_to_run:
                injections = suite.get_probes_for_task(it_id) if it_id else {}
                result = await run_task(
                    control_url,
                    agent_client,
                    run_id,
                    ut_id,
                    it_id,
                    injections,
                    backend=lifecycle_backend,
                )
                utility_results[TaskPair(ut_id, it_id or "")] = result["utility"]
                eval_id = result["eval_id"]
                eval_url = f"{control_url}/runs/{run_id}/evaluations/{eval_id}"
                label = f"[bold]{ut_id}[/bold] x [bold]{it_id}[/bold]" if it_id else f"[bold]{ut_id}[/bold]"
                console.print(f"  [dim]\\[eval: [link={eval_url}][cyan]{eval_id}[/cyan][/link]][/dim] {label}")
                _print_agent_text("agent input", result["prompt"])
                _print_agent_text("agent output", result["agent_output"])
                console.print("    ", _utility(result["utility"]))
                if it_id:
                    hit_channels = await _injection_reached_agent(control_url, run_id, eval_id, injections)
                    if hit_channels:
                        security_results[TaskPair(ut_id, it_id)] = result["security"]
                        security_reasons[TaskPair(ut_id, it_id)] = result.get("security_reason")
                        counts = Counter(hit_channels)
                        parts = [f"{ch} x{n}" if n > 1 else ch for ch, n in counts.items()]
                        via = ", ".join(parts)
                        detail = f"injection in {via}"
                        reason = result.get("security_reason")
                        if result["security"] and reason:
                            # attack succeeded — name the criterion that graded it
                            detail += f" · {reason}"
                        console.print("    ", _security(result["security"]), Text(f"  ({detail})", style="dim"))
                    else:
                        console.print("    ", Text("N/A (payload not in any result)", style="dim"))
    finally:
        if lifecycle_backend is not None:
            console.print()
            with console.status("[dim]draining and deleting the run workspace…[/dim]", spinner="dots"):
                await asyncio.to_thread(lifecycle_backend.end_run)  # type: ignore[attr-defined]
            console.print("  [magenta]openshell[/magenta] [dim]workspace[/dim] [green]cleaned up[/green]")

    console.print()

    logdir.mkdir(parents=True, exist_ok=True)
    results_file = logdir / "results.json"
    all_security = {f"{k.user_task_id},{k.injection_task_id}": security_results.get(k) for k in utility_results}
    all_security_reason = {f"{k.user_task_id},{k.injection_task_id}": security_reasons.get(k) for k in utility_results}
    with open(results_file, "w") as f:
        json.dump(
            {
                "utility": {f"{k.user_task_id},{k.injection_task_id}": v for k, v in utility_results.items()},
                "security": all_security,
                "security_reason": all_security_reason,
            },
            f,
            indent=2,
        )

    _print_results_table(utility_results, security_results, bool(injection_tasks_to_run), results_file)


@click.command()
@click.option("--control-url", default="http://localhost:8080", help="URL of the benchmark MCP server control plane.")
@click.option(
    "--agent-uri",
    required=True,
    help="Where to reach the agent. A URL for http/a2a/ogx/openai; a local path to the "
    "agent dir for pi; the OpenShell gateway name for openshell.",
)
@click.option(
    "--suite", "suite_name", required=True, help=f"Benchmark suite name. Built-in: {', '.join(list_suites())}."
)
@click.option("--user-task", "-ut", "user_tasks", multiple=True, default=(), help="Specific user task IDs.")
@click.option(
    "--injection-task", "-it", "injection_tasks", multiple=True, default=(), help="Specific injection task IDs."
)
@click.option("--logdir", default="./runs", type=Path, help="Directory to store results.")
@click.option(
    "--module-to-load", "-ml", "modules_to_load", multiple=True, default=(), help="Additional modules to import."
)
@click.option(
    "--protocol",
    type=click.Choice(["http", "a2a", "pi", "ogx", "openai", "openshell"]),
    required=True,
    help="Agent communication protocol. "
    "API keys are read from env vars: OPENAI_API_KEY (openai), OGX_CLIENT_API_KEY (ogx). "
    "For openshell: pass the gateway name via --agent-uri.",
)
@click.option(
    "--ogx-shield", default=None, envvar="OGX_SHIELD_ID", help="Shield ID for OGX guardrails (ogx protocol only)."
)
@click.option(
    "--mcp-server-label",
    default=None,
    envvar="MCP_SERVER_LABEL",
    help="Label the MCP server is registered under on the agent's inference server. "
    "Defaults to the suite name. Override when the server expects a different label.",
)
@click.option(
    "--model-name",
    default=None,
    envvar="MODEL_NAME",
    help="Model ID for the Responses API (ogx and openai protocols). "
    "Env: MODEL_NAME. Example: gpt-4o-mini, ollama/qwen3.5:2b.",
)
def main(
    control_url: str,
    agent_uri: str,
    suite_name: str,
    user_tasks: tuple[str, ...],
    injection_tasks: tuple[str, ...],
    logdir: Path,
    modules_to_load: tuple[str, ...],
    protocol: str,
    ogx_shield: str | None,
    mcp_server_label: str | None,
    model_name: str | None,
) -> None:
    for module in modules_to_load:
        importlib.import_module(module)

    suite = get_suite(suite_name)
    agent_client: AgentClient
    lifecycle_backend: EnvironmentBackend | None = None

    if protocol == "openshell":
        from midojo.backends.openshell import OpenShellBackend

        if not isinstance(suite.backend, OpenShellBackend):
            raise click.UsageError("--protocol openshell requires a suite with 'backend: {type: openshell, ...}'")
        suite.backend.configure(cluster=agent_uri, control_url=control_url)
        agent_client = OpenShellAgentClient(backend=suite.backend)
        lifecycle_backend = suite.backend
    elif protocol == "a2a":
        agent_client = A2AAgentClient(agent_uri)
    elif protocol == "pi":
        agent_client = PIAgentClient(agent_uri, control_url)
    elif protocol == "ogx":
        system_message = _resolve_system_message(suite_name)
        agent_client = OGXResponsesClient(
            ogx_url=agent_uri,
            model=model_name or os.environ.get("MODEL_NAME", "litellm/llama-scout-17b"),
            mcp_server_url=os.environ.get("MCP_SERVER_URL", "http://localhost:8082/mcp"),
            mcp_server_label=mcp_server_label or suite_name,
            instructions=system_message,
            shield_id=ogx_shield,
        )
    elif protocol == "openai":
        system_message = _resolve_system_message(suite_name)
        agent_client = OpenAIResponsesAgentClient(
            base_url=agent_uri,
            model=model_name or os.environ.get("MODEL_NAME", "gpt-4o-mini"),
            mcp_server_url=os.environ.get("MCP_SERVER_URL", "http://localhost:8082/mcp"),
            mcp_server_label=mcp_server_label or suite_name,
            api_key=os.environ.get("OPENAI_API_KEY", "x"),
            instructions=system_message,
        )
    else:
        agent_client = SimpleHTTPAgentClient(agent_uri)

    asyncio.run(
        run_benchmark(
            control_url=control_url,
            agent_client=agent_client,
            agent_uri=agent_uri,
            protocol=protocol,
            suite=suite,
            suite_name=suite_name,
            user_task_ids=list(user_tasks) if user_tasks else None,
            injection_task_ids=list(injection_tasks) if injection_tasks else None,
            logdir=logdir,
            lifecycle_backend=lifecycle_backend,
        )
    )


if __name__ == "__main__":
    main()
