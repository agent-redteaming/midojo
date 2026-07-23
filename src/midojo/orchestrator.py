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
    PIAgentClient,
    SimpleHTTPAgentClient,
)
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
        console.print(
            f"[dim]No SYSTEM_MESSAGE in '{suite_name}' — running without a system prompt.[/dim]"
        )
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
    agent_url: str,
    protocol: str,
    user_tasks_to_run: list[str],
    injection_tasks_to_run: list[str],
) -> None:
    lines = Text()
    lines.append("Suite       ", style="dim")
    lines.append(f"{suite_name}\n")
    lines.append("Agent       ", style="dim")
    lines.append(f"{agent_url} ({protocol})\n")
    lines.append("Tasks       ", style="dim")
    if injection_tasks_to_run:
        lines.append(f"{len(user_tasks_to_run)} user x {len(injection_tasks_to_run)} injection\n")
    else:
        lines.append(f"{len(user_tasks_to_run)} user (no injections)\n")
    lines.append("Tools       ", style="dim")
    lines.append(", ".join(suite_info["tools"]))

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


async def _run_single_eval(
    control_url: str,
    agent_client: AgentClient,
    run_id: str,
    user_task_id: str,
    injection_task_id: str | None,
    injection,
) -> dict:
    """Execute one complete evaluation cycle. Called once by static attacks,
    N times by iterative strategies (PAIR, TAP, etc.).

    The ``injection`` parameter is a redteam_attacks.Injection (probes dict,
    prompt content, tool modifications) or a plain dict for backward compat.
    """
    from midojo.types import ToolModification

    probes: dict[str, str] = {}
    prompt_content: str | None = None
    prompt_mode: str = "append"
    tool_mods: list[dict] = []
    out_hooks: list[dict] = []

    mem_entries: list[dict] = []
    ia_messages: list[dict] = []

    if hasattr(injection, "probes"):
        probes = injection.probes or {}
        prompt_content = injection.prompt_content
        prompt_mode = getattr(injection, "prompt_mode", "append")
        tool_mods = injection.tool_modifications or []
        out_hooks = getattr(injection, "output_hooks", None) or []
        mem_entries = getattr(injection, "memory_entries", None) or []
        ia_messages = getattr(injection, "inter_agent_messages", None) or []
    elif isinstance(injection, dict):
        probes = injection

    async with httpx.AsyncClient(timeout=300.0) as client:
        eval_body: dict = {
            "user_task_id": user_task_id,
            "injection_task_id": injection_task_id,
            "injections": probes,
        }
        if tool_mods:
            eval_body["tool_modifications"] = [
                m.model_dump() if isinstance(m, ToolModification) else m
                for m in tool_mods
            ]
        if out_hooks:
            eval_body["output_hooks"] = [
                h.model_dump() if hasattr(h, "model_dump") else h
                for h in out_hooks
            ]
        if mem_entries:
            eval_body["memory_entries"] = [
                e.model_dump() if hasattr(e, "model_dump") else e
                for e in mem_entries
            ]
        if ia_messages:
            eval_body["inter_agent_messages"] = [
                m.model_dump() if hasattr(m, "model_dump") else m
                for m in ia_messages
            ]
        eval_resp = await client.post(
            f"{control_url}/runs/{run_id}/evaluations",
            json=eval_body,
        )
        eval_resp.raise_for_status()
        eval_data = eval_resp.json()
        eval_id = eval_data["id"]
        prompt = eval_data["prompt"]

        if prompt_content:
            if prompt_mode == "append":
                prompt = f"{prompt}\n\n{prompt_content}"
            elif prompt_mode == "prepend":
                prompt = f"{prompt_content}\n\n{prompt}"

        agent_output = await agent_client.send_task(prompt)

        complete_resp = await client.post(
            f"{control_url}/runs/{run_id}/evaluations/{eval_id}/complete",
            json={"agent_output": agent_output},
        )
        complete_resp.raise_for_status()

        grade_resp = await client.post(f"{control_url}/runs/{run_id}/evaluations/{eval_id}/grade")
        grade_resp.raise_for_status()
        grade = grade_resp.json()

        calls_resp = await client.get(
            f"{control_url}/runs/{run_id}/evaluations/{eval_id}/function-calls"
        )
        calls = calls_resp.json() if calls_resp.status_code == 200 else []

    return {
        "eval_id": eval_id,
        "prompt": prompt,
        "agent_output": agent_output,
        "utility": grade["utility"],
        "security": grade["security"],
        "function_calls": calls,
    }


async def _run_multi_turn_eval(
    control_url: str,
    agent_client: AgentClient,
    run_id: str,
    user_task_id: str,
    injection_task_id: str | None,
    turn_generator,
) -> dict:
    """Execute a multi-turn evaluation. The turn_generator is an async callable
    that receives a send_message callback and drives the conversation.

    Returns an EvalResult-compatible dict with the final conversation state.
    """
    async with httpx.AsyncClient(timeout=300.0) as client:
        eval_resp = await client.post(
            f"{control_url}/runs/{run_id}/evaluations",
            json={
                "user_task_id": user_task_id,
                "injection_task_id": injection_task_id,
                "injections": {},
            },
        )
        eval_resp.raise_for_status()
        eval_data = eval_resp.json()
        eval_id = eval_data["id"]

        async def send_message(message: str, previous_response_id: str | None = None) -> tuple[str, str | None]:
            return await agent_client.send_message(message, previous_response_id)

        eval_result_holder: dict = {}
        last_output = await turn_generator(send_message, eval_result_holder)

        complete_resp = await client.post(
            f"{control_url}/runs/{run_id}/evaluations/{eval_id}/complete",
            json={"agent_output": last_output or ""},
        )
        complete_resp.raise_for_status()

        grade_resp = await client.post(f"{control_url}/runs/{run_id}/evaluations/{eval_id}/grade")
        grade_resp.raise_for_status()
        grade = grade_resp.json()

        calls_resp = await client.get(
            f"{control_url}/runs/{run_id}/evaluations/{eval_id}/function-calls"
        )
        calls = calls_resp.json() if calls_resp.status_code == 200 else []

    from redteam_attacks.types import EvalResult

    return EvalResult(
        agent_output=last_output or "",
        function_calls=calls,
        security_passed=grade["security"],
        utility_passed=grade["utility"],
    )


async def run_task(
    control_url: str,
    agent_client: AgentClient,
    run_id: str,
    suite: YAMLTaskSuite,
    user_task_id: str,
    injection_task_id: str | None,
    injections: dict[str, str],
    prompt_injections: list | None = None,
    tool_modifications: list | None = None,
    output_hooks: list | None = None,
    memory_entries: list | None = None,
    inter_agent_messages: list | None = None,
    attacker_config: dict | None = None,
) -> dict:
    from midojo.types import InterAgentMessage, MemoryEntry, OutputHook, PromptModification, ToolModification

    attack_spec = None
    if injection_task_id and injection_task_id in suite.injection_tasks:
        attack_spec = suite.injection_tasks[injection_task_id].attack_spec

    if attack_spec and attack_spec.get("strategy") not in (None, "static"):
        from redteam_attacks import Attack, AttackContext, EvalResult, Injection, TargetContext

        async def _eval_callback(inj: Injection) -> EvalResult:
            raw = await _run_single_eval(
                control_url, agent_client, run_id,
                user_task_id, injection_task_id, inj,
            )
            return EvalResult(
                agent_output=raw.get("agent_output", ""),
                function_calls=raw.get("function_calls", []),
                security_passed=raw.get("security", True),
                utility_passed=raw.get("utility", True),
            )

        async def _multi_turn_callback(turn_generator) -> EvalResult:
            return await _run_multi_turn_eval(
                control_url, agent_client, run_id,
                user_task_id, injection_task_id, turn_generator,
            )

        # Build target context for the attacker LLM.
        # Tools and dry-run trace are always available (black-box).
        # System prompt is only available when testing your own agent.
        tool_defs = [t.model_dump() for t in suite.get_tool_definitions()]
        system_prompt = ""
        try:
            mod = importlib.import_module(f"suites.{suite.name}" if "." not in suite.name else suite.name)
            system_prompt = getattr(mod, "SYSTEM_MESSAGE", "")
        except (ImportError, AttributeError):
            pass

        user_prompt = suite.user_tasks[user_task_id].prompt if user_task_id in suite.user_tasks else ""

        env_summary = ""
        try:
            env_schema = suite.environment_type.model_json_schema()
            fields = env_schema.get("properties", {})
            env_parts = []
            for fname, finfo in fields.items():
                ftype = finfo.get("type", "?")
                env_parts.append(f"  {fname}: {ftype}")
            env_summary = "Fields:\n" + "\n".join(env_parts) if env_parts else ""
        except Exception:
            pass

        # Dry-run: run the task with no injections to see what the agent normally does
        dry_run_trace: list[dict] = []
        try:
            dry_inj = Injection(probes={})
            dry_result = await _eval_callback(dry_inj)
            dry_run_trace = dry_result.function_calls
        except Exception:
            pass

        target = TargetContext(
            tools=tool_defs,
            system_prompt=system_prompt,
            user_task_prompt=user_prompt,
            environment_summary=env_summary,
            dry_run_trace=dry_run_trace,
        )

        ctx = AttackContext(
            run_evaluation=_eval_callback,
            run_multi_turn=_multi_turn_callback,
            tool_names=suite.get_tool_names(),
            user_task_id=user_task_id,
            injection_task_id=injection_task_id or "",
            target=target,
            attacker_model=(attacker_config or {}).get("attacker_model"),
            attacker_base_url=(attacker_config or {}).get("attacker_base_url"),
            attacker_api_key=(attacker_config or {}).get("attacker_api_key"),
        )

        seed_payloads = attack_spec.get("seed_payloads") or list(injections.values()) or []
        attack = Attack.from_spec(attack_spec, seed_payloads=seed_payloads)
        attack_result = await attack.execute(ctx)

        last_eval = attack_result.evaluations[-1] if attack_result.evaluations else None
        # Use Midojo verifier (security_passed) for consistent reporting.
        # The library's goal evaluator (attack_result.success) is used as the
        # PAIR/TAP stopping criterion but NOT as the final security score.
        # Check ALL evaluations: attack succeeded if ANY eval broke security.
        any_security_broken = any(
            not e.security_passed for e in attack_result.evaluations
        )
        return {
            "utility": last_eval.utility_passed if last_eval else False,
            "security": any_security_broken,
            "eval_id": "attack-multi",
            "prompt": f"(iterative: {attack_result.strategy_metadata.get('strategy', '?')}, "
                      f"{len(attack_result.evaluations)} evals)",
            "agent_output": last_eval.agent_output if last_eval else "",
            "attack_result": attack_result,
        }

    # --- Static path (unchanged behavior) ---
    from redteam_attacks.types import Injection

    inj = Injection(probes=injections)
    if prompt_injections:
        for mod in prompt_injections:
            if isinstance(mod, PromptModification):
                inj.prompt_content = mod.content
                inj.prompt_mode = mod.mode
                break
    if tool_modifications:
        inj.tool_modifications = [
            m.model_dump() if isinstance(m, ToolModification) else m
            for m in tool_modifications
        ]
    if output_hooks:
        inj.output_hooks = [
            h.model_dump() if isinstance(h, OutputHook) else h
            for h in output_hooks
        ]
    if memory_entries:
        inj.memory_entries = [
            e.model_dump() if isinstance(e, MemoryEntry) else e
            for e in memory_entries
        ]
    if inter_agent_messages:
        inj.inter_agent_messages = [
            m.model_dump() if isinstance(m, InterAgentMessage) else m
            for m in inter_agent_messages
        ]

    raw = await _run_single_eval(
        control_url, agent_client, run_id,
        user_task_id, injection_task_id, inj,
    )
    return raw


async def run_benchmark(
    control_url: str,
    agent_client: AgentClient,
    agent_url: str,
    protocol: str,
    suite: YAMLTaskSuite,
    suite_name: str,
    user_task_ids: list[str] | None,
    injection_task_ids: list[str] | None,
    logdir: Path,
    attacker_config: dict | None = None,
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
    _print_banner(suite_name, suite_info, agent_url, protocol, user_tasks_to_run, injection_tasks_to_run)

    run_id = await _create_run(control_url)
    console.print(f"  [dim]run[/dim] [cyan underline]{run_id}[/cyan underline]\n")

    utility_results: dict[TaskPair, bool] = {}
    security_results: dict[TaskPair, bool] = {}

    it_ids_to_run: list[str | None] = injection_tasks_to_run or [None]
    for ut_id in user_tasks_to_run:
        for it_id in it_ids_to_run:
            injections = suite.get_probes_for_task(it_id) if it_id else {}
            prompt_injs = suite.get_prompt_injections_for_task(it_id) if it_id else []
            tool_mods = suite.get_tool_modifications_for_task(it_id) if it_id else []
            output_hooks = suite.get_output_hooks_for_task(it_id) if it_id else []
            mem_entries = suite.get_memory_entries_for_task(it_id) if it_id else []
            ia_messages = suite.get_inter_agent_messages_for_task(it_id) if it_id else []
            result = await run_task(
                control_url, agent_client, run_id, suite, ut_id, it_id,
                injections, prompt_injs, tool_mods, output_hooks, mem_entries, ia_messages,
                attacker_config,
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
                if "attack_result" in result:
                    ar = result["attack_result"]
                    security_results[TaskPair(ut_id, it_id)] = ar.success
                    n_evals = len(ar.evaluations)
                    console.print(
                        "    ",
                        _security(ar.success),
                        Text(f"  ({n_evals} evals via {ar.strategy_metadata.get('strategy', '?')})", style="dim"),
                    )
                else:
                    all_payloads = dict(injections)
                    for pi in prompt_injs:
                        all_payloads[f"__prompt_injection_{id(pi)}"] = pi.content
                    hit_channels = await _injection_reached_agent(control_url, run_id, eval_id, all_payloads)
                    if hit_channels:
                        security_results[TaskPair(ut_id, it_id)] = result["security"]
                        counts = Counter(hit_channels)
                        parts = [f"{ch} x{n}" if n > 1 else ch for ch, n in counts.items()]
                        via = ", ".join(parts)
                        console.print("    ", _security(result["security"]), Text(f"  (injection in {via})", style="dim"))
                    else:
                        console.print("    ", Text("N/A (payload not in any result)", style="dim"))

    console.print()

    logdir.mkdir(parents=True, exist_ok=True)
    results_file = logdir / "results.json"
    all_security = {f"{k.user_task_id},{k.injection_task_id}": security_results.get(k) for k in utility_results}
    with open(results_file, "w") as f:
        json.dump(
            {
                "utility": {f"{k.user_task_id},{k.injection_task_id}": v for k, v in utility_results.items()},
                "security": all_security,
            },
            f,
            indent=2,
        )

    _print_results_table(utility_results, security_results, bool(injection_tasks_to_run), results_file)


@click.command()
@click.option("--control-url", default="http://localhost:8080", help="URL of the benchmark MCP server control plane.")
@click.option("--agent-url", required=True, help="URL of the agent to test.")
@click.option("--suite", "suite_name", required=True, help=f"Benchmark suite name. Built-in: {', '.join(list_suites())}.")
@click.option("--user-task", "-ut", "user_tasks", multiple=True, default=(), help="Specific user task IDs.")
@click.option(
    "--injection-task", "-it", "injection_tasks", multiple=True, default=(), help="Specific injection task IDs."
)
@click.option("--logdir", default="./runs", type=Path, help="Directory to store results.")
@click.option(
    "--module-to-load", "-ml", "modules_to_load", multiple=True, default=(), help="Additional modules to import."
)
@click.option(
    "--protocol", type=click.Choice(["http", "a2a", "pi", "ogx", "openai"]), required=True,
    help="Agent communication protocol. "
         "API keys are read from env vars: OPENAI_API_KEY (openai), OGX_CLIENT_API_KEY (ogx).",
)
@click.option(
    "--ogx-shield", default=None, envvar="OGX_SHIELD_ID", help="Shield ID for OGX guardrails (ogx protocol only)."
)
@click.option(
    "--mcp-server-label", default=None, envvar="MCP_SERVER_LABEL",
    help="Label the MCP server is registered under on the agent's inference server. "
         "Defaults to the suite name. Override when the server expects a different label.",
)
@click.option(
    "--model-name", default=None, envvar="MODEL_NAME",
    help="Model ID for the Responses API (ogx and openai protocols). "
         "Env: MODEL_NAME. Example: gpt-4o-mini, ollama/qwen3.5:2b.",
)
@click.option(
    "--attacker-model", default=None, envvar="ATTACKER_MODEL",
    help="Model for the attacker LLM in adaptive strategies (PAIR, TAP). "
         "Env: ATTACKER_MODEL.",
)
@click.option(
    "--attacker-base-url", default=None, envvar="ATTACKER_BASE_URL",
    help="Base URL for the attacker LLM API. Env: ATTACKER_BASE_URL.",
)
@click.option(
    "--attacker-api-key", default=None, envvar="ATTACKER_API_KEY",
    help="API key for the attacker LLM. Env: ATTACKER_API_KEY.",
)
def main(
    control_url: str,
    agent_url: str,
    suite_name: str,
    user_tasks: tuple[str, ...],
    injection_tasks: tuple[str, ...],
    logdir: Path,
    modules_to_load: tuple[str, ...],
    protocol: str,
    ogx_shield: str | None,
    mcp_server_label: str | None,
    model_name: str | None,
    attacker_model: str | None,
    attacker_base_url: str | None,
    attacker_api_key: str | None,
) -> None:
    for module in modules_to_load:
        importlib.import_module(module)

    suite = get_suite(suite_name)
    agent_client: AgentClient
    if protocol == "a2a":
        agent_client = A2AAgentClient(agent_url)
    elif protocol == "pi":
        agent_client = PIAgentClient(agent_url, control_url)
    elif protocol == "ogx":
        system_message = _resolve_system_message(suite_name)
        agent_client = OGXResponsesClient(
            ogx_url=agent_url,
            model=model_name or os.environ.get("MODEL_NAME", "litellm/llama-scout-17b"),
            mcp_server_url=os.environ.get("MCP_SERVER_URL", "http://localhost:8082/mcp"),
            mcp_server_label=mcp_server_label or suite_name,
            instructions=system_message,
            shield_id=ogx_shield,
        )
    elif protocol == "openai":
        system_message = _resolve_system_message(suite_name)
        agent_client = OpenAIResponsesAgentClient(
            base_url=agent_url,
            model=model_name or os.environ.get("MODEL_NAME", "gpt-4o-mini"),
            mcp_server_url=os.environ.get("MCP_SERVER_URL", "http://localhost:8082/mcp"),
            mcp_server_label=mcp_server_label or suite_name,
            api_key=os.environ.get("OPENAI_API_KEY", "x"),
            instructions=system_message,
        )
    else:
        agent_client = SimpleHTTPAgentClient(agent_url)

    attacker_cfg = None
    if attacker_model:
        attacker_cfg = {
            "attacker_model": attacker_model,
            "attacker_base_url": attacker_base_url,
            "attacker_api_key": attacker_api_key,
        }

    asyncio.run(
        run_benchmark(
            control_url=control_url,
            agent_client=agent_client,
            agent_url=agent_url,
            protocol=protocol,
            suite=suite,
            suite_name=suite_name,
            user_task_ids=list(user_tasks) if user_tasks else None,
            injection_task_ids=list(injection_tasks) if injection_tasks else None,
            logdir=logdir,
            attacker_config=attacker_cfg,
        )
    )


if __name__ == "__main__":
    main()
