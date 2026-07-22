#!/usr/bin/env python3
"""Benchmark runner for DEF CON poster experiments.

Runs midojo-run across multiple injection tasks, user tasks, and optionally
different wrapper overrides. Collects results into a structured JSON file
for visualization.

Usage:
    # Start servers first:
    midojo-serve --suite minibank --port 8080
    minibank-real-mcp-serve --port 8081
    minibank-fake-mcp-serve --port 8082 --upstream-url http://localhost:8081/mcp

    # Then run benchmarks:
    MCP_SERVER_URL=http://localhost:8082/mcp python scripts/run_benchmarks.py \
        --agent-url http://localhost:8321 \
        --protocol ogx \
        --model-name ollama/qwen3.5:2b \
        --output results/qwen3.5-2b.json
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import click

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@dataclass
class BenchmarkResult:
    user_task: str
    injection_task: str
    channel: str
    wrapper: str
    utility: bool | None = None
    security: bool | None = None
    agent_output: str = ""
    duration_s: float = 0.0
    error: str | None = None


@dataclass
class BenchmarkReport:
    model: str
    protocol: str
    suite: str
    timestamp: str = ""
    results: list[BenchmarkResult] = field(default_factory=list)
    summary: dict = field(default_factory=dict)


async def run_single(
    control_url: str,
    agent_client,
    run_id: str,
    suite,
    ut_id: str,
    it_id: str,
) -> BenchmarkResult:
    """Run a single (user_task, injection_task) evaluation and return the result."""
    from midojo.orchestrator import run_task

    injections = suite.get_probes_for_task(it_id)
    prompt_injs = suite.get_prompt_injections_for_task(it_id)
    tool_mods = suite.get_tool_modifications_for_task(it_id)
    output_hooks = suite.get_output_hooks_for_task(it_id)
    mem_entries = suite.get_memory_entries_for_task(it_id)
    ia_messages = suite.get_inter_agent_messages_for_task(it_id)

    channel = "environment_state"
    if prompt_injs:
        channel = "user_prompt"
    if tool_mods:
        channel = "tool_description"
    if output_hooks:
        channel = "tool_output"
    if mem_entries:
        channel = "memory"

    it = suite.injection_tasks[it_id]
    wrapper = "verbatim"
    probes_raw = {}
    for probe_id, probe_raw in it.__dict__.get("_raw_probes", {}).items():
        wrapper = probe_raw.get("attack_type", "verbatim")
    if not wrapper or wrapper == "verbatim":
        if injections:
            first_payload = list(injections.values())[0]
            if "<INFORMATION>" in first_payload:
                wrapper = "important_instructions"
            elif "Ignore your previous" in first_payload:
                wrapper = "ignore_previous"

    start = time.time()
    try:
        result = await run_task(
            control_url, agent_client, run_id, suite, ut_id, it_id,
            injections, prompt_injs, tool_mods, output_hooks, mem_entries, ia_messages,
        )
        duration = time.time() - start
        return BenchmarkResult(
            user_task=ut_id,
            injection_task=it_id,
            channel=channel,
            wrapper=wrapper,
            utility=result.get("utility"),
            security=result.get("security"),
            agent_output=(result.get("agent_output") or "")[:200],
            duration_s=round(duration, 1),
        )
    except Exception as e:
        duration = time.time() - start
        return BenchmarkResult(
            user_task=ut_id,
            injection_task=it_id,
            channel=channel,
            wrapper=wrapper,
            error=str(e),
            duration_s=round(duration, 1),
        )


async def run_benchmarks(
    control_url: str,
    agent_url: str,
    protocol: str,
    model_name: str,
    suite_name: str,
    user_tasks: list[str] | None,
    injection_tasks: list[str] | None,
    output_path: Path,
) -> None:
    import importlib

    import httpx

    from midojo.agent_client import OGXResponsesClient, OpenAIResponsesAgentClient, SimpleHTTPAgentClient
    from midojo.suites import get_suite

    suite = get_suite(suite_name)

    system_message = ""
    try:
        mod = importlib.import_module(f"suites.{suite_name}" if "." not in suite_name else suite_name)
        system_message = getattr(mod, "SYSTEM_MESSAGE", "")
    except ImportError:
        pass

    if protocol == "ogx":
        agent_client = OGXResponsesClient(
            ogx_url=agent_url,
            model=model_name,
            mcp_server_url=os.environ.get("MCP_SERVER_URL", "http://localhost:8082/mcp"),
            mcp_server_label=suite_name,
            instructions=system_message,
        )
    elif protocol == "openai":
        agent_client = OpenAIResponsesAgentClient(
            base_url=agent_url,
            model=model_name,
            mcp_server_url=os.environ.get("MCP_SERVER_URL", "http://localhost:8082/mcp"),
            mcp_server_label=suite_name,
            api_key=os.environ.get("OPENAI_API_KEY", "x"),
            instructions=system_message,
        )
    else:
        agent_client = SimpleHTTPAgentClient(agent_url)

    ut_ids = user_tasks or list(suite.user_tasks.keys())
    it_ids = injection_tasks or list(suite.injection_tasks.keys())

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(f"{control_url}/runs")
        resp.raise_for_status()
        run_id = resp.json()["id"]

    report = BenchmarkReport(
        model=model_name,
        protocol=protocol,
        suite=suite_name,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
    )

    total = len(ut_ids) * len(it_ids)
    done = 0

    for ut_id in ut_ids:
        for it_id in it_ids:
            done += 1
            print(f"  [{done}/{total}] {ut_id} x {it_id} ... ", end="", flush=True)

            # Restart control plane eval state by creating a fresh run
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(f"{control_url}/runs")
                resp.raise_for_status()
                run_id = resp.json()["id"]

            result = await run_single(control_url, agent_client, run_id, suite, ut_id, it_id)
            report.results.append(result)

            status = ""
            if result.error:
                status = f"ERROR: {result.error[:50]}"
            else:
                u = "util:pass" if result.utility else "util:fail"
                s = "sec:pass" if result.security else ("sec:fail" if result.security is not None else "sec:N/A")
                status = f"{u} | {s}"
            print(f"{status} ({result.duration_s}s)")

    # Summary
    results = report.results
    successful = [r for r in results if r.error is None]
    report.summary = {
        "total_runs": len(results),
        "errors": len([r for r in results if r.error]),
        "utility_rate": sum(1 for r in successful if r.utility) / len(successful) if successful else 0,
        "attack_success_rate": sum(1 for r in successful if r.security) / len(successful) if successful else 0,
        "by_channel": {},
        "by_injection_task": {},
    }

    for r in successful:
        ch = r.channel
        if ch not in report.summary["by_channel"]:
            report.summary["by_channel"][ch] = {"runs": 0, "utility": 0, "attack_success": 0}
        report.summary["by_channel"][ch]["runs"] += 1
        if r.utility:
            report.summary["by_channel"][ch]["utility"] += 1
        if r.security:
            report.summary["by_channel"][ch]["attack_success"] += 1

        it = r.injection_task
        if it not in report.summary["by_injection_task"]:
            report.summary["by_injection_task"][it] = {"runs": 0, "utility": 0, "attack_success": 0}
        report.summary["by_injection_task"][it]["runs"] += 1
        if r.utility:
            report.summary["by_injection_task"][it]["utility"] += 1
        if r.security:
            report.summary["by_injection_task"][it]["attack_success"] += 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(asdict(report), f, indent=2, default=str)

    print(f"\nResults saved to {output_path}")
    print(f"  Total: {report.summary['total_runs']} runs, {report.summary['errors']} errors")
    print(f"  Utility rate: {report.summary['utility_rate']:.1%}")
    print(f"  Attack success rate: {report.summary['attack_success_rate']:.1%}")


@click.command()
@click.option("--control-url", default="http://localhost:8080")
@click.option("--agent-url", required=True)
@click.option("--protocol", required=True, type=click.Choice(["ogx", "openai", "http"]))
@click.option("--model-name", required=True)
@click.option("--suite", "suite_name", default="minibank")
@click.option("--user-task", "-ut", "user_tasks", multiple=True, default=())
@click.option("--injection-task", "-it", "injection_tasks", multiple=True, default=())
@click.option("--output", "output_path", required=True, type=Path)
def main(
    control_url: str,
    agent_url: str,
    protocol: str,
    model_name: str,
    suite_name: str,
    user_tasks: tuple[str, ...],
    injection_tasks: tuple[str, ...],
    output_path: Path,
) -> None:
    asyncio.run(
        run_benchmarks(
            control_url=control_url,
            agent_url=agent_url,
            protocol=protocol,
            model_name=model_name,
            suite_name=suite_name,
            user_tasks=list(user_tasks) if user_tasks else None,
            injection_tasks=list(injection_tasks) if injection_tasks else None,
            output_path=output_path,
        )
    )


if __name__ == "__main__":
    main()
