"""CLI for MiDojo artifact generation from scenario-forge output.

Usage:
    python -m midojo.artifact_gen /path/to/forge-run \\
        --output ./midojo-artifacts \\
        --llm-url http://localhost:8321/v1 \\
        --llm-model openai/gemma-4-26b
"""

from __future__ import annotations

import logging
from pathlib import Path

import click

from midojo.artifact_gen.assembler import assemble_artifacts
from midojo.artifact_gen.forge_reader import ForgeRun, load_forge_run
from midojo.artifact_gen.llm_bridge import generate_content

logger = logging.getLogger("midojo.artifact_gen")


def _classify_scenario_tier(profile) -> str:
    """Determine which tier a scenario belongs to based on entry points."""
    if profile.indirect_entry_points:
        return "grey_box"
    return "black_box"


def _run(
    forge_run: ForgeRun,
    output_dir: Path,
    llm_url: str,
    llm_model: str,
    llm_api_key: str,
    tiers: list[str],
) -> None:
    """Run the full artifact generation pipeline."""
    profile = forge_run.capability_profile
    loss = forge_run.loss_analysis

    has_indirect = len(profile.indirect_entry_points) > 0
    has_direct = len(profile.direct_entry_points) > 0

    total = len(forge_run.scenarios)
    generated = []
    for i, scenario in enumerate(forge_run.scenarios, 1):
        if has_direct and "black_box" in tiers:
            content = generate_content(
                scenario, profile, loss, "black_box",
                llm_url=llm_url, llm_model=llm_model, llm_api_key=llm_api_key,
                scenario_number=i, total_scenarios=total,
            )
            generated.append(content)

        if has_indirect and "grey_box" in tiers:
            content = generate_content(
                scenario, profile, loss, "grey_box",
                llm_url=llm_url, llm_model=llm_model, llm_api_key=llm_api_key,
                scenario_number=i, total_scenarios=total,
            )
            generated.append(content)

    if not generated:
        logger.warning("no content generated — check tiers and entry points")
        return

    outputs = assemble_artifacts(forge_run, generated, output_dir)

    click.echo("\nMiDojo artifacts generated:")
    for tier, path in outputs.items():
        suite = path / "suite.yaml"
        click.echo(f"  {tier}: {suite}")
    click.echo(f"  run script: {output_dir / 'run.sh'}")


@click.command()
@click.argument("forge_run_dir", type=click.Path(exists=True))
@click.option("--output", "-o", default="./midojo-artifacts", type=click.Path(), help="Output directory")
@click.option("--llm-url", required=True, help="LLM endpoint URL (OpenAI-compatible)")
@click.option("--llm-model", required=True, help="LLM model name")
@click.option("--llm-api-key", default="no-key", help="LLM API key")
@click.option("--tiers", default="black_box,grey_box", help="Comma-separated tiers to generate")
@click.option("--log-level", default="INFO", help="Log level")
def main(
    forge_run_dir: str,
    output: str,
    llm_url: str,
    llm_model: str,
    llm_api_key: str,
    tiers: str,
    log_level: str,
) -> None:
    """Generate MiDojo test artifacts from a scenario-forge STPA-Sec run."""
    logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO))

    forge_run = load_forge_run(forge_run_dir)
    click.echo(f"Loaded forge run: {len(forge_run.scenarios)} scenarios, "
               f"{len(forge_run.capability_profile.tools)} tools, "
               f"{len(forge_run.loss_analysis.security_constraints)} constraints")

    tier_list = [t.strip() for t in tiers.split(",")]
    _run(forge_run, Path(output), llm_url, llm_model, llm_api_key, tier_list)


if __name__ == "__main__":
    main()
