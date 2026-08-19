"""Read and parse a scenario-forge STPA-Sec run directory."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("midojo.artifact_gen")


@dataclass
class EntryPoint:
    name: str
    entry_point_type: str
    direction: str
    controllability: str
    ingress_zone: str | None = None
    entry_point_id: str = ""

    @property
    def is_direct(self) -> bool:
        return self.controllability == "direct"

    @property
    def is_indirect(self) -> bool:
        return self.controllability == "indirect"


@dataclass
class Tool:
    name: str
    description: str
    tool_id: str = ""
    kind: str = ""


@dataclass
class CapabilityProfile:
    zones_active: list[str]
    entry_points: list[EntryPoint]
    tools: list[Tool]
    kc_subcodes: list[str] = field(default_factory=list)

    @property
    def direct_entry_points(self) -> list[EntryPoint]:
        return [ep for ep in self.entry_points if ep.is_direct]

    @property
    def indirect_entry_points(self) -> list[EntryPoint]:
        return [ep for ep in self.entry_points if ep.is_indirect]

    @property
    def tool_names(self) -> list[str]:
        return [t.name for t in self.tools]


@dataclass
class SecurityConstraint:
    id: str
    text: str


@dataclass
class LossAnalysis:
    losses: list[dict[str, Any]]
    hazards: list[dict[str, Any]]
    security_constraints: list[SecurityConstraint]


@dataclass
class ScenarioEnvelope:
    scenario_id: str
    scenario_spec: dict[str, Any]
    narrative: str
    attack_tree: dict[str, Any]
    gherkin_spec: dict[str, Any]
    ica_type: str
    target_responsibility: str
    catalog_mappings: list[dict[str, Any]]
    provenance: str
    raw: dict[str, Any]

    @property
    def attacker_bdi(self) -> dict[str, Any]:
        return self.scenario_spec.get("attacker_bdi", {})

    @property
    def defender_bdi(self) -> dict[str, Any]:
        return self.scenario_spec.get("defender_bdi", {})

    @property
    def loss_scenario(self) -> str:
        return self.scenario_spec.get("loss_scenario", "")

    @property
    def attack_leaves(self) -> list[str]:
        leaves = self.attack_tree.get("leaves", [])
        if leaves:
            return leaves
        root = self.attack_tree.get("root")
        if isinstance(root, dict):
            return _extract_tree_leaves(root)
        return []

    @property
    def gherkin_when(self) -> list[str]:
        return self.gherkin_spec.get("when", [])

    @property
    def gherkin_then_expected(self) -> list[str]:
        return self.gherkin_spec.get("then_expected", [])

    @property
    def gherkin_then_actual(self) -> list[str]:
        return self.gherkin_spec.get("then_actual", [])

    @property
    def gherkin_given(self) -> list[str]:
        return self.gherkin_spec.get("given", [])


@dataclass
class ForgeRun:
    """All artifacts from a single scenario-forge STPA-Sec run."""
    run_dir: Path
    capability_profile: CapabilityProfile
    loss_analysis: LossAnalysis
    scenarios: list[ScenarioEnvelope]
    run_manifest: dict[str, Any] = field(default_factory=dict)


def _extract_tree_leaves(node: dict) -> list[str]:
    """Walk an attack tree dict and collect leaf node labels."""
    children = node.get("children", [])
    if not children:
        label = node.get("label", "")
        return [label] if label else []
    leaves: list[str] = []
    for child in children:
        if isinstance(child, dict):
            leaves.extend(_extract_tree_leaves(child))
    return leaves


def load_forge_run(run_dir: str | Path) -> ForgeRun:
    """Load all artifacts from a forge run directory."""
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise FileNotFoundError(f"Forge run directory not found: {run_dir}")

    profile = _load_capability_profile(run_dir / "capability-profile.yaml")
    loss = _load_loss_analysis(run_dir / "loss-analysis.yaml")
    scenarios = _load_scenarios(run_dir / "scenarios")
    manifest = _load_yaml(run_dir / "run-manifest.yaml")

    logger.info(
        "loaded forge run: %d scenarios, %d tools, %d entry points, %d constraints",
        len(scenarios), len(profile.tools), len(profile.entry_points),
        len(loss.security_constraints),
    )
    return ForgeRun(
        run_dir=run_dir,
        capability_profile=profile,
        loss_analysis=loss,
        scenarios=scenarios,
        run_manifest=manifest,
    )


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def _load_capability_profile(path: Path) -> CapabilityProfile:
    raw = _load_yaml(path)
    entry_points = [
        EntryPoint(
            name=ep.get("name", ""),
            entry_point_type=ep.get("entry_point_type", ""),
            direction=ep.get("direction", ""),
            controllability=ep.get("controllability", ""),
            ingress_zone=ep.get("ingress_zone"),
            entry_point_id=ep.get("entry_point_id", ""),
        )
        for ep in raw.get("entry_points", [])
    ]
    tools = [
        Tool(
            name=t.get("name", ""),
            description=t.get("description", ""),
            tool_id=t.get("tool_id", ""),
        )
        for t in raw.get("tool_inventory", [])
    ]
    return CapabilityProfile(
        zones_active=raw.get("zones_active", []),
        entry_points=entry_points,
        tools=tools,
        kc_subcodes=raw.get("kc_subcodes", []),
    )


def _load_loss_analysis(path: Path) -> LossAnalysis:
    raw = _load_yaml(path)
    constraints = []
    for sc in raw.get("security_constraints", []):
        if isinstance(sc, dict):
            constraints.append(SecurityConstraint(
                id=sc.get("id", sc.get("sc_id", sc.get("constraint_id", ""))),
                text=sc.get("text", sc.get("constraint", sc.get("description", ""))),
            ))
        elif isinstance(sc, str):
            constraints.append(SecurityConstraint(id="", text=sc))
    return LossAnalysis(
        losses=raw.get("losses", []),
        hazards=raw.get("hazards", []),
        security_constraints=constraints,
    )


def _load_scenarios(scenarios_dir: Path) -> list[ScenarioEnvelope]:
    if not scenarios_dir.is_dir():
        return []
    scenarios = []
    for yaml_file in sorted(scenarios_dir.glob("*.yaml")):
        if yaml_file.name.startswith("."):
            continue
        raw = _load_yaml(yaml_file)
        if not raw or "scenario_id" not in raw:
            continue
        envelope = _parse_scenario_envelope(raw)
        if envelope:
            scenarios.append(envelope)
    return scenarios


def _parse_scenario_envelope(raw: dict) -> ScenarioEnvelope | None:
    """Parse a scenario YAML into a normalized ScenarioEnvelope.

    Handles both STPA format (SCN-001 with scenario_spec/gherkin_spec) and
    non-STPA/taxonomy format (AP-T7-01 with actor_profile/behavior_spec).
    """
    scenario_id = raw.get("scenario_id", "")

    if "scenario_spec" in raw:
        return _parse_stpa_envelope(raw)
    if "actor_profile" in raw or "scenario_seed_metadata" in raw:
        return _parse_taxonomy_envelope(raw)

    logger.warning("unrecognized scenario format for %s, skipping", scenario_id)
    return None


def _parse_stpa_envelope(raw: dict) -> ScenarioEnvelope:
    """Parse STPA-Sec ScenarioEnvelope (SCN-NNN format)."""
    return ScenarioEnvelope(
        scenario_id=raw.get("scenario_id", ""),
        scenario_spec=raw.get("scenario_spec", {}),
        narrative=raw.get("narrative", ""),
        attack_tree=raw.get("attack_tree", {}),
        gherkin_spec=raw.get("gherkin_spec", {}),
        ica_type=raw.get("ica_type", ""),
        target_responsibility=raw.get("target_responsibility", ""),
        catalog_mappings=raw.get("catalog_mappings", []),
        provenance=raw.get("provenance", ""),
        raw=raw,
    )


def _parse_taxonomy_envelope(raw: dict) -> ScenarioEnvelope:
    """Parse taxonomy/risk-driven ScenarioEnvelope (AP-* format).

    Normalizes into the same ScenarioEnvelope structure by mapping:
    - actor_profile → scenario_spec.attacker_bdi
    - narrative.summary + steps → narrative (string)
    - behavior_spec (raw Gherkin string) → gherkin_spec (parsed)
    - faceting.risk_card → loss_scenario
    - attack_tree leaves → attack_leaves
    """
    actor = raw.get("actor_profile", {})
    narrative_raw = raw.get("narrative", {})
    faceting = raw.get("faceting", {})
    risk_card = faceting.get("risk_card", {})
    meta = raw.get("scenario_seed_metadata", {})

    # Build normalized narrative string
    if isinstance(narrative_raw, dict):
        narrative_parts = [narrative_raw.get("summary", "")]
        for step in narrative_raw.get("steps", []):
            narrative_parts.append(f"Step {step.get('step_number', '?')} ({step.get('zone', '?')}): {step.get('action', '')}")
        narrative_str = "\n".join(narrative_parts)
    else:
        narrative_str = str(narrative_raw)

    # Build normalized gherkin_spec from behavior_spec
    gherkin_spec = _parse_behavior_spec_to_gherkin(raw.get("behavior_spec", ""))

    # Build normalized scenario_spec (attacker/defender BDI)
    scenario_spec = {
        "attacker_bdi": {
            "beliefs": actor.get("beliefs", []),
            "desires": actor.get("desires", []),
            "intentions": actor.get("intentions", []),
        },
        "defender_bdi": {
            "intentions": [
                {"content": step.get("effect", "")}
                for step in narrative_raw.get("steps", [])
                if step.get("zone") == "tool_execution"
            ] if isinstance(narrative_raw, dict) else [],
        },
        "loss_scenario": f"{risk_card.get('consequence', '')} {risk_card.get('impact', '')}".strip(),
        "catalog_context": [],
    }

    # Extract catalog mappings from taxonomy chain
    taxonomy = faceting.get("taxonomy_chain", {})
    catalog_mappings = []
    for atlas_id in taxonomy.get("atlas_technique_ids", []):
        catalog_mappings.append({"catalog": "ATLAS", "id": atlas_id})
    for threat_id in taxonomy.get("agentic_threat_ids", []):
        catalog_mappings.append({"catalog": "OWASP_AGENTIC", "id": threat_id})

    # Walk attack tree for leaves
    attack_tree = raw.get("attack_tree", {})

    return ScenarioEnvelope(
        scenario_id=raw.get("scenario_id", ""),
        scenario_spec=scenario_spec,
        narrative=narrative_str,
        attack_tree=attack_tree,
        gherkin_spec=gherkin_spec,
        ica_type=meta.get("threat_name", ""),
        target_responsibility=meta.get("mechanism_name", ""),
        catalog_mappings=catalog_mappings,
        provenance="taxonomy",
        raw=raw,
    )


def _parse_behavior_spec_to_gherkin(spec: Any) -> dict[str, list[str]]:
    """Parse a behavior_spec (raw Gherkin string or structured) into gherkin_spec format."""
    if isinstance(spec, dict):
        return spec

    if not isinstance(spec, str) or not spec.strip():
        return {"given": [], "when": [], "then_expected": [], "then_actual": []}

    given, when, then_expected, then_actual = [], [], [], []
    for line in spec.strip().split("\n"):
        line = line.strip()
        if line.startswith("Given ") or (line.startswith("And ") and given and not when):
            given.append(line)
        elif line.startswith("When "):
            when.append(line)
        elif line.startswith("Then "):
            then_expected.append(line)
        elif line.startswith("But "):
            then_actual.append(line)
        elif line.startswith("And ") and then_actual:
            then_actual.append(line)
        elif line.startswith("And ") and then_expected:
            then_expected.append(line)
        elif line.startswith("And ") and when:
            when.append(line)

    return {"given": given, "when": when, "then_expected": then_expected, "then_actual": then_actual}
