"""The attack library: catalog of attack techniques (vehicles) and payload sets.

``AttackLibrary`` is the generic catalog mechanism; ``DEFAULT_LIBRARY`` is the
instance every suite resolves against, populated from ``attacks.builtin``
(vehicles) and the vendored corpora in ``attacks/data`` (payload sets).

Suites reference a vehicle by id through a probe's ``attack_type`` and a
payload set through a probe's ``source``; both resolve once at suite-load time
in ``YAMLTaskSuite._parse_probes``, so probes hold final, ready-to-substitute
strings. A ``source`` string is either ``file:<path>`` (a JSON file resolved
relative to the suite directory) or a payload-set id looked up here
(``builtin:<name>``, ``garak:<name>``).
"""

from __future__ import annotations

import json
from pathlib import Path

from midojo.attacks.builtin import BUILTIN_TECHNIQUES
from midojo.attacks.records import AttackTechnique, Origin, PayloadSet
from midojo.attacks.taxonomy import ASICategory, parse_asi_category

_BUILTIN_IDS = {t.id for t in BUILTIN_TECHNIQUES}


def _load_external_techniques() -> list[AttackTechnique]:
    """Import wrappers from the redteam-attacks package if installed."""
    try:
        from redteam_attacks import ALL_WRAPPERS
    except ImportError:
        return []
    return [
        AttackTechnique(id=w.id, wrapper=w.fn, description=w.description)
        for w in ALL_WRAPPERS
        if w.id not in _BUILTIN_IDS
    ]

_DATA_DIR = Path(__file__).parent / "data"
_FILE_SCHEME = "file:"


class AttackLibrary:
    """In-memory catalog of attack techniques and payload sets, keyed by id."""

    def __init__(
        self,
        techniques: list[AttackTechnique] | None = None,
        payload_sets: list[PayloadSet] | None = None,
    ) -> None:
        self._techniques: dict[str, AttackTechnique] = {}
        self._payload_sets: dict[str, PayloadSet] = {}
        for technique in techniques or []:
            self.register(technique)
        for payload_set in payload_sets or []:
            self.register_payload_set(payload_set)

    def register(self, technique: AttackTechnique) -> None:
        if technique.id in self._techniques:
            raise ValueError(f"Attack technique '{technique.id}' is already registered")
        self._techniques[technique.id] = technique

    def get(self, technique_id: str) -> AttackTechnique:
        if technique_id not in self._techniques:
            raise ValueError(f"Unsupported attack_type '{technique_id}'. Supported: {sorted(self._techniques)}")
        return self._techniques[technique_id]

    def ids(self) -> list[str]:
        return sorted(self._techniques)

    def wrap_payload(self, payload: str, technique_id: str) -> str:
        """Apply the named vehicle to a payload."""
        return self.get(technique_id).wrapper(payload)

    def register_payload_set(self, payload_set: PayloadSet) -> None:
        if payload_set.id in self._payload_sets:
            raise ValueError(f"Payload set '{payload_set.id}' is already registered")
        self._payload_sets[payload_set.id] = payload_set

    def get_payload_set(self, set_id: str) -> PayloadSet:
        if set_id not in self._payload_sets:
            raise ValueError(f"Unknown payload set '{set_id}'. Known: {sorted(self._payload_sets)}")
        return self._payload_sets[set_id]

    def payload_set_ids(self) -> list[str]:
        return sorted(self._payload_sets)

    def by_asi(self, category: str | ASICategory) -> list[PayloadSet]:
        """Payload sets exercising the given OWASP ASI risk category."""
        category = parse_asi_category(category)
        return [s for _, s in sorted(self._payload_sets.items()) if category in s.asi_categories]


def load_payload_set_file(path: Path) -> PayloadSet:
    """Load a payload set from a JSON file.

    Accepts both MiDojo's payload-set shape and Garak's raw payload shape
    (``garak_payload_name`` + ``payloads``), so a probe can point straight at a
    file from a Garak checkout.
    """
    raw = json.loads(path.read_text())
    if "garak_payload_name" in raw:
        return PayloadSet(
            id=f"file:{path.name}",
            payloads=tuple(raw["payloads"]),
            description=raw["garak_payload_name"],
            origin=Origin(kind="file", path=path.name),
        )
    raw.setdefault("origin", {"kind": "file", "path": path.name})
    return PayloadSet.model_validate(raw)


def _load_vendored_payload_sets() -> list[PayloadSet]:
    return [load_payload_set_file(path) for path in sorted(_DATA_DIR.glob("*.json"))]


# The default library every suite resolves against.
DEFAULT_LIBRARY = AttackLibrary(
    BUILTIN_TECHNIQUES + _load_external_techniques(),
    _load_vendored_payload_sets(),
)


def resolve_source(
    source: str,
    *,
    library: AttackLibrary = DEFAULT_LIBRARY,
    base_dir: Path | None = None,
) -> PayloadSet:
    """Resolve a probe ``source:`` string to a payload set."""
    if source.startswith(_FILE_SCHEME):
        path = Path(source.removeprefix(_FILE_SCHEME))
        if not path.is_absolute():
            path = (base_dir or Path.cwd()) / path
        if not path.is_file():
            raise ValueError(f"Payload set file not found: {path}")
        return load_payload_set_file(path)
    return library.get_payload_set(source)


def wrap_payload(payload: str, attack_type: str) -> str:
    """Apply the named attack_type vehicle from the default library."""
    return DEFAULT_LIBRARY.wrap_payload(payload, attack_type)
