"""Bridge PyRIT's jailbreak templates and research datasets to MiDojo PayloadSets.

Loads PyRIT's 653 jailbreak templates and exposes them as MiDojo PayloadSet
entries, so suite YAML can reference them via ``source: "pyrit:jailbreak"``
or ``source: "pyrit:jailbreak:in_the_wild"``.

Usage::

    from midojo.attacks.pyrit.datasets import register_pyrit_datasets

    register_pyrit_datasets()  # call once, idempotent

Then in suite YAML::

    probes:
      main:
        source: "pyrit:jailbreak"        # all 653 templates
        index: 42                          # pick one by index
      alt:
        source: "pyrit:jailbreak:Arth_Singh"  # 30 templates from Arth Singh

Requires ``pyrit`` — install with ``pip install midojo[pyrit]``.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

logger = logging.getLogger("midojo.pyrit.datasets")

_REGISTERED = False


def _load_jailbreak_payloads(templates_dir: Path) -> dict[str, list[str]]:
    """Load all jailbreak templates grouped by source directory."""
    groups: dict[str, list[str]] = {"all": []}

    for yaml_file in sorted(templates_dir.rglob("*.yaml")):
        try:
            raw = yaml.safe_load(yaml_file.read_text())
            value = raw.get("value", "")
            if not value or not isinstance(value, str):
                continue

            group = yaml_file.parent.name if yaml_file.parent != templates_dir else "core"
            groups.setdefault(group, [])
            groups[group].append(value)
            groups["all"].append(value)
        except Exception:
            continue

    return groups


def register_pyrit_datasets() -> None:
    """Register PyRIT jailbreak templates as MiDojo PayloadSets.

    Creates payload sets:
    - ``pyrit:jailbreak`` — all templates
    - ``pyrit:jailbreak:<source>`` — per-source subsets

    Safe to call multiple times — idempotent after first registration.
    """
    global _REGISTERED
    if _REGISTERED:
        return
    _REGISTERED = True

    try:
        import pyrit
    except ImportError:
        logger.debug("PyRIT not installed, skipping dataset registration")
        return

    from midojo.attacks.records import Origin, PayloadSet
    from midojo.attacks.registry import DEFAULT_LIBRARY

    templates_dir = Path(pyrit.__file__).parent / "datasets" / "jailbreak" / "templates"
    if not templates_dir.exists():
        logger.warning("PyRIT jailbreak templates directory not found: %s", templates_dir)
        return

    groups = _load_jailbreak_payloads(templates_dir)
    pyrit_origin = Origin(kind="pyrit")
    registered = 0

    for group_name, payloads in groups.items():
        if not payloads:
            continue

        set_id = "pyrit:jailbreak" if group_name == "all" else f"pyrit:jailbreak:{group_name}"
        payload_set = PayloadSet(
            id=set_id,
            payloads=tuple(payloads),
            description=f"PyRIT jailbreak templates ({group_name}, {len(payloads)} templates)",
            origin=pyrit_origin,
        )
        try:
            DEFAULT_LIBRARY.register_payload_set(payload_set)
            registered += 1
        except ValueError:
            pass

    logger.info("registered %d PyRIT jailbreak payload sets (%d total templates)", registered, len(groups.get("all", [])))
