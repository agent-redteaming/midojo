"""Catalog record shapes for the attack library.

The library holds two kinds of entry (issue #36):

* **Vehicles** — *how* you attack: a `Callable[[str], str]` that wraps a payload
  (the cargo) in a delivery technique. ``AttackTechnique`` below.
* **Payload sets** — *what* you say: a corpus of payload strings (e.g. Garak's
  hijack strings) that a suite probe draws from. ``PayloadSet`` below.

Both carry an ``Origin`` recording where the material came from, so imported
attacks keep attribution. OWASP ASI categorization (see ``attacks.taxonomy``)
is a property of the *harm* an attack probes for, so it lives on the payload
set (the cargo) — not on the vehicle, which is a category-agnostic delivery
mechanism.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from midojo.attacks.taxonomy import ASICategory

# A vehicle: take a payload (cargo), return the wrapped payload.
PayloadWrapper = Callable[[str], str]

# Upstream repos we vendor from; vendored kinds must pin commit + path.
_VENDORED_REPO_URLS: dict[str, str] = {
    "garak": "https://github.com/NVIDIA/garak",
    "agentdojo": "https://github.com/ethz-spylab/agentdojo",
}


class Origin(BaseModel):
    """Where a catalog entry's material came from."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["builtin", "garak", "agentdojo", "file", "pyrit"] = Field(
        description=(
            "'builtin' = hand-written in this repo; 'garak'/'agentdojo' = vendored "
            "from that upstream repo; 'file' = loaded from a user file at suite-load time; "
            "'pyrit' = technique provided by PyRIT integration."
        )
    )
    path: str | None = Field(
        default=None,
        description="Repo-relative path of the vendored material, or the loaded file's name for kind 'file'.",
    )
    commit: str | None = Field(
        default=None,
        description="Upstream git commit the material was copied at (vendored kinds only).",
    )

    @model_validator(mode="after")
    def _require_pin_for_kind(self) -> Origin:
        if self.kind in _VENDORED_REPO_URLS and not (self.path and self.commit):
            raise ValueError(f"Origin kind '{self.kind}' is vendored and requires 'path' and 'commit'")
        if self.kind == "file" and not self.path:
            raise ValueError("Origin kind 'file' requires 'path'")
        return self

    @computed_field
    @property
    def uri(self) -> str:
        """Compact provenance string, e.g. ``garak@<commit>:<path>``."""
        pin = f"@{self.commit}" if self.commit else ""
        location = f":{self.path}" if self.path else ""
        return f"{self.kind}{pin}{location}"

    @computed_field
    @property
    def url(self) -> str | None:
        """Browseable link to the exact upstream snapshot (vendored kinds only)."""
        repo_url = _VENDORED_REPO_URLS.get(self.kind)
        if repo_url is None:
            return None
        return f"{repo_url}/blob/{self.commit}/{self.path}"


BUILTIN_ORIGIN = Origin(kind="builtin")


class AttackTechnique(BaseModel):
    """A vehicle entry: a reusable wrapping technique plus its provenance.

    For static wrappers, ``wrapper`` transforms the payload string directly.
    For strategy-backed techniques (PyRIT), ``wrapper`` is typically identity
    and ``strategy_config`` carries the PyRIT execution configuration.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="The name suites reference via a probe's `attack_type`.")
    wrapper: PayloadWrapper = Field(description="Wraps a payload (the cargo) in the delivery technique.")
    description: str = Field(description="What the delivery technique does.")
    origin: Origin = Field(default=BUILTIN_ORIGIN, description="Where the technique came from.")
    references: tuple[str, ...] = Field(default=(), description="Links to the originating research or tooling.")
    license: str | None = Field(default=None, description="License of the upstream material, if imported.")
    strategy_config: dict | None = Field(
        default=None,
        description="PyRIT strategy config for adaptive techniques. When set, the orchestrator dispatches to PyRIT.",
    )


class PayloadSet(BaseModel):
    """A payload-set entry: a corpus of payload strings plus its provenance."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="The name suites reference via a probe's `source` (e.g. 'garak:hijack_hate_humans').")
    payloads: tuple[str, ...] = Field(description="The corpus of payload strings a probe draws from.")
    description: str = Field(description="What the payloads try to make the agent do.")
    origin: Origin = Field(default=BUILTIN_ORIGIN, description="Where the corpus came from.")
    asi_categories: tuple[ASICategory, ...] = Field(
        default=(),
        description="OWASP ASI risk categories the payloads exercise, so the catalog can be queried by risk.",
    )
    references: tuple[str, ...] = Field(default=(), description="Links to the originating research or tooling.")
    license: str | None = Field(default=None, description="License of the upstream material, if imported.")
