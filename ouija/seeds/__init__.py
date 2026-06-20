"""Seed corpora — versioned attack payloads keyed by OWASP taxonomy (Packet 02 Appendix E).

Seeds are *data*, not hardcoded module logic. Each seed carries its ASI/LLM
mapping, the compatible target, a render template with ``{canary}`` / ``{oob}``
placeholders, and the effect(s) it expects.

PROVENANCE / ADAPTATION: Packet 02 Appendix E sketches seeds as YAML. ouija's
venv has no YAML dependency and the existing corpus convention (``ouija/corpus``)
is JSON, so seeds ship as JSON to stay dependency-free and consistent. Behavioral
seeds are *derived from* the public AgentDojo / InjecAgent / BIPIA task pairs —
cited in each file's ``_source`` header; they are not claimed as original
research. All payloads are inert: markers/canaries stand in for a real effect and
the OOB collector is local (§15).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources


@dataclass
class Seed:
    """One attack seed (Appendix E schema).

    Attributes:
        name: stable identifier.
        asi/llm: OWASP category ids.
        target: which adapter kind this seed drives (rag/agent/mcp/raw_llm).
        template: payload text with ``{canary}`` / ``{oob}`` placeholders.
        effect_expected: the effect type(s) a vulnerable target should exhibit.
        trigger_query: for RAG seeds — the benign query that should retrieve the
            planted document.
        technique: short label for reporting.
    """

    name: str
    asi: str
    llm: str
    target: str
    template: str
    effect_expected: list[str] = field(default_factory=list)
    trigger_query: str = ""
    technique: str = ""

    def render(self, *, canary: str = "", oob: str = "") -> str:
        """Fill the template's ``{canary}`` / ``{oob}`` placeholders."""
        return self.template.replace("{canary}", canary).replace("{oob}", oob)


def load_seeds(name: str) -> list[Seed]:
    """Load the seed list from ``ouija/seeds/<name>.json``."""
    raw = resources.files("ouija.seeds").joinpath(f"{name}.json").read_text(
        encoding="utf-8"
    )
    blob = json.loads(raw)
    return [Seed(**s) for s in blob["seeds"]]


def seed_sets() -> list[str]:
    """The available seed-set names (files in this package, sans extension)."""
    out: list[str] = []
    for entry in resources.files("ouija.seeds").iterdir():
        n = entry.name
        if n.endswith(".json"):
            out.append(n[:-5])
    return sorted(out)
