"""Attack corpus loader.

Loads hand-curated attack patterns shipped as JSON alongside this module.
Each corpus file carries its OWASP LLM Top 10 mapping and a default category.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Iterable

from ouija.models import AttackPattern

# Maps an --attack-set value to the corpus JSON files it draws from.
_SETS: dict[str, list[str]] = {
    "injection": ["injection.json"],
    "disclosure": ["disclosure.json"],
    "dos": ["dos.json"],
    "exfil": ["exfil.json"],
    "agency": ["agency.json"],
    "misinfo": ["misinfo.json"],
    "activecontent": ["activecontent.json"],
    "ragpoison": ["ragpoison.json"],
    "safetybypass": ["safetybypass.json"],
    "pii": ["pii.json"],
    "supplychain": ["supplychain.json"],
    "all": [
        "injection.json",
        "disclosure.json",
        "dos.json",
        "exfil.json",
        "agency.json",
        "misinfo.json",
        "activecontent.json",
        "ragpoison.json",
        "safetybypass.json",
        "pii.json",
        "supplychain.json",
    ],
}

ATTACK_SETS = tuple(_SETS.keys())


class LoadedSet:
    """A loaded attack set: patterns plus their shared category/owasp metadata."""

    def __init__(self, patterns: list[AttackPattern], meta: dict[str, dict[str, str]]):
        self.patterns = patterns
        # pattern.id -> {"category": ..., "owasp": ...}
        self.meta = meta


def _load_file(filename: str) -> dict:
    data = resources.files("ouija.corpus").joinpath(filename).read_text(
        encoding="utf-8"
    )
    return json.loads(data)


def load_attack_set(name: str) -> LoadedSet:
    """Load all patterns for a given attack-set name."""
    if name not in _SETS:
        raise ValueError(
            f"unknown attack set '{name}'; expected one of {sorted(_SETS)}"
        )
    patterns: list[AttackPattern] = []
    meta: dict[str, dict[str, str]] = {}
    for filename in _SETS[name]:
        blob = _load_file(filename)
        category = blob["category"]
        owasp = blob["owasp"]
        for raw in blob["patterns"]:
            pattern = AttackPattern(**raw)
            patterns.append(pattern)
            meta[pattern.id] = {"category": category, "owasp": owasp}
    return LoadedSet(patterns, meta)


def count_patterns(filenames: Iterable[str]) -> int:
    """Helper: total pattern count across the given corpus files."""
    return sum(len(_load_file(f)["patterns"]) for f in filenames)
