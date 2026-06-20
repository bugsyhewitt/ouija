"""Unit tests for the seed corpora (Appendix E)."""

from __future__ import annotations

from ouija.asitax import ASI, LLM
from ouija.seeds import Seed, load_seeds, seed_sets


def test_seed_sets_present():
    sets = seed_sets()
    for required in ("asi06_rag_behavioral", "asi01_tool_result",
                     "asi02_excessive_agency"):
        assert required in sets


def test_every_seed_is_well_formed_and_mapped():
    for name in seed_sets():
        seeds = load_seeds(name)
        assert seeds, f"{name} has no seeds"
        for s in seeds:
            assert isinstance(s, Seed)
            assert s.asi in ASI, f"{name}/{s.name} bad asi {s.asi}"
            assert s.llm in LLM, f"{name}/{s.name} bad llm {s.llm}"
            assert s.target in ("rag", "agent", "mcp", "raw_llm")
            assert s.effect_expected, f"{name}/{s.name} declares no expected effect"


def test_seed_render_fills_placeholders():
    seeds = load_seeds("asi06_rag_behavioral")
    s = seeds[0]
    out = s.render(canary="CAN-X", oob="http://127.0.0.1:1/c/CAN-X")
    assert "CAN-X" in out
    assert "{canary}" not in out and "{oob}" not in out


def test_seed_provenance_header_present():
    # Provenance must be cited (Appendix E) — the JSON carries a _source key.
    import json
    from importlib import resources

    for name in seed_sets():
        blob = json.loads(
            resources.files("ouija.seeds").joinpath(f"{name}.json").read_text()
        )
        assert "_source" in blob and blob["_source"]
