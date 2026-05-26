"""Corpus tests (criterion 5: >=20 injection + >=10 disclosure patterns)."""

from __future__ import annotations

from ouija.corpus import load_attack_set


def test_injection_corpus_has_at_least_20_patterns():
    loaded = load_attack_set("injection")
    assert len(loaded.patterns) >= 20
    for p in loaded.patterns:
        assert loaded.meta[p.id]["category"] == "prompt_injection"


def test_disclosure_corpus_has_at_least_10_patterns():
    loaded = load_attack_set("disclosure")
    assert len(loaded.patterns) >= 10
    for p in loaded.patterns:
        assert loaded.meta[p.id]["category"] == "sensitive_info_disclosure"


def test_all_set_includes_injection_disclosure_and_dos():
    loaded = load_attack_set("all")
    categories = {loaded.meta[p.id]["category"] for p in loaded.patterns}
    assert "prompt_injection" in categories
    assert "sensitive_info_disclosure" in categories
    assert "model_dos" in categories


def test_patterns_carry_owasp_mapping():
    loaded = load_attack_set("injection")
    assert all(loaded.meta[p.id]["owasp"].startswith("LLM") for p in loaded.patterns)
