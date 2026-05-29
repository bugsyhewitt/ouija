"""Tests for structured, deterministic finding IDs.

A bug-bounty finding's ID must be *stable*: the same logical finding has to
produce the same ID on every scan so triagers can track it, so reruns dedupe
instead of duplicating, and so SARIF ``partialFingerprints`` let GitHub
code-scanning collapse repeat alerts. Before this change ouija minted a random
UUID per finding, which silently broke all three of those workflows.
"""

from __future__ import annotations

import json
import re

from ouija.cli import main
from ouija.detect import stable_finding_id

# ouija-<category-prefix>-<8 lowercase hex>
_ID_RE = re.compile(r"^ouija-[a-z]+-[0-9a-f]{8}$")


def _run_json(mock_llm, scope_file, capsys, attack_set="injection"):
    main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            attack_set,
            "--format",
            "json",
        ]
    )
    out = capsys.readouterr().out
    return json.loads(out)


# --- pure-function unit tests (no network) ---


def test_stable_id_is_deterministic():
    """Same identity tuple -> same ID, every call."""
    a = stable_finding_id("prompt_injection", "inj-1/base", "marker-echo", "LLM01")
    b = stable_finding_id("prompt_injection", "inj-1/base", "marker-echo", "LLM01")
    assert a == b


def test_stable_id_matches_documented_format():
    """ID is ``ouija-<category-prefix>-<8 hex>``."""
    fid = stable_finding_id("prompt_injection", "inj-1/base", "marker-echo", "LLM01")
    assert _ID_RE.match(fid), fid
    assert fid.startswith("ouija-inj-")


def test_stable_id_differs_when_identity_differs():
    """Different variant -> different ID (no collisions on distinct findings)."""
    base = stable_finding_id("prompt_injection", "inj-1/base", "marker-echo", "LLM01")
    other_variant = stable_finding_id(
        "prompt_injection", "inj-1/polite", "marker-echo", "LLM01"
    )
    other_category = stable_finding_id(
        "pii_disclosure", "inj-1/base", "marker-echo", "LLM01"
    )
    assert base != other_variant
    assert base != other_category


def test_stable_id_unknown_category_falls_back_to_find_prefix():
    """An unmapped category still produces a well-formed ID."""
    fid = stable_finding_id("brand_new_category", "x/base", "tech", "LLM99")
    assert fid.startswith("ouija-find-")
    assert _ID_RE.match(fid), fid


# --- end-to-end tests (through the scanner / CLI) ---


def test_finding_ids_are_stable_across_runs(mock_llm, scope_file, capsys):
    """The same scan, run twice, yields the same set of finding IDs."""
    first = _run_json(mock_llm, scope_file, capsys)
    second = _run_json(mock_llm, scope_file, capsys)
    assert first["findings"], "expected at least one finding from the vuln mock"
    first_ids = sorted(f["id"] for f in first["findings"])
    second_ids = sorted(f["id"] for f in second["findings"])
    assert first_ids == second_ids


def test_finding_ids_are_structured(mock_llm, scope_file, capsys):
    """Every emitted finding ID matches the structured format (not a raw UUID)."""
    data = _run_json(mock_llm, scope_file, capsys)
    assert data["findings"]
    for finding in data["findings"]:
        assert _ID_RE.match(finding["id"]), finding["id"]


def test_finding_ids_are_unique_within_a_scan(mock_llm, scope_file, capsys):
    """Distinct findings in one scan have distinct IDs (no accidental merge)."""
    data = _run_json(mock_llm, scope_file, capsys, attack_set="all")
    ids = [f["id"] for f in data["findings"]]
    assert len(ids) == len(set(ids)), f"duplicate finding IDs: {ids}"


def test_sarif_fingerprint_is_stable_across_runs(mock_llm, scope_file, capsys):
    """SARIF partialFingerprints.ouijaFindingId must be reproducible run-to-run.

    This is the whole point of a fingerprint: GitHub code-scanning uses it to
    recognise a result it has already seen and avoid re-opening the alert.
    """

    def _run_sarif():
        main(
            [
                "--target",
                mock_llm.url,
                "--scope-file",
                scope_file,
                "--attack-set",
                "injection",
                "--format",
                "sarif",
            ]
        )
        return json.loads(capsys.readouterr().out)

    first = _run_sarif()
    second = _run_sarif()
    first_fps = sorted(
        r["partialFingerprints"]["ouijaFindingId"]
        for r in first["runs"][0]["results"]
    )
    second_fps = sorted(
        r["partialFingerprints"]["ouijaFindingId"]
        for r in second["runs"][0]["results"]
    )
    assert first_fps, "expected at least one SARIF result"
    assert first_fps == second_fps
