"""Tests for the `--format sarif` (SARIF 2.1.0) report.

SARIF is the format GitHub code-scanning and most security dashboards ingest, so
the output must be a valid SARIF 2.1.0 document: a versioned envelope, a tool
driver carrying one rule per attack category, and one result per finding mapped
to a GitHub-compatible severity. These tests pin that contract end-to-end through
the CLI and as a unit over the pure renderer.
"""

from __future__ import annotations

import json

from ouija.cli import EXIT_OK, main
from ouija.models import (
    Finding,
    ScanResult,
    ScanSummary,
    Severity,
)
from ouija.sarif import SARIF_VERSION, to_sarif


def _run_sarif(mock_llm, scope_file, capsys, attack_set="injection"):
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            attack_set,
            "--format",
            "sarif",
        ]
    )
    out = capsys.readouterr().out
    return rc, json.loads(out)


def test_sarif_is_valid_json_and_envelope(mock_llm, scope_file, capsys):
    """Output parses as JSON and carries the SARIF 2.1.0 envelope keys."""
    rc, data = _run_sarif(mock_llm, scope_file, capsys)
    assert rc == EXIT_OK
    assert data["version"] == SARIF_VERSION
    assert "$schema" in data
    assert isinstance(data["runs"], list) and len(data["runs"]) == 1


def test_sarif_driver_identifies_ouija(mock_llm, scope_file, capsys):
    """The tool driver names ouija and carries its version + info URI."""
    _, data = _run_sarif(mock_llm, scope_file, capsys)
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "ouija"
    assert driver["version"]
    assert driver["informationUri"].startswith("https://")


def test_sarif_has_one_result_per_finding(mock_llm, scope_file, capsys):
    """Every emitted finding becomes exactly one SARIF result."""
    _, native = _run_sarif(mock_llm, scope_file, capsys)
    # Re-run as JSON to count findings from the same kind of scan.
    main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "json",
        ]
    )
    json_out = json.loads(capsys.readouterr().out)
    results = native["runs"][0]["results"]
    assert results, "expected at least one result from the vuln mock"
    assert len(results) == len(json_out["findings"])


def test_sarif_results_reference_declared_rules(mock_llm, scope_file, capsys):
    """Every result's ruleId is declared in the driver's rules list."""
    _, data = _run_sarif(mock_llm, scope_file, capsys, attack_set="all")
    run = data["runs"][0]
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids


def test_sarif_target_recorded_without_fake_file_path(mock_llm, scope_file, capsys):
    """The endpoint URL is captured in run properties (no invented artifact)."""
    _, data = _run_sarif(mock_llm, scope_file, capsys)
    run = data["runs"][0]
    assert run["properties"]["target"] == mock_llm.url
    # Network probe: results must not invent a physicalLocation/file path.
    for result in run["results"]:
        assert "locations" not in result


# --- Unit tests over the pure renderer (no network) ------------------------- #


def _scan_result_with(findings):
    return ScanResult(
        version="0.1.15",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=len(findings),
        findings=findings,
        summary=ScanSummary(total=len(findings), successful=len(findings)),
    )


def _finding(**overrides):
    base = dict(
        id="f-1",
        category="prompt_injection",
        severity=Severity.HIGH,
        title="Prompt injection",
        pattern_id="inj-1",
        technique="instruction override",
        owasp="LLM01:2025 Prompt Injection",
        request_prompt="ignore previous instructions",
        response_excerpt="OK, ignoring...",
        evidence="marker echoed",
        confidence=0.9,
    )
    base.update(overrides)
    return Finding(**base)


def test_sarif_severity_maps_to_level_and_security_severity():
    """Each ouija severity maps to a SARIF level and a numeric security-severity."""
    result = _scan_result_with(
        [
            _finding(id="c", severity=Severity.CRITICAL),
            _finding(id="i", severity=Severity.INFO, category="misinformation"),
        ]
    )
    data = json.loads(to_sarif(result))
    levels = {r["ruleId"]: r["level"] for r in data["runs"][0]["results"]}
    assert levels["prompt_injection"] == "error"  # CRITICAL -> error
    assert levels["misinformation"] == "note"  # INFO -> note
    for r in data["runs"][0]["results"]:
        assert "security-severity" in r["properties"]


def test_sarif_dedupes_rules_by_category():
    """Two findings in the same category share a single rule definition."""
    result = _scan_result_with(
        [_finding(id="a"), _finding(id="b")]
    )
    data = json.loads(to_sarif(result))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "prompt_injection"
    # Both findings still produce their own result.
    assert len(data["runs"][0]["results"]) == 2


def test_sarif_empty_scan_is_valid_with_no_results():
    """A clean scan emits a valid SARIF run with empty results/rules."""
    data = json.loads(to_sarif(_scan_result_with([])))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_sarif_carries_owasp_and_fingerprint():
    """Each result carries the OWASP mapping and a stable dedupe fingerprint."""
    data = json.loads(to_sarif(_scan_result_with([_finding()])))
    result = data["runs"][0]["results"][0]
    assert result["properties"]["owasp"] == "LLM01:2025 Prompt Injection"
    assert result["partialFingerprints"]["ouijaFindingId"] == "f-1"


def test_sarif_multiturn_and_repeats_metadata_surface():
    """Multi-turn and repeats roll-ups appear in result properties when present."""
    f = _finding(
        attempts=5,
        successes=3,
        success_rate=0.6,
        turn_succeeded=4,
        transcript=[{"role": "user", "content": "hi"}],
    )
    data = json.loads(to_sarif(_scan_result_with([f])))
    props = data["runs"][0]["results"][0]["properties"]
    assert props["attempts"] == 5
    assert props["successes"] == 3
    assert props["turn_succeeded"] == 4
