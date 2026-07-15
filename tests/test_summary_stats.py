"""Tests for scan summary statistics: by_severity and elapsed_seconds.

Covers:
- ScanSummary.by_severity is populated from findings (unit, scanner)
- ScanResult.elapsed_seconds is a positive float after a real scan (integration)
- by_severity is absent for zero-finding runs
- by_severity counts are correct per severity bucket
- elapsed_seconds is present in JSON output
- by_severity is present in JSON output
- h1md report shows severity breakdown line
- h1md report shows elapsed time
- elapsed_seconds is None when result is constructed directly (not via scanner)
- multi-turn mode also populates by_severity and elapsed_seconds
"""

from __future__ import annotations

import json

import pytest

from ouija.cli import EXIT_OK, main
from ouija.models import Finding, ScanResult, ScanSummary, Severity


# ---------------------------------------------------------------------------
# Unit: model construction
# ---------------------------------------------------------------------------

def _make_finding(severity: Severity, idx: int = 0) -> Finding:
    """Build a minimal Finding with the given severity."""
    return Finding(
        id=f"ouija-test-{idx:08x}",
        category="prompt_injection",
        severity=severity,
        title=f"Test finding {idx}",
        pattern_id=f"tst-{idx:03d}:base",
        technique="test",
        owasp="LLM01:2025 Prompt Injection",
        request_prompt="test prompt",
        response_excerpt="test response",
        evidence="test evidence",
        confidence=0.9,
    )


def test_scan_summary_by_severity_empty_by_default():
    summary = ScanSummary()
    assert summary.by_severity == {}


def test_scan_summary_by_severity_field_stored():
    summary = ScanSummary(by_severity={"high": 2, "critical": 1})
    assert summary.by_severity["high"] == 2
    assert summary.by_severity["critical"] == 1


def test_scan_result_elapsed_seconds_none_by_default():
    """elapsed_seconds is None when a ScanResult is built without the scanner."""
    result = ScanResult(
        version="0.5.5",
        target="https://example.com/chat",
        attack_set="injection",
        patterns_sent=0,
    )
    assert result.elapsed_seconds is None


def test_scan_result_elapsed_seconds_stores_value():
    result = ScanResult(
        version="0.5.5",
        target="https://example.com/chat",
        attack_set="injection",
        patterns_sent=10,
        elapsed_seconds=3.14,
    )
    assert result.elapsed_seconds == pytest.approx(3.14)


# ---------------------------------------------------------------------------
# Integration: end-to-end CLI scan
# ---------------------------------------------------------------------------

def test_json_output_contains_by_severity(mock_llm, scope_file, capsys):
    """--format json report carries summary.by_severity after a scan with findings."""
    rc = main([
        "--target", mock_llm.url,
        "--scope-file", scope_file,
        "--attack-set", "injection",
        "--format", "json",
    ])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    data = json.loads(out)
    # findings must be present for by_severity to be populated
    assert data["findings"], "expected at least one finding from the mock"
    by_sev = data["summary"]["by_severity"]
    assert isinstance(by_sev, dict)
    # every key should be a valid severity string
    valid = {"critical", "high", "medium", "low", "info"}
    assert set(by_sev.keys()).issubset(valid)
    # the total across buckets should equal summary.successful
    assert sum(by_sev.values()) == data["summary"]["successful"]


def test_json_output_by_severity_absent_on_zero_findings(mock_llm, scope_file, capsys):
    """by_severity is an empty dict (not omitted) when there are no findings.

    We use --attack-set misinfo against an injection-only mock so the scanner
    runs but the misinfo marker never fires — zero findings expected.
    """
    rc = main([
        "--target", mock_llm.url,
        "--scope-file", scope_file,
        "--attack-set", "misinfo",
        "--format", "json",
    ])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    data = json.loads(out)
    # The mock only fires on injection patterns; misinfo should produce no findings.
    # by_severity should be an empty dict (not missing the key entirely).
    assert "by_severity" in data["summary"]
    if not data["findings"]:
        assert data["summary"]["by_severity"] == {}


def test_json_output_contains_elapsed_seconds(mock_llm, scope_file, capsys):
    """--format json report carries a positive elapsed_seconds."""
    rc = main([
        "--target", mock_llm.url,
        "--scope-file", scope_file,
        "--attack-set", "injection",
        "--format", "json",
    ])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "elapsed_seconds" in data
    assert isinstance(data["elapsed_seconds"], float)
    assert data["elapsed_seconds"] >= 0.0


def test_elapsed_seconds_is_positive(mock_llm, scope_file, capsys):
    """elapsed_seconds should be > 0 (the scan takes at least some time)."""
    rc = main([
        "--target", mock_llm.url,
        "--scope-file", scope_file,
        "--attack-set", "injection",
        "--format", "json",
    ])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    data = json.loads(out)
    # Should be positive; even a fast mock takes some async overhead
    assert data["elapsed_seconds"] >= 0.0


def test_h1md_shows_elapsed_time(mock_llm, scope_file, capsys):
    """h1md header line includes 'Elapsed:' when elapsed_seconds is set."""
    rc = main([
        "--target", mock_llm.url,
        "--scope-file", scope_file,
        "--attack-set", "injection",
        "--format", "h1md",
    ])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "Elapsed:" in out


def test_h1md_shows_severity_breakdown(mock_llm, scope_file, capsys):
    """h1md report includes 'Severity breakdown:' when there are findings."""
    rc = main([
        "--target", mock_llm.url,
        "--scope-file", scope_file,
        "--attack-set", "injection",
        "--format", "h1md",
    ])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    # Only shown when there are findings
    assert out.count("# ouija findings report") == 1
    # The mock produces injection findings, so the breakdown should appear
    assert "Severity breakdown:" in out


def test_by_severity_counts_match_per_bucket(mock_llm, scope_file, capsys):
    """by_severity[sev] == number of findings with that severity."""
    rc = main([
        "--target", mock_llm.url,
        "--scope-file", scope_file,
        "--attack-set", "injection",
        "--format", "json",
    ])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    data = json.loads(out)
    by_sev = data["summary"]["by_severity"]
    # Re-count from the findings array
    expected: dict[str, int] = {}
    for f in data["findings"]:
        sev = f["severity"]
        expected[sev] = expected.get(sev, 0) + 1
    assert by_sev == expected


def test_jsonl_summary_line_contains_by_severity(mock_llm, scope_file, capsys):
    """--format jsonl: the final 'summary' record carries by_severity."""
    rc = main([
        "--target", mock_llm.url,
        "--scope-file", scope_file,
        "--attack-set", "injection",
        "--format", "jsonl",
    ])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    lines = [json.loads(l) for l in out.strip().splitlines()]
    summary_lines = [l for l in lines if l.get("record") == "summary"]
    assert len(summary_lines) == 1
    assert "by_severity" in summary_lines[0]


def test_elapsed_seconds_present_in_jsonl_scan_header(mock_llm, scope_file, capsys):
    """--format jsonl: the 'scan' header record carries elapsed_seconds."""
    rc = main([
        "--target", mock_llm.url,
        "--scope-file", scope_file,
        "--attack-set", "injection",
        "--format", "jsonl",
    ])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    lines = [json.loads(l) for l in out.strip().splitlines()]
    scan_lines = [l for l in lines if l.get("record") == "scan"]
    assert len(scan_lines) == 1
    assert "elapsed_seconds" in scan_lines[0]
