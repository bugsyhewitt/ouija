"""Tests for CI/CD severity gating (--fail-on).

Covers the pure gate helper and the CLI exit-code wiring. The gate must:
- never trip when --fail-on is "none" (default; backward compatible),
- trip when a finding is at or above the threshold,
- not trip when every finding is below the threshold,
- leave scope (2) and usage (3) errors taking precedence over the gate.
"""

from __future__ import annotations

import json

import pytest

from ouija.cli import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    EXIT_OUT_OF_SCOPE,
    main,
)
from ouija.gate import (
    FAIL_ON_CHOICES,
    FAIL_ON_NONE,
    findings_meet_threshold,
    gate_exit_code,
)
from ouija.models import Finding, ScanResult, Severity


def _finding(severity: Severity) -> Finding:
    return Finding(
        id=f"f-{severity.value}",
        category="prompt_injection",
        severity=severity,
        title="t",
        pattern_id="p",
        technique="tech",
        owasp="LLM01:2025 Prompt Injection",
        request_prompt="req",
        response_excerpt="resp",
        evidence="ev",
        confidence=0.9,
    )


def _result(*severities: Severity) -> ScanResult:
    return ScanResult(
        version="0.1.14",
        target="https://t.example/chat",
        attack_set="injection",
        patterns_sent=len(severities),
        findings=[_finding(s) for s in severities],
    )


# ---------------------------------------------------------------------------
# Pure gate helper
# ---------------------------------------------------------------------------

def test_fail_on_choices_contains_none_and_every_severity():
    assert FAIL_ON_NONE in FAIL_ON_CHOICES
    for sev in Severity:
        assert sev.value in FAIL_ON_CHOICES


def test_none_never_trips_even_with_critical():
    result = _result(Severity.CRITICAL)
    assert findings_meet_threshold(result, FAIL_ON_NONE) is False


def test_empty_findings_never_trips():
    result = _result()
    for choice in FAIL_ON_CHOICES:
        assert findings_meet_threshold(result, choice) is False


def test_trips_at_exact_threshold():
    result = _result(Severity.HIGH)
    assert findings_meet_threshold(result, "high") is True


def test_trips_above_threshold():
    result = _result(Severity.CRITICAL)
    assert findings_meet_threshold(result, "high") is True


def test_does_not_trip_below_threshold():
    result = _result(Severity.LOW, Severity.MEDIUM)
    assert findings_meet_threshold(result, "high") is False


def test_trips_when_any_finding_meets_threshold():
    result = _result(Severity.INFO, Severity.LOW, Severity.HIGH)
    assert findings_meet_threshold(result, "high") is True


@pytest.mark.parametrize(
    "threshold,expected",
    [
        ("info", True),
        ("low", True),
        ("medium", True),
        ("high", False),
        ("critical", False),
    ],
)
def test_threshold_ladder_against_medium_finding(threshold, expected):
    result = _result(Severity.MEDIUM)
    assert findings_meet_threshold(result, threshold) is expected


def test_gate_exit_code_maps_to_supplied_codes():
    tripped = _result(Severity.HIGH)
    clean = _result(Severity.LOW)
    assert gate_exit_code(tripped, "high", ok_code=0, findings_code=1) == 1
    assert gate_exit_code(clean, "high", ok_code=0, findings_code=1) == 0


def test_invalid_threshold_raises():
    with pytest.raises(ValueError):
        findings_meet_threshold(_result(Severity.HIGH), "bogus")


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

def test_cli_default_is_exit_ok_even_with_findings(mock_llm, scope_file, capsys):
    """Default (no --fail-on) preserves historical exit-0-on-completion."""
    rc = main(
        [
            "--target", mock_llm.url,
            "--scope-file", scope_file,
            "--attack-set", "injection",
            "--format", "json",
        ]
    )
    data = json.loads(capsys.readouterr().out)
    assert data["findings"], "mock should yield findings"
    assert rc == EXIT_OK


def test_cli_fail_on_high_exits_1_when_high_finding_present(
    mock_llm, scope_file, capsys
):
    rc = main(
        [
            "--target", mock_llm.url,
            "--scope-file", scope_file,
            "--attack-set", "injection",
            "--format", "json",
            "--fail-on", "high",
        ]
    )
    data = json.loads(capsys.readouterr().out)
    # prompt_injection findings are HIGH severity, so the gate trips.
    assert any(f["severity"] == "high" for f in data["findings"])
    assert rc == EXIT_FINDINGS


def test_cli_fail_on_critical_does_not_trip_on_high_only(
    mock_llm, scope_file, capsys
):
    """Injection findings top out at HIGH, so --fail-on critical must NOT trip."""
    rc = main(
        [
            "--target", mock_llm.url,
            "--scope-file", scope_file,
            "--attack-set", "injection",
            "--format", "json",
            "--fail-on", "critical",
        ]
    )
    data = json.loads(capsys.readouterr().out)
    assert data["findings"]
    assert all(f["severity"] != "critical" for f in data["findings"])
    assert rc == EXIT_OK


def test_cli_report_is_still_printed_when_gate_trips(mock_llm, scope_file, capsys):
    """The gate changes the exit code only — the report must still be emitted."""
    rc = main(
        [
            "--target", mock_llm.url,
            "--scope-file", scope_file,
            "--attack-set", "injection",
            "--format", "h1md",
            "--fail-on", "high",
        ]
    )
    out = capsys.readouterr().out
    assert out.startswith("# ouija findings report")
    assert rc == EXIT_FINDINGS


def test_scope_error_takes_precedence_over_fail_on(scope_file, capsys):
    """Out-of-scope (2) must win over the gate even with --fail-on set."""
    rc = main(
        [
            "--target", "https://not-in-scope.example/chat",
            "--scope-file", scope_file,
            "--fail-on", "info",
        ]
    )
    assert rc == EXIT_OUT_OF_SCOPE


def test_usage_error_takes_precedence_over_fail_on(mock_llm, scope_file, capsys):
    """A bad --request-template (usage error, 3) must win over the gate."""
    rc = main(
        [
            "--target", mock_llm.url,
            "--scope-file", scope_file,
            "--request-template", "{not valid json}",
            "--fail-on", "info",
        ]
    )
    assert rc == EXIT_ERROR


def test_help_lists_fail_on(capsys):
    from ouija.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--fail-on" in out
