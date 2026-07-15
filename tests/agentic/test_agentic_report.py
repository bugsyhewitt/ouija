"""Tests for ouija/agentic_report.py — --format h1md for ouija-agentic."""

from __future__ import annotations

import json

from tests.agentic.conftest import FAST_REPEATS

from ouija.agentic_cli import EXIT_CONFIRMED, EXIT_OK, main
from ouija.agentic_report import to_h1md
from ouija.agentic_scan import ScanReport
from ouija.findings import ouija_finding


# ---------------------------------------------------------------------------
# Unit: to_h1md on a hand-crafted ScanReport
# ---------------------------------------------------------------------------

def _mock_confirmed() -> dict:
    f = ouija_finding(
        "scan_mcp",
        target="http://127.0.0.1/mcp",
        state="confirmed",
        title="MCP Tool Poisoning via get_weather",
        evidence="Unrequested send_message call with canary in args",
        surface="get_weather",
        asi=("ASI02", "ASI04"),
        llm=("LLM01",),
        effect="tool_call",
        confidence=0.85,
        raw={"asr": 0.85, "ci95": [0.65, 0.97], "n": 20,
             "tool_call": True, "oob_exfil": False},
    )
    return f


def _mock_detected() -> dict:
    return ouija_finding(
        "scan_mcp",
        target="http://127.0.0.1/mcp",
        state="detected",
        title="Tool description carries injected instruction (static lint)",
        evidence="Tool 'admin' description contains 'ignore previous instructions'",
        surface="admin",
        asi=("ASI02",),
        llm=("LLM01",),
        effect=None,
        confidence=0.7,
    )


def _mock_not_vulnerable() -> dict:
    return ouija_finding(
        "scan_mcp",
        target="http://127.0.0.1/mcp",
        state="not_vulnerable",
        title="Clean tool",
        evidence="",
    )


def test_h1md_confirmed_finding_has_key_sections():
    report = ScanReport(
        verb="scan_mcp",
        target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed()],
    )
    out = to_h1md(report)
    assert "# ouija agentic findings" in out
    assert "CONFIRMED" in out
    assert "MCP Tool Poisoning" in out
    assert "ASI02" in out
    assert "85%" in out          # confidence or ASR
    assert "Attack Success Rate" in out
    assert "95% CI" in out
    assert "Business Impact" in out
    # evidence in a code fence
    assert "Unrequested send_message" in out


def test_h1md_detected_finding_labelled_as_static():
    report = ScanReport(
        verb="scan_mcp",
        target="http://127.0.0.1/mcp",
        findings=[_mock_detected()],
    )
    out = to_h1md(report)
    assert "DETECTED (static)" in out
    assert "Tool description carries" in out
    # no ASR line (not confirmed)
    assert "Attack Success Rate" not in out


def test_h1md_not_vulnerable_omitted():
    report = ScanReport(
        verb="scan_mcp",
        target="http://127.0.0.1/mcp",
        findings=[_mock_not_vulnerable()],
    )
    out = to_h1md(report)
    assert "No findings" in out
    assert "Clean tool" not in out


def test_h1md_zero_findings_renders_clean():
    report = ScanReport(verb="scan_rag", target="http://127.0.0.1/rag", findings=[])
    out = to_h1md(report)
    assert "No findings" in out
    assert "ouija agentic findings" in out


def test_h1md_confirmed_first_then_detected():
    report = ScanReport(
        verb="scan_mcp",
        target="http://127.0.0.1/mcp",
        findings=[_mock_detected(), _mock_confirmed()],
    )
    out = to_h1md(report)
    confirmed_pos = out.index("CONFIRMED")
    detected_pos = out.index("DETECTED")
    assert confirmed_pos < detected_pos, "confirmed findings should appear before detected"


def test_h1md_multiple_findings_numbered():
    report = ScanReport(
        verb="scan_mcp",
        target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed(), _mock_detected()],
    )
    out = to_h1md(report)
    assert "## Finding 1:" in out
    assert "## Finding 2:" in out


def test_h1md_markdown_injection_in_evidence_cleaned():
    """Attacker-influenced evidence must not break the report structure."""
    f = ouija_finding(
        "fuzz_agent",
        target="http://127.0.0.1/agent",
        state="confirmed",
        title="Exfil via tool",
        evidence="``` injected fence ```\n# injected heading",
        effect="oob_exfil",
        asi=("ASI01",),
        raw={"asr": 1.0, "ci95": [0.82, 1.0], "n": 5},
    )
    report = ScanReport(verb="fuzz_agent", target="http://127.0.0.1/agent",
                        findings=[f])
    out = to_h1md(report)
    # triple backticks in evidence must be escaped so they don't close the fence
    assert "```\n```" not in out  # the injected fence shouldn't open a raw block inside


def test_h1md_effect_label_rendered():
    """Known effect types get a human-readable label."""
    f = ouija_finding(
        "fuzz_agent",
        target="http://127.0.0.1/agent",
        state="confirmed",
        title="OOB exfil confirmed",
        effect="oob_exfil",
        asi=("ASI02",),
        raw={"asr": 0.9, "ci95": [0.7, 1.0], "n": 10},
    )
    report = ScanReport(verb="fuzz_agent", target="http://127.0.0.1/agent",
                        findings=[f])
    out = to_h1md(report)
    assert "Out-of-band exfiltration" in out


def test_h1md_refs_in_header_line():
    report = ScanReport(
        verb="scan_rag",
        target="http://127.0.0.1/rag",
        findings=[_mock_confirmed()],
    )
    out = to_h1md(report)
    # refs must appear in the OWASP Mapping line
    assert "ASI02" in out and "LLM01" in out


def test_h1md_summary_line_counts():
    report = ScanReport(
        verb="scan_mcp",
        target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed(), _mock_detected()],
    )
    out = to_h1md(report)
    assert "2 finding(s)" in out
    assert "1 confirmed" in out
    assert "1 detected" in out


# ---------------------------------------------------------------------------
# CLI integration: --format h1md through main()
# ---------------------------------------------------------------------------

def test_cli_h1md_format_lab_scan_mcp(capsys):
    rc = main(["scan-mcp", "--lab", "--confirm",
               "--repeats", str(FAST_REPEATS), "--format", "h1md"])
    assert rc == EXIT_CONFIRMED
    out = capsys.readouterr().out
    assert "# ouija agentic findings" in out
    assert "CONFIRMED" in out
    # must NOT be JSON
    assert not out.strip().startswith("{")


def test_cli_h1md_format_lab_scan_rag(capsys):
    rc = main(["scan-rag", "--lab", "--confirm",
               "--repeats", str(FAST_REPEATS), "--format", "h1md"])
    assert rc == EXIT_CONFIRMED
    out = capsys.readouterr().out
    assert "ouija agentic findings" in out


def test_cli_h1md_format_lab_fuzz_agent(capsys):
    rc = main(["fuzz-agent", "--lab", "--confirm",
               "--repeats", str(FAST_REPEATS), "--format", "h1md"])
    assert rc == EXIT_CONFIRMED
    out = capsys.readouterr().out
    assert "ouija agentic findings" in out


def test_cli_h1md_in_help(capsys):
    import pytest
    from ouija.agentic_cli import build_parser
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan-mcp", "--help"])
    out = capsys.readouterr().out
    assert "h1md" in out


def test_cli_json_format_still_works(capsys):
    """Regression: --format json must still emit valid JSON after the change."""
    rc = main(["scan-mcp", "--lab", "--confirm",
               "--repeats", str(FAST_REPEATS), "--format", "json"])
    assert rc == EXIT_CONFIRMED
    data = json.loads(capsys.readouterr().out)
    assert data["verb"] == "scan_mcp"
    assert "findings" in data
