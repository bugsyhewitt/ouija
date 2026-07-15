"""Tests for ouija/agentic_report.py — --format h1md and --format sarif."""

from __future__ import annotations

import json

from tests.agentic.conftest import FAST_REPEATS

from ouija.agentic_cli import EXIT_CONFIRMED, EXIT_OK, main
from ouija.agentic_report import SARIF_VERSION, to_h1md, to_sarif
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


# ---------------------------------------------------------------------------
# Unit: to_sarif on hand-crafted ScanReports
# ---------------------------------------------------------------------------

def test_sarif_valid_schema_root():
    """to_sarif emits valid SARIF 2.1.0 structure (version, schema, runs)."""
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed()],
    )
    doc = json.loads(to_sarif(report))
    assert doc["version"] == SARIF_VERSION
    assert "sarif-schema-2.1.0" in doc["$schema"]
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "ouija-agentic"


def test_sarif_confirmed_finding_maps_to_error_level():
    """A confirmed finding must have SARIF level 'error'."""
    report = ScanReport(
        verb="fuzz_agent", target="http://127.0.0.1/agent",
        findings=[_mock_confirmed()],
    )
    doc = json.loads(to_sarif(report))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "error"


def test_sarif_detected_finding_maps_to_warning_level():
    """A detected (static-only) finding must have SARIF level 'warning'."""
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_detected()],
    )
    doc = json.loads(to_sarif(report))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "warning"


def test_sarif_not_vulnerable_omitted():
    """not_vulnerable findings must not appear in the SARIF results array."""
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_not_vulnerable()],
    )
    doc = json.loads(to_sarif(report))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_zero_findings_clean():
    """An empty report must produce a valid, zero-results SARIF document."""
    report = ScanReport(verb="scan_rag", target="http://127.0.0.1/rag", findings=[])
    doc = json.loads(to_sarif(report))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_rules_one_per_owasp_ref():
    """Each distinct OWASP ref in reportable findings produces exactly one rule."""
    confirmed = _mock_confirmed()   # refs include ASI02, ASI04, LLM01
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[confirmed, _mock_detected()],
    )
    doc = json.loads(to_sarif(report))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    # ASI02, ASI04, LLM01 from confirmed; ASI02, LLM01 from detected (overlap de-duped)
    assert "ASI02" in rule_ids
    assert "LLM01" in rule_ids
    # Confirm no duplicates
    ids_list = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert len(ids_list) == len(set(ids_list))


def test_sarif_result_rule_id_matches_first_asi_llm_ref():
    """The SARIF ruleId must be the first ASI/LLM ref in the finding's refs."""
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed()],  # refs=["ASI02", "ASI04", "LLM01"]
    )
    doc = json.loads(to_sarif(report))
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "ASI02"


def test_sarif_result_message_contains_title():
    """The SARIF result message must contain the finding title."""
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed()],
    )
    doc = json.loads(to_sarif(report))
    msg = doc["runs"][0]["results"][0]["message"]["text"]
    assert "MCP Tool Poisoning" in msg


def test_sarif_oob_exfil_security_severity_high():
    """oob_exfil effect must yield a security-severity of 8.0 (HIGH)."""
    from ouija.findings import ouija_finding
    f = ouija_finding(
        "fuzz_agent", target="http://127.0.0.1/agent", state="confirmed",
        title="OOB exfil confirmed", effect="oob_exfil",
        asi=("ASI02",), raw={"asr": 1.0, "ci95": [0.82, 1.0], "n": 5},
    )
    report = ScanReport(verb="fuzz_agent", target="http://127.0.0.1/agent",
                        findings=[f])
    doc = json.loads(to_sarif(report))
    result = doc["runs"][0]["results"][0]
    assert result["properties"]["security-severity"] == "8.0"


def test_sarif_answer_flip_security_severity_medium():
    """answer_flip effect must yield a security-severity of 6.0 (MEDIUM)."""
    from ouija.findings import ouija_finding
    f = ouija_finding(
        "fuzz_agent", target="http://127.0.0.1/agent", state="confirmed",
        title="Answer flipped", effect="answer_flip",
        asi=("ASI09",), raw={"asr": 0.8, "ci95": [0.6, 0.95], "n": 20},
    )
    report = ScanReport(verb="fuzz_agent", target="http://127.0.0.1/agent",
                        findings=[f])
    doc = json.loads(to_sarif(report))
    result = doc["runs"][0]["results"][0]
    assert result["properties"]["security-severity"] == "6.0"


def test_sarif_partial_fingerprints_present():
    """Every result must carry a partialFingerprints.ouijaFindingId for dedup."""
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed(), _mock_detected()],
    )
    doc = json.loads(to_sarif(report))
    for result in doc["runs"][0]["results"]:
        assert "ouijaFindingId" in result.get("partialFingerprints", {})


def test_sarif_asr_in_properties_when_confirmed():
    """Confirmed findings (with ASR in raw) must expose asr in SARIF properties."""
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed()],
    )
    doc = json.loads(to_sarif(report))
    props = doc["runs"][0]["results"][0]["properties"]
    assert "asr" in props
    assert props["asr"] == 0.85


def test_sarif_automation_details_carries_verb():
    """automationDetails.id must carry the verb for run-level identification."""
    report = ScanReport(verb="fuzz_agent", target="http://127.0.0.1/agent",
                        findings=[])
    doc = json.loads(to_sarif(report))
    assert "fuzz_agent" in doc["runs"][0]["automationDetails"]["id"]


def test_sarif_rule_has_full_description_from_impact():
    """Each rule's fullDescription must match the _IMPACT text for the ref."""
    from ouija.agentic_report import _IMPACT
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed()],  # first ref is ASI02
    )
    doc = json.loads(to_sarif(report))
    asi02_rule = next(
        r for r in doc["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "ASI02"
    )
    assert asi02_rule["fullDescription"]["text"] == _IMPACT["ASI02"]


# ---------------------------------------------------------------------------
# CLI integration: --format sarif through main()
# ---------------------------------------------------------------------------

def test_cli_sarif_format_lab_scan_mcp(capsys):
    """--format sarif on scan-mcp --lab must emit valid SARIF with confirmed findings."""
    rc = main(["scan-mcp", "--lab", "--confirm",
               "--repeats", str(FAST_REPEATS), "--format", "sarif"])
    assert rc == EXIT_CONFIRMED
    out = capsys.readouterr().out
    doc = json.loads(out)  # must be valid JSON
    assert doc["version"] == SARIF_VERSION
    results = doc["runs"][0]["results"]
    # lab scan_mcp always yields at least one confirmed finding
    confirmed_results = [r for r in results if r["level"] == "error"]
    assert confirmed_results, "expected at least one error-level SARIF result"


def test_cli_sarif_format_lab_fuzz_agent(capsys):
    """--format sarif on fuzz-agent --lab must emit valid SARIF."""
    rc = main(["fuzz-agent", "--lab", "--confirm",
               "--repeats", str(FAST_REPEATS), "--format", "sarif"])
    assert rc == EXIT_CONFIRMED
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["version"] == SARIF_VERSION
    assert len(doc["runs"]) == 1


def test_cli_sarif_in_help(capsys):
    """'sarif' must appear in the --format help text for active verbs."""
    import pytest
    from ouija.agentic_cli import build_parser
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan-mcp", "--help"])
    out = capsys.readouterr().out
    assert "sarif" in out


# ---------------------------------------------------------------------------
# Unit: to_markdown_table on hand-crafted ScanReports
# ---------------------------------------------------------------------------

def test_markdown_table_has_header_and_separator():
    """Output must start with a title line and contain the column header row."""
    from ouija.agentic_report import to_markdown_table, _MD_TABLE_COLUMNS
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed()],
    )
    out = to_markdown_table(report)
    # Title line
    assert "# ouija agentic findings" in out
    assert "http://127.0.0.1/mcp" in out
    # GFM column header and separator
    for col in _MD_TABLE_COLUMNS:
        assert col in out
    assert "|---|" in out


def test_markdown_table_confirmed_finding_row():
    """A confirmed finding must appear with CONFIRMED state and ASR percentage."""
    from ouija.agentic_report import to_markdown_table
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed()],
    )
    out = to_markdown_table(report)
    assert "CONFIRMED" in out
    assert "85%" in out          # ASR from raw["asr"] = 0.85
    assert "MCP Tool Poisoning" in out
    assert "ASI02" in out


def test_markdown_table_detected_finding_shows_dash_asr():
    """A detected (static-only) finding must show '-' in the asr column."""
    from ouija.agentic_report import to_markdown_table
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_detected()],
    )
    out = to_markdown_table(report)
    assert "DETECTED" in out
    # ASR column must show '-' (no ASR for static findings)
    rows = [line for line in out.split("\n") if "DETECTED" in line]
    assert rows, "expected at least one DETECTED row"
    # The '-' must be in the DETECTED row (last cell = asr)
    assert rows[0].endswith("- |")


def test_markdown_table_not_vulnerable_omitted():
    """not_vulnerable findings must not appear in the table."""
    from ouija.agentic_report import to_markdown_table
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_not_vulnerable()],
    )
    out = to_markdown_table(report)
    assert "Clean tool" not in out
    # Zero reportable findings -> no-findings notice
    assert "No findings" in out


def test_markdown_table_zero_findings_still_emits_header():
    """A zero-finding run must still emit the title and column header."""
    from ouija.agentic_report import to_markdown_table, _MD_TABLE_COLUMNS
    report = ScanReport(verb="scan_rag", target="http://127.0.0.1/rag", findings=[])
    out = to_markdown_table(report)
    assert "# ouija agentic findings" in out
    assert "No findings" in out
    for col in _MD_TABLE_COLUMNS:
        assert col in out


def test_markdown_table_confirmed_before_detected():
    """Confirmed findings must appear before detected in the table output."""
    from ouija.agentic_report import to_markdown_table
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_detected(), _mock_confirmed()],
    )
    out = to_markdown_table(report)
    confirmed_pos = out.index("CONFIRMED")
    detected_pos = out.index("DETECTED")
    assert confirmed_pos < detected_pos, "confirmed row should appear before detected row"


def test_markdown_table_pipe_in_title_escaped():
    """A pipe character in an attacker-controlled title must be escaped."""
    from ouija.agentic_report import to_markdown_table
    f = ouija_finding(
        "fuzz_agent", target="http://127.0.0.1/agent",
        state="confirmed",
        title="Pipe | injection | attempt",
        effect="tool_call",
        asi=("ASI02",),
        raw={"asr": 1.0, "ci95": [0.82, 1.0], "n": 5},
    )
    report = ScanReport(verb="fuzz_agent", target="http://127.0.0.1/agent",
                        findings=[f])
    out = to_markdown_table(report)
    # Raw unescaped pipe would break the table; escaped form must be present
    assert "\\|" in out
    # The table must still be parseable as GFM (each data row has the right
    # column count — check the data row has the right number of cells)
    data_rows = [
        line for line in out.split("\n")
        if line.startswith("| ") and "CONFIRMED" in line
    ]
    assert data_rows, "expected at least one data row"
    # Count unescaped pipes in the row (escaped \| must not count as column delimiters).
    # A 6-column GFM row `| c1 | c2 | c3 | c4 | c5 | c6 |` has exactly 7 unescaped
    # pipes (one leading, one between each pair, one trailing).
    import re
    unescaped_pipes = re.findall(r"(?<!\\)\|", data_rows[0])
    assert len(unescaped_pipes) == 7, (
        f"expected 7 unescaped pipes for 6 columns: got {len(unescaped_pipes)}"
    )


def test_markdown_table_newline_in_surface_collapsed():
    """A newline in the surface field must be collapsed to a space."""
    from ouija.agentic_report import to_markdown_table
    f = ouija_finding(
        "fuzz_agent", target="http://127.0.0.1/agent",
        state="detected",
        title="Newline in surface",
        surface="tool\nname",
        effect="answer_flip",
        asi=("ASI01",),
    )
    report = ScanReport(verb="fuzz_agent", target="http://127.0.0.1/agent",
                        findings=[f])
    out = to_markdown_table(report)
    # The raw newline must not appear in the output (would break GFM row)
    assert "tool\nname" not in out
    assert "tool name" in out


def test_markdown_table_effect_label_rendered():
    """Known effect types get the human-readable label, not the raw key."""
    from ouija.agentic_report import to_markdown_table, _EFFECT_LABEL
    f = ouija_finding(
        "fuzz_agent", target="http://127.0.0.1/agent",
        state="confirmed",
        title="OOB exfil confirmed",
        effect="oob_exfil",
        asi=("ASI02",),
        raw={"asr": 0.9, "ci95": [0.7, 1.0], "n": 10},
    )
    report = ScanReport(verb="fuzz_agent", target="http://127.0.0.1/agent",
                        findings=[f])
    out = to_markdown_table(report)
    assert _EFFECT_LABEL["oob_exfil"] in out


def test_markdown_table_summary_counts_in_title():
    """The title line must carry confirmed and detected counts."""
    from ouija.agentic_report import to_markdown_table
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed(), _mock_detected()],
    )
    out = to_markdown_table(report)
    assert "2 finding(s)" in out
    assert "1 confirmed" in out
    assert "1 detected" in out


def test_markdown_table_multiple_refs_joined():
    """All OWASP refs must appear in the owasp cell, space-joined."""
    from ouija.agentic_report import to_markdown_table
    report = ScanReport(
        verb="scan_mcp", target="http://127.0.0.1/mcp",
        findings=[_mock_confirmed()],  # refs: ASI02, ASI04, LLM01
    )
    out = to_markdown_table(report)
    owasp_row = [line for line in out.split("\n") if "ASI02" in line]
    assert owasp_row, "expected a row containing ASI02"
    assert "ASI04" in owasp_row[0]
    assert "LLM01" in owasp_row[0]


# ---------------------------------------------------------------------------
# CLI integration: --format markdown-table through main()
# ---------------------------------------------------------------------------

def test_cli_markdown_table_format_lab_scan_mcp(capsys):
    """--format markdown-table on scan-mcp --lab must emit a GFM table with findings."""
    rc = main(["scan-mcp", "--lab", "--confirm",
               "--repeats", str(FAST_REPEATS), "--format", "markdown-table"])
    assert rc == EXIT_CONFIRMED
    out = capsys.readouterr().out
    assert "# ouija agentic findings" in out
    assert "CONFIRMED" in out
    assert "|---|" in out
    # must NOT be JSON
    assert not out.strip().startswith("{")


def test_cli_markdown_table_format_lab_fuzz_agent(capsys):
    """--format markdown-table on fuzz-agent --lab must emit a GFM table."""
    rc = main(["fuzz-agent", "--lab", "--confirm",
               "--repeats", str(FAST_REPEATS), "--format", "markdown-table"])
    assert rc == EXIT_CONFIRMED
    out = capsys.readouterr().out
    assert "# ouija agentic findings" in out
    assert "|---|" in out


def test_cli_markdown_table_in_help(capsys):
    """'markdown-table' must appear in the --format help text for active verbs."""
    import pytest
    from ouija.agentic_cli import build_parser
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan-mcp", "--help"])
    out = capsys.readouterr().out
    assert "markdown-table" in out
