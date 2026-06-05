"""Tests for the ``--format teams`` (Microsoft Teams MessageCard) output.

Where ``--format slack`` is the Slack-native Block Kit payload, ``--format
teams`` is the Microsoft Teams incoming-webhook MessageCard: a JSON document
POST-able directly to a Teams connector URL.  The contract:

    * a JSON document whose top level carries ``@type``, ``@context``,
      ``themeColor``, ``summary``, ``title``, and ``sections``;
    * ``themeColor`` reflects the highest finding severity in the run
      (critical→red, high→orange, medium→amber, low→blue, info→grey);
      a zero-finding run uses a distinct green colour;
    * at least one "Run summary" section carrying target, attack-set,
      request count, finding count, and scan-ID as ``facts`` pairs;
    * one per-finding section per finding (severity-sorted, capped at 20,
      with an overflow note for heavier scans);
    * every attacker-influenced value (titles, evidence, IDs) is HTML-escaped
      so a response excerpt carrying ``<script>`` / ``<img>`` cannot inject
      HTML into the rendered card;
    * evidence is truncated so no single finding generates an unreadably
      long card section;
    * a zero-finding run renders a clean "No findings" section with no crash.
"""

from __future__ import annotations

import json

from ouija.cli import EXIT_OK, main
from ouija.models import ScanResult
from ouija.report import to_teams


# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------


def _two_finding_result() -> ScanResult:
    base = {
        "version": "9.9.9",
        "scan_id": "scan-teams-test",
        "timestamp": "2026-06-05T18:00:00Z",
        "target": "https://example.test/llm",
        "attack_set": "injection",
        "patterns_sent": 8,
        "findings": [
            {
                "id": "f-aaaa",
                "category": "prompt_injection",
                "severity": "medium",
                "title": "demo finding two",
                "pattern_id": "p2",
                "technique": "smuggle",
                "owasp": "LLM01:2025",
                "request_prompt": "second prompt",
                "response_excerpt": "second reply",
                "evidence": "marker present",
                "confidence": 0.7,
            },
            {
                "id": "f-bbbb",
                "category": "prompt_injection",
                "severity": "critical",
                "title": "demo finding one",
                "pattern_id": "p1",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "ignore previous",
                "response_excerpt": "ok, ignoring",
                "evidence": "marker present",
                "confidence": 0.9,
            },
        ],
        "summary": {
            "total": 8,
            "successful": 2,
            "attack_sets": {"injection": 2},
        },
    }
    return ScanResult(**base)


def _payload(result: ScanResult) -> dict:
    return json.loads(to_teams(result))


# ---------------------------------------------------------------------------
# Top-level structure
# ---------------------------------------------------------------------------


def test_teams_payload_is_valid_json_with_required_keys():
    payload = _payload(_two_finding_result())
    assert payload["@type"] == "MessageCard"
    assert payload["@context"] == "https://schema.org/extensions"
    assert "themeColor" in payload
    assert "summary" in payload
    assert "title" in payload
    assert "sections" in payload
    assert isinstance(payload["sections"], list)


def test_teams_title_contains_target():
    payload = _payload(_two_finding_result())
    assert "https://example.test/llm" in payload["title"]


def test_teams_summary_mentions_finding_count_and_request_count():
    payload = _payload(_two_finding_result())
    summary = payload["summary"]
    assert "2 finding(s)" in summary
    assert "8 request(s)" in summary


# ---------------------------------------------------------------------------
# themeColor by severity
# ---------------------------------------------------------------------------


def test_teams_theme_color_critical_is_red():
    payload = _payload(_two_finding_result())
    # Critical is the top severity in the two-finding fixture
    assert payload["themeColor"] == "b30000"


def test_teams_theme_color_high():
    result = ScanResult(
        version="9.9.9",
        target="https://t.test/llm",
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-h",
                "category": "prompt_injection",
                "severity": "high",
                "title": "high finding",
                "pattern_id": "p1",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.8,
            }
        ],
    )
    assert _payload(result)["themeColor"] == "d9480f"


def test_teams_theme_color_medium():
    result = ScanResult(
        version="9.9.9",
        target="https://t.test/llm",
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-m",
                "category": "prompt_injection",
                "severity": "medium",
                "title": "medium finding",
                "pattern_id": "p1",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.7,
            }
        ],
    )
    assert _payload(result)["themeColor"] == "f08c00"


def test_teams_theme_color_zero_findings_is_green():
    """A clean run uses a distinct green accent — visually different from any
    findings card at a glance in a Teams channel."""
    result = ScanResult(
        version="9.9.9",
        target="https://t.test/llm",
        attack_set="injection",
        patterns_sent=3,
    )
    assert _payload(result)["themeColor"] == "2f9e44"


# ---------------------------------------------------------------------------
# Run summary section
# ---------------------------------------------------------------------------


def test_teams_first_section_is_run_summary():
    payload = _payload(_two_finding_result())
    first = payload["sections"][0]
    assert "activityTitle" in first or "facts" in first
    # Must carry a facts list
    assert "facts" in first
    fact_names = {f["name"] for f in first["facts"]}
    assert "Target" in fact_names
    assert "Attack set" in fact_names
    assert "Requests sent" in fact_names
    assert "Findings" in fact_names
    assert "Scan ID" in fact_names


def test_teams_run_summary_facts_carry_correct_values():
    result = _two_finding_result()
    payload = _payload(result)
    facts = {f["name"]: f["value"] for f in payload["sections"][0]["facts"]}
    assert facts["Target"] == "https://example.test/llm"
    assert facts["Attack set"] == "injection"
    assert facts["Requests sent"] == "8"
    assert facts["Findings"] == "2"


# ---------------------------------------------------------------------------
# Per-finding sections
# ---------------------------------------------------------------------------


def test_teams_findings_are_sorted_by_severity_desc():
    """Critical sorts above medium — the first per-finding section must be the
    critical one."""
    payload = _payload(_two_finding_result())
    # sections[0] = run summary; sections[1..N] = findings
    finding_sections = [
        s for s in payload["sections"]
        if "activityTitle" in s and "Finding ID" in str(s.get("facts", []))
    ]
    assert len(finding_sections) == 2
    # Critical is section[0], medium is section[1]
    assert "[CRITICAL]" in finding_sections[0]["activityTitle"]
    assert "[MEDIUM]" in finding_sections[1]["activityTitle"]


def test_teams_finding_section_has_expected_fact_keys():
    payload = _payload(_two_finding_result())
    finding_sections = [
        s for s in payload["sections"]
        if "activityTitle" in s and "Finding ID" in str(s.get("facts", []))
    ]
    facts = {f["name"]: f["value"] for f in finding_sections[0]["facts"]}
    assert "Category" in facts
    assert "OWASP" in facts
    assert "Confidence" in facts
    assert "Pattern ID" in facts
    assert "Finding ID" in facts
    assert "Technique" in facts


def test_teams_finding_section_includes_evidence_text():
    payload = _payload(_two_finding_result())
    finding_sections = [
        s for s in payload["sections"]
        if "activityTitle" in s and "Finding ID" in str(s.get("facts", []))
    ]
    # The evidence text field is present and non-empty
    assert "text" in finding_sections[0]
    assert "Evidence" in finding_sections[0]["text"]


# ---------------------------------------------------------------------------
# Zero-finding run
# ---------------------------------------------------------------------------


def test_teams_zero_finding_run_no_crash():
    result = ScanResult(
        version="9.9.9",
        target="https://t.test/llm",
        attack_set="injection",
        patterns_sent=4,
    )
    payload = _payload(result)
    sections_text = json.dumps(payload["sections"])
    assert "No findings" in sections_text


def test_teams_zero_finding_run_has_two_sections_summary_and_clean():
    result = ScanResult(
        version="9.9.9",
        target="https://t.test/llm",
        attack_set="injection",
        patterns_sent=4,
    )
    payload = _payload(result)
    # One run-summary section + one "No findings" section
    assert len(payload["sections"]) == 2


# ---------------------------------------------------------------------------
# HTML escaping of attacker-influenced values
# ---------------------------------------------------------------------------


def test_teams_escapes_html_in_title():
    """A finding title carrying ``<script>`` MUST be HTML-escaped so Teams
    does not render live HTML in the card."""
    result = ScanResult(
        version="9.9.9",
        target="https://t.test/llm",
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-xss",
                "category": "prompt_injection",
                "severity": "high",
                "title": "<script>alert('xss')</script>",
                "pattern_id": "pX",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.9,
            }
        ],
    )
    payload = _payload(result)
    sections_text = json.dumps(payload["sections"])
    assert "<script>" not in sections_text
    assert "&lt;script&gt;" in sections_text


def test_teams_escapes_html_in_evidence():
    """Evidence carrying ``<img src=x onerror=...>`` MUST be HTML-escaped."""
    result = ScanResult(
        version="9.9.9",
        target="https://t.test/llm",
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-img",
                "category": "improper_output_handling",
                "severity": "critical",
                "title": "image exfil",
                "pattern_id": "pY",
                "technique": "canary",
                "owasp": "LLM05:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": '<img src="http://attacker.test/c" onerror="fetch(...)">',
                "confidence": 0.95,
            }
        ],
    )
    payload = _payload(result)
    sections_text = json.dumps(payload["sections"])
    assert "<img " not in sections_text
    assert "&lt;img" in sections_text


# ---------------------------------------------------------------------------
# Evidence truncation
# ---------------------------------------------------------------------------


def test_teams_truncates_very_long_evidence():
    """A 5000-char evidence string MUST be capped so the card section does not
    become unreadably long.  The full evidence stays in --format json."""
    result = ScanResult(
        version="9.9.9",
        target="https://t.test/llm",
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-long",
                "category": "prompt_injection",
                "severity": "high",
                "title": "long evidence",
                "pattern_id": "pZ",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "E" * 5000,
                "confidence": 0.8,
            }
        ],
    )
    payload = _payload(result)
    finding_sections = [
        s for s in payload["sections"]
        if "text" in s and "Evidence" in s.get("text", "")
    ]
    # Should have exactly one finding section with a text field
    assert len(finding_sections) == 1
    evidence_text = finding_sections[0]["text"]
    # Well under 5000 chars
    assert len(evidence_text) < 2000
    # Truncation marker present
    assert "…" in evidence_text


# ---------------------------------------------------------------------------
# Overflow (many findings)
# ---------------------------------------------------------------------------


def test_teams_overflow_finding_count_is_summarised():
    """A scan with 25 findings MUST NOT dump all 25 sections into the card.
    The renderer caps at 20 and emits one overflow note section."""
    findings = []
    for i in range(25):
        findings.append(
            {
                "id": f"f-{i:04d}",
                "category": "prompt_injection",
                "severity": "low",
                "title": f"finding {i}",
                "pattern_id": f"p{i}",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.5,
            }
        )
    result = ScanResult(
        version="9.9.9",
        target="https://t.test/llm",
        attack_set="injection",
        patterns_sent=25,
        findings=findings,
        summary={"total": 25, "successful": 25, "attack_sets": {"injection": 25}},
    )
    payload = _payload(result)
    # Count full per-finding sections (they all have a "facts" list with Finding ID)
    full_finding_sections = [
        s for s in payload["sections"]
        if "facts" in s and any(f["name"] == "Finding ID" for f in s["facts"])
    ]
    assert len(full_finding_sections) == 20
    # Overflow note section is present
    overflow_sections = [
        s for s in payload["sections"]
        if "additional finding" in str(s.get("activityTitle", ""))
    ]
    assert len(overflow_sections) == 1


# ---------------------------------------------------------------------------
# Reliability fields (--repeats > 1)
# ---------------------------------------------------------------------------


def test_teams_reliability_fact_present_when_repeats_gt_1():
    """When ``--repeats N`` produced the finding, the 'Reliability' fact must
    appear in the finding section and carry the hit-rate string."""
    result = ScanResult(
        version="9.9.9",
        target="https://t.test/llm",
        attack_set="injection",
        patterns_sent=5,
        findings=[
            {
                "id": "f-rep",
                "category": "prompt_injection",
                "severity": "high",
                "title": "repeated finding",
                "pattern_id": "pR",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.9,
                "attempts": 5,
                "successes": 3,
                "success_rate": 0.6,
            }
        ],
    )
    payload = _payload(result)
    finding_sections = [
        s for s in payload["sections"]
        if "facts" in s and any(f["name"] == "Finding ID" for f in s["facts"])
    ]
    assert len(finding_sections) == 1
    facts = {f["name"]: f["value"] for f in finding_sections[0]["facts"]}
    assert "Reliability" in facts
    assert "3/5" in facts["Reliability"]
    assert "60%" in facts["Reliability"]


def test_teams_no_reliability_fact_when_single_attempt():
    """For a standard single-shot finding, the 'Reliability' fact must NOT
    appear (it would just say '1/1 (100%)' which adds noise, not signal)."""
    result = ScanResult(
        version="9.9.9",
        target="https://t.test/llm",
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-once",
                "category": "prompt_injection",
                "severity": "medium",
                "title": "single shot",
                "pattern_id": "pS",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.7,
            }
        ],
    )
    payload = _payload(result)
    finding_sections = [
        s for s in payload["sections"]
        if "facts" in s and any(f["name"] == "Finding ID" for f in s["facts"])
    ]
    assert len(finding_sections) == 1
    fact_names = {f["name"] for f in finding_sections[0]["facts"]}
    assert "Reliability" not in fact_names


# ---------------------------------------------------------------------------
# CLI round-trip
# ---------------------------------------------------------------------------


def test_teams_format_is_accepted_by_cli(tmp_path, capsys):
    """End-to-end: ``--format teams`` is a valid CLI choice that is accepted
    by the argument parser and runs through ``--plan`` mode without touching
    the network, exiting 0."""
    scope = tmp_path / "scope.txt"
    scope.write_text("https://example.test/\n")

    code = main([
        "--target", "https://example.test/llm",
        "--scope-file", str(scope),
        "--format", "teams",
        "--plan",
    ])

    assert code == EXIT_OK
    out = capsys.readouterr().out
    # --plan with a non-json format renders a human-readable plan summary
    assert out.strip() != ""
