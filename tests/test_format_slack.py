"""Tests for the `--format slack` (Slack Block Kit JSON payload) output.

Where `--format markdown-table` is the inline-in-GitHub triage view but appears
as raw, unrendered pipe-text when posted to a Slack channel (Slack's ``mrkdwn``
dialect does NOT support GFM pipe-tables), `--format slack` is the Slack-native
rendering: a Block Kit ``blocks`` array wrapped in an ``attachments[0]``
coloured by the top finding's severity. The contract:

    * a JSON document that is a valid Slack ``chat.postMessage`` /
      incoming-webhook payload — ``text`` fallback + ``attachments`` array
      carrying a Block Kit ``blocks`` list;
    * the attachment ``color`` reflects the highest finding severity in the
      run (omitted entirely for a zero-finding run);
    * exactly one ``header`` block, one summary ``section``, one
      ``section`` per finding (severity-sorted, capped, with an overflow
      line), and a trailing ``context`` block;
    * every attacker-influenced value (titles, evidence, ids) is Slack-
      escaped so a response that smuggles ``<script>`` / ``<@U123>`` /
      ``<!channel>`` cannot inject Slack syntax into the rendered message;
    * per-section text is length-capped so a noisy finding cannot exceed
      Slack's 3000-char per-text limit (full evidence stays in
      ``--format json``);
    * a zero-finding run renders a clean "no findings" section, no header
      crash, and no attachment color.
"""

from __future__ import annotations

import json

from ouija.cli import EXIT_OK, main
from ouija.models import ScanResult
from ouija.report import to_slack


def _two_finding_result() -> ScanResult:
    base = {
        "version": "9.9.9",
        "scan_id": "scan-xyz",
        "timestamp": "2026-05-29T12:00:00Z",
        "target": "https://example.test/llm",
        "attack_set": "injection",
        "patterns_sent": 7,
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
            "total": 7,
            "successful": 2,
            "attack_sets": {"injection": 2},
        },
    }
    return ScanResult(**base)


def _payload(result: ScanResult) -> dict:
    return json.loads(to_slack(result))


def test_slack_payload_is_valid_json_with_text_and_attachments():
    payload = _payload(_two_finding_result())
    assert "text" in payload, "Slack requires a fallback 'text' field"
    assert "attachments" in payload
    assert isinstance(payload["attachments"], list)
    assert len(payload["attachments"]) == 1
    att = payload["attachments"][0]
    assert "blocks" in att, "Block Kit blocks live inside the attachment"
    assert "fallback" in att


def test_slack_attachment_color_reflects_top_severity():
    """A critical finding drives a red sidebar; a clean run has NO color key
    so Slack renders the message with no severity accent at all."""
    payload = _payload(_two_finding_result())
    # Critical is the highest severity in the two-finding fixture
    assert payload["attachments"][0].get("color") == "#b30000"


def test_slack_zero_finding_run_has_no_attachment_color():
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=3,
    )
    payload = _payload(result)
    # No color on a clean run — message renders without a severity accent
    assert "color" not in payload["attachments"][0]
    # And the explicit clean-run message is present
    blocks_text = json.dumps(payload["attachments"][0]["blocks"])
    assert "No findings" in blocks_text


def test_slack_block_shape_has_header_summary_findings_and_context():
    payload = _payload(_two_finding_result())
    blocks = payload["attachments"][0]["blocks"]
    types = [b["type"] for b in blocks]
    # First block is the header carrying the target
    assert types[0] == "header"
    assert "ouija findings" in blocks[0]["text"]["text"]
    assert "https://example.test/llm" in blocks[0]["text"]["text"]
    # Summary section follows the header
    assert types[1] == "section"
    summary_text = blocks[1]["text"]["text"]
    assert "Target:" in summary_text
    assert "Findings:" in summary_text
    assert "Requests sent:" in summary_text
    # Last block is a context block (the footer caption)
    assert types[-1] == "context"
    # Between summary and context there's at least one divider and two finding
    # section blocks
    assert "divider" in types
    finding_sections = [
        b for b in blocks
        if b["type"] == "section" and "Finding ID:" in b["text"]["text"]
    ]
    assert len(finding_sections) == 2


def test_slack_findings_are_sorted_by_severity_desc():
    """Critical sorts above medium — same ordering as h1md / csv / html /
    markdown-table. The first finding section carries the critical finding."""
    blocks = _payload(_two_finding_result())["attachments"][0]["blocks"]
    finding_sections = [
        b for b in blocks
        if b["type"] == "section" and "Finding ID:" in b["text"]["text"]
    ]
    # First finding shown is the critical one
    assert "[CRITICAL]" in finding_sections[0]["text"]["text"]
    assert "[MEDIUM]" in finding_sections[1]["text"]["text"]


def test_slack_escapes_hostile_slack_syntax_in_attacker_text():
    """A response excerpt containing Slack control characters (``<``, ``>``,
    ``&``) MUST be escaped to the Slack-documented ``&lt;`` / ``&gt;`` /
    ``&amp;`` forms so a ``<@U123>`` user-mention, a ``<!channel>`` channel
    ping, or a ``<http://attacker.test|click>`` link injected by an attacker
    cannot be rendered by Slack as live markup."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-cccc",
                "category": "prompt_injection",
                "severity": "high",
                # Hostile title carrying every Slack control sequence
                "title": "<script>x</script> & <@U123> & <!channel>",
                "pattern_id": "p3",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.8,
            },
        ],
    )
    blocks = _payload(result)["attachments"][0]["blocks"]
    finding_sections = [
        b for b in blocks
        if b["type"] == "section" and "Finding ID:" in b["text"]["text"]
    ]
    text = finding_sections[0]["text"]["text"]
    # Raw control sequences must NOT appear — they would be parsed by Slack
    assert "<script>" not in text
    assert "<@U123>" not in text
    assert "<!channel>" not in text
    # Their escaped forms MUST appear
    assert "&lt;script&gt;" in text
    assert "&lt;@U123&gt;" in text
    assert "&lt;!channel&gt;" in text
    # And ``&`` is escaped to ``&amp;`` (done first so we don't double-escape)
    assert "&amp;" in text


def test_slack_truncates_very_long_evidence_to_avoid_slack_text_limit():
    """Slack's per-section text limit is 3000 chars. A pathological evidence
    string MUST be capped so the section block does not exceed it; the full
    evidence stays in ``--format json``."""
    long_evidence = "X" * 5000
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-dddd",
                "category": "prompt_injection",
                "severity": "high",
                "title": "long evidence finding",
                "pattern_id": "p4",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": long_evidence,
                "confidence": 0.8,
            },
        ],
    )
    blocks = _payload(result)["attachments"][0]["blocks"]
    finding_sections = [
        b for b in blocks
        if b["type"] == "section" and "Finding ID:" in b["text"]["text"]
    ]
    text = finding_sections[0]["text"]["text"]
    # Comfortably under Slack's 3000-char per-section text cap
    assert len(text) < 3000
    # And the truncation marker is present
    assert "…" in text


def test_slack_overflow_finding_count_is_summarised_not_blasted():
    """A heavy scan (many findings) MUST NOT spill past Slack's 50-block per-
    message hard limit. The renderer caps the number of full per-finding
    section blocks and emits an overflow line carrying the count of findings
    NOT shown, pointing the reader at ``--format json`` for the rest."""
    # 30 findings — well past the 20-section cap
    findings = []
    for i in range(30):
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
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=30,
        findings=findings,
        summary={"total": 30, "successful": 30, "attack_sets": {"injection": 30}},
    )
    blocks = _payload(result)["attachments"][0]["blocks"]
    finding_sections = [
        b for b in blocks
        if b["type"] == "section" and "Finding ID:" in b["text"]["text"]
    ]
    # Capped at 20 full per-finding section blocks
    assert len(finding_sections) == 20
    # The overflow line names the remaining 10 findings
    all_text = json.dumps(blocks)
    assert "10 additional finding(s) not shown" in all_text
    # The whole message stays well under Slack's 50-block hard cap
    assert len(blocks) < 50


def test_slack_reliability_rendered_only_when_repeats_used():
    """attempts > 1 → reliability line carries ``successes/attempts (rate%)``;
    attempts == 1 → no reliability line (matches ``markdown-table``/h1md)."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=5,
        findings=[
            {
                "id": "f-eeee",
                "category": "prompt_injection",
                "severity": "high",
                "title": "flaky finding",
                "pattern_id": "p5",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.8,
                "attempts": 5,
                "successes": 3,
                "success_rate": 0.6,
            },
        ],
    )
    blocks = _payload(result)["attachments"][0]["blocks"]
    finding_sections = [
        b for b in blocks
        if b["type"] == "section" and "Finding ID:" in b["text"]["text"]
    ]
    assert "Reliability:" in finding_sections[0]["text"]["text"]
    assert "3/5" in finding_sections[0]["text"]["text"]


def test_slack_block_text_uses_mrkdwn_not_plain_text_for_section_blocks():
    """Section blocks MUST declare ``type: mrkdwn`` so Slack renders the bold
    ``*…*`` markers and inline ``code``. The header block is the ONLY block
    that uses plain_text (Slack header blocks accept plain_text only)."""
    blocks = _payload(_two_finding_result())["attachments"][0]["blocks"]
    for b in blocks:
        if b["type"] == "section":
            assert b["text"]["type"] == "mrkdwn"
        if b["type"] == "header":
            assert b["text"]["type"] == "plain_text"


def test_slack_end_to_end_via_cli(mock_llm, scope_file, capsys):
    """``--format slack`` from the CLI exits 0 and emits a parseable Slack
    webhook payload. Smoke-tests the wiring: CLI choice accepted, render()
    dispatches the new format, the payload parses as JSON and carries the
    documented top-level shape."""
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "slack",
        ]
    )
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    payload = json.loads(out)
    assert "text" in payload and "attachments" in payload
    assert payload["attachments"][0]["blocks"][0]["type"] == "header"
