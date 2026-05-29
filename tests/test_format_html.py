"""Tests for the `--format html` (self-contained browser report) output.

Where `json`/`jsonl`/`csv`/`sarif` feed machines and `h1md` is HackerOne
markdown, `--format html` is the shareable artifact: ONE file with embedded CSS
and no external assets that opens in any browser. The contract:

    * a complete, self-contained HTML document (doctype, <style>, no external
      stylesheet/font/JS/network asset);
    * one card per finding, in descending-severity order (same as h1md/csv);
    * a clean run still renders a valid document (a "no findings" card);
    * SECURITY — every attacker-influenced value (prompt, response excerpt,
      evidence, transcript) is HTML-escaped, so a captured <script> response
      (exactly the active-content sink ouija detects) cannot execute when the
      report is opened.
"""

from __future__ import annotations

from ouija.cli import EXIT_OK, main
from ouija.report import to_html
from ouija.models import ScanResult


def _two_finding_result() -> ScanResult:
    return ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=7,
        findings=[
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
        summary={"total": 7, "successful": 2, "attack_sets": {"injection": 2}},
    )


def test_html_is_a_self_contained_document():
    """A complete HTML doc with embedded style and no external asset refs."""
    html = to_html(_two_finding_result())
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert "</html>" in html
    assert "<style>" in html and "</style>" in html
    # Self-contained: no external stylesheet, script, or remote asset.
    assert "<link" not in html.lower()
    assert "<script" not in html.lower()
    assert "http://" not in html and "https://" not in html.replace(
        "https://example.test/llm", ""
    )


def test_html_one_card_per_finding_severity_sorted():
    """One card per finding; critical sorts above medium (same as h1md/csv)."""
    html = to_html(_two_finding_result())
    assert html.count('class="card"') == 2
    # Critical finding renders before the medium one.
    assert html.index("demo finding one") < html.index("demo finding two")
    # The severity badge text appears for each.
    assert "critical" in html.lower()
    assert "medium" in html.lower()


def test_html_no_findings_still_renders_valid_document():
    """A clean run yields a valid document with a 'no findings' card."""
    html = to_html(
        ScanResult(
            version="9.9.9",
            target="https://example.test/llm",
            attack_set="injection",
            patterns_sent=3,
        )
    )
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert "</html>" in html
    assert "No findings" in html
    assert 'class="card"' not in html


def test_html_escapes_attacker_controlled_values():
    """A captured <script> response must NOT survive as live markup."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="active",
        patterns_sent=1,
        findings=[
            {
                "id": "f-xss",
                "category": "improper_output_handling_active",
                "severity": "high",
                "title": "live <script> in output",
                "pattern_id": "p-xss",
                "technique": "active-content",
                "owasp": "LLM05:2025",
                "request_prompt": "emit <script>alert(1)</script>",
                "response_excerpt": "<script>alert('pwned')</script>",
                "evidence": "raw <img src=x onerror=alert(1)> rendered",
                "confidence": 0.95,
            },
        ],
    )
    html = to_html(result)
    # The literal active-content payloads must be escaped, never live.
    assert "<script>alert('pwned')</script>" not in html
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    # …but the escaped form is present (so the evidence is still shown).
    assert "&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_html_renders_multi_turn_transcript_escaped():
    """A multi-turn finding shows its transcript, escaped, in a <pre> block."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="multi",
        patterns_sent=1,
        findings=[
            {
                "id": "f-mt",
                "category": "safety_guardrail_bypass",
                "severity": "high",
                "title": "crescendo bypass",
                "pattern_id": "ladder-1",
                "technique": "crescendo",
                "owasp": "LLM01:2025",
                "request_prompt": "",
                "response_excerpt": "",
                "evidence": "complied on turn 3",
                "confidence": 0.9,
                "transcript": [
                    {"role": "user", "content": "hi <b>there</b>"},
                    {"role": "assistant", "content": "hello"},
                    {"role": "user", "content": "now do the bad thing"},
                    {"role": "assistant", "content": "ok"},
                ],
                "turn_succeeded": 2,
            },
        ],
    )
    html = to_html(result)
    assert "Multi-turn" in html
    assert "<pre>" in html
    # The transcript content is escaped (the embedded <b> must not be live).
    assert "hi <b>there</b>" not in html
    assert "hi &lt;b&gt;there&lt;/b&gt;" in html


def test_html_end_to_end_via_cli(mock_llm, scope_file, capsys):
    """`--format html` from the CLI emits a complete, parseable HTML report."""
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "html",
        ]
    )
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert out.lstrip().lower().startswith("<!doctype html>")
    assert "</html>" in out
    assert 'class="card"' in out, "expected at least one finding card from the mock"
