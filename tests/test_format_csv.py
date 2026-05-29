"""Tests for the `--format csv` (spreadsheet-friendly) output.

Where `--format json`/`jsonl` are machine-pipe formats and `h1md` is a prose
report, `--format csv` emits one row per finding with a stable header — the
shape a bug-bounty triager pastes straight into a spreadsheet to sort, filter,
and assign findings by severity/category. The contract:

    * exactly one header row, always (even with zero findings);
    * one data row per finding, in descending-severity order;
    * RFC-4180 quoting so multi-line evidence / prompts never break a row;
    * a fixed, documented column set keyed off the Finding model fields a
      triager cares about (id, severity, category, owasp, title, …).
"""

from __future__ import annotations

import csv
import io

from ouija.cli import EXIT_OK, main
from ouija.report import CSV_COLUMNS, to_csv
from ouija.models import ScanResult


def _parse(csv_text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(csv_text)))


def _two_finding_result() -> ScanResult:
    base = {
        "version": "9.9.9",
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


def test_csv_has_header_and_one_row_per_finding():
    result = _two_finding_result()
    rows = _parse(to_csv(result))
    assert len(rows) == 2, "one data row per finding"
    assert list(rows[0].keys()) == list(CSV_COLUMNS), "stable column order"


def test_csv_rows_are_sorted_by_severity_desc():
    """Critical sorts above medium — same ordering as the h1md report."""
    result = _two_finding_result()
    rows = _parse(to_csv(result))
    assert rows[0]["severity"] == "critical"
    assert rows[1]["severity"] == "medium"


def test_csv_no_findings_still_emits_header_only():
    """A clean run yields the header row and zero data rows."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=3,
    )
    text = to_csv(result)
    rows = _parse(text)
    assert rows == [], "no findings → no data rows"
    # but the header line is still present
    header = text.splitlines()[0]
    assert header.split(",")[0] == CSV_COLUMNS[0]


def test_csv_quotes_fields_with_commas_and_newlines():
    """RFC-4180 quoting: a comma/newline in evidence must not break the row."""
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
                "title": "tricky, finding",
                "pattern_id": "p3",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "line one\nline two, with comma",
                "response_excerpt": 'he said "hi"',
                "evidence": "a, b\nc",
                "confidence": 0.8,
            },
        ],
    )
    text = to_csv(result)
    rows = _parse(text)
    assert len(rows) == 1, "the multi-line/comma field stayed in one logical row"
    assert rows[0]["request_prompt"] == "line one\nline two, with comma"
    assert rows[0]["evidence"] == "a, b\nc"
    assert rows[0]["response_excerpt"] == 'he said "hi"'


def test_csv_carries_reliability_columns():
    """attempts/successes/success_rate land in the row when --repeats > 1."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=5,
        findings=[
            {
                "id": "f-dddd",
                "category": "prompt_injection",
                "severity": "high",
                "title": "flaky finding",
                "pattern_id": "p4",
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
    rows = _parse(to_csv(result))
    assert rows[0]["attempts"] == "5"
    assert rows[0]["successes"] == "3"
    assert rows[0]["success_rate"] == "0.6"


def test_csv_end_to_end_via_cli(mock_llm, scope_file, capsys):
    """`--format csv` from the CLI yields a parseable header + finding rows."""
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "csv",
        ]
    )
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    rows = _parse(out)
    assert rows, "expected at least one finding row from the vuln mock"
    for row in rows:
        assert set(CSV_COLUMNS) <= set(row.keys())
        assert row["id"]
        assert row["severity"]
