"""Tests for the streaming `--format jsonl` (JSON Lines / NDJSON) output.

Where `--format json` emits one indented document, `--format jsonl` emits one
compact JSON object per line so the output is *streamable* — a log shipper,
`jq -c`, or a `while read line` loop can consume each record without buffering
the whole report. The stream is a discriminated sequence:

    {"record": "scan", ...}      # exactly one header line, first
    {"record": "finding", ...}   # zero-or-more, one full finding each
    {"record": "summary", ...}   # exactly one footer line, last

This contract must stay information-equivalent to the single `json` document.
"""

from __future__ import annotations

import json

from ouija.cli import EXIT_OK, main
from ouija.report import to_json, to_jsonl
from ouija.models import ScanResult


def _run_jsonl(mock_llm, scope_file, capsys, attack_set="injection"):
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            attack_set,
            "--format",
            "jsonl",
        ]
    )
    out = capsys.readouterr().out.strip()
    records = [json.loads(line) for line in out.splitlines() if line.strip()]
    return rc, records


def test_jsonl_every_line_is_standalone_json(mock_llm, scope_file, capsys):
    """Each non-empty stdout line parses independently as one JSON object."""
    rc, records = _run_jsonl(mock_llm, scope_file, capsys)
    assert rc == EXIT_OK
    assert records, "expected at least the scan + summary records"
    for rec in records:
        assert isinstance(rec, dict)
        assert "record" in rec, "every line must carry a 'record' discriminator"


def test_jsonl_is_not_a_single_indented_document(mock_llm, scope_file, capsys):
    """jsonl must differ from json: multiple lines, no leading whitespace indent."""
    main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "jsonl",
        ]
    )
    out = capsys.readouterr().out.strip()
    # More than one line, and the whole blob is NOT one parseable JSON document.
    assert "\n" in out
    try:
        json.loads(out)
        parsed_whole = True
    except json.JSONDecodeError:
        parsed_whole = False
    assert not parsed_whole, "jsonl output must not be one JSON document"


def test_jsonl_record_order_scan_findings_summary(mock_llm, scope_file, capsys):
    """The stream is exactly: one 'scan' first, then findings, one 'summary' last."""
    _, records = _run_jsonl(mock_llm, scope_file, capsys)
    kinds = [r["record"] for r in records]
    assert kinds[0] == "scan", "first record must be the scan header"
    assert kinds[-1] == "summary", "last record must be the summary footer"
    assert kinds.count("scan") == 1
    assert kinds.count("summary") == 1
    # Everything between the header and footer is a finding.
    assert all(k == "finding" for k in kinds[1:-1])


def test_jsonl_scan_header_carries_run_identity(mock_llm, scope_file, capsys):
    """The 'scan' header carries top-level run identity but NOT findings/summary."""
    _, records = _run_jsonl(mock_llm, scope_file, capsys)
    scan = next(r for r in records if r["record"] == "scan")
    for key in (
        "tool",
        "version",
        "scan_id",
        "timestamp",
        "target",
        "attack_set",
        "patterns_sent",
    ):
        assert key in scan, f"scan header missing {key!r}"
    # findings/summary are streamed as their own records, not nested here.
    assert "findings" not in scan
    assert "summary" not in scan


def test_jsonl_findings_carry_all_finding_fields(mock_llm, scope_file, capsys):
    """Each 'finding' record carries every documented Finding field."""
    _, records = _run_jsonl(mock_llm, scope_file, capsys)
    findings = [r for r in records if r["record"] == "finding"]
    assert findings, "expected at least one finding from the vuln mock"
    required = {
        "id",
        "category",
        "severity",
        "title",
        "pattern_id",
        "technique",
        "owasp",
        "request_prompt",
        "response_excerpt",
        "evidence",
        "confidence",
        "attempts",
        "successes",
        "success_rate",
    }
    for finding in findings:
        missing = required - set(finding)
        assert not missing, f"finding record missing fields: {missing}"


def test_jsonl_summary_footer_matches_finding_count(mock_llm, scope_file, capsys):
    """The 'summary' footer's counts agree with the streamed finding lines."""
    _, records = _run_jsonl(mock_llm, scope_file, capsys)
    findings = [r for r in records if r["record"] == "finding"]
    summary = next(r for r in records if r["record"] == "summary")
    for key in ("total", "successful", "attack_sets"):
        assert key in summary, f"summary footer missing {key!r}"
    assert summary["successful"] == len(findings)
    assert sum(summary["attack_sets"].values()) == len(findings)


def test_jsonl_is_information_equivalent_to_json():
    """jsonl reshapes the json document without losing any detail.

    Reassembling the discriminated records back into a single object must
    reproduce the exact `model_dump` that `--format json` serializes.
    """
    # Build a result with two findings so reassembly covers >1 finding line.
    base = {
        "version": "9.9.9",
        "target": "https://example.test/llm",
        "attack_set": "injection",
        "patterns_sent": 7,
        "findings": [
            {
                "id": "f-aaaa",
                "category": "prompt_injection",
                "severity": "high",
                "title": "demo finding one",
                "pattern_id": "p1",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "ignore previous",
                "response_excerpt": "ok, ignoring",
                "evidence": "marker present",
                "confidence": 0.9,
            },
            {
                "id": "f-bbbb",
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
        ],
        "summary": {
            "total": 7,
            "successful": 2,
            "attack_sets": {"injection": 2},
        },
    }
    result = ScanResult(**base)

    json_doc = json.loads(to_json(result))

    lines = [json.loads(line) for line in to_jsonl(result).splitlines()]
    scan = next(line for line in lines if line["record"] == "scan")
    findings = [line for line in lines if line["record"] == "finding"]
    summary = next(line for line in lines if line["record"] == "summary")

    # Strip the record discriminators and reassemble.
    reassembled = {k: v for k, v in scan.items() if k != "record"}
    reassembled["findings"] = [
        {k: v for k, v in f.items() if k != "record"} for f in findings
    ]
    reassembled["summary"] = {k: v for k, v in summary.items() if k != "record"}

    assert reassembled == json_doc


def test_jsonl_no_findings_still_emits_scan_and_summary(mock_llm, scope_file, capsys):
    """A clean (no-finding) result still yields exactly a scan + summary line."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=3,
    )
    lines = [json.loads(line) for line in to_jsonl(result).splitlines()]
    kinds = [line["record"] for line in lines]
    assert kinds == ["scan", "summary"]
