"""Tests for the structured `--format json` report schema.

Bug-bounty hunters pipe ouija's JSON into jq, grep, and report templates, so the
JSON output must be a stable, machine-readable contract: a scan_id, an ISO
timestamp, every Finding field, and a roll-up summary block.
"""

from __future__ import annotations

import datetime
import json

from ouija.cli import EXIT_OK, main


def _run_json(mock_llm, scope_file, capsys, attack_set="injection"):
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            attack_set,
            "--format",
            "json",
        ]
    )
    out = capsys.readouterr().out
    return rc, json.loads(out)


def test_json_is_valid_and_top_level_schema(mock_llm, scope_file, capsys):
    """Output parses as JSON and carries the documented top-level keys."""
    rc, data = _run_json(mock_llm, scope_file, capsys)
    assert rc == EXIT_OK
    for key in (
        "tool",
        "version",
        "scan_id",
        "timestamp",
        "target",
        "attack_set",
        "patterns_sent",
        "findings",
        "summary",
    ):
        assert key in data, f"missing top-level key {key!r}"
    assert data["tool"] == "ouija"


def test_json_scan_id_is_present_and_unique(mock_llm, scope_file, capsys):
    """Each run gets a distinct scan_id so artifacts can be correlated/deduped."""
    _, first = _run_json(mock_llm, scope_file, capsys)
    _, second = _run_json(mock_llm, scope_file, capsys)
    assert first["scan_id"]
    assert second["scan_id"]
    assert first["scan_id"] != second["scan_id"]


def test_json_timestamp_is_iso8601(mock_llm, scope_file, capsys):
    """timestamp must be a parseable ISO-8601 instant."""
    _, data = _run_json(mock_llm, scope_file, capsys)
    # Raises ValueError if not ISO-8601; that's the assertion.
    parsed = datetime.datetime.fromisoformat(data["timestamp"])
    assert parsed.tzinfo is not None, "timestamp must be timezone-aware (UTC)"


def test_json_findings_carry_all_finding_fields(mock_llm, scope_file, capsys):
    """Every Finding field required by the schema is present on each finding."""
    _, data = _run_json(mock_llm, scope_file, capsys)
    assert data["findings"], "expected at least one finding from the vuln mock"
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
    for finding in data["findings"]:
        missing = required - set(finding)
        assert not missing, f"finding missing fields: {missing}"


def test_json_summary_schema_and_consistency(mock_llm, scope_file, capsys):
    """summary block has total/successful/attack_sets and is internally consistent."""
    _, data = _run_json(mock_llm, scope_file, capsys)
    summary = data["summary"]
    for key in ("total", "successful", "attack_sets"):
        assert key in summary, f"summary missing {key!r}"

    # successful counts the emitted findings.
    assert summary["successful"] == len(data["findings"])
    # total mirrors patterns_sent (number of probes dispatched).
    assert summary["total"] == data["patterns_sent"]
    # per-attack-set counts sum to the total number of findings.
    assert sum(summary["attack_sets"].values()) == len(data["findings"])


def test_json_summary_attack_set_breakdown_on_all(mock_llm, scope_file, capsys):
    """An 'all' run breaks findings down by attack-set name in the summary."""
    _, data = _run_json(mock_llm, scope_file, capsys, attack_set="all")
    summary = data["summary"]
    assert summary["successful"] >= 1
    # Keys are human-readable attack-set names, not raw categories.
    assert all(isinstance(k, str) for k in summary["attack_sets"])
    assert "injection" in summary["attack_sets"]


def test_json_is_jq_pipeable_single_object(mock_llm, scope_file, capsys):
    """Output is exactly one JSON document (no banner/log noise on stdout)."""
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
    out = capsys.readouterr().out.strip()
    # json.loads over the whole stdout must succeed and consume all of it.
    obj = json.loads(out)
    assert isinstance(obj, dict)
