"""Tests for the finding baseline / suppression feature.

A baseline lets a bug-bounty hunter snapshot already-triaged finding IDs and, on
a later run, suppress them — so reruns surface only genuinely new findings and a
``--fail-on`` CI gate breaks only on what is new. The IDs are deterministic
(:func:`ouija.detect.stable_finding_id`), so a baseline is just a set of IDs.
"""

from __future__ import annotations

import json

import pytest

from ouija.baseline import (
    BaselineError,
    apply_baseline,
    load_baseline,
    write_baseline,
)
from ouija.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from ouija.models import Finding, ScanResult, ScanSummary, Severity


# --- pure-function unit tests (no network) ---


def _finding(fid: str, category: str = "prompt_injection") -> Finding:
    return Finding(
        id=fid,
        category=category,
        severity=Severity.HIGH,
        title="t",
        pattern_id="p",
        technique="tech",
        owasp="LLM01",
        request_prompt="rp",
        response_excerpt="re",
        evidence="ev",
        confidence=0.9,
    )


def _result(*findings: Finding) -> ScanResult:
    return ScanResult(
        version="0.0.0",
        target="http://t",
        attack_set="injection",
        patterns_sent=10,
        findings=list(findings),
        summary=ScanSummary(
            total=10, successful=len(findings), attack_sets={"injection": len(findings)}
        ),
    )


def test_load_baseline_line_format(tmp_path):
    p = tmp_path / "baseline.txt"
    p.write_text(
        "# a header comment\n"
        "ouija-inj-aaaaaaaa\n"
        "\n"
        "ouija-pii-bbbbbbbb   # inline comment\n"
    )
    assert load_baseline(str(p)) == {"ouija-inj-aaaaaaaa", "ouija-pii-bbbbbbbb"}


def test_load_baseline_from_saved_json_report(tmp_path):
    """A saved ``ouija --format json`` report is accepted as a baseline."""
    doc = {
        "tool": "ouija",
        "findings": [
            {"id": "ouija-inj-11111111"},
            {"id": "ouija-pii-22222222"},
        ],
    }
    p = tmp_path / "report.json"
    p.write_text(json.dumps(doc))
    assert load_baseline(str(p)) == {"ouija-inj-11111111", "ouija-pii-22222222"}


def test_load_baseline_missing_file_raises():
    with pytest.raises(BaselineError):
        load_baseline("/nonexistent/path/baseline.txt")


def test_load_baseline_malformed_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json")
    with pytest.raises(BaselineError):
        load_baseline(str(p))


def test_apply_baseline_removes_matched_findings():
    result = _result(_finding("ouija-inj-aaaaaaaa"), _finding("ouija-pii-bbbbbbbb"))
    outcome = apply_baseline(result, {"ouija-inj-aaaaaaaa"})
    assert outcome.suppressed == 1
    remaining = [f.id for f in outcome.result.findings]
    assert remaining == ["ouija-pii-bbbbbbbb"]
    # patterns_sent preserved; summary recomputed.
    assert outcome.result.patterns_sent == 10
    assert outcome.result.summary.successful == 1


def test_apply_baseline_does_not_mutate_input():
    result = _result(_finding("ouija-inj-aaaaaaaa"))
    apply_baseline(result, {"ouija-inj-aaaaaaaa"})
    assert len(result.findings) == 1, "input result must be left untouched"


def test_apply_empty_baseline_is_noop():
    result = _result(_finding("ouija-inj-aaaaaaaa"))
    outcome = apply_baseline(result, set())
    assert outcome.suppressed == 0
    assert outcome.result is result


def test_write_baseline_roundtrips(tmp_path):
    """Writing then loading a baseline preserves exactly the finding ID set."""
    result = _result(
        _finding("ouija-inj-aaaaaaaa"),
        _finding("ouija-pii-bbbbbbbb", category="pii_disclosure"),
    )
    p = tmp_path / "out.txt"
    count = write_baseline(result, str(p))
    assert count == 2
    assert load_baseline(str(p)) == {"ouija-inj-aaaaaaaa", "ouija-pii-bbbbbbbb"}


def test_write_baseline_dedupes(tmp_path):
    result = _result(_finding("ouija-inj-aaaaaaaa"), _finding("ouija-inj-aaaaaaaa"))
    p = tmp_path / "out.txt"
    count = write_baseline(result, str(p))
    assert count == 1


# --- end-to-end tests (through the CLI) ---


def _scan_json(mock_llm, scope_file, capsys, *extra):
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "json",
            *extra,
        ]
    )
    return rc, json.loads(capsys.readouterr().out)


def test_write_then_baseline_suppresses_everything(mock_llm, scope_file, capsys, tmp_path):
    """A baseline written from a run suppresses every finding on an identical rerun."""
    baseline = tmp_path / "baseline.txt"
    rc1, first = _scan_json(mock_llm, scope_file, capsys, "--write-baseline", str(baseline))
    assert rc1 == EXIT_OK
    assert first["findings"], "expected findings on the first run"

    rc2, second = _scan_json(mock_llm, scope_file, capsys, "--baseline", str(baseline))
    assert rc2 == EXIT_OK
    assert second["findings"] == [], "all findings should be suppressed by the baseline"
    assert second["summary"]["successful"] == 0
    # patterns_sent still reflects the work done.
    assert second["patterns_sent"] == first["patterns_sent"]


def test_baseline_excludes_suppressed_from_fail_on_gate(mock_llm, scope_file, capsys, tmp_path):
    """A baselined finding must not trip --fail-on (it is already triaged)."""
    baseline = tmp_path / "baseline.txt"
    # First, snapshot the findings and confirm --fail-on would otherwise trip.
    rc_gate = main(
        [
            "--target", mock_llm.url, "--scope-file", scope_file,
            "--attack-set", "injection", "--format", "json",
            "--fail-on", "info", "--write-baseline", str(baseline),
        ]
    )
    capsys.readouterr()
    assert rc_gate == EXIT_FINDINGS, "without a baseline, findings should fail the gate"

    # Now the same scan with that baseline must pass the gate.
    rc_clean = main(
        [
            "--target", mock_llm.url, "--scope-file", scope_file,
            "--attack-set", "injection", "--format", "json",
            "--fail-on", "info", "--baseline", str(baseline),
        ]
    )
    capsys.readouterr()
    assert rc_clean == EXIT_OK, "baselined findings must not trip --fail-on"


def test_baseline_missing_file_exits_3_before_scanning(mock_llm, scope_file, capsys):
    rc = main(
        [
            "--target", mock_llm.url, "--scope-file", scope_file,
            "--baseline", "/nonexistent/baseline.txt",
        ]
    )
    assert rc == EXIT_ERROR
    err = capsys.readouterr().err
    assert "baseline" in err


def test_baseline_h1md_omits_suppressed_finding(mock_llm, scope_file, capsys, tmp_path):
    """h1md output reflects suppression (no findings -> the empty-report line)."""
    baseline = tmp_path / "baseline.txt"
    main(
        [
            "--target", mock_llm.url, "--scope-file", scope_file,
            "--attack-set", "injection", "--format", "json",
            "--write-baseline", str(baseline),
        ]
    )
    capsys.readouterr()
    rc = main(
        [
            "--target", mock_llm.url, "--scope-file", scope_file,
            "--attack-set", "injection", "--format", "h1md",
            "--baseline", str(baseline),
        ]
    )
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "No findings" in out


def test_help_lists_baseline_flags(capsys):
    from ouija.cli import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--baseline" in out
    assert "--write-baseline" in out
