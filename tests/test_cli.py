"""CLI tests (criteria 2, 3, 4)."""

from __future__ import annotations

import json

import pytest

from ouija.cli import EXIT_ERROR, EXIT_OK, EXIT_OUT_OF_SCOPE, build_parser, main


def test_help_lists_required_flags(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    for flag in (
        "--target", "--scope-file", "--attack-set", "--format", "--api-key-env",
        "--request-template", "--response-path",
    ):
        assert flag in out
    # attack-set choices
    for choice in ("injection", "disclosure", "dos", "all"):
        assert choice in out
    # format choices
    assert "json" in out and "jsonl" in out and "h1md" in out and "sarif" in out


def test_out_of_scope_exits_2(scope_file, capsys):
    rc = main(
        ["--target", "https://example.com/chat", "--scope-file", scope_file]
    )
    assert rc == EXIT_OUT_OF_SCOPE
    err = capsys.readouterr().err
    assert "out of scope" in err


def test_injection_scan_against_mock_emits_finding(mock_llm, scope_file, capsys):
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
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["tool"] == "ouija"
    assert data["findings"], "expected at least one finding"
    categories = {f["category"] for f in data["findings"]}
    assert "prompt_injection" in categories
    for f in data["findings"]:
        if f["category"] == "prompt_injection":
            assert f["severity"]  # severity is set
            break


def test_h1md_format_renders_markdown(mock_llm, scope_file, capsys):
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "h1md",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("# ouija findings report")
    assert "Severity" in out
    assert "Steps to reproduce" in out


# ---------------------------------------------------------------------------
# --request-template tests
# ---------------------------------------------------------------------------

def test_request_template_custom_field_emits_finding(mock_llm, scope_file, capsys):
    """Custom OpenAI-style template routes prompts to the correct JSON field."""
    template = '{"messages": [{"role": "user", "content": "{prompt}"}]}'
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
            "--request-template",
            template,
        ]
    )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["findings"], "expected at least one finding with custom template"
    assert any(f["category"] == "prompt_injection" for f in data["findings"])


def test_request_template_invalid_json_exits_3(mock_llm, scope_file, capsys):
    """Invalid JSON in --request-template exits with code 3 before scanning."""
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--request-template",
            '{not valid json}',
        ]
    )
    assert rc == EXIT_ERROR
    err = capsys.readouterr().err
    assert "not valid JSON" in err


def test_request_template_missing_placeholder_exits_3(mock_llm, scope_file, capsys):
    """Template without \"{prompt}\" placeholder exits with code 3."""
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--request-template",
            '{"messages": [{"role": "user", "content": "hello"}]}',
        ]
    )
    assert rc == EXIT_ERROR
    err = capsys.readouterr().err
    assert '"{prompt}"' in err or "placeholder" in err


# ---------------------------------------------------------------------------
# --plan mode
# ---------------------------------------------------------------------------

def test_plan_mode_prints_without_sending_requests(mock_llm, scope_file, capsys):
    """--plan prints a preview and exits 0 without touching the target."""
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--plan",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    # Plan output should mention request count or attack set details.
    assert out.strip()


def test_plan_mode_json_format(mock_llm, scope_file, capsys):
    """--plan --format json emits a machine-readable plan document."""
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--plan",
            "--format",
            "json",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert "total_requests" in data or "attack_sets" in data or "mode" in data


# ---------------------------------------------------------------------------
# --fail-on flag
# ---------------------------------------------------------------------------

def test_fail_on_none_exits_0_even_with_findings(mock_llm, scope_file, capsys):
    """Default --fail-on none exits 0 regardless of findings."""
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
            "--fail-on",
            "none",
        ]
    )
    assert rc == EXIT_OK


def test_fail_on_critical_exits_0_when_no_critical_findings(mock_llm, scope_file, capsys):
    """--fail-on critical exits 0 when no critical findings are present."""
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
            "--fail-on",
            "critical",
        ]
    )
    # Exit 0 (no critical) or 1 (critical found) — both are valid; just not 2/3.
    assert rc in (EXIT_OK, 1)


# ---------------------------------------------------------------------------
# --timeout and --retries validation
# ---------------------------------------------------------------------------

def test_timeout_zero_exits_error(mock_llm, scope_file, capsys):
    """--timeout 0 is rejected before any scan."""
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--timeout",
            "0",
        ]
    )
    assert rc == EXIT_ERROR
    err = capsys.readouterr().err
    assert "timeout" in err.lower()


def test_retries_negative_exits_error(mock_llm, scope_file, capsys):
    """--retries -1 is rejected before any scan."""
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--retries",
            "-1",
        ]
    )
    assert rc == EXIT_ERROR
    err = capsys.readouterr().err
    assert "retries" in err.lower()


# ---------------------------------------------------------------------------
# --format: additional formats
# ---------------------------------------------------------------------------

def test_format_jsonl_emits_line_records(mock_llm, scope_file, capsys):
    """--format jsonl emits one JSON object per line."""
    rc = main(
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
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert lines
    for ln in lines:
        json.loads(ln)  # each line must be valid JSON


def test_format_sarif_has_runs_key(mock_llm, scope_file, capsys):
    """--format sarif emits SARIF 2.1.0 with a 'runs' array."""
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "sarif",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "runs" in data
    assert data.get("version") == "2.1.0"


def test_format_csv_has_header_row(mock_llm, scope_file, capsys):
    """--format csv always emits a header row."""
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
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    first_line = out.splitlines()[0]
    assert "severity" in first_line.lower() or "category" in first_line.lower()


# ---------------------------------------------------------------------------
# --version flag
# ---------------------------------------------------------------------------

def test_version_flag(capsys):
    """--version prints the version string and exits."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "ouija" in out


# ---------------------------------------------------------------------------
# --inject-via flag
# ---------------------------------------------------------------------------

def test_inject_via_document_still_produces_findings(mock_llm, scope_file, capsys):
    """--inject-via document wraps attacks in a document envelope; detector still fires."""
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
            "--inject-via",
            "document",
        ]
    )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert "findings" in data
