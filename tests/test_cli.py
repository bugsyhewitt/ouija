"""CLI tests (criteria 2, 3, 4)."""

from __future__ import annotations

import json

import pytest

from ouija.cli import EXIT_OK, EXIT_OUT_OF_SCOPE, build_parser, main


def test_help_lists_required_flags(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    for flag in ("--target", "--scope-file", "--attack-set", "--format", "--api-key-env"):
        assert flag in out
    # attack-set choices
    for choice in ("injection", "disclosure", "dos", "all"):
        assert choice in out
    # format choices
    assert "json" in out and "h1md" in out


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
