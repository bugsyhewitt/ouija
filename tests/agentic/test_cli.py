"""Unit tests for the ouija-agentic CLI (exit codes + gates + output)."""

from __future__ import annotations

import json

import pytest

from ouija.agentic_cli import (
    EXIT_CONFIRMED,
    EXIT_ERROR,
    EXIT_OK,
    EXIT_REFUSED,
    build_parser,
    main,
)


def test_list_probes_json(capsys):
    rc = main(["list-probes", "--format", "json"])
    assert rc == EXIT_OK
    cat = json.loads(capsys.readouterr().out)
    assert len(cat) >= 14


def test_list_probes_table(capsys):
    rc = main(["list-probes", "--format", "table"])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "mcp_tool_poisoning" in out and "ASI02" in out


def test_active_verb_requires_confirm(capsys):
    rc = main(["scan-mcp", "--url", "http://example.com/mcp"])
    assert rc == EXIT_ERROR
    assert "ACTIVE" in capsys.readouterr().err


def test_active_verb_refuses_non_allowlisted(capsys):
    rc = main(["scan-mcp", "--url", "http://evil.example/mcp", "--confirm"])
    assert rc == EXIT_REFUSED
    assert "allow-list" in capsys.readouterr().err


def test_scan_mcp_lab_exits_confirmed(capsys):
    rc = main(["scan-mcp", "--lab", "--confirm", "--repeats", "6"])
    assert rc == EXIT_CONFIRMED  # confirmed findings -> exit 1 (CI-gateable)
    data = json.loads(capsys.readouterr().out)
    assert data["verb"] == "scan_mcp"
    assert data["summary"]["confirmed"] >= 1
    assert data["summary"]["detected"] >= 1
    assert "by_owasp" in data["summary"]


def test_scan_rag_lab_exits_confirmed(capsys):
    rc = main(["scan-rag", "--lab", "--confirm", "--repeats", "6"])
    assert rc == EXIT_CONFIRMED
    data = json.loads(capsys.readouterr().out)
    assert data["verb"] == "scan_rag" and data["summary"]["confirmed"] >= 1


def test_fuzz_agent_lab_exits_confirmed(capsys):
    rc = main(["fuzz-agent", "--lab", "--confirm", "--repeats", "6"])
    assert rc == EXIT_CONFIRMED
    data = json.loads(capsys.readouterr().out)
    assert data["verb"] == "fuzz_agent" and data["summary"]["confirmed"] >= 1


def test_missing_target_without_lab(capsys):
    rc = main(["scan-rag", "--confirm"])
    assert rc == EXIT_ERROR
    assert "target" in capsys.readouterr().err.lower()


def test_parser_requires_subcommand():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])
