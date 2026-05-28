"""Tests for --response-path: pinned response extraction (POST_V01 Item 3).

Covers three layers:
  1. The dependency-free selector parser/extractor (unit).
  2. End-to-end CLI scan against an OpenAI-shaped response that the heuristic
     would otherwise mis-read — proving --response-path is what makes the
     finding land (criterion: no silent zero-finding on non-standard shapes).
  3. Invalid --response-path syntax exits 3 before any request.
"""

from __future__ import annotations

import json

import pytest

from ouija.client import (
    ResponsePathError,
    extract_by_path,
    parse_response_path,
)
from ouija.cli import EXIT_ERROR, EXIT_OK, main
from tests.mock_llm import MockLLM, openai_response_shape


# ---------------------------------------------------------------------------
# Parser unit tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "path,expected",
    [
        ("reply", ["reply"]),
        ("choices.0.message.content", ["choices", 0, "message", "content"]),
        ("choices[0].message.content", ["choices", 0, "message", "content"]),
        ("data[0][1].text", ["data", 0, 1, "text"]),
        ("a.b.c", ["a", "b", "c"]),
        # Bracket-quoted keys are unquoted (useful when a key looks numeric).
        ("data['0'].text", ["data", "0", "text"]),
    ],
)
def test_parse_response_path(path, expected):
    assert parse_response_path(path) == expected


@pytest.mark.parametrize("bad", ["", "   ", "a..b", "a[", "a[]", "a[0", "a[0]b"])
def test_parse_response_path_invalid(bad):
    with pytest.raises(ResponsePathError):
        parse_response_path(bad)


# ---------------------------------------------------------------------------
# Extractor unit tests
# ---------------------------------------------------------------------------

def test_extract_by_path_openai_shape():
    payload = {
        "choices": [{"message": {"content": "HELLO", "refusal": None}}]
    }
    steps = parse_response_path("choices.0.message.content")
    assert extract_by_path(payload, steps) == "HELLO"


def test_extract_by_path_missing_returns_empty():
    payload = {"choices": []}
    steps = parse_response_path("choices.0.message.content")
    # Out-of-range index resolves to "" (caller falls back to raw body).
    assert extract_by_path(payload, steps) == ""


def test_extract_by_path_non_string_returns_empty():
    payload = {"a": {"b": 123}}
    steps = parse_response_path("a.b")
    assert extract_by_path(payload, steps) == ""


def test_extract_by_path_negative_index():
    payload = {"items": ["first", "last"]}
    steps = parse_response_path("items[-1]")
    assert extract_by_path(payload, steps) == "last"


# ---------------------------------------------------------------------------
# End-to-end: OpenAI request + response shape driven by template + path
# ---------------------------------------------------------------------------

def test_response_path_reads_openai_shape_and_emits_finding(scope_file, capsys):
    """With --request-template + --response-path, ouija targets a fully
    OpenAI-shaped endpoint (messages-in, choices[0].message.content-out) and
    still lands the injection finding."""
    template = '{"messages": [{"role": "user", "content": "{prompt}"}]}'
    with MockLLM(response_shape=openai_response_shape) as server:
        rc = main(
            [
                "--target", server.url,
                "--scope-file", scope_file,
                "--attack-set", "injection",
                "--format", "json",
                "--request-template", template,
                "--response-path", "choices.0.message.content",
            ]
        )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["findings"], "expected a finding when response-path pins the reply"
    assert any(f["category"] == "prompt_injection" for f in data["findings"])


def test_invalid_response_path_exits_3(mock_llm, scope_file, capsys):
    rc = main(
        [
            "--target", mock_llm.url,
            "--scope-file", scope_file,
            "--response-path", "a..b",
        ]
    )
    assert rc == EXIT_ERROR
    assert "response-path" in capsys.readouterr().err


def test_default_extraction_unchanged_without_response_path(mock_llm, scope_file, capsys):
    """Regression guard: omitting --response-path preserves heuristic behaviour."""
    rc = main(
        [
            "--target", mock_llm.url,
            "--scope-file", scope_file,
            "--attack-set", "injection",
            "--format", "json",
        ]
    )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["findings"]
