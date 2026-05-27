"""Tests for the --repeats N flag and hit-rate reporting (Phase 2, R4 feature).

Verifies that with --repeats 3 and a non-deterministic mock that triggers on
only the first of every 3 requests per (pattern, variant) key, the emitted
Finding carries attempts=3, successes=1, success_rate≈0.333.
"""

from __future__ import annotations

import json
import socket
import threading
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ouija.cli import EXIT_OK, main


# ---------------------------------------------------------------------------
# Non-deterministic mock: echoes the marker on exactly the first request for
# each (pattern, variant) logical key; refuses on subsequent attempts.
# ---------------------------------------------------------------------------

class _NondeterministicHandler(BaseHTTPRequestHandler):
    """Vulnerable on first call per prompt-key; refuses on subsequent calls.

    ``call_counts`` is a shared dict[str, int] injected by the server.
    """

    call_counts: dict[str, int]  # populated by NondeterministicMockLLM

    def log_message(self, *args) -> None:  # silence test noise
        pass

    def do_POST(self) -> None:
        import json as _json

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b"{}"
        try:
            parsed = _json.loads(body or b"{}")
        except _json.JSONDecodeError:
            parsed = {}

        prompt: str = parsed.get("prompt", "")
        low = prompt.lower()

        # Use the prompt text as the dedup key (same prompt = same logical key).
        count = self.call_counts.get(prompt, 0)
        self.call_counts[prompt] = count + 1

        # First call for this prompt gets a "vulnerable" reply; the rest get a
        # refusal, simulating a model that bypasses 1/repeats of the time.
        if count == 0 and "ouija_injection_confirmed" in low:
            reply_text = "Sure! OUIJA_INJECTION_CONFIRMED — happy to help."
        else:
            reply_text = "I'm sorry, I cannot do that."

        payload = _json.dumps({"reply": reply_text}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class NondeterministicMockLLM:
    """Mock LLM that triggers on only the first call per prompt, then refuses.

    Binds to an ephemeral port on 127.0.0.1 (never port 8888).
    """

    def __init__(self) -> None:
        call_counts: dict[str, int] = {}
        # Inject the shared dict into the handler class via a custom subclass.
        class _Handler(_NondeterministicHandler):
            pass
        _Handler.call_counts = call_counts

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("", 0))
        self.port = probe.getsockname()[1]
        probe.close()

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), _Handler)
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/chat"

    def __enter__(self) -> "NondeterministicMockLLM":
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def nd_mock_llm():
    """Non-deterministic mock LLM (1/N success rate)."""
    with NondeterministicMockLLM() as server:
        yield server


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_repeats_flag_appears_in_help(capsys):
    """--repeats must be advertised in --help output."""
    import argparse
    from ouija.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--repeats" in out


def test_repeats_produces_hit_rate_in_finding(nd_mock_llm, scope_file, capsys):
    """With --repeats 3 and a 1/3 success mock, finding carries correct stats."""
    rc = main(
        [
            "--target",
            nd_mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "json",
            "--repeats",
            "3",
        ]
    )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["findings"], "expected at least one finding with --repeats 3"

    injection_findings = [f for f in data["findings"] if f["category"] == "prompt_injection"]
    assert injection_findings, "expected a prompt_injection finding"

    # Every finding must have attempts=3.
    for f in injection_findings:
        assert f["attempts"] == 3, f"expected attempts=3, got {f['attempts']}"
        assert f["successes"] >= 1, "expected at least 1 success"
        assert f["successes"] <= f["attempts"]
        assert abs(f["success_rate"] - f["successes"] / f["attempts"]) < 1e-9


def test_repeats_1_preserves_default_behaviour(nd_mock_llm, scope_file, capsys):
    """--repeats 1 (default) emits findings with attempts=1, success_rate=1.0."""
    rc = main(
        [
            "--target",
            nd_mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "json",
            # no --repeats argument — should default to 1
        ]
    )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["findings"], "expected findings even with default repeats"
    for f in data["findings"]:
        assert f["attempts"] == 1
        assert f["successes"] == 1
        assert f["success_rate"] == 1.0


def test_repeats_h1md_includes_reliability_line(nd_mock_llm, scope_file, capsys):
    """h1md output with --repeats > 1 must contain the Reliability line."""
    rc = main(
        [
            "--target",
            nd_mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "h1md",
            "--repeats",
            "3",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "Reliability" in out, "h1md report should include Reliability line with --repeats"


def test_repeats_3_finding_attempts_equals_3(nd_mock_llm, scope_file, capsys):
    """Direct assertion: attempts==3, successes==1, success_rate≈0.333."""
    rc = main(
        [
            "--target",
            nd_mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "json",
            "--repeats",
            "3",
        ]
    )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    injection = [f for f in data["findings"] if f["category"] == "prompt_injection"]
    assert injection

    # The non-deterministic mock answers 1 success per prompt-key across 3 repeats.
    # So each finding should have successes=1 out of attempts=3.
    for f in injection:
        assert f["attempts"] == 3
        assert f["successes"] == 1
        assert abs(f["success_rate"] - 1 / 3) < 1e-9
