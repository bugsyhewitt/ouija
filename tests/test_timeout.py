"""Tests for --timeout SECONDS: per-probe HTTP request timeout.

ouija probes live LLM endpoints that may be very slow — inference can take
tens of seconds or more for long-running DoS probes.  Without a configurable
timeout, operators are stuck with the hardcoded 20 s default even when they
want a 5 s fast-fail on an unresponsive server, or 120 s on a slow inference
box.  ``--timeout SECONDS`` exposes that control.

Coverage:
  - --timeout appears in --help.
  - --timeout defaults to 20.0 in argparse.
  - --timeout 0 exits with code 3 (validation error, must be > 0).
  - --timeout -5 exits with code 3 (negative not allowed).
  - TargetClient stores an explicit timeout value.
  - TargetClient defaults to 20.0 seconds when not overridden.
  - TargetClient passes its timeout to the underlying httpx POST call.
  - run_scan() threads timeout through to TargetClient.
  - End-to-end: --timeout N with a fast mock server completes successfully.
  - End-to-end: --timeout 0.05 against a server that sleeps exits with code 3
    (scan fails with a timeout/transport error, surfaced as usage/runtime error).
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from ouija.cli import EXIT_ERROR, EXIT_OK, build_parser, main
from ouija.client import TargetClient


# ---------------------------------------------------------------------------
# Mock servers
# ---------------------------------------------------------------------------

class _ImmediateHandler(BaseHTTPRequestHandler):
    """Returns a valid JSON response immediately."""
    log_message = lambda *a: None  # silence request logs

    def do_POST(self):  # noqa: N802
        body = json.dumps({"reply": "hello"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SlowHandler(BaseHTTPRequestHandler):
    """Sleeps before responding, to trigger timeouts."""
    delay: float = 1.0
    log_message = lambda *a: None

    def do_POST(self):  # noqa: N802
        time.sleep(self.__class__.delay)
        body = json.dumps({"reply": "late"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_server(handler_class) -> tuple[ThreadingHTTPServer, str]:
    """Start a ThreadingHTTPServer on an ephemeral port; return (server, url)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler_class)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# CLI unit tests: flag presence, default, validation
# ---------------------------------------------------------------------------

def test_timeout_flag_in_help():
    """--timeout is advertised in --help output."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    import io, sys
    buf = io.StringIO()
    try:
        parser.parse_args(["--help"])
    except SystemExit:
        pass
    # build_parser() is not a help action we can capture easily without capsys,
    # so just confirm --timeout exists in the argument namespace.
    # (capsys-based assertion is in the integration test below)
    assert any(a.dest == "timeout" for a in parser._actions)


def test_timeout_flag_in_help_output(capsys):
    """--timeout appears in the --help text."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--timeout" in out


def test_timeout_default_is_20(capsys):
    """argparse default for --timeout is 20.0 seconds."""
    parser = build_parser()
    args = parser.parse_args([
        "--target", "http://127.0.0.1:1",
        "--scope-file", "scope.txt",
    ])
    assert args.timeout == 20.0


def test_timeout_zero_exits_error(scope_file, capsys):
    """--timeout 0 is rejected with exit code 3 (must be > 0)."""
    rc = main([
        "--target", "http://127.0.0.1:1",
        "--scope-file", scope_file,
        "--timeout", "0",
    ])
    assert rc == EXIT_ERROR
    err = capsys.readouterr().err
    assert "timeout" in err.lower()


def test_timeout_negative_exits_error(scope_file, capsys):
    """--timeout -5 is rejected with exit code 3."""
    rc = main([
        "--target", "http://127.0.0.1:1",
        "--scope-file", scope_file,
        "--timeout", "-5",
    ])
    assert rc == EXIT_ERROR
    err = capsys.readouterr().err
    assert "timeout" in err.lower()


# ---------------------------------------------------------------------------
# TargetClient unit tests
# ---------------------------------------------------------------------------

def test_target_client_timeout_defaults_to_20():
    """TargetClient.timeout defaults to 20.0 s when not supplied."""
    client = TargetClient("http://127.0.0.1:1")
    assert client.timeout == 20.0


def test_target_client_timeout_stored():
    """Explicit timeout value is stored on the instance."""
    client = TargetClient("http://127.0.0.1:1", timeout=42.5)
    assert client.timeout == 42.5


def test_target_client_passes_timeout_to_httpx():
    """TargetClient._do_post passes its timeout to httpx.AsyncClient.post."""
    client = TargetClient("http://127.0.0.1:1", timeout=7.0)

    calls: list = []

    async def _run():
        async def fake_post(url, *, content, headers, timeout):
            calls.append(timeout)
            # Return a minimal mock response so _do_post's retryable check works.
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            return mock_resp

        mock_http = AsyncMock()
        mock_http.post = fake_post
        await client._do_post(mock_http, b'{"prompt":"test"}')

    asyncio.run(_run())
    assert calls == [7.0], f"expected [7.0], got {calls}"


# ---------------------------------------------------------------------------
# Integration tests (real HTTP server)
# ---------------------------------------------------------------------------

def test_timeout_valid_value_scan_completes(scope_file, capsys):
    """--timeout 30 with a fast mock server completes with exit 0."""
    srv, url = _start_server(_ImmediateHandler)
    try:
        rc = main([
            "--target", url,
            "--scope-file", scope_file,
            "--attack-set", "injection",
            "--format", "json",
            "--timeout", "30",
        ])
    finally:
        srv.shutdown()
    # Exit 0 = scan completed without --fail-on tripping.
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["tool"] == "ouija"


def test_timeout_very_short_against_slow_server_exits_error(scope_file, capsys):
    """A very short --timeout against a slow server surfaces as exit code 3.

    The slow server sleeps 1 s; we set --timeout 0.05 (50 ms) so every probe
    times out.  httpx raises TimeoutException → scanner catches it and exits 3.
    """
    _SlowHandler.delay = 1.0
    srv, url = _start_server(_SlowHandler)
    try:
        rc = main([
            "--target", url,
            "--scope-file", scope_file,
            "--attack-set", "injection",
            "--concurrency", "1",   # one probe at a time so we don't flood
            "--timeout", "0.05",
        ])
    finally:
        srv.shutdown()
    assert rc == EXIT_ERROR
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_timeout_plan_mode_accepts_custom_timeout(scope_file, capsys):
    """--plan does not send requests; --timeout is validated but not used."""
    rc = main([
        "--target", "http://127.0.0.1:1",
        "--scope-file", scope_file,
        "--attack-set", "injection",
        "--timeout", "60",
        "--plan",
    ])
    # --plan exits 0 (scope gate doesn't fire because 127.0.0.1 is in scope).
    assert rc == EXIT_OK


def test_run_scan_threads_timeout(scope_file):
    """run_scan() passes timeout to TargetClient (unit-level check via mock)."""
    from ouija.corpus import load_attack_set
    from ouija.scanner import run_scan

    loaded = load_attack_set("injection")

    captured: list = []

    original_init = TargetClient.__init__

    def patched_init(self, target, **kwargs):
        captured.append(kwargs.get("timeout", "NOT_PASSED"))
        original_init(self, target, **kwargs)

    with patch.object(TargetClient, "__init__", patched_init):
        # Use a dead port — scan will fail, that's fine; we only care the
        # timeout was forwarded.
        try:
            run_scan(
                target="http://127.0.0.1:1",
                attack_set_name="injection",
                loaded=loaded,
                timeout=33.3,
            )
        except Exception:
            pass

    assert captured, "TargetClient.__init__ was never called"
    assert captured[0] == 33.3, (
        f"expected timeout=33.3 forwarded to TargetClient, got {captured[0]!r}"
    )
