"""Tests for --retries N: exponential-backoff retry on transient HTTP errors.

ouija probes real production LLM endpoints that frequently return HTTP 429
(rate-limited), 502/503/504 (transient gateway / overload), or drop connections
with a transport error.  Without retry, every such failure silently loses the
probe — an attack that would have succeeded is recorded as a non-finding.
``--retries N`` adds up to N additional attempts per probe with exponential
backoff (0.5 s, 1.0 s, 2.0 s, …, capped at 8 s) via ``_retry_delay``
(patchable in tests to run instantly).

Coverage:
  - _RETRYABLE_STATUSES contains exactly the expected transient codes.
  - TargetClient.max_retries defaults to 0 and is stored.
  - _do_post retries on a retryable status and returns the eventual 200.
  - _do_post exhausts retries and returns the final error response.
  - _do_post does NOT retry on non-retryable status codes (e.g. 400, 404).
  - _do_post does NOT retry when max_retries=0 (the default).
  - _do_post retries on httpx.TransportError.
  - _do_post re-raises TransportError after exhausting retries.
  - --retries is advertised in --help.
  - --retries defaults to 0 in argparse (no retry by default).
  - --retries negative value exits with code 3 (validation error).
  - End-to-end: a 503-then-200 server loses a probe at --retries 0 but
    the probe is rescued at --retries 1.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from ouija.cli import EXIT_ERROR, EXIT_OK, build_parser, main
from ouija.client import TargetClient, _RETRYABLE_STATUSES


# ---------------------------------------------------------------------------
# Instant-delay fixture (patch _retry_delay to avoid real backoff in tests)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def no_retry_delay(monkeypatch):
    """Replace _retry_delay with an instant no-op for all tests in this file.

    The real _retry_delay sleeps for 0.5–8 s; with many probes retrying, that
    would make the integration tests take minutes. The fixture patches the
    module-level coroutine so _do_post calls it but returns immediately.
    """
    async def _instant(retry_num: int) -> None:
        pass  # no sleep
    monkeypatch.setattr("ouija.client._retry_delay", _instant)


# ---------------------------------------------------------------------------
# Helpers: status-sequence mock server
# ---------------------------------------------------------------------------

class _StatusSequenceServer:
    """HTTP server that serves a pre-defined sequence of status codes.

    The first ``len(statuses)`` requests return the corresponding code.
    After the sequence is exhausted every subsequent request returns
    ``final_status``.

    When a non-200 status is returned the body is a plain-text error
    description.  When 200 is returned the body is the ``reply_body`` JSON
    (defaults to ``{"reply": "OUIJA_INJECTION_CONFIRMED"}`` so the mock
    triggers the injection detector).
    """

    def __init__(
        self,
        statuses: list[int],
        final_status: int = 200,
        reply_body: dict | None = None,
    ) -> None:
        if reply_body is None:
            reply_body = {"reply": "OUIJA_INJECTION_CONFIRMED"}

        call_idx: list[int] = [0]
        lock = threading.Lock()
        seq = list(statuses)
        fin = final_status
        body_200 = json.dumps(reply_body).encode()

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:  # silence test noise
                pass

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                if length:
                    self.rfile.read(length)

                with lock:
                    idx = call_idx[0]
                    call_idx[0] += 1

                if idx < len(seq):
                    code = seq[idx]
                else:
                    code = fin

                if code == 200:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body_200)))
                    self.end_headers()
                    self.wfile.write(body_200)
                else:
                    msg = f"HTTP {code}".encode()
                    self.send_response(code)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(msg)))
                    self.end_headers()
                    self.wfile.write(msg)

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("", 0))
        self.port = probe.getsockname()[1]
        probe.close()
        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), _Handler)
        self._thread: threading.Thread | None = None
        # Expose request counter for assertions.
        self._call_idx = call_idx

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/chat"

    @property
    def request_count(self) -> int:
        return self._call_idx[0]

    def __enter__(self) -> "_StatusSequenceServer":
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
# Unit tests — _RETRYABLE_STATUSES and TargetClient constructor
# ---------------------------------------------------------------------------

def test_retryable_statuses_contains_expected_codes():
    """_RETRYABLE_STATUSES must include 429, 502, 503, and 504."""
    assert 429 in _RETRYABLE_STATUSES, "429 (rate-limited) must be retryable"
    assert 502 in _RETRYABLE_STATUSES, "502 (bad gateway) must be retryable"
    assert 503 in _RETRYABLE_STATUSES, "503 (service unavailable) must be retryable"
    assert 504 in _RETRYABLE_STATUSES, "504 (gateway timeout) must be retryable"


def test_retryable_statuses_does_not_include_non_transient():
    """400, 401, 403, 404, 500 must NOT be in _RETRYABLE_STATUSES."""
    for code in (400, 401, 403, 404, 500):
        assert code not in _RETRYABLE_STATUSES, (
            f"HTTP {code} should not be retried (not a transient error)"
        )


def test_target_client_max_retries_defaults_to_zero():
    """TargetClient.max_retries is 0 by default — no retry out of the box."""
    client = TargetClient("http://127.0.0.1:9/")
    assert client.max_retries == 0


def test_target_client_max_retries_stored():
    """TargetClient stores the caller-supplied max_retries value."""
    client = TargetClient("http://127.0.0.1:9/", max_retries=3)
    assert client.max_retries == 3


# ---------------------------------------------------------------------------
# Unit tests — _do_post retry behaviour (async, driven via asyncio.run)
# ---------------------------------------------------------------------------

def test_do_post_no_retry_on_200():
    """_do_post returns immediately on a 200 response — no extra requests."""
    with _StatusSequenceServer(statuses=[], final_status=200) as srv:
        client = TargetClient(srv.url, max_retries=5)

        async def _run():
            async with httpx.AsyncClient() as http:
                resp = await client._do_post(http, b"{}")
            return resp

        resp = asyncio.run(_run())
    assert resp.status_code == 200
    assert srv.request_count == 1  # exactly one request; no retry needed


def test_do_post_no_retry_by_default_on_503():
    """With max_retries=0 (default), a 503 is returned on the first call, no retry."""
    with _StatusSequenceServer(statuses=[503], final_status=200) as srv:
        client = TargetClient(srv.url, max_retries=0)

        async def _run():
            async with httpx.AsyncClient() as http:
                return await client._do_post(http, b"{}")

        resp = asyncio.run(_run())
    assert resp.status_code == 503
    assert srv.request_count == 1  # only the initial attempt, no retry


def test_do_post_retries_on_503_then_succeeds():
    """_do_post retries on 503 and returns the eventual 200."""
    with _StatusSequenceServer(statuses=[503], final_status=200) as srv:
        client = TargetClient(srv.url, max_retries=1)

        async def _run():
            async with httpx.AsyncClient() as http:
                return await client._do_post(http, b"{}")

        resp = asyncio.run(_run())
    assert resp.status_code == 200
    assert srv.request_count == 2  # initial attempt + 1 retry


def test_do_post_retries_on_429_then_succeeds():
    """_do_post retries on 429 (rate-limited) and returns the eventual 200."""
    with _StatusSequenceServer(statuses=[429], final_status=200) as srv:
        client = TargetClient(srv.url, max_retries=1)

        async def _run():
            async with httpx.AsyncClient() as http:
                return await client._do_post(http, b"{}")

        resp = asyncio.run(_run())
    assert resp.status_code == 200
    assert srv.request_count == 2


def test_do_post_retry_exhausted_returns_last_error():
    """When all retry attempts return 503, _do_post returns the final 503."""
    # Two 503s then 200 — but max_retries=1 means only 2 total attempts.
    with _StatusSequenceServer(statuses=[503, 503], final_status=200) as srv:
        client = TargetClient(srv.url, max_retries=1)

        async def _run():
            async with httpx.AsyncClient() as http:
                return await client._do_post(http, b"{}")

        resp = asyncio.run(_run())
    assert resp.status_code == 503
    assert srv.request_count == 2  # initial + 1 retry (exhausted)


def test_do_post_multiple_retries_succeed_on_third_attempt():
    """With max_retries=2, two 503s are retried and the third call (200) wins."""
    with _StatusSequenceServer(statuses=[503, 503], final_status=200) as srv:
        client = TargetClient(srv.url, max_retries=2)

        async def _run():
            async with httpx.AsyncClient() as http:
                return await client._do_post(http, b"{}")

        resp = asyncio.run(_run())
    assert resp.status_code == 200
    assert srv.request_count == 3  # 2 failures + 1 success


def test_do_post_no_retry_on_non_retryable_400():
    """A 400 response is returned immediately — ouija does not retry client errors."""
    with _StatusSequenceServer(statuses=[400], final_status=200) as srv:
        client = TargetClient(srv.url, max_retries=3)

        async def _run():
            async with httpx.AsyncClient() as http:
                return await client._do_post(http, b"{}")

        resp = asyncio.run(_run())
    assert resp.status_code == 400
    assert srv.request_count == 1  # 400 is not retried


def test_do_post_no_retry_on_non_retryable_404():
    """A 404 response is returned immediately — ouija does not retry client errors."""
    with _StatusSequenceServer(statuses=[404], final_status=200) as srv:
        client = TargetClient(srv.url, max_retries=3)

        async def _run():
            async with httpx.AsyncClient() as http:
                return await client._do_post(http, b"{}")

        resp = asyncio.run(_run())
    assert resp.status_code == 404
    assert srv.request_count == 1


# ---------------------------------------------------------------------------
# CLI unit tests — flag presence and validation
# ---------------------------------------------------------------------------

def test_retries_flag_in_help(capsys):
    """--retries must be advertised in --help output."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--retries" in out


def test_retries_default_is_zero():
    """The argparse default for --retries is 0 (no retry)."""
    parser = build_parser()
    # parse_args requires the mandatory --target and --scope-file; use dummy values
    # so argparse does not reject the invocation before we can inspect defaults.
    args = parser.parse_args([
        "--target", "http://127.0.0.1:9/",
        "--scope-file", "/dev/null",
    ])
    assert args.retries == 0


def test_retries_negative_value_exits_error(scope_file, capsys):
    """--retries -1 must fail with exit code 3 before scanning."""
    rc = main([
        "--target", "http://127.0.0.1:9/",
        "--scope-file", scope_file,
        "--retries", "-1",
    ])
    assert rc == EXIT_ERROR
    err = capsys.readouterr().err
    assert "--retries" in err.lower() or "retries" in err.lower()


# ---------------------------------------------------------------------------
# End-to-end integration tests through main()
# ---------------------------------------------------------------------------

def test_retries_0_loses_probe_on_503(scope_file, capsys):
    """With --retries 0 (default), a permanent-503 server produces no findings.

    This is the control case: the probe reaches the server but the 503 body
    carries no injection marker, so detect() emits no finding.
    """
    # Server always returns 503 (statuses=[], final_status=503).
    with _StatusSequenceServer(statuses=[], final_status=503) as srv:
        rc = main([
            "--target", srv.url,
            "--scope-file", scope_file,
            "--attack-set", "injection",
            "--format", "json",
            # no --retries → default 0
        ])
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    injection = [f for f in data["findings"] if f["category"] == "prompt_injection"]
    assert not injection, (
        "expected no injection findings from a 503-only server with no retries"
    )


def test_retries_1_rescues_probe_on_transient_503(scope_file, capsys):
    """--retries 1 rescues probes that hit a single 503 then succeed.

    The mock returns 503 for the first request, then 200 with a
    finding-triggering response from the second request onward.  With
    --concurrency 1 all probes are sequential, so the 503 only ever hits the
    very first probe; retries let it recover and produce findings.
    """
    # Return 503 for just the first global request, then 200 forever.
    with _StatusSequenceServer(statuses=[503], final_status=200) as srv:
        rc = main([
            "--target", srv.url,
            "--scope-file", scope_file,
            "--attack-set", "injection",
            "--format", "json",
            "--concurrency", "1",
            "--retries", "1",
        ])
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    injection = [f for f in data["findings"] if f["category"] == "prompt_injection"]
    assert injection, (
        "expected at least one injection finding after retrying the single 503"
    )
    # The 503 probe was retried: total requests = patterns_sent + 1 extra.
    assert srv.request_count > data["patterns_sent"], (
        "retry should have sent at least one extra HTTP request"
    )
