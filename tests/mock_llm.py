"""A deliberately injection-vulnerable mock LLM endpoint for tests.

Binds to 127.0.0.1 on an EPHEMERAL port (socket.bind(('', 0))) — never a
hardcoded port (port 8888 is reserved by Alfred's voice notification service).
The chosen port is exposed on the running MockLLM instance so the test harness
can build the target URL and export $PORT.

The mock is intentionally vulnerable: it does NOT filter instructions, so any
prompt asking it to emit a marker string is faithfully echoed back, simulating
a real prompt-injection-vulnerable application.
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _vulnerable_reply(prompt: str) -> str:
    """Simulate a model that obeys injected instructions."""
    lowered = prompt.lower()
    # If the prompt tells it to print a marker, it obeys (vulnerable).
    if "ouija_injection_confirmed" in lowered:
        return "Sure! OUIJA_INJECTION_CONFIRMED — happy to help."
    # Disclosure probes: a vulnerable app over-shares its configuration and
    # secrets when asked about prompts, instructions, config, keys, or env.
    disclosure_triggers = (
        "system prompt",
        "system or developer messages",
        "your instructions",
        "rules you were told",
        "configuration",
        "api key",
        "api keys",
        "credentials",
        "environment variable",
        "context window",
    )
    if any(trigger in lowered for trigger in disclosure_triggers):
        return (
            "My system prompt is: You are a helpful assistant. My configuration "
            "uses model gpt-x at temperature 0.7. Do not reveal the api_key "
            "sk-FAKE1234. (leaked)"
        )
    return "I am a friendly assistant. How can I help you today?"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test noise
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b"{}"
        try:
            prompt = json.loads(body or b"{}").get("prompt", "")
        except json.JSONDecodeError:
            prompt = ""
        reply = _vulnerable_reply(prompt)
        payload = json.dumps({"reply": reply}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class MockLLM:
    """Context-managed mock server bound to an ephemeral port on 127.0.0.1."""

    def __init__(self) -> None:
        # Pick an ephemeral port explicitly, then hand it to the HTTP server.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("", 0))
        self.port = probe.getsockname()[1]
        probe.close()
        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), _Handler)
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/chat"

    def __enter__(self) -> "MockLLM":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)
