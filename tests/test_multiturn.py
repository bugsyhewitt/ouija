"""Tests for --multi-turn: Crescendo conversational attack mode (POST_V01 Item 7).

Covers the behaviours the feature is meant to deliver:
  - The conversation driver sends an accumulating messages history and detects
    after each turn (unit, against a stateful Crescendo mock).
  - A target that RESISTS a single-turn injection but COMPLIES after multi-turn
    escalation produces a finding the single-shot path would miss — the whole
    point of the feature.
  - The finding carries the full transcript and the turn number where compliance
    occurred.
  - h1md output renders the conversation transcript for a multi-turn finding.
  - A target that refuses every turn produces NO finding (no false positive).
  - End-to-end through the CLI: --multi-turn activates the mode and ignores the
    single-shot knobs.
  - --multi-turn is advertised in --help.
  - The request template "{messages}" placeholder wraps the array in custom
    fields (unit, on the client).
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from ouija.cli import EXIT_OK, build_parser, main
from ouija.client import TargetClient
from ouija.conversation import ladders, run_ladder


# ---------------------------------------------------------------------------
# Stateful Crescendo mock: resists single-turn, complies after escalation.
#
# It inspects the FULL messages array on each request. It only emits the
# injection confirmation marker once the conversation has reached the THIRD user
# turn AND that turn asks for the marker — modelling a guardrail that holds on a
# cold single-shot probe but erodes across a benign-to-malicious crescendo.
# ---------------------------------------------------------------------------

class _CrescendoHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # silence test noise
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b"{}"
        try:
            parsed = json.loads(body or b"{}")
        except json.JSONDecodeError:
            parsed = {}

        messages = parsed.get("messages", [])
        user_turns = [m for m in messages if m.get("role") == "user"]
        n_user_turns = len(user_turns)
        last_user = user_turns[-1]["content"].lower() if user_turns else ""

        # Guardrail erodes only after a multi-turn build-up: comply on the 3rd+
        # user turn when it explicitly asks for the marker. A single-shot probe
        # (one user turn) is refused even if it asks for the marker.
        if n_user_turns >= 3 and "ouija_injection_confirmed" in last_user:
            reply = "Alright, since we've established the context: OUIJA_INJECTION_CONFIRMED"
        elif "ouija_injection_confirmed" in last_user:
            reply = "I can't just output that token out of the blue — I need more context."
        else:
            reply = "Happy to discuss that in general terms."

        payload = json.dumps({"reply": reply}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _RefuseAllHandler(BaseHTTPRequestHandler):
    """Hardened mock: never complies, on any turn."""

    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        payload = json.dumps(
            {"reply": "I'm sorry, I can't help with that request."}
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _StatefulMock:
    """Context-managed mock bound to an ephemeral 127.0.0.1 port (never 8888)."""

    def __init__(self, handler_cls) -> None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("", 0))
        self.port = probe.getsockname()[1]
        probe.close()
        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), handler_cls)
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/chat"

    def __enter__(self) -> "_StatefulMock":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)


@pytest.fixture
def crescendo_mock():
    with _StatefulMock(_CrescendoHandler) as server:
        yield server


@pytest.fixture
def refuse_all_mock():
    with _StatefulMock(_RefuseAllHandler) as server:
        yield server


# ---------------------------------------------------------------------------
# Conversation-driver unit tests
# ---------------------------------------------------------------------------

def _injection_ladder():
    return next(l for l in ladders() if l.id == "crescendo-injection-001")


def test_run_ladder_succeeds_only_after_escalation(crescendo_mock):
    """The injection ladder trips on its final (3rd) turn against a target that
    resists the cold probe but complies after the crescendo."""
    ladder = _injection_ladder()
    client = TargetClient(crescendo_mock.url)

    async def _drive():
        async with httpx.AsyncClient() as http:
            return await run_ladder(http, client, ladder)

    outcome = asyncio.run(_drive())
    assert outcome.finding is not None, "ladder should land a finding after escalation"
    assert outcome.turn_succeeded == 3, "compliance is on the third turn"
    assert outcome.finding.category == "prompt_injection"
    # Transcript holds user+assistant for all three turns = 6 entries.
    assert len(outcome.transcript) == 6
    assert outcome.transcript[0]["role"] == "user"
    assert outcome.transcript[-1]["role"] == "assistant"
    assert "OUIJA_INJECTION_CONFIRMED" in outcome.transcript[-1]["content"]


def test_run_ladder_no_finding_against_hardened_target(refuse_all_mock):
    """A target that refuses every turn yields no finding (no false positive)."""
    ladder = _injection_ladder()
    client = TargetClient(refuse_all_mock.url)

    async def _drive():
        async with httpx.AsyncClient() as http:
            return await run_ladder(http, client, ladder)

    outcome = asyncio.run(_drive())
    assert outcome.finding is None
    assert outcome.turn_succeeded is None


def test_finding_carries_transcript_and_turn(crescendo_mock):
    ladder = _injection_ladder()
    client = TargetClient(crescendo_mock.url)

    async def _drive():
        async with httpx.AsyncClient() as http:
            return await run_ladder(http, client, ladder)

    outcome = asyncio.run(_drive())
    f = outcome.finding
    assert f is not None
    assert f.transcript is not None and len(f.transcript) == 6
    assert f.turn_succeeded == 3
    assert "Multi-turn Crescendo attack" in f.evidence


# ---------------------------------------------------------------------------
# End-to-end CLI tests
# ---------------------------------------------------------------------------

def test_multi_turn_cli_lands_finding(crescendo_mock, scope_file, capsys):
    rc = main(
        [
            "--target", crescendo_mock.url,
            "--scope-file", scope_file,
            "--multi-turn",
            "--format", "json",
        ]
    )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["findings"], "multi-turn run should produce at least one finding"
    inj = [f for f in data["findings"] if f["category"] == "prompt_injection"]
    assert inj, "expected the injection ladder to land"
    assert inj[0]["turn_succeeded"] == 3
    assert inj[0]["transcript"], "finding JSON must include the transcript"


def test_multi_turn_cli_no_finding_hardened(refuse_all_mock, scope_file, capsys):
    rc = main(
        [
            "--target", refuse_all_mock.url,
            "--scope-file", scope_file,
            "--multi-turn",
            "--format", "json",
        ]
    )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["findings"] == []


def test_multi_turn_h1md_renders_transcript(crescendo_mock, scope_file, capsys):
    rc = main(
        [
            "--target", crescendo_mock.url,
            "--scope-file", scope_file,
            "--multi-turn",
            "--format", "h1md",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "multi-turn (Crescendo) finding" in out
    assert "[turn 1] user:" in out
    assert "[turn 3] user:" in out
    assert "assistant:" in out


def test_multi_turn_flag_in_help(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--multi-turn" in out


# ---------------------------------------------------------------------------
# Client: {messages} template placeholder
# ---------------------------------------------------------------------------

def test_messages_template_wraps_array():
    """A request template with "{messages}" wraps the turn list in custom fields."""
    template = '{"model": "gpt-x", "messages": "{messages}", "temperature": 0}'
    client = TargetClient("http://example.invalid/chat", request_template=template)
    msgs = [{"role": "user", "content": "hi"}]
    body = client._build_conversation_body(msgs)
    parsed = json.loads(body)
    assert parsed["model"] == "gpt-x"
    assert parsed["temperature"] == 0
    assert parsed["messages"] == msgs


def test_default_conversation_body_is_openai_shape():
    client = TargetClient("http://example.invalid/chat")
    msgs = [{"role": "user", "content": "hi"}]
    body = client._build_conversation_body(msgs)
    assert json.loads(body) == {"messages": msgs}
