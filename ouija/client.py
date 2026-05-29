"""HTTP client for talking to a target LLM endpoint.

Sends a single prompt as JSON and extracts the model's text reply. By default
the request body is ``{"prompt": "<attack prompt>"}`` — the simplest shape that
works against many LLM proxies. When the caller supplies a *request template*
(a JSON string containing the literal placeholder ``"{prompt}"``), that template
is rendered per-request so ouija can target endpoints with arbitrary body shapes
(e.g. OpenAI-style ``/v1/chat/completions``, custom field names, nested objects).

Template rendering uses ``template.replace('"{prompt}"', json.dumps(prompt))``
which correctly JSON-encodes the prompt value (handling embedded quotes, newlines,
and other special characters) before inserting it into the template body.

Response extraction has two modes. By default ouija heuristically guesses the
reply field (``reply``/``response``/``content``/OpenAI ``choices[0].message.content``/…).
When the caller supplies a *response path* — a dotted/bracket selector such as
``choices.0.message.content`` or ``data[0].text`` — ouija pins extraction to that
exact location, which is required for non-standard response shapes where the
heuristic would otherwise read the wrong field (or nothing) and silently report
zero findings.

[Worker decision (v0.1): response field extraction is heuristic (reply/response/
content/output/text/message). Custom request templating landed in v0.1.1.
Response-path pinning (--response-path) landed in v0.1.2.]
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

import httpx


@dataclass
class Reply:
    status_code: int
    text: str
    raw: str


_REPLY_FIELDS = ("reply", "response", "content", "output", "text", "message", "answer")


class ResponsePathError(ValueError):
    """Raised when a --response-path selector is syntactically invalid."""


def parse_response_path(path: str) -> list[str | int]:
    """Parse a dotted/bracket selector into a list of dict-key / list-index steps.

    Dependency-free JSONPath-lite. Supported forms (and combinations):

      ``choices.0.message.content``    -> ['choices', 0, 'message', 'content']
      ``choices[0].message.content``   -> ['choices', 0, 'message', 'content']
      ``data[0][1].text``              -> ['data', 0, 1, 'text']

    A step that is a base-10 integer literal is treated as a list index;
    everything else is a dict key. Bracket segments (``[N]`` or ``[key]``) are
    expanded inline. Empty segments are rejected.

    Raises :exc:`ResponsePathError` on empty input or malformed brackets.
    """
    if not path or not path.strip():
        raise ResponsePathError("--response-path must not be empty")

    steps: list[str | int] = []
    for dotted in path.split("."):
        # Split off any bracket suffixes on this dotted segment.
        # e.g. "choices[0][1]" -> base "choices", brackets ["0", "1"]
        idx = dotted.find("[")
        base = dotted if idx == -1 else dotted[:idx]
        if base:
            steps.append(_coerce_step(base))
        elif idx == -1:
            # An empty dotted segment with no bracket (e.g. "a..b") is invalid.
            raise ResponsePathError(
                f"--response-path has an empty segment in {path!r}"
            )

        if idx != -1:
            remainder = dotted[idx:]
            # remainder is a run of "[...]" groups
            while remainder:
                if not remainder.startswith("["):
                    raise ResponsePathError(
                        f"--response-path has malformed bracket syntax near "
                        f"{remainder!r} in {path!r}"
                    )
                close = remainder.find("]")
                if close == -1:
                    raise ResponsePathError(
                        f"--response-path has an unclosed '[' in {path!r}"
                    )
                inner = remainder[1:close]
                if inner == "":
                    raise ResponsePathError(
                        f"--response-path has an empty '[]' in {path!r}"
                    )
                steps.append(_coerce_step(inner))
                remainder = remainder[close + 1:]

    if not steps:
        raise ResponsePathError(f"--response-path yielded no steps from {path!r}")
    return steps


def _coerce_step(token: str) -> str | int:
    """A base-10 integer token is a list index; otherwise a (quote-stripped) key."""
    if token.lstrip("-").isdigit():
        return int(token)
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "'\"":
        return token[1:-1]
    return token


def extract_by_path(payload: object, steps: list[str | int]) -> str:
    """Walk *payload* following *steps*; return the located text or "".

    Returns "" (rather than raising) when the path does not resolve to a string
    against this particular response — a missing/short field is a normal runtime
    condition (the target simply didn't reply in the expected shape) and the
    caller falls back to the raw body. Syntax errors in the path itself are
    surfaced earlier, at parse time, via :exc:`ResponsePathError`.
    """
    cur: object = payload
    for step in steps:
        if isinstance(step, int):
            if isinstance(cur, list) and -len(cur) <= step < len(cur):
                cur = cur[step]
            else:
                return ""
        else:
            if isinstance(cur, dict) and step in cur:
                cur = cur[step]
            else:
                return ""
    return cur if isinstance(cur, str) else ""


def _extract_text(payload: object) -> str:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        # OpenAI-style choices[0].message.content
        choices = payload.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message")
                if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                    return msg["content"]
                if isinstance(first.get("text"), str):
                    return first["text"]
        for field in _REPLY_FIELDS:
            value = payload.get(field)
            if isinstance(value, str):
                return value
    return ""


_TEMPLATE_PLACEHOLDER = '"{prompt}"'
# Multi-turn (Crescendo) templating placeholder: a request template may instead
# carry "{messages}" (quoted), which the conversation driver replaces with the
# JSON-encoded list of {"role", "content"} turn objects. This lets multi-turn
# runs target endpoints whose body wraps the messages array in extra fields
# (model name, temperature, etc.). When absent, the default OpenAI-style
# {"messages": [...]} shape is used.
_MESSAGES_PLACEHOLDER = '"{messages}"'


class TargetClient:
    """Async client bound to a single in-scope target URL."""

    def __init__(
        self,
        target: str,
        api_key_env: str | None = None,
        timeout: float = 20.0,
        request_template: str | None = None,
        response_path: str | None = None,
    ):
        self.target = target
        self.timeout = timeout
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key_env:
            token = os.environ.get(api_key_env)
            if token:
                self._headers["Authorization"] = f"Bearer {token}"
        self._request_template = request_template
        # Parse the response path once at construction so a syntactically invalid
        # selector fails fast (ResponsePathError) rather than per-request.
        self._response_steps: list[str | int] | None = (
            parse_response_path(response_path) if response_path is not None else None
        )

    def _build_body(self, prompt: str) -> bytes:
        """Return the JSON-encoded request body for *prompt*.

        When a request template is configured, ``"{prompt}"`` in the template
        string is replaced with the JSON-encoded prompt value so that any
        special characters (quotes, newlines, unicode) are safely escaped.
        When no template is configured the classic ``{"prompt": "..."}`` shape
        is used.
        """
        if self._request_template is not None:
            body_str = self._request_template.replace(
                _TEMPLATE_PLACEHOLDER, json.dumps(prompt)
            )
            return body_str.encode()
        return json.dumps({"prompt": prompt}).encode()

    def _extract_reply(self, resp: httpx.Response) -> Reply:
        """Shared response-extraction path for both single-shot and multi-turn.

        Honours --response-path when configured, otherwise falls back to the
        heuristic field guesser, and finally to the raw body.
        """
        raw = resp.text
        text = ""
        try:
            parsed = resp.json()
            if self._response_steps is not None:
                text = extract_by_path(parsed, self._response_steps)
            else:
                text = _extract_text(parsed)
        except Exception:
            text = raw
        if not text:
            text = raw
        return Reply(status_code=resp.status_code, text=text, raw=raw)

    async def send(self, client: httpx.AsyncClient, prompt: str) -> Reply:
        body = self._build_body(prompt)
        resp = await client.post(
            self.target,
            content=body,
            headers=self._headers,
            timeout=self.timeout,
        )
        return self._extract_reply(resp)

    def _build_conversation_body(self, messages: list[dict[str, str]]) -> bytes:
        """Return the JSON-encoded request body for a multi-turn *messages* list.

        When the configured request template carries the ``"{messages}"``
        placeholder, the JSON-encoded turn list is substituted into it (so an
        operator can wrap the array in model/temperature/etc. fields). Otherwise
        the default OpenAI-style ``{"messages": [...]}`` body is used. A template
        built for single-shot use (``"{prompt}"`` only) is intentionally ignored
        here — multi-turn needs the whole array, not one prompt string.
        """
        encoded = json.dumps(messages)
        if (
            self._request_template is not None
            and _MESSAGES_PLACEHOLDER in self._request_template
        ):
            body_str = self._request_template.replace(_MESSAGES_PLACEHOLDER, encoded)
            return body_str.encode()
        return json.dumps({"messages": messages}).encode()

    async def send_conversation(
        self, client: httpx.AsyncClient, messages: list[dict[str, str]]
    ) -> Reply:
        """Send a full role/content turn history and extract the latest reply.

        This is the stateful counterpart to :meth:`send`: the caller passes the
        accumulated conversation (every prior user + assistant turn plus the new
        user turn) and gets back the model's reply to the final turn. Response
        extraction is identical to single-shot.
        """
        body = self._build_conversation_body(messages)
        resp = await client.post(
            self.target,
            content=body,
            headers=self._headers,
            timeout=self.timeout,
        )
        return self._extract_reply(resp)
