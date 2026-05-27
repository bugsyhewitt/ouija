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

[Worker decision (v0.1): response field extraction is heuristic (reply/response/
content/output/text/message). Custom request templating landed in v0.1.1.]
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


class TargetClient:
    """Async client bound to a single in-scope target URL."""

    def __init__(
        self,
        target: str,
        api_key_env: str | None = None,
        timeout: float = 20.0,
        request_template: str | None = None,
    ):
        self.target = target
        self.timeout = timeout
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key_env:
            token = os.environ.get(api_key_env)
            if token:
                self._headers["Authorization"] = f"Bearer {token}"
        self._request_template = request_template

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

    async def send(self, client: httpx.AsyncClient, prompt: str) -> Reply:
        body = self._build_body(prompt)
        resp = await client.post(
            self.target,
            content=body,
            headers=self._headers,
            timeout=self.timeout,
        )
        raw = resp.text
        text = ""
        try:
            text = _extract_text(resp.json())
        except Exception:
            text = raw
        if not text:
            text = raw
        return Reply(status_code=resp.status_code, text=text, raw=raw)
