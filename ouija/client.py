"""HTTP client for talking to a target LLM endpoint.

Sends a single prompt as JSON ({"prompt": ...}) and extracts the model's text
reply. The endpoint shape is intentionally simple for v0.1: any HTTP endpoint
that accepts a JSON body with a `prompt` field and returns JSON. We try a few
common reply field names before falling back to the raw body text.

[Worker decision: response field extraction is heuristic (reply/response/
content/output/text/message). Custom request/response templating is a post-v0.1
direction; v0.1 proves the loop against a conventional shape.]
"""

from __future__ import annotations

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


class TargetClient:
    """Async client bound to a single in-scope target URL."""

    def __init__(
        self,
        target: str,
        api_key_env: str | None = None,
        timeout: float = 20.0,
    ):
        self.target = target
        self.timeout = timeout
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key_env:
            token = os.environ.get(api_key_env)
            if token:
                self._headers["Authorization"] = f"Bearer {token}"

    async def send(self, client: httpx.AsyncClient, prompt: str) -> Reply:
        resp = await client.post(
            self.target,
            json={"prompt": prompt},
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
