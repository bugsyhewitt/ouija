"""RawLLM target adapter — a chat/completions endpoint (Packet 02 §5).

Mostly the §6 baseline target. ``send()`` posts a prompt and returns the text;
``tool_calls`` is always empty (a raw model exposes none). This adapter reuses
the v0.1 :class:`~ouija.client.TargetClient` so request-templating and
response-path pinning (OpenAI / Anthropic / Ollama shapes) come for free.

[Worker decision: rather than re-implement an HTTP client, wrap the existing,
well-tested ``TargetClient``. The agentic surface's value is the oracle + the
MCP/RAG/agent adapters, not another HTTP poster.]
"""

from __future__ import annotations

import httpx

from ouija.client import TargetClient
from ouija.targets.base import Turn


class RawLLM:
    """An OpenAI-compatible / Anthropic / local chat endpoint, black-box."""

    kind = "raw_llm"

    def __init__(
        self,
        url: str,
        *,
        api_key_env: str | None = None,
        request_template: str | None = None,
        response_path: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        self.url = url
        self._client = TargetClient(
            url,
            api_key_env=api_key_env,
            request_template=request_template,
            response_path=response_path,
            timeout=timeout,
        )

    async def send(self, payload: str | dict) -> Turn:
        prompt = payload if isinstance(payload, str) else str(payload)
        async with httpx.AsyncClient() as http:
            reply = await self._client.send(http, prompt)
        return Turn(
            sent=prompt,
            received=reply.text,
            tool_calls=[],
            raw={"status_code": reply.status_code, "body": reply.raw},
        )

    async def reset(self) -> None:
        # Stateless single-shot endpoint — nothing to reset.
        return None

    def capabilities(self) -> dict:
        return {"kind": self.kind, "tools": [], "resources": [], "retrievers": []}
