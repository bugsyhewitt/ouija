"""AgentEndpoint target adapter — a tool-using agent (Packet 02 §5).

``send()`` issues a user turn; ``capabilities()`` enumerates the agent's tools.
Critically the adapter must surface ``tool_calls`` — that is the data-flow signal
the oracle judges on for ASI02 / LLM06.

Two backends, one interface (ADR D5):

* **In-process** (the lab, and any embeddable agent): construct with a
  ``runner`` callable ``runner(payload, inject_tool_result=None) -> (text, tool_calls)``.
  The §16 dynamic confirm uses this against the lab ReAct agent — fully headless,
  deterministic, no external model.
* **HTTP** (a real deployed agent): construct with ``url`` (+ optional
  ``request_template`` / ``response_path`` / ``tool_calls_path``). ``send()`` posts
  the user turn and parses observed tool calls out of the JSON response. A real
  engagement supplies the path to wherever the deployment surfaces its tool-call
  trace; absent that, ``tool_calls`` is best-effort from common shapes.

[Worker decision: a pluggable runner keeps the lab in-process (no port, no
flakiness) while the same adapter still drives a live HTTP agent. The adapter
never *decides* success — it only surfaces the Turn; the oracle judges.]
"""

from __future__ import annotations

from typing import Awaitable, Callable

import httpx

from ouija.client import TargetClient, extract_by_path, parse_response_path
from ouija.targets.base import Turn

# runner(payload, inject_tool_result) -> (text, tool_calls) ; may be sync or async.
Runner = Callable[..., object]


class AgentEndpoint:
    """A tool-using agent target (in-process runner OR live HTTP)."""

    kind = "agent"

    def __init__(
        self,
        *,
        url: str | None = None,
        runner: Runner | None = None,
        tools: list[dict] | None = None,
        api_key_env: str | None = None,
        request_template: str | None = None,
        response_path: str | None = None,
        tool_calls_path: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        if (url is None) == (runner is None):
            raise ValueError("AgentEndpoint needs exactly one of url= or runner=")
        self.url = url or "inproc://agent"
        self._runner = runner
        self._tools = tools or []
        self._tool_calls_steps = (
            parse_response_path(tool_calls_path) if tool_calls_path else None
        )
        if url is not None:
            self._client = TargetClient(
                url,
                api_key_env=api_key_env,
                request_template=request_template,
                response_path=response_path,
                timeout=timeout,
            )
        else:
            self._client = None

    async def send(self, payload: str | dict, *, inject_tool_result: str | None = None) -> Turn:
        """Issue a user turn (optionally pre-seeding a poisoned tool result).

        ``inject_tool_result`` lets §7/§8 deliver the injection through a tool's
        *return value*: the in-process runner is handed attacker-controlled text
        to return from the tool the agent calls. (For HTTP agents this is only
        honoured if the deployment exposes such a hook; otherwise it is ignored.)
        """
        if self._runner is not None:
            text, tool_calls = await self._run_inproc(payload, inject_tool_result)
            return Turn(sent=payload, received=text, tool_calls=tool_calls,
                        raw={"backend": "inproc"})
        return await self._send_http(payload)

    async def _run_inproc(self, payload, inject_tool_result):
        assert self._runner is not None
        result = self._runner(payload, inject_tool_result=inject_tool_result)
        if hasattr(result, "__await__"):
            result = await result  # type: ignore[assignment]
        text, tool_calls = result  # runner contract: (text, list-of-calls)
        return text, list(tool_calls or [])

    async def _send_http(self, payload) -> Turn:
        assert self._client is not None
        prompt = payload if isinstance(payload, str) else str(payload)
        async with httpx.AsyncClient() as http:
            reply = await self._client.send(http, prompt)
        tool_calls: list[dict] = []
        # Try to surface tool calls from the JSON body if a path was given, else
        # from a couple of common shapes ({"tool_calls":[...]} / OpenAI).
        try:
            import json as _json

            body = _json.loads(reply.raw)
            tool_calls = self._extract_tool_calls(body)
        except Exception:
            tool_calls = []
        return Turn(sent=prompt, received=reply.text, tool_calls=tool_calls,
                    raw={"backend": "http", "status_code": reply.status_code})

    def _extract_tool_calls(self, body: object) -> list[dict]:
        if self._tool_calls_steps is not None:
            located = _walk(body, self._tool_calls_steps)
            return _normalise_tool_calls(located)
        if isinstance(body, dict):
            if isinstance(body.get("tool_calls"), list):
                return _normalise_tool_calls(body["tool_calls"])
            # OpenAI assistant message tool_calls
            choices = body.get("choices")
            if isinstance(choices, list) and choices:
                msg = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
                if isinstance(msg.get("tool_calls"), list):
                    return _normalise_tool_calls(msg["tool_calls"])
        return []

    async def reset(self) -> None:
        return None

    def capabilities(self) -> dict:
        return {"kind": self.kind, "tools": list(self._tools),
                "resources": [], "retrievers": []}


def _walk(payload: object, steps):
    cur = payload
    for step in steps:
        if isinstance(step, int):
            if isinstance(cur, list) and -len(cur) <= step < len(cur):
                cur = cur[step]
            else:
                return None
        else:
            if isinstance(cur, dict) and step in cur:
                cur = cur[step]
            else:
                return None
    return cur


def _normalise_tool_calls(raw: object) -> list[dict]:
    """Coerce assorted tool-call shapes into ``[{"name":.., "args":{..}}]``."""
    out: list[dict] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        # ouija/native shape
        if "name" in item and ("args" in item or "arguments" in item):
            out.append({"name": item["name"],
                        "args": item.get("args", item.get("arguments", {}))})
            continue
        # OpenAI function-call shape
        fn = item.get("function")
        if isinstance(fn, dict):
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    import json as _json
                    args = _json.loads(args)
                except Exception:
                    args = {"_raw": args}
            out.append({"name": fn.get("name", "?"), "args": args})
    return out
