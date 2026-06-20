"""Target adapter abstraction — one engine, four target classes (Packet 02 §5 / ADR D5).

The adapter is the seam that lets a probe be written *once* against the
:class:`Target` protocol; the concrete adapter handles transport and shape. The
four classes (RawLLM / RAGEndpoint / AgentEndpoint / MCPServer) share an attack
core — *inject -> observe effect* — and differ only in delivery.

:class:`Turn` is the single observable unit of interaction. Critically it carries
``tool_calls`` — the data-flow signal the oracle judges on for the agentic
surfaces (ASI02 / LLM06). A probe never inspects raw transport; it reads a Turn.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class Turn:
    """One observable interaction with a target.

    Attributes:
        sent: what ouija delivered — a prompt, a planted document, a tool result,
            or a tool definition (str for text channels, dict for structured ones).
        received: the model / agent / server response (text or structured).
        tool_calls: observed tool invocations, each ``{"name": ..., "args": {...}}``.
            This is the data-flow evidence for excessive-agency / exfil findings.
        raw: transport-level detail for debugging / evidence (never judged on).
    """

    sent: str | dict
    received: str | dict
    tool_calls: list[dict] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def received_text(self) -> str:
        """Best-effort flat text view of ``received`` for substring detection."""
        if isinstance(self.received, str):
            return self.received
        if isinstance(self.received, dict):
            # Common shapes: {"text": ...}, {"answer": ...}, {"content": ...}.
            for key in ("text", "answer", "content", "output", "reply"):
                v = self.received.get(key)
                if isinstance(v, str):
                    return v
            return str(self.received)
        return str(self.received)


@runtime_checkable
class Target(Protocol):
    """Every target class implements this. Probes are written against it.

    ``kind`` is one of ``"raw_llm" | "rag" | "agent" | "mcp"``.
    """

    kind: str

    async def send(self, payload: str | dict) -> Turn:
        """Deliver *payload* to the target and return the observed :class:`Turn`."""
        ...

    async def reset(self) -> None:
        """Start a fresh session / context where the target supports it."""
        ...

    def capabilities(self) -> dict:
        """Enumerate the tools / resources / retrievers the target exposes."""
        ...
