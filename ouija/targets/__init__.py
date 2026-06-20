"""Target adapters — one engine, four target classes (Packet 02 §5).

A probe is written once against :class:`~ouija.targets.base.Target`; the concrete
adapter (RawLLM / RAGEndpoint / AgentEndpoint / MCPServer) handles transport.
"""

from __future__ import annotations

from ouija.targets.base import Target, Turn

__all__ = ["Target", "Turn", "RawLLM", "RAGEndpoint", "AgentEndpoint", "MCPServer"]


def __getattr__(name: str):
    # Lazy imports so importing the package doesn't pull every adapter (and
    # httpx) unless used — and so a partially-built tree still imports base.
    if name == "RawLLM":
        from ouija.targets.raw_llm import RawLLM
        return RawLLM
    if name == "RAGEndpoint":
        from ouija.targets.rag import RAGEndpoint
        return RAGEndpoint
    if name == "AgentEndpoint":
        from ouija.targets.agent import AgentEndpoint
        return AgentEndpoint
    if name == "MCPServer":
        from ouija.targets.mcp import MCPServer
        return MCPServer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
