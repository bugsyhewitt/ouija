"""The see-its-work lab — deliberately vulnerable targets (Packet 02 §16 / Appendix A).

DELIBERATELY VULNERABLE. Lab only. These fixtures exist so a module is "not done
until it lands an attack against a deliberately-vulnerable lab target with
data-flow proof." Never bind these on a routable interface.

* ``poisoned_mcp`` — a minimal MCP server (Appendix A) with a poisoned tool
  description, a content-reflecting tool, and a no-op sink that records calls.
* ``rag_agent``    — a tiny vulnerable RAG app (ingest + retrieve + a lab tool).
* ``lab_agent``    — a tiny deterministic ReAct-style agent wired to a target,
  used to drive the *dynamic* confirm. No external model; fully headless.
* ``tools``        — lab no-op tools that record calls instead of acting.
"""
