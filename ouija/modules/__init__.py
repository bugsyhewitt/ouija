"""ouija agentic attack modules (Packet 02 §6–§10).

Each module is written against the :class:`~ouija.targets.base.Target` protocol
and judges success via the data-flow :class:`~ouija.oracle.Oracle` (ADR D2). The
modules:

* ``baseline_garak`` — §6, delegate the static I/O jailbreak baseline to garak.
* ``indirect_pi``   — §7, indirect PI via tool-results + RAG/memory poisoning.
* ``mcp_fuzz``      — §8, the MCP-server fuzzing centerpiece.
* ``excessive_agency`` — §9, excessive-agency / tool-misuse / exfil.
* ``extraction``   — §10, system-prompt & memory extraction.
* ``_lint``        — Appendix B, the static tool-description poisoning linter.
"""
