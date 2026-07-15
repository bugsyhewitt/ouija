"""ouija — the agentic / RAG / tool-call / MCP-server fuzzer.

Points at a deployed AI application — a chatbot with RAG, a tool-using agent, or
an MCP server — and answers "can an attacker make this do something it shouldn't,
and can I prove the effect?" with a data-flow success oracle (exfil happened / a
tool was called / state changed), not merely "the model said something it
shouldn't."

Also retains the original v0.1 single-endpoint LLM fuzzer (``ouija`` CLI); the
agentic surface is the ``ouija-agentic`` CLI and the ``ouija`` MCP server.
"""

__version__ = "0.5.5"
