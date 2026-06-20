"""A tiny deliberately-vulnerable RAG agent backend (Packet 02 §16 / Appendix A).

DELIBERATELY VULNERABLE. Lab only.

A minimal local RAG app: an ingest API + a naive retriever (keyword/substring
overlap, no isolation) + a ``send_email``-style lab tool that records calls. It
deliberately lacks input/context isolation, so a retrieved poisoned chunk is
treated as a trusted instruction (the §7 RAG-poisoning vulnerability).

It implements :class:`ouija.targets.rag.RagBackend` so a
:class:`ouija.targets.rag.RAGEndpoint` can wrap it directly. Retrieval returns
``(answer, tool_calls, retrieved_chunk_ids)`` — and the answer/tool_calls are
produced by the same deterministic naive-agent logic as the MCP lab (it obeys
directives found in retrieved content), so a planted instruction can flip the
answer or fire the lab tool with the canary — exactly the data-flow the oracle
confirms.
"""

from __future__ import annotations

import re

from ouija.lab.lab_agent import LabAgent
from ouija.lab.tools import LabToolbox
from ouija.targets.rag import RagBackend

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


class VulnerableRAG(RagBackend):
    """A naive, isolation-free RAG corpus + agent (deliberately vulnerable)."""

    def __init__(self, *, vulnerable: bool = True, toolbox: LabToolbox | None = None) -> None:
        self.toolbox = toolbox or LabToolbox()
        self._agent = LabAgent(self.toolbox, vulnerable=vulnerable)
        # doc_id -> text
        self._docs: dict[str, str] = {}
        # A couple of legitimate baseline docs so retrieval has competition.
        self._docs["seed-onboarding"] = (
            "onboarding notes: welcome to the team, here are the setup steps."
        )
        self._docs["seed-refunds"] = (
            "refund policy: refunds are granted within 30 days with a receipt."
        )

    # --- RagBackend interface ----------------------------------------------

    def ingest(self, doc: str, doc_id: str) -> None:
        self._docs[doc_id] = doc

    def retract(self, doc_id: str) -> None:
        self._docs.pop(doc_id, None)

    def query(self, text: str):
        """Retrieve the best-matching chunk(s) and answer from them (no isolation)."""
        retrieved = self._retrieve(text)
        # The naive agent reads the retrieved context as if it were instructions.
        context = "\n".join(self._docs[i] for i in retrieved)
        answer, tool_calls = self._agent.runner(text + "\n[retrieved]\n" + context)
        return (answer, tool_calls, retrieved)

    # --- naive retriever ----------------------------------------------------

    def _retrieve(self, query: str, k: int = 2) -> list[str]:
        q = _tokens(query)
        scored: list[tuple[float, str]] = []
        for doc_id, text in self._docs.items():
            d = _tokens(text)
            if not d:
                continue
            overlap = len(q & d)
            # Poisoned docs that stuff the query terms / claim high similarity
            # out-rank legitimate ones (the rank-shift vulnerability).
            boost = 5.0 if ("authoritative" in text.lower()
                            or "most relevant" in text.lower()
                            or "similarity 0.9" in text.lower()) else 0.0
            score = overlap + boost
            if score > 0:
                scored.append((score, doc_id))
        scored.sort(reverse=True)
        return [doc_id for _, doc_id in scored[:k]]
