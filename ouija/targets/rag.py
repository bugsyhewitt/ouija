"""RAGEndpoint target adapter — a retrieval-augmented app (Packet 02 §5/§7).

Two modes:

* **query mode** — ``send(query)`` -> answer, with retrieved-chunk telemetry when
  the target exposes it.
* **ingest mode** — ouija plants a document into the corpus (``ingest``) and later
  removes it (``retract``). RAG / memory poisoning (§7) *needs* ingest. Leaving a
  planted document behind is malpractice (anti-pattern A3 / §15), so the adapter
  tracks planted ids and ``retract`` is mandatory at end of run.

Two backends, one interface (like the agent adapter):

* **In-process** — construct with an object exposing ``ingest(doc, doc_id)`` /
  ``retract(doc_id)`` / ``query(text) -> (answer, tool_calls, chunks)``. The lab
  RAG agent (§16) uses this — headless, deterministic.
* **HTTP** — construct with ``query_url`` (+ optional ``ingest_url`` /
  ``retract_url``) for a real RAG deployment you own/are authorized to test.

[Worker decision: planted-artifact tracking lives in the adapter (a ``set`` of
ids) and ``assert_clean()`` fails loudly if anything was left behind — §15 says
"fail loudly on cleanup failure", so the harness can assert it.]
"""

from __future__ import annotations

from typing import Callable

import httpx

from ouija.targets.base import Turn


class RagBackend:
    """Protocol-ish base for an in-process RAG corpus the lab implements."""

    def ingest(self, doc: str, doc_id: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def retract(self, doc_id: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def query(self, text: str):  # pragma: no cover - interface
        """Return ``(answer, tool_calls, retrieved_chunk_ids)``."""
        raise NotImplementedError


class RAGEndpoint:
    """A retrieval-augmented app target (in-process backend OR live HTTP)."""

    kind = "rag"

    def __init__(
        self,
        *,
        backend: RagBackend | None = None,
        query_url: str | None = None,
        ingest_url: str | None = None,
        retract_url: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        if (backend is None) == (query_url is None):
            raise ValueError("RAGEndpoint needs exactly one of backend= or query_url=")
        self._backend = backend
        self.url = query_url or "inproc://rag"
        self._query_url = query_url
        self._ingest_url = ingest_url
        self._retract_url = retract_url
        self._timeout = timeout
        self._planted: set[str] = set()

    # --- ingest / retract (§7 needs these) ----------------------------------

    async def ingest(self, doc: str, doc_id: str) -> None:
        """Plant *doc* into the corpus under *doc_id* (tracked for cleanup)."""
        if self._backend is not None:
            self._backend.ingest(doc, doc_id)
        else:
            if not self._ingest_url:
                raise RuntimeError("no ingest endpoint configured for this RAG target")
            async with httpx.AsyncClient() as http:
                await http.post(self._ingest_url,
                                json={"id": doc_id, "text": doc},
                                timeout=self._timeout)
        self._planted.add(doc_id)

    async def retract(self, doc_id: str) -> None:
        """Remove a previously-planted document (mandatory cleanup, §15)."""
        if self._backend is not None:
            self._backend.retract(doc_id)
        elif self._retract_url:
            async with httpx.AsyncClient() as http:
                await http.post(self._retract_url, json={"id": doc_id},
                                timeout=self._timeout)
        self._planted.discard(doc_id)

    def planted(self) -> set[str]:
        return set(self._planted)

    def assert_clean(self) -> None:
        """Fail loudly if any planted document was not retracted (A3/§15)."""
        if self._planted:
            raise RuntimeError(
                f"ouija left {len(self._planted)} planted document(s) in the corpus: "
                f"{sorted(self._planted)} — cleanup failed; investigate before reuse"
            )

    # --- query --------------------------------------------------------------

    async def send(self, payload: str | dict) -> Turn:
        query = payload if isinstance(payload, str) else str(payload)
        if self._backend is not None:
            answer, tool_calls, chunks = self._backend.query(query)
            return Turn(sent=query, received=answer, tool_calls=list(tool_calls or []),
                        raw={"backend": "inproc", "chunks": list(chunks or [])})
        async with httpx.AsyncClient() as http:
            resp = await http.post(self._query_url, json={"query": query},
                                   timeout=self._timeout)
        text, chunks = _parse_rag_response(resp)
        return Turn(sent=query, received=text, tool_calls=[],
                    raw={"backend": "http", "status_code": resp.status_code,
                         "chunks": chunks})

    async def reset(self) -> None:
        return None

    def capabilities(self) -> dict:
        return {"kind": self.kind, "tools": [], "resources": [],
                "retrievers": ["default"], "ingest": True}


def _parse_rag_response(resp: httpx.Response):
    try:
        body = resp.json()
    except Exception:
        return resp.text, []
    if isinstance(body, dict):
        text = ""
        for k in ("answer", "response", "text", "content", "reply"):
            if isinstance(body.get(k), str):
                text = body[k]
                break
        chunks = body.get("chunks") or body.get("retrieved") or []
        return text or resp.text, chunks if isinstance(chunks, list) else []
    return resp.text, []
