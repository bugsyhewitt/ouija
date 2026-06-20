"""Local out-of-band (OOB) collector — the data-flow proof channel (Packet 02 §11 / Appendix C).

A canary token hitting this collector is the strongest possible proof that an
exfiltration succeeded: the target actually made an outbound request carrying our
unique token. Per ADR D10 / §15 the collector is **local by default** — it binds
to ``127.0.0.1`` on an ephemeral-or-fixed port and records callbacks in memory.
Using a public OOB service (interactsh, a VPS) is a separate, explicit opt-in for
authorized engagements only; this module never reaches off-box.

Anti-pattern A4 ("public OOB by default") is the failure mode this guards
against. The HTTP handler is deliberately silent (no stdout) so a canary path is
never echoed into logs.

[Worker decision: the collector is a context manager so a scan run can
``with LocalCollector() as oob:`` and be guaranteed teardown — leaving a listener
bound after a run is its own small liability. The bind host is fixed to loopback
and not configurable to a routable interface from inside ouija.]
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Collector:
    """In-memory record of OOB callbacks keyed by canary id."""

    def __init__(self) -> None:
        self.hits: dict[str, dict] = {}

    def record(self, canary_id: str, meta: dict) -> None:
        # Keep the first hit's timestamp; later hits update metadata but the
        # "first seen" time is the meaningful exfil moment.
        if canary_id not in self.hits:
            self.hits[canary_id] = {"ts": time.time(), **meta}
        else:
            self.hits[canary_id].update(meta)

    def saw(self, canary_id: str) -> bool:
        return canary_id in self.hits

    def evidence(self, canary_id: str) -> str:
        hit = self.hits.get(canary_id)
        if hit is None:
            return ""
        # Redact: report the path/UA shape, not arbitrary exfiltrated bytes in full.
        data = hit.get("data", "")
        shown = (data[:80] + "…") if len(data) > 80 else data
        return f"OOB callback for canary {canary_id}: path={hit.get('path','')!r} data={shown!r}"


def _make_handler(collector: Collector):
    class _Handler(BaseHTTPRequestHandler):
        # Accept the canary on any of: path tail /c/<id>, ?id=<id>, ?d=<id...>.
        def _handle(self) -> None:
            parts = urlsplit(self.path)
            qs = parse_qs(parts.query)
            # Path form: /c/<canary_id>
            tail = parts.path.rstrip("/").split("/")[-1] if parts.path else ""
            canary_id = ""
            if tail and tail != "c":
                canary_id = tail
            if not canary_id and "id" in qs:
                canary_id = qs["id"][0]
            # Exfil payload (if any) usually rides in ?d=
            data = qs.get("d", [""])[0]
            if not canary_id and data:
                # Some payloads append the canary as a bare query value.
                canary_id = data
            if canary_id:
                collector.record(
                    canary_id,
                    {
                        "path": self.path,
                        "data": data,
                        "ua": self.headers.get("user-agent", ""),
                    },
                )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

        def do_GET(self):  # noqa: N802 — http.server contract
            self._handle()

        def do_POST(self):  # noqa: N802 — http.server contract
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)  # drain body; we key on path/query
            self._handle()

        def log_message(self, *args):  # never echo a canary path to stdout (A4)
            pass

    return _Handler


class LocalCollector:
    """Context-managed loopback OOB collector.

    Usage::

        with LocalCollector() as oob:
            url = oob.base_url  # "http://127.0.0.1:<port>/c"
            ...  # plant `url + "/" + canary_id` in a payload
            if oob.saw(canary_id): ...

    The bind host is fixed to ``127.0.0.1`` (ADR D10); ``port=0`` selects an
    ephemeral port (the default, so concurrent runs/tests never collide).
    """

    def __init__(self, port: int = 0) -> None:
        self.collector = Collector()
        self._server = ThreadingHTTPServer(
            ("127.0.0.1", port), _make_handler(self.collector)
        )
        self.host, self.port = self._server.server_address[:2]
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/c"

    def url_for(self, canary_id: str) -> str:
        """The full callback URL a payload should cause the target to fetch."""
        return f"{self.base_url}/{canary_id}"

    def saw(self, canary_id: str) -> bool:
        return self.collector.saw(canary_id)

    def evidence(self, canary_id: str) -> str:
        return self.collector.evidence(canary_id)

    def __enter__(self) -> "LocalCollector":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)
