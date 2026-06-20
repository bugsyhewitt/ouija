"""ouija's own MCP surface — agent-callable, gated (Packet 02 §13).

Per the necromancer_mcp contract (Packet 01 §4.3/§6), all of ouija's scan/fuzz
verbs are *active* (``[A]``) and gated: each requires ``confirm=true`` and an
allow-listed target before it sends adversarial traffic (§15). ``list_probes`` is
safe (read-only).

ADAPTATION: Packet 01's Python ``necromancer_mcp.Server`` is not available on this
machine (necromancer_mcp is Go-only), so ouija's server is built on
:class:`ouija.mcp_proto.Server` — ouija's own minimal MCP server — which is the
self-contained equivalent. The ``must_active`` gate and the allow-list are
implemented here, not borrowed.

Recursion note: ouija can be pointed at *another* necromancer MCP server (useful
for self-testing the suite's own servers), but the allow-list and ``confirm`` gate
still apply (anti-pattern A5 — no bypass).
"""

from __future__ import annotations

from ouija import __version__
from ouija.agentic_scan import (
    fuzz_agent_target,
    scan_mcp_target,
    scan_rag_target,
)
from ouija.allowlist import AllowlistError, enforce_allowlist
from ouija.asitax import probe_catalog
from ouija.mcp_proto import Server


class GateError(Exception):
    """Raised when an active verb is called without confirm=true."""


def must_active(confirm: bool) -> None:
    """Refuse an active verb unless the caller explicitly confirmed (§13/§15)."""
    if not confirm:
        raise GateError(
            "this verb is ACTIVE: it sends adversarial payloads to a live target. "
            "Pass confirm=true to authorize, and ensure the target is allow-listed."
        )


def build_server(allowlist: object = ()) -> Server:
    """Construct ouija's MCP server with the four verbs (§13).

    *allowlist* is the set of authorized targets; the active verbs enforce it.
    """
    srv = Server("ouija", __version__)

    @srv.tool
    def list_probes() -> str:
        """List ouija's probe families with their OWASP ASI/LLM mappings (safe)."""
        import json
        return json.dumps(probe_catalog())

    @srv.tool
    async def scan_mcp(url: str = "", token: str = "", confirm: str = "false",
                       lab: str = "false", repeats: str = "20") -> str:
        """Fuzz a target MCP server (tool-poisoning, tool-result injection,
        rug-pull, oauth, ssrf). ACTIVE: requires confirm=true and an allow-listed
        target (§15)."""
        is_lab = _truthy(lab)
        must_active(_truthy(confirm))
        if not is_lab:
            enforce_allowlist(url, allowlist)
        report = await scan_mcp_target(
            url=url or None, token=token or None,
            allowlist=allowlist if not is_lab else [_lab_host()],
            lab_target=is_lab, repeats=int(repeats))
        return _dump(report)

    @srv.tool
    async def scan_rag(endpoint: str = "", confirm: str = "false",
                       lab: str = "false", repeats: str = "20") -> str:
        """Fuzz a RAG pipeline for poisoning / indirect injection. ACTIVE, gated,
        allow-listed."""
        is_lab = _truthy(lab)
        must_active(_truthy(confirm))
        if not is_lab:
            enforce_allowlist(endpoint, allowlist)
        report = await scan_rag_target(
            query_url=endpoint or None,
            allowlist=allowlist if not is_lab else [_lab_host()],
            lab_target=is_lab, repeats=int(repeats))
        return _dump(report)

    @srv.tool
    async def fuzz_agent(endpoint: str = "", confirm: str = "false",
                         lab: str = "false", repeats: str = "20") -> str:
        """Fuzz a tool-using agent for IPI / excessive-agency / exfil. ACTIVE,
        gated, allow-listed."""
        is_lab = _truthy(lab)
        must_active(_truthy(confirm))
        if not is_lab:
            enforce_allowlist(endpoint, allowlist)
        report = await fuzz_agent_target(
            endpoint=endpoint or None,
            allowlist=allowlist if not is_lab else [_lab_host()],
            lab_target=is_lab, repeats=int(repeats))
        return _dump(report)

    return srv


def _truthy(v: object) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _lab_host() -> str:
    return "127.0.0.1"


def _dump(report) -> str:
    import json
    return json.dumps({
        "verb": report.verb,
        "target": report.target,
        "findings": report.findings,
        "summary": {
            "total": len(report.findings),
            "confirmed": len(report.confirmed()),
            "detected": len(report.detected()),
        },
    })


if __name__ == "__main__":  # pragma: no cover - manual stdio run only
    build_server().run()
