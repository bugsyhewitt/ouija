"""Unit tests for ouija's own MCP server (§13) — the Packet-01 three-tier shape."""

from __future__ import annotations

import json

from tests.agentic.conftest import FAST_REPEATS, run

from ouija.mcp_proto import ClientSession, McpError
from ouija.mcp_server import GateError, build_server, must_active


# --- tier: unit (gate logic) ------------------------------------------------


def test_must_active_gate():
    must_active(True)  # no raise
    try:
        must_active(False)
        assert False
    except GateError as exc:
        assert "ACTIVE" in str(exc)


# --- tier: Inspector-equivalent (advertised surface) ------------------------


def test_server_advertises_four_verbs():
    srv = build_server(allowlist=["127.0.0.1"])

    async def go():
        cs = ClientSession(srv)
        await cs.initialize()
        return await cs.list_tools()

    tools = run(go())
    names = {t.name for t in tools}
    assert names == {"list_probes", "scan_mcp", "scan_rag", "fuzz_agent"}


def test_list_probes_is_safe_and_returns_catalog():
    srv = build_server()

    async def go():
        cs = ClientSession(srv)
        await cs.initialize()
        return json.loads(await cs.call_tool("list_probes", {}))

    cat = run(go())
    assert len(cat) >= 14


def test_active_verb_gated_without_confirm():
    srv = build_server(allowlist=["127.0.0.1"])

    async def go():
        cs = ClientSession(srv)
        await cs.initialize()
        await cs.call_tool("scan_mcp", {"lab": "true", "confirm": "false"})

    try:
        run(go())
        assert False
    except McpError as exc:
        assert "ACTIVE" in str(exc) or "confirm" in str(exc)


def test_active_verb_allowlist_enforced_on_live_url():
    srv = build_server(allowlist=["127.0.0.1"])

    async def go():
        cs = ClientSession(srv)
        await cs.initialize()
        # live (non-lab) url that is not allow-listed -> refused
        await cs.call_tool("scan_mcp",
                           {"url": "http://evil.example/mcp", "confirm": "true"})

    try:
        run(go())
        assert False
    except McpError as exc:
        assert "allow-list" in str(exc)


# --- tier: live smoke (drive scan_mcp against the lab server OVER MCP) -------


def test_live_smoke_scan_mcp_over_mcp_against_lab():
    srv = build_server(allowlist=["127.0.0.1"])

    async def go():
        cs = ClientSession(srv)
        await cs.initialize()
        out = await cs.call_tool(
            "scan_mcp", {"lab": "true", "confirm": "true",
                         "repeats": str(FAST_REPEATS)})
        return json.loads(out)

    result = run(go())
    assert result["summary"]["detected"] >= 1
    assert result["summary"]["confirmed"] >= 1
    assert result["verb"] == "scan_mcp"
