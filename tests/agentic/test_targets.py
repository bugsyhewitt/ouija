"""Unit tests for the four target adapters (§5)."""

from __future__ import annotations

from tests.agentic.conftest import run

from ouija.lab.poisoned_mcp import build_poisoned_mcp
from ouija.lab.rag_agent import VulnerableRAG
from ouija.targets import AgentEndpoint, MCPServer, RAGEndpoint, RawLLM, Target


def test_adapters_declare_kind():
    assert RawLLM.kind == "raw_llm"
    assert RAGEndpoint.kind == "rag"
    assert AgentEndpoint.kind == "agent"
    assert MCPServer.kind == "mcp"


def test_agent_requires_exactly_one_backend():
    try:
        AgentEndpoint()  # neither url nor runner
        assert False
    except ValueError:
        pass
    try:
        AgentEndpoint(url="http://x", runner=lambda *a, **k: ("", []))
        assert False
    except ValueError:
        pass


def test_agent_inproc_runner_surfaces_tool_calls():
    def runner(payload, inject_tool_result=None):
        return ("done", [{"name": "send_email", "args": {"body": "x"}}])

    ag = AgentEndpoint(runner=runner, tools=[{"name": "send_email"}])
    turn = run(ag.send("go"))
    assert turn.tool_calls[0]["name"] == "send_email"
    assert ag.capabilities()["tools"][0]["name"] == "send_email"


def test_agent_normalises_openai_tool_calls():
    from ouija.targets.agent import _normalise_tool_calls

    raw = [{"function": {"name": "wire", "arguments": '{"amt": "9"}'}}]
    out = _normalise_tool_calls(raw)
    assert out == [{"name": "wire", "args": {"amt": "9"}}]


def test_rag_requires_exactly_one_backend():
    try:
        RAGEndpoint()
        assert False
    except ValueError:
        pass


def test_rag_ingest_retract_and_clean_assertion():
    rag = RAGEndpoint(backend=VulnerableRAG())
    run(rag.ingest("planted poisoned doc", "d1"))
    assert rag.planted() == {"d1"}
    # leaving a plant behind fails loudly
    try:
        rag.assert_clean()
        assert False, "should have failed with a plant outstanding"
    except RuntimeError as exc:
        assert "planted" in str(exc)
    run(rag.retract("d1"))
    rag.assert_clean()  # now clean


def test_rag_query_returns_chunks():
    rag = RAGEndpoint(backend=VulnerableRAG(vulnerable=False))
    turn = run(rag.send("what is the refund policy?"))
    assert turn.raw.get("chunks")  # retriever surfaced chunk ids


def test_mcp_adapter_lists_surface_and_calls():
    srv, _ = build_poisoned_mcp()
    mt = MCPServer.from_server(srv, url="http://127.0.0.1:9920/mcp")
    surface = run(mt.list_surface())
    names = {t["name"] for t in surface["tools"]}
    assert {"get_weather", "fetch_url", "send_message", "echo"} == names
    turn = run(mt.call_tool("echo", {"text": "hello"}))
    assert turn.received == "hello"
    assert turn.tool_calls[0]["name"] == "echo"


def test_mcp_adapter_send_dict_and_string():
    srv, _ = build_poisoned_mcp()
    mt = MCPServer.from_server(srv)
    t1 = run(mt.send({"tool": "echo", "arguments": {"text": "a"}}))
    assert t1.received == "a"
    # bare tool name (all-default-args tool): send_message records a lab no-op
    t2 = run(mt.send("send_message"))
    assert t2.received == "ok"
    assert t2.tool_calls[0]["name"] == "send_message"
