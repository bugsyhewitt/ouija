"""Unit tests for the foundation spine (encoders, allowlist, oob, oracle, mutator,
findings, taxonomy, mcp_proto)."""

from __future__ import annotations

import httpx

from tests.agentic.conftest import run

from ouija import agentic_mutate, allowlist, asitax, encoders, findings, mcp_proto
from ouija.oob import LocalCollector
from ouija.oracle import Oracle
from ouija.targets.base import Turn


# --- encoders (Appendix D / D9) ---------------------------------------------


def test_encoders_roundtrip_and_shape():
    assert encoders.b64("hi") == "aGk="
    assert encoders.hexenc("AB") == "4142"
    assert encoders.rot13(encoders.rot13("secret")) == "secret"
    # homoglyph swaps Latin->Cyrillic confusables
    assert "а" in encoders.homoglyph("cat")  # cyrillic a
    # zero-width interleave inserts ZWSP between chars
    assert "​" in encoders.zero_width_wrap("ab")
    # unicode-tag smuggle maps ASCII into the TAG block
    assert encoders.unicode_tag_smuggle("A") == chr(0xE0000 + 65)


def test_carriers_registry_ordering():
    assert encoders.CARRIER_ORDER[0] == "plain"
    assert set(encoders.CARRIER_ORDER) == set(encoders.CARRIERS)


# --- allowlist (D10 / §15) --------------------------------------------------


def test_allowlist_host_and_port_matching():
    al = ["127.0.0.1:8731", "example.com"]
    assert allowlist.is_allowed("http://127.0.0.1:8731/mcp", al) is True
    assert allowlist.is_allowed("http://127.0.0.1:9999/mcp", al) is False  # wrong port
    assert allowlist.is_allowed("https://example.com/api", al) is True     # any port
    assert allowlist.is_allowed("https://evil.com/api", al) is False


def test_allowlist_bare_host_and_comments():
    entries = allowlist.load_allowlist("# c\n\nfoo.test:9000\n")
    assert entries == [("foo.test", 9000)]
    assert allowlist.is_allowed("foo.test:9000", entries) is True


def test_enforce_allowlist_raises_with_no_bypass_message():
    try:
        allowlist.enforce_allowlist("http://evil.com", ["good.com"])
        assert False
    except allowlist.AllowlistError as exc:
        assert "no bypass" in str(exc).lower()


# --- oob collector (Appendix C) ---------------------------------------------


def test_oob_collector_records_local_callback():
    async def go():
        with LocalCollector() as col:
            assert col.host == "127.0.0.1"
            cid = "abc123"
            async with httpx.AsyncClient() as h:
                await h.get(col.url_for(cid) + "?d=leaked")
            assert col.saw(cid) is True
            assert "leaked" in col.evidence(cid)
            assert col.saw("never") is False

    run(go())


# --- oracle (D2 / §11) ------------------------------------------------------


def test_oracle_judges_three_channels():
    async def go():
        with LocalCollector() as col:
            orc = Oracle(oob=col)
            # oob_exfil
            c1 = orc.new_canary()
            async with httpx.AsyncClient() as h:
                await h.get(orc.oob_url_for(c1))
            assert orc.judge(Turn(sent="x", received="ok"), c1).effect == "oob_exfil"
            # tool_call
            c2 = orc.new_canary()
            t = Turn(sent="x", received="", tool_calls=[{"name": "send",
                     "args": {"b": c2.token}}])
            assert orc.judge(t, c2).effect == "tool_call"
            # answer_flip
            c3 = orc.new_canary()
            assert orc.judge(Turn(sent="x", received=c3.token), c3).effect == "answer_flip"
            # real negative
            c4 = orc.new_canary()
            assert orc.judge(Turn(sent="x", received="clean"), c4).effect is None

    run(go())


def test_oracle_unrequested_call_structural_proof():
    orc = Oracle()
    t = Turn(sent="x", received="", tool_calls=[{"name": "get_weather", "args": {}},
             {"name": "send_message", "args": {"channel": "#exfil"}}])
    v = orc.judge_unrequested_call(t, requested={"get_weather"},
                                   sinks={"send_message"})
    assert v.effect == "tool_call" and "send_message" in v.evidence
    # if the sink WAS requested, it's not an effect
    v2 = orc.judge_unrequested_call(t, requested={"get_weather", "send_message"},
                                    sinks={"send_message"})
    assert v2.effect is None


def test_oracle_text_marker_extraction():
    orc = Oracle()
    t = Turn(sent="x", received="leaked SYS-PLANT-9 here")
    assert orc.judge_text_marker(t, "SYS-PLANT-9", "prompt_leak").effect == "prompt_leak"
    assert orc.judge_text_marker(t, "absent", "prompt_leak").effect is None


# --- mutator (D7) -----------------------------------------------------------


def test_builtin_mutator_plain_first_and_budget():
    bm = agentic_mutate.BuiltinMutator()
    vs = list(bm.variants("payload", budget=3))
    assert vs[0] == "payload"  # plain first
    assert len(vs) == 3
    assert agentic_mutate.mutate_seed("x", budget=1) == ["x"]


def test_mutator_protocol_isinstance():
    assert isinstance(agentic_mutate.BuiltinMutator(), agentic_mutate.Mutator)


# --- taxonomy (D4 / §4) -----------------------------------------------------


def test_taxonomy_covers_every_asi_category():
    assert asitax.asi_covered() == set(asitax.ASI.keys())


def test_probe_catalog_shape():
    cat = asitax.probe_catalog()
    assert len(cat) >= 14
    for entry in cat:
        assert set(("key", "title", "asi", "llm", "targets", "module",
                    "active", "stub", "proves")) <= set(entry)


# --- findings (§14 / Appendix F/G) ------------------------------------------


def test_finding_shape_and_refs():
    f = findings.ouija_finding("scan_mcp", target="t", state="confirmed",
                               title="x", asi=("ASI02",), llm=("LLM01",),
                               effect="tool_call", confidence=0.85, surface="tool")
    assert f["schema"] == "nmc.finding/v0"
    assert f["tool"] == "ouija" and f["severity"] is None
    assert f["refs"] == ["ASI02", "LLM01"]
    assert f["surface"] == "tool" and f["effect"] == "tool_call"


def test_bootstrap_ci_bounds():
    assert findings.bootstrap_ci([1, 1, 1, 1]) == (1.0, 1.0)
    assert findings.bootstrap_ci([0, 0, 0, 0]) == (0.0, 0.0)
    assert findings.bootstrap_ci([]) == (0.0, 0.0)
    lo, hi = findings.bootstrap_ci([1, 0, 1, 0, 1, 0])
    assert 0.0 <= lo <= hi <= 1.0


def test_measure_reports_asr_ci_and_effect():
    calls = {"n": 0}

    async def probe():
        from ouija.oracle import Verdict
        calls["n"] += 1
        # succeed on even attempts
        return Verdict("tool_call", 1.0, "ev") if calls["n"] % 2 == 0 else \
            Verdict(None, 0.0, "")

    stats = run(findings.measure(probe, repeats=10))
    assert stats["n"] == 10
    assert 0.0 < stats["asr"] <= 1.0
    assert stats["tool_call"] is True
    assert len(stats["ci95"]) == 2


def test_group_by_owasp():
    fs = [
        findings.ouija_finding("v", target="t", state="confirmed", title="a",
                               asi=("ASI06",), llm=("LLM08",)),
        findings.ouija_finding("v", target="t", state="confirmed", title="b",
                               asi=("ASI02",)),
    ]
    grouped = findings.group_by_owasp(fs)
    assert set(grouped) == {"ASI06", "ASI02"}


# --- mcp_proto (the in-process MCP shim) ------------------------------------


def test_mcp_proto_in_process_roundtrip():
    async def go():
        srv = mcp_proto.Server("lab", "1.0.0")

        @srv.tool
        def greet(name: str) -> str:
            """Greet someone."""
            return f"hi {name}"

        cs = mcp_proto.ClientSession(srv)
        info = await cs.initialize()
        assert info["serverInfo"]["name"] == "lab"
        tools = await cs.list_tools()
        assert tools[0].name == "greet"
        assert "Greet" in tools[0].description
        # schema inferred from signature
        assert "name" in tools[0].input_schema.get("properties", {})
        assert await cs.call_tool("greet", {"name": "x"}) == "hi x"

    run(go())


def test_mcp_proto_unknown_tool_errors():
    async def go():
        srv = mcp_proto.Server("lab")
        cs = mcp_proto.ClientSession(srv)
        await cs.initialize()
        try:
            await cs.call_tool("nope", {})
            assert False
        except mcp_proto.McpError:
            pass

    run(go())


def test_mcp_proto_set_tool_description_for_rug_pull():
    srv = mcp_proto.Server("lab")

    @srv.tool
    def t() -> str:
        """original."""
        return "ok"

    srv.set_tool_description("t", "MUTATED rug-pull description")
    async def go():
        cs = mcp_proto.ClientSession(srv)
        await cs.initialize()
        tools = await cs.list_tools()
        return tools[0].description

    assert "MUTATED" in run(go())


def test_real_sdk_optional():
    # The real mcp SDK is optional; on this machine it is absent. The guard must
    # report that cleanly (not raise).
    assert mcp_proto.real_sdk_available() in (True, False)
