"""Unit tests for indirect_pi, excessive_agency, extraction, baseline_garak."""

from __future__ import annotations

from tests.agentic.conftest import FAST_REPEATS, run

from ouija.allowlist import AllowlistError
from ouija.lab.lab_agent import LabAgent
from ouija.lab.rag_agent import VulnerableRAG
from ouija.lab.tools import LabToolbox
from ouija.modules import baseline_garak, excessive_agency, extraction, indirect_pi
from ouija.oob import LocalCollector
from ouija.oracle import Oracle
from ouija.targets import AgentEndpoint, RAGEndpoint
from ouija.targets.base import Turn


# --- indirect_pi (§7) -------------------------------------------------------


def test_rag_poisoning_confirms_and_cleans_up():
    with LocalCollector() as oob:
        orc = Oracle(oob=oob)
        rag = RAGEndpoint(backend=VulnerableRAG(vulnerable=True, toolbox=LabToolbox()))
        rag.url = "http://127.0.0.1/rag"
        findings = run(indirect_pi.probe_rag_poisoning(
            rag, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    assert findings
    assert {f["effect"] for f in findings} & {"oob_exfil", "tool_call", "answer_flip"}
    assert rag.planted() == set()  # cleaned up


def test_rag_poisoning_safe_target_no_findings():
    orc = Oracle()
    rag = RAGEndpoint(backend=VulnerableRAG(vulnerable=False, toolbox=LabToolbox()))
    rag.url = "http://127.0.0.1/rag"
    findings = run(indirect_pi.probe_rag_poisoning(
        rag, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    assert findings == []
    rag.assert_clean()


def test_tool_result_injection_confirms():
    with LocalCollector() as oob:
        orc = Oracle(oob=oob)
        agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=True).runner)
        agent.url = "http://127.0.0.1/agent"
        findings = run(indirect_pi.probe_tool_result_injection(
            agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    assert findings
    assert all(f["verb"] == "fuzz_agent" for f in findings)


def test_indirect_pi_enforces_allowlist():
    rag = RAGEndpoint(backend=VulnerableRAG())
    rag.url = "http://evil.example/rag"
    try:
        run(indirect_pi.probe_rag_poisoning(rag, Oracle(),
                                            allowlist=["127.0.0.1"], repeats=2))
        assert False
    except AllowlistError:
        pass


# --- excessive_agency (§9) --------------------------------------------------


def test_fuzz_agent_confirms_exfil_and_tool_misuse():
    with LocalCollector() as oob:
        orc = Oracle(oob=oob)
        agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=True).runner)
        agent.url = "http://127.0.0.1/agent"
        findings = run(excessive_agency.fuzz_agent(
            agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    effects = {f["effect"] for f in findings}
    assert "oob_exfil" in effects  # exfil through a permitted tool
    assert "tool_call" in effects  # dangerous-tool / scope-escalation


def test_fuzz_agent_hardened_no_findings():
    orc = Oracle()
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=False).runner)
    agent.url = "http://127.0.0.1/agent"
    findings = run(excessive_agency.fuzz_agent(
        agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    assert findings == []


def test_fuzz_agent_asr_is_stochastic_not_inflated():
    # Regression: a fresh canary must be minted PER attempt. A flaky (~50%)
    # target must yield an ASR strictly between 0 and 1 — a single shared canary
    # would make the sticky OOB collector read every repeat after the first as a
    # hit and collapse the ASR to 1.0 (anti-pattern A6).
    import random
    import re

    import httpx

    rng = random.Random(7)

    class _FlakyAgent:
        def runner(self, payload, inject_tool_result=None):
            m = re.search(r"http://127[^ ]+", payload)
            if m and rng.random() < 0.5:
                try:
                    httpx.get(m.group(0), timeout=1.0)
                except Exception:
                    pass
                return ("ok", [{"name": "send_email", "args": {"to": m.group(0)}}])
            return ("ok", [])

    with LocalCollector() as oob:
        orc = Oracle(oob=oob)
        agent = AgentEndpoint(runner=_FlakyAgent().runner)
        agent.url = "http://127.0.0.1/agent"
        findings = run(excessive_agency.fuzz_agent(
            agent, orc, allowlist=["127.0.0.1"], repeats=40))
    asrs = [f["raw"]["asr"] for f in findings]
    assert any(0.05 < a < 0.98 for a in asrs), (
        f"expected a stochastic ASR strictly between 0 and 1, got {asrs}")


# --- trust exploitation / ASI09 (§7 / ASI09) --------------------------------


def test_trust_exploitation_confirms_on_vulnerable_agent():
    orc = Oracle()
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=True).runner)
    agent.url = "http://127.0.0.1/agent"
    findings = run(indirect_pi.probe_trust_exploitation(
        agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    assert findings, "expected at least one trust-exploitation finding on a vulnerable agent"
    assert all(f["verb"] == "fuzz_agent" for f in findings)
    effects = {f["effect"] for f in findings}
    assert "answer_flip" in effects, "trust exploitation must confirm via answer_flip"
    asi_refs = {ref for f in findings for ref in f["refs"]}
    assert "ASI09" in asi_refs, "finding must be tagged ASI09"


def test_trust_exploitation_no_finding_on_hardened_agent():
    orc = Oracle()
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=False).runner)
    agent.url = "http://127.0.0.1/agent"
    findings = run(indirect_pi.probe_trust_exploitation(
        agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    assert findings == [], "hardened agent must produce no trust-exploitation finding"


def test_trust_exploitation_enforces_allowlist():
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=True).runner)
    agent.url = "http://evil.example/agent"
    try:
        run(indirect_pi.probe_trust_exploitation(
            agent, Oracle(), allowlist=["127.0.0.1"], repeats=2))
        assert False, "expected AllowlistError"
    except AllowlistError:
        pass


def test_trust_exploitation_asr_and_ci_on_confirmed():
    orc = Oracle()
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=True).runner)
    agent.url = "http://127.0.0.1/agent"
    findings = run(indirect_pi.probe_trust_exploitation(
        agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    for f in findings:
        assert "asr" in f["raw"] and "ci95" in f["raw"]
        lo, hi = f["raw"]["ci95"]
        assert 0.0 <= lo <= hi <= 1.0


# --- unexpected_code_exec / ASI05 -------------------------------------------


def test_unexpected_code_exec_confirms_on_vulnerable_agent():
    orc = Oracle()
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=True).runner)
    agent.url = "http://127.0.0.1/agent"
    findings = run(indirect_pi.probe_unexpected_code_exec(
        agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    assert findings, "expected at least one code-exec finding on a vulnerable agent"
    assert all(f["verb"] == "fuzz_agent" for f in findings)
    effects = {f["effect"] for f in findings}
    assert "tool_call" in effects, "code exec must confirm via tool_call"
    asi_refs = {ref for f in findings for ref in f["refs"]}
    assert "ASI05" in asi_refs, "finding must be tagged ASI05"


def test_unexpected_code_exec_no_finding_on_hardened_agent():
    orc = Oracle()
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=False).runner)
    agent.url = "http://127.0.0.1/agent"
    findings = run(indirect_pi.probe_unexpected_code_exec(
        agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    assert findings == [], "hardened agent must produce no code-exec finding"


def test_unexpected_code_exec_enforces_allowlist():
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=True).runner)
    agent.url = "http://evil.example/agent"
    try:
        run(indirect_pi.probe_unexpected_code_exec(
            agent, Oracle(), allowlist=["127.0.0.1"], repeats=2))
        assert False, "expected AllowlistError"
    except AllowlistError:
        pass


def test_unexpected_code_exec_asr_and_ci_on_confirmed():
    orc = Oracle()
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=True).runner)
    agent.url = "http://127.0.0.1/agent"
    findings = run(indirect_pi.probe_unexpected_code_exec(
        agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    for f in findings:
        assert "asr" in f["raw"] and "ci95" in f["raw"]
        lo, hi = f["raw"]["ci95"]
        assert 0.0 <= lo <= hi <= 1.0


# --- inter_agent_spoofing / ASI07 -------------------------------------------


def test_inter_agent_spoofing_confirms_on_vulnerable_agent():
    orc = Oracle()
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=True).runner)
    agent.url = "http://127.0.0.1/agent"
    findings = run(indirect_pi.probe_inter_agent_spoofing(
        agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    assert findings, "expected at least one spoofing finding on a vulnerable agent"
    assert all(f["verb"] == "fuzz_agent" for f in findings)
    effects = {f["effect"] for f in findings}
    assert "answer_flip" in effects, "inter-agent spoofing must confirm via answer_flip"
    asi_refs = {ref for f in findings for ref in f["refs"]}
    assert "ASI07" in asi_refs, "finding must be tagged ASI07"


def test_inter_agent_spoofing_no_finding_on_hardened_agent():
    orc = Oracle()
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=False).runner)
    agent.url = "http://127.0.0.1/agent"
    findings = run(indirect_pi.probe_inter_agent_spoofing(
        agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    assert findings == [], "hardened agent must produce no inter-agent-spoofing finding"


def test_inter_agent_spoofing_enforces_allowlist():
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=True).runner)
    agent.url = "http://evil.example/agent"
    try:
        run(indirect_pi.probe_inter_agent_spoofing(
            agent, Oracle(), allowlist=["127.0.0.1"], repeats=2))
        assert False, "expected AllowlistError"
    except AllowlistError:
        pass


def test_inter_agent_spoofing_asr_and_ci_on_confirmed():
    orc = Oracle()
    agent = AgentEndpoint(runner=LabAgent(LabToolbox(), vulnerable=True).runner)
    agent.url = "http://127.0.0.1/agent"
    findings = run(indirect_pi.probe_inter_agent_spoofing(
        agent, orc, allowlist=["127.0.0.1"], repeats=FAST_REPEATS))
    for f in findings:
        assert "asr" in f["raw"] and "ci95" in f["raw"]
        lo, hi = f["raw"]["ci95"]
        assert 0.0 <= lo <= hi <= 1.0


# --- extraction (§10) -------------------------------------------------------


class _LeakyTarget:
    kind = "agent"
    url = "http://127.0.0.1/leaky"

    def __init__(self, marker: str, leak: bool = True):
        self._marker = marker
        self._leak = leak

    async def send(self, payload):
        body = f"You are ACME bot. {self._marker}" if self._leak else \
            "I won't reveal my system prompt."
        return Turn(sent=payload, received=body)

    async def reset(self):
        pass

    def capabilities(self):
        return {}


def test_extraction_confirms_only_on_planted_marker():
    orc = Oracle()
    findings = run(extraction.probe_system_prompt_extraction(
        _LeakyTarget("SYS-PLANT-42", leak=True), orc, allowlist=["127.0.0.1"],
        planted_marker="SYS-PLANT-42", repeats=4))
    assert findings and findings[0]["effect"] == "prompt_leak"
    assert "LLM07" in findings[0]["refs"]


def test_extraction_no_finding_when_not_leaked():
    orc = Oracle()
    findings = run(extraction.probe_system_prompt_extraction(
        _LeakyTarget("SYS-PLANT-42", leak=False), orc, allowlist=["127.0.0.1"],
        planted_marker="SYS-PLANT-42", repeats=4))
    assert findings == []


def test_memory_extraction_confirms():
    orc = Oracle()
    findings = run(extraction.probe_memory_extraction(
        _LeakyTarget("MEM-PLANT-9", leak=True), orc, allowlist=["127.0.0.1"],
        planted_marker="MEM-PLANT-9", repeats=4))
    assert findings and findings[0]["effect"] == "memory_leak"
    assert "ASI06" in findings[0]["refs"]


# --- baseline_garak (§6) ----------------------------------------------------


def test_garak_parser_maps_failed_eval_to_llm01():
    line = ('{"entry_type": "eval", "probe": "p", "detector": "d", '
            '"passed": false, "asr": 0.5}')
    findings = baseline_garak.parse_garak_report(line, target="t")
    assert len(findings) == 1
    f = findings[0]
    assert f["state"] == "confirmed" and "LLM01" in f["refs"] and "garak" in f["refs"]
    assert f["raw"]["asr"] == 0.5


def test_garak_parser_records_negative():
    line = '{"entry_type": "eval", "probe": "p", "passed": true, "asr": 0.0}'
    findings = baseline_garak.parse_garak_report(line)
    assert findings[0]["state"] == "not_vulnerable"


def test_garak_parser_ignores_non_eval_and_garbage():
    text = '{"entry_type": "start_run"}\nnot json\n{"entry_type": "eval", "probe": "p", "passed": false}'
    findings = baseline_garak.parse_garak_report(text)
    assert len(findings) == 1


def test_garak_runner_raises_clearly_when_binary_absent(monkeypatch):
    monkeypatch.setattr(baseline_garak, "garak_available", lambda: False)
    try:
        run(baseline_garak.run_garak_baseline("rest", "m"))
        assert False
    except RuntimeError as exc:
        assert "garak is not installed" in str(exc)
