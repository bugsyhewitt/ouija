"""OWASP taxonomy backbone — ASI01–ASI10 + LLM Top-10 (Packet 02 §4 / ADR D4).

Every ouija agentic probe declares which OWASP ASI (Top 10 for Agentic
Applications 2026) and/or LLM (Top 10 for LLM Apps 2025) category it exercises.
This is the differentiator versus garak's flat probe list: standards-mapped
reporting (DeepTeam's proven edge) and a coverage rule that forces modules to be
*complete* against a recognised taxonomy instead of ad hoc.

Coverage rule (§4): ouija ships modules covering **every ASI category** at least
at a smoke level before v1.0. The probe catalog below maps each family; the
later-lap categories (ASI05 / ASI08 / ASI10) are declared as stubs so the
taxonomy is never *silently* incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --- OWASP ASI Top 10 for Agentic Applications 2026 (announced 2025-12-09) ---
ASI = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Agent Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# --- relevant OWASP LLM Top 10 for LLM Apps 2025 entries --------------------
LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
}


@dataclass(frozen=True)
class ProbeFamily:
    """One row of the §4 probe taxonomy — the build checklist for the modules."""

    key: str
    title: str
    asi: tuple[str, ...]
    llm: tuple[str, ...]
    targets: tuple[str, ...]  # subset of raw_llm/rag/agent/mcp
    module: str
    proves: str
    # `active` is always True (ouija sends adversarial input). `stub` flags a
    # taxonomy-declared family whose probe is a later-lap smoke, not yet a full
    # implementation — so coverage is legible, not silently missing.
    active: bool = True
    stub: bool = False
    references: tuple[str, ...] = field(default_factory=tuple)


# The probe taxonomy spine (§4). Each entry maps a family to its OWASP categories,
# compatible target adapters, and the module that owns it.
PROBE_FAMILIES: tuple[ProbeFamily, ...] = (
    ProbeFamily(
        "direct_pi", "Direct prompt injection / jailbreak (baseline)",
        ("ASI01",), ("LLM01",), ("raw_llm", "agent"),
        "baseline_garak",
        "Model-level instruction override (weak signal on frontier models).",
    ),
    ProbeFamily(
        "carrier_evasion", "Carrier/encoding evasion (transform)",
        (), ("LLM01",), ("raw_llm", "rag", "agent", "mcp"),
        "encoders",
        "Bypass of input filters via Base64/homoglyph/zero-width/Unicode-tag.",
    ),
    ProbeFamily(
        "indirect_pi_tool_result", "Indirect PI via tool results",
        ("ASI01",), ("LLM01",), ("agent", "mcp"),
        "indirect_pi",
        "Injection delivered in a tool's return value changes agent behaviour.",
    ),
    ProbeFamily(
        "rag_poisoning", "RAG / memory poisoning",
        ("ASI06",), ("LLM08",), ("rag", "agent"),
        "indirect_pi",
        "A planted document is retrieved and steers output / tool-calls.",
    ),
    ProbeFamily(
        "rag_rank_shift", "Retrieval rank-shift / corpus poisoning",
        ("ASI06",), ("LLM08",), ("rag",),
        "indirect_pi",
        "Attacker content out-ranks legitimate docs in retrieval.",
    ),
    ProbeFamily(
        "mcp_tool_poisoning", "MCP tool poisoning",
        ("ASI02", "ASI04"), ("LLM01",), ("mcp",),
        "mcp_fuzz",
        "Malicious instructions in tool description/schema influence the agent.",
    ),
    ProbeFamily(
        "mcp_rug_pull", "MCP rug-pull / definition drift",
        ("ASI04",), (), ("mcp",),
        "mcp_fuzz",
        "Tool definition changes post-approval (TOCTOU).",
    ),
    ProbeFamily(
        "mcp_confused_deputy", "MCP confused-deputy / OAuth",
        ("ASI03", "ASI07"), (), ("mcp",),
        "mcp_fuzz",
        "Server acts with elevated privilege; OAuth redirect/consent reuse.",
    ),
    ProbeFamily(
        "mcp_token_passthrough", "MCP token passthrough / audience",
        ("ASI03",), (), ("mcp",),
        "mcp_fuzz",
        "Server accepts a token not minted for it (audience-check bypass).",
    ),
    ProbeFamily(
        "mcp_ssrf_discovery", "MCP SSRF-in-discovery",
        ("ASI04",), (), ("mcp",),
        "mcp_fuzz",
        "Attacker URL in protected-resource metadata fetched server-side.",
    ),
    ProbeFamily(
        "excessive_agency", "Excessive agency / tool misuse",
        ("ASI02",), ("LLM06",), ("agent", "mcp"),
        "excessive_agency",
        "Agent invokes dangerous tools, escalates scope, recurses unbounded.",
    ),
    ProbeFamily(
        "exfil_via_tool_chain", "Data exfiltration via tool chain",
        ("ASI02",), ("LLM06",), ("agent",),
        "excessive_agency",
        "Injected instruction causes a real exfil through a permitted tool.",
    ),
    ProbeFamily(
        "system_prompt_extraction", "System-prompt extraction",
        (), ("LLM07",), ("raw_llm", "agent"),
        "extraction",
        "The system/developer prompt is recovered.",
    ),
    ProbeFamily(
        "memory_extraction", "Memory/context extraction",
        ("ASI06",), (), ("agent",),
        "extraction",
        "Persistent memory or other users' context is read.",
    ),
    # --- taxonomy-declared stubs (later laps) — keep coverage legible -------
    ProbeFamily(
        "inter_agent_spoofing", "Inter-agent message spoofing",
        ("ASI07",), (), ("agent",),
        "excessive_agency",
        "Forged/replayed messages between agents are accepted.",
        stub=True,
    ),
    ProbeFamily(
        "unexpected_code_exec", "Unexpected code execution",
        ("ASI05",), (), ("agent", "mcp"),
        "excessive_agency",
        "Injected input reaches a code-exec sink (eval/exec/shell).",
        stub=True,
    ),
    ProbeFamily(
        "cascading_failures", "Cascading failures",
        ("ASI08",), (), ("agent",),
        "excessive_agency",
        "Unbounded recursion / step-budget exhaustion cascades across tools.",
        stub=True,
    ),
    ProbeFamily(
        "rogue_agents", "Rogue agents",
        ("ASI10",), (), ("agent",),
        "excessive_agency",
        "An agent persists self-reinforcing/adversarial behaviour (Zombie).",
        stub=True,
    ),
    ProbeFamily(
        "human_agent_trust", "Human-agent trust exploitation",
        ("ASI09",), ("LLM01",), ("agent", "mcp"),
        "indirect_pi",
        "Attacker content is surfaced to the human as trusted agent output / "
        "consent (line-jumping into a confirmation the user rubber-stamps).",
    ),
)

_BY_KEY = {f.key: f for f in PROBE_FAMILIES}


def probe_catalog() -> list[dict]:
    """List ouija's probe families with their OWASP ASI/LLM mappings (safe).

    This is what the ``list_probes`` MCP verb (§13) returns. It is read-only and
    sends nothing — purely the advertised capability surface.
    """
    out: list[dict] = []
    for f in PROBE_FAMILIES:
        out.append(
            {
                "key": f.key,
                "title": f.title,
                "asi": list(f.asi),
                "llm": list(f.llm),
                "targets": list(f.targets),
                "module": f.module,
                "active": f.active,
                "stub": f.stub,
                "proves": f.proves,
            }
        )
    return out


def family(key: str) -> ProbeFamily:
    """Look up a probe family by key (raises KeyError if unknown)."""
    return _BY_KEY[key]


def asi_covered() -> set[str]:
    """The set of ASI categories any probe family declares (for the coverage rule)."""
    covered: set[str] = set()
    for f in PROBE_FAMILIES:
        covered.update(f.asi)
    return covered


def refs_for(asi: tuple[str, ...] = (), llm: tuple[str, ...] = ()) -> list[str]:
    """Build a finding's ``refs`` list: ASI/LLM ids + their human titles.

    Per §14, asi/llm go in ``refs`` until Packet 03 adds first-class fields.
    """
    refs: list[str] = []
    for a in asi:
        refs.append(a)
    for l in llm:
        refs.append(l)
    return refs
