"""Human-readable HackerOne-style markdown report for ouija-agentic findings.

``to_h1md(report)`` renders a ``ScanReport`` from the agentic scanner into a
HackerOne-compatible markdown draft.  It is the agentic scanner's peer of
``ouija/report.py``'s ``to_h1md()`` for the single-endpoint fuzzer.

Design choices:
  - Confirmed findings (data-flow proof) are shown prominently with their
    ASR/CI, so a triager immediately sees reliability.
  - Detected (static-only) findings are labelled clearly so a reviewer knows
    the effect has not yet been dynamically confirmed.
  - Not-vulnerable findings are omitted; they add bulk without reporting value.
  - Business-impact text is keyed off OWASP ASI/LLM refs (the same refs the
    ``nmc.finding/v0`` schema carries in ``refs``).
  - Every attacker-influenced string (evidence, surface, title) goes through
    ``_clean_md`` before insertion to prevent raw markdown syntax from breaking
    the report structure.
"""

from __future__ import annotations

from ouija import __version__

# ---------------------------------------------------------------------------
# OWASP-ref → business-impact text (abbreviated for the report)
# ---------------------------------------------------------------------------
_IMPACT = {
    "ASI01": (
        "An attacker who can hijack the agent's goal can redirect it to perform "
        "unauthorized actions, leak data, or abandon its intended task entirely."
    ),
    "ASI02": (
        "Tool misuse lets an attacker coerce the agent into invoking privileged "
        "or destructive tools with no human-in-the-loop approval gate — the blast "
        "radius is the union of every tool the agent can reach."
    ),
    "ASI03": (
        "Agent identity / privilege abuse allows an attacker to impersonate a "
        "higher-privilege agent or escalate the agent's effective permissions, "
        "bypassing authorization boundaries."
    ),
    "ASI04": (
        "Agentic supply-chain compromise means an attacker can inject malicious "
        "tool definitions or plugin updates into the agent's environment."
    ),
    "ASI05": (
        "Unexpected code execution via the agent's tool calls allows an attacker "
        "to run arbitrary code in the agent's execution environment."
    ),
    "ASI06": (
        "Memory / context poisoning lets an attacker plant persistent instructions "
        "in the agent's retrieval store that outlast the conversation and steer "
        "future sessions."
    ),
    "ASI07": (
        "Insecure inter-agent communication allows a message from one agent to "
        "inject instructions into another, escalating the attack across a "
        "multi-agent pipeline."
    ),
    "ASI08": (
        "Cascading failures in an agentic pipeline can cause a single compromised "
        "tool to propagate attacker-controlled state through downstream agents."
    ),
    "ASI09": (
        "Human-agent trust exploitation abuses the human operator's tendency to "
        "follow agent recommendations without verification."
    ),
    "ASI10": (
        "A rogue agent that operates outside its intended mandate can exfiltrate "
        "data, invoke unauthorized tools, or persist beyond a session."
    ),
    "LLM01": (
        "Prompt injection allows an attacker to override the application's system "
        "instructions, ignoring guardrails and causing the LLM to execute "
        "attacker-controlled instructions."
    ),
    "LLM02": (
        "Sensitive-information disclosure exposes system-prompt contents, API keys, "
        "or configuration secrets to an unauthorized caller."
    ),
    "LLM06": (
        "Excessive agency means the LLM can be coerced into taking privileged "
        "real-world actions (send email, call APIs, delete records) without the "
        "operator's explicit consent."
    ),
    "LLM07": (
        "System-prompt leakage reveals the application's hidden instructions, "
        "business rules, and any embedded secrets to an attacker, providing the "
        "blueprint for reliable follow-on attacks."
    ),
    "LLM08": (
        "Vector and embedding weaknesses in the RAG pipeline allow an attacker to "
        "plant documents that are retrieved and treated as trusted instructions, "
        "poisoning the model's answers or triggering unauthorized tool calls."
    ),
}

_EFFECT_LABEL = {
    "oob_exfil": "Out-of-band exfiltration (OOB callback confirmed)",
    "tool_call": "Unrequested tool call",
    "answer_flip": "Answer flipped to attacker-controlled content",
    "prompt_leak": "System-prompt / memory leaked",
}


def _clean_md(s: object) -> str:
    """Collapse a value to a single line with no unescaped backtick-fences."""
    return " ".join(str(s).split()).replace("```", "'''")


def _refs_display(refs: list) -> str:
    """Join refs into a display string, e.g. 'ASI02, ASI04, LLM01'."""
    return ", ".join(str(r) for r in refs) if refs else "—"


def _impact_for_refs(refs: list) -> str:
    """Return the first non-None impact string for the finding's OWASP refs."""
    for ref in refs:
        text = _IMPACT.get(str(ref))
        if text:
            return text
    return (
        "This finding demonstrates the target can be coerced into behaviour "
        "outside its intended mandate. Review the OWASP mapping for a precise "
        "business-impact assessment."
    )


def _asr_line(raw: dict) -> str:
    """Render the ASR/CI line for a confirmed finding."""
    asr = raw.get("asr")
    ci = raw.get("ci95")
    n = raw.get("n")
    if asr is None:
        return ""
    parts = [f"{asr:.0%}"]
    if ci and len(ci) == 2:
        lo, hi = ci
        parts.append(f"95% CI [{lo:.0%}, {hi:.0%}]")
    if n:
        parts.append(f"n={n}")
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Main renderer
# ---------------------------------------------------------------------------

def to_h1md(report) -> str:
    """Render a ``ScanReport`` as a HackerOne-style markdown report.

    Confirmed and detected findings are included; not-vulnerable entries are
    omitted.  Findings are ordered: confirmed first (strongest signal), then
    detected.
    """
    lines: list[str] = []

    confirmed = report.confirmed()
    detected = report.detected()
    reportable = confirmed + [
        f for f in report.findings
        if f.get("state") == "detected"
    ]

    lines.append(f"# ouija agentic findings — {report.target}")
    lines.append("")
    lines.append(
        f"_Generated by ouija-agentic v{__version__}. "
        f"Verb: `{report.verb}`. "
        f"{len(reportable)} finding(s) "
        f"({len(confirmed)} confirmed, {len(detected)} detected)._"
    )
    lines.append("")

    if not reportable:
        lines.append("## No findings")
        lines.append("")
        lines.append(
            "The agentic scan completed without observing a data-flow effect or "
            "a static indicator against the target."
        )
        return "\n".join(lines)

    lines.append("---")
    lines.append("")

    for idx, f in enumerate(reportable, start=1):
        state = f.get("state", "detected")
        state_label = "CONFIRMED" if state == "confirmed" else "DETECTED (static)"
        title = _clean_md(f.get("title", "Agentic finding"))
        refs = f.get("refs", [])
        surface = f.get("surface")
        effect = f.get("effect")
        evidence = _clean_md(f.get("evidence", ""))
        raw = f.get("raw") or {}

        lines.append(f"## Finding {idx}: {title}")
        lines.append("")
        lines.append(f"**State:** {state_label}")
        lines.append(f"**Effect:** {_EFFECT_LABEL.get(effect, effect or '—')}")
        lines.append(f"**OWASP Mapping:** {_refs_display(refs)}")
        if surface:
            lines.append(f"**Surface:** `{_clean_md(surface)}`")
        if state == "confirmed":
            asr_line = _asr_line(raw)
            if asr_line:
                lines.append(f"**Attack Success Rate:** {asr_line}")
        conf = f.get("confidence")
        if conf is not None:
            lines.append(f"**Confidence:** {float(conf):.0%}")

        if evidence:
            lines.append("")
            lines.append("### Evidence")
            lines.append("")
            lines.append(f"```\n{evidence}\n```")

        lines.append("")
        lines.append("### Business Impact")
        lines.append("")
        lines.append(_impact_for_refs(refs))
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
