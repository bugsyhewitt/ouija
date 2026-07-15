"""Agentic report renderers for ouija-agentic findings.

Two renderers live here:

* ``to_h1md(report)`` — HackerOne-style markdown draft, the agentic peer of
  ``ouija/report.py``'s ``to_h1md()`` for the single-endpoint fuzzer.
* ``to_sarif(report)`` — SARIF 2.1.0 JSON, the CI/CD integration format; lets
  users upload agentic scan results to GitHub Code Scanning, Azure DevOps, and
  any SARIF-compatible aggregator. The agentic peer of ``ouija/sarif.py``.

Design choices (both renderers):
  - Confirmed findings (data-flow proof) are shown prominently with their
    ASR/CI, so a triager immediately sees reliability.
  - Detected (static-only) findings are labelled clearly so a reviewer knows
    the effect has not yet been dynamically confirmed.
  - Not-vulnerable findings are omitted; they add bulk without reporting value.
  - Business-impact text is keyed off OWASP ASI/LLM refs (the same refs the
    ``nmc.finding/v0`` schema carries in ``refs``).
  - Every attacker-influenced string (evidence, surface, title) goes through
    ``_clean_md`` (h1md) or JSON-encoding (SARIF) before insertion to prevent
    injection into the report structure.
"""

from __future__ import annotations

import json as _json

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


# ---------------------------------------------------------------------------
# SARIF 2.1.0 renderer
# ---------------------------------------------------------------------------

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/bugsyhewitt/ouija"

# Data-flow effect → SARIF security-severity (CVSS-aligned numeric string).
# GitHub Code Scanning buckets: 0.0-3.9 low, 4.0-6.9 medium, 7.0-8.9 high,
# 9.0-10.0 critical.
_SARIF_SEVERITY: dict[str, str] = {
    "oob_exfil": "8.0",    # high — data left the system
    "prompt_leak": "8.0",  # high — system-prompt / memory recovered
    "memory_leak": "8.0",  # high — cross-session memory recovered
    "tool_call": "7.0",    # high — privileged tool invoked with attacker args
    "answer_flip": "6.0",  # medium — attacker-controlled content surfaced
}
_SARIF_LEVEL: dict[str, str] = {
    "confirmed": "error",
    "detected": "warning",
    "not_vulnerable": "note",  # suppressed in practice; not emitted by to_sarif
}


def _sarif_rule(ref: str) -> dict:
    """SARIF reportingDescriptor (rule) for an OWASP ASI/LLM ref."""
    impact = _IMPACT.get(ref, "See ouija documentation for this OWASP ref.")
    return {
        "id": ref,
        "name": ref.replace(":", "_"),
        "shortDescription": {"text": f"ouija {ref} finding"},
        "fullDescription": {"text": impact},
        "helpUri": INFORMATION_URI,
        "properties": {"tags": ["security", "llm-security", "owasp-asi"]},
    }


def _sarif_result(finding: dict) -> dict:
    """SARIF result for one ``nmc.finding/v0`` dict."""
    state = finding.get("state", "detected")
    effect = finding.get("effect")
    refs = finding.get("refs", [])
    # The first ASI/LLM ref is the primary SARIF rule anchor.
    primary_ref = next(
        (r for r in refs if r.startswith(("ASI", "LLM"))), "ouija"
    )

    raw = finding.get("raw") or {}
    props: dict[str, object] = {
        "security-severity": _SARIF_SEVERITY.get(effect or "", "4.0"),
        "ouija-effect": effect or "—",
        "ouija-state": state,
        "ouija-confidence": finding.get("confidence", 0.0),
        "refs": refs,
        "verb": finding.get("verb", ""),
        "target": finding.get("target", ""),
    }
    asr = raw.get("asr")
    if asr is not None:
        props["asr"] = asr
        ci = raw.get("ci95")
        if ci:
            props["ci95"] = ci
    if finding.get("surface"):
        props["surface"] = finding["surface"]

    title = finding.get("title", "Agentic finding")
    evidence = finding.get("evidence") or ""
    msg = f"{title}: {evidence}".strip().rstrip(":") if evidence else title

    # Build a stable per-finding fingerprint for deduplication across runs.
    # nmc.finding/v0 has no top-level id field; compose one from stable
    # structural fields (probe-derived, not model-response-derived).
    surface = finding.get("surface") or ""
    fingerprint = (
        f"{finding.get('verb','')}/{finding.get('target','')}"
        f"/{surface}/{primary_ref}/{effect or 'none'}"
    )

    return {
        "ruleId": primary_ref,
        "level": _SARIF_LEVEL.get(state, "warning"),
        "message": {"text": msg},
        "properties": props,
        "partialFingerprints": {"ouijaFindingId": fingerprint},
    }


def to_sarif(report) -> str:
    """Render a ``ScanReport`` as a SARIF 2.1.0 JSON document.

    Maps ouija-agentic ``nmc.finding/v0`` records to SARIF 2.1.0 results.
    Not-vulnerable findings are omitted (they carry no security signal).
    Each distinct OWASP ref present in reportable findings becomes a SARIF rule.

    The output is suitable for direct upload to GitHub Advanced Security
    (``gh code-scanning upload-results``) or Azure DevOps to surface agentic
    scan findings as code-scanning alerts with OWASP mapping, severity, and
    ASR metadata.
    """
    reportable = [
        f for f in report.findings if f.get("state") != "not_vulnerable"
    ]

    # Collect distinct OWASP refs in first-seen order for a deterministic rule list.
    refs_seen: list[str] = []
    for f in reportable:
        for ref in f.get("refs", []):
            if ref.startswith(("ASI", "LLM")) and ref not in refs_seen:
                refs_seen.append(ref)

    rules = [_sarif_rule(ref) for ref in refs_seen]
    results = [_sarif_result(f) for f in reportable]

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ouija-agentic",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {
                    "id": f"ouija-agentic/{report.verb}",
                    "description": {
                        "text": (
                            f"ouija-agentic {report.verb} against {report.target}"
                        ),
                    },
                },
                "properties": {
                    "verb": report.verb,
                    "target": report.target,
                },
                "results": results,
            }
        ],
    }
    return _json.dumps(sarif, indent=2)
