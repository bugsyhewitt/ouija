"""Report rendering: JSON and HackerOne-style markdown (h1md)."""

from __future__ import annotations

import json

from ouija.models import ScanResult, Severity

# Bug-bounty business-impact framing per category.
_IMPACT = {
    "prompt_injection": (
        "An attacker can override the application's system instructions, "
        "causing the LLM to ignore its guardrails. Depending on the app's "
        "capabilities this enables unauthorized actions, content-policy "
        "bypass, data exfiltration via downstream tools, and reputational harm."
    ),
    "sensitive_info_disclosure": (
        "The endpoint leaks information it should keep confidential (system "
        "prompts, configuration, credentials, or PII). This aids further "
        "attacks and may itself be a privacy/compliance violation."
    ),
    "model_dos": (
        "The endpoint can be coerced into unbounded generation, driving up "
        "latency and cost (token-based billing) and degrading availability "
        "for legitimate users."
    ),
    "improper_output_handling": (
        "The endpoint renders attacker-controlled markup (markdown images, "
        "links, or HTML) into its output. When that output is auto-rendered by "
        "a downstream surface, the embedded URL is fetched silently — "
        "exfiltrating system prompts, conversation history, or secrets to an "
        "attacker-controlled host with zero user interaction (EchoLeak / "
        "CVE-2025-32711 'lethal trifecta' class)."
    ),
    "excessive_agency": (
        "The endpoint is an agent that can be coerced into invoking privileged "
        "or destructive tools/actions (sending email, calling state-changing "
        "APIs, running commands, escalating privileges) without a "
        "human-in-the-loop confirmation. An attacker who controls the prompt "
        "controls the agent's actions: the impact is the union of every tool the "
        "agent can reach — unauthorized transactions, data destruction, lateral "
        "movement, and exfiltration (OWASP LLM06:2025 Excessive Agency)."
    ),
    "improper_output_handling_active": (
        "The endpoint emits live, executable active content (HTML <script> "
        "tags, event-handler attributes, javascript: URIs, SQL fragments, or "
        "shell command strings) directly into its output. When a downstream "
        "application renders or executes that output without sanitization, an "
        "attacker who controls the prompt achieves stored or reflected XSS, SQL "
        "injection, or command injection through the LLM — enabling session "
        "theft, account takeover, data exfiltration, and server-side pivoting "
        "(OWASP LLM05:2025 Improper Output Handling)."
    ),
    "misinformation": (
        "The endpoint produces confident, authoritative-sounding content that "
        "is fabricated — invented citations and DOIs, non-existent CVEs, made-up "
        "statutes, false medical/dosage facts, or unverifiable figures — without "
        "any uncertainty hedge or grounding. Users and downstream systems that "
        "trust the output over-rely on it, leading to flawed decisions, "
        "reputational and legal exposure, propagation of false claims, and — for "
        "fabricated package/API references — supply-chain risk such as "
        "slopsquatting (OWASP LLM09:2025 Misinformation)."
    ),
    "safety_guardrail_bypass": (
        "The endpoint can be jailbroken: under a refusal-suppression framing "
        "(DAN / 'do-anything-now' persona override, hypothetical or fiction "
        "frame, a forged research/authority exception, or a simulated unlocked "
        "'developer mode'), the model abandons its safety guardrails and "
        "confirms it will comply with requests it would normally refuse. An "
        "attacker who controls the prompt can then drive the model to produce "
        "disallowed content — hate speech, dangerous instructions, malware, "
        "disinformation, CSAM-adjacent or self-harm content — which the "
        "deploying organization is liable for serving, with severe legal, "
        "safety, and reputational exposure (OWASP LLM01:2025 Prompt Injection, "
        "jailbreak / safety-bypass sub-vector)."
    ),
    "vector_embedding_weakness": (
        "The endpoint is backed by a vector store / RAG pipeline that fails to "
        "isolate or validate its retrieval context. An attacker can poison the "
        "knowledge base so retrieved chunks carry instructions the model obeys "
        "(indirect injection through the retrieval channel), or coerce the model "
        "into leaking isolated context — other tenants' documents, raw retrieved "
        "chunks, source metadata, or data recovered from stored embeddings. The "
        "impact is guardrail bypass delivered via trusted content and "
        "cross-context data exfiltration in multi-tenant deployments (OWASP "
        "LLM08:2025 Vector and Embedding Weaknesses)."
    ),
    "pii_disclosure": (
        "The endpoint regurgitates personally identifiable information — email "
        "addresses, phone numbers, social security numbers, payment-card "
        "numbers, or IBANs — that it memorized from training data or was given "
        "in its context/conversation, instead of refusing or redacting. An "
        "attacker can extract real individuals' personal and financial data, a "
        "direct privacy breach carrying regulatory exposure (GDPR / CCPA), "
        "identity-theft and payment-fraud risk, and — for cross-session leakage "
        "— a tenant-isolation failure (OWASP LLM02:2025 Sensitive Information "
        "Disclosure, PII / memorized-data sub-vector)."
    ),
}

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def to_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2)


def to_h1md(result: ScanResult) -> str:
    findings = sorted(
        result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)
    )
    lines: list[str] = []
    lines.append(f"# ouija findings report — {result.target}")
    lines.append("")
    lines.append(
        f"_Generated by ouija v{result.version}. Attack set: `{result.attack_set}`. "
        f"{result.patterns_sent} attack requests sent. "
        f"{len(findings)} finding(s)._"
    )
    lines.append("")

    if not findings:
        lines.append("No findings. The target refused or sanitized all probes "
                     "in this attack set.")
        lines.append("")
        return "\n".join(lines)

    for idx, f in enumerate(findings, start=1):
        lines.append(f"## Finding {idx}: {f.title}")
        lines.append("")
        lines.append(f"**Severity:** {f.severity.value.upper()}  ")
        lines.append(f"**Category:** {f.category}  ")
        lines.append(f"**OWASP LLM Top 10:** {f.owasp}  ")
        lines.append(f"**Confidence:** {f.confidence:.0%}  ")
        if f.attempts > 1:
            lines.append(
                f"**Reliability:** {f.successes}/{f.attempts} attempts "
                f"({f.success_rate:.0%})  "
            )
        lines.append(f"**Finding ID:** `{f.id}`  ")
        lines.append(f"**Pattern:** `{f.pattern_id}` (technique: {f.technique})")
        lines.append("")
        lines.append("### Summary")
        lines.append(f.evidence)
        lines.append("")
        lines.append("### Steps to reproduce")
        lines.append("")
        lines.append(f"1. Send the following prompt to `{result.target}`:")
        lines.append("")
        lines.append("```")
        lines.append(f.request_prompt)
        lines.append("```")
        lines.append("")
        lines.append("2. Observe the response, which contained:")
        lines.append("")
        lines.append("```")
        lines.append(f.response_excerpt)
        lines.append("```")
        lines.append("")
        lines.append("### Business impact")
        lines.append(_IMPACT.get(f.category, "See category description."))
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def render(result: ScanResult, fmt: str) -> str:
    if fmt == "json":
        return to_json(result)
    if fmt == "h1md":
        return to_h1md(result)
    raise ValueError(f"unknown format '{fmt}'")
