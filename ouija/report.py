"""Report rendering: JSON and HackerOne-style markdown (h1md)."""

from __future__ import annotations

import csv
import html
import io
import json

from ouija.models import Finding, ScanResult, Severity

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
    "supply_chain_poisoning": (
        "The endpoint recommends installing an attacker-controlled package — it "
        "emits a concrete, copy-pasteable install or dependency directive (a "
        "pip/npm/gem/cargo/apt/composer/poetry install command, a curl|sh "
        "bootstrap, or a requirements.txt / package.json dependency line) "
        "referencing a package name an attacker registers. A developer or a CI "
        "pipeline that trusts the model's suggestion then pulls and executes "
        "attacker code in the build and runtime environment. This is the "
        "slopsquatting attack chain: the model hallucinates or is steered into "
        "naming a non-existent / typosquatted package, the attacker registers "
        "that exact name, and every consumer of the model's advice is "
        "compromised — software-supply-chain code execution with downstream "
        "blast radius (OWASP LLM03:2025 Supply Chain)."
    ),
    "system_prompt_extraction": (
        "The endpoint reproduces its hidden system / developer prompt verbatim "
        "when pressed with a bypass technique — an instruction-hierarchy "
        "override, a roleplay / persona reframe, completion priming, a 'repeat "
        "the words above' request, or translation laundering — instead of "
        "refusing. The leaked prompt exposes the application's guardrails, "
        "allowed tools and capabilities, business rules, and any credentials or "
        "URLs embedded directly in the prompt. An attacker who reads the system "
        "prompt gains the blueprint to craft reliable follow-on prompt-injection "
        "and jailbreak attacks, to impersonate the application's framing, and to "
        "harvest any prompt-embedded secrets — a foothold that multiplies the "
        "blast radius of every other attack class (OWASP LLM07:2025 System "
        "Prompt Leakage)."
    ),
    "output_integrity_violation": (
        "The endpoint violates its own machine-consumed output contract — it was "
        "bound to a strict, downstream-parsed format (ONLY valid JSON, exactly "
        "one line, only the bare enum value, only content inside a fence or "
        "delimiter region) and silently smuggled out-of-band content past that "
        "contract. When the model's output is consumed by an automated downstream "
        "system without re-validation — a JSON.parse, a webhook router keyed on "
        "the response, an agent's tool-argument deserializer, a CI gate that "
        "greps for an exact status token — the smuggled, out-of-format content "
        "causes mis-parsing, mis-routing, or unintended action on attacker-shaped "
        "data. This is the output-INTEGRITY failure mode of improper output "
        "handling, distinct from the data-exfiltration (markdown-image canary) "
        "and code-execution (live active-content sink) LLM05 sub-vectors: here "
        "the harm is that a model trusted to honour a format can be made to break "
        "it silently, defeating every downstream control that assumes the "
        "contract holds (OWASP LLM05:2025 Improper Output Handling)."
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


def to_jsonl(result: ScanResult) -> str:
    """Render the scan as newline-delimited JSON (JSON Lines / NDJSON).

    Where ``--format json`` emits a single indented document that a consumer
    must read whole, ``--format jsonl`` emits one compact JSON object per line
    so the output is *streamable*: a log shipper, ``jq -c``, ``while read line``,
    or a line-buffered tail can consume each record as a standalone document
    without buffering the entire (potentially large) report.

    [Worker decision (Phase 2 / R27): chose JSON-streaming output (``jsonl``)
    over ``--schedule`` recurring-scan. The R26 ``--notify`` worker already
    assessed and rejected ``--schedule`` because a scheduler implies a
    long-running stateful daemon + persistence, which fights ouija's stateless
    single-run CLI design (the README delegates recurrence to external cron).
    That assessment still holds at R27. JSONL, by contrast, is a pure function
    over the final ``ScanResult`` — same shape as ``to_json``/``to_sarif`` — so
    it needs no async restructuring of the scanner and changes no architecture.]

    The stream is exactly three *record kinds*, in order, each tagged with a
    ``"record"`` discriminator so a consumer can route by line:

    * one ``"scan"`` header line — the run identity and counts (every top-level
      ``ScanResult`` field EXCEPT ``findings``/``summary``);
    * zero-or-more ``"finding"`` lines — one full :class:`~ouija.models.Finding`
      per line, carrying every field the ``json`` report's findings carry;
    * one ``"summary"`` footer line — the roll-up block.

    The union of all lines is information-equivalent to the single ``json``
    document, so no detail is lost; it is only reshaped for streaming.
    """
    dumped = result.model_dump(mode="json")
    findings = dumped.pop("findings")
    summary = dumped.pop("summary")

    lines: list[str] = []
    lines.append(json.dumps({"record": "scan", **dumped}))
    for finding in findings:
        lines.append(json.dumps({"record": "finding", **finding}))
    lines.append(json.dumps({"record": "summary", **summary}))
    return "\n".join(lines)


# Stable, documented column order for the `--format csv` triage export. One row
# per finding; the columns are the Finding fields a bug-bounty triager sorts and
# filters on in a spreadsheet (severity/category/owasp first), plus the
# reliability metrics (attempts/successes/success_rate) populated by --repeats.
# The full evidence/prompt/response text columns come last because they are the
# wide free-text fields. Multi-turn transcripts are NOT flattened into CSV (they
# are a nested structure with no sensible single-cell form) — use --format json
# or h1md for those; the row still appears, identified by its id/pattern_id.
CSV_COLUMNS: tuple[str, ...] = (
    "id",
    "severity",
    "category",
    "owasp",
    "title",
    "confidence",
    "attempts",
    "successes",
    "success_rate",
    "pattern_id",
    "technique",
    "request_prompt",
    "response_excerpt",
    "evidence",
)


def to_csv(result: ScanResult) -> str:
    """Render the findings as RFC-4180 CSV — one header row, one row per finding.

    Where ``--format json``/``jsonl`` are machine-pipe formats and ``h1md`` is a
    prose report, ``--format csv`` is the spreadsheet hand-off: a triager pastes
    it into Excel / Google Sheets / a ticket importer to sort by severity, filter
    by category, and assign findings. The header is emitted even for a zero-
    finding run so a downstream importer always sees the schema.

    [Worker decision (Phase 2 / R28): chose ``--format csv`` over
    ``--output-file`` auto-rotation. CSV is a pure function over the final
    :class:`~ouija.models.ScanResult` — identical in shape to
    ``to_json``/``to_jsonl``/``to_sarif`` — so it touches no scanner state and
    no architecture, matching how every prior format was added. ``--output-file``
    rotation, by contrast, would introduce file-writing + a rotation/retention
    policy into a tool that is deliberately stdout-only (the README delegates
    artifact management to shell redirection and CI upload steps), a larger and
    less defensible change. ``--schedule`` stays deferred (stateful daemon).]

    Findings are ordered by descending severity (critical first), matching the
    ``h1md`` report, and quoting follows :mod:`csv`'s default RFC-4180 rules so a
    comma or newline embedded in a prompt/evidence cell never breaks a row.
    """
    findings = sorted(
        result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)
    )
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(CSV_COLUMNS),
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    for f in findings:
        row = f.model_dump(mode="json")
        row["severity"] = f.severity.value
        writer.writerow({col: row.get(col, "") for col in CSV_COLUMNS})
    return buf.getvalue().rstrip("\n")


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
        if f.transcript:
            # Multi-turn / Crescendo finding: reproduce the full conversation so a
            # triager can replay the exact escalation that defeated the guardrail.
            lines.append(
                f"This is a multi-turn (Crescendo) finding. The target complied "
                f"on turn {f.turn_succeeded} after conversational escalation. "
                f"Replay the conversation against `{result.target}`, sending each "
                f"user turn in order and carrying the full message history:"
            )
            lines.append("")
            lines.append("```")
            turn_no = 0
            for msg in f.transcript:
                if msg["role"] == "user":
                    turn_no += 1
                    lines.append(f"[turn {turn_no}] user: {msg['content']}")
                else:
                    lines.append(f"          assistant: {msg['content']}")
            lines.append("```")
            lines.append("")
        else:
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


# Per-severity accent colours for the HTML report. Chosen for clear visual
# triage (critical/high jump out) and sufficient contrast against a light card
# background; values are inlined into the self-contained <style> block so the
# report needs no external stylesheet, font, or asset to render.
_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#b30000",
    Severity.HIGH: "#d9480f",
    Severity.MEDIUM: "#b8860b",
    Severity.LOW: "#1c7ed6",
    Severity.INFO: "#5c6770",
}


def _esc(text: str) -> str:
    """HTML-escape *text* for safe interpolation into element content/attributes.

    Every value that originates from the target's response or an attack prompt
    is attacker-influenced, so it MUST be escaped before being placed into the
    HTML report — otherwise a finding's response_excerpt containing ``<script>``
    (exactly the active-content class ouija detects) would execute when the
    report is opened in a browser. :func:`html.escape` with ``quote=True``
    neutralises ``< > & " '`` so the value can sit safely in both element bodies
    and quoted attributes.
    """
    return html.escape(str(text), quote=True)


def _html_transcript(f: Finding) -> str:
    """Render a multi-turn finding's transcript as an escaped <pre> block."""
    lines: list[str] = []
    turn_no = 0
    for msg in f.transcript or []:
        if msg["role"] == "user":
            turn_no += 1
            lines.append(f"[turn {turn_no}] user: {msg['content']}")
        else:
            lines.append(f"          assistant: {msg['content']}")
    return _esc("\n".join(lines))


def to_html(result: ScanResult) -> str:
    """Render the scan as a single, self-contained HTML document.

    Where ``--format h1md`` emits HackerOne markdown a hunter pastes into a
    report form, and ``json``/``jsonl``/``csv``/``sarif`` feed machines,
    ``--format html`` is the *shareable artifact*: one file with embedded CSS
    (no external stylesheet, font, JS, or network asset) that opens in any
    browser. Redirect it to ``report.html`` and hand it to a stakeholder, attach
    it to a ticket, or archive it as the human-readable run record.

    [Worker decision (Phase 2 / R29): chose ``--format html`` over
    ``--format markdown-table``. Both were unshipped post-v0.1 directions; HTML
    is the more defensible single improvement because it is a *complete*
    deliverable — a triager or non-technical stakeholder opens it directly in a
    browser with no markdown-rendering toolchain and no question of which
    flavour renders tables. Like every prior format (json/jsonl/csv/sarif/h1md)
    it is a pure function over the final :class:`~ouija.models.ScanResult`, so it
    touches no scanner state and no architecture. ``--schedule`` stays deferred
    (it requires a stateful daemon, per the prior R26/R27/R28 assessments).

    SECURITY: every attacker-influenced value (prompts, response excerpts,
    evidence, transcripts) is HTML-escaped via :func:`_esc` before insertion, so
    a finding whose response contains live ``<script>``/HTML — precisely the
    active-content sink ouija reports — cannot execute when the report is
    opened.]
    """
    findings = sorted(
        result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)
    )

    style = (
        "body{font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;"
        "margin:0;background:#f4f5f7;color:#1a1d21}"
        ".wrap{max-width:920px;margin:0 auto;padding:2rem 1.25rem}"
        "h1{font-size:1.6rem;margin:0 0 .25rem}"
        ".meta{color:#5c6770;font-size:.9rem;margin-bottom:1.5rem}"
        ".card{background:#fff;border:1px solid #e3e6ea;border-radius:8px;"
        "padding:1.25rem 1.5rem;margin-bottom:1.25rem;"
        "box-shadow:0 1px 2px rgba(0,0,0,.04)}"
        ".card h2{font-size:1.15rem;margin:0 0 .75rem}"
        ".badge{display:inline-block;color:#fff;font-size:.72rem;font-weight:700;"
        "letter-spacing:.04em;padding:.15rem .5rem;border-radius:4px;"
        "text-transform:uppercase;vertical-align:middle;margin-right:.5rem}"
        ".kv{margin:.15rem 0;color:#3a3f45;font-size:.92rem}"
        ".kv b{color:#1a1d21}"
        "code{background:#f0f1f3;padding:.1rem .3rem;border-radius:3px;"
        "font-size:.85em}"
        "pre{background:#1e2126;color:#e6e6e6;padding:.9rem 1rem;border-radius:6px;"
        "overflow:auto;font-size:.85rem;white-space:pre-wrap;word-break:break-word}"
        ".section{font-size:.8rem;font-weight:700;text-transform:uppercase;"
        "letter-spacing:.05em;color:#5c6770;margin:1rem 0 .35rem}"
        ".impact{color:#3a3f45}"
        ".clean{background:#fff;border:1px solid #e3e6ea;border-radius:8px;"
        "padding:2rem;text-align:center;color:#2b8a3e;font-weight:600}"
    )

    out: list[str] = []
    out.append("<!doctype html>")
    out.append('<html lang="en">')
    out.append("<head>")
    out.append('<meta charset="utf-8">')
    out.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    out.append(f"<title>ouija findings — {_esc(result.target)}</title>")
    out.append(f"<style>{style}</style>")
    out.append("</head>")
    out.append("<body>")
    out.append('<div class="wrap">')
    out.append(f"<h1>ouija findings report</h1>")
    out.append(
        '<p class="meta">Target <code>{target}</code> &middot; '
        "generated by ouija v{version} &middot; attack set "
        "<code>{aset}</code> &middot; {sent} attack request(s) sent &middot; "
        "{n} finding(s)</p>".format(
            target=_esc(result.target),
            version=_esc(result.version),
            aset=_esc(result.attack_set),
            sent=result.patterns_sent,
            n=len(findings),
        )
    )

    if not findings:
        out.append(
            '<div class="clean">No findings. The target refused or sanitized '
            "all probes in this attack set.</div>"
        )
        out.append("</div></body></html>")
        return "\n".join(out)

    for idx, f in enumerate(findings, start=1):
        color = _SEVERITY_COLOR.get(f.severity, "#5c6770")
        out.append('<div class="card">')
        out.append(
            '<h2><span class="badge" style="background:{c}">{sev}</span>'
            "Finding {i}: {title}</h2>".format(
                c=color,
                sev=_esc(f.severity.value),
                i=idx,
                title=_esc(f.title),
            )
        )
        out.append(
            f'<p class="kv"><b>Category:</b> {_esc(f.category)} &middot; '
            f"<b>OWASP:</b> {_esc(f.owasp)} &middot; "
            f"<b>Confidence:</b> {f.confidence:.0%}</p>"
        )
        if f.attempts > 1:
            out.append(
                f'<p class="kv"><b>Reliability:</b> {f.successes}/{f.attempts} '
                f"attempts ({f.success_rate:.0%})</p>"
            )
        out.append(
            f'<p class="kv"><b>Finding ID:</b> <code>{_esc(f.id)}</code> '
            f"&middot; <b>Pattern:</b> <code>{_esc(f.pattern_id)}</code> "
            f"(technique: {_esc(f.technique)})</p>"
        )

        out.append('<div class="section">Summary</div>')
        out.append(f"<p>{_esc(f.evidence)}</p>")

        out.append('<div class="section">Steps to reproduce</div>')
        if f.transcript:
            out.append(
                "<p>Multi-turn (Crescendo) finding — the target complied on "
                f"turn {f.turn_succeeded} after conversational escalation. "
                "Replay each user turn in order, carrying the full history:</p>"
            )
            out.append(f"<pre>{_html_transcript(f)}</pre>")
        else:
            out.append(
                f"<p>1. Send this prompt to <code>{_esc(result.target)}</code>:</p>"
            )
            out.append(f"<pre>{_esc(f.request_prompt)}</pre>")
            out.append("<p>2. Observe the response, which contained:</p>")
            out.append(f"<pre>{_esc(f.response_excerpt)}</pre>")

        out.append('<div class="section">Business impact</div>')
        out.append(
            f'<p class="impact">'
            f'{_esc(_IMPACT.get(f.category, "See category description."))}</p>'
        )
        out.append("</div>")

    out.append("</div></body></html>")
    return "\n".join(out)


def render(result: ScanResult, fmt: str) -> str:
    if fmt == "json":
        return to_json(result)
    if fmt == "jsonl":
        return to_jsonl(result)
    if fmt == "csv":
        return to_csv(result)
    if fmt == "h1md":
        return to_h1md(result)
    if fmt == "html":
        return to_html(result)
    if fmt == "sarif":
        # Imported lazily so the SARIF code path is only loaded when requested.
        from ouija.sarif import to_sarif

        return to_sarif(result)
    raise ValueError(f"unknown format '{fmt}'")
