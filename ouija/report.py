"""Report rendering: JSON and HackerOne-style markdown (h1md)."""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any

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


# Stable, documented column order for the `--format markdown-table` triage view.
# One pipe-delimited GFM row per finding; the column set is the *compact* triage
# slice (severity / category / owasp / title / id / confidence / reliability) —
# deliberately NARROWER than the CSV export because a markdown table is read by
# humans in a GitHub issue / PR comment / ticket body, not pasted into a
# spreadsheet. The wide free-text fields (request_prompt, response_excerpt,
# evidence) are intentionally OMITTED — they contain multi-line attacker text
# that would explode row height and break GFM table rendering; read --format
# json or h1md for those. Multi-turn transcripts are likewise not flattened.
MD_TABLE_COLUMNS: tuple[str, ...] = (
    "severity",
    "category",
    "owasp",
    "title",
    "id",
    "confidence",
    "reliability",
)


def _md_escape_cell(text: str) -> str:
    """Escape a value for safe placement inside a GFM table cell.

    GFM splits table rows on the literal pipe (``|``) character, so any pipe in
    the value would otherwise break the row's column count. Newlines similarly
    terminate a row. We escape pipes (``\\|``) and replace any newline / carriage
    return with a single space so each cell stays on one logical line. The other
    markdown metacharacters (``*``, ``_``, ``` ` ```) are left as-is — they
    render as styling inside a cell, which is harmless for a triage table.
    """
    if not text:
        return ""
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r\n", " ")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def to_markdown_table(result: ScanResult) -> str:
    """Render the findings as a compact GitHub-flavoured-markdown table.

    Where ``--format h1md`` is a long-form HackerOne report (one ``## Finding``
    section per finding, complete with reproduction steps and business-impact
    prose), ``--format markdown-table`` is the *one-screen triage view*: a
    single GFM table — one header row plus one data row per finding,
    severity-sorted — that renders cleanly inline in a GitHub issue, PR
    comment, project README, Slack/Discord message, or any markdown-rendered
    surface. Use it when a stakeholder asks "what did the scan find?" and
    wants the answer at a glance.

    [Worker decision (Phase 2 / R30): chose ``--format markdown-table`` over
    ``--format pdf``. Both were unshipped post-v0.1 directions; markdown-table
    is the more defensible single improvement because (a) it is a pure
    standard-library function over the final
    :class:`~ouija.models.ScanResult`, matching every prior format
    (json/jsonl/csv/sarif/h1md/html), so it touches no scanner state and no
    architecture, and (b) PDF generation requires a heavy third-party
    dependency (weasyprint / reportlab) which would fight ouija's
    deliberately-minimal dependency surface (httpx + pydantic only). A
    stakeholder who wants a PDF can already render ``--format html`` to PDF
    via the browser or ``wkhtmltopdf`` without ouija owning the
    rendering toolchain.]

    Output shape (severity-sorted, critical first):

    * a header row of column names;
    * the GFM separator row (``|---|---|...``);
    * one data row per finding, with reliability emitted as
      ``successes/attempts (rate%)`` when ``--repeats`` > 1, or ``-`` for the
      single-shot default.

    Wide free-text fields (request_prompt, response_excerpt, evidence) are
    deliberately omitted — they contain multi-line attacker-controlled text
    that would break GFM table rendering. Read ``--format json``/``h1md`` for
    full evidence. A zero-finding run still emits the header so a downstream
    template (e.g. a PR-comment macro) always sees the table shape.
    """
    findings = sorted(
        result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)
    )

    header = "| " + " | ".join(MD_TABLE_COLUMNS) + " |"
    separator = "|" + "|".join("---" for _ in MD_TABLE_COLUMNS) + "|"

    title_line = (
        f"# ouija findings — {_md_escape_cell(result.target)} "
        f"({len(findings)} finding(s), {result.patterns_sent} request(s))"
    )

    if not findings:
        return "\n".join(
            [
                title_line,
                "",
                "_No findings. The target refused or sanitized all probes "
                "in this attack set._",
                "",
                header,
                separator,
            ]
        )

    rows: list[str] = [title_line, "", header, separator]
    for f in findings:
        if f.attempts > 1:
            reliability = f"{f.successes}/{f.attempts} ({f.success_rate:.0%})"
        else:
            reliability = "-"
        cells = {
            "severity": f.severity.value,
            "category": f.category,
            "owasp": f.owasp,
            "title": f.title,
            "id": f"`{f.id}`",
            "confidence": f"{f.confidence:.0%}",
            "reliability": reliability,
        }
        row = (
            "| "
            + " | ".join(_md_escape_cell(cells[col]) for col in MD_TABLE_COLUMNS)
            + " |"
        )
        rows.append(row)
    return "\n".join(rows)


# Per-severity "attachment color" bar accents for the Slack Block Kit payload.
# Slack renders ``attachments[].color`` as a coloured left border on the message
# card, which is the standard severity-at-a-glance visual signal in
# security-tool Slack integrations (matches how PagerDuty, Snyk, gitleaks and
# similar tools highlight critical/high findings). Values are the documented
# Slack-good/warning/danger aliases for medium/low/info-equivalents and explicit
# hex for the elevated severities to differentiate critical from high.
_SLACK_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#b30000",
    Severity.HIGH: "#d9480f",
    Severity.MEDIUM: "warning",
    Severity.LOW: "#1c7ed6",
    Severity.INFO: "#5c6770",
}

# Slack message-text rendering uses "mrkdwn" — Slack's markdown DIALECT — which
# is NOT GitHub-flavoured-markdown. The two important divergences for our
# payload: (a) bold is ``*bold*`` (single asterisks), not ``**bold**``; (b)
# Slack does NOT render GFM pipe-tables, which is why ``--format markdown-table``
# is unreadable when posted to a Slack channel and this format exists. See
# https://api.slack.com/reference/surfaces/formatting for the dialect.

# Maximum number of full per-finding "section" blocks we render. Slack imposes a
# hard 50-block limit per message and truncates beyond that; cap conservatively
# so the run summary + per-finding sections + footer stay well under the limit
# even on a heavy scan, and surface the overflow count in the footer.
_SLACK_MAX_FINDING_BLOCKS = 20

# Per-finding excerpt cap so a single noisy finding cannot blow past Slack's
# 3000-character per-section-text limit (we render summary + impact in one
# section block; keep each piece comfortably under the cap).
_SLACK_TEXT_CAP = 600


def _slack_escape(text: str) -> str:
    """Escape *text* for safe inclusion in a Slack ``mrkdwn`` text field.

    Slack treats ``&``, ``<`` and ``>`` as control characters used to delimit
    its own link / user-mention / channel-reference syntax (e.g.
    ``<http://example.com|click>``, ``<@U123>``, ``<!channel>``). An
    unescaped ``<`` or ``>`` in attacker-influenced content (a response excerpt
    that happens to contain ``<script>``, exactly the active-content sink ouija
    reports) would otherwise be parsed by Slack as the start of one of those
    constructs and corrupt the surrounding message. The Slack-documented
    escapes are ``&amp;`` / ``&lt;`` / ``&gt;``. We do these in
    ``&``-first order so we don't double-escape an already-escaped sequence.
    """
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _slack_truncate(text: str, cap: int = _SLACK_TEXT_CAP) -> str:
    """Truncate *text* to *cap* characters with a trailing ellipsis marker.

    A single multi-line attacker-shaped excerpt could otherwise push a section
    block past Slack's 3000-char per-text limit and the message would be
    rejected. Truncation here is purely a Slack-surface constraint — the full
    evidence is always available in the ``--format json`` report; this payload
    is the *alert*, the JSON report is the *evidence* (same rule as ``notify``).
    """
    if not text:
        return ""
    s = str(text)
    if len(s) <= cap:
        return s
    return s[: cap - 1].rstrip() + "…"


def to_slack(result: ScanResult) -> str:
    """Render the scan as a Slack Block Kit JSON payload (``--format slack``).

    Where ``--format markdown-table`` renders inline in GitHub markdown but
    appears as raw, unrendered pipe-text in Slack (Slack's ``mrkdwn`` dialect
    does NOT support GFM tables), ``--format slack`` is the Slack-native
    rendering: a Block Kit ``blocks`` array wrapped in an ``attachments[0]``
    coloured by the top finding's severity, so the message lands with a
    severity-accented sidebar, a header, a run-summary section, and one
    section block per finding (capped, with an overflow line). Redirect the
    payload to a file or pipe it directly into a Slack incoming webhook:

    .. code-block:: bash

        ouija --target … --scope-file scope.txt --format slack > slack.json
        curl -X POST -H 'Content-Type: application/json' \\
             --data @slack.json "$SLACK_WEBHOOK_URL"

    [Worker decision (Phase 2 / R32): chose ``--format slack`` (Slack Block Kit
    JSON) over ``--format pdf``. Both were unshipped post-v0.1 directions.
    R30 already assessed and rejected ``--format pdf`` because PDF rendering
    requires a heavy third-party dependency (weasyprint / reportlab) that
    fights ouija's deliberately-minimal dependency surface (httpx + pydantic
    only), and a stakeholder who wants a PDF can already render
    ``--format html`` to PDF via the browser or ``wkhtmltopdf`` without ouija
    owning the rendering toolchain. That assessment still holds at R32. Slack,
    by contrast, is a pure-stdlib JSON shaping function over the final
    :class:`~ouija.models.ScanResult` — identical in shape to
    ``to_json``/``to_jsonl``/``to_sarif`` — so it touches no scanner state and
    no architecture, matching how every prior format was added. It also
    closes a real, observed gap: ``--format markdown-table`` is advertised as
    "renders inline in Slack" but Slack's ``mrkdwn`` does not support GFM
    pipe-tables, so that format actually appears as raw text in a Slack
    channel; ``--format slack`` is the correct native rendering. Composes
    naturally with ``--notify`` (which sends a compact webhook digest):
    ``--format slack`` is for when the operator wants the full rendered Block
    Kit payload, ``--notify`` is the lightweight side-channel alert.

    SECURITY: every attacker-influenced value (titles, prompts, response
    excerpts, evidence) is Slack-escaped via :func:`_slack_escape` before
    insertion, so a finding whose response contains ``<script>`` /
    ``<@user>`` / ``<!channel>`` — exactly the active-content / mention
    injection class — cannot smuggle Slack syntax into the rendered message.
    Per-section text is also length-capped (the full evidence stays in the
    ``--format json`` report) so no single noisy finding can exceed Slack's
    3000-char per-section limit.]
    """
    findings = sorted(
        result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)
    )

    # Top severity drives the attachment color — same rule as the notify
    # payload's ``top_severity``: highest of the run, or None for a clean run.
    top_color: str | None = None
    if findings:
        top_color = _SLACK_SEVERITY_COLOR.get(findings[0].severity)

    blocks: list[dict[str, Any]] = []

    # Header — the message title that lands in the channel notification list.
    # ``header`` blocks accept plain_text only (no mrkdwn), max 150 chars.
    header_text = f"ouija findings: {result.target}"
    if len(header_text) > 150:
        header_text = header_text[:149] + "…"
    blocks.append(
        {
            "type": "header",
            "text": {"type": "plain_text", "text": header_text, "emoji": True},
        }
    )

    # Summary — the run identity / counts the triager wants at a glance.
    summary_lines = [
        f"*Target:* `{_slack_escape(result.target)}`",
        f"*Attack set:* `{_slack_escape(result.attack_set)}`",
        f"*Requests sent:* {result.patterns_sent}",
        f"*Findings:* {len(findings)}",
        f"*ouija version:* {_slack_escape(result.version)}",
    ]
    blocks.append(
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(summary_lines)},
        }
    )

    if not findings:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        ":white_check_mark: *No findings.* The target refused "
                        "or sanitized all probes in this attack set."
                    ),
                },
            }
        )
    else:
        blocks.append({"type": "divider"})

        shown = findings[:_SLACK_MAX_FINDING_BLOCKS]
        overflow = len(findings) - len(shown)

        for idx, f in enumerate(shown, start=1):
            sev = f.severity.value.upper()
            reliability = ""
            if f.attempts > 1:
                reliability = (
                    f" · *Reliability:* {f.successes}/{f.attempts} "
                    f"({f.success_rate:.0%})"
                )
            title_line = (
                f"*{idx}. [{sev}] {_slack_escape(f.title)}*"
            )
            meta_line = (
                f"*Category:* `{_slack_escape(f.category)}` · "
                f"*OWASP:* `{_slack_escape(f.owasp)}` · "
                f"*Confidence:* {f.confidence:.0%}{reliability}"
            )
            id_line = (
                f"*Finding ID:* `{_slack_escape(f.id)}` · "
                f"*Pattern:* `{_slack_escape(f.pattern_id)}` "
                f"(technique: {_slack_escape(f.technique)})"
            )
            evidence_line = (
                "*Evidence:* "
                + _slack_escape(_slack_truncate(f.evidence))
            )
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "\n".join(
                            [title_line, meta_line, id_line, evidence_line]
                        ),
                    },
                }
            )

        if overflow > 0:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"_… {overflow} additional finding(s) not "
                            f"shown (Slack block-limit). Read the full "
                            f"`--format json` report for the rest._"
                        ),
                    },
                }
            )

    # Footer — context block holds small grey caption text at the bottom.
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"Generated by ouija v{_slack_escape(result.version)} "
                        f"· scan `{_slack_escape(result.scan_id)}` "
                        f"· {_slack_escape(result.timestamp)}"
                    ),
                }
            ],
        }
    )

    # Plain-text fallback for notification previews / accessibility / clients
    # that cannot render Block Kit. Slack uses ``text`` as the notification
    # preview and the screen-reader label.
    fallback_text = (
        f"ouija scan of {result.target}: "
        f"{len(findings)} finding(s) across {result.patterns_sent} request(s)."
    )

    payload: dict[str, Any] = {
        "text": fallback_text,
        "attachments": [
            {
                # ``color`` is the coloured left border on the message card.
                # ``blocks`` inside the attachment is the modern Block Kit
                # rendering — the attachment wrapper exists purely to carry
                # the color accent; the content is Block Kit, not the legacy
                # attachment fields. Omit ``color`` entirely on a clean run.
                **({"color": top_color} if top_color else {}),
                "blocks": blocks,
                "fallback": fallback_text,
            }
        ],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# PagerDuty Events API v2 payload (`--format pagerduty`)
# ---------------------------------------------------------------------------
# Reference: https://developer.pagerduty.com/docs/3d063fd4814a6-events-api-v2-overview
# Reference: https://developer.pagerduty.com/api-reference/368ae3d938c9e-send-an-event
#
# The Events API v2 endpoint (https://events.pagerduty.com/v2/enqueue) accepts
# a single JSON document with a fixed shape:
#
#   {
#     "routing_key": "<32-char Events-API-v2 integration key>",
#     "event_action": "trigger" | "acknowledge" | "resolve",
#     "dedup_key":   "<stable key — events sharing this key collapse into
#                     a single incident; an `event_action: resolve` against
#                     the same dedup_key closes the incident>",
#     "payload": {
#       "summary":   "<<= 1024-char one-line description>",
#       "severity":  "critical" | "error" | "warning" | "info",
#       "source":    "<the affected component / hostname / URL>",
#       "component": "<optional>",
#       "group":     "<optional>",
#       "class":     "<optional>",
#       "timestamp": "<ISO-8601>",
#       "custom_details": { ... arbitrary JSON-serialisable object ... }
#     }
#   }
#
# Severity must be one of the four PagerDuty-defined strings — there is no
# "high" / "medium" / "low" / "info" set; ouija's five-bucket scale maps as:
#
#   ouija       → PagerDuty
#   critical    → critical
#   high        → error
#   medium      → warning
#   low         → info
#   info        → info
#
# A clean run (zero findings) emits `event_action: resolve` against the same
# dedup_key the prior trigger would have used, so a rerun that finds nothing
# automatically closes the previous PagerDuty incident — the same "alert" /
# "no longer alert" pairing PagerDuty's own integrations (Datadog, Nagios,
# Prometheus Alertmanager) follow.

# Ouija severity -> PagerDuty Events-API-v2 severity. PagerDuty only accepts
# the four strings below; anything else is rejected at enqueue time with HTTP
# 400. Map ouija's five-bucket scale into the four PagerDuty buckets.
_PAGERDUTY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "info",
    Severity.INFO: "info",
}

# Literal placeholder the operator MUST substitute before POSTing. Emitting a
# placeholder (rather than reading the key from an env var inside ouija) keeps
# the same "ouija renders, you pipe" boundary every other format honours:
# `--format slack` does not POST to Slack, `--format sarif` does not upload to
# code-scanning, and `--format pagerduty` does not enqueue to PagerDuty. The
# operator substitutes once (`sed`, `jq --arg`, env-templating, etc.) and pipes
# the result into `curl`. This also keeps the routing key off the ouija
# command line and out of the scan artifact / log stream.
_PAGERDUTY_ROUTING_KEY_PLACEHOLDER = "YOUR_PAGERDUTY_ROUTING_KEY"

# PagerDuty's `payload.summary` field is hard-capped at 1024 characters; events
# whose summary exceeds the cap are rejected. We render an at-a-glance
# one-line summary so the cap is comfortable on real scans, but truncate
# defensively against very long target URLs or very large finding counts.
_PAGERDUTY_SUMMARY_CAP = 1024


def _pagerduty_dedup_key(result: ScanResult) -> str:
    """Stable dedup_key derived from target + attack-set.

    PagerDuty collapses events sharing a ``dedup_key`` into a single incident
    and pairs ``event_action: resolve`` against the same key to close it. We
    want re-scanning the SAME target with the SAME attack set to update the
    SAME incident (so a triager isn't deluged with one new incident per
    rescan), and a later clean run to resolve it. Using ``scan_id`` would
    defeat that — every scan has a fresh random ``scan_id`` — so we key on
    the stable scan inputs instead: target URL + attack set.
    """
    return f"ouija::{result.target}::{result.attack_set}"


def to_pagerduty(result: ScanResult) -> str:
    """Render the scan as a PagerDuty Events API v2 enqueue payload.

    Where ``--format slack`` is the chat-channel alert and ``--format sarif``
    is the CI / code-scanning artifact, ``--format pagerduty`` is the
    on-call / incident-response surface: an Events-API-v2-shaped JSON
    document the operator pipes straight into
    ``https://events.pagerduty.com/v2/enqueue`` to page whoever owns the LLM
    endpoint. The payload is one *aggregated* event per scan (not one event
    per finding) — PagerDuty's incident model is alert-per-symptom, not
    alert-per-detail, and a single ouija scan that turns up 12 prompt-
    injection findings should page the on-call as ONE incident ("ouija found
    12 LLM-security issues on https://api.example.com/v1/chat"), with the
    per-finding breakdown carried under ``payload.custom_details`` where the
    incident-detail UI renders it as structured JSON.

    Usage:

    .. code-block:: bash

        ouija --target https://api.example.com/v1/chat --scope-file scope.txt \\
              --format pagerduty > pd.json
        # substitute your Events-API-v2 integration key:
        sed -i 's/YOUR_PAGERDUTY_ROUTING_KEY/'"$PD_ROUTING_KEY"'/' pd.json
        curl -X POST -H 'Content-Type: application/json' \\
             --data @pd.json https://events.pagerduty.com/v2/enqueue

    Behaviour:

    * A run with one or more findings emits ``event_action: trigger`` and a
      ``payload.severity`` mapped from the *highest* finding severity in the
      run (ouija ``critical`` → PD ``critical``, ``high`` → ``error``,
      ``medium`` → ``warning``, ``low`` / ``info`` → ``info``).
    * A *clean* run (zero findings) emits ``event_action: resolve`` against
      the same stable ``dedup_key`` a prior trigger would have used, so a
      rerun that finds nothing automatically closes the previous PagerDuty
      incident — the same "alert" / "no longer alert" pairing PagerDuty's
      own integrations (Datadog, Prometheus Alertmanager, Nagios) follow.
    * ``dedup_key`` is derived from target + attack-set (not the per-run
      random ``scan_id``) so re-scanning the SAME target with the SAME
      attack set updates the SAME incident instead of flooding the on-call
      with a new incident per rescan.
    * ``routing_key`` is emitted as the literal placeholder string
      ``YOUR_PAGERDUTY_ROUTING_KEY``; the operator substitutes it once
      before piping into ``curl``. This keeps the integration key off the
      ouija command line and out of the scan artifact / log stream, and
      preserves the same "ouija renders, you pipe" boundary every other
      format honours (``--format slack`` does not POST to Slack,
      ``--format sarif`` does not upload to code-scanning).

    [Worker decision (Phase 2 / R33): chose ``--format pagerduty``
    (PagerDuty Events API v2 payload) over ``--format jira`` (Jira REST
    issue-create payload). Both were unshipped post-v0.1 directions and both
    extend the same "render-only, you pipe" pattern every prior format
    follows. PagerDuty Events API v2 has a single fixed payload schema
    (``routing_key``, ``event_action``, ``dedup_key``, ``payload.{summary,
    severity, source, custom_details, ...}``) accepted by every PagerDuty
    account with no per-tenant variation, so the payload ouija emits works
    against any account by substituting the integration key. Jira's
    issue-create payload, by contrast, requires the caller to know the
    target tenant's project key, issue type, and any required custom fields
    — values ouija cannot know at scan time — so a Jira format would
    either need an additional ``--jira-project-key`` / ``--jira-issue-type``
    flag surface OR emit a placeholder that fails against most real Jira
    instances. PagerDuty's single-payload-fits-all-tenants shape is the
    more tractable, more deterministic deliverable. It also closes a real
    operational gap: ouija already covers chat alerts (``--format slack``,
    ``--notify``), CI / code-scanning (``--format sarif``), and triager
    hand-off (``--format csv``, ``--format html``), but had no surface for
    paging the on-call when a scheduled scan against production turns up a
    high/critical finding. Same shape as ``to_slack`` (pure stdlib JSON
    shaping over the final :class:`~ouija.models.ScanResult` — touches no
    scanner state, no architecture).]
    """
    findings = sorted(
        result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)
    )
    dedup_key = _pagerduty_dedup_key(result)

    # Clean run — emit a `resolve` against the stable dedup_key so a prior
    # `trigger` against the same target+attack-set is auto-closed. Per the
    # Events API v2 spec a `resolve` event is the minimal shape: routing_key
    # + event_action + dedup_key only; `payload` is NOT required (and is
    # ignored if present) for non-trigger actions.
    if not findings:
        resolve_payload: dict[str, Any] = {
            "routing_key": _PAGERDUTY_ROUTING_KEY_PLACEHOLDER,
            "event_action": "resolve",
            "dedup_key": dedup_key,
        }
        return json.dumps(resolve_payload, indent=2)

    top = findings[0]
    pd_severity = _PAGERDUTY_SEVERITY.get(top.severity, "info")

    # One-line summary — what lands in the on-call's phone notification.
    # Cap defensively against the 1024-char Events-API limit.
    summary = (
        f"ouija: {len(findings)} finding(s) on {result.target} "
        f"[top severity: {top.severity.value}]"
    )
    if len(summary) > _PAGERDUTY_SUMMARY_CAP:
        summary = summary[: _PAGERDUTY_SUMMARY_CAP - 1] + "…"

    # Per-finding compact records under custom_details. Keep each record
    # small enough that a heavy scan (dozens of findings) still produces a
    # payload PagerDuty will accept. Full prompts / response excerpts /
    # multi-turn transcripts stay in `--format json` — this payload is the
    # *alert*, the JSON report is the *evidence* (same rule as `--notify` /
    # `--format slack`).
    finding_records = [
        {
            "id": f.id,
            "severity": f.severity.value,
            "title": f.title,
            "category": f.category,
            "owasp": f.owasp,
            "pattern_id": f.pattern_id,
            "technique": f.technique,
            "confidence": round(f.confidence, 3),
        }
        for f in findings
    ]

    # Severity-bucket counts so the incident detail surfaces the breakdown
    # without the on-call having to count rows.
    severity_counts: dict[str, int] = {}
    for f in findings:
        key = f.severity.value
        severity_counts[key] = severity_counts.get(key, 0) + 1

    custom_details: dict[str, Any] = {
        "tool": result.tool,
        "ouija_version": result.version,
        "scan_id": result.scan_id,
        "attack_set": result.attack_set,
        "patterns_sent": result.patterns_sent,
        "findings_total": len(findings),
        "severity_counts": severity_counts,
        "top_finding": {
            "id": top.id,
            "severity": top.severity.value,
            "title": top.title,
            "owasp": top.owasp,
        },
        "findings": finding_records,
    }

    payload: dict[str, Any] = {
        "routing_key": _PAGERDUTY_ROUTING_KEY_PLACEHOLDER,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": summary,
            "severity": pd_severity,
            "source": result.target,
            "component": "llm-endpoint",
            "group": result.attack_set,
            "class": "llm-security-finding",
            "timestamp": result.timestamp,
            "custom_details": custom_details,
        },
        # Optional `client` / `client_url` fields surface in the PagerDuty
        # incident header as "Reported by". Identifying the tool makes the
        # incident self-describing without a triager having to read
        # custom_details first.
        "client": f"ouija v{result.version}",
    }
    return json.dumps(payload, indent=2)


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
    if fmt == "markdown-table":
        return to_markdown_table(result)
    if fmt == "slack":
        return to_slack(result)
    if fmt == "pagerduty":
        return to_pagerduty(result)
    if fmt == "sarif":
        # Imported lazily so the SARIF code path is only loaded when requested.
        from ouija.sarif import to_sarif

        return to_sarif(result)
    raise ValueError(f"unknown format '{fmt}'")
