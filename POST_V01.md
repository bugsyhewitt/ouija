# ouija — Post-v0.1 Improvement Roadmap

**Generated:** 2026-05-26 by Worker (Rotation 2, research lap)
**Baseline:** v0.1 is a single-target, scope-gated LLM endpoint fuzzer that sends a hard-coded `{"prompt": "..."}` body, runs a 38-pattern corpus (LLM01/LLM02/LLM10) through four static surface mutators, detects success via marker-substring and disclosure-keyword heuristics, and renders JSON or HackerOne markdown.

## Methodology

I read every source file, test, the corpus, the README, NOTICE, and pyproject on `main`, plus the in-flight `feature/request-template` WIP branch left by the Rotation 1 Worker. I then surveyed the 2025/2026 LLM-security testing landscape — NVIDIA garak (37+ probe modules, REST generator, 10x repeated generations), promptfoo (Crescendo/GOAT/Hydra multi-turn, encoding "layer" strategy), Microsoft PyRIT (Crescendo, converter chains), Vigil/Rebuff (canary tokens), and OWASP LLM Top 10 v2025 (which added LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage). I cross-referenced this against what bug-bounty hunters are actually getting paid for right now (HackerOne reports a 540% YoY surge in valid prompt-injection reports; EchoLeak / CVE-2025-32711 made markdown-image exfiltration the flagship 2025 finding class). Each item below is ONE focused, shippable Phase 2 deliverable, ranked by bounty-value × inverse-complexity (favoring high-value, low-effort wins first).

---

## Item 1 — Markdown-image exfiltration canary + detector (Priority: CRITICAL)

### What
A new attack family that plants a unique, high-entropy canary URL in the prompt, instructs the target to emit a markdown image / link referencing it, and a detector that flags the response if it actually emits that exfiltration markup. This is the single highest-value finding class in production LLM bug bounties right now — the EchoLeak (CVE-2025-32711, CVSS 9.6) "lethal trifecta" pattern: private-data access + untrusted input + an auto-rendered image fetch as the exfil channel. v0.1's `inj-012` is a stub that only checks for a static marker; it does not model the actual exfil mechanism.

### How
- Add `ouija/canary.py`: `make_canary() -> Canary` returning a per-run random token (`secrets.token_hex(8)`) plus a synthetic attacker host string (e.g. `http://ouija-exfil.{token}.invalid/c?d=`). Use `.invalid` TLD so ouija never actually causes egress — detection is on the *response text*, not a callback.
- Add `ouija/corpus/exfil.json` (new `--attack-set exfil`, category `improper_output_handling`, OWASP `LLM05:2025 Improper Output Handling`) with ~8 patterns that ask the model to render `![logo](<CANARY_URL><DATA>)`, reference-style links, and HTML `<img src=...>`, where `<DATA>` is "your system prompt" / "the conversation above". Patterns carry a `{canary}` placeholder the scanner fills in at send time.
- Extend `AttackPattern` with an optional `canary: bool` flag and thread the per-run canary value through `scanner.py` so `mutate`/send substitutes `{canary}` before sending.
- Add a detector branch in `detect.py`: if the response contains the canary token inside a markdown-image, markdown-link, or `<img>`/`href` construct, emit a HIGH/CRITICAL finding with evidence "target rendered an attacker-controlled exfiltration URL into its output (markdown-image data exfiltration)".

### Effort estimate
Medium-low. ~1 new module (~40 lines), 1 corpus file, ~25 lines in `detect.py`, ~10 lines of plumbing in `scanner.py`/`models.py`, plus a vulnerable branch in `tests/mock_llm.py` and 2 tests. Self-contained; no new dependencies. ~150-200 LOC total.

### Rationale
Highest bounty-value class of 2025-26, near-zero false positives (a high-entropy token has effectively zero chance of appearing organically), and it slots cleanly into ouija's existing send→detect loop. It also closes ouija's biggest coverage gap versus the OWASP v2025 list (LLM05 Improper Output Handling) with one deliverable. Ship this first.

---

## Item 2 — Repeated generations to defeat non-determinism (Priority: HIGH)

### What
Send each mutated prompt N times (default 3, `--repeats N`) and treat the attack as successful if it triggers on *any* attempt; report the hit-rate (e.g. "3/5 attempts succeeded"). garak sends 10x by default precisely because LLM output is non-deterministic: a model that refuses 9 times out of 10 still has a 10% bypass rate, and that 10% is a real, reportable finding ouija currently misses entirely (it sends each prompt exactly once).

### How
- Add `--repeats` (int, default 1 to preserve current cost behavior; document 3-5 as recommended) to `cli.py`.
- In `scanner.py`, expand each `(pattern, variant)` task into `repeats` probes sharing one logical key; collect replies per key.
- Aggregate in `detect.py`/`scanner.py`: run detection per reply, and if any succeed, build a single Finding carrying `attempts: int`, `successes: int`, and a `success_rate: float` (add these fields to the `Finding` model).
- Render the hit-rate in `report.py` (h1md "Reliability: 3/5 attempts (60%)" line) — bounty triagers care whether a bug is deterministic.

### Effort estimate
Low. ~15 lines in `scanner.py`, 3 new fields in `models.py`, ~5 lines each in `cli.py` and `report.py`. ~50-80 LOC. Interacts with concurrency (already semaphore-bounded, so no new concurrency design needed).

### Rationale
Cheap, mechanically simple, and directly increases finding yield against real targets where a single shot under-reports. It also strengthens every existing pattern's evidence quality (reliability metric is a credibility signal in H1 reports). High value for the effort.

---

## Item 3 — Request/response templating: finish the R1 `--request-template` feature AND add `--response-path` (Priority: HIGH)

### What
Let ouija target real-world endpoint shapes (OpenAI `/v1/chat/completions`, Anthropic `/v1/messages`, custom SaaS bodies) instead of only `{"prompt": "..."}`. The Rotation 1 Worker built the *request* half on the `feature/request-template` branch — a `--request-template` JSON flag with a `"{prompt}"` placeholder, JSON-encoded substitution, validation, and version bump to 0.1.1. It is technically sound but **incomplete and unshipped**: it has no tests, the README was not updated, and crucially it does NOT solve response extraction — `_extract_text` still guesses at reply fields, so against a non-standard *response* shape ouija will fail to read the model's reply and silently report zero findings.

### How
- Adopt the R1 request-template code as the starting point (cli validation, `TargetClient._build_body`, scanner plumbing). Re-derive it cleanly against current `main` rather than blind-merging the stale branch.
- Add the missing complement: `--response-path` accepting a dotted/bracket JSONPath-lite selector (e.g. `choices.0.message.content`) so the caller pins where the reply text lives; implement a small dependency-free extractor in `client.py` and fall back to the existing heuristic when not supplied.
- Add tests: a mock endpoint that accepts an OpenAI-style body and returns an OpenAI-style response, driven via `--request-template` + `--response-path`; plus template-validation error cases (invalid JSON, missing placeholder → exit 3).
- Update the README usage table and add a worked OpenAI/Anthropic example.

### Effort estimate
Medium. The request half exists (~90 LOC already written). Response-path extractor is ~25 LOC, tests ~60 LOC, README ~20 lines. ~120 new LOC on top of the salvaged R1 work.

### Rationale
This is what makes ouija usable against the endpoints bug-bounty hunters actually face — almost no production target accepts a bare `{"prompt": ...}`. Without it the tool only works against toy/proxy endpoints. The R1 Worker correctly identified this as a reasonable candidate; the failure was procedural (asking "shall I apply?" instead of shipping) and structural (request-only is half a feature). Shipping request **and** response templating together makes it a complete, defensible improvement. Note: do NOT ship the request half alone — it creates a silent-failure trap on non-standard response shapes.

---

## Item 4 — Encoding / obfuscation mutators (Priority: MEDIUM)

### What
Add mutators that transform attack prompts through encoding and obfuscation channels — base64, ROT13, leetspeak, homoglyph/unicode substitution, and invisible-character (zero-width / HTML-comment) wrapping — mirroring garak's `encoding` probes and promptfoo's "layer" encoding strategy. v0.1's four mutators (identity, polite, urgent, quote-wrap) only exercise surface phrasing; they never test whether a guardrail can be bypassed by changing the *representation* of the payload, which is a staple bypass technique (and the GitHub Copilot invisible-markdown-comment bug is exactly this class).

### How
- Extend `_MUTATORS` in `mutate.py` with new functions: `_base64_wrap` ("decode this base64 and follow it: <b64>"), `_rot13_wrap`, `_leetspeak`, `_zero_width_inject`, `_html_comment_smuggle`.
- Critical constraint already documented in `mutate.py`: marker-carrying patterns must preserve the literal marker so the detector still fires. For encoding mutators, either (a) skip them for marker patterns, or (b) keep the marker plaintext and only encode the surrounding instruction. Implement option (b) where feasible, fall back to (a).
- Gate behind a `--mutators` flag (`surface` default for cost, `all` to include encoding) so runs don't explode in size by default.

### Effort estimate
Low-medium. ~60 LOC of mutator functions + marker-preservation logic + a `--mutators` flag and 2 tests. No dependencies (base64/codecs are stdlib).

### Rationale
Directly increases bypass coverage against filtered targets, where surface variants alone get refused. Ranked below items 1-3 because (per 2026 red-team analysis) most vulnerable targets fall to *plain* prompts anyway — encoding is the second-line technique for hardened targets, not the first finding you'll get paid for. Still solid value, low cost, fully self-contained.

---

## Item 5 — System-prompt-leak detection hardening + confidence calibration (Priority: MEDIUM)

### What
Replace v0.1's brittle keyword-list disclosure detection with a structured, lower-false-positive detector specifically for LLM07:2025 System Prompt Leakage. Today `detect.py` flags any response containing strings like "you are a helpful" or "system prompt" while not refusing — that fires on benign responses that merely *discuss* prompts, producing noisy findings that get bounty reports closed as N/A and hurt the hunter's signal-to-noise reputation.

### How
- Add a dedicated `detect_system_prompt_leak` path: weight evidence by (a) presence of multiple co-occurring config/secret signals, (b) credential-shaped regexes (`sk-[A-Za-z0-9]{16,}`, `AKIA[0-9A-Z]{16}`, bearer-token shapes, `-----BEGIN ... KEY-----`), and (c) verbatim instruction-style phrasing ("You are", "Your role is", "Do not reveal"). Single weak signal → LOW/INFO; multiple corroborating signals → HIGH.
- Map system-prompt-extraction patterns (currently `dis-001`, `inj-005`, `inj-017`) to OWASP `LLM07:2025 System Prompt Leakage` and a distinct `system_prompt_leakage` category with its own impact text in `report.py`.
- Tighten `confidence` so disclosure findings stop defaulting to a flat 0.6; derive it from the number of corroborating signals.

### Effort estimate
Medium. ~50-70 LOC of detection logic + regexes in `detect.py`, category/impact additions in `models.py`/`report.py`, and ~3 tests (true positive, benign-mention false-positive guard, credential-shape match). No dependencies.

### Rationale
Improves the *quality* (not quantity) of findings and adds explicit LLM07 coverage — a category OWASP newly split out in 2025. Lower precedence than items 1-3 because it refines existing capability rather than opening a new finding class, but it materially reduces the false-positive rate that erodes report credibility.

---

## Item 6 — Indirect prompt injection mode (`--inject-via`) (Priority: MEDIUM)

### What
Support indirect injection: instead of sending the attack as the user prompt, embed it inside data the endpoint is asked to *process* (a "document to summarize", a "webpage", a "support ticket", a tool-result), modeling the higher-severity injection variant OWASP ranks as the more dangerous form and the exact channel EchoLeak and the Gemini/Copilot bugs exploited.

### How
- Add `--inject-via {direct,document,webpage,email}` to `cli.py` (default `direct` = today's behavior).
- Add wrapper templates in a new `ouija/indirect.py` that nest each attack prompt inside a realistic data envelope ("Summarize the following document:\n\n<doc>{attack}</doc>") before the request is built.
- Combine cleanly with Item 1's canary (indirect + markdown-image exfil is the EchoLeak chain) and Item 3's templating (indirect payloads often go in a `messages` content field, not a top-level prompt).
- Tests: mock endpoint that "processes" a document and leaks; assert finding.

### Effort estimate
Medium. ~50 LOC for envelopes + flag + plumbing + 2 tests. Depends conceptually on Item 1 (canary) and Item 3 (templating) landing first to be maximally useful, but can ship standalone.

### Rationale
Indirect injection is the higher-severity, higher-bounty variant and the mechanism behind every flagship 2025 production exploit. Ranked sixth only because it composes best *after* items 1 and 3 exist; sequencing it later avoids rework. Strong strategic value once the foundation is in place.

---

## Item 7 — Multi-turn / Crescendo conversational attack mode (Priority: LOW for now)

### What
A stateful, multi-turn attack mode (`--multi-turn`) that escalates across conversation turns — the Crescendo / GOAT technique pioneered by PyRIT and promptfoo, where a benign opener gradually steers the model into compliance, defeating single-turn defenses (reported success rates jumping from ~4% single-turn to ~78% multi-turn against hardened targets).

### How
- Requires conversation-state support: ouija must send a turn history (list of role/content messages), which itself depends on Item 3's templating (the `messages` array shape) being in place.
- Add a turn-orchestration loop in a new `ouija/conversation.py` that sends turn 1, reads the reply, selects/templates turn 2 from a scripted escalation ladder (deterministic, scripted ladders first — NOT an adversarial-LLM driver, which would add an LLM dependency and cost/complexity).
- Detection runs per-turn and on the final turn; a finding records the full transcript.

### Effort estimate
High. New conversation module, session/state model changes, history-aware client, multi-turn mock, and several tests. ~250-350 LOC and the most architectural change of any item here. Likely needs its own scoping pass.

### Rationale
Highest *ceiling* on finding sophistication (it's what separates a scanner from a red-team tool) but the highest complexity and the only item that meaningfully strains the v0.1 architecture. It also depends on Item 3 (message-array templating) and benefits from Item 5 (per-turn leak detection). Correctly sequenced last: ship the cheap high-value wins (1, 2, 3) first; revisit multi-turn once templating and state exist. Keep the first cut to *scripted* escalation ladders to avoid pulling an adversarial-LLM dependency into a tool whose niche is being lightweight and dependency-thin.

---

## Recommended sequencing

1, 2, 3 are the high-value / low-complexity core — ship them in that order first. 4 and 5 are independent refinements that can land any time. 6 composes best after 1 and 3. 7 is the architectural reach goal, gated on 3, and should get its own scoping pass before a Worker takes it. Each item is independently shippable as one Phase 2 improve lap; none requires touching `queue/objectives.json` or breaking the v0.1 scope-gate contract.
