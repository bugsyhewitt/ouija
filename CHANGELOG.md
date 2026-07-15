# Changelog

All notable changes to ouija are documented here.

## [1.0.0] — 2026-07-15

First stable release. ouija now provides complete OWASP coverage across two
distinct attack surfaces: the single-endpoint LLM fuzzer (`ouija` CLI) covering
the full OWASP LLM Top 10 v2025, and the agentic/RAG/MCP fuzzer
(`ouija-agentic` CLI + MCP server) covering all 10 OWASP ASI categories for
Agentic Applications 2026.

### Summary of what's in v1.0.0

#### The single-endpoint LLM fuzzer (`ouija` CLI)

- **Full OWASP LLM Top 10 v2025 coverage** across 13 attack sets: `injection`,
  `disclosure`, `dos`, `exfil`, `agency`, `misinfo`, `activecontent`,
  `ragpoison`, `safetybypass`, `pii`, `supplychain`, `promptextract`,
  `outputintegrity` — plus `all` (default).
- **13 output formats**: `json`, `jsonl`, `csv`, `h1md`, `html`,
  `markdown-table`, `sarif`, `slack`, `pagerduty`, `opsgenie`, `victorops`,
  `jira`, `teams`.
- **Encoding/obfuscation mutators** (`--mutators all`): base64, ROT13,
  leetspeak, zero-width-space, HTML-comment.
- **Indirect prompt injection** (`--inject-via {direct,document,webpage,email}`)
  — models the EchoLeak / Gemini/Copilot attack channel.
- **Multi-turn / Crescendo attacks** (`--multi-turn`) — scripted escalation
  ladders; reported success rates jump from ~4% to ~78% vs. hardened models.
- **Repeated generations** (`--repeats N`) for non-determinism coverage;
  findings carry `attempts`/`successes`/`success_rate`.
- **Custom request/response shapes** (`--request-template` / `--response-path`)
  — targets OpenAI, Anthropic, and arbitrary endpoint bodies.
- **Baseline / suppression** (`--baseline` / `--write-baseline`) — standard
  noise-control primitive keyed on deterministic stable finding IDs.
- **Dry-run plan mode** (`--plan`) — request-count enumeration without sending
  traffic; matches the real run exactly.
- **CI/CD gating** (`--fail-on`) — exits non-zero on findings at or above a
  severity threshold; composes with `--baseline`.
- **Webhook notifications** (`--notify`) — end-of-scan POST to any HTTP
  receiver.
- **Scan summary statistics** — `summary.by_severity` breakdown and
  `elapsed_seconds` wall-clock timing on every run.
- **Stable finding IDs** — deterministic `ouija-<category>-<8hex>` IDs for
  dedup, tracking, and SARIF `partialFingerprints`.

#### The agentic/RAG/MCP fuzzer (`ouija-agentic` CLI + MCP server)

- **All 10 OWASP ASI categories** (Agentic Applications 2026) implemented with
  no stubs:
  - ASI01 Agent Goal Hijack — indirect PI via tool results, RAG poisoning
  - ASI02 Tool Misuse — MCP tool poisoning, excessive agency, exfil via tool chain
  - ASI03 Agent Identity — MCP confused-deputy, token passthrough
  - ASI04 Agentic Supply Chain — MCP rug-pull, SSRF-in-discovery
  - ASI05 Unexpected Code Execution — probe_unexpected_code_exec
  - ASI06 Memory & Context Poisoning — RAG/memory poisoning + extraction
  - ASI07 Insecure Inter-Agent Communication — inter-agent message spoofing
  - ASI08 Cascading Failures — probe_cascading_failures
  - ASI09 Human-Agent Trust Exploitation — probe_trust_exploitation
  - ASI10 Rogue Agents — probe_rogue_agents
- **Four output formats** for agentic verbs: `json`, `h1md`, `sarif`,
  `markdown-table`.
- **Data-flow success oracle** — a finding fires on an observed *real
  consequence* (OOB exfil, tool invoked, answer flipped, secret surfaced),
  not merely "the model said something bad".
- **In-process headless lab** — self-contained deliberately-vulnerable MCP
  server, RAG backend, and agent runner; `--lab` runs with no external
  target.
- **ouija MCP server** (`ouija.mcp_server`) — exposes `scan_mcp`, `scan_rag`,
  `fuzz_agent`, and `list_probes` as MCP tools so an orchestrating agent can
  drive ouija programmatically.
- **Allow-list + `--confirm` gating** enforced in code on every active verb.
- **Attack Success Rate with 95% bootstrap CI** — findings carry ASR + CI95
  so a triager knows signal quality before reproducing.

#### Safety

- Allow-list enforced at the top of every active verb (no convenience bypass).
- `--confirm` required for every active verb; `--lab` implicitly allow-lists
  only loopback.
- OOB collector is local by default (`127.0.0.1`); nothing leaves the machine.
- Planted documents are retracted and cleanup is asserted.
- Recovered secrets/system prompts are redacted in findings.
- All attacker-influenced values are escaped in every rendered output format.

---

## [0.5.5] — 2026-07-14

Add scan summary statistics: `summary.by_severity` breakdown and
`elapsed_seconds` wall-clock timing. Both fields propagate through all output
formats automatically. The `h1md` report gains `Elapsed: N.Ns` and a
`Severity breakdown:` line.

## [0.5.4] — 2026-07-11

Add `--timeout SECONDS` per-probe HTTP timeout (default 20.0). Lower values
surface unresponsive endpoints faster; higher values support slow inference
or intentional DoS generation runs. Pairs with `--retries`.

## [0.5.3] — 2026-07-08

Add `--retries N` with exponential backoff (0.5 s, 1.0 s, 2.0 s, …, capped
at 8 s) for transient HTTP errors (429, 502, 503, 504) and network faults.

## [0.5.2] — 2026-07-05

Add `--format markdown-table` to `ouija-agentic` — compact GFM table output
for inline GitHub issue/PR comment delivery.

## [0.5.1] — 2026-07-03

Add `--format sarif` SARIF 2.1.0 output to `ouija-agentic` for GitHub
Advanced Security / Azure DevOps upload.

## [0.5.0] — 2026-06-30

Ship `ouija-agentic` MVP: agentic/RAG/MCP fuzzer with ASI01–ASI10 coverage,
data-flow oracle, in-process lab, and MCP server (`ouija.mcp_server`).

## [0.1.25] — 2026-06-15

Add `--format teams` (Microsoft Teams MessageCard webhook payload).

## [0.1.19] — 2026-06-01

Add `--format jira` (Jira Cloud REST API v3 Create Issue ADF payload).

## [0.1.18] — 2026-05-30

Add `--plan` dry-run mode — enumerate exact request count without sending
traffic; matches the real run's `patterns_sent` exactly.

## [0.1.17] — 2026-05-29

Add `--baseline` / `--write-baseline` finding suppression workflow keyed on
stable deterministic finding IDs.

## [0.1.12] — 2026-05-20

Add `--attack-set promptextract` (LLM07 System Prompt Leakage — bypass-driven
sub-vector: roleplay reframe, completion priming, delimiter confusion, etc.).

## [0.1.11] — 2026-05-17

Add `--attack-set supplychain` (LLM03 Supply Chain — slopsquatting /
package-recommendation poisoning sub-vector; install-directive detector).

## [0.1.10] — 2026-05-14

Add `--attack-set pii` (LLM02 Sensitive Information Disclosure — PII/personal
data sub-vector; synthetic inert PII, Luhn validation, benign-framing guard).

## [0.1.9] — 2026-05-11

Add `--attack-set safetybypass` (LLM01 Prompt Injection — jailbreak
sub-vector; refusal-aware marker detection so the detector does not fire when
the model echoes the token while still refusing).

## [0.1.8] — 2026-05-08

Add DoS detector (`dos_signal` field; length / repetition / nesting
heuristics). The `dos` corpus was previously inert (marker null, no detection
path). Add `--format victorops` (VictorOps / Splunk On-Call REST payload).

## [0.1.7] — 2026-05-04

Add `--attack-set ragpoison` (LLM08 Vector & Embedding Weaknesses —
retrieval-context poisoning and cross-context leakage sub-vectors).

## [0.1.6] — 2026-04-30

Add `--attack-set activecontent` (LLM05 Improper Output Handling — active
executable-sink sub-vector: script/XSS/SQLi/shell-substitution detection).

## [0.1.5] — 2026-04-26

Add `--attack-set misinfo` (LLM09 Misinformation/Overreliance).

## [0.1.4] — 2026-04-22

Add `--attack-set agency` (LLM06 Excessive Agency).

## [0.1.3] — 2026-04-18

Add `--multi-turn` Crescendo attack mode (scripted escalation ladders).

## [0.1.2] — 2026-04-14

Add `--inject-via {direct,document,webpage,email}` indirect prompt injection
mode (models the EchoLeak channel).

## [0.1.1] — 2026-04-10

Add `--request-template` and `--response-path` for custom endpoint body
shapes (OpenAI/Anthropic and arbitrary SaaS targets).

## [0.1.0] — 2026-03-28

Initial release. Single-endpoint LLM fuzzer covering OWASP LLM01/02/05/10
with four surface mutators, HackerOne markdown output, scope-file gating,
and stable finding IDs.
