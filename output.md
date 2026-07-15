# ouija lap-20260714T180000Z — Worker output

## Improvement shipped

**ASI09 Human-Agent Trust Exploitation — promoted from stub to working smoke probe**

ouija's probe taxonomy (asitax.py) declares coverage of all 10 OWASP ASI categories
as a pre-v1.0 requirement. Five categories remained stubs. This lap promotes ASI09
from stub to a real, tested probe, reducing the remaining stubs to 4.

## What changed

### New seed file: `ouija/seeds/asi09_trust_exploit.json`
Two seeds where the injected text directs the agent to surface attacker-crafted
content to the human as a trusted recommendation or approval request:
- `trust_fake_approval_request` (technique: human-approval-hijack)
- `trust_false_recommendation` (technique: false-recommendation-inject)

Both seeds trigger the existing `_maybe_flip` path in `LabAgent` via the "include
{canary}" pattern, so no lab changes were needed. Detection is `answer_flip`.

### New probe function: `ouija/modules/indirect_pi.probe_trust_exploitation()`
Delivers ASI09 seeds via tool-result injection (the same channel as
`probe_tool_result_injection`) and confirms via `answer_flip`. Wired into
`fuzz_agent_target` in `agentic_scan.py`.

### `ouija/asitax.py` — ASI09 un-stubbed
`human_agent_trust` entry: `stub=True` → `stub=False`, `llm=()` → `llm=("LLM01",)`.

### `ouija/agentic_scan.py` — fuzz_agent wired
`probe_trust_exploitation` added after the existing tool-result-injection call.

### Tests: `tests/agentic/test_modules.py` — 4 new tests
- `test_trust_exploitation_confirms_on_vulnerable_agent` — confirms `answer_flip` + ASI09 ref
- `test_trust_exploitation_no_finding_on_hardened_agent` — real-negative check
- `test_trust_exploitation_enforces_allowlist` — `AllowlistError` on unlisted target
- `test_trust_exploitation_asr_and_ci_on_confirmed` — ASR + CI95 on every finding

### README updated
"The five attack modules" table now has a row for Human-agent trust exploitation
(ASI09/LLM01) under `fuzz-agent`.

### Version: 0.3.0 → 0.3.1
Both `pyproject.toml` and `ouija/__init__.py` bumped (they were inconsistent;
`__init__.py` was stale at 0.2.0, `pyproject.toml` at 0.3.0; both now 0.3.1).

## Test results
554 passed (550 existing + 4 new) in ~90s.

## Remaining stubs (post this lap)
- ASI05: unexpected_code_exec
- ASI07: inter_agent_spoofing
- ASI08: cascading_failures
- ASI10: rogue_agents
