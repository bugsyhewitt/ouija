# ouija lap-20260715T120000Z — v1.0.0 release Worker output

## Release shipped

**v1.0.0** — first stable release of ouija. No new feature was required; the
project was already feature-complete at v0.5.5 with full OWASP coverage, no
taxonomy stubs, and 645 passing tests.

## Changes made

### `ouija/__init__.py`
`__version__` bumped `"0.5.5"` → `"1.0.0"`.

### `pyproject.toml`
`version` bumped `"0.5.5"` → `"1.0.0"`.

### `tests/test_wheel_ship_gate.py`
- `EXPECTED_VERSION` updated to `"1.0.0"`.
- Test function renamed `test_version_is_1_0_0`.

### `README.md`
JSON schema example updated to `"version": "1.0.0"`.

### `CHANGELOG.md` (new file)
Full release history from v0.1.0 through v1.0.0, including all 25+ improve
laps that brought the tool from a single-endpoint LLM fuzzer to a dual-surface
scanner covering all 10 OWASP ASI categories and the full OWASP LLM Top 10 v2025.

## Why no new feature

Assessment of readiness for v1.0.0:

- All OWASP ASI01–ASI10 categories implemented with `stub=False` — the
  `test_no_asi_stubs_remain` ship gate confirms zero taxonomy stubs remain.
- OWASP LLM Top 10 v2025 coverage complete across 13 attack sets.
- Full dual-surface feature set: `ouija` (single-endpoint fuzzer) and
  `ouija-agentic` (agentic/RAG/MCP fuzzer + MCP server exposing its own tools).
- 13 output formats including SARIF, Slack, PagerDuty, OpsGenie, VictorOps,
  Jira, Teams.
- Baseline/suppression, plan mode, multi-turn Crescendo, indirect injection,
  encoding mutators, retries, timeout, summary stats — all shipped.

No meaningful gap to close. Release cut clean per the "otherwise cut the
release clean" instruction.

## Test results

645 passed (all non-integration tests), including both ship gate tests:
- `test_version_is_1_0_0` PASSED
- `test_no_asi_stubs_remain` PASSED

See `test-output.txt` for the full run output.

## Files changed

- `ouija/__init__.py` — version 0.5.5 → 1.0.0
- `pyproject.toml` — version 0.5.5 → 1.0.0
- `tests/test_wheel_ship_gate.py` — version gate updated, test renamed
- `README.md` — JSON schema example version updated
- `CHANGELOG.md` — new file, full release history
- `output.md` — this file
- `test-output.txt` — test run results
