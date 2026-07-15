# ouija lap-20260715T110000Z — Worker output

## Improvement shipped

**Scan summary statistics** — two new fields added to the JSON report and
`ScanSummary` model:

- `summary.by_severity` — a `severity → count` map (e.g. `{"critical": 1,
  "high": 2}`) that gives at-a-glance risk triage without iterating the full
  findings array. Zero-finding runs emit `{}`. Consumable directly with
  `jq '.summary.by_severity'`.
- `elapsed_seconds` (top-level on `ScanResult`) — wall-clock seconds elapsed
  during the probe loop (first request sent to last reply received), rounded to
  millisecond precision. Enables throughput benchmarking and `--concurrency` /
  `--timeout` trade-off sizing.

Both fields propagate through every output format automatically (pydantic
serialisation). The `--format h1md` report gains two new visible enhancements:
the preamble line now includes `Elapsed: N.Ns`, and a **Severity breakdown:**
line (e.g. `high: 2, medium: 1`) appears between the header and the first
finding when at least one finding was produced.

## Problem this solves

The existing `ScanSummary` had `total` (probes sent), `successful` (number of
findings), and `attack_sets` (findings by attack-set name). Two pieces of
information practitioners need at a glance were missing:

1. **Risk profile at a glance**: seeing "3 findings" doesn't tell you whether
   they are all INFO or all CRITICAL. Every mature scanner (gitleaks, semgrep,
   trivy) surfaces a severity breakdown in its summary. Without it, a pipeline
   must iterate `findings[]` and group by severity — a re-derivation that every
   downstream consumer re-implements.

2. **Scan duration**: there was no way to know how long a scan took without
   external timing (`time ouija …`). Duration matters for sizing `--concurrency`
   and `--timeout`, for benchmarking endpoint responsiveness, and for CI
   reporting.

## What changed

### `ouija/models.py`

- `ScanSummary` gains `by_severity: dict[str, int]` (default `{}`).
- `ScanResult` gains `elapsed_seconds: Optional[float]` (default `None`; `None`
  when a `ScanResult` is constructed directly without going through the scanner,
  preserving compatibility with tests that build results manually).

### `ouija/scanner.py`

- `import time` added.
- In `_run_async`: `t_start = time.monotonic()` captured before
  `asyncio.gather`, `elapsed` computed after the gather completes;
  `result.elapsed_seconds = round(elapsed, 3)` set before returning.
- In `_run_multi_turn`: same pattern — `t_start` before the ladder loop,
  `result.elapsed_seconds` set after.
- Both summary roll-ups now also compute `per_severity: dict[str, int]` from
  `finding.severity.value` and pass `by_severity=per_severity` to `ScanSummary`.

### `ouija/report.py` (`to_h1md`)

- Preamble line appended with `Elapsed: N.Ns` (omitted when
  `elapsed_seconds is None`).
- **Severity breakdown:** line inserted after the preamble when findings are
  present and `summary.by_severity` is non-empty, listing severity buckets in
  descending order (critical → high → medium → low → info).

### `ouija/__init__.py` and `pyproject.toml` — version bumped

`0.5.4` → `0.5.5`.

### `tests/test_wheel_ship_gate.py`

`EXPECTED_VERSION` updated to `"0.5.5"`. Test function renamed
`test_version_is_0_5_5`.

### `README.md` — JSON schema and new jq examples

- JSON schema example updated to `v0.5.5` with `elapsed_seconds` and
  `summary.by_severity` fields documented with inline comments.
- New prose section explaining `elapsed_seconds` and `summary.by_severity`,
  with `jq` snippets for at-a-glance risk triage and severity counting.

### `tests/test_summary_stats.py` — 13 new tests (new file)

**Unit tests:**
- `test_scan_summary_by_severity_empty_by_default` — default `by_severity` is
  `{}`.
- `test_scan_summary_by_severity_field_stored` — explicit value stored.
- `test_scan_result_elapsed_seconds_none_by_default` — default is `None`.
- `test_scan_result_elapsed_seconds_stores_value` — explicit value stored.

**Integration tests (real mock HTTP server):**
- `test_json_output_contains_by_severity` — `summary.by_severity` is a dict of
  valid severity strings with counts summing to `summary.successful`.
- `test_json_output_by_severity_absent_on_zero_findings` — `by_severity` is
  `{}` on a zero-finding run.
- `test_json_output_contains_elapsed_seconds` — `elapsed_seconds` is a float
  ≥ 0 in the JSON output.
- `test_elapsed_seconds_is_positive` — value is non-negative.
- `test_h1md_shows_elapsed_time` — `Elapsed:` appears in h1md output.
- `test_h1md_shows_severity_breakdown` — `Severity breakdown:` appears in h1md
  when findings are present.
- `test_by_severity_counts_match_per_bucket` — counts in `by_severity` exactly
  match a re-count from the `findings[]` array.
- `test_jsonl_summary_line_contains_by_severity` — JSONL `summary` record
  carries `by_severity`.
- `test_elapsed_seconds_present_in_jsonl_scan_header` — JSONL `scan` record
  carries `elapsed_seconds`.

## Test results

645 passed (632 pre-existing + 13 new). See `test-output.txt`.

## Files changed

- `ouija/models.py` — `by_severity` in `ScanSummary`; `elapsed_seconds` in
  `ScanResult`
- `ouija/scanner.py` — time tracking + `by_severity` computation in both
  `_run_async` and `_run_multi_turn`
- `ouija/report.py` — `to_h1md` shows elapsed time and severity breakdown
- `ouija/__init__.py` — version `0.5.4` → `0.5.5`
- `pyproject.toml` — version `0.5.4` → `0.5.5`
- `tests/test_summary_stats.py` — 13 new tests (new file)
- `tests/test_wheel_ship_gate.py` — version gate updated
- `README.md` — JSON schema and new jq examples for `elapsed_seconds` /
  `by_severity`
