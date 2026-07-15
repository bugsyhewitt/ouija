# ouija lap-20260715T100000Z — Worker output

## Improvement shipped

**`--timeout SECONDS` per-probe HTTP request timeout** — expose ouija's
previously-hardcoded 20 s per-probe timeout as a user-configurable CLI flag.
Operators scanning slow inference endpoints can raise it (e.g. `--timeout 120`);
operators wanting to surface unresponsive targets fast can lower it (e.g.
`--timeout 5`). Timed-out probes compose with `--retries N` — a retry fires
after each timeout just as it does after a 429 or 503.

## Problem this solves

`TargetClient` accepted a `timeout` parameter since v0.1 but the scanner hardcoded
`timeout=20.0` and never plumbed it through `run_scan()` / `_run_async()`. There
was no way to change the timeout from the CLI. Two real use cases it blocked:

1. **`--attack-set dos`** — DoS probes deliberately instruct the model to
   generate very long outputs. 20 s is too short for many inference stacks under
   load; these probes were silently dropping as transport errors and losing real
   findings.
2. **Fast fail on dead endpoints** — a 20 s wait per probe means a CI job
   hitting a dead endpoint burns 20 s × N patterns before realising the target is
   down. `--timeout 5` surfaces the error in seconds.

## What changed

### `ouija/scanner.py`

- `timeout: float = 20.0` added to `_run_async()` signature; passed as
  `timeout=timeout` to `TargetClient()`.
- `timeout: float = 20.0` added to `run_scan()` signature; forwarded to
  `_run_async()`.

### `ouija/cli.py`

- New `--timeout SECONDS` argument (float, default 20.0, metavar `SECONDS`).
  Help text describes the fast-fail and slow-inference use cases and documents
  the `> 0` constraint.
- Validation: `--timeout <= 0.0` prints an error and exits with code 3, before
  any scope gate or request is attempted (same pattern as `--retries < 0`).
- `args.timeout` passed as `timeout=args.timeout` to `run_scan()`.

### `tests/test_timeout.py` — 12 new tests (new file)

**CLI unit tests:**
- `test_timeout_flag_in_help` — `--timeout` action present in the parser.
- `test_timeout_flag_in_help_output` — `--timeout` appears in `--help` text.
- `test_timeout_default_is_20` — argparse default is `20.0`.
- `test_timeout_zero_exits_error` — `--timeout 0` → exit 3 with an error
  mentioning "timeout".
- `test_timeout_negative_exits_error` — `--timeout -5` → exit 3.

**TargetClient unit tests:**
- `test_target_client_timeout_defaults_to_20` — default attribute value is 20.0.
- `test_target_client_timeout_stored` — explicit value stored correctly.
- `test_target_client_passes_timeout_to_httpx` — `_do_post` passes `timeout`
  to `httpx.AsyncClient.post` (verified via a fake POST that records the kwarg).

**Integration tests (real HTTP servers on ephemeral ports):**
- `test_timeout_valid_value_scan_completes` — `--timeout 30` with a fast mock
  server returns exit 0 and a valid JSON report.
- `test_timeout_very_short_against_slow_server_exits_error` — a 50 ms timeout
  against a 1 s-delay server causes every probe to time out; the scan fails
  with exit 3.
- `test_timeout_plan_mode_accepts_custom_timeout` — `--plan --timeout 60` exits
  0 (plan mode doesn't send requests; timeout is validated but unused).
- `test_run_scan_threads_timeout` — `run_scan(timeout=33.3)` forwards the value
  to `TargetClient.__init__` (verified via a monkey-patched `__init__`).

### `ouija/__init__.py` and `pyproject.toml` — version bumped

`0.5.3` → `0.5.4`.

### `tests/test_wheel_ship_gate.py` — version gate updated

`EXPECTED_VERSION` updated to `"0.5.4"`. Test function renamed
`test_version_is_0_5_4`.

### `README.md` — `--timeout` row added to flag table

New row between `--concurrency` and `--retries` describing the default (20.0 s),
the fast-fail use case (5–10 s), the slow-inference use case (60–120 s), the
interaction with `--retries`, and the `> 0` constraint.

## Test results

632 passed (620 pre-existing + 12 new). See `test-output.txt`.

## Files changed

- `ouija/scanner.py` — `timeout` parameter in `_run_async()` and `run_scan()`
- `ouija/cli.py` — `--timeout` flag, `> 0` validation, pass-through to `run_scan()`
- `ouija/__init__.py` — version 0.5.3 → 0.5.4
- `pyproject.toml` — version 0.5.3 → 0.5.4
- `tests/test_timeout.py` — 12 new tests (new file)
- `tests/test_wheel_ship_gate.py` — version gate updated
- `README.md` — `--timeout` row added to flag table
