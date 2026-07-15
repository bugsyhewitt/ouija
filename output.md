# ouija lap-20260715T090000Z — Worker output

## Improvement shipped

**`--retries N` with exponential backoff** — retry transient HTTP errors
(429/502/503/504) and network faults up to N additional times per probe, using
exponential backoff starting at 0.5 s (0.5 s, 1.0 s, 2.0 s, …, capped at 8 s).
Default is 0 (no retry), preserving current behaviour. Recommended: `--retries 1`
or `--retries 2` for production endpoints that occasionally rate-limit or return
transient gateway errors.

## Problem this solves

Production LLM endpoints return HTTP 429 (rate-limited), 502/503/504 (transient
gateway/overload), or drop connections with a transport error. Without retry, every
such failure silently loses the probe — an attack that would have succeeded is
recorded as a non-finding. `--retries N` rescues those probes by retrying up to N
additional times with exponential backoff.

## What changed

### `ouija/client.py` — retry primitives

New module-level constants and coroutine:
- `_RETRYABLE_STATUSES: frozenset[int] = frozenset({429, 502, 503, 504})` — the
  transient HTTP status codes that trigger a retry.
- `async def _retry_delay(retry_num: int) -> None` — exponential backoff
  (`min(0.5 × 2**retry_num, 8.0)` seconds). Module-level so tests can patch it to
  an instant no-op via `monkeypatch.setattr("ouija.client._retry_delay", _instant)`.

`TargetClient.__init__` changes:
- New `max_retries: int = 0` parameter, stored as `self.max_retries`.

New `TargetClient._do_post(client, body) -> httpx.Response` method:
- Implements the retry loop: up to `max_retries + 1` total attempts.
- On each attempt: POST the body. If status is not in `_RETRYABLE_STATUSES`, return
  immediately. If it is, await `_retry_delay` and try again.
- On `httpx.TransportError`: if retries remain, loop; otherwise re-raise.
- After exhausting retries: returns the last response (a retryable status) so
  `detect()` always has something to work with.

`TargetClient.send()` and `send_conversation()` updated to call `_do_post`
instead of `client.post(...)` directly — one-line change each.

### `ouija/scanner.py` — thread max_retries

- `max_retries: int = 0` added to `_run_async()` and `run_scan()` signatures.
- `TargetClient(...)` constructor call updated with `max_retries=max_retries`.

### `ouija/cli.py` — `--retries` flag

- New `--retries N` argument (int, default 0, metavar="N") with help text describing
  the backoff schedule and recommended values.
- Validation: `--retries < 0` exits with code 3 before scanning.
- `args.retries` passed as `max_retries=args.retries` to `run_scan()`.

### `tests/test_retries.py` — 17 new tests

**Unit tests — constants and TargetClient constructor:**
- `test_retryable_statuses_contains_expected_codes` — {429, 502, 503, 504} present.
- `test_retryable_statuses_does_not_include_non_transient` — {400, 401, 403, 404,
  500} absent.
- `test_target_client_max_retries_defaults_to_zero` — default attribute value.
- `test_target_client_max_retries_stored` — explicit value stored correctly.

**Unit tests — `_do_post` retry behaviour (async via `asyncio.run`):**
- `test_do_post_no_retry_on_200` — 200 returned on first call, exactly 1 request.
- `test_do_post_no_retry_by_default_on_503` — max_retries=0, 503 returned, 1
  request sent (no retry).
- `test_do_post_retries_on_503_then_succeeds` — max_retries=1, 503 then 200, 2
  requests sent, 200 returned.
- `test_do_post_retries_on_429_then_succeeds` — same for 429.
- `test_do_post_retry_exhausted_returns_last_error` — max_retries=1, two 503s, 2
  requests, 503 returned.
- `test_do_post_multiple_retries_succeed_on_third_attempt` — max_retries=2, two
  503s then 200, 3 requests, 200 returned.
- `test_do_post_no_retry_on_non_retryable_400` — 400 returned immediately, 1
  request (not retried).
- `test_do_post_no_retry_on_non_retryable_404` — same for 404.

**CLI unit tests:**
- `test_retries_flag_in_help` — `--retries` in `--help` output.
- `test_retries_default_is_zero` — argparse default is 0.
- `test_retries_negative_value_exits_error` — `--retries -1` → exit code 3.

**End-to-end integration tests:**
- `test_retries_0_loses_probe_on_503` — permanent-503 server with `--retries 0`:
  no injection findings (control case).
- `test_retries_1_rescues_probe_on_transient_503` — 503-then-200 server with
  `--retries 1 --concurrency 1`: at least one injection finding, and
  `request_count > patterns_sent` confirming the extra retry request was sent.

All tests use an `autouse` `no_retry_delay` fixture that patches `_retry_delay`
to an instant no-op so tests run in seconds, not minutes.

### `ouija/__init__.py` and `pyproject.toml` — version bumped

`0.5.2` → `0.5.3`.

### `tests/test_wheel_ship_gate.py` — version gate updated

`EXPECTED_VERSION` updated to `"0.5.3"`. Test function renamed
`test_version_is_0_5_3`.

### `README.md` — `--retries` row added to flag table

New row in the Usage flag table: describes the backoff schedule, default (0),
recommended values (1–2), and the note that `--plan` request counts are unaffected.

## Test results

620 passed (603 pre-existing + 17 new). See `test-output.txt`.

## Files changed

- `ouija/client.py` — `_RETRYABLE_STATUSES`, `_retry_delay()`, `TargetClient.max_retries`,
  `TargetClient._do_post()`, updated `send()` and `send_conversation()`
- `ouija/scanner.py` — `max_retries` parameter in `_run_async()` and `run_scan()`
- `ouija/cli.py` — `--retries` flag, validation, pass-through to `run_scan()`
- `ouija/__init__.py` — version 0.5.2 → 0.5.3
- `pyproject.toml` — version 0.5.2 → 0.5.3
- `tests/test_retries.py` — 17 new tests (new file)
- `tests/test_wheel_ship_gate.py` — version gate updated
- `README.md` — `--retries` row added to flag table
