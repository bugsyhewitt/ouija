# ouija lap-20260715T080000Z — Worker output

## Improvement shipped

**`--format markdown-table` for `ouija-agentic`** — a compact GitHub-flavoured-markdown
triage table for the agentic scanner, closing the gap between the single-endpoint
fuzzer (which has had `--format markdown-table` since Rotation 30) and
`ouija-agentic` (which had only `json`, `h1md`, `sarif`).

## What changed

### `ouija/agentic_report.py` — new `to_markdown_table()` renderer

New function renders a `ScanReport` as a compact GFM table:
- Confirmed findings appear before detected (strongest signal first, matching h1md ordering).
- Not-vulnerable findings are omitted (same as h1md and sarif).
- A zero-finding run still emits the header row so a downstream PR-comment macro always
  sees the table shape.
- Columns (agentic-specific, different from the single-endpoint scanner's table):
  `state` | `effect` | `owasp` | `title` | `surface` | `asr`
- `asr` shows the Attack Success Rate percentage for confirmed findings; '-' for detected.
- All attacker-influenced values (title, surface) are passed through `_md_escape_cell`
  — a finding whose title contains `|` or a newline cannot break the table structure.
- Module docstring updated (Two renderers → Three renderers).

New helpers (module-level, reused by `to_markdown_table`):
- `_MD_TABLE_COLUMNS`: stable column-order tuple for the agentic table.
- `_STATE_ORDER`: sort key dict for confirmed-before-detected ordering.
- `_md_escape_cell()`: pipe/newline escaping for GFM table cells.
- `_asr_cell()`: formats the asr column value.

### `ouija/agentic_cli.py` — `markdown-table` wired into CLI

- Import: `to_markdown_table` added to the `from ouija.agentic_report import …` line.
- `--format` choices extended: `["json", "h1md", "sarif", "markdown-table"]`.
- `_render()`: new branch `if fmt == "markdown-table": return to_markdown_table(report)`.

### `tests/agentic/test_agentic_report.py` — 14 new tests

Unit tests (hand-crafted `ScanReport`):
- `test_markdown_table_has_header_and_separator` — title line + all column names + separator row.
- `test_markdown_table_confirmed_finding_row` — CONFIRMED state, ASR percentage, title, OWASP refs.
- `test_markdown_table_detected_finding_shows_dash_asr` — DETECTED state, '-' in asr cell.
- `test_markdown_table_not_vulnerable_omitted` — not_vulnerable findings excluded; no-findings notice.
- `test_markdown_table_zero_findings_still_emits_header` — zero-finding report still has header.
- `test_markdown_table_confirmed_before_detected` — ordering assertion.
- `test_markdown_table_pipe_in_title_escaped` — raw `|` in title escaped to `\|`; row column count correct.
- `test_markdown_table_newline_in_surface_collapsed` — `\n` in surface collapsed to space.
- `test_markdown_table_effect_label_rendered` — human-readable effect label (not raw key).
- `test_markdown_table_summary_counts_in_title` — title line carries confirmed/detected counts.
- `test_markdown_table_multiple_refs_joined` — all OWASP refs appear space-joined in owasp cell.

CLI integration tests:
- `test_cli_markdown_table_format_lab_scan_mcp` — end-to-end lab scan, GFM output, CONFIRMED row, not JSON.
- `test_cli_markdown_table_format_lab_fuzz_agent` — end-to-end fuzz-agent lab, GFM output.
- `test_cli_markdown_table_in_help` — 'markdown-table' appears in --help text.

### `tests/test_wheel_ship_gate.py` — version gate bumped to 0.5.2

`EXPECTED_VERSION` updated from `"0.5.1"` to `"0.5.2"`. Test function renamed
`test_version_is_0_5_2` (was `test_version_is_0_5_1`). Error message updated.

### `ouija/__init__.py` and `pyproject.toml` — version bumped

`0.5.1` → `0.5.2`.

### `README.md` — Output formats section updated

- Header updated: "three output formats" → "four output formats".
- New `markdown-table` row in the formats table.
- New `--format markdown-table` bash example (standalone + `gh pr comment` pipe).
- Prose description of the markdown-table format (columns, ordering, zero-finding behaviour,
  attacker-value escaping, full-evidence note).
- Rendered example showing the table structure.

## Test results

603 passed in ~105s (589 pre-existing + 14 new). See `test-output.txt`.

## Files changed

- `ouija/agentic_report.py` — new `to_markdown_table()` + helpers
- `ouija/agentic_cli.py` — import + format choice + `_render()` branch
- `ouija/__init__.py` — version 0.5.1 → 0.5.2
- `pyproject.toml` — version 0.5.1 → 0.5.2
- `tests/agentic/test_agentic_report.py` — 14 new tests
- `tests/test_wheel_ship_gate.py` — version gate updated
- `README.md` — Output formats section updated
