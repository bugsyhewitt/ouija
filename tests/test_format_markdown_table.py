"""Tests for the `--format markdown-table` (compact triage table) output.

Where `--format h1md` is the long-form HackerOne report (one ``## Finding``
section per finding with reproduction steps and impact prose), `--format
markdown-table` is the one-screen triage view: a single GitHub-flavoured-
markdown table — header row, separator row, and one data row per finding,
severity-sorted — that pastes inline in a GitHub issue, PR comment, README,
or any markdown-rendered surface. The contract:

    * a single title line above the table identifying the target / counts;
    * exactly one header row of the documented column set;
    * the GFM separator row (``|---|---|...``);
    * one data row per finding, descending-severity-sorted;
    * pipe (``|``) and newline characters inside any cell are escaped /
      collapsed so the row count stays well-formed even with hostile content;
    * even a zero-finding run still emits the header so a downstream
      template (e.g. a PR-comment macro) always sees the table shape;
    * wide free-text fields (request_prompt, response_excerpt, evidence) are
      DELIBERATELY OMITTED — they would break GFM table rendering. Read
      ``--format json`` / ``--format h1md`` for full evidence.
"""

from __future__ import annotations

from ouija.cli import EXIT_OK, main
from ouija.report import MD_TABLE_COLUMNS, to_markdown_table
from ouija.models import ScanResult


def _two_finding_result() -> ScanResult:
    base = {
        "version": "9.9.9",
        "target": "https://example.test/llm",
        "attack_set": "injection",
        "patterns_sent": 7,
        "findings": [
            {
                "id": "f-aaaa",
                "category": "prompt_injection",
                "severity": "medium",
                "title": "demo finding two",
                "pattern_id": "p2",
                "technique": "smuggle",
                "owasp": "LLM01:2025",
                "request_prompt": "second prompt",
                "response_excerpt": "second reply",
                "evidence": "marker present",
                "confidence": 0.7,
            },
            {
                "id": "f-bbbb",
                "category": "prompt_injection",
                "severity": "critical",
                "title": "demo finding one",
                "pattern_id": "p1",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "ignore previous",
                "response_excerpt": "ok, ignoring",
                "evidence": "marker present",
                "confidence": 0.9,
            },
        ],
        "summary": {
            "total": 7,
            "successful": 2,
            "attack_sets": {"injection": 2},
        },
    }
    return ScanResult(**base)


def _data_rows(text: str) -> list[str]:
    """Return only the data rows of the rendered table (skipping the title
    line, the optional blank line, the header row, and the GFM separator row).
    """
    lines = text.splitlines()
    out: list[str] = []
    after_separator = False
    for line in lines:
        if after_separator:
            if line.startswith("|"):
                out.append(line)
            continue
        if line.startswith("|") and set(line.replace("|", "").strip()) <= {"-"}:
            after_separator = True
    return out


def test_markdown_table_has_title_header_and_one_row_per_finding():
    result = _two_finding_result()
    text = to_markdown_table(result)
    # Title carries the target and the finding count
    assert text.splitlines()[0].startswith("# ouija findings")
    assert "https://example.test/llm" in text.splitlines()[0]
    assert "2 finding(s)" in text.splitlines()[0]
    # Header row contains the documented columns in order
    header_line = next(
        line for line in text.splitlines()
        if line.startswith("|") and "severity" in line
    )
    for col in MD_TABLE_COLUMNS:
        assert f" {col} " in header_line, f"missing column {col}"
    # One data row per finding
    rows = _data_rows(text)
    assert len(rows) == 2


def test_markdown_table_rows_are_sorted_by_severity_desc():
    """Critical sorts above medium — same ordering as h1md / csv / html."""
    text = to_markdown_table(_two_finding_result())
    rows = _data_rows(text)
    assert rows[0].split("|")[1].strip() == "critical"
    assert rows[1].split("|")[1].strip() == "medium"


def test_markdown_table_separator_row_present_and_well_formed():
    """The GFM separator row gates a renderer recognising the block as a
    table. It must sit immediately under the header row and carry one ``---``
    cell per column."""
    text = to_markdown_table(_two_finding_result())
    lines = text.splitlines()
    sep_idx = next(
        i for i, line in enumerate(lines)
        if line.startswith("|") and set(line.replace("|", "").strip()) <= {"-"}
    )
    # Header row sits directly above the separator
    assert "severity" in lines[sep_idx - 1]
    # Separator has the right number of column markers
    assert lines[sep_idx].count("---") == len(MD_TABLE_COLUMNS)


def test_markdown_table_no_findings_still_emits_header_row():
    """A clean-run zero-finding scan still yields the header + separator so a
    downstream PR-comment template always sees the table shape."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=3,
    )
    text = to_markdown_table(result)
    # Title carries 0 findings, not crash
    assert "0 finding(s)" in text.splitlines()[0]
    # The reassuring prose line for a clean run is present
    assert "No findings" in text
    # Header + separator still emitted
    header_line = next(
        line for line in text.splitlines()
        if line.startswith("|") and "severity" in line
    )
    for col in MD_TABLE_COLUMNS:
        assert col in header_line
    assert _data_rows(text) == [], "no findings → zero data rows"


def test_markdown_table_escapes_pipe_in_cell():
    """A literal ``|`` in a title/category MUST NOT be allowed to break the
    column count of the row. We escape it as ``\\|`` so the GFM renderer
    treats it as content."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-cccc",
                "category": "prompt_injection",
                "severity": "high",
                # Hostile title: contains a pipe that, if unescaped, would
                # spawn a phantom column and break the table.
                "title": "a|b|c title",
                "pattern_id": "p3",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.8,
            },
        ],
    )
    text = to_markdown_table(result)
    rows = _data_rows(text)
    assert len(rows) == 1
    # The row has exactly one cell per column (== len(cols)+1 leading +
    # trailing pipes giving len(cols)+1 splits, but accounting for trailing
    # empty string from the trailing pipe: split yields len(cols)+2 parts).
    # Stricter check: count UNESCAPED pipes — must equal the column count + 1
    # (the leading + trailing pipes of the row).
    raw = rows[0]
    unescaped_pipes = 0
    i = 0
    while i < len(raw):
        if raw[i] == "\\" and i + 1 < len(raw) and raw[i + 1] == "|":
            i += 2
            continue
        if raw[i] == "|":
            unescaped_pipes += 1
        i += 1
    assert unescaped_pipes == len(MD_TABLE_COLUMNS) + 1, (
        "unescaped pipe in a cell would split the row into extra columns"
    )
    # The escaped form of the title is present
    assert "a\\|b\\|c title" in raw


def test_markdown_table_collapses_newlines_in_cell():
    """A multi-line title (rare but possible — patterns are author-supplied)
    would otherwise terminate the row. We replace newlines with a single
    space so each cell stays on one logical line."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-dddd",
                "category": "prompt_injection",
                "severity": "high",
                "title": "line one\nline two",
                "pattern_id": "p4",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.8,
            },
        ],
    )
    text = to_markdown_table(result)
    rows = _data_rows(text)
    assert len(rows) == 1, (
        "newline in the title must not split the row across two table lines"
    )
    assert "line one line two" in rows[0]
    assert "line one\nline two" not in rows[0]


def test_markdown_table_emits_reliability_when_repeats_used():
    """attempts > 1 → reliability cell carries ``successes/attempts (rate%)``;
    attempts == 1 → reliability cell is ``-``."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=5,
        findings=[
            {
                "id": "f-eeee",
                "category": "prompt_injection",
                "severity": "high",
                "title": "flaky finding",
                "pattern_id": "p5",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.8,
                "attempts": 5,
                "successes": 3,
                "success_rate": 0.6,
            },
            {
                "id": "f-ffff",
                "category": "prompt_injection",
                "severity": "low",
                "title": "single-shot finding",
                "pattern_id": "p6",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.5,
            },
        ],
    )
    rows = _data_rows(to_markdown_table(result))
    assert "3/5 (60%)" in rows[0], "repeated-generation reliability is shown"
    # The single-shot row's reliability cell is a literal ``-`` placeholder
    cells_single = [c.strip() for c in rows[1].strip("|").split("|")]
    rel_idx = MD_TABLE_COLUMNS.index("reliability")
    assert cells_single[rel_idx] == "-"


def test_markdown_table_finding_id_is_inline_code():
    """The finding ``id`` is wrapped in backticks so it renders as inline code
    in the GFM table — a triager can copy-click it."""
    text = to_markdown_table(_two_finding_result())
    assert "`f-bbbb`" in text
    assert "`f-aaaa`" in text


def test_markdown_table_end_to_end_via_cli(mock_llm, scope_file, capsys):
    """``--format markdown-table`` from the CLI exits 0 and renders the table.

    Smoke-tests the wiring: CLI choice accepted, render() dispatches the new
    format, output contains the title line and at least one data row whose
    severity cell holds one of the known severity values.
    """
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "injection",
            "--format",
            "markdown-table",
        ]
    )
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert out.splitlines()[0].startswith("# ouija findings")
    rows = _data_rows(out)
    assert rows, "expected at least one finding row from the vuln mock"
    known = {"critical", "high", "medium", "low", "info"}
    for row in rows:
        sev = row.split("|")[1].strip()
        assert sev in known, f"unexpected severity cell value: {sev!r}"
