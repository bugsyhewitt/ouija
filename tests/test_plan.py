"""Tests for the --plan dry-run mode (R25).

The plan must (a) re-derive the scanner's exact request-count math so a preview
never disagrees with the real run, and (b) send nothing — the CLI integration
test asserts zero requests reach the target.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ouija.cli import EXIT_ERROR, EXIT_OK, EXIT_OUT_OF_SCOPE, build_parser, main
from ouija.corpus import load_attack_set
from ouija.conversation import ladders
from ouija.mutate import mutate
from ouija.plan import (
    ScanPlan,
    build_plan,
    plan_to_json,
    plan_to_text,
    render_plan,
)

TARGET = "http://127.0.0.1:9/chat"  # never actually contacted by plan tests


# ---------------------------------------------------------------------------
# Pure build_plan() — single-shot math
# ---------------------------------------------------------------------------

def test_build_plan_single_set_surface_math():
    """total_requests == patterns * variants(surface=4) * repeats."""
    loaded = load_attack_set("injection")
    plan = build_plan(
        target=TARGET,
        attack_set_name="injection",
        loaded=loaded,
        repeats=3,
        mutator_set="surface",
    )
    expected = len(loaded.patterns) * 4 * 3
    assert plan.total_requests == expected
    assert plan.kind == "plan"
    assert plan.multi_turn is False
    assert sum(s.requests for s in plan.attack_sets) == expected


def test_build_plan_all_mutators_uses_nine_variants():
    """The 'all' mutator family yields 9 variants per pattern (4 surface + 5 enc)."""
    loaded = load_attack_set("injection")
    plan = build_plan(
        target=TARGET,
        attack_set_name="injection",
        loaded=loaded,
        repeats=1,
        mutator_set="all",
    )
    assert all(s.variants_per_pattern == 9 for s in plan.attack_sets)
    assert plan.total_requests == len(loaded.patterns) * 9


def test_build_plan_matches_real_mutate_count_for_all_sets():
    """Plan's variants_per_pattern equals what mutate() actually yields."""
    loaded = load_attack_set("all")
    plan = build_plan(
        target=TARGET,
        attack_set_name="all",
        loaded=loaded,
        repeats=1,
        mutator_set="surface",
    )
    # Independently recompute total from the corpus + mutate generator.
    independent_total = 0
    for pattern in loaded.patterns:
        independent_total += sum(1 for _ in mutate(pattern, "surface"))
    assert plan.total_requests == independent_total


def test_build_plan_groups_by_category():
    """An 'all' run breaks down into one entry per corpus category."""
    loaded = load_attack_set("all")
    plan = build_plan(
        target=TARGET,
        attack_set_name="all",
        loaded=loaded,
    )
    categories = {s.category for s in plan.attack_sets}
    # A representative sampling of the corpus categories must be present.
    assert "prompt_injection" in categories
    assert "sensitive_info_disclosure" in categories
    assert len(plan.attack_sets) >= 5


def test_build_plan_echoes_knobs():
    loaded = load_attack_set("injection")
    plan = build_plan(
        target=TARGET,
        attack_set_name="injection",
        loaded=loaded,
        repeats=5,
        mutator_set="all",
        inject_via="document",
    )
    assert plan.repeats == 5
    assert plan.mutator_set == "all"
    assert plan.inject_via == "document"
    assert plan.target == TARGET
    assert plan.attack_set == "injection"


# ---------------------------------------------------------------------------
# Pure build_plan() — multi-turn
# ---------------------------------------------------------------------------

def test_build_plan_multi_turn_enumerates_ladders():
    loaded = load_attack_set("injection")  # ignored in multi-turn
    plan = build_plan(
        target=TARGET,
        attack_set_name="injection",
        loaded=loaded,
        multi_turn=True,
    )
    assert plan.multi_turn is True
    assert plan.attack_sets == []
    assert len(plan.ladders) == len(ladders())
    # total_requests == sum of each ladder's max turns.
    expected_turns = sum(len(l.turns) for l in ladders())
    assert plan.total_requests == expected_turns


def test_build_plan_multi_turn_ladder_fields():
    plan = build_plan(
        target=TARGET,
        attack_set_name="all",
        loaded=load_attack_set("injection"),
        multi_turn=True,
    )
    real = {l.id: l for l in ladders()}
    for planned in plan.ladders:
        assert planned.id in real
        assert planned.max_turns == len(real[planned.id].turns)
        assert planned.category == real[planned.id].category


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def test_plan_to_json_roundtrips():
    plan = build_plan(
        target=TARGET,
        attack_set_name="injection",
        loaded=load_attack_set("injection"),
    )
    data = json.loads(plan_to_json(plan))
    assert data["tool"] == "ouija"
    assert data["kind"] == "plan"
    assert "findings" not in data  # a plan is NOT a result
    assert data["total_requests"] == plan.total_requests


def test_plan_to_text_single_shot_is_human_readable():
    plan = build_plan(
        target=TARGET,
        attack_set_name="injection",
        loaded=load_attack_set("injection"),
        repeats=2,
    )
    text = plan_to_text(plan)
    assert "dry run" in text
    assert "no requests sent" in text
    assert "single-shot" in text
    assert str(plan.total_requests) in text


def test_plan_to_text_multi_turn_lists_ladders():
    plan = build_plan(
        target=TARGET,
        attack_set_name="injection",
        loaded=load_attack_set("injection"),
        multi_turn=True,
    )
    text = plan_to_text(plan)
    assert "multi-turn" in text
    for ladder in ladders():
        assert ladder.id in text


def test_render_plan_non_json_falls_back_to_text():
    plan = build_plan(
        target=TARGET,
        attack_set_name="injection",
        loaded=load_attack_set("injection"),
    )
    # h1md and sarif are finding-shaped; the plan falls back to text for both.
    assert render_plan(plan, "h1md") == plan_to_text(plan)
    assert render_plan(plan, "sarif") == plan_to_text(plan)
    assert render_plan(plan, "json") == plan_to_json(plan)


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

def test_cli_plan_flag_in_help():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])


def test_cli_plan_emits_json_plan(mock_llm, scope_file, capsys):
    rc = main(
        [
            "--target", mock_llm.url,
            "--scope-file", scope_file,
            "--attack-set", "injection",
            "--format", "json",
            "--plan",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["kind"] == "plan"
    assert data["total_requests"] > 0
    assert "findings" not in data


def test_cli_plan_default_format_is_text(mock_llm, scope_file, capsys):
    rc = main(
        [
            "--target", mock_llm.url,
            "--scope-file", scope_file,
            "--attack-set", "injection",
            "--format", "h1md",
            "--plan",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "dry run" in out
    assert "no requests sent" in out


def test_cli_plan_still_respects_scope_gate(scope_file, capsys):
    """--plan must not preview an out-of-scope target."""
    rc = main(
        ["--target", "https://example.com/chat", "--scope-file", scope_file, "--plan"]
    )
    assert rc == EXIT_OUT_OF_SCOPE


def test_cli_plan_sends_zero_requests(scope_file, capsys, tmp_path):
    """The defining contract: --plan must not touch the target at all."""
    hits = {"count": 0}

    class _Counter(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            hits["count"] += 1
            body = b'{"reply": "x"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    import socket

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("", 0))
    port = probe.getsockname()[1]
    probe.close()
    server = ThreadingHTTPServer(("127.0.0.1", port), _Counter)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Scope file authorizing 127.0.0.1:<port>.
    scope = tmp_path / "scope.txt"
    scope.write_text(f"127.0.0.1:{port}\n", encoding="utf-8")

    try:
        rc = main(
            [
                "--target", f"http://127.0.0.1:{port}/chat",
                "--scope-file", str(scope),
                "--attack-set", "all",
                "--format", "json",
                "--plan",
            ]
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert rc == EXIT_OK
    assert hits["count"] == 0, "plan mode must send ZERO requests to the target"


def test_cli_plan_multi_turn(mock_llm, scope_file, capsys):
    rc = main(
        [
            "--target", mock_llm.url,
            "--scope-file", scope_file,
            "--multi-turn",
            "--format", "json",
            "--plan",
        ]
    )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "plan"
    assert data["multi_turn"] is True
    assert len(data["ladders"]) == len(ladders())


def test_cli_plan_bad_template_still_validated(mock_llm, scope_file, capsys):
    """--plan does not bypass request-template validation (fail fast, code 3)."""
    rc = main(
        [
            "--target", mock_llm.url,
            "--scope-file", scope_file,
            "--request-template", "{not valid json}",
            "--plan",
        ]
    )
    assert rc == EXIT_ERROR
