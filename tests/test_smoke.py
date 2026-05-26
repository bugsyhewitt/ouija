"""End-to-end smoke test (criterion 6).

Drives the full pipeline — scope gate, corpus load, mutate, send to the bundled
mock endpoint (ephemeral port), detect, render — and asserts a usable finding
comes out the other end.
"""

from __future__ import annotations

import json

from ouija.cli import EXIT_OK, main


def test_smoke_end_to_end(mock_llm, scope_file, capsys):
    rc = main(
        [
            "--target",
            mock_llm.url,
            "--scope-file",
            scope_file,
            "--attack-set",
            "all",
            "--format",
            "json",
        ]
    )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)

    assert data["target"] == mock_llm.url
    assert data["attack_set"] == "all"
    assert data["patterns_sent"] > 0
    assert len(data["findings"]) >= 1

    # The deliberately-vulnerable mock should yield a prompt_injection finding
    # with a severity and reproduction prompt.
    injection = [f for f in data["findings"] if f["category"] == "prompt_injection"]
    assert injection, "expected a prompt_injection finding from the vulnerable mock"
    f = injection[0]
    assert f["severity"]
    assert f["request_prompt"]
    assert f["response_excerpt"]
    assert 0.0 < f["confidence"] <= 1.0
