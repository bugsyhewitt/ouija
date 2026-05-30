"""Tests for the ``--format pagerduty`` (PagerDuty Events API v2 enqueue
payload) output.

Where ``--format slack`` is the chat-channel alert and ``--format sarif`` is
the CI / code-scanning artifact, ``--format pagerduty`` is the on-call /
incident-response surface: an Events-API-v2-shaped JSON document the operator
pipes straight into ``https://events.pagerduty.com/v2/enqueue``. The contract:

    * a JSON document whose top-level keys are exactly
      ``routing_key`` + ``event_action`` + ``dedup_key`` (+ ``payload`` and
      ``client`` on a trigger), matching the PagerDuty Events API v2 schema;
    * ``routing_key`` is emitted as the literal placeholder
      ``YOUR_PAGERDUTY_ROUTING_KEY`` so the operator substitutes it once
      before piping into ``curl`` and the key never lands on the ouija
      command line or in the scan artifact;
    * one *aggregated* event per scan — not one event per finding — because
      PagerDuty's incident model is alert-per-symptom;
    * ``payload.severity`` is one of the four PagerDuty-accepted strings
      (``critical`` / ``error`` / ``warning`` / ``info``), mapped from the
      *highest* finding severity in the run;
    * ``payload.summary`` fits PagerDuty's 1024-char hard cap;
    * ``dedup_key`` is stable across reruns of the same target+attack-set
      (so re-scanning updates the same incident, not floods a new one);
    * a zero-finding run emits ``event_action: resolve`` against the same
      dedup_key (auto-closes the prior incident — the standard PagerDuty
      "alert" / "no longer alert" pairing).
"""

from __future__ import annotations

import json

from ouija.cli import EXIT_OK, main
from ouija.models import ScanResult
from ouija.report import to_pagerduty


def _two_finding_result() -> ScanResult:
    base = {
        "version": "9.9.9",
        "scan_id": "scan-xyz",
        "timestamp": "2026-05-29T12:00:00Z",
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


def _payload(result: ScanResult) -> dict:
    return json.loads(to_pagerduty(result))


def test_pagerduty_payload_is_valid_json_with_events_api_v2_shape():
    """Top-level keys must match the PagerDuty Events API v2 trigger schema:
    routing_key + event_action + dedup_key + payload."""
    payload = _payload(_two_finding_result())
    assert payload["routing_key"] == "YOUR_PAGERDUTY_ROUTING_KEY"
    assert payload["event_action"] == "trigger"
    assert "dedup_key" in payload
    assert isinstance(payload["dedup_key"], str) and payload["dedup_key"]
    assert "payload" in payload
    assert isinstance(payload["payload"], dict)


def test_pagerduty_payload_required_inner_fields_present():
    """The inner `payload` object must carry the four required Events-API-v2
    fields: summary, severity, source, timestamp. Optional fields we set
    (component, group, class, custom_details) come along for the ride."""
    payload = _payload(_two_finding_result())
    inner = payload["payload"]
    for required in ("summary", "severity", "source", "timestamp"):
        assert required in inner, f"missing required field: {required}"
    assert isinstance(inner["summary"], str) and inner["summary"]
    assert inner["source"] == "https://example.test/llm"
    assert inner["timestamp"] == "2026-05-29T12:00:00Z"


def test_pagerduty_severity_maps_from_top_finding():
    """Severity must be one of the four PagerDuty-accepted strings
    (critical / error / warning / info), driven by the *highest* finding
    severity in the run. A critical ouija finding maps to PagerDuty
    'critical'; a 'high' finding maps to PagerDuty 'error' (PagerDuty has
    no 'high')."""
    # The two-finding fixture has a critical finding → PD 'critical'
    payload = _payload(_two_finding_result())
    assert payload["payload"]["severity"] == "critical"


def test_pagerduty_severity_high_maps_to_error():
    """Ouija 'high' has no PagerDuty equivalent and must map to 'error'."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-h",
                "category": "prompt_injection",
                "severity": "high",
                "title": "h",
                "pattern_id": "p",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.8,
            }
        ],
    )
    assert _payload(result)["payload"]["severity"] == "error"


def test_pagerduty_severity_medium_low_info_map_correctly():
    """medium→warning, low→info, info→info — exhaust the mapping table so a
    later refactor that drops an entry trips this test instead of producing
    an event PagerDuty silently rejects with HTTP 400."""
    for ouija_sev, pd_sev in (("medium", "warning"), ("low", "info"), ("info", "info")):
        result = ScanResult(
            version="9.9.9",
            target="https://example.test/llm",
            attack_set="injection",
            patterns_sent=1,
            findings=[
                {
                    "id": f"f-{ouija_sev}",
                    "category": "prompt_injection",
                    "severity": ouija_sev,
                    "title": "t",
                    "pattern_id": "p",
                    "technique": "override",
                    "owasp": "LLM01:2025",
                    "request_prompt": "x",
                    "response_excerpt": "y",
                    "evidence": "z",
                    "confidence": 0.5,
                }
            ],
        )
        assert _payload(result)["payload"]["severity"] == pd_sev, (
            f"ouija {ouija_sev} should map to PagerDuty {pd_sev}"
        )


def test_pagerduty_severity_is_in_allowed_set():
    """Even if the mapping table changes, the emitted severity must always be
    one of the four PagerDuty-accepted strings — anything else makes the
    enqueue call fail with HTTP 400."""
    payload = _payload(_two_finding_result())
    assert payload["payload"]["severity"] in {"critical", "error", "warning", "info"}


def test_pagerduty_summary_fits_pd_1024_char_cap():
    """PagerDuty rejects events whose summary exceeds 1024 chars. Even with
    a pathological target URL, we must stay under the cap."""
    long_target = "https://example.test/" + ("a" * 2000)
    result = ScanResult(
        version="9.9.9",
        target=long_target,
        attack_set="injection",
        patterns_sent=1,
        findings=[
            {
                "id": "f-x",
                "category": "prompt_injection",
                "severity": "critical",
                "title": "t",
                "pattern_id": "p",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "x",
                "response_excerpt": "y",
                "evidence": "z",
                "confidence": 0.9,
            }
        ],
    )
    assert len(_payload(result)["payload"]["summary"]) <= 1024


def test_pagerduty_dedup_key_is_stable_across_runs():
    """Two scans of the same target + attack-set must produce the SAME
    dedup_key so PagerDuty collapses them into one incident (instead of
    paging a fresh incident on every rerun). The per-run random scan_id
    must NOT leak into the dedup_key."""
    r1 = _two_finding_result()
    r2 = ScanResult(**{**r1.model_dump(mode="json"), "scan_id": "different-scan"})
    p1 = _payload(r1)
    p2 = _payload(r2)
    assert p1["dedup_key"] == p2["dedup_key"]
    # And specifically: it carries target + attack_set, NOT scan_id
    assert "scan-xyz" not in p1["dedup_key"]
    assert "https://example.test/llm" in p1["dedup_key"]
    assert "injection" in p1["dedup_key"]


def test_pagerduty_dedup_key_differs_across_targets_and_attack_sets():
    """Different target OR different attack-set must produce a DIFFERENT
    dedup_key — otherwise scanning two endpoints would collide their
    incidents."""
    base = _two_finding_result()
    other_target = ScanResult(
        **{**base.model_dump(mode="json"), "target": "https://other.test/llm"}
    )
    other_set = ScanResult(
        **{**base.model_dump(mode="json"), "attack_set": "exfil"}
    )
    assert _payload(base)["dedup_key"] != _payload(other_target)["dedup_key"]
    assert _payload(base)["dedup_key"] != _payload(other_set)["dedup_key"]


def test_pagerduty_custom_details_carries_per_finding_breakdown():
    """The on-call needs the per-finding breakdown in the incident detail
    pane — that lives under payload.custom_details.findings, severity-
    sorted, with the same id/category/owasp/severity each other format
    surfaces."""
    payload = _payload(_two_finding_result())
    details = payload["payload"]["custom_details"]
    assert details["findings_total"] == 2
    assert details["attack_set"] == "injection"
    assert details["patterns_sent"] == 7
    findings = details["findings"]
    assert len(findings) == 2
    # Severity-sorted, critical first (same order every other format honours)
    assert findings[0]["severity"] == "critical"
    assert findings[1]["severity"] == "medium"
    # Each finding record carries the stable id and OWASP mapping
    assert findings[0]["id"] == "f-bbbb"
    assert findings[0]["owasp"] == "LLM01:2025"


def test_pagerduty_custom_details_severity_counts_match_findings():
    """severity_counts is a roll-up the incident UI can render at a glance.
    It must match the actual finding distribution."""
    details = _payload(_two_finding_result())["payload"]["custom_details"]
    assert details["severity_counts"] == {"critical": 1, "medium": 1}


def test_pagerduty_zero_finding_run_emits_resolve_event():
    """A clean run must emit ``event_action: resolve`` against the SAME
    dedup_key a prior trigger would have used, so PagerDuty auto-closes the
    previous incident — the standard 'alert' / 'no longer alert' pairing
    PagerDuty's own integrations (Datadog, Prometheus Alertmanager,
    Nagios) follow. The Events API v2 spec says a resolve event needs only
    routing_key + event_action + dedup_key; we intentionally do NOT emit a
    `payload` block on resolve."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=3,
    )
    payload = _payload(result)
    assert payload["event_action"] == "resolve"
    assert payload["routing_key"] == "YOUR_PAGERDUTY_ROUTING_KEY"
    assert "dedup_key" in payload
    # The resolve event must use the SAME dedup_key as a trigger against the
    # same target+attack-set — otherwise auto-resolve doesn't actually close
    # the prior incident.
    trigger = _payload(_two_finding_result())
    assert payload["dedup_key"] == trigger["dedup_key"]
    # And a resolve has no payload block.
    assert "payload" not in payload


def test_pagerduty_client_field_identifies_the_tool():
    """`client` shows up in the PagerDuty incident header as 'Reported by';
    identifying ouija + version makes the incident self-describing without
    the triager having to read custom_details first."""
    payload = _payload(_two_finding_result())
    assert "client" in payload
    assert "ouija" in payload["client"]
    assert "9.9.9" in payload["client"]


def test_pagerduty_routing_key_is_placeholder_never_a_real_key():
    """ouija MUST NOT read a routing key from env or argv — the operator
    substitutes the placeholder before piping into curl. This keeps the
    integration key off the ouija command line and out of the scan
    artifact. If a future refactor changes this, this test fails loudly."""
    payload = _payload(_two_finding_result())
    assert payload["routing_key"] == "YOUR_PAGERDUTY_ROUTING_KEY"


def test_pagerduty_payload_is_indented_for_human_inspection():
    """All other --format outputs that emit JSON (json, sarif, slack) are
    indented for human inspection, not minified. The PagerDuty payload is
    no exception — operators read it before substituting the routing key
    and piping it into curl."""
    raw = to_pagerduty(_two_finding_result())
    # An indented JSON document contains newlines; a minified one doesn't.
    assert "\n" in raw
    # And it round-trips through json.loads cleanly.
    json.loads(raw)


def test_pagerduty_format_is_accepted_by_cli(tmp_path, monkeypatch, capsys):
    """End-to-end: `--format pagerduty` is a valid choice on the CLI parser,
    runs through `--plan` (so we don't have to mock a target endpoint), and
    --plan with a non-json format prints a human-readable summary (not the
    PagerDuty payload) — same contract every prior non-json format honours."""
    scope = tmp_path / "scope.txt"
    scope.write_text("https://example.test/\n")
    rc = main(
        [
            "--target",
            "https://example.test/llm",
            "--scope-file",
            str(scope),
            "--format",
            "pagerduty",
            "--plan",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    # --plan with a non-json format prints a readable summary; the
    # pagerduty payload itself is exercised by the to_pagerduty unit tests
    # above (a --plan with --format json would emit the JSON plan).
    assert "ouija" in out.lower() or "plan" in out.lower()
