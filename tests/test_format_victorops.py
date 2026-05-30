"""Tests for the ``--format victorops`` (VictorOps / Splunk On-Call REST
integration payload) output.

Where ``--format pagerduty`` targets PagerDuty's Events API v2 and
``--format opsgenie`` targets OpsGenie's Alert API v2, ``--format victorops``
is the VictorOps / Splunk On-Call on-call / incident-response surface: a
REST-integration-shaped JSON document the operator pipes straight into
``https://alert.victorops.com/integrations/generic/20131114/alert/<api-key>/<routing-key>``
to page whoever owns the LLM endpoint. The contract:

    * a JSON document whose top-level keys match the VictorOps REST
      integration schema (``message_type`` + ``entity_id`` plus the
      strongly-recommended ``entity_display_name`` / ``state_message`` /
      ``state_start_time`` / ``monitoring_tool`` set, with per-finding
      structured detail under additional documented keys);
    * one *aggregated* event per scan — not one event per finding —
      because VictorOps' incident model is alert-per-symptom (same rule
      as ``--format pagerduty`` / ``--format opsgenie``);
    * ``message_type`` is one of the five VictorOps-accepted strings
      (``CRITICAL`` / ``WARNING`` / ``INFO`` / ``ACKNOWLEDGEMENT`` /
      ``RECOVERY``), mapped from the *highest* finding severity in the
      run (or ``RECOVERY`` on a zero-finding rerun, to auto-close);
    * ``entity_id`` is stable across reruns of the same target+attack-set
      (so re-scanning updates the same incident, not floods a new one);
    * ``state_start_time`` is the epoch-seconds form of the scan timestamp
      (VictorOps documents the field as epoch seconds);
    * a zero-finding run emits a RECOVERY message against the same
      ``entity_id`` — the standard VictorOps "alert" / "no longer alert"
      pairing;
    * the API key + routing key are NEVER in the payload body (they travel
      in the integration URL at curl time, so neither key lands in the
      ouija command line, the scan artifact, or the log stream).
"""

from __future__ import annotations

import json

from ouija.cli import EXIT_OK, main
from ouija.models import ScanResult
from ouija.report import to_victorops


def _two_finding_result() -> ScanResult:
    base = {
        "version": "9.9.9",
        "scan_id": "scan-xyz",
        "timestamp": "2026-05-29T12:00:00+00:00",
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
    return json.loads(to_victorops(result))


def test_victorops_payload_is_valid_json_with_rest_integration_shape():
    """Top-level keys must match the VictorOps REST integration schema:
    message_type + entity_id + entity_display_name + state_message +
    state_start_time + monitoring_tool are all present on a trigger
    payload."""
    payload = _payload(_two_finding_result())
    for required in (
        "message_type",
        "entity_id",
        "entity_display_name",
        "state_message",
        "state_start_time",
        "monitoring_tool",
    ):
        assert required in payload, f"missing required field: {required}"
    assert isinstance(payload["message_type"], str)
    assert isinstance(payload["entity_id"], str) and payload["entity_id"]
    assert isinstance(payload["entity_display_name"], str)
    assert isinstance(payload["state_message"], str)


def test_victorops_message_type_maps_from_top_finding_critical():
    """message_type must be one of the five VictorOps-accepted strings,
    driven by the *highest* finding severity in the run. A critical
    ouija finding maps to VictorOps CRITICAL."""
    payload = _payload(_two_finding_result())
    assert payload["message_type"] == "CRITICAL"


def test_victorops_message_type_full_mapping_table():
    """Exhaust the severity→message_type mapping table so a later refactor
    that drops an entry trips this test instead of producing an event
    VictorOps silently drops. VictorOps' three-bucket alert scale collapses
    ouija's five-bucket severity scale: critical/high→CRITICAL,
    medium→WARNING, low/info→INFO."""
    cases = (
        ("critical", "CRITICAL"),
        ("high", "CRITICAL"),
        ("medium", "WARNING"),
        ("low", "INFO"),
        ("info", "INFO"),
    )
    for ouija_sev, vo_type in cases:
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
        assert _payload(result)["message_type"] == vo_type, (
            f"ouija {ouija_sev} should map to VictorOps {vo_type}"
        )


def test_victorops_message_type_is_in_allowed_set():
    """Even if the mapping table changes, the emitted message_type must
    always be one of the five VictorOps-accepted strings — anything else
    is silently dropped by the VictorOps REST endpoint."""
    payload = _payload(_two_finding_result())
    assert payload["message_type"] in {
        "CRITICAL",
        "WARNING",
        "INFO",
        "ACKNOWLEDGEMENT",
        "RECOVERY",
    }


def test_victorops_entity_id_is_stable_across_runs():
    """Two scans of the same target + attack-set must produce the SAME
    entity_id so VictorOps collapses them into one incident (instead of
    opening a fresh one per rerun). The per-run random scan_id must NOT
    leak into the entity_id."""
    r1 = _two_finding_result()
    r2 = ScanResult(**{**r1.model_dump(mode="json"), "scan_id": "different-scan"})
    p1 = _payload(r1)
    p2 = _payload(r2)
    assert p1["entity_id"] == p2["entity_id"]
    assert "scan-xyz" not in p1["entity_id"]
    assert "https://example.test/llm" in p1["entity_id"]
    assert "injection" in p1["entity_id"]


def test_victorops_entity_id_differs_across_targets_and_attack_sets():
    """Different target OR different attack-set must produce a DIFFERENT
    entity_id — otherwise scanning two endpoints would collide their
    incidents into one."""
    base = _two_finding_result()
    other_target = ScanResult(
        **{**base.model_dump(mode="json"), "target": "https://other.test/llm"}
    )
    other_set = ScanResult(
        **{**base.model_dump(mode="json"), "attack_set": "exfil"}
    )
    assert _payload(base)["entity_id"] != _payload(other_target)["entity_id"]
    assert _payload(base)["entity_id"] != _payload(other_set)["entity_id"]


def test_victorops_state_start_time_is_epoch_seconds_integer():
    """VictorOps documents `state_start_time` as epoch seconds (an integer
    Unix timestamp). Emitting an ISO string or a millisecond timestamp
    there is silently coerced or rejected — keep it as a plain int second
    count derived from the scan's ISO timestamp."""
    payload = _payload(_two_finding_result())
    assert isinstance(payload["state_start_time"], int)
    # 2026-05-29T12:00:00+00:00 → 1780056000 epoch seconds.
    assert payload["state_start_time"] == 1780056000


def test_victorops_monitoring_tool_identifies_ouija():
    """`monitoring_tool` shows up in the VictorOps incident as the
    reporter ('Monitoring Tool'). Identifying ouija + version makes the
    incident self-describing without the on-call having to open
    custom details first."""
    payload = _payload(_two_finding_result())
    assert "ouija" in payload["monitoring_tool"]
    assert "9.9.9" in payload["monitoring_tool"]


def test_victorops_entity_display_name_identifies_the_scan():
    """`entity_display_name` is the at-a-glance incident title that
    lands in the on-call's notification list. It must identify the
    target and surface the finding count + top severity."""
    payload = _payload(_two_finding_result())
    name = payload["entity_display_name"]
    assert "ouija" in name.lower()
    assert "https://example.test/llm" in name
    assert "critical" in name.lower()


def test_victorops_state_message_carries_long_form_detail():
    """`state_message` is the long-form digest the on-call reads in the
    incident detail pane. It must include the target, the attack set,
    the finding count, the request count, and the severity breakdown."""
    payload = _payload(_two_finding_result())
    msg = payload["state_message"]
    assert "https://example.test/llm" in msg
    assert "injection" in msg
    assert "7" in msg  # patterns_sent
    assert "2" in msg  # findings count
    assert "critical" in msg.lower()


def test_victorops_carries_per_finding_breakdown():
    """The on-call needs the per-finding breakdown in the incident
    detail pane. VictorOps accepts arbitrary additional keys and
    surfaces them in the incident timeline, so the per-finding records
    are emitted under `ouija_findings` (severity-sorted, critical
    first, with the same id/category/owasp/severity each other format
    surfaces)."""
    payload = _payload(_two_finding_result())
    assert "ouija_findings" in payload
    findings = payload["ouija_findings"]
    assert len(findings) == 2
    assert findings[0]["severity"] == "critical"
    assert findings[1]["severity"] == "medium"
    assert findings[0]["id"] == "f-bbbb"
    assert findings[0]["owasp"] == "LLM01:2025"


def test_victorops_carries_severity_counts_rollup():
    """`ouija_severity_counts` is a roll-up the incident detail can
    render at a glance. It must match the actual finding distribution."""
    payload = _payload(_two_finding_result())
    assert payload["ouija_severity_counts"] == {"critical": 1, "medium": 1}


def test_victorops_carries_scan_metadata():
    """The scan-identity metadata (tool, version, scan_id, attack_set,
    patterns_sent) must be carried on the payload so the on-call can
    correlate the page back to a specific ouija run without re-deriving
    it from the JSON report."""
    payload = _payload(_two_finding_result())
    assert payload["ouija_scan_id"] == "scan-xyz"
    assert payload["ouija_attack_set"] == "injection"
    assert payload["ouija_patterns_sent"] == 7
    assert payload["ouija_version"] == "9.9.9"


def test_victorops_zero_finding_run_emits_recovery_payload():
    """A clean run must emit a RECOVERY message against the SAME
    entity_id an earlier trigger would have used, so VictorOps
    auto-closes the previous incident — the standard 'alert' / 'no
    longer alert' pairing (matches the PagerDuty `event_action: resolve`
    and OpsGenie Close-Alert rules)."""
    result = ScanResult(
        version="9.9.9",
        scan_id="scan-clean",
        timestamp="2026-05-29T12:00:00+00:00",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=3,
    )
    payload = _payload(result)
    assert payload["message_type"] == "RECOVERY"
    assert "entity_id" in payload
    # The recovery entity_id must match what a trigger would have used —
    # otherwise auto-close does not actually close the prior incident.
    trigger = _payload(_two_finding_result())
    assert payload["entity_id"] == trigger["entity_id"]


def test_victorops_api_key_and_routing_key_never_in_payload_body():
    """The VictorOps API key + routing key both travel in the integration
    URL at curl time, NOT in the body. ouija MUST NOT smuggle either key
    or a placeholder for either key into the body anywhere, so neither
    key lands in the scan artifact or log stream. If a future refactor
    changes this, this test fails loudly."""
    raw = to_victorops(_two_finding_result())
    for forbidden in (
        "VICTOROPS_API_KEY",
        "YOUR_VICTOROPS_KEY",
        "YOUR_API_KEY",
        "YOUR_ROUTING_KEY",
        "api_key",
        "routing_key",
    ):
        assert forbidden not in raw, (
            f"VictorOps key leak: {forbidden!r} found in payload"
        )


def test_victorops_payload_is_indented_for_human_inspection():
    """All other --format outputs that emit JSON (json, sarif, slack,
    pagerduty, opsgenie) are indented for human inspection, not minified.
    The VictorOps payload is no exception — operators read it before
    piping it into curl."""
    raw = to_victorops(_two_finding_result())
    assert "\n" in raw
    json.loads(raw)


def test_victorops_recovery_payload_is_also_indented_and_valid_json():
    """The clean-run RECOVERY payload must also round-trip through
    json.loads cleanly and be indented for human inspection — same
    contract the trigger payload honours."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=3,
    )
    raw = to_victorops(result)
    assert "\n" in raw
    json.loads(raw)


def test_victorops_format_is_accepted_by_cli(tmp_path, capsys):
    """End-to-end: `--format victorops` is a valid choice on the CLI
    parser, runs through `--plan` (so we don't have to mock a target
    endpoint), and --plan with a non-json format prints a human-readable
    summary (not the VictorOps payload) — same contract every prior
    non-json format honours."""
    scope = tmp_path / "scope.txt"
    scope.write_text("https://example.test/\n")
    rc = main(
        [
            "--target",
            "https://example.test/llm",
            "--scope-file",
            str(scope),
            "--format",
            "victorops",
            "--plan",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "ouija" in out.lower() or "plan" in out.lower()
