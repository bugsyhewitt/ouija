"""Tests for the ``--format opsgenie`` (OpsGenie Alert API v2 create-alert
payload) output.

Where ``--format pagerduty`` targets PagerDuty's Events API v2 and
``--format slack`` is the chat-channel alert, ``--format opsgenie`` is the
OpsGenie on-call / incident-response surface: a Create-Alert-shaped JSON
document the operator pipes straight into
``https://api.opsgenie.com/v2/alerts`` (with an
``Authorization: GenieKey <key>`` header). The contract:

    * a JSON document whose top-level keys match the OpsGenie Create-Alert
      schema (``message`` + optional ``alias`` / ``description`` /
      ``priority`` / ``source`` / ``entity`` / ``tags`` / ``details`` /
      ``note``);
    * one *aggregated* alert per scan — not one alert per finding —
      because OpsGenie's alert model is alert-per-symptom (same rule as
      ``--format pagerduty``);
    * ``priority`` is one of the five OpsGenie-accepted strings
      (``P1`` / ``P2`` / ``P3`` / ``P4`` / ``P5``), mapped 1:1 from the
      *highest* finding severity in the run;
    * ``message`` fits OpsGenie's 130-char hard cap;
    * ``alias`` fits the 512-char hard cap and is stable across reruns of
      the same target+attack-set (so re-scanning updates the same alert,
      not floods a new one);
    * ``description`` fits the 15000-char hard cap;
    * ``details`` is a string→string map (per the OpsGenie schema — every
      value must be a string, not an int / bool / object);
    * a zero-finding run emits a Close-Alert-shaped payload against the
      same alias (auto-closes the prior alert — the standard OpsGenie
      "alert" / "no longer alert" pairing);
    * the GenieKey is NEVER in the payload body (it travels in the
      ``Authorization: GenieKey <key>`` HTTP header at curl time, so the
      key never lands in the ouija command line, the scan artifact, or the
      log stream).
"""

from __future__ import annotations

import json

from ouija.cli import EXIT_OK, main
from ouija.models import ScanResult
from ouija.report import to_opsgenie


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
    return json.loads(to_opsgenie(result))


def test_opsgenie_payload_is_valid_json_with_create_alert_shape():
    """Top-level keys must match the OpsGenie Create-Alert schema:
    message + alias + description + priority + source + entity + tags +
    details + note are all present on a trigger payload."""
    payload = _payload(_two_finding_result())
    for required in (
        "message",
        "alias",
        "description",
        "priority",
        "source",
        "entity",
        "tags",
        "details",
    ):
        assert required in payload, f"missing required field: {required}"
    assert isinstance(payload["message"], str) and payload["message"]
    assert isinstance(payload["alias"], str) and payload["alias"]
    assert isinstance(payload["tags"], list)
    assert isinstance(payload["details"], dict)


def test_opsgenie_priority_maps_from_top_finding_critical():
    """Priority must be one of the five OpsGenie-accepted strings
    (P1..P5), driven by the *highest* finding severity in the run.
    A critical ouija finding maps to OpsGenie P1."""
    payload = _payload(_two_finding_result())
    assert payload["priority"] == "P1"


def test_opsgenie_priority_full_mapping_table():
    """Exhaust the severity→priority mapping table so a later refactor
    that drops an entry trips this test instead of producing an alert
    OpsGenie silently rejects with HTTP 422. Mapping is 1:1 (both scales
    are five-bucket): critical→P1, high→P2, medium→P3, low→P4, info→P5."""
    cases = (
        ("critical", "P1"),
        ("high", "P2"),
        ("medium", "P3"),
        ("low", "P4"),
        ("info", "P5"),
    )
    for ouija_sev, og_priority in cases:
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
        assert _payload(result)["priority"] == og_priority, (
            f"ouija {ouija_sev} should map to OpsGenie {og_priority}"
        )


def test_opsgenie_priority_is_in_allowed_set():
    """Even if the mapping table changes, the emitted priority must always
    be one of the five OpsGenie-accepted strings — anything else makes
    the create call fail with HTTP 422."""
    payload = _payload(_two_finding_result())
    assert payload["priority"] in {"P1", "P2", "P3", "P4", "P5"}


def test_opsgenie_message_fits_130_char_cap():
    """OpsGenie rejects alerts whose message exceeds 130 chars. Even with
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
    assert len(_payload(result)["message"]) <= 130


def test_opsgenie_alias_fits_512_char_cap():
    """OpsGenie's `alias` field is hard-capped at 512 characters. The
    dedup behaviour relies on the alias matching exactly across reruns,
    so the alias must fit deterministically within the cap."""
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
    assert len(_payload(result)["alias"]) <= 512


def test_opsgenie_description_fits_15000_char_cap():
    """OpsGenie's `description` field is hard-capped at 15000 chars; the
    create call fails for anything larger."""
    payload = _payload(_two_finding_result())
    assert len(payload["description"]) <= 15000


def test_opsgenie_alias_is_stable_across_runs():
    """Two scans of the same target + attack-set must produce the SAME
    alias so OpsGenie collapses them into one alert (instead of opening
    a fresh alert on every rerun). The per-run random scan_id must NOT
    leak into the alias."""
    r1 = _two_finding_result()
    r2 = ScanResult(**{**r1.model_dump(mode="json"), "scan_id": "different-scan"})
    p1 = _payload(r1)
    p2 = _payload(r2)
    assert p1["alias"] == p2["alias"]
    assert "scan-xyz" not in p1["alias"]
    assert "https://example.test/llm" in p1["alias"]
    assert "injection" in p1["alias"]


def test_opsgenie_alias_differs_across_targets_and_attack_sets():
    """Different target OR different attack-set must produce a DIFFERENT
    alias — otherwise scanning two endpoints would collide their alerts
    into one."""
    base = _two_finding_result()
    other_target = ScanResult(
        **{**base.model_dump(mode="json"), "target": "https://other.test/llm"}
    )
    other_set = ScanResult(
        **{**base.model_dump(mode="json"), "attack_set": "exfil"}
    )
    assert _payload(base)["alias"] != _payload(other_target)["alias"]
    assert _payload(base)["alias"] != _payload(other_set)["alias"]


def test_opsgenie_details_is_string_to_string_map():
    """OpsGenie's `details` field is documented as a string→string map.
    Emitting a raw int / bool / nested object there is silently dropped
    or rejected by some accounts — every value must be a string."""
    details = _payload(_two_finding_result())["details"]
    for key, value in details.items():
        assert isinstance(key, str), f"non-string key: {key!r}"
        assert isinstance(value, str), (
            f"details[{key!r}] is {type(value).__name__}, must be str "
            "(OpsGenie details map is string→string)"
        )


def test_opsgenie_details_carries_per_finding_breakdown():
    """The on-call needs the per-finding breakdown in the alert detail
    pane — that lives under details.findings as a JSON-encoded string
    (because `details` must be string→string), severity-sorted, with
    the same id/category/owasp/severity each other format surfaces."""
    details = _payload(_two_finding_result())["details"]
    assert details["findings_total"] == "2"
    assert details["attack_set"] == "injection"
    assert details["patterns_sent"] == "7"
    findings = json.loads(details["findings"])
    assert len(findings) == 2
    assert findings[0]["severity"] == "critical"
    assert findings[1]["severity"] == "medium"
    assert findings[0]["id"] == "f-bbbb"
    assert findings[0]["owasp"] == "LLM01:2025"


def test_opsgenie_details_severity_counts_match_findings():
    """severity_counts (JSON-encoded into the details map) is a roll-up
    the alert UI can render at a glance. It must match the actual finding
    distribution."""
    details = _payload(_two_finding_result())["details"]
    counts = json.loads(details["severity_counts"])
    assert counts == {"critical": 1, "medium": 1}


def test_opsgenie_tags_include_tool_attack_set_severity_and_owasp():
    """Tags surface as triage pills in the OpsGenie alert list. They
    must include the tool name, the attack set, the top severity, and
    each distinct OWASP category present."""
    tags = _payload(_two_finding_result())["tags"]
    assert "ouija" in tags
    assert "attack-set:injection" in tags
    assert "top-severity:critical" in tags
    assert "LLM01:2025" in tags


def test_opsgenie_zero_finding_run_emits_close_payload():
    """A clean run must emit a Close-Alert payload against the SAME
    alias an earlier create would have used, so OpsGenie auto-closes
    the previous alert — the standard 'alert' / 'no longer alert'
    pairing (matches the PagerDuty `event_action: resolve` rule).

    The Close-Alert endpoint accepts only `note` / `user` / `source` in
    the body (the alias travels in the URL), so the emitted document is
    deliberately minimal: it MUST NOT carry `message` / `priority` /
    `description` / `tags` / `details` (those are Create-Alert-only
    fields, and their presence on a close call is either ignored or
    rejected depending on tenant configuration). We DO include `alias`
    in the body even though the close endpoint expects it in the URL,
    so the operator can substitute it into the URL with a single
    `jq -r .alias` without re-deriving it."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=3,
    )
    payload = _payload(result)
    assert "alias" in payload
    assert "note" in payload
    assert "source" in payload
    for create_only_field in ("message", "priority", "description", "tags", "details"):
        assert create_only_field not in payload, (
            f"close payload must not carry the Create-Alert-only field "
            f"{create_only_field!r}"
        )
    # The close alias must match what a trigger would have used —
    # otherwise auto-close does not actually close the prior alert.
    trigger = _payload(_two_finding_result())
    assert payload["alias"] == trigger["alias"]


def test_opsgenie_genie_key_is_never_in_the_payload_body():
    """The OpsGenie GenieKey travels in the `Authorization: GenieKey
    <key>` HTTP header at curl time, NOT in the body — unlike the
    PagerDuty `routing_key` which IS a body field. ouija MUST NOT
    smuggle a GenieKey or a GenieKey placeholder into the body anywhere,
    so the key never lands in the scan artifact or log stream. If a
    future refactor changes this, this test fails loudly."""
    raw = to_opsgenie(_two_finding_result())
    # Any GenieKey-shaped substring (the auth scheme name itself)
    # appearing in the body means we've leaked the key surface.
    assert "GenieKey" not in raw
    # And the literal API-key placeholder forms must not appear either.
    for forbidden in ("OPSGENIE_API_KEY", "YOUR_OPSGENIE_KEY", "api_key"):
        assert forbidden not in raw, f"GenieKey leak: {forbidden!r} found in payload"


def test_opsgenie_source_and_entity_identify_the_scan():
    """`source` shows up in the OpsGenie alert as the reporter ('Reported
    by'), and `entity` is the thing the alert is about. Identifying ouija
    + version as source and the target URL as entity makes the alert
    self-describing without the triager having to open `details` first."""
    payload = _payload(_two_finding_result())
    assert "ouija" in payload["source"]
    assert "9.9.9" in payload["source"]
    assert payload["entity"] == "https://example.test/llm"


def test_opsgenie_payload_is_indented_for_human_inspection():
    """All other --format outputs that emit JSON (json, sarif, slack,
    pagerduty) are indented for human inspection, not minified. The
    OpsGenie payload is no exception — operators read it before piping
    it into curl."""
    raw = to_opsgenie(_two_finding_result())
    assert "\n" in raw
    json.loads(raw)


def test_opsgenie_close_payload_is_also_indented_and_valid_json():
    """The clean-run Close-Alert payload must also round-trip through
    json.loads cleanly and be indented for human inspection — same
    contract the trigger payload honours."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=3,
    )
    raw = to_opsgenie(result)
    assert "\n" in raw
    json.loads(raw)


def test_opsgenie_format_is_accepted_by_cli(tmp_path, capsys):
    """End-to-end: `--format opsgenie` is a valid choice on the CLI
    parser, runs through `--plan` (so we don't have to mock a target
    endpoint), and --plan with a non-json format prints a human-readable
    summary (not the OpsGenie payload) — same contract every prior
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
            "opsgenie",
            "--plan",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "ouija" in out.lower() or "plan" in out.lower()
