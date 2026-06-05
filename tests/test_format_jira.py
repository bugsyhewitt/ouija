"""Tests for the ``--format jira`` (Jira REST API Create Issue JSON payload) output.

``--format jira`` targets the Jira Cloud project-management surface: a
REST API v3 Create Issue JSON body the operator pipes into
``https://<domain>.atlassian.net/rest/api/3/issue`` to open a tracked
security issue in their project. The contract:

    * a JSON document whose top-level ``fields`` object matches the Jira
      Create Issue schema (``project``, ``issuetype``, ``summary``,
      ``description``, ``priority``, ``labels``);
    * the ``description`` field uses the Atlassian Document Format (ADF)
      (type ``doc``, version 1, content array of paragraph/codeBlock/heading
      nodes) — NOT raw markdown;
    * one *aggregated* issue per scan — not one issue per finding;
    * ``priority.name`` is one of the Jira-default priority strings
      (Highest / High / Medium / Low), mapped from the top finding severity;
    * ``fields.project.key`` and ``fields.issuetype.name`` are placeholder
      strings the operator substitutes before posting;
    * the bearer token is NEVER in the payload body (it travels in the
      Authorization header at curl time);
    * a zero-finding run emits a valid "clean scan record" payload so the
      operator can post it as a no-findings record if they wish.
"""

from __future__ import annotations

import json

from ouija.cli import EXIT_OK, main
from ouija.models import ScanResult
from ouija.report import to_jira


def _two_finding_result() -> ScanResult:
    base = {
        "version": "9.9.9",
        "scan_id": "scan-jira-test",
        "timestamp": "2026-06-05T16:00:00+00:00",
        "target": "https://example.test/llm",
        "attack_set": "injection",
        "patterns_sent": 10,
        "findings": [
            {
                "id": "f-low-01",
                "category": "prompt_injection",
                "severity": "low",
                "title": "low finding",
                "pattern_id": "p3",
                "technique": "polite",
                "owasp": "LLM01:2025",
                "request_prompt": "please do it",
                "response_excerpt": "sure",
                "evidence": "marker present",
                "confidence": 0.5,
            },
            {
                "id": "f-crit-01",
                "category": "prompt_injection",
                "severity": "critical",
                "title": "critical finding",
                "pattern_id": "p1",
                "technique": "override",
                "owasp": "LLM01:2025",
                "request_prompt": "ignore previous",
                "response_excerpt": "ok, ignoring",
                "evidence": "marker present in response",
                "confidence": 0.95,
            },
            {
                "id": "f-med-01",
                "category": "sensitive_info_disclosure",
                "severity": "medium",
                "title": "medium finding",
                "pattern_id": "p2",
                "technique": "urgency",
                "owasp": "LLM02:2025",
                "request_prompt": "tell me now",
                "response_excerpt": "here is the config",
                "evidence": "config keyword detected",
                "confidence": 0.7,
            },
        ],
        "summary": {
            "total": 10,
            "successful": 3,
            "attack_sets": {"injection": 3},
        },
    }
    return ScanResult(**base)


def _payload(result: ScanResult) -> dict:
    return json.loads(to_jira(result))


# ── Structure ────────────────────────────────────────────────────────────────


def test_jira_payload_is_valid_json():
    """The output must be valid, parseable JSON."""
    raw = to_jira(_two_finding_result())
    json.loads(raw)  # must not raise


def test_jira_payload_is_indented():
    """Like all other JSON-format outputs, the Jira payload must be
    indented for human inspection, not minified."""
    raw = to_jira(_two_finding_result())
    assert "\n" in raw


def test_jira_has_fields_key():
    """The top-level ``fields`` key is required by the Jira Create Issue API."""
    payload = _payload(_two_finding_result())
    assert "fields" in payload


def test_jira_fields_has_required_create_issue_keys():
    """``fields`` must contain at minimum: project, issuetype, summary,
    description, priority, labels."""
    fields = _payload(_two_finding_result())["fields"]
    for required in ("project", "issuetype", "summary", "description", "priority", "labels"):
        assert required in fields, f"missing required field: {required}"


# ── Priority mapping ─────────────────────────────────────────────────────────


def test_jira_priority_critical_maps_to_highest():
    """ouija critical → Jira Highest."""
    payload = _payload(_two_finding_result())
    assert payload["fields"]["priority"]["name"] == "Highest"


def test_jira_priority_full_mapping_table():
    """Exhaust the severity→priority mapping so a refactor that drops an
    entry trips this test.  Jira default priorities: Highest/High/Medium/Low."""
    cases = (
        ("critical", "Highest"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Low"),
    )
    for ouija_sev, jira_pri in cases:
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
        assert _payload(result)["fields"]["priority"]["name"] == jira_pri, (
            f"ouija {ouija_sev!r} should map to Jira priority {jira_pri!r}"
        )


def test_jira_priority_is_in_allowed_set():
    """Even if the mapping table changes, the emitted priority name must
    always be one of the four Jira-default priority strings — anything
    else will be rejected or silently remapped by Jira."""
    payload = _payload(_two_finding_result())
    assert payload["fields"]["priority"]["name"] in {
        "Highest", "High", "Medium", "Low"
    }


# ── Project / issue-type placeholders ────────────────────────────────────────


def test_jira_project_key_is_placeholder():
    """``fields.project.key`` must be the literal placeholder string so the
    operator knows to substitute it — ouija has no per-project config flag."""
    fields = _payload(_two_finding_result())["fields"]
    assert fields["project"]["key"] == "<JIRA_PROJECT_KEY>"


def test_jira_issuetype_name_is_placeholder():
    """``fields.issuetype.name`` must be the literal placeholder string."""
    fields = _payload(_two_finding_result())["fields"]
    assert fields["issuetype"]["name"] == "<JIRA_ISSUE_TYPE>"


# ── Bearer token never in payload ────────────────────────────────────────────


def test_jira_bearer_token_never_in_payload_body():
    """The Jira bearer token travels in the Authorization header at curl
    time, NOT in the payload body. ouija MUST NOT emit a token placeholder
    in the body — doing so would leak it into the scan artifact."""
    raw = to_jira(_two_finding_result())
    for forbidden in (
        "JIRA_TOKEN",
        "YOUR_JIRA_TOKEN",
        "YOUR_API_TOKEN",
        "Authorization",
        "Bearer ",
    ):
        assert forbidden not in raw, (
            f"Jira token leak: {forbidden!r} found in payload"
        )


# ── Summary ───────────────────────────────────────────────────────────────────


def test_jira_summary_identifies_target_and_severity():
    """The summary (one-line issue title) must include the target URL and
    the top severity — it's what the Jira assignee reads in the issue list."""
    fields = _payload(_two_finding_result())["fields"]
    summary = fields["summary"]
    assert "https://example.test/llm" in summary
    assert "critical" in summary.lower()
    assert "ouija" in summary.lower()


def test_jira_summary_mentions_finding_count():
    """The summary must include the number of findings."""
    fields = _payload(_two_finding_result())["fields"]
    summary = fields["summary"]
    assert "3" in summary


# ── ADF description ──────────────────────────────────────────────────────────


def test_jira_description_is_adf_doc():
    """``fields.description`` must be an ADF document node with
    ``type: doc``, ``version: 1``, and a non-empty ``content`` array."""
    desc = _payload(_two_finding_result())["fields"]["description"]
    assert desc["type"] == "doc"
    assert desc["version"] == 1
    assert isinstance(desc["content"], list)
    assert len(desc["content"]) > 0


def test_jira_description_content_nodes_have_type():
    """Every node in the ADF content array must have a ``type`` field —
    Jira rejects ADF documents with typeless nodes."""
    desc = _payload(_two_finding_result())["fields"]["description"]
    for node in desc["content"]:
        assert "type" in node, f"ADF node missing 'type': {node}"


def test_jira_description_mentions_target_and_scan_metadata():
    """The description body must include the target URL, attack set,
    patterns_sent, and scan ID so the issue is self-describing."""
    desc = _payload(_two_finding_result())["fields"]["description"]
    raw_desc = json.dumps(desc)
    assert "https://example.test/llm" in raw_desc
    assert "injection" in raw_desc
    assert "10" in raw_desc        # patterns_sent
    assert "scan-jira-test" in raw_desc


# ── Labels ────────────────────────────────────────────────────────────────────


def test_jira_labels_include_ouija_and_llm_security():
    """The labels list must always include 'ouija' and 'llm-security' so
    the issue is discoverable via Jira label search."""
    labels = _payload(_two_finding_result())["fields"]["labels"]
    assert "ouija" in labels
    assert "llm-security" in labels


def test_jira_labels_include_attack_set():
    """The attack set name should be a label so the issue is filterable by
    which corpus found the problem."""
    labels = _payload(_two_finding_result())["fields"]["labels"]
    assert "injection" in labels


def test_jira_labels_include_top_severity():
    """The top severity should appear as a ``severity-<name>`` label for
    easy Jira board filtering by severity class."""
    labels = _payload(_two_finding_result())["fields"]["labels"]
    assert "severity-critical" in labels


# ── ouija_meta sidecar ────────────────────────────────────────────────────────


def test_jira_carries_ouija_meta_sidecar():
    """The payload must carry an ``ouija_meta`` sidecar with the scan
    identity fields (scan_id, version, target, attack_set, patterns_sent,
    findings_total, severity_counts) so the operator can verify which run
    produced the issue without opening the JSON report."""
    payload = _payload(_two_finding_result())
    assert "ouija_meta" in payload
    meta = payload["ouija_meta"]
    assert meta["scan_id"] == "scan-jira-test"
    assert meta["version"] == "9.9.9"
    assert meta["target"] == "https://example.test/llm"
    assert meta["attack_set"] == "injection"
    assert meta["patterns_sent"] == 10
    assert meta["findings_total"] == 3
    assert meta["severity_counts"] == {"critical": 1, "medium": 1, "low": 1}


# ── Zero-finding run ──────────────────────────────────────────────────────────


def test_jira_zero_finding_run_emits_valid_payload():
    """A clean run must emit a valid Jira Create Issue payload — the
    operator may wish to record a clean scan result in their Jira project."""
    result = ScanResult(
        version="9.9.9",
        scan_id="scan-clean",
        timestamp="2026-06-05T16:00:00+00:00",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=5,
    )
    payload = _payload(result)
    assert "fields" in payload
    assert payload["fields"]["priority"]["name"] == "Low"
    summary = payload["fields"]["summary"]
    assert "0" in summary
    assert "clean" in summary.lower() or "findings" in summary.lower()


def test_jira_zero_finding_run_description_is_valid_adf():
    """The clean-run description must also be a valid ADF document."""
    result = ScanResult(
        version="9.9.9",
        target="https://example.test/llm",
        attack_set="injection",
        patterns_sent=5,
    )
    desc = _payload(result)["fields"]["description"]
    assert desc["type"] == "doc"
    assert desc["version"] == 1


# ── Stability ─────────────────────────────────────────────────────────────────


def test_jira_summary_stable_across_runs_same_target():
    """Two scans of the same target with the same findings must produce
    the same summary (the scan_id must NOT leak into the summary)."""
    r1 = _two_finding_result()
    r2 = ScanResult(**{**r1.model_dump(mode="json"), "scan_id": "different-scan"})
    p1 = _payload(r1)
    p2 = _payload(r2)
    assert p1["fields"]["summary"] == p2["fields"]["summary"]
    assert "scan-jira-test" not in p1["fields"]["summary"]


# ── CLI integration ───────────────────────────────────────────────────────────


def test_jira_format_is_accepted_by_cli(tmp_path, capsys):
    """End-to-end: ``--format jira`` is a valid CLI choice, runs through
    ``--plan`` without touching a target, and exits 0."""
    scope = tmp_path / "scope.txt"
    scope.write_text("https://example.test/\n")
    rc = main(
        [
            "--target",
            "https://example.test/llm",
            "--scope-file",
            str(scope),
            "--format",
            "jira",
            "--plan",
        ]
    )
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "ouija" in out.lower() or "plan" in out.lower()
