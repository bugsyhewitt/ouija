"""SARIF 2.1.0 report rendering.

SARIF (Static Analysis Results Interchange Format, OASIS standard 2.1.0) is the
lingua franca of security-tooling CI integration: GitHub Advanced Security's
code-scanning, Azure DevOps, and most aggregation dashboards ingest SARIF
directly. ouija already gates a pipeline with ``--fail-on`` (exit non-zero on a
finding); SARIF is the companion that lets the same run *upload* its findings so
they surface as code-scanning alerts with severity, rule documentation, and the
OWASP LLM Top-10 mapping — no bespoke parsing of ouija's native JSON required.

This module is a pure function over a :class:`~ouija.models.ScanResult`; it adds
no new attack surface and does not touch the scanner. Each distinct attack
*category* present in the findings becomes a SARIF ``rule`` (carrying the
category's business-impact text as the rule's full description), and each
:class:`~ouija.models.Finding` becomes a SARIF ``result`` referencing its rule.

ouija probes a network endpoint, not a source file, so there is no on-disk
artifact location. Per the SARIF spec a result's location is optional; we encode
the tested endpoint URL in each result's ``properties`` (and as the
``automationDetails.id``) so consumers retain the target without inventing a
fake file path that would mislead code-scanning's source attribution.
"""

from __future__ import annotations

import json

from ouija.models import ScanResult, Severity
from ouija.report import _IMPACT

# Map ouija's bug-bounty severity buckets onto SARIF result levels and onto the
# numeric security-severity scale GitHub code-scanning uses to bucket alerts
# (0.0-10.0, CVSS-aligned). SARIF only has note/warning/error for `level`; the
# finer-grained ranking lives in the `security-severity` property.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

# GitHub code-scanning `security-severity` numeric bands (string-valued by spec).
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.INFO: "0.0",
    Severity.LOW: "2.0",
    Severity.MEDIUM: "5.0",
    Severity.HIGH: "8.0",
    Severity.CRITICAL: "9.5",
}

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/bugsyhewitt/ouija"


def _rule_for_category(category: str) -> dict:
    """Build a SARIF reportingDescriptor (rule) for an attack *category*."""
    impact = _IMPACT.get(category, "See ouija documentation for this category.")
    return {
        "id": category,
        "name": "".join(part.capitalize() for part in category.split("_")),
        "shortDescription": {"text": f"ouija {category} finding"},
        "fullDescription": {"text": impact},
        "helpUri": INFORMATION_URI,
        "properties": {"tags": ["security", "llm", "owasp-llm-top-10"]},
    }


def _result_for_finding(finding) -> dict:
    """Build a SARIF result object for a single :class:`Finding`."""
    severity = finding.severity
    properties: dict[str, object] = {
        "security-severity": _SECURITY_SEVERITY.get(severity, "0.0"),
        "ouija-severity": severity.value,
        "owasp": finding.owasp,
        "technique": finding.technique,
        "pattern_id": finding.pattern_id,
        "confidence": finding.confidence,
    }
    # Reliability roll-up surfaces only when --repeats produced multiple attempts.
    if finding.attempts > 1:
        properties["attempts"] = finding.attempts
        properties["successes"] = finding.successes
        properties["success_rate"] = finding.success_rate
    # Multi-turn / Crescendo findings carry the turn at which the target complied.
    if finding.turn_succeeded is not None:
        properties["turn_succeeded"] = finding.turn_succeeded

    return {
        "ruleId": finding.category,
        "level": _SARIF_LEVEL.get(severity, "warning"),
        "message": {"text": f"{finding.title}: {finding.evidence}"},
        "properties": properties,
        # A stable per-finding fingerprint lets code-scanning dedupe/track alerts
        # across runs without treating every scan as brand-new findings.
        "partialFingerprints": {"ouijaFindingId": finding.id},
    }


def to_sarif(result: ScanResult) -> str:
    """Render a :class:`ScanResult` as a SARIF 2.1.0 JSON document (string)."""
    # One rule per distinct category present, in first-seen order for determinism.
    categories: list[str] = []
    for finding in result.findings:
        if finding.category not in categories:
            categories.append(finding.category)
    rules = [_rule_for_category(category) for category in categories]
    results = [_result_for_finding(finding) for finding in result.findings]

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": result.tool,
                        "version": result.version,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"ouija/{result.scan_id}"},
                "properties": {
                    "target": result.target,
                    "attack_set": result.attack_set,
                    "patterns_sent": result.patterns_sent,
                    "timestamp": result.timestamp,
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
