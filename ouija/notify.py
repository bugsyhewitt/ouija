"""Webhook notification: POST a compact scan summary to a callback URL.

A bug-bounty hunter or a CI/security pipeline wants to be *told* when a scan
finds something — not have to poll a report artifact. ``--notify <url>`` fires a
single HTTP POST carrying a compact JSON summary of the run (target, counts,
top severity, the per-finding id/severity/category roll-up) to a webhook the
operator controls: a Slack/Teams incoming webhook proxy, a ticketing intake, a
chatops bot, or a CI fan-out endpoint.

Design constraints that keep this consistent with ouija's architecture:

* **Summary, not the full report.** The webhook payload is a bounded digest, not
  the (potentially large) findings list with full prompts/transcripts. A
  consumer that wants the detail reads the ``--format json`` report; the webhook
  is the *alert*, the report is the *evidence*. This keeps the POST small and
  avoids leaking raw attack prompts / exfil canaries into a chat channel.
* **Pure payload builder.** :func:`build_notification` is a pure function over a
  :class:`~ouija.models.ScanResult` — trivially testable, no I/O. The thin
  :func:`send_notification` is the only thing that touches the network.
* **Non-fatal.** A webhook is a side channel. A delivery failure (bad URL,
  timeout, non-2xx) MUST NOT crash the scan or change the security exit code —
  the CLI surfaces a warning on stderr and proceeds. The finding gate
  (``--fail-on``) is the source of truth for the build verdict, not the webhook.

[Worker decision (Phase 2 / R26): chose ``--notify`` (webhook output) over
``--schedule`` (recurring-scan). Scheduling implies a long-running stateful
daemon and persistence, which fights ouija's stateless single-run CLI design —
and the README already delegates recurrence to external cron. A webhook is a
pure, bounded, side-effect-at-the-edge integration that composes naturally with
``--fail-on`` and the existing render pipeline, so it is the more feasible and
more architecturally consistent integration feature.]
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import httpx

from ouija.models import ScanResult, Severity

# Highest-first severity ordering, used to compute the run's top severity.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class NotifyError(ValueError):
    """Raised when a --notify URL is syntactically invalid (fail fast)."""


def validate_notify_url(url: str) -> str:
    """Validate *url* as an http(s) webhook target; return it unchanged on success.

    Validated at CLI parse time so a malformed URL fails fast (exit 3) BEFORE any
    request is sent to the scan target — never mid-run after spending requests.

    Raises :exc:`NotifyError` when the URL is empty or is not an absolute
    http/https URL with a host.
    """
    if not url or not url.strip():
        raise NotifyError("--notify URL must not be empty")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise NotifyError(
            f"--notify URL must be an http(s) URL, got scheme {parsed.scheme!r}"
        )
    if not parsed.netloc:
        raise NotifyError(f"--notify URL must include a host: {url!r}")
    return url


def _top_severity(result: ScanResult) -> str | None:
    """Return the highest finding severity in the run, or None if no findings."""
    if not result.findings:
        return None
    top = max(result.findings, key=lambda f: _SEVERITY_RANK.get(f.severity, -1))
    return top.severity.value


def build_notification(result: ScanResult) -> dict[str, Any]:
    """Build the compact webhook payload for a completed scan. Pure: no I/O.

    The payload is a bounded digest — it carries the run identity, the headline
    counts, the top severity, and a per-finding ``{id, severity, category,
    title}`` roll-up — but NOT the full prompts, response excerpts, or
    multi-turn transcripts (those stay in the ``--format json`` report). This
    keeps the POST small and avoids spilling raw attack payloads / exfil
    canaries into a chat channel.
    """
    findings_digest = [
        {
            "id": f.id,
            "severity": f.severity.value,
            "category": f.category,
            "title": f.title,
            "owasp": f.owasp,
        }
        for f in result.findings
    ]
    return {
        "tool": result.tool,
        "version": result.version,
        "event": "scan_complete",
        "scan_id": result.scan_id,
        "timestamp": result.timestamp,
        "target": result.target,
        "attack_set": result.attack_set,
        "requests_sent": result.patterns_sent,
        "findings_count": len(result.findings),
        "top_severity": _top_severity(result),
        "attack_sets": dict(result.summary.attack_sets),
        "findings": findings_digest,
    }


def send_notification(
    url: str,
    result: ScanResult,
    *,
    timeout: float = 10.0,
) -> int:
    """POST the scan-completion summary to *url*; return the response status code.

    Raises :exc:`httpx.HTTPError` (or a subclass) on a transport failure or a
    non-2xx response. The CLI catches this and treats a webhook failure as a
    non-fatal warning — a side-channel delivery problem must not change the
    security exit code.
    """
    payload = build_notification(result)
    body = json.dumps(payload).encode()
    resp = httpx.post(
        url,
        content=body,
        headers={"Content-Type": "application/json"},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.status_code
