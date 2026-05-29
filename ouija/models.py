"""Pydantic data models for ouija.

[Worker decision: pydantic models keep the JSON output schema stable and give
us free validation of the structured response we parse from target endpoints.]
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


def _new_scan_id() -> str:
    """A short, unique identifier for a single scan run."""
    return uuid.uuid4().hex


def _utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with a trailing Z."""
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    """Bug-bounty-aligned severity buckets (loosely CVSS-mapped)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackPattern(BaseModel):
    """A single attack prompt loaded from the corpus."""

    id: str
    name: str
    prompt: str
    technique: str
    # When set, presence of this marker string in the response is strong
    # evidence the injection succeeded.
    marker: Optional[str] = None
    # When True, the prompt carries a `{canary}` placeholder that the scanner
    # fills with a per-run exfiltration canary URL before sending; detection is
    # then on whether the response renders that canary as markup (EchoLeak).
    canary: bool = False
    # For the `dos` set only: selects which response-characteristic heuristic
    # decides whether the target *complied* with an unbounded-consumption attack
    # (LLM10:2025). One of "length", "repetition", or "nesting". DoS patterns
    # carry no marker, so this drives detection instead of marker matching.
    dos_signal: Optional[str] = None


class Finding(BaseModel):
    """A single ship-able finding produced by the fuzzer."""

    id: str
    category: str
    severity: Severity
    title: str
    pattern_id: str
    technique: str
    owasp: str
    request_prompt: str
    response_excerpt: str
    evidence: str
    confidence: float = Field(ge=0.0, le=1.0)
    # Reliability fields — populated when --repeats > 1.
    attempts: int = 1
    successes: int = 1
    success_rate: float = Field(default=1.0, ge=0.0, le=1.0)


class ScanSummary(BaseModel):
    """Machine-readable roll-up of a scan, for jq / report templates.

    Kept separate from the per-finding list so consumers can read totals
    without iterating every finding (e.g. ``jq '.summary.successful'``).
    """

    total: int = 0
    successful: int = 0
    # attack_set name -> number of findings attributed to it.
    attack_sets: dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Top-level result emitted as JSON."""

    tool: str = "ouija"
    version: str
    # Unique per-run identifier — lets downstream tooling correlate, dedupe,
    # and name report artifacts deterministically.
    scan_id: str = Field(default_factory=_new_scan_id)
    # ISO-8601 UTC timestamp of when the scan result was constructed.
    timestamp: str = Field(default_factory=_utc_now_iso)
    target: str
    attack_set: str
    patterns_sent: int
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
