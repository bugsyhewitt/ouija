"""Pydantic data models for ouija.

[Worker decision: pydantic models keep the JSON output schema stable and give
us free validation of the structured response we parse from target endpoints.]
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


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


class ScanResult(BaseModel):
    """Top-level result emitted as JSON."""

    tool: str = "ouija"
    version: str
    target: str
    attack_set: str
    patterns_sent: int
    findings: list[Finding] = Field(default_factory=list)
