"""CI/CD severity gating.

A scanner is only pipeline-usable if it can fail a build when it finds
something. ouija historically exited 0 on any *completed* scan regardless of
findings, so a bug-bounty / security-CI workflow had no way to break the
pipeline on a hit. This module adds severity-threshold gating, mirroring the
convention every mature scanner uses (trivy, semgrep, bandit, gitleaks, grype):
``--fail-on <severity>`` makes ouija exit non-zero when at least one finding is
at or above the chosen severity.

The gate is a pure function over a :class:`~ouija.models.ScanResult`; the CLI
maps its boolean verdict onto the process exit code. The default threshold is
``none`` so existing behaviour (exit 0 on a completed scan) is preserved — the
gate is strictly opt-in and never breaks a caller who does not pass the flag.
"""

from __future__ import annotations

from ouija.models import ScanResult, Severity

# Severity ordering, lowest -> highest. Used to decide whether a finding meets
# or exceeds the configured threshold.
_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Sentinel meaning "never fail on findings" — preserves pre-0.1.14 behaviour.
FAIL_ON_NONE = "none"

# The accepted --fail-on values: every severity name plus the "none" sentinel.
FAIL_ON_CHOICES: tuple[str, ...] = (FAIL_ON_NONE,) + tuple(s.value for s in Severity)


def findings_meet_threshold(result: ScanResult, fail_on: str) -> bool:
    """Return True if any finding is at or above the *fail_on* severity.

    *fail_on* is one of :data:`FAIL_ON_CHOICES`. ``"none"`` always returns
    ``False`` (gate disabled). Any other value is a severity name; the gate
    trips when at least one finding's severity rank is >= that threshold's rank.
    """
    if fail_on == FAIL_ON_NONE:
        return False

    try:
        threshold_rank = _RANK[Severity(fail_on)]
    except ValueError as exc:  # pragma: no cover - guarded by CLI choices
        raise ValueError(
            f"invalid --fail-on value {fail_on!r}; expected one of "
            f"{list(FAIL_ON_CHOICES)}"
        ) from exc

    return any(
        _RANK.get(f.severity, -1) >= threshold_rank for f in result.findings
    )


def gate_exit_code(
    result: ScanResult,
    fail_on: str,
    *,
    ok_code: int,
    findings_code: int,
) -> int:
    """Map a scan result + threshold onto a process exit code.

    Returns *findings_code* when :func:`findings_meet_threshold` trips,
    otherwise *ok_code*. Keeping the codes as explicit arguments lets the CLI
    own the exit-code constants (single source of truth) while this stays a
    pure, trivially-testable function.
    """
    if findings_meet_threshold(result, fail_on):
        return findings_code
    return ok_code
