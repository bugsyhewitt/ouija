"""nmc.finding/v0 emitter + ASR/CI runner (Packet 02 §14 / Appendix F / Appendix G).

ouija's agentic modules emit ``nmc.finding/v0`` records (the Packet 01 schema;
schema-bumped in Packet 03). ``asi`` / ``llm`` go in ``refs`` until Packet 03 adds
first-class taxonomy fields. Severity stays ``null`` here — Packet 04 enriches —
but ouija sets a ``confidence`` and the data-flow ``effect``, which Packet 04/05
consume.

Two pieces live here:

* :func:`ouija_finding` — builds a well-formed ``nmc.finding/v0`` dict.
* :func:`measure` / :func:`bootstrap_ci` — the ASR-with-CI runner (Appendix F).
  LLM attacks are stochastic (garak ships bootstrap CIs for exactly this reason,
  anti-pattern A6): a one-shot "it worked once" is noise. The runner repeats a
  landed probe N times and reports ASR ± 95% CI in the finding's ``raw``.

A finding's ``state`` is ``confirmed`` if ``asr > 0`` (effect observed at least
once and reproducibly characterised) with the CI reported; ``not_vulnerable`` if
``asr == 0`` across the repeats. ``detected`` is reserved for a *static* indicator
(e.g. an MCP tool-description lint hit) with no agent wired (§11 / Appendix G).
"""

from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Awaitable, Callable

from ouija import __version__
from ouija.oracle import Verdict

SCHEMA = "nmc.finding/v0"

# Finding lifecycle states (§11). ouija largely skips the ambiguous middle.
STATE_DETECTED = "detected"          # static indicator, no data-flow proof yet
STATE_CONFIRMED = "confirmed"        # data-flow effect observed (the headline)
STATE_NOT_VULNERABLE = "not_vulnerable"  # a real negative across repeats


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ouija_finding(
    verb: str,
    *,
    target: str,
    state: str,
    title: str,
    evidence: str = "",
    surface: str | None = None,
    asi: tuple[str, ...] = (),
    llm: tuple[str, ...] = (),
    effect: str | None = None,
    confidence: float = 0.0,
    active: bool = True,
    extra_refs: tuple[str, ...] = (),
    raw: dict | None = None,
) -> dict:
    """Build an ``nmc.finding/v0`` record (Appendix G shape).

    Args:
        verb: the producing verb — ``scan_mcp`` / ``scan_rag`` / ``fuzz_agent``.
        target: the target URL / identifier the finding is about.
        state: one of the ``STATE_*`` constants.
        title: a one-line human summary.
        evidence: the proof string (collector hit / tool args / matched span).
        surface: the specific tool / endpoint surface, when applicable.
        asi/llm: OWASP category ids; emitted in ``refs`` (§14).
        effect: the data-flow effect type (``oob_exfil`` / ``tool_call`` / …) or None.
        confidence: 0..1; the runner fills this from ASR.
        active: ouija sends adversarial input, so findings are active by default.
        raw: extra machine fields (asr / ci95 / n / effect booleans).
    """
    refs: list[str] = list(asi) + list(llm) + list(extra_refs)
    record: dict = {
        "schema": SCHEMA,
        "tool": "ouija",
        "tool_version": __version__,
        "verb": verb,
        "active": active,
        "target": target,
        "state": state,
        "severity": None,  # Packet 04 enriches
        "title": title,
        "evidence": evidence,
        "effect": effect,
        "confidence": round(float(confidence), 4),
        "refs": refs,
        "raw": dict(raw or {}),
        "ts": _utc_now_iso(),
    }
    if surface is not None:
        record["surface"] = surface
    return record


def bootstrap_ci(outcomes: list[int], *, resamples: int = 1000,
                 rng: random.Random | None = None) -> tuple[float, float]:
    """A simple bootstrap 95% CI over a 0/1 outcome vector (Appendix F).

    Resamples *outcomes* with replacement *resamples* times, takes the mean of
    each resample, and returns the 2.5th / 97.5th percentiles. An empty vector
    yields ``(0.0, 0.0)``.
    """
    if not outcomes:
        return (0.0, 0.0)
    r = rng or random.Random()
    n = len(outcomes)
    boots = []
    for _ in range(resamples):
        sample = [outcomes[r.randrange(n)] for _ in range(n)]
        boots.append(sum(sample) / n)
    boots.sort()
    lo = boots[int(0.025 * len(boots))]
    hi = boots[min(len(boots) - 1, int(0.975 * len(boots)))]
    return (round(lo, 4), round(hi, 4))


async def measure(
    probe_fn: Callable[[], Awaitable[Verdict]],
    *,
    repeats: int = 20,
    rng: random.Random | None = None,
) -> dict:
    """Run *probe_fn* ``repeats`` times; return ASR + bootstrap CI + evidence (Appendix F).

    ``probe_fn`` is an async thunk that performs one probe attempt and returns a
    :class:`~ouija.oracle.Verdict`. The returned dict carries ``asr``, ``ci95``,
    ``n``, the first observed ``evidence`` / ``effect``, and per-effect booleans
    for the finding's ``raw``.
    """
    outcomes: list[int] = []
    evidence: str | None = None
    effect: str | None = None
    effects_seen: set[str] = set()
    for _ in range(max(1, repeats)):
        v = await probe_fn()
        outcomes.append(1 if v.hit else 0)
        if v.hit:
            if v.effect:
                effects_seen.add(v.effect)
            if evidence is None:
                evidence, effect = v.evidence, v.effect
    asr = sum(outcomes) / len(outcomes)
    lo, hi = bootstrap_ci(outcomes, rng=rng)
    return {
        "asr": round(asr, 4),
        "ci95": [lo, hi],
        "n": len(outcomes),
        "evidence": evidence,
        "effect": effect,
        "effects": sorted(effects_seen),
        "oob_exfil": "oob_exfil" in effects_seen,
        "tool_call": "tool_call" in effects_seen,
        "answer_flip": "answer_flip" in effects_seen,
    }


def group_by_owasp(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by their first ASI/LLM ref for a standards-mapped report (§14)."""
    grouped: dict[str, list[dict]] = {}
    for f in findings:
        refs = f.get("refs", [])
        key = next((r for r in refs if r.startswith(("ASI", "LLM"))), "unmapped")
        grouped.setdefault(key, []).append(f)
    return grouped
