"""Direct prompt injection / jailbreak baseline — delegate to garak (Packet 02 §6 / ADR D3).

Don't reimplement (anti-pattern A1). garak owns the 50+ static input/output
jailbreak/toxicity/encoding probe zoo, with 23 backends, 28 detectors, and
bootstrap CIs on attack-success rate — a solved, maintained baseline. ouija shells
out to garak for the ``RawLLM`` / ``Agent`` static baseline and ingests its JSONL
report into ``nmc.finding/v0`` records mapped to LLM01.

ouija adds exactly one thing at this layer (§6): carrier/encoding evasion as a
mutator transform (D9) so the baseline payloads also get tried Base64/homoglyph/
zero-width-wrapped — a cheap, high-yield delta over vanilla garak against filtered
inputs. Everything else here is garak's job.

OPERATIONAL NOTE: garak is an external binary that hits a live model — it costs
money / time and may violate ToS. This module never runs it implicitly; the runner
(:func:`run_garak_baseline`) is opt-in, logs the request, and is *not* exercised in
CI (the parser is tested against a fixture instead). When the ``garak`` binary is
absent, :func:`run_garak_baseline` raises a clear, actionable error.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import shutil
import tempfile

from ouija.findings import STATE_CONFIRMED, STATE_NOT_VULNERABLE, ouija_finding


def garak_available() -> bool:
    """True iff the ``garak`` binary is on PATH."""
    return shutil.which("garak") is not None


def parse_garak_report(text: str, *, target: str = "") -> list[dict]:
    """Parse a garak JSONL report into ``nmc.finding/v0`` records (D3).

    garak emits one JSON object per line. We map each failed ``eval`` entry (a
    probe whose detector found the model complied) to an LLM01 finding, carrying
    garak's attack-success rate / CI in ``raw`` where present.
    """
    findings: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("entry_type") != "eval":
            continue
        # garak marks a probe as failed (model vulnerable) when passed is False,
        # or when the attack-success rate is > 0.
        passed = rec.get("passed")
        asr = rec.get("asr", rec.get("attack_success_rate"))
        vulnerable = (passed is False) or (isinstance(asr, (int, float)) and asr > 0)
        probe = rec.get("probe", rec.get("probe_name", "unknown"))
        detector = rec.get("detector", rec.get("detector_name", ""))
        raw: dict = {"garak_probe": probe, "garak_detector": detector,
                     "source": "garak"}
        if asr is not None:
            raw["asr"] = asr
        for ci_key in ("ci95", "asr_ci", "confidence_interval"):
            if ci_key in rec:
                raw["ci95"] = rec[ci_key]
                break
        findings.append(
            ouija_finding(
                "baseline_garak",
                target=target or rec.get("model_name", ""),
                state=STATE_CONFIRMED if vulnerable else STATE_NOT_VULNERABLE,
                surface=str(probe),
                title=f"garak baseline: {probe} ({detector or 'detector'})",
                evidence=f"garak probe {probe!r} flagged via detector "
                         f"{detector!r}" + (f"; ASR={asr}" if asr is not None else ""),
                asi=("ASI01",), llm=("LLM01",),
                effect="model_compliance" if vulnerable else None,
                confidence=float(asr) if isinstance(asr, (int, float)) else (
                    0.5 if vulnerable else 0.0),
                extra_refs=("garak",),
                raw=raw,
            )
        )
    return findings


async def run_garak_baseline(
    model_type: str,
    model_name: str,
    *,
    probes: str = "all",
    timeout: float = 1800.0,
) -> list[dict]:
    """Run garak against a target and parse its report (opt-in; not run in CI).

    Raises:
        RuntimeError: if the ``garak`` binary is not installed (with guidance).
    """
    if not garak_available():
        raise RuntimeError(
            "garak is not installed; the §6 static baseline delegates to it. "
            "Install garak ('pipx install garak') to run this layer, or rely on "
            "ouija's agentic/RAG/MCP modules (the differentiator) which need no "
            "garak. ouija deliberately does not reimplement garak's probe zoo (D3)."
        )
    workdir = pathlib.Path(tempfile.mkdtemp(prefix="ouija-garak-"))
    prefix = workdir / "garak"
    report = prefix.with_suffix(".report.jsonl")
    proc = await asyncio.create_subprocess_exec(
        "garak", "--model_type", model_type, "--model_name", model_name,
        "--probes", probes, "--report_prefix", str(prefix),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError(f"garak run exceeded {timeout}s; aborted")
    if not report.exists():
        # garak sometimes writes <prefix>.jsonl; try a couple of names.
        for cand in (prefix.with_suffix(".jsonl"), workdir / "garak.report.jsonl"):
            if cand.exists():
                report = cand
                break
    if not report.exists():
        raise RuntimeError(f"garak produced no report under {workdir}")
    return parse_garak_report(report.read_text(encoding="utf-8"),
                              target=f"{model_type}:{model_name}")
