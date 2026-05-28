"""Scanner: orchestrate mutate -> send -> detect across an attack set."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import NamedTuple

import httpx

from ouija import __version__
from ouija.canary import CANARY_PLACEHOLDER, make_canary
from ouija.client import TargetClient
from ouija.corpus import LoadedSet
from ouija.detect import detect
from ouija.indirect import DEFAULT_INJECT_VIA, wrap_indirect
from ouija.models import Finding, ScanResult, ScanSummary
from ouija.mutate import DEFAULT_MUTATOR_SET, mutate

# Maps a finding's corpus category back to the --attack-set name it belongs to,
# so the JSON summary can break findings down per attack set even on an "all" run.
_CATEGORY_TO_ATTACK_SET = {
    "prompt_injection": "injection",
    "sensitive_info_disclosure": "disclosure",
    "model_dos": "dos",
    "improper_output_handling": "exfil",
    "excessive_agency": "agency",
}


class _ProbeResult(NamedTuple):
    """Result of a single probe attempt."""

    key: str           # "<pattern.id>/<variant_id>" — logical identity across repeats
    finding: Finding | None
    attempt_prompt: str
    attempt_reply_text: str


async def _run_async(
    target: str,
    attack_set_name: str,
    loaded: LoadedSet,
    api_key_env: str | None,
    concurrency: int,
    request_template: str | None = None,
    response_path: str | None = None,
    repeats: int = 1,
    mutator_set: str = DEFAULT_MUTATOR_SET,
    inject_via: str = DEFAULT_INJECT_VIA,
) -> ScanResult:
    client = TargetClient(
        target,
        api_key_env=api_key_env,
        request_template=request_template,
        response_path=response_path,
    )
    result = ScanResult(
        version=__version__,
        target=target,
        attack_set=attack_set_name,
        patterns_sent=0,
    )
    sem = asyncio.Semaphore(concurrency)

    # One per-run exfiltration canary shared by all canary patterns this scan.
    # A fresh high-entropy token per run keeps detection near-zero-false-positive
    # and prevents a target from learning the token across runs.
    canary = make_canary()

    async with httpx.AsyncClient() as http:

        async def probe(pattern, variant_id, prompt, attempt_num) -> _ProbeResult:
            async with sem:
                reply = await client.send(http, prompt)
            meta = loaded.meta[pattern.id]
            finding = detect(
                pattern,
                variant_id,
                prompt,
                reply,
                category=meta["category"],
                owasp=meta["owasp"],
                canary_token=canary.token if pattern.canary else None,
            )
            key = f"{pattern.id}/{variant_id}"
            return _ProbeResult(
                key=key,
                finding=finding,
                attempt_prompt=prompt,
                attempt_reply_text=reply.text or "",
            )

        tasks = []
        for pattern in loaded.patterns:
            for variant_id, prompt in mutate(pattern, mutator_set):
                # Indirect injection: nest the attack inside a data envelope the
                # endpoint is asked to process. Non-destructive — the marker and
                # the {canary} placeholder survive verbatim, so canary
                # substitution (below) and detection are unaffected.
                prompt = wrap_indirect(prompt, inject_via)
                if pattern.canary:
                    prompt = prompt.replace(CANARY_PLACEHOLDER, canary.url)
                for attempt_num in range(repeats):
                    tasks.append(probe(pattern, variant_id, prompt, attempt_num))

        result.patterns_sent = len(tasks)
        raw_results: list[_ProbeResult] = await asyncio.gather(*tasks)

    # --- aggregate per logical key ---
    # Group all attempt results by key.
    by_key: dict[str, list[_ProbeResult]] = defaultdict(list)
    for pr in raw_results:
        by_key[pr.key].append(pr)

    # For each key: if ANY attempt yielded a finding, emit one Finding
    # annotated with hit-rate stats.
    for key, attempts_list in by_key.items():
        total = len(attempts_list)
        successes_list = [pr for pr in attempts_list if pr.finding is not None]
        n_successes = len(successes_list)

        if n_successes == 0:
            continue

        # Use the first successful finding as the canonical finding.
        base_finding = successes_list[0].finding
        assert base_finding is not None  # guaranteed by filter above

        if total == 1:
            # No repeat data — emit as-is (preserve existing behaviour).
            result.findings.append(base_finding)
        else:
            rate = n_successes / total
            annotated = base_finding.model_copy(
                update={
                    "attempts": total,
                    "successes": n_successes,
                    "success_rate": rate,
                }
            )
            result.findings.append(annotated)

    # --- machine-readable summary roll-up ---
    per_set: dict[str, int] = {}
    for finding in result.findings:
        set_name = _CATEGORY_TO_ATTACK_SET.get(finding.category, finding.category)
        per_set[set_name] = per_set.get(set_name, 0) + 1

    result.summary = ScanSummary(
        total=result.patterns_sent,
        successful=len(result.findings),
        attack_sets=per_set,
    )

    return result


def run_scan(
    target: str,
    attack_set_name: str,
    loaded: LoadedSet,
    api_key_env: str | None = None,
    concurrency: int = 5,
    request_template: str | None = None,
    response_path: str | None = None,
    repeats: int = 1,
    mutator_set: str = DEFAULT_MUTATOR_SET,
    inject_via: str = DEFAULT_INJECT_VIA,
) -> ScanResult:
    """Synchronous entry point that drives the async probe loop."""
    return asyncio.run(
        _run_async(
            target,
            attack_set_name,
            loaded,
            api_key_env,
            concurrency,
            request_template=request_template,
            response_path=response_path,
            repeats=repeats,
            mutator_set=mutator_set,
            inject_via=inject_via,
        )
    )
