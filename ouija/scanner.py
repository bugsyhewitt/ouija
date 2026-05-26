"""Scanner: orchestrate mutate -> send -> detect across an attack set."""

from __future__ import annotations

import asyncio

import httpx

from ouija import __version__
from ouija.client import TargetClient
from ouija.corpus import LoadedSet
from ouija.detect import detect
from ouija.models import ScanResult
from ouija.mutate import mutate


async def _run_async(
    target: str,
    attack_set_name: str,
    loaded: LoadedSet,
    api_key_env: str | None,
    concurrency: int,
) -> ScanResult:
    client = TargetClient(target, api_key_env=api_key_env)
    result = ScanResult(
        version=__version__,
        target=target,
        attack_set=attack_set_name,
        patterns_sent=0,
    )
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient() as http:

        async def probe(pattern, variant_id, prompt):
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
            )
            return finding

        tasks = []
        for pattern in loaded.patterns:
            for variant_id, prompt in mutate(pattern):
                tasks.append(probe(pattern, variant_id, prompt))

        result.patterns_sent = len(tasks)
        for finding in await asyncio.gather(*tasks):
            if finding is not None:
                result.findings.append(finding)

    return result


def run_scan(
    target: str,
    attack_set_name: str,
    loaded: LoadedSet,
    api_key_env: str | None = None,
    concurrency: int = 5,
) -> ScanResult:
    """Synchronous entry point that drives the async probe loop."""
    return asyncio.run(
        _run_async(target, attack_set_name, loaded, api_key_env, concurrency)
    )
