"""Shared fixtures + helpers for the agentic test suite (Packet 02).

All async tests run via :func:`run` (``asyncio.run``) rather than pytest-asyncio,
matching the v0.1 suite's convention (it uses sync wrappers and does not depend on
pytest-asyncio). Lower the ASR/CI repeat count to keep the suite fast — correctness
of the confirm, not statistical precision, is what's under test here.
"""

from __future__ import annotations

import asyncio

import pytest

FAST_REPEATS = 6


def run(coro):
    """Run an async coroutine to completion (sync test bodies call this)."""
    return asyncio.run(coro)


@pytest.fixture
def allowlist_loopback():
    return ["127.0.0.1"]
