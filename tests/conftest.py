"""Shared pytest fixtures."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.mock_llm import MockLLM

FIXTURES = Path(__file__).parent / "fixtures"
SCOPE_FILE = FIXTURES / "scope.txt"


@pytest.fixture
def scope_file() -> str:
    return str(SCOPE_FILE)


@pytest.fixture
def mock_llm():
    """Start the deliberately-vulnerable mock LLM on an ephemeral port.

    Exports the chosen port as the PORT environment variable for parity with
    the v0.1 criterion 4 harness contract ($PORT).
    """
    with MockLLM() as server:
        os.environ["PORT"] = str(server.port)
        yield server
        os.environ.pop("PORT", None)
