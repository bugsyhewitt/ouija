"""Wheel ship gate — version and taxonomy completeness assertions.

These tests block a wheel release if the version constant is wrong or the
OWASP ASI taxonomy has promoted stubs still left behind.
"""

from __future__ import annotations

import ouija
from ouija.asitax import PROBE_FAMILIES


EXPECTED_VERSION = "0.5.0"


def test_version_is_0_5_0():
    assert ouija.__version__ == EXPECTED_VERSION, (
        f"expected version {EXPECTED_VERSION}, got {ouija.__version__!r} — "
        "bump ouija/__init__.py and pyproject.toml before shipping"
    )


def test_no_asi_stubs_remain():
    stubs = [f.key for f in PROBE_FAMILIES if f.stub]
    assert not stubs, (
        f"ASI taxonomy has promoted stubs that are still marked stub=True: {stubs} — "
        "promote each stub to a working probe before v0.5.0 ships"
    )
