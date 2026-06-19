"""Carrier / encoding transforms — the built-in mutator's variant set (Packet 02 §D9 / Appendix D).

These are *orthogonal delivery transforms* applied to any payload by the mutator
layer (ADR D9). They are the carrier/encoding evasion vectors repeatedly shown
effective in the literature: Base64, hex, ROT13, Latin->Cyrillic homoglyphs,
zero-width interleaving, and Unicode TAG-block smuggling.

The symmetry that matters for a suite that *targets and is targeted*: the
``homoglyph`` and ``unicode_tag_smuggle`` carriers here are exactly what the
§8.1 tool-description linter (:mod:`ouija.modules._lint`) detects. ouija ships
both the carrier and its detector.

[Worker decision: these transforms are deliberately pure ``str -> str`` functions
with no state, so they compose freely and are trivial to unit-test. They live in
their own module (not bolted onto each attack module) precisely because D9 says
encoding is a cross-cutting transform, not an attack class.]
"""

from __future__ import annotations

import base64
import codecs

# --- single-payload carrier transforms -------------------------------------


def b64(s: str) -> str:
    """Base64-encode the UTF-8 bytes of *s*."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def hexenc(s: str) -> str:
    """Hex-encode the UTF-8 bytes of *s*."""
    return s.encode("utf-8").hex()


def rot13(s: str) -> str:
    """ROT13 the ASCII letters of *s* (non-letters pass through)."""
    return codecs.encode(s, "rot_13")


# Latin -> Cyrillic confusables. A human reads "secret"; a naive ASCII substring
# filter never matches, but many models still read it as the Latin word.
_HOMO = str.maketrans(
    {
        "a": "а",  # CYRILLIC SMALL LETTER A
        "c": "с",  # CYRILLIC SMALL LETTER ES
        "e": "е",  # CYRILLIC SMALL LETTER IE
        "o": "о",  # CYRILLIC SMALL LETTER O
        "p": "р",  # CYRILLIC SMALL LETTER ER
        "x": "х",  # CYRILLIC SMALL LETTER HA
        "y": "у",  # CYRILLIC SMALL LETTER U
    }
)


def homoglyph(s: str) -> str:
    """Replace a handful of Latin letters with Cyrillic confusables."""
    return s.translate(_HOMO)


# Zero-width space — invisible in most renderers but present in the byte stream.
_ZWSP = "​"


def zero_width_wrap(s: str) -> str:
    """Interleave zero-width spaces between characters to defeat naive filters."""
    return _ZWSP.join(s)


def unicode_tag_smuggle(s: str) -> str:
    """Encode ASCII into the Unicode TAG block (U+E0000+).

    Invisible to humans, historically interpreted by some models. Non-ASCII
    characters pass through unchanged (the TAG block only covers code points
    < 0x80).
    """
    return "".join(chr(0xE0000 + ord(c)) if ord(c) < 0x80 else c for c in s)


# Public registry of carriers, keyed by short name. ``plain`` is the identity
# transform and is always first so a budget of 1 yields the unmodified payload.
CARRIERS = {
    "plain": lambda s: s,
    "b64": b64,
    "hex": hexenc,
    "rot13": rot13,
    "homoglyph": homoglyph,
    "zwsp": zero_width_wrap,
    "utag": unicode_tag_smuggle,
}

# Stable ordering for budget slicing (dict preserves insertion order in 3.7+,
# but make the contract explicit for the mutator).
CARRIER_ORDER = ("plain", "b64", "hex", "rot13", "homoglyph", "zwsp", "utag")
