"""Per-run exfiltration canary for the EchoLeak attack class.

The EchoLeak pattern (CVE-2025-32711, CVSS 9.6) is the flagship 2025 LLM data
exfiltration class: untrusted input coerces the model into emitting a markdown
image / link whose URL points at an attacker host, and the rendering surface
auto-fetches it — leaking whatever data was embedded in the URL's query string.

ouija models this *defensively and safely*:

  - We plant a unique, high-entropy token (`secrets.token_hex(8)`, 64 bits) in
    a synthetic attacker URL, and ask the target to render it.
  - The URL uses the reserved `.invalid` TLD (RFC 6761), so even if some
    downstream renderer tried to fetch it, it resolves nowhere — ouija never
    causes real network egress.
  - Detection is purely on the *response text*: did the target echo our canary
    token back inside a markdown-image / link / `<img src=...>` construct? A
    64-bit token has effectively zero chance of appearing organically, so a hit
    is near-zero-false-positive evidence the target rendered attacker-controlled
    exfiltration markup.

[Worker decision: `.invalid` TLD + response-text-only detection means no
callback server and no real egress — the canary is a marker, not a beacon.]
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

# The literal placeholder corpus patterns carry; the scanner substitutes the
# rendered canary URL for it before sending.
CANARY_PLACEHOLDER = "{canary}"


@dataclass(frozen=True)
class Canary:
    """A per-run exfiltration canary.

    Attributes:
        token: the high-entropy hex token unique to this run.
        url:   the synthetic attacker URL ending in ``d=`` so a pattern can
               append the data it wants exfiltrated (e.g. the system prompt).
    """

    token: str
    url: str


def make_canary() -> Canary:
    """Return a fresh per-run :class:`Canary`.

    The token is 8 bytes of CSPRNG output rendered as 16 hex chars (64 bits of
    entropy). The URL embeds the token in the host label and ends in ``?d=`` so
    a corpus pattern can instruct the model to append exfiltrated data.
    """
    token = secrets.token_hex(8)
    url = f"http://ouija-exfil.{token}.invalid/c?d="
    return Canary(token=token, url=url)
