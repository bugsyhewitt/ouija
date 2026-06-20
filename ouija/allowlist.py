"""Target allow-list — live-endpoint safety enforced in code, not docs (Packet 02 §15 / ADR D10).

ouija sends adversarial payloads to live LLM/agent/MCP endpoints. That costs
money, may violate provider ToS, and must only ever hit targets you own or are
authorized to test. Every active verb calls :func:`enforce_allowlist` at its top
before touching the network. **There is no "skip for convenience" flag**
(anti-pattern A5): the one time you skip the allow-list is the time you hit prod.

An allow-list entry is a ``host`` or ``host:port`` string. A target URL (or bare
host) is in scope iff its host matches an entry exactly *and*, when the entry
pins a port, the target's port matches too. Loopback (``127.0.0.1`` /
``localhost`` / ``::1``) is **not** implicitly trusted — the lab still passes its
own loopback targets through the allow-list, so the enforcement path itself is
exercised on every run (and the §16 acceptance test asserts a non-allow-listed
target is refused).

[Worker decision: this mirrors the existing v0.1 ``ouija/scope.py`` posture
(refuse-before-send, explicit scope file) but is a *separate* gate for the
agentic surface, because the agentic targets are MCP/agent/RAG endpoints, not the
single HTTP LLM endpoint scope.py guards, and the failure mode (autonomous exfil
to an unauthorized host) is more severe.]
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


class AllowlistError(Exception):
    """Raised when a target is not present on the active allow-list."""


def _split_host_port(entry: str) -> tuple[str, int | None]:
    """Split a ``host`` or ``host:port`` allow-list entry / target authority.

    IPv6 literals in bracket form (``[::1]:8731``) are handled. A bare IPv6
    literal without brackets and without a port is returned host-only.
    """
    entry = entry.strip()
    if not entry:
        return "", None
    # Bracketed IPv6, optionally with a port: [::1] or [::1]:8731
    if entry.startswith("["):
        close = entry.find("]")
        if close != -1:
            host = entry[1:close]
            rest = entry[close + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                return _norm_host(host), int(rest[1:])
            return _norm_host(host), None
    # If there are 2+ colons and no brackets, treat as a bare IPv6 literal.
    if entry.count(":") >= 2:
        return _norm_host(entry), None
    host, sep, port = entry.partition(":")
    if sep and port.isdigit():
        return _norm_host(host), int(port)
    return _norm_host(entry), None


def _norm_host(host: str) -> str:
    """Lower-case a host; normalise an IP literal to its canonical text form."""
    host = host.strip().lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host


def _target_authority(target: str) -> tuple[str, int | None]:
    """Extract ``(host, port)`` from a target URL or bare ``host[:port]`` string."""
    candidate = target.strip()
    if "://" not in candidate:
        # Bare host[:port]; give urlparse a scheme so netloc parsing works.
        candidate = "ouija://" + candidate
    parsed = urlparse(candidate)
    host = parsed.hostname or ""
    return _norm_host(host), parsed.port


def load_allowlist(raw: object) -> list[tuple[str, int | None]]:
    """Normalise an allow-list (list of strings, or newline text) into entries.

    Accepts either an iterable of entry strings or a single newline-delimited
    string (``#`` comments and blank lines ignored, matching ``scope.py``).
    """
    entries: list[tuple[str, int | None]] = []
    if isinstance(raw, str):
        lines = raw.splitlines()
    else:
        lines = list(raw)  # type: ignore[arg-type]
    for line in lines:
        line = str(line).strip()
        if not line or line.startswith("#"):
            continue
        host, port = _split_host_port(line)
        if host:
            entries.append((host, port))
    return entries


def is_allowed(target: str, allowlist: object) -> bool:
    """Return True iff *target*'s host (and port, if pinned) is on *allowlist*."""
    entries = (
        allowlist
        if isinstance(allowlist, list)
        and all(isinstance(e, tuple) for e in allowlist)
        else load_allowlist(allowlist)
    )
    if not entries:
        return False
    t_host, t_port = _target_authority(target)
    if not t_host:
        return False
    for a_host, a_port in entries:
        if a_host != t_host:
            continue
        if a_port is None or a_port == t_port:
            return True
    return False


def enforce_allowlist(target: str, allowlist: object) -> None:
    """Raise :exc:`AllowlistError` unless *target* is on *allowlist*.

    Called at the top of every active verb (ADR D10). The error message names
    the rejected host so the operator can fix scope, never the convenience of a
    bypass.
    """
    if not is_allowed(target, allowlist):
        host, port = _target_authority(target)
        shown = host + (f":{port}" if port is not None else "")
        raise AllowlistError(
            f"target {shown!r} is not on the allow-list; ouija refuses to send "
            f"adversarial traffic to a target you have not explicitly authorized "
            f"(§15/D10). Add it to the allow-list to proceed. There is no bypass."
        )
