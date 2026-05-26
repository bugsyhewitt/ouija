"""Scope gating — refuse to test endpoints not explicitly in scope.

The scope file is a newline-delimited list of authorized hosts (one per line).
Blank lines and lines starting with '#' are ignored. A target is in scope if
its host (and, when a port is specified in the scope entry, its port) matches
an entry. Scheme is ignored for matching; we match on host[:port].

[Worker decision: bug-bounty programs authorize by host, not full URL path, so
we gate on host[:port]. Path-level scoping is out of v0.1 scope.]
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a target is not authorized by the scope file."""


def _host_port(url_or_host: str) -> tuple[str, int | None]:
    """Extract (host, port) from a URL or bare host[:port] string."""
    candidate = url_or_host.strip()
    if "://" not in candidate:
        candidate = "//" + candidate
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    return host, parsed.port


def load_scope(scope_file: str | Path) -> list[tuple[str, int | None]]:
    """Parse a scope file into a list of (host, port) authorizations."""
    path = Path(scope_file)
    if not path.is_file():
        raise ScopeError(f"scope file not found: {scope_file}")
    entries: list[tuple[str, int | None]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(_host_port(line))
    return entries


def assert_in_scope(target: str, scope_file: str | Path) -> None:
    """Raise ScopeError if `target` is not authorized by `scope_file`."""
    entries = load_scope(scope_file)
    t_host, t_port = _host_port(target)
    if not t_host:
        raise ScopeError(f"out of scope: could not parse host from target '{target}'")
    for s_host, s_port in entries:
        if s_host != t_host:
            continue
        # If the scope entry pins a port, the target must match it.
        if s_port is not None and t_port is not None and s_port != t_port:
            continue
        return
    raise ScopeError(
        f"out of scope: target host '{t_host}' is not authorized by the scope file"
    )
