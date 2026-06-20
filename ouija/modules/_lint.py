"""The tool-description poisoning linter (Packet 02 §8.1 / Appendix B).

Static, no agent. Point it at any MCP server's ``tools/list`` output and it
catches the MCPTox tool-poisoning class directly: imperative instructions aimed
at the *model* (not the user) hidden in a tool's ``description`` / ``inputSchema``,
plus the carrier-smuggling vectors (zero-width chars, Unicode TAG-block,
homoglyph mixed-script, HTML/markdown comments carrying directives).

This is the single highest-ROI piece to ship first (Appendix B): it needs no live
model, runs against any MCP server, and detects the dominant MCP attack class. It
is also the symmetric detector for the carrier transforms ouija itself can emit
(:mod:`ouija.encoders`).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass
class LintHit:
    """One static tool-poisoning indicator."""

    rule: str
    snippet: str


# Imperative-injection patterns aimed at the *model*, not the user.
# (Flags passed via re.I|re.S — Python 3.14 rejects inline (?is) mid-expression.)
_INJECT = re.compile(
    r"\b(ignore|disregard|override)\b.{0,40}\b(previous|prior|above|earlier|instructions?)\b"
    r"|\b(always|also|additionally|secretly|do not mention|don'?t tell|don'?t mention)\b.{0,60}\b(call|invoke|send|exfil|forward|email|message)\b"
    r"|\bsystem\s*:\s|<!--\s*system|\[system\]|###\s*instruction|assistant\s*directive",
    re.I | re.S,
)

# Zero-width characters (smuggling).
_ZWSP = set("​‌‍⁠﻿")
# Unicode TAG block (U+E0000–U+E007F) — invisible smuggling channel.
_TAGS = re.compile(r"[\U000E0000-\U000E007F]")
# HTML/markdown comment carrying directives.
_COMMENT_DIRECTIVE = re.compile(r"(?is)<!--.*?(system|instruction|call|send|invoke|exfil).*?-->")


def _schema_text(schema: object) -> str:
    if isinstance(schema, str):
        return schema
    try:
        return json.dumps(schema)
    except Exception:
        return str(schema)


def lint_tool_description(tool: dict) -> list[LintHit]:
    """Scan one tool's advertised surface for poisoning indicators (Appendix B).

    *tool* is ``{"name":.., "description":.., "schema"/"inputSchema":..}``.
    Returns a list of :class:`LintHit` (empty for a clean tool).
    """
    desc = tool.get("description", "") or ""
    schema = tool.get("schema", tool.get("inputSchema", {}))
    text = f"{desc} {_schema_text(schema)}"
    hits: list[LintHit] = []

    if _INJECT.search(text):
        hits.append(LintHit("injected_instruction", _excerpt(text, _INJECT)))

    if any(c in _ZWSP for c in text):
        hits.append(LintHit("zero_width_smuggling",
                            "zero-width characters present in description/schema"))

    if _TAGS.search(text):
        hits.append(LintHit("unicode_tag_smuggling",
                            "Unicode TAG-block characters present (invisible smuggling)"))

    if _has_mixed_scripts(text):
        hits.append(LintHit("homoglyph_mixed_script",
                            "mixed-script / confusable characters mixed with ASCII"))

    if _COMMENT_DIRECTIVE.search(text):
        hits.append(LintHit("comment_carried_directive",
                            _excerpt(text, _COMMENT_DIRECTIVE)))

    return hits


def _has_mixed_scripts(s: str) -> bool:
    """True if alphabetic chars mix Latin with Cyrillic/Greek (homoglyph red flag)."""
    import unicodedata

    scripts: set[str] = set()
    for ch in s:
        if ch.isalpha() and ord(ch) > 0x7F:
            try:
                scripts.add(unicodedata.name(ch).split()[0])
            except ValueError:
                pass
        elif ch.isalpha():
            scripts.add("LATIN")
    interesting = {x for x in scripts if x in {"LATIN", "CYRILLIC", "GREEK"}}
    return len(interesting) > 1


def _excerpt(text: str, pattern: re.Pattern, ctx: int = 40) -> str:
    m = pattern.search(text)
    if not m:
        return text[:80]
    start = max(0, m.start() - ctx)
    end = min(len(text), m.end() + ctx)
    return ("…" if start else "") + text[start:end].replace("\n", " ").strip() + (
        "…" if end < len(text) else ""
    )
