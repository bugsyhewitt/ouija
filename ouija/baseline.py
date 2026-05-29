"""Finding baseline / suppression.

A bug-bounty hunter re-runs ouija against the same endpoint many times — after
filing a report, while waiting on triage, after a vendor claims a fix. Without a
way to say "I already know about these," every rerun re-surfaces the same
already-triaged findings, drowning genuinely new ones in noise and (with
``--fail-on``) breaking CI on a bug that is already filed and accepted.

A *baseline* is a snapshot of the finding IDs a hunter has already triaged.
Because finding IDs are deterministic and stable across runs (see
:func:`ouija.detect.stable_finding_id`), a baseline file is just the set of those
IDs. On a later run, any finding whose ID is in the baseline is *suppressed*:
dropped from the rendered report and excluded from the ``--fail-on`` gate, so the
run shows — and the pipeline breaks on — only what is genuinely new.

Two halves of one workflow:

- ``--write-baseline PATH`` snapshots the current run's finding IDs to *PATH*.
- ``--baseline PATH`` reads that file on a later run and suppresses its IDs.

The baseline file format is intentionally forgiving:

- One finding ID per line (``ouija-<prefix>-<8hex>``).
- Blank lines and ``#`` comments are ignored.
- A JSON document produced by ``ouija --format json`` is also accepted: its
  ``findings[].id`` values are extracted. This lets a hunter feed a saved report
  straight back in as a baseline without converting it first.
"""

from __future__ import annotations

import json
from typing import NamedTuple

from ouija.models import ScanResult, ScanSummary

# Reuse the scanner's category -> attack-set mapping for the summary roll-up so a
# suppressed result's ``summary.attack_sets`` stays consistent with a normal run.
from ouija.scanner import _CATEGORY_TO_ATTACK_SET


class BaselineError(Exception):
    """Raised when a baseline file cannot be read or parsed."""


def load_baseline(path: str) -> set[str]:
    """Read *path* and return the set of finding IDs it declares.

    Accepts either the line-oriented format (one ID per line, ``#`` comments and
    blank lines ignored) or a JSON document produced by ``ouija --format json``
    (the ``findings[].id`` values are extracted).

    Raises :class:`BaselineError` if the file cannot be read.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise BaselineError(f"cannot read baseline file {path!r}: {exc}") from exc

    stripped = raw.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return _ids_from_json(raw, path)
    return _ids_from_lines(raw)


def _ids_from_lines(raw: str) -> set[str]:
    """Parse the line-oriented baseline format."""
    ids: set[str] = set()
    for line in raw.splitlines():
        # Strip inline comments and surrounding whitespace.
        text = line.split("#", 1)[0].strip()
        if text:
            ids.add(text)
    return ids


def _ids_from_json(raw: str, path: str) -> set[str]:
    """Extract finding IDs from a saved ``ouija --format json`` document."""
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(
            f"baseline file {path!r} looks like JSON but does not parse: {exc}"
        ) from exc

    # A scan result object, or a bare list of finding objects / id strings.
    findings = doc.get("findings", []) if isinstance(doc, dict) else doc
    ids: set[str] = set()
    for item in findings:
        if isinstance(item, str):
            ids.add(item)
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            ids.add(item["id"])
    return ids


class SuppressionOutcome(NamedTuple):
    """Result of applying a baseline to a scan."""

    result: ScanResult       # a new ScanResult with suppressed findings removed
    suppressed: int          # how many findings the baseline suppressed


def apply_baseline(result: ScanResult, baseline_ids: set[str]) -> SuppressionOutcome:
    """Return *result* with any finding whose ID is in *baseline_ids* removed.

    The returned :class:`~ouija.models.ScanResult` is a copy — the input is left
    untouched. ``patterns_sent`` is preserved (the work was still done), but
    ``findings`` and the ``summary`` roll-up are recomputed over the surviving
    findings only, so the report and the ``--fail-on`` gate both see exactly the
    new findings.
    """
    if not baseline_ids:
        return SuppressionOutcome(result=result, suppressed=0)

    kept = [f for f in result.findings if f.id not in baseline_ids]
    suppressed = len(result.findings) - len(kept)

    per_set: dict[str, int] = {}
    for finding in kept:
        set_name = _CATEGORY_TO_ATTACK_SET.get(finding.category, finding.category)
        per_set[set_name] = per_set.get(set_name, 0) + 1

    new_result = result.model_copy(
        update={
            "findings": kept,
            "summary": ScanSummary(
                total=result.summary.total,
                successful=len(kept),
                attack_sets=per_set,
            ),
        }
    )
    return SuppressionOutcome(result=new_result, suppressed=suppressed)


def write_baseline(result: ScanResult, path: str) -> int:
    """Write the finding IDs of *result* to *path*, one per line.

    The written file is a valid baseline (consumable by :func:`load_baseline`)
    with a header comment recording provenance. Returns the number of IDs
    written. Raises :class:`BaselineError` if the file cannot be written.

    IDs are de-duplicated and sorted so the file is stable and diff-friendly.
    """
    ids = sorted({f.id for f in result.findings})
    lines = [
        "# ouija baseline — suppress these already-triaged finding IDs on rerun",
        f"# target: {result.target}",
        f"# attack_set: {result.attack_set}",
        f"# generated: {result.timestamp}",
        f"# scan_id: {result.scan_id}",
        "",
    ]
    lines.extend(ids)
    body = "\n".join(lines) + "\n"
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    except OSError as exc:
        raise BaselineError(f"cannot write baseline file {path!r}: {exc}") from exc
    return len(ids)
