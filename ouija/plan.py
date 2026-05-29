"""Dry-run / plan mode: enumerate what a scan WILL send, sending nothing.

A bug-bounty hunter (and a CI pipeline) wants to know the blast radius of a run
*before* spending requests and tokens against a production endpoint: how many
requests will hit the target, which attack classes, which mutators, what the
indirect-injection / multi-turn shape is. ``--plan`` answers that without making
a single request to the target — the scope gate still runs first, so a preview is
only ever produced for an authorized host.

This module is a **pure function** over the same inputs the scanner consumes
(``LoadedSet`` + the mutator/repeats/inject-via/multi-turn knobs) and re-derives
the *exact* request-count math the scanner's fan-out uses, so the plan and the
real run never disagree. It performs no I/O and imports nothing network-related,
which is what lets the CLI guarantee ``--plan`` is side-effect-free.

[Worker decision (Phase 2 / R25): emitted as its own ``ScanPlan`` pydantic model
rather than reusing ``ScanResult`` — a plan has no findings, and conflating the
two schemas would let a downstream triage consumer mistake a preview for a
result. The JSON plan is machine-readable for triage/CI integration; a stable
human-readable text rendering is the fallback for non-JSON ``--format`` values
(h1md/sarif are finding-shaped and meaningless for a zero-finding preview).]
"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

from ouija import __version__
from ouija.conversation import ladders
from ouija.corpus import LoadedSet
from ouija.indirect import DEFAULT_INJECT_VIA
from ouija.mutate import DEFAULT_MUTATOR_SET, mutate
from ouija.models import AttackPattern


class PlannedAttackSet(BaseModel):
    """Per-attack-set breakdown of a planned scan."""

    # The corpus category this group of patterns belongs to (e.g.
    # "prompt_injection") — useful for triage routing.
    category: str
    # Number of base patterns in this set.
    patterns: int
    # Mutated variants per pattern (surface=4, all=9). Multiplied by patterns
    # and repeats to give this set's request count.
    variants_per_pattern: int
    # Total requests this set contributes: patterns * variants_per_pattern * repeats.
    requests: int


class PlannedLadder(BaseModel):
    """One scripted Crescendo ladder in a multi-turn plan."""

    id: str
    name: str
    category: str
    # Maximum conversation turns this ladder would issue (the scanner stops early
    # at the first turn that trips detection, so this is the upper bound).
    max_turns: int


class ScanPlan(BaseModel):
    """A dry-run preview of a scan: what WILL be sent, with nothing sent yet.

    Distinct from :class:`ouija.models.ScanResult` — a plan carries no findings.
    Emitted by ``--plan`` so a hunter or CI pipeline can size a run (request
    count, attack classes, mode) before spending requests against the target.
    """

    tool: str = "ouija"
    version: str
    # Echoes the kind of artifact so a consumer never confuses a plan with a
    # result even if it inspects only the top-level keys.
    kind: str = "plan"
    target: str
    attack_set: str
    multi_turn: bool = False
    mutator_set: str
    repeats: int
    inject_via: str
    # Total requests the run will send to the target (the headline number).
    total_requests: int
    # Single-shot breakdown (empty in multi-turn mode).
    attack_sets: list[PlannedAttackSet] = Field(default_factory=list)
    # Multi-turn breakdown (empty in single-shot mode).
    ladders: list[PlannedLadder] = Field(default_factory=list)


def _variants_per_pattern(pattern: AttackPattern, mutator_set: str) -> int:
    """Count the variants ``mutate`` yields for one pattern.

    Derived by actually running the generator so it can never drift from the
    scanner's real fan-out — the single source of truth for variant expansion is
    :func:`ouija.mutate.mutate`.
    """
    return sum(1 for _ in mutate(pattern, mutator_set))


def build_plan(
    *,
    target: str,
    attack_set_name: str,
    loaded: LoadedSet,
    repeats: int = 1,
    mutator_set: str = DEFAULT_MUTATOR_SET,
    inject_via: str = DEFAULT_INJECT_VIA,
    multi_turn: bool = False,
) -> ScanPlan:
    """Compute the dry-run plan for a scan. Pure: sends nothing, no I/O.

    Re-derives the scanner's request-count math so the preview matches the real
    run exactly. In multi-turn mode the single-shot knobs (attack_set, mutators,
    repeats, inject_via) are ignored — mirroring the scanner — and the plan
    enumerates the Crescendo ladders and their maximum turn counts instead.
    """
    if multi_turn:
        planned_ladders: list[PlannedLadder] = []
        total = 0
        for ladder in ladders():
            max_turns = len(ladder.turns)
            total += max_turns
            planned_ladders.append(
                PlannedLadder(
                    id=ladder.id,
                    name=ladder.name,
                    category=ladder.category,
                    max_turns=max_turns,
                )
            )
        return ScanPlan(
            version=__version__,
            target=target,
            attack_set=attack_set_name,
            multi_turn=True,
            mutator_set=mutator_set,
            repeats=repeats,
            inject_via=inject_via,
            total_requests=total,
            ladders=planned_ladders,
        )

    # Single-shot: group patterns by their corpus category, then size each group
    # with the scanner's exact variants * repeats math.
    by_category: dict[str, list[AttackPattern]] = {}
    for pattern in loaded.patterns:
        category = loaded.meta[pattern.id]["category"]
        by_category.setdefault(category, []).append(pattern)

    attack_sets: list[PlannedAttackSet] = []
    total = 0
    for category, patterns in by_category.items():
        # Every pattern in a set yields the same variant count (mutate's expansion
        # depends only on the mutator_set, not pattern contents), so sample the
        # first to size the whole group.
        vpp = _variants_per_pattern(patterns[0], mutator_set)
        requests = len(patterns) * vpp * repeats
        total += requests
        attack_sets.append(
            PlannedAttackSet(
                category=category,
                patterns=len(patterns),
                variants_per_pattern=vpp,
                requests=requests,
            )
        )

    return ScanPlan(
        version=__version__,
        target=target,
        attack_set=attack_set_name,
        multi_turn=False,
        mutator_set=mutator_set,
        repeats=repeats,
        inject_via=inject_via,
        total_requests=total,
        attack_sets=attack_sets,
    )


def plan_to_json(plan: ScanPlan) -> str:
    """Render a plan as indented JSON (machine-readable, triage/CI integration)."""
    return json.dumps(plan.model_dump(mode="json"), indent=2)


def plan_to_text(plan: ScanPlan) -> str:
    """Render a plan as a stable human-readable summary.

    Used as the fallback for non-JSON ``--format`` values, since the
    finding-shaped h1md/sarif renderers are meaningless for a zero-finding
    preview.
    """
    lines: list[str] = []
    lines.append(f"ouija scan plan (dry run — no requests sent) — {plan.target}")
    lines.append(f"  tool version : ouija v{plan.version}")
    lines.append(f"  attack set   : {plan.attack_set}")
    if plan.multi_turn:
        lines.append("  mode         : multi-turn (Crescendo)")
        lines.append(f"  ladders      : {len(plan.ladders)}")
        lines.append(
            f"  total turns  : {plan.total_requests} (upper bound; "
            "early-exit on first success)"
        )
        lines.append("")
        lines.append("  Ladders:")
        for ladder in plan.ladders:
            lines.append(
                f"    - {ladder.id} [{ladder.category}] "
                f"max {ladder.max_turns} turn(s)"
            )
    else:
        lines.append("  mode         : single-shot")
        lines.append(f"  mutators     : {plan.mutator_set}")
        lines.append(f"  repeats      : {plan.repeats}")
        lines.append(f"  inject-via   : {plan.inject_via}")
        lines.append(f"  total reqs   : {plan.total_requests}")
        lines.append("")
        lines.append("  Per attack set (patterns x variants x repeats = requests):")
        for entry in plan.attack_sets:
            lines.append(
                f"    - {entry.category}: {entry.patterns} x "
                f"{entry.variants_per_pattern} x {plan.repeats} = "
                f"{entry.requests}"
            )
    return "\n".join(lines)


def render_plan(plan: ScanPlan, fmt: str) -> str:
    """Render a plan in the requested format.

    ``json`` produces the machine-readable plan; every other format falls back
    to the human-readable text summary (h1md/sarif are finding-shaped).
    """
    if fmt == "json":
        return plan_to_json(plan)
    return plan_to_text(plan)
