"""The mutation hook — defer the brain to Packet 06 (Packet 02 §12 / ADR D7 / Appendix D).

ouija ships a *trivial* built-in mutator now and a clean :class:`Mutator`
interface so Packet 06's MCTS / evolutionary / LLM-guided engine drops in without
touching the modules. The built-in does template substitution + the
carrier-encoding transforms (:mod:`ouija.encoders`, ADR D9). The Packet-06 engine
will implement :meth:`Mutator.variants` with a reward loop fed by the oracle's
``Verdict.effect`` / ``confidence`` — the AgentFuzzer/AGENTVIGIL MCTS pattern.

Anti-pattern A10: do **not** build the smart engine here. Ship the hook + a
trivial built-in. The interface is the contract.

This is a *separate* module from the existing v0.1 ``ouija/mutate.py`` (which
mutates ``AttackPattern`` objects for the single-endpoint scanner). The agentic
surface mutates raw seed *strings* and threads oracle feedback, so it gets its
own protocol rather than overloading the v0.1 one.
"""

from __future__ import annotations

from typing import Iterable, Protocol, runtime_checkable

from ouija.encoders import CARRIER_ORDER, CARRIERS


@runtime_checkable
class Mutator(Protocol):
    """The payload-mutation contract Packet 06 implements.

    ``variants`` yields payload strings derived from *seed*. ``budget`` bounds how
    many to produce. ``feedback`` (the oracle's last :class:`~ouija.oracle.Verdict`)
    enables guided search — the built-in ignores it; Packet 06 uses it for a
    reward loop.
    """

    def variants(self, seed: str, *, budget: int = 7, feedback=None) -> Iterable[str]:
        ...


class BuiltinMutator:
    """The trivial built-in: each seed wrapped in the carrier-encoding variants (D7/D9).

    Deterministic and feedback-free. The first variant is always the plain
    (unencoded) seed, so a budget of 1 sends the raw payload. ``feedback`` is
    accepted (to satisfy the protocol) but ignored — that's the seam Packet 06
    fills.
    """

    name = "builtin"

    def __init__(self, carriers: Iterable[str] | None = None) -> None:
        # Default carrier order puts "plain" first (see encoders.CARRIER_ORDER).
        self._order = tuple(carriers) if carriers is not None else CARRIER_ORDER

    def variants(self, seed: str, *, budget: int = 7, feedback=None) -> Iterable[str]:
        n = max(1, budget)
        seen: set[str] = set()
        for cname in self._order[:n]:
            fn = CARRIERS.get(cname)
            if fn is None:
                continue
            out = fn(seed)
            if out in seen:
                continue
            seen.add(out)
            yield out


# A module-level default instance the modules use when no engine is injected.
DEFAULT_MUTATOR: Mutator = BuiltinMutator()


def mutate_seed(seed: str, mutator: Mutator | None = None, *, budget: int = 7,
                feedback=None) -> list[str]:
    """Convenience: materialise a seed's variants with *mutator* (or the default)."""
    m = mutator or DEFAULT_MUTATOR
    return list(m.variants(seed, budget=budget, feedback=feedback))
