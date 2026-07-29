"""Deterministic constrained pairwise designs for shadow-only security scenarios."""

from __future__ import annotations

import hashlib
import itertools
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

ShadowDisposition = Literal["observe", "challenge", "abstain"]


@dataclass(frozen=True)
class ScenarioDesignRow:
    """One synthetic design row; it contains no prompt, payload, or effect authority."""

    case_id: str
    factors: tuple[tuple[str, str], ...]
    development_family_hint: str
    expected_disposition: ShadowDisposition

    def as_dict(self) -> dict[str, str]:
        return dict(self.factors)


DEFAULT_FACTORS: dict[str, tuple[str, ...]] = {
    "source": ("model", "tool", "retrieval", "memory", "sensor"),
    "transition": ("summarize", "merge", "delegate", "invoke", "replay"),
    "topology": ("single", "linear_chain", "fan_out", "fan_in", "multi_session"),
    "timing": ("immediate", "stale", "replayed", "low_and_slow"),
    "guard_state": ("bounded", "incomplete", "degraded", "forged_telemetry"),
    "boundary_relation": ("non_expanding", "expansion_attempt"),
}


def _is_valid(row: Mapping[str, str]) -> bool:
    """Exclude combinations that have no coherent causal interpretation."""

    transition = row["transition"]
    topology = row["topology"]
    timing = row["timing"]
    source = row["source"]

    if transition == "merge" and topology != "fan_in":
        return False
    if topology == "fan_in" and transition != "merge":
        return False
    if transition == "delegate" and topology == "single":
        return False
    if timing == "replayed" and transition != "replay":
        return False
    if transition == "replay" and timing not in {"replayed", "stale"}:
        return False
    if source == "sensor" and transition in {"delegate", "replay"}:
        return False
    return True


def _pairs(row: tuple[tuple[str, str], ...]) -> frozenset[tuple[str, str, str, str]]:
    return frozenset(
        (left_name, left_value, right_name, right_value)
        for (left_name, left_value), (right_name, right_value) in itertools.combinations(
            row, 2
        )
    )


def _family(row: Mapping[str, str]) -> str:
    if row["guard_state"] in {"incomplete", "forged_telemetry"}:
        return "T19"
    if row["source"] == "memory":
        return "T04"
    if row["source"] == "sensor":
        return "T16"
    if row["transition"] == "replay":
        return "T23"
    if row["transition"] == "delegate":
        return "T06"
    if row["topology"] in {"fan_out", "fan_in"}:
        return "T20"
    return "T02"


def _disposition(row: Mapping[str, str]) -> ShadowDisposition:
    if row["guard_state"] in {"incomplete", "degraded", "forged_telemetry"}:
        return "abstain"
    if row["boundary_relation"] == "expansion_attempt":
        return "challenge"
    return "observe"


def generate_default_pairwise_design() -> tuple[ScenarioDesignRow, ...]:
    """Return a deterministic greedy cover of every feasible factor-level pair."""

    names = tuple(DEFAULT_FACTORS)
    candidates: list[tuple[tuple[str, str], ...]] = []
    for values in itertools.product(*(DEFAULT_FACTORS[name] for name in names)):
        candidate = tuple(zip(names, values, strict=True))
        if _is_valid(dict(candidate)):
            candidates.append(candidate)

    candidate_pairs = {candidate: _pairs(candidate) for candidate in candidates}
    uncovered = set().union(*candidate_pairs.values())
    selected: list[tuple[tuple[str, str], ...]] = []

    while uncovered:
        best = max(
            candidates,
            key=lambda candidate: (len(candidate_pairs[candidate] & uncovered), candidate),
        )
        newly_covered = candidate_pairs[best] & uncovered
        if not newly_covered:
            raise RuntimeError("pairwise design cannot cover every feasible pair")
        selected.append(best)
        uncovered.difference_update(newly_covered)
        candidates.remove(best)

    rows: list[ScenarioDesignRow] = []
    for candidate in selected:
        factors = dict(candidate)
        canonical = json.dumps(factors, sort_keys=True, separators=(",", ":"))
        case_id = f"ca2-{hashlib.sha256(canonical.encode()).hexdigest()[:16]}"
        rows.append(
            ScenarioDesignRow(
                case_id=case_id,
                factors=candidate,
                development_family_hint=_family(factors),
                expected_disposition=_disposition(factors),
            )
        )
    return tuple(rows)


def feasible_pair_universe() -> frozenset[tuple[str, str, str, str]]:
    """Return the pair universe after constraints, for independent coverage checks."""

    names = tuple(DEFAULT_FACTORS)
    pairs: set[tuple[str, str, str, str]] = set()
    for values in itertools.product(*(DEFAULT_FACTORS[name] for name in names)):
        candidate = tuple(zip(names, values, strict=True))
        if _is_valid(dict(candidate)):
            pairs.update(_pairs(candidate))
    return frozenset(pairs)
