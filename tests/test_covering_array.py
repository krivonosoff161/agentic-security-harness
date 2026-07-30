from __future__ import annotations

from agentic_security_harness.covering_array import (
    DEFAULT_FACTORS,
    feasible_pair_universe,
    generate_default_pairwise_design,
)


def _covered_pairs() -> set[tuple[str, str, str, str]]:
    covered: set[tuple[str, str, str, str]] = set()
    for row in generate_default_pairwise_design():
        for left_index, (left_name, left_value) in enumerate(row.factors):
            for right_name, right_value in row.factors[left_index + 1 :]:
                covered.add((left_name, left_value, right_name, right_value))
    return covered


def test_design_covers_every_feasible_factor_pair() -> None:
    assert _covered_pairs() == set(feasible_pair_universe())


def test_design_is_deterministic_unique_and_smaller_than_cartesian_product() -> None:
    first = generate_default_pairwise_design()
    second = generate_default_pairwise_design()
    cartesian_size = 1
    for levels in DEFAULT_FACTORS.values():
        cartesian_size *= len(levels)

    assert first == second
    assert len({row.case_id for row in first}) == len(first)
    assert len(first) < cartesian_size // 10


def test_constraints_exclude_causally_invalid_rows() -> None:
    for row in generate_default_pairwise_design():
        factors = row.as_dict()
        if factors["transition"] == "merge":
            assert factors["topology"] == "fan_in"
        if factors["topology"] == "fan_in":
            assert factors["transition"] == "merge"
        if factors["timing"] == "replayed":
            assert factors["transition"] == "replay"
        if factors["source"] == "sensor":
            assert factors["transition"] not in {"delegate", "replay"}


def test_shadow_oracle_never_produces_allow_or_effect_authority() -> None:
    rows = generate_default_pairwise_design()
    assert {row.expected_disposition for row in rows} <= {
        "observe",
        "challenge",
        "abstain",
    }
    for row in rows:
        factors = row.as_dict()
        if factors["guard_state"] != "bounded":
            assert row.expected_disposition == "abstain"
        elif factors["boundary_relation"] == "expansion_attempt":
            assert row.expected_disposition == "challenge"
        else:
            assert row.expected_disposition == "observe"
