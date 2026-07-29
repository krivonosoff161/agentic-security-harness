from __future__ import annotations

import re
from collections import Counter

from agentic_security_harness.scenario_adjudication import build_scenario_adjudication


def test_every_authoritative_builder_unit_has_one_explicit_primary_family() -> None:
    rows = build_scenario_adjudication()
    identities = [(row.source_builder, row.source_id) for row in rows]

    assert len(rows) == 120
    assert len(identities) == len(set(identities))
    assert all(re.fullmatch(r"T(?:0[1-9]|1[0-9]|2[0-6])", row.primary_family) for row in rows)
    assert all(row.canonical_alias_key.startswith(f"{row.primary_family}:") for row in rows)
    assert {row.review_status for row in rows} == {"provisional_internal_review"}


def test_alias_keys_deduplicate_variants_without_erasing_distinct_invariants() -> None:
    rows = build_scenario_adjudication()
    by_identity = {(row.source_builder, row.source_id): row for row in rows}

    assert (
        by_identity[("evidence_campaign", "db.attack.label_stripping")].canonical_alias_key
        == by_identity[
            ("local_swarm_matrix", "base.handoff_label_stripping")
        ].canonical_alias_key
    )
    assert (
        by_identity[("local_swarm_matrix", "audit.omitted_source_label")].canonical_alias_key
        != by_identity[
            ("local_swarm_matrix", "base.handoff_label_stripping")
        ].canonical_alias_key
    )
    assert (
        by_identity[("local_swarm_matrix", "cross_provider.metadata_drop")].canonical_alias_key
        != by_identity[
            ("local_swarm_matrix", "base.handoff_label_stripping")
        ].canonical_alias_key
    )


def test_adjudication_keeps_counting_units_visible() -> None:
    counts = Counter(row.unit_kind for row in build_scenario_adjudication())
    assert counts == {
        "case": 64,
        "scenario": 9,
        "variation_row": 43,
        "contour_primitive": 4,
    }
