from __future__ import annotations

import re
from collections import Counter

from agentic_security_harness.scenario_adjudication import build_scenario_adjudication


def test_every_authoritative_builder_unit_has_one_explicit_primary_family() -> None:
    rows = build_scenario_adjudication()
    identities = [(row.source_builder, row.source_id) for row in rows]

    assert len(rows) == 127
    assert len(identities) == len(set(identities))
    assert all(re.fullmatch(r"T(?:0[1-9]|1[0-9]|2[0-6])", row.primary_family) for row in rows)
    assert all(row.causal_case_key.startswith(f"{row.primary_family}:") for row in rows)
    assert len({row.causal_case_key for row in rows}) == len(rows)
    assert {row.review_status for row in rows} == {"provisional_internal_review"}
    assert sum(row.source_builder == "swarm_resilience_campaign" for row in rows) == 7
    assert {row.source_builder for row in rows} == {
        "context_consent_campaign",
        "evidence_campaign",
        "local_swarm_matrix",
        "marketing_web_injection_campaign",
        "memory_rehydration_campaign",
        "planner_task_campaign",
        "rag_context_campaign",
        "secret_leak_campaign",
        "semantic_drift_campaign",
        "semantic_propagation_campaign",
        "swarm_defense_contour",
        "swarm_resilience_campaign",
        "tool_authority_campaign",
    }


def test_equivalence_requires_an_explicit_reviewed_key() -> None:
    rows = build_scenario_adjudication()
    by_identity = {(row.source_builder, row.source_id): row for row in rows}

    assert all(row.equivalence_key is None for row in rows)
    assert (
        by_identity[
            ("local_swarm_matrix", "deep.handoff_payload_rewrite_hash_mismatch")
        ].causal_case_key
        != by_identity[
            ("local_swarm_matrix", "deep.handoff_policy_version_decay")
        ].causal_case_key
    )
    assert (
        by_identity[
            ("swarm_resilience_campaign", "source_trust_poisoning")
        ].primary_family
        == "T10"
    )
    assert (
        by_identity[
            ("local_swarm_matrix", "deep.memory_ttl_removed_on_read")
        ].causal_case_key
        != by_identity[
            ("local_swarm_matrix", "deep.memory_forwarding_weakened_on_store")
        ].causal_case_key
    )


def test_adjudication_keeps_counting_units_visible() -> None:
    counts = Counter(row.unit_kind for row in build_scenario_adjudication())
    assert counts == {
        "case": 64,
        "scenario": 16,
        "variation_row": 43,
        "contour_primitive": 4,
    }
