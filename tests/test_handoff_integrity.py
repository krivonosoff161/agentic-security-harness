"""Tests for deterministic inter-agent handoff verifier math."""

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from agentic_security_harness.handoff_integrity import (
    HandoffEnvelope,
    canonical_payload_bytes,
    payload_sha256,
    verify_handoff,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
EXPIRES = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "handoff_toy_topology.json"


def _summary_envelope(payload: Mapping[str, object]) -> HandoffEnvelope:
    return HandoffEnvelope(
        envelope_id="env-test-summary",
        created_at=NOW,
        sender_id="worker_a",
        receiver_id="senior",
        task_id="task-1",
        session_id="session-1",
        payload_type="summary",
        payload_hash=payload_sha256(payload),
        source_labels=["user_input:synthetic", "tool_output:synthetic"],
        transformation_chain=[
            {
                "agent_id": "worker_a",
                "action": "summarize",
                "input_hash": payload_sha256({"source": "synthetic"}),
            }
        ],
        authority_scope=["read", "summarize"],
        purpose="brief",
        allowed_recipients=["senior"],
        ttl_seconds=300,
        expires_at=EXPIRES,
        policy_version="handoff-policy-v1",
        receiver_supported_policy_versions=["handoff-policy-v1"],
        audit_entry_hash="audit-1",
    )


def test_payload_hash_is_canonical_and_stable() -> None:
    left = {"b": 2, "a": {"x": 1}}
    right = {"a": {"x": 1}, "b": 2}

    assert canonical_payload_bytes(left) == canonical_payload_bytes(right)
    assert payload_sha256(left) == payload_sha256(right)
    assert len(payload_sha256(left)) == 64


def test_clean_summary_handoff_passes_with_zero_scores() -> None:
    payload = {"summary": "synthetic fact", "source": "fixture"}
    envelope = _summary_envelope(payload)

    result = verify_handoff(
        envelope,
        payload,
        current_time=NOW,
        parent_source_labels=["user_input:synthetic"],
        parent_authority_scope=["read", "summarize"],
    )

    assert result.verdict == "pass"
    assert result.failure_reasons == []
    assert result.structural_score == 0.0
    assert result.semantic_score == 0.0
    assert result.combined_score == 0.0


def test_missing_labels_are_blocked_and_scored_structurally() -> None:
    payload = {"summary": "synthetic fact", "source": "fixture"}
    envelope = _summary_envelope(payload).model_copy(
        update={"source_labels": [], "audit_entry_hash": None}
    )

    result = verify_handoff(
        envelope,
        payload,
        current_time=NOW,
        parent_source_labels=["user_input:synthetic"],
        unsafe_consumptions=1,
        total_consumptions=1,
    )

    assert result.verdict == "blocked"
    assert result.failure_reasons == ["missing_provenance", "label_loss"]
    assert result.structural_score == 1.0
    assert result.semantic_score == 1.0
    assert result.combined_score == 1.0


def test_capability_scope_expansion_is_hard_blocker_with_multiplier() -> None:
    payload = {"capability_id": "cap-2", "scope": ["read", "write"]}
    envelope = HandoffEnvelope(
        envelope_id="env-cap",
        created_at=NOW,
        sender_id="worker",
        receiver_id="delegate",
        payload_type="capability",
        payload_hash=payload_sha256(payload),
        authority_issuer="senior",
        authority_scope=["read", "write"],
        purpose="any",
        delegation_depth=2,
        max_delegation_depth=1,
        can_delegate=True,
        allowed_recipients=["delegate"],
        ttl_seconds=300,
        expires_at=EXPIRES,
        policy_version="handoff-policy-v1",
        receiver_supported_policy_versions=["handoff-policy-v1"],
    )

    result = verify_handoff(
        envelope,
        payload,
        current_time=NOW,
        parent_authority_scope=["read"],
    )

    assert result.verdict == "blocked"
    assert result.failure_reasons == ["authority_expansion"]
    assert result.payload_multiplier == 1.5
    assert result.combined_score == 0.7


def test_integrity_policy_recipient_and_freshness_fail_closed() -> None:
    payload = {"summary": "original"}
    envelope = _summary_envelope(payload).model_copy(
        update={
            "payload_hash": payload_sha256({"summary": "different"}),
            "receiver_id": "unexpected_receiver",
            "expires_at": datetime(2026, 1, 1, 11, 59, tzinfo=UTC),
            "policy_version": "handoff-policy-v2",
        }
    )

    result = verify_handoff(envelope, payload, current_time=NOW)

    assert result.verdict == "blocked"
    assert result.failure_reasons == [
        "integrity_mismatch",
        "recipient_violation",
        "stale_or_replayed",
        "policy_mismatch",
    ]


def test_verifier_outage_is_blocked_not_pass() -> None:
    result = verify_handoff(
        None,
        {"summary": "unverified"},
        current_time=NOW,
        verifier_available=False,
    )

    assert result.verdict == "blocked"
    assert result.failure_reasons == ["verifier_error"]
    assert result.structural_score == 1.0


def test_committed_handoff_fixture_matches_verifier_expectations() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    by_id = {scenario["id"]: scenario for scenario in fixture["scenarios"]}

    summary_payload = {
        "claim": "synthetic briefing item",
        "task": "conference_briefing",
        "source": "trusted_policy_fixture",
    }
    summary = by_id["summary_label_stripping"]
    summary_envelope = _summary_envelope(summary_payload).model_copy(
        update={
            "payload_hash": summary["payload_hash"],
            "source_labels": summary["receiver_source_labels"],
            "audit_entry_hash": None,
        }
    )
    summary_result = verify_handoff(
        summary_envelope,
        summary_payload,
        current_time=NOW,
        parent_source_labels=summary["sender_source_labels"],
    )
    assert summary_result.verdict == summary["expected_verdict"]
    assert summary_result.failure_reasons == summary["expected_failure_reasons"]

    capability = by_id["capability_scope_expansion"]
    delegated_payload = {
        "capability_id": "cap-delegated",
        "subject": "agent_c",
        "scope": ["read", "write"],
        "purpose": "any",
        "ttl_seconds": 3600,
    }
    assert payload_sha256(delegated_payload) == capability["delegated_payload_hash"]
    capability_envelope = HandoffEnvelope(
        envelope_id="env-fixture-capability",
        created_at=NOW,
        sender_id="agent_b",
        receiver_id="agent_c",
        payload_type="capability",
        payload_hash=capability["delegated_payload_hash"],
        authority_issuer=None,
        authority_scope=capability["delegated_authority_scope"],
        purpose="any",
        delegation_depth=2,
        max_delegation_depth=1,
        can_delegate=True,
        allowed_recipients=["agent_c"],
        ttl_seconds=300,
        expires_at=EXPIRES,
        policy_version=fixture["policy_version"],
        receiver_supported_policy_versions=[fixture["policy_version"]],
    )
    capability_result = verify_handoff(
        capability_envelope,
        delegated_payload,
        current_time=NOW,
        parent_authority_scope=capability["parent_authority_scope"],
    )
    assert capability_result.verdict == capability["expected_verdict"]
    assert capability_result.failure_reasons == capability["expected_failure_reasons"]
