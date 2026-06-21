"""Variation-matrix tests for boundary-layer research claims.

These tests deliberately read like tables.  Each row corresponds to one public claim
axis in the handoff, authority, or memory-governance theory docs.  The goal is not
larger coverage by accident; it is to make every documented axis executable.
"""

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from agentic_security_harness.handoff_integrity import (
    HandoffEnvelope,
    payload_sha256,
    verify_handoff,
    verify_raw_handoff,
)
from agentic_security_harness.memory_governance import (
    MemoryGovernanceRecord,
    MemoryReadRequest,
    validate_memory_read,
)
from agentic_security_harness.models import DataEnvelope

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
EXPIRES = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)


def _env(**updates: Any) -> DataEnvelope:
    base = DataEnvelope(
        data_class="confidential",
        allowed_recipients=["agent_a"],
        allowed_purpose=["summarize"],
        can_store=True,
        can_forward=False,
        ttl_seconds=60,
        requires_confirmation=True,
        classification_source="trusted_policy",
        classification_mutable=False,
    )
    return base.model_copy(update=updates)


def _summary_envelope(payload: Mapping[str, object]) -> HandoffEnvelope:
    return HandoffEnvelope(
        envelope_id="env-matrix-summary",
        created_at=NOW,
        sender_id="worker",
        receiver_id="senior",
        payload_type="summary",
        payload_hash=payload_sha256(payload),
        source_labels=["user_input:synthetic", "tool_output:synthetic"],
        transformation_chain=[{"agent_id": "worker", "action": "summarize"}],
        authority_scope=["read", "summarize"],
        purpose="brief",
        allowed_recipients=["senior"],
        ttl_seconds=300,
        expires_at=EXPIRES,
        policy_version="handoff-policy-v1",
        receiver_supported_policy_versions=["handoff-policy-v1"],
        audit_entry_hash="audit-1",
    )


def _capability_envelope(payload: Mapping[str, object]) -> HandoffEnvelope:
    return HandoffEnvelope(
        envelope_id="env-matrix-capability",
        created_at=NOW,
        sender_id="worker",
        receiver_id="delegate",
        payload_type="capability",
        payload_hash=payload_sha256(payload),
        authority_issuer="senior",
        authority_scope=["read"],
        purpose="summarize",
        delegation_depth=1,
        max_delegation_depth=1,
        can_delegate=True,
        allowed_recipients=["delegate"],
        ttl_seconds=60,
        expires_at=EXPIRES,
        policy_version="handoff-policy-v1",
        receiver_supported_policy_versions=["handoff-policy-v1"],
        audit_entry_hash="audit-1",
    )


def _memory_record(**updates: Any) -> MemoryGovernanceRecord:
    fields: dict[str, Any] = {
        "key": "briefing",
        "value_hash": "sha256:trusted",
        "write_envelope": _env(),
        "stored_envelope": _env(),
        "source_channel": "trusted_policy_fixture",
        "trust_level": "trusted_policy",
        "scope_id": "user_a",
        "written_at_step": 10,
    }
    fields.update(updates)
    return MemoryGovernanceRecord(**fields)


def _memory_request(**updates: Any) -> MemoryReadRequest:
    fields: dict[str, Any] = {
        "key": "briefing",
        "read_envelope": _env(ttl_seconds=30),
        "reader_scope_id": "user_a",
        "read_at_step": 20,
        "min_trust_level": "user",
    }
    fields.update(updates)
    return MemoryReadRequest(**fields)


def test_handoff_variation_matrix_blocks_each_declared_hard_reason_once() -> None:
    payload = {"summary": "synthetic fact", "source": "fixture"}
    base = _summary_envelope(payload)

    rows: tuple[tuple[str, Callable[[], Sequence[str]]], ...] = (
        (
            "missing_envelope",
            lambda: verify_raw_handoff(None, payload, current_time=NOW).failure_reasons,
        ),
        (
            "verifier_error",
            lambda: verify_raw_handoff(
                {**base.model_dump(mode="json"), "payload_hash": None},
                payload,
                current_time=NOW,
            ).failure_reasons,
        ),
        (
            "integrity_mismatch",
            lambda: verify_handoff(
                base.model_copy(update={"payload_hash": payload_sha256({"other": "bytes"})}),
                payload,
                current_time=NOW,
            ).failure_reasons,
        ),
        (
            "missing_provenance",
            lambda: verify_handoff(
                base.model_copy(update={"source_labels": []}),
                payload,
                current_time=NOW,
            ).failure_reasons,
        ),
        (
            "label_loss",
            lambda: verify_handoff(
                base.model_copy(update={"source_labels": ["tool_output:synthetic"]}),
                payload,
                current_time=NOW,
                parent_source_labels=["user_input:synthetic"],
            ).failure_reasons,
        ),
        (
            "recipient_violation",
            lambda: verify_handoff(
                base.model_copy(update={"receiver_id": "agent_b"}),
                payload,
                current_time=NOW,
            ).failure_reasons,
        ),
        (
            "stale_or_replayed",
            lambda: verify_handoff(
                base.model_copy(update={"expires_at": datetime(2026, 1, 1, 11, 59, tzinfo=UTC)}),
                payload,
                current_time=NOW,
            ).failure_reasons,
        ),
        (
            "policy_mismatch",
            lambda: verify_handoff(
                base.model_copy(update={"policy_version": "handoff-policy-v2"}),
                payload,
                current_time=NOW,
            ).failure_reasons,
        ),
        (
            "verifier_error",
            lambda: verify_handoff(base, payload, current_time=NOW, verifier_available=False)
            .failure_reasons,
        ),
    )

    for expected, run in rows:
        assert expected in run(), expected


def test_authority_non_expansion_matrix_blocks_every_observable_axis() -> None:
    payload = {"capability_id": "cap-1", "scope": ["read"]}
    base = _capability_envelope(payload)

    rows: tuple[tuple[str, dict[str, object]], ...] = (
        ("scope", {"authority_scope": ["read", "write"]}),
        ("issuer", {"authority_issuer": "claimed_supervisor"}),
        ("purpose", {"purpose": "export"}),
        ("ttl", {"ttl_seconds": 3600}),
        ("depth", {"delegation_depth": 2, "max_delegation_depth": 1}),
    )

    clean = verify_handoff(
        base,
        payload,
        current_time=NOW,
        parent_authority_scope=["read"],
        parent_authority_issuer="senior",
        parent_purpose="summarize",
        parent_ttl_seconds=60,
    )
    assert clean.verdict == "pass"

    for axis, update in rows:
        result = verify_handoff(
            base.model_copy(update=update),
            payload,
            current_time=NOW,
            parent_authority_scope=["read"],
            parent_authority_issuer="senior",
            parent_purpose="summarize",
            parent_ttl_seconds=60,
        )
        assert result.verdict == "blocked", axis
        assert result.failure_reasons == ["authority_expansion"], axis


def test_memory_governance_variation_matrix_blocks_each_declared_axis() -> None:
    trusted_competitor = _memory_record(value_hash="sha256:system", trust_level="system")
    rows: tuple[
        tuple[
            str,
            MemoryGovernanceRecord,
            MemoryReadRequest,
            tuple[MemoryGovernanceRecord, ...],
            str,
        ],
        ...,
    ] = (
        ("key binding", _memory_record(), _memory_request(key="other"), (), "key_mismatch"),
        (
            "scope isolation",
            _memory_record(scope_id="user_a"),
            _memory_request(reader_scope_id="user_b"),
            (),
            "scope_mismatch",
        ),
        (
            "time direction",
            _memory_record(written_at_step=10),
            _memory_request(read_at_step=9),
            (),
            "read_before_write",
        ),
        (
            "minimum trust",
            _memory_record(trust_level="tool_output"),
            _memory_request(min_trust_level="trusted_policy"),
            (),
            "trust_too_low",
        ),
        (
            "stored envelope preservation",
            _memory_record(stored_envelope=_env(can_forward=True)),
            _memory_request(),
            (),
            "stored:can_forward_weakened",
        ),
        (
            "read envelope preservation",
            _memory_record(),
            _memory_request(read_envelope=_env(allowed_recipients=["agent_a", "agent_b"])),
            (),
            "read:allowed_recipients_expanded",
        ),
        (
            "ttl from write",
            _memory_record(written_at_step=10),
            _memory_request(read_at_step=71),
            (),
            "read:ttl_expired_from_write_time",
        ),
        (
            "trust precedence",
            _memory_record(value_hash="sha256:tool", trust_level="tool_output"),
            _memory_request(min_trust_level="untrusted", read_at_step=20),
            (trusted_competitor,),
            "trust_precedence_violation",
        ),
    )

    clean = validate_memory_read(_memory_record(), _memory_request())
    assert clean.ok

    for axis, record, request, competitors, expected in rows:
        decision = validate_memory_read(
            record,
            request,
            competing_records=competitors,
        )
        assert decision.ok is False, axis
        assert expected in decision.violations, axis
