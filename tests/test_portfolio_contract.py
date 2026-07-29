from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agentic_security_harness.portfolio_contract import (
    AdapterAudit,
    AdvisoryAssessment,
    CanonicalObservationEvent,
    SafeEvidencePointer,
    evaluate_shadow_event,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
GIT_SHA = "d" * 40
NOW = datetime(2026, 7, 28, 10, 0, tzinfo=UTC)


def _event(**updates: object) -> CanonicalObservationEvent:
    data: dict[str, object] = {
        "event_id": SHA_A,
        "project_id": "agentic-security-harness",
        "repository_id": "krivonosoff161/agentic-security-harness",
        "repository_sha": GIT_SHA,
        "occurred_at": NOW,
        "producer_id_hash": SHA_B,
        "producer_attestation": "unattested",
        "source_surface": "agent",
        "activity": "handoff.summary",
        "entity_refs": (
            SafeEvidencePointer(kind="trace", digest=SHA_C, locator_id=SHA_B),
        ),
        "data_envelope_ref": SHA_C,
        "telemetry_state": "complete",
    }
    data.update(updates)
    return CanonicalObservationEvent.model_validate(data)


def _assessment(**updates: object) -> AdvisoryAssessment:
    data: dict[str, object] = {
        "assessment_id": SHA_B,
        "event_id": SHA_A,
        "family_ids": ("T02",),
        "disposition": "challenge",
        "reason_codes": ("envelope.summary_boundary_loss",),
        "detector_version": "synthetic-v0",
        "policy_version": "portfolio-v0",
    }
    data.update(updates)
    return AdvisoryAssessment.model_validate(data)


def test_shadow_slice_challenges_without_operational_authority() -> None:
    decision = evaluate_shadow_event(_event(), (_assessment(),), decided_at=NOW)

    assert decision.disposition == "challenge"
    assert decision.operational_authority == "none"
    assert set(decision.model_dump()) == {
        "schema_version",
        "event_id",
        "disposition",
        "reason_codes",
        "assessment_ids",
        "decided_at",
        "operational_authority",
    }


def test_incomplete_telemetry_forces_abstention() -> None:
    decision = evaluate_shadow_event(
        _event(telemetry_state="incomplete"),
        (_assessment(disposition="observe"),),
        decided_at=NOW,
    )

    assert decision.disposition == "abstain"
    assert decision.reason_codes == ("telemetry.incomplete",)


def test_missing_assessment_forces_abstention() -> None:
    decision = evaluate_shadow_event(_event(), (), decided_at=NOW)
    assert decision.disposition == "abstain"
    assert decision.reason_codes == ("advisory.missing",)


def test_advisory_inconclusive_forces_abstention() -> None:
    decision = evaluate_shadow_event(
        _event(),
        (_assessment(disposition="inconclusive"),),
        decided_at=NOW,
    )

    assert decision.disposition == "abstain"


def test_assessment_must_bind_exact_event() -> None:
    with pytest.raises(ValueError, match="exact event"):
        evaluate_shadow_event(
            _event(),
            (_assessment(event_id=SHA_C),),
            decided_at=NOW,
        )


def test_event_rejects_unknown_or_raw_content_fields() -> None:
    data = _event().model_dump()
    data["raw_prompt"] = "secret-shaped synthetic text"

    with pytest.raises(ValidationError):
        CanonicalObservationEvent.model_validate(data)


def test_event_rejects_naive_time_and_self_parent() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        _event(occurred_at=datetime(2026, 7, 28, 10, 0))
    with pytest.raises(ValidationError, match="own parent"):
        _event(parent_event_ids=(SHA_A,))
    with pytest.raises(ValidationError, match="supported range"):
        _event(occurred_at=datetime(9999, 1, 1, tzinfo=UTC))


def test_verified_attestation_cannot_be_self_declared_in_observation() -> None:
    with pytest.raises(ValidationError):
        _event(producer_attestation="verified")


def test_advisory_cannot_represent_allow() -> None:
    with pytest.raises(ValidationError):
        _assessment(disposition="allow")


def test_adapter_audit_requires_authority_downgrade_for_synthesis() -> None:
    with pytest.raises(ValidationError, match="authority downgrade"):
        AdapterAudit(
            source_model="transfer_verifier.transfer_envelope",
            completeness="partial",
            mapped_fields=("producer",),
            dropped_fields=("payload",),
            synthesized_fields=("producer_id_hash",),
            authority_downgrade=False,
            reason_codes=("adapter.raw_identity_requires_pseudonymizer",),
        )


def test_adapter_audit_field_classifications_are_pairwise_disjoint() -> None:
    with pytest.raises(ValidationError, match="disjoint"):
        AdapterAudit(
            source_model="runtime_guard.observation_event",
            completeness="complete",
            mapped_fields=("event_id",),
            dropped_fields=(),
            synthesized_fields=("event_id",),
            authority_downgrade=True,
            reason_codes=(),
        )


def test_decision_cannot_precede_observation() -> None:
    with pytest.raises(ValueError, match="cannot precede"):
        evaluate_shadow_event(
            _event(),
            (_assessment(),),
            decided_at=datetime(2026, 7, 28, 9, 59, tzinfo=UTC),
        )


def test_partial_adapter_requires_reason_code() -> None:
    with pytest.raises(ValidationError, match="require reason codes"):
        AdapterAudit(
            source_model="runtime_guard.observation_event",
            completeness="partial",
            mapped_fields=("event_id",),
            dropped_fields=("authority_envelope_ref",),
            synthesized_fields=(),
            authority_downgrade=True,
            reason_codes=(),
        )
