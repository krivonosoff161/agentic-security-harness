from typing import Any

from agentic_security_harness.envelope_policy import (
    envelope_violations,
    is_envelope_restriction,
    validate_memory_read_envelope,
)
from agentic_security_harness.models import DataEnvelope


def _env(**updates: Any) -> DataEnvelope:
    base = DataEnvelope(
        data_class="confidential",
        allowed_recipients=["agent_a", "agent_b"],
        allowed_purpose=["summarize", "classify"],
        can_store=True,
        can_forward=False,
        ttl_seconds=60,
        requires_confirmation=True,
        classification_source="trusted_policy",
        classification_mutable=False,
    )
    return base.model_copy(update=updates)


def test_equal_envelope_is_restriction() -> None:
    baseline = _env()
    assert is_envelope_restriction(baseline, baseline)


def test_narrower_recipients_purpose_ttl_and_store_are_allowed() -> None:
    baseline = _env()
    candidate = _env(
        allowed_recipients=["agent_a"],
        allowed_purpose=["summarize"],
        can_store=False,
        ttl_seconds=30,
    )
    assert is_envelope_restriction(candidate, baseline)


def test_recipient_and_purpose_expansion_are_rejected() -> None:
    baseline = _env()
    candidate = _env(
        allowed_recipients=["agent_a", "agent_b", "agent_c"],
        allowed_purpose=["summarize", "classify", "export"],
    )
    assert envelope_violations(candidate, baseline) == (
        "allowed_recipients_expanded",
        "allowed_purpose_expanded",
    )


def test_classification_order_direction() -> None:
    baseline = _env(data_class="confidential")
    assert is_envelope_restriction(_env(data_class="restricted"), baseline)
    assert "data_class_downgraded" in envelope_violations(_env(data_class="internal"), baseline)


def test_boolean_weakenings_are_rejected() -> None:
    baseline = _env(
        can_store=False,
        can_forward=False,
        requires_confirmation=True,
        classification_mutable=False,
    )
    candidate = _env(
        can_store=True,
        can_forward=True,
        requires_confirmation=False,
        classification_mutable=True,
    )
    assert envelope_violations(candidate, baseline) == (
        "can_store_weakened",
        "can_forward_weakened",
        "requires_confirmation_removed",
        "classification_mutable_weakened",
    )


def test_ttl_removed_or_expanded_is_rejected() -> None:
    baseline = _env(ttl_seconds=60)
    assert envelope_violations(_env(ttl_seconds=None), baseline) == ("ttl_removed",)
    assert envelope_violations(_env(ttl_seconds=120), baseline) == ("ttl_expanded",)


def test_unknown_classification_or_source_must_stay_identical() -> None:
    baseline = _env(data_class="partner_confidential", classification_source="partner_policy")
    assert is_envelope_restriction(
        _env(data_class="partner_confidential", classification_source="partner_policy"),
        baseline,
    )
    assert envelope_violations(
        _env(data_class="confidential", classification_source="trusted_policy"),
        baseline,
    ) == (
        "data_class_policy_unknown_or_changed",
        "classification_source_policy_unknown_or_changed",
    )


def test_missing_candidate_envelope_is_rejected_when_baseline_exists() -> None:
    assert envelope_violations(None, _env()) == ("missing_envelope",)


def test_memory_read_chain_accepts_preserved_or_narrowed_envelope() -> None:
    write = _env()
    stored = _env(allowed_recipients=["agent_a"], ttl_seconds=30)
    read = _env(allowed_recipients=["agent_a"], ttl_seconds=30, can_store=False)
    result = validate_memory_read_envelope(
        write_envelope=write,
        stored_envelope=stored,
        read_envelope=read,
        elapsed_seconds=20,
    )
    assert result.ok
    assert result.violations == ()


def test_memory_read_chain_rejects_drift_and_expired_ttl_from_write_time() -> None:
    write = _env(can_forward=False, ttl_seconds=60)
    stored = _env(can_forward=False, ttl_seconds=60)
    read = _env(can_forward=True, ttl_seconds=None)
    result = validate_memory_read_envelope(
        write_envelope=write,
        stored_envelope=stored,
        read_envelope=read,
        elapsed_seconds=61,
    )
    assert result.ok is False
    assert result.violations == (
        "read:can_forward_weakened",
        "read:ttl_removed",
        "read:ttl_expired_from_write_time",
    )
