from typing import Any

import pytest

from agentic_security_harness.memory_governance import (
    MemoryGovernanceRecord,
    MemoryReadRequest,
    select_governed_memory,
    validate_memory_read,
)
from agentic_security_harness.models import DataEnvelope


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


def _record(**updates: Any) -> MemoryGovernanceRecord:
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


def _request(**updates: Any) -> MemoryReadRequest:
    fields: dict[str, Any] = {
        "key": "briefing",
        "read_envelope": _env(allowed_recipients=["agent_a"], ttl_seconds=30),
        "reader_scope_id": "user_a",
        "read_at_step": 20,
        "min_trust_level": "user",
    }
    fields.update(updates)
    return MemoryReadRequest(**fields)


def test_memory_read_accepts_preserved_metadata() -> None:
    decision = validate_memory_read(_record(), _request())

    assert decision.ok
    assert decision.violations == ()


def test_memory_read_rejects_expired_ttl_from_write_time() -> None:
    decision = validate_memory_read(_record(), _request(read_at_step=71))

    assert decision.ok is False
    assert decision.violations == ("read:ttl_expired_from_write_time",)


def test_memory_read_rejects_scope_mismatch() -> None:
    decision = validate_memory_read(_record(scope_id="user_a"), _request(reader_scope_id="user_b"))

    assert decision.ok is False
    assert decision.violations == ("scope_mismatch",)


@pytest.mark.parametrize(
    ("read_envelope", "expected"),
    [
        (_env(allowed_recipients=["agent_a", "agent_b"]), "read:allowed_recipients_expanded"),
        (_env(allowed_purpose=["summarize", "export"]), "read:allowed_purpose_expanded"),
        (_env(can_forward=True), "read:can_forward_weakened"),
        (_env(data_class="public"), "read:data_class_downgraded"),
        (_env(classification_source="untrusted"), "read:classification_source_downgraded"),
    ],
)
def test_memory_read_rejects_read_time_envelope_drift(
    read_envelope: DataEnvelope, expected: str
) -> None:
    decision = validate_memory_read(_record(), _request(read_envelope=read_envelope))

    assert decision.ok is False
    assert expected in decision.violations


def test_memory_read_rejects_missing_provenance_metadata() -> None:
    with pytest.raises(ValueError, match="source_channel"):
        _record(source_channel="")


def test_memory_read_rejects_low_trust_record() -> None:
    decision = validate_memory_read(
        _record(trust_level="tool_output"),
        _request(min_trust_level="trusted_policy"),
    )

    assert decision.ok is False
    assert decision.violations == ("trust_too_low",)


def test_memory_read_rejects_lower_trust_override_when_higher_trust_record_exists() -> None:
    trusted = _record(value_hash="sha256:trusted", trust_level="trusted_policy", written_at_step=10)
    lower = _record(value_hash="sha256:tool", trust_level="tool_output", written_at_step=20)

    decision = validate_memory_read(
        lower,
        _request(min_trust_level="untrusted", read_at_step=30),
        competing_records=(trusted,),
    )

    assert decision.ok is False
    assert "trust_precedence_violation" in decision.violations


def test_select_governed_memory_prefers_higher_trust_over_newer_lower_trust() -> None:
    trusted = _record(value_hash="sha256:trusted", trust_level="trusted_policy", written_at_step=10)
    newer_lower = _record(value_hash="sha256:tool", trust_level="tool_output", written_at_step=20)

    selected = select_governed_memory(
        (newer_lower, trusted),
        _request(min_trust_level="untrusted", read_at_step=30),
    )

    assert selected is not None
    assert selected.value_hash == "sha256:trusted"
