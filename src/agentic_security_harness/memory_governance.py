"""Deterministic memory-governance checks for synthetic agent memory records.

This module intentionally stays below a real memory-store implementation. It models
the invariants a memory read must satisfy before stored content can influence a later
agent decision:

* the stored/read envelopes do not weaken the write envelope;
* TTL is measured from the write event, not restarted at read time;
* provenance and trust labels are present;
* lower-trust records cannot override higher-trust records for the same key/scope;
* a reader cannot cross a user/session scope boundary.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.envelope_policy import validate_memory_read_envelope
from agentic_security_harness.models import DataEnvelope

TrustLevel = Literal["untrusted", "tool_output", "user", "trusted_policy", "system"]

TRUST_RANK: dict[TrustLevel, int] = {
    "untrusted": 0,
    "tool_output": 1,
    "user": 2,
    "trusted_policy": 3,
    "system": 4,
}


class MemoryGovernanceRecord(BaseModel):
    """A synthetic memory record with governance metadata.

    ``value_hash`` is used instead of raw content so tests and public docs can discuss
    memory behavior without committing sensitive text.
    """

    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1)
    value_hash: str = Field(min_length=1)
    write_envelope: DataEnvelope
    stored_envelope: DataEnvelope
    source_channel: str = Field(min_length=1)
    trust_level: TrustLevel
    scope_id: str = Field(min_length=1)
    written_at_step: int = Field(ge=0)


class MemoryReadRequest(BaseModel):
    """A synthetic read request against one memory key."""

    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1)
    read_envelope: DataEnvelope
    reader_scope_id: str = Field(min_length=1)
    read_at_step: int = Field(ge=0)
    min_trust_level: TrustLevel = "untrusted"


class MemoryGovernanceDecision(BaseModel):
    """Deterministic result of a memory-governance check."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    violations: tuple[str, ...] = ()


def validate_memory_read(
    record: MemoryGovernanceRecord,
    request: MemoryReadRequest,
    *,
    competing_records: tuple[MemoryGovernanceRecord, ...] = (),
) -> MemoryGovernanceDecision:
    """Validate whether ``record`` may satisfy ``request``.

    The check is conservative and deterministic. It does not prove semantic truthfulness
    of the stored value; it only verifies that the governance metadata did not weaken.
    """

    violations: list[str] = []

    if record.key != request.key:
        violations.append("key_mismatch")
    if record.scope_id != request.reader_scope_id:
        violations.append("scope_mismatch")
    if request.read_at_step < record.written_at_step:
        violations.append("read_before_write")
    if TRUST_RANK[record.trust_level] < TRUST_RANK[request.min_trust_level]:
        violations.append("trust_too_low")

    envelope = validate_memory_read_envelope(
        write_envelope=record.write_envelope,
        stored_envelope=record.stored_envelope,
        read_envelope=request.read_envelope,
        elapsed_seconds=max(0, request.read_at_step - record.written_at_step),
    )
    violations.extend(envelope.violations)

    for competitor in competing_records:
        if competitor.key != record.key or competitor.scope_id != record.scope_id:
            continue
        if TRUST_RANK[competitor.trust_level] > TRUST_RANK[record.trust_level]:
            violations.append("trust_precedence_violation")
            break

    return MemoryGovernanceDecision(ok=not violations, violations=tuple(violations))


def select_governed_memory(
    records: tuple[MemoryGovernanceRecord, ...],
    request: MemoryReadRequest,
) -> MemoryGovernanceRecord | None:
    """Return the highest-trust valid record for ``request`` or ``None``.

    This helper is the toy policy for trust precedence: among valid records for the same
    key and scope, prefer higher trust, then the newest write. It is not a storage engine.
    """

    valid: list[MemoryGovernanceRecord] = []
    for record in records:
        if record.key != request.key or record.scope_id != request.reader_scope_id:
            continue
        decision = validate_memory_read(record, request)
        if decision.ok:
            valid.append(record)

    if not valid:
        return None

    return max(valid, key=lambda item: (TRUST_RANK[item.trust_level], item.written_at_step))
