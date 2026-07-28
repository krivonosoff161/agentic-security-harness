"""Authority-free portfolio interchange models for the first shadow integration slice."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_OBJECT_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
PROJECT_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,127}$"
REPOSITORY_ID_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
FAMILY_ID_PATTERN = r"^T(?:0[1-9]|1[0-9]|2[0-6])$"
TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")

TelemetryState = Literal["complete", "incomplete", "malformed", "unattested", "conflicting"]
SourceSurface = Literal[
    "user",
    "agent",
    "model",
    "tool",
    "mcp",
    "retrieval",
    "memory",
    "document",
    "app",
    "sensor",
    "environment",
    "provider",
    "audit",
]
AdvisoryDisposition = Literal["observe", "challenge", "escalate", "abstain", "inconclusive"]
ShadowDisposition = Literal["observe", "challenge", "escalate", "abstain"]


class SafeEvidencePointer(BaseModel):
    """Content-bound pointer with no raw payload or machine path."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["artifact", "event", "policy", "trace", "report"]
    digest: str = Field(pattern=SHA256_PATTERN)
    locator_id: str = Field(pattern=SHA256_PATTERN)


class CanonicalObservationEvent(BaseModel):
    """Minimal cross-project observation; it cannot carry operational authority."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["portfolio-observation-v0.1"] = "portfolio-observation-v0.1"
    event_id: str = Field(pattern=SHA256_PATTERN)
    project_id: str = Field(pattern=PROJECT_ID_PATTERN)
    repository_id: str = Field(pattern=REPOSITORY_ID_PATTERN)
    repository_sha: str = Field(pattern=GIT_OBJECT_PATTERN)
    occurred_at: datetime
    producer_id_hash: str = Field(pattern=SHA256_PATTERN)
    producer_attestation: Literal["unattested", "verified"]
    source_surface: SourceSurface
    activity: str = Field(min_length=1, max_length=128)
    entity_refs: tuple[SafeEvidencePointer, ...] = Field(default_factory=tuple)
    parent_event_ids: tuple[str, ...] = Field(default_factory=tuple)
    data_envelope_ref: str = Field(pattern=SHA256_PATTERN)
    authority_envelope_ref: str | None = Field(default=None, pattern=SHA256_PATTERN)
    telemetry_state: TelemetryState
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _validate_event(self) -> CanonicalObservationEvent:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        if self.occurred_at.astimezone(UTC).year < 1970:
            raise ValueError("occurred_at is outside the supported range")
        if not TOKEN_PATTERN.fullmatch(self.activity):
            raise ValueError("activity must be a canonical token")
        if len(self.parent_event_ids) != len(set(self.parent_event_ids)):
            raise ValueError("parent event ids must be unique")
        if any(not re.fullmatch(SHA256_PATTERN, value) for value in self.parent_event_ids):
            raise ValueError("parent event ids must be lowercase SHA-256")
        if self.event_id in self.parent_event_ids:
            raise ValueError("an event cannot be its own parent")
        return self


class AdvisoryAssessment(BaseModel):
    """Non-authoritative detector or semantic-model assessment."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["portfolio-advisory-v0.1"] = "portfolio-advisory-v0.1"
    assessment_id: str = Field(pattern=SHA256_PATTERN)
    event_id: str = Field(pattern=SHA256_PATTERN)
    family_ids: tuple[str, ...] = Field(min_length=1)
    disposition: AdvisoryDisposition
    reason_codes: tuple[str, ...] = Field(min_length=1)
    evidence: tuple[SafeEvidencePointer, ...] = Field(default_factory=tuple)
    detector_version: str = Field(min_length=1, max_length=128)
    policy_version: str = Field(min_length=1, max_length=128)
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _validate_assessment(self) -> AdvisoryAssessment:
        if len(self.family_ids) != len(set(self.family_ids)):
            raise ValueError("family ids must be unique")
        if any(not re.fullmatch(FAMILY_ID_PATTERN, value) for value in self.family_ids):
            raise ValueError("family id is outside the ontology")
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("reason codes must be unique")
        if any(not TOKEN_PATTERN.fullmatch(value) for value in self.reason_codes):
            raise ValueError("reason codes must be canonical tokens")
        return self


class AdapterAudit(BaseModel):
    """Loss accounting for a source-to-canonical projection."""

    model_config = ConfigDict(extra="forbid")

    source_model: Literal[
        "harness.runtime_guard_foundation",
        "runtime_guard.observation_event",
        "transfer_verifier.transfer_envelope",
    ]
    completeness: Literal["complete", "partial", "rejected"]
    mapped_fields: tuple[str, ...]
    dropped_fields: tuple[str, ...]
    synthesized_fields: tuple[str, ...]
    authority_downgrade: bool
    reason_codes: tuple[str, ...]
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _validate_audit(self) -> AdapterAudit:
        groups = (self.mapped_fields, self.dropped_fields, self.synthesized_fields)
        if any(len(group) != len(set(group)) for group in groups):
            raise ValueError("adapter field lists must be unique")
        if set(self.mapped_fields) & set(self.dropped_fields):
            raise ValueError("a field cannot be both mapped and dropped")
        if self.synthesized_fields and not self.authority_downgrade:
            raise ValueError("synthesized fields require an authority downgrade")
        if self.completeness != "complete" and not self.reason_codes:
            raise ValueError("non-complete adapters require reason codes")
        return self


class ShadowDecision(BaseModel):
    """Evidence-only result that has no allow or effect representation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["portfolio-shadow-decision-v0.1"] = (
        "portfolio-shadow-decision-v0.1"
    )
    event_id: str = Field(pattern=SHA256_PATTERN)
    disposition: ShadowDisposition
    reason_codes: tuple[str, ...]
    assessment_ids: tuple[str, ...]
    decided_at: datetime
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _validate_decision(self) -> ShadowDecision:
        if self.decided_at.tzinfo is None or self.decided_at.utcoffset() is None:
            raise ValueError("decided_at must be timezone-aware")
        if len(self.assessment_ids) != len(set(self.assessment_ids)):
            raise ValueError("assessment ids must be unique")
        return self


def evaluate_shadow_event(
    event: CanonicalObservationEvent,
    assessments: tuple[AdvisoryAssessment, ...],
    *,
    decided_at: datetime,
) -> ShadowDecision:
    """Combine authority-free observations without producing an allow decision."""

    if decided_at.tzinfo is None or decided_at.utcoffset() is None:
        raise ValueError("decided_at must be timezone-aware")
    mismatched = tuple(item for item in assessments if item.event_id != event.event_id)
    if mismatched:
        raise ValueError("every assessment must bind the exact event")

    reason_codes: list[str] = []
    if event.telemetry_state != "complete":
        disposition: ShadowDisposition = "abstain"
        reason_codes.append(f"telemetry.{event.telemetry_state}")
    elif any(item.disposition in {"abstain", "inconclusive"} for item in assessments):
        disposition = "abstain"
        reason_codes.append("advisory.incomplete")
    elif any(item.disposition == "escalate" for item in assessments):
        disposition = "escalate"
        reason_codes.append("advisory.escalation")
    elif any(item.disposition == "challenge" for item in assessments):
        disposition = "challenge"
        reason_codes.append("advisory.challenge")
    else:
        disposition = "observe"
        reason_codes.append("advisory.observe_only")

    return ShadowDecision(
        event_id=event.event_id,
        disposition=disposition,
        reason_codes=tuple(reason_codes),
        assessment_ids=tuple(item.assessment_id for item in assessments),
        decided_at=decided_at,
    )
