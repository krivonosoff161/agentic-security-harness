"""Authority-free portfolio interchange models for the first shadow integration slice."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_OBJECT_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
PROJECT_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,127}$"
REPOSITORY_ID_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
FAMILY_ID_PATTERN = r"^T(?:0[1-9]|1[0-9]|2[0-6])$"
TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
MAX_SUPPORTED_TIME = datetime(2100, 1, 1, tzinfo=UTC)
PORTFOLIO_OBSERVATION_V1 = "portfolio-observation-v1.0"
PORTFOLIO_OBSERVATION_COMMITMENT_V1 = "portfolio-observation-commitment-v1.0"
PORTFOLIO_OBSERVATION_COMMITMENT_DOMAIN = (
    "agentic-security-portfolio/observation/v1.0"
)
MAX_PORTFOLIO_OBSERVATION_BYTES = 4_096
MAX_OBSERVATION_ENTITY_REFS = 64
MAX_OBSERVATION_PARENT_EVENTS = 64
MAX_ADAPTER_AUDIT_FIELDS = 128
MAX_ADAPTER_AUDIT_MAPPINGS = 128
MAX_ADAPTER_AUDIT_REASON_CODES = 64

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
    """Digest-shaped pointer with no raw payload or machine path.

    Shape validation does not prove that the referenced content exists or is authentic.
    """

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
    producer_attestation: Literal["unattested"] = "unattested"
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
        if self.occurred_at.astimezone(UTC) > MAX_SUPPORTED_TIME:
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


class CanonicalObservationEventV1(BaseModel):
    """Stable authority-free wire observation.

    ``event_id`` remains a producer-claimed digest-shaped identifier. The separate
    :class:`ObservationCommitmentV1` binds canonical bytes without promoting that claim.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["portfolio-observation-v1.0"]
    event_id: str = Field(pattern=SHA256_PATTERN)
    project_id: str = Field(pattern=PROJECT_ID_PATTERN)
    repository_id: str = Field(pattern=REPOSITORY_ID_PATTERN)
    repository_sha: str = Field(pattern=GIT_OBJECT_PATTERN)
    occurred_at: datetime
    producer_id_hash: str = Field(pattern=SHA256_PATTERN)
    producer_attestation: Literal["unattested"]
    source_surface: SourceSurface
    activity: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]{0,127}$",
    )
    entity_refs: tuple[SafeEvidencePointer, ...] = Field(
        max_length=MAX_OBSERVATION_ENTITY_REFS
    )
    parent_event_ids: tuple[
        Annotated[str, Field(pattern=SHA256_PATTERN)], ...
    ] = Field(max_length=MAX_OBSERVATION_PARENT_EVENTS)
    data_envelope_ref: str = Field(pattern=SHA256_PATTERN)
    authority_envelope_ref: str | None = Field(pattern=SHA256_PATTERN)
    telemetry_state: TelemetryState
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_event(self) -> CanonicalObservationEventV1:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        normalized = self.occurred_at.astimezone(UTC)
        if normalized.year < 1970 or normalized > MAX_SUPPORTED_TIME:
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


class ObservationCommitmentV1(BaseModel):
    """Domain-separated commitment to exact canonical observation bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["portfolio-observation-commitment-v1.0"]
    observation_schema_version: Literal["portfolio-observation-v1.0"]
    domain: Literal["agentic-security-portfolio/observation/v1.0"]
    content_sha256: str = Field(pattern=SHA256_PATTERN)
    commitment_sha256: str = Field(pattern=SHA256_PATTERN)
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_commitment(self) -> ObservationCommitmentV1:
        expected = _observation_commitment_digest(
            domain=self.domain,
            observation_schema_version=self.observation_schema_version,
            content_sha256=self.content_sha256,
        )
        if self.commitment_sha256 != expected:
            raise ValueError("commitment does not bind domain, schema, and content")
        return self


class PortfolioObservationContractError(ValueError):
    """Raised when bytes do not satisfy the stable V1 wire contract."""


def encode_portfolio_observation_v1(event: CanonicalObservationEventV1) -> bytes:
    """Return the one canonical UTF-8 JSON representation of a V1 observation."""

    payload = event.model_dump(mode="json")
    payload["occurred_at"] = (
        event.occurred_at.astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise PortfolioObservationContractError(
            "observation cannot be encoded as canonical JSON"
        ) from exc
    if len(encoded) > MAX_PORTFOLIO_OBSERVATION_BYTES:
        raise PortfolioObservationContractError("observation exceeds the V1 byte limit")
    return encoded


def decode_portfolio_observation_v1(payload: bytes) -> CanonicalObservationEventV1:
    """Decode exact canonical V1 bytes; malformed or ambiguous inputs fail closed."""

    if not isinstance(payload, bytes):
        raise PortfolioObservationContractError("observation payload must be bytes")
    if len(payload) > MAX_PORTFOLIO_OBSERVATION_BYTES:
        raise PortfolioObservationContractError("observation exceeds the V1 byte limit")
    try:
        text = payload.decode("utf-8")
        decoded = json.loads(text, object_pairs_hook=_strict_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PortfolioObservationContractError("observation is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise PortfolioObservationContractError("observation must be a JSON object")
    expected_fields = set(CanonicalObservationEventV1.model_fields)
    if set(decoded) != expected_fields:
        raise PortfolioObservationContractError("observation fields do not match V1")
    if decoded.get("schema_version") != PORTFOLIO_OBSERVATION_V1:
        raise PortfolioObservationContractError("unsupported observation schema version")
    try:
        event = CanonicalObservationEventV1.model_validate(decoded)
    except ValueError as exc:
        raise PortfolioObservationContractError("observation values violate V1") from exc
    if encode_portfolio_observation_v1(event) != payload:
        raise PortfolioObservationContractError("observation JSON is not canonical V1")
    return event


def commit_portfolio_observation_v1(
    event: CanonicalObservationEventV1,
) -> ObservationCommitmentV1:
    """Bind schema, domain and exact canonical bytes without trusting ``event_id``."""

    encoded = encode_portfolio_observation_v1(event)
    content_sha256 = hashlib.sha256(encoded).hexdigest()
    return ObservationCommitmentV1(
        schema_version="portfolio-observation-commitment-v1.0",
        observation_schema_version="portfolio-observation-v1.0",
        domain="agentic-security-portfolio/observation/v1.0",
        content_sha256=content_sha256,
        commitment_sha256=_observation_commitment_digest(
            domain=PORTFOLIO_OBSERVATION_COMMITMENT_DOMAIN,
            observation_schema_version=PORTFOLIO_OBSERVATION_V1,
            content_sha256=content_sha256,
        ),
        operational_authority="none",
    )


def portfolio_observation_v1_json_schema() -> dict[str, Any]:
    """Return the generated public JSON Schema for the stable V1 model."""

    return CanonicalObservationEventV1.model_json_schema()


def _observation_commitment_digest(
    *,
    domain: str,
    observation_schema_version: str,
    content_sha256: str,
) -> str:
    commitment_input = "\0".join(
        (domain, observation_schema_version, content_sha256)
    ).encode("ascii")
    return hashlib.sha256(commitment_input).hexdigest()


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PortfolioObservationContractError("duplicate JSON field")
        result[key] = value
    return result


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
        for index, group in enumerate(groups):
            for other in groups[index + 1 :]:
                if set(group) & set(other):
                    raise ValueError("adapter field classifications must be disjoint")
        if any(not TOKEN_PATTERN.fullmatch(value) for group in groups for value in group):
            raise ValueError("adapter field names must be canonical tokens")
        if any(not TOKEN_PATTERN.fullmatch(value) for value in self.reason_codes):
            raise ValueError("adapter reason codes must be canonical tokens")
        if self.synthesized_fields and not self.authority_downgrade:
            raise ValueError("synthesized fields require an authority downgrade")
        if self.completeness != "complete" and not self.reason_codes:
            raise ValueError("non-complete adapters require reason codes")
        return self


class AdapterFieldMappingV1(BaseModel):
    """Explicit source dependency to canonical target mapping."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_fields: tuple[str, ...] = Field(
        min_length=1, max_length=MAX_ADAPTER_AUDIT_FIELDS
    )
    target_fields: tuple[str, ...] = Field(
        min_length=1, max_length=MAX_ADAPTER_AUDIT_FIELDS
    )
    transformation: Literal["identity", "derived"]
    authority_effect: Literal["none", "downgrade"]

    @model_validator(mode="after")
    def _validate_mapping(self) -> AdapterFieldMappingV1:
        groups = (self.source_fields, self.target_fields)
        if any(len(group) != len(set(group)) for group in groups):
            raise ValueError("mapping fields must be unique")
        if any(not TOKEN_PATTERN.fullmatch(value) for group in groups for value in group):
            raise ValueError("mapping fields must be canonical tokens")
        if self.transformation == "identity":
            if len(self.source_fields) != 1 or self.source_fields != self.target_fields:
                raise ValueError("identity mapping requires one identical field")
        return self


class AdapterAuditV1(BaseModel):
    """Exhaustive, authority-aware accounting for one V1 projection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["portfolio-adapter-audit-v1.0"]
    source_model: Literal[
        "harness.runtime_guard_foundation",
        "handoff.metadata_sidecar",
        "runtime_guard.observation_event",
        "transfer_verifier.transfer_envelope",
    ]
    target_model: Literal["portfolio-observation-v1.0"]
    completeness: Literal["complete", "partial", "rejected"]
    source_fields: tuple[str, ...] = Field(
        min_length=1, max_length=MAX_ADAPTER_AUDIT_FIELDS
    )
    target_fields: tuple[str, ...] = Field(
        min_length=1, max_length=MAX_ADAPTER_AUDIT_FIELDS
    )
    mappings: tuple[AdapterFieldMappingV1, ...] = Field(
        max_length=MAX_ADAPTER_AUDIT_MAPPINGS
    )
    dropped_source_fields: tuple[str, ...] = Field(
        max_length=MAX_ADAPTER_AUDIT_FIELDS
    )
    context_target_fields: tuple[str, ...] = Field(
        max_length=MAX_ADAPTER_AUDIT_FIELDS
    )
    constant_target_fields: tuple[str, ...] = Field(
        max_length=MAX_ADAPTER_AUDIT_FIELDS
    )
    authority_downgrade: bool
    reason_codes: tuple[str, ...] = Field(max_length=MAX_ADAPTER_AUDIT_REASON_CODES)
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_audit(self) -> AdapterAuditV1:
        canonical_targets = set(CanonicalObservationEventV1.model_fields)
        if set(self.target_fields) != canonical_targets:
            raise ValueError(
                "target_fields must equal the CanonicalObservationEventV1 field universe"
            )
        if "operational_authority" not in self.constant_target_fields:
            raise ValueError("operational_authority must be a constant target field")
        if "authority_envelope_ref" not in self.constant_target_fields:
            raise ValueError("authority_envelope_ref must be a constant target field")
        declared_groups = (self.source_fields, self.target_fields)
        classified_groups = (
            self.dropped_source_fields,
            self.context_target_fields,
            self.constant_target_fields,
            self.reason_codes,
        )
        if any(len(group) != len(set(group)) for group in (*declared_groups, *classified_groups)):
            raise ValueError("adapter audit field lists must be unique")
        if any(
            not TOKEN_PATTERN.fullmatch(value)
            for group in (*declared_groups, *classified_groups)
            for value in group
        ):
            raise ValueError("adapter audit fields and reasons must be canonical tokens")

        mapped_sources = [value for item in self.mappings for value in item.source_fields]
        mapped_targets = [value for item in self.mappings for value in item.target_fields]
        classified_sources = mapped_sources + list(self.dropped_source_fields)
        classified_targets = (
            mapped_targets
            + list(self.context_target_fields)
            + list(self.constant_target_fields)
        )
        if len(classified_sources) != len(set(classified_sources)):
            raise ValueError("source field classifications must be disjoint")
        if len(classified_targets) != len(set(classified_targets)):
            raise ValueError("target field classifications must be disjoint")
        if set(classified_sources) != set(self.source_fields):
            raise ValueError("source field accounting must be exhaustive")
        if set(classified_targets) != set(self.target_fields):
            raise ValueError("target field accounting must be exhaustive")

        downgrade_required = bool(
            self.dropped_source_fields
            or self.context_target_fields
            or self.constant_target_fields
            or any(
                item.transformation == "derived" or item.authority_effect == "downgrade"
                for item in self.mappings
            )
        )
        if downgrade_required and not self.authority_downgrade:
            raise ValueError("non-identity projection requires an authority downgrade")
        if self.completeness == "complete" and self.dropped_source_fields:
            raise ValueError("complete projection cannot drop source fields")
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
        if any(not re.fullmatch(SHA256_PATTERN, value) for value in self.assessment_ids):
            raise ValueError("assessment ids must be lowercase SHA-256")
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("reason codes must be unique")
        if any(not TOKEN_PATTERN.fullmatch(value) for value in self.reason_codes):
            raise ValueError("reason codes must be canonical tokens")
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
    if decided_at < event.occurred_at:
        raise ValueError("decided_at cannot precede the observed event")
    mismatched = tuple(item for item in assessments if item.event_id != event.event_id)
    if mismatched:
        raise ValueError("every assessment must bind the exact event")

    reason_codes: list[str] = []
    if event.telemetry_state != "complete":
        disposition: ShadowDisposition = "abstain"
        reason_codes.append(f"telemetry.{event.telemetry_state}")
    elif not assessments:
        disposition = "abstain"
        reason_codes.append("advisory.missing")
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
