"""Authority-free R4 companion contracts for portfolio observations.

These records extend, but never modify or promote, ``portfolio-observation-v1.0``.
They deliberately keep scientific labels and raw MCP content outside runtime records.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict, deque
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from agentic_security_harness.portfolio_contract import (
    GIT_OBJECT_PATTERN,
    PROJECT_ID_PATTERN,
    REPOSITORY_ID_PATTERN,
    AdapterAuditV1,
)

SHA256_PATTERN = r"^[0-9a-f]{64}$"
TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
MAX_TRAJECTORY_EVENTS = 4096
MAX_MCP_NODES = 4096
MAX_MCP_DEPTH = 32
MAX_MCP_INPUT_BYTES = 65_536
MAX_MCP_KEY_LENGTH = 128
MAX_COMPANION_RECORD_BYTES = 262_144


class CompanionContractError(ValueError):
    """Raised when a companion record is malformed or non-canonical."""


class _OutcomeBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["portfolio-outcome-v1.0"]
    record_id: str = Field(pattern=SHA256_PATTERN)
    observation_commitment_sha256: str = Field(pattern=SHA256_PATTERN)
    producer_attestation: Literal["unattested"]
    evidence_only: Literal[True]
    executable: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_record_id(self) -> _OutcomeBase:
        payload = self.model_dump(mode="json", exclude={"record_id"})
        expected = _domain_digest("agentic-security-portfolio/outcome-record/v1.0", payload)
        if self.record_id != expected:
            raise ValueError("record id does not bind the outcome content")
        return self


class AdvisoryOutcomeV1(_OutcomeBase):
    layer: Literal["advisory"]
    reported_value: Literal["observe", "challenge", "escalate", "abstain", "inconclusive"]
    candidate_visibility: Literal["visible"]


class PolicyDecisionOutcomeV1(_OutcomeBase):
    layer: Literal["policy_decision"]
    reported_value: Literal["allow", "block", "ask_user", "sandbox_only", "log_only"]
    candidate_visibility: Literal["evaluator_only"]


class VerificationOutcomeV1(_OutcomeBase):
    layer: Literal["verification"]
    reported_value: Literal["pass", "warn", "fail"]
    candidate_visibility: Literal["evaluator_only"]


class ExecutionOutcomeV1(_OutcomeBase):
    layer: Literal["execution"]
    reported_value: Literal["succeeded", "failed", "rejected"]
    candidate_visibility: Literal["evaluator_only"]


class ShadowSinkOutcomeV1(_OutcomeBase):
    layer: Literal["shadow_sink"]
    reported_value: Literal["accepted_no_effect", "rejected_invalid", "incomplete"]
    candidate_visibility: Literal["evaluator_only"]


PortfolioOutcomeV1: TypeAlias = Annotated[
    AdvisoryOutcomeV1
    | PolicyDecisionOutcomeV1
    | VerificationOutcomeV1
    | ExecutionOutcomeV1
    | ShadowSinkOutcomeV1,
    Field(discriminator="layer"),
]
_OUTCOME_ADAPTER: TypeAdapter[PortfolioOutcomeV1] = TypeAdapter(PortfolioOutcomeV1)

MCPTopLevelType: TypeAlias = Literal["object", "array", "scalar"]
MCPDroppedFieldClass: TypeAlias = Literal[
    "credential",
    "locator",
    "raw_argument",
    "raw_error",
    "raw_output",
    "embedded_resource",
    "raw_scalar",
]
MCPTelemetryState: TypeAlias = Literal["complete", "incomplete", "rejected"]
TrajectoryCycleVerdict: TypeAlias = Literal["acyclic", "cycle_detected"]
TrajectoryCompleteness: TypeAlias = Literal["complete", "incomplete", "invalid"]
RetryCause: TypeAlias = Literal[
    "initial", "bounded_retry", "policy_retry", "transport_retry", "unknown"
]
RouteTransitionReason: TypeAlias = Literal[
    "initial", "declared_failover", "policy_transition", "unknown"
]
ConstraintEncounter: TypeAlias = Literal[
    "budget_boundary",
    "route_not_permitted",
    "time_boundary",
    "tool_boundary",
    "unknown",
]


def validate_portfolio_outcome_v1(value: object) -> PortfolioOutcomeV1:
    """Validate one layer-discriminated authority-free outcome."""

    return _OUTCOME_ADAPTER.validate_python(value)


def build_portfolio_outcome_v1(
    *,
    layer: str,
    reported_value: str,
    observation_commitment_sha256: str,
) -> PortfolioOutcomeV1:
    """Build a content-bound evidence-only outcome with no executable authority."""

    visibility = "visible" if layer == "advisory" else "evaluator_only"
    payload = {
        "schema_version": "portfolio-outcome-v1.0",
        "observation_commitment_sha256": observation_commitment_sha256,
        "producer_attestation": "unattested",
        "evidence_only": True,
        "executable": False,
        "operational_authority": "none",
        "layer": layer,
        "reported_value": reported_value,
        "candidate_visibility": visibility,
    }
    payload["record_id"] = _domain_digest("agentic-security-portfolio/outcome-record/v1.0", payload)
    return validate_portfolio_outcome_v1(payload)


def project_outcome_for_candidate_v1(
    outcome: PortfolioOutcomeV1,
) -> AdvisoryOutcomeV1 | None:
    """Physically exclude evaluator-only effect and shadow-sink evidence."""

    outcome = validate_portfolio_outcome_v1(outcome.model_dump(mode="python"))
    if outcome.candidate_visibility == "evaluator_only":
        return None
    if isinstance(outcome, AdvisoryOutcomeV1):
        return outcome
    raise CompanionContractError("unknown candidate-visible outcome layer")


def portfolio_outcome_v1_json_schema() -> dict[str, Any]:
    """Return the generated schema for the discriminated outcome union."""

    return _OUTCOME_ADAPTER.json_schema()


def r4_companion_json_schemas() -> dict[str, dict[str, Any]]:
    """Return every Harness-owned R4 companion schema by stable contract id."""

    return {
        "portfolio-outcome-v1.0": portfolio_outcome_v1_json_schema(),
        "mcp-redaction-receipt-v1.0": MCPRedactionReceiptV1.model_json_schema(),
        "portfolio-trajectory-accounting-v1.0": (TrajectoryAccountingV1.model_json_schema()),
        "portfolio-telemetry-manifest-v1.0": TelemetryManifestV1.model_json_schema(),
        "portfolio-coverage-expectation-v1.0": (CoverageExpectationProfileV1.model_json_schema()),
    }


class MCPRedactionReceiptV1(BaseModel):
    """A bounded structural receipt that contains no raw MCP values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["mcp-redaction-receipt-v1.0"]
    source_surface: Literal["mcp"]
    redaction_profile: Literal["portfolio-mcp-structural-v1"]
    top_level_type: MCPTopLevelType
    visited_node_count: int = Field(ge=0, le=MAX_MCP_NODES)
    object_count: int = Field(ge=0, le=MAX_MCP_NODES)
    array_count: int = Field(ge=0, le=MAX_MCP_NODES)
    scalar_count: int = Field(ge=0, le=MAX_MCP_NODES)
    content_block_count: int = Field(ge=0, le=MAX_MCP_NODES)
    embedded_resource_count: int = Field(ge=0, le=MAX_MCP_NODES)
    unknown_content_type_count: int = Field(ge=0, le=MAX_MCP_NODES)
    truncated_count: int = Field(ge=0, le=MAX_MCP_NODES)
    dropped_field_classes: tuple[MCPDroppedFieldClass, ...]
    telemetry_state: MCPTelemetryState
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_receipt(self) -> MCPRedactionReceiptV1:
        if len(self.dropped_field_classes) != len(set(self.dropped_field_classes)):
            raise ValueError("dropped field classes must be unique")
        if tuple(sorted(self.dropped_field_classes)) != self.dropped_field_classes:
            raise ValueError("dropped field classes must be sorted")
        if self.telemetry_state == "complete" and (
            self.unknown_content_type_count or self.truncated_count
        ):
            raise ValueError("complete telemetry cannot contain unknown or truncated nodes")
        if self.visited_node_count != (self.object_count + self.array_count + self.scalar_count):
            raise ValueError("visited count does not equal structural node counts")
        if self.content_block_count > self.object_count:
            raise ValueError("content block count exceeds object count")
        if self.embedded_resource_count > self.content_block_count:
            raise ValueError("embedded resource count exceeds content blocks")
        if ("raw_scalar" in self.dropped_field_classes) != (self.scalar_count > 0):
            raise ValueError("scalar loss accounting does not match scalar count")
        if self.embedded_resource_count > 0 and (
            "embedded_resource" not in self.dropped_field_classes
        ):
            raise ValueError("embedded-resource loss accounting does not match count")
        root_count = {
            "object": self.object_count,
            "array": self.array_count,
            "scalar": self.scalar_count,
        }[self.top_level_type]
        if root_count == 0:
            raise ValueError("top-level type is inconsistent with structural counts")
        if self.top_level_type == "scalar" and self.telemetry_state != "rejected":
            raise ValueError("a scalar top-level MCP payload must be rejected")
        return self


_MCP_FIELD_CLASSES: tuple[tuple[re.Pattern[str], MCPDroppedFieldClass], ...] = (
    (re.compile(r"(?i)(credential|secret|password|authorization|api[_-]?key|token)"), "credential"),
    (re.compile(r"(?i)(url|uri|endpoint|host|locator)"), "locator"),
    (re.compile(r"(?i)(argument|arguments|params|parameters)"), "raw_argument"),
    (re.compile(r"(?i)(error|exception|traceback|stack)"), "raw_error"),
    (re.compile(r"(?i)(output|result|text|data|blob|content)"), "raw_output"),
    (re.compile(r"(?i)(resource|embedded)"), "embedded_resource"),
)


def summarize_mcp_payload_v1(
    payload: bytes,
    *,
    max_nodes: int = 256,
    max_depth: int = 8,
) -> MCPRedactionReceiptV1:
    """Decode bounded strict JSON and retain no MCP key value or raw content."""

    if not 1 <= max_nodes <= MAX_MCP_NODES:
        raise CompanionContractError("max_nodes is outside the bounded range")
    if not 1 <= max_depth <= MAX_MCP_DEPTH:
        raise CompanionContractError("max_depth is outside the bounded range")
    if not isinstance(payload, bytes):
        raise CompanionContractError("MCP payload must be strict JSON bytes")
    if not 1 <= len(payload) <= MAX_MCP_INPUT_BYTES:
        raise CompanionContractError("MCP payload is outside the byte bound")
    try:
        decoded = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                CompanionContractError("non-finite JSON value")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CompanionContractError("MCP payload is not strict UTF-8 JSON") from exc

    counts: Counter[str] = Counter()
    dropped: set[MCPDroppedFieldClass] = set()
    queue: deque[tuple[object, int]] = deque([(decoded, 0)])

    def record_truncation(count: int) -> None:
        counts["truncated"] = min(
            MAX_MCP_NODES,
            counts["truncated"] + max(0, count),
        )

    while queue:
        value, depth = queue.popleft()
        if counts["visited"] >= max_nodes or depth > max_depth:
            record_truncation(1)
            continue
        counts["visited"] += 1
        if isinstance(value, dict):
            counts["object"] += 1
            block_type = value.get("type")
            if isinstance(block_type, str):
                counts["content_block"] += 1
                if block_type not in {
                    "audio",
                    "call_tool_result",
                    "image",
                    "resource",
                    "resource_link",
                    "text",
                    "tool_result",
                }:
                    counts["unknown_content"] += 1
                if block_type in {"resource", "resource_link"}:
                    counts["embedded_resource"] += 1
                    dropped.add("embedded_resource")
            available = max(0, max_nodes - counts["visited"] - len(queue))
            for index, (key, child) in enumerate(value.items()):
                if index >= available:
                    record_truncation(len(value) - index)
                    break
                key_text = key if isinstance(key, str) else ""
                if not key_text:
                    counts["unknown_content"] += 1
                elif len(key_text) > MAX_MCP_KEY_LENGTH:
                    counts["unknown_content"] += 1
                    record_truncation(1)
                    continue
                for pattern, field_class in _MCP_FIELD_CLASSES:
                    if pattern.search(key_text):
                        dropped.add(field_class)
                queue.append((child, depth + 1))
        elif isinstance(value, (list, tuple)):
            counts["array"] += 1
            available = max(0, max_nodes - counts["visited"] - len(queue))
            accepted = min(len(value), available)
            queue.extend((child, depth + 1) for child in value[:accepted])
            record_truncation(len(value) - accepted)
        elif value is None or isinstance(value, (str, int, float, bool)):
            counts["scalar"] += 1
            dropped.add("raw_scalar")
        else:
            raise CompanionContractError("strict JSON decoder produced an unknown type")

    top_level_type: MCPTopLevelType
    if isinstance(decoded, dict):
        top_level_type = "object"
    elif isinstance(decoded, (list, tuple)):
        top_level_type = "array"
    elif decoded is None or isinstance(decoded, (str, int, float, bool)):
        top_level_type = "scalar"
    else:
        raise CompanionContractError("strict JSON decoder produced an unknown root type")
    state: MCPTelemetryState = "complete"
    if counts["unknown_content"] or counts["truncated"]:
        state = "incomplete"
    if top_level_type == "scalar":
        state = "rejected"
    return MCPRedactionReceiptV1(
        schema_version="mcp-redaction-receipt-v1.0",
        source_surface="mcp",
        redaction_profile="portfolio-mcp-structural-v1",
        top_level_type=top_level_type,
        visited_node_count=counts["visited"],
        object_count=counts["object"],
        array_count=counts["array"],
        scalar_count=counts["scalar"],
        content_block_count=counts["content_block"],
        embedded_resource_count=counts["embedded_resource"],
        unknown_content_type_count=counts["unknown_content"],
        truncated_count=counts["truncated"],
        dropped_field_classes=tuple(sorted(dropped)),
        telemetry_state=state,
        operational_authority="none",
    )


class TrajectoryObservationRefV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=SHA256_PATTERN)
    occurred_at: datetime
    observation_commitment_sha256: str = Field(pattern=SHA256_PATTERN)
    logical_operation_id: str = Field(pattern=SHA256_PATTERN)
    attempt_id: str = Field(pattern=SHA256_PATTERN)
    attempt_ordinal: int = Field(ge=1, le=MAX_TRAJECTORY_EVENTS)
    idempotency_identity: str = Field(pattern=SHA256_PATTERN)
    retry_cause: RetryCause
    route_id_hash: str = Field(pattern=SHA256_PATTERN)
    route_transition_reason: RouteTransitionReason
    permitted_route_set_sha256: str = Field(pattern=SHA256_PATTERN)
    route_permitted: bool
    constraint_encounters: tuple[ConstraintEncounter, ...] = Field(max_length=16)
    parent_event_ids: tuple[Annotated[str, Field(pattern=SHA256_PATTERN)], ...] = Field(
        max_length=64
    )

    @model_validator(mode="after")
    def _validate_ref(self) -> TrajectoryObservationRefV1:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("trajectory event time must be timezone-aware")
        if self.occurred_at.utcoffset() != timedelta(0):
            raise ValueError("trajectory event time must use canonical UTC representation")
        if self.event_id in self.parent_event_ids:
            raise ValueError("an event cannot be its own parent")
        if len(self.parent_event_ids) != len(set(self.parent_event_ids)):
            raise ValueError("parent event ids must be unique")
        if tuple(sorted(set(self.constraint_encounters))) != self.constraint_encounters:
            raise ValueError("constraint encounters must be sorted and unique")
        if ("route_not_permitted" in self.constraint_encounters) != (not self.route_permitted):
            raise ValueError("route verdict and constraint accounting disagree")
        if self.attempt_ordinal == 1 and self.retry_cause != "initial":
            raise ValueError("first attempt must use the initial cause")
        if self.attempt_ordinal > 1 and self.retry_cause == "initial":
            raise ValueError("retry attempt cannot use the initial cause")
        if self.attempt_ordinal == 1 and self.route_transition_reason != "initial":
            raise ValueError("first attempt must use the initial route transition")
        if self.attempt_ordinal > 1 and self.route_transition_reason == "initial":
            raise ValueError("retry attempt cannot use the initial route transition")
        return self


class TrajectoryEdgeV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    parent_event_id: str = Field(pattern=SHA256_PATTERN)
    child_event_id: str = Field(pattern=SHA256_PATTERN)


class TrajectoryCommitmentBindingV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=SHA256_PATTERN)
    observation_commitment_sha256: str = Field(pattern=SHA256_PATTERN)


def _canonical_observations(
    observations: tuple[TrajectoryObservationRefV1, ...],
) -> tuple[TrajectoryObservationRefV1, ...]:
    validated_items: list[TrajectoryObservationRefV1] = []
    for item in observations:
        payload = item.model_dump(mode="python")
        occurred_at = payload.get("occurred_at")
        if not isinstance(occurred_at, datetime):
            raise CompanionContractError("trajectory event time is absent")
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise CompanionContractError("trajectory event time is not timezone-aware")
        payload["occurred_at"] = occurred_at.astimezone(UTC)
        validated_items.append(TrajectoryObservationRefV1.model_validate(payload))
    validated = tuple(validated_items)
    return tuple(
        sorted(
            validated,
            key=lambda item: (
                item.event_id,
                item.attempt_ordinal,
                item.attempt_id,
                item.observation_commitment_sha256,
            ),
        )
    )


class TrajectoryAccountingV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["portfolio-trajectory-accounting-v1.0"]
    trajectory_id: str = Field(pattern=SHA256_PATTERN)
    candidate_visibility: Literal["evaluator_only"]
    logical_operation_id: str = Field(pattern=SHA256_PATTERN)
    expected_event_count: int = Field(ge=1, le=MAX_TRAJECTORY_EVENTS)
    observed_event_count: int = Field(ge=0, le=MAX_TRAJECTORY_EVENTS)
    observation_horizon_started_at: datetime
    observation_horizon_ended_at: datetime
    censoring_state: Literal["complete", "left_censored", "right_censored"]
    observations: tuple[TrajectoryObservationRefV1, ...] = Field(
        min_length=1, max_length=MAX_TRAJECTORY_EVENTS
    )
    event_commitments: tuple[TrajectoryCommitmentBindingV1, ...] = Field(
        max_length=MAX_TRAJECTORY_EVENTS
    )
    edges: tuple[TrajectoryEdgeV1, ...] = Field(max_length=MAX_TRAJECTORY_EVENTS * 64)
    attempt_ids: tuple[Annotated[str, Field(pattern=SHA256_PATTERN)], ...] = Field(
        max_length=MAX_TRAJECTORY_EVENTS
    )
    idempotency_identities: tuple[Annotated[str, Field(pattern=SHA256_PATTERN)], ...] = Field(
        max_length=MAX_TRAJECTORY_EVENTS
    )
    route_violation_event_ids: tuple[Annotated[str, Field(pattern=SHA256_PATTERN)], ...] = Field(
        max_length=MAX_TRAJECTORY_EVENTS
    )
    root_event_ids: tuple[Annotated[str, Field(pattern=SHA256_PATTERN)], ...] = Field(
        max_length=MAX_TRAJECTORY_EVENTS
    )
    leaf_event_ids: tuple[Annotated[str, Field(pattern=SHA256_PATTERN)], ...] = Field(
        max_length=MAX_TRAJECTORY_EVENTS
    )
    unresolved_parent_event_ids: tuple[Annotated[str, Field(pattern=SHA256_PATTERN)], ...] = Field(
        max_length=MAX_TRAJECTORY_EVENTS * 64
    )
    duplicate_event_ids: tuple[Annotated[str, Field(pattern=SHA256_PATTERN)], ...] = Field(
        max_length=MAX_TRAJECTORY_EVENTS
    )
    duplicate_observation_commitments: tuple[Annotated[str, Field(pattern=SHA256_PATTERN)], ...] = (
        Field(max_length=MAX_TRAJECTORY_EVENTS)
    )
    cycle_verdict: TrajectoryCycleVerdict
    completeness: TrajectoryCompleteness
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_accounting(self) -> TrajectoryAccountingV1:
        ordered_fields = (
            self.attempt_ids,
            self.idempotency_identities,
            self.route_violation_event_ids,
            self.root_event_ids,
            self.leaf_event_ids,
            self.unresolved_parent_event_ids,
            self.duplicate_event_ids,
            self.duplicate_observation_commitments,
        )
        if any(tuple(sorted(values)) != values for values in ordered_fields):
            raise ValueError("trajectory accounting sets must be sorted")
        if any(len(values) != len(set(values)) for values in ordered_fields):
            raise ValueError("trajectory accounting sets must be unique")
        if (
            tuple(
                sorted(
                    self.event_commitments,
                    key=lambda value: (value.event_id, value.observation_commitment_sha256),
                )
            )
            != self.event_commitments
        ):
            raise ValueError("event commitments must be sorted")
        if (
            tuple(
                sorted(self.edges, key=lambda value: (value.parent_event_id, value.child_event_id))
            )
            != self.edges
        ):
            raise ValueError("trajectory edges must be sorted")
        if len(self.edges) != len(
            {(value.parent_event_id, value.child_event_id) for value in self.edges}
        ):
            raise ValueError("trajectory edges must be unique")
        aware = all(
            value.tzinfo is not None and value.utcoffset() is not None
            for value in (
                self.observation_horizon_started_at,
                self.observation_horizon_ended_at,
            )
        )
        if not aware or self.observation_horizon_started_at.astimezone(UTC) > (
            self.observation_horizon_ended_at.astimezone(UTC)
        ):
            raise ValueError("observation horizon must be a valid aware interval")
        if any(
            value.utcoffset() != timedelta(0)
            for value in (
                self.observation_horizon_started_at,
                self.observation_horizon_ended_at,
            )
        ):
            raise ValueError("observation horizon must use canonical UTC representation")
        observations = _canonical_observations(self.observations)
        if self.observations != observations:
            raise ValueError("trajectory observations must use canonical order")
        event_times = tuple(item.occurred_at.astimezone(UTC) for item in observations)
        if self.censoring_state == "complete" and (
            self.observation_horizon_started_at.astimezone(UTC) != min(event_times)
            or self.observation_horizon_ended_at.astimezone(UTC) != max(event_times)
        ):
            raise ValueError("complete trajectory horizon must equal observed event span")
        if self.censoring_state == "left_censored" and (
            self.observation_horizon_started_at.astimezone(UTC) > min(event_times)
            or self.observation_horizon_ended_at.astimezone(UTC) != max(event_times)
        ):
            raise ValueError("left-censored horizon is inconsistent with event times")
        if self.censoring_state == "right_censored" and (
            self.observation_horizon_started_at.astimezone(UTC) != min(event_times)
            or self.observation_horizon_ended_at.astimezone(UTC) < max(event_times)
        ):
            raise ValueError("right-censored horizon is inconsistent with event times")
        expected = _expected_trajectory_facts(
            observations, self.expected_event_count, self.censoring_state
        )
        for field_name, expected_value in expected.items():
            if getattr(self, field_name) != expected_value:
                raise ValueError(
                    f"trajectory field {field_name} does not match observation evidence"
                )
        expected_id = _trajectory_identity(
            observations=observations,
            expected_event_count=self.expected_event_count,
            observation_horizon_started_at=self.observation_horizon_started_at,
            observation_horizon_ended_at=self.observation_horizon_ended_at,
            censoring_state=self.censoring_state,
        )
        if self.trajectory_id != expected_id:
            raise ValueError("trajectory id does not bind the full observation unit")
        return self


def _trajectory_identity(
    *,
    observations: tuple[TrajectoryObservationRefV1, ...],
    expected_event_count: int,
    observation_horizon_started_at: datetime,
    observation_horizon_ended_at: datetime,
    censoring_state: Literal["complete", "left_censored", "right_censored"],
) -> str:
    normalized_observations: list[dict[str, Any]] = []
    for item in _canonical_observations(observations):
        payload = item.model_dump(mode="json")
        payload["occurred_at"] = item.occurred_at.astimezone(UTC).isoformat()
        normalized_observations.append(payload)
    return _domain_digest(
        "agentic-security-portfolio/trajectory-unit/v1.0",
        {
            "observations": normalized_observations,
            "expected_event_count": expected_event_count,
            "observation_horizon_started_at": observation_horizon_started_at.astimezone(
                UTC
            ).isoformat(),
            "observation_horizon_ended_at": observation_horizon_ended_at.astimezone(
                UTC
            ).isoformat(),
            "censoring_state": censoring_state,
        },
    )


def _expected_trajectory_facts(
    observations: tuple[TrajectoryObservationRefV1, ...],
    expected_event_count: int,
    censoring_state: Literal["complete", "left_censored", "right_censored"],
) -> dict[str, object]:
    """Recompute every redundant fact from full per-event retry/route bindings."""

    counts = Counter(item.event_id for item in observations)
    duplicates = {event_id for event_id, count in counts.items() if count > 1}
    commitment_counts = Counter(item.observation_commitment_sha256 for item in observations)
    duplicate_commitments = {
        commitment for commitment, count in commitment_counts.items() if count > 1
    }
    logical_operations = {item.logical_operation_id for item in observations}
    if len(logical_operations) != 1:
        raise CompanionContractError("trajectory must contain one logical operation")
    by_id = {item.event_id: item for item in observations}
    attempt_bindings: dict[str, set[tuple[int, str]]] = defaultdict(set)
    ordinal_bindings: dict[int, set[str]] = defaultdict(set)
    for item in observations:
        attempt_bindings[item.attempt_id].add((item.attempt_ordinal, item.retry_cause))
        ordinal_bindings[item.attempt_ordinal].add(item.attempt_id)
    if any(len(values) != 1 for values in attempt_bindings.values()):
        raise CompanionContractError("attempt id has conflicting ordinal or cause")
    if any(len(values) != 1 for values in ordinal_bindings.values()):
        raise CompanionContractError("attempt ordinal maps to multiple attempt ids")
    ordinals = sorted(ordinal_bindings)
    if ordinals != list(range(1, max(ordinals) + 1)):
        raise CompanionContractError("attempt ordinals must be contiguous from one")
    known = set(by_id)
    for item in by_id.values():
        if item.attempt_ordinal > 1 and not any(
            parent in known and by_id[parent].attempt_ordinal < item.attempt_ordinal
            for parent in item.parent_event_ids
        ):
            raise CompanionContractError("retry event lacks resolved ancestry from a prior attempt")
    earliest_by_ordinal = {
        ordinal: min(
            item.occurred_at.astimezone(UTC)
            for item in observations
            if item.attempt_ordinal == ordinal
        )
        for ordinal in ordinal_bindings
    }
    if any(
        earliest_by_ordinal[ordinal] < earliest_by_ordinal[ordinal - 1]
        for ordinal in range(2, max(earliest_by_ordinal) + 1)
    ):
        raise CompanionContractError("retry attempt time precedes a prior attempt")
    unresolved = {
        parent for item in observations for parent in item.parent_event_ids if parent not in known
    }
    children: dict[str, set[str]] = defaultdict(set)
    indegree = {event_id: 0 for event_id in known}
    for item in by_id.values():
        for parent in item.parent_event_ids:
            if parent in known:
                if by_id[parent].occurred_at.astimezone(UTC) > item.occurred_at.astimezone(UTC):
                    raise CompanionContractError("child event precedes its parent in time")
                children[parent].add(item.event_id)
                indegree[item.event_id] += 1
    roots = {item.event_id for item in by_id.values() if not item.parent_event_ids}
    leaves = known - set(children)
    queue = deque(sorted(event_id for event_id, degree in indegree.items() if degree == 0))
    visited = 0
    while queue:
        event_id = queue.popleft()
        visited += 1
        for child in sorted(children.get(event_id, ())):
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    cycle_verdict: TrajectoryCycleVerdict = "acyclic" if visited == len(known) else "cycle_detected"
    if cycle_verdict == "acyclic" and any(
        by_id[parent].attempt_ordinal > item.attempt_ordinal
        for item in by_id.values()
        for parent in item.parent_event_ids
        if parent in known
    ):
        raise CompanionContractError("child precedes its parent attempt")
    invalid = cycle_verdict == "cycle_detected" or bool(duplicates) or bool(duplicate_commitments)
    incomplete = (
        bool(unresolved)
        or expected_event_count != len(observations)
        or censoring_state != "complete"
        or any(
            item.retry_cause == "unknown"
            or item.route_transition_reason == "unknown"
            or "unknown" in item.constraint_encounters
            for item in observations
        )
    )
    completeness: TrajectoryCompleteness = (
        "invalid" if invalid else "incomplete" if incomplete else "complete"
    )
    return {
        "logical_operation_id": next(iter(logical_operations)),
        "observed_event_count": len(observations),
        "event_commitments": tuple(
            sorted(
                (
                    TrajectoryCommitmentBindingV1(
                        event_id=item.event_id,
                        observation_commitment_sha256=item.observation_commitment_sha256,
                    )
                    for item in by_id.values()
                ),
                key=lambda value: (
                    value.event_id,
                    value.observation_commitment_sha256,
                ),
            )
        ),
        "edges": tuple(
            sorted(
                (
                    TrajectoryEdgeV1(parent_event_id=parent, child_event_id=item.event_id)
                    for item in by_id.values()
                    for parent in item.parent_event_ids
                ),
                key=lambda value: (value.parent_event_id, value.child_event_id),
            )
        ),
        "attempt_ids": tuple(sorted({item.attempt_id for item in observations})),
        "idempotency_identities": tuple(
            sorted({item.idempotency_identity for item in observations})
        ),
        "route_violation_event_ids": tuple(
            sorted(item.event_id for item in observations if not item.route_permitted)
        ),
        "root_event_ids": tuple(sorted(roots)),
        "leaf_event_ids": tuple(sorted(leaves)),
        "unresolved_parent_event_ids": tuple(sorted(unresolved)),
        "duplicate_event_ids": tuple(sorted(duplicates)),
        "duplicate_observation_commitments": tuple(sorted(duplicate_commitments)),
        "cycle_verdict": cycle_verdict,
        "completeness": completeness,
    }


def build_trajectory_accounting_v1(
    *,
    expected_event_count: int,
    observations: tuple[TrajectoryObservationRefV1, ...],
    censoring_state: Literal["complete", "left_censored", "right_censored"] = "complete",
) -> TrajectoryAccountingV1:
    """Build bounded structural DAG accounting without claiming authenticated causality."""

    if len(observations) > MAX_TRAJECTORY_EVENTS:
        raise CompanionContractError("trajectory exceeds the event bound")
    if not observations:
        raise CompanionContractError("trajectory requires at least one observation")
    observations = _canonical_observations(observations)
    event_times = tuple(item.occurred_at.astimezone(UTC) for item in observations)
    observation_horizon_started_at = min(event_times)
    observation_horizon_ended_at = max(event_times)
    counts = Counter(item.event_id for item in observations)
    duplicates = {event_id for event_id, count in counts.items() if count > 1}
    commitment_counts = Counter(item.observation_commitment_sha256 for item in observations)
    duplicate_commitments = {
        commitment for commitment, count in commitment_counts.items() if count > 1
    }
    logical_operations = {item.logical_operation_id for item in observations}
    if len(logical_operations) != 1:
        raise CompanionContractError("trajectory must contain one logical operation")
    logical_operation_id = next(iter(logical_operations))
    by_id = {item.event_id: item for item in observations}
    known = set(by_id)
    unresolved = {
        parent for item in observations for parent in item.parent_event_ids if parent not in known
    }
    children: dict[str, set[str]] = defaultdict(set)
    indegree = {event_id: 0 for event_id in known}
    for item in by_id.values():
        for parent in item.parent_event_ids:
            if parent in known:
                children[parent].add(item.event_id)
                indegree[item.event_id] += 1
    roots = {item.event_id for item in by_id.values() if not item.parent_event_ids}
    leaves = known - set(children)
    # Cycle detection starts from every node with no *known* incoming edge.
    # A node that declares an unresolved external parent is not a semantic root,
    # but the absent parent must not fabricate a cycle inside the observed graph.
    queue = deque(sorted(event_id for event_id, degree in indegree.items() if degree == 0))
    visited = 0
    while queue:
        event_id = queue.popleft()
        visited += 1
        for child in sorted(children.get(event_id, ())):
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    cycle_verdict: TrajectoryCycleVerdict = "acyclic" if visited == len(known) else "cycle_detected"
    invalid = cycle_verdict == "cycle_detected" or bool(duplicates) or bool(duplicate_commitments)
    incomplete = (
        bool(unresolved)
        or expected_event_count != len(observations)
        or censoring_state != "complete"
        or any(
            item.retry_cause == "unknown"
            or item.route_transition_reason == "unknown"
            or "unknown" in item.constraint_encounters
            for item in observations
        )
    )
    completeness: TrajectoryCompleteness = (
        "invalid" if invalid else "incomplete" if incomplete else "complete"
    )
    return TrajectoryAccountingV1(
        schema_version="portfolio-trajectory-accounting-v1.0",
        trajectory_id=_trajectory_identity(
            observations=observations,
            expected_event_count=expected_event_count,
            observation_horizon_started_at=observation_horizon_started_at,
            observation_horizon_ended_at=observation_horizon_ended_at,
            censoring_state=censoring_state,
        ),
        candidate_visibility="evaluator_only",
        logical_operation_id=logical_operation_id,
        expected_event_count=expected_event_count,
        observed_event_count=len(observations),
        observation_horizon_started_at=observation_horizon_started_at,
        observation_horizon_ended_at=observation_horizon_ended_at,
        censoring_state=censoring_state,
        observations=observations,
        event_commitments=tuple(
            sorted(
                (
                    TrajectoryCommitmentBindingV1(
                        event_id=item.event_id,
                        observation_commitment_sha256=item.observation_commitment_sha256,
                    )
                    for item in by_id.values()
                ),
                key=lambda value: (value.event_id, value.observation_commitment_sha256),
            )
        ),
        edges=tuple(
            sorted(
                (
                    TrajectoryEdgeV1(parent_event_id=parent, child_event_id=item.event_id)
                    for item in by_id.values()
                    for parent in item.parent_event_ids
                ),
                key=lambda value: (value.parent_event_id, value.child_event_id),
            )
        ),
        attempt_ids=tuple(sorted({item.attempt_id for item in observations})),
        idempotency_identities=tuple(sorted({item.idempotency_identity for item in observations})),
        route_violation_event_ids=tuple(
            sorted(item.event_id for item in observations if not item.route_permitted)
        ),
        root_event_ids=tuple(sorted(roots)),
        leaf_event_ids=tuple(sorted(leaves)),
        unresolved_parent_event_ids=tuple(sorted(unresolved)),
        duplicate_event_ids=tuple(sorted(duplicates)),
        duplicate_observation_commitments=tuple(sorted(duplicate_commitments)),
        cycle_verdict=cycle_verdict,
        completeness=completeness,
        operational_authority="none",
    )


class CoverageExpectationProfileV1(BaseModel):
    """Precommitted expectation boundary; it is evidence, never authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["portfolio-coverage-expectation-v1.0"]
    profile_id: str = Field(pattern=SHA256_PATTERN)
    project_id: str = Field(pattern=PROJECT_ID_PATTERN)
    repository_id: str = Field(pattern=REPOSITORY_ID_PATTERN)
    repository_sha: str = Field(pattern=GIT_OBJECT_PATTERN)
    expected_channels: tuple[str, ...] = Field(min_length=1, max_length=64)
    expected_event_count: int = Field(ge=1, le=MAX_TRAJECTORY_EVENTS)
    expectation_source_sha256: str = Field(pattern=SHA256_PATTERN)
    producer_attestation: Literal["unattested"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_profile(self) -> CoverageExpectationProfileV1:
        if tuple(sorted(set(self.expected_channels))) != self.expected_channels:
            raise ValueError("expected channels must be sorted and unique")
        if any(not TOKEN_PATTERN.fullmatch(value) for value in self.expected_channels):
            raise ValueError("expected channels must be canonical tokens")
        payload = self.model_dump(mode="json", exclude={"profile_id"})
        expected = _domain_digest("agentic-security-portfolio/coverage-expectation/v1.0", payload)
        if self.profile_id != expected:
            raise ValueError("profile id does not bind coverage expectations")
        return self


def build_coverage_expectation_profile_v1(
    *,
    project_id: str,
    repository_id: str,
    repository_sha: str,
    expected_channels: tuple[str, ...],
    expected_event_count: int,
    expectation_source_sha256: str,
) -> CoverageExpectationProfileV1:
    payload = {
        "schema_version": "portfolio-coverage-expectation-v1.0",
        "project_id": project_id,
        "repository_id": repository_id,
        "repository_sha": repository_sha,
        "expected_channels": tuple(sorted(set(expected_channels))),
        "expected_event_count": expected_event_count,
        "expectation_source_sha256": expectation_source_sha256,
        "producer_attestation": "unattested",
        "operational_authority": "none",
    }
    payload["profile_id"] = _domain_digest(
        "agentic-security-portfolio/coverage-expectation/v1.0", payload
    )
    return CoverageExpectationProfileV1.model_validate(payload)


class TelemetryManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["portfolio-telemetry-manifest-v1.0"]
    candidate_visibility: Literal["evaluator_only"]
    project_id: str = Field(pattern=PROJECT_ID_PATTERN)
    repository_id: str = Field(pattern=REPOSITORY_ID_PATTERN)
    repository_sha: str = Field(pattern=GIT_OBJECT_PATTERN)
    coverage_expectation_profile: CoverageExpectationProfileV1
    coverage_expectation_profile_id: str = Field(pattern=SHA256_PATTERN)
    window_started_at: datetime
    window_ended_at: datetime
    expected_channels: tuple[str, ...] = Field(min_length=1, max_length=64)
    observed_channels: tuple[str, ...] = Field(max_length=64)
    dropped_record_count: int = Field(ge=0)
    rejected_record_count: int = Field(ge=0)
    adapter_audit: AdapterAuditV1
    trajectory_accounting: TrajectoryAccountingV1
    adapter_audit_sha256: str = Field(pattern=SHA256_PATTERN)
    trajectory_accounting_sha256: str = Field(pattern=SHA256_PATTERN)
    trajectory_completeness: Literal["complete", "incomplete", "invalid"]
    telemetry_state: Literal["complete", "incomplete", "rejected"]
    incomplete_reason: Literal[
        "none",
        "missing_channel",
        "dropped_or_rejected_records",
        "trajectory_not_complete",
        "invalid_window",
    ]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_manifest(self) -> TelemetryManifestV1:
        profile = CoverageExpectationProfileV1.model_validate(
            self.coverage_expectation_profile.model_dump(mode="python")
        )
        adapter_audit = AdapterAuditV1.model_validate(self.adapter_audit.model_dump(mode="python"))
        trajectory = TrajectoryAccountingV1.model_validate(
            self.trajectory_accounting.model_dump(mode="python")
        )
        if (
            self.coverage_expectation_profile_id != profile.profile_id
            or self.project_id != profile.project_id
            or self.repository_id != profile.repository_id
            or self.repository_sha != profile.repository_sha
            or self.expected_channels != profile.expected_channels
        ):
            raise ValueError("telemetry manifest does not match its embedded profile")
        if self.adapter_audit_sha256 != _domain_digest(
            "agentic-security-portfolio/adapter-audit-evidence/v1.0",
            adapter_audit.model_dump(mode="json"),
        ):
            raise ValueError("telemetry manifest does not match its adapter audit")
        if self.trajectory_accounting_sha256 != canonical_companion_digest(trajectory):
            raise ValueError("telemetry manifest does not match its trajectory evidence")
        if (
            self.trajectory_completeness != trajectory.completeness
            or trajectory.expected_event_count != profile.expected_event_count
            or trajectory.observed_event_count > profile.expected_event_count
        ):
            raise ValueError("telemetry manifest trajectory accounting is inconsistent")
        for value in (*self.expected_channels, *self.observed_channels):
            if not TOKEN_PATTERN.fullmatch(value):
                raise ValueError("telemetry channel must be a canonical token")
        if tuple(sorted(set(self.expected_channels))) != self.expected_channels:
            raise ValueError("expected channels must be sorted and unique")
        if tuple(sorted(set(self.observed_channels))) != self.observed_channels:
            raise ValueError("observed channels must be sorted and unique")
        aware = all(
            value.tzinfo is not None and value.utcoffset() is not None
            for value in (self.window_started_at, self.window_ended_at)
        )
        valid_window = aware and self.window_started_at.astimezone(UTC) <= (
            self.window_ended_at.astimezone(UTC)
        )
        if aware and any(
            value.utcoffset() != timedelta(0)
            for value in (self.window_started_at, self.window_ended_at)
        ):
            valid_window = False
        if valid_window:
            valid_window = self.window_started_at.astimezone(UTC) <= (
                trajectory.observation_horizon_started_at.astimezone(UTC)
            ) and self.window_ended_at.astimezone(UTC) >= (
                trajectory.observation_horizon_ended_at.astimezone(UTC)
            )
        missing = set(self.expected_channels) - set(self.observed_channels)
        if not valid_window:
            state, reason = "rejected", "invalid_window"
        elif self.trajectory_completeness == "invalid":
            state, reason = "rejected", "trajectory_not_complete"
        elif self.trajectory_completeness != "complete":
            state, reason = "incomplete", "trajectory_not_complete"
        elif self.dropped_record_count or self.rejected_record_count:
            state, reason = "incomplete", "dropped_or_rejected_records"
        elif missing:
            state, reason = "incomplete", "missing_channel"
        else:
            state, reason = "complete", "none"
        if (self.telemetry_state, self.incomplete_reason) != (state, reason):
            raise ValueError("telemetry verdict does not match manifest evidence")
        return self


def build_telemetry_manifest_v1(
    *,
    profile: CoverageExpectationProfileV1,
    observed_channels: tuple[str, ...],
    dropped_record_count: int,
    rejected_record_count: int,
    adapter_audit: AdapterAuditV1,
    trajectory: TrajectoryAccountingV1,
    window_started_at: datetime,
    window_ended_at: datetime,
) -> TelemetryManifestV1:
    """Bind telemetry accounting to the reviewed profile and actual companion objects."""

    # Revalidate copied/deserialized models so ``model_copy(update=...)`` cannot
    # bypass the relational invariants on any input crossing this boundary.
    profile = CoverageExpectationProfileV1.model_validate(profile.model_dump(mode="python"))
    adapter_audit = AdapterAuditV1.model_validate(adapter_audit.model_dump(mode="python"))
    trajectory = TrajectoryAccountingV1.model_validate(trajectory.model_dump(mode="python"))
    if trajectory.expected_event_count != profile.expected_event_count:
        raise CompanionContractError("trajectory does not match the expectation profile")
    if trajectory.observed_event_count > profile.expected_event_count:
        raise CompanionContractError("trajectory exceeds the expectation profile")
    if (
        window_started_at.tzinfo is not None
        and window_started_at.utcoffset() is not None
        and window_ended_at.tzinfo is not None
        and window_ended_at.utcoffset() is not None
        and (
            window_started_at.astimezone(UTC)
            > trajectory.observation_horizon_started_at.astimezone(UTC)
            or window_ended_at.astimezone(UTC)
            < trajectory.observation_horizon_ended_at.astimezone(UTC)
        )
    ):
        raise CompanionContractError("telemetry window does not contain trajectory horizon")
    observed = tuple(sorted(set(observed_channels)))
    missing = set(profile.expected_channels) - set(observed)
    state: Literal["complete", "incomplete", "rejected"]
    reason: Literal[
        "none",
        "missing_channel",
        "dropped_or_rejected_records",
        "trajectory_not_complete",
        "invalid_window",
    ]
    if trajectory.completeness == "invalid":
        state, reason = "rejected", "trajectory_not_complete"
    elif trajectory.completeness != "complete":
        state, reason = "incomplete", "trajectory_not_complete"
    elif dropped_record_count or rejected_record_count:
        state, reason = "incomplete", "dropped_or_rejected_records"
    elif missing:
        state, reason = "incomplete", "missing_channel"
    else:
        state, reason = "complete", "none"
    if (
        window_started_at.tzinfo is None
        or window_started_at.utcoffset() is None
        or window_ended_at.tzinfo is None
        or window_ended_at.utcoffset() is None
        or (window_started_at.astimezone(UTC) > window_ended_at.astimezone(UTC))
    ):
        state, reason = "rejected", "invalid_window"
    return TelemetryManifestV1(
        schema_version="portfolio-telemetry-manifest-v1.0",
        candidate_visibility="evaluator_only",
        project_id=profile.project_id,
        repository_id=profile.repository_id,
        repository_sha=profile.repository_sha,
        coverage_expectation_profile=profile,
        coverage_expectation_profile_id=profile.profile_id,
        window_started_at=window_started_at,
        window_ended_at=window_ended_at,
        expected_channels=profile.expected_channels,
        observed_channels=observed,
        dropped_record_count=dropped_record_count,
        rejected_record_count=rejected_record_count,
        adapter_audit=adapter_audit,
        trajectory_accounting=trajectory,
        adapter_audit_sha256=_domain_digest(
            "agentic-security-portfolio/adapter-audit-evidence/v1.0",
            adapter_audit.model_dump(mode="json"),
        ),
        trajectory_accounting_sha256=canonical_companion_digest(trajectory),
        trajectory_completeness=trajectory.completeness,
        telemetry_state=state,
        incomplete_reason=reason,
        operational_authority="none",
    )


def _revalidate_companion_model(value: BaseModel) -> BaseModel:
    """Revalidate exact dumped content before any canonical encoding or digest."""

    payload = value.model_dump(mode="python")
    version = payload.get("schema_version")
    if version == "portfolio-outcome-v1.0":
        return validate_portfolio_outcome_v1(payload)
    if version == "mcp-redaction-receipt-v1.0":
        return MCPRedactionReceiptV1.model_validate(payload)
    if version == "portfolio-trajectory-accounting-v1.0":
        return TrajectoryAccountingV1.model_validate(payload)
    if version == "portfolio-coverage-expectation-v1.0":
        return CoverageExpectationProfileV1.model_validate(payload)
    if version == "portfolio-telemetry-manifest-v1.0":
        return TelemetryManifestV1.model_validate(payload)
    raise CompanionContractError("unsupported model for companion encoding")


def encode_companion_record_v1(value: BaseModel) -> bytes:
    """Return bounded canonical JSON bytes for one validated companion model."""

    value = _revalidate_companion_model(value)
    encoded = (
        json.dumps(
            value.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    if len(encoded) > MAX_COMPANION_RECORD_BYTES:
        raise CompanionContractError("companion record exceeds the wire byte bound")
    return encoded


def canonical_companion_digest(value: BaseModel) -> str:
    """Return a schema/domain-separated digest of canonical companion bytes."""

    schema_version = getattr(value, "schema_version", None)
    if not isinstance(schema_version, str) or not schema_version:
        raise CompanionContractError("record lacks a schema-version domain")
    encoded = encode_companion_record_v1(value)
    return hashlib.sha256(
        b"agentic-security-portfolio/companion-record/v1.0\0"
        + schema_version.encode("ascii")
        + b"\0"
        + encoded
    ).hexdigest()


DecodedCompanionV1: TypeAlias = (
    PortfolioOutcomeV1
    | MCPRedactionReceiptV1
    | TrajectoryAccountingV1
    | CoverageExpectationProfileV1
    | TelemetryManifestV1
)


def project_companion_for_candidate_v1(
    value: DecodedCompanionV1,
) -> AdvisoryOutcomeV1 | None:
    """Physical scientific boundary: candidates receive advisory outcomes only."""

    validated = _revalidate_companion_model(value)
    if isinstance(validated, AdvisoryOutcomeV1):
        return validated
    return None


def decode_companion_record_v1(payload: bytes) -> DecodedCompanionV1:
    """Strictly decode exact canonical R4 bytes with duplicate-key rejection."""

    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_COMPANION_RECORD_BYTES:
        raise CompanionContractError("companion payload is outside the wire byte bound")
    try:
        decoded = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                CompanionContractError("non-finite JSON value")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CompanionContractError("companion payload is not strict UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise CompanionContractError("companion payload must be an object")
    version = decoded.get("schema_version")
    try:
        if version == "portfolio-outcome-v1.0":
            value: DecodedCompanionV1 = validate_portfolio_outcome_v1(decoded)
        elif version == "mcp-redaction-receipt-v1.0":
            value = MCPRedactionReceiptV1.model_validate(decoded)
        elif version == "portfolio-trajectory-accounting-v1.0":
            value = TrajectoryAccountingV1.model_validate(decoded)
        elif version == "portfolio-coverage-expectation-v1.0":
            value = CoverageExpectationProfileV1.model_validate(decoded)
        elif version == "portfolio-telemetry-manifest-v1.0":
            value = TelemetryManifestV1.model_validate(decoded)
        else:
            raise CompanionContractError("unsupported companion schema version")
    except ValueError as exc:
        raise CompanionContractError("companion values violate the declared schema") from exc
    if encode_companion_record_v1(value) != payload:
        raise CompanionContractError("companion JSON is not canonical")
    return value


def _domain_digest(domain: str, payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(domain.encode("ascii") + b"\0" + encoded).hexdigest()


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CompanionContractError("duplicate JSON field")
        value[key] = item
    return value
