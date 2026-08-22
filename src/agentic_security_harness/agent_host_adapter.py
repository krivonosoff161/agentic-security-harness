"""Provider-neutral, observation-only Agent Host Adapter SDK.

The public Harness must not execute an arbitrary host, trust a host self-report as a
security verdict, or mint operational authority.  This module therefore defines a
record/replay boundary over the existing canonical portfolio observation contract.
Provider-specific collectors can implement :class:`AgentHostAdapterV1` later; this
first slice validates their retained, authority-free observation records offline.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.corpus import (
    V1_PATTERN_IDS,
    corpus_manifest_sha256,
)
from agentic_security_harness.models import DefensivePattern
from agentic_security_harness.portfolio_contract import (
    SHA256_PATTERN,
    CanonicalObservationEventV1,
    ObservationCommitmentV1,
    commit_portfolio_observation_v1,
    encode_portfolio_observation_v1,
)
from agentic_security_harness.safe_io import is_link_or_reparse

AGENT_HOST_RECORDING_V1: Final[Literal["agent-host-recording-v1.0"]] = (
    "agent-host-recording-v1.0"
)
AGENT_HOST_RECORDING_COMMITMENT_V1: Final[
    Literal["agent-host-recording-commitment-v1.0"]
] = "agent-host-recording-commitment-v1.0"
AGENT_HOST_RECORDING_COMMITMENT_DOMAIN: Final[
    Literal["agentic-security-harness/agent-host-recording/v1.0"]
] = (
    "agentic-security-harness/agent-host-recording/v1.0"
)
AGENT_HOST_INSPECTION_V1: Final[Literal["agent-host-inspection-v1.0"]] = (
    "agent-host-inspection-v1.0"
)
MAX_AGENT_HOST_RECORDING_BYTES = 1_048_576
MAX_AGENT_HOST_EVENTS = 2_048
_TOKEN_PATTERN = r"^[a-z][a-z0-9_.-]{0,127}$"
_VERSION_PATTERN = r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$"

AgentHostTerminalStatus = Literal["completed", "inconclusive", "adapter_error"]
AgentHostTelemetryState = Literal[
    "complete", "incomplete", "malformed", "unattested", "conflicting"
]


class AgentHostContractError(ValueError):
    """Raised when an Agent Host record violates the closed V1 contract."""


class AgentHostDescriptorV1(BaseModel):
    """Safe, provider-neutral description of the producing host adapter.

    Values are producer declarations, not provider attestations.  The descriptor cannot
    contain credentials, endpoints, raw prompts, tool arguments, or authority grants.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["agent-host-descriptor-v1.0"]
    adapter_id: str = Field(pattern=_TOKEN_PATTERN)
    adapter_version: str = Field(pattern=_VERSION_PATTERN)
    host_type: str = Field(pattern=_TOKEN_PATTERN)
    runtime_id: str = Field(pattern=_TOKEN_PATTERN)
    runtime_version: str = Field(pattern=_VERSION_PATTERN)
    capture_mode: Literal["recorded_offline", "authorized_live_capture"]
    network_mode: Literal["off", "local_only", "authorized_external"]
    raw_payload_policy: Literal["digests_only"]
    producer_attestation: Literal["unattested"]
    operational_authority: Literal["none"]


class AgentHostRecordingV1(BaseModel):
    """Closed record of one corpus pattern observed at an external agent host.

    The record deliberately contains no security verdict.  It binds a self-contained,
    ordered event graph and exact per-event commitments so a later evaluator can reason
    over evidence without treating the producer as an authority.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["agent-host-recording-v1.0"]
    recording_id: str = Field(pattern=SHA256_PATTERN)
    corpus_version: Literal["1.0.0"]
    corpus_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    pattern_id: str = Field(pattern=_TOKEN_PATTERN)
    host: AgentHostDescriptorV1
    events: tuple[CanonicalObservationEventV1, ...] = Field(
        min_length=1,
        max_length=MAX_AGENT_HOST_EVENTS,
    )
    event_commitments: tuple[ObservationCommitmentV1, ...] = Field(
        min_length=1,
        max_length=MAX_AGENT_HOST_EVENTS,
    )
    terminal_status: AgentHostTerminalStatus
    telemetry_state: AgentHostTelemetryState
    verdict_semantics: Literal["observation_only_no_security_verdict"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_recording(self) -> AgentHostRecordingV1:
        if self.pattern_id not in V1_PATTERN_IDS:
            raise ValueError("pattern_id is not in the stable corpus")
        if self.corpus_manifest_sha256 != corpus_manifest_sha256():
            raise ValueError("recording does not bind the stable corpus manifest")
        if len(self.events) != len(self.event_commitments):
            raise ValueError("every event must have one ordered commitment")

        event_ids = tuple(event.event_id for event in self.events)
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("event ids must be unique within a recording")

        seen: set[str] = set()
        previous_time = None
        first = self.events[0]
        identity = (first.project_id, first.repository_id, first.repository_sha)
        for event, commitment in zip(
            self.events,
            self.event_commitments,
            strict=True,
        ):
            if (event.project_id, event.repository_id, event.repository_sha) != identity:
                raise ValueError("all events must share one project/repository identity")
            if previous_time is not None and event.occurred_at < previous_time:
                raise ValueError("events must be ordered by occurred_at")
            if any(parent not in seen for parent in event.parent_event_ids):
                raise ValueError("parent events must precede their child in the recording")
            expected = commit_portfolio_observation_v1(event)
            if commitment != expected:
                raise ValueError("event commitment does not bind the exact event")
            previous_time = event.occurred_at
            seen.add(event.event_id)

        expected_telemetry = _aggregate_telemetry(self.events)
        if self.telemetry_state != expected_telemetry:
            raise ValueError("recording telemetry does not match its events")
        if self.terminal_status == "completed" and self.telemetry_state != "complete":
            raise ValueError("completed recording requires complete telemetry")
        if self.recording_id != _recording_identity(self):
            raise ValueError("recording_id does not bind the recording fields")
        return self


class AgentHostRecordingCommitmentV1(BaseModel):
    """Domain-separated commitment to exact canonical recording bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["agent-host-recording-commitment-v1.0"]
    recording_schema_version: Literal["agent-host-recording-v1.0"]
    domain: Literal["agentic-security-harness/agent-host-recording/v1.0"]
    content_sha256: str = Field(pattern=SHA256_PATTERN)
    commitment_sha256: str = Field(pattern=SHA256_PATTERN)
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_commitment(self) -> AgentHostRecordingCommitmentV1:
        expected = _recording_commitment_digest(self.content_sha256)
        if self.commitment_sha256 != expected:
            raise ValueError("recording commitment does not bind domain and content")
        return self


class AgentHostInspectionV1(BaseModel):
    """Safe replay summary; it is not a detector decision or provider attestation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["agent-host-inspection-v1.0"]
    recording_id: str = Field(pattern=SHA256_PATTERN)
    recording_commitment_sha256: str = Field(pattern=SHA256_PATTERN)
    pattern_id: str = Field(pattern=_TOKEN_PATTERN)
    event_count: int = Field(ge=1, le=MAX_AGENT_HOST_EVENTS)
    source_surfaces: tuple[str, ...]
    activities: tuple[str, ...]
    terminal_status: AgentHostTerminalStatus
    telemetry_state: AgentHostTelemetryState
    capture_mode: Literal["recorded_offline", "authorized_live_capture"]
    network_mode: Literal["off", "local_only", "authorized_external"]
    tool_activity_observed: bool
    producer_attestation: Literal["unattested"]
    verdict_semantics: Literal["observation_only_no_security_verdict"]
    operational_authority: Literal["none"]


class AgentHostAdapterV1(Protocol):
    """Collection boundary for a future authorized host-specific adapter."""

    descriptor: AgentHostDescriptorV1

    def collect(self, pattern: DefensivePattern) -> AgentHostRecordingV1: ...


class StaticAgentHostAdapterV1:
    """Offline reference adapter over already-validated recording objects.

    It never imports a plugin, executes a host, opens a network connection, or converts
    observations into PASS/FAIL.  Missing patterns are explicit adapter errors.
    """

    def __init__(self, recordings: tuple[AgentHostRecordingV1, ...]) -> None:
        if not recordings:
            raise AgentHostContractError("at least one recording is required")
        by_pattern = {recording.pattern_id: recording for recording in recordings}
        if len(by_pattern) != len(recordings):
            raise AgentHostContractError("recording pattern ids must be unique")
        descriptors = {recording.host for recording in recordings}
        if len(descriptors) != 1:
            raise AgentHostContractError("static adapter recordings must share one host")
        self.descriptor = recordings[0].host
        self._recordings = by_pattern

    def collect(self, pattern: DefensivePattern) -> AgentHostRecordingV1:
        try:
            return self._recordings[pattern.pattern_id]
        except KeyError as exc:
            raise AgentHostContractError(
                "no recording is available for the requested corpus pattern"
            ) from exc


def build_agent_host_recording_v1(
    *,
    pattern_id: str,
    host: AgentHostDescriptorV1,
    events: tuple[CanonicalObservationEventV1, ...],
    terminal_status: AgentHostTerminalStatus,
) -> AgentHostRecordingV1:
    """Build one exact V1 record and derive all commitments and identity fields."""

    commitments = tuple(commit_portfolio_observation_v1(event) for event in events)
    provisional = AgentHostRecordingV1.model_construct(
        schema_version=AGENT_HOST_RECORDING_V1,
        recording_id="0" * 64,
        corpus_version="1.0.0",
        corpus_manifest_sha256=corpus_manifest_sha256(),
        pattern_id=pattern_id,
        host=host,
        events=events,
        event_commitments=commitments,
        terminal_status=terminal_status,
        telemetry_state=_aggregate_telemetry(events),
        verdict_semantics="observation_only_no_security_verdict",
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["recording_id"] = _recording_identity(provisional)
    return AgentHostRecordingV1.model_validate(payload)


def encode_agent_host_recording_v1(recording: AgentHostRecordingV1) -> bytes:
    """Return the sole canonical UTF-8 JSON representation of a V1 recording."""

    payload = recording.model_dump(mode="json")
    payload["events"] = [
        json.loads(encode_portfolio_observation_v1(event)) for event in recording.events
    ]
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise AgentHostContractError(
            "recording cannot be encoded as canonical JSON"
        ) from exc
    if len(encoded) > MAX_AGENT_HOST_RECORDING_BYTES:
        raise AgentHostContractError("recording exceeds the V1 byte limit")
    return encoded


def decode_agent_host_recording_v1(payload: bytes) -> AgentHostRecordingV1:
    """Decode exact canonical V1 bytes; ambiguous or malformed input fails closed."""

    if not isinstance(payload, bytes):
        raise AgentHostContractError("recording payload must be bytes")
    if not payload or len(payload) > MAX_AGENT_HOST_RECORDING_BYTES:
        raise AgentHostContractError("recording payload size is outside the V1 limit")
    try:
        decoded = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AgentHostContractError("recording is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise AgentHostContractError("recording must be a JSON object")
    if set(decoded) != set(AgentHostRecordingV1.model_fields):
        raise AgentHostContractError("recording fields do not match V1")
    if decoded.get("schema_version") != AGENT_HOST_RECORDING_V1:
        raise AgentHostContractError("unsupported recording schema version")
    try:
        recording = AgentHostRecordingV1.model_validate(decoded)
    except ValueError as exc:
        raise AgentHostContractError("recording values violate V1") from exc
    if encode_agent_host_recording_v1(recording) != payload:
        raise AgentHostContractError("recording JSON is not canonical V1")
    return recording


def read_agent_host_recording_v1(path: Path) -> AgentHostRecordingV1:
    """Read a stable, regular, single-link recording without following unsafe paths."""

    candidate = path.absolute()
    _require_safe_input_path(candidate)
    before = candidate.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise AgentHostContractError("recording input must be a regular single-link file")
    if before.st_size <= 0 or before.st_size > MAX_AGENT_HOST_RECORDING_BYTES:
        raise AgentHostContractError("recording input size is outside the V1 limit")
    payload = candidate.read_bytes()
    after = candidate.lstat()
    _require_safe_input_path(candidate)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if identity_before != identity_after:
        raise AgentHostContractError("recording input changed while it was read")
    return decode_agent_host_recording_v1(payload)


def commit_agent_host_recording_v1(
    recording: AgentHostRecordingV1,
) -> AgentHostRecordingCommitmentV1:
    """Bind the exact canonical recording without granting trust or authority."""

    content_sha256 = hashlib.sha256(encode_agent_host_recording_v1(recording)).hexdigest()
    return AgentHostRecordingCommitmentV1(
        schema_version=AGENT_HOST_RECORDING_COMMITMENT_V1,
        recording_schema_version=AGENT_HOST_RECORDING_V1,
        domain=AGENT_HOST_RECORDING_COMMITMENT_DOMAIN,
        content_sha256=content_sha256,
        commitment_sha256=_recording_commitment_digest(content_sha256),
        operational_authority="none",
    )


def inspect_agent_host_recording_v1(
    recording: AgentHostRecordingV1,
) -> AgentHostInspectionV1:
    """Replay the event order into a safe summary without producing a verdict."""

    commitment = commit_agent_host_recording_v1(recording)
    source_surfaces = tuple(sorted({event.source_surface for event in recording.events}))
    activities = tuple(dict.fromkeys(event.activity for event in recording.events))
    tool_activity_observed = any(
        event.source_surface in {"tool", "mcp"}
        or event.activity.startswith(("tool.", "mcp."))
        for event in recording.events
    )
    return AgentHostInspectionV1(
        schema_version=AGENT_HOST_INSPECTION_V1,
        recording_id=recording.recording_id,
        recording_commitment_sha256=commitment.commitment_sha256,
        pattern_id=recording.pattern_id,
        event_count=len(recording.events),
        source_surfaces=source_surfaces,
        activities=activities,
        terminal_status=recording.terminal_status,
        telemetry_state=recording.telemetry_state,
        capture_mode=recording.host.capture_mode,
        network_mode=recording.host.network_mode,
        tool_activity_observed=tool_activity_observed,
        producer_attestation="unattested",
        verdict_semantics="observation_only_no_security_verdict",
        operational_authority="none",
    )


def agent_host_recording_v1_json_schema() -> dict[str, Any]:
    """Return the generated public JSON Schema for the closed V1 record."""

    return AgentHostRecordingV1.model_json_schema()


def _aggregate_telemetry(
    events: tuple[CanonicalObservationEventV1, ...],
) -> AgentHostTelemetryState:
    if not events:
        return "incomplete"
    states = {event.telemetry_state for event in events}
    if states == {"complete"}:
        return "complete"
    for state in ("malformed", "conflicting", "incomplete", "unattested"):
        if state in states:
            return state
    return "incomplete"


def _recording_identity(recording: AgentHostRecordingV1) -> str:
    payload = {
        "domain": "agentic-security-harness/agent-host-recording-id/v1.0",
        "schema_version": recording.schema_version,
        "corpus_version": recording.corpus_version,
        "corpus_manifest_sha256": recording.corpus_manifest_sha256,
        "pattern_id": recording.pattern_id,
        "host": recording.host.model_dump(mode="json"),
        "event_commitment_sha256": [
            commitment.commitment_sha256
            for commitment in recording.event_commitments
        ],
        "terminal_status": recording.terminal_status,
        "telemetry_state": recording.telemetry_state,
        "verdict_semantics": recording.verdict_semantics,
        "operational_authority": recording.operational_authority,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _recording_commitment_digest(content_sha256: str) -> str:
    data = "\0".join(
        (
            AGENT_HOST_RECORDING_COMMITMENT_DOMAIN,
            AGENT_HOST_RECORDING_V1,
            content_sha256,
        )
    ).encode("ascii")
    return hashlib.sha256(data).hexdigest()


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AgentHostContractError("duplicate JSON field")
        result[key] = value
    return result


def _require_safe_input_path(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        raise AgentHostContractError("recording input does not exist")
    for component in (path, *path.parents):
        if is_link_or_reparse(component):
            raise AgentHostContractError(
                "recording input must not traverse a link or reparse point"
            )
        if component.parent == component:
            break
    try:
        info = path.lstat()
    except OSError as exc:
        raise AgentHostContractError("recording input metadata is unavailable") from exc
    if os.name == "nt":
        attributes = int(getattr(info, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
        if reparse_flag and attributes & reparse_flag:
            raise AgentHostContractError("recording input must not be a reparse point")
