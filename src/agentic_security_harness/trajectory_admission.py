"""Observational, checkpoint-bound composition of retained telemetry evidence.

The caller owns the store, checkpoint, expectation, policy, and host phase.  This
module neither discovers their currentness nor authorizes operational effects.
AncestryStore.snapshot may perform its own recovery and rewrite its witness.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

from pydantic import ValidationError

from .ancestry_store import AncestryRecord, AncestryStore, Checkpoint
from .companion_contracts import (
    CoverageExpectationProfileV1,
    TelemetryManifestV1,
    TrajectoryObservationRefV1,
    build_trajectory_accounting_v1,
    canonical_companion_digest,
)

_ROOT_SCHEMA = "ash-retained-telemetry-root-v1"
_EVENT_SCHEMA = "ash-retained-telemetry-event-v1"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ROOT_SCOPE = ("retained-telemetry",)
_EVENT_SCOPE = _ROOT_SCOPE
_MAX_COMPOSED_EVENTS = 4095  # AncestryStore's 4096 records include the root.


@dataclass(frozen=True)
class TelemetryAdmission:
    retained_binding: Literal["matched", "rejected"]
    coverage_state: Literal["complete", "incomplete", "rejected"]
    completion: Literal["pending", "incomplete", "complete", "rejected"]
    reason: str
    observed_event_count: int
    operational_authority: Literal["none"] = "none"
    may_authorize_effects: Literal[False] = False


def _json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _profile(value: CoverageExpectationProfileV1) -> CoverageExpectationProfileV1:
    if type(value) is not CoverageExpectationProfileV1:
        raise ValueError("expected profile has wrong type")
    return CoverageExpectationProfileV1.model_validate(value.model_dump(mode="python"))


def _observation(value: TrajectoryObservationRefV1) -> TrajectoryObservationRefV1:
    if type(value) is not TrajectoryObservationRefV1:
        raise ValueError("observation has wrong type")
    return TrajectoryObservationRefV1.model_validate(value.model_dump(mode="python"))


def _host_fields(logical_operation_id: str, policy_sha256: str) -> None:
    if type(logical_operation_id) is not str or _SHA.fullmatch(logical_operation_id) is None:
        raise ValueError("logical operation must be a lowercase SHA-256 identity")
    if type(policy_sha256) is not str or _SHA.fullmatch(policy_sha256) is None:
        raise ValueError("policy must be a lowercase SHA-256 digest")


def build_coverage_root_record(
    *,
    context: str,
    expected_profile: CoverageExpectationProfileV1,
    logical_operation_id: str,
    policy_sha256: str,
) -> AncestryRecord:
    """Build a canonical host-bound root; caller persists it with AncestryStore."""
    profile = _profile(expected_profile)
    _host_fields(logical_operation_id, policy_sha256)
    if profile.expected_event_count > _MAX_COMPOSED_EVENTS:
        raise ValueError("profile exceeds root-plus-events store capacity")
    return AncestryRecord(
        record_id="root",
        context=context,
        payload=_json(
            {
                "schema_version": _ROOT_SCHEMA,
                "profile": profile.model_dump(mode="json"),
                "logical_operation_id": logical_operation_id,
                "policy_sha256": policy_sha256,
            }
        ),
        parents=(),
        scope=_ROOT_SCOPE,
    )


def build_coverage_event_record(
    *,
    context: str,
    sequence: int,
    observation: TrajectoryObservationRefV1,
    channel: str,
) -> AncestryRecord:
    """Build a host capture-order record; this order is not trajectory causality."""
    if type(sequence) is not int or not 1 <= sequence <= _MAX_COMPOSED_EVENTS:
        raise ValueError("event sequence must be between 1 and 4095")
    if type(channel) is not str or re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", channel) is None:
        raise ValueError("channel must be a canonical token")
    ref = _observation(observation)
    return AncestryRecord(
        record_id=f"event-{sequence:04d}",
        context=context,
        payload=_json(
            {
                "schema_version": _EVENT_SCHEMA,
                "sequence": sequence,
                "channel": channel,
                "observation": ref.model_dump(mode="json"),
            }
        ),
        parents=("root" if sequence == 1 else f"event-{sequence - 1:04d}",),
        scope=_EVENT_SCOPE,
    )


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject(reason: str, count: int = 0) -> TelemetryAdmission:
    return TelemetryAdmission("rejected", "rejected", "rejected", reason, count)


def assess_retained_telemetry(
    store: AncestryStore,
    *,
    expected_checkpoint: Checkpoint,
    expected_profile: CoverageExpectationProfileV1,
    logical_operation_id: str,
    policy_sha256: str,
    expected_manifest_sha256: str,
    host_phase: Literal["pending", "sealed"] = "pending",
    manifest: TelemetryManifestV1,
) -> TelemetryAdmission:
    """Compare exact retained bytes with host inputs, never grant execution authority.

    Store snapshot errors (including stale checkpoints) deliberately propagate.
    A snapshot may recover the store and rewrite its witness; this function
    itself does not append records or grant effects.
    The host must retain/admit expected_manifest_sha256 independently of the
    candidate; digesting an incoming candidate here is not host admission.
    Host-supplied checkpoint currentness and phase are external trust premises.
    """
    if type(store) is not AncestryStore:
        raise TypeError("AncestryStore required")
    try:
        profile = _profile(expected_profile)
        _host_fields(logical_operation_id, policy_sha256)
        if (
            type(expected_manifest_sha256) is not str
            or _SHA.fullmatch(expected_manifest_sha256) is None
        ):
            raise ValueError("expected manifest digest must be lowercase SHA-256")
        if host_phase not in ("pending", "sealed") or type(host_phase) is not str:
            raise ValueError("invalid host phase")
        if profile.expected_event_count > _MAX_COMPOSED_EVENTS:
            raise ValueError("profile exceeds root-plus-events store capacity")
    except (ValueError, TypeError, ValidationError):
        return _reject("invalid_host_input")
    try:
        if type(manifest) is not TelemetryManifestV1:
            raise ValueError("manifest has wrong type")
        checked_manifest = TelemetryManifestV1.model_validate(manifest.model_dump(mode="python"))
        manifest_digest = canonical_companion_digest(checked_manifest)
    except (ValueError, TypeError, ValidationError):
        return _reject("invalid_manifest")
    if manifest_digest != expected_manifest_sha256:
        return _reject("manifest_anchor_mismatch")
    snapshot = store.snapshot(expected=expected_checkpoint)
    try:
        expected_root = build_coverage_root_record(
            context=snapshot.checkpoint.context,
            expected_profile=profile,
            logical_operation_id=logical_operation_id,
            policy_sha256=policy_sha256,
        )
    except (ValueError, TypeError, ValidationError):
        return _reject("invalid_host_input")
    records = snapshot.records
    if not records or records[0] != expected_root:
        return _reject("root_binding_mismatch")
    event_records = records[1:]
    if not event_records or len(event_records) > profile.expected_event_count:
        return _reject("event_count_out_of_bounds", len(event_records))
    observations: list[TrajectoryObservationRefV1] = []
    channels: set[str] = set()
    for sequence, record in enumerate(event_records, 1):
        try:
            payload = json.loads(record.payload.decode("ascii"), object_pairs_hook=_pairs)
            if type(payload) is not dict or set(payload) != {
                "schema_version", "sequence", "channel", "observation"
            }:
                raise ValueError("event layout")
            if payload["schema_version"] != _EVENT_SCHEMA or type(payload["sequence"]) is not int:
                raise ValueError("event schema or sequence")
            if type(payload["observation"]) is not dict:
                raise ValueError("observation layout")
            ref = TrajectoryObservationRefV1.model_validate(payload["observation"])
            expected_event = build_coverage_event_record(
                context=snapshot.checkpoint.context,
                sequence=sequence,
                observation=ref,
                channel=payload["channel"],
            )
            if record != expected_event or ref.logical_operation_id != logical_operation_id:
                raise ValueError("event binding")
        except (ValueError, TypeError, UnicodeError, RecursionError, ValidationError):
            return _reject("event_binding_mismatch", len(event_records))
        observations.append(ref)
        channels.add(payload["channel"])
    try:
        rebuilt = build_trajectory_accounting_v1(
            expected_event_count=profile.expected_event_count,
            observations=tuple(observations),
            censoring_state=checked_manifest.trajectory_accounting.censoring_state,
        )
    except (ValueError, TypeError, ValidationError):
        return _reject("trajectory_reconstruction_failed", len(event_records))
    if (
        checked_manifest.coverage_expectation_profile != profile
        or checked_manifest.trajectory_accounting.logical_operation_id != logical_operation_id
        or checked_manifest.trajectory_accounting != rebuilt
        or checked_manifest.observed_channels != tuple(sorted(channels))
    ):
        return TelemetryAdmission(
            "matched", "rejected", "rejected", "manifest_retained_mismatch", len(event_records)
        )
    coverage = checked_manifest.telemetry_state
    completion: Literal["pending", "incomplete", "complete", "rejected"] = (
        "rejected" if coverage == "rejected" else "pending" if host_phase == "pending" else coverage
    )
    return TelemetryAdmission(
        "matched", coverage, completion, "retained_evidence_matched", len(event_records)
    )
