"""Host-owned, authority-free source capture for a guarded workspace operation.

The caller chooses and retains the profile, store paths, checkpoint, and returned
manifest anchor. This local capture is unattested and cannot prove uncaptured
events absent or protect a producer-controlled checkpoint from rollback.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from agentic_security_harness.ancestry_store import AncestryStore
from agentic_security_harness.companion_contracts import (
    CoverageExpectationProfileV1,
    TrajectoryObservationRefV1,
    build_telemetry_manifest_v1,
    build_trajectory_accounting_v1,
    canonical_companion_digest,
)
from agentic_security_harness.portfolio_contract import (
    AdapterAuditV1,
    AdapterFieldMappingV1,
    CanonicalObservationEventV1,
    SafeEvidencePointer,
    commit_portfolio_observation_v1,
)
from agentic_security_harness.trajectory_admission import (
    build_coverage_event_record,
    build_coverage_root_record,
)
from agentic_security_harness.workspace_admission import (
    WorkspaceAdmission,
    WorkspaceAdmissionError,
    WorkspaceSources,
)
from agentic_security_harness.workspace_writer import WorkspacePolicy

_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SURFACES: dict[str, Literal["user", "tool", "memory", "document"]] = {
    "input": "user",
    "tool_output": "tool",
    "memory": "memory",
    "handoff": "document",
}


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _audit() -> AdapterAuditV1:
    mappings = (
        AdapterFieldMappingV1(
            source_fields=("event_id",),
            target_fields=("event_id",),
            transformation="identity",
            authority_effect="none",
        ),
        AdapterFieldMappingV1(
            source_fields=("occurred_at",),
            target_fields=("occurred_at",),
            transformation="identity",
            authority_effect="none",
        ),
        AdapterFieldMappingV1(
            source_fields=("source_kind",),
            target_fields=("source_surface",),
            transformation="derived",
            authority_effect="downgrade",
        ),
        AdapterFieldMappingV1(
            source_fields=("content_sha256",),
            target_fields=("entity_refs",),
            transformation="derived",
            authority_effect="downgrade",
        ),
        AdapterFieldMappingV1(
            source_fields=("restrictions_sha256",),
            target_fields=("data_envelope_ref",),
            transformation="derived",
            authority_effect="downgrade",
        ),
    )
    return AdapterAuditV1(
        schema_version="portfolio-adapter-audit-v1.0",
        source_model="harness.workspace_source_capture",
        target_model="portfolio-observation-v1.0",
        completeness="partial",
        source_fields=(
            "event_id",
            "occurred_at",
            "source_kind",
            "content_sha256",
            "restrictions_sha256",
        ),
        target_fields=tuple(CanonicalObservationEventV1.model_fields),
        mappings=mappings,
        dropped_source_fields=(),
        context_target_fields=("project_id", "repository_id", "repository_sha", "producer_id_hash"),
        constant_target_fields=(
            "schema_version",
            "producer_attestation",
            "activity",
            "parent_event_ids",
            "authority_envelope_ref",
            "telemetry_state",
            "operational_authority",
        ),
        authority_downgrade=True,
        reason_codes=("adapter.host_context_supplied",),
        operational_authority="none",
    )


@dataclass(frozen=True)
class WorkspaceCapture:
    """Observed source events plus a host-retainable admission context."""

    admission: WorkspaceAdmission
    observations: tuple[CanonicalObservationEventV1, ...]


def capture_workspace_sources(
    store_path: Path,
    witness_path: Path,
    *,
    sources: WorkspaceSources,
    policy: WorkspacePolicy,
    expected_profile: CoverageExpectationProfileV1,
    logical_operation_id: str,
    context: str = "workspace-source-capture",
) -> WorkspaceCapture:
    """Capture a fixed host-selected source bundle; never authorize an effect.

    Invalid host inputs are rejected before store creation. Once creation starts,
    any storage failure leaves its evidence in place for explicit owner handling.
    """
    if (
        not isinstance(store_path, Path)
        or not isinstance(witness_path, Path)
        or type(sources) is not WorkspaceSources
        or type(policy) is not WorkspacePolicy
        or type(expected_profile) is not CoverageExpectationProfileV1
        or type(logical_operation_id) is not str
        or _SHA.fullmatch(logical_operation_id) is None
        or type(context) is not str
    ):
        raise WorkspaceAdmissionError("capture_host_input_invalid")
    try:
        profile = CoverageExpectationProfileV1.model_validate(
            expected_profile.model_dump(mode="python")
        )
        sources._revalidate()
        bound = sources.bind_policy(policy)
        if bound != policy or policy.source_restrictions_sha256 is None:
            raise WorkspaceAdmissionError("capture_policy_unbound")
        if profile.expected_event_count != len(sources.parts) or profile.expected_channels != tuple(
            sorted({part.kind for part in sources.parts})
        ):
            raise WorkspaceAdmissionError("capture_expectation_mismatch")
        sources.input_bytes(policy)
        root = build_coverage_root_record(
            context=context,
            expected_profile=profile,
            logical_operation_id=logical_operation_id,
            policy_sha256=policy.sha256,
        )
        audit = _audit()
    except WorkspaceAdmissionError:
        raise
    except (ValueError, TypeError, AttributeError, RecursionError) as exc:
        raise WorkspaceAdmissionError("capture_host_input_invalid") from exc

    store = AncestryStore.create(store_path, witness_path, context=context, root=root)
    checkpoint = store.checkpoint()
    started = datetime.now(UTC)
    observations: list[CanonicalObservationEventV1] = []
    refs: list[TrajectoryObservationRefV1] = []
    producer = _digest(_canonical(["workspace-source-capture", context, logical_operation_id]))
    attempt = _digest(_canonical(["capture-attempt", logical_operation_id]))
    for sequence, part in enumerate(sources.parts, 1):
        observed = datetime.now(UTC)
        content_sha = _digest(part.content)
        restriction_sha = part.restrictions.sha256
        event_id = _digest(
            _canonical(
                [
                    "source-capture",
                    logical_operation_id,
                    sequence,
                    part.kind,
                    part.source_id,
                    content_sha,
                    restriction_sha,
                    observed.isoformat(),
                ]
            )
        )
        observation = CanonicalObservationEventV1(
            schema_version="portfolio-observation-v1.0",
            event_id=event_id,
            project_id=profile.project_id,
            repository_id=profile.repository_id,
            repository_sha=profile.repository_sha,
            occurred_at=observed,
            producer_id_hash=producer,
            producer_attestation="unattested",
            source_surface=_SURFACES[part.kind],
            activity="workspace.source_captured",
            entity_refs=(
                SafeEvidencePointer(
                    kind="artifact",
                    digest=content_sha,
                    locator_id=_digest(_canonical([part.kind, part.source_id])),
                ),
            ),
            parent_event_ids=(),
            data_envelope_ref=restriction_sha,
            authority_envelope_ref=None,
            telemetry_state="unattested",
            operational_authority="none",
        )
        ref = TrajectoryObservationRefV1(
            event_id=event_id,
            occurred_at=observed,
            observation_commitment_sha256=commit_portfolio_observation_v1(
                observation
            ).commitment_sha256,
            logical_operation_id=logical_operation_id,
            attempt_id=attempt,
            attempt_ordinal=1,
            idempotency_identity=_digest(logical_operation_id.encode()),
            retry_cause="initial",
            route_id_hash=_digest(b"workspace-source-capture-route"),
            route_transition_reason="initial",
            permitted_route_set_sha256=_digest(b"workspace-source-capture-route-set"),
            route_permitted=True,
            constraint_encounters=(),
            parent_event_ids=(),
        )
        checkpoint = store.append(
            build_coverage_event_record(
                context=context,
                sequence=sequence,
                observation=ref,
                channel=part.kind,
            ),
            expected=checkpoint,
        )
        observations.append(observation)
        refs.append(ref)
    ended = datetime.now(UTC)
    manifest = build_telemetry_manifest_v1(
        profile=profile,
        observed_channels=profile.expected_channels,
        dropped_record_count=0,
        rejected_record_count=0,
        adapter_audit=audit,
        trajectory=build_trajectory_accounting_v1(
            expected_event_count=profile.expected_event_count, observations=tuple(refs)
        ),
        window_started_at=started,
        window_ended_at=ended,
    )
    admission = WorkspaceAdmission(
        sources=sources,
        store=store,
        expected_checkpoint=checkpoint,
        expected_profile=profile,
        logical_operation_id=logical_operation_id,
        policy_sha256=policy.sha256,
        expected_manifest_sha256=canonical_companion_digest(manifest),
        host_phase="sealed",
        manifest=manifest,
    )
    admission.verify(operation_id=logical_operation_id, policy=policy)
    return WorkspaceCapture(admission=admission, observations=tuple(observations))
