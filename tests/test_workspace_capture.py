"""Focused, offline tests for host-owned workspace source capture."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentic_security_harness.ancestry_store import AncestryRecord, AncestryStore, Checkpoint
from agentic_security_harness.companion_contracts import (
    CoverageExpectationProfileV1,
    build_coverage_expectation_profile_v1,
)
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.models import DataEnvelope
from agentic_security_harness.portfolio_contract import commit_portfolio_observation_v1
from agentic_security_harness.workspace_admission import (
    WorkspaceAdmissionError,
    WorkspaceSource,
    WorkspaceSources,
)
from agentic_security_harness.workspace_capture import capture_workspace_sources
from agentic_security_harness.workspace_operation import WorkspaceOperation
from agentic_security_harness.workspace_writer import WorkspacePolicy

KINDS = ("input", "tool_output", "memory", "handoff")
OPERATION = hashlib.sha256(b"capture-factory-operation").hexdigest()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def inputs(
    tmp_path: Path, *, expired: bool = False,
) -> tuple[WorkspaceSources, WorkspacePolicy, CoverageExpectationProfileV1]:
    output = tmp_path / "output"
    output.mkdir()
    envelope = DataEnvelope(
        data_class="synthetic",
        allowed_recipients=["local-model"],
        allowed_purpose=["document-generation"],
        can_store=True,
        can_forward=True,
        ttl_seconds=0 if expired else 3600,
        requires_confirmation=False,
        classification_source="host",
        classification_mutable=False,
    )
    parts = []
    for index, kind in enumerate(KINDS):
        content = f"synthetic {kind} {index}".encode()
        restriction = DocumentSourceRestrictions.bind(
            content,
            envelope,
            created_at=datetime.now(UTC) - timedelta(seconds=2),
        )
        parts.append(WorkspaceSource(kind, f"part{index}", content, restriction))
    sources = WorkspaceSources.bind(tuple(parts))
    policy = sources.bind_policy(
        WorkspacePolicy(
            output,
            (("report", "report.md"),),
            data_class="synthetic",
            max_proposals=1,
        )
    )
    profile = build_coverage_expectation_profile_v1(
        project_id="agentic-security-harness",
        repository_id="krivonosoff161/agentic-security-harness",
        repository_sha="a" * 40,
        expected_channels=tuple(sorted(KINDS)),
        expected_event_count=4,
        expectation_source_sha256=sha(b"host-fixed-four-sources"),
    )
    return sources, policy, profile


def paths(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "capture.db", tmp_path / "capture.witness"


def test_four_sources_commit_canonical_evidence_and_write(tmp_path: Path) -> None:
    sources, policy, profile = inputs(tmp_path)
    db, witness = paths(tmp_path)
    result = capture_workspace_sources(
        db,
        witness,
        sources=sources,
        policy=policy,
        expected_profile=profile,
        logical_operation_id=OPERATION,
    )
    assert len(result.observations) == 4
    assert result.admission.verify(operation_id=OPERATION, policy=policy).completion == "complete"
    assert (
        result.admission.manifest.adapter_audit.source_model == "harness.workspace_source_capture"
    )
    assert result.admission.manifest.operational_authority == "none"
    assert result.admission.expected_profile == profile
    assert result.admission.expected_checkpoint.sequence == 5
    snapshot = result.admission.store.snapshot(expected=result.admission.expected_checkpoint)
    expected_surfaces = ("user", "tool", "memory", "document")
    for index, (part, observation, surface) in enumerate(
        zip(sources.parts, result.observations, expected_surfaces, strict=True), 1
    ):
        ref = result.admission.manifest.trajectory_accounting.observations
        matching = next(item for item in ref if item.event_id == observation.event_id)
        assert matching.observation_commitment_sha256 == (
            commit_portfolio_observation_v1(observation).commitment_sha256
        )
        assert observation.source_surface == surface
        assert observation.entity_refs[0].digest == sha(part.content)
        assert observation.data_envelope_ref == part.restrictions.sha256
        assert observation.producer_attestation == "unattested"
        assert observation.operational_authority == "none"
        assert observation.authority_envelope_ref is None
        assert part.content not in snapshot.records[index].payload
    operation = WorkspaceOperation.create(
        tmp_path / "operation.db",
        policy,
        operation_id=OPERATION,
        artifact="report",
        content="synthetic report",
        admission=result.admission,
    )
    assert operation.deliver(operation.authorize())["state"] == "DELIVERED_RECEIPT"
    assert (policy.output_dir / "report.md").read_text(encoding="utf-8") == "synthetic report"


@pytest.mark.parametrize(
    "change", ["count", "channel", "forged", "forged_bundle", "unbound", "expired"],
)
def test_invalid_inputs_refuse_before_store(tmp_path: Path, change: str) -> None:
    sources, policy, profile = inputs(tmp_path, expired=change == "expired")
    if change == "count":
        profile = build_coverage_expectation_profile_v1(
            project_id=profile.project_id,
            repository_id=profile.repository_id,
            repository_sha=profile.repository_sha,
            expected_channels=profile.expected_channels,
            expected_event_count=3,
            expectation_source_sha256=profile.expectation_source_sha256,
        )
    elif change == "channel":
        profile = build_coverage_expectation_profile_v1(
            project_id=profile.project_id,
            repository_id=profile.repository_id,
            repository_sha=profile.repository_sha,
            expected_channels=("input", "memory", "tool_output"),
            expected_event_count=4,
            expectation_source_sha256=profile.expectation_source_sha256,
        )
    elif change == "forged":
        profile = CoverageExpectationProfileV1.model_construct(
            **{
                **profile.model_dump(mode="python"),
                "expected_event_count": 3,
            }
        )
    elif change == "forged_bundle":
        object.__setattr__(sources, "binding_sha256", "0" * 64)
    elif change == "unbound":
        policy = WorkspacePolicy(
            policy.output_dir,
            policy.outputs,
            data_class="synthetic",
            max_proposals=1,
        )
    db, witness = paths(tmp_path)
    with pytest.raises(WorkspaceAdmissionError):
        capture_workspace_sources(
            db,
            witness,
            sources=sources,
            policy=policy,
            expected_profile=profile,
            logical_operation_id=OPERATION,
        )
    assert not db.exists() and not witness.exists()


def test_partial_append_failure_retains_existing_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources, policy, profile = inputs(tmp_path)
    db, witness = paths(tmp_path)
    original = AncestryStore.append
    calls = 0

    def fail_second(
        self: AncestryStore, record: AncestryRecord, *, expected: Checkpoint,
    ) -> Checkpoint:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic storage failure")
        return original(self, record, expected=expected)

    monkeypatch.setattr(AncestryStore, "append", fail_second)
    with pytest.raises(OSError, match="synthetic storage failure"):
        capture_workspace_sources(
            db,
            witness,
            sources=sources,
            policy=policy,
            expected_profile=profile,
            logical_operation_id=OPERATION,
        )
    assert db.exists() and witness.exists()
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        root_digest = connection.execute(
            "SELECT value FROM meta WHERE key='root_digest'",
        ).fetchone()[0]
    retained = AncestryStore.open(
        db, witness, context="workspace-source-capture", root_digest=root_digest
    )
    checkpoint = retained.checkpoint()
    assert checkpoint.sequence == 2  # Root and first capture survive; no cleanup/retry.


def test_changed_or_stale_capture_context_refuses(tmp_path: Path) -> None:
    sources, policy, profile = inputs(tmp_path)
    db, witness = paths(tmp_path)
    result = capture_workspace_sources(
        db,
        witness,
        sources=sources,
        policy=policy,
        expected_profile=profile,
        logical_operation_id=OPERATION,
    )
    changed = replace(
        result.admission,
        expected_checkpoint=replace(result.admission.expected_checkpoint, context="other-context"),
    )
    with pytest.raises(WorkspaceAdmissionError):
        changed.verify(operation_id=OPERATION, policy=policy)
    store = result.admission.store
    store.append(
        AncestryRecord(
            record_id="later",
            context=store.context,
            payload=b"later",
            parents=("event-0004",),
            scope=("retained-telemetry",),
        ),
        expected=result.admission.expected_checkpoint,
    )
    with pytest.raises(WorkspaceAdmissionError):
        result.admission.verify(operation_id=OPERATION, policy=policy)
