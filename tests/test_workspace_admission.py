"""Pre-action evidence never replaces host policy or authenticates document meaning."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness.ancestry_store import AncestryStore
from agentic_security_harness.companion_contracts import (
    TrajectoryObservationRefV1,
    build_coverage_expectation_profile_v1,
    build_telemetry_manifest_v1,
    build_trajectory_accounting_v1,
    canonical_companion_digest,
)
from agentic_security_harness.document_multisource import DocumentMultiSourceRestrictions
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.models import DataEnvelope
from agentic_security_harness.portfolio_contract import (
    AdapterAuditV1,
    AdapterFieldMappingV1,
    CanonicalObservationEventV1,
)
from agentic_security_harness.trajectory_admission import (
    build_coverage_event_record,
    build_coverage_root_record,
)
from agentic_security_harness.workspace_admission import (
    WorkspaceAdmission,
    WorkspaceAdmissionError,
    WorkspaceSource,
    WorkspaceSources,
)
from agentic_security_harness.workspace_operation import WorkspaceOperation, WorkspaceOperationError
from agentic_security_harness.workspace_writer import WorkspacePolicy

KINDS = ("input", "tool_output", "memory", "handoff")
TEXT = "# Account summary\n\nApproved: 30\nRejected: 4\n"
OPERATION = hashlib.sha256(b"host-selected-operation").hexdigest()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def envelope(**changes: Any) -> DataEnvelope:
    values: dict[str, Any] = {
        "data_class": "synthetic", "allowed_recipients": ["local-model"],
        "allowed_purpose": ["document-generation"], "can_store": True,
        "can_forward": True, "ttl_seconds": 3600, "requires_confirmation": False,
        "classification_source": "host", "classification_mutable": False,
    } | changes
    return DataEnvelope(**values)


def parts(**changes: Any) -> tuple[WorkspaceSource, ...]:
    origin = datetime.now(UTC) - timedelta(seconds=1)
    result = []
    for index, kind in enumerate(KINDS):
        raw = f"Host-selected {kind} data {index}.".encode()
        restriction = DocumentSourceRestrictions.bind(
            raw, envelope(**changes), created_at=origin,
        )
        result.append(WorkspaceSource(kind, f"source{index}", raw, restriction))
    return tuple(result)


def audit() -> AdapterAuditV1:
    return AdapterAuditV1(
        schema_version="portfolio-adapter-audit-v1.0",
        source_model="harness.workspace_source_capture", target_model="portfolio-observation-v1.0",
        completeness="partial", source_fields=("event_id", "source_kind"),
        target_fields=tuple(CanonicalObservationEventV1.model_fields),
        mappings=(
            AdapterFieldMappingV1(source_fields=("event_id",), target_fields=("event_id",),
                                  transformation="identity", authority_effect="none"),
            AdapterFieldMappingV1(source_fields=("source_kind",), target_fields=("activity",),
                                  transformation="derived", authority_effect="downgrade"),
        ),
        dropped_source_fields=(),
        context_target_fields=("project_id", "repository_id", "repository_sha", "occurred_at",
                               "producer_id_hash", "source_surface", "entity_refs",
                               "parent_event_ids", "data_envelope_ref", "telemetry_state"),
        constant_target_fields=("schema_version", "producer_attestation",
                                "authority_envelope_ref", "operational_authority"),
        authority_downgrade=True, reason_codes=("adapter.host_context_supplied",),
        operational_authority="none",
    )


def test_host_capture_audit_has_no_runtime_or_action_authority() -> None:
    value = audit()
    assert value.source_model == "harness.workspace_source_capture"
    assert value.operational_authority == "none"
    assert value.authority_downgrade
    assert "authority_envelope_ref" in value.constant_target_fields


@pytest.mark.parametrize("changes", [
    {"source_model": "unrecognized.remote_producer"},
    {"operational_authority": "allow"},
    {"authority_downgrade": False},
])
def test_host_capture_audit_does_not_relax_existing_validation(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        AdapterAuditV1.model_validate(audit().model_dump() | changes)


@dataclass
class Host:
    path: Path
    policy: WorkspacePolicy
    admission: WorkspaceAdmission

    def operation(self, *, content: str = TEXT) -> WorkspaceOperation:
        return WorkspaceOperation.create(
            self.path, self.policy, operation_id=OPERATION, artifact="report", content=content,
            admission=self.admission,
        )

    def reopen(self, **changes: Any) -> WorkspaceOperation:
        args: dict[str, Any] = {"operation_id": OPERATION, "artifact": "report", "content": TEXT,
                                "admission": self.admission} | changes
        return WorkspaceOperation.open(self.path, self.policy, **args)


def host(tmp_path: Path, *, count: int = 4, **source_changes: Any) -> Host:
    source_parts = parts(**source_changes)
    sources = WorkspaceSources.bind(source_parts)
    output = tmp_path / "output"
    output.mkdir()
    (output / "protected.txt").write_text("untouched", encoding="utf-8")
    policy = sources.bind_policy(WorkspacePolicy(
        output, (("report", "summary.md"),), data_class="synthetic", max_proposals=1,
    ))
    # These expectations are chosen before constructing the supplied history.
    profile = build_coverage_expectation_profile_v1(
        project_id="agentic-security-harness",
        repository_id="krivonosoff161/agentic-security-harness",
        repository_sha="a" * 40, expected_channels=tuple(sorted(KINDS)),
        expected_event_count=4, expectation_source_sha256=digest("four fixed source boundaries"),
    )
    root = build_coverage_root_record(context="owned-input-capture", expected_profile=profile,
                                      logical_operation_id=OPERATION, policy_sha256=policy.sha256)
    store = AncestryStore.create(tmp_path / "history.db", tmp_path / "history.witness",
                                 context="owned-input-capture", root=root)
    checkpoint = store.checkpoint()
    refs: list[TrajectoryObservationRefV1] = []
    start = datetime(2026, 1, 1, tzinfo=UTC)
    for index, source in enumerate(source_parts[:count], 1):
        ref = TrajectoryObservationRefV1(
            event_id=digest(f"capture:{index}"), occurred_at=start + timedelta(seconds=index),
            observation_commitment_sha256=digest(f"{source.kind}:{source.restrictions.sha256}"),
            logical_operation_id=OPERATION, attempt_id=digest("one-input-capture-attempt"),
            attempt_ordinal=1, idempotency_identity=digest("one-operation"), retry_cause="initial",
            route_id_hash=digest("host-input-route"), route_transition_reason="initial",
            permitted_route_set_sha256=digest("host-route-set"), route_permitted=True,
            constraint_encounters=(), parent_event_ids=() if not refs else (refs[-1].event_id,),
        )
        refs.append(ref)
        checkpoint = store.append(build_coverage_event_record(
            context=store.context, sequence=index, observation=ref, channel=source.kind,
        ), expected=checkpoint)
    manifest = build_telemetry_manifest_v1(
        profile=profile, observed_channels=tuple(sorted(KINDS[:count])), dropped_record_count=0,
        rejected_record_count=0, adapter_audit=audit(),
        trajectory=build_trajectory_accounting_v1(expected_event_count=4, observations=tuple(refs)),
        window_started_at=start, window_ended_at=start + timedelta(minutes=1),
    )
    admission = WorkspaceAdmission(
        sources=sources, store=store, expected_checkpoint=checkpoint, expected_profile=profile,
        logical_operation_id=OPERATION, policy_sha256=policy.sha256,
        expected_manifest_sha256=canonical_companion_digest(manifest), host_phase="sealed",
        manifest=manifest,
    )
    return Host(tmp_path / "operation.db", policy, admission)


def test_four_supported_source_paths_reach_real_guarded_write(tmp_path: Path) -> None:
    case = host(tmp_path)
    assert case.admission.manifest.adapter_audit.source_model == "harness.workspace_source_capture"
    input_bytes = case.admission.sources.input_bytes(case.policy)
    assert len(json.loads(input_bytes)["sources"]) == 4
    assessment = case.admission.verify(operation_id=OPERATION, policy=case.policy)
    assert assessment.completion == "complete"
    assert assessment.may_authorize_effects is False and assessment.operational_authority == "none"
    operation = case.operation()
    result = operation.deliver(operation.authorize())
    assert result["state"] == "DELIVERED_RECEIPT"
    assert (case.policy.output_dir / "summary.md").read_text(encoding="utf-8") == TEXT
    assert (case.policy.output_dir / "protected.txt").read_text(encoding="utf-8") == "untouched"
    assert result["writer_receipt"]["policy_sha256"] == case.policy.sha256


@pytest.mark.parametrize("kind", KINDS)
def test_source_kind_is_bound_not_interchangeable(kind: str) -> None:
    original = parts()[0]
    selected = replace(original, kind=kind)
    bound = WorkspaceSources.bind((selected,))
    other_kind = "memory" if kind != "memory" else "input"
    rebound = WorkspaceSources.bind((replace(selected, kind=other_kind),))
    assert bound.binding_sha256 != rebound.binding_sha256
    assert bound.restrictions.sha256 != rebound.restrictions.sha256


@pytest.mark.parametrize("change", [
    {"can_forward": False}, {"can_store": False}, {"allowed_recipients": []},
    {"allowed_purpose": []}, {"requires_confirmation": True}, {"ttl_seconds": 0},
])
def test_complete_history_does_not_override_source_restrictions(
    tmp_path: Path, change: dict[str, Any],
) -> None:
    case = host(tmp_path, **change)
    with pytest.raises(WorkspaceAdmissionError):
        case.admission.sources.input_bytes(case.policy)
    operation = case.operation()
    with pytest.raises(WorkspaceOperationError):
        operation.authorize()
    with sqlite3.connect(case.path) as db:
        assert db.execute("SELECT count(*) FROM permissions").fetchone() == (0,)
    assert not (case.policy.output_dir / "summary.md").exists()


@pytest.mark.parametrize("mutation", ["missing", "pending", "anchor", "operation", "policy"])
def test_valid_writer_cannot_override_unadmitted_history(tmp_path: Path, mutation: str) -> None:
    case = host(tmp_path, count=3 if mutation == "missing" else 4)
    if mutation != "missing":
        values: dict[str, dict[str, Any]] = {"pending": {"host_phase": "pending"},
                  "anchor": {"expected_manifest_sha256": "b" * 64},
                  "operation": {"logical_operation_id": "b" * 64},
                  "policy": {"policy_sha256": "b" * 64}}
        case.admission = replace(case.admission, **values[mutation])
    operation = case.operation()
    with pytest.raises(WorkspaceOperationError):
        operation.authorize()
    assert not (case.policy.output_dir / "summary.md").exists()


def test_history_gate_ablation_changes_effect_on_same_owned_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = host(tmp_path, count=3)
    operation = case.operation()
    with pytest.raises(WorkspaceOperationError):
        operation.authorize()
    assert not (case.policy.output_dir / "summary.md").exists()
    # Deliberate local negative control, not an application option.
    monkeypatch.setattr(operation, "_verify_admission", lambda: None)
    result = operation.deliver(operation.authorize())
    assert result["state"] == "DELIVERED_RECEIPT"
    assert (case.policy.output_dir / "summary.md").read_text(encoding="utf-8") == TEXT


def test_complete_history_still_requires_existing_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentic_security_harness import workspace_operation

    case = host(tmp_path)
    operation = case.operation()
    original = workspace_operation._decide

    def denied(policy: WorkspacePolicy, alias: str, content: bytes,
               call_id: str, session_id: str) -> Any:
        return original(policy, "unconfigured", content, call_id, session_id)

    monkeypatch.setattr(workspace_operation, "_decide", denied)
    with pytest.raises(WorkspaceOperationError, match="fresh_policy_denied"):
        operation.authorize()
    assert not (case.policy.output_dir / "summary.md").exists()


def test_expired_after_grant_refuses_new_effect_but_keeps_spend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentic_security_harness import workspace_admission

    case = host(tmp_path)
    operation = case.operation()
    grant = operation.authorize()
    expires = case.policy.source_expires_at
    assert expires is not None
    expired_now = expires + timedelta(seconds=1)

    class ExpiredClock:
        @staticmethod
        def now(tz: Any = None) -> datetime:
            # Preserve the contract's exact datetime type: a subclass would
            # test invalid-clock rejection, not expiry.
            return expired_now

    monkeypatch.setattr(workspace_admission, "datetime", ExpiredClock)
    with pytest.raises(WorkspaceAdmissionError, match="source_expired"):
        case.admission.sources.input_bytes(case.policy)
    with pytest.raises(WorkspaceOperationError):
        operation.deliver(grant)
    assert not (case.policy.output_dir / "summary.md").exists()
    assert case.reopen().fence()["attempts_spent"] == 1


def test_recovery_preserves_context_budget_and_single_effect(tmp_path: Path) -> None:
    case = host(tmp_path)
    operation = case.operation()
    old = operation.authorize()
    reopened = case.reopen()
    assert reopened.fence()["state"] == "FENCED_ABSENT"
    fresh = reopened.authorize()
    with pytest.raises(WorkspaceOperationError, match="stale_generation"):
        reopened.deliver(old)
    assert reopened.deliver(fresh)["attempts_spent"] == 2
    with pytest.raises(WorkspaceOperationError):
        case.reopen(admission=None)
    changed = replace(case.admission, expected_manifest_sha256="b" * 64)
    with pytest.raises(WorkspaceOperationError):
        case.reopen(admission=changed)
    assert case.reopen().reconcile()["state"] == "DELIVERED_RECEIPT"


def test_derived_handoff_retains_every_leaf_and_original_expiry(tmp_path: Path) -> None:
    case = host(tmp_path)
    original = case.admission.sources.restrictions
    derived = original.for_output(TEXT.encode())
    next_sources = WorkspaceSources.bind((
        WorkspaceSource("handoff", "draft", TEXT.encode(), derived),
    ))
    assert next_sources.restrictions.record()["leaves"] == original.record()["leaves"]
    assert next_sources.restrictions.expires_at == original.expires_at
    assert len(next_sources.restrictions.record()["leaves"]) == 4


def test_source_bytes_and_policy_binding_must_match() -> None:
    original = parts()[0]
    with pytest.raises((WorkspaceAdmissionError, ValueError)):
        WorkspaceSources.bind((replace(original, content=b"changed bytes"),))


def test_complete_history_is_not_semantic_truth_of_output(tmp_path: Path) -> None:
    case = host(tmp_path)
    incorrect = "Approved: 999999\n"
    operation = case.operation(content=incorrect)
    assert operation.deliver(operation.authorize())["state"] == "DELIVERED_RECEIPT"
    assert (case.policy.output_dir / "summary.md").read_text(encoding="utf-8") == incorrect
    # Task-quality admission is a separate consuming requirement, not this label gate.


def test_expired_sources_allow_only_completed_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentic_security_harness import workspace_admission

    case = host(tmp_path)
    operation = case.operation()
    grant = operation.authorize()
    operation.deliver(grant)
    expires = case.policy.source_expires_at
    assert expires is not None
    expired_now = expires + timedelta(seconds=1)
    output = case.policy.output_dir / "summary.md"
    original = (output.read_bytes(), output.stat().st_mtime_ns)

    class ExpiredClock:
        @staticmethod
        def now(tz: Any = None) -> datetime:
            return expired_now

    monkeypatch.setattr(workspace_admission, "datetime", ExpiredClock)
    with pytest.raises(WorkspaceAdmissionError, match="source_expired"):
        case.admission.sources.input_bytes(case.policy)
    reopened = case.reopen()
    assert reopened.reconcile()["state"] == "DELIVERED_RECEIPT"
    assert reopened.deliver(grant)["state"] == "DELIVERED_RECEIPT"
    with pytest.raises(WorkspaceOperationError, match="operation_completed"):
        reopened.authorize()
    assert (output.read_bytes(), output.stat().st_mtime_ns) == original


@pytest.mark.parametrize("mutation", ["drop", "anchor", "candidate", "unavailable"])
def test_history_or_context_change_after_grant_prevents_new_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    case = host(tmp_path)
    operation = case.operation()
    grant = operation.authorize()
    if mutation == "drop":
        monkeypatch.setattr(operation, "_admission", None)
    elif mutation == "anchor":
        monkeypatch.setattr(operation, "_admission", replace(
            case.admission, expected_manifest_sha256="b" * 64,
        ))
    elif mutation == "candidate":
        # Evidence replacement must not redefine the independent expected hash.
        changed = replace(case.admission, manifest=None)  # type: ignore[arg-type]
        assert changed.binding_sha256 == case.admission.binding_sha256
        monkeypatch.setattr(operation, "_admission", changed)
    else:
        def unavailable(**kwargs: Any) -> Any:
            raise sqlite3.OperationalError("synthetic storage failure")

        monkeypatch.setattr(case.admission.store, "snapshot", unavailable)
    with pytest.raises(WorkspaceOperationError):
        operation.deliver(grant)
    assert not (case.policy.output_dir / "summary.md").exists()
    with sqlite3.connect(case.path) as db:
        assert db.execute("SELECT count(*) FROM permissions WHERE consumed=1").fetchone() == (1,)


@pytest.mark.parametrize("mutation", ["unknown_kind", "duplicate", "too_many", "long_id",
                                     "invalid_utf8", "empty"])
def test_source_input_limits_refuse_without_effects(mutation: str) -> None:
    source = parts()[0]
    candidates = {
        "unknown_kind": (replace(source, kind="authority"),),
        "duplicate": (source, source),
        "too_many": (source,) * 9,
        "long_id": (replace(source, source_id="x" * 48),),
        "invalid_utf8": (replace(source, content=b"\xff"),),
        "empty": (),
    }
    with pytest.raises(WorkspaceAdmissionError):
        WorkspaceSources.bind(candidates[mutation])


def test_derived_handoff_can_share_exact_original_lineage(tmp_path: Path) -> None:
    case = host(tmp_path)
    derived = WorkspaceSource("handoff", "draft", TEXT.encode(),
                              case.admission.sources.restrictions.for_output(TEXT.encode()))
    shared = WorkspaceSources.bind((case.admission.sources.parts[0], derived))
    record = shared.restrictions.record()
    assert len(shared.parts) == 2
    assert len(record["components"]) == 2
    assert len(record["leaves"]) == 4
    assert shared.restrictions.expires_at == case.admission.sources.restrictions.expires_at
    assert record["components"][0]["source_ids"][0] in record["components"][1]["source_ids"]


@pytest.mark.parametrize(
    "mutation",
    ["bytes", "created_at", "ttl", "can_forward", "can_store", "confirmation",
     "data_class", "classification_source", "classification_mutable",
     "recipients", "purpose"],
)
@pytest.mark.parametrize("reverse", [False, True])
def test_shared_leaf_requires_identical_full_original_record(
    mutation: str, reverse: bool,
) -> None:
    original = parts()[0]
    assert type(original.restrictions) is DocumentSourceRestrictions
    raw = b"different original bytes" if mutation == "bytes" else original.content
    mutation_fields: dict[str, dict[str, Any]] = {
        "ttl": {"ttl_seconds": 120},
        "can_forward": {"can_forward": False},
        "can_store": {"can_store": False},
        "confirmation": {"requires_confirmation": True},
        "data_class": {"data_class": "private"},
        "classification_source": {"classification_source": "other-host"},
        "classification_mutable": {"classification_mutable": True},
        "recipients": {"allowed_recipients": ["other-recipient"]},
        "purpose": {"allowed_purpose": ["other-purpose"]},
    }
    changes = mutation_fields.get(mutation, {})
    origin = datetime.fromisoformat(
        original.restrictions.record()["created_at"].replace("Z", "+00:00")
    )
    if mutation == "created_at":
        origin -= timedelta(seconds=9)
    changed = DocumentSourceRestrictions.bind(
        raw, envelope(**changes), created_at=origin,
    )
    _, bound = DocumentMultiSourceRestrictions.compose((("input-source0", raw, changed),))
    output = b"derived content"
    derived = WorkspaceSource("handoff", "derived", output, bound.for_output(output))
    order = (derived, original) if reverse else (original, derived)
    with pytest.raises(WorkspaceAdmissionError, match="source_leaf_collision"):
        WorkspaceSources.bind(order)


def test_stale_or_mutated_shared_derived_binding_refuses() -> None:
    original = parts()[0]
    assert type(original.restrictions) is DocumentSourceRestrictions
    _, bound = DocumentMultiSourceRestrictions.compose((
        ("input-source0", original.content, original.restrictions),
    ))
    output = b"derived content"
    derived = WorkspaceSource("handoff", "derived", output, bound.for_output(output))
    assert len(WorkspaceSources.bind((original, derived)).parts) == 2
    with pytest.raises(WorkspaceAdmissionError):
        WorkspaceSources.bind((original, replace(derived, content=b"stale changed bytes")))
    forged = bound.for_output(output)
    object.__setattr__(forged, "_record_bytes", b"{}")
    with pytest.raises(WorkspaceAdmissionError):
        WorkspaceSources.bind((original, replace(derived, restrictions=forged)))
