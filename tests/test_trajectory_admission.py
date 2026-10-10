"""Offline tests for the observational, non-authorizing telemetry bridge."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta, timezone

import pytest

from agentic_security_harness.ancestry_store import (
    AncestryRecord,
    AncestryStore,
    CheckpointConflict,
)
from agentic_security_harness.companion_contracts import (
    TelemetryManifestV1,
    TrajectoryObservationRefV1,
    build_coverage_expectation_profile_v1,
    build_telemetry_manifest_v1,
    build_trajectory_accounting_v1,
    canonical_companion_digest,
)
from agentic_security_harness.portfolio_contract import (
    AdapterAuditV1,
    AdapterFieldMappingV1,
    CanonicalObservationEventV1,
)
from agentic_security_harness.trajectory_admission import (
    assess_retained_telemetry,
    build_coverage_event_record,
    build_coverage_root_record,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _audit() -> AdapterAuditV1:
    return AdapterAuditV1(
        schema_version="portfolio-adapter-audit-v1.0",
        source_model="runtime_guard.observation_event",
        target_model="portfolio-observation-v1.0",
        completeness="partial",
        source_fields=("event_id", "effect", "authority_level"),
        target_fields=tuple(CanonicalObservationEventV1.model_fields),
        mappings=(
            AdapterFieldMappingV1(
                source_fields=("event_id",),
                target_fields=("event_id",),
                transformation="identity",
                authority_effect="none",
            ),
            AdapterFieldMappingV1(
                source_fields=("effect",),
                target_fields=("activity",),
                transformation="derived",
                authority_effect="downgrade",
            ),
        ),
        dropped_source_fields=("authority_level",),
        context_target_fields=(
            "project_id", "repository_id", "repository_sha", "occurred_at",
            "producer_id_hash", "source_surface", "entity_refs", "parent_event_ids",
            "data_envelope_ref", "telemetry_state",
        ),
        constant_target_fields=(
            "schema_version", "producer_attestation", "authority_envelope_ref",
            "operational_authority",
        ),
        authority_downgrade=True,
        reason_codes=("adapter.authority_dropped",),
        operational_authority="none",
    )


def _fixture(tmp_path, *, count: int = 3, channels: tuple[str, ...] = ("mcp", "runtime", "mcp")):
    operation = _sha("operation")
    policy = _sha("policy")
    profile = build_coverage_expectation_profile_v1(
        project_id="agentic-security-harness",
        repository_id="krivonosoff161/agentic-security-harness",
        repository_sha="a" * 40,
        expected_channels=("mcp", "runtime"),
        expected_event_count=3,
        expectation_source_sha256=_sha("expectation"),
    )
    context = "telemetry-test"
    root = build_coverage_root_record(
        context=context, expected_profile=profile,
        logical_operation_id=operation, policy_sha256=policy,
    )
    store = AncestryStore.create(
        tmp_path / "store.db", tmp_path / "store.witness", context=context, root=root
    )
    checkpoint = store.checkpoint()
    refs = []
    for index in range(1, count + 1):
        ref = TrajectoryObservationRefV1(
            event_id=_sha(f"event:{index}"),
            occurred_at=datetime(2026, 8, 2, tzinfo=UTC) + timedelta(seconds=index),
            observation_commitment_sha256=_sha(f"commit:{index}"),
            logical_operation_id=operation,
            attempt_id=_sha(f"attempt:{index}"),
            attempt_ordinal=index,
            idempotency_identity=_sha("idempotency"),
            retry_cause="initial" if index == 1 else "bounded_retry",
            route_id_hash=_sha(f"route:{index}"),
            route_transition_reason="initial" if index == 1 else "declared_failover",
            permitted_route_set_sha256=_sha("permitted"),
            route_permitted=True,
            constraint_encounters=(),
            parent_event_ids=() if index == 1 else (refs[-1].event_id,),
        )
        refs.append(ref)
        checkpoint = store.append(
            build_coverage_event_record(
                context=context, sequence=index, observation=ref, channel=channels[index - 1]
            ),
            expected=checkpoint,
        )
    trajectory = build_trajectory_accounting_v1(
        expected_event_count=3, observations=tuple(refs)
    )
    manifest = build_telemetry_manifest_v1(
        profile=profile,
        observed_channels=tuple(sorted(set(channels[:count]))),
        dropped_record_count=0,
        rejected_record_count=0,
        adapter_audit=_audit(),
        trajectory=trajectory,
        window_started_at=datetime(2026, 8, 2, tzinfo=UTC),
        window_ended_at=datetime(2026, 8, 2, 0, 1, tzinfo=UTC),
    )
    kwargs = dict(
        expected_checkpoint=checkpoint, expected_profile=profile,
        logical_operation_id=operation, policy_sha256=policy,
        expected_manifest_sha256=canonical_companion_digest(manifest), manifest=manifest,
    )
    return store, kwargs, tuple(refs)


def test_full_sealed_and_pending_are_distinct(tmp_path) -> None:
    store, kwargs, _ = _fixture(tmp_path)
    before = store.snapshot(expected=kwargs["expected_checkpoint"])
    sealed = assess_retained_telemetry(store, host_phase="sealed", **kwargs)
    pending = assess_retained_telemetry(store, host_phase="pending", **kwargs)
    assert store.snapshot(expected=kwargs["expected_checkpoint"]) == before
    assert (sealed.retained_binding, sealed.coverage_state, sealed.completion) == (
        "matched", "complete", "complete"
    )
    assert pending.completion == "pending"
    assert pending.coverage_state == "complete"
    assert sealed.operational_authority == pending.operational_authority == "none"
    assert sealed.may_authorize_effects is pending.may_authorize_effects is False


def test_authentic_prefix_is_incomplete(tmp_path) -> None:
    store, kwargs, _ = _fixture(tmp_path, count=2)
    result = assess_retained_telemetry(store, host_phase="sealed", **kwargs)
    assert (result.retained_binding, result.coverage_state, result.completion) == (
        "matched", "incomplete", "incomplete"
    )


@pytest.mark.parametrize("mutation", ["profile", "manifest", "channels", "operation", "policy"])
def test_host_and_manifest_mismatch_rejected(tmp_path, mutation: str) -> None:
    store, kwargs, _ = _fixture(tmp_path)
    if mutation == "profile":
        kwargs["expected_profile"] = kwargs["expected_profile"].model_copy(
            update={"expected_channels": ("other",)}
        )
    elif mutation == "manifest":
        kwargs["manifest"] = kwargs["manifest"].model_copy(
            update={"telemetry_state": "incomplete"}
        )
    elif mutation == "channels":
        kwargs["manifest"] = kwargs["manifest"].model_copy(
            update={"observed_channels": ("mcp",)}
        )
    elif mutation == "operation":
        kwargs["logical_operation_id"] = _sha("other-operation")
    else:
        kwargs["policy_sha256"] = _sha("other-policy")
    result = assess_retained_telemetry(store, host_phase="sealed", **kwargs)
    assert result.completion == "rejected"
    assert result.may_authorize_effects is False
    if mutation == "profile":
        assert result.reason == "invalid_host_input"
    if mutation in ("manifest", "channels"):
        assert result.reason == "invalid_manifest"


def test_invalid_inputs_are_rejected_before_store_snapshot(tmp_path, monkeypatch) -> None:
    store, kwargs, _ = _fixture(tmp_path)

    def unexpected_snapshot(*, expected):
        raise AssertionError("snapshot should not run for invalid inputs")

    monkeypatch.setattr(store, "snapshot", unexpected_snapshot)
    bad_profile = kwargs["expected_profile"].model_copy(
        update={"expected_channels": ("other",)}
    )
    assert assess_retained_telemetry(
        store, host_phase="sealed", **{**kwargs, "expected_profile": bad_profile}
    ).reason == "invalid_host_input"
    bad_nested = kwargs["manifest"].coverage_expectation_profile.model_copy(
        update={"expected_channels": ("other",)}
    )
    bad_manifest = kwargs["manifest"].model_copy(
        update={"coverage_expectation_profile": bad_nested}
    )
    assert assess_retained_telemetry(
        store, host_phase="sealed", **{**kwargs, "manifest": bad_manifest}
    ).reason == "invalid_manifest"
    assert assess_retained_telemetry(
        store, host_phase="sealed", **{**kwargs, "expected_manifest_sha256": "not-a-digest"}
    ).reason == "invalid_host_input"
    assert assess_retained_telemetry(
        store, host_phase="sealed", **{**kwargs, "expected_manifest_sha256": _sha("other")}
    ).reason == "manifest_anchor_mismatch"


def test_rejected_window_is_not_masked_by_pending_phase(tmp_path) -> None:
    store, kwargs, _ = _fixture(tmp_path)
    east_one = timezone(timedelta(hours=1))
    kwargs["manifest"] = TelemetryManifestV1.model_validate(
        {
            **kwargs["manifest"].model_dump(mode="python"),
            "window_started_at": datetime(2026, 8, 2, 1, tzinfo=east_one),
            "window_ended_at": datetime(2026, 8, 2, 1, 1, tzinfo=east_one),
            "telemetry_state": "rejected",
            "incomplete_reason": "invalid_window",
        }
    )
    kwargs["expected_manifest_sha256"] = canonical_companion_digest(kwargs["manifest"])
    assert kwargs["manifest"].telemetry_state == "rejected"
    result = assess_retained_telemetry(store, host_phase="pending", **kwargs)
    assert (result.retained_binding, result.coverage_state, result.completion) == (
        "matched", "rejected", "rejected"
    )


def test_manifest_encoding_failure_is_rejected_before_snapshot(tmp_path, monkeypatch) -> None:
    from agentic_security_harness import trajectory_admission

    store, kwargs, _ = _fixture(tmp_path)

    def unavailable_encoding(_manifest):
        raise ValueError("companion record exceeds the wire byte bound")

    def unexpected_snapshot(*, expected):
        raise AssertionError("snapshot should not run for an unencodable manifest")

    monkeypatch.setattr(trajectory_admission, "canonical_companion_digest", unavailable_encoding)
    monkeypatch.setattr(store, "snapshot", unexpected_snapshot)
    assert assess_retained_telemetry(store, **kwargs).reason == "invalid_manifest"


def test_rewritten_retained_observation_and_channel_cannot_match(tmp_path) -> None:
    store, kwargs, refs = _fixture(tmp_path)
    # The stored graph is immutable here; a copied manifest claiming different
    # event bytes or channel coverage cannot bind to its snapshot.
    replaced = refs[1].model_copy(update={"observation_commitment_sha256": _sha("rewritten")})
    trajectory = build_trajectory_accounting_v1(
        expected_event_count=3, observations=(refs[0], replaced, refs[2])
    )
    kwargs["manifest"] = build_telemetry_manifest_v1(
        profile=kwargs["expected_profile"],
        observed_channels=("mcp", "runtime"),
        dropped_record_count=0,
        rejected_record_count=0,
        adapter_audit=_audit(),
        trajectory=trajectory,
        window_started_at=datetime(2026, 8, 2, tzinfo=UTC),
        window_ended_at=datetime(2026, 8, 2, 0, 1, tzinfo=UTC),
    )
    kwargs["expected_manifest_sha256"] = canonical_companion_digest(kwargs["manifest"])
    result = assess_retained_telemetry(store, host_phase="sealed", **kwargs)
    assert result.reason == "manifest_retained_mismatch"


def test_manifest_anchor_blocks_verdict_field_rewrites(tmp_path) -> None:
    store, kwargs, refs = _fixture(tmp_path)
    complete = kwargs["manifest"]
    trajectory = build_trajectory_accounting_v1(expected_event_count=3, observations=refs)
    dropped = build_telemetry_manifest_v1(
        profile=kwargs["expected_profile"], observed_channels=("mcp", "runtime"),
        dropped_record_count=1, rejected_record_count=0, adapter_audit=_audit(),
        trajectory=trajectory,
        window_started_at=datetime(2026, 8, 2, tzinfo=UTC),
        window_ended_at=datetime(2026, 8, 2, 0, 1, tzinfo=UTC),
    )
    censored = build_telemetry_manifest_v1(
        profile=kwargs["expected_profile"], observed_channels=("mcp", "runtime"),
        dropped_record_count=0, rejected_record_count=0, adapter_audit=_audit(),
        trajectory=build_trajectory_accounting_v1(
            expected_event_count=3, observations=refs, censoring_state="left_censored"
        ),
        window_started_at=datetime(2026, 8, 2, tzinfo=UTC),
        window_ended_at=datetime(2026, 8, 2, 0, 1, tzinfo=UTC),
    )
    east_one = timezone(timedelta(hours=1))
    rejected_window = TelemetryManifestV1.model_validate(
        {
            **complete.model_dump(mode="python"),
            "window_started_at": datetime(2026, 8, 2, 1, tzinfo=east_one),
            "window_ended_at": datetime(2026, 8, 2, 1, 1, tzinfo=east_one),
            "telemetry_state": "rejected", "incomplete_reason": "invalid_window",
        }
    )
    for host_admitted in (dropped, censored, rejected_window):
        anchored = {
            **kwargs,
            "manifest": host_admitted,
            "expected_manifest_sha256": canonical_companion_digest(host_admitted),
        }
        admitted = assess_retained_telemetry(store, host_phase="sealed", **anchored)
        assert admitted.completion == host_admitted.telemetry_state
        rewritten = {**anchored, "manifest": complete}
        refused = assess_retained_telemetry(store, host_phase="sealed", **rewritten)
        assert refused.reason == "manifest_anchor_mismatch"
        assert refused.completion == "rejected"


def test_rebound_channel_manifest_is_rejected_even_when_self_consistent(tmp_path) -> None:
    store, kwargs, refs = _fixture(tmp_path)
    kwargs["manifest"] = build_telemetry_manifest_v1(
        profile=kwargs["expected_profile"],
        observed_channels=("mcp",),
        dropped_record_count=0,
        rejected_record_count=0,
        adapter_audit=_audit(),
        trajectory=build_trajectory_accounting_v1(expected_event_count=3, observations=refs),
        window_started_at=datetime(2026, 8, 2, tzinfo=UTC),
        window_ended_at=datetime(2026, 8, 2, 0, 1, tzinfo=UTC),
    )
    kwargs["expected_manifest_sha256"] = canonical_companion_digest(kwargs["manifest"])
    result = assess_retained_telemetry(store, host_phase="sealed", **kwargs)
    assert result.reason == "manifest_retained_mismatch"
    assert result.completion == "rejected"


def test_noncanonical_retained_event_layout_rejected(tmp_path) -> None:
    store, kwargs, _ = _fixture(tmp_path, count=2)
    next_checkpoint = store.append(
        AncestryRecord(
            record_id="event-0003", context="telemetry-test",
            payload=b'{"schema_version":"ash-retained-telemetry-event-v1","extra":true}',
            parents=("event-0002",), scope=("retained-telemetry",),
        ),
        expected=kwargs["expected_checkpoint"],
    )
    kwargs["expected_checkpoint"] = next_checkpoint
    result = assess_retained_telemetry(store, host_phase="sealed", **kwargs)
    assert result.reason == "event_binding_mismatch"
    assert result.completion == "rejected"


@pytest.mark.parametrize("kind", ["deep_json", "wrong_sequence", "whitespace"])
def test_hostile_or_noncanonical_payload_rejected(tmp_path, kind: str) -> None:
    store, kwargs, refs = _fixture(tmp_path, count=2)
    next_ref = TrajectoryObservationRefV1(
        **{
            **refs[-1].model_dump(mode="python"),
            "event_id": _sha("third"),
            "observation_commitment_sha256": _sha("third-commit"),
            "attempt_id": _sha("third-attempt"),
            "attempt_ordinal": 3,
            "occurred_at": datetime(2026, 8, 2, 0, 0, 3, tzinfo=UTC),
            "parent_event_ids": (refs[-1].event_id,),
        }
    )
    valid = build_coverage_event_record(
        context="telemetry-test", sequence=3, observation=next_ref, channel="mcp"
    )
    if kind == "deep_json":
        payload = b"[" * 2000 + b"0" + b"]" * 2000
    elif kind == "wrong_sequence":
        payload = valid.payload.replace(b'"sequence":3', b'"sequence":2')
    else:
        payload = b" " + valid.payload
    checkpoint = store.append(
        AncestryRecord(
            record_id=valid.record_id, context=valid.context, payload=payload,
            parents=valid.parents, scope=valid.scope,
        ),
        expected=kwargs["expected_checkpoint"],
    )
    kwargs["expected_checkpoint"] = checkpoint
    result = assess_retained_telemetry(store, host_phase="sealed", **kwargs)
    assert result.reason == "event_binding_mismatch"


def test_builder_capacity_and_invalid_inputs(tmp_path) -> None:
    store, kwargs, refs = _fixture(tmp_path, count=2)
    assert store.snapshot(expected=kwargs["expected_checkpoint"]).records
    for sequence in (0, 4096, True):
        with pytest.raises(ValueError):
            build_coverage_event_record(
                context="telemetry-test", sequence=sequence,
                observation=refs[0], channel="mcp",
            )
    with pytest.raises(ValueError):
        build_coverage_event_record(
            context="telemetry-test", sequence=3, observation=refs[0], channel="Bad"
        )
    oversized_profile = build_coverage_expectation_profile_v1(
        project_id="agentic-security-harness",
        repository_id="krivonosoff161/agentic-security-harness",
        repository_sha="a" * 40,
        expected_channels=("mcp", "runtime"),
        expected_event_count=4096,
        expectation_source_sha256=_sha("expectation"),
    )
    with pytest.raises(ValueError):
        build_coverage_root_record(
            context="telemetry-test", expected_profile=oversized_profile,
            logical_operation_id=kwargs["logical_operation_id"],
            policy_sha256=kwargs["policy_sha256"],
        )


def test_wrong_root_and_stale_checkpoint(tmp_path) -> None:
    store, kwargs, _ = _fixture(tmp_path)
    kwargs["expected_profile"] = build_coverage_expectation_profile_v1(
        project_id="agentic-security-harness",
        repository_id="krivonosoff161/agentic-security-harness",
        repository_sha="a" * 40,
        expected_channels=("mcp", "runtime"),
        expected_event_count=3,
        expectation_source_sha256=_sha("other"),
    )
    result = assess_retained_telemetry(store, host_phase="sealed", **kwargs)
    assert (result.retained_binding, result.completion) == ("rejected", "rejected")


def test_old_anchor_same_bytes_limitation_and_stale_after_extension(tmp_path) -> None:
    store, kwargs, refs = _fixture(tmp_path, count=2)
    old_checkpoint = kwargs["expected_checkpoint"]
    assert (
        assess_retained_telemetry(store, host_phase="sealed", **kwargs).completion
        == "incomplete"
    )
    # Supplying the same old checkpoint before any extension is still accepted:
    # this API has no independent latest-checkpoint oracle.
    assert (
        assess_retained_telemetry(store, host_phase="sealed", **kwargs).completion
        == "incomplete"
    )
    next_ref = TrajectoryObservationRefV1(
        **{
            **refs[-1].model_dump(mode="python"),
            "event_id": _sha("extension"),
            "observation_commitment_sha256": _sha("extension-commit"),
            "attempt_id": _sha("extension-attempt"),
            "attempt_ordinal": 3,
            "occurred_at": datetime(2026, 8, 2, 0, 0, 3, tzinfo=UTC),
            "parent_event_ids": (refs[-1].event_id,),
        }
    )
    store.append(
        build_coverage_event_record(
            context="telemetry-test", sequence=3, observation=next_ref, channel="runtime"
        ),
        expected=old_checkpoint,
    )
    with pytest.raises(CheckpointConflict):
        assess_retained_telemetry(store, host_phase="sealed", **kwargs)
