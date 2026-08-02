from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError
from tools.r4_companion_schemas import (
    FIXTURE_PATH,
    FIXTURE_RUNNER_PATH,
    MANIFEST_PATH,
    SCHEMA_PATHS,
    VALIDATOR_PATH,
)

from agentic_security_harness.companion_contracts import (
    CompanionContractError,
    MCPRedactionReceiptV1,
    TrajectoryObservationRefV1,
    build_coverage_expectation_profile_v1,
    build_portfolio_outcome_v1,
    build_telemetry_manifest_v1,
    build_trajectory_accounting_v1,
    canonical_companion_digest,
    decode_companion_record_v1,
    encode_companion_record_v1,
    portfolio_outcome_v1_json_schema,
    project_companion_for_candidate_v1,
    project_outcome_for_candidate_v1,
    r4_companion_json_schemas,
    summarize_mcp_payload_v1,
    validate_portfolio_outcome_v1,
)
from agentic_security_harness.portfolio_contract import (
    AdapterAuditV1,
    AdapterFieldMappingV1,
    CanonicalObservationEventV1,
)

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 8, 2, tzinfo=UTC)
END = datetime(2026, 8, 2, 0, 1, tzinfo=UTC)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def outcome(layer: str, reported_value: str) -> dict[str, object]:
    return build_portfolio_outcome_v1(
        layer=layer,
        reported_value=reported_value,
        observation_commitment_sha256=sha("observation"),
    ).model_dump(mode="json")


@pytest.mark.parametrize(
    ("layer", "reported_value"),
    [
        ("advisory", "abstain"),
        ("policy_decision", "sandbox_only"),
        ("verification", "warn"),
        ("execution", "failed"),
        ("shadow_sink", "accepted_no_effect"),
    ],
)
def test_outcome_layers_accept_only_their_closed_values(layer: str, reported_value: str) -> None:
    record = validate_portfolio_outcome_v1(outcome(layer, reported_value))
    assert record.layer == layer
    assert record.reported_value == reported_value
    assert record.evidence_only is True
    assert record.executable is False
    assert record.operational_authority == "none"


def test_outcome_layer_confusion_identity_and_authority_fail_closed() -> None:
    with pytest.raises(ValidationError):
        build_portfolio_outcome_v1(
            layer="advisory",
            reported_value="allow",
            observation_commitment_sha256=sha("observation"),
        )
    promoted = outcome("policy_decision", "allow")
    promoted["operational_authority"] = "execute"
    with pytest.raises(ValidationError):
        validate_portfolio_outcome_v1(promoted)
    tampered = outcome("advisory", "observe")
    tampered["reported_value"] = "challenge"
    with pytest.raises(ValidationError):
        validate_portfolio_outcome_v1(tampered)
    leaked = outcome("advisory", "observe")
    leaked["attack_label"] = "harmful"
    with pytest.raises(ValidationError):
        validate_portfolio_outcome_v1(leaked)


def test_candidate_projection_physically_excludes_effect_and_sink_outcomes() -> None:
    visible = build_portfolio_outcome_v1(
        layer="advisory",
        reported_value="observe",
        observation_commitment_sha256=sha("observation"),
    )
    execution = build_portfolio_outcome_v1(
        layer="execution",
        reported_value="succeeded",
        observation_commitment_sha256=sha("observation"),
    )
    sink = build_portfolio_outcome_v1(
        layer="shadow_sink",
        reported_value="accepted_no_effect",
        observation_commitment_sha256=sha("observation"),
    )
    assert project_outcome_for_candidate_v1(visible) == visible
    assert (
        project_outcome_for_candidate_v1(
            build_portfolio_outcome_v1(
                layer="policy_decision",
                reported_value="allow",
                observation_commitment_sha256=sha("observation"),
            )
        )
        is None
    )
    assert (
        project_outcome_for_candidate_v1(
            build_portfolio_outcome_v1(
                layer="verification",
                reported_value="fail",
                observation_commitment_sha256=sha("observation"),
            )
        )
        is None
    )
    assert project_outcome_for_candidate_v1(execution) is None
    assert project_outcome_for_candidate_v1(sink) is None
    assert project_companion_for_candidate_v1(execution) is None
    poisoned = visible.model_copy(update={"reported_value": "harmful"})
    with pytest.raises(ValidationError):
        project_outcome_for_candidate_v1(poisoned)
    with pytest.raises(ValidationError):
        encode_companion_record_v1(visible.model_copy(update={"operational_authority": "execute"}))


def test_outcome_schema_is_discriminated_and_contains_no_scientific_label() -> None:
    schema = portfolio_outcome_v1_json_schema()
    assert schema["discriminator"]["propertyName"] == "layer"
    text = json.dumps(schema, sort_keys=True)
    assert "attack_label" not in text
    assert "holdout" not in text


def mcp_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def test_mcp_receipt_drops_secret_shaped_and_raw_values_without_reproducing_them() -> None:
    secret = "synthetic-sensitive-value-not-persisted"
    raw_error = "synthetic private error text"
    payload = mcp_bytes(
        {
            "type": "tool_result",
            "arguments": {"api_key": secret, "target_url": "https://user:pass@example.test"},
            "content": [{"type": "text", "text": secret}],
            "error": raw_error,
        }
    )
    receipt = summarize_mcp_payload_v1(payload)
    encoded = receipt.model_dump_json()
    assert receipt.telemetry_state == "complete"
    assert receipt.operational_authority == "none"
    assert {
        "credential",
        "locator",
        "raw_argument",
        "raw_error",
        "raw_output",
        "raw_scalar",
    } <= set(receipt.dropped_field_classes)
    assert secret not in encoded
    assert raw_error not in encoded
    assert "example.test" not in encoded


def test_mcp_unknown_content_truncation_and_scalar_fail_closed() -> None:
    receipt = summarize_mcp_payload_v1(mcp_bytes({"type": "unrecognized_block"}))
    assert receipt.telemetry_state == "incomplete"
    assert receipt.unknown_content_type_count == 1
    truncated = summarize_mcp_payload_v1(mcp_bytes({"items": list(range(10))}), max_nodes=2)
    assert truncated.telemetry_state == "incomplete"
    assert truncated.truncated_count > 0
    scalar = summarize_mcp_payload_v1(mcp_bytes("secret scalar"))
    assert scalar.telemetry_state == "rejected"
    assert "raw_scalar" in scalar.dropped_field_classes


def test_mcp_impossible_counts_and_noncanonical_json_are_rejected() -> None:
    valid = summarize_mcp_payload_v1(mcp_bytes({"type": "tool_result", "content": []}))
    impossible = {
        **valid.model_dump(),
        "visited_node_count": 0,
        "object_count": 100,
        "content_block_count": 100,
    }
    with pytest.raises(ValidationError):
        MCPRedactionReceiptV1.model_validate(impossible)
    missing_loss = valid.model_dump(mode="python")
    missing_loss["dropped_field_classes"] = tuple(
        value for value in valid.dropped_field_classes if value != "raw_scalar"
    )
    with pytest.raises(ValidationError):
        MCPRedactionReceiptV1.model_validate(missing_loss)
    with pytest.raises(CompanionContractError):
        summarize_mcp_payload_v1(b'{"type":"text","type":"image"}')
    with pytest.raises(CompanionContractError):
        summarize_mcp_payload_v1(b'{"value":NaN}')


def test_mcp_bounded_walk_does_not_enqueue_unbounded_fanout() -> None:
    receipt = summarize_mcp_payload_v1(mcp_bytes(list(range(1000))), max_nodes=2)
    assert receipt.visited_node_count == 2
    assert 0 < receipt.truncated_count <= 4096
    assert receipt.telemetry_state == "incomplete"


@pytest.mark.parametrize(
    "payload",
    [
        {"resource": "synthetic"},
        {"embedded_data": "synthetic"},
        {"type": "tool_result", "resource": "synthetic"},
    ],
)
def test_mcp_resource_shaped_keys_are_accounted_without_crashing(payload: object) -> None:
    receipt = summarize_mcp_payload_v1(mcp_bytes(payload))
    assert "embedded_resource" in receipt.dropped_field_classes
    assert receipt.operational_authority == "none"


def ref(
    name: str,
    *,
    parent_event_ids: tuple[str, ...],
    attempt_ordinal: int,
    route_permitted: bool = True,
    commitment_name: str | None = None,
) -> TrajectoryObservationRefV1:
    return TrajectoryObservationRefV1(
        event_id=sha(name),
        occurred_at=START + timedelta(seconds=attempt_ordinal),
        observation_commitment_sha256=sha(commitment_name or f"commitment:{name}"),
        logical_operation_id=sha("logical-operation"),
        attempt_id=sha(f"attempt:{attempt_ordinal}"),
        attempt_ordinal=attempt_ordinal,
        idempotency_identity=sha("idempotency:operation"),
        retry_cause="initial" if attempt_ordinal == 1 else "bounded_retry",
        route_id_hash=sha(f"route:{attempt_ordinal}"),
        route_transition_reason="initial" if attempt_ordinal == 1 else "declared_failover",
        permitted_route_set_sha256=sha("permitted-routes"),
        route_permitted=route_permitted,
        constraint_encounters=() if route_permitted else ("route_not_permitted",),
        parent_event_ids=parent_event_ids,
    )


def refs() -> tuple[TrajectoryObservationRefV1, ...]:
    first = ref("first", parent_event_ids=(), attempt_ordinal=1)
    second = ref("second", parent_event_ids=(first.event_id,), attempt_ordinal=2)
    third = ref("third", parent_event_ids=(second.event_id,), attempt_ordinal=3)
    return first, second, third


def accounting(
    observations: tuple[TrajectoryObservationRefV1, ...],
    *,
    expected_event_count: int | None = None,
):
    return build_trajectory_accounting_v1(
        expected_event_count=expected_event_count or len(observations),
        observations=observations,
    )


def test_trajectory_accounting_binds_complete_dag_retry_and_route_state() -> None:
    value = accounting(refs())
    assert value.completeness == "complete"
    assert value.cycle_verdict == "acyclic"
    assert value.logical_operation_id == sha("logical-operation")
    assert value.root_event_ids == (sha("first"),)
    assert value.leaf_event_ids == (sha("third"),)
    assert len(value.event_commitments) == 3
    assert len(value.edges) == 2
    assert len(value.attempt_ids) == 3
    assert value.route_violation_event_ids == ()
    assert value.candidate_visibility == "evaluator_only"
    assert project_companion_for_candidate_v1(value) is None
    assert value.operational_authority == "none"


def test_different_lineages_produce_different_models_and_digests() -> None:
    first = ref("first", parent_event_ids=(), attempt_ordinal=1)
    second = ref("second", parent_event_ids=(first.event_id,), attempt_ordinal=2)
    third = ref("third", parent_event_ids=(second.event_id,), attempt_ordinal=3)
    fourth = ref("fourth", parent_event_ids=(third.event_id,), attempt_ordinal=4)
    graph_one = accounting((first, second, third, fourth))

    third_alt = third.model_copy(update={"parent_event_ids": (first.event_id,)})
    second_alt = second
    fourth_alt = fourth.model_copy(update={"parent_event_ids": (second.event_id, third.event_id)})
    graph_two = accounting((first, second_alt, third_alt, fourth_alt))
    assert graph_one != graph_two
    assert canonical_companion_digest(graph_one) != canonical_companion_digest(graph_two)


def test_retry_and_route_bindings_are_per_event_and_digest_distinct() -> None:
    first, second, third = refs()
    baseline = accounting((first, second, third))
    changed_second = second.model_copy(
        update={
            "retry_cause": "policy_retry",
            "route_id_hash": sha("other-route"),
            "route_transition_reason": "policy_transition",
            "permitted_route_set_sha256": sha("other-permitted-set"),
            "constraint_encounters": ("budget_boundary",),
        }
    )
    changed = accounting((first, changed_second, third))
    assert baseline != changed
    assert baseline.trajectory_id != changed.trajectory_id
    assert canonical_companion_digest(baseline) != canonical_companion_digest(changed)


def test_trajectory_closed_vocabulary_and_retry_identity_fail_closed() -> None:
    first, second, third = refs()
    poisoned = second.model_copy(update={"retry_cause": "harmful"})
    with pytest.raises((ValidationError, CompanionContractError)):
        accounting((first, poisoned, third))
    contradictory_route = second.model_copy(
        update={"route_permitted": True, "constraint_encounters": ("route_not_permitted",)}
    )
    with pytest.raises((ValidationError, CompanionContractError)):
        accounting((first, contradictory_route, third))
    conflicting_attempt = second.model_copy(update={"attempt_id": first.attempt_id})
    with pytest.raises((ValidationError, CompanionContractError)):
        accounting((first, conflicting_attempt, third))
    reversed_time = second.model_copy(
        update={"occurred_at": first.occurred_at - timedelta(seconds=10)}
    )
    with pytest.raises((ValidationError, CompanionContractError)):
        accounting((first, reversed_time, third))
    bad_initial_route = second.model_copy(update={"route_transition_reason": "initial"})
    with pytest.raises((ValidationError, CompanionContractError)):
        accounting((first, bad_initial_route, third))
    orphan_retry = second.model_copy(
        update={
            "parent_event_ids": (),
            "occurred_at": first.occurred_at - timedelta(seconds=1),
        }
    )
    with pytest.raises((ValidationError, CompanionContractError)):
        accounting((first, orphan_retry, third))


@pytest.mark.parametrize(
    "update",
    [
        {"retry_cause": "unknown"},
        {"route_transition_reason": "unknown"},
        {"constraint_encounters": ("unknown",)},
    ],
)
def test_unknown_trajectory_semantics_force_incomplete_telemetry(
    update: dict[str, object],
) -> None:
    first, second, third = refs()
    trajectory = accounting((first, second.model_copy(update=update), third))
    assert trajectory.completeness == "incomplete"
    manifest = build_telemetry_manifest_v1(
        profile=profile(),
        observed_channels=("mcp", "runtime"),
        dropped_record_count=0,
        rejected_record_count=0,
        adapter_audit=audit(),
        trajectory=trajectory,
        window_started_at=START,
        window_ended_at=END,
    )
    assert manifest.telemetry_state == "incomplete"
    assert manifest.incomplete_reason == "trajectory_not_complete"


def test_trajectory_wire_recomputes_topology_and_membership() -> None:
    value = accounting(refs())
    forged = value.model_dump(mode="python")
    forged.update(
        {
            "edges": (),
            "root_event_ids": (sha("forged-root"),),
            "leaf_event_ids": (sha("forged-leaf"),),
            "route_violation_event_ids": (sha("forged-route-event"),),
            "completeness": "complete",
        }
    )
    with pytest.raises(ValidationError):
        type(value).model_validate(forged)


def test_trajectory_identity_normalizes_order_timezone_and_event_span() -> None:
    observations = refs()
    baseline = accounting(observations)
    reordered = accounting(tuple(reversed(observations)))
    plus_three = timezone(timedelta(hours=3))
    shifted = accounting(
        tuple(
            item.model_copy(update={"occurred_at": item.occurred_at.astimezone(plus_three)})
            for item in observations
        )
    )
    assert reordered == baseline
    assert shifted == baseline
    assert canonical_companion_digest(reordered) == canonical_companion_digest(baseline)
    assert canonical_companion_digest(shifted) == canonical_companion_digest(baseline)
    alternate_wire = baseline.model_dump(mode="python")
    alternate_wire["observations"] = tuple(
        {
            **item,
            "occurred_at": item["occurred_at"].astimezone(plus_three),
        }
        for item in alternate_wire["observations"]
    )
    alternate_wire["observation_horizon_started_at"] = alternate_wire[
        "observation_horizon_started_at"
    ].astimezone(plus_three)
    alternate_wire["observation_horizon_ended_at"] = alternate_wire[
        "observation_horizon_ended_at"
    ].astimezone(plus_three)
    with pytest.raises(ValidationError):
        type(baseline).model_validate(alternate_wire)
    forged_horizon = baseline.model_dump(mode="python")
    forged_horizon["observation_horizon_started_at"] = START
    with pytest.raises(ValidationError):
        type(baseline).model_validate(forged_horizon)


def test_trajectory_unresolved_duplicate_commitment_and_cycle_fail_closed() -> None:
    first, second = refs()[:2]
    unresolved = first.model_copy(update={"parent_event_ids": (sha("missing"),)})
    incomplete = accounting((unresolved, second))
    assert incomplete.completeness == "incomplete"
    assert unresolved.event_id not in incomplete.root_event_ids
    duplicate = accounting((first, first))
    assert duplicate.completeness == "invalid"
    aliased = second.model_copy(
        update={"observation_commitment_sha256": first.observation_commitment_sha256}
    )
    commitment_alias = accounting((first, aliased))
    assert commitment_alias.completeness == "invalid"
    assert commitment_alias.duplicate_observation_commitments
    cycle_a = first.model_copy(
        update={
            "parent_event_ids": (second.event_id,),
            "occurred_at": second.occurred_at,
        }
    )
    cycle_b = second.model_copy(update={"parent_event_ids": (first.event_id,)})
    cycle = accounting((cycle_a, cycle_b))
    assert cycle.completeness == "invalid"
    assert cycle.cycle_verdict == "cycle_detected"


def audit() -> AdapterAuditV1:
    target_fields = tuple(CanonicalObservationEventV1.model_fields)
    return AdapterAuditV1(
        schema_version="portfolio-adapter-audit-v1.0",
        source_model="runtime_guard.observation_event",
        target_model="portfolio-observation-v1.0",
        completeness="partial",
        source_fields=("event_id", "effect", "authority_level"),
        target_fields=target_fields,
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
            "project_id",
            "repository_id",
            "repository_sha",
            "occurred_at",
            "producer_id_hash",
            "source_surface",
            "entity_refs",
            "parent_event_ids",
            "data_envelope_ref",
            "telemetry_state",
        ),
        constant_target_fields=(
            "schema_version",
            "producer_attestation",
            "authority_envelope_ref",
            "operational_authority",
        ),
        authority_downgrade=True,
        reason_codes=("adapter.authority_dropped",),
        operational_authority="none",
    )


def profile(expected_event_count: int = 3):
    return build_coverage_expectation_profile_v1(
        project_id="agentic-security-harness",
        repository_id="krivonosoff161/agentic-security-harness",
        repository_sha="a" * 40,
        expected_channels=("mcp", "runtime"),
        expected_event_count=expected_event_count,
        expectation_source_sha256=sha("reviewed-expectations"),
    )


def test_telemetry_builder_binds_profile_audit_and_trajectory() -> None:
    trajectory = accounting(refs())
    value = build_telemetry_manifest_v1(
        profile=profile(),
        observed_channels=("runtime", "mcp"),
        dropped_record_count=0,
        rejected_record_count=0,
        adapter_audit=audit(),
        trajectory=trajectory,
        window_started_at=START,
        window_ended_at=END,
    )
    assert value.telemetry_state == "complete"
    assert value.expected_channels == ("mcp", "runtime")
    assert value.coverage_expectation_profile_id == profile().profile_id
    assert value.trajectory_accounting_sha256 == canonical_companion_digest(trajectory)
    assert value.candidate_visibility == "evaluator_only"
    assert project_companion_for_candidate_v1(value) is None


def test_telemetry_missing_channel_profile_drift_and_invalid_trajectory_fail_closed() -> None:
    incomplete = build_telemetry_manifest_v1(
        profile=profile(),
        observed_channels=("mcp",),
        dropped_record_count=0,
        rejected_record_count=0,
        adapter_audit=audit(),
        trajectory=accounting(refs()),
        window_started_at=START,
        window_ended_at=END,
    )
    assert incomplete.telemetry_state == "incomplete"
    assert incomplete.incomplete_reason == "missing_channel"
    with pytest.raises(CompanionContractError):
        build_telemetry_manifest_v1(
            profile=profile(expected_event_count=4),
            observed_channels=("mcp", "runtime"),
            dropped_record_count=0,
            rejected_record_count=0,
            adapter_audit=audit(),
            trajectory=accounting(refs()),
            window_started_at=START,
            window_ended_at=END,
        )
    complete = build_telemetry_manifest_v1(
        profile=profile(),
        observed_channels=("mcp", "runtime"),
        dropped_record_count=0,
        rejected_record_count=0,
        adapter_audit=audit(),
        trajectory=accounting(refs()),
        window_started_at=START,
        window_ended_at=END,
    )
    forged = complete.model_dump(mode="python")
    forged["expected_channels"] = ("mcp",)
    forged["observed_channels"] = ("mcp",)
    with pytest.raises(ValidationError):
        type(complete).model_validate(forged)

    missing_evidence = complete.model_dump(mode="python")
    missing_evidence["adapter_audit_sha256"] = sha("nonexistent-audit")
    missing_evidence["trajectory_accounting_sha256"] = sha("nonexistent-trajectory")
    with pytest.raises(ValidationError):
        type(complete).model_validate(missing_evidence)

    invalid_window = complete.model_dump(mode="python")
    invalid_window["window_started_at"] = START + timedelta(seconds=2)
    with pytest.raises(ValidationError):
        type(complete).model_validate(invalid_window)


def test_companion_canonical_decoder_rejects_duplicate_and_noncanonical_wire() -> None:
    value = build_portfolio_outcome_v1(
        layer="advisory",
        reported_value="observe",
        observation_commitment_sha256=sha("observation"),
    )
    encoded = encode_companion_record_v1(value)
    assert decode_companion_record_v1(encoded) == value
    assert len(canonical_companion_digest(value)) == 64
    with pytest.raises(CompanionContractError):
        decode_companion_record_v1(encoded.replace(b"{", b'{"layer":"advisory",', 1))
    with pytest.raises(CompanionContractError):
        decode_companion_record_v1(json.dumps(value.model_dump(mode="json")).encode())
    with pytest.raises(CompanionContractError):
        encode_companion_record_v1(audit())


def _run_fixture_operation(operation: str) -> str:
    try:
        if operation == "outcome_valid":
            validate_portfolio_outcome_v1(outcome("advisory", "observe"))
        elif operation == "outcome_authority_promotion":
            value = outcome("advisory", "observe")
            value["operational_authority"] = "execute"
            validate_portfolio_outcome_v1(value)
        elif operation == "mcp_impossible_counts":
            value = summarize_mcp_payload_v1(mcp_bytes({"type": "tool_result"}))
            payload = value.model_dump(mode="python")
            payload["object_count"] = value.object_count + 1
            MCPRedactionReceiptV1.model_validate(payload)
        elif operation == "trajectory_distinct_lineage":
            first, second, third = refs()
            baseline = accounting((first, second, third))
            changed = accounting(
                (first, second, third.model_copy(update={"parent_event_ids": (first.event_id,)}))
            )
            if canonical_companion_digest(baseline) == canonical_companion_digest(changed):
                raise CompanionContractError("distinct lineage collided")
        elif operation == "telemetry_missing_channel":
            manifest = build_telemetry_manifest_v1(
                profile=profile(),
                observed_channels=("mcp",),
                dropped_record_count=0,
                rejected_record_count=0,
                adapter_audit=audit(),
                trajectory=accounting(refs()),
                window_started_at=START,
                window_ended_at=END,
            )
            if manifest.telemetry_state != "incomplete":
                raise CompanionContractError("missing channel was not marked incomplete")
        elif operation == "coverage_profile_tamper":
            payload = profile().model_dump(mode="python")
            payload["expected_event_count"] = 4
            type(profile()).model_validate(payload)
        elif operation == "mcp_resource_shaped_key":
            summarize_mcp_payload_v1(mcp_bytes({"resource": "synthetic"}))
        elif operation == "trajectory_label_token":
            first, second, third = refs()
            accounting((first, second.model_copy(update={"retry_cause": "harmful"}), third))
        elif operation == "trajectory_attempt_conflict":
            first, second, third = refs()
            accounting((first, second.model_copy(update={"attempt_id": first.attempt_id}), third))
        elif operation == "telemetry_missing_evidence":
            manifest = build_telemetry_manifest_v1(
                profile=profile(),
                observed_channels=("mcp", "runtime"),
                dropped_record_count=0,
                rejected_record_count=0,
                adapter_audit=audit(),
                trajectory=accounting(refs()),
                window_started_at=START,
                window_ended_at=END,
            )
            payload = manifest.model_dump(mode="python")
            payload["trajectory_accounting_sha256"] = sha("missing")
            type(manifest).model_validate(payload)
        elif operation == "trajectory_order_timezone_normalization":
            observations = refs()
            baseline = accounting(observations)
            plus_three = timezone(timedelta(hours=3))
            shifted = tuple(
                item.model_copy(update={"occurred_at": item.occurred_at.astimezone(plus_three)})
                for item in reversed(observations)
            )
            if accounting(shifted) != baseline:
                raise CompanionContractError("equivalent trajectory was not normalized")
        elif operation == "trajectory_event_span_tamper":
            value = accounting(refs())
            payload = value.model_dump(mode="python")
            payload["observation_horizon_started_at"] = START
            type(value).model_validate(payload)
        elif operation == "candidate_evaluator_boundary":
            if project_companion_for_candidate_v1(accounting(refs())) is not None:
                raise CompanionContractError("evaluator record crossed candidate boundary")
        elif operation == "trajectory_reversed_causal_time":
            first, second, third = refs()
            accounting(
                (
                    first,
                    second.model_copy(
                        update={"occurred_at": first.occurred_at - timedelta(seconds=1)}
                    ),
                    third,
                )
            )
        elif operation == "trajectory_unknown_incomplete":
            first, second, third = refs()
            if (
                accounting(
                    (first, second.model_copy(update={"retry_cause": "unknown"}), third)
                ).completeness
                != "incomplete"
            ):
                raise CompanionContractError("unknown evidence was promoted to complete")
        elif operation == "trajectory_route_phase_conflict":
            first, second, third = refs()
            accounting(
                (
                    first,
                    second.model_copy(update={"route_transition_reason": "initial"}),
                    third,
                )
            )
        elif operation == "trajectory_orphan_retry":
            first, second, third = refs()
            accounting(
                (
                    first,
                    second.model_copy(
                        update={
                            "parent_event_ids": (),
                            "occurred_at": first.occurred_at - timedelta(seconds=1),
                        }
                    ),
                    third,
                )
            )
        else:
            raise AssertionError(f"unknown fixture operation: {operation}")
    except (CompanionContractError, ValidationError, ValueError):
        return "invalid"
    return "valid"


def test_content_bound_fixture_corpus_is_fully_executed() -> None:
    corpus = json.loads((ROOT / FIXTURE_PATH).read_text(encoding="utf-8"))
    assert corpus["authority"] == "none"
    seen: set[str] = set()
    for case in corpus["cases"]:
        seen.add(case["case_id"])
        assert _run_fixture_operation(case["operation"]) == case["expected_verdict"]
    assert len(seen) == len(corpus["cases"])


def test_stored_r4_schemas_and_manifest_are_content_bound() -> None:
    generated = r4_companion_json_schemas()
    manifest = json.loads((ROOT / MANIFEST_PATH).read_text(encoding="utf-8"))
    assert manifest["authority"] == "none"
    assert manifest["observation_contract_unchanged"] == "portfolio-observation-v1.0"
    assert manifest["schema_role"].startswith("shape_only_")
    assert manifest["validator"]["path"] == VALIDATOR_PATH
    assert (
        manifest["validator"]["sha256"]
        == hashlib.sha256((ROOT / VALIDATOR_PATH).read_bytes()).hexdigest()
    )
    assert manifest["fixtures"] == [
        {
            "path": FIXTURE_PATH,
            "sha256": hashlib.sha256((ROOT / FIXTURE_PATH).read_bytes()).hexdigest(),
            "verdict_semantics": "valid_must_accept_invalid_must_reject",
        }
    ]
    assert manifest["fixture_runner"] == {
        "path": FIXTURE_RUNNER_PATH,
        "sha256": hashlib.sha256((ROOT / FIXTURE_RUNNER_PATH).read_bytes()).hexdigest(),
    }
    rows = {row["contract_id"]: row for row in manifest["contracts"]}
    assert set(rows) == set(SCHEMA_PATHS) == set(generated)
    for contract_id, relative in SCHEMA_PATHS.items():
        path = ROOT / relative
        assert json.loads(path.read_text(encoding="utf-8")) == generated[contract_id]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == rows[contract_id]["schema_sha256"]
