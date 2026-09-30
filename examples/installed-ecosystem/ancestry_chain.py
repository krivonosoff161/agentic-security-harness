"""Opt-in retained ancestry to installed, synthetic ecosystem chain.

The ancestry snapshot is data admission only. Only the final GatewayEngine may
execute its built-in pure lookup/digest operations. No provider is contacted.
"""

from __future__ import annotations

import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agentic_security_harness.ancestry_store import (
    AncestryError,
    AncestryRecord,
    AncestryStore,
    Checkpoint,
    CheckpointConflict,
    IntegrityError,
)

_HANDOFF_DECLARED_RELEASE_SHA = "bef6edcd5683982d9a8f251ec93974701ed5457a"


def _chain_helpers() -> Any:
    """Load the unchanged installed-example helpers after ancestry admission."""
    path = Path(__file__).with_name("chain.py")
    module = types.ModuleType("installed_chain_reference")
    module.__file__ = str(path)
    # Execute the exact source selected by the caller's artifact pin. Do not let
    # an unrelated bytecode cache replace that source at this integration seam.
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def _closure(records: tuple[AncestryRecord, ...], target: str) -> tuple[AncestryRecord, ...]:
    by_id = {record.record_id: record for record in records}
    if target not in by_id:
        return ()
    ids: set[str] = set()
    pending = [target]
    while pending:
        record_id = pending.pop()
        if record_id not in ids:
            ids.add(record_id)
            pending.extend(by_id[record_id].parents)
    return tuple(record for record in records if record.record_id in ids)


def run_retained_case(
    store: AncestryStore,
    target: str,
    expected: Checkpoint,
    candidate_records: tuple[AncestryRecord, ...] | None = None,
    *,
    return_pure_result: bool = False,
) -> dict[str, Any]:
    """Evaluate retained bytes through exact installed components.

    Returned evidence contains digests, dispositions and counts. The optional
    pure_result exists only in the returned in-memory object; callers must not
    persist raw results. Handoff sequence records capture order, not DAG edges.
    """
    from hashlib import sha256

    def sha(data: bytes) -> str:
        return sha256(data).hexdigest()

    row: dict[str, Any] = {
        "schema": "retained-ancestry-chain.v1",
        "outcome": "rejected",
        "stages": [],
        "synthetic_executions": 0,
        "fake_transport_calls": 0,
        "result_sha256": None,
        "operational_authority": "none",
        "may_authorize_effects": False,
    }

    def stage(name: str, disposition: str, **evidence: Any) -> None:
        row["stages"].append({"stage": name, "disposition": disposition, **evidence})

    if type(return_pure_result) is not bool:
        stage("ancestry", "reject", reason="invalid_result_option")
        return row
    try:
        snapshot = store.snapshot(expected=expected)
        supplied = (_closure(snapshot.records, target)
                    if candidate_records is None else candidate_records)
        if not store.verify_candidate(target, supplied, expected=expected):
            stage("ancestry", "reject", reason="candidate_mismatch")
            return row
    except CheckpointConflict:
        stage("ancestry", "reject", reason="checkpoint_conflict")
        return row
    except IntegrityError:
        stage("ancestry", "recovery_required", reason="retained_state_integrity")
        row["outcome"] = "recovery_required"
        return row
    except (AncestryError, TypeError):
        stage("ancestry", "reject", reason="invalid_candidate")
        return row

    retained = {record.record_id: record for record in snapshot.records}
    target_record = retained[target]
    payload = target_record.payload
    target_sha = sha(payload)
    stage("ancestry", "accepted", target_payload_sha256=target_sha,
          checkpoint_event_head=snapshot.checkpoint.event_head,
          root_digest=snapshot.checkpoint.root_digest,
          ancestor_count=len(supplied))

    # All imports below occur after exact store admission. The Router helper's
    # transport is a declared in-memory fake and invokes no provider.
    chain = _chain_helpers()
    from agent_guard.handoff_metadata import (
        HandoffAdapterContext,
        HandoffMetadataError,
        build_handoff_metadata,
        project_handoff_metadata,
    )
    from agentic_transfer_verifier.models import ProvenanceStep, TransferEnvelope
    from agentic_transfer_verifier.verifier import verify_envelope
    from llm_cheap_filter.policy import EscalationPolicy
    from llm_cheap_filter.prefilter import PreFilter
    from llm_router.receipt import (
        InvocationAttemptV1,
        InvocationReceiptError,
        build_invocation_receipt_v1,
        decode_invocation_receipt_v1,
        encode_invocation_receipt_v1,
    )
    from llm_safety_playbooks import policy_pack_bytes

    from agentic_security_harness.policy_pack_extension import (
        PolicyPackExtensionError,
        PolicyPackSignalsV1,
        build_policy_pack_signal_binding_v1,
        decode_policy_pack_v1,
        evaluate_policy_pack_binding_v1,
    )
    from agentic_security_harness.portfolio_contract import CanonicalObservationEventV1
    from agentic_security_harness.quarantine_connector import (
        ProviderAdapterProfileRegistryV1,
        ProviderAdapterProfileV1,
        QuarantineCapabilityBindingV1,
        bridge_quarantine_admission_v1,
        evaluate_quarantine_input_v1,
    )
    from agentic_security_harness.runtime_gateway import GatewayEngine

    registry = ProviderAdapterProfileRegistryV1(
        profiles=(ProviderAdapterProfileV1(
            profile_id="example.chain",
            profile_version="v1",
            capabilities=(
                QuarantineCapabilityBindingV1(
                    capability_id="bounded.digest", gateway_protocol="mcp",
                    gateway_tool_name="synthetic.sha256",
                    allowed_argument_keys=("text",), required_argument_keys=("text",),
                ),
                QuarantineCapabilityBindingV1(
                    capability_id="bounded.lookup", gateway_protocol="mcp",
                    gateway_tool_name="synthetic.lookup",
                    allowed_argument_keys=("key",), required_argument_keys=("key",),
                ),
            ),
        ),),
    )
    verdict = evaluate_quarantine_input_v1(
        registry, selected_profile_id="example.chain",
        selected_profile_version="v1", payload=payload,
    )
    stage("quarantine", verdict.disposition, input_payload_sha256=target_sha,
          verdict_sha256=sha(chain.canonical(verdict.model_dump(mode="json"))))
    if verdict.disposition != "admit":
        return row
    if verdict.capability_request is None:
        row["outcome"] = "no_request"
        return row
    request = verdict.capability_request
    if request.capability_id not in target_record.scope:
        stage("scope", "reject", reason="capability_not_in_retained_scope",
              requested_capability=request.capability_id)
        return row
    if verdict.operational_authority != "none":
        stage("quarantine_authority", "reject", reason="unexpected_authority")
        return row

    filtered = PreFilter(min_chars=1).score(payload.decode("utf-8"), [])
    role = EscalationPolicy().decide(0.5)
    stage("filter", role, keep=filtered.keep, request_sha256=request.sha256())
    if not filtered.keep or role == "drop":
        row["outcome"] = "filtered"
        return row

    text, usage, row["fake_transport_calls"] = chain.router_with_in_memory_transport(
        role, payload
    )
    try:
        if text.encode("utf-8") != payload:
            raise ValueError("Router output changed retained bytes")
        # All provider/status/usage fields below are synthetic fixture assertions
        # for receipt-schema conformance, not provider-attested telemetry. The
        # transport above is in-memory: no OpenAI or other provider is called.
        receipt = build_invocation_receipt_v1(
            occurred_at="2026-09-21T00:00:00.000000Z",
            producer_id_hash=target_sha,
            request_payload_sha256=target_sha,
            provider_id="openai",
            model_id_sha256=sha(b"public-toy"),
            role=role,
            attempts=(InvocationAttemptV1(
                attempt_index=1, outcome="success", http_status=200,
                reason_code="provider.success", response_payload_sha256=target_sha,
            ),),
            terminal_status="success",
            response_payload_sha256=target_sha,
            output_text_sha256=target_sha,
            usage_provenance="provider_reported",
            input_tokens=usage["input_tokens"],
            output_tokens=usage["output_tokens"],
            total_tokens=usage["total_tokens"],
            pricing_source="unpriced",
            pricing_source_ref_sha256=None,
            input_rate_usd_nanos_per_million=0,
            output_rate_usd_nanos_per_million=0,
        )
        receipt_bytes = encode_invocation_receipt_v1(receipt)
        if decode_invocation_receipt_v1(receipt_bytes) != receipt:
            raise ValueError("receipt roundtrip mismatch")
    except (InvocationReceiptError, ValueError):
        stage("router", "reject", reason="route_or_receipt_integrity")
        return row
    stage("router", role, input_payload_sha256=target_sha,
          response_payload_sha256=sha(text.encode("utf-8")),
          receipt_sha256=sha(receipt_bytes))

    checkpoint = snapshot.checkpoint
    cp_data = {
        "context": checkpoint.context,
        "root_digest": checkpoint.root_digest,
        "version": checkpoint.version,
        "sequence": checkpoint.sequence,
        "event_head": checkpoint.event_head,
    }
    envelope = TransferEnvelope(
        envelope_id=sha(chain.canonical({"target": target, "checkpoint": cp_data,
                                         "payload_sha256": target_sha})),
        producer="public-router", consumer="public-handoff",
        payload_kind="invocation-receipt", trust_level="untrusted",
        authority_scope="none",
        payload={"receipt_sha256": sha(receipt_bytes),
                 "request_sha256": request.sha256(),
                 "target_payload_sha256": target_sha,
                 "checkpoint": cp_data},
        provenance=[ProvenanceStep(actor="public-router", action="fixture",
                                   source="public_synthetic")],
        parent_envelope_id="",
    )
    transfer = verify_envelope(envelope)
    stage("transfer", transfer.status, target_payload_sha256=target_sha,
          checkpoint_sha256=sha(chain.canonical(cp_data)),
          verdict_sha256=sha(chain.canonical(transfer.to_dict())))
    if transfer.status != "PASS":
        return row

    artifact = chain.canonical(envelope.to_dict())
    handoff_context = HandoffAdapterContext(
        project_id="ai-agent-handoff",
        repository_id="krivonosoff161/ai-agent-handoff",
        # Declared installed Handoff v0.3.0 identity, not authenticated provenance.
        repository_sha=_HANDOFF_DECLARED_RELEASE_SHA,
        source_surface="agent",
        data_envelope_ref=sha(artifact),
    )
    created = datetime(2026, 9, 21, tzinfo=UTC)
    previous = None
    previous_projection = None
    try:
        for sequence, ancestor in enumerate(supplied):
            metadata = build_handoff_metadata(
                artifact_kind="task", artifact_bytes=ancestor.payload,
                sequence=sequence,
                created_at=created + timedelta(seconds=sequence),
                producer_id_hash=sha(b"public-toy-handoff"),
                parent_artifact_sha256=(previous.artifact_sha256
                                        if previous is not None else None),
            )
            projection = project_handoff_metadata(
                metadata, ancestor.payload, handoff_context,
                previous=previous,
                previous_observation=(previous_projection.observation
                                      if previous_projection is not None else None),
            )
            previous, previous_projection = metadata, projection
    except HandoffMetadataError:
        stage("handoff", "reject", reason="retained_artifact_or_capture_order")
        return row
    if previous_projection is None:
        stage("handoff", "reject", reason="empty_closure")
        return row
    event = CanonicalObservationEventV1.model_validate(previous_projection.observation.to_dict())
    if event.operational_authority != "none" or event.authority_envelope_ref is not None:
        stage("handoff", "reject", reason="unexpected_authority")
        return row
    stage("handoff", "accepted", target_payload_sha256=sha(supplied[-1].payload),
          capture_order="retained_admission_sequence_not_dag_edges",
          ancestor_count=len(supplied),
          event_sha256=sha(chain.canonical(event.model_dump(mode="json"))))
    if sha(supplied[-1].payload) != target_sha:
        stage("handoff_binding", "reject", reason="target_byte_mismatch")
        return row

    try:
        pack = decode_policy_pack_v1(policy_pack_bytes(),
                                     expected_file_sha256=chain.PACK_SHA256)
        signals = PolicyPackSignalsV1(**dict.fromkeys(PolicyPackSignalsV1.model_fields,
                                                     "absent"))
        binding = build_policy_pack_signal_binding_v1(
            event, signals=signals, source_class="synthetic_fixture"
        )
        advice = evaluate_policy_pack_binding_v1(pack, binding, event)
    except PolicyPackExtensionError:
        stage("playbooks", "reject", reason="pack_integrity")
        return row
    stage("playbooks", advice.overall_advisory_disposition,
          pack_sha256=chain.PACK_SHA256,
          advice_sha256=sha(chain.canonical(advice.model_dump(mode="json"))))
    if (advice.operational_authority != "none" or advice.may_authorize_effects or
            advice.overall_advisory_disposition != "observe"):
        row["outcome"] = "inconclusive"
        return row

    bridge = bridge_quarantine_admission_v1(verdict, registry)
    if bridge is None:
        stage("gateway", "reject", reason="missing_quarantine_bridge")
        return row
    audit = chain.MemoryAudit()
    engine = GatewayEngine(audit=audit)
    decision, result = engine.call_tool(
        bridge.gateway_call, request_id="retained:" + sha(target.encode("ascii"))[:24]
    )
    row["synthetic_executions"] = engine.execution_count
    row["result_sha256"] = sha(chain.canonical(result))
    stage("gateway", decision.disposition, result_sha256=row["result_sha256"],
          decision_sha256=sha(chain.canonical(decision.model_dump(mode="json"))))
    row["outcome"] = "completed" if decision.execution_permitted else "denied"
    if return_pure_result and decision.execution_permitted:
        row["pure_result"] = result
    return row
