from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from tools.companion_extension_contracts import generated_contracts

from agentic_security_harness.companion_extensions import (
    COMPANION_PIN_V1,
    REVIEWED_COMPANION_SOURCES_V1,
    CompanionContractPinV1,
    CompanionExtensionError,
    HandoffMetadataExtensionV1,
    PlaybookGuidanceExtensionV1,
    TransferVerificationEvidenceV1,
    TransferVerifierExtensionV1,
    build_handoff_metadata_evidence_v1,
    build_playbook_guidance_config_v1,
    build_transfer_verification_evidence_v1,
    companion_extension_v1_json_schemas,
    reviewed_companion_sources_v1,
)
from agentic_security_harness.extension_sdk import (
    ExtensionObservationEnvelopeV1,
    StaticExtensionRegistryV1,
    build_extension_envelope_v1,
    run_extension_pipeline_v1,
    run_extension_v1,
)
from agentic_security_harness.portfolio_contract import (
    CanonicalObservationEventV1,
    SafeEvidencePointer,
)

NOW = datetime(2026, 8, 24, 2, 0, tzinfo=UTC)
REPOSITORY_SHA = "a" * 40
SOURCE_COMMITMENT = "b" * 64
PRODUCER = "c" * 64
DATA_ENVELOPE = "d" * 64
ROOT = Path(__file__).resolve().parents[1]
TRANSFER_CONTRACT_SHA = REVIEWED_COMPANION_SOURCES_V1[0].contract_sha256
HANDOFF_CONTRACT_SHA = REVIEWED_COMPANION_SOURCES_V1[1].contract_sha256
PLAYBOOK_CONTRACT_SHA = REVIEWED_COMPANION_SOURCES_V1[2].contract_sha256


def _pin(
    component_id: str,
    contract_id: str,
    version: str,
    *,
    contract_sha256: str | None = None,
) -> CompanionContractPinV1:
    reviewed = next(
        item for item in REVIEWED_COMPANION_SOURCES_V1 if item.component_id == component_id
    )
    return CompanionContractPinV1(
        schema_version=COMPANION_PIN_V1,
        component_id=component_id,
        source_commit=reviewed.commit,
        component_manifest_sha256=reviewed.component_manifest_sha256,
        contract_id=contract_id,
        contract_version=version,
        contract_sha256=contract_sha256 or reviewed.contract_sha256,
        contract_digest_semantics="sha256_lf_normalized_text_v1",
        verification="exact_public_git_reviewed",
        operational_authority="none",
    )


def _event(
    event_id: str,
    *,
    activity: str,
    occurred_at: datetime = NOW,
    parent_event_ids: tuple[str, ...] = (),
    entity_refs: tuple[SafeEvidencePointer, ...] = (),
    producer_id_hash: str = PRODUCER,
    telemetry_state: str = "complete",
) -> CanonicalObservationEventV1:
    return CanonicalObservationEventV1.model_validate(
        {
            "schema_version": "portfolio-observation-v1.0",
            "event_id": event_id,
            "project_id": "agentic-security-harness",
            "repository_id": "example/companion-fixture",
            "repository_sha": REPOSITORY_SHA,
            "occurred_at": occurred_at,
            "producer_id_hash": producer_id_hash,
            "producer_attestation": "unattested",
            "source_surface": "agent",
            "activity": activity,
            "entity_refs": entity_refs,
            "parent_event_ids": parent_event_ids,
            "data_envelope_ref": DATA_ENVELOPE,
            "authority_envelope_ref": None,
            "telemetry_state": telemetry_state,
            "operational_authority": "none",
        }
    )


def _envelope(
    *events: CanonicalObservationEventV1,
) -> ExtensionObservationEnvelopeV1:
    return build_extension_envelope_v1(
        source_component_id="agentic-security-harness",
        source_commitment_sha256=SOURCE_COMMITMENT,
        events=events,
    )


def _handoff_locator(
    artifact_kind: str, sequence: int, artifact_sha256: str, producer_id_hash: str
) -> str:
    value = f"{artifact_kind}:{sequence}:{artifact_sha256}:{producer_id_hash}"
    return hashlib.sha256(f"ai-agent-handoff/artifact-locator\0{value}".encode()).hexdigest()


def _transfer_report(
    *, status: str = "PASS", findings: list[dict[str, str]] | None = None
) -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "envelope_id": "owned-transfer-001",
        "status": status,
        "findings": [] if findings is None else findings,
    }


def _transfer_event_for_report(
    report: dict[str, object], *, activity: str = "transfer.data.task"
) -> CanonicalObservationEventV1:
    envelope_id = report["envelope_id"]
    assert isinstance(envelope_id, str)
    event_id = hashlib.sha256(
        f"agentic-transfer-verifier/transfer-envelope-id\0{envelope_id}".encode()
    ).hexdigest()
    return _event(event_id, activity=activity)


def _transfer_evidence(
    report: dict[str, object],
    event: CanonicalObservationEventV1 | None = None,
) -> TransferVerificationEvidenceV1:
    source_event = event or _transfer_event_for_report(report)
    return build_transfer_verification_evidence_v1(
        report,
        source_event.model_dump(mode="json"),
        source_contract_sha256=TRANSFER_CONTRACT_SHA,
    )


def _guidance() -> dict[str, object]:
    return {
        "schema_version": "portfolio-observation-guidance-v1.0",
        "contract_id": "portfolio-observation-v1.0",
        "owner_pin_path": "contracts/portfolio-observation.v1.owner-pin.json",
        "guidance_mode": "human_guidance_only",
        "required_metadata": [
            "schema_version",
            "event_id",
            "project_id",
            "repository_id",
            "repository_sha",
            "occurred_at",
            "producer_id_hash",
            "producer_attestation",
            "source_surface",
            "activity",
            "entity_refs",
            "parent_event_ids",
            "data_envelope_ref",
            "authority_envelope_ref",
            "telemetry_state",
            "operational_authority",
        ],
        "missing_or_invalid_metadata_disposition": "abstain",
        "allowed_human_dispositions": [
            "observe",
            "challenge",
            "escalate",
            "abstain",
        ],
        "forbidden_promotions": [
            "authority",
            "capability",
            "consent",
            "authenticated_identity",
            "allow_receipt",
            "producer_attestation",
        ],
        "authority_envelope_interpretation": "evidence_pointer_only",
        "producer_attestation_interpretation": "unattested_only",
        "human_playbook_path": "playbooks/canonical-observation-review.md",
        "human_playbook_sha256": (
            "bd2c518c484072804f860d50d4b4ff52c246fafbaac4c7fb87db86aafd2f79f0"
        ),
        "operational_authority": "none",
    }


def test_transfer_report_flows_into_content_bound_extension_receipt() -> None:
    report = _transfer_report()
    event = _transfer_event_for_report(report)
    evidence = _transfer_evidence(report, event)
    extension = TransferVerifierExtensionV1(
        pin=_pin(
            "agentic-transfer-verifier", "transfer-verification-report", "0.1"
        ),
        evidence=(evidence,),
    )

    receipt = run_extension_v1(extension, _envelope(event))

    finding = receipt.result.findings[0]
    assert finding.outcome == "pass"
    assert finding.severity == "none"
    assert finding.evidence_event_ids == (event.event_id,)
    assert receipt.result.extension_manifest_sha256
    assert extension.manifest.implementation_sha256
    assert extension.manifest.configuration_sha256
    assert extension.manifest.operational_authority == "none"


def test_transfer_failure_is_advisory_and_raw_message_is_not_retained() -> None:
    report = _transfer_report(
        status="FAIL",
        findings=[
            {
                "code": "untrusted_authority",
                "severity": "high",
                "message": "synthetic raw explanation must not enter extension evidence",
            }
        ],
    )
    event = _transfer_event_for_report(report, activity="transfer.policy.task")
    evidence = _transfer_evidence(report, event)
    extension = TransferVerifierExtensionV1(
        pin=_pin(
            "agentic-transfer-verifier", "transfer-verification-report", "0.1"
        ),
        evidence=(evidence,),
    )
    receipt = run_extension_v1(
        extension, _envelope(event)
    )

    serialized = receipt.model_dump_json()
    assert receipt.result.findings[0].outcome == "finding"
    assert receipt.result.findings[0].severity == "high"
    assert "synthetic raw explanation" not in serialized
    assert "untrusted_authority" not in serialized


def test_handoff_metadata_chain_binds_events_without_artifact_bytes() -> None:
    first_metadata = {
        "schema_version": "handoff-metadata-v1.0",
        "artifact_kind": "task",
        "artifact_sha256": "2" * 64,
        "sequence": 0,
        "created_at": NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "producer_id_hash": PRODUCER,
        "parent_artifact_sha256": None,
    }
    second_metadata = {
        **first_metadata,
        "artifact_sha256": "3" * 64,
        "sequence": 1,
        "created_at": (NOW + timedelta(microseconds=1))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        "parent_artifact_sha256": "2" * 64,
    }
    first = build_handoff_metadata_evidence_v1(
        first_metadata, source_contract_sha256=HANDOFF_CONTRACT_SHA
    )
    second = build_handoff_metadata_evidence_v1(
        second_metadata, source_contract_sha256=HANDOFF_CONTRACT_SHA
    )
    first_event = _event(
        first.event_id,
        activity="handoff.task",
        entity_refs=(
            SafeEvidencePointer(
                kind="artifact",
                digest=first.artifact_sha256,
                locator_id=_handoff_locator(
                    first.artifact_kind,
                    first.sequence,
                    first.artifact_sha256,
                    first.producer_id_hash,
                ),
            ),
        ),
    )
    second_event = _event(
        second.event_id,
        activity="handoff.task",
        occurred_at=NOW + timedelta(microseconds=1),
        parent_event_ids=(first.event_id,),
        entity_refs=(
            SafeEvidencePointer(
                kind="artifact",
                digest=second.artifact_sha256,
                locator_id=_handoff_locator(
                    second.artifact_kind,
                    second.sequence,
                    second.artifact_sha256,
                    second.producer_id_hash,
                ),
            ),
        ),
    )
    extension = HandoffMetadataExtensionV1(
        pin=_pin("ai-agent-handoff", "handoff-metadata", "1.0"),
        evidence=(first, second),
    )

    receipt = run_extension_v1(extension, _envelope(first_event, second_event))

    assert [item.outcome for item in receipt.result.findings] == ["pass", "pass"]
    assert "artifact_bytes" not in receipt.model_dump_json()


def test_playbook_is_executable_advisory_not_allow_or_enforcement() -> None:
    guidance = build_playbook_guidance_config_v1(
        _guidance(), source_contract_sha256=PLAYBOOK_CONTRACT_SHA
    )
    pin = _pin(
        "llm-safety-playbooks",
        "portfolio-observation-guidance",
        "1.0",
        contract_sha256=guidance.source_guidance_sha256,
    )
    report = _transfer_report()
    event = _transfer_event_for_report(report)
    transfer = _transfer_evidence(report, event)
    registry = StaticExtensionRegistryV1(
        (
            TransferVerifierExtensionV1(
                pin=_pin(
                    "agentic-transfer-verifier",
                    "transfer-verification-report",
                    "0.1",
                ),
                evidence=(transfer,),
            ),
            PlaybookGuidanceExtensionV1(pin=pin, guidance=guidance),
        )
    )

    receipt = run_extension_pipeline_v1(
        registry,
        (
            "agentic-transfer-verifier.verification",
            "llm-safety-playbooks.observation-review",
        ),
        _envelope(event),
    )

    advisory = receipt.runs[-1].result.findings[0]
    assert advisory.outcome == "inconclusive"
    assert advisory.reason_code == "playbook.human_review_required"
    assert "allow" not in advisory.reason_code
    assert receipt.operational_authority == "none"


def test_companion_contracts_fail_closed_on_drift_and_duplicates() -> None:
    with pytest.raises(ValidationError, match="status"):
        build_transfer_verification_evidence_v1(
            (report := _transfer_report(status="PASS", findings=[
                {"code": "warning", "severity": "medium", "message": "synthetic"}
            ])),
            _transfer_event_for_report(report).model_dump(mode="json"),
            source_contract_sha256=TRANSFER_CONTRACT_SHA,
        )

    report = _transfer_report()
    evidence = _transfer_evidence(report)
    with pytest.raises(CompanionExtensionError, match="event ids must be unique"):
        TransferVerifierExtensionV1(
            pin=_pin(
                "agentic-transfer-verifier", "transfer-verification-report", "0.1"
            ),
            evidence=(evidence, evidence),
        )
    with pytest.raises(CompanionExtensionError, match="does not match"):
        TransferVerifierExtensionV1(
            pin=_pin(
                "agentic-transfer-verifier",
                "transfer-verification-report",
                "0.1",
                contract_sha256="0" * 64,
            ),
            evidence=(evidence,),
        )
    forged = _pin(
        "agentic-transfer-verifier", "transfer-verification-report", "0.1"
    ).model_copy(update={"source_commit": "0" * 40})
    with pytest.raises(CompanionExtensionError, match="does not match"):
        TransferVerifierExtensionV1(pin=forged, evidence=(evidence,))

    guidance = _guidance()
    guidance["allowed_human_dispositions"] = ["observe", "allow"]
    with pytest.raises(CompanionExtensionError, match="semantic contract drift"):
        build_playbook_guidance_config_v1(
            guidance, source_contract_sha256=PLAYBOOK_CONTRACT_SHA
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_commit", "0" * 40),
        ("component_manifest_sha256", "0" * 64),
        ("contract_sha256", "0" * 64),
    ],
)
def test_reviewed_companion_pin_rejects_forged_identity(
    field: str, value: str
) -> None:
    report = _transfer_report()
    evidence = _transfer_evidence(report)
    pin = _pin(
        "agentic-transfer-verifier", "transfer-verification-report", "0.1"
    ).model_copy(update={field: value})

    with pytest.raises(CompanionExtensionError, match="does not match"):
        TransferVerifierExtensionV1(pin=pin, evidence=(evidence,))


def test_handoff_sequence_gap_and_binding_drift_are_rejected() -> None:
    metadata = {
        "schema_version": "handoff-metadata-v1.0",
        "artifact_kind": "task",
        "artifact_sha256": "6" * 64,
        "sequence": 1,
        "created_at": NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "producer_id_hash": PRODUCER,
        "parent_artifact_sha256": "7" * 64,
    }
    evidence = build_handoff_metadata_evidence_v1(
        metadata, source_contract_sha256=HANDOFF_CONTRACT_SHA
    )
    with pytest.raises(CompanionExtensionError, match="not contiguous"):
        HandoffMetadataExtensionV1(
            pin=_pin("ai-agent-handoff", "handoff-metadata", "1.0"),
            evidence=(evidence,),
        )


def test_transfer_report_cannot_pass_for_a_different_observation() -> None:
    report = _transfer_report()
    original = _transfer_event_for_report(report)
    evidence = _transfer_evidence(report, original)
    drifted = CanonicalObservationEventV1.model_validate(
        {**original.model_dump(mode="json"), "data_envelope_ref": "9" * 64}
    )
    extension = TransferVerifierExtensionV1(
        pin=_pin(
            "agentic-transfer-verifier", "transfer-verification-report", "0.1"
        ),
        evidence=(evidence,),
    )

    finding = run_extension_v1(extension, _envelope(drifted)).result.findings[0]

    assert finding.outcome == "finding"
    assert finding.severity == "high"
    assert finding.reason_code == "transfer.observation_binding_drift"


@pytest.mark.parametrize("drift", ["digest_replay", "timestamp_rollback"])
def test_handoff_replays_and_timestamp_rollbacks_are_rejected(drift: str) -> None:
    first_metadata = {
        "schema_version": "handoff-metadata-v1.0",
        "artifact_kind": "task",
        "artifact_sha256": "6" * 64,
        "sequence": 0,
        "created_at": NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "producer_id_hash": PRODUCER,
        "parent_artifact_sha256": None,
    }
    second_metadata = {
        **first_metadata,
        "artifact_sha256": "7" * 64,
        "sequence": 1,
        "created_at": (NOW + timedelta(microseconds=1))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        "parent_artifact_sha256": first_metadata["artifact_sha256"],
    }
    if drift == "digest_replay":
        second_metadata["artifact_sha256"] = first_metadata["artifact_sha256"]
    else:
        second_metadata["created_at"] = first_metadata["created_at"]
    evidence = tuple(
        build_handoff_metadata_evidence_v1(
            item, source_contract_sha256=HANDOFF_CONTRACT_SHA
        )
        for item in (first_metadata, second_metadata)
    )

    with pytest.raises(CompanionExtensionError, match="replay|timestamp rollback"):
        HandoffMetadataExtensionV1(
            pin=_pin("ai-agent-handoff", "handoff-metadata", "1.0"),
            evidence=evidence,
        )


def test_handoff_rejects_coerced_sequence_and_locator_drift() -> None:
    metadata: dict[str, object] = {
        "schema_version": "handoff-metadata-v1.0",
        "artifact_kind": "task",
        "artifact_sha256": "8" * 64,
        "sequence": "0",
        "created_at": NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "producer_id_hash": PRODUCER,
        "parent_artifact_sha256": None,
    }
    with pytest.raises(ValidationError):
        build_handoff_metadata_evidence_v1(
            metadata, source_contract_sha256=HANDOFF_CONTRACT_SHA
        )

    metadata["sequence"] = 0
    evidence = build_handoff_metadata_evidence_v1(
        metadata, source_contract_sha256=HANDOFF_CONTRACT_SHA
    )
    event = _event(
        evidence.event_id,
        activity="handoff.task",
        entity_refs=(
            SafeEvidencePointer(
                kind="artifact", digest=evidence.artifact_sha256, locator_id="9" * 64
            ),
        ),
    )
    extension = HandoffMetadataExtensionV1(
        pin=_pin("ai-agent-handoff", "handoff-metadata", "1.0"),
        evidence=(evidence,),
    )

    finding = run_extension_v1(extension, _envelope(event)).result.findings[0]

    assert finding.outcome == "finding"
    assert finding.reason_code == "handoff.metadata_binding_drift"


def test_configuration_digest_changes_with_companion_evidence() -> None:
    clean_report = _transfer_report()
    clean = _transfer_evidence(clean_report)
    failed_report = _transfer_report(
        status="FAIL",
        findings=[
            {"code": "untrusted_authority", "severity": "high", "message": "x"}
        ],
    )
    failed = _transfer_evidence(failed_report)
    pin = _pin("agentic-transfer-verifier", "transfer-verification-report", "0.1")

    clean_extension = TransferVerifierExtensionV1(pin=pin, evidence=(clean,))
    failed_extension = TransferVerifierExtensionV1(pin=pin, evidence=(failed,))

    assert (
        clean_extension.manifest.implementation_sha256
        == failed_extension.manifest.implementation_sha256
    )
    assert (
        clean_extension.manifest.configuration_sha256
        != failed_extension.manifest.configuration_sha256
    )


def test_companion_schemas_and_manifest_are_closed_and_content_bound() -> None:
    schemas = companion_extension_v1_json_schemas()
    assert set(schemas) == {
        "companion-contract-pin.v1.schema.json",
        "handoff-metadata-evidence.v1.schema.json",
        "playbook-guidance-config.v1.schema.json",
        "transfer-verification-evidence.v1.schema.json",
    }
    for name, schema in schemas.items():
        assert schema["additionalProperties"] is False
        assert json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8")) == schema

    expected = generated_contracts()
    for path, content in expected.items():
        assert path.read_bytes() == content
    manifest = json.loads(
        (ROOT / "schemas" / "companion-extensions.v1.manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest["code_auto_discovery"] is False
    assert manifest["companion_package_imports_at_runtime"] is False
    assert manifest["operational_authority"] == "none"
    assert manifest["contract_digest_semantics"] == "sha256_lf_normalized_text_v1"
    assert manifest["json_schema_scope"] == (
        "closed_shape_only_semantic_validation_in_python"
    )
    assert manifest["reviewed_sources"] == list(reviewed_companion_sources_v1())
    integration_candidate = manifest["integration_candidate"]
    assert set(integration_candidate) == {
        "compatibility",
        "documentation",
        "test",
        "workflow",
    }
    for binding in manifest["schemas"] + [
        manifest["implementation"],
        manifest["extension_sdk_contract"],
        manifest["generator"],
        manifest["unit_tests"],
        manifest["cross_repository_tests"],
        manifest["workflow"],
        manifest["documentation"],
        *integration_candidate.values(),
    ]:
        assert hashlib.sha256((ROOT / binding["path"]).read_bytes()).hexdigest() == binding[
            "sha256"
        ]
