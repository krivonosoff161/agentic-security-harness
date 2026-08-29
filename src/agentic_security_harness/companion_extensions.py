"""Explicit offline Extension SDK adapters for reviewed companion contracts.

The adapters consume normalized, digest-bound outputs from companion repositories. They
do not import companion packages, discover installed code, read raw handoff artifacts, or
turn guidance into enforcement. Cross-repository tests exercise the real producers and
then cross this narrow data boundary.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, NamedTuple, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_security_harness.extension_sdk import (
    EXTENSION_MANIFEST_V1,
    ExtensionContractRefV1,
    ExtensionFindingV1,
    ExtensionManifestV1,
    ExtensionObservationEnvelopeV1,
)
from agentic_security_harness.portfolio_contract import (
    GIT_OBJECT_PATTERN,
    PROJECT_ID_PATTERN,
    SHA256_PATTERN,
    CanonicalObservationEventV1,
)

COMPANION_PIN_V1: Final = "harness-companion-contract-pin-v1.0"
TRANSFER_EVIDENCE_V1: Final = "harness-transfer-verification-evidence-v1.0"
HANDOFF_EVIDENCE_V1: Final = "harness-handoff-metadata-evidence-v1.0"
PLAYBOOK_GUIDANCE_V1: Final = "harness-playbook-guidance-v1.0"
MAX_COMPANION_RECORDS: Final = 2_048
MAX_SOURCE_FINDINGS: Final = 512
MAX_SOURCE_PAYLOAD_BYTES: Final = 2_097_152
PLAYBOOK_GUIDANCE_SEMANTIC_SHA256: Final = (
    "db05510bc1fb7f3da0edd27851d911392f027207a0f40e8c19f6d5c806a99cae"
)
PORTFOLIO_OBSERVATION_REQUIRED_METADATA_V1: Final = (
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
)
_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9_.-]{0,127}$"
_VERSION_PATTERN = r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$"


class ReviewedCompanionSourceV1(NamedTuple):
    """Compiled source identity proven by the exact cross-repository CI contour."""

    component_id: str
    repository: str
    commit: str
    component_manifest_sha256: str
    contract_id: str
    contract_version: str
    contract_path: str
    contract_sha256: str


REVIEWED_COMPANION_SOURCES_V1: Final = (
    ReviewedCompanionSourceV1(
        component_id="agentic-transfer-verifier",
        repository="https://github.com/krivonosoff161/agentic-transfer-verifier",
        commit="f4f464a085734b3a9296d337ad87897954905e2a",
        component_manifest_sha256=(
            "bc547e9f24153effa559496716eec4592ac7ed29bb98916c819532ecdaba6b94"
        ),
        contract_id="transfer-verification-report",
        contract_version="0.1",
        contract_path="src/agentic_transfer_verifier/verifier.py",
        contract_sha256=(
            "7335162fcf546ac3927e8a2f2ccb35c7102eaa7d29be53d8a41389e513a70e3d"
        ),
    ),
    ReviewedCompanionSourceV1(
        component_id="ai-agent-handoff",
        repository="https://github.com/krivonosoff161/ai-agent-handoff",
        commit="46aba8284dd1a006bf9739edaa1c9d3212b7e735",
        component_manifest_sha256=(
            "8cef93d0efade9b9a10198118f69978b6a1482060f9820752653efe60a6792d6"
        ),
        contract_id="handoff-metadata",
        contract_version="1.0",
        contract_path="contracts/handoff-metadata.v1.schema.json",
        contract_sha256=(
            "d1015a42c31c260049d104b581c025556cb421fcdbf63af3fbac1f7eadb55f90"
        ),
    ),
    ReviewedCompanionSourceV1(
        component_id="llm-safety-playbooks",
        repository="https://github.com/krivonosoff161/llm-safety-playbooks",
        commit="190769a15a44f5a5af790b33fc37724e6417c27f",
        component_manifest_sha256=(
            "1f0acd74191514a7ccab3fabfeb831e40cba51cbac4b05a8654a1b32366b2186"
        ),
        contract_id="portfolio-observation-guidance",
        contract_version="1.0",
        contract_path="contracts/portfolio-observation-guidance.v1.json",
        contract_sha256=(
            "f87253b6a1e541ba8e05a2bdc844d70a13d3324975d4f28dd525574c2041de4e"
        ),
    ),
)


class CompanionExtensionError(ValueError):
    """Raised when a companion artifact cannot enter the Harness evidence boundary."""


class CompanionContractPinV1(BaseModel):
    """Exact reviewed source and contract identity for one companion adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-companion-contract-pin-v1.0"]
    component_id: str = Field(pattern=PROJECT_ID_PATTERN)
    source_commit: str = Field(pattern=GIT_OBJECT_PATTERN)
    component_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    contract_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    contract_version: str = Field(pattern=_VERSION_PATTERN)
    contract_sha256: str = Field(pattern=SHA256_PATTERN)
    contract_digest_semantics: Literal["sha256_lf_normalized_text_v1"]
    verification: Literal["exact_public_git_reviewed"]
    operational_authority: Literal["none"]


class TransferSourceFindingV1(BaseModel):
    """Sanitized structural finding from Transfer Verifier report V0.1."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(pattern=_IDENTIFIER_PATTERN)
    severity: Literal["low", "medium", "high"]


class TransferVerificationEvidenceV1(BaseModel):
    """Privacy-minimized binding from a Transfer report to its projected event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-transfer-verification-evidence-v1.0"]
    event_id: str = Field(pattern=SHA256_PATTERN)
    source_envelope_id_sha256: str = Field(pattern=SHA256_PATTERN)
    source_report_sha256: str = Field(pattern=SHA256_PATTERN)
    source_observation_sha256: str = Field(pattern=SHA256_PATTERN)
    report_status: Literal["PASS", "WARN", "FAIL"]
    findings: tuple[TransferSourceFindingV1, ...] = Field(
        max_length=MAX_SOURCE_FINDINGS
    )
    source_contract_sha256: str = Field(pattern=SHA256_PATTERN)
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _status_matches_findings(self) -> TransferVerificationEvidenceV1:
        expected = "PASS"
        if any(item.severity == "high" for item in self.findings):
            expected = "FAIL"
        elif self.findings:
            expected = "WARN"
        if self.report_status != expected:
            raise ValueError("transfer report status does not match finding severities")
        return self


class HandoffMetadataEvidenceV1(BaseModel):
    """Canonical handoff metadata only; raw task/session bytes never cross this boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-handoff-metadata-evidence-v1.0"]
    event_id: str = Field(pattern=SHA256_PATTERN)
    metadata_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact_kind: Literal["task", "session"]
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(strict=True, ge=0, le=1_000_000_000)
    created_at: str = Field(min_length=1, max_length=64)
    producer_id_hash: str = Field(pattern=SHA256_PATTERN)
    parent_artifact_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    source_contract_sha256: str = Field(pattern=SHA256_PATTERN)
    operational_authority: Literal["none"]

    @field_validator("created_at")
    @classmethod
    def _created_at_is_canonical(cls, value: str) -> str:
        _parse_canonical_utc_timestamp(value)
        return value

    @model_validator(mode="after")
    def _parent_matches_sequence(self) -> HandoffMetadataEvidenceV1:
        if (self.sequence == 0) != (self.parent_artifact_sha256 is None):
            raise ValueError("only the initial handoff sequence may omit its parent")
        return self


class PlaybookGuidanceConfigV1(BaseModel):
    """Exact machine-checkable subset of the human observation-review playbook."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-playbook-guidance-v1.0"]
    source_guidance_sha256: str = Field(pattern=SHA256_PATTERN)
    required_metadata: tuple[str, ...] = Field(min_length=1, max_length=64)
    missing_or_invalid_metadata_disposition: Literal["abstain"]
    allowed_human_dispositions: tuple[
        Literal["observe", "challenge", "escalate", "abstain"], ...
    ]
    forbidden_promotions: tuple[
        Literal[
            "authority",
            "capability",
            "consent",
            "authenticated_identity",
            "allow_receipt",
            "producer_attestation",
        ],
        ...,
    ]
    human_playbook_sha256: str = Field(pattern=SHA256_PATTERN)
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _guidance_is_complete(self) -> PlaybookGuidanceConfigV1:
        if len(self.required_metadata) != len(set(self.required_metadata)):
            raise ValueError("playbook required metadata must be unique")
        if self.allowed_human_dispositions != (
            "observe",
            "challenge",
            "escalate",
            "abstain",
        ):
            raise ValueError("playbook dispositions must remain the reviewed advisory set")
        required_promotions = {
            "authority",
            "capability",
            "consent",
            "authenticated_identity",
            "allow_receipt",
            "producer_attestation",
        }
        if set(self.forbidden_promotions) != required_promotions or len(
            self.forbidden_promotions
        ) != len(required_promotions):
            raise ValueError("playbook forbidden-promotion coverage drift")
        return self


class TransferVerifierExtensionV1:
    """Adapt exact Transfer Verifier reports into advisory Extension findings."""

    def __init__(
        self,
        *,
        pin: CompanionContractPinV1,
        evidence: tuple[TransferVerificationEvidenceV1, ...],
    ) -> None:
        _require_pin(pin, "agentic-transfer-verifier", "transfer-verification-report", "0.1")
        if any(item.source_contract_sha256 != pin.contract_sha256 for item in evidence):
            raise CompanionExtensionError("transfer evidence contract digest drift")
        self._evidence = _unique_by_event(evidence, "transfer evidence")
        self.manifest = _manifest(
            extension_id="agentic-transfer-verifier.verification",
            kind="check_extension",
            configuration={"pin": pin, "evidence": evidence},
        )

    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        findings: list[ExtensionFindingV1] = []
        for event in envelope.events:
            if not event.activity.startswith("transfer."):
                continue
            evidence = self._evidence.get(event.event_id)
            if evidence is None:
                findings.append(
                    _finding(
                        "transfer.verification",
                        event.event_id,
                        "inconclusive",
                        "medium",
                        "transfer.report_missing",
                    )
                )
                continue
            if evidence.source_observation_sha256 != hashlib.sha256(
                _canonical_bytes(event.model_dump(mode="json"))
            ).hexdigest():
                findings.append(
                    _finding(
                        "transfer.verification",
                        event.event_id,
                        "finding",
                        "high",
                        "transfer.observation_binding_drift",
                    )
                )
            else:
                severity = _highest_transfer_severity(evidence.findings)
                findings.append(
                    _finding(
                        "transfer.verification",
                        event.event_id,
                        "pass" if evidence.report_status == "PASS" else "finding",
                        severity,
                        f"transfer.report_{evidence.report_status.lower()}",
                    )
                )
        return tuple(findings) or (_no_matching_event("transfer.verification"),)


class HandoffMetadataExtensionV1:
    """Verify retained handoff metadata bindings without opening handoff bodies."""

    def __init__(
        self,
        *,
        pin: CompanionContractPinV1,
        evidence: tuple[HandoffMetadataEvidenceV1, ...],
    ) -> None:
        _require_pin(pin, "ai-agent-handoff", "handoff-metadata", "1.0")
        if any(item.source_contract_sha256 != pin.contract_sha256 for item in evidence):
            raise CompanionExtensionError("handoff evidence contract digest drift")
        self._evidence = _unique_by_event(evidence, "handoff evidence")
        self._validate_sequence(tuple(self._evidence.values()))
        self.manifest = _manifest(
            extension_id="ai-agent-handoff.metadata",
            kind="check_extension",
            configuration={"pin": pin, "evidence": evidence},
        )

    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        findings: list[ExtensionFindingV1] = []
        previous_event_id: str | None = None
        for event in envelope.events:
            if event.activity not in {"handoff.task", "handoff.session"}:
                continue
            evidence = self._evidence.get(event.event_id)
            reason = "handoff.metadata_bound"
            outcome: Literal["pass", "finding", "inconclusive", "error"] = "pass"
            severity: Literal["none", "low", "medium", "high", "critical"] = "none"
            if evidence is None:
                outcome, severity, reason = (
                    "inconclusive",
                    "medium",
                    "handoff.metadata_missing",
                )
            elif (
                event.activity != f"handoff.{evidence.artifact_kind}"
                or event.producer_id_hash != evidence.producer_id_hash
                or event.occurred_at.isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                )
                != evidence.created_at
                or len(event.entity_refs) != 1
                or event.entity_refs[0].kind != "artifact"
                or event.entity_refs[0].digest != evidence.artifact_sha256
                or event.entity_refs[0].locator_id
                != _domain_digest(
                    "ai-agent-handoff/artifact-locator",
                    (
                        f"{evidence.artifact_kind}:{evidence.sequence}:"
                        f"{evidence.artifact_sha256}:{evidence.producer_id_hash}"
                    ),
                )
                or event.parent_event_ids
                != (() if evidence.sequence == 0 else (previous_event_id,))
            ):
                outcome, severity, reason = (
                    "finding",
                    "high",
                    "handoff.metadata_binding_drift",
                )
            findings.append(
                _finding(
                    "handoff.metadata",
                    event.event_id,
                    outcome,
                    severity,
                    reason,
                )
            )
            previous_event_id = event.event_id
        return tuple(findings) or (_no_matching_event("handoff.metadata"),)

    @staticmethod
    def _validate_sequence(evidence: tuple[HandoffMetadataEvidenceV1, ...]) -> None:
        if not evidence:
            raise CompanionExtensionError("handoff evidence must not be empty")
        ordered = sorted(evidence, key=lambda item: item.sequence)
        for index, item in enumerate(ordered):
            if item.sequence != index:
                raise CompanionExtensionError("handoff evidence sequence is not contiguous")
            if index and item.parent_artifact_sha256 != ordered[index - 1].artifact_sha256:
                raise CompanionExtensionError("handoff evidence parent binding drift")
            if index and item.artifact_kind != ordered[index - 1].artifact_kind:
                raise CompanionExtensionError("handoff artifact kind changed in sequence")
            if index and item.producer_id_hash != ordered[index - 1].producer_id_hash:
                raise CompanionExtensionError("handoff producer changed in sequence")
            if index and item.artifact_sha256 == ordered[index - 1].artifact_sha256:
                raise CompanionExtensionError("handoff artifact digest replay detected")
            if index and _parse_canonical_utc_timestamp(
                item.created_at
            ) <= _parse_canonical_utc_timestamp(ordered[index - 1].created_at):
                raise CompanionExtensionError("handoff timestamp rollback detected")


class PlaybookGuidanceExtensionV1:
    """Emit review advisories; a playbook never produces an allow or enforcement effect."""

    def __init__(
        self,
        *,
        pin: CompanionContractPinV1,
        guidance: PlaybookGuidanceConfigV1,
    ) -> None:
        _require_pin(
            pin,
            "llm-safety-playbooks",
            "portfolio-observation-guidance",
            "1.0",
        )
        if guidance.source_guidance_sha256 != pin.contract_sha256:
            raise CompanionExtensionError("playbook guidance contract digest drift")
        self._guidance = guidance
        self.manifest = _manifest(
            extension_id="llm-safety-playbooks.observation-review",
            kind="declarative_pack",
            configuration={"pin": pin, "guidance": guidance},
        )

    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        findings: list[ExtensionFindingV1] = []
        for event in envelope.events:
            if event.telemetry_state == "complete":
                outcome: Literal["pass", "finding", "inconclusive", "error"] = (
                    "inconclusive"
                )
                severity: Literal["none", "low", "medium", "high", "critical"] = "none"
                reason = "playbook.human_review_required"
            else:
                outcome, severity, reason = (
                    "finding",
                    "medium",
                    "playbook.telemetry_incomplete",
                )
            findings.append(
                _finding(
                    "playbook.observation_review",
                    event.event_id,
                    outcome,
                    severity,
                    reason,
                )
            )
        return tuple(findings)


def build_transfer_verification_evidence_v1(
    report: Mapping[str, object],
    observation: Mapping[str, object],
    *,
    source_contract_sha256: str,
) -> TransferVerificationEvidenceV1:
    """Normalize exact Transfer VerificationReport V0.1 data without retaining messages."""

    _require_exact_fields(
        report,
        {"schema_version", "envelope_id", "status", "findings"},
        "transfer report",
    )
    if report["schema_version"] != "0.1":
        raise CompanionExtensionError("unsupported transfer report schema")
    envelope_id = _required_string(report, "envelope_id", max_length=512)
    try:
        source_observation = CanonicalObservationEventV1.model_validate(observation)
    except ValueError as exc:
        raise CompanionExtensionError("transfer observation violates canonical V1") from exc
    expected_event_id = _domain_digest(
        "agentic-transfer-verifier/transfer-envelope-id", envelope_id
    )
    if (
        source_observation.event_id != expected_event_id
        or not source_observation.activity.startswith("transfer.")
    ):
        raise CompanionExtensionError("transfer report does not bind its observation")
    status = report["status"]
    if status not in {"PASS", "WARN", "FAIL"}:
        raise CompanionExtensionError("unsupported transfer report status")
    raw_findings = report["findings"]
    if not isinstance(raw_findings, list) or len(raw_findings) > MAX_SOURCE_FINDINGS:
        raise CompanionExtensionError("transfer findings exceed the supported shape")
    sanitized: list[TransferSourceFindingV1] = []
    for raw in raw_findings:
        if not isinstance(raw, Mapping):
            raise CompanionExtensionError("transfer finding must be an object")
        _require_exact_fields(raw, {"code", "severity", "message"}, "transfer finding")
        if not isinstance(raw["message"], str):
            raise CompanionExtensionError("transfer finding message must be text")
        sanitized.append(
            TransferSourceFindingV1(
                code=_required_string(raw, "code", max_length=128),
                severity=raw["severity"],
            )
        )
    report_bytes = _canonical_bytes(report)
    return TransferVerificationEvidenceV1(
        schema_version=TRANSFER_EVIDENCE_V1,
        event_id=expected_event_id,
        source_envelope_id_sha256=hashlib.sha256(envelope_id.encode("utf-8")).hexdigest(),
        source_report_sha256=hashlib.sha256(report_bytes).hexdigest(),
        source_observation_sha256=hashlib.sha256(
            _canonical_bytes(source_observation.model_dump(mode="json"))
        ).hexdigest(),
        report_status=cast(Literal["PASS", "WARN", "FAIL"], status),
        findings=tuple(sanitized),
        source_contract_sha256=source_contract_sha256,
        operational_authority="none",
    )


def build_handoff_metadata_evidence_v1(
    metadata: Mapping[str, object],
    *,
    source_contract_sha256: str,
) -> HandoffMetadataEvidenceV1:
    """Normalize exact HandoffMetadataV1 data; artifact bytes are not accepted."""

    required = {
        "schema_version",
        "artifact_kind",
        "artifact_sha256",
        "sequence",
        "created_at",
        "producer_id_hash",
        "parent_artifact_sha256",
    }
    _require_exact_fields(metadata, required, "handoff metadata")
    if metadata["schema_version"] != "handoff-metadata-v1.0":
        raise CompanionExtensionError("unsupported handoff metadata schema")
    body = _canonical_bytes(metadata)
    event_body = {
        "metadata": metadata,
        "projection_schema": "portfolio-observation-v1.0",
    }
    return HandoffMetadataEvidenceV1(
        schema_version=HANDOFF_EVIDENCE_V1,
        event_id=hashlib.sha256(
            b"ai-agent-handoff/event-id/v1\0" + _canonical_bytes(event_body)
        ).hexdigest(),
        metadata_sha256=hashlib.sha256(body).hexdigest(),
        artifact_kind=metadata["artifact_kind"],  # type: ignore[arg-type]
        artifact_sha256=_required_string(metadata, "artifact_sha256", max_length=64),
        sequence=metadata["sequence"],  # type: ignore[arg-type]
        created_at=_required_string(metadata, "created_at", max_length=64),
        producer_id_hash=_required_string(metadata, "producer_id_hash", max_length=64),
        parent_artifact_sha256=metadata["parent_artifact_sha256"],  # type: ignore[arg-type]
        source_contract_sha256=source_contract_sha256,
        operational_authority="none",
    )


def build_playbook_guidance_config_v1(
    guidance: Mapping[str, object],
    *,
    source_contract_sha256: str,
) -> PlaybookGuidanceConfigV1:
    """Normalize the exact public guidance contract into an executable advisory config."""

    required = {
        "schema_version",
        "contract_id",
        "owner_pin_path",
        "guidance_mode",
        "required_metadata",
        "missing_or_invalid_metadata_disposition",
        "allowed_human_dispositions",
        "forbidden_promotions",
        "authority_envelope_interpretation",
        "producer_attestation_interpretation",
        "human_playbook_path",
        "human_playbook_sha256",
        "operational_authority",
    }
    _require_exact_fields(guidance, required, "playbook guidance")
    if (
        hashlib.sha256(_canonical_bytes(guidance)).hexdigest()
        != PLAYBOOK_GUIDANCE_SEMANTIC_SHA256
    ):
        raise CompanionExtensionError("playbook guidance semantic contract drift")
    required_metadata = _string_tuple(guidance, "required_metadata")
    if (
        guidance["schema_version"] != "portfolio-observation-guidance-v1.0"
        or guidance["contract_id"] != "portfolio-observation-v1.0"
        or guidance["owner_pin_path"]
        != "contracts/portfolio-observation.v1.owner-pin.json"
        or guidance["guidance_mode"] != "human_guidance_only"
        or required_metadata != PORTFOLIO_OBSERVATION_REQUIRED_METADATA_V1
        or guidance["authority_envelope_interpretation"] != "evidence_pointer_only"
        or guidance["producer_attestation_interpretation"] != "unattested_only"
        or guidance["human_playbook_path"]
        != "playbooks/canonical-observation-review.md"
        or guidance["operational_authority"] != "none"
    ):
        raise CompanionExtensionError("playbook guidance exceeds the advisory V1 boundary")
    return PlaybookGuidanceConfigV1(
        schema_version=PLAYBOOK_GUIDANCE_V1,
        source_guidance_sha256=source_contract_sha256,
        required_metadata=required_metadata,
        missing_or_invalid_metadata_disposition=guidance[
            "missing_or_invalid_metadata_disposition"
        ],  # type: ignore[arg-type]
        allowed_human_dispositions=_string_tuple(
            guidance, "allowed_human_dispositions"
        ),  # type: ignore[arg-type]
        forbidden_promotions=_string_tuple(
            guidance, "forbidden_promotions"
        ),  # type: ignore[arg-type]
        human_playbook_sha256=_required_string(
            guidance, "human_playbook_sha256", max_length=64
        ),
        operational_authority="none",
    )


def companion_extension_v1_json_schemas() -> dict[str, dict[str, Any]]:
    """Return the closed public schemas for the reviewed companion boundary."""

    models: dict[str, type[BaseModel]] = {
        "companion-contract-pin.v1.schema.json": CompanionContractPinV1,
        "transfer-verification-evidence.v1.schema.json": (
            TransferVerificationEvidenceV1
        ),
        "handoff-metadata-evidence.v1.schema.json": HandoffMetadataEvidenceV1,
        "playbook-guidance-config.v1.schema.json": PlaybookGuidanceConfigV1,
    }
    return {name: model.model_json_schema() for name, model in models.items()}


def reviewed_companion_sources_v1() -> tuple[dict[str, str], ...]:
    """Return a detached JSON-ready copy of the compiled reviewed source registry."""

    return tuple(row._asdict() for row in REVIEWED_COMPANION_SOURCES_V1)


def _manifest(
    *,
    extension_id: str,
    kind: Literal["check_extension", "declarative_pack"],
    configuration: object,
) -> ExtensionManifestV1:
    return ExtensionManifestV1(
        schema_version=EXTENSION_MANIFEST_V1,
        extension_id=extension_id,
        extension_version="1.0.0",
        component_id="agentic-security-harness",
        implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        configuration_sha256=_domain_object_digest(
            "agentic-security-harness/companion-extension-configuration/v1.0",
            configuration,
        ),
        harness_api="1",
        kind=kind,
        capabilities=("observation.read", "finding.emit"),
        consumes=(
            ExtensionContractRefV1(
                contract_id="portfolio-observation", version="1.0", required=True
            ),
        ),
        produces=(
            ExtensionContractRefV1(
                contract_id="extension-finding", version="1.0", required=True
            ),
        ),
        deterministic=True,
        evidence_provenance="producer_declared",
        network_mode="off",
        raw_data_policy="digests_only",
        execution_model="in_process_operator_approved_not_sandboxed",
        operational_authority="none",
    )


def _require_pin(
    pin: CompanionContractPinV1,
    component_id: str,
    contract_id: str,
    contract_version: str,
) -> None:
    reviewed = next(
        (
            row
            for row in REVIEWED_COMPANION_SOURCES_V1
            if row.component_id == component_id
            and row.contract_id == contract_id
            and row.contract_version == contract_version
        ),
        None,
    )
    if reviewed is None or (
        pin.component_id,
        pin.source_commit,
        pin.component_manifest_sha256,
        pin.contract_id,
        pin.contract_version,
        pin.contract_sha256,
    ) != (
        reviewed.component_id,
        reviewed.commit,
        reviewed.component_manifest_sha256,
        reviewed.contract_id,
        reviewed.contract_version,
        reviewed.contract_sha256,
    ):
        raise CompanionExtensionError("companion contract pin does not match the adapter")


def _unique_by_event(
    evidence: Sequence[TransferVerificationEvidenceV1 | HandoffMetadataEvidenceV1],
    label: str,
) -> dict[str, Any]:
    if not evidence or len(evidence) > MAX_COMPANION_RECORDS:
        raise CompanionExtensionError(f"{label} count is outside the V1 limit")
    result = {item.event_id: item for item in evidence}
    if len(result) != len(evidence):
        raise CompanionExtensionError(f"{label} event ids must be unique")
    return result


def _highest_transfer_severity(
    findings: tuple[TransferSourceFindingV1, ...],
) -> Literal["none", "low", "medium", "high", "critical"]:
    if not findings:
        return "none"
    rank = {"low": 1, "medium": 2, "high": 3}
    return max((item.severity for item in findings), key=rank.__getitem__)


def _finding(
    namespace: str,
    event_id: str,
    outcome: Literal["pass", "finding", "inconclusive", "error"],
    severity: Literal["none", "low", "medium", "high", "critical"],
    reason_code: str,
) -> ExtensionFindingV1:
    return ExtensionFindingV1(
        check_id=f"{namespace}.{event_id}",
        outcome=outcome,
        severity=severity,
        reason_code=reason_code,
        evidence_event_ids=(event_id,),
    )


def _no_matching_event(namespace: str) -> ExtensionFindingV1:
    return ExtensionFindingV1(
        check_id=f"{namespace}.scope",
        outcome="inconclusive",
        severity="none",
        reason_code="scope.no_matching_events",
        evidence_event_ids=(),
    )


def _require_exact_fields(
    value: Mapping[str, object], expected: set[str], label: str
) -> None:
    if set(value) != expected:
        raise CompanionExtensionError(f"{label} fields do not match the reviewed contract")


def _required_string(
    value: Mapping[str, object], field: str, *, max_length: int
) -> str:
    candidate = value[field]
    if not isinstance(candidate, str) or not candidate or len(candidate) > max_length:
        raise CompanionExtensionError(f"{field} is not a bounded required string")
    return candidate


def _string_tuple(value: Mapping[str, object], field: str) -> tuple[str, ...]:
    candidate = value[field]
    if (
        not isinstance(candidate, list)
        or len(candidate) > 64
        or any(not isinstance(item, str) for item in candidate)
    ):
        raise CompanionExtensionError(f"{field} must be a bounded string list")
    return tuple(candidate)


def _canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            default=_json_default,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CompanionExtensionError("companion value is not canonical JSON data") from exc
    if len(encoded) > MAX_SOURCE_PAYLOAD_BYTES:
        raise CompanionExtensionError("companion value exceeds the V1 byte limit")
    return encoded


def _json_default(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"unsupported canonical JSON type: {type(value).__name__}")


def _domain_digest(domain: str, value: str) -> str:
    return hashlib.sha256(f"{domain}\0{value}".encode()).hexdigest()


def _domain_object_digest(domain: str, value: object) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + _canonical_bytes(value)).hexdigest()


def _parse_canonical_utc_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("handoff timestamp is not canonical UTC") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.astimezone(UTC).isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
        != value
        or parsed.year < 1970
        or parsed.astimezone(UTC) > datetime(2100, 1, 1, tzinfo=UTC)
    ):
        raise ValueError("handoff timestamp is not canonical UTC")
    return parsed.astimezone(UTC)
