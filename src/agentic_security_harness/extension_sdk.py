"""Closed, authority-free Extension SDK V1 contracts and offline runner.

The SDK deliberately separates an executable dataflow contract from installed-code
discovery.  Extensions are registered explicitly by the operator or embedding process;
this module never scans entry points, imports arbitrary packages, opens the network, or
claims that in-process Python code is sandboxed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.portfolio_contract import (
    PROJECT_ID_PATTERN,
    SHA256_PATTERN,
    CanonicalObservationEventV1,
    ObservationCommitmentV1,
    commit_portfolio_observation_v1,
    encode_portfolio_observation_v1,
)
from agentic_security_harness.safe_io import is_link_or_reparse

EXTENSION_MANIFEST_V1: Final = "harness-extension-manifest-v1.0"
EXTENSION_ENVELOPE_V1: Final = "harness-extension-envelope-v1.0"
EXTENSION_RESULT_V1: Final = "harness-extension-result-v1.0"
EXTENSION_RUN_RECEIPT_V1: Final = "harness-extension-run-receipt-v1.0"
EXTENSION_PIPELINE_RECEIPT_V1: Final = "harness-extension-pipeline-receipt-v1.0"
MAX_EXTENSION_EVENTS = 2_048
MAX_EXTENSION_FINDINGS = 512
MAX_EXTENSION_CHAIN = 32
MAX_EXTENSION_PAYLOAD_BYTES = 2_097_152
_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9_.-]{0,127}$"
_VERSION_PATTERN = r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$"

ExtensionKind = Literal[
    "check_extension",
    "declarative_pack",
    "support_adapter",
    "collector",
    "reporter",
]
ExtensionCapability = Literal[
    "observation.read",
    "finding.emit",
    "policy.evaluate",
    "observation.transform",
    "intelligence.collect",
    "report.enrich",
]
ExtensionOutcome = Literal["pass", "finding", "inconclusive", "error"]
ExtensionSeverity = Literal["none", "low", "medium", "high", "critical"]
ExtensionEvidenceClass = Literal[
    "deterministic_rule",
    "heuristic_unreviewed",
    "producer_declared",
    "external_unreviewed",
]


class ExtensionContractError(ValueError):
    """Raised when an extension or its bytes violate the closed V1 contract."""


class ExtensionContractRefV1(BaseModel):
    """One exact data contract consumed or produced by an extension."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    version: str = Field(pattern=_VERSION_PATTERN)
    required: bool


class ExtensionManifestV1(BaseModel):
    """Closed metadata for explicitly registered, non-sandboxed extension code."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-extension-manifest-v1.0"]
    extension_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    extension_version: str = Field(pattern=_VERSION_PATTERN)
    component_id: str = Field(pattern=PROJECT_ID_PATTERN)
    implementation_sha256: str = Field(pattern=SHA256_PATTERN)
    configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    harness_api: Literal["1"]
    kind: ExtensionKind
    capabilities: tuple[ExtensionCapability, ...] = Field(min_length=1, max_length=16)
    consumes: tuple[ExtensionContractRefV1, ...] = Field(min_length=1, max_length=32)
    produces: tuple[ExtensionContractRefV1, ...] = Field(min_length=1, max_length=32)
    deterministic: bool
    network_mode: Literal["off", "local_only", "authorized_external"]
    raw_data_policy: Literal["digests_only"]
    execution_model: Literal["in_process_operator_approved_not_sandboxed"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_manifest(self) -> ExtensionManifestV1:
        if len(self.capabilities) != len(set(self.capabilities)):
            raise ValueError("extension capabilities must be unique")
        for label, contracts in (("consumes", self.consumes), ("produces", self.produces)):
            identities = tuple((item.contract_id, item.version) for item in contracts)
            if len(identities) != len(set(identities)):
                raise ValueError(f"extension {label} contracts must be unique")
        if "observation.read" not in self.capabilities:
            raise ValueError("V1 extensions must declare observation.read")
        if not any(
            item.contract_id == "portfolio-observation" and item.version == "1.0"
            for item in self.consumes
        ):
            raise ValueError("V1 extensions must consume portfolio-observation 1.0")
        if "finding.emit" not in self.capabilities:
            raise ValueError("V1 extensions must declare finding.emit")
        if not any(
            item.contract_id == "extension-finding" and item.version == "1.0"
            for item in self.produces
        ):
            raise ValueError("V1 extensions must produce extension-finding 1.0")
        if self.deterministic and self.network_mode != "off":
            raise ValueError("deterministic extensions must keep network_mode off")
        return self


class ExtensionObservationEnvelopeV1(BaseModel):
    """Self-contained ordered observation graph passed between extensions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-extension-envelope-v1.0"]
    envelope_id: str = Field(pattern=SHA256_PATTERN)
    source_component_id: str = Field(pattern=PROJECT_ID_PATTERN)
    source_commitment_sha256: str = Field(pattern=SHA256_PATTERN)
    events: tuple[CanonicalObservationEventV1, ...] = Field(
        min_length=1, max_length=MAX_EXTENSION_EVENTS
    )
    event_commitments: tuple[ObservationCommitmentV1, ...] = Field(
        min_length=1, max_length=MAX_EXTENSION_EVENTS
    )
    extension_chain: tuple[str, ...] = Field(max_length=MAX_EXTENSION_CHAIN)
    verdict_semantics: Literal["observation_only_no_security_verdict"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_envelope(self) -> ExtensionObservationEnvelopeV1:
        if len(self.events) != len(self.event_commitments):
            raise ValueError("every extension event requires one commitment")
        if len(self.extension_chain) != len(set(self.extension_chain)):
            raise ValueError("an extension cannot occur twice in one V1 chain")
        if any(
            not re.fullmatch(_IDENTIFIER_PATTERN, item) for item in self.extension_chain
        ):
            raise ValueError("extension chain ids must be canonical tokens")

        seen: set[str] = set()
        identity: tuple[str, str, str] | None = None
        previous_time = None
        for event, commitment in zip(self.events, self.event_commitments, strict=True):
            current_identity = (event.project_id, event.repository_id, event.repository_sha)
            if identity is None:
                identity = current_identity
            elif current_identity != identity:
                raise ValueError("extension events must share one repository identity")
            if event.event_id in seen:
                raise ValueError("extension event ids must be unique")
            if any(parent not in seen for parent in event.parent_event_ids):
                raise ValueError("extension parents must precede their child")
            if previous_time is not None and event.occurred_at < previous_time:
                raise ValueError("extension events must be ordered by occurred_at")
            if commitment != commit_portfolio_observation_v1(event):
                raise ValueError("extension event commitment drift")
            seen.add(event.event_id)
            previous_time = event.occurred_at
        if self.envelope_id != _envelope_identity(self):
            raise ValueError("envelope_id does not bind the extension envelope")
        return self


class ExtensionFindingV1(BaseModel):
    """One advisory observation emitted by an extension; it cannot allow an action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    check_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    outcome: ExtensionOutcome
    severity: ExtensionSeverity
    reason_code: str = Field(pattern=_IDENTIFIER_PATTERN)
    evidence_event_ids: tuple[str, ...] = Field(max_length=MAX_EXTENSION_EVENTS)

    @model_validator(mode="after")
    def _validate_finding(self) -> ExtensionFindingV1:
        if len(self.evidence_event_ids) != len(set(self.evidence_event_ids)):
            raise ValueError("finding evidence ids must be unique")
        if any(not re.fullmatch(SHA256_PATTERN, item) for item in self.evidence_event_ids):
            raise ValueError("finding evidence ids must be lowercase SHA-256")
        if self.outcome == "pass" and self.severity != "none":
            raise ValueError("pass findings must use severity none")
        if self.outcome == "finding" and self.severity == "none":
            raise ValueError("security findings require a non-none severity")
        return self


class ExtensionResultV1(BaseModel):
    """Content-bound result from one explicit extension invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-extension-result-v1.0"]
    result_id: str = Field(pattern=SHA256_PATTERN)
    extension_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    extension_version: str = Field(pattern=_VERSION_PATTERN)
    extension_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    input_envelope_id: str = Field(pattern=SHA256_PATTERN)
    input_envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    findings: tuple[ExtensionFindingV1, ...] = Field(
        min_length=1, max_length=MAX_EXTENSION_FINDINGS
    )
    evidence_class: ExtensionEvidenceClass
    verdict_semantics: Literal["advisory_only_no_operational_effect"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_result(self) -> ExtensionResultV1:
        check_ids = tuple(item.check_id for item in self.findings)
        if len(check_ids) != len(set(check_ids)):
            raise ValueError("extension finding check ids must be unique")
        if self.result_id != _result_identity(self):
            raise ValueError("result_id does not bind the extension result")
        return self


class ExtensionRunReceiptV1(BaseModel):
    """One input/result/output transition in the extension pipeline."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-extension-run-receipt-v1.0"]
    receipt_id: str = Field(pattern=SHA256_PATTERN)
    input_envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    result: ExtensionResultV1
    output_envelope: ExtensionObservationEnvelopeV1
    execution_semantics: Literal["explicit_in_process_not_sandboxed"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_receipt(self) -> ExtensionRunReceiptV1:
        if self.result.input_envelope_sha256 != self.input_envelope_sha256:
            raise ValueError("run receipt input digest drift")
        if not self.output_envelope.extension_chain:
            raise ValueError("run receipt output must extend the chain")
        if self.output_envelope.extension_chain[-1] != self.result.extension_id:
            raise ValueError("run receipt output chain does not bind the extension")
        if self.receipt_id != _run_receipt_identity(self):
            raise ValueError("receipt_id does not bind the extension run")
        return self


class ExtensionPipelineReceiptV1(BaseModel):
    """Ordered content-bound receipt for a complete extension pipeline."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-extension-pipeline-receipt-v1.0"]
    pipeline_id: str = Field(pattern=SHA256_PATTERN)
    input_envelope_id: str = Field(pattern=SHA256_PATTERN)
    final_envelope_id: str = Field(pattern=SHA256_PATTERN)
    runs: tuple[ExtensionRunReceiptV1, ...] = Field(
        min_length=1, max_length=MAX_EXTENSION_CHAIN
    )
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_pipeline(self) -> ExtensionPipelineReceiptV1:
        if self.runs[0].result.input_envelope_id != self.input_envelope_id:
            raise ValueError("pipeline does not bind its first input")
        if self.runs[-1].output_envelope.envelope_id != self.final_envelope_id:
            raise ValueError("pipeline does not bind its final envelope")
        for previous, current in zip(self.runs, self.runs[1:], strict=False):
            if current.result.input_envelope_id != previous.output_envelope.envelope_id:
                raise ValueError("pipeline run chain is discontinuous")
        if self.pipeline_id != _pipeline_identity(self):
            raise ValueError("pipeline_id does not bind the ordered runs")
        return self


class ExtensionV1(Protocol):
    """Structural protocol for explicitly registered V1 extension code."""

    manifest: ExtensionManifestV1

    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]: ...


class StaticExtensionRegistryV1:
    """Explicit in-memory registry; it performs no package discovery or code loading."""

    def __init__(self, extensions: tuple[ExtensionV1, ...] = ()) -> None:
        self._extensions: dict[str, ExtensionV1] = {}
        for extension in extensions:
            self.register(extension)

    def register(self, extension: ExtensionV1) -> None:
        manifest = _validated_extension_manifest(extension)
        if manifest.extension_id in self._extensions:
            raise ExtensionContractError("extension id is already registered")
        if not callable(getattr(extension, "evaluate", None)):
            raise ExtensionContractError("extension does not implement evaluate")
        self._extensions[manifest.extension_id] = extension

    def get(self, extension_id: str) -> ExtensionV1:
        try:
            return self._extensions[extension_id]
        except KeyError as exc:
            raise ExtensionContractError("extension id is not registered") from exc

    def manifests(self) -> tuple[ExtensionManifestV1, ...]:
        return tuple(
            self._extensions[item].manifest for item in sorted(self._extensions)
        )


def build_extension_envelope_v1(
    *,
    source_component_id: str,
    source_commitment_sha256: str,
    events: tuple[CanonicalObservationEventV1, ...],
    extension_chain: tuple[str, ...] = (),
) -> ExtensionObservationEnvelopeV1:
    """Build a self-contained envelope from existing canonical observations."""

    commitments = tuple(commit_portfolio_observation_v1(event) for event in events)
    provisional = ExtensionObservationEnvelopeV1.model_construct(
        schema_version=EXTENSION_ENVELOPE_V1,
        envelope_id="0" * 64,
        source_component_id=source_component_id,
        source_commitment_sha256=source_commitment_sha256,
        events=events,
        event_commitments=commitments,
        extension_chain=extension_chain,
        verdict_semantics="observation_only_no_security_verdict",
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["envelope_id"] = _envelope_identity(provisional)
    return ExtensionObservationEnvelopeV1.model_validate(payload)


def encode_extension_manifest_v1(manifest: ExtensionManifestV1) -> bytes:
    return _bounded_canonical_bytes(manifest.model_dump(mode="json"), "manifest")


def decode_extension_manifest_v1(payload: bytes) -> ExtensionManifestV1:
    """Decode exact canonical manifest bytes; duplicate or unknown fields fail closed."""

    decoded = _decode_json_object(payload, "manifest")
    if set(decoded) != set(ExtensionManifestV1.model_fields):
        raise ExtensionContractError("extension manifest fields do not match V1")
    try:
        manifest = ExtensionManifestV1.model_validate(decoded)
    except ValueError as exc:
        raise ExtensionContractError("extension manifest values violate V1") from exc
    if encode_extension_manifest_v1(manifest) != payload:
        raise ExtensionContractError("extension manifest JSON is not canonical V1")
    return manifest


def read_extension_manifest_v1(path: Path) -> ExtensionManifestV1:
    """Read one stable regular manifest without following links or reparse points."""

    candidate = path.absolute()
    _require_safe_manifest_path(candidate)
    before = candidate.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ExtensionContractError("extension manifest must be a regular single-link file")
    if before.st_size <= 0 or before.st_size > MAX_EXTENSION_PAYLOAD_BYTES:
        raise ExtensionContractError("extension manifest size is outside the V1 limit")
    payload = candidate.read_bytes()
    after = candidate.lstat()
    _require_safe_manifest_path(candidate)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise ExtensionContractError("extension manifest changed while it was read")
    return decode_extension_manifest_v1(payload)


def encode_extension_envelope_v1(envelope: ExtensionObservationEnvelopeV1) -> bytes:
    payload = envelope.model_dump(mode="json")
    payload["events"] = [
        json.loads(encode_portfolio_observation_v1(event)) for event in envelope.events
    ]
    return _bounded_canonical_bytes(payload, "envelope")


def extension_manifest_sha256(manifest: ExtensionManifestV1) -> str:
    return hashlib.sha256(encode_extension_manifest_v1(manifest)).hexdigest()


def run_extension_v1(
    extension: ExtensionV1,
    envelope: ExtensionObservationEnvelopeV1,
) -> ExtensionRunReceiptV1:
    """Run one explicit extension over an isolated copy and verify all bindings."""

    manifest = _validated_extension_manifest(extension)
    if manifest.extension_id in envelope.extension_chain:
        raise ExtensionContractError("extension already appears in this pipeline chain")
    isolated = ExtensionObservationEnvelopeV1.model_validate(
        envelope.model_dump(mode="python")
    )
    input_bytes = encode_extension_envelope_v1(isolated)
    try:
        raw_findings = extension.evaluate(isolated)
    except Exception as exc:
        raise ExtensionContractError("extension evaluation failed") from exc
    if _validated_extension_manifest(extension) != manifest:
        raise ExtensionContractError("extension manifest changed during evaluation")
    if encode_extension_envelope_v1(isolated) != input_bytes:
        raise ExtensionContractError("extension mutated its isolated input envelope")
    if not isinstance(raw_findings, tuple):
        raise ExtensionContractError("extension findings must be a tuple")
    if not raw_findings or len(raw_findings) > MAX_EXTENSION_FINDINGS:
        raise ExtensionContractError("extension finding count is outside the V1 limit")
    try:
        findings = tuple(ExtensionFindingV1.model_validate(item) for item in raw_findings)
    except ValueError as exc:
        raise ExtensionContractError("extension findings violate V1") from exc
    known_events = {event.event_id for event in envelope.events}
    if any(
        event_id not in known_events
        for finding in findings
        for event_id in finding.evidence_event_ids
    ):
        raise ExtensionContractError("extension finding references an unknown event")

    input_sha256 = hashlib.sha256(input_bytes).hexdigest()
    result = _build_result(manifest, envelope, input_sha256, findings)
    output = build_extension_envelope_v1(
        source_component_id=envelope.source_component_id,
        source_commitment_sha256=envelope.source_commitment_sha256,
        events=envelope.events,
        extension_chain=(*envelope.extension_chain, manifest.extension_id),
    )
    provisional = ExtensionRunReceiptV1.model_construct(
        schema_version=EXTENSION_RUN_RECEIPT_V1,
        receipt_id="0" * 64,
        input_envelope_sha256=input_sha256,
        result=result,
        output_envelope=output,
        execution_semantics="explicit_in_process_not_sandboxed",
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["receipt_id"] = _run_receipt_identity(provisional)
    return ExtensionRunReceiptV1.model_validate(payload)


def run_extension_pipeline_v1(
    registry: StaticExtensionRegistryV1,
    extension_ids: tuple[str, ...],
    envelope: ExtensionObservationEnvelopeV1,
) -> ExtensionPipelineReceiptV1:
    """Run an explicit ordered extension list; there is no implicit discovery."""

    if not extension_ids or len(extension_ids) > MAX_EXTENSION_CHAIN:
        raise ExtensionContractError("pipeline extension count is outside the V1 limit")
    if len(extension_ids) != len(set(extension_ids)):
        raise ExtensionContractError("pipeline extension ids must be unique")
    current = envelope
    receipts: list[ExtensionRunReceiptV1] = []
    for extension_id in extension_ids:
        receipt = run_extension_v1(registry.get(extension_id), current)
        receipts.append(receipt)
        current = receipt.output_envelope
    provisional = ExtensionPipelineReceiptV1.model_construct(
        schema_version=EXTENSION_PIPELINE_RECEIPT_V1,
        pipeline_id="0" * 64,
        input_envelope_id=envelope.envelope_id,
        final_envelope_id=current.envelope_id,
        runs=tuple(receipts),
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["pipeline_id"] = _pipeline_identity(provisional)
    return ExtensionPipelineReceiptV1.model_validate(payload)


def extension_v1_json_schemas() -> dict[str, dict[str, Any]]:
    """Return the closed public JSON Schemas for the V1 interchange surface."""

    return {
        "extension-manifest.v1.schema.json": ExtensionManifestV1.model_json_schema(),
        "extension-envelope.v1.schema.json": ExtensionObservationEnvelopeV1.model_json_schema(),
        "extension-result.v1.schema.json": ExtensionResultV1.model_json_schema(),
        "extension-run-receipt.v1.schema.json": ExtensionRunReceiptV1.model_json_schema(),
        "extension-pipeline-receipt.v1.schema.json": ExtensionPipelineReceiptV1.model_json_schema(),
    }


def _validated_extension_manifest(extension: ExtensionV1) -> ExtensionManifestV1:
    try:
        manifest = extension.manifest
        if not isinstance(manifest, ExtensionManifestV1):
            raise TypeError("manifest is not ExtensionManifestV1")
        return ExtensionManifestV1.model_validate(manifest.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExtensionContractError("extension manifest violates V1") from exc


def _build_result(
    manifest: ExtensionManifestV1,
    envelope: ExtensionObservationEnvelopeV1,
    input_sha256: str,
    findings: tuple[ExtensionFindingV1, ...],
) -> ExtensionResultV1:
    provisional = ExtensionResultV1.model_construct(
        schema_version=EXTENSION_RESULT_V1,
        result_id="0" * 64,
        extension_id=manifest.extension_id,
        extension_version=manifest.extension_version,
        extension_manifest_sha256=extension_manifest_sha256(manifest),
        input_envelope_id=envelope.envelope_id,
        input_envelope_sha256=input_sha256,
        findings=findings,
        evidence_class=(
            "deterministic_rule" if manifest.deterministic else "heuristic_unreviewed"
        ),
        verdict_semantics="advisory_only_no_operational_effect",
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["result_id"] = _result_identity(provisional)
    return ExtensionResultV1.model_validate(payload)


def _bounded_canonical_bytes(payload: object, label: str) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise ExtensionContractError(f"extension {label} is not canonical JSON") from exc
    if len(encoded) > MAX_EXTENSION_PAYLOAD_BYTES:
        raise ExtensionContractError(f"extension {label} exceeds the V1 byte limit")
    return encoded


def _decode_json_object(payload: bytes, label: str) -> dict[str, Any]:
    if not isinstance(payload, bytes):
        raise ExtensionContractError(f"extension {label} payload must be bytes")
    if not payload or len(payload) > MAX_EXTENSION_PAYLOAD_BYTES:
        raise ExtensionContractError(f"extension {label} size is outside the V1 limit")
    try:
        decoded = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ExtensionContractError(f"extension {label} is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise ExtensionContractError(f"extension {label} must be a JSON object")
    return decoded


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExtensionContractError("duplicate extension JSON field")
        result[key] = value
    return result


def _require_safe_manifest_path(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        raise ExtensionContractError("extension manifest does not exist")
    for component in (path, *path.parents):
        if is_link_or_reparse(component):
            raise ExtensionContractError(
                "extension manifest must not traverse a link or reparse point"
            )
        if component.parent == component:
            break
    try:
        info = path.lstat()
    except OSError as exc:
        raise ExtensionContractError("extension manifest metadata is unavailable") from exc
    if os.name == "nt":
        attributes = int(getattr(info, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
        if reparse_flag and attributes & reparse_flag:
            raise ExtensionContractError("extension manifest must not be a reparse point")


def _digest_payload(domain: str, payload: object) -> str:
    return hashlib.sha256(
        domain.encode("ascii") + b"\0" + _bounded_canonical_bytes(payload, "identity")
    ).hexdigest()


def _envelope_identity(envelope: ExtensionObservationEnvelopeV1) -> str:
    payload = envelope.model_dump(mode="json", exclude={"envelope_id"})
    payload["events"] = [
        json.loads(encode_portfolio_observation_v1(event)) for event in envelope.events
    ]
    return _digest_payload("agentic-security-harness/extension-envelope/v1.0", payload)


def _result_identity(result: ExtensionResultV1) -> str:
    return _digest_payload(
        "agentic-security-harness/extension-result/v1.0",
        result.model_dump(mode="json", exclude={"result_id"}),
    )


def _run_receipt_identity(receipt: ExtensionRunReceiptV1) -> str:
    return _digest_payload(
        "agentic-security-harness/extension-run-receipt/v1.0",
        receipt.model_dump(mode="json", exclude={"receipt_id"}),
    )


def _pipeline_identity(receipt: ExtensionPipelineReceiptV1) -> str:
    return _digest_payload(
        "agentic-security-harness/extension-pipeline-receipt/v1.0",
        receipt.model_dump(mode="json", exclude={"pipeline_id"}),
    )
