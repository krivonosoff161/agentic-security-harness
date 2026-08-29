"""Deterministic, authority-free auditors for exact-pinned companion receipts.

The production path accepts caller-supplied canonical receipt bytes.  It never imports
or calls a companion package, discovers installed code, opens the network, starts a
subprocess, or executes an injected callable.  Valid accounting remains advisory and
inconclusive; malformed or drifted bindings are findings, never permission decisions.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field, model_validator

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

RECEIPT_SOURCE_PIN_V1: Final = "harness-receipt-source-pin-v1.0"
RECEIPT_ARTIFACT_BINDING_V1: Final = "harness-receipt-artifact-binding-v1.0"
ROUTER_RECEIPT_V1: Final = "llm-router-invocation-receipt-v1.0"
FILTER_RECEIPT_V1: Final = "llm-cheap-filter-triage-batch-receipt-v1.0"
MAX_ROUTER_RECEIPT_BYTES: Final = 1_048_576
MAX_FILTER_RECEIPT_BYTES: Final = 16_777_216
MAX_RECEIPT_BINDINGS: Final = 2_048
MAX_ROUTER_ATTEMPTS: Final = 16
MAX_ROUTER_COUNT: Final = 1_000_000_000_000
MAX_FIXED_POINT: Final = 10**24
MAX_FILTER_RESULTS: Final = 100_000
MAX_FILTER_TOKENS: Final = 9_007_199_254_740_991
MAX_FILTER_COST_USD: Final = 1_000_000_000.0
NANOS_PER_UNIT: Final = 1_000_000_000
TOKENS_PER_MILLION: Final = 1_000_000
USD_IDENTITY_SOURCE_SHA256: Final = hashlib.sha256(
    b"llm-router/fx-identity/v1\0USD=USD"
).hexdigest()
_TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_ROUTER_TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")
_SHA256_RE = re.compile(SHA256_PATTERN)


class ReviewedReceiptSourceV1(NamedTuple):
    """Exact public producer identity compiled into the Harness adapter."""

    component_id: str
    repository: str
    commit: str
    tree: str
    component_manifest_sha256: str
    contract_id: str
    contract_version: str
    contract_path: str
    contract_sha256: str
    implementation_path: str
    implementation_sha256: str
    contract_manifest_path: str | None
    contract_manifest_sha256: str | None
    evidence_class: Literal["producer_declared", "external_unreviewed"]


REVIEWED_RECEIPT_SOURCES_V1: Final = (
    ReviewedReceiptSourceV1(
        component_id="llm-router",
        repository="https://github.com/krivonosoff161/llm-router",
        commit="69642b42d9999285a0c4642fcaa0405b67e619ad",
        tree="bb1507c6389c6f4e91edd447b91c4c90b915f9a7",
        component_manifest_sha256=(
            "34eef49ca982d4894823f581ac16c2e944d0706e483977db2aff389a33e0fb87"
        ),
        contract_id="router-invocation-receipt",
        contract_version="1.0",
        contract_path="contracts/router-invocation-receipt.v1.schema.json",
        contract_sha256=("6ab8e12695cf4a4cd7e938842b001ad12009b39cc53d16c65babd11e04fbf596"),
        implementation_path="src/llm_router/receipt.py",
        implementation_sha256=("68b054179bd4c9df33ab0782b8873b81da96e942f6fa923bdc3fbcb94485d468"),
        contract_manifest_path=None,
        contract_manifest_sha256=None,
        evidence_class="producer_declared",
    ),
    ReviewedReceiptSourceV1(
        component_id="llm-cheap-filter",
        repository="https://github.com/krivonosoff161/llm-cheap-filter",
        commit="17f13fd3986a2869686e59ca62123340fd56178b",
        tree="5fc988323cada929a5c74846c4e28ddd468d26be",
        component_manifest_sha256=(
            "c9dd234324ee368a591a5e33b9436827fcdf0ff5a45db16711250ca21aa4d529"
        ),
        contract_id="triage-batch-receipt",
        contract_version="1.0",
        contract_path="schemas/triage-batch-receipt.v1.schema.json",
        contract_sha256=("556a67e3c99e3415650e2a9a461c653b80686e000511b549a9c50fde1ae79522"),
        implementation_path="src/llm_cheap_filter/receipt.py",
        implementation_sha256=("e939e1ea1d58efd30ec447a522f4886da1d8a7f8a66eae06d711d4ed7a2dfc4c"),
        contract_manifest_path="schemas/triage-batch-receipt.v1.manifest.json",
        contract_manifest_sha256=(
            "9e5ff8d25c8786651671679517ae767caaf244fb006a3541b2b89cb67e5458ed"
        ),
        evidence_class="external_unreviewed",
    ),
)


class ReceiptAuditContractError(ValueError):
    """Raised when a receipt cannot enter the closed Harness audit boundary."""


class ReceiptSourcePinV1(BaseModel):
    """Exact producer commit/tree and contract/manifest hashes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-receipt-source-pin-v1.0"]
    component_id: str = Field(pattern=PROJECT_ID_PATTERN)
    source_commit: str = Field(pattern=GIT_OBJECT_PATTERN)
    source_tree: str = Field(pattern=GIT_OBJECT_PATTERN)
    component_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    contract_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    contract_version: str = Field(pattern=r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
    contract_sha256: str = Field(pattern=SHA256_PATTERN)
    implementation_sha256: str = Field(pattern=SHA256_PATTERN)
    contract_manifest_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    digest_semantics: Literal["sha256_lf_normalized_text_v1"]
    verification: Literal["exact_public_git_reviewed"]
    operational_authority: Literal["none"]


class ReceiptArtifactBindingV1(BaseModel):
    """Privacy-minimized binding between one observation event and receipt bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-receipt-artifact-binding-v1.0"]
    event_id: str = Field(pattern=SHA256_PATTERN)
    component_id: str = Field(pattern=PROJECT_ID_PATTERN)
    receipt_sha256: str = Field(pattern=SHA256_PATTERN)
    receipt_id: str | None = Field(default=None, pattern=SHA256_PATTERN)
    accounting_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    audit_state: Literal["valid_accounting", "malformed"]
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    source_contract_sha256: str = Field(pattern=SHA256_PATTERN)
    evidence_class: Literal["producer_declared", "external_unreviewed"]
    verdict_semantics: Literal["accounting_audit_only_no_security_verdict"]
    may_lower_security_decision: Literal[False]
    payload_retention: Literal["caller_owned_not_emitted"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _state_is_coherent(self) -> ReceiptArtifactBindingV1:
        if self.audit_state == "valid_accounting":
            if self.receipt_id is None or self.accounting_sha256 is None:
                raise ValueError("valid accounting requires receipt and accounting identities")
            if self.reason_code != f"{self.component_id}.receipt_accounting_valid":
                raise ValueError("valid accounting reason code drift")
        elif self.receipt_id is not None or self.accounting_sha256 is not None:
            raise ValueError("malformed receipt cannot retain asserted semantic identities")
        return self


@dataclass(frozen=True)
class _AuditedReceipt:
    receipt_id: str
    accounting_sha256: str
    producer_id_hash: str | None = None
    occurred_at: datetime | None = None


class _ReceiptAuditorBase:
    _component_id: str
    _repository_id: str
    _activity: str
    _source_surface: str
    _evidence_class: Literal["producer_declared", "external_unreviewed"]

    def __init__(
        self,
        *,
        pin: ReceiptSourcePinV1,
        bindings: tuple[ReceiptArtifactBindingV1, ...],
        receipt_payloads: tuple[bytes, ...],
    ) -> None:
        source = _require_pin(pin, self._component_id)
        if not bindings or len(bindings) > MAX_RECEIPT_BINDINGS:
            raise ReceiptAuditContractError("receipt binding count is outside the V1 limit")
        if len(receipt_payloads) != len(bindings):
            raise ReceiptAuditContractError("every receipt binding requires one payload")
        if len({item.event_id for item in bindings}) != len(bindings):
            raise ReceiptAuditContractError("receipt binding event ids must be unique")
        if len({item.receipt_sha256 for item in bindings}) != len(bindings):
            raise ReceiptAuditContractError("receipt payload replay detected")
        payload_by_sha = {
            hashlib.sha256(bytes(item)).hexdigest(): bytes(item) for item in receipt_payloads
        }
        if len(payload_by_sha) != len(receipt_payloads):
            raise ReceiptAuditContractError("receipt payload replay detected")
        if set(payload_by_sha) != {item.receipt_sha256 for item in bindings}:
            raise ReceiptAuditContractError("receipt binding payload coverage drift")
        receipt_ids: set[str] = set()
        for binding in bindings:
            if (
                binding.component_id != self._component_id
                or binding.source_contract_sha256 != pin.contract_sha256
                or binding.evidence_class != self._evidence_class
            ):
                raise ReceiptAuditContractError("receipt binding source pin drift")
            expected = build_receipt_artifact_binding_v1(
                pin=pin,
                event_id=binding.event_id,
                payload=payload_by_sha[binding.receipt_sha256],
            )
            if expected != binding:
                raise ReceiptAuditContractError("receipt binding semantic drift")
            if binding.receipt_id is not None:
                if binding.receipt_id in receipt_ids:
                    raise ReceiptAuditContractError("receipt identity replay detected")
                receipt_ids.add(binding.receipt_id)
        self._pin = pin
        self._source = source
        self._bindings = {item.event_id: item for item in bindings}
        self._payloads = payload_by_sha
        self.manifest = _manifest(
            component_id=self._component_id,
            evidence_class=self._evidence_class,
            pin=pin,
            bindings=bindings,
        )

    def evaluate(self, envelope: ExtensionObservationEnvelopeV1) -> tuple[ExtensionFindingV1, ...]:
        findings: list[ExtensionFindingV1] = []
        for event in envelope.events:
            if event.activity != self._activity:
                continue
            binding = self._bindings.get(event.event_id)
            if binding is None:
                findings.append(
                    _finding(
                        self._component_id,
                        event.event_id,
                        "inconclusive",
                        "medium",
                        f"{self._component_id}.receipt_evidence_missing",
                    )
                )
                continue
            if _event_static_binding_drift(
                event, binding, self._source, self._activity, self._source_surface
            ):
                findings.append(
                    _finding(
                        self._component_id,
                        event.event_id,
                        "finding",
                        "high",
                        f"{self._component_id}.event_receipt_binding_drift",
                    )
                )
                continue
            if binding.audit_state == "malformed":
                findings.append(
                    _finding(
                        self._component_id,
                        event.event_id,
                        "finding",
                        "high",
                        f"{self._component_id}.receipt_malformed",
                    )
                )
                continue
            audited = _audit_payload(self._component_id, self._payloads[binding.receipt_sha256])
            if _event_binding_drift(
                event, binding, audited, self._source, self._activity, self._source_surface
            ):
                findings.append(
                    _finding(
                        self._component_id,
                        event.event_id,
                        "finding",
                        "high",
                        f"{self._component_id}.event_receipt_binding_drift",
                    )
                )
            elif event.telemetry_state != "complete":
                findings.append(
                    _finding(
                        self._component_id,
                        event.event_id,
                        "inconclusive",
                        "medium",
                        f"{self._component_id}.telemetry_incomplete",
                    )
                )
            else:
                findings.append(
                    _finding(
                        self._component_id,
                        event.event_id,
                        "inconclusive",
                        "none",
                        f"{self._component_id}.accounting_bound_no_security_verdict",
                    )
                )
        return tuple(findings) or (
            ExtensionFindingV1(
                check_id=f"{self._component_id}.receipt_audit.scope",
                outcome="inconclusive",
                severity="none",
                reason_code="scope.no_matching_events",
                evidence_event_ids=(),
            ),
        )


class RouterInvocationReceiptAuditExtensionV1(_ReceiptAuditorBase):
    """Audit exact Router receipt bytes without invoking or importing the Router."""

    _component_id = "llm-router"
    _repository_id = "krivonosoff161/llm-router"
    _activity = "router.invocation_accounted"
    _source_surface = "provider"
    _evidence_class = "producer_declared"


class CheapFilterReceiptAuditExtensionV1(_ReceiptAuditorBase):
    """Audit exact Cheap Filter receipt bytes without executing triage callables."""

    _component_id = "llm-cheap-filter"
    _repository_id = "krivonosoff161/llm-cheap-filter"
    _activity = "filter.triage_accounted"
    _source_surface = "audit"
    _evidence_class = "external_unreviewed"


def build_receipt_source_pin_v1(component_id: str) -> ReceiptSourcePinV1:
    source = _reviewed_source(component_id)
    return ReceiptSourcePinV1(
        schema_version=RECEIPT_SOURCE_PIN_V1,
        component_id=source.component_id,
        source_commit=source.commit,
        source_tree=source.tree,
        component_manifest_sha256=source.component_manifest_sha256,
        contract_id=source.contract_id,
        contract_version=source.contract_version,
        contract_sha256=source.contract_sha256,
        implementation_sha256=source.implementation_sha256,
        contract_manifest_sha256=source.contract_manifest_sha256,
        digest_semantics="sha256_lf_normalized_text_v1",
        verification="exact_public_git_reviewed",
        operational_authority="none",
    )


def build_receipt_artifact_binding_v1(
    *, pin: ReceiptSourcePinV1, event_id: str, payload: bytes
) -> ReceiptArtifactBindingV1:
    source = _require_pin(pin, pin.component_id)
    _require_sha(event_id, "event_id")
    if not isinstance(payload, bytes):
        raise ReceiptAuditContractError("receipt payload must be bytes")
    receipt_sha = hashlib.sha256(payload).hexdigest()
    try:
        audited = _audit_payload(pin.component_id, payload)
    except ReceiptAuditContractError:
        audited = None
    return ReceiptArtifactBindingV1(
        schema_version=RECEIPT_ARTIFACT_BINDING_V1,
        event_id=event_id,
        component_id=pin.component_id,
        receipt_sha256=receipt_sha,
        receipt_id=None if audited is None else audited.receipt_id,
        accounting_sha256=None if audited is None else audited.accounting_sha256,
        audit_state="malformed" if audited is None else "valid_accounting",
        reason_code=(
            f"{pin.component_id}.receipt_malformed"
            if audited is None
            else f"{pin.component_id}.receipt_accounting_valid"
        ),
        source_contract_sha256=pin.contract_sha256,
        evidence_class=source.evidence_class,
        verdict_semantics="accounting_audit_only_no_security_verdict",
        may_lower_security_decision=False,
        payload_retention="caller_owned_not_emitted",
        operational_authority="none",
    )


def reviewed_receipt_sources_v1() -> tuple[dict[str, object], ...]:
    return tuple(row._asdict() for row in REVIEWED_RECEIPT_SOURCES_V1)


def receipt_auditor_v1_json_schemas() -> dict[str, dict[str, Any]]:
    return {
        "receipt-source-pin.v1.schema.json": ReceiptSourcePinV1.model_json_schema(),
        "receipt-artifact-binding.v1.schema.json": ReceiptArtifactBindingV1.model_json_schema(),
    }


def _manifest(
    *,
    component_id: str,
    evidence_class: Literal["producer_declared", "external_unreviewed"],
    pin: ReceiptSourcePinV1,
    bindings: tuple[ReceiptArtifactBindingV1, ...],
) -> ExtensionManifestV1:
    return ExtensionManifestV1(
        schema_version=EXTENSION_MANIFEST_V1,
        extension_id=f"{component_id}.receipt-audit",
        extension_version="1.0.0",
        component_id="agentic-security-harness",
        implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        configuration_sha256=_domain_object_digest(
            "agentic-security-harness/receipt-auditor-configuration/v1.0",
            {"pin": pin, "bindings": bindings},
        ),
        harness_api="1",
        kind="check_extension",
        capabilities=("observation.read", "finding.emit"),
        consumes=(
            ExtensionContractRefV1(
                contract_id="portfolio-observation", version="1.0", required=True
            ),
            ExtensionContractRefV1(
                contract_id=pin.contract_id, version=pin.contract_version, required=True
            ),
        ),
        produces=(
            ExtensionContractRefV1(contract_id="extension-finding", version="1.0", required=True),
        ),
        deterministic=True,
        evidence_provenance=evidence_class,
        network_mode="off",
        raw_data_policy="digests_only",
        execution_model="in_process_operator_approved_not_sandboxed",
        operational_authority="none",
    )


def _reviewed_source(component_id: str) -> ReviewedReceiptSourceV1:
    try:
        return next(row for row in REVIEWED_RECEIPT_SOURCES_V1 if row.component_id == component_id)
    except StopIteration as exc:
        raise ReceiptAuditContractError("receipt source is not reviewed and pinned") from exc


def _require_pin(pin: ReceiptSourcePinV1, component_id: str) -> ReviewedReceiptSourceV1:
    source = _reviewed_source(component_id)
    observed = (
        pin.component_id,
        pin.source_commit,
        pin.source_tree,
        pin.component_manifest_sha256,
        pin.contract_id,
        pin.contract_version,
        pin.contract_sha256,
        pin.implementation_sha256,
        pin.contract_manifest_sha256,
        pin.digest_semantics,
        pin.verification,
        pin.operational_authority,
    )
    required = (
        source.component_id,
        source.commit,
        source.tree,
        source.component_manifest_sha256,
        source.contract_id,
        source.contract_version,
        source.contract_sha256,
        source.implementation_sha256,
        source.contract_manifest_sha256,
        "sha256_lf_normalized_text_v1",
        "exact_public_git_reviewed",
        "none",
    )
    if pin.schema_version != RECEIPT_SOURCE_PIN_V1 or observed != required:
        raise ReceiptAuditContractError("receipt source pin does not match reviewed bytes")
    return source


def _event_binding_drift(
    event: CanonicalObservationEventV1,
    binding: ReceiptArtifactBindingV1,
    audited: _AuditedReceipt,
    source: ReviewedReceiptSourceV1,
    activity: str,
    source_surface: str,
) -> bool:
    entity_ok = (
        len(event.entity_refs) == 1
        and event.entity_refs[0].kind == "artifact"
        and event.entity_refs[0].digest == audited.receipt_id
        and event.entity_refs[0].locator_id == binding.receipt_sha256
    )
    occurred_ok = audited.occurred_at is None or event.occurred_at == audited.occurred_at
    producer_ok = (
        audited.producer_id_hash is None or event.producer_id_hash == audited.producer_id_hash
    )
    return not (entity_ok and occurred_ok and producer_ok)


def _event_static_binding_drift(
    event: CanonicalObservationEventV1,
    binding: ReceiptArtifactBindingV1,
    source: ReviewedReceiptSourceV1,
    activity: str,
    source_surface: str,
) -> bool:
    """Validate source and byte linkage even when receipt semantics are malformed."""

    entity_ok = (
        len(event.entity_refs) == 1
        and event.entity_refs[0].kind == "artifact"
        and event.entity_refs[0].locator_id == binding.receipt_sha256
    )
    return not (
        event.project_id == source.component_id
        and event.repository_id == source.repository.removeprefix("https://github.com/")
        and event.repository_sha == source.commit
        and event.activity == activity
        and event.source_surface == source_surface
        and event.data_envelope_ref == binding.receipt_sha256
        and event.authority_envelope_ref is None
        and entity_ok
    )


def _audit_payload(component_id: str, payload: bytes) -> _AuditedReceipt:
    if component_id == "llm-router":
        return _audit_router_receipt(payload)
    if component_id == "llm-cheap-filter":
        return _audit_filter_receipt(payload)
    raise ReceiptAuditContractError("unsupported receipt component")


def _audit_router_receipt(payload: bytes) -> _AuditedReceipt:
    root = _decode_canonical_object(payload, MAX_ROUTER_RECEIPT_BYTES)
    fields = {
        "attempts",
        "cost_local_nanos",
        "cost_usd_nanos",
        "currency",
        "fx_rate_local_nanos_per_usd",
        "fx_source",
        "fx_source_ref_sha256",
        "input_rate_usd_nanos_per_million",
        "input_tokens",
        "invoice_authoritative",
        "model_id_sha256",
        "occurred_at",
        "operational_authority",
        "output_rate_usd_nanos_per_million",
        "output_text_sha256",
        "output_tokens",
        "pricing_ref_sha256",
        "pricing_source",
        "pricing_source_ref_sha256",
        "producer_id_hash",
        "provider_id",
        "receipt_id",
        "request_payload_sha256",
        "response_payload_sha256",
        "role",
        "rounding_mode",
        "schema_version",
        "terminal_reason_code",
        "terminal_status",
        "total_tokens",
        "usage_provenance",
    }
    _exact_fields(root, fields, "router receipt")
    if root["schema_version"] != ROUTER_RECEIPT_V1:
        raise ReceiptAuditContractError("router receipt version drift")
    for name in (
        "receipt_id",
        "producer_id_hash",
        "request_payload_sha256",
        "model_id_sha256",
        "pricing_ref_sha256",
    ):
        _require_sha(root[name], name)
    for name in (
        "response_payload_sha256",
        "output_text_sha256",
        "pricing_source_ref_sha256",
        "fx_source_ref_sha256",
    ):
        _require_optional_sha(root[name], name)
    if not isinstance(root["provider_id"], str) or not _ROUTER_TOKEN_PATTERN.fullmatch(
        root["provider_id"]
    ):
        raise ReceiptAuditContractError("router provider token drift")
    _require_member(root["role"], {"cheap", "mid", "chief", "audit"}, "router role")
    occurred_at = _parse_canonical_timestamp(root["occurred_at"])
    attempts = root["attempts"]
    if not isinstance(attempts, list) or len(attempts) > MAX_ROUTER_ATTEMPTS:
        raise ReceiptAuditContractError("router attempt count drift")
    attempt_reason = {
        "rate_limited": "provider.rate_limited",
        "server_error": "provider.server_error",
        "nonretryable_http_error": "provider.nonretryable_http_error",
        "network_error": "provider.network_error",
        "invalid_response": "provider.invalid_response",
        "success": "provider.success",
    }
    retryable = {"rate_limited", "server_error", "network_error", "invalid_response"}
    parsed_attempts: list[dict[str, object]] = []
    for index, raw in enumerate(attempts, 1):
        _exact_fields(
            raw,
            {"attempt_index", "http_status", "outcome", "reason_code", "response_payload_sha256"},
            "router attempt",
        )
        _bounded_int(raw["attempt_index"], 1, MAX_ROUTER_ATTEMPTS, "attempt_index")
        outcome = _require_member(raw["outcome"], set(attempt_reason), "router outcome")
        if raw["attempt_index"] != index or raw["reason_code"] != attempt_reason[outcome]:
            raise ReceiptAuditContractError("router attempt accounting drift")
        _validate_router_http(outcome, raw["http_status"])
        _require_optional_sha(raw["response_payload_sha256"], "response_payload_sha256")
        parsed_attempts.append(raw)
    terminal_reason = {
        "success": "router.success",
        "empty_content": "router.empty_content",
        "missing_configuration": "router.missing_configuration",
        "nonretryable_http_error": "router.nonretryable_http_error",
        "retry_exhausted": "router.retry_exhausted",
    }
    terminal = _require_member(
        root["terminal_status"], set(terminal_reason), "router terminal state"
    )
    if root["terminal_reason_code"] != terminal_reason[terminal]:
        raise ReceiptAuditContractError("router terminal state drift")
    if terminal == "missing_configuration":
        if parsed_attempts:
            raise ReceiptAuditContractError("router missing configuration attempt drift")
    else:
        if not parsed_attempts or any(
            item["outcome"] not in retryable for item in parsed_attempts[:-1]
        ):
            raise ReceiptAuditContractError("router retry state drift")
        final = parsed_attempts[-1]
        expected_final = {
            "success": "success",
            "empty_content": "success",
            "nonretryable_http_error": "nonretryable_http_error",
        }.get(terminal)
        if expected_final is not None and final["outcome"] != expected_final:
            raise ReceiptAuditContractError("router final attempt drift")
        if terminal == "retry_exhausted" and final["outcome"] not in retryable:
            raise ReceiptAuditContractError("router retry exhaustion drift")
    final_response = parsed_attempts[-1]["response_payload_sha256"] if parsed_attempts else None
    if root["response_payload_sha256"] != final_response:
        raise ReceiptAuditContractError("router response binding drift")
    if terminal in {"success", "empty_content"} and final_response is None:
        raise ReceiptAuditContractError("router successful response digest missing")
    if (terminal == "success") != (root["output_text_sha256"] is not None):
        raise ReceiptAuditContractError("router output digest state drift")
    for name in ("input_tokens", "output_tokens", "total_tokens"):
        _bounded_int(root[name], 0, MAX_ROUTER_COUNT, name)
    for name in (
        "input_rate_usd_nanos_per_million",
        "output_rate_usd_nanos_per_million",
        "cost_usd_nanos",
        "fx_rate_local_nanos_per_usd",
        "cost_local_nanos",
    ):
        _bounded_int(root[name], 0, MAX_FIXED_POINT, name)
    usage_provenance = _require_member(
        root["usage_provenance"], {"provider_reported", "absent"}, "router usage provenance"
    )
    if usage_provenance == "absent":
        if any(root[name] for name in ("input_tokens", "output_tokens", "total_tokens")):
            raise ReceiptAuditContractError("router absent usage drift")
    elif root["total_tokens"] != root["input_tokens"] + root["output_tokens"]:
        raise ReceiptAuditContractError("router token accounting drift")
    if terminal not in {"success", "empty_content"} and usage_provenance != "absent":
        raise ReceiptAuditContractError("router failed usage drift")
    _validate_router_pricing(root)
    if root["invoice_authoritative"] is not False or root["operational_authority"] != "none":
        raise ReceiptAuditContractError("router authority drift")
    identity_payload = dict(root)
    identity_payload.pop("receipt_id")
    expected_id = hashlib.sha256(
        b"llm-router/invocation-receipt/v1\0" + _canonical_bytes(identity_payload)
    ).hexdigest()
    if root["receipt_id"] != expected_id:
        raise ReceiptAuditContractError("router receipt identity drift")
    accounting = {
        "attempts": parsed_attempts,
        "terminal_status": terminal,
        "usage": {
            name: root[name]
            for name in ("usage_provenance", "input_tokens", "output_tokens", "total_tokens")
        },
        "pricing_ref_sha256": root["pricing_ref_sha256"],
        "cost_usd_nanos": root["cost_usd_nanos"],
        "cost_local_nanos": root["cost_local_nanos"],
    }
    return _AuditedReceipt(
        receipt_id=root["receipt_id"],
        accounting_sha256=_domain_object_digest(
            "agentic-security-harness/router-accounting/v1.0", accounting
        ),
        producer_id_hash=root["producer_id_hash"],
        occurred_at=occurred_at,
    )


def _validate_router_http(outcome: object, status: object) -> None:
    if status is not None:
        _bounded_int(status, 100, 599, "http_status")
    valid = {
        "rate_limited": status == 429,
        "server_error": isinstance(status, int)
        and not isinstance(status, bool)
        and 500 <= status <= 599,
        "nonretryable_http_error": isinstance(status, int)
        and not isinstance(status, bool)
        and 100 <= status <= 499
        and status not in {200, 429},
        "network_error": status is None,
        "invalid_response": status in {None, 200},
        "success": status == 200,
    }
    if not isinstance(outcome, str) or not valid.get(outcome, False):
        raise ReceiptAuditContractError("router HTTP outcome drift")


def _validate_router_pricing(root: Mapping[str, Any]) -> None:
    pricing_source = _require_member(
        root["pricing_source"],
        {"illustrative_builtin", "operator_override", "unpriced"},
        "router pricing source",
    )
    if root["rounding_mode"] != "half_even":
        raise ReceiptAuditContractError("router pricing source drift")
    rates = (root["input_rate_usd_nanos_per_million"], root["output_rate_usd_nanos_per_million"])
    if pricing_source == "unpriced":
        if any(rates) or root["cost_usd_nanos"] or root["pricing_source_ref_sha256"] is not None:
            raise ReceiptAuditContractError("router unpriced accounting drift")
    else:
        if root["pricing_source_ref_sha256"] is None or not any(rates):
            raise ReceiptAuditContractError("router priced source evidence missing")
        expected = _half_even(
            root["input_tokens"] * rates[0] + root["output_tokens"] * rates[1], TOKENS_PER_MILLION
        )
        if root["cost_usd_nanos"] != expected:
            raise ReceiptAuditContractError("router USD cost drift")
    if not isinstance(root["currency"], str) or not _CURRENCY_PATTERN.fullmatch(root["currency"]):
        raise ReceiptAuditContractError("router currency drift")
    fx = root["fx_source"]
    if fx == "identity":
        valid = (
            root["currency"] == "USD"
            and root["fx_rate_local_nanos_per_usd"] == NANOS_PER_UNIT
            and root["cost_local_nanos"] == root["cost_usd_nanos"]
            and root["fx_source_ref_sha256"] == USD_IDENTITY_SOURCE_SHA256
        )
    elif fx == "unavailable":
        valid = (
            root["currency"] == "XXX"
            and root["fx_rate_local_nanos_per_usd"] == 0
            and root["cost_local_nanos"] == 0
            and root["fx_source_ref_sha256"] is None
        )
    elif fx == "operator_declared":
        valid = (
            root["currency"] not in {"USD", "XXX"}
            and root["fx_rate_local_nanos_per_usd"] > 0
            and root["fx_source_ref_sha256"] is not None
            and root["cost_local_nanos"]
            == _half_even(
                root["cost_usd_nanos"] * root["fx_rate_local_nanos_per_usd"], NANOS_PER_UNIT
            )
        )
    else:
        valid = False
    if not valid:
        raise ReceiptAuditContractError("router FX accounting drift")
    pricing = {
        name: root[name]
        for name in (
            "currency",
            "fx_rate_local_nanos_per_usd",
            "fx_source",
            "fx_source_ref_sha256",
            "input_rate_usd_nanos_per_million",
            "output_rate_usd_nanos_per_million",
            "pricing_source",
            "pricing_source_ref_sha256",
            "rounding_mode",
        )
    }
    if root["pricing_ref_sha256"] != _domain_object_digest(
        "llm-router/pricing-reference/v1", pricing
    ):
        raise ReceiptAuditContractError("router pricing reference drift")


def _audit_filter_receipt(payload: bytes) -> _AuditedReceipt:
    root = _decode_canonical_object(payload, MAX_FILTER_RECEIPT_BYTES)
    _exact_fields(
        root,
        {
            "schema_version",
            "receipt_id",
            "input_batch_sha256",
            "prefilter_configuration_sha256",
            "escalation_policy_sha256",
            "results",
            "summary",
            "verdict_semantics",
            "may_lower_security_decision",
            "operational_authority",
        },
        "filter receipt",
    )
    if root["schema_version"] != FILTER_RECEIPT_V1:
        raise ReceiptAuditContractError("filter receipt version drift")
    for name in (
        "receipt_id",
        "input_batch_sha256",
        "prefilter_configuration_sha256",
        "escalation_policy_sha256",
    ):
        _require_sha(root[name], name)
    results = root["results"]
    if not isinstance(results, list) or len(results) > MAX_FILTER_RESULTS:
        raise ReceiptAuditContractError("filter result count drift")
    stages = {"prefilter_drop", "cheap_drop", "cheap_keep", "chief", "error", "cancelled"}
    counts = {stage: 0 for stage in stages}
    total_tokens = 0
    total_cost = 0.0
    input_rows: list[dict[str, object]] = []
    for index, item in enumerate(results):
        _exact_fields(
            item,
            {
                "input_index",
                "input_sha256",
                "stage",
                "score",
                "flagged",
                "total_tokens",
                "cost_usd",
                "reason_codes",
                "decision_sha256",
                "may_lower_security_decision",
                "operational_authority",
            },
            "filter result",
        )
        if (
            item["input_index"] != index
            or isinstance(item["input_index"], bool)
            or not isinstance(item["input_index"], int)
        ):
            raise ReceiptAuditContractError("filter input order drift")
        _require_sha(item["input_sha256"], "input_sha256")
        _require_sha(item["decision_sha256"], "decision_sha256")
        stage = _require_member(item["stage"], stages, "filter stage")
        _bounded_float(item["score"], 0.0, 1.0, "score")
        if item["flagged"] is not None and not isinstance(item["flagged"], bool):
            raise ReceiptAuditContractError("filter flag drift")
        _bounded_int(item["total_tokens"], 0, MAX_FILTER_TOKENS, "total_tokens")
        _bounded_float(item["cost_usd"], 0.0, MAX_FILTER_COST_USD, "cost_usd")
        reasons = item["reason_codes"]
        if (
            not isinstance(reasons, list)
            or not 1 <= len(reasons) <= 16
            or any(
                not isinstance(code, str) or not _TOKEN_PATTERN.fullmatch(code) for code in reasons
            )
            or len(reasons) != len(set(reasons))
        ):
            raise ReceiptAuditContractError("filter reason code drift")
        if (
            item["may_lower_security_decision"] is not False
            or item["operational_authority"] != "none"
        ):
            raise ReceiptAuditContractError("filter result authority drift")
        counts[stage] += 1
        total_tokens += item["total_tokens"]
        total_cost += item["cost_usd"]
        if (
            total_tokens > MAX_FILTER_TOKENS
            or not math.isfinite(total_cost)
            or total_cost > MAX_FILTER_COST_USD
        ):
            raise ReceiptAuditContractError("filter aggregate usage drift")
        input_rows.append({"input_index": index, "input_sha256": item["input_sha256"]})
    summary = root["summary"]
    summary_fields = {
        "input_count",
        "prefilter_drop",
        "cheap_drop",
        "cheap_keep",
        "chief",
        "error",
        "cancelled",
        "total_tokens",
        "total_cost_usd",
    }
    _exact_fields(summary, summary_fields, "filter summary")
    for name in summary_fields - {"total_cost_usd"}:
        _bounded_int(
            summary[name],
            0,
            MAX_FILTER_TOKENS if name == "total_tokens" else MAX_FILTER_RESULTS,
            name,
        )
    _bounded_float(summary["total_cost_usd"], 0.0, MAX_FILTER_COST_USD, "total_cost_usd")
    expected_summary = {
        "input_count": len(results),
        **counts,
        "total_tokens": total_tokens,
        "total_cost_usd": total_cost,
    }
    if summary != expected_summary:
        raise ReceiptAuditContractError("filter summary accounting drift")
    expected_batch = hashlib.sha256(
        b"llm-cheap-filter/triage-input-batch/v1\0" + _canonical_bytes(input_rows)
    ).hexdigest()
    if root["input_batch_sha256"] != expected_batch:
        raise ReceiptAuditContractError("filter input batch drift")
    if (
        root["verdict_semantics"] != "triage_accounting_only_no_security_verdict"
        or root["may_lower_security_decision"] is not False
        or root["operational_authority"] != "none"
    ):
        raise ReceiptAuditContractError("filter authority drift")
    identity_payload = dict(root)
    identity_payload.pop("receipt_id")
    expected_id = hashlib.sha256(
        b"llm-cheap-filter/triage-batch-receipt/v1\0" + _canonical_bytes(identity_payload)
    ).hexdigest()
    if root["receipt_id"] != expected_id:
        raise ReceiptAuditContractError("filter receipt identity drift")
    accounting = {
        "input_batch_sha256": root["input_batch_sha256"],
        "results": results,
        "summary": summary,
        "prefilter_configuration_sha256": root["prefilter_configuration_sha256"],
        "escalation_policy_sha256": root["escalation_policy_sha256"],
    }
    return _AuditedReceipt(
        receipt_id=root["receipt_id"],
        accounting_sha256=_domain_object_digest(
            "agentic-security-harness/filter-accounting/v1.0", accounting
        ),
    )


def _decode_canonical_object(payload: bytes, maximum: int) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > maximum:
        raise ReceiptAuditContractError("receipt payload size is outside the reviewed limit")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ReceiptAuditContractError,
    ) as exc:
        raise ReceiptAuditContractError("receipt is not canonical UTF-8 JSON") from exc
    if not isinstance(value, dict) or _canonical_bytes(value) + b"\n" != payload:
        raise ReceiptAuditContractError("receipt JSON is not canonical")
    return value


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptAuditContractError("duplicate receipt field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ReceiptAuditContractError("non-finite receipt number")


def _exact_fields(value: object, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ReceiptAuditContractError(f"{label} fields drift")


def _bounded_int(value: object, minimum: int, maximum: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ReceiptAuditContractError(f"{label} integer drift")


def _bounded_float(value: object, minimum: float, maximum: float, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, float)
        or not math.isfinite(value)
        or (value == 0.0 and math.copysign(1.0, value) < 0.0)
        or not minimum <= value <= maximum
    ):
        raise ReceiptAuditContractError(f"{label} number drift")


def _require_sha(value: object, label: str) -> None:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ReceiptAuditContractError(f"{label} digest drift")


def _require_optional_sha(value: object, label: str) -> None:
    if value is not None:
        _require_sha(value, label)


def _require_member(value: object, allowed: set[str], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ReceiptAuditContractError(f"{label} drift")
    return value


def _parse_canonical_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 32:
        raise ReceiptAuditContractError("receipt timestamp drift")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReceiptAuditContractError("receipt timestamp drift") from exc
    normalized = parsed.astimezone(UTC) if parsed.tzinfo is not None else None
    if (
        normalized is None
        or normalized.isoformat(timespec="microseconds").replace("+00:00", "Z") != value
        or not 1970 <= normalized.year <= 2100
    ):
        raise ReceiptAuditContractError("receipt timestamp drift")
    return normalized


def _half_even(numerator: int, denominator: int) -> int:
    quotient, remainder = divmod(numerator, denominator)
    if remainder * 2 > denominator or (remainder * 2 == denominator and quotient % 2):
        quotient += 1
    if quotient > MAX_FIXED_POINT:
        raise ReceiptAuditContractError("fixed-point result drift")
    return quotient


def _finding(
    component_id: str,
    event_id: str,
    outcome: Literal["finding", "inconclusive"],
    severity: Literal["none", "medium", "high"],
    reason_code: str,
) -> ExtensionFindingV1:
    return ExtensionFindingV1(
        check_id=f"{component_id}.receipt_audit.{event_id}",
        outcome=outcome,
        severity=severity,
        reason_code=reason_code,
        evidence_event_ids=(event_id,),
    )


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            default=_json_default,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ReceiptAuditContractError("receipt value is not canonical JSON") from exc


def _json_default(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"unsupported canonical JSON type: {type(value).__name__}")


def _domain_object_digest(domain: str, value: object) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + _canonical_bytes(value)).hexdigest()
