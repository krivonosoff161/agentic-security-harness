"""Opt-in, authority-free advisory projection into the pure Runtime Gateway decision.

The caller supplies canonical advisory bytes, one exact immutable profile, and an
existing deterministic Gateway policy. Advisory data can satisfy a closed code-owned
mapping but cannot supply a capability, tool, policy, permission, or dispatch action.
This module performs no discovery, companion import, provider/model call, audit write,
stateful engine construction, tool execution, or network/process activity.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agentic_security_harness.quarantine_connector import CapabilityRequestV1
from agentic_security_harness.runtime_gateway import (
    SAFE_TOKEN_PATTERN,
    SHA256_PATTERN,
    GatewayDecisionV1,
    GatewayPolicyV1,
    GatewayProtocol,
    GatewayToolCallV1,
    evaluate_gateway_tool_call,
)

ADVISORY_GATEWAY_CONNECTOR_API_VERSION = (
    "AgenticSecurityHarnessAdvisoryGatewayConnector.v1"
)
MAX_ADVISORY_INPUT_BYTES = 16_384
MAX_ADVISORY_TEXT_BYTES = 4_096
MAX_ADVISORY_SUMMARY_BYTES = 512
MAX_PROFILE_ARGUMENT_BYTES = 4_096

AdvisoryDisposition = Literal["admit", "reject", "inconclusive"]
AdvisoryComponent = Literal["llm-cheap-filter", "llm-safety-playbooks"]
AdvisoryKind = Literal["cheap_filter_finding", "playbooks_policy_evaluation"]
AdvisoryRiskLabel = Literal[
    "none",
    "low",
    "medium",
    "high",
    "critical",
    "inconclusive",
    "observe",
    "challenge",
    "escalate",
    "abstain",
]
AdvisoryEvidenceClass = Literal[
    "producer_declared",
    "external_unreviewed",
    "synthetic_fixture",
    "sanitized_metadata",
]

_ENVELOPE_SCHEMA_VERSION: Literal["AgenticSecurityHarnessAdvisoryEnvelope.v1"] = (
    "AgenticSecurityHarnessAdvisoryEnvelope.v1"
)
_PROVENANCE_SCHEMA_VERSION: Literal["AgenticSecurityHarnessAdvisoryProvenance.v1"] = (
    "AgenticSecurityHarnessAdvisoryProvenance.v1"
)
_SOURCE_CONTRACT_ID_PATTERN = r"^[a-z][a-z0-9_.-]{0,127}$"
_SOURCE_CONTRACT_VERSION_PATTERN = r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$"
_GIT_SHA_PATTERN = r"^[0-9a-f]{40}$"
_FORBIDDEN_AUTHORITY_KEYS = frozenset(
    {
        "allow",
        "approval",
        "budget",
        "capability",
        "capability_id",
        "dispatch",
        "effect",
        "execution_permission",
        "executor",
        "permission",
        "policy",
        "policy_version",
        "principal",
        "recipient",
        "role",
        "scope",
        "token",
        "tool",
        "tool_definition",
        "tool_name",
        "route",
        "version",
    }
)
_NORMALIZED_FORBIDDEN_AUTHORITY_KEYS = frozenset(
    "".join(character for character in key.casefold() if character.isalnum())
    for key in _FORBIDDEN_AUTHORITY_KEYS
)
_COMPONENT_KIND_LABELS: dict[tuple[str, str], frozenset[str]] = {
    ("llm-cheap-filter", "cheap_filter_finding"): frozenset(
        {"none", "low", "medium", "high", "critical", "inconclusive"}
    ),
    ("llm-safety-playbooks", "playbooks_policy_evaluation"): frozenset(
        {"observe", "challenge", "escalate", "abstain"}
    ),
}


class AdvisoryGatewayConnectorError(ValueError):
    """Raised only for trusted caller/configuration misuse."""


class AdvisoryProvenanceV1(BaseModel):
    """Exact source and result commitments carried by an untrusted advisory."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessAdvisoryProvenance.v1"] = (
        _PROVENANCE_SCHEMA_VERSION
    )
    source_commit: str = Field(pattern=_GIT_SHA_PATTERN)
    source_tree: str = Field(pattern=_GIT_SHA_PATTERN)
    source_contract_sha256: str = Field(pattern=SHA256_PATTERN)
    source_result_sha256: str = Field(pattern=SHA256_PATTERN)
    evidence_class: AdvisoryEvidenceClass
    operational_authority: Literal["none"] = "none"


class AdvisoryEnvelopeV1(BaseModel):
    """Canonical advisory evidence; its text is always opaque and untrusted."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessAdvisoryEnvelope.v1"] = (
        _ENVELOPE_SCHEMA_VERSION
    )
    advisory_id: str = Field(pattern=SHA256_PATTERN)
    source_component_id: AdvisoryComponent
    source_contract_id: str = Field(pattern=_SOURCE_CONTRACT_ID_PATTERN)
    source_contract_version: str = Field(pattern=_SOURCE_CONTRACT_VERSION_PATTERN)
    advisory_kind: AdvisoryKind
    risk_label: AdvisoryRiskLabel
    advisory_text: str
    summary: str
    provenance: AdvisoryProvenanceV1
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _closed_advisory(self) -> AdvisoryEnvelopeV1:
        labels = _COMPONENT_KIND_LABELS.get((self.source_component_id, self.advisory_kind))
        if labels is None or self.risk_label not in labels:
            raise ValueError("component, kind, and risk label do not form a supported tuple")
        _validate_unicode_scalar_string(self.advisory_text)
        _validate_unicode_scalar_string(self.summary)
        if not self.advisory_text and not self.summary:
            raise ValueError("advisory text or summary must be non-empty")
        if len(self.advisory_text.encode("utf-8")) > MAX_ADVISORY_TEXT_BYTES:
            raise ValueError("advisory text exceeds the V1 byte limit")
        if len(self.summary.encode("utf-8")) > MAX_ADVISORY_SUMMARY_BYTES:
            raise ValueError("advisory summary exceeds the V1 byte limit")
        unsigned = self.model_dump(mode="json", exclude={"advisory_id"})
        expected = hashlib.sha256(
            b"ash-advisory-envelope-v1\0" + _canonical_json_bytes(unsigned)
        ).hexdigest()
        if self.advisory_id != expected:
            raise ValueError("advisory identity does not match canonical content")
        return self

    def sha256(self) -> str:
        """Return the contract-defined advisory content identity."""

        return self.advisory_id


class AdvisorySourcePinV1(BaseModel):
    """Exact producer contract and result accepted by one immutable profile."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessAdvisorySourcePin.v1"] = (
        "AgenticSecurityHarnessAdvisorySourcePin.v1"
    )
    source_component_id: AdvisoryComponent
    advisory_kind: AdvisoryKind
    source_contract_id: str = Field(pattern=_SOURCE_CONTRACT_ID_PATTERN)
    source_contract_version: str = Field(pattern=_SOURCE_CONTRACT_VERSION_PATTERN)
    source_commit: str = Field(pattern=_GIT_SHA_PATTERN)
    source_tree: str = Field(pattern=_GIT_SHA_PATTERN)
    source_contract_sha256: str = Field(pattern=SHA256_PATTERN)
    source_result_sha256: str = Field(pattern=SHA256_PATTERN)
    accepted_evidence_classes: tuple[AdvisoryEvidenceClass, ...] = Field(
        min_length=1, max_length=4
    )

    @model_validator(mode="after")
    def _closed_source(self) -> AdvisorySourcePinV1:
        if (self.source_component_id, self.advisory_kind) not in _COMPONENT_KIND_LABELS:
            raise ValueError("source component and advisory kind do not match")
        if self.accepted_evidence_classes != tuple(sorted(set(self.accepted_evidence_classes))):
            raise ValueError("accepted evidence classes must be sorted and unique")
        return self

    def matches(self, envelope: AdvisoryEnvelopeV1) -> bool:
        """Match every source/result commitment before any label mapping is considered."""

        return (
            self.source_component_id == envelope.source_component_id
            and self.advisory_kind == envelope.advisory_kind
            and self.source_contract_id == envelope.source_contract_id
            and self.source_contract_version == envelope.source_contract_version
            and self.source_commit == envelope.provenance.source_commit
            and self.source_tree == envelope.provenance.source_tree
            and self.source_contract_sha256 == envelope.provenance.source_contract_sha256
            and self.source_result_sha256 == envelope.provenance.source_result_sha256
            and envelope.provenance.evidence_class in self.accepted_evidence_classes
        )


class AdvisoryFixedArgumentV1(BaseModel):
    """One immutable primitive argument owned by the selected profile."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessAdvisoryFixedArgument.v1"] = (
        "AgenticSecurityHarnessAdvisoryFixedArgument.v1"
    )
    name: str = Field(pattern=SAFE_TOKEN_PATTERN)
    value: str | int | bool | None

    @model_validator(mode="after")
    def _bounded_constant(self) -> AdvisoryFixedArgumentV1:
        if _normalized_key(self.name) in _NORMALIZED_FORBIDDEN_AUTHORITY_KEYS:
            raise ValueError("argument name cannot be authority-shaped")
        if isinstance(self.value, str):
            _validate_unicode_scalar_string(self.value)
            if len(self.value.encode("utf-8")) > 1_024:
                raise ValueError("fixed string argument exceeds the V1 byte limit")
        return self


class AdvisoryCapabilityBindingV1(BaseModel):
    """Code-owned fixed capability and Gateway call projection."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessAdvisoryCapabilityBinding.v1"] = (
        "AgenticSecurityHarnessAdvisoryCapabilityBinding.v1"
    )
    binding_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    capability_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    gateway_protocol: GatewayProtocol
    gateway_tool_name: str = Field(pattern=SAFE_TOKEN_PATTERN)
    fixed_arguments: tuple[AdvisoryFixedArgumentV1, ...] = Field(
        default=(), max_length=32, repr=False
    )

    @model_validator(mode="after")
    def _closed_arguments(self) -> AdvisoryCapabilityBindingV1:
        names = [item.name for item in self.fixed_arguments]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("fixed arguments must be sorted and unique")
        if len(_canonical_json_bytes(self.arguments())) > MAX_PROFILE_ARGUMENT_BYTES:
            raise ValueError("binding arguments exceed the V1 byte limit")
        return self

    def arguments(self) -> dict[str, str | int | bool | None]:
        """Materialize a fresh Gateway argument object from immutable constants."""

        return {item.name: item.value for item in self.fixed_arguments}

    def sha256(self) -> str:
        return _domain_sha256("ash-advisory-capability-binding-v1", self.model_dump(mode="json"))


class AdvisoryMappingRuleV1(BaseModel):
    """Closed tuple-to-binding mapping owned entirely by application code."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessAdvisoryMappingRule.v1"] = (
        "AgenticSecurityHarnessAdvisoryMappingRule.v1"
    )
    source_component_id: AdvisoryComponent
    advisory_kind: AdvisoryKind
    risk_label: AdvisoryRiskLabel
    binding_id: str = Field(pattern=SAFE_TOKEN_PATTERN)

    @model_validator(mode="after")
    def _closed_tuple(self) -> AdvisoryMappingRuleV1:
        labels = _COMPONENT_KIND_LABELS.get((self.source_component_id, self.advisory_kind))
        if labels is None or self.risk_label not in labels:
            raise ValueError("mapping component, kind, and risk label do not match")
        return self


class AdvisoryGatewayProfileV1(BaseModel):
    """One explicit immutable profile; no registry discovery, fallback, or upgrade."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessAdvisoryGatewayProfile.v1"] = (
        "AgenticSecurityHarnessAdvisoryGatewayProfile.v1"
    )
    profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    source_pins: tuple[AdvisorySourcePinV1, ...] = Field(min_length=1, max_length=32)
    bindings: tuple[AdvisoryCapabilityBindingV1, ...] = Field(min_length=1, max_length=32)
    mappings: tuple[AdvisoryMappingRuleV1, ...] = Field(max_length=64)
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _closed_profile(self) -> AdvisoryGatewayProfileV1:
        source_keys = [_source_pin_key(item) for item in self.source_pins]
        if source_keys != sorted(source_keys) or len(source_keys) != len(set(source_keys)):
            raise ValueError("source pins must be sorted and unique")
        binding_ids = [item.binding_id for item in self.bindings]
        if binding_ids != sorted(binding_ids) or len(binding_ids) != len(set(binding_ids)):
            raise ValueError("bindings must be sorted and unique")
        mapping_keys = [_mapping_key(item) for item in self.mappings]
        mapping_inputs = [item[:3] for item in mapping_keys]
        if mapping_keys != sorted(mapping_keys) or len(mapping_inputs) != len(
            set(mapping_inputs)
        ):
            raise ValueError("mappings must be sorted and unique")
        known_bindings = set(binding_ids)
        if any(item.binding_id not in known_bindings for item in self.mappings):
            raise ValueError("mapping references an unknown binding")
        source_pairs = {(item.source_component_id, item.advisory_kind) for item in self.source_pins}
        if any(
            (item.source_component_id, item.advisory_kind) not in source_pairs
            for item in self.mappings
        ):
            raise ValueError("mapping references an unpinned source")
        return self

    def sha256(self) -> str:
        return _domain_sha256("ash-advisory-gateway-profile-v1", self.model_dump(mode="json"))

    def source_matches(self, envelope: AdvisoryEnvelopeV1) -> bool:
        return any(item.matches(envelope) for item in self.source_pins)

    def mapping_for(self, envelope: AdvisoryEnvelopeV1) -> AdvisoryMappingRuleV1 | None:
        key = (envelope.source_component_id, envelope.advisory_kind, envelope.risk_label)
        return next((item for item in self.mappings if _mapping_key(item)[:3] == key), None)

    def binding(self, binding_id: str) -> AdvisoryCapabilityBindingV1:
        item = next(
            (candidate for candidate in self.bindings if candidate.binding_id == binding_id),
            None,
        )
        if item is None:  # pragma: no cover - guarded by profile validation
            raise AdvisoryGatewayConnectorError("profile binding disappeared")
        return item


class AdvisoryGatewayOutcomeV1(BaseModel):
    """Digest-linked, safe-to-publish result ending before execution or dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessAdvisoryGatewayOutcome.v1"] = (
        "AgenticSecurityHarnessAdvisoryGatewayOutcome.v1"
    )
    disposition: AdvisoryDisposition
    reason_code: str = Field(pattern=SAFE_TOKEN_PATTERN)
    selected_profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    selected_profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    input_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    profile_sha256: str = Field(pattern=SHA256_PATTERN)
    advisory_id: str | None = Field(default=None, pattern=SHA256_PATTERN)
    capability_request_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    gateway_call_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    gateway_decision_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    gateway_decision: GatewayDecisionV1 | None = Field(default=None, repr=False)
    gateway_evaluated: bool = False
    dispatch_performed: Literal[False] = False
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _coherent_outcome(self) -> AdvisoryGatewayOutcomeV1:
        gateway_links = (
            self.capability_request_sha256,
            self.gateway_call_sha256,
            self.gateway_decision_sha256,
            self.gateway_decision,
        )
        if self.disposition != "admit":
            if any(item is not None for item in gateway_links) or self.gateway_evaluated:
                raise ValueError("non-admit outcome cannot retain Gateway linkage")
            return self
        if self.advisory_id is None or any(item is None for item in gateway_links):
            raise ValueError(
                "admit outcome requires advisory, request, call, and decision identities"
            )
        if not self.gateway_evaluated:
            raise ValueError("admit outcome requires one pure Gateway evaluation")
        if self.gateway_decision_sha256 != _gateway_decision_sha256(self.gateway_decision):
            raise ValueError("Gateway decision commitment drifted")
        return self

    def sha256(self) -> str:
        return _domain_sha256("ash-advisory-gateway-outcome-v1", self.model_dump(mode="json"))


def compose_advisory_gateway_v1(
    profile: AdvisoryGatewayProfileV1,
    *,
    selected_profile_id: str,
    selected_profile_version: str,
    payload: bytes,
    gateway_policy: GatewayPolicyV1,
) -> AdvisoryGatewayOutcomeV1:
    """Map one exact advisory through one code-owned binding to a pure Gateway decision."""

    if type(profile) is not AdvisoryGatewayProfileV1:
        raise AdvisoryGatewayConnectorError("profile must be the exact V1 type")
    if type(gateway_policy) is not GatewayPolicyV1:
        raise AdvisoryGatewayConnectorError("gateway policy must be the exact V1 type")
    if not _is_safe_token(selected_profile_id) or not _is_safe_token(selected_profile_version):
        raise AdvisoryGatewayConnectorError("selected profile identity must use safe tokens")

    input_sha256 = _bounded_input_sha256(payload)
    common: dict[str, Any] = {
        "selected_profile_id": selected_profile_id,
        "selected_profile_version": selected_profile_version,
        "input_sha256": input_sha256,
        "profile_sha256": profile.sha256(),
    }
    if (
        selected_profile_id != profile.profile_id
        or selected_profile_version != profile.profile_version
    ):
        return AdvisoryGatewayOutcomeV1(
            disposition="reject", reason_code="profile_identity_mismatch", **common
        )

    try:
        envelope = _decode_advisory_envelope(payload)
    except _InputViolation as exc:
        return AdvisoryGatewayOutcomeV1(
            disposition="reject", reason_code=exc.reason_code, **common
        )
    common["advisory_id"] = envelope.advisory_id

    # Source pinning deliberately precedes label-to-capability mapping.
    if not profile.source_matches(envelope):
        return AdvisoryGatewayOutcomeV1(
            disposition="reject", reason_code="source_pin_mismatch", **common
        )
    mapping = profile.mapping_for(envelope)
    if mapping is None:
        return AdvisoryGatewayOutcomeV1(
            disposition="inconclusive", reason_code="mapping_not_registered", **common
        )

    binding = profile.binding(mapping.binding_id)
    request_id = "advisory:" + _domain_sha256(
        "ash-advisory-capability-request-id-v1",
        {
            "advisory_id": envelope.advisory_id,
            "binding_sha256": binding.sha256(),
            "profile_sha256": profile.sha256(),
        },
    )
    request = CapabilityRequestV1(
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        request_id=request_id,
        capability_id=binding.capability_id,
        arguments=binding.arguments(),
    )
    call = GatewayToolCallV1(
        call_id=f"advisory:{request.sha256()}",
        protocol=binding.gateway_protocol,
        tool_name=binding.gateway_tool_name,
        arguments=request.arguments,
    )
    decision = evaluate_gateway_tool_call(call, gateway_policy)
    return AdvisoryGatewayOutcomeV1(
        disposition="admit",
        reason_code="admitted_gateway_decision",
        capability_request_sha256=request.sha256(),
        gateway_call_sha256=_gateway_call_sha256(call),
        gateway_decision_sha256=_gateway_decision_sha256(decision),
        gateway_decision=decision,
        gateway_evaluated=True,
        **common,
    )


def advisory_gateway_connector_v1_json_schemas() -> dict[str, dict[str, Any]]:
    """Return deterministic schemas for the additive source-level API."""

    models: tuple[type[BaseModel], ...] = (
        AdvisoryProvenanceV1,
        AdvisoryEnvelopeV1,
        AdvisorySourcePinV1,
        AdvisoryFixedArgumentV1,
        AdvisoryCapabilityBindingV1,
        AdvisoryMappingRuleV1,
        AdvisoryGatewayProfileV1,
        AdvisoryGatewayOutcomeV1,
    )
    return {model.__name__: model.model_json_schema() for model in models}


def advisory_gateway_connector_v1_api_sha256() -> str:
    """Digest the explicit API and closed schema set for sanitized handoff."""

    return _domain_sha256(
        "ash-advisory-gateway-connector-api-v1",
        {
            "api_version": ADVISORY_GATEWAY_CONNECTOR_API_VERSION,
            "dependencies": {
                CapabilityRequestV1.__name__: CapabilityRequestV1.model_json_schema(),
                GatewayDecisionV1.__name__: GatewayDecisionV1.model_json_schema(),
                GatewayPolicyV1.__name__: GatewayPolicyV1.model_json_schema(),
                GatewayToolCallV1.__name__: GatewayToolCallV1.model_json_schema(),
            },
            "entry_points": ["compose_advisory_gateway_v1"],
            "schemas": advisory_gateway_connector_v1_json_schemas(),
        },
    )


def _decode_advisory_envelope(payload: bytes) -> AdvisoryEnvelopeV1:
    if type(payload) is not bytes:
        raise _InputViolation("input_type_invalid")
    if not payload:
        raise _InputViolation("input_empty")
    if len(payload) > MAX_ADVISORY_INPUT_BYTES:
        raise _InputViolation("input_oversized")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _InputViolation("malformed_utf8") from exc
    if text.startswith("\ufeff"):
        raise _InputViolation("bom_forbidden")
    try:
        root = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except _DuplicateKey as exc:
        raise _InputViolation("duplicate_json_key") from exc
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _InputViolation("malformed_json") from exc
    if type(root) is not dict:
        raise _InputViolation("root_type_invalid")
    try:
        _validate_json_value(root, depth=1, max_depth=4)
        canonical = _canonical_json_bytes(root)
    except (AdvisoryGatewayConnectorError, UnicodeEncodeError) as exc:
        raise _InputViolation("input_bounds_invalid") from exc
    if canonical != payload:
        raise _InputViolation("noncanonical_json")
    if _contains_forbidden_key(root):
        raise _InputViolation("authority_claim_forbidden")
    try:
        return AdvisoryEnvelopeV1.model_validate(root)
    except ValidationError as exc:
        reason = (
            "advisory_identity_mismatch"
            if "advisory identity does not match" in str(exc)
            else "envelope_shape_invalid"
        )
        raise _InputViolation(reason) from exc


def _validate_json_value(value: Any, *, depth: int, max_depth: int) -> None:
    if depth > max_depth:
        raise AdvisoryGatewayConnectorError("JSON depth exceeds the V1 limit")
    if value is None or isinstance(value, (bool, int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise AdvisoryGatewayConnectorError("non-finite JSON number")
        return
    if isinstance(value, str):
        _validate_unicode_scalar_string(value)
        if len(value.encode("utf-8")) > MAX_ADVISORY_INPUT_BYTES:
            raise AdvisoryGatewayConnectorError("JSON string exceeds the V1 limit")
        return
    if isinstance(value, list):
        if len(value) > 64:
            raise AdvisoryGatewayConnectorError("JSON array exceeds the V1 limit")
        for item in value:
            _validate_json_value(item, depth=depth + 1, max_depth=max_depth)
        return
    if isinstance(value, dict):
        if len(value) > 32:
            raise AdvisoryGatewayConnectorError("JSON object exceeds the V1 limit")
        for key, item in value.items():
            if not isinstance(key, str):
                raise AdvisoryGatewayConnectorError("JSON object key must be a string")
            _validate_unicode_scalar_string(key)
            _validate_json_value(item, depth=depth + 1, max_depth=max_depth)
        return
    raise AdvisoryGatewayConnectorError("unsupported JSON value")


def _validate_unicode_scalar_string(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise AdvisoryGatewayConnectorError("string contains a non-scalar Unicode value")


def _contains_forbidden_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = _normalized_key(key)
            if normalized in _NORMALIZED_FORBIDDEN_AUTHORITY_KEYS:
                return True
            if _contains_forbidden_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False


def _source_pin_key(item: AdvisorySourcePinV1) -> tuple[str, ...]:
    return (
        item.source_component_id,
        item.advisory_kind,
        item.source_contract_id,
        item.source_contract_version,
        item.source_commit,
        item.source_tree,
        item.source_contract_sha256,
        item.source_result_sha256,
    )


def _normalized_key(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _mapping_key(item: AdvisoryMappingRuleV1) -> tuple[str, str, str, str]:
    return (
        item.source_component_id,
        item.advisory_kind,
        item.risk_label,
        item.binding_id,
    )


def _bounded_input_sha256(payload: object) -> str | None:
    if type(payload) is not bytes or len(payload) > MAX_ADVISORY_INPUT_BYTES:
        return None
    return hashlib.sha256(b"ash-advisory-input-v1\0" + payload).hexdigest()


def _gateway_call_sha256(call: GatewayToolCallV1) -> str:
    return _domain_sha256("ash-advisory-gateway-call-link-v1", call.model_dump(mode="json"))


def _gateway_decision_sha256(decision: GatewayDecisionV1 | None) -> str | None:
    if decision is None:
        return None
    return _domain_sha256(
        "ash-advisory-gateway-decision-link-v1", decision.model_dump(mode="json")
    )


def _domain_sha256(domain: str, value: Any) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + _canonical_json_bytes(value)).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _is_safe_token(value: object) -> bool:
    import re

    return isinstance(value, str) and re.fullmatch(SAFE_TOKEN_PATTERN, value) is not None


class _DuplicateKey(ValueError):
    pass


class _InputViolation(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


__all__ = [
    "ADVISORY_GATEWAY_CONNECTOR_API_VERSION",
    "MAX_ADVISORY_INPUT_BYTES",
    "AdvisoryCapabilityBindingV1",
    "AdvisoryComponent",
    "AdvisoryDisposition",
    "AdvisoryEnvelopeV1",
    "AdvisoryEvidenceClass",
    "AdvisoryFixedArgumentV1",
    "AdvisoryGatewayConnectorError",
    "AdvisoryGatewayOutcomeV1",
    "AdvisoryGatewayProfileV1",
    "AdvisoryKind",
    "AdvisoryMappingRuleV1",
    "AdvisoryProvenanceV1",
    "AdvisoryRiskLabel",
    "AdvisorySourcePinV1",
    "advisory_gateway_connector_v1_api_sha256",
    "advisory_gateway_connector_v1_json_schemas",
    "compose_advisory_gateway_v1",
]
