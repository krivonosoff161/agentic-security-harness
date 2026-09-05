"""Strict, opt-in source-result ingress for the advisory Gateway connector.

This module validates two already-reviewed Harness data contracts without importing or
invoking their companion distributions.  It binds exact result bytes to maintainer-owned
source/profile authority, applies a caller-owned replay transition, and may call only the
existing pure advisory-to-Gateway composition.  It never dispatches or causes an effect.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agentic_security_harness.advisory_gateway_connector import (
    AdvisoryCapabilityBindingV1,
    AdvisoryEnvelopeV1,
    AdvisoryEvidenceClass,
    AdvisoryGatewayOutcomeV1,
    AdvisoryGatewayProfileV1,
    AdvisoryKind,
    AdvisoryMappingRuleV1,
    AdvisoryProvenanceV1,
    AdvisoryRiskLabel,
    AdvisorySourcePinV1,
    compose_advisory_gateway_v1,
)
from agentic_security_harness.policy_pack_extension import (
    PolicyPackEvaluationV1,
    reviewed_policy_pack_source_v1,
)
from agentic_security_harness.receipt_auditors import (
    MAX_FILTER_RECEIPT_BYTES,
    build_receipt_artifact_binding_v1,
    build_receipt_source_pin_v1,
)
from agentic_security_harness.runtime_gateway import (
    SAFE_TOKEN_PATTERN,
    SHA256_PATTERN,
    GatewayPolicyV1,
)

ADVISORY_INGRESS_API_VERSION = "AgenticSecurityHarnessAdvisoryIngress.v1"
MAX_PLAYBOOKS_EVALUATION_BYTES = 1_048_576
MAX_CONSUMED_RESULTS = 64
MAX_SEQUENCE = 9_007_199_254_740_991

AdvisoryIngressDisposition = Literal["admit", "reject"]
AdvisoryIngressSourceKind = Literal[
    "cheap_filter_receipt",
    "playbooks_policy_evaluation",
]

_GIT_SHA_PATTERN = r"^[0-9a-f]{40}$"
_SOURCE_CONTRACT_ID_PATTERN = r"^[a-z][a-z0-9_.-]{0,127}$"
_SOURCE_CONTRACT_VERSION_PATTERN = r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$"
_FORBIDDEN_SOURCE_KEYS = frozenset(
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
        "route",
        "scope",
        "token",
        "tool",
        "tool_definition",
        "tool_name",
    }
)
_NORMALIZED_FORBIDDEN_SOURCE_KEYS = frozenset(
    "".join(character for character in key.casefold() if character.isalnum())
    for key in _FORBIDDEN_SOURCE_KEYS
)


class AdvisoryIngressError(ValueError):
    """Raised only for trusted caller or profile misuse."""


class AdvisoryIngressProfileV1(BaseModel):
    """Immutable source authority and Gateway mapping selected by application code."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessAdvisoryIngressProfile.v1"] = (
        "AgenticSecurityHarnessAdvisoryIngressProfile.v1"
    )
    profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    source_kind: AdvisoryIngressSourceKind
    source_component_id: Literal["llm-cheap-filter", "llm-safety-playbooks"]
    advisory_kind: AdvisoryKind
    source_contract_id: str = Field(pattern=_SOURCE_CONTRACT_ID_PATTERN)
    source_contract_version: str = Field(pattern=_SOURCE_CONTRACT_VERSION_PATTERN)
    source_commit: str = Field(pattern=_GIT_SHA_PATTERN)
    source_tree: str = Field(pattern=_GIT_SHA_PATTERN)
    source_contract_sha256: str = Field(pattern=SHA256_PATTERN)
    evidence_class: AdvisoryEvidenceClass
    fixed_risk_label: AdvisoryRiskLabel
    fixed_advisory_text: str = Field(min_length=1, max_length=512, repr=False)
    fixed_summary: str = Field(min_length=1, max_length=256, repr=False)
    bindings: tuple[AdvisoryCapabilityBindingV1, ...] = Field(min_length=1, max_length=32)
    mappings: tuple[AdvisoryMappingRuleV1, ...] = Field(max_length=1)
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _closed_source_and_mapping(self) -> AdvisoryIngressProfileV1:
        _validate_profile_text(
            self.fixed_advisory_text, "fixed advisory text", maximum_bytes=4_096
        )
        _validate_profile_text(self.fixed_summary, "fixed summary", maximum_bytes=512)
        if self.source_kind == "cheap_filter_receipt":
            pin = build_receipt_source_pin_v1("llm-cheap-filter")
            if self.evidence_class != "external_unreviewed":
                raise ValueError("Cheap Filter receipt evidence class must remain unreviewed")
            expected = (
                "llm-cheap-filter",
                "cheap_filter_finding",
                pin.contract_id,
                pin.contract_version,
                pin.source_commit,
                pin.source_tree,
                pin.contract_sha256,
                "inconclusive",
            )
        else:
            source = reviewed_policy_pack_source_v1()
            expected = (
                "llm-safety-playbooks",
                "playbooks_policy_evaluation",
                "policy-pack-evaluation",
                "1.0",
                source.source_commit,
                source.source_tree,
                source.output_schema_sha256,
                self.fixed_risk_label,
            )
        actual = (
            self.source_component_id,
            self.advisory_kind,
            self.source_contract_id,
            self.source_contract_version,
            self.source_commit,
            self.source_tree,
            self.source_contract_sha256,
            self.fixed_risk_label,
        )
        if actual != expected:
            raise ValueError("ingress profile does not match the reviewed source contract")
        if any(
            (
                item.source_component_id,
                item.advisory_kind,
                item.risk_label,
            )
            != (
                self.source_component_id,
                self.advisory_kind,
                self.fixed_risk_label,
            )
            for item in self.mappings
        ):
            raise ValueError("ingress mapping must use the fixed source tuple")
        _derived_gateway_profile(self, source_result_sha256="0" * 64)
        return self

    def sha256(self) -> str:
        """Return the stable identity of the static maintainer-owned profile."""

        return _domain_sha256("ash-advisory-ingress-profile-v1", self.model_dump(mode="json"))


class AdvisoryIngressReplayStateV1(BaseModel):
    """Caller-owned bounded state for one explicit sequential ingress session."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessAdvisoryIngressReplayState.v1"] = (
        "AgenticSecurityHarnessAdvisoryIngressReplayState.v1"
    )
    session_sha256: str = Field(pattern=SHA256_PATTERN)
    next_sequence: int = Field(ge=0, le=MAX_SEQUENCE)
    previous_ingress_receipt_sha256: str | None = Field(
        default=None, pattern=SHA256_PATTERN
    )
    consumed_source_result_sha256s: tuple[str, ...] = Field(
        default=(), max_length=MAX_CONSUMED_RESULTS
    )
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _closed_history(self) -> AdvisoryIngressReplayStateV1:
        values = self.consumed_source_result_sha256s
        if values != tuple(sorted(set(values))):
            raise ValueError("consumed source-result digests must be sorted and unique")
        if self.next_sequence == 0:
            if self.previous_ingress_receipt_sha256 is not None or values:
                raise ValueError("initial replay state cannot retain prior transitions")
        elif self.previous_ingress_receipt_sha256 is None:
            raise ValueError("advanced replay state requires the previous receipt digest")
        return self

    def sha256(self) -> str:
        return _domain_sha256("ash-advisory-ingress-replay-state-v1", self.model_dump(mode="json"))


class AdvisoryIngressOutcomeV1(BaseModel):
    """Safe metadata for one rejected or admitted source-result transition."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessAdvisoryIngressOutcome.v1"] = (
        "AgenticSecurityHarnessAdvisoryIngressOutcome.v1"
    )
    ingress_disposition: AdvisoryIngressDisposition
    reason_code: str = Field(pattern=SAFE_TOKEN_PATTERN)
    selected_profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    selected_profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    ingress_profile_sha256: str = Field(pattern=SHA256_PATTERN)
    selected_session_sha256: str = Field(pattern=SHA256_PATTERN)
    input_state_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0, le=MAX_SEQUENCE)
    source_result_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    advisory_id: str | None = Field(default=None, pattern=SHA256_PATTERN)
    connector_outcome_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    connector_outcome: AdvisoryGatewayOutcomeV1 | None = Field(default=None, repr=False)
    next_replay_state: AdvisoryIngressReplayStateV1 | None = Field(default=None, repr=False)
    ingress_receipt_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    connector_invoked: bool = False
    gateway_evaluated: bool = False
    dispatch_performed: Literal[False] = False
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _coherent_transition(self) -> AdvisoryIngressOutcomeV1:
        links = (
            self.advisory_id,
            self.connector_outcome_sha256,
            self.connector_outcome,
            self.next_replay_state,
            self.ingress_receipt_sha256,
        )
        if self.ingress_disposition == "reject":
            if any(item is not None for item in links) or self.connector_invoked:
                raise ValueError("rejected ingress cannot retain connector or transition links")
            if self.gateway_evaluated:
                raise ValueError("rejected ingress cannot evaluate the Gateway")
            return self
        if self.source_result_sha256 is None or any(item is None for item in links):
            raise ValueError("admitted ingress requires complete source and transition links")
        if not self.connector_invoked:
            raise ValueError("admitted ingress requires exactly one connector invocation")
        assert self.connector_outcome is not None
        assert self.next_replay_state is not None
        if self.connector_outcome_sha256 != self.connector_outcome.sha256():
            raise ValueError("connector outcome commitment drifted")
        if self.gateway_evaluated != self.connector_outcome.gateway_evaluated:
            raise ValueError("Gateway evaluation state drifted")
        if self.next_replay_state.previous_ingress_receipt_sha256 != (
            self.ingress_receipt_sha256
        ):
            raise ValueError("next replay state does not bind the ingress receipt")
        return self

    def sha256(self) -> str:
        return _domain_sha256("ash-advisory-ingress-outcome-v1", self.model_dump(mode="json"))


def ingest_advisory_source_result_v1(
    profile: AdvisoryIngressProfileV1,
    *,
    selected_profile_id: str,
    selected_profile_version: str,
    selected_session_sha256: str,
    sequence: int,
    replay_state: AdvisoryIngressReplayStateV1,
    payload: bytes,
    gateway_policy: GatewayPolicyV1,
) -> AdvisoryIngressOutcomeV1:
    """Validate, bind, and project one exact result through the pure connector."""

    profile, replay_state, gateway_policy = _require_trusted_inputs(
        profile,
        selected_profile_id=selected_profile_id,
        selected_profile_version=selected_profile_version,
        selected_session_sha256=selected_session_sha256,
        sequence=sequence,
        replay_state=replay_state,
        gateway_policy=gateway_policy,
    )
    profile_sha256 = profile.sha256()
    input_state_sha256 = replay_state.sha256()
    common: dict[str, Any] = {
        "selected_profile_id": selected_profile_id,
        "selected_profile_version": selected_profile_version,
        "ingress_profile_sha256": profile_sha256,
        "selected_session_sha256": selected_session_sha256,
        "input_state_sha256": input_state_sha256,
        "sequence": sequence,
    }
    if (
        selected_profile_id != profile.profile_id
        or selected_profile_version != profile.profile_version
    ):
        return _rejected("profile_identity_mismatch", common)
    if selected_session_sha256 != replay_state.session_sha256:
        return _rejected("session_identity_mismatch", common)
    if sequence != replay_state.next_sequence:
        return _rejected("sequence_mismatch", common)
    if len(replay_state.consumed_source_result_sha256s) >= MAX_CONSUMED_RESULTS:
        return _rejected("replay_history_full", common)

    preliminary_sha256 = _bounded_source_result_sha256(profile, payload)
    if preliminary_sha256 in replay_state.consumed_source_result_sha256s:
        return _rejected(
            "source_result_replay",
            common,
            source_result_sha256=preliminary_sha256,
        )

    try:
        source_result_sha256, semantic_label = _validate_source_result(profile, payload)
    except _IngressViolation as exc:
        return _rejected(exc.reason_code, common, source_result_sha256=exc.input_sha256)
    common["source_result_sha256"] = source_result_sha256
    if semantic_label != profile.fixed_risk_label:
        return _rejected("source_semantic_label_mismatch", common)

    envelope_bytes, advisory_id = _derived_envelope(profile, source_result_sha256)
    connector_profile = _derived_gateway_profile(profile, source_result_sha256)
    connector_outcome = compose_advisory_gateway_v1(
        connector_profile,
        selected_profile_id=selected_profile_id,
        selected_profile_version=selected_profile_version,
        payload=envelope_bytes,
        gateway_policy=gateway_policy,
    )
    consumed = tuple(
        sorted((*replay_state.consumed_source_result_sha256s, source_result_sha256))
    )
    transition = {
        "advisory_id": advisory_id,
        "connector_outcome_sha256": connector_outcome.sha256(),
        "input_state_sha256": input_state_sha256,
        "ingress_profile_sha256": profile_sha256,
        "next_consumed_source_result_sha256s": consumed,
        "next_sequence": sequence + 1,
        "selected_session_sha256": selected_session_sha256,
        "sequence": sequence,
        "source_result_sha256": source_result_sha256,
    }
    ingress_receipt_sha256 = _domain_sha256(
        "ash-advisory-ingress-transition-v1", transition
    )
    next_state = AdvisoryIngressReplayStateV1(
        session_sha256=selected_session_sha256,
        next_sequence=sequence + 1,
        previous_ingress_receipt_sha256=ingress_receipt_sha256,
        consumed_source_result_sha256s=consumed,
    )
    return AdvisoryIngressOutcomeV1(
        ingress_disposition="admit",
        reason_code="source_result_admitted",
        advisory_id=advisory_id,
        connector_outcome_sha256=connector_outcome.sha256(),
        connector_outcome=connector_outcome,
        next_replay_state=next_state,
        ingress_receipt_sha256=ingress_receipt_sha256,
        connector_invoked=True,
        gateway_evaluated=connector_outcome.gateway_evaluated,
        **common,
    )


def advisory_ingress_v1_json_schemas() -> dict[str, dict[str, Any]]:
    """Return the closed public schema set for the explicit ingress API."""

    models: tuple[type[BaseModel], ...] = (
        AdvisoryIngressProfileV1,
        AdvisoryIngressReplayStateV1,
        AdvisoryIngressOutcomeV1,
    )
    return {model.__name__: model.model_json_schema() for model in models}


def advisory_ingress_v1_api_sha256() -> str:
    """Return a sanitized identity for this API and its dependencies."""

    return _domain_sha256(
        "ash-advisory-ingress-api-v1",
        {
            "api_version": ADVISORY_INGRESS_API_VERSION,
            "dependencies": {
                "AdvisoryGatewayOutcomeV1": AdvisoryGatewayOutcomeV1.model_json_schema(),
                "GatewayPolicyV1": GatewayPolicyV1.model_json_schema(),
                "PolicyPackEvaluationV1": PolicyPackEvaluationV1.model_json_schema(),
            },
            "entry_points": ["ingest_advisory_source_result_v1"],
            "schemas": advisory_ingress_v1_json_schemas(),
        },
    )


def _validate_source_result(
    profile: AdvisoryIngressProfileV1, payload: object
) -> tuple[str, AdvisoryRiskLabel]:
    maximum = (
        MAX_FILTER_RECEIPT_BYTES
        if profile.source_kind == "cheap_filter_receipt"
        else MAX_PLAYBOOKS_EVALUATION_BYTES
    )
    if type(payload) is not bytes:
        raise _IngressViolation("input_type_invalid")
    if not payload:
        raise _IngressViolation("input_empty")
    if len(payload) > maximum:
        raise _IngressViolation("input_oversized")
    input_sha256 = hashlib.sha256(payload).hexdigest()
    try:
        root = _decode_canonical_object(
            payload,
            trailing_newline=profile.source_kind == "cheap_filter_receipt",
        )
    except _IngressViolation as exc:
        exc.input_sha256 = input_sha256
        raise
    if _contains_forbidden_key(root):
        raise _IngressViolation("authority_claim_forbidden", input_sha256)
    if profile.source_kind == "cheap_filter_receipt":
        pin = build_receipt_source_pin_v1("llm-cheap-filter")
        event_id = hashlib.sha256(b"ash-advisory-ingress-event-v1\0" + payload).hexdigest()
        binding = build_receipt_artifact_binding_v1(
            pin=pin,
            event_id=event_id,
            payload=payload,
        )
        if binding.audit_state != "valid_accounting":
            raise _IngressViolation("source_contract_invalid", input_sha256)
        return input_sha256, "inconclusive"
    try:
        evaluation = PolicyPackEvaluationV1.model_validate(root)
    except ValidationError as exc:
        raise _IngressViolation("source_contract_invalid", input_sha256) from exc
    if _canonical_json_bytes(evaluation.model_dump(mode="json")) != payload:
        raise _IngressViolation("source_contract_invalid", input_sha256)
    return input_sha256, evaluation.overall_advisory_disposition


def _derived_envelope(
    profile: AdvisoryIngressProfileV1, source_result_sha256: str
) -> tuple[bytes, str]:
    unsigned: dict[str, Any] = {
        "advisory_kind": profile.advisory_kind,
        "advisory_text": profile.fixed_advisory_text,
        "operational_authority": "none",
        "provenance": AdvisoryProvenanceV1(
            source_commit=profile.source_commit,
            source_tree=profile.source_tree,
            source_contract_sha256=profile.source_contract_sha256,
            source_result_sha256=source_result_sha256,
            evidence_class=profile.evidence_class,
        ).model_dump(mode="json"),
        "risk_label": profile.fixed_risk_label,
        "schema_version": "AgenticSecurityHarnessAdvisoryEnvelope.v1",
        "source_component_id": profile.source_component_id,
        "source_contract_id": profile.source_contract_id,
        "source_contract_version": profile.source_contract_version,
        "summary": profile.fixed_summary,
    }
    advisory_id = hashlib.sha256(
        b"ash-advisory-envelope-v1\0" + _canonical_json_bytes(unsigned)
    ).hexdigest()
    envelope = AdvisoryEnvelopeV1(advisory_id=advisory_id, **unsigned)
    return _canonical_json_bytes(envelope.model_dump(mode="json")), advisory_id


def _derived_gateway_profile(
    profile: AdvisoryIngressProfileV1, source_result_sha256: str
) -> AdvisoryGatewayProfileV1:
    return AdvisoryGatewayProfileV1(
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        source_pins=(
            AdvisorySourcePinV1(
                source_component_id=profile.source_component_id,
                advisory_kind=profile.advisory_kind,
                source_contract_id=profile.source_contract_id,
                source_contract_version=profile.source_contract_version,
                source_commit=profile.source_commit,
                source_tree=profile.source_tree,
                source_contract_sha256=profile.source_contract_sha256,
                source_result_sha256=source_result_sha256,
                accepted_evidence_classes=(profile.evidence_class,),
            ),
        ),
        bindings=profile.bindings,
        mappings=profile.mappings,
    )


def _decode_canonical_object(payload: bytes, *, trailing_newline: bool) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _IngressViolation("malformed_utf8") from exc
    if text.startswith("\ufeff"):
        raise _IngressViolation("bom_forbidden")
    try:
        root = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except _DuplicateKey as exc:
        raise _IngressViolation("duplicate_json_key") from exc
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _IngressViolation("malformed_json") from exc
    if type(root) is not dict:
        raise _IngressViolation("root_type_invalid")
    try:
        _validate_json_value(root, depth=1, max_depth=8)
        canonical = _canonical_json_bytes(root) + (b"\n" if trailing_newline else b"")
    except (AdvisoryIngressError, UnicodeEncodeError) as exc:
        raise _IngressViolation("input_bounds_invalid") from exc
    if payload != canonical:
        raise _IngressViolation("noncanonical_json")
    return root


def _validate_json_value(value: Any, *, depth: int, max_depth: int) -> None:
    if depth > max_depth:
        raise AdvisoryIngressError("JSON depth exceeds the V1 limit")
    if value is None or isinstance(value, (bool, int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise AdvisoryIngressError("non-finite JSON number")
        return
    if isinstance(value, str):
        _validate_unicode_scalar_string(value)
        return
    if isinstance(value, list):
        if len(value) > 100_000:
            raise AdvisoryIngressError("JSON array exceeds the V1 limit")
        for item in value:
            _validate_json_value(item, depth=depth + 1, max_depth=max_depth)
        return
    if isinstance(value, dict):
        if len(value) > 128:
            raise AdvisoryIngressError("JSON object exceeds the V1 limit")
        for key, item in value.items():
            _validate_unicode_scalar_string(key)
            _validate_json_value(item, depth=depth + 1, max_depth=max_depth)
        return
    raise AdvisoryIngressError("unsupported JSON value")


def _contains_forbidden_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = "".join(
                character for character in key.casefold() if character.isalnum()
            )
            if normalized in _NORMALIZED_FORBIDDEN_SOURCE_KEYS:
                return True
            if _contains_forbidden_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False


def _require_trusted_inputs(
    profile: object,
    *,
    selected_profile_id: object,
    selected_profile_version: object,
    selected_session_sha256: object,
    sequence: object,
    replay_state: object,
    gateway_policy: object,
) -> tuple[AdvisoryIngressProfileV1, AdvisoryIngressReplayStateV1, GatewayPolicyV1]:
    if type(profile) is not AdvisoryIngressProfileV1:
        raise AdvisoryIngressError("profile must be the exact V1 type")
    if type(replay_state) is not AdvisoryIngressReplayStateV1:
        raise AdvisoryIngressError("replay state must be the exact V1 type")
    if type(gateway_policy) is not GatewayPolicyV1:
        raise AdvisoryIngressError("gateway policy must be the exact V1 type")
    try:
        checked_profile = AdvisoryIngressProfileV1.model_validate(
            profile.model_dump(mode="python")
        )
        checked_state = AdvisoryIngressReplayStateV1.model_validate(
            replay_state.model_dump(mode="python")
        )
        checked_policy = GatewayPolicyV1.model_validate(gateway_policy.model_dump(mode="python"))
    except (AttributeError, ValidationError, ValueError) as exc:
        raise AdvisoryIngressError("trusted ingress configuration violates V1") from exc
    if (
        checked_profile != profile
        or checked_state != replay_state
        or checked_policy != gateway_policy
    ):
        raise AdvisoryIngressError("trusted ingress configuration changed during validation")
    if not _is_safe_token(selected_profile_id) or not _is_safe_token(
        selected_profile_version
    ):
        raise AdvisoryIngressError("selected profile identity must use safe tokens")
    if not isinstance(selected_session_sha256, str) or re.fullmatch(
        SHA256_PATTERN, selected_session_sha256
    ) is None:
        raise AdvisoryIngressError("selected session identity must be lowercase SHA-256")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= (
        MAX_SEQUENCE - 1
    ):
        raise AdvisoryIngressError("sequence is outside the V1 range")
    return checked_profile, checked_state, checked_policy


def _bounded_source_result_sha256(
    profile: AdvisoryIngressProfileV1, payload: object
) -> str | None:
    maximum = (
        MAX_FILTER_RECEIPT_BYTES
        if profile.source_kind == "cheap_filter_receipt"
        else MAX_PLAYBOOKS_EVALUATION_BYTES
    )
    if type(payload) is not bytes or not payload or len(payload) > maximum:
        return None
    return hashlib.sha256(payload).hexdigest()


def _rejected(
    reason_code: str,
    common: dict[str, Any],
    *,
    source_result_sha256: str | None = None,
) -> AdvisoryIngressOutcomeV1:
    values = dict(common)
    if source_result_sha256 is not None:
        values["source_result_sha256"] = source_result_sha256
    return AdvisoryIngressOutcomeV1(
        ingress_disposition="reject",
        reason_code=reason_code,
        **values,
    )


def _validate_profile_text(value: str, label: str, *, maximum_bytes: int) -> None:
    _validate_unicode_scalar_string(value)
    if len(value.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{label} exceeds the V1 byte limit")


def _validate_unicode_scalar_string(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise AdvisoryIngressError("string contains a non-scalar Unicode value")


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _domain_sha256(domain: str, value: Any) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + _canonical_json_bytes(value)).hexdigest()


def _is_safe_token(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(SAFE_TOKEN_PATTERN, value) is not None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


class _DuplicateKey(ValueError):
    pass


class _IngressViolation(ValueError):
    def __init__(self, reason_code: str, input_sha256: str | None = None) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.input_sha256 = input_sha256


__all__ = [
    "ADVISORY_INGRESS_API_VERSION",
    "AdvisoryIngressError",
    "AdvisoryIngressOutcomeV1",
    "AdvisoryIngressProfileV1",
    "AdvisoryIngressReplayStateV1",
    "advisory_ingress_v1_api_sha256",
    "advisory_ingress_v1_json_schemas",
    "ingest_advisory_source_result_v1",
]
