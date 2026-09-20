"""Strict external Playbooks receipt-pair ingress for the advisory connector.

The caller supplies exact, already-produced input and output receipt bytes plus an
immutable code-owned profile.  This module never imports or invokes Playbooks and ends at
the existing pure Gateway policy decision.  It retains only content-free commitments.
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
    AdvisoryGatewayOutcomeV1,
    AdvisoryGatewayProfileV1,
    AdvisoryMappingRuleV1,
    AdvisoryProvenanceV1,
    AdvisorySourcePinV1,
    compose_advisory_gateway_v1,
)
from agentic_security_harness.advisory_ingress import AdvisoryIngressReplayStateV1
from agentic_security_harness.runtime_gateway import (
    SAFE_TOKEN_PATTERN,
    SHA256_PATTERN,
    GatewayPolicyV1,
)

EXTERNAL_PLAYBOOKS_INGRESS_API_VERSION = "AgenticSecurityHarnessExternalPlaybooksIngress.v1"
PLAYBOOKS_INPUT_SCHEMA = "llm-safety-policy-input-receipt-v1.0"
PLAYBOOKS_OUTPUT_SCHEMA = "llm-safety-policy-evaluation-receipt-v1.0"
PLAYBOOKS_SOURCE_COMMIT = "190769a15a44f5a5af790b33fc37724e6417c27f"
PLAYBOOKS_SOURCE_TREE = "e3a5601a779c8b2e2f92516da30cf2750d320b5b"
PLAYBOOKS_SOURCE_BLOB = "5efefc3aa8baecb5496ee87717b625c4efe71331"
PLAYBOOKS_SOURCE_SHA256 = "3e117b26a75e4aa297ef82658059a627d251000f27bb819f5b332edfbc06c5c8"
PLAYBOOKS_PACK_SHA256 = "44fa5aced73c6a2fc1eb3cb827955d245c887fa8d7c596e353bb2e9678119169"
PLAYBOOKS_PACK_ARTIFACT_SHA256 = "1c8ca14e6ab83d92742f6fba0b0d1b1bc422ebe30163c6619e9c80f5413b8915"
PLAYBOOKS_PACK_SCHEMA_SHA256 = "fd99422169c4cbfbe0f80a16a39cf7557d7ef6d28669b03ae940b24b9e2172a1"
PLAYBOOKS_INPUT_SCHEMA_SHA256 = "d6a39ad8cb1cfc9e61094fa3c92b11d66b2df3370a326f89ecb4a52c49dd3e8b"
PLAYBOOKS_OUTPUT_SCHEMA_SHA256 = "b5e4d5554fb930529fd493dad903a25698c99c62c57d99934f66edda8b4f6f1c"
PLAYBOOKS_MANIFEST_SHA256 = "f16f7b905150a5b19adbf8c412c1f6eede23718ef0dd35187e4fd8381d92463c"
MAX_EXTERNAL_PLAYBOOKS_INPUT_BYTES = 16_384
MAX_EXTERNAL_PLAYBOOKS_OUTPUT_BYTES = 65_536
MAX_EXTERNAL_PLAYBOOKS_DEPTH = 8

ExternalPlaybooksDisposition = Literal["admit", "reject"]
ExternalPlaybooksStage = Literal[
    "configuration",
    "replay",
    "input_bytes",
    "output_bytes",
    "schema_authority",
    "identity_correspondence",
    "semantic_mapping",
    "complete",
]
PlaybooksDisposition = Literal["observe", "challenge", "escalate", "abstain"]

_INPUT_DOMAIN = b"llm-safety-playbooks/policy-input/v1\0"
_OUTPUT_DOMAIN = b"llm-safety-playbooks/policy-output/v1\0"
_INPUT_BYTES_DOMAIN = b"llm-safety-playbooks/policy-input-bytes/v1\0"
_DISPOSITION_RANK = {
    value: index for index, value in enumerate(("observe", "challenge", "escalate", "abstain"))
}
_SOURCE_CONTRACT_ID = "llm-safety-policy-evaluation-receipt"
_SOURCE_CONTRACT_VERSION = "1.0"
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
        "route",
        "scope",
        "token",
        "tool",
        "tool_definition",
        "tool_name",
    }
)
_NORMALIZED_FORBIDDEN_AUTHORITY_KEYS = frozenset(
    "".join(character for character in key.casefold() if character.isalnum())
    for key in _FORBIDDEN_AUTHORITY_KEYS
)
_RULES: tuple[dict[str, str], ...] = (
    {
        "rule_id": "untrusted-instructions-v1",
        "signal": "untrusted_instructions_detected",
        "playbook_path": "playbooks/data-vs-instructions.md",
        "playbook_sha256": "bf993293a8a4b8340029bdfbc8fa3ee2052450c7a5ad4618143a0b08e44c9298",
        "present": "challenge",
        "unknown": "challenge",
    },
    {
        "rule_id": "secret-exposure-v1",
        "signal": "secret_exposure_risk",
        "playbook_path": "playbooks/secret-handling.md",
        "playbook_sha256": "91f1d24612c787bf93f7d2e4e7c7fb7d129c4a0994ca26da3ea0f5715b4b0618",
        "present": "abstain",
        "unknown": "abstain",
    },
    {
        "rule_id": "generated-resource-v1",
        "signal": "generated_resource_unverified",
        "playbook_path": "playbooks/generated-resource-check.md",
        "playbook_sha256": "3e4884da1b30fcb56b5ebed2cedb5b7f6b652dcabcf3a7221bb331a514fafc95",
        "present": "challenge",
        "unknown": "challenge",
    },
    {
        "rule_id": "git-change-control-v1",
        "signal": "git_change_control_unclear",
        "playbook_path": "playbooks/git-agent-safety.md",
        "playbook_sha256": "a5fc7e5ac3c17e7b12dffa0bee026e3b3515e7bf1e3a24e1b8d3c57453b06ca2",
        "present": "escalate",
        "unknown": "escalate",
    },
    {
        "rule_id": "handoff-verification-v1",
        "signal": "handoff_verification_incomplete",
        "playbook_path": "playbooks/handoff-verification.md",
        "playbook_sha256": "46553384d34f5fa4c13c2d745d9260bc6fc83f2923e280f792ad5c14d9280bec",
        "present": "challenge",
        "unknown": "challenge",
    },
    {
        "rule_id": "research-authorization-v1",
        "signal": "research_authorization_unclear",
        "playbook_path": "playbooks/safe-research-scope.md",
        "playbook_sha256": "709c4482278af2d2497317352d92e05059b20a0108d11dc108234ab6c791c221",
        "present": "abstain",
        "unknown": "abstain",
    },
    {
        "rule_id": "observation-metadata-v1",
        "signal": "observation_metadata_invalid",
        "playbook_path": "playbooks/canonical-observation-review.md",
        "playbook_sha256": "bd2c518c484072804f860d50d4b4ff52c246fafbaac4c7fb87db86aafd2f79f0",
        "present": "abstain",
        "unknown": "abstain",
    },
)


class ExternalPlaybooksIngressError(ValueError):
    """Raised only for trusted caller/configuration misuse."""


class ExternalPlaybooksIngressProfileV1(BaseModel):
    """Immutable source pins and application-owned advisory mapping."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessExternalPlaybooksIngressProfile.v1"] = (
        "AgenticSecurityHarnessExternalPlaybooksIngressProfile.v1"
    )
    profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    source_commit: str = PLAYBOOKS_SOURCE_COMMIT
    source_tree: str = PLAYBOOKS_SOURCE_TREE
    source_blob: str = PLAYBOOKS_SOURCE_BLOB
    source_sha256: str = Field(default=PLAYBOOKS_SOURCE_SHA256, pattern=SHA256_PATTERN)
    input_schema_sha256: str = Field(default=PLAYBOOKS_INPUT_SCHEMA_SHA256, pattern=SHA256_PATTERN)
    output_schema_sha256: str = Field(
        default=PLAYBOOKS_OUTPUT_SCHEMA_SHA256, pattern=SHA256_PATTERN
    )
    pack_sha256: str = Field(default=PLAYBOOKS_PACK_SHA256, pattern=SHA256_PATTERN)
    pack_artifact_sha256: str = Field(
        default=PLAYBOOKS_PACK_ARTIFACT_SHA256, pattern=SHA256_PATTERN
    )
    pack_schema_sha256: str = Field(default=PLAYBOOKS_PACK_SCHEMA_SHA256, pattern=SHA256_PATTERN)
    manifest_sha256: str = Field(default=PLAYBOOKS_MANIFEST_SHA256, pattern=SHA256_PATTERN)
    expected_disposition: PlaybooksDisposition
    fixed_advisory_text: str = Field(min_length=1, max_length=512, repr=False)
    fixed_summary: str = Field(min_length=1, max_length=256, repr=False)
    bindings: tuple[AdvisoryCapabilityBindingV1, ...] = Field(min_length=1, max_length=32)
    mappings: tuple[AdvisoryMappingRuleV1, ...] = Field(min_length=1, max_length=1)
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _closed_profile(self) -> ExternalPlaybooksIngressProfileV1:
        actual_pins = (
            self.source_commit,
            self.source_tree,
            self.source_blob,
            self.source_sha256,
            self.input_schema_sha256,
            self.output_schema_sha256,
            self.pack_sha256,
            self.pack_artifact_sha256,
            self.pack_schema_sha256,
            self.manifest_sha256,
        )
        expected_pins = (
            PLAYBOOKS_SOURCE_COMMIT,
            PLAYBOOKS_SOURCE_TREE,
            PLAYBOOKS_SOURCE_BLOB,
            PLAYBOOKS_SOURCE_SHA256,
            PLAYBOOKS_INPUT_SCHEMA_SHA256,
            PLAYBOOKS_OUTPUT_SCHEMA_SHA256,
            PLAYBOOKS_PACK_SHA256,
            PLAYBOOKS_PACK_ARTIFACT_SHA256,
            PLAYBOOKS_PACK_SCHEMA_SHA256,
            PLAYBOOKS_MANIFEST_SHA256,
        )
        if actual_pins != expected_pins:
            raise ValueError("external Playbooks profile pin drift")
        _validate_scalar_text(self.fixed_advisory_text, 4_096)
        _validate_scalar_text(self.fixed_summary, 512)
        mapping = self.mappings[0]
        if (
            mapping.source_component_id,
            mapping.advisory_kind,
            mapping.risk_label,
        ) != (
            "llm-safety-playbooks",
            "playbooks_policy_evaluation",
            self.expected_disposition,
        ):
            raise ValueError("mapping must use the fixed external Playbooks tuple")
        _derived_connector_profile(self, "0" * 64)
        return self

    def sha256(self) -> str:
        value = self.model_dump(mode="json")
        value["rule_table"] = _RULES
        return _domain_sha256("ash-external-playbooks-profile-v1", value)


class ExternalPlaybooksIngressOutcomeV1(BaseModel):
    """Content-free result for one external pair and replay transition."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessExternalPlaybooksIngressOutcome.v1"] = (
        "AgenticSecurityHarnessExternalPlaybooksIngressOutcome.v1"
    )
    ingress_disposition: ExternalPlaybooksDisposition
    stage: ExternalPlaybooksStage
    reason_code: str = Field(pattern=SAFE_TOKEN_PATTERN)
    selected_profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    selected_profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    profile_sha256: str = Field(pattern=SHA256_PATTERN)
    selected_subject_sha256: str = Field(pattern=SHA256_PATTERN)
    selected_session_sha256: str = Field(pattern=SHA256_PATTERN)
    input_state_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0, le=9_007_199_254_740_991)
    input_bytes_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    source_result_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    input_receipt_id: str | None = Field(default=None, pattern=SHA256_PATTERN)
    external_receipt_id: str | None = Field(default=None, pattern=SHA256_PATTERN)
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
    def _coherent(self) -> ExternalPlaybooksIngressOutcomeV1:
        downstream = (
            self.advisory_id,
            self.connector_outcome_sha256,
            self.connector_outcome,
            self.next_replay_state,
            self.ingress_receipt_sha256,
        )
        if self.ingress_disposition == "reject":
            if any(value is not None for value in downstream):
                raise ValueError("rejected pair cannot retain downstream links")
            if self.connector_invoked or self.gateway_evaluated or self.stage == "complete":
                raise ValueError("rejected pair cannot reach a downstream stage")
            return self
        required = (
            self.input_bytes_sha256,
            self.source_result_sha256,
            self.input_receipt_id,
            self.external_receipt_id,
            *downstream,
        )
        if self.stage != "complete" or any(value is None for value in required):
            raise ValueError("admitted pair requires complete digest linkage")
        if not self.connector_invoked:
            raise ValueError("admitted pair requires one advisory connector call")
        next_state = self.next_replay_state
        if self.connector_outcome is None or next_state is None:
            raise ValueError("admitted pair requires complete digest linkage")
        if self.connector_outcome_sha256 != self.connector_outcome.sha256():
            raise ValueError("connector outcome commitment drift")
        if self.gateway_evaluated != self.connector_outcome.gateway_evaluated:
            raise ValueError("Gateway evaluation state drift")
        if next_state.previous_ingress_receipt_sha256 != self.ingress_receipt_sha256:
            raise ValueError("next replay state does not bind the ingress receipt")
        return self

    def sha256(self) -> str:
        return _domain_sha256("ash-external-playbooks-outcome-v1", self.model_dump(mode="json"))


def ingest_external_playbooks_pair_v1(
    profile: ExternalPlaybooksIngressProfileV1,
    *,
    selected_profile_id: str,
    selected_profile_version: str,
    selected_subject_sha256: str,
    selected_session_sha256: str,
    sequence: int,
    replay_state: AdvisoryIngressReplayStateV1,
    input_payload: bytes,
    output_payload: bytes,
    gateway_policy: GatewayPolicyV1,
) -> ExternalPlaybooksIngressOutcomeV1:
    """Validate one exact pair, then call only the non-executing advisory connector."""

    profile, replay_state, gateway_policy = _require_trusted_inputs(
        profile, replay_state, gateway_policy
    )
    common: dict[str, Any] = {
        "selected_profile_id": selected_profile_id,
        "selected_profile_version": selected_profile_version,
        "profile_sha256": profile.sha256(),
        "selected_subject_sha256": selected_subject_sha256,
        "selected_session_sha256": selected_session_sha256,
        "input_state_sha256": replay_state.sha256(),
        "sequence": sequence,
    }
    if not _valid_token(selected_profile_id) or not _valid_token(selected_profile_version):
        raise ExternalPlaybooksIngressError("selected profile identity must use safe tokens")
    if not _valid_sha256(selected_subject_sha256) or not _valid_sha256(selected_session_sha256):
        raise ExternalPlaybooksIngressError("selected identities must be lowercase SHA-256")
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 0 <= sequence < (9_007_199_254_740_991)
    ):
        raise ExternalPlaybooksIngressError("sequence is outside the V1 range")
    if (
        selected_profile_id != profile.profile_id
        or selected_profile_version != profile.profile_version
    ):
        return _rejected("configuration", "profile_identity_mismatch", common)
    if selected_session_sha256 != replay_state.session_sha256:
        return _rejected("configuration", "session_identity_mismatch", common)
    if sequence != replay_state.next_sequence:
        return _rejected("configuration", "sequence_mismatch", common)
    if len(replay_state.consumed_source_result_sha256s) >= 64:
        return _rejected("configuration", "replay_history_full", common)

    output_sha256 = _bounded_sha256(output_payload, MAX_EXTERNAL_PLAYBOOKS_OUTPUT_BYTES)
    if output_sha256 in replay_state.consumed_source_result_sha256s:
        common["source_result_sha256"] = output_sha256
        return _rejected("replay", "source_result_replay", common)

    try:
        input_root, input_sha256 = _decode_wire(
            input_payload, maximum=MAX_EXTERNAL_PLAYBOOKS_INPUT_BYTES, label="input"
        )
        common["input_bytes_sha256"] = input_sha256
        output_root, output_sha256 = _decode_wire(
            output_payload, maximum=MAX_EXTERNAL_PLAYBOOKS_OUTPUT_BYTES, label="output"
        )
        common["source_result_sha256"] = output_sha256
        if _contains_forbidden_key(input_root) or _contains_forbidden_key(output_root):
            raise _PairViolation("schema_authority", "authority_claim_forbidden")
        _validate_input(input_root)
        _validate_output(output_root)
        common["input_receipt_id"] = input_root["input_receipt_id"]
        common["external_receipt_id"] = output_root["receipt_id"]
        _validate_pair(
            profile,
            selected_subject_sha256,
            input_root,
            input_payload,
            output_root,
        )
    except _PairViolation as exc:
        return _rejected(exc.stage, exc.reason_code, common)

    if output_root["overall_advisory_disposition"] != profile.expected_disposition:
        return _rejected("semantic_mapping", "source_semantic_label_mismatch", common)
    if output_sha256 is None:
        raise ExternalPlaybooksIngressError("validated output has no content commitment")
    envelope_bytes, advisory_id = _derived_envelope(profile, output_sha256)
    connector_outcome = compose_advisory_gateway_v1(
        _derived_connector_profile(profile, output_sha256),
        selected_profile_id=selected_profile_id,
        selected_profile_version=selected_profile_version,
        payload=envelope_bytes,
        gateway_policy=gateway_policy,
    )
    consumed = tuple(sorted((*replay_state.consumed_source_result_sha256s, output_sha256)))
    transition = {
        "advisory_id": advisory_id,
        "connector_outcome_sha256": connector_outcome.sha256(),
        "external_receipt_id": output_root["receipt_id"],
        "input_bytes_sha256": input_sha256,
        "input_receipt_id": input_root["input_receipt_id"],
        "input_state_sha256": replay_state.sha256(),
        "next_consumed_source_result_sha256s": consumed,
        "next_sequence": sequence + 1,
        "profile_sha256": profile.sha256(),
        "selected_session_sha256": selected_session_sha256,
        "selected_subject_sha256": selected_subject_sha256,
        "sequence": sequence,
        "source_result_sha256": output_sha256,
    }
    receipt_sha256 = _domain_sha256("ash-external-playbooks-transition-v1", transition)
    next_state = AdvisoryIngressReplayStateV1(
        session_sha256=selected_session_sha256,
        next_sequence=sequence + 1,
        previous_ingress_receipt_sha256=receipt_sha256,
        consumed_source_result_sha256s=consumed,
    )
    return ExternalPlaybooksIngressOutcomeV1(
        ingress_disposition="admit",
        stage="complete",
        reason_code="external_playbooks_pair_admitted",
        advisory_id=advisory_id,
        connector_outcome_sha256=connector_outcome.sha256(),
        connector_outcome=connector_outcome,
        next_replay_state=next_state,
        ingress_receipt_sha256=receipt_sha256,
        connector_invoked=True,
        gateway_evaluated=connector_outcome.gateway_evaluated,
        **common,
    )


def external_playbooks_ingress_v1_json_schemas() -> dict[str, dict[str, Any]]:
    models: tuple[type[BaseModel], ...] = (
        ExternalPlaybooksIngressProfileV1,
        ExternalPlaybooksIngressOutcomeV1,
    )
    return {model.__name__: model.model_json_schema() for model in models}


def external_playbooks_ingress_v1_api_sha256() -> str:
    return _domain_sha256(
        "ash-external-playbooks-api-v1",
        {
            "api_version": EXTERNAL_PLAYBOOKS_INGRESS_API_VERSION,
            "entry_points": ["ingest_external_playbooks_pair_v1"],
            "input_schema": PLAYBOOKS_INPUT_SCHEMA,
            "output_schema": PLAYBOOKS_OUTPUT_SCHEMA,
            "pins": {
                "source_commit": PLAYBOOKS_SOURCE_COMMIT,
                "source_tree": PLAYBOOKS_SOURCE_TREE,
                "source_blob": PLAYBOOKS_SOURCE_BLOB,
                "source_sha256": PLAYBOOKS_SOURCE_SHA256,
                "input_schema_sha256": PLAYBOOKS_INPUT_SCHEMA_SHA256,
                "output_schema_sha256": PLAYBOOKS_OUTPUT_SCHEMA_SHA256,
                "pack_sha256": PLAYBOOKS_PACK_SHA256,
                "pack_artifact_sha256": PLAYBOOKS_PACK_ARTIFACT_SHA256,
                "pack_schema_sha256": PLAYBOOKS_PACK_SCHEMA_SHA256,
                "manifest_sha256": PLAYBOOKS_MANIFEST_SHA256,
            },
            "rule_table": _RULES,
            "schemas": external_playbooks_ingress_v1_json_schemas(),
        },
    )


def _validate_input(root: dict[str, Any]) -> None:
    fields = {
        "schema_version",
        "input_receipt_id",
        "pack_sha256",
        "subject_sha256",
        "subject_digest_semantics",
        "source_class",
        "signals",
        "raw_content_included",
        "digest_is_authentication",
        "may_authorize_effects",
        "operational_authority",
    }
    if set(root) != fields or root.get("schema_version") != PLAYBOOKS_INPUT_SCHEMA:
        raise _PairViolation("schema_authority", "external_schema_invalid")
    if any(
        not _valid_sha256(root.get(name))
        for name in ("input_receipt_id", "pack_sha256", "subject_sha256")
    ):
        raise _PairViolation("schema_authority", "external_schema_invalid")
    if (
        root.get("subject_digest_semantics")
        != "caller_supplied_sanitized_subject_commitment"
        or root.get("source_class") != "synthetic_fixture"
    ):
        raise _PairViolation("schema_authority", "external_schema_invalid")
    signals = root.get("signals")
    expected_signals = {rule["signal"] for rule in _RULES}
    if (
        type(signals) is not dict
        or set(signals) != expected_signals
        or any(
            type(value) is not str or value not in {"absent", "present", "unknown"}
            for value in signals.values()
        )
    ):
        raise _PairViolation("schema_authority", "external_schema_invalid")
    if (
        root.get("raw_content_included") is not False
        or root.get("digest_is_authentication") is not False
        or root.get("may_authorize_effects") is not False
        or root.get("operational_authority") != "none"
    ):
        raise _PairViolation("schema_authority", "authority_claim_forbidden")
    unsigned = dict(root)
    supplied = unsigned.pop("input_receipt_id")
    if supplied != hashlib.sha256(_INPUT_DOMAIN + _canonical(unsigned)).hexdigest():
        raise _PairViolation("identity_correspondence", "receipt_identity_mismatch")


def _validate_output(root: dict[str, Any]) -> None:
    fields = {
        "schema_version",
        "receipt_id",
        "input_receipt_id",
        "input_sha256",
        "pack_sha256",
        "results",
        "summary",
        "overall_advisory_disposition",
        "verdict_semantics",
        "may_authorize_effects",
        "operational_authority",
    }
    if set(root) != fields or root.get("schema_version") != PLAYBOOKS_OUTPUT_SCHEMA:
        raise _PairViolation("schema_authority", "external_schema_invalid")
    if any(
        not _valid_sha256(root.get(name))
        for name in ("receipt_id", "input_receipt_id", "input_sha256", "pack_sha256")
    ):
        raise _PairViolation("schema_authority", "external_schema_invalid")
    if (
        root.get("verdict_semantics") != "advisory_only_no_allow_or_enforcement"
        or root.get("may_authorize_effects") is not False
        or root.get("operational_authority") != "none"
    ):
        raise _PairViolation("schema_authority", "authority_claim_forbidden")
    if type(root.get("results")) is not list or len(root["results"]) != len(_RULES):
        raise _PairViolation("schema_authority", "external_schema_invalid")
    summary = root.get("summary")
    summary_fields = {
        "signal_count",
        "absent",
        "present",
        "unknown",
        "observe",
        "challenge",
        "escalate",
        "abstain",
    }
    if (
        type(summary) is not dict
        or set(summary) != summary_fields
        or any(
            type(value) is not int or value < 0 or value > len(_RULES) for value in summary.values()
        )
    ):
        raise _PairViolation("schema_authority", "external_schema_invalid")
    if (
        type(root.get("overall_advisory_disposition")) is not str
        or root["overall_advisory_disposition"] not in _DISPOSITION_RANK
    ):
        raise _PairViolation("schema_authority", "external_schema_invalid")
    unsigned = dict(root)
    supplied = unsigned.pop("receipt_id")
    if supplied != hashlib.sha256(_OUTPUT_DOMAIN + _canonical(unsigned)).hexdigest():
        raise _PairViolation("identity_correspondence", "receipt_identity_mismatch")


def _validate_pair(
    profile: ExternalPlaybooksIngressProfileV1,
    expected_subject_sha256: str,
    input_root: dict[str, Any],
    input_payload: bytes,
    output_root: dict[str, Any],
) -> None:
    if input_root["subject_sha256"] != expected_subject_sha256:
        raise _PairViolation("identity_correspondence", "subject_binding_mismatch")
    if (
        input_root["pack_sha256"] != profile.pack_sha256
        or output_root["pack_sha256"] != profile.pack_sha256
    ):
        raise _PairViolation("identity_correspondence", "pack_binding_mismatch")
    if (
        output_root["input_receipt_id"] != input_root["input_receipt_id"]
        or output_root["input_sha256"]
        != hashlib.sha256(_INPUT_BYTES_DOMAIN + input_payload).hexdigest()
    ):
        raise _PairViolation("identity_correspondence", "input_output_binding_mismatch")
    counts = {
        name: 0
        for name in ("absent", "present", "unknown", "observe", "challenge", "escalate", "abstain")
    }
    dispositions: list[str] = []
    for rule, result in zip(_RULES, output_root["results"], strict=True):
        fields = {
            "rule_id",
            "signal",
            "signal_state",
            "matched",
            "advisory_disposition",
            "reason_codes",
            "playbook_path",
            "playbook_sha256",
            "may_authorize_effects",
            "operational_authority",
        }
        if type(result) is not dict or set(result) != fields:
            raise _PairViolation("schema_authority", "external_schema_invalid")
        if (
            result.get("may_authorize_effects") is not False
            or result.get("operational_authority") != "none"
        ):
            raise _PairViolation("schema_authority", "authority_claim_forbidden")
        if (
            result.get("rule_id") != rule["rule_id"]
            or result.get("signal") != rule["signal"]
            or result.get("playbook_path") != rule["playbook_path"]
            or result.get("playbook_sha256") != rule["playbook_sha256"]
        ):
            raise _PairViolation("identity_correspondence", "rule_binding_mismatch")
        state = input_root["signals"][rule["signal"]]
        expected_disposition = "observe" if state == "absent" else rule[state]
        expected_reason = f"policy.{rule['rule_id']}.{state}"
        if (
            result.get("signal_state") != state
            or result.get("matched") is not (state != "absent")
            or result.get("advisory_disposition") != expected_disposition
            or result.get("reason_codes") != [expected_reason]
        ):
            raise _PairViolation("identity_correspondence", "semantic_accounting_mismatch")
        counts[state] += 1
        counts[expected_disposition] += 1
        dispositions.append(expected_disposition)
    expected_summary = {"signal_count": len(_RULES), **counts}
    expected_overall = max(dispositions, key=_DISPOSITION_RANK.__getitem__)
    if (
        output_root["summary"] != expected_summary
        or output_root["overall_advisory_disposition"] != expected_overall
    ):
        raise _PairViolation("identity_correspondence", "semantic_accounting_mismatch")


def _derived_envelope(
    profile: ExternalPlaybooksIngressProfileV1, output_sha256: str
) -> tuple[bytes, str]:
    unsigned: dict[str, Any] = {
        "advisory_kind": "playbooks_policy_evaluation",
        "advisory_text": profile.fixed_advisory_text,
        "operational_authority": "none",
        "provenance": AdvisoryProvenanceV1(
            source_commit=profile.source_commit,
            source_tree=profile.source_tree,
            source_contract_sha256=profile.output_schema_sha256,
            source_result_sha256=output_sha256,
            evidence_class="synthetic_fixture",
        ).model_dump(mode="json"),
        "risk_label": profile.expected_disposition,
        "schema_version": "AgenticSecurityHarnessAdvisoryEnvelope.v1",
        "source_component_id": "llm-safety-playbooks",
        "source_contract_id": _SOURCE_CONTRACT_ID,
        "source_contract_version": _SOURCE_CONTRACT_VERSION,
        "summary": profile.fixed_summary,
    }
    advisory_id = hashlib.sha256(b"ash-advisory-envelope-v1\0" + _canonical(unsigned)).hexdigest()
    envelope = AdvisoryEnvelopeV1(advisory_id=advisory_id, **unsigned)
    return _canonical(envelope.model_dump(mode="json")), advisory_id


def _derived_connector_profile(
    profile: ExternalPlaybooksIngressProfileV1, output_sha256: str
) -> AdvisoryGatewayProfileV1:
    return AdvisoryGatewayProfileV1(
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        source_pins=(
            AdvisorySourcePinV1(
                source_component_id="llm-safety-playbooks",
                advisory_kind="playbooks_policy_evaluation",
                source_contract_id=_SOURCE_CONTRACT_ID,
                source_contract_version=_SOURCE_CONTRACT_VERSION,
                source_commit=profile.source_commit,
                source_tree=profile.source_tree,
                source_contract_sha256=profile.output_schema_sha256,
                source_result_sha256=output_sha256,
                accepted_evidence_classes=("synthetic_fixture",),
            ),
        ),
        bindings=profile.bindings,
        mappings=profile.mappings,
    )


def _decode_wire(
    payload: object, *, maximum: int, label: Literal["input", "output"]
) -> tuple[dict[str, Any], str]:
    stage: ExternalPlaybooksStage = "input_bytes" if label == "input" else "output_bytes"
    if type(payload) is not bytes:
        raise _PairViolation(stage, f"{label}_type_invalid")
    if not payload:
        raise _PairViolation(stage, f"{label}_empty")
    if len(payload) > maximum:
        raise _PairViolation(stage, f"{label}_oversized")
    digest = hashlib.sha256(payload).hexdigest()
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _PairViolation(stage, "malformed_utf8") from exc
    if text.startswith("\ufeff"):
        raise _PairViolation(stage, "bom_forbidden")
    try:
        root = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except _DuplicateKey as exc:
        raise _PairViolation(stage, "duplicate_json_key") from exc
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _PairViolation(stage, "malformed_json") from exc
    if type(root) is not dict:
        raise _PairViolation(stage, "root_type_invalid")
    try:
        _validate_json_value(root, depth=1)
        canonical = _canonical(root) + b"\n"
    except ValueError as exc:
        raise _PairViolation(stage, "input_bounds_invalid") from exc
    if canonical != payload:
        raise _PairViolation(stage, "noncanonical_json")
    return root, digest


def _require_trusted_inputs(
    profile: object, replay_state: object, gateway_policy: object
) -> tuple[ExternalPlaybooksIngressProfileV1, AdvisoryIngressReplayStateV1, GatewayPolicyV1]:
    if type(profile) is not ExternalPlaybooksIngressProfileV1:
        raise ExternalPlaybooksIngressError("profile must be the exact V1 type")
    if type(replay_state) is not AdvisoryIngressReplayStateV1:
        raise ExternalPlaybooksIngressError("replay state must be the exact V1 type")
    if type(gateway_policy) is not GatewayPolicyV1:
        raise ExternalPlaybooksIngressError("gateway policy must be the exact V1 type")
    try:
        checked_profile = ExternalPlaybooksIngressProfileV1.model_validate(
            profile.model_dump(mode="python")
        )
        checked_state = AdvisoryIngressReplayStateV1.model_validate(
            replay_state.model_dump(mode="python")
        )
        checked_policy = GatewayPolicyV1.model_validate(gateway_policy.model_dump(mode="python"))
    except (AttributeError, ValidationError, ValueError) as exc:
        raise ExternalPlaybooksIngressError("trusted configuration violates V1") from exc
    if (checked_profile, checked_state, checked_policy) != (profile, replay_state, gateway_policy):
        raise ExternalPlaybooksIngressError("trusted configuration changed during validation")
    return checked_profile, checked_state, checked_policy


def _rejected(
    stage: ExternalPlaybooksStage, reason: str, common: dict[str, Any]
) -> ExternalPlaybooksIngressOutcomeV1:
    return ExternalPlaybooksIngressOutcomeV1(
        ingress_disposition="reject", stage=stage, reason_code=reason, **common
    )


def _validate_json_value(value: Any, *, depth: int) -> None:
    if depth > MAX_EXTERNAL_PLAYBOOKS_DEPTH:
        raise ExternalPlaybooksIngressError("JSON depth exceeds the V1 limit")
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ExternalPlaybooksIngressError("non-finite JSON number")
        return
    if type(value) is str:
        _validate_scalar_text(value, 65_536)
        return
    if type(value) is list:
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if type(value) is dict:
        if len(value) > 128:
            raise ExternalPlaybooksIngressError("JSON object exceeds the V1 limit")
        for key, item in value.items():
            _validate_scalar_text(key, 1_024)
            _validate_json_value(item, depth=depth + 1)
        return
    raise ExternalPlaybooksIngressError("unsupported JSON value")


def _contains_forbidden_key(value: Any) -> bool:
    if type(value) is dict:
        for key, item in value.items():
            normalized = "".join(character for character in key.casefold() if character.isalnum())
            if normalized in _NORMALIZED_FORBIDDEN_AUTHORITY_KEYS or _contains_forbidden_key(item):
                return True
    elif type(value) is list:
        return any(_contains_forbidden_key(item) for item in value)
    return False


def _validate_scalar_text(value: str, maximum_bytes: int) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("text contains a non-scalar Unicode value")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise ValueError("text exceeds the V1 byte limit")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _domain_sha256(domain: str, value: Any) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + _canonical(value)).hexdigest()


def _bounded_sha256(value: object, maximum: int) -> str | None:
    if type(value) is not bytes or not value or len(value) > maximum:
        return None
    return hashlib.sha256(value).hexdigest()


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(SHA256_PATTERN, value) is not None


def _valid_token(value: object) -> bool:
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


class _PairViolation(ValueError):
    def __init__(self, stage: ExternalPlaybooksStage, reason_code: str) -> None:
        super().__init__(reason_code)
        self.stage = stage
        self.reason_code = reason_code


__all__ = [
    "EXTERNAL_PLAYBOOKS_INGRESS_API_VERSION",
    "ExternalPlaybooksIngressError",
    "ExternalPlaybooksIngressOutcomeV1",
    "ExternalPlaybooksIngressProfileV1",
    "external_playbooks_ingress_v1_api_sha256",
    "external_playbooks_ingress_v1_json_schemas",
    "ingest_external_playbooks_pair_v1",
]
