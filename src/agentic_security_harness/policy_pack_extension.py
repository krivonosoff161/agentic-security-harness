"""Exact-pinned, data-only Policy Pack V1 Extension SDK bridge.

Production code in this module never imports, executes, discovers, or downloads the
``llm-safety-playbooks`` repository.  It independently validates one reviewed canonical
JSON pack, evaluates content-free signal bindings, and emits authority-free Extension
SDK findings and run receipts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.extension_sdk import (
    EXTENSION_MANIFEST_V1,
    ExtensionContractRefV1,
    ExtensionFindingV1,
    ExtensionManifestV1,
    ExtensionObservationEnvelopeV1,
    ExtensionRunReceiptV1,
    run_extension_v1,
)
from agentic_security_harness.portfolio_contract import (
    GIT_OBJECT_PATTERN,
    MAX_PORTFOLIO_OBSERVATION_BYTES,
    SHA256_PATTERN,
    CanonicalObservationEventV1,
    decode_portfolio_observation_v1,
    encode_portfolio_observation_v1,
)
from agentic_security_harness.safe_io import is_link_or_reparse

POLICY_PACK_V1: Final = "llm-safety-policy-pack-v1.0"
POLICY_PACK_SIGNAL_BINDING_V1: Final = "harness-policy-pack-signal-binding-v1.0"
POLICY_PACK_EVALUATION_V1: Final = "harness-policy-pack-evaluation-v1.0"
POLICY_PACK_SOURCE_PIN_V1: Final = "harness-policy-pack-source-pin-v1.0"
POLICY_PACK_ID: Final = "llm-safety-playbooks-core"
POLICY_PACK_SEMANTIC_SHA256: Final = (
    "44fa5aced73c6a2fc1eb3cb827955d245c887fa8d7c596e353bb2e9678119169"
)
POLICY_PACK_FILE_SHA256: Final = (
    "1c8ca14e6ab83d92742f6fba0b0d1b1bc422ebe30163c6619e9c80f5413b8915"
)
POLICY_PACK_SCHEMA_SHA256: Final = (
    "fd99422169c4cbfbe0f80a16a39cf7557d7ef6d28669b03ae940b24b9e2172a1"
)
POLICY_PACK_MANIFEST_SHA256: Final = (
    "72cefee83964c53930ff64750584faa35e144ab8fa8db1ef5ccf066e11604a41"
)
POLICY_PACK_COMPONENT_SHA256: Final = (
    "f429ce29a5edcffe954b89246c58399247f04c74d7348b431fc714c0198a7004"
)
POLICY_PACK_INPUT_SCHEMA_SHA256: Final = (
    "d6a39ad8cb1cfc9e61094fa3c92b11d66b2df3370a326f89ecb4a52c49dd3e8b"
)
POLICY_PACK_OUTPUT_SCHEMA_SHA256: Final = (
    "b5e4d5554fb930529fd493dad903a25698c99c62c57d99934f66edda8b4f6f1c"
)
POLICY_PACK_SOURCE_COMMIT: Final = "3e6795a4671cc6417bc04aad17163238a8b01ddc"
POLICY_PACK_SOURCE_TREE: Final = "c5e34452e978193877fef660e417e4f376904a34"
POLICY_PACK_DOMAIN: Final = b"llm-safety-playbooks/policy-pack/v1\0"
POLICY_SIGNAL_BINDING_DOMAIN: Final = (
    b"agentic-security-harness/policy-pack-signal-binding/v1\0"
)
POLICY_EVALUATION_DOMAIN: Final = b"agentic-security-harness/policy-pack-evaluation/v1\0"
MAX_POLICY_PACK_BYTES: Final = 65_536
MAX_POLICY_SIGNAL_BYTES: Final = 16_384
MAX_POLICY_EVENTS: Final = 64
MAX_JSON_DEPTH: Final = 16

PolicySignalState = Literal["absent", "present", "unknown"]
PolicyDisposition = Literal["observe", "challenge", "escalate", "abstain"]
PolicySourceClass = Literal[
    "synthetic_fixture", "sanitized_metadata", "external_adapter_receipt"
]

_RULE_SPECS: Final = (
    (
        "untrusted-instructions-v1",
        "untrusted_instructions_detected",
        "playbooks/data-vs-instructions.md",
        "bf993293a8a4b8340029bdfbc8fa3ee2052450c7a5ad4618143a0b08e44c9298",
        "challenge",
        "challenge",
    ),
    (
        "secret-exposure-v1",
        "secret_exposure_risk",
        "playbooks/secret-handling.md",
        "91f1d24612c787bf93f7d2e4e7c7fb7d129c4a0994ca26da3ea0f5715b4b0618",
        "abstain",
        "abstain",
    ),
    (
        "generated-resource-v1",
        "generated_resource_unverified",
        "playbooks/generated-resource-check.md",
        "3e4884da1b30fcb56b5ebed2cedb5b7f6b652dcabcf3a7221bb331a514fafc95",
        "challenge",
        "challenge",
    ),
    (
        "git-change-control-v1",
        "git_change_control_unclear",
        "playbooks/git-agent-safety.md",
        "a5fc7e5ac3c17e7b12dffa0bee026e3b3515e7bf1e3a24e1b8d3c57453b06ca2",
        "escalate",
        "escalate",
    ),
    (
        "handoff-verification-v1",
        "handoff_verification_incomplete",
        "playbooks/handoff-verification.md",
        "46553384d34f5fa4c13c2d745d9260bc6fc83f2923e280f792ad5c14d9280bec",
        "challenge",
        "challenge",
    ),
    (
        "research-authorization-v1",
        "research_authorization_unclear",
        "playbooks/safe-research-scope.md",
        "709c4482278af2d2497317352d92e05059b20a0108d11dc108234ab6c791c221",
        "abstain",
        "abstain",
    ),
    (
        "observation-metadata-v1",
        "observation_metadata_invalid",
        "playbooks/canonical-observation-review.md",
        "bd2c518c484072804f860d50d4b4ff52c246fafbaac4c7fb87db86aafd2f79f0",
        "abstain",
        "abstain",
    ),
)
_DISPOSITION_RANK: Final = {"observe": 0, "challenge": 1, "escalate": 2, "abstain": 3}
_IDENTIFIER_PATTERN: Final = r"^[a-z][a-z0-9_.-]{0,127}$"


class PolicyPackExtensionError(ValueError):
    """Raised when a policy-pack input crosses the closed data-only boundary."""


class PolicyPackSourcePinV1(BaseModel):
    """Compiled identity for the exact reviewed playbooks source tree and artifacts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-policy-pack-source-pin-v1.0"]
    component_id: Literal["llm-safety-playbooks"]
    repository: Literal["https://github.com/krivonosoff161/llm-safety-playbooks"]
    source_commit: str = Field(pattern=GIT_OBJECT_PATTERN)
    source_tree: str = Field(pattern=GIT_OBJECT_PATTERN)
    pack_file_sha256: str = Field(pattern=SHA256_PATTERN)
    pack_schema_sha256: str = Field(pattern=SHA256_PATTERN)
    pack_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    component_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    input_schema_sha256: str = Field(pattern=SHA256_PATTERN)
    output_schema_sha256: str = Field(pattern=SHA256_PATTERN)
    pack_sha256: str = Field(pattern=SHA256_PATTERN)
    verification: Literal["exact_public_git_reviewed"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _is_reviewed_source(self) -> PolicyPackSourcePinV1:
        expected = reviewed_policy_pack_source_v1().model_dump(mode="python")
        if self.model_dump(mode="python") != expected:
            raise ValueError("policy-pack source pin is not the reviewed exact source")
        return self


class PolicyPackRuleV1(BaseModel):
    """One exact advisory rule retained as data, never executable playbook text."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    signal: str = Field(pattern=_IDENTIFIER_PATTERN)
    playbook_path: str = Field(min_length=1, max_length=256)
    playbook_sha256: str = Field(pattern=SHA256_PATTERN)
    absent_disposition: Literal["observe"]
    present_disposition: PolicyDisposition
    unknown_disposition: PolicyDisposition
    may_authorize_effects: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _path_is_inert_and_relative(self) -> PolicyPackRuleV1:
        path = PurePosixPath(self.playbook_path)
        if (
            "\\" in self.playbook_path
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.suffix != ".md"
        ):
            raise ValueError("playbook path is not inert repository-relative POSIX data")
        return self


class PolicyPackV1(BaseModel):
    """Closed semantic model of the exact reviewed canonical policy pack."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["llm-safety-policy-pack-v1.0"]
    pack_id: Literal["llm-safety-playbooks-core"]
    pack_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_mode: Literal["deterministic_offline_advisory_only"]
    playbook_digest_semantics: Literal["sha256_lf_normalized_text_v1"]
    rules: tuple[PolicyPackRuleV1, ...] = Field(min_length=7, max_length=7)
    allowed_dispositions: tuple[
        Literal["observe", "challenge", "escalate", "abstain"], ...
    ]
    verdict_semantics: Literal["advisory_only_no_allow_or_enforcement"]
    may_authorize_effects: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _semantic_identity(self) -> PolicyPackV1:
        if self.allowed_dispositions != ("observe", "challenge", "escalate", "abstain"):
            raise ValueError("policy-pack dispositions drifted")
        if "allow" in self.allowed_dispositions:
            raise ValueError("policy pack cannot represent allow")
        actual = tuple(
            (
                item.rule_id,
                item.signal,
                item.playbook_path,
                item.playbook_sha256,
                item.present_disposition,
                item.unknown_disposition,
            )
            for item in self.rules
        )
        if actual != _RULE_SPECS:
            raise ValueError("policy-pack rule order or semantics drifted")
        if self.pack_sha256 != _policy_pack_semantic_digest(self):
            raise ValueError("policy-pack semantic digest drifted")
        return self


class PolicyPackSignalsV1(BaseModel):
    """Seven content-free signal states owned by the caller, not inferred from content."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    untrusted_instructions_detected: PolicySignalState
    secret_exposure_risk: PolicySignalState
    generated_resource_unverified: PolicySignalState
    git_change_control_unclear: PolicySignalState
    handoff_verification_incomplete: PolicySignalState
    research_authorization_unclear: PolicySignalState
    observation_metadata_invalid: PolicySignalState


class PolicyPackSignalBindingV1(BaseModel):
    """Content-free signal receipt bound to one exact canonical observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-policy-pack-signal-binding-v1.0"]
    binding_sha256: str = Field(pattern=SHA256_PATTERN)
    event_id: str = Field(pattern=SHA256_PATTERN)
    observation_sha256: str = Field(pattern=SHA256_PATTERN)
    pack_sha256: str = Field(pattern=SHA256_PATTERN)
    source_class: PolicySourceClass
    signals: PolicyPackSignalsV1
    raw_content_included: Literal[False]
    digest_is_authentication: Literal[False]
    may_authorize_effects: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _binding_identity(self) -> PolicyPackSignalBindingV1:
        if self.pack_sha256 != POLICY_PACK_SEMANTIC_SHA256:
            raise ValueError("signal binding pack digest is not reviewed")
        if self.binding_sha256 != _model_identity(
            POLICY_SIGNAL_BINDING_DOMAIN, self, "binding_sha256"
        ):
            raise ValueError("policy signal binding digest drifted")
        return self


class PolicyPackRuleEvaluationV1(BaseModel):
    """Deterministic parity projection of one source rule result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    signal: str = Field(pattern=_IDENTIFIER_PATTERN)
    signal_state: PolicySignalState
    matched: bool
    advisory_disposition: PolicyDisposition
    reason_code: str = Field(pattern=_IDENTIFIER_PATTERN)
    playbook_path: str = Field(min_length=1, max_length=256)
    playbook_sha256: str = Field(pattern=SHA256_PATTERN)
    may_authorize_effects: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _reviewed_rule_result(self) -> PolicyPackRuleEvaluationV1:
        spec = next((item for item in _RULE_SPECS if item[0] == self.rule_id), None)
        if spec is None:
            raise ValueError("policy evaluation contains an unknown rule")
        rule_id, signal, playbook_path, playbook_sha256, present, unknown = spec
        expected_disposition = {
            "absent": "observe",
            "present": present,
            "unknown": unknown,
        }[self.signal_state]
        if (
            self.rule_id != rule_id
            or self.signal != signal
            or self.playbook_path != playbook_path
            or self.playbook_sha256 != playbook_sha256
            or self.matched is not (self.signal_state != "absent")
            or self.advisory_disposition != expected_disposition
            or self.reason_code != f"policy.{rule_id}.{self.signal_state}"
        ):
            raise ValueError("policy rule evaluation semantics drifted")
        return self


class PolicyPackEvaluationV1(BaseModel):
    """Self-bound authority-free result used to prove deterministic pack parity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-policy-pack-evaluation-v1.0"]
    evaluation_sha256: str = Field(pattern=SHA256_PATTERN)
    event_id: str = Field(pattern=SHA256_PATTERN)
    signal_binding_sha256: str = Field(pattern=SHA256_PATTERN)
    pack_sha256: str = Field(pattern=SHA256_PATTERN)
    results: tuple[PolicyPackRuleEvaluationV1, ...] = Field(min_length=7, max_length=7)
    overall_advisory_disposition: PolicyDisposition
    verdict_semantics: Literal["advisory_only_no_allow_or_enforcement"]
    may_authorize_effects: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _evaluation_identity(self) -> PolicyPackEvaluationV1:
        if self.pack_sha256 != POLICY_PACK_SEMANTIC_SHA256:
            raise ValueError("policy evaluation pack digest is not reviewed")
        if tuple(item.rule_id for item in self.results) != tuple(
            item[0] for item in _RULE_SPECS
        ):
            raise ValueError("policy evaluation rule order drifted")
        if tuple(item.signal for item in self.results) != tuple(
            item[1] for item in _RULE_SPECS
        ):
            raise ValueError("policy evaluation signal order drifted")
        expected_overall = max(
            (item.advisory_disposition for item in self.results),
            key=_DISPOSITION_RANK.__getitem__,
        )
        if self.overall_advisory_disposition != expected_overall:
            raise ValueError("policy evaluation overall disposition drifted")
        if self.evaluation_sha256 != _model_identity(
            POLICY_EVALUATION_DOMAIN, self, "evaluation_sha256"
        ):
            raise ValueError("policy evaluation digest drifted")
        return self


def reviewed_policy_pack_source_v1() -> PolicyPackSourcePinV1:
    """Return the compiled exact source identity as a detached immutable model."""

    return PolicyPackSourcePinV1.model_construct(
        schema_version=POLICY_PACK_SOURCE_PIN_V1,
        component_id="llm-safety-playbooks",
        repository="https://github.com/krivonosoff161/llm-safety-playbooks",
        source_commit=POLICY_PACK_SOURCE_COMMIT,
        source_tree=POLICY_PACK_SOURCE_TREE,
        pack_file_sha256=POLICY_PACK_FILE_SHA256,
        pack_schema_sha256=POLICY_PACK_SCHEMA_SHA256,
        pack_manifest_sha256=POLICY_PACK_MANIFEST_SHA256,
        component_manifest_sha256=POLICY_PACK_COMPONENT_SHA256,
        input_schema_sha256=POLICY_PACK_INPUT_SCHEMA_SHA256,
        output_schema_sha256=POLICY_PACK_OUTPUT_SCHEMA_SHA256,
        pack_sha256=POLICY_PACK_SEMANTIC_SHA256,
        verification="exact_public_git_reviewed",
        operational_authority="none",
    )


def decode_policy_pack_v1(
    payload: bytes,
    *,
    expected_file_sha256: str,
) -> PolicyPackV1:
    """Decode only the reviewed canonical bytes under a caller-approved exact digest."""

    if type(payload) is not bytes:
        raise PolicyPackExtensionError("policy-pack payload must be exact bytes")
    _require_digest(expected_file_sha256, "expected policy-pack file digest")
    if expected_file_sha256 != POLICY_PACK_FILE_SHA256:
        raise PolicyPackExtensionError("expected policy-pack digest is not the reviewed pin")
    decoded = _decode_canonical_object(payload, MAX_POLICY_PACK_BYTES, "policy pack")
    if hashlib.sha256(payload).hexdigest() != expected_file_sha256:
        raise PolicyPackExtensionError("policy-pack bytes do not match the expected digest")
    try:
        pack = PolicyPackV1.model_validate(decoded)
    except ValueError as exc:
        raise PolicyPackExtensionError(
            "policy-pack values violate the reviewed V1 contract"
        ) from exc
    if _canonical_json(pack.model_dump(mode="json")) + b"\n" != payload:
        raise PolicyPackExtensionError("policy-pack bytes are not canonical reviewed V1")
    return pack


def verify_policy_pack_source_artifacts_v1(
    *,
    pack_bytes: bytes,
    pack_schema_bytes: bytes,
    pack_manifest_bytes: bytes,
    component_manifest_bytes: bytes,
    input_schema_bytes: bytes,
    output_schema_bytes: bytes,
    pin: PolicyPackSourcePinV1 | None = None,
) -> PolicyPackV1:
    """Verify exact raw artifact pins plus independent authority-free semantics."""

    reviewed = reviewed_policy_pack_source_v1()
    supplied = reviewed if pin is None else _revalidate_source_pin(pin)
    if supplied != reviewed:
        raise PolicyPackExtensionError("policy-pack source pin drifted")
    artifacts = {
        "policy pack": (pack_bytes, reviewed.pack_file_sha256),
        "policy-pack schema": (pack_schema_bytes, reviewed.pack_schema_sha256),
        "policy-pack manifest": (pack_manifest_bytes, reviewed.pack_manifest_sha256),
        "component manifest": (component_manifest_bytes, reviewed.component_manifest_sha256),
        "policy input schema": (input_schema_bytes, reviewed.input_schema_sha256),
        "policy output schema": (output_schema_bytes, reviewed.output_schema_sha256),
    }
    for label, (raw, expected) in artifacts.items():
        if (
            type(raw) is not bytes
            or not raw
            or len(raw) > MAX_POLICY_PACK_BYTES
            or hashlib.sha256(raw).hexdigest() != expected
        ):
            raise PolicyPackExtensionError(f"{label} does not match the exact source pin")
    pack = decode_policy_pack_v1(pack_bytes, expected_file_sha256=reviewed.pack_file_sha256)
    schema = _decode_json_object(pack_schema_bytes, MAX_POLICY_PACK_BYTES, "policy-pack schema")
    manifest = _decode_json_object(
        pack_manifest_bytes, MAX_POLICY_PACK_BYTES, "policy-pack manifest"
    )
    component = _decode_json_object(
        component_manifest_bytes, MAX_POLICY_PACK_BYTES, "component manifest"
    )
    _decode_json_object(input_schema_bytes, MAX_POLICY_PACK_BYTES, "policy input schema")
    _decode_json_object(output_schema_bytes, MAX_POLICY_PACK_BYTES, "policy output schema")
    if (
        schema.get("additionalProperties") is not False
        or schema.get("properties", {}).get("pack_id", {}).get("const") != POLICY_PACK_ID
        or schema.get("properties", {}).get("operational_authority", {}).get("const") != "none"
    ):
        raise PolicyPackExtensionError("policy-pack schema widens the reviewed boundary")
    if (
        manifest.get("pack_sha256") != pack.pack_sha256
        or manifest.get("may_authorize_effects") is not False
        or manifest.get("operational_authority") != "none"
        or manifest.get("artifacts", {}).get("contracts/policy-pack.v1.json")
        != reviewed.pack_file_sha256
        or manifest.get("artifacts", {}).get("contracts/policy-pack.v1.schema.json")
        != reviewed.pack_schema_sha256
        or manifest.get("bound_files", {}).get("component.yaml")
        != reviewed.component_manifest_sha256
    ):
        raise PolicyPackExtensionError("policy-pack manifest bindings drifted")
    if (
        component.get("component_id") != "llm-safety-playbooks"
        or component.get("kind") != "declarative_pack"
        or component.get("authority") != "none"
        or "policy-pack-v1" not in component.get("owns", {}).get("contracts", [])
    ):
        raise PolicyPackExtensionError("component manifest semantics drifted")
    return pack


def build_policy_pack_signal_binding_v1(
    event: CanonicalObservationEventV1,
    *,
    signals: PolicyPackSignalsV1,
    source_class: PolicySourceClass,
) -> PolicyPackSignalBindingV1:
    """Bind caller-owned content-free signals to exact canonical observation bytes."""

    try:
        checked_event = CanonicalObservationEventV1.model_validate(event.model_dump(mode="python"))
        checked_signals = PolicyPackSignalsV1.model_validate(signals.model_dump(mode="python"))
    except (AttributeError, ValueError) as exc:
        raise PolicyPackExtensionError("policy signal input violates the closed V1 types") from exc
    provisional = PolicyPackSignalBindingV1.model_construct(
        schema_version=POLICY_PACK_SIGNAL_BINDING_V1,
        binding_sha256="0" * 64,
        event_id=checked_event.event_id,
        observation_sha256=hashlib.sha256(encode_portfolio_observation_v1(checked_event)).hexdigest(),
        pack_sha256=POLICY_PACK_SEMANTIC_SHA256,
        source_class=source_class,
        signals=checked_signals,
        raw_content_included=False,
        digest_is_authentication=False,
        may_authorize_effects=False,
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["binding_sha256"] = _model_identity(
        POLICY_SIGNAL_BINDING_DOMAIN, provisional, "binding_sha256"
    )
    return PolicyPackSignalBindingV1.model_validate(payload)


def encode_policy_pack_signal_binding_v1(binding: PolicyPackSignalBindingV1) -> bytes:
    checked = _revalidate_binding(binding)
    encoded = _canonical_json(checked.model_dump(mode="json")) + b"\n"
    if len(encoded) > MAX_POLICY_SIGNAL_BYTES:
        raise PolicyPackExtensionError("policy signal binding exceeds the V1 byte limit")
    return encoded


def decode_policy_pack_signal_binding_v1(payload: bytes) -> PolicyPackSignalBindingV1:
    decoded = _decode_canonical_object(payload, MAX_POLICY_SIGNAL_BYTES, "policy signal binding")
    try:
        binding = PolicyPackSignalBindingV1.model_validate(decoded)
    except ValueError as exc:
        raise PolicyPackExtensionError("policy signal binding violates V1") from exc
    if encode_policy_pack_signal_binding_v1(binding) != payload:
        raise PolicyPackExtensionError("policy signal binding is not canonical V1")
    return binding


def evaluate_policy_pack_binding_v1(
    pack: PolicyPackV1,
    binding: PolicyPackSignalBindingV1,
    event: CanonicalObservationEventV1,
) -> PolicyPackEvaluationV1:
    """Evaluate one exact event binding with source-compatible deterministic ordering."""

    checked_pack = _revalidate_pack(pack)
    checked_binding = _revalidate_binding(binding)
    try:
        checked_event = CanonicalObservationEventV1.model_validate(event.model_dump(mode="python"))
    except (AttributeError, ValueError) as exc:
        raise PolicyPackExtensionError("policy event violates canonical observation V1") from exc
    event_sha = hashlib.sha256(encode_portfolio_observation_v1(checked_event)).hexdigest()
    if (
        checked_binding.event_id != checked_event.event_id
        or checked_binding.observation_sha256 != event_sha
        or checked_binding.pack_sha256 != checked_pack.pack_sha256
    ):
        raise PolicyPackExtensionError("policy signal binding does not match the event and pack")
    states = checked_binding.signals.model_dump(mode="python")
    results: list[PolicyPackRuleEvaluationV1] = []
    for rule in checked_pack.rules:
        state = states[rule.signal]
        disposition = (
            rule.absent_disposition
            if state == "absent"
            else getattr(rule, f"{state}_disposition")
        )
        results.append(
            PolicyPackRuleEvaluationV1(
                rule_id=rule.rule_id,
                signal=rule.signal,
                signal_state=state,
                matched=state != "absent",
                advisory_disposition=disposition,
                reason_code=f"policy.{rule.rule_id}.{state}",
                playbook_path=rule.playbook_path,
                playbook_sha256=rule.playbook_sha256,
                may_authorize_effects=False,
                operational_authority="none",
            )
        )
    overall = max(
        (item.advisory_disposition for item in results),
        key=_DISPOSITION_RANK.__getitem__,
    )
    provisional = PolicyPackEvaluationV1.model_construct(
        schema_version=POLICY_PACK_EVALUATION_V1,
        evaluation_sha256="0" * 64,
        event_id=checked_event.event_id,
        signal_binding_sha256=checked_binding.binding_sha256,
        pack_sha256=checked_pack.pack_sha256,
        results=tuple(results),
        overall_advisory_disposition=overall,
        verdict_semantics="advisory_only_no_allow_or_enforcement",
        may_authorize_effects=False,
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["evaluation_sha256"] = _model_identity(
        POLICY_EVALUATION_DOMAIN, provisional, "evaluation_sha256"
    )
    return PolicyPackEvaluationV1.model_validate(payload)


class PolicyPackExtensionV1:
    """Explicit declarative extension; missing pack remains an inconclusive run."""

    def __init__(
        self,
        *,
        pack_bytes: bytes | None,
        expected_pack_file_sha256: str,
        bindings: tuple[PolicyPackSignalBindingV1, ...],
    ) -> None:
        _require_digest(expected_pack_file_sha256, "expected policy-pack file digest")
        if expected_pack_file_sha256 != POLICY_PACK_FILE_SHA256:
            raise PolicyPackExtensionError("expected policy-pack digest is not reviewed")
        if not bindings or len(bindings) > MAX_POLICY_EVENTS:
            raise PolicyPackExtensionError("policy signal binding count is outside V1")
        checked_bindings = tuple(_revalidate_binding(item) for item in bindings)
        event_ids = tuple(item.event_id for item in checked_bindings)
        if len(event_ids) != len(set(event_ids)):
            raise PolicyPackExtensionError("policy signal event replay detected")
        self._bindings = {item.event_id: item for item in checked_bindings}
        self._pack = (
            None
            if pack_bytes is None
            else decode_policy_pack_v1(
                pack_bytes, expected_file_sha256=expected_pack_file_sha256
            )
        )
        configuration = {
            "source_pin": reviewed_policy_pack_source_v1().model_dump(mode="json"),
            "expected_pack_file_sha256": expected_pack_file_sha256,
            "pack_state": "missing" if self._pack is None else "verified",
            "binding_sha256": [item.binding_sha256 for item in checked_bindings],
            "raw_content_included": False,
            "operational_authority": "none",
        }
        self.manifest = ExtensionManifestV1(
            schema_version=EXTENSION_MANIFEST_V1,
            extension_id="llm-safety-playbooks.policy-pack",
            extension_version="1.0.0",
            component_id="agentic-security-harness",
            implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            configuration_sha256=_domain_object_digest(
                "agentic-security-harness/policy-pack-extension-configuration/v1",
                configuration,
            ),
            harness_api="1",
            kind="declarative_pack",
            capabilities=("observation.read", "finding.emit", "policy.evaluate"),
            consumes=(
                ExtensionContractRefV1(
                    contract_id="portfolio-observation", version="1.0", required=True
                ),
                ExtensionContractRefV1(
                    contract_id="policy-pack-signal-binding", version="1.0", required=True
                ),
            ),
            produces=(
                ExtensionContractRefV1(
                    contract_id="extension-finding", version="1.0", required=True
                ),
                ExtensionContractRefV1(
                    contract_id="policy-pack-evaluation", version="1.0", required=False
                ),
            ),
            deterministic=True,
            evidence_provenance="deterministic_rule",
            network_mode="off",
            raw_data_policy="digests_only",
            execution_model="in_process_operator_approved_not_sandboxed",
            operational_authority="none",
        )

    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        if len(envelope.events) > MAX_POLICY_EVENTS:
            raise PolicyPackExtensionError("policy-pack event count exceeds V1")
        known = {event.event_id for event in envelope.events}
        if any(event_id not in known for event_id in self._bindings):
            raise PolicyPackExtensionError("policy signal binding references unknown event")
        findings: list[ExtensionFindingV1] = []
        for event in envelope.events:
            binding = self._bindings.get(event.event_id)
            if self._pack is None:
                findings.append(_finding(event.event_id, "pack-missing", "inconclusive", "medium"))
                continue
            if binding is None:
                findings.append(
                    _finding(event.event_id, "signals-missing", "inconclusive", "medium")
                )
                continue
            evaluation = evaluate_policy_pack_binding_v1(self._pack, binding, event)
            for result in evaluation.results:
                outcome: Literal["finding", "inconclusive"]
                severity: Literal["none", "medium", "high"]
                if result.signal_state == "absent":
                    outcome, severity = "inconclusive", "none"
                elif result.signal_state == "unknown":
                    outcome, severity = "inconclusive", "medium"
                else:
                    outcome = "finding"
                    severity = (
                        "high"
                        if result.advisory_disposition in {"escalate", "abstain"}
                        else "medium"
                    )
                findings.append(
                    ExtensionFindingV1(
                        check_id=f"policy_pack.{result.rule_id}.{event.event_id}",
                        outcome=outcome,
                        severity=severity,
                        reason_code=result.reason_code,
                        evidence_event_ids=(event.event_id,),
                    )
                )
        return tuple(findings)


def run_policy_pack_extension_v1(
    *,
    pack_bytes: bytes | None,
    expected_pack_file_sha256: str,
    bindings: tuple[PolicyPackSignalBindingV1, ...],
    envelope: ExtensionObservationEnvelopeV1,
) -> ExtensionRunReceiptV1:
    extension = PolicyPackExtensionV1(
        pack_bytes=pack_bytes,
        expected_pack_file_sha256=expected_pack_file_sha256,
        bindings=bindings,
    )
    return run_extension_v1(extension, envelope)


def read_local_policy_pack_bytes_v1(
    path: Path,
    *,
    expected_file_sha256: str,
) -> bytes | None:
    """Read an explicit stable local pack; absence is represented without path retention."""

    _require_digest(expected_file_sha256, "expected policy-pack file digest")
    candidate = _explicit_local_path(path)
    _require_safe_ancestors(candidate.parent)
    if is_link_or_reparse(candidate):
        raise PolicyPackExtensionError("policy pack path is a link or reparse point")
    if not candidate.exists():
        return None
    payload = _read_stable_regular_file(candidate, MAX_POLICY_PACK_BYTES, "policy pack")
    decode_policy_pack_v1(payload, expected_file_sha256=expected_file_sha256)
    return payload


def read_local_policy_signal_binding_v1(path: Path) -> PolicyPackSignalBindingV1:
    candidate = _explicit_local_path(path)
    payload = _read_stable_regular_file(candidate, MAX_POLICY_SIGNAL_BYTES, "policy signals")
    return decode_policy_pack_signal_binding_v1(payload)


def read_local_policy_observation_v1(path: Path) -> CanonicalObservationEventV1:
    """Read one explicit stable canonical observation without retaining its path."""

    candidate = _explicit_local_path(path)
    payload = _read_stable_regular_file(
        candidate, MAX_PORTFOLIO_OBSERVATION_BYTES, "policy observation"
    )
    try:
        return decode_portfolio_observation_v1(payload)
    except ValueError as exc:
        raise PolicyPackExtensionError("policy observation violates canonical V1") from exc


def policy_pack_extension_v1_json_schemas() -> dict[str, dict[str, Any]]:
    return {
        "policy-pack-source-pin.v1.schema.json": PolicyPackSourcePinV1.model_json_schema(),
        "policy-pack.v1.schema.json": PolicyPackV1.model_json_schema(),
        "policy-pack-signals.v1.schema.json": PolicyPackSignalsV1.model_json_schema(),
        "policy-pack-signal-binding.v1.schema.json": (
            PolicyPackSignalBindingV1.model_json_schema()
        ),
        "policy-pack-rule-evaluation.v1.schema.json": (
            PolicyPackRuleEvaluationV1.model_json_schema()
        ),
        "policy-pack-evaluation.v1.schema.json": PolicyPackEvaluationV1.model_json_schema(),
    }


def _finding(
    event_id: str,
    reason: str,
    outcome: Literal["inconclusive"],
    severity: Literal["medium"],
) -> ExtensionFindingV1:
    return ExtensionFindingV1(
        check_id=f"policy_pack.{reason}.{event_id}",
        outcome=outcome,
        severity=severity,
        reason_code=f"policy_pack.{reason}",
        evidence_event_ids=(event_id,),
    )


def _policy_pack_semantic_digest(pack: PolicyPackV1) -> str:
    payload = pack.model_dump(mode="json")
    payload.pop("pack_sha256", None)
    return hashlib.sha256(POLICY_PACK_DOMAIN + _canonical_json(payload)).hexdigest()


def _model_identity(domain: bytes, model: BaseModel, identity_field: str) -> str:
    payload = model.model_dump(mode="json")
    payload.pop(identity_field, None)
    return hashlib.sha256(domain + _canonical_json(payload)).hexdigest()


def _domain_object_digest(domain: str, value: object) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + _canonical_json(value)).hexdigest()


def _revalidate_source_pin(pin: PolicyPackSourcePinV1) -> PolicyPackSourcePinV1:
    if type(pin) is not PolicyPackSourcePinV1:
        raise PolicyPackExtensionError("policy-pack source pin must be the exact V1 type")
    try:
        return PolicyPackSourcePinV1.model_validate(pin.model_dump(mode="python"))
    except ValueError as exc:
        raise PolicyPackExtensionError("policy-pack source pin violates V1") from exc


def _revalidate_pack(pack: PolicyPackV1) -> PolicyPackV1:
    if type(pack) is not PolicyPackV1:
        raise PolicyPackExtensionError("policy pack must be the exact V1 type")
    try:
        return PolicyPackV1.model_validate(pack.model_dump(mode="python"))
    except ValueError as exc:
        raise PolicyPackExtensionError("policy pack violates the reviewed V1 semantics") from exc


def _revalidate_binding(binding: PolicyPackSignalBindingV1) -> PolicyPackSignalBindingV1:
    if type(binding) is not PolicyPackSignalBindingV1:
        raise PolicyPackExtensionError("policy signal binding must be the exact V1 type")
    try:
        return PolicyPackSignalBindingV1.model_validate(binding.model_dump(mode="python"))
    except ValueError as exc:
        raise PolicyPackExtensionError("policy signal binding violates V1") from exc


def _decode_canonical_object(payload: bytes, limit: int, label: str) -> dict[str, Any]:
    decoded = _decode_json_object(payload, limit, label)
    if _canonical_json(decoded) + b"\n" != payload:
        raise PolicyPackExtensionError(f"{label} is not canonical JSON")
    return decoded


def _decode_json_object(payload: bytes, limit: int, label: str) -> dict[str, Any]:
    if type(payload) is not bytes or not payload or len(payload) > limit:
        raise PolicyPackExtensionError(f"{label} byte size is outside V1")
    _require_json_depth(payload, label)
    try:
        decoded = json.loads(
            payload,
            object_pairs_hook=_strict_object,
            parse_int=_bounded_int,
            parse_float=_bounded_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise PolicyPackExtensionError(f"{label} is not strict UTF-8 JSON") from exc
    if type(decoded) is not dict:
        raise PolicyPackExtensionError(f"{label} root must be an object")
    return decoded


def _require_json_depth(payload: bytes, label: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in payload:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in {0x5B, 0x7B}:
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise PolicyPackExtensionError(f"{label} exceeds V1 JSON nesting depth")
        elif byte in {0x5D, 0x7D}:
            depth -= 1
            if depth < 0:
                raise PolicyPackExtensionError(f"{label} JSON nesting is unbalanced")
    if depth != 0 or in_string or escaped:
        raise PolicyPackExtensionError(f"{label} JSON structure is incomplete")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _bounded_int(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > 10:
        raise ValueError("JSON integer exceeds V1")
    return int(token, 10)


def _bounded_float(_token: str) -> float:
    raise ValueError("JSON floats are outside the policy-pack boundary")


def _reject_constant(_token: str) -> None:
    raise ValueError("non-finite JSON constants are forbidden")


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise PolicyPackExtensionError("value is not canonical JSON data") from exc


def _require_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or re.fullmatch(SHA256_PATTERN, value) is None:
        raise PolicyPackExtensionError(f"{label} must be lowercase SHA-256")


def _require_safe_ancestors(path: Path) -> None:
    current = path
    while True:
        if current.exists() and is_link_or_reparse(current):
            raise PolicyPackExtensionError("local policy path crosses a link or reparse point")
        if current.parent == current:
            return
        current = current.parent


def _explicit_local_path(path: Path) -> Path:
    if not isinstance(path, Path) or ".." in path.parts:
        raise PolicyPackExtensionError("local policy path is not an explicit safe path")
    return path.absolute()


def _read_stable_regular_file(path: Path, limit: int, label: str) -> bytes:
    _require_safe_ancestors(path.parent)
    if not path.exists() or is_link_or_reparse(path):
        raise PolicyPackExtensionError(f"{label} is missing or unsafe")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise PolicyPackExtensionError(f"{label} must be a regular single-link file")
    if before.st_size <= 0 or before.st_size > limit:
        raise PolicyPackExtensionError(f"{label} byte size is outside V1")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PolicyPackExtensionError(f"{label} could not be opened safely") from exc
    try:
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_nlink != 1
            or _file_reference(before) != _file_reference(opened_before)
        ):
            raise PolicyPackExtensionError(f"{label} changed before it was read")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if not payload or len(payload) > limit:
            raise PolicyPackExtensionError(f"{label} byte size is outside V1")
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    _require_safe_ancestors(path.parent)
    if not path.exists() or is_link_or_reparse(path):
        raise PolicyPackExtensionError(f"{label} changed while it was read")
    after = path.lstat()
    if not (
        _stat_identity(before)
        == _stat_identity(opened_before)
        == _stat_identity(opened_after)
        == _stat_identity(after)
    ):
        raise PolicyPackExtensionError(f"{label} changed while it was read")
    return payload


def _file_reference(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


__all__ = [
    "MAX_POLICY_EVENTS",
    "POLICY_PACK_COMPONENT_SHA256",
    "POLICY_PACK_FILE_SHA256",
    "POLICY_PACK_MANIFEST_SHA256",
    "POLICY_PACK_SCHEMA_SHA256",
    "POLICY_PACK_SEMANTIC_SHA256",
    "POLICY_PACK_SOURCE_COMMIT",
    "POLICY_PACK_SOURCE_TREE",
    "PolicyPackEvaluationV1",
    "PolicyPackExtensionError",
    "PolicyPackExtensionV1",
    "PolicyPackRuleEvaluationV1",
    "PolicyPackRuleV1",
    "PolicyPackSignalBindingV1",
    "PolicyPackSignalsV1",
    "PolicyPackSourcePinV1",
    "PolicyPackV1",
    "build_policy_pack_signal_binding_v1",
    "decode_policy_pack_signal_binding_v1",
    "decode_policy_pack_v1",
    "encode_policy_pack_signal_binding_v1",
    "evaluate_policy_pack_binding_v1",
    "policy_pack_extension_v1_json_schemas",
    "read_local_policy_pack_bytes_v1",
    "read_local_policy_observation_v1",
    "read_local_policy_signal_binding_v1",
    "reviewed_policy_pack_source_v1",
    "run_policy_pack_extension_v1",
    "verify_policy_pack_source_artifacts_v1",
]
