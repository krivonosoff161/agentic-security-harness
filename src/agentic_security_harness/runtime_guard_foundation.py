"""Deterministic executable specification for a future agentic Runtime Guard.

This module is a product-foundation contract, not a production proxy or policy
enforcement point.  It accepts metadata and hashes only; raw prompts, model responses,
employee conversations, credentials, and secret values are intentionally absent.

The evaluator owns the verdict.  Model output, tool output, remembered text, and agent
handoffs cannot mint authority: capability grants, consent receipts, provider-policy
records, and handoff verification must be authenticated by a separate trust domain
before they are marked ``verified`` here.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.models import CapabilityToken, DataEnvelope

GuardDisposition = Literal[
    "allow",
    "redact",
    "block",
    "ask_user",
    "sandbox_only",
    "log_only",
]
ActionType = Literal[
    "observe",
    "read",
    "model_query",
    "tool_call",
    "filesystem_write",
    "git_write",
    "code_execute",
    "network_request",
    "external_send",
    "process_control",
    "secret_access",
    "iam_change",
    "merge",
    "release",
    "deployment",
    "destructive",
]
GuardDataClass = Literal[
    "public",
    "synthetic",
    "sanitized",
    "restricted",
    "private",
    "secret",
]
VerificationState = Literal["verified", "unverified"]
ProviderResearchStatus = Literal["eligible_for_bounded_review", "hold"]
DataLoggingMode = Literal["disabled", "contract_limited", "vendor_default", "unknown"]
RetentionClass = Literal["no_storage", "transient", "contract_reviewed", "unknown"]
TrainingUse = Literal[
    "disabled",
    "no_training_without_consent",
    "allowed",
    "unknown",
]
OutputUsePolicy = Literal[
    "internal_research_only",
    "commercial_use_reviewed",
    "blocked",
    "unknown",
]
PublicationStatus = Literal[
    "aggregates_allowed",
    "provider_clearance_required",
    "blocked",
    "unknown",
]

GLOBAL_CLOUD_REQUEST_CAP = 200
GLOBAL_CLOUD_COST_CAP_KOPECKS = 150_000
SHA256_PATTERN = r"^[0-9a-f]{64}$"
_OWNER_GATE_ACTIONS: frozenset[ActionType] = frozenset(
    {
        "secret_access",
        "iam_change",
        "merge",
        "release",
        "deployment",
        "destructive",
    }
)
_CONSENT_ACTIONS: frozenset[ActionType] = frozenset(
    {
        "filesystem_write",
        "git_write",
        "model_query",
        "network_request",
        "external_send",
        "process_control",
        *_OWNER_GATE_ACTIONS,
    }
)
_EXTERNAL_ALLOWED_DATA: frozenset[GuardDataClass] = frozenset(
    {"public", "synthetic", "sanitized"}
)
_EXTERNAL_TARGET_SCHEMES = frozenset(
    {
        "dns",
        "ftp",
        "ftps",
        "grpc",
        "grpcs",
        "git",
        "http",
        "https",
        "mailto",
        "provider",
        "sftp",
        "ssh",
        "tcp",
        "tls",
        "udp",
        "ws",
        "wss",
    }
)
_LOCAL_TARGET_SCHEMES = frozenset(
    {"file", "fixture", "local", "local-git", "memory", "process"}
)


class RuntimeDataEnvelope(DataEnvelope):
    """Existing harness data policy narrowed to Runtime Guard classifications."""

    data_class: GuardDataClass = "public"
    classification_receipt_sha256: str = Field(pattern=SHA256_PATTERN)
    classified_content_sha256: str = Field(pattern=SHA256_PATTERN)
    classifier_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    classifier_trust_root_id: str = Field(min_length=1)
    classification_checked_at: datetime
    classification_expires_at: datetime
    classification_verification: VerificationState = "unverified"

    @model_validator(mode="after")
    def _classification_interval(self) -> RuntimeDataEnvelope:
        _require_aware(self.classification_checked_at, self.classification_expires_at)
        if self.classification_expires_at <= self.classification_checked_at:
            raise ValueError("classification expiry must follow verification")
        return self

    def classification_binding_digest(self) -> str:
        """Bind every classification assertion to one trusted-context digest."""
        return _sha256_json(
            {
                "receipt": self.classification_receipt_sha256,
                "content": self.classified_content_sha256,
                "data_class": self.data_class,
                "classification_source": self.classification_source,
                "classification_mutable": self.classification_mutable,
                "policy": self.classifier_policy_sha256,
                "root": self.classifier_trust_root_id,
                "checked_at": self.classification_checked_at.astimezone(UTC).isoformat(),
                "expires_at": self.classification_expires_at.astimezone(UTC).isoformat(),
                "verification": self.classification_verification,
            }
        )


class CapabilityGrant(BaseModel):
    """Verified, bounded authority supplied by a separate authority service."""

    model_config = ConfigDict(extra="forbid")

    grant_id: str = Field(min_length=1)
    issuer: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    scopes: tuple[str, ...] = Field(min_length=1)
    target_patterns: tuple[str, ...] = Field(min_length=1)
    purpose: str = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    can_delegate: bool = False
    delegation_depth: int = Field(default=0, ge=0)
    max_delegation_depth: int = Field(default=0, ge=0)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    authority_receipt_sha256: str = Field(pattern=SHA256_PATTERN)
    authorized_action_digest: str = Field(pattern=SHA256_PATTERN)
    issuer_trust_root_id: str = Field(min_length=1)
    nonce_sha256: str = Field(pattern=SHA256_PATTERN)
    max_uses: int = Field(default=1, ge=1)
    uses: int = Field(default=0, ge=0)
    revoked: bool = False
    verification: VerificationState = "unverified"

    @model_validator(mode="after")
    def _valid_interval_and_depth(self) -> CapabilityGrant:
        _require_aware(self.issued_at, self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("capability expiry must follow issuance")
        if self.delegation_depth > self.max_delegation_depth:
            raise ValueError("capability delegation depth exceeds maximum")
        if self.uses >= self.max_uses:
            raise ValueError("capability has no remaining uses")
        return self


class ConsentReceipt(BaseModel):
    """Action-bound consent; it is not inferred from text or conversation history."""

    model_config = ConfigDict(extra="forbid")

    receipt_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    action_digest: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    receipt_sha256: str = Field(pattern=SHA256_PATTERN)
    issuer_trust_root_id: str = Field(min_length=1)
    nonce_sha256: str = Field(pattern=SHA256_PATTERN)
    issued_at: datetime
    expires_at: datetime
    approved: bool
    verification: VerificationState = "unverified"

    @model_validator(mode="after")
    def _valid_interval(self) -> ConsentReceipt:
        _require_aware(self.issued_at, self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("consent expiry must follow issuance")
        return self


class ProviderPolicy(BaseModel):
    """Reviewed provider boundary without credentials or account identifiers."""

    model_config = ConfigDict(extra="forbid")

    provider_id: str = Field(min_length=1)
    invocation_route_id_hash: str = Field(pattern=SHA256_PATTERN)
    destination_id_hash: str = Field(pattern=SHA256_PATTERN)
    model_id_hash: str = Field(pattern=SHA256_PATTERN)
    target_sha256: str = Field(pattern=SHA256_PATTERN)
    terms_url: str = Field(min_length=1)
    terms_sha256: str = Field(pattern=SHA256_PATTERN)
    acceptable_use_url: str = Field(min_length=1)
    acceptable_use_sha256: str = Field(pattern=SHA256_PATTERN)
    privacy_policy_url: str = Field(min_length=1)
    privacy_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    terms_reviewed_at: datetime
    terms_review_expires_at: datetime
    model_license_id: str = Field(min_length=1)
    model_license_url: str = Field(min_length=1)
    model_license_sha256: str = Field(pattern=SHA256_PATTERN)
    model_license_status: Literal["reviewed", "blocked", "uncertain"]
    input_rights_status: Literal[
        "synthetic_owned",
        "license_reviewed",
        "blocked",
        "uncertain",
    ]
    permitted_purposes: tuple[str, ...] = Field(min_length=1)
    allowed_data_classes: tuple[GuardDataClass, ...] = (
        "public",
        "synthetic",
        "sanitized",
    )
    request_cap: int = Field(default=GLOBAL_CLOUD_REQUEST_CAP, ge=0)
    cost_cap_kopecks: int = Field(default=GLOBAL_CLOUD_COST_CAP_KOPECKS, ge=0)
    retention_class: RetentionClass
    data_logging_mode: DataLoggingMode
    training_use: TrainingUse
    output_use_policy: OutputUsePolicy
    publication_status: PublicationStatus
    automated_api_use_allowed: bool
    benchmark_use_status: Literal["allowed", "blocked", "uncertain"]
    security_research_status: ProviderResearchStatus
    region: str = Field(min_length=1)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    issuer_trust_root_id: str = Field(min_length=1)
    verification: VerificationState = "unverified"

    @model_validator(mode="after")
    def _bounded_caps_and_review(self) -> ProviderPolicy:
        _require_aware(self.terms_reviewed_at, self.terms_review_expires_at)
        if self.terms_review_expires_at <= self.terms_reviewed_at:
            raise ValueError("provider terms review expiry must follow review")
        if self.request_cap > GLOBAL_CLOUD_REQUEST_CAP:
            raise ValueError("provider request cap exceeds cycle cap")
        if self.cost_cap_kopecks > GLOBAL_CLOUD_COST_CAP_KOPECKS:
            raise ValueError("provider cost cap exceeds cycle cap")
        return self


class ProviderUsage(BaseModel):
    """Provider-specific spend observed before the proposed reservation."""

    model_config = ConfigDict(extra="forbid")

    provider_id: str = Field(min_length=1)
    requests_used: int = Field(default=0, ge=0)
    cost_used_kopecks: int = Field(default=0, ge=0)


class BudgetReservation(BaseModel):
    """One-action conservative maximum issued atomically outside this evaluator."""

    model_config = ConfigDict(extra="forbid")

    reservation_id: str = Field(min_length=1)
    action_digest: str = Field(pattern=SHA256_PATTERN)
    provider_id: str = Field(min_length=1)
    requests: int = Field(ge=1)
    max_cost_kopecks: int = Field(ge=0)
    currency: Literal["RUB"] = "RUB"
    issued_at: datetime
    expires_at: datetime
    reservation_receipt_sha256: str = Field(pattern=SHA256_PATTERN)
    pricing_quote_sha256: str = Field(pattern=SHA256_PATTERN)
    pricing_quote_issued_at: datetime
    pricing_quote_expires_at: datetime
    fx_evidence_sha256: str = Field(pattern=SHA256_PATTERN)
    rounding_rule: Literal["ceil_to_kopeck"] = "ceil_to_kopeck"
    safety_margin_bps: int = Field(ge=1, le=10_000)
    issuer_trust_root_id: str = Field(min_length=1)
    verification: VerificationState = "unverified"

    @model_validator(mode="after")
    def _aware_expiry(self) -> BudgetReservation:
        _require_aware(
            self.issued_at,
            self.expires_at,
            self.pricing_quote_issued_at,
            self.pricing_quote_expires_at,
        )
        if self.expires_at <= self.issued_at:
            raise ValueError("budget reservation expiry must follow issuance")
        if self.pricing_quote_expires_at <= self.pricing_quote_issued_at:
            raise ValueError("pricing quote expiry must follow issuance")
        return self


class HandoffEvidenceBinding(BaseModel):
    """Hash binding to the existing HandoffEnvelope/HandoffVerification artifacts."""

    model_config = ConfigDict(extra="forbid")

    envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    verification_sha256: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    receiver_id_hash: str = Field(pattern=SHA256_PATTERN)
    verdict: Literal["pass", "blocked", "needs_review", "quarantine"]
    checked_at: datetime
    expires_at: datetime
    verifier_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    issuer_trust_root_id: str = Field(min_length=1)
    verification: VerificationState = "unverified"

    @model_validator(mode="after")
    def _aware_check_time(self) -> HandoffEvidenceBinding:
        _require_aware(self.checked_at, self.expires_at)
        if self.expires_at <= self.checked_at:
            raise ValueError("handoff expiry must follow verification")
        return self

    def binding_digest(self) -> str:
        """Bind every handoff assertion to one trusted-context digest."""
        return _sha256_json(self.model_dump(mode="json"))


class ToolEvidenceBinding(BaseModel):
    """Pinned tool identity and schema supplied by a separate trusted registry."""

    model_config = ConfigDict(extra="forbid")

    tool_id_hash: str = Field(pattern=SHA256_PATTERN)
    schema_sha256: str = Field(pattern=SHA256_PATTERN)
    registry_sha256: str = Field(pattern=SHA256_PATTERN)
    declared_effect: ActionType
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    issuer_trust_root_id: str = Field(min_length=1)
    verification: VerificationState = "unverified"

    def binding_digest(self) -> str:
        """Bind every tool-registry assertion to one trusted-context digest."""
        return _sha256_json(self.model_dump(mode="json"))


class ActionEnvelope(BaseModel):
    """Metadata-only description of a proposed agent action."""

    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    session_id_hash: str = Field(pattern=SHA256_PATTERN)
    sponsor_id_hash: str = Field(pattern=SHA256_PATTERN)
    call_chain_digest: str = Field(pattern=SHA256_PATTERN)
    action_type: ActionType
    effect_type: ActionType | None = None
    target: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    requested_scopes: tuple[str, ...] = Field(min_length=1)
    data_envelope: RuntimeDataEnvelope
    content_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime
    expires_at: datetime
    provider_id: str | None = None
    destination_id_hash: str | None = Field(default=None, pattern=SHA256_PATTERN)
    invocation_route_id_hash: str | None = Field(default=None, pattern=SHA256_PATTERN)
    model_id_hash: str | None = Field(default=None, pattern=SHA256_PATTERN)
    provider_region: str | None = Field(default=None, min_length=1)
    reserved_cloud_requests: int = Field(default=0, ge=0)
    max_cost_kopecks: int = Field(default=0, ge=0)
    handoff: HandoffEvidenceBinding | None = None
    tool: ToolEvidenceBinding | None = None
    call_chain_depth: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _valid_interval_and_provider_shape(self) -> ActionEnvelope:
        _require_aware(self.created_at, self.expires_at)
        if self.expires_at <= self.created_at:
            raise ValueError("action expiry must follow creation")
        if self.target != self.target.strip() or "\\" in self.target:
            raise ValueError("target must be normalized")
        parsed_target = urlsplit(self.target)
        decoded_path = unquote(parsed_target.path)
        raw_scheme, separator, raw_remainder = self.target.partition("://")
        raw_authority = raw_remainder.split("/", 1)[0]
        if (
            not parsed_target.scheme
            or not separator
            or raw_scheme != raw_scheme.lower()
            or raw_authority != raw_authority.lower()
            or parsed_target.fragment
            or parsed_target.query
            or parsed_target.username is not None
            or parsed_target.password is not None
            or parsed_target.port is not None
            or (
                parsed_target.hostname is not None
                and parsed_target.hostname.endswith(".")
            )
            or not self.target.isascii()
            or "%" in self.target
            or any(ord(char) < 32 for char in self.target)
            or "//" in decoded_path
            or any(part in {".", ".."} for part in decoded_path.split("/"))
        ):
            raise ValueError("target must be an absolute canonical resource URI")
        if self.action_type == "model_query" and self.provider_id is None:
            raise ValueError("model query requires provider_id")
        if self.action_type in {"model_query", "network_request", "external_send"}:
            if (
                self.provider_id is None
                or self.destination_id_hash is None
                or self.invocation_route_id_hash is None
                or self.model_id_hash is None
                or self.provider_region is None
            ):
                raise ValueError(
                    "external action requires provider, route, destination, model, region"
                )
        if self.action_type == "tool_call" and (
            self.tool is None or self.effect_type is None
        ):
            raise ValueError("tool call requires pinned tool and effect bindings")
        if self.action_type != "tool_call" and self.effect_type is not None:
            raise ValueError("effect_type is valid only for a pinned tool call")
        effective_action = self.effective_action_type()
        external_effect = effective_action in {
            "model_query",
            "network_request",
            "external_send",
        }
        if parsed_target.scheme not in (
            _EXTERNAL_TARGET_SCHEMES | _LOCAL_TARGET_SCHEMES
        ):
            raise ValueError("target scheme is not in the closed policy vocabulary")
        if (
            parsed_target.scheme in _EXTERNAL_TARGET_SCHEMES
            and effective_action
            not in {"model_query", "network_request", "external_send"}
        ):
            raise ValueError("external target requires an authenticated egress effect")
        if external_effect and parsed_target.scheme not in _EXTERNAL_TARGET_SCHEMES:
            raise ValueError("egress effect requires an external target scheme")
        if (
            parsed_target.scheme in _EXTERNAL_TARGET_SCHEMES
            and not parsed_target.netloc
        ):
            raise ValueError("external target requires a non-empty authority")
        if parsed_target.scheme == "file" and parsed_target.netloc:
            raise ValueError("file target cannot name a remote authority")
        if parsed_target.scheme == "local-git" and parsed_target.netloc != "repository":
            raise ValueError("local-git target requires the abstract repository authority")
        if external_effect and (
            self.provider_id is None
            or self.destination_id_hash is None
            or self.invocation_route_id_hash is None
            or self.model_id_hash is None
            or self.provider_region is None
        ):
            raise ValueError("egress effect requires exact provider route and model")
        if self.provider_id is not None and not external_effect:
            raise ValueError("provider metadata is valid only for an egress effect")
        if self.provider_id is None and any(
            value is not None
            for value in (
                self.destination_id_hash,
                self.invocation_route_id_hash,
                self.model_id_hash,
                self.provider_region,
            )
        ):
            raise ValueError("provider route metadata requires provider_id")
        if self.call_chain_depth > 0 and self.handoff is None:
            raise ValueError("delegated action requires a handoff binding")
        if self.provider_id is None and (
            self.reserved_cloud_requests or self.max_cost_kopecks
        ):
            raise ValueError("cloud estimates require provider_id")
        if self.provider_id is not None and self.reserved_cloud_requests < 1:
            raise ValueError("external provider action requires at least one request")
        return self

    def action_digest(self) -> str:
        """Bind consent to exact action semantics without retaining content bytes."""
        return _sha256_json(
            {
                "action_id": self.action_id,
                "actor_id": self.actor_id,
                "action_type": self.action_type,
                "effect_type": self.effect_type,
                "target": self.target,
                "purpose": self.purpose,
                "requested_scopes": sorted(self.requested_scopes),
                "data_envelope": self.data_envelope.model_dump(mode="json"),
                "content_sha256": self.content_sha256,
                "provider_id": self.provider_id,
                "destination_id_hash": self.destination_id_hash,
                "invocation_route_id_hash": self.invocation_route_id_hash,
                "model_id_hash": self.model_id_hash,
                "provider_region": self.provider_region,
                "session_id_hash": self.session_id_hash,
                "sponsor_id_hash": self.sponsor_id_hash,
                "call_chain_digest": self.call_chain_digest,
                "call_chain_depth": self.call_chain_depth,
                "created_at": self.created_at.astimezone(UTC).isoformat(),
                "expires_at": self.expires_at.astimezone(UTC).isoformat(),
                "reserved_cloud_requests": self.reserved_cloud_requests,
                "max_cost_kopecks": self.max_cost_kopecks,
                "handoff": (
                    None if self.handoff is None else self.handoff.model_dump(mode="json")
                ),
                "tool": None if self.tool is None else self.tool.model_dump(mode="json"),
                "policy_sha256": self.policy_sha256,
            }
        )

    def effective_action_type(self) -> ActionType:
        """Return the effect guarded for consent/owner-gate decisions."""
        return self.effect_type or self.action_type


class GuardContext(BaseModel):
    """Current, code-owned inputs to one deterministic decision."""

    model_config = ConfigDict(extra="forbid")

    evaluated_at: datetime
    policy_version: str = Field(min_length=1)
    active_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    capabilities: tuple[CapabilityGrant, ...] = Field(default_factory=tuple)
    consent_receipts: tuple[ConsentReceipt, ...] = Field(default_factory=tuple)
    provider_policies: tuple[ProviderPolicy, ...] = Field(default_factory=tuple)
    provider_usages: tuple[ProviderUsage, ...] = Field(default_factory=tuple)
    budget_reservations: tuple[BudgetReservation, ...] = Field(default_factory=tuple)
    cloud_requests_used: int = Field(default=0, ge=0)
    cloud_cost_used_kopecks: int = Field(default=0, ge=0)
    evidence_previous_hash: str = Field(pattern=SHA256_PATTERN)
    seen_action_digests: tuple[str, ...] = Field(default_factory=tuple)
    seen_action_id_hashes: tuple[str, ...] = Field(default_factory=tuple)
    trusted_authority_root_ids: tuple[str, ...] = Field(min_length=1)
    trusted_consent_root_ids: tuple[str, ...] = Field(min_length=1)
    trusted_handoff_root_ids: tuple[str, ...] = Field(min_length=1)
    trusted_budget_root_ids: tuple[str, ...] = Field(min_length=1)
    trusted_classifier_root_ids: tuple[str, ...] = Field(min_length=1)
    trusted_tool_registry_root_ids: tuple[str, ...] = Field(min_length=1)
    trusted_provider_policy_root_ids: tuple[str, ...] = Field(min_length=1)
    authenticated_classification_bindings: tuple[str, ...] = Field(min_length=1)
    authenticated_handoff_bindings: tuple[str, ...] = Field(default_factory=tuple)
    authenticated_tool_bindings: tuple[str, ...] = Field(default_factory=tuple)
    verifier_available: bool = True

    @model_validator(mode="after")
    def _aware_evaluation_time(self) -> GuardContext:
        _require_aware(self.evaluated_at)
        if any(not _is_sha256(value) for value in self.seen_action_digests):
            raise ValueError("seen action digests must be lowercase SHA-256")
        if any(not _is_sha256(value) for value in self.seen_action_id_hashes):
            raise ValueError("seen action id hashes must be lowercase SHA-256")
        _require_unique(
            "provider policy ids",
            tuple(item.provider_id for item in self.provider_policies),
        )
        _require_unique(
            "provider usage ids",
            tuple(item.provider_id for item in self.provider_usages),
        )
        _require_unique("grant ids", tuple(item.grant_id for item in self.capabilities))
        _require_unique(
            "grant nonces", tuple(item.nonce_sha256 for item in self.capabilities)
        )
        _require_unique(
            "consent ids", tuple(item.receipt_id for item in self.consent_receipts)
        )
        _require_unique(
            "consent nonces",
            tuple(item.nonce_sha256 for item in self.consent_receipts),
        )
        _require_unique(
            "reservation ids",
            tuple(item.reservation_id for item in self.budget_reservations),
        )
        _require_unique("seen action digests", self.seen_action_digests)
        _require_unique("seen action id hashes", self.seen_action_id_hashes)
        _require_unique(
            "authenticated classification receipts",
            self.authenticated_classification_bindings,
        )
        _require_unique(
            "authenticated handoff verifications",
            self.authenticated_handoff_bindings,
        )
        _require_unique(
            "authenticated tool registries",
            self.authenticated_tool_bindings,
        )
        return self


class EvidenceReceipt(BaseModel):
    """Secret-safe decision evidence.  No raw action or conversation data."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["runtime-guard-evidence-v0.1"] = (
        "runtime-guard-evidence-v0.1"
    )
    action_id_hash: str = Field(pattern=SHA256_PATTERN)
    action_digest: str = Field(pattern=SHA256_PATTERN)
    content_sha256: str = Field(pattern=SHA256_PATTERN)
    context_digest: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_version: str = Field(min_length=1)
    disposition: GuardDisposition
    reason_codes: tuple[str, ...]
    evaluated_at: datetime
    previous_hash: str = Field(pattern=SHA256_PATTERN)
    origin_authentication: Literal["unverified"] = "unverified"
    trusted_time: Literal["not_recorded"] = "not_recorded"
    receipt_kind: Literal["decision_only"] = "decision_only"
    decision_hash: str = Field(pattern=SHA256_PATTERN)


class GuardDecision(BaseModel):
    """Fail-closed product-foundation verdict."""

    model_config = ConfigDict(extra="forbid")

    disposition: GuardDisposition
    reason_codes: tuple[str, ...]
    owner_gate_required: bool
    evidence: EvidenceReceipt


def capability_grant_from_synthetic_token(
    token: CapabilityToken,
    *,
    grant_id: str,
    target_patterns: tuple[str, ...],
    issued_at: datetime,
    expires_at: datetime,
    policy_sha256: str,
    token_sha256: str,
) -> CapabilityGrant:
    """Map a harness ``CapabilityToken`` into an explicitly unverified draft grant.

    The existing token is a synthetic test object, not a credential.  Conversion
    preserves its non-expansion fields but deliberately cannot authenticate it or make
    it usable by :func:`evaluate_action`.
    """

    return CapabilityGrant(
        grant_id=grant_id,
        issuer=token.issuer,
        subject=token.subject,
        scopes=tuple(token.scope),
        target_patterns=target_patterns,
        purpose=token.purpose,
        issued_at=issued_at,
        expires_at=expires_at,
        can_delegate=token.can_delegate,
        delegation_depth=token.depth,
        max_delegation_depth=token.depth,
        policy_sha256=policy_sha256,
        authority_receipt_sha256=token_sha256,
        authorized_action_digest=token_sha256,
        issuer_trust_root_id="synthetic-harness-token",
        nonce_sha256=token_sha256,
        verification="unverified",
    )


def evaluate_action(action: ActionEnvelope, context: GuardContext) -> GuardDecision:
    """Evaluate one proposed action using deterministic, model-independent policy."""

    reasons: list[str] = []
    effective_action = action.effective_action_type()
    owner_gate_required = effective_action in _OWNER_GATE_ACTIONS

    if not context.verifier_available:
        reasons.append("verifier_unavailable")
    if action.created_at > context.evaluated_at:
        reasons.append("action_created_in_future")
    if context.evaluated_at > action.expires_at:
        reasons.append("action_expired")
    if action.action_digest() in set(context.seen_action_digests):
        reasons.append("action_replay_detected")
    if _sha256_text(action.action_id) in set(context.seen_action_id_hashes):
        reasons.append("action_id_reused")
    if action.policy_sha256 != context.active_policy_sha256:
        reasons.append("active_policy_mismatch")
    if action.handoff is not None and (
        action.handoff.verification != "verified"
        or action.handoff.verdict != "pass"
        or action.handoff.verifier_policy_sha256 != context.active_policy_sha256
        or action.handoff.payload_sha256 != action.content_sha256
        or action.handoff.receiver_id_hash != _sha256_text(action.actor_id)
        or action.handoff.checked_at > context.evaluated_at
        or action.handoff.expires_at < context.evaluated_at
        or action.handoff.binding_digest()
        not in set(context.authenticated_handoff_bindings)
        or action.handoff.issuer_trust_root_id
        not in set(context.trusted_handoff_root_ids)
    ):
        reasons.append("handoff_not_verified")
    if action.tool is not None and (
        action.tool.verification != "verified"
        or action.tool.policy_sha256 != context.active_policy_sha256
        or action.tool.declared_effect != action.effect_type
        or action.tool.binding_digest()
        not in set(context.authenticated_tool_bindings)
        or action.tool.issuer_trust_root_id
        not in set(context.trusted_tool_registry_root_ids)
    ):
        reasons.append("tool_not_verified")
    if action.data_envelope.data_class == "secret":
        reasons.append("secret_data_forbidden")
    if action.purpose not in set(action.data_envelope.allowed_purpose):
        reasons.append("data_purpose_forbidden")
    if action.data_envelope.classification_source == "unknown":
        reasons.append("data_classification_unknown")
    if (
        action.data_envelope.classification_verification != "verified"
        or action.data_envelope.classification_binding_digest()
        not in set(context.authenticated_classification_bindings)
        or action.data_envelope.classified_content_sha256 != action.content_sha256
        or action.data_envelope.classifier_policy_sha256
        != context.active_policy_sha256
        or action.data_envelope.classification_checked_at > context.evaluated_at
        or action.data_envelope.classification_expires_at < context.evaluated_at
        or action.data_envelope.classifier_trust_root_id
        not in set(context.trusted_classifier_root_ids)
    ):
        reasons.append("data_classification_unverified")
    if action.data_envelope.classification_mutable:
        reasons.append("data_classification_mutable")
    if action.data_envelope.ttl_seconds is not None:
        age = (context.evaluated_at - action.created_at).total_seconds()
        if age > action.data_envelope.ttl_seconds:
            reasons.append("data_ttl_expired")
    if effective_action in {"filesystem_write", "git_write"} and not (
        action.data_envelope.can_store
    ):
        reasons.append("data_storage_forbidden")
    if action.provider_id is not None and not action.data_envelope.can_forward:
        reasons.append("data_forwarding_forbidden")
    if (
        action.provider_id is not None
        and (
            not action.data_envelope.allowed_recipients
            or action.provider_id not in set(action.data_envelope.allowed_recipients)
        )
    ):
        reasons.append("data_recipient_forbidden")
    if action.provider_id is None and action.action_type in {
        "network_request",
        "external_send",
    }:
        reasons.append("external_route_missing_provider")

    capability_ok = _has_capability(action, context)
    if action.requested_scopes and not capability_ok:
        reasons.append("capability_missing_or_invalid")

    consent_ok = _has_consent(action, context)
    if (effective_action in _CONSENT_ACTIONS or action.data_envelope.requires_confirmation) and (
        not consent_ok
    ):
        reasons.append("current_action_consent_missing")

    if action.provider_id is not None:
        reasons.extend(_provider_reasons(action, context))

    hard_block = any(
        reason
        in {
            "verifier_unavailable",
            "action_created_in_future",
            "action_expired",
            "action_replay_detected",
            "action_id_reused",
            "active_policy_mismatch",
            "handoff_not_verified",
            "tool_not_verified",
            "secret_data_forbidden",
            "data_purpose_forbidden",
            "data_classification_unknown",
            "data_classification_unverified",
            "data_classification_mutable",
            "data_ttl_expired",
            "data_storage_forbidden",
            "data_forwarding_forbidden",
            "data_recipient_forbidden",
            "external_route_missing_provider",
            "provider_policy_missing_or_unverified",
            "provider_route_or_model_mismatch",
            "provider_terms_review_stale",
            "provider_research_on_hold",
            "provider_automated_api_forbidden",
            "provider_benchmark_status_not_allowed",
            "provider_logging_boundary_unacceptable",
            "provider_retention_unknown",
            "provider_training_use_unacceptable",
            "provider_output_use_unacceptable",
            "provider_publication_status_unacceptable",
            "provider_model_license_unreviewed",
            "provider_input_rights_unverified",
            "provider_purpose_forbidden",
            "provider_data_class_forbidden",
            "budget_reservation_missing_or_invalid",
            "global_request_budget_exceeded",
            "global_cost_budget_exceeded",
            "provider_request_budget_exceeded",
            "provider_cost_budget_exceeded",
            "provider_usage_missing",
        }
        for reason in reasons
    )

    if hard_block:
        disposition: GuardDisposition = "block"
    elif owner_gate_required:
        disposition = "ask_user"
    elif "capability_missing_or_invalid" in reasons:
        disposition = "block"
    elif (
        action.provider_id is not None
        and action.data_envelope.data_class == "restricted"
    ):
        disposition = "redact"
    elif "current_action_consent_missing" in reasons:
        disposition = "ask_user"
    elif effective_action == "code_execute":
        disposition = "sandbox_only"
    elif action.action_type == "observe":
        disposition = "log_only"
    else:
        disposition = "allow"

    ordered_reasons = tuple(sorted(set(reasons)))
    if not ordered_reasons:
        ordered_reasons = ("policy_satisfied",)
    evidence = _evidence_receipt(
        action=action,
        context=context,
        disposition=disposition,
        reasons=ordered_reasons,
    )
    return GuardDecision(
        disposition=disposition,
        reason_codes=ordered_reasons,
        owner_gate_required=owner_gate_required,
        evidence=evidence,
    )


def _has_capability(action: ActionEnvelope, context: GuardContext) -> bool:
    requested = set(action.requested_scopes)
    if not requested:
        return True
    for grant in context.capabilities:
        if grant.verification != "verified":
            continue
        if grant.revoked or grant.policy_sha256 != context.active_policy_sha256:
            continue
        if grant.issuer_trust_root_id not in set(context.trusted_authority_root_ids):
            continue
        if grant.authorized_action_digest != action.action_digest():
            continue
        if grant.subject != action.actor_id or grant.purpose != action.purpose:
            continue
        if grant.delegation_depth != action.call_chain_depth:
            continue
        if not (grant.issued_at <= context.evaluated_at <= grant.expires_at):
            continue
        if not requested.issubset(set(grant.scopes)):
            continue
        if not any(
            fnmatch.fnmatchcase(action.target, pattern)
            for pattern in grant.target_patterns
        ):
            continue
        return True
    return False


def _has_consent(action: ActionEnvelope, context: GuardContext) -> bool:
    expected_digest = action.action_digest()
    for receipt in context.consent_receipts:
        if receipt.verification != "verified" or not receipt.approved:
            continue
        if receipt.issuer_trust_root_id not in set(context.trusted_consent_root_ids):
            continue
        if receipt.action_id != action.action_id or receipt.actor_id != action.actor_id:
            continue
        if receipt.action_digest != expected_digest:
            continue
        if receipt.policy_sha256 != context.active_policy_sha256:
            continue
        if receipt.issued_at <= context.evaluated_at <= receipt.expires_at:
            return True
    return False


def _provider_reasons(action: ActionEnvelope, context: GuardContext) -> list[str]:
    policy = next(
        (
            item
            for item in context.provider_policies
            if item.provider_id == action.provider_id
            and item.verification == "verified"
            and item.issuer_trust_root_id
            in set(context.trusted_provider_policy_root_ids)
        ),
        None,
    )
    if policy is None:
        return ["provider_policy_missing_or_unverified"]

    reasons: list[str] = []
    if policy.policy_sha256 != context.active_policy_sha256:
        reasons.append("provider_policy_missing_or_unverified")
    if (
        policy.invocation_route_id_hash != action.invocation_route_id_hash
        or policy.destination_id_hash != action.destination_id_hash
        or policy.model_id_hash != action.model_id_hash
        or policy.target_sha256 != _sha256_text(action.target)
        or policy.region != action.provider_region
    ):
        reasons.append("provider_route_or_model_mismatch")
    if not (
        policy.terms_reviewed_at
        <= context.evaluated_at
        <= policy.terms_review_expires_at
    ):
        reasons.append("provider_terms_review_stale")
    if policy.security_research_status != "eligible_for_bounded_review":
        reasons.append("provider_research_on_hold")
    if not policy.automated_api_use_allowed:
        reasons.append("provider_automated_api_forbidden")
    if policy.benchmark_use_status != "allowed":
        reasons.append("provider_benchmark_status_not_allowed")
    if policy.data_logging_mode not in {"disabled", "contract_limited"}:
        reasons.append("provider_logging_boundary_unacceptable")
    if policy.retention_class not in {"no_storage", "transient", "contract_reviewed"}:
        reasons.append("provider_retention_unknown")
    if policy.training_use not in {"disabled", "no_training_without_consent"}:
        reasons.append("provider_training_use_unacceptable")
    if policy.output_use_policy not in {
        "internal_research_only",
        "commercial_use_reviewed",
    }:
        reasons.append("provider_output_use_unacceptable")
    if policy.publication_status != "aggregates_allowed":
        reasons.append("provider_publication_status_unacceptable")
    if policy.model_license_status != "reviewed":
        reasons.append("provider_model_license_unreviewed")
    if policy.input_rights_status not in {"synthetic_owned", "license_reviewed"}:
        reasons.append("provider_input_rights_unverified")
    if action.purpose not in policy.permitted_purposes:
        reasons.append("provider_purpose_forbidden")
    if action.data_envelope.data_class == "restricted":
        reasons.append("provider_redaction_required")
    elif (
        action.data_envelope.data_class not in _EXTERNAL_ALLOWED_DATA
        or action.data_envelope.data_class not in set(policy.allowed_data_classes)
    ):
        reasons.append("provider_data_class_forbidden")

    if action.data_envelope.data_class == "restricted":
        return reasons

    reservation = next(
        (
            item
            for item in context.budget_reservations
            if item.action_digest == action.action_digest()
            and item.provider_id == action.provider_id
            and item.requests == action.reserved_cloud_requests
            and item.max_cost_kopecks == action.max_cost_kopecks
            and item.verification == "verified"
            and item.issuer_trust_root_id in set(context.trusted_budget_root_ids)
            and item.issued_at <= context.evaluated_at
            and context.evaluated_at <= item.expires_at
            and item.pricing_quote_issued_at <= context.evaluated_at
            and context.evaluated_at <= item.pricing_quote_expires_at
        ),
        None,
    )
    if reservation is None:
        reasons.append("budget_reservation_missing_or_invalid")

    active_reservations = tuple(
        item
        for item in context.budget_reservations
        if item.verification == "verified"
        and item.issuer_trust_root_id in set(context.trusted_budget_root_ids)
        and item.issued_at <= context.evaluated_at <= item.expires_at
    )
    request_total = context.cloud_requests_used + sum(
        item.requests for item in active_reservations
    )
    cost_total = context.cloud_cost_used_kopecks + sum(
        item.max_cost_kopecks for item in active_reservations
    )
    if request_total > GLOBAL_CLOUD_REQUEST_CAP:
        reasons.append("global_request_budget_exceeded")
    if cost_total > GLOBAL_CLOUD_COST_CAP_KOPECKS:
        reasons.append("global_cost_budget_exceeded")
    usage = next(
        (
            item
            for item in context.provider_usages
            if item.provider_id == action.provider_id
        ),
        None,
    )
    if usage is None:
        reasons.append("provider_usage_missing")
        return reasons
    provider_reserved_requests = sum(
        item.requests
        for item in active_reservations
        if item.provider_id == action.provider_id
    )
    provider_reserved_cost = sum(
        item.max_cost_kopecks
        for item in active_reservations
        if item.provider_id == action.provider_id
    )
    if usage.requests_used + provider_reserved_requests > policy.request_cap:
        reasons.append("provider_request_budget_exceeded")
    if usage.cost_used_kopecks + provider_reserved_cost > policy.cost_cap_kopecks:
        reasons.append("provider_cost_budget_exceeded")
    return reasons


def _evidence_receipt(
    *,
    action: ActionEnvelope,
    context: GuardContext,
    disposition: GuardDisposition,
    reasons: tuple[str, ...],
) -> EvidenceReceipt:
    context_digest = _sha256_json(
        {
            "policy_version": context.policy_version,
            "active_policy_sha256": context.active_policy_sha256,
            "capability_ids": sorted(
                _sha256_json(item.model_dump(mode="json"))
                for item in context.capabilities
                if item.verification == "verified"
            ),
            "consent_ids": sorted(
                _sha256_json(item.model_dump(mode="json"))
                for item in context.consent_receipts
                if item.verification == "verified"
            ),
            "provider_policy_ids": sorted(
                _sha256_json(item.model_dump(mode="json"))
                for item in context.provider_policies
                if item.verification == "verified"
            ),
            "reservation_ids": sorted(
                _sha256_json(item.model_dump(mode="json"))
                for item in context.budget_reservations
                if item.verification == "verified"
            ),
            "provider_usages": sorted(
                _sha256_json(item.model_dump(mode="json"))
                for item in context.provider_usages
            ),
            "seen_action_digests": sorted(context.seen_action_digests),
            "seen_action_id_hashes": sorted(context.seen_action_id_hashes),
            "trusted_roots_digest": _sha256_json(
                {
                    "authority": sorted(context.trusted_authority_root_ids),
                    "consent": sorted(context.trusted_consent_root_ids),
                    "handoff": sorted(context.trusted_handoff_root_ids),
                    "budget": sorted(context.trusted_budget_root_ids),
                    "classifier": sorted(context.trusted_classifier_root_ids),
                    "tool": sorted(context.trusted_tool_registry_root_ids),
                    "provider": sorted(context.trusted_provider_policy_root_ids),
                }
            ),
            "authenticated_receipts_digest": _sha256_json(
                {
                    "classifications": sorted(
                        context.authenticated_classification_bindings
                    ),
                    "handoffs": sorted(
                        context.authenticated_handoff_bindings
                    ),
                    "tools": sorted(context.authenticated_tool_bindings),
                }
            ),
            "cloud_requests_used": context.cloud_requests_used,
            "cloud_cost_used_kopecks": context.cloud_cost_used_kopecks,
            "verifier_available": context.verifier_available,
        }
    )
    action_id_hash = _sha256_text(action.action_id)
    evaluated_at = context.evaluated_at.astimezone(UTC).isoformat()
    decision_payload: dict[str, object] = {
        "action_id_hash": action_id_hash,
        "action_digest": action.action_digest(),
        "content_sha256": action.content_sha256,
        "context_digest": context_digest,
        "policy_version": context.policy_version,
        "policy_sha256": context.active_policy_sha256,
        "disposition": disposition,
        "reason_codes": reasons,
        "evaluated_at": evaluated_at,
        "previous_hash": context.evidence_previous_hash,
    }
    return EvidenceReceipt(
        action_id_hash=action_id_hash,
        action_digest=action.action_digest(),
        content_sha256=action.content_sha256,
        context_digest=context_digest,
        policy_version=context.policy_version,
        policy_sha256=context.active_policy_sha256,
        disposition=disposition,
        reason_codes=reasons,
        evaluated_at=context.evaluated_at,
        previous_hash=context.evidence_previous_hash,
        decision_hash=_sha256_json(decision_payload),
    )


def _sha256_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_aware(*values: datetime) -> None:
    if any(value.tzinfo is None or value.utcoffset() is None for value in values):
        raise ValueError("timestamps must include a timezone")


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _require_unique(label: str, values: tuple[str, ...]) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
