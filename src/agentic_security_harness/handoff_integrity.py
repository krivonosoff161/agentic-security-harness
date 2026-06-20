"""Deterministic inter-agent handoff integrity checks.

The verifier is intentionally small and local. It models the mathematical contract for
the first toy coordinator/worker topology: a receiver may consume a handoff only if the
payload bytes, provenance labels, authority scope, freshness, policy version, and
recipient constraints are reproducibly valid.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

HandoffPayloadType = Literal[
    "summary",
    "tool_output",
    "capability",
    "approval",
    "memory_recall",
    "decision",
    "error",
]
HandoffVerdict = Literal["pass", "blocked", "needs_review", "quarantine"]
FailureReason = Literal[
    "missing_envelope",
    "missing_provenance",
    "integrity_mismatch",
    "label_loss",
    "authority_expansion",
    "recipient_violation",
    "stale_or_replayed",
    "policy_mismatch",
    "verifier_error",
    "unsafe_consumption",
]

_HARD_REASON_ORDER: tuple[FailureReason, ...] = (
    "missing_envelope",
    "missing_provenance",
    "integrity_mismatch",
    "label_loss",
    "authority_expansion",
    "recipient_violation",
    "stale_or_replayed",
    "policy_mismatch",
    "verifier_error",
)
_SOURCE_LABEL_REQUIRED: frozenset[HandoffPayloadType] = frozenset(
    {"summary", "tool_output", "approval", "memory_recall"}
)
_PAYLOAD_MULTIPLIERS: dict[HandoffPayloadType, float] = {
    "capability": 1.5,
    "approval": 1.3,
    "summary": 1.0,
    "tool_output": 0.8,
    "memory_recall": 1.2,
    "decision": 1.0,
    "error": 1.0,
}


class HandoffEnvelope(BaseModel):
    """Minimal typed envelope for a synthetic inter-agent handoff."""

    model_config = ConfigDict(extra="forbid")

    envelope_id: str = Field(min_length=1)
    created_at: datetime
    sender_id: str = Field(min_length=1)
    receiver_id: str = Field(min_length=1)
    task_id: str | None = None
    session_id: str | None = None
    payload_type: HandoffPayloadType
    payload_hash: str = Field(min_length=64, max_length=64)
    payload_canonicalization: Literal["json-v1"] = "json-v1"
    payload_ref: str | None = None
    source_labels: list[str] = Field(default_factory=list)
    transformation_chain: list[dict[str, str]] = Field(default_factory=list)
    authority_issuer: str | None = None
    authority_scope: list[str] = Field(default_factory=list)
    purpose: str = ""
    delegation_depth: int = Field(default=0, ge=0)
    max_delegation_depth: int = Field(default=0, ge=0)
    can_delegate: bool = False
    allowed_recipients: list[str] = Field(default_factory=list)
    ttl_seconds: int = Field(ge=0)
    expires_at: datetime
    policy_version: str = Field(min_length=1)
    schema_version: str = "handoff-envelope-v0.1"
    receiver_supported_policy_versions: list[str] = Field(default_factory=list)
    verification_status: Literal["pending", "verified", "failed", "skipped"] = "pending"
    verification_error: str | None = None
    failure_action: Literal["block", "review", "downgrade", "quarantine"] = "block"
    audit_previous_hash: str | None = None
    audit_entry_hash: str | None = None


class HandoffVerification(BaseModel):
    """Deterministic verifier output used by toy traces and tests."""

    model_config = ConfigDict(extra="forbid")

    verdict: HandoffVerdict
    failure_reasons: list[FailureReason] = Field(default_factory=list)
    hard_blockers: list[FailureReason] = Field(default_factory=list)
    review_reasons: list[str] = Field(default_factory=list)
    structural_score: float = Field(ge=0.0, le=1.0)
    semantic_score: float = Field(ge=0.0, le=1.0)
    combined_score: float = Field(ge=0.0, le=1.0)
    payload_multiplier: float = Field(ge=0.0)
    unsafe_consumptions: int = Field(default=0, ge=0)
    total_consumptions: int = Field(default=0, ge=0)
    checked_at: datetime


def canonical_payload_bytes(payload: Any) -> bytes:
    """Return stable JSON bytes for payload hashing."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def payload_sha256(payload: Any) -> str:
    """Return the SHA-256 hex digest for the canonical payload."""
    return hashlib.sha256(canonical_payload_bytes(payload)).hexdigest()


def verify_handoff(
    envelope: HandoffEnvelope | None,
    payload: Any,
    *,
    current_time: datetime | None = None,
    parent_source_labels: list[str] | None = None,
    parent_authority_scope: list[str] | None = None,
    unsafe_consumptions: int = 0,
    total_consumptions: int = 0,
    verifier_available: bool = True,
) -> HandoffVerification:
    """Verify a handoff envelope and return deterministic verdict + scores.

    The verdict is a blocker decision. The score is reporting metadata:

    ``S_structural = 1`` for hard blockers, ``0.5`` for review-only uncertainty, else ``0``.
    ``S_semantic = n_unsafe / n_consumptions`` with a zero-consumption guard.
    ``S_combined = 0.7 * min(1, multiplier * S_structural) + 0.3 * S_semantic``.
    """
    now = current_time or datetime.now(UTC)
    semantic_score = _semantic_score(unsafe_consumptions, total_consumptions)
    if not verifier_available:
        return _result(
            payload_type="summary",
            hard_blockers=["verifier_error"],
            review_reasons=[],
            semantic_score=semantic_score,
            unsafe_consumptions=unsafe_consumptions,
            total_consumptions=total_consumptions,
            checked_at=now,
        )
    if envelope is None:
        return _result(
            payload_type="summary",
            hard_blockers=["missing_envelope"],
            review_reasons=[],
            semantic_score=semantic_score,
            unsafe_consumptions=unsafe_consumptions,
            total_consumptions=total_consumptions,
            checked_at=now,
        )

    hard_blockers: list[FailureReason] = []
    if payload_sha256(payload) != envelope.payload_hash:
        hard_blockers.append("integrity_mismatch")
    if envelope.payload_type in _SOURCE_LABEL_REQUIRED and not envelope.source_labels:
        hard_blockers.append("missing_provenance")
    if parent_source_labels and not set(parent_source_labels).issubset(
        set(envelope.source_labels)
    ):
        hard_blockers.append("label_loss")
    if parent_authority_scope and not set(envelope.authority_scope).issubset(
        set(parent_authority_scope)
    ):
        hard_blockers.append("authority_expansion")
    if envelope.allowed_recipients and envelope.receiver_id not in envelope.allowed_recipients:
        hard_blockers.append("recipient_violation")
    if now > envelope.expires_at:
        hard_blockers.append("stale_or_replayed")
    if envelope.policy_version not in envelope.receiver_supported_policy_versions:
        hard_blockers.append("policy_mismatch")
    if envelope.delegation_depth > envelope.max_delegation_depth:
        hard_blockers.append("authority_expansion")
    if envelope.verification_error:
        hard_blockers.append("verifier_error")

    review_reasons: list[str] = []
    if envelope.failure_action != "block" and hard_blockers:
        review_reasons.append("failure_action_not_fail_closed")
    if envelope.audit_entry_hash is None:
        review_reasons.append("audit_hash_recommended")

    return _result(
        payload_type=envelope.payload_type,
        hard_blockers=_ordered_unique(hard_blockers),
        review_reasons=review_reasons,
        semantic_score=semantic_score,
        unsafe_consumptions=unsafe_consumptions,
        total_consumptions=total_consumptions,
        checked_at=now,
    )


def format_verification_summary(result: HandoffVerification) -> str:
    """Compact deterministic text for trace observations."""
    reasons = ",".join(result.failure_reasons) if result.failure_reasons else "-"
    reviews = ",".join(result.review_reasons) if result.review_reasons else "-"
    return (
        f"verdict={result.verdict}; failure_reasons={reasons}; "
        f"review_reasons={reviews}; S_structural={result.structural_score:.2f}; "
        f"S_semantic={result.semantic_score:.2f}; S_combined={result.combined_score:.2f}"
    )


def _semantic_score(unsafe_consumptions: int, total_consumptions: int) -> float:
    if total_consumptions <= 0:
        return 0.0
    return max(0.0, min(1.0, unsafe_consumptions / total_consumptions))


def _ordered_unique(reasons: list[FailureReason]) -> list[FailureReason]:
    present = set(reasons)
    return [reason for reason in _HARD_REASON_ORDER if reason in present]


def _result(
    *,
    payload_type: HandoffPayloadType,
    hard_blockers: list[FailureReason],
    review_reasons: list[str],
    semantic_score: float,
    unsafe_consumptions: int,
    total_consumptions: int,
    checked_at: datetime,
) -> HandoffVerification:
    structural_score = 1.0 if hard_blockers else (0.5 if review_reasons else 0.0)
    verdict: HandoffVerdict = (
        "blocked" if hard_blockers else ("needs_review" if review_reasons else "pass")
    )
    multiplier = _PAYLOAD_MULTIPLIERS[payload_type]
    structural_weighted = min(1.0, multiplier * structural_score)
    combined = min(1.0, (0.7 * structural_weighted) + (0.3 * semantic_score))
    return HandoffVerification(
        verdict=verdict,
        failure_reasons=list(hard_blockers),
        hard_blockers=list(hard_blockers),
        review_reasons=review_reasons,
        structural_score=round(structural_score, 4),
        semantic_score=round(semantic_score, 4),
        combined_score=round(combined, 4),
        payload_multiplier=multiplier,
        unsafe_consumptions=unsafe_consumptions,
        total_consumptions=total_consumptions,
        checked_at=checked_at,
    )
