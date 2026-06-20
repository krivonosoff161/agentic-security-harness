"""Deterministic DataEnvelope restriction checks.

The relation implemented here is the local synthetic model used by the corpus:
``candidate <= baseline`` means the candidate envelope is equal to or more restrictive
than the baseline envelope. This is a policy-label comparison, not encryption and not a
semantic truthfulness proof.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentic_security_harness.models import DataEnvelope

CLASSIFICATION_RANK = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}

SOURCE_RANK = {
    "unknown": 0,
    "untrusted": 0,
    "untrusted_source": 0,
    "tool_output": 0,
    "user": 1,
    "trusted_policy": 2,
    "trusted_source": 2,
    "policy_engine": 3,
}


@dataclass(frozen=True)
class EnvelopeCheck:
    """Result of a deterministic envelope restriction check."""

    ok: bool
    violations: tuple[str, ...] = ()


def _ranked_non_decrease(
    candidate: str,
    baseline: str,
    ranks: dict[str, int],
    *,
    field: str,
) -> str | None:
    """Return a violation code if candidate weakens baseline under a rank table.

    Unknown labels are not guessed. They must stay byte-identical unless the caller
    extends the policy table.
    """

    left = str(candidate)
    right = str(baseline)
    if left not in ranks or right not in ranks:
        return None if left == right else f"{field}_policy_unknown_or_changed"
    if ranks[left] < ranks[right]:
        return f"{field}_downgraded"
    return None


def envelope_violations(
    candidate: DataEnvelope | None,
    baseline: DataEnvelope | None,
) -> tuple[str, ...]:
    """Return violation codes for ``candidate <= baseline``.

    ``None`` is never an acceptable candidate when a baseline envelope exists: a read or
    downstream use without an envelope is a label-loss failure.
    """

    if baseline is None:
        return () if candidate is None else ("unexpected_envelope_without_baseline",)
    if candidate is None:
        return ("missing_envelope",)

    violations: list[str] = []

    baseline_recipients = set(baseline.allowed_recipients)
    candidate_recipients = set(candidate.allowed_recipients)
    if not candidate_recipients.issubset(baseline_recipients):
        violations.append("allowed_recipients_expanded")

    baseline_purpose = set(baseline.allowed_purpose)
    candidate_purpose = set(candidate.allowed_purpose)
    if not candidate_purpose.issubset(baseline_purpose):
        violations.append("allowed_purpose_expanded")

    class_violation = _ranked_non_decrease(
        candidate.data_class,
        baseline.data_class,
        CLASSIFICATION_RANK,
        field="data_class",
    )
    if class_violation:
        violations.append(class_violation)

    if baseline.can_store is False and candidate.can_store is True:
        violations.append("can_store_weakened")
    if baseline.can_forward is False and candidate.can_forward is True:
        violations.append("can_forward_weakened")

    if baseline.ttl_seconds is not None:
        if candidate.ttl_seconds is None:
            violations.append("ttl_removed")
        elif candidate.ttl_seconds > baseline.ttl_seconds:
            violations.append("ttl_expanded")

    if baseline.requires_confirmation is True and candidate.requires_confirmation is False:
        violations.append("requires_confirmation_removed")

    source_violation = _ranked_non_decrease(
        candidate.classification_source,
        baseline.classification_source,
        SOURCE_RANK,
        field="classification_source",
    )
    if source_violation:
        violations.append(source_violation)

    if baseline.classification_mutable is False and candidate.classification_mutable is True:
        violations.append("classification_mutable_weakened")

    return tuple(violations)


def is_envelope_restriction(candidate: DataEnvelope | None, baseline: DataEnvelope | None) -> bool:
    """Return True when ``candidate`` is equal to or more restrictive than ``baseline``."""

    return not envelope_violations(candidate, baseline)


def validate_memory_read_envelope(
    *,
    write_envelope: DataEnvelope | None,
    stored_envelope: DataEnvelope | None,
    read_envelope: DataEnvelope | None,
    elapsed_seconds: int | None = None,
) -> EnvelopeCheck:
    """Validate envelope preservation across write -> stored record -> read.

    TTL is measured from the write event. A read cannot restart the TTL clock.
    """

    violations: list[str] = []
    violations.extend(f"stored:{v}" for v in envelope_violations(stored_envelope, write_envelope))
    violations.extend(f"read:{v}" for v in envelope_violations(read_envelope, stored_envelope))

    if (
        write_envelope is not None
        and write_envelope.ttl_seconds is not None
        and elapsed_seconds is not None
        and elapsed_seconds > write_envelope.ttl_seconds
    ):
        violations.append("read:ttl_expired_from_write_time")

    return EnvelopeCheck(ok=not violations, violations=tuple(violations))
