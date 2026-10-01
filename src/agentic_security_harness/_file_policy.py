"""Report-only authority for the explicitly created public-synthetic fixture.

The trusted benchmark owns these classification/authority roots. They are local
policy facts, not remote authentication or portable production credentials.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from agentic_security_harness.runtime_guard_foundation import (
    ActionEnvelope,
    CapabilityGrant,
    ConsentReceipt,
    GuardContext,
    GuardDecision,
    RuntimeDataEnvelope,
    evaluate_action,
)

REPORT_TARGET = "fixture://controlled-file/report"
_POLICY = hashlib.sha256(b"ash-controlled-file-report-only-v1").hexdigest()


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def decide_file_write(
    *, artifact: str, content: bytes, call_id: str, session_id: str, now: datetime
) -> GuardDecision:
    """Bind one proposed effect to report-only authority; never perform an effect."""
    if artifact not in ("report", "protected"):
        raise ValueError("unknown fixture artifact")
    digest = hashlib.sha256(content).hexdigest()
    created, expires = now - timedelta(seconds=1), now + timedelta(seconds=60)
    envelope = RuntimeDataEnvelope(
        data_class="synthetic",
        allowed_recipients=[],
        allowed_purpose=["defensive_research"],
        can_store=True,
        can_forward=False,
        ttl_seconds=60,
        requires_confirmation=False,
        classification_source="owned_public_synthetic_fixture",
        classification_mutable=False,
        classification_receipt_sha256=_sha(f"classification:{session_id}:{call_id}:{digest}"),
        classified_content_sha256=digest,
        classifier_policy_sha256=_POLICY,
        classifier_trust_root_id="fixture-classifier",
        classification_checked_at=created,
        classification_expires_at=expires,
        classification_verification="verified",
    )

    def action(target: str) -> ActionEnvelope:
        return ActionEnvelope(
            action_id=call_id,
            actor_id="fixture-worker",
            session_id_hash=_sha(session_id),
            sponsor_id_hash=_sha("fixture-owner"),
            call_chain_digest=_sha(f"{session_id}:{call_id}"),
            action_type="filesystem_write",
            target=target,
            purpose="defensive_research",
            requested_scopes=("fixture:write",),
            data_envelope=envelope,
            content_sha256=digest,
            policy_sha256=_POLICY,
            created_at=created,
            expires_at=expires,
        )

    granted = action(REPORT_TARGET)
    grant_digest = granted.action_digest()
    capability = CapabilityGrant(
        grant_id=f"grant:{call_id}",
        issuer="fixture-owner",
        subject="fixture-worker",
        scopes=("fixture:write",),
        target_patterns=(REPORT_TARGET,),
        purpose="defensive_research",
        issued_at=created,
        expires_at=expires,
        policy_sha256=_POLICY,
        authority_receipt_sha256=_sha(f"grant:{grant_digest}"),
        authorized_action_digest=grant_digest,
        issuer_trust_root_id="fixture-authority",
        nonce_sha256=_sha(f"grant:{session_id}:{call_id}"),
        verification="verified",
    )
    consent = ConsentReceipt(
        receipt_id=f"consent:{call_id}",
        action_id=call_id,
        actor_id="fixture-worker",
        action_digest=grant_digest,
        policy_sha256=_POLICY,
        receipt_sha256=_sha(f"consent:{grant_digest}"),
        issuer_trust_root_id="fixture-consent",
        nonce_sha256=_sha(f"consent:{session_id}:{call_id}"),
        issued_at=created,
        expires_at=expires,
        approved=True,
        verification="verified",
    )
    context = GuardContext(
        evaluated_at=now,
        policy_version="controlled-file-v1",
        active_policy_sha256=_POLICY,
        capabilities=(capability,),
        consent_receipts=(consent,),
        evidence_previous_hash="0" * 64,
        trusted_authority_root_ids=("fixture-authority",),
        trusted_consent_root_ids=("fixture-consent",),
        trusted_classifier_root_ids=("fixture-classifier",),
        trusted_handoff_root_ids=("unused-handoff",),
        trusted_budget_root_ids=("unused-budget",),
        trusted_tool_registry_root_ids=("unused-tool",),
        trusted_provider_policy_root_ids=("unused-provider",),
        authenticated_classification_bindings=(envelope.classification_binding_digest(),),
    )
    target = REPORT_TARGET if artifact == "report" else "fixture://controlled-file/protected"
    return evaluate_action(action(target), context)
