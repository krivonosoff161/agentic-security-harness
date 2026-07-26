"""Adversarial tests for the Runtime Guard executable specification."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from agentic_security_harness.models import CapabilityToken
from agentic_security_harness.runtime_guard_foundation import (
    GLOBAL_CLOUD_COST_CAP_KOPECKS,
    GLOBAL_CLOUD_REQUEST_CAP,
    ActionEnvelope,
    BudgetReservation,
    CapabilityGrant,
    ConsentReceipt,
    GuardContext,
    GuardDataClass,
    HandoffEvidenceBinding,
    ProviderPolicy,
    ProviderUsage,
    RuntimeDataEnvelope,
    ToolEvidenceBinding,
    capability_grant_from_synthetic_token,
    evaluate_action,
)

NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
HASH = "a" * 64
POLICY_HASH = "c" * 64
ROOT = Path(__file__).resolve().parents[1]


def _data_envelope(
    data_class: GuardDataClass = "synthetic",
    *,
    content_sha256: str = HASH,
) -> RuntimeDataEnvelope:
    return RuntimeDataEnvelope(
        data_class=data_class,
        allowed_recipients=["synthetic-provider"],
        allowed_purpose=["defensive_research"],
        can_store=False,
        can_forward=True,
        ttl_seconds=600,
        classification_source="deterministic-fixture",
        classification_receipt_sha256="a" * 64,
        classified_content_sha256=content_sha256,
        classifier_policy_sha256=POLICY_HASH,
        classifier_trust_root_id="classifier-root",
        classification_checked_at=NOW - timedelta(minutes=1),
        classification_expires_at=NOW + timedelta(minutes=5),
        classification_verification="verified",
    )


def _action(**updates: object) -> ActionEnvelope:
    values: dict[str, object] = {
        "action_id": "action-1",
        "actor_id": "agent-1",
        "session_id_hash": "b" * 64,
        "sponsor_id_hash": "d" * 64,
        "call_chain_digest": "e" * 64,
        "action_type": "read",
        "target": "fixture://public/case-1",
        "purpose": "defensive_research",
        "requested_scopes": ("fixture:read",),
        "data_envelope": _data_envelope(),
        "content_sha256": HASH,
        "policy_sha256": POLICY_HASH,
        "created_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=4),
    }
    values.update(updates)
    return ActionEnvelope.model_validate(values)


def _capability(action: ActionEnvelope, **updates: object) -> CapabilityGrant:
    values: dict[str, object] = {
        "grant_id": "grant-1",
        "issuer": "owner-authority-service",
        "subject": action.actor_id,
        "scopes": action.requested_scopes or ("fixture:read",),
        "target_patterns": (
            "fixture://public/*",
            "provider://*",
            "local-git://repository/main",
        ),
        "purpose": action.purpose,
        "issued_at": NOW - timedelta(minutes=2),
        "expires_at": NOW + timedelta(minutes=10),
        "policy_sha256": POLICY_HASH,
        "authority_receipt_sha256": "1" * 64,
        "authorized_action_digest": action.action_digest(),
        "issuer_trust_root_id": "owner-authority-root",
        "nonce_sha256": "2" * 64,
        "verification": "verified",
    }
    values.update(updates)
    return CapabilityGrant.model_validate(values)


def _consent(action: ActionEnvelope, **updates: object) -> ConsentReceipt:
    values: dict[str, object] = {
        "receipt_id": "consent-1",
        "action_id": action.action_id,
        "actor_id": action.actor_id,
        "action_digest": action.action_digest(),
        "policy_sha256": POLICY_HASH,
        "receipt_sha256": "3" * 64,
        "issuer_trust_root_id": "owner-consent-root",
        "nonce_sha256": "4" * 64,
        "issued_at": NOW - timedelta(seconds=30),
        "expires_at": NOW + timedelta(minutes=2),
        "approved": True,
        "verification": "verified",
    }
    values.update(updates)
    return ConsentReceipt.model_validate(values)


def _provider(**updates: object) -> ProviderPolicy:
    values: dict[str, object] = {
        "provider_id": "synthetic-provider",
        "invocation_route_id_hash": "b" * 64,
        "destination_id_hash": "f" * 64,
        "model_id_hash": "d" * 64,
        "target_sha256": hashlib.sha256(
            b"provider://synthetic-provider/model"
        ).hexdigest(),
        "terms_url": "https://provider.invalid/terms",
        "terms_sha256": "5" * 64,
        "acceptable_use_url": "https://provider.invalid/aup",
        "acceptable_use_sha256": "6" * 64,
        "privacy_policy_url": "https://provider.invalid/privacy",
        "privacy_policy_sha256": "7" * 64,
        "terms_reviewed_at": NOW - timedelta(days=1),
        "terms_review_expires_at": NOW + timedelta(days=29),
        "model_license_id": "LicenseRef-Synthetic-Test",
        "model_license_url": "https://provider.invalid/model-license",
        "model_license_sha256": "8" * 64,
        "model_license_status": "reviewed",
        "input_rights_status": "synthetic_owned",
        "permitted_purposes": ("defensive_research",),
        "retention_class": "no_storage",
        "data_logging_mode": "disabled",
        "training_use": "disabled",
        "output_use_policy": "internal_research_only",
        "publication_status": "aggregates_allowed",
        "automated_api_use_allowed": True,
        "benchmark_use_status": "allowed",
        "security_research_status": "eligible_for_bounded_review",
        "region": "declared-region",
        "policy_sha256": POLICY_HASH,
        "issuer_trust_root_id": "provider-policy-root",
        "verification": "verified",
    }
    values.update(updates)
    return ProviderPolicy.model_validate(values)


def _context(
    action: ActionEnvelope,
    *,
    capability: CapabilityGrant | None = None,
    consent: ConsentReceipt | None = None,
    provider: ProviderPolicy | None = None,
    reserve_budget: bool = True,
    requests_used: int = 0,
    cost_used: int = 0,
    verifier_available: bool = True,
    seen_action_digests: tuple[str, ...] = (),
) -> GuardContext:
    reservations: tuple[BudgetReservation, ...] = ()
    usages: tuple[ProviderUsage, ...] = ()
    if provider is not None and action.provider_id is not None:
        usages = (ProviderUsage(provider_id=action.provider_id),)
        if reserve_budget:
            reservations = (
                BudgetReservation(
                    reservation_id="reservation-1",
                    action_digest=action.action_digest(),
                    provider_id=action.provider_id,
                    requests=action.reserved_cloud_requests,
                    max_cost_kopecks=action.max_cost_kopecks,
                    issued_at=NOW - timedelta(seconds=10),
                    expires_at=NOW + timedelta(minutes=1),
                    reservation_receipt_sha256="9" * 64,
                    pricing_quote_sha256="0" * 64,
                    pricing_quote_issued_at=NOW - timedelta(minutes=1),
                    pricing_quote_expires_at=NOW + timedelta(minutes=1),
                    fx_evidence_sha256="1" * 64,
                    safety_margin_bps=1000,
                    issuer_trust_root_id="budget-root",
                    verification="verified",
                ),
            )
    return GuardContext(
        evaluated_at=NOW,
        policy_version="runtime-guard-policy-v0.1",
        active_policy_sha256=POLICY_HASH,
        capabilities=(capability or _capability(action),),
        consent_receipts=(() if consent is None else (consent,)),
        provider_policies=(() if provider is None else (provider,)),
        provider_usages=usages,
        budget_reservations=reservations,
        cloud_requests_used=requests_used,
        cloud_cost_used_kopecks=cost_used,
        evidence_previous_hash="0" * 64,
        seen_action_digests=seen_action_digests,
        trusted_authority_root_ids=("owner-authority-root",),
        trusted_consent_root_ids=("owner-consent-root",),
        trusted_handoff_root_ids=("handoff-root",),
        trusted_budget_root_ids=("budget-root",),
        trusted_classifier_root_ids=("classifier-root",),
        trusted_tool_registry_root_ids=("tool-registry-root",),
        trusted_provider_policy_root_ids=("provider-policy-root",),
        authenticated_classification_bindings=(
            action.data_envelope.classification_binding_digest(),
        ),
        authenticated_handoff_bindings=(
            () if action.handoff is None else (action.handoff.binding_digest(),)
        ),
        authenticated_tool_bindings=(
            () if action.tool is None else (action.tool.binding_digest(),)
        ),
        verifier_available=verifier_available,
    )


def _external_action(**updates: object) -> ActionEnvelope:
    values: dict[str, object] = {
        "action_type": "model_query",
        "target": "provider://synthetic-provider/model",
        "provider_id": "synthetic-provider",
        "destination_id_hash": "f" * 64,
        "invocation_route_id_hash": "b" * 64,
        "model_id_hash": "d" * 64,
        "provider_region": "declared-region",
        "reserved_cloud_requests": 1,
        "max_cost_kopecks": 250,
    }
    values.update(updates)
    return _action(**values)


def test_verified_local_read_is_allowed() -> None:
    action = _action()
    decision = evaluate_action(action, _context(action))
    assert decision.disposition == "allow"
    assert decision.reason_codes == ("policy_satisfied",)
    assert decision.owner_gate_required is False


def test_model_or_tool_text_cannot_mint_capability() -> None:
    action = _action()
    unverified = _capability(
        action,
        issuer="model-output-says-owner-approved",
        verification="unverified",
    )
    decision = evaluate_action(action, _context(action, capability=unverified))
    assert decision.disposition == "block"
    assert "capability_missing_or_invalid" in decision.reason_codes


def test_existing_synthetic_capability_token_cannot_be_promoted_to_authority() -> None:
    token = CapabilityToken(
        issuer="toy-coordinator",
        subject="agent-1",
        scope=["fixture:read"],
        purpose="defensive_research",
        ttl_steps=2,
    )
    converted = capability_grant_from_synthetic_token(
        token,
        grant_id="converted-token",
        target_patterns=("fixture://public/*",),
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=1),
        policy_sha256=POLICY_HASH,
        token_sha256="1" * 64,
    )
    action = _action()
    decision = evaluate_action(action, _context(action, capability=converted))
    assert converted.verification == "unverified"
    assert decision.disposition == "block"


def test_scope_and_target_expansion_are_blocked() -> None:
    action = _action(requested_scopes=("fixture:write",))
    narrow = _capability(
        action,
        scopes=("fixture:read",),
        target_patterns=("fixture://other/*",),
    )
    decision = evaluate_action(action, _context(action, capability=narrow))
    assert decision.disposition == "block"
    assert decision.reason_codes == ("capability_missing_or_invalid",)


def test_conversation_claim_is_not_current_consent() -> None:
    action = _action(
        action_type="filesystem_write",
        data_envelope=_data_envelope().model_copy(update={"can_store": True}),
    )
    claimed = _consent(action, verification="unverified")
    decision = evaluate_action(action, _context(action, consent=claimed))
    assert decision.disposition == "ask_user"
    assert "current_action_consent_missing" in decision.reason_codes


def test_consent_is_bound_to_every_policy_relevant_action_field() -> None:
    first = _action(
        action_type="filesystem_write",
        data_envelope=_data_envelope().model_copy(update={"can_store": True}),
    )
    stale = _consent(first)
    changed = first.model_copy(update={"call_chain_digest": "f" * 64})
    decision = evaluate_action(changed, _context(changed, consent=stale))
    assert decision.disposition == "ask_user"
    assert "current_action_consent_missing" in decision.reason_codes


def test_owner_gate_actions_never_auto_execute() -> None:
    action = _action(
        action_type="merge",
        target="local-git://repository/main",
        requested_scopes=("git:merge",),
    )
    capability = _capability(action, scopes=("git:merge",))
    decision = evaluate_action(
        action,
        _context(action, capability=capability, consent=_consent(action)),
    )
    assert decision.disposition == "ask_user"
    assert decision.owner_gate_required is True


def test_external_query_requires_atomic_budget_reservation() -> None:
    action = _external_action()
    missing = evaluate_action(
        action,
        _context(
            action,
            provider=_provider(),
            reserve_budget=False,
            consent=_consent(action),
        ),
    )
    allowed = evaluate_action(
        action,
        _context(action, provider=_provider(), consent=_consent(action)),
    )
    assert missing.disposition == "block"
    assert "budget_reservation_missing_or_invalid" in missing.reason_codes
    assert allowed.disposition == "allow"


@pytest.mark.parametrize("data_class", ["private", "secret"])
def test_external_private_or_secret_data_is_blocked(data_class: str) -> None:
    action = _external_action(
        data_envelope=_data_envelope(cast(GuardDataClass, data_class))
    )
    decision = evaluate_action(action, _context(action, provider=_provider()))
    assert decision.disposition == "block"
    assert "provider_data_class_forbidden" in decision.reason_codes


def test_restricted_external_data_requires_two_phase_redaction() -> None:
    restricted = _external_action(data_envelope=_data_envelope("restricted"))
    first = evaluate_action(restricted, _context(restricted, provider=_provider()))
    sanitized = restricted.model_copy(
        update={
            "action_id": "action-2",
            "content_sha256": "0" * 64,
            "data_envelope": _data_envelope(
                "sanitized",
                content_sha256="0" * 64,
            ),
        }
    )
    second = evaluate_action(
        sanitized,
        _context(sanitized, provider=_provider(), consent=_consent(sanitized)),
    )
    assert first.disposition == "redact"
    assert "provider_redaction_required" in first.reason_codes
    assert second.disposition == "allow"
    assert sanitized.content_sha256 != restricted.content_sha256


def test_missing_stale_or_held_provider_policy_fails_closed() -> None:
    action = _external_action()
    stale = _provider(terms_review_expires_at=NOW - timedelta(seconds=1))
    held = _provider(security_research_status="hold")
    missing_decision = evaluate_action(action, _context(action))
    stale_decision = evaluate_action(action, _context(action, provider=stale))
    held_decision = evaluate_action(action, _context(action, provider=held))
    assert "provider_policy_missing_or_unverified" in missing_decision.reason_codes
    assert "provider_terms_review_stale" in stale_decision.reason_codes
    assert "provider_research_on_hold" in held_decision.reason_codes


def test_global_request_and_cost_budgets_fail_closed() -> None:
    action = _external_action(max_cost_kopecks=1)
    decision = evaluate_action(
        action,
        _context(
            action,
            provider=_provider(),
            requests_used=GLOBAL_CLOUD_REQUEST_CAP,
            cost_used=GLOBAL_CLOUD_COST_CAP_KOPECKS,
        ),
    )
    assert decision.disposition == "block"
    assert "global_request_budget_exceeded" in decision.reason_codes
    assert "global_cost_budget_exceeded" in decision.reason_codes


def test_provider_usage_is_not_confused_with_global_usage() -> None:
    action = _external_action()
    context = _context(
        action,
        provider=_provider(request_cap=2),
        consent=_consent(action),
    )
    context = context.model_copy(
        update={
            "cloud_requests_used": 199,
            "provider_usages": (
                ProviderUsage(provider_id="synthetic-provider", requests_used=0),
            ),
        }
    )
    decision = evaluate_action(action, context)
    assert "provider_request_budget_exceeded" not in decision.reason_codes
    assert decision.disposition == "allow"


def test_model_query_requires_current_action_consent() -> None:
    action = _external_action()
    decision = evaluate_action(action, _context(action, provider=_provider()))
    assert decision.disposition == "ask_user"
    assert "current_action_consent_missing" in decision.reason_codes


def test_unverified_handoff_and_replay_fail_closed() -> None:
    handoff = HandoffEvidenceBinding(
        envelope_sha256="1" * 64,
        verification_sha256="2" * 64,
        payload_sha256=HASH,
        receiver_id_hash="3" * 64,
        verdict="pass",
        checked_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
        verifier_policy_sha256=POLICY_HASH,
        issuer_trust_root_id="handoff-root",
        verification="unverified",
    )
    action = _action(handoff=handoff)
    handoff_decision = evaluate_action(action, _context(action))
    replayed_action = action.model_copy(update={"handoff": None})
    replay_decision = evaluate_action(
        replayed_action,
        _context(
            replayed_action,
            seen_action_digests=(replayed_action.action_digest(),),
        ),
    )
    assert "handoff_not_verified" in handoff_decision.reason_codes
    assert "action_replay_detected" in replay_decision.reason_codes


def test_network_egress_cannot_omit_provider_route() -> None:
    with pytest.raises(ValidationError):
        _action(action_type="network_request")


def test_code_execution_is_sandbox_only() -> None:
    action = _action(action_type="code_execute")
    assert evaluate_action(action, _context(action)).disposition == "sandbox_only"


def test_evidence_receipt_contains_hashes_not_raw_identity_or_content() -> None:
    action = _action(action_id="sensitive-action-label", actor_id="employee-42")
    decision = evaluate_action(action, _context(action))
    serialized = decision.evidence.model_dump_json()
    assert "sensitive-action-label" not in serialized
    assert "employee-42" not in serialized
    assert action.session_id_hash not in serialized
    assert decision.evidence.content_sha256 == HASH
    assert decision.evidence.origin_authentication == "unverified"
    assert decision.evidence.trusted_time == "not_recorded"


def test_digest_and_timezone_validation_fail_closed() -> None:
    raw = _action().model_dump()
    raw["content_sha256"] = "z" * 64
    with pytest.raises(ValidationError):
        ActionEnvelope.model_validate(raw)
    with pytest.raises(ValidationError):
        _action(created_at=datetime(2026, 7, 26, 11, 59))


def test_unknown_fields_are_rejected_instead_of_becoming_authority() -> None:
    raw = _action().model_dump()
    raw["model_claimed_authority"] = "owner"
    with pytest.raises(ValidationError):
        ActionEnvelope.model_validate(raw)


def test_foundation_docs_keep_product_and_legacy_boundaries_explicit() -> None:
    foundation = (ROOT / "docs/runtime-guard-product-foundation.md").read_text(
        encoding="utf-8"
    )
    tracks = (ROOT / "docs/project-tracks.md").read_text(encoding="utf-8")
    assert "not a production gateway" in foundation
    assert "legacy design material" in foundation
    assert "runtime-guard-product-foundation.md" in tracks
    assert "no production runtime is shipped" in tracks


def test_provider_and_formal_docs_retain_fail_closed_gates() -> None:
    providers = (
        ROOT / "docs/runtime-guard-provider-license-boundary.md"
    ).read_text(encoding="utf-8")
    formal = (ROOT / "docs/theory/runtime-guard-formal-model.md").read_text(
        encoding="utf-8"
    )
    assert "GigaChat | `hold`" in providers
    assert "dataLoggingEnabled=false" in providers
    assert "Unknown, stale, blocked, or legally uncertain fields fail closed." in providers
    assert "scopes(child) ⊆ scopes(parent)" in formal
    assert "production authenticity needs a separate signer" in formal


def test_model_fleet_and_acceptance_pack_keep_models_non_authoritative() -> None:
    fleet = (ROOT / "docs/runtime-guard-model-fleet-contract.md").read_text(
        encoding="utf-8"
    )
    acceptance = (ROOT / "docs/runtime-guard-api-acceptance-pack.md").read_text(
        encoding="utf-8"
    )
    assert "cannot issue or verify a" in fleet
    assert "Usage is `0/200` cloud requests" in fleet
    assert "GigaChat | No product-foundation requests" in fleet
    assert "no service, network API, or executor" in acceptance
    assert "complete mediation" in acceptance
    assert "model-issued authority or consensus-as-proof" in acceptance


def test_empty_scope_request_is_rejected_at_schema_boundary() -> None:
    with pytest.raises(ValidationError):
        _action(requested_scopes=())


def test_sanitized_label_without_trusted_classification_is_blocked() -> None:
    envelope = _data_envelope("sanitized").model_copy(
        update={"classification_verification": "unverified"}
    )
    action = _external_action(data_envelope=envelope)
    decision = evaluate_action(action, _context(action, provider=_provider()))
    assert "data_classification_unverified" in decision.reason_codes
    assert decision.disposition == "block"


def test_storage_effect_obeys_can_store() -> None:
    action = _action(action_type="filesystem_write")
    decision = evaluate_action(
        action,
        _context(action, consent=_consent(action)),
    )
    assert "data_storage_forbidden" in decision.reason_codes
    assert decision.disposition == "block"


def test_external_recipient_must_be_explicit() -> None:
    envelope = _data_envelope().model_copy(update={"allowed_recipients": []})
    action = _external_action(data_envelope=envelope)
    decision = evaluate_action(action, _context(action, provider=_provider()))
    assert "data_recipient_forbidden" in decision.reason_codes


def test_untrusted_authority_root_cannot_mint_capability() -> None:
    action = _action()
    forged = _capability(action, issuer_trust_root_id="attacker-root")
    decision = evaluate_action(action, _context(action, capability=forged))
    assert "capability_missing_or_invalid" in decision.reason_codes


def test_duplicate_grant_ids_and_nonces_are_rejected() -> None:
    action = _action()
    grant = _capability(action)
    raw = _context(action).model_dump()
    raw["capabilities"] = [grant.model_dump(), grant.model_dump()]
    with pytest.raises(ValidationError):
        GuardContext.model_validate(raw)


def test_all_active_reservations_count_toward_global_budget() -> None:
    action = _external_action(reserved_cloud_requests=1, max_cost_kopecks=1)
    context = _context(action, provider=_provider())
    unrelated = BudgetReservation(
        reservation_id="reservation-other",
        action_digest="4" * 64,
        provider_id="other-provider",
        requests=GLOBAL_CLOUD_REQUEST_CAP,
        max_cost_kopecks=GLOBAL_CLOUD_COST_CAP_KOPECKS,
        issued_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=1),
        reservation_receipt_sha256="5" * 64,
        pricing_quote_sha256="6" * 64,
        pricing_quote_issued_at=NOW - timedelta(minutes=1),
        pricing_quote_expires_at=NOW + timedelta(minutes=1),
        fx_evidence_sha256="7" * 64,
        safety_margin_bps=1000,
        issuer_trust_root_id="budget-root",
        verification="verified",
    )
    context = context.model_copy(
        update={"budget_reservations": (*context.budget_reservations, unrelated)}
    )
    decision = evaluate_action(action, context)
    assert "global_request_budget_exceeded" in decision.reason_codes
    assert "global_cost_budget_exceeded" in decision.reason_codes


def test_tool_declared_effect_is_bound_to_consent_and_policy() -> None:
    tool = ToolEvidenceBinding(
        tool_id_hash="1" * 64,
        schema_sha256="2" * 64,
        registry_sha256="3" * 64,
        declared_effect="filesystem_write",
        policy_sha256=POLICY_HASH,
        issuer_trust_root_id="tool-registry-root",
        verification="verified",
    )
    action = _action(
        action_type="tool_call",
        effect_type="filesystem_write",
        tool=tool,
    )
    decision = evaluate_action(action, _context(action, consent=_consent(action)))
    assert decision.disposition == "block"
    assert "data_storage_forbidden" in decision.reason_codes


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"retention_class": "unknown"}, "provider_retention_unknown"),
        ({"training_use": "allowed"}, "provider_training_use_unacceptable"),
        ({"output_use_policy": "blocked"}, "provider_output_use_unacceptable"),
        (
            {"publication_status": "blocked"},
            "provider_publication_status_unacceptable",
        ),
        (
            {"publication_status": "provider_clearance_required"},
            "provider_publication_status_unacceptable",
        ),
        ({"model_license_status": "uncertain"}, "provider_model_license_unreviewed"),
        ({"input_rights_status": "uncertain"}, "provider_input_rights_unverified"),
    ],
)
def test_provider_legal_uncertainty_fails_closed(
    updates: dict[str, object],
    reason: str,
) -> None:
    action = _external_action()
    decision = evaluate_action(action, _context(action, provider=_provider(**updates)))
    assert decision.disposition == "block"
    assert reason in decision.reason_codes


@pytest.mark.parametrize(
    "target",
    [
        "HTTP://provider.invalid/model",
        "https://Provider.invalid/model",
        "https://provider.invalid/a/../model",
        "https://provider.invalid/a%2fmodel",
        "https://provider.invalid/a//model",
        "https://user@provider.invalid/model",
        "https://provider.invalid/model#fragment",
        "https://provider.invalid:443/model",
        "https://provider.invalid./model",
        "https://provider.invalid/model?variant=a",
    ],
)
def test_ambiguous_targets_are_rejected(target: str) -> None:
    with pytest.raises(ValidationError):
        _external_action(target=target)


def test_future_handoff_verification_is_rejected() -> None:
    handoff = HandoffEvidenceBinding(
        envelope_sha256="1" * 64,
        verification_sha256="2" * 64,
        payload_sha256=HASH,
        receiver_id_hash="3" * 64,
        verdict="pass",
        checked_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=1),
        verifier_policy_sha256=POLICY_HASH,
        issuer_trust_root_id="handoff-root",
        verification="verified",
    )
    action = _action(handoff=handoff)
    decision = evaluate_action(action, _context(action))
    assert "handoff_not_verified" in decision.reason_codes


def test_context_digest_binds_authority_and_usage_records() -> None:
    action = _external_action()
    baseline = evaluate_action(action, _context(action, provider=_provider()))
    changed_context = _context(action, provider=_provider())
    changed_context = changed_context.model_copy(
        update={
            "provider_usages": (
                ProviderUsage(
                    provider_id="synthetic-provider",
                    requests_used=1,
                    cost_used_kopecks=1,
                ),
            )
        }
    )
    changed = evaluate_action(action, changed_context)
    assert baseline.evidence.context_digest != changed.evidence.context_digest


@pytest.mark.parametrize(
    ("action_type", "effect_type"),
    [
        ("merge", "read"),
        ("filesystem_write", "read"),
        ("external_send", "read"),
    ],
)
def test_non_tool_actions_cannot_downgrade_their_effect(
    action_type: str,
    effect_type: str,
) -> None:
    with pytest.raises(ValidationError):
        _action(action_type=action_type, effect_type=effect_type)


def test_tool_wrapped_egress_cannot_omit_exact_route() -> None:
    tool = ToolEvidenceBinding(
        tool_id_hash="1" * 64,
        schema_sha256="2" * 64,
        registry_sha256="3" * 64,
        declared_effect="network_request",
        policy_sha256=POLICY_HASH,
        issuer_trust_root_id="tool-registry-root",
        verification="verified",
    )
    with pytest.raises(ValidationError):
        _action(
            action_type="tool_call",
            effect_type="network_request",
            target="https://provider.invalid/model",
            tool=tool,
        )


@pytest.mark.parametrize(
    "updates",
    [
        {"invocation_route_id_hash": "e" * 64},
        {"destination_id_hash": "e" * 64},
        {"model_id_hash": "e" * 64},
        {"target_sha256": "e" * 64},
        {"region": "other-region"},
    ],
)
def test_provider_policy_is_bound_to_route_destination_model_target_and_region(
    updates: dict[str, object],
) -> None:
    action = _external_action()
    mismatched = _provider(**updates)
    decision = evaluate_action(action, _context(action, provider=mismatched))
    assert decision.disposition == "block"
    assert "provider_route_or_model_mismatch" in decision.reason_codes


def test_verified_strings_without_authenticated_context_record_fail_closed() -> None:
    baseline = _action()
    context = _context(baseline)
    envelope = _data_envelope().model_copy(
        update={"classification_receipt_sha256": "e" * 64}
    )
    action = baseline.model_copy(update={"data_envelope": envelope})
    decision = evaluate_action(action, context)
    assert decision.disposition == "block"
    assert "data_classification_unverified" in decision.reason_codes


def test_classification_receipt_cannot_be_reused_for_other_content() -> None:
    baseline = _action()
    context = _context(baseline)
    changed_envelope = baseline.data_envelope.model_copy(
        update={"classified_content_sha256": "e" * 64}
    )
    action = baseline.model_copy(
        update={
            "content_sha256": "e" * 64,
            "data_envelope": changed_envelope,
        }
    )
    decision = evaluate_action(action, context)
    assert decision.disposition == "block"
    assert "data_classification_unverified" in decision.reason_codes


def test_authenticated_handoff_digest_cannot_be_reused_after_field_change() -> None:
    handoff = HandoffEvidenceBinding(
        envelope_sha256="1" * 64,
        verification_sha256="2" * 64,
        payload_sha256=HASH,
        receiver_id_hash=hashlib.sha256(b"agent-1").hexdigest(),
        verdict="pass",
        checked_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=1),
        verifier_policy_sha256=POLICY_HASH,
        issuer_trust_root_id="handoff-root",
        verification="verified",
    )
    baseline = _action(handoff=handoff)
    context = _context(baseline)
    forged = baseline.model_copy(
        update={"handoff": handoff.model_copy(update={"payload_sha256": "e" * 64})}
    )
    decision = evaluate_action(forged, context)
    assert "handoff_not_verified" in decision.reason_codes


def test_authenticated_tool_digest_cannot_be_reused_after_effect_change() -> None:
    tool = ToolEvidenceBinding(
        tool_id_hash="1" * 64,
        schema_sha256="2" * 64,
        registry_sha256="3" * 64,
        declared_effect="filesystem_write",
        policy_sha256=POLICY_HASH,
        issuer_trust_root_id="tool-registry-root",
        verification="verified",
    )
    baseline = _action(
        action_type="tool_call",
        effect_type="filesystem_write",
        tool=tool,
        data_envelope=_data_envelope().model_copy(update={"can_store": True}),
    )
    context = _context(baseline, consent=_consent(baseline))
    forged_tool = tool.model_copy(update={"declared_effect": "git_write"})
    forged = baseline.model_copy(
        update={"effect_type": "git_write", "tool": forged_tool}
    )
    decision = evaluate_action(forged, context)
    assert "tool_not_verified" in decision.reason_codes


def test_capability_is_bound_to_one_exact_action_and_delegation_depth() -> None:
    first = _action()
    grant = _capability(first)
    second = _action(action_id="action-2")
    reused = evaluate_action(second, _context(second, capability=grant))
    delegated = _action(
        action_id="action-3",
        call_chain_depth=1,
        handoff=HandoffEvidenceBinding(
            envelope_sha256="1" * 64,
            verification_sha256="2" * 64,
            payload_sha256=HASH,
            receiver_id_hash=hashlib.sha256(b"agent-1").hexdigest(),
            verdict="pass",
            checked_at=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(minutes=1),
            verifier_policy_sha256=POLICY_HASH,
            issuer_trust_root_id="handoff-root",
            verification="verified",
        ),
    )
    wrong_depth = evaluate_action(
        delegated,
        _context(delegated, capability=_capability(delegated, delegation_depth=0)),
    )
    assert "capability_missing_or_invalid" in reused.reason_codes
    assert "capability_missing_or_invalid" in wrong_depth.reason_codes


def test_missing_provider_usage_record_fails_closed() -> None:
    action = _external_action()
    context = _context(action, provider=_provider()).model_copy(
        update={"provider_usages": ()}
    )
    decision = evaluate_action(action, context)
    assert decision.disposition == "block"
    assert "provider_usage_missing" in decision.reason_codes


def test_stale_pricing_quote_invalidates_budget_reservation() -> None:
    action = _external_action()
    context = _context(action, provider=_provider())
    reservation = context.budget_reservations[0].model_copy(
        update={"pricing_quote_expires_at": NOW - timedelta(seconds=1)}
    )
    context = context.model_copy(update={"budget_reservations": (reservation,)})
    decision = evaluate_action(action, context)
    assert decision.disposition == "block"
    assert "budget_reservation_missing_or_invalid" in decision.reason_codes


@pytest.mark.parametrize(
    "target",
    [
        "https://outside.invalid/data",
        "provider://outside/model",
        "wss://outside.invalid/socket",
        "sftp://outside.invalid/file",
    ],
)
def test_external_target_cannot_be_mislabeled_as_local_read(target: str) -> None:
    with pytest.raises(ValidationError):
        _action(action_type="read", target=target)


@pytest.mark.parametrize("target", ["https:///model", "provider:///model"])
def test_external_target_requires_nonempty_authority(target: str) -> None:
    with pytest.raises(ValidationError):
        _external_action(target=target)


@pytest.mark.parametrize("target", ["custom://outside/data", "s3://bucket/object"])
def test_unknown_target_scheme_fails_closed(target: str) -> None:
    with pytest.raises(ValidationError):
        _action(target=target)


def test_egress_effect_cannot_use_local_target_scheme() -> None:
    with pytest.raises(ValidationError):
        _external_action(target="fixture://public/case-1")


@pytest.mark.parametrize(
    "target",
    [
        "file://outside.invalid/share",
        "git://outside.invalid/repository",
        "local-git://outside.invalid/repository",
    ],
)
def test_network_capable_or_noncanonical_local_authority_is_not_local(
    target: str,
) -> None:
    with pytest.raises(ValidationError):
        _action(action_type="read", target=target)


def test_classification_source_and_mutability_are_in_trusted_binding() -> None:
    baseline = _action()
    context = _context(baseline)
    forged_envelope = baseline.data_envelope.model_copy(
        update={
            "classification_source": "attacker-asserted",
            "classification_mutable": True,
        }
    )
    forged = baseline.model_copy(update={"data_envelope": forged_envelope})
    context = context.model_copy(update={"capabilities": (_capability(forged),)})
    decision = evaluate_action(forged, context)
    assert decision.disposition == "block"
    assert "data_classification_unverified" in decision.reason_codes
