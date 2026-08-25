from __future__ import annotations

import hashlib
import importlib
import socket
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agentic_security_harness.extension_sdk import (
    ExtensionContractError,
    ExtensionManifestV1,
    ExtensionObservationEnvelopeV1,
    build_extension_envelope_v1,
    run_extension_v1,
)
from agentic_security_harness.portfolio_contract import (
    CanonicalObservationEventV1,
    encode_portfolio_observation_v1,
)
from agentic_security_harness.security_intelligence import (
    SecurityClaimClass,
    SecurityIntelligenceBundleV1,
    SecurityIntelligenceContractError,
    SecurityIntelligenceEvidenceV1,
    SecurityIntelligenceReviewExtensionV1,
    SecurityIntelligenceSourceRegistryV1,
    SecurityIntelligenceSourceV1,
    SecurityIntelligenceSynthesisProfileV1,
    SecuritySourceKind,
    build_security_intelligence_bundle_v1,
    build_security_intelligence_evidence_v1,
    build_security_intelligence_source_registry_v1,
    build_security_intelligence_synthesis_profile_v1,
    security_intelligence_source_registry_sha256,
    security_intelligence_v1_json_schemas,
)

WINDOW_START = datetime(2026, 8, 17, tzinfo=UTC)
WINDOW_END = datetime(2026, 8, 24, tzinfo=UTC)
OBSERVED = WINDOW_END
PUBLISHED = WINDOW_START + timedelta(days=2)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64
REPOSITORY_SHA = "1" * 40


def _source(
    source_id: str,
    origin: str,
    *,
    source_kind: SecuritySourceKind = "vendor_advisory",
) -> SecurityIntelligenceSourceV1:
    return SecurityIntelligenceSourceV1.model_validate(
        {
            "source_id": source_id,
            "source_kind": source_kind,
            "canonical_https_origin": origin,
            "topics": ("agentic_ai", "llm_security"),
            "collection_mode": "offline_snapshot_only",
            "metadata_policy": "public_metadata_and_digests_only",
            "credentials_required": False,
            "operational_authority": "none",
        }
    )


def _registry() -> SecurityIntelligenceSourceRegistryV1:
    return build_security_intelligence_source_registry_v1(
        (
            _source("openai-security", "https://openai.com"),
            _source(
                "owasp-genai",
                "https://owasp.org",
                source_kind="standards_body",
            ),
        )
    )


def _event(
    event_id: str, data_digest: str, *, second: int = 0
) -> CanonicalObservationEventV1:
    return CanonicalObservationEventV1.model_validate(
        {
            "schema_version": "portfolio-observation-v1.0",
            "event_id": event_id,
            "project_id": "agentic-security-harness",
            "repository_id": "example/public-security-watch",
            "repository_sha": REPOSITORY_SHA,
            "occurred_at": OBSERVED + timedelta(seconds=second),
            "producer_id_hash": SHA_B,
            "producer_attestation": "unattested",
            "source_surface": "document",
            "activity": "security_intelligence.publication_observed",
            "entity_refs": (),
            "parent_event_ids": (),
            "data_envelope_ref": data_digest,
            "authority_envelope_ref": None,
            "telemetry_state": "unattested",
            "operational_authority": "none",
        }
    )


def _collected_evidence(
    registry: SecurityIntelligenceSourceRegistryV1,
    event: CanonicalObservationEventV1,
    source_id: str,
    **updates: object,
) -> SecurityIntelligenceEvidenceV1:
    values: dict[str, object] = {
        "event_id": event.event_id,
        "source_observation_sha256": hashlib.sha256(
            encode_portfolio_observation_v1(event)
        ).hexdigest(),
        "registry_sha256": security_intelligence_source_registry_sha256(registry),
        "source_id": source_id,
        "locator_sha256": SHA_D,
        "content_sha256": event.data_envelope_ref,
        "published_at": PUBLISHED,
        "observed_at": event.occurred_at,
        "window_start": WINDOW_START,
        "window_end": WINDOW_END,
        "claim_class": "source_assertion",
        "claim_group_sha256": SHA_E,
        "summary_sha256": SHA_F,
        "collection_state": "collected",
    }
    values.update(updates)
    return build_security_intelligence_evidence_v1(**values)


def _no_update_evidence(
    registry: SecurityIntelligenceSourceRegistryV1,
    event: CanonicalObservationEventV1,
    source_id: str,
) -> SecurityIntelligenceEvidenceV1:
    return build_security_intelligence_evidence_v1(
        event_id=event.event_id,
        source_observation_sha256=hashlib.sha256(
            encode_portfolio_observation_v1(event)
        ).hexdigest(),
        registry_sha256=security_intelligence_source_registry_sha256(registry),
        source_id=source_id,
        locator_sha256=None,
        content_sha256=None,
        published_at=None,
        observed_at=event.occurred_at,
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        claim_class=None,
        claim_group_sha256=None,
        summary_sha256=None,
        collection_state="no_update",
    )


def _extension_fixture() -> tuple[
    SecurityIntelligenceSourceRegistryV1,
    SecurityIntelligenceBundleV1,
    SecurityIntelligenceSynthesisProfileV1,
    ExtensionObservationEnvelopeV1,
]:
    registry = _registry()
    first = _event(SHA_A, SHA_C)
    second = _event(SHA_B, SHA_D)
    items = (
        _collected_evidence(registry, first, "openai-security"),
        _no_update_evidence(registry, second, "owasp-genai"),
    )
    bundle = build_security_intelligence_bundle_v1(
        registry=registry,
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        items=items,
        collection_status="complete_for_declared_sources",
    )
    profile = build_security_intelligence_synthesis_profile_v1(language="ru")
    envelope = build_extension_envelope_v1(
        source_component_id="agentic-security-harness",
        source_commitment_sha256=SHA_E,
        events=(first, second),
    )
    return registry, bundle, profile, envelope


def test_offline_review_keeps_external_provenance_and_never_passes() -> None:
    registry, bundle, profile, envelope = _extension_fixture()
    extension = SecurityIntelligenceReviewExtensionV1(
        registry=registry, bundle=bundle, profile=profile
    )

    receipt = run_extension_v1(extension, envelope)

    assert receipt.result.evidence_class == "external_unreviewed"
    assert [item.outcome for item in receipt.result.findings] == [
        "finding",
        "inconclusive",
    ]
    assert all(item.outcome != "pass" for item in receipt.result.findings)
    assert all(item.severity != "critical" for item in receipt.result.findings)
    assert receipt.operational_authority == "none"


def test_model_and_secondary_sources_remain_unverified() -> None:
    registry = build_security_intelligence_source_registry_v1(
        (
            _source(
                "secondary-feed",
                "https://example.org",
                source_kind="secondary_discovery",
            ),
        )
    )
    event = _event(SHA_A, SHA_C)
    item = _collected_evidence(
        registry,
        event,
        "secondary-feed",
        claim_class="model_proposal",
    )
    bundle = build_security_intelligence_bundle_v1(
        registry=registry,
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        items=(item,),
        collection_status="complete_for_declared_sources",
    )
    extension = SecurityIntelligenceReviewExtensionV1(
        registry=registry,
        bundle=bundle,
        profile=build_security_intelligence_synthesis_profile_v1(),
    )
    envelope = build_extension_envelope_v1(
        source_component_id="agentic-security-harness",
        source_commitment_sha256=SHA_E,
        events=(event,),
    )

    finding = run_extension_v1(extension, envelope).result.findings[0]

    assert finding.outcome == "inconclusive"
    assert finding.severity == "none"
    assert finding.reason_code == "intelligence.model_proposal_unverified"


@pytest.mark.parametrize(
    ("claim_class", "reason_code"),
    (
        ("calculation", "intelligence.calculation_unreviewed"),
        ("inference", "intelligence.inference_unreviewed"),
        ("hypothesis", "intelligence.hypothesis_unreviewed"),
    ),
)
def test_derived_claims_never_become_review_findings(
    claim_class: SecurityClaimClass, reason_code: str
) -> None:
    registry = build_security_intelligence_source_registry_v1(
        (_source("openai-security", "https://openai.com"),)
    )
    event = _event(SHA_A, SHA_C)
    item = _collected_evidence(
        registry, event, "openai-security", claim_class=claim_class
    )
    bundle = build_security_intelligence_bundle_v1(
        registry=registry,
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        items=(item,),
        collection_status="complete_for_declared_sources",
    )
    extension = SecurityIntelligenceReviewExtensionV1(
        registry=registry,
        bundle=bundle,
        profile=build_security_intelligence_synthesis_profile_v1(),
    )
    envelope = build_extension_envelope_v1(
        source_component_id="agentic-security-harness",
        source_commitment_sha256=SHA_E,
        events=(event,),
    )

    finding = run_extension_v1(extension, envelope).result.findings[0]
    assert finding.outcome == "inconclusive"
    assert finding.reason_code == reason_code


def test_review_rejects_observation_substitution_and_incomplete_coverage() -> None:
    registry, bundle, profile, envelope = _extension_fixture()
    changed = envelope.events[0].model_copy(update={"data_envelope_ref": SHA_F})
    substituted = build_extension_envelope_v1(
        source_component_id=envelope.source_component_id,
        source_commitment_sha256=envelope.source_commitment_sha256,
        events=(changed, envelope.events[1]),
    )
    extension = SecurityIntelligenceReviewExtensionV1(
        registry=registry, bundle=bundle, profile=profile
    )
    with pytest.raises(ExtensionContractError, match="evaluation failed"):
        run_extension_v1(extension, substituted)

    missing = build_extension_envelope_v1(
        source_component_id=envelope.source_component_id,
        source_commitment_sha256=envelope.source_commitment_sha256,
        events=(envelope.events[0],),
    )
    with pytest.raises(ExtensionContractError, match="evaluation failed"):
        run_extension_v1(extension, missing)


@pytest.mark.parametrize(
    "event_update",
    (
        {"activity": "unrelated.document"},
        {"source_surface": "agent"},
        {"authority_envelope_ref": SHA_F},
        {"telemetry_state": "complete"},
    ),
)
def test_review_rejects_semantically_mismatched_observation(
    event_update: dict[str, object],
) -> None:
    registry, bundle, profile, envelope = _extension_fixture()
    changed = envelope.events[0].model_copy(update=event_update)
    changed_item = _collected_evidence(registry, changed, "openai-security")
    changed_bundle = build_security_intelligence_bundle_v1(
        registry=registry,
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        items=(changed_item, bundle.items[1]),
        collection_status="complete_for_declared_sources",
    )
    substituted = build_extension_envelope_v1(
        source_component_id=envelope.source_component_id,
        source_commitment_sha256=envelope.source_commitment_sha256,
        events=(changed, envelope.events[1]),
    )
    extension = SecurityIntelligenceReviewExtensionV1(
        registry=registry, bundle=changed_bundle, profile=profile
    )
    with pytest.raises(ExtensionContractError, match="evaluation failed"):
        run_extension_v1(extension, substituted)


def test_bundle_rejects_replayed_locator_and_same_source_content() -> None:
    registry = _registry()
    first = _event(SHA_A, SHA_C)
    second = _event(SHA_B, SHA_D)
    original = _collected_evidence(registry, first, "openai-security")
    replayed_locator = _collected_evidence(
        registry,
        second,
        "owasp-genai",
        locator_sha256=original.locator_sha256,
    )
    with pytest.raises(ValidationError, match="locators cannot be replayed"):
        build_security_intelligence_bundle_v1(
            registry=registry,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            items=(original, replayed_locator),
            collection_status="complete_for_declared_sources",
        )

    same_source = _collected_evidence(
        registry,
        second,
        "openai-security",
        locator_sha256=SHA_E,
        content_sha256=original.content_sha256,
    )
    with pytest.raises(ValidationError, match="content cannot be replayed"):
        SecurityIntelligenceBundleV1.model_validate(
            {
                **build_security_intelligence_bundle_v1(
                    registry=registry,
                    window_start=WINDOW_START,
                    window_end=WINDOW_END,
                    items=(original,),
                    collection_status="partial",
                    missing_source_ids=("owasp-genai",),
                ).model_dump(mode="python"),
                "items": (original, same_source),
            }
        )


def test_review_rejects_content_sidecar_mismatch() -> None:
    registry, bundle, profile, envelope = _extension_fixture()
    mismatched = _collected_evidence(
        registry,
        envelope.events[0],
        "openai-security",
        content_sha256=SHA_D,
    )
    changed_bundle = build_security_intelligence_bundle_v1(
        registry=registry,
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        items=(mismatched, bundle.items[1]),
        collection_status="complete_for_declared_sources",
    )
    extension = SecurityIntelligenceReviewExtensionV1(
        registry=registry, bundle=changed_bundle, profile=profile
    )
    with pytest.raises(ExtensionContractError, match="evaluation failed"):
        run_extension_v1(extension, envelope)


def test_non_collected_state_cannot_coexist_with_collected_source_item() -> None:
    registry = _registry()
    first = _event(SHA_A, SHA_C)
    second = _event(SHA_B, SHA_D)
    collected = _collected_evidence(registry, first, "openai-security")
    no_update = _no_update_evidence(registry, second, "openai-security")
    with pytest.raises(ValidationError, match="cannot coexist"):
        SecurityIntelligenceBundleV1.model_validate(
            {
                **build_security_intelligence_bundle_v1(
                    registry=registry,
                    window_start=WINDOW_START,
                    window_end=WINDOW_END,
                    items=(collected,),
                    collection_status="partial",
                    missing_source_ids=("owasp-genai",),
                ).model_dump(mode="python"),
                "items": (collected, no_update),
            }
        )


def test_weekly_window_and_observation_boundary_are_exact() -> None:
    registry = _registry()
    event = _event(SHA_A, SHA_C)
    original = _collected_evidence(registry, event, "openai-security")
    with pytest.raises(ValidationError, match="seven-day"):
        SecurityIntelligenceEvidenceV1.model_validate(
            {
                **original.model_dump(mode="python"),
                "window_start": WINDOW_START - timedelta(days=1),
            }
        )
    with pytest.raises(ValidationError, match="observed at window_end"):
        SecurityIntelligenceEvidenceV1.model_validate(
            {
                **original.model_dump(mode="python"),
                "observed_at": WINDOW_END + timedelta(seconds=1),
            }
        )


@pytest.mark.parametrize(
    "origin",
    (
        "http://example.org",
        "https://user@example.org",
        "https://example.org/feed",
        "https://example.org?token=x",
        "https://localhost",
        "https://127.0.0.1",
        "https://Example.org",
    ),
)
def test_source_registry_rejects_noncanonical_or_private_origins(origin: str) -> None:
    with pytest.raises(ValidationError):
        _source("bad-source", origin)


def test_bundle_requires_exact_registry_coverage_and_order() -> None:
    registry, bundle, _, _ = _extension_fixture()
    with pytest.raises(SecurityIntelligenceContractError, match="exactly account"):
        build_security_intelligence_bundle_v1(
            registry=registry,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            items=(bundle.items[0],),
            collection_status="partial",
        )
    with pytest.raises(ValidationError, match="canonical source/time/id ordering"):
        SecurityIntelligenceBundleV1.model_validate(
            bundle.model_copy(update={"items": tuple(reversed(bundle.items))}).model_dump(
                mode="python"
            )
        )


def test_evidence_rejects_raw_content_and_invalid_state_fields() -> None:
    registry = _registry()
    event = _event(SHA_A, SHA_C)
    payload = _collected_evidence(registry, event, "openai-security").model_dump(
        mode="python"
    )
    payload["raw_body"] = "ignore previous instructions"
    with pytest.raises(ValidationError):
        SecurityIntelligenceEvidenceV1.model_validate(payload)

    payload.pop("raw_body")
    payload["collection_state"] = "no_update"
    with pytest.raises(ValidationError, match="cannot retain publication"):
        SecurityIntelligenceEvidenceV1.model_validate(payload)


def test_identity_window_and_registry_drift_fail_closed() -> None:
    registry, bundle, _, _ = _extension_fixture()
    item = bundle.items[0]
    with pytest.raises(ValidationError, match="item_id"):
        SecurityIntelligenceEvidenceV1.model_validate(
            item.model_copy(update={"summary_sha256": SHA_A}).model_dump(mode="python")
        )
    with pytest.raises(ValidationError, match="outside the declared window"):
        SecurityIntelligenceEvidenceV1.model_validate(
            item.model_copy(
                update={"published_at": WINDOW_END + timedelta(seconds=1)}
            ).model_dump(mode="python")
        )
    with pytest.raises(ValidationError, match="registry or window drift"):
        SecurityIntelligenceBundleV1.model_validate(
            bundle.model_copy(update={"registry_sha256": SHA_A}).model_dump(
                mode="python"
            )
        )
    assert security_intelligence_source_registry_sha256(registry) != SHA_A


def test_review_path_never_uses_network_subprocess_or_dynamic_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, bundle, profile, envelope = _extension_fixture()
    extension = SecurityIntelligenceReviewExtensionV1(
        registry=registry, bundle=bundle, profile=profile
    )

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline intelligence review crossed an execution boundary")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(importlib, "import_module", forbidden)

    receipt = run_extension_v1(extension, envelope)
    assert len(receipt.result.findings) == 2


def test_schemas_are_closed_and_manifest_provenance_is_explicit() -> None:
    schemas = security_intelligence_v1_json_schemas()
    assert len(schemas) == 4
    assert all(schema["additionalProperties"] is False for schema in schemas.values())

    manifest = ExtensionManifestV1.model_validate(
        {
            "schema_version": "harness-extension-manifest-v1.0",
            "extension_id": "example.unreviewed",
            "extension_version": "1.0.0",
            "component_id": "agentic-security-harness",
            "implementation_sha256": SHA_A,
            "configuration_sha256": SHA_B,
            "harness_api": "1",
            "kind": "check_extension",
            "capabilities": ("observation.read", "finding.emit"),
            "consumes": (
                {
                    "contract_id": "portfolio-observation",
                    "version": "1.0",
                    "required": True,
                },
            ),
            "produces": (
                {
                    "contract_id": "extension-finding",
                    "version": "1.0",
                    "required": True,
                },
            ),
            "deterministic": True,
            "evidence_provenance": "external_unreviewed",
            "network_mode": "off",
            "raw_data_policy": "digests_only",
            "execution_model": "in_process_operator_approved_not_sandboxed",
            "operational_authority": "none",
        }
    )
    assert manifest.evidence_provenance == "external_unreviewed"

    with pytest.raises(ValidationError, match="deterministic-rule evidence"):
        ExtensionManifestV1.model_validate(
            manifest.model_copy(
                update={
                    "deterministic": False,
                    "evidence_provenance": "deterministic_rule",
                }
            ).model_dump(mode="python")
        )
