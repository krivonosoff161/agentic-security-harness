from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentic_security_harness.portfolio_contract import (
    MAX_ADAPTER_AUDIT_FIELDS,
    MAX_ADAPTER_AUDIT_MAPPINGS,
    MAX_ADAPTER_AUDIT_REASON_CODES,
    MAX_OBSERVATION_ENTITY_REFS,
    MAX_OBSERVATION_PARENT_EVENTS,
    MAX_PORTFOLIO_OBSERVATION_BYTES,
    AdapterAuditV1,
    AdapterFieldMappingV1,
    CanonicalObservationEventV1,
    ObservationCommitmentV1,
    PortfolioObservationContractError,
    SafeEvidencePointer,
    commit_portfolio_observation_v1,
    decode_portfolio_observation_v1,
    encode_portfolio_observation_v1,
    portfolio_observation_v1_json_schema,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "portfolio-observation-v1"
SCHEMA_PATH = ROOT / "schemas" / "portfolio-observation.v1.schema.json"
MANIFEST_PATH = ROOT / "schemas" / "portfolio-observation.v1.manifest.json"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _event(**updates: object) -> CanonicalObservationEventV1:
    values: dict[str, object] = {
        "schema_version": "portfolio-observation-v1.0",
        "event_id": SHA_A,
        "project_id": "agentic-security-harness",
        "repository_id": "krivonosoff161/agentic-security-harness",
        "repository_sha": "d" * 40,
        "occurred_at": datetime(2026, 8, 2, 10, 30, tzinfo=UTC),
        "producer_id_hash": SHA_B,
        "producer_attestation": "unattested",
        "source_surface": "agent",
        "activity": "handoff.summary",
        "entity_refs": (
            SafeEvidencePointer(kind="trace", digest=SHA_C, locator_id=SHA_B),
        ),
        "parent_event_ids": (),
        "data_envelope_ref": SHA_C,
        "authority_envelope_ref": None,
        "telemetry_state": "complete",
        "operational_authority": "none",
    }
    values.update(updates)
    return CanonicalObservationEventV1.model_validate(values)


def _audit(**updates: object) -> AdapterAuditV1:
    target_fields = tuple(CanonicalObservationEventV1.model_fields)
    values: dict[str, object] = {
        "schema_version": "portfolio-adapter-audit-v1.0",
        "source_model": "runtime_guard.observation_event",
        "target_model": "portfolio-observation-v1.0",
        "completeness": "partial",
        "source_fields": ("event_id", "effect", "authority_level"),
        "target_fields": target_fields,
        "mappings": (
            AdapterFieldMappingV1(
                source_fields=("event_id",),
                target_fields=("event_id",),
                transformation="identity",
                authority_effect="none",
            ),
            AdapterFieldMappingV1(
                source_fields=("effect",),
                target_fields=("activity",),
                transformation="derived",
                authority_effect="downgrade",
            ),
        ),
        "dropped_source_fields": ("authority_level",),
        "context_target_fields": (
            "project_id",
            "repository_id",
            "repository_sha",
            "occurred_at",
            "producer_id_hash",
            "source_surface",
            "entity_refs",
            "parent_event_ids",
            "data_envelope_ref",
            "telemetry_state",
        ),
        "constant_target_fields": (
            "schema_version",
            "producer_attestation",
            "authority_envelope_ref",
            "operational_authority",
        ),
        "authority_downgrade": True,
        "reason_codes": ("adapter.authority_dropped",),
        "operational_authority": "none",
    }
    values.update(updates)
    return AdapterAuditV1.model_validate(values)


def test_v1_wire_round_trip_is_exact_bounded_and_timezone_canonical() -> None:
    event = _event()
    encoded = encode_portfolio_observation_v1(event)

    assert len(encoded) <= MAX_PORTFOLIO_OBSERVATION_BYTES
    assert decode_portfolio_observation_v1(encoded) == event
    assert encoded == encode_portfolio_observation_v1(event)
    offset = timezone(timedelta(hours=3))
    same_instant = _event(occurred_at=datetime(2026, 8, 2, 13, 30, tzinfo=offset))
    assert encode_portfolio_observation_v1(same_instant) == encoded


def test_v1_commitment_is_separate_from_untrusted_producer_event_id() -> None:
    first = commit_portfolio_observation_v1(_event())
    second = commit_portfolio_observation_v1(_event(activity="handoff.validate"))

    assert first.content_sha256 != SHA_A
    assert first.commitment_sha256 != SHA_A
    assert first.commitment_sha256 != first.content_sha256
    assert first.commitment_sha256 != second.commitment_sha256
    assert first.operational_authority == "none"


def test_v1_commitment_revalidates_domain_schema_content_relation() -> None:
    commitment = commit_portfolio_observation_v1(_event())
    values = commitment.model_dump()
    values["content_sha256"] = "f" * 64

    with pytest.raises(ValidationError, match="does not bind"):
        ObservationCommitmentV1.model_validate(values)


def test_v1_decoder_rejects_ambiguous_noncanonical_and_oversized_payloads() -> None:
    encoded = encode_portfolio_observation_v1(_event())
    decoded = json.loads(encoded)

    unknown = dict(decoded, raw_prompt="synthetic-secret-shaped-value")
    with pytest.raises(PortfolioObservationContractError, match="fields"):
        decode_portfolio_observation_v1(json.dumps(unknown).encode())
    missing = dict(decoded)
    del missing["data_envelope_ref"]
    with pytest.raises(PortfolioObservationContractError, match="fields"):
        decode_portfolio_observation_v1(json.dumps(missing).encode())
    wrong_version = dict(decoded, schema_version="portfolio-observation-v2.0")
    with pytest.raises(PortfolioObservationContractError, match="version"):
        decode_portfolio_observation_v1(json.dumps(wrong_version).encode())
    duplicate = encoded.replace(
        b'"schema_version":"portfolio-observation-v1.0"',
        b'"schema_version":"portfolio-observation-v1.0",'
        b'"schema_version":"portfolio-observation-v1.0"',
    )
    with pytest.raises(PortfolioObservationContractError, match="duplicate"):
        decode_portfolio_observation_v1(duplicate)
    with pytest.raises(PortfolioObservationContractError, match="canonical"):
        decode_portfolio_observation_v1(json.dumps(decoded, indent=2).encode())
    with pytest.raises(PortfolioObservationContractError, match="byte limit"):
        decode_portfolio_observation_v1(b"x" * (MAX_PORTFOLIO_OBSERVATION_BYTES + 1))
    deep_json = b'{"x":' + b"[" * 1_500 + b"0" + b"]" * 1_500 + b"}\n"
    with pytest.raises(PortfolioObservationContractError, match="UTF-8 JSON"):
        decode_portfolio_observation_v1(deep_json)


def test_v1_model_rejects_authority_promotion_and_raw_fields() -> None:
    values = _event().model_dump()
    values["operational_authority"] = "allow"
    with pytest.raises(ValidationError):
        CanonicalObservationEventV1.model_validate(values)
    values = _event().model_dump()
    values["producer_attestation"] = "verified"
    with pytest.raises(ValidationError):
        CanonicalObservationEventV1.model_validate(values)
    values = _event().model_dump()
    values["raw_tool_output"] = "synthetic"
    with pytest.raises(ValidationError):
        CanonicalObservationEventV1.model_validate(values)


def test_adapter_audit_v1_proves_exhaustive_source_and_target_accounting() -> None:
    audit = _audit()
    assert audit.authority_downgrade is True
    assert audit.operational_authority == "none"

    with pytest.raises(ValidationError, match="source field accounting"):
        _audit(source_fields=("event_id", "effect", "authority_level", "action_digest"))
    with pytest.raises(ValidationError, match="target field accounting"):
        _audit(
            context_target_fields=tuple(
                value for value in _audit().context_target_fields if value != "repository_id"
            )
        )
    with pytest.raises(ValidationError, match="field universe"):
        _audit(target_fields=("event_id", "activity", "operational_authority"))
    with pytest.raises(ValidationError, match="source field classifications"):
        _audit(dropped_source_fields=("authority_level", "effect"))
    with pytest.raises(ValidationError, match="authority downgrade"):
        _audit(authority_downgrade=False)
    with pytest.raises(ValidationError, match="operational_authority"):
        _audit(
            constant_target_fields=("schema_version", "authority_envelope_ref"),
        )
    with pytest.raises(ValidationError, match="authority_envelope_ref"):
        _audit(
            constant_target_fields=("schema_version", "operational_authority"),
        )


def test_v1_collection_cardinalities_fail_closed() -> None:
    pointer = SafeEvidencePointer(kind="trace", digest=SHA_C, locator_id=SHA_B)
    with pytest.raises(ValidationError, match="at most 64"):
        _event(entity_refs=(pointer,) * (MAX_OBSERVATION_ENTITY_REFS + 1))
    with pytest.raises(ValidationError, match="at most 64"):
        _event(
            parent_event_ids=tuple(
                f"{index:064x}" for index in range(MAX_OBSERVATION_PARENT_EVENTS + 1)
            )
        )

    too_many_fields = tuple(
        f"field_{index}" for index in range(MAX_ADAPTER_AUDIT_FIELDS + 1)
    )
    with pytest.raises(ValidationError, match="at most 128"):
        AdapterFieldMappingV1(
            source_fields=too_many_fields,
            target_fields=("activity",),
            transformation="derived",
            authority_effect="downgrade",
        )
    with pytest.raises(ValidationError, match="at most 128"):
        _audit(dropped_source_fields=too_many_fields)
    with pytest.raises(ValidationError, match="at most 128"):
        _audit(mappings=_audit().mappings * (MAX_ADAPTER_AUDIT_MAPPINGS + 1))
    with pytest.raises(ValidationError, match="at most 64"):
        _audit(
            reason_codes=tuple(
                f"reason_{index}" for index in range(MAX_ADAPTER_AUDIT_REASON_CODES + 1)
            )
        )


def test_schema_manifest_and_synthetic_fixtures_are_content_bound() -> None:
    generated_schema = portfolio_observation_v1_json_schema()
    stored_schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert stored_schema == generated_schema

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "portfolio-observation-contract-manifest-v1.0"
    assert manifest["contract_id"] == "portfolio-observation-v1.0"
    assert (
        manifest["canonicalization"]
        == "utf8-json-sort-keys-compact-utc-microseconds-lf-v1"
    )
    assert manifest["max_bytes"] == MAX_PORTFOLIO_OBSERVATION_BYTES
    assert manifest["max_entity_refs"] == MAX_OBSERVATION_ENTITY_REFS
    assert manifest["max_parent_event_ids"] == MAX_OBSERVATION_PARENT_EVENTS
    assert manifest["max_adapter_fields"] == MAX_ADAPTER_AUDIT_FIELDS
    assert manifest["max_adapter_mappings"] == MAX_ADAPTER_AUDIT_MAPPINGS
    assert manifest["max_adapter_reason_codes"] == MAX_ADAPTER_AUDIT_REASON_CODES
    assert manifest["commitment_domain"] == "agentic-security-portfolio/observation/v1.0"
    assert manifest["event_id_semantics"] == "producer_claim_shape_only"
    assert manifest["producer_attestation"] == "unattested_only"
    assert manifest["operational_authority"] == "none"
    assert manifest["schema_path"] == "schemas/portfolio-observation.v1.schema.json"
    assert manifest["schema_sha256"] == hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
    expected_fixture_paths = [
        "tests/fixtures/portfolio-observation-v1/valid/minimal.json",
        "tests/fixtures/portfolio-observation-v1/invalid/unknown-field.json",
        "tests/fixtures/portfolio-observation-v1/invalid/missing-field.json",
        "tests/fixtures/portfolio-observation-v1/invalid/wrong-version.json",
        "tests/fixtures/portfolio-observation-v1/invalid/duplicate-field.json",
    ]
    assert [fixture["path"] for fixture in manifest["fixtures"]] == expected_fixture_paths
    assert sorted(
        path.relative_to(ROOT).as_posix() for path in FIXTURE_ROOT.rglob("*.json")
    ) == sorted(expected_fixture_paths)
    assert [fixture["expected"] for fixture in manifest["fixtures"]] == [
        "accept",
        "reject",
        "reject",
        "reject",
        "reject",
    ]
    for fixture in manifest["fixtures"]:
        path = ROOT / fixture["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == fixture["sha256"]
        if fixture["expected"] == "accept":
            decode_portfolio_observation_v1(path.read_bytes())
        else:
            with pytest.raises(PortfolioObservationContractError):
                decode_portfolio_observation_v1(path.read_bytes())


def test_valid_golden_fixture_is_the_canonical_encoder_output() -> None:
    fixture = FIXTURE_ROOT / "valid" / "minimal.json"
    assert fixture.read_bytes() == encode_portfolio_observation_v1(_event())
