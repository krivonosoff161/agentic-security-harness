import json
import re
from datetime import date
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from agentic_security_harness.evidence_status import (
    EvidenceStatusEntry,
    EvidenceStatusRegistry,
    load_evidence_status_registry,
    parse_registry_json,
    registry_json_schema,
    validate_registry_artifact_paths,
)
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS
from agentic_security_harness.validation import validate_path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "docs" / "evidence-status-registry.json"


def _entry(**overrides: object) -> EvidenceStatusEntry:
    data: dict[str, object] = {
        "evidence_id": "test.synthetic",
        "title": "Synthetic test entry",
        "lifecycle_status": "shipped",
        "evidence_class": "executable_specification",
        "schema_state": "current_executed",
        "causal_scope": "rule_derived_dependency",
        "label_source": "none",
        "label_coverage": 0.0,
        "reconciliation_state": "not_applicable",
        "origin_authentication": "self_declared",
        "artifact_paths": ["examples/demo-report"],
        "validator_anchor": "tests/test_validation.py",
        "supported_claim": "The declared fixture branch is reproducible.",
        "forbidden_claims": ["production safety"],
    }
    data.update(overrides)
    return EvidenceStatusEntry.model_validate(data)


def _registry(entries: list[EvidenceStatusEntry]) -> EvidenceStatusRegistry:
    return EvidenceStatusRegistry(
        schema_version=SCHEMA_VERSIONS["evidence_status_registry"],
        reviewed_at=date(2026, 7, 15),
        entries=entries,
    )


def test_public_evidence_status_registry_is_valid_and_resolves_paths() -> None:
    registry = load_evidence_status_registry(REGISTRY_PATH)

    assert len(registry.entries) == 27
    assert validate_registry_artifact_paths(registry, repository_root=ROOT) == []
    assert all(entry.lifecycle_status == "shipped" for entry in registry.entries)
    assert all(
        entry.origin_authentication != "signed_attested"
        for entry in registry.entries
    )
    assert not any(
        entry.evidence_class
        in {"local_empirical_reconciled", "independently_labelled_evaluation"}
        for entry in registry.entries
    )


def test_registry_separates_mixed_semantic_artifact_components() -> None:
    registry = load_evidence_status_registry(REGISTRY_PATH)
    by_id = {entry.evidence_id: entry for entry in registry.entries}

    for prefix in ("semantic.drift", "semantic.propagation"):
        specification = by_id[f"{prefix}-specification"]
        history = by_id[f"{prefix}-history"]

        assert specification.artifact_paths == history.artifact_paths
        assert specification.evidence_class == "historical_rule_snapshot"
        assert specification.causal_scope == "rule_derived_dependency"
        assert history.evidence_class == "historical_detector_summary"
        assert history.causal_scope == "detector_observation"
        assert history.reconciliation_state == "absent"


def test_registry_covers_every_showcase_campaign_directory() -> None:
    registry = load_evidence_status_registry(REGISTRY_PATH)
    registered = {
        path
        for entry in registry.entries
        for path in entry.artifact_paths
        if path.startswith("examples/")
    }
    required = {
        "examples/comparison-report",
        "examples/external-demo-report",
        "examples/handoff-toy-comparison",
        "examples/local-swarm-report",
        "examples/local-swarm-attack-matrix",
        "examples/evidence-campaign-sanitized",
        "examples/secret-leak-campaign-sanitized",
        "examples/secret-leak-variations-sanitized",
        "examples/semantic-drift-sanitized",
        "examples/semantic-propagation-sanitized",
        "examples/swarm-defense-contour-sanitized",
        "examples/swarm-defense-live-sanitized",
        "examples/swarm-defense-live-long-session-sanitized",
        "examples/swarm-defense-live-deep-sanitized",
        "examples/marketing-web-injection-sanitized",
        "examples/marketing-web-live-sanitized",
        "examples/swarm-resilience-sanitized",
        "examples/context-consent-sanitized",
        "examples/tool-authority-sanitized",
        "examples/rag-context-sanitized",
        "examples/planner-task-sanitized",
        "examples/memory-rehydration-sanitized",
    }

    assert registered == required


def test_showcase_mapping_has_exact_bidirectional_registry_coverage() -> None:
    registry = load_evidence_status_registry(REGISTRY_PATH)
    showcase = (ROOT / "docs" / "showcase" / "index.md").read_text(encoding="utf-8")
    mapping = showcase.split("Machine-readable row mapping:", 1)[1].split(
        "| Evidence | Status |", 1
    )[0]
    mapped_ids = re.findall(r"evidence-id:([a-z0-9][a-z0-9._-]+)", mapping)
    registry_ids = {entry.evidence_id for entry in registry.entries}

    assert len(mapped_ids) == len(set(mapped_ids))
    assert set(mapped_ids) == registry_ids


def test_registry_separates_workflow_specs_from_unreconciled_runtime_reports() -> None:
    registry = load_evidence_status_registry(REGISTRY_PATH)
    by_id = {entry.evidence_id: entry for entry in registry.entries}

    assert by_id["runtime.local-suite-specification"].evidence_class == (
        "executable_specification"
    )
    for evidence_id in (
        "runtime.prometheus-smoke-history",
        "runtime.local-swarm-history",
    ):
        entry = by_id[evidence_id]
        assert entry.evidence_class == "maintainer_declaration_unverified"
        assert entry.schema_state == "not_applicable"
        assert entry.causal_scope == "none"
        assert entry.label_source == "none"
        assert entry.reconciliation_state == "absent"
        assert entry.origin_authentication == "self_declared"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {
                "evidence_class": "executable_specification",
                "reconciliation_state": "reconciled_with_receipt",
            },
            "synthetic evidence cannot claim byte reconciliation",
        ),
        (
            {
                "evidence_class": "historical_detector_summary",
                "schema_state": "current_executed",
                "causal_scope": "detector_observation",
                "reconciliation_state": "absent",
            },
            "historical detector evidence must be legacy_readable",
        ),
        (
            {
                "evidence_class": "executable_specification",
                "schema_state": "legacy_readable",
            },
            "executable specifications cannot use a legacy artifact schema",
        ),
        (
            {
                "evidence_class": "local_empirical_unreconciled",
                "schema_state": "current_executed",
                "causal_scope": "detector_observation",
                "reconciliation_state": "reconciled_with_receipt",
            },
            "unreconciled evidence cannot claim a receipt",
        ),
        (
            {
                "evidence_class": "local_empirical_unreconciled",
                "schema_state": "current_unexecuted",
                "causal_scope": "detector_observation",
                "reconciliation_state": "absent",
            },
            "empirical evidence requires an executed artifact schema",
        ),
        (
            {
                "causal_scope": "independent_causal_estimate",
            },
            "synthetic evidence cannot claim empirical causal scope",
        ),
        (
            {
                "label_source": "detector_derived",
                "label_coverage": 1.0,
            },
            "only independent_review may have non-zero label_coverage",
        ),
        (
            {
                "evidence_class": "independently_labelled_evaluation",
                "label_source": "independent_review",
                "label_coverage": 0.0,
            },
            "independent_review requires non-zero label_coverage",
        ),
    ],
)
def test_evidence_status_rejects_logically_impossible_promotions(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        _entry(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "evidence_class": "local_empirical_reconciled",
            "causal_scope": "observed_association",
            "reconciliation_state": "reconciled_with_receipt",
        },
        {
            "evidence_class": "independently_labelled_evaluation",
            "causal_scope": "observed_association",
            "label_source": "independent_review",
            "label_coverage": 1.0,
        },
        {"origin_authentication": "content_bound"},
        {"origin_authentication": "signed_attested"},
    ],
)
def test_registry_contract_rejects_unverifiable_assurance_promotions(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(
        ValidationError,
        match="requires a validated public receipt/attestation contract",
    ):
        _entry(**overrides)


def test_validate_path_rejects_coherent_reconciled_promotion_without_receipt(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (tmp_path / "src" / "agentic_security_harness").mkdir(parents=True)
    (tmp_path / "examples" / "demo-report").mkdir(parents=True)
    validator = tmp_path / "tests" / "test_validation.py"
    validator.parent.mkdir()
    validator.write_text("# validator anchor\n", encoding="utf-8")
    entry = _entry().model_dump(mode="json")
    entry.update(
        {
            "evidence_class": "local_empirical_reconciled",
            "causal_scope": "observed_association",
            "reconciliation_state": "reconciled_with_receipt",
        }
    )
    payload = {
        "schema_version": SCHEMA_VERSIONS["evidence_status_registry"],
        "reviewed_at": "2026-07-15",
        "entries": [entry],
    }
    path = tmp_path / "docs" / "evidence-status-registry.json"
    path.parent.mkdir()
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_path(path)

    assert not result.ok
    assert any(
        "requires a validated public receipt/attestation contract" in error
        for error in result.errors
    )


def test_evidence_status_rejects_escaping_and_duplicate_paths() -> None:
    with pytest.raises(ValidationError, match="relative repository paths"):
        _entry(artifact_paths=["../outside"])
    with pytest.raises(ValidationError, match="artifact_paths must be unique"):
        _entry(artifact_paths=["examples/demo-report", "examples/demo-report"])
    with pytest.raises(ValidationError, match="relative repository paths"):
        _entry(artifact_paths=[""])
    with pytest.raises(ValidationError, match="relative repository paths"):
        _entry(artifact_paths=["./examples/demo-report"])
    with pytest.raises(ValidationError, match="validator_anchor"):
        _entry(validator_anchor="../outside.py")


def test_evidence_status_rejects_blank_duplicate_or_overlapping_claims() -> None:
    with pytest.raises(ValidationError, match="must be nonblank"):
        _entry(supported_claim="   ")
    with pytest.raises(ValidationError, match="must be nonblank"):
        _entry(forbidden_claims=["   "])
    with pytest.raises(ValidationError, match="unique after normalization"):
        _entry(forbidden_claims=["Production safety", " production   SAFETY "])
    with pytest.raises(ValidationError, match="must not duplicate"):
        _entry(
            supported_claim="Production safety",
            forbidden_claims=[" production   SAFETY "],
        )


def test_registry_rejects_duplicate_evidence_ids() -> None:
    entry = _entry()
    with pytest.raises(ValidationError, match="evidence_id values must be unique"):
        _registry([entry, entry.model_copy()])


def test_registry_rejects_impossible_review_date() -> None:
    with pytest.raises(ValidationError):
        EvidenceStatusRegistry.model_validate({
            "schema_version": SCHEMA_VERSIONS["evidence_status_registry"],
            "reviewed_at": "2026-99-99",
            "entries": [_entry()],
        })


def test_registry_reports_missing_public_artifact_without_reading_it(
    tmp_path: Path,
) -> None:
    validator = tmp_path / "tests" / "test_validation.py"
    validator.parent.mkdir()
    validator.write_text("# validator anchor\n", encoding="utf-8")
    registry = _registry([_entry(artifact_paths=["examples/missing"])])

    errors = validate_registry_artifact_paths(registry, repository_root=tmp_path)

    assert errors == [
        "test.synthetic: artifact path is missing: examples/missing"
    ]


def test_registry_reports_missing_validator_anchor(tmp_path: Path) -> None:
    artifact = tmp_path / "examples" / "demo-report"
    artifact.mkdir(parents=True)
    (artifact / "run_config.json").write_text("{}", encoding="utf-8")
    registry = _registry([_entry()])

    errors = validate_registry_artifact_paths(registry, repository_root=tmp_path)

    assert errors == [
        "test.synthetic: validator anchor is missing: tests/test_validation.py"
    ]


def test_registry_rejects_wrong_but_existing_validator_anchor(tmp_path: Path) -> None:
    artifact = tmp_path / "examples" / "demo-report"
    artifact.mkdir(parents=True)
    (artifact / "run_config.json").write_text("{}", encoding="utf-8")
    wrong_anchor = tmp_path / "tests" / "test_local_swarm.py"
    wrong_anchor.parent.mkdir()
    wrong_anchor.write_text("# unrelated validator\n", encoding="utf-8")
    registry = _registry([_entry(validator_anchor="tests/test_local_swarm.py")])

    errors = validate_registry_artifact_paths(registry, repository_root=tmp_path)

    assert errors == [
        "test.synthetic: validator anchor is incompatible with artifact family: "
        "tests/test_local_swarm.py -> examples/demo-report"
    ]


def test_validate_path_accepts_public_evidence_status_registry() -> None:
    result = validate_path(REGISTRY_PATH)

    assert result.ok
    assert result.evidence_status_registry_files == [
        "evidence-status-registry.json"
    ]
    assert result.evidence_statuses == []


def test_validate_examples_attaches_machine_readable_evidence_limitations() -> None:
    result = validate_path(ROOT / "examples")
    unverified = {
        status.evidence_id
        for status in result.evidence_statuses
        if status.projection_verification == "unverified-private-projection"
    }

    assert result.ok
    assert len(result.evidence_statuses) == 24
    assert unverified == {
        "egress.local-variations",
        "marketing.live-history",
        "semantic.drift-history",
        "semantic.propagation-history",
        "swarm.live-history",
    }


def test_validate_mixed_semantic_artifact_keeps_component_statuses_separate() -> None:
    result = validate_path(ROOT / "examples" / "semantic-drift-sanitized")
    by_id = {status.evidence_id: status for status in result.evidence_statuses}

    assert result.ok
    assert set(by_id) == {
        "semantic.drift-history",
        "semantic.drift-specification",
    }
    assert by_id["semantic.drift-history"].projection_verification == (
        "unverified-private-projection"
    )
    assert by_id["semantic.drift-specification"].projection_verification == (
        "legacy-structural-only"
    )


def test_validate_path_rejects_malformed_registry(tmp_path: Path) -> None:
    path = tmp_path / "evidence-status-registry.json"
    path.write_text("{", encoding="utf-8")

    result = validate_path(path)

    assert not result.ok
    assert result.evidence_status_registry_files == [path.name]
    assert any("schema" in error for error in result.errors)


def test_validate_path_rejects_missing_registry_artifact(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (tmp_path / "src" / "agentic_security_harness").mkdir(parents=True)
    validator = tmp_path / "tests" / "test_validation.py"
    validator.parent.mkdir()
    validator.write_text("# validator anchor\n", encoding="utf-8")
    registry = _registry([_entry(artifact_paths=["examples/missing"])])
    path = tmp_path / "docs" / "evidence-status-registry.json"
    path.parent.mkdir()
    path.write_text(registry.model_dump_json(indent=2), encoding="utf-8")

    result = validate_path(path)

    assert not result.ok
    assert any("artifact path is missing" in error for error in result.errors)


def test_validate_path_keeps_arbitrary_json_outside_registry_contract(
    tmp_path: Path,
) -> None:
    path = tmp_path / "other.json"
    path.write_text("{}", encoding="utf-8")

    result = validate_path(path)

    assert not result.ok
    assert result.evidence_status_registry_files == []
    assert result.errors == ["not a directory: other.json"]


def test_registry_parser_and_generated_schema_are_public_contracts() -> None:
    registry = parse_registry_json(REGISTRY_PATH.read_text(encoding="utf-8"))
    schema = cast(dict[str, Any], registry_json_schema())

    assert registry.schema_version == SCHEMA_VERSIONS["evidence_status_registry"]
    assert schema["properties"]["schema_version"]["type"] == "string"
    assert "schema_version" in schema["required"]
    assert schema["properties"]["reviewed_at"]["format"] == "date"


def test_registry_parser_rejects_invalid_json() -> None:
    with pytest.raises(ValueError, match="invalid evidence status JSON"):
        parse_registry_json("{")


def test_registry_json_is_plain_machine_readable_contract() -> None:
    payload = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

    assert payload["schema_version"] == SCHEMA_VERSIONS["evidence_status_registry"]


@pytest.mark.parametrize("payload", [{}, {"schema_version": "9.9"}])
def test_registry_rejects_missing_or_future_schema_version(
    payload: dict[str, object],
) -> None:
    data: dict[str, object] = {
        "schema_version": SCHEMA_VERSIONS["evidence_status_registry"],
        "reviewed_at": "2026-07-15",
        "entries": [_entry().model_dump(mode="json")],
    }
    data.update(payload)
    if payload == {}:
        data.pop("schema_version")

    with pytest.raises(ValidationError):
        EvidenceStatusRegistry.model_validate(data)
