from __future__ import annotations

import copy
from pathlib import Path

import pytest
from pydantic import ValidationError
from tools.ecosystem_docs import (
    ECOSYSTEM,
    ROOT,
    SCHEMAS,
    ComponentManifest,
    EcosystemRoadmap,
    build_document_registry,
    check_generated,
    generated_schemas,
    load_contract,
    validate_all,
    validate_component_set,
)


def test_shape_and_semantic_validators_accept_canonical_contracts() -> None:
    component, roadmap, compatibility = validate_all()

    assert component.component_id == "agentic-security-harness"
    assert roadmap.components == [row.component_id for row in compatibility.rows]
    assert roadmap.authority == "none"
    assert component.authority == "none"


def test_generated_json_schemas_are_exact() -> None:
    expected = generated_schemas()

    assert set(expected) == {
        "compatibility.v1.schema.json",
        "component-manifest.v1.schema.json",
        "ecosystem-roadmap.v1.schema.json",
    }
    for name, content in expected.items():
        assert (SCHEMAS / name).read_bytes() == content


def test_component_schema_rejects_unknown_fields_and_unsafe_paths() -> None:
    payload = load_contract(ROOT / "component.yaml")
    assert isinstance(payload, dict)

    unknown = copy.deepcopy(payload)
    unknown["operational_authority"] = "granted"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ComponentManifest.model_validate(unknown)

    unsafe = copy.deepcopy(payload)
    unsafe["docs"][0]["path"] = "../private/evidence.md"
    with pytest.raises(ValidationError, match="unsafe or non-portable path"):
        ComponentManifest.model_validate(unsafe)


def test_private_component_cannot_publish_repository_location() -> None:
    payload = load_contract(ROOT / "component.yaml")
    assert isinstance(payload, dict)
    payload["visibility"] = "private"

    with pytest.raises(ValidationError, match="must not enter the public manifest"):
        ComponentManifest.model_validate(payload)


def test_roadmap_rejects_dependency_cycles() -> None:
    payload = load_contract(ECOSYSTEM / "roadmap.yaml")
    assert isinstance(payload, dict)
    payload["phases"][0]["depends_on"] = [payload["phases"][-1]["id"]]

    with pytest.raises(ValidationError, match="dependency cycle"):
        EcosystemRoadmap.model_validate(payload)


def test_roadmap_rejects_completed_phase_with_incomplete_dependency() -> None:
    payload = load_contract(ECOSYSTEM / "roadmap.yaml")
    assert isinstance(payload, dict)
    payload["phases"][1]["status"] = "complete"

    with pytest.raises(ValidationError, match="incomplete dependencies"):
        EcosystemRoadmap.model_validate(payload)


def test_document_registry_covers_every_current_document() -> None:
    registry = build_document_registry()
    entries = registry["entries"]
    assert isinstance(entries, list)
    registered = {entry["path"] for entry in entries}
    expected = {
        "README.md",
        "CHANGELOG.md",
        "GOVERNANCE.md",
        *{
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "docs").rglob("*")
            if path.is_file() and path.suffix.lower() in {".md", ".json", ".yaml", ".yml"}
        },
    }

    assert registered == expected
    assert len(registered) == len(entries)
    assert all(entry["role"] and entry["disposition"] for entry in entries)


def test_generated_outputs_are_idempotent() -> None:
    check_generated()
    before = (ECOSYSTEM / "document-registry.json").read_bytes()

    check_generated()

    assert (ECOSYSTEM / "document-registry.json").read_bytes() == before


def test_machine_contracts_use_json_syntax_valid_in_yaml_1_2() -> None:
    for path in (ROOT / "component.yaml", ECOSYSTEM / "roadmap.yaml"):
        assert isinstance(load_contract(path), dict)
        assert Path(path).suffix == ".yaml"


def test_component_set_requires_every_roadmap_component() -> None:
    with pytest.raises(ValueError, match="exactly follow roadmap component order"):
        validate_component_set([ROOT])
