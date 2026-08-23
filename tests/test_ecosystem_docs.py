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
    ComponentsLock,
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
        "components-lock.v1.schema.json",
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
    assert [entry["path"] for entry in entries] == sorted(registered)
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


def test_component_lock_binds_public_git_and_bounded_private_projection() -> None:
    payload = load_contract(ECOSYSTEM / "components.lock.json")
    lock = ComponentsLock.model_validate(payload)

    assert [entry.component_id for entry in lock.entries] == [
        "agentic-security-harness",
        "agentic-transfer-verifier",
        "ai-agent-handoff",
        "llm-safety-playbooks",
        "llm-router",
        "llm-cheap-filter",
        "agentic-runtime-guard",
        "krivonosoff161",
    ]
    private = lock.entries[6]
    assert private.verification == "sanitized_projection"
    assert private.repository is None
    assert private.source_ref is None
    assert private.source_commit is None
    assert private.source_tree is None


def test_component_lock_rejects_private_git_identity() -> None:
    payload = load_contract(ECOSYSTEM / "components.lock.json")
    assert isinstance(payload, dict)
    payload["entries"][6]["source_commit"] = "0" * 40

    with pytest.raises(ValidationError, match="must not expose private Git identity"):
        ComponentsLock.model_validate(payload)


def test_runtime_guard_public_projection_has_no_private_evidence_markers() -> None:
    projection = ECOSYSTEM / "component-projections" / "agentic-runtime-guard.json"
    payload = ComponentManifest.model_validate(load_contract(projection))
    text = projection.read_text(encoding="utf-8").lower()

    assert payload.repository is None
    assert payload.docs == []
    assert payload.evidence_refs == []
    for marker in ("sealed", "custody", "holdout", "private path", "r5-"):
        assert marker not in text


def test_workflow_public_checkout_pins_match_component_lock() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ecosystem-docs.yml").read_text(
        encoding="utf-8"
    )
    lock = ComponentsLock.model_validate(
        load_contract(ECOSYSTEM / "components.lock.json")
    )

    for entry in lock.entries:
        if (
            entry.verification == "exact_public_git"
            and entry.component_id != "agentic-security-harness"
        ):
            assert entry.repository is not None
            assert entry.source_commit is not None
            assert entry.repository.removeprefix("https://github.com/") in workflow
            assert f"ref: {entry.source_commit}" in workflow

    assert "agentic-runtime-guard" not in workflow
