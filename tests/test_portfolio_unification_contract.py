from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ONTOLOGY_PATH = ROOT / "docs" / "threat-ontology.md"
ENVELOPE_PATH = ROOT / "docs" / "unified-event-envelope.md"
SCENARIO_REGISTRY_PATH = ROOT / "docs" / "scenario-family-registry.json"


def test_portfolio_artifacts_do_not_embed_machine_paths_or_secrets() -> None:
    artifacts = (
        ROOT / "AGENTS.md",
        SCENARIO_REGISTRY_PATH,
        ONTOLOGY_PATH,
        ENVELOPE_PATH,
    )
    forbidden_paths = (
        "C:\\Users",
        "C:/Users",
        "E:\\AI",
        "E:/AI",
    )
    for artifact in artifacts:
        text = artifact.read_text(encoding="utf-8").lower()
        for marker in forbidden_paths:
            assert marker.lower() not in text
        assert not re.search(
            r"(?im)^\s*[a-z][a-z0-9_]*(?:key|token|secret|password)[a-z0-9_]*\s*=",
            text,
        )


def test_ontology_has_unique_canonical_family_ids() -> None:
    text = ONTOLOGY_PATH.read_text(encoding="utf-8")
    family_ids = re.findall(r"^\| (T\d{2}) \|", text, flags=re.MULTILINE)
    assert family_ids == [f"T{index:02d}" for index in range(1, 27)]
    assert len(family_ids) == len(set(family_ids))


def test_unified_contract_keeps_advisory_non_authoritative() -> None:
    text = ENVELOPE_PATH.read_text(encoding="utf-8")
    required = (
        "operational_authority=none",
        "It cannot independently cause\n`allow`",
        "No conversion among these objects is implicit",
        "Missing lineage or producer attestation cannot be silently filled",
    )
    for phrase in required:
        assert phrase in text


def test_every_baseline_pattern_has_one_primary_family() -> None:
    from agentic_security_harness.corpus import corpus_manifest

    registry = json.loads(SCENARIO_REGISTRY_PATH.read_text(encoding="utf-8"))
    families = registry["families"]
    aliases = [
        alias
        for family in families
        for alias in family["implemented_aliases"] + family["planned_aliases"]
    ]
    baseline_ids = [entry.pattern_id for entry in corpus_manifest()]

    assert len(aliases) == len(set(aliases))
    assert set(baseline_ids).issubset(aliases)
    assert len(baseline_ids) == 24


def test_scenario_registry_matches_ontology_family_ids() -> None:
    registry = json.loads(SCENARIO_REGISTRY_PATH.read_text(encoding="utf-8"))
    family_ids = [family["id"] for family in registry["families"]]
    assert family_ids == [f"T{index:02d}" for index in range(1, 27)]
