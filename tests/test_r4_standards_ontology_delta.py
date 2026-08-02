from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DELTA = ROOT / "docs" / "r4-standards-ontology-delta.json"


def delta() -> dict[str, Any]:
    return json.loads(DELTA.read_text(encoding="utf-8"))


def test_r4_delta_covers_exact_owasp_agentic_top_ten() -> None:
    value = delta()
    rows = value["owasp_crosswalk"]
    assert isinstance(rows, list)
    assert [row["external_id"] for row in rows] == [
        f"ASI{index:02d}" for index in range(1, 11)
    ]


def test_r4_delta_keeps_candidate_invariants_out_of_canonical_families() -> None:
    value = delta()
    assert value["new_canonical_family"] is False
    allowed = {f"T{index:02d}" for index in range(1, 27)}
    rows = list(value["owasp_crosswalk"]) + list(value["atlas_2026_07_delta"])
    assert rows
    for row in rows:
        families = row.get("primary_families", row.get("families", []))
        assert families
        assert set(families) <= allowed

    candidates = value["candidate_invariants"]
    assert [candidate["candidate_id"] for candidate in candidates] == ["T27", "T28"]
    assert all(candidate["status"] == "candidate_not_canonical" for candidate in candidates)
    assert {row.get("candidate_invariant") for row in value["owasp_crosswalk"]} - {None} == {
        "T27",
        "T28",
    }


def test_r4_trajectory_contract_separates_candidate_and_evaluator_views() -> None:
    hypothesis = delta()["trajectory_hypothesis"]
    visible = set(hypothesis["candidate_visible_required_fields"])
    evaluator_only = set(hypothesis["evaluator_only_fields"])
    forbidden = set(hypothesis["forbidden_candidate_fields"])

    assert hypothesis["status"] == "contract_extension_required"
    assert visible.isdisjoint(evaluator_only)
    assert visible.isdisjoint(forbidden)
    assert {"effect_occurred", "containment_escaped"} <= evaluator_only
    assert "escape_outcome" in forbidden


def test_r4_delta_is_authority_free_and_pins_primary_sources() -> None:
    value = delta()
    assert value["authority"] == "none"
    sources = {source["id"]: source for source in value["sources"]}
    assert sources["owasp-agentic-top10"]["version"] == "2026"
    assert sources["mitre-atlas"]["version"] == "2026.07"
    assert sources["mitre-atlas"]["url"].endswith("ATLAS-2026.07.yaml")
    assert all(source["url"].startswith("https://") for source in sources.values())


def test_r4_delta_contains_no_machine_paths_or_secret_shaped_fields() -> None:
    text = DELTA.read_text(encoding="utf-8")
    assert "C:\\Users" not in text
    assert "E:\\AI" not in text
    lowered = text.lower()
    for forbidden in ("api_key", "access_token", "client_secret", "password"):
        assert forbidden not in lowered
