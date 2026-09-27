"""Completeness of the question crosswalk, not proof of the questions' answers."""

import json
import re
from pathlib import Path

from agentic_security_harness.patterns import seed_patterns

ROOT = Path(__file__).resolve().parents[1]


def test_all_original_questions_have_owned_falsifiable_evidence_cells() -> None:
    matrix = json.loads((ROOT / "docs/foundation-matrix.json").read_text(encoding="utf-8"))
    catalog = (ROOT / "docs/problem-solution-catalog.md").read_text(encoding="utf-8")
    numbered = [int(value) for value in re.findall(r"^## (\d+)\.", catalog, re.MULTILINE)]
    assert numbered == list(range(1, 18))
    rows = matrix["questions"]
    assert [row["id"] for row in rows] == numbered
    assert set(matrix["components"]) == {
        "core", "transfer", "handoff", "router", "filter", "playbooks"
    }
    pattern_ids = {pattern.pattern_id for pattern in seed_patterns()}
    contract = (ROOT / matrix["contract_document"]).read_text(encoding="utf-8")
    for row in rows:
        assert row["title"] and row["property"] and row["next_question"]
        assert row["owners"] and set(row["owners"]) <= set(matrix["components"])
        assert row["obligations"]
        for obligation in row["obligations"]:
            assert f"## {obligation}." in contract
        assert set(row["pattern_ids"]) <= pattern_ids
        assert row["evidence_class"] in matrix["evidence_classes"]
        for path in row["core_code"] + row["core_tests"]:
            assert not Path(path).is_absolute() and ".." not in Path(path).parts
            assert (ROOT / path).is_file(), path
        if row["evidence_class"] == "planned":
            assert not row["pattern_ids"] and not row["core_code"] and not row["core_tests"]
        else:
            assert row["pattern_ids"] and row["core_code"] and row["core_tests"]
    for component in matrix["components"].values():
        assert re.fullmatch(r"[0-9a-f]{40}", component["source_commit"])
        assert component["repository"].startswith("krivonosoff161/")


def test_human_readable_crosswalk_keeps_every_question_and_residual() -> None:
    matrix = json.loads((ROOT / "docs/foundation-matrix.json").read_text(encoding="utf-8"))
    markdown = (ROOT / "docs/foundation-matrix.md").read_text(encoding="utf-8")
    for row in matrix["questions"]:
        assert f"### {row['id']}. {row['title']}" in markdown
        assert row["property"] in markdown
        assert row["next_question"] in markdown
