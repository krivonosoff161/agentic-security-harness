"""Deterministic document-shape checks never stand in for semantic review."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from agentic_security_harness.document_quality import (
    DocumentRequirements,
    evaluate_document,
)


def _checklist() -> DocumentRequirements:
    return DocumentRequirements.from_record({
        "schema_version": "ash.document-requirements.v1", "mode": "markdown",
        "checklist_items": 2,
        "expected_item_terms": [["Alice", "Friday"], ["Bob", "Tuesday"]],
    })


def test_default_does_not_claim_quality_and_returns_only_hashes() -> None:
    raw = b"A plausible but possibly false statement.\n"
    result = evaluate_document(raw)
    assert result == {"status": "review_required", "reason": "human_review_required",
                      "requirements_sha256": None,
                      "content_sha256": hashlib.sha256(raw).hexdigest(),
                      "authority": "none", "semantics_verified": False}
    assert raw.decode().strip() not in json.dumps(result)


def test_quickstart_copy_with_unclosed_fence_fails() -> None:
    raw = (b"Run these commands:\n```sh\nash document-init --dir demo --model local\n"
           b"ash document-check --config demo/document.json\n")
    assert evaluate_document(raw)["reason"] == "unclosed_fence"
    assert evaluate_document(raw, _checklist())["status"] == "failed"


def test_prose_or_fenced_bullets_are_not_checklist_items() -> None:
    requirements = _checklist()
    prose = b"Alice finishes Friday. Bob finishes Tuesday.\n"
    assert evaluate_document(prose, requirements)["reason"] == "checklist_count_mismatch"
    fenced = b"```md\n- Alice Friday\n- Bob Tuesday\n```\n"
    assert evaluate_document(fenced, requirements)["reason"] == "checklist_count_mismatch"


def test_owner_deadline_terms_must_share_distinct_bullet_lines() -> None:
    requirements = _checklist()
    split = b"- Alice handles the first task; Bob handles the second.\n- Friday then Tuesday.\n"
    assert evaluate_document(split, requirements)["reason"] == "checklist_terms_mismatch"
    repeated = b"- Alice Friday and Bob Tuesday\n- Miscellaneous item\n"
    assert evaluate_document(repeated, requirements)["reason"] == "checklist_terms_mismatch"
    paired = b"- [ ] Alice: send by Friday\n- [x] Bob: review by Tuesday\n"
    result = evaluate_document(paired, requirements)
    assert result["status"] == "checked" and result["reason"] == "declared_checklist_match"
    assert result["semantics_verified"] is False
    assert requirements.record()["expected_item_terms"] == [["Alice", "Friday"],
                                                           ["Bob", "Tuesday"]]
    with pytest.raises(FrozenInstanceError):
        requirements.mode = "exact_json"  # type: ignore[misc]


def test_markdown_structure_only_still_needs_review() -> None:
    requirements = DocumentRequirements(mode="markdown", checklist_items=1)
    result = evaluate_document(b"- An item without declared fact terms\n", requirements)
    assert result["status"] == "review_required"
    assert result["reason"] == "structure_only_review_required"


@pytest.mark.parametrize("raw,reason", [
    (b'{"a":1,"a":1}', "json_invalid"),
    (b'{"a":NaN}', "json_invalid"),
    (b'{"a":Infinity}', "json_invalid"),
    (b'{"a":true}', "json_mismatch"),
    (b'{"a":1.0}', "json_mismatch"),
])
def test_exact_json_strict_values(raw: bytes, reason: str) -> None:
    requirements = DocumentRequirements.from_record({
        "schema_version": "ash.document-requirements.v1", "mode": "exact_json",
        "expected_json": {"a": 1},
    })
    assert evaluate_document(raw, requirements)["reason"] == reason
    assert evaluate_document(b'{"a":1}', requirements)["status"] == "checked"
    assert requirements.record()["expected_json"] == {"a": 1}


def test_unicode_casefold_and_control_rejection() -> None:
    requirements = DocumentRequirements(mode="markdown", checklist_items=1,
                                        expected_item_terms=(("Маша", "пятницу"),))
    result = evaluate_document("- МАША: завершит к ПЯТНИЦУ\n".encode(), requirements)
    assert result["status"] == "checked"
    assert evaluate_document(b"\xff", requirements)["reason"] == "invalid_utf8"
    assert evaluate_document(b"a\x00b", requirements)["reason"] == "control_character"
    assert evaluate_document(b"  \n", requirements)["reason"] == "empty_document"
    assert evaluate_document(b"a" * 16_385, requirements)["reason"] == "document_too_large"


@pytest.mark.parametrize("record", [
    {},
    {"schema_version": "wrong", "mode": "markdown"},
    {"schema_version": "ash.document-requirements.v1", "mode": "markdown",
     "expected_json": {}},
    {"schema_version": "ash.document-requirements.v1", "mode": "markdown",
     "checklist_items": True},
    {"schema_version": "ash.document-requirements.v1", "mode": "markdown",
     "checklist_items": None},
    {"schema_version": "ash.document-requirements.v1", "mode": "markdown",
     "expected_item_terms": None},
    {"schema_version": "ash.document-requirements.v1", "mode": "markdown",
     "checklist_items": 2, "expected_item_terms": [["Alice"]]},
    {"schema_version": "ash.document-requirements.v1", "mode": "exact_json",
     "expected_json": {"n": float("nan")}},
    {"schema_version": "ash.document-requirements.v1", "mode": "exact_json",
     "expected_json": [0] * 257},
])
def test_host_spec_invalid_before_evaluation(record: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="^invalid document requirements$"):
        DocumentRequirements.from_record(record)


def test_expected_json_record_is_copy_and_null_is_valid() -> None:
    expected = {"items": ["first"]}
    requirements = DocumentRequirements(mode="exact_json", expected_json=expected)
    expected["items"].append("second")
    assert requirements.record()["expected_json"] == {"items": ["first"]}
    assert evaluate_document(b'{"items":["first"]}', requirements)["status"] == "checked"
    null_requirement = DocumentRequirements.from_record({
        "schema_version": "ash.document-requirements.v1", "mode": "exact_json",
        "expected_json": None,
    })
    assert evaluate_document(b"null", null_requirement)["status"] == "checked"
