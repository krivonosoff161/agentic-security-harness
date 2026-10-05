"""Bounded, content-free checks of declared document shape and exact JSON values.

These checks never establish factual correctness or grant write authority.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import InitVar, dataclass, field
from typing import Any

_SCHEMA = "ash.document-requirements.v1"
_MAX_DOCUMENT = 16_384
_MAX_SPEC = 8_192
_LIST_ITEM = re.compile(r"^ {0,3}(?:[-*+]|[0-9]{1,3}[.)])\s+(?:\[[ xX]\]\s*)?(.*)$")
_FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


def _invalid_spec() -> ValueError:
    return ValueError("invalid document requirements")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise _invalid_spec() from exc


def _validate_tree(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if depth > 8 or count[0] > 256:
        raise _invalid_spec()
    if value is None or type(value) in {bool, int, str}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise _invalid_spec()
        return
    if type(value) is list:
        for item in value:
            _validate_tree(item, depth + 1, count)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise _invalid_spec()
            _validate_tree(item, depth + 1, count)
        return
    raise _invalid_spec()


@dataclass(frozen=True)
class DocumentRequirements:
    """Host-declared checks; expected JSON is stored as immutable canonical bytes."""

    mode: str
    checklist_items: int | None = None
    expected_item_terms: tuple[tuple[str, ...], ...] | None = None
    expected_json: InitVar[Any] = None
    _expected_json_bytes: bytes | None = field(init=False, repr=False, compare=True)

    def __post_init__(self, expected_json: Any) -> None:
        if self.mode == "exact_json":
            if self.checklist_items is not None or self.expected_item_terms is not None:
                raise _invalid_spec()
            _validate_tree(expected_json)
            object.__setattr__(self, "_expected_json_bytes", _canonical(expected_json))
        elif self.mode == "markdown":
            if expected_json is not None:
                raise _invalid_spec()
            object.__setattr__(self, "_expected_json_bytes", None)
            if self.checklist_items is not None and (
                type(self.checklist_items) is not int or not 1 <= self.checklist_items <= 100
            ):
                raise _invalid_spec()
            terms = self.expected_item_terms
            if terms is not None:
                if (self.checklist_items is None or type(terms) is not tuple
                        or len(terms) != self.checklist_items):
                    raise _invalid_spec()
                for group in terms:
                    if type(group) is not tuple or not 1 <= len(group) <= 8:
                        raise _invalid_spec()
                    if any(type(term) is not str or not 0 < len(term) <= 100
                           or term != term.strip() or any(unicodedata.category(ch) == "Cc"
                                                            for ch in term) for term in group):
                        raise _invalid_spec()
        else:
            raise _invalid_spec()
        if len(_canonical(self.record())) > _MAX_SPEC:
            raise _invalid_spec()

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> DocumentRequirements:
        if type(record) is not dict or record.get("schema_version") != _SCHEMA:
            raise _invalid_spec()
        mode = record.get("mode")
        if mode == "exact_json":
            if set(record) != {"schema_version", "mode", "expected_json"}:
                raise _invalid_spec()
            return cls(mode="exact_json", expected_json=record["expected_json"])
        if mode == "markdown":
            if set(record) - {"schema_version", "mode", "checklist_items",
                              "expected_item_terms"}:
                raise _invalid_spec()
            if "checklist_items" in record and type(record["checklist_items"]) is not int:
                raise _invalid_spec()
            terms = record.get("expected_item_terms")
            if "expected_item_terms" in record and terms is None:
                raise _invalid_spec()
            if terms is not None:
                if type(terms) is not list or any(type(group) is not list for group in terms):
                    raise _invalid_spec()
                terms = tuple(tuple(group) for group in terms)
            return cls(mode="markdown", checklist_items=record.get("checklist_items"),
                       expected_item_terms=terms)
        raise _invalid_spec()

    def record(self) -> dict[str, Any]:
        value: dict[str, Any] = {"schema_version": _SCHEMA, "mode": self.mode}
        if self.mode == "exact_json":
            assert self._expected_json_bytes is not None
            value["expected_json"] = json.loads(self._expected_json_bytes)
        else:
            if self.checklist_items is not None:
                value["checklist_items"] = self.checklist_items
            if self.expected_item_terms is not None:
                value["expected_item_terms"] = [list(group) for group in self.expected_item_terms]
        return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _nonfinite(_: str) -> Any:
    raise ValueError("nonfinite JSON number")


def _outside_fences(text: str) -> tuple[list[str], bool]:
    outside: list[str] = []
    marker = ""
    length = 0
    for line in text.splitlines():
        opening = _FENCE_OPEN.match(line)
        if marker:
            if opening and opening.group(1)[0] == marker and len(opening.group(1)) >= length \
                    and not opening.group(2).strip():
                marker = ""
            continue
        if opening:
            marker = opening.group(1)[0]
            length = len(opening.group(1))
        else:
            outside.append(line)
    return outside, bool(marker)


def _terms_match(items: list[str], groups: tuple[tuple[str, ...], ...]) -> bool:
    edges: list[list[int]] = []
    for group in groups:
        edges.append([i for i, item in enumerate(items) if all(
            re.search(r"(?<!\w)" + re.escape(term.casefold()) + r"(?!\w)",
                      item.casefold()) is not None for term in group)])
    assigned: dict[int, int] = {}

    def assign(group: int, seen: set[int]) -> bool:
        for item in edges[group]:
            if item in seen:
                continue
            seen.add(item)
            if item not in assigned or assign(assigned[item], seen):
                assigned[item] = group
                return True
        return False

    return all(assign(group, set()) for group in range(len(groups)))


def evaluate_document(
    raw: bytes, requirements: DocumentRequirements | None = None
) -> dict[str, Any]:
    """Check bytes without returning document text or claiming semantic truth."""
    if type(raw) is not bytes or (requirements is not None
                                  and type(requirements) is not DocumentRequirements):
        raise ValueError("invalid document evaluation input")
    result: dict[str, Any] = {
        "status": "review_required", "reason": "human_review_required",
        "requirements_sha256": hashlib.sha256(_canonical(requirements.record())).hexdigest()
        if requirements is not None else None,
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "authority": "none", "semantics_verified": False,
    }

    def outcome(status: str, reason: str) -> dict[str, Any]:
        return {**result, "status": status, "reason": reason}

    if len(raw) > _MAX_DOCUMENT:
        return outcome("failed", "document_too_large")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return outcome("failed", "invalid_utf8")
    if not text.strip():
        return outcome("failed", "empty_document")
    if any(unicodedata.category(ch) == "Cc" and ch not in "\t\n\r" for ch in text):
        return outcome("failed", "control_character")
    if requirements is not None and requirements.mode == "exact_json":
        try:
            actual = json.loads(text, object_pairs_hook=_pairs, parse_constant=_nonfinite)
            _validate_tree(actual)
            actual_bytes = _canonical(actual)
        except (ValueError, TypeError, RecursionError):
            return outcome("failed", "json_invalid")
        if actual_bytes != requirements._expected_json_bytes:
            return outcome("failed", "json_mismatch")
        return outcome("checked", "declared_json_match")
    lines, incomplete = _outside_fences(text)
    if incomplete:
        return outcome("failed", "unclosed_fence")
    if requirements is None or requirements.checklist_items is None:
        return result
    items = [match.group(1) for line in lines if (match := _LIST_ITEM.match(line))]
    if len(items) != requirements.checklist_items:
        return outcome("failed", "checklist_count_mismatch")
    if requirements.expected_item_terms is None:
        return outcome("review_required", "structure_only_review_required")
    if not _terms_match(items, requirements.expected_item_terms):
        return outcome("failed", "checklist_terms_mismatch")
    return outcome("checked", "declared_checklist_match")
