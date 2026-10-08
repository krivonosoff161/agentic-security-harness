"""Finite multi-source document bindings preserve original bytes and deadlines."""

from __future__ import annotations

import copy
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from agentic_security_harness.document_multisource import DocumentMultiSourceRestrictions
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.models import DataEnvelope

ORIGIN = datetime(2026, 10, 1, tzinfo=UTC)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _binding(
    content: bytes, *, origin: datetime = ORIGIN, ttl: int | None = None,
    data_class: str = "private", classification_source: str = "host-config",
    recipients: list[str] | None = None, purposes: list[str] | None = None,
    can_store: bool = True, can_forward: bool = True,
    requires_confirmation: bool = False,
) -> DocumentSourceRestrictions:
    return DocumentSourceRestrictions.bind(content, DataEnvelope(
        data_class=data_class,
        allowed_recipients=["local-model"] if recipients is None else recipients,
        allowed_purpose=["document-generation"] if purposes is None else purposes,
        can_store=can_store, can_forward=can_forward, ttl_seconds=ttl,
        requires_confirmation=requires_confirmation,
        classification_source=classification_source, classification_mutable=False,
    ), created_at=origin)


def _pair(
    first: DocumentSourceRestrictions | None = None,
    second: DocumentSourceRestrictions | None = None,
) -> tuple[bytes, DocumentMultiSourceRestrictions]:
    a, b = b"first", b"second"
    return DocumentMultiSourceRestrictions.compose((
        ("one", a, first or _binding(a)),
        ("two", b, second or _binding(b)),
    ))


def test_exact_framed_bytes_roundtrip_snapshot_and_rebound_output() -> None:
    content, binding = _pair()
    assert b'"id":"one"' in content and b'"text":"first"' in content
    assert binding.admission_reason(content, data_class="private", now=ORIGIN) is None
    record = binding.record()
    assert record["content_sha256"] == _sha(content)
    assert record["assembly_sha256"] == _sha(content)
    assert [row["source_id"] for row in record["leaves"]] == ["one", "two"]
    assert [row["restrictions"]["content_sha256"] for row in record["leaves"]] == [
        _sha(b"first"), _sha(b"second"),
    ]
    restored = DocumentMultiSourceRestrictions.from_record(record)
    assert restored == binding and restored.sha256 == binding.sha256
    record["leaves"][0]["restrictions"]["envelope"]["can_forward"] = False
    assert binding.record()["leaves"][0]["restrictions"]["envelope"]["can_forward"] is True

    output = b"derived exact bytes"
    rebound = binding.for_output(output)
    assert rebound.record()["content_sha256"] == _sha(output)
    assert rebound.record()["assembly_sha256"] == _sha(content)
    assert rebound.record()["leaves"] == binding.record()["leaves"]
    assert rebound.admission_reason(content, data_class="private", now=ORIGIN) == (
        "source_digest_mismatch"
    )
    assert rebound.admission_reason(output, data_class="private", now=ORIGIN) is None


def test_different_origins_expire_at_earliest_subsecond_deadline() -> None:
    first = _binding(b"first", origin=ORIGIN, ttl=1)
    second = _binding(b"second", origin=ORIGIN + timedelta(microseconds=750_000), ttl=1)
    content, combined = _pair(first, second)
    assert combined.expires_at == ORIGIN + timedelta(seconds=1)
    assert combined.admission_reason(
        content, data_class="private", now=ORIGIN + timedelta(microseconds=999_999),
    ) is None
    assert combined.admission_reason(
        content, data_class="private", now=ORIGIN + timedelta(seconds=1),
    ) == "source_expired"
    assert combined.for_output(b"output").expires_at == combined.expires_at
    assert combined.admission_reason(content, data_class="private", now=ORIGIN) == (
        "source_clock_invalid"
    )
    with pytest.raises(ValueError, match="future origin"):
        _binding(b"future", origin=datetime.now(UTC) + timedelta(seconds=10), ttl=1)


def test_no_ttl_cannot_extend_finite_deadline() -> None:
    finite = _binding(b"first", ttl=2)
    unlimited = _binding(b"second", ttl=None)
    content, combined = _pair(finite, unlimited)
    assert combined.expires_at == ORIGIN + timedelta(seconds=2)
    assert combined.admission_reason(content, data_class="private", now=ORIGIN +
                                     timedelta(seconds=2)) == "source_expired"
    assert _pair()[1].expires_at is None


@pytest.mark.parametrize("field,expected", [
    ("recipients", "source_recipient_forbidden"),
    ("purposes", "source_purpose_forbidden"),
    ("can_store", "source_storage_forbidden"),
    ("can_forward", "source_forwarding_forbidden"),
    ("requires_confirmation", "source_confirmation_required"),
])
def test_meet_cannot_grant_permission(field: str, expected: str) -> None:
    changes: dict[str, Any] = {
        "recipients": [], "purposes": [], "can_store": False,
        "can_forward": False, "requires_confirmation": True,
    }
    second = _binding(b"second", **{field: changes[field]})
    content, combined = _pair(second=second)
    assert combined.admission_reason(content, data_class="private", now=ORIGIN) == expected


@pytest.mark.parametrize("field,value", [
    ("data_class", "sanitized"),
    ("data_class", "internal"),
    ("classification_source", "model-output"),
])
def test_incomparable_class_or_source_conflicts(field: str, value: str) -> None:
    second = (_binding(b"second", data_class=value) if field == "data_class"
              else _binding(b"second", classification_source=value))
    with pytest.raises(ValueError, match="class or classification source conflict"):
        _pair(second=second)


def test_recomposition_keeps_original_leaves_and_deadline() -> None:
    first = _binding(b"first", ttl=1)
    second = _binding(b"second", ttl=3)
    content, combined = _pair(first, second)
    derived = combined.for_output(b"derived")
    third = _binding(b"third", origin=ORIGIN + timedelta(microseconds=500_000), ttl=4)
    recomposed_content, recomposed = DocumentMultiSourceRestrictions.compose((
        ("prior", b"derived", derived),
        ("third", b"third", third),
    ))
    assert recomposed.expires_at == ORIGIN + timedelta(seconds=1)
    assert [row["source_id"] for row in recomposed.record()["leaves"]] == [
        "one", "third", "two",
    ]
    assert recomposed.record()["components"][0]["binding_sha256"] == derived.sha256
    assert recomposed.admission_reason(
        recomposed_content, data_class="private", now=ORIGIN + timedelta(seconds=1),
    ) == "source_expired"
    assert len(content) != len(recomposed_content)


def test_duplicate_source_id_with_different_original_bytes_rejects() -> None:
    first = _binding(b"first")
    changed = _binding(b"changed")
    old_bytes, old = DocumentMultiSourceRestrictions.compose((("same", b"first", first),))
    new_bytes, new = DocumentMultiSourceRestrictions.compose((("same", b"changed", changed),))
    with pytest.raises(ValueError, match="source ID conflicts"):
        DocumentMultiSourceRestrictions.compose((
            ("old_component", old_bytes, old), ("new_component", new_bytes, new),
        ))


def test_identical_source_id_and_binding_coalesce_but_changed_policy_conflicts() -> None:
    original = b"same original source"
    leaf = _binding(original, ttl=4)
    content, bound = DocumentMultiSourceRestrictions.compose((("shared", original, leaf),))
    combined_bytes, combined = DocumentMultiSourceRestrictions.compose((
        ("left", content, bound), ("right", content, bound),
    ))
    record = combined.record()
    assert [row["source_id"] for row in record["leaves"]] == ["shared"]
    assert [row["component_id"] for row in record["components"]] == ["left", "right"]
    assert all(row["source_ids"] == ["shared"] for row in record["components"])
    assert combined.expires_at == bound.expires_at
    assert combined.admission_reason(
        combined_bytes, data_class="private", now=ORIGIN,
    ) is None
    # A matching ID is an alias only for the same original restriction record.
    changed = _binding(original, ttl=2)
    changed_bytes, changed_bound = DocumentMultiSourceRestrictions.compose((
        ("shared", original, changed),
    ))
    with pytest.raises(ValueError, match="source ID conflicts"):
        DocumentMultiSourceRestrictions.compose((
            ("left", content, bound), ("right", changed_bytes, changed_bound),
        ))


def test_bounds_and_wrong_current_bytes_refuse() -> None:
    parts = tuple((f"s{index}", b"x", _binding(b"x")) for index in range(9))
    with pytest.raises(ValueError, match="bounded immutable"):
        DocumentMultiSourceRestrictions.compose(parts)
    large = b"x" * 9000
    with pytest.raises(ValueError, match="assembled document byte limit"):
        DocumentMultiSourceRestrictions.compose((
            ("one", large, _binding(large)), ("two", large, _binding(large)),
        ))
    with pytest.raises(ValueError, match="UTF-8 source"):
        DocumentMultiSourceRestrictions.compose((("one", b"\xff", _binding(b"\xff")),))
    with pytest.raises(ValueError, match="source digest"):
        DocumentMultiSourceRestrictions.compose((("one", b"wrong", _binding(b"right")),))
    content, binding = _pair()
    assert binding.admission_reason(content + b"!", data_class="private", now=ORIGIN) == (
        "source_digest_mismatch"
    )
    assert binding.admission_reason(content, data_class="public", now=ORIGIN) == (
        "source_class_mismatch"
    )
    with pytest.raises(ValueError, match="bounded output"):
        binding.for_output(b"x" * 16385)


@pytest.mark.parametrize("change", [
    "extra", "missing", "bad_digest", "bool_length", "duplicate_leaf",
    "unknown_component_leaf", "future_origin", "mixed_class",
])
def test_closed_record_refuses_hostile_fields(change: str) -> None:
    _, binding = _pair()
    record = copy.deepcopy(binding.record())
    if change == "extra":
        record["authority"] = "model"
    elif change == "missing":
        del record["assembly_sha256"]
    elif change == "bad_digest":
        record["content_sha256"] = "not-a-digest"
    elif change == "bool_length":
        record["content_length"] = True
    elif change == "duplicate_leaf":
        record["leaves"][1]["source_id"] = "one"
    elif change == "unknown_component_leaf":
        record["components"][1]["source_ids"] = ["phantom"]
    elif change == "future_origin":
        record["leaves"][0]["restrictions"]["created_at"] = "9999-01-01T00:00:00.000000Z"
    else:
        record["leaves"][1]["restrictions"]["envelope"]["data_class"] = "sanitized"
    with pytest.raises(ValueError):
        DocumentMultiSourceRestrictions.from_record(record)
