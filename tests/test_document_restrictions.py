"""Source restrictions are immutable host labels, not model-provided authority."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.models import DataEnvelope

ORIGIN = datetime(2026, 1, 1, tzinfo=UTC)
CONTENT = b"Host-selected source text."


def _envelope(**changes: Any) -> DataEnvelope:
    fields: dict[str, Any] = {
        "data_class": "private", "allowed_recipients": ["local-model"],
        "allowed_purpose": ["document-generation"], "can_store": True,
        "can_forward": True, "ttl_seconds": 60, "requires_confirmation": False,
        "classification_source": "host", "classification_mutable": False,
    }
    return DataEnvelope(**(fields | changes))


def _bound(**changes: Any) -> DocumentSourceRestrictions:
    return DocumentSourceRestrictions.bind(CONTENT, _envelope(**changes), created_at=ORIGIN)


def test_benign_admission_roundtrip_and_content_free_record() -> None:
    bound = _bound()
    assert bound.admission_reason(CONTENT, data_class="private", now=ORIGIN) is None
    record = bound.record()
    assert CONTENT.decode() not in str(record)
    restored = DocumentSourceRestrictions.from_record(record)
    assert restored == bound and restored.sha256 == bound.sha256
    assert record["created_at"] == "2026-01-01T00:00:00.000000Z"


def test_deep_snapshot_survives_caller_and_record_mutation() -> None:
    envelope = _envelope()
    bound = DocumentSourceRestrictions.bind(CONTENT, envelope, created_at=ORIGIN)
    envelope.allowed_recipients.clear()
    envelope.allowed_purpose.append("other")
    envelope.data_class = "sanitized"
    record = bound.record()
    record["envelope"]["allowed_recipients"].clear()
    assert bound.record()["envelope"]["allowed_recipients"] == ["local-model"]
    assert bound.admission_reason(CONTENT, data_class="private", now=ORIGIN) is None
    with pytest.raises(FrozenInstanceError):
        bound._content_sha256 = "0" * 64  # type: ignore[misc]


@pytest.mark.parametrize(("change", "reason"), [
    ({"can_store": False}, "source_storage_forbidden"),
    ({"can_forward": False}, "source_forwarding_forbidden"),
    ({"allowed_recipients": []}, "source_recipient_forbidden"),
    ({"allowed_recipients": ["another-model"]}, "source_recipient_forbidden"),
    ({"allowed_purpose": []}, "source_purpose_forbidden"),
    ({"allowed_purpose": ["other"]}, "source_purpose_forbidden"),
    ({"requires_confirmation": True}, "source_confirmation_required"),
])
def test_denied_restrictions(change: dict[str, Any], reason: str) -> None:
    assert _bound(**change).admission_reason(
        CONTENT, data_class="private", now=ORIGIN,
    ) == reason


def test_digest_and_class_are_exact_not_ranked() -> None:
    bound = _bound()
    assert bound.admission_reason(b"changed", data_class="private", now=ORIGIN) == (
        "source_digest_mismatch"
    )
    assert bound.admission_reason(CONTENT, data_class="sanitized", now=ORIGIN) == (
        "source_class_mismatch"
    )
    assert _bound(data_class="sanitized").admission_reason(
        CONTENT, data_class="private", now=ORIGIN,
    ) == "source_class_mismatch"


def test_original_deadline_survives_repeated_output_derivation() -> None:
    source = _bound()
    first = source.for_output(b"first result")
    second = first.for_output(b"second result")
    for item, content in ((source, CONTENT), (first, b"first result"),
                          (second, b"second result")):
        assert item.record()["created_at"] == source.record()["created_at"]
        assert item.record()["envelope"] == source.record()["envelope"]
        assert item.admission_reason(
            content, data_class="private", now=ORIGIN + timedelta(seconds=59),
        ) is None
        assert item.admission_reason(
            content, data_class="private", now=ORIGIN + timedelta(seconds=60),
        ) == (
            "source_expired"
        )
    assert first.sha256 != source.sha256 != second.sha256


def test_unlimited_ttl_and_aware_utc_normalization() -> None:
    local_time = ORIGIN.astimezone(timezone(timedelta(hours=3)))
    bound = DocumentSourceRestrictions.bind(
        CONTENT, _envelope(ttl_seconds=None), created_at=local_time,
    )
    assert bound.record()["created_at"] == "2026-01-01T00:00:00.000000Z"
    assert bound.admission_reason(
        CONTENT, data_class="private", now=ORIGIN + timedelta(days=365),
    ) is None


def test_direct_constructor_normalizes_offset_time_before_z_record() -> None:
    bound = _bound()
    offset_time = ORIGIN.astimezone(timezone(timedelta(hours=3)))
    direct = DocumentSourceRestrictions(
        bound.record()["content_sha256"], bound._envelope_bytes, offset_time,
    )
    assert direct.record()["created_at"] == "2026-01-01T00:00:00.000000Z"
    assert direct == bound
    assert DocumentSourceRestrictions.from_record(direct.record()) == bound
    assert direct.admission_reason(CONTENT, data_class="private", now=ORIGIN) is None


@pytest.mark.parametrize("now", [ORIGIN - timedelta(microseconds=1),
                                  datetime(2026, 1, 1), None, "2026-01-01"])
def test_invalid_or_rolled_back_clock_denied(now: object) -> None:
    assert _bound().admission_reason(
        CONTENT, data_class="private", now=now,  # type: ignore[arg-type]
    ) == "source_clock_invalid"


@pytest.mark.parametrize("origin", [datetime(2026, 1, 1), datetime(2999, 1, 1, tzinfo=UTC)])
def test_naive_or_future_origin_rejected(origin: datetime) -> None:
    with pytest.raises(ValueError):
        DocumentSourceRestrictions.bind(CONTENT, _envelope(), created_at=origin)


@pytest.mark.parametrize(("field", "invalid"), [
    ("can_store", 1), ("can_forward", "true"), ("requires_confirmation", 0),
    ("classification_mutable", None), ("ttl_seconds", -1),
    ("ttl_seconds", True), ("ttl_seconds", 1.0), ("ttl_seconds", float("nan")),
    ("allowed_recipients", ["local-model", "local-model"]),
    ("allowed_purpose", ["document-generation\x00"]),
    ("classification_source", "host\x00"),
])
def test_record_rejects_bad_envelope_types_and_tokens(field: str, invalid: object) -> None:
    record = _bound().record()
    record["envelope"][field] = invalid
    with pytest.raises(ValueError):
        DocumentSourceRestrictions.from_record(record)


@pytest.mark.parametrize(("field", "invalid"), [
    ("schema_version", "other"), ("content_sha256", "bad"),
    ("created_at", "2026-01-01T00:00:00Z"),
    ("created_at", "2026-01-01T00:00:00.000000+00:00"),
    ("created_at", "2026-01-01T00:00:00.000000Z\x00"),
    ("created_at", "2999-01-01T00:00:00.000000Z"),
    ("created_at", float("nan")),
])
def test_record_rejects_invalid_outer_fields(field: str, invalid: object) -> None:
    record = _bound().record()
    record[field] = invalid
    with pytest.raises(ValueError):
        DocumentSourceRestrictions.from_record(record)


def test_record_rejects_extras_and_non_records() -> None:
    record = _bound().record()
    record["authority"] = "owner"
    with pytest.raises(ValueError):
        DocumentSourceRestrictions.from_record(record)
    record.pop("authority")
    record["envelope"]["authority"] = "owner"
    with pytest.raises(ValueError):
        DocumentSourceRestrictions.from_record(record)
    values: tuple[object, ...] = (None, [], "claim", 1)
    for value in values:
        with pytest.raises(ValueError):
            DocumentSourceRestrictions.from_record(value)


def test_content_type_and_limit_fail_closed() -> None:
    with pytest.raises(ValueError):
        DocumentSourceRestrictions.bind("text", _envelope(), created_at=ORIGIN)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _bound().for_output(b"x" * 65_537)
    assert _bound().admission_reason(
        "text", data_class="private", now=ORIGIN,  # type: ignore[arg-type]
    ) == "source_digest_mismatch"
