"""Host-declared source restrictions for one local document-generation boundary.

This content-free value binds labels to bytes and the original timestamp. It
does not authenticate the host, classify content, or grant write authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from agentic_security_harness.models import DataEnvelope

if TYPE_CHECKING:
    from agentic_security_harness.document_multisource import DocumentMultiSourceRestrictions

_VERSION = "ash.document-source-restrictions.v1"
_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z", re.ASCII)
_ENVELOPE_FIELDS = frozenset({
    "data_class", "allowed_recipients", "allowed_purpose", "can_store",
    "can_forward", "ttl_seconds", "requires_confirmation",
    "classification_source", "classification_mutable",
})
_RECORD_FIELDS = frozenset({"schema_version", "content_sha256", "created_at", "envelope"})
_MAX_CONTENT_BYTES = 65_536
_MAX_LIST_ITEMS = 16
_MAX_TTL_SECONDS = 31_536_000


def _content_digest(content: bytes) -> str:
    if type(content) is not bytes or len(content) > _MAX_CONTENT_BYTES:
        raise ValueError("bounded content bytes required")
    return hashlib.sha256(content).hexdigest()


def _token(value: object) -> bool:
    return type(value) is str and _TOKEN.fullmatch(value) is not None


def _token_list(value: object) -> bool:
    return (type(value) is list and len(value) <= _MAX_LIST_ITEMS
            and all(_token(item) for item in value) and len(set(value)) == len(value))


def _envelope_record(value: object) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _ENVELOPE_FIELDS:
        raise ValueError("closed DataEnvelope fields required")
    if not _token(value["data_class"]) or not _token(value["classification_source"]):
        raise ValueError("bounded class and source labels required")
    if not _token_list(value["allowed_recipients"]) or not _token_list(value["allowed_purpose"]):
        raise ValueError("bounded unique recipient and purpose labels required")
    for key in ("can_store", "can_forward", "requires_confirmation", "classification_mutable"):
        if type(value[key]) is not bool:
            raise ValueError("strict boolean restrictions required")
    ttl = value["ttl_seconds"]
    if ttl is not None and (type(ttl) is not int or not 0 <= ttl <= _MAX_TTL_SECONDS):
        raise ValueError("bounded nonnegative integer ttl required")
    # Validate through the existing public label type, then copy every mutable list.
    DataEnvelope.model_validate(value)
    return {**value, "allowed_recipients": list(value["allowed_recipients"]),
            "allowed_purpose": list(value["allowed_purpose"])}


def _utc_time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("aware origin time required")
    result = value.astimezone(UTC)
    if result > datetime.now(UTC):
        raise ValueError("future origin time rejected")
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class DocumentSourceRestrictions:
    """Immutable host snapshot; derived output keeps the source's original epoch."""

    _content_sha256: str
    _envelope_bytes: bytes
    _created_at: datetime

    def __post_init__(self) -> None:
        if type(self._content_sha256) is not str or _DIGEST.fullmatch(self._content_sha256) is None:
            raise ValueError("content digest required")
        if type(self._envelope_bytes) is not bytes or len(self._envelope_bytes) > 4096:
            raise ValueError("bounded canonical envelope required")
        try:
            parsed = json.loads(self._envelope_bytes)
        except (UnicodeError, ValueError) as exc:
            raise ValueError("canonical envelope required") from exc
        if _canonical(_envelope_record(parsed)) != self._envelope_bytes:
            raise ValueError("canonical envelope required")
        object.__setattr__(self, "_created_at", _utc_time(self._created_at))

    @classmethod
    def bind(
        cls, content: bytes, envelope: DataEnvelope, *, created_at: datetime,
    ) -> DocumentSourceRestrictions:
        if type(envelope) is not DataEnvelope:
            raise ValueError("DataEnvelope required")
        fields = {key: getattr(envelope, key) for key in _ENVELOPE_FIELDS}
        snapshot = _envelope_record(fields)
        return cls(_content_digest(content), _canonical(snapshot), _utc_time(created_at))

    @classmethod
    def from_record(cls, value: object) -> DocumentSourceRestrictions:
        if type(value) is not dict or set(value) != _RECORD_FIELDS:
            raise ValueError("closed restrictions record required")
        if value["schema_version"] != _VERSION:
            raise ValueError("unsupported restrictions version")
        digest = value["content_sha256"]
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise ValueError("content digest required")
        timestamp = value["created_at"]
        if type(timestamp) is not str or _TIMESTAMP.fullmatch(timestamp) is None:
            raise ValueError("canonical UTC timestamp required")
        try:
            origin = datetime.fromisoformat(timestamp[:-1] + "+00:00")
        except ValueError as exc:
            raise ValueError("valid UTC timestamp required") from exc
        if origin.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != timestamp:
            raise ValueError("canonical UTC timestamp required")
        snapshot = _envelope_record(value["envelope"])
        return cls(digest, _canonical(snapshot), _utc_time(origin))

    def record(self) -> dict[str, Any]:
        return {
            "schema_version": _VERSION,
            "content_sha256": self._content_sha256,
            "created_at": self._created_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "envelope": json.loads(self._envelope_bytes),
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(b"ash-document-source-restrictions-v1\0"
                              + _canonical(self.record())).hexdigest()

    @property
    def data_class(self) -> str:
        return str(json.loads(self._envelope_bytes)["data_class"])

    def for_output(self, content: bytes) -> DocumentSourceRestrictions:
        return type(self)(_content_digest(content), self._envelope_bytes, self._created_at)

    @property
    def expires_at(self) -> datetime | None:
        ttl = json.loads(self._envelope_bytes)["ttl_seconds"]
        return self._created_at + timedelta(seconds=ttl) if ttl is not None else None

    def admission_reason(
        self, content: bytes, *, data_class: str, now: datetime,
    ) -> str | None:
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            return "source_clock_invalid"
        current = now.astimezone(UTC)
        if current < self._created_at:
            return "source_clock_invalid"
        if type(content) is not bytes or len(content) > _MAX_CONTENT_BYTES:
            return "source_digest_mismatch"
        if hashlib.sha256(content).hexdigest() != self._content_sha256:
            return "source_digest_mismatch"
        envelope = json.loads(self._envelope_bytes)
        if type(data_class) is not str or data_class != envelope["data_class"]:
            return "source_class_mismatch"
        if not envelope["can_store"]:
            return "source_storage_forbidden"
        if not envelope["can_forward"]:
            return "source_forwarding_forbidden"
        if "local-model" not in envelope["allowed_recipients"]:
            return "source_recipient_forbidden"
        if "document-generation" not in envelope["allowed_purpose"]:
            return "source_purpose_forbidden"
        if envelope["requires_confirmation"]:
            return "source_confirmation_required"
        ttl = envelope["ttl_seconds"]
        if ttl is not None and current >= self._created_at + timedelta(seconds=ttl):
            return "source_expired"
        return None


def parse_source_restrictions(
    value: object,
) -> DocumentSourceRestrictions | DocumentMultiSourceRestrictions:
    """Parse only the two closed, host-owned document restriction records."""
    from agentic_security_harness.document_multisource import DocumentMultiSourceRestrictions

    if type(value) is not dict:
        raise ValueError("closed source restrictions record required")
    schema = value.get("schema_version")
    if schema == _VERSION:
        return DocumentSourceRestrictions.from_record(value)
    if schema == "ash.document-multisource-restrictions.v1":
        return DocumentMultiSourceRestrictions.from_record(value)
    raise ValueError("unsupported source restrictions version")
