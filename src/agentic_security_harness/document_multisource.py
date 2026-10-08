"""Bounded multi-source document labels with original byte and time provenance.

The host chooses sources and uses the returned assembled bytes. Records contain
hashes and labels, not source text; they do not authenticate a hostile host or
make model-visible framing an instruction boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from agentic_security_harness.document_restrictions import DocumentSourceRestrictions

_VERSION = "ash.document-multisource-restrictions.v1"
_ID = re.compile(r"[a-z][a-z0-9_-]{0,47}\Z", re.ASCII)
_SHA = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_FIELDS = frozenset({
    "schema_version", "content_sha256", "content_length", "assembly_sha256",
    "assembly_length", "leaves", "components",
})
_LEAF_FIELDS = frozenset({"source_id", "restrictions"})
_COMPONENT_FIELDS = frozenset({
    "component_id", "content_sha256", "content_length", "binding_sha256", "source_ids",
})
_MAX_PARTS = 8
_MAX_CONTENT = 16_384
_MAX_RECORD = 8_192


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":")).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _digest(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _size(value: object, *, positive: bool = False) -> bool:
    return type(value) is int and (0 < value <= _MAX_CONTENT if positive
                                    else 0 <= value <= _MAX_CONTENT)


def _merged(leaves: list[dict[str, Any]]) -> tuple[dict[str, Any], datetime | None]:
    restrictions = [DocumentSourceRestrictions.from_record(row["restrictions"])
                    for row in leaves]
    envelopes = [item.record()["envelope"] for item in restrictions]
    first = envelopes[0]
    if any(item["data_class"] != first["data_class"]
           or item["classification_source"] != first["classification_source"]
           for item in envelopes[1:]):
        raise ValueError("source class or classification source conflict")
    recipients = set(first["allowed_recipients"])
    purposes = set(first["allowed_purpose"])
    for item in envelopes[1:]:
        recipients.intersection_update(item["allowed_recipients"])
        purposes.intersection_update(item["allowed_purpose"])
    finite = [item.expires_at for item in restrictions if item.expires_at is not None]
    policy = {
        "data_class": first["data_class"],
        "classification_source": first["classification_source"],
        "allowed_recipients": recipients,
        "allowed_purpose": purposes,
        "can_store": all(item["can_store"] for item in envelopes),
        "can_forward": all(item["can_forward"] for item in envelopes),
        "requires_confirmation": any(item["requires_confirmation"] for item in envelopes),
        "classification_mutable": all(item["classification_mutable"]
                                      for item in envelopes),
    }
    return policy, min(finite) if finite else None


def _checked_record(value: object) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _FIELDS or value["schema_version"] != _VERSION:
        raise ValueError("closed multi-source record required")
    if (not _digest(value["content_sha256"])
            or not _size(value["content_length"])
            or not _digest(value["assembly_sha256"])
            or not _size(value["assembly_length"], positive=True)):
        raise ValueError("bounded multi-source content binding required")
    leaves = value["leaves"]
    components = value["components"]
    if (type(leaves) is not list or not 1 <= len(leaves) <= _MAX_PARTS
            or type(components) is not list or not 1 <= len(components) <= _MAX_PARTS):
        raise ValueError("bounded source leaves and components required")
    leaf_ids: list[str] = []
    checked_leaves: list[dict[str, Any]] = []
    for row in leaves:
        if type(row) is not dict or set(row) != _LEAF_FIELDS or not _id(row["source_id"]):
            raise ValueError("closed original source leaf required")
        restriction = DocumentSourceRestrictions.from_record(row["restrictions"])
        leaf_ids.append(row["source_id"])
        checked_leaves.append({"source_id": row["source_id"],
                               "restrictions": restriction.record()})
    if leaf_ids != sorted(set(leaf_ids)):
        raise ValueError("unique sorted original source IDs required")
    _merged(checked_leaves)  # Reject incomparable labels before accepting a record.
    component_ids: set[str] = set()
    referenced: set[str] = set()
    checked_components: list[dict[str, Any]] = []
    for row in components:
        if (type(row) is not dict or set(row) != _COMPONENT_FIELDS
                or not _id(row["component_id"]) or row["component_id"] in component_ids
                or not _digest(row["content_sha256"])
                or not _size(row["content_length"])
                or not _digest(row["binding_sha256"])):
            raise ValueError("closed source component required")
        source_ids = row["source_ids"]
        if (type(source_ids) is not list or not 1 <= len(source_ids) <= _MAX_PARTS
                or any(not _id(item) for item in source_ids)
                or source_ids != sorted(set(source_ids))):
            raise ValueError("bounded component source IDs required")
        component_ids.add(row["component_id"])
        referenced.update(source_ids)
        checked_components.append(dict(row))
    if referenced != set(leaf_ids):
        raise ValueError("components do not cover original leaves")
    result = {
        "schema_version": _VERSION,
        "content_sha256": value["content_sha256"],
        "content_length": value["content_length"],
        "assembly_sha256": value["assembly_sha256"],
        "assembly_length": value["assembly_length"],
        "leaves": checked_leaves,
        "components": checked_components,
    }
    if len(_canonical(result)) > _MAX_RECORD:
        raise ValueError("multi-source record size limit")
    return result


@dataclass(frozen=True)
class DocumentMultiSourceRestrictions:
    """Immutable digest-bound current bytes and retained original leaf records."""

    _record_bytes: bytes

    def __post_init__(self) -> None:
        if type(self._record_bytes) is not bytes or len(self._record_bytes) > _MAX_RECORD:
            raise ValueError("bounded canonical multi-source record required")
        try:
            parsed = json.loads(self._record_bytes)
            checked = _checked_record(parsed)
        except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
            raise ValueError("canonical multi-source record required") from exc
        if _canonical(checked) != self._record_bytes:
            raise ValueError("canonical multi-source record required")

    @classmethod
    def from_record(cls, value: object) -> DocumentMultiSourceRestrictions:
        return cls(_canonical(_checked_record(value)))

    @classmethod
    def compose(
        cls,
        parts: tuple[
            tuple[str, bytes, DocumentSourceRestrictions | DocumentMultiSourceRestrictions], ...
        ],
    ) -> tuple[bytes, DocumentMultiSourceRestrictions]:
        """Frame exact host-selected UTF-8 parts and bind the returned bytes."""
        if type(parts) is not tuple or not 1 <= len(parts) <= _MAX_PARTS:
            raise ValueError("bounded immutable source parts required")
        text_parts: list[dict[str, str]] = []
        components: list[dict[str, Any]] = []
        leaves: dict[str, dict[str, Any]] = {}
        component_ids: set[str] = set()
        for part in parts:
            if type(part) is not tuple or len(part) != 3:
                raise ValueError("closed source part required")
            component_id, raw, binding = part
            if (not _id(component_id) or component_id in component_ids
                    or type(raw) is not bytes or len(raw) > _MAX_CONTENT):
                raise ValueError("bounded unique source component required")
            try:
                text_value = raw.decode("utf-8")
            except UnicodeError as exc:
                raise ValueError("UTF-8 source required") from exc
            if type(binding) is DocumentSourceRestrictions:
                record = binding.record()
                if record["content_sha256"] != _sha(raw):
                    raise ValueError("source digest differs from original binding")
                child_leaves = [{"source_id": component_id, "restrictions": record}]
            elif type(binding) is DocumentMultiSourceRestrictions:
                record = binding.record()
                if record["content_sha256"] != _sha(raw) or record["content_length"] != len(raw):
                    raise ValueError("derived source digest differs from binding")
                child_leaves = record["leaves"]
            else:
                raise ValueError("source restrictions required")
            for leaf in child_leaves:
                source_id = cast(str, leaf["source_id"])
                if source_id in leaves and leaves[source_id] != leaf:
                    raise ValueError("source ID conflicts with original provenance")
                leaves[source_id] = leaf
            components.append({
                "component_id": component_id,
                "content_sha256": _sha(raw), "content_length": len(raw),
                "binding_sha256": binding.sha256,
                "source_ids": sorted(leaf["source_id"] for leaf in child_leaves),
            })
            text_parts.append({"id": component_id, "text": text_value})
            component_ids.add(component_id)
        if len(leaves) > _MAX_PARTS:
            raise ValueError("original source leaf limit")
        assembled = _canonical({"sources": text_parts})
        if len(assembled) > _MAX_CONTENT:
            raise ValueError("assembled document byte limit")
        value = {
            "schema_version": _VERSION,
            "content_sha256": _sha(assembled), "content_length": len(assembled),
            "assembly_sha256": _sha(assembled), "assembly_length": len(assembled),
            "leaves": [leaves[source_id] for source_id in sorted(leaves)],
            "components": components,
        }
        return assembled, cls.from_record(value)

    def record(self) -> dict[str, Any]:
        return json.loads(self._record_bytes)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(b"ash-document-multisource-v1\0"
                              + self._record_bytes).hexdigest()

    @property
    def data_class(self) -> str:
        merged, _ = _merged(self.record()["leaves"])
        return cast(str, merged["data_class"])

    @property
    def expires_at(self) -> datetime | None:
        _, deadline = _merged(self.record()["leaves"])
        return deadline

    def for_output(self, content: bytes) -> DocumentMultiSourceRestrictions:
        if type(content) is not bytes or len(content) > _MAX_CONTENT:
            raise ValueError("bounded output bytes required")
        value = self.record()
        value["content_sha256"] = _sha(content)
        value["content_length"] = len(content)
        return type(self).from_record(value)

    def admission_reason(
        self, content: bytes, *, data_class: str, now: datetime,
    ) -> str | None:
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            return "source_clock_invalid"
        current = now.astimezone(UTC)
        record = self.record()
        origins = [DocumentSourceRestrictions.from_record(row["restrictions"])
                   for row in record["leaves"]]
        if any(current < datetime.fromisoformat(item.record()["created_at"].replace(
            "Z", "+00:00",
        )) for item in origins):
            return "source_clock_invalid"
        if (type(content) is not bytes or len(content) != record["content_length"]
                or _sha(content) != record["content_sha256"]):
            return "source_digest_mismatch"
        merged, deadline = _merged(record["leaves"])
        if type(data_class) is not str or data_class != merged["data_class"]:
            return "source_class_mismatch"
        if not merged["can_store"]:
            return "source_storage_forbidden"
        if not merged["can_forward"]:
            return "source_forwarding_forbidden"
        if "local-model" not in merged["allowed_recipients"]:
            return "source_recipient_forbidden"
        if "document-generation" not in merged["allowed_purpose"]:
            return "source_purpose_forbidden"
        if merged["requires_confirmation"]:
            return "source_confirmation_required"
        if deadline is not None and current >= deadline:
            return "source_expired"
        return None
