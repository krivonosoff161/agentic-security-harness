"""Stable v1 trace parsing and legacy migration helpers.

The public v1 writer emits trace schema ``1.0``. During the v1 compatibility window the
reader also accepts the historical ``0.1`` shape and can migrate it without changing any
trace semantics. Unknown fields fail closed through the Pydantic models; the explicitly
open ``reproducibility`` mapping is the only extension point in the trace contract.
"""

from __future__ import annotations

from typing import Any

from agentic_security_harness.models import ExploitTrace
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS, check_schema_version

TRACE_SCHEMA_V1 = SCHEMA_VERSIONS["trace"]
TRACE_SCHEMA_LEGACY_VERSIONS = frozenset({"0.1"})


def parse_trace_payload(payload: object) -> ExploitTrace:
    """Parse one current or explicitly supported legacy trace payload."""
    if not isinstance(payload, dict):
        raise ValueError("trace payload must be a JSON object")
    version = payload.get("schema_version")
    version_error = check_schema_version(
        "trace", version if isinstance(version, str) else None
    )
    if version_error:
        raise ValueError(version_error)
    return ExploitTrace.model_validate(payload, strict=True)


def migrate_trace_payload_to_v1(payload: object) -> dict[str, Any]:
    """Return the canonical v1 JSON object for one supported trace payload.

    The migration validates the complete closed model, changes only ``schema_version``,
    and is idempotent for already-current payloads.
    """
    trace = parse_trace_payload(payload)
    migrated = trace.model_copy(update={"schema_version": TRACE_SCHEMA_V1})
    return migrated.model_dump(mode="json")


__all__ = [
    "TRACE_SCHEMA_LEGACY_VERSIONS",
    "TRACE_SCHEMA_V1",
    "migrate_trace_payload_to_v1",
    "parse_trace_payload",
]
