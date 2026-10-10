"""Host-owned source and retained-telemetry admission for workspace operations.

This composes existing source and ancestry contracts; it does not authenticate a
producer, classify text, call a model, or confer effect authority on telemetry.
AncestryStore.snapshot may perform its documented local witness recovery.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Literal

from pydantic import ValidationError

from agentic_security_harness.ancestry_store import AncestryError, AncestryStore, Checkpoint
from agentic_security_harness.companion_contracts import (
    CoverageExpectationProfileV1,
    TelemetryManifestV1,
)
from agentic_security_harness.document_multisource import DocumentMultiSourceRestrictions
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.trajectory_admission import (
    TelemetryAdmission,
    assess_retained_telemetry,
)
from agentic_security_harness.workspace_writer import WorkspacePolicy

_KINDS = frozenset({"input", "tool_output", "memory", "handoff"})
_SOURCE_ID = re.compile(r"[a-z][a-z0-9_-]*\Z", re.ASCII)
_COMPONENT_ID = re.compile(r"[a-z][a-z0-9_-]{0,47}\Z", re.ASCII)
_SHA = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_CONTEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z", re.ASCII)
_MAX_PARTS = 8
_MAX_BYTES = 16_384
_VERSION = "ash.workspace-admission.v1"


class WorkspaceAdmissionError(ValueError):
    """Content-free source or telemetry refusal."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _checked_restrictions(
    value: DocumentSourceRestrictions | DocumentMultiSourceRestrictions,
) -> DocumentSourceRestrictions | DocumentMultiSourceRestrictions:
    if type(value) is DocumentSourceRestrictions:
        return DocumentSourceRestrictions.from_record(value.record())
    if type(value) is DocumentMultiSourceRestrictions:
        return DocumentMultiSourceRestrictions.from_record(value.record())
    raise WorkspaceAdmissionError("source_restrictions_invalid")


@dataclass(frozen=True)
class WorkspaceSource:
    kind: str
    source_id: str
    content: bytes
    restrictions: DocumentSourceRestrictions | DocumentMultiSourceRestrictions


@dataclass(frozen=True, init=False)
class WorkspaceSources:
    parts: tuple[WorkspaceSource, ...]
    restrictions: DocumentMultiSourceRestrictions
    content: bytes
    binding_sha256: str

    @classmethod
    def bind(cls, parts: tuple[WorkspaceSource, ...]) -> WorkspaceSources:
        if type(parts) is not tuple or not 1 <= len(parts) <= _MAX_PARTS:
            raise WorkspaceAdmissionError("source_parts_invalid")
        composition: list[tuple[
            str, bytes, DocumentSourceRestrictions | DocumentMultiSourceRestrictions,
        ]] = []
        bound_parts: list[WorkspaceSource] = []
        component_ids: set[str] = set()
        # Repeated ancestry is permitted only when it names the exact same
        # validated original record. Components remain distinct capture events;
        # a shared leaf is not a new independent source.
        leaves: dict[str, bytes] = {}
        for item in parts:
            if (type(item) is not WorkspaceSource or type(item.kind) is not str
                    or item.kind not in _KINDS or type(item.source_id) is not str
                    or _SOURCE_ID.fullmatch(item.source_id) is None
                    or type(item.content) is not bytes or len(item.content) > _MAX_BYTES):
                raise WorkspaceAdmissionError("source_part_invalid")
            component_id = f"{item.kind}-{item.source_id}"
            if _COMPONENT_ID.fullmatch(component_id) is None or component_id in component_ids:
                raise WorkspaceAdmissionError("source_component_collision")
            try:
                checked = _checked_restrictions(item.restrictions)
                current_leaves = (
                    ((component_id, checked.record()),)
                    if type(checked) is DocumentSourceRestrictions else
                    tuple((row["source_id"], row["restrictions"])
                          for row in checked.record()["leaves"])
                )
                for source_id, original in current_leaves:
                    canonical = _canonical(
                        DocumentSourceRestrictions.from_record(original).record()
                    )
                    if source_id in leaves and leaves[source_id] != canonical:
                        raise WorkspaceAdmissionError("source_leaf_collision")
                    leaves[source_id] = canonical
                component_ids.add(component_id)
                composition.append((component_id, item.content, checked))
                bound_parts.append(WorkspaceSource(item.kind, item.source_id,
                                                   item.content, checked))
            except WorkspaceAdmissionError:
                raise
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                raise WorkspaceAdmissionError("source_part_invalid") from exc
        try:
            assembled, merged = DocumentMultiSourceRestrictions.compose(tuple(composition))
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise WorkspaceAdmissionError("source_composition_invalid") from exc
        binding = _sha(b"ash-workspace-sources-v1\0" + _canonical({
            "parts": [{"kind": item.kind, "source_id": item.source_id,
                       "content_sha256": _sha(item.content), "content_length": len(item.content),
                       "restrictions_sha256": item.restrictions.sha256}
                      for item in bound_parts],
            "framed_sha256": _sha(assembled), "framed_length": len(assembled),
            "merged_restrictions_sha256": merged.sha256,
        }))
        instance = object.__new__(cls)
        object.__setattr__(instance, "parts", tuple(bound_parts))
        object.__setattr__(instance, "restrictions", merged)
        object.__setattr__(instance, "content", assembled)
        object.__setattr__(instance, "binding_sha256", binding)
        return instance

    def _admit(self, policy: WorkspacePolicy) -> None:
        if type(policy) is not WorkspacePolicy:
            raise WorkspaceAdmissionError("source_policy_invalid")
        self._revalidate()
        if (policy.data_class != self.restrictions.data_class
                or policy.source_restrictions_sha256 != self.restrictions.sha256
                or policy.source_expires_at != self.restrictions.expires_at):
            raise WorkspaceAdmissionError("source_policy_binding_mismatch")
        now = datetime.now(UTC)
        for item in self.parts:
            try:
                reason = item.restrictions.admission_reason(
                    item.content, data_class=policy.data_class, now=now,
                )
            except (ValueError, TypeError, RecursionError) as exc:
                raise WorkspaceAdmissionError("source_restrictions_invalid") from exc
            if reason is not None:
                raise WorkspaceAdmissionError(reason)
        try:
            reason = self.restrictions.admission_reason(
                self.content, data_class=policy.data_class, now=now,
            )
        except (ValueError, TypeError, RecursionError) as exc:
            raise WorkspaceAdmissionError("source_restrictions_invalid") from exc
        if reason is not None:
            raise WorkspaceAdmissionError(reason)

    def _revalidate(self) -> None:
        try:
            rebound = type(self).bind(self.parts)
            if (self.content != rebound.content
                    or self.restrictions.sha256 != rebound.restrictions.sha256
                    or self.binding_sha256 != rebound.binding_sha256):
                raise WorkspaceAdmissionError("source_bundle_binding_mismatch")
        except WorkspaceAdmissionError:
            raise
        except (AttributeError, ValueError, TypeError, RecursionError) as exc:
            raise WorkspaceAdmissionError("source_bundle_invalid") from exc

    def bind_policy(self, policy: WorkspacePolicy) -> WorkspacePolicy:
        if type(policy) is not WorkspacePolicy:
            raise WorkspaceAdmissionError("source_policy_invalid")
        self._revalidate()
        if policy.data_class != self.restrictions.data_class:
            raise WorkspaceAdmissionError("source_class_mismatch")
        expected_sha = self.restrictions.sha256
        expected_expiry = self.restrictions.expires_at
        if (policy.source_restrictions_sha256 not in (None, expected_sha)
                or (policy.source_restrictions_sha256 is not None
                    and policy.source_expires_at != expected_expiry)):
            raise WorkspaceAdmissionError("source_policy_binding_mismatch")
        try:
            bound = replace(policy, source_restrictions_sha256=expected_sha,
                            source_expires_at=expected_expiry)
        except (ValueError, TypeError) as exc:
            raise WorkspaceAdmissionError("source_policy_invalid") from exc
        return bound

    def input_bytes(self, policy: WorkspacePolicy) -> bytes:
        """Recheck restrictions at actual use; returned framing is untrusted text."""
        self._admit(policy)
        return self.content


@dataclass(frozen=True)
class WorkspaceAdmission:
    sources: WorkspaceSources
    store: AncestryStore
    expected_checkpoint: Checkpoint
    expected_profile: CoverageExpectationProfileV1
    logical_operation_id: str
    policy_sha256: str
    expected_manifest_sha256: str
    host_phase: Literal["pending", "sealed"]
    manifest: TelemetryManifestV1

    @property
    def binding_sha256(self) -> str:
        """Bind independently supplied host expectations, not candidate evidence."""
        self._host_inputs()
        self.sources._revalidate()
        try:
            profile = CoverageExpectationProfileV1.model_validate(
                self.expected_profile.model_dump(mode="python")
            )
            return _sha(b"ash-workspace-admission-v1\0" + _canonical({
                "schema_version": _VERSION,
                "sources_binding_sha256": self.sources.binding_sha256,
                "source_restrictions_sha256": self.sources.restrictions.sha256,
                "checkpoint": {
                    "context": self.expected_checkpoint.context,
                    "root_digest": self.expected_checkpoint.root_digest,
                    "version": self.expected_checkpoint.version,
                    "sequence": self.expected_checkpoint.sequence,
                    "event_head": self.expected_checkpoint.event_head,
                },
                "profile": profile.model_dump(mode="json"),
                "logical_operation_id": self.logical_operation_id,
                "policy_sha256": self.policy_sha256,
                "expected_manifest_sha256": self.expected_manifest_sha256,
                "host_phase": self.host_phase,
            }))
        except (ValueError, TypeError, ValidationError, RecursionError) as exc:
            raise WorkspaceAdmissionError("admission_host_input_invalid") from exc

    def _host_inputs(self) -> None:
        if (type(self.sources) is not WorkspaceSources or type(self.store) is not AncestryStore
                or type(self.expected_checkpoint) is not Checkpoint
                or type(self.expected_profile) is not CoverageExpectationProfileV1
                or not _digest(self.logical_operation_id) or not _digest(self.policy_sha256)
                or not _digest(self.expected_manifest_sha256)
                or type(self.host_phase) is not str
                or self.host_phase not in ("pending", "sealed")):
            raise WorkspaceAdmissionError("admission_host_input_invalid")
        checkpoint = self.expected_checkpoint
        if (type(checkpoint.context) is not str or _CONTEXT.fullmatch(checkpoint.context) is None
                or type(checkpoint.version) is not int or checkpoint.version != 1
                or type(checkpoint.sequence) is not int
                or not 1 <= checkpoint.sequence <= 4096
                or not _digest(checkpoint.root_digest) or not _digest(checkpoint.event_head)):
            raise WorkspaceAdmissionError("admission_host_input_invalid")

    def verify(self, *, operation_id: str, policy: WorkspacePolicy) -> TelemetryAdmission:
        self._host_inputs()
        if (not _digest(operation_id) or operation_id != self.logical_operation_id
                or type(policy) is not WorkspacePolicy
                or policy.sha256 != self.policy_sha256):
            raise WorkspaceAdmissionError("admission_operation_binding_mismatch")
        self.sources.input_bytes(policy)
        try:
            result = assess_retained_telemetry(
                self.store,
                expected_checkpoint=self.expected_checkpoint,
                expected_profile=self.expected_profile,
                logical_operation_id=self.logical_operation_id,
                policy_sha256=self.policy_sha256,
                expected_manifest_sha256=self.expected_manifest_sha256,
                host_phase=self.host_phase,
                manifest=self.manifest,
            )
        except (AncestryError, OSError, sqlite3.Error, ValueError, TypeError) as exc:
            raise WorkspaceAdmissionError("retained_telemetry_unavailable") from exc
        if (result.retained_binding != "matched" or result.coverage_state != "complete"
                or result.completion != "complete" or result.reason != "retained_evidence_matched"):
            raise WorkspaceAdmissionError("retained_telemetry_not_complete")
        return result
