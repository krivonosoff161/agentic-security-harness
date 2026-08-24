"""Closed, deterministic Corpus Pack SDK V1.

Corpus packs are optional, sanitized metadata extensions to the frozen core corpus.  They
do not mutate :mod:`agentic_security_harness.corpus`, load Python code, execute a target,
or grant operational authority.  Callers provide exact canonical manifest bytes or an
explicit directory containing ``corpus-pack.v1.json``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.corpus import V1_PATTERN_IDS, corpus_manifest_sha256
from agentic_security_harness.extension_sdk import ExtensionObservationEnvelopeV1
from agentic_security_harness.models import Severity
from agentic_security_harness.portfolio_contract import (
    GIT_OBJECT_PATTERN,
    PROJECT_ID_PATTERN,
    REPOSITORY_ID_PATTERN,
    SHA256_PATTERN,
    SourceSurface,
)
from agentic_security_harness.safe_io import is_link_or_reparse

CORPUS_PACK_MANIFEST_V1: Final = "harness-corpus-pack-manifest-v1.0"
CORPUS_PACK_COMPOSITION_V1: Final = "harness-corpus-composition-v1.0"
CORPUS_PACK_EVIDENCE_ASSESSMENT_V1: Final = (
    "harness-corpus-pack-evidence-assessment-v1.0"
)
CORPUS_PACK_FILENAME_V1: Final = "corpus-pack.v1.json"
CORE_CORPUS_VERSION_V1: Final = "1.0.0"
MAX_CORPUS_PACK_BYTES: Final = 1_048_576
MAX_CORPUS_PACK_PATTERNS: Final = 256
MAX_COMPOSED_PACKS: Final = 64
MAX_COMPOSED_OPTIONAL_PATTERNS: Final = 2_048
MAX_CORPUS_PACK_MISSING_CODES: Final = 50
MAX_CORPUS_PACK_JSON_DEPTH: Final = 32
MAX_CORPUS_PACK_INTEGER_DIGITS: Final = 10

_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9_.-]{0,127}$"
_SEMVER_PATTERN = r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
_OBSERVATION_FIELD_NAMES = frozenset(ExtensionObservationEnvelopeV1.model_fields)
_REQUIRED_OBSERVATION_FIELDS = _OBSERVATION_FIELD_NAMES


class CorpusPackContractError(ValueError):
    """Raised when corpus-pack input violates the closed V1 contract."""


class CorpusPackSourceV1(BaseModel):
    """Unattested source identity and exact content commitments supplied by a pack."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    component_id: str = Field(pattern=PROJECT_ID_PATTERN)
    repository_id: str = Field(pattern=REPOSITORY_ID_PATTERN)
    source_commit: str = Field(pattern=GIT_OBJECT_PATTERN)
    component_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    implementation_sha256: str = Field(pattern=SHA256_PATTERN)
    distribution_sha256: str = Field(pattern=SHA256_PATTERN)
    producer_attestation: Literal["unattested"]


class CorpusPackObservationRequirementsV1(BaseModel):
    """Evidence shape required before a pack-owned rule could be evaluated."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_schema_version: Literal["portfolio-observation-v1.0"]
    extension_envelope_schema_version: Literal["harness-extension-envelope-v1.0"]
    required_envelope_fields: tuple[str, ...] = Field(min_length=9, max_length=16)
    required_source_surfaces: tuple[SourceSurface, ...] = Field(min_length=1, max_length=13)
    required_activities: tuple[str, ...] = Field(min_length=1, max_length=32)
    terminal_activity: str = Field(pattern=_IDENTIFIER_PATTERN)
    minimum_event_count: int = Field(ge=1, le=2_048)
    requires_complete_telemetry: Literal[True]
    requires_parent_link: bool
    requires_authority_envelope_ref: bool
    evidence_semantics: Literal[
        "declared_requirements_only_not_proof_of_presence_or_security"
    ]

    @model_validator(mode="after")
    def _validate_requirements(self) -> CorpusPackObservationRequirementsV1:
        for label, values in (
            ("required envelope fields", self.required_envelope_fields),
            ("required source surfaces", self.required_source_surfaces),
            ("required activities", self.required_activities),
        ):
            if tuple(values) != tuple(sorted(values)) or len(values) != len(set(values)):
                raise ValueError(f"{label} must be sorted and unique")
        fields = set(self.required_envelope_fields)
        if not _REQUIRED_OBSERVATION_FIELDS <= fields:
            raise ValueError("required envelope fields omit the V1 minimum")
        if not fields <= _OBSERVATION_FIELD_NAMES:
            raise ValueError("required envelope fields are outside Extension SDK V1")
        if any(not re.fullmatch(_IDENTIFIER_PATTERN, value) for value in self.required_activities):
            raise ValueError("required activities must be canonical tokens")
        if self.terminal_activity not in self.required_activities:
            raise ValueError("terminal activity must be one of the required activities")
        return self


class CorpusPackTerminalSemanticsV1(BaseModel):
    """Closed outcome meanings; a pack cannot redefine PASS or missing evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    invariant_preserved: Literal["pass"]
    invariant_violated: Literal["finding"]
    evidence_missing: Literal["inconclusive"]
    contract_invalid: Literal["error"]
    verdict_scope: Literal["declared_pattern_only_not_security_certification"]
    may_lower_security_decision: Literal[False]
    operational_authority: Literal["none"]


class CorpusPackPatternV1(BaseModel):
    """One namespaced boundary-invariant descriptor with no raw payload fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    invariant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    category: str = Field(pattern=_IDENTIFIER_PATTERN)
    severity: Severity
    boundary_surface: SourceSurface
    data_boundary_fields: tuple[
        Literal[
            "allowed_purpose",
            "allowed_recipients",
            "can_forward",
            "can_store",
            "classification_mutable",
            "classification_source",
            "data_class",
            "requires_confirmation",
            "ttl_seconds",
        ],
        ...,
    ] = Field(max_length=9)
    control_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    observation_requirements: CorpusPackObservationRequirementsV1
    terminal_semantics: CorpusPackTerminalSemanticsV1
    payload_policy: Literal["metadata_and_digests_only_no_raw_or_private_payloads"]

    @model_validator(mode="after")
    def _validate_pattern(self) -> CorpusPackPatternV1:
        for label, values in (
            ("data boundary fields", self.data_boundary_fields),
            ("control ids", self.control_ids),
        ):
            if tuple(values) != tuple(sorted(values)) or len(values) != len(set(values)):
                raise ValueError(f"{label} must be sorted and unique")
        if any(not re.fullmatch(_IDENTIFIER_PATTERN, value) for value in self.control_ids):
            raise ValueError("control ids must be canonical tokens")
        if self.boundary_surface not in self.observation_requirements.required_source_surfaces:
            raise ValueError("boundary surface must be required trace evidence")
        return self


class CorpusPackManifestV1(BaseModel):
    """Canonical optional pack; source identity is bound but remains unattested."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-corpus-pack-manifest-v1.0"]
    pack_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    pack_version: str = Field(pattern=_SEMVER_PATTERN)
    harness_api: Literal["1"]
    core_corpus_version: Literal["1.0.0"]
    core_corpus_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    source: CorpusPackSourceV1
    supported_platforms: tuple[Literal["linux", "windows"], ...] = Field(
        min_length=1, max_length=2
    )
    tested_platforms: tuple[Literal["linux", "windows"], ...] = Field(
        min_length=1, max_length=2
    )
    pattern_count: int = Field(ge=1, le=MAX_CORPUS_PACK_PATTERNS)
    patterns: tuple[CorpusPackPatternV1, ...] = Field(
        min_length=1, max_length=MAX_CORPUS_PACK_PATTERNS
    )
    pack_content_sha256: str = Field(pattern=SHA256_PATTERN)
    loading_model: Literal["explicit_canonical_bytes_or_fixed_manifest_path"]
    execution_model: Literal["offline_metadata_only_no_code_loading_or_execution"]
    network_mode: Literal["off"]
    raw_data_policy: Literal["digests_only"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_manifest(self) -> CorpusPackManifestV1:
        if self.core_corpus_manifest_sha256 != corpus_manifest_sha256():
            raise ValueError("pack core corpus digest does not bind frozen corpus 1.0.0")
        for label, values in (
            ("supported platforms", self.supported_platforms),
            ("tested platforms", self.tested_platforms),
        ):
            if tuple(values) != tuple(sorted(values)) or len(values) != len(set(values)):
                raise ValueError(f"{label} must be sorted and unique")
        if not set(self.tested_platforms) <= set(self.supported_platforms):
            raise ValueError("tested platforms must be a subset of supported platforms")
        ids = tuple(pattern.pattern_id for pattern in self.patterns)
        if self.pattern_count != len(ids):
            raise ValueError("pattern_count does not match patterns")
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ValueError("pack pattern ids must be sorted and unique")
        prefix = f"{self.pack_id}."
        if any(not pattern_id.startswith(prefix) for pattern_id in ids):
            raise ValueError("pack pattern ids must be namespaced by pack_id")
        if set(ids) & set(V1_PATTERN_IDS):
            raise ValueError("pack pattern ids must not override frozen core ids")
        if self.pack_content_sha256 != _pack_content_digest(self):
            raise ValueError("pack content digest does not bind manifest content")
        return self


class CorpusPackCommitmentV1(BaseModel):
    """Digest-bound source summary used by a deterministic composition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pack_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    pack_version: str = Field(pattern=_SEMVER_PATTERN)
    source_component_id: str = Field(pattern=PROJECT_ID_PATTERN)
    source_repository_id: str = Field(pattern=REPOSITORY_ID_PATTERN)
    source_commit: str = Field(pattern=GIT_OBJECT_PATTERN)
    component_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    implementation_sha256: str = Field(pattern=SHA256_PATTERN)
    distribution_sha256: str = Field(pattern=SHA256_PATTERN)
    pack_content_sha256: str = Field(pattern=SHA256_PATTERN)
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    pattern_count: int = Field(ge=1, le=MAX_CORPUS_PACK_PATTERNS)
    pattern_refs_sha256: str = Field(pattern=SHA256_PATTERN)
    supported_platforms: tuple[Literal["linux", "windows"], ...] = Field(
        min_length=1, max_length=2
    )
    tested_platforms: tuple[Literal["linux", "windows"], ...] = Field(
        min_length=1, max_length=2
    )
    producer_attestation: Literal["unattested"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_commitment(self) -> CorpusPackCommitmentV1:
        for label, values in (
            ("supported platforms", self.supported_platforms),
            ("tested platforms", self.tested_platforms),
        ):
            if tuple(values) != tuple(sorted(values)) or len(values) != len(set(values)):
                raise ValueError(f"commitment {label} must be sorted and unique")
        if not set(self.tested_platforms) <= set(self.supported_platforms):
            raise ValueError("commitment tested platforms must be supported")
        return self


class ComposedCorpusPatternRefV1(BaseModel):
    """Identity-only reference; it carries no executable rule or raw scenario."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    source_kind: Literal["core", "optional_pack"]
    source_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    source_version: str = Field(pattern=_SEMVER_PATTERN)
    pattern_sha256: str = Field(pattern=SHA256_PATTERN)


class ComposedCorpusV1(BaseModel):
    """Deterministic registry composition that leaves the core corpus untouched."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-corpus-composition-v1.0"]
    composition_id: str = Field(pattern=SHA256_PATTERN)
    core_corpus_version: Literal["1.0.0"]
    core_corpus_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    core_pattern_ids: tuple[str, ...]
    pack_commitments: tuple[CorpusPackCommitmentV1, ...] = Field(max_length=MAX_COMPOSED_PACKS)
    patterns: tuple[ComposedCorpusPatternRefV1, ...] = Field(
        max_length=len(V1_PATTERN_IDS) + MAX_COMPOSED_OPTIONAL_PATTERNS
    )
    execution_semantics: Literal["registry_only_no_pattern_execution"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_composition(self) -> ComposedCorpusV1:
        if self.core_corpus_manifest_sha256 != corpus_manifest_sha256():
            raise ValueError("composition core digest drift")
        if self.core_pattern_ids != V1_PATTERN_IDS:
            raise ValueError("composition changed frozen core pattern ids or order")
        pack_ids = tuple(item.pack_id for item in self.pack_commitments)
        if pack_ids != tuple(sorted(pack_ids)) or len(pack_ids) != len(set(pack_ids)):
            raise ValueError("composition pack ids must be sorted and unique")
        pattern_ids = tuple(item.pattern_id for item in self.patterns)
        if len(pattern_ids) != len(set(pattern_ids)):
            raise ValueError("composition pattern ids must be unique")
        if pattern_ids[: len(V1_PATTERN_IDS)] != V1_PATTERN_IDS:
            raise ValueError("composition must preserve frozen core prefix")
        expected_core = _core_pattern_refs()
        if self.patterns[: len(V1_PATTERN_IDS)] != expected_core:
            raise ValueError("composition core pattern commitments drift")
        versions = {item.pack_id: item.pack_version for item in self.pack_commitments}
        optional = self.patterns[len(V1_PATTERN_IDS) :]
        optional_order = tuple((item.source_id, item.pattern_id) for item in optional)
        if optional_order != tuple(sorted(optional_order)):
            raise ValueError("composition optional patterns must be sorted by pack and id")
        optional_sources = {item.source_id for item in optional}
        if optional_sources != set(pack_ids):
            raise ValueError("every committed pack must own optional pattern references")
        for item in optional:
            if item.source_kind != "optional_pack":
                raise ValueError("optional pattern reference source kind drift")
            if not item.pattern_id.startswith(f"{item.source_id}."):
                raise ValueError("optional pattern reference namespace drift")
            if versions.get(item.source_id) != item.source_version:
                raise ValueError("optional pattern reference version drift")
        for commitment in self.pack_commitments:
            owned_refs = tuple(
                item for item in optional if item.source_id == commitment.pack_id
            )
            if len(owned_refs) != commitment.pattern_count:
                raise ValueError("pack commitment pattern count drift")
            if _pack_pattern_refs_digest(owned_refs) != commitment.pattern_refs_sha256:
                raise ValueError("pack commitment pattern reference digest drift")
        if self.composition_id != _composition_digest(self):
            raise ValueError("composition identity drift")
        return self


class CorpusPackEvidenceAssessmentV1(BaseModel):
    """Evidence-readiness result; it never evaluates the security invariant itself."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-corpus-pack-evidence-assessment-v1.0"]
    assessment_id: str = Field(pattern=SHA256_PATTERN)
    pattern_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    envelope_id: str = Field(pattern=SHA256_PATTERN)
    requirements_sha256: str = Field(pattern=SHA256_PATTERN)
    evidence_state: Literal["ready_for_rule_evaluation", "incomplete"]
    missing_requirement_codes: tuple[str, ...] = Field(
        max_length=MAX_CORPUS_PACK_MISSING_CODES
    )
    terminal_disposition: Literal["inconclusive"]
    verdict_semantics: Literal["evidence_readiness_only_no_security_verdict"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_assessment(self) -> CorpusPackEvidenceAssessmentV1:
        if tuple(self.missing_requirement_codes) != tuple(
            sorted(self.missing_requirement_codes)
        ) or len(self.missing_requirement_codes) != len(set(self.missing_requirement_codes)):
            raise ValueError("missing requirement codes must be sorted and unique")
        if self.evidence_state == "ready_for_rule_evaluation" and self.missing_requirement_codes:
            raise ValueError("ready evidence cannot have missing requirements")
        if self.evidence_state == "incomplete" and not self.missing_requirement_codes:
            raise ValueError("incomplete evidence requires missing requirements")
        if self.assessment_id != _assessment_digest(self):
            raise ValueError("assessment identity drift")
        return self


def build_corpus_pack_manifest_v1(
    *,
    pack_id: str,
    pack_version: str,
    source: CorpusPackSourceV1,
    supported_platforms: tuple[Literal["linux", "windows"], ...],
    tested_platforms: tuple[Literal["linux", "windows"], ...],
    patterns: tuple[CorpusPackPatternV1, ...],
) -> CorpusPackManifestV1:
    """Build one canonical manifest while deriving its semantic content digest."""

    provisional = CorpusPackManifestV1.model_construct(
        schema_version=CORPUS_PACK_MANIFEST_V1,
        pack_id=pack_id,
        pack_version=pack_version,
        harness_api="1",
        core_corpus_version=CORE_CORPUS_VERSION_V1,
        core_corpus_manifest_sha256=corpus_manifest_sha256(),
        source=source,
        supported_platforms=supported_platforms,
        tested_platforms=tested_platforms,
        pattern_count=len(patterns),
        patterns=patterns,
        pack_content_sha256="0" * 64,
        loading_model="explicit_canonical_bytes_or_fixed_manifest_path",
        execution_model="offline_metadata_only_no_code_loading_or_execution",
        network_mode="off",
        raw_data_policy="digests_only",
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["pack_content_sha256"] = _pack_content_digest(provisional)
    return CorpusPackManifestV1.model_validate(payload)


def encode_corpus_pack_manifest_v1(manifest: CorpusPackManifestV1) -> bytes:
    """Encode exact canonical UTF-8 JSON with one LF terminator."""

    validated = CorpusPackManifestV1.model_validate(manifest.model_dump(mode="python"))
    return _bounded_canonical_bytes(validated.model_dump(mode="json"), "manifest")


def decode_corpus_pack_manifest_v1(payload: bytes) -> CorpusPackManifestV1:
    """Decode exact canonical bytes; duplicates, drift and noncanonical JSON fail closed."""

    decoded = _decode_json_object(payload, "manifest")
    try:
        manifest = CorpusPackManifestV1.model_validate(decoded)
    except ValueError as exc:
        raise CorpusPackContractError("corpus pack manifest values violate V1") from exc
    if encode_corpus_pack_manifest_v1(manifest) != payload:
        raise CorpusPackContractError("corpus pack manifest JSON is not canonical V1")
    return manifest


def load_corpus_pack_directory_v1(
    root: Path, *, expected_manifest_sha256: str
) -> CorpusPackManifestV1:
    """Load the fixed manifest only when its bytes match an external digest pin."""

    expected_sha256 = _require_expected_manifest_sha256(expected_manifest_sha256)
    directory = root.absolute()
    _require_safe_path(directory, expected_directory=True)
    candidate = directory / CORPUS_PACK_FILENAME_V1
    _require_safe_path(candidate, expected_directory=False)
    before = candidate.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise CorpusPackContractError("corpus pack manifest must be a regular single-link file")
    if before.st_size <= 0 or before.st_size > MAX_CORPUS_PACK_BYTES:
        raise CorpusPackContractError("corpus pack manifest size is outside the V1 limit")
    payload = _read_stable_file(candidate, before)
    after = candidate.lstat()
    _require_safe_path(candidate, expected_directory=False)
    if not stat.S_ISREG(after.st_mode) or after.st_nlink != 1:
        raise CorpusPackContractError("corpus pack manifest topology changed while read")
    before_id = _file_identity(before)
    after_id = _file_identity(after)
    if before_id != after_id:
        raise CorpusPackContractError("corpus pack manifest changed while being read")
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != expected_sha256:
        raise CorpusPackContractError("corpus pack manifest does not match expected SHA-256")
    return decode_corpus_pack_manifest_v1(payload)


def corpus_pack_manifest_sha256(manifest: CorpusPackManifestV1) -> str:
    """Return the exact canonical manifest-byte digest (not producer authentication)."""

    return hashlib.sha256(encode_corpus_pack_manifest_v1(manifest)).hexdigest()


def compose_corpus_packs_v1(
    manifests: tuple[CorpusPackManifestV1, ...],
    *,
    expected_manifest_sha256s: Mapping[str, str],
) -> ComposedCorpusV1:
    """Compose pinned, validated packs deterministically without changing core APIs."""

    if len(manifests) > MAX_COMPOSED_PACKS:
        raise CorpusPackContractError("corpus pack count exceeds the V1 limit")
    validated: list[CorpusPackManifestV1] = []
    for manifest in manifests:
        try:
            validated.append(
                CorpusPackManifestV1.model_validate(manifest.model_dump(mode="python"))
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise CorpusPackContractError("corpus pack object violates V1") from exc
    pack_ids = [manifest.pack_id for manifest in validated]
    if len(pack_ids) != len(set(pack_ids)):
        raise CorpusPackContractError("duplicate or replayed corpus pack id")
    if not isinstance(expected_manifest_sha256s, Mapping):
        raise CorpusPackContractError("expected manifest SHA-256 pins must be a mapping")
    if set(expected_manifest_sha256s) != set(pack_ids):
        raise CorpusPackContractError("expected manifest SHA-256 pins must match pack ids")
    expected_sha256s = {
        pack_id: _require_expected_manifest_sha256(expected_manifest_sha256s[pack_id])
        for pack_id in pack_ids
    }
    if sum(len(manifest.patterns) for manifest in validated) > MAX_COMPOSED_OPTIONAL_PATTERNS:
        raise CorpusPackContractError("composed optional pattern count exceeds the V1 limit")

    ordered = sorted(validated, key=lambda item: item.pack_id)
    seen = set(V1_PATTERN_IDS)
    refs = list(_core_pattern_refs())
    commitments: list[CorpusPackCommitmentV1] = []
    for manifest in ordered:
        manifest_sha256 = corpus_pack_manifest_sha256(manifest)
        if manifest_sha256 != expected_sha256s[manifest.pack_id]:
            raise CorpusPackContractError(
                "corpus pack manifest does not match expected SHA-256"
            )
        pack_refs: list[ComposedCorpusPatternRefV1] = []
        for pattern in manifest.patterns:
            if pattern.pattern_id in seen:
                raise CorpusPackContractError("corpus pattern id collision")
            seen.add(pattern.pattern_id)
            pack_refs.append(
                ComposedCorpusPatternRefV1(
                    pattern_id=pattern.pattern_id,
                    source_kind="optional_pack",
                    source_id=manifest.pack_id,
                    source_version=manifest.pack_version,
                    pattern_sha256=_pattern_digest(pattern),
                )
            )
        refs.extend(pack_refs)
        commitments.append(
            CorpusPackCommitmentV1(
                pack_id=manifest.pack_id,
                pack_version=manifest.pack_version,
                source_component_id=manifest.source.component_id,
                source_repository_id=manifest.source.repository_id,
                source_commit=manifest.source.source_commit,
                component_manifest_sha256=manifest.source.component_manifest_sha256,
                implementation_sha256=manifest.source.implementation_sha256,
                distribution_sha256=manifest.source.distribution_sha256,
                pack_content_sha256=manifest.pack_content_sha256,
                manifest_sha256=manifest_sha256,
                pattern_count=len(pack_refs),
                pattern_refs_sha256=_pack_pattern_refs_digest(tuple(pack_refs)),
                supported_platforms=manifest.supported_platforms,
                tested_platforms=manifest.tested_platforms,
                producer_attestation="unattested",
                operational_authority="none",
            )
        )

    provisional = ComposedCorpusV1.model_construct(
        schema_version=CORPUS_PACK_COMPOSITION_V1,
        composition_id="0" * 64,
        core_corpus_version=CORE_CORPUS_VERSION_V1,
        core_corpus_manifest_sha256=corpus_manifest_sha256(),
        core_pattern_ids=V1_PATTERN_IDS,
        pack_commitments=tuple(commitments),
        patterns=tuple(refs),
        execution_semantics="registry_only_no_pattern_execution",
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["composition_id"] = _composition_digest(provisional)
    return ComposedCorpusV1.model_validate(payload)


def assess_corpus_pack_evidence_v1(
    pattern: CorpusPackPatternV1,
    envelope: ExtensionObservationEnvelopeV1,
) -> CorpusPackEvidenceAssessmentV1:
    """Check observation readiness only; never decide whether an invariant holds."""

    try:
        checked_pattern = CorpusPackPatternV1.model_validate(
            pattern.model_dump(mode="python")
        )
        checked_envelope = ExtensionObservationEnvelopeV1.model_validate(
            envelope.model_dump(mode="python")
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise CorpusPackContractError(
            "corpus pack evidence inputs violate their V1 contracts"
        ) from exc
    requirement = checked_pattern.observation_requirements
    missing: set[str] = set()
    if len(checked_envelope.events) < requirement.minimum_event_count:
        missing.add("event_count")
    observed_surfaces = {event.source_surface for event in checked_envelope.events}
    for surface in requirement.required_source_surfaces:
        if surface not in observed_surfaces:
            missing.add(f"surface.{surface}")
    observed_activities = {event.activity for event in checked_envelope.events}
    for activity in requirement.required_activities:
        if activity not in observed_activities:
            missing.add(f"activity.{activity}")
    if (
        not checked_envelope.events
        or checked_envelope.events[-1].activity != requirement.terminal_activity
    ):
        missing.add("terminal_activity")
    if requirement.requires_complete_telemetry and any(
        event.telemetry_state != "complete" for event in checked_envelope.events
    ):
        missing.add("telemetry.complete")
    if requirement.requires_parent_link and not any(
        event.parent_event_ids for event in checked_envelope.events
    ):
        missing.add("parent_link")
    if requirement.requires_authority_envelope_ref and not any(
        event.authority_envelope_ref is not None for event in checked_envelope.events
    ):
        missing.add("authority_envelope_ref")
    ordered_missing = tuple(sorted(missing))
    provisional = CorpusPackEvidenceAssessmentV1.model_construct(
        schema_version=CORPUS_PACK_EVIDENCE_ASSESSMENT_V1,
        assessment_id="0" * 64,
        pattern_id=checked_pattern.pattern_id,
        envelope_id=checked_envelope.envelope_id,
        requirements_sha256=_requirements_digest(requirement),
        evidence_state=(
            "incomplete" if ordered_missing else "ready_for_rule_evaluation"
        ),
        missing_requirement_codes=ordered_missing,
        terminal_disposition="inconclusive",
        verdict_semantics="evidence_readiness_only_no_security_verdict",
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["assessment_id"] = _assessment_digest(provisional)
    return CorpusPackEvidenceAssessmentV1.model_validate(payload)


def corpus_pack_v1_json_schemas() -> dict[str, dict[str, Any]]:
    """Return the closed public shape schemas; Python owns semantic validation."""

    return {
        "corpus-pack-manifest.v1.schema.json": CorpusPackManifestV1.model_json_schema(),
        "corpus-composition.v1.schema.json": ComposedCorpusV1.model_json_schema(),
        "corpus-pack-evidence-assessment.v1.schema.json": (
            CorpusPackEvidenceAssessmentV1.model_json_schema()
        ),
    }


def _pack_content_digest(manifest: CorpusPackManifestV1) -> str:
    return _digest_payload(
        "agentic-security-harness/corpus-pack-content/v1.0",
        manifest.model_dump(mode="json", exclude={"pack_content_sha256"}),
    )


def _pattern_digest(pattern: CorpusPackPatternV1) -> str:
    return _digest_payload(
        "agentic-security-harness/corpus-pack-pattern/v1.0",
        pattern.model_dump(mode="json"),
    )


def _requirements_digest(requirements: CorpusPackObservationRequirementsV1) -> str:
    return _digest_payload(
        "agentic-security-harness/corpus-pack-evidence-requirements/v1.0",
        requirements.model_dump(mode="json"),
    )


def _pack_pattern_refs_digest(
    references: tuple[ComposedCorpusPatternRefV1, ...],
) -> str:
    return _digest_payload(
        "agentic-security-harness/corpus-pack-pattern-refs/v1.0",
        [item.model_dump(mode="json") for item in references],
    )


def _composition_digest(composition: ComposedCorpusV1) -> str:
    return _digest_payload(
        "agentic-security-harness/corpus-composition/v1.0",
        composition.model_dump(mode="json", exclude={"composition_id"}),
    )


def _assessment_digest(assessment: CorpusPackEvidenceAssessmentV1) -> str:
    return _digest_payload(
        "agentic-security-harness/corpus-pack-evidence-assessment/v1.0",
        assessment.model_dump(mode="json", exclude={"assessment_id"}),
    )


def _core_pattern_refs() -> tuple[ComposedCorpusPatternRefV1, ...]:
    digest = corpus_manifest_sha256()
    return tuple(
        ComposedCorpusPatternRefV1(
            pattern_id=pattern_id,
            source_kind="core",
            source_id="agentic-security-harness",
            source_version=CORE_CORPUS_VERSION_V1,
            pattern_sha256=_digest_payload(
                "agentic-security-harness/core-corpus-pattern-ref/v1.0",
                {
                    "core_corpus_manifest_sha256": digest,
                    "pattern_id": pattern_id,
                },
            ),
        )
        for pattern_id in V1_PATTERN_IDS
    )


def _bounded_canonical_bytes(payload: object, label: str) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise CorpusPackContractError(f"corpus pack {label} is not canonical JSON") from exc
    if len(encoded) > MAX_CORPUS_PACK_BYTES:
        raise CorpusPackContractError(f"corpus pack {label} exceeds the V1 byte limit")
    return encoded


def _decode_json_object(payload: bytes, label: str) -> dict[str, Any]:
    if not isinstance(payload, bytes):
        raise CorpusPackContractError(f"corpus pack {label} must be bytes")
    if not payload or len(payload) > MAX_CORPUS_PACK_BYTES:
        raise CorpusPackContractError(f"corpus pack {label} size is outside the V1 limit")
    try:
        text = payload.decode("utf-8")
        _require_bounded_json_nesting(text)
        decoded = json.loads(
            text,
            object_pairs_hook=_strict_json_object,
            parse_int=_bounded_json_integer,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except CorpusPackContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CorpusPackContractError(
            f"corpus pack {label} is not valid bounded UTF-8 JSON"
        ) from exc
    if not isinstance(decoded, dict):
        raise CorpusPackContractError(f"corpus pack {label} must be a JSON object")
    return decoded


def _require_bounded_json_nesting(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_CORPUS_PACK_JSON_DEPTH:
                raise CorpusPackContractError("corpus pack JSON nesting exceeds the V1 limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise CorpusPackContractError("corpus pack JSON nesting is invalid")


def _bounded_json_integer(token: str) -> int:
    digits = token.removeprefix("-")
    if len(digits) > MAX_CORPUS_PACK_INTEGER_DIGITS:
        raise CorpusPackContractError("corpus pack JSON integer exceeds the V1 limit")
    return int(token)


def _reject_json_float(_token: str) -> float:
    raise CorpusPackContractError("corpus pack JSON floating-point values are forbidden")


def _reject_json_constant(_token: str) -> None:
    raise CorpusPackContractError("corpus pack JSON non-finite constants are forbidden")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CorpusPackContractError("duplicate corpus pack JSON field")
        result[key] = value
    return result


def _require_safe_path(path: Path, *, expected_directory: bool) -> None:
    if not path.exists() and not path.is_symlink():
        raise CorpusPackContractError("corpus pack path does not exist")
    for component in (path, *path.parents):
        if is_link_or_reparse(component):
            raise CorpusPackContractError(
                "corpus pack path must not traverse a link or reparse point"
            )
        if component.parent == component:
            break
    try:
        info = path.lstat()
    except OSError as exc:
        raise CorpusPackContractError("corpus pack path metadata is unavailable") from exc
    if os.name == "nt":
        attributes = int(getattr(info, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
        if reparse_flag and attributes & reparse_flag:
            raise CorpusPackContractError("corpus pack path must not be a reparse point")
    if expected_directory and not stat.S_ISDIR(info.st_mode):
        raise CorpusPackContractError("corpus pack root must be a directory")


def _read_stable_file(path: Path, expected: os.stat_result) -> bytes:
    """Prove descriptor identity and require two identical bounded reads."""

    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(expected):
            raise CorpusPackContractError("corpus pack manifest changed before being read")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise CorpusPackContractError(
                "corpus pack manifest must remain a regular single-link file"
            )
        first = _read_descriptor_contents(descriptor)
        between = os.fstat(descriptor)
        if _file_identity(between) != _file_identity(opened):
            raise CorpusPackContractError("corpus pack manifest changed while being read")
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_descriptor_contents(descriptor)
        closed = os.fstat(descriptor)
        if _file_identity(closed) != _file_identity(opened) or first != second:
            raise CorpusPackContractError("corpus pack manifest changed while being read")
        return first
    except CorpusPackContractError:
        raise
    except OSError as exc:
        raise CorpusPackContractError("corpus pack manifest could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_descriptor_contents(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_CORPUS_PACK_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    content = b"".join(chunks)
    if not content or len(content) > MAX_CORPUS_PACK_BYTES:
        raise CorpusPackContractError("corpus pack manifest size is outside the V1 limit")
    return content


def _require_expected_manifest_sha256(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(SHA256_PATTERN, value) is None:
        raise CorpusPackContractError(
            "expected corpus pack manifest SHA-256 must be lowercase hexadecimal"
        )
    return value


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _digest_payload(domain: str, payload: object) -> str:
    return hashlib.sha256(
        domain.encode("ascii") + b"\0" + _bounded_canonical_bytes(payload, "identity")
    ).hexdigest()
