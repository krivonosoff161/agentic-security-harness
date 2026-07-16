"""Machine-readable evidence classification for public project artifacts.

The registry deliberately separates publication lifecycle, evidence class, schema
currency, causal scope, label source, reconciliation, and origin authentication.
A committed example is not automatically empirical, current, reconciled, or authentic.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_security_harness.schema_versions import check_schema_version

LifecycleStatus = Literal["shipped", "withdrawn", "planned"]
EvidenceClass = Literal[
    "deterministic_synthetic",
    "executable_specification",
    "historical_rule_snapshot",
    "maintainer_declaration_unverified",
    "historical_detector_summary",
    "local_empirical_unreconciled",
    "local_empirical_reconciled",
    "independently_labelled_evaluation",
]
SchemaState = Literal[
    "current_executed",
    "current_unexecuted",
    "legacy_readable",
    "not_applicable",
]
CausalScope = Literal[
    "none",
    "rule_derived_dependency",
    "detector_observation",
    "observed_association",
    "independent_causal_estimate",
]
LabelSource = Literal["none", "scenario_author", "detector_derived", "independent_review"]
ReconciliationState = Literal[
    "not_applicable",
    "absent",
    "retained_unreconciled",
    "reconciled_with_receipt",
]
OriginAuthentication = Literal["none", "self_declared", "content_bound", "signed_attested"]

# A validator anchor is a typed route, not merely an existing file. Each route is bound to
# the public artifact marker(s) that its validator is expected to recognize. This keeps an
# arbitrary existing source/test file from being presented as evidence of validator coverage.
_VALIDATOR_CONTRACT_MARKERS: dict[str, frozenset[str]] = {
    "src/agentic_security_harness/validation.py": frozenset({
        "comparison.md",
        "semantic_drift_summary.json",
        "semantic_propagation_summary.json",
    }),
    "tests/test_validation.py": frozenset({"run_config.json"}),
    "tests/test_local_swarm.py": frozenset({
        "local_swarm_summary.json",
        "local-swarm-real-model-evaluation.md",
    }),
    "tests/test_local_swarm_matrix.py": frozenset({"local_swarm_attack_matrix.json"}),
    "tests/test_evidence_campaign.py": frozenset({"evidence_campaign_summary.json"}),
    "tests/test_secret_leak_campaign.py": frozenset({
        "secret_leak_campaign_summary.json",
        "secret_leak_variation_summary.json",
    }),
    "tests/test_semantic_drift_campaign.py": frozenset({"semantic_drift_summary.json"}),
    "tests/test_semantic_propagation_campaign.py": frozenset({
        "semantic_propagation_summary.json"
    }),
    "tests/test_swarm_defense_contour.py": frozenset({
        "swarm_defense_contour_summary.json"
    }),
    "tests/test_swarm_defense_live_campaign.py": frozenset({
        "swarm_defense_live_summary.json"
    }),
    "tests/test_marketing_web_injection_campaign.py": frozenset({
        "marketing_web_injection_summary.json"
    }),
    "tests/test_marketing_web_live_campaign.py": frozenset({
        "marketing_web_live_summary.json"
    }),
    "tests/test_swarm_resilience_campaign.py": frozenset({
        "swarm_resilience_summary.json"
    }),
    "tests/test_context_consent_campaign.py": frozenset({"context_consent_summary.json"}),
    "tests/test_tool_authority_campaign.py": frozenset({"tool_authority_summary.json"}),
    "tests/test_rag_context_campaign.py": frozenset({"rag_context_summary.json"}),
    "tests/test_planner_task_campaign.py": frozenset({"planner_task_summary.json"}),
    "tests/test_memory_rehydration_campaign.py": frozenset({
        "memory_rehydration_summary.json"
    }),
    "tests/test_handoff_integrity.py": frozenset({"comparison.md"}),
    "tests/test_local_suite.py": frozenset({"local-prometheus-workflow.md"}),
}


def _is_relative_repository_path(raw_path: str) -> bool:
    path = PurePosixPath(raw_path)
    return (
        bool(raw_path)
        and raw_path == path.as_posix()
        and not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in raw_path
    )


def _normalize_claim(value: str) -> str:
    return " ".join(value.split()).casefold()


class EvidenceStatusEntry(BaseModel):
    """One independently classified evidence component."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]+$")
    title: str = Field(min_length=1)
    lifecycle_status: LifecycleStatus
    evidence_class: EvidenceClass
    schema_state: SchemaState
    causal_scope: CausalScope
    label_source: LabelSource
    label_coverage: float = Field(ge=0.0, le=1.0)
    reconciliation_state: ReconciliationState
    origin_authentication: OriginAuthentication
    artifact_paths: list[str] = Field(min_length=1)
    validator_anchor: str = Field(min_length=1)
    supported_claim: str = Field(min_length=1)
    forbidden_claims: list[str] = Field(min_length=1)

    @field_validator("title", "supported_claim")
    @classmethod
    def validate_nonblank_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("title and supported_claim must be nonblank")
        return stripped

    @field_validator("forbidden_claims")
    @classmethod
    def validate_forbidden_claims(cls, values: list[str]) -> list[str]:
        stripped = [value.strip() for value in values]
        if any(not value for value in stripped):
            raise ValueError("forbidden_claims must be nonblank")
        normalized = [_normalize_claim(value) for value in stripped]
        if len(normalized) != len(set(normalized)):
            raise ValueError("forbidden_claims must be unique after normalization")
        return stripped

    @model_validator(mode="after")
    def validate_evidence_semantics(self) -> EvidenceStatusEntry:
        if len(self.artifact_paths) != len(set(self.artifact_paths)):
            raise ValueError("artifact_paths must be unique")
        for raw_path in self.artifact_paths:
            if not _is_relative_repository_path(raw_path):
                raise ValueError("artifact_paths must be relative repository paths")
        if not _is_relative_repository_path(self.validator_anchor):
            raise ValueError("validator_anchor must be a relative repository path")
        if _normalize_claim(self.supported_claim) in {
            _normalize_claim(value) for value in self.forbidden_claims
        }:
            raise ValueError("supported_claim must not duplicate a forbidden claim")

        if self.label_source == "none" and self.label_coverage != 0.0:
            raise ValueError("label_source=none requires zero label_coverage")
        if self.label_source != "independent_review" and self.label_coverage != 0.0:
            raise ValueError("only independent_review may have non-zero label_coverage")
        if self.label_source == "independent_review" and self.label_coverage == 0.0:
            raise ValueError("independent_review requires non-zero label_coverage")
        if (
            self.evidence_class == "independently_labelled_evaluation"
            and self.label_source != "independent_review"
        ):
            raise ValueError("independently labelled evidence requires independent review")

        if self.evidence_class in {
            "deterministic_synthetic",
            "executable_specification",
            "historical_rule_snapshot",
        }:
            if self.reconciliation_state != "not_applicable":
                raise ValueError("synthetic evidence cannot claim byte reconciliation")
            if self.causal_scope not in {"none", "rule_derived_dependency"}:
                raise ValueError("synthetic evidence cannot claim empirical causal scope")

        if self.evidence_class == "executable_specification" and self.schema_state not in {
            "current_executed",
            "not_applicable",
        }:
            raise ValueError("executable specifications cannot use a legacy artifact schema")

        if self.evidence_class == "historical_rule_snapshot":
            if self.schema_state != "legacy_readable":
                raise ValueError("historical rule snapshots must be legacy_readable")
            if self.causal_scope != "rule_derived_dependency":
                raise ValueError("historical rule snapshots retain rule-derived rows")
            if self.label_source != "none" or self.label_coverage != 0.0:
                raise ValueError("historical rule snapshots cannot claim label coverage")

        if self.evidence_class == "historical_detector_summary":
            if self.schema_state != "legacy_readable":
                raise ValueError("historical detector evidence must be legacy_readable")
            if self.causal_scope != "detector_observation":
                raise ValueError("historical detector evidence is detector observation")

        if self.evidence_class == "maintainer_declaration_unverified":
            if self.schema_state != "not_applicable":
                raise ValueError("maintainer declarations have no artifact schema state")
            if self.causal_scope != "none":
                raise ValueError("maintainer declarations cannot claim observations")
            if self.label_source != "none" or self.label_coverage != 0.0:
                raise ValueError("maintainer declarations cannot claim label coverage")
            if self.reconciliation_state != "absent":
                raise ValueError("maintainer declarations have no reconciliation receipt")
            if self.origin_authentication != "self_declared":
                raise ValueError("maintainer declarations must remain self_declared")

        if self.evidence_class == "local_empirical_unreconciled":
            if self.schema_state not in {"current_executed", "legacy_readable"}:
                raise ValueError("empirical evidence requires an executed artifact schema")
            if self.reconciliation_state not in {"absent", "retained_unreconciled"}:
                raise ValueError("unreconciled evidence cannot claim a receipt")
            if self.origin_authentication == "signed_attested":
                raise ValueError("unreconciled evidence cannot claim signed attestation")

        if self.evidence_class == "local_empirical_reconciled":
            if self.schema_state not in {"current_executed", "legacy_readable"}:
                raise ValueError("empirical evidence requires an executed artifact schema")
            if self.reconciliation_state != "reconciled_with_receipt":
                raise ValueError("reconciled evidence requires a receipt")

        if self.causal_scope == "independent_causal_estimate" and self.evidence_class not in {
            "independently_labelled_evaluation",
            "local_empirical_reconciled",
        }:
            raise ValueError("independent causal estimates require stronger evidence")

        if self.origin_authentication == "signed_attested" and self.evidence_class in {
            "historical_detector_summary",
            "local_empirical_unreconciled",
        }:
            raise ValueError("unreconciled/historical evidence cannot be signed-attested")

        unsupported_assurance_promotion = (
            self.evidence_class
            in {
                "local_empirical_reconciled",
                "independently_labelled_evaluation",
            }
            or self.reconciliation_state == "reconciled_with_receipt"
            or self.label_source == "independent_review"
            or self.causal_scope == "independent_causal_estimate"
            or self.origin_authentication in {"content_bound", "signed_attested"}
        )
        if unsupported_assurance_promotion:
            raise ValueError(
                "unsupported assurance promotion: requires a validated public "
                "receipt/attestation contract"
            )
        return self


class EvidenceStatusRegistry(BaseModel):
    """Versioned registry of independently classified public evidence components."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str
    reviewed_at: date
    entries: list[EvidenceStatusEntry] = Field(min_length=1)

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: str) -> str:
        error = check_schema_version("evidence_status_registry", value)
        if error is not None:
            raise ValueError(error)
        return value

    @model_validator(mode="after")
    def validate_unique_ids(self) -> EvidenceStatusRegistry:
        ids = [entry.evidence_id for entry in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence_id values must be unique")
        return self


def load_evidence_status_registry(path: Path) -> EvidenceStatusRegistry:
    """Load and validate a registry without executing referenced artifacts."""

    return EvidenceStatusRegistry.model_validate_json(path.read_text(encoding="utf-8"))


def validate_registry_artifact_paths(
    registry: EvidenceStatusRegistry,
    *,
    repository_root: Path,
) -> list[str]:
    """Return public-safe errors for paths and typed validator-route mismatches."""

    root = repository_root.resolve(strict=True)
    errors: list[str] = []
    for entry in registry.entries:
        allowed_markers = _VALIDATOR_CONTRACT_MARKERS.get(entry.validator_anchor)
        if allowed_markers is None:
            errors.append(
                f"{entry.evidence_id}: validator anchor has no registered artifact contract: "
                f"{entry.validator_anchor}"
            )
        for raw_path in entry.artifact_paths:
            candidate = (root / PurePosixPath(raw_path)).resolve(strict=False)
            try:
                candidate.relative_to(root)
            except ValueError:
                errors.append(f"{entry.evidence_id}: artifact path escapes repository root")
                continue
            if not candidate.exists():
                errors.append(f"{entry.evidence_id}: artifact path is missing: {raw_path}")
                continue
            candidate_markers = (
                {candidate.name}
                if candidate.is_file()
                else {child.name for child in candidate.iterdir()}
            )
            if allowed_markers is not None and not candidate_markers & allowed_markers:
                errors.append(
                    f"{entry.evidence_id}: validator anchor is incompatible with artifact "
                    f"family: {entry.validator_anchor} -> {raw_path}"
                )
        validator = (root / PurePosixPath(entry.validator_anchor)).resolve(strict=False)
        try:
            validator.relative_to(root)
        except ValueError:
            errors.append(f"{entry.evidence_id}: validator anchor escapes repository root")
            continue
        if not validator.is_file():
            errors.append(
                f"{entry.evidence_id}: validator anchor is missing: "
                f"{entry.validator_anchor}"
            )
    return errors


def registry_json_schema() -> dict[str, object]:
    """Return the Pydantic-generated JSON schema for synchronization tests."""

    return EvidenceStatusRegistry.model_json_schema()


def parse_registry_json(raw: str) -> EvidenceStatusRegistry:
    """Parse helper used by callers that already hold public JSON text."""

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid evidence status JSON: {exc.msg}") from exc
    return EvidenceStatusRegistry.model_validate(data)
