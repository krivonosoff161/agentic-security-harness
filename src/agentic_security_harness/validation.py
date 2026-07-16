"""Validation layer for committed benchmark artifacts and evidence contracts.

Deterministic, stdlib + Pydantic only - no network, no new dependencies. Validates each
recognized artifact family against its applicable structural, semantic, identity, and
content-binding contracts, then scans public artifacts for forbidden secret-shaped markers.

Passing validation means only that the inspected artifacts satisfy those applicable contracts
and contain no forbidden marker patterns - NOT that any system is secure.
"""

import hashlib
import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.evidence_status import (
    load_evidence_status_registry,
    validate_registry_artifact_paths,
)
from agentic_security_harness.ground_truth import build_ground_truth_metrics
from agentic_security_harness.models import ExploitTrace, TargetDescriptor
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.reporting import (
    _SEVERITY_RANK,
    build_comparison_md,
    build_executive_md,
    build_summary_md,
)
from agentic_security_harness.safe_io import is_link_or_reparse
from agentic_security_harness.schema_versions import (
    CORPUS_VERSION,
    SCHEMA_VERSIONS,
    check_schema_version,
)
from agentic_security_harness.scorecard import ScorecardSummary, build_scorecard

if TYPE_CHECKING:
    from agentic_security_harness.run_config import ExternalResult, ExternalSummary, RunConfig

# Three validation tiers by target type:
#   baseline  -> vulnerable-by-design demo targets; MUST FAIL every pattern.
#   protected -> controlled demo target; MUST PASS every pattern.
#   neutral   -> any other adapter (toy / arbitrary system under test); findings are
#                optional, but any finding must still be corpus-consistent.
_PROTECTED_TYPES = {"protected_demo_agent", "protected_toy_multi_agent"}
_BASELINE_TYPES = {"mock_agent", "demo_agent"}

# Conservative, format-anchored markers. The left look-behind keeps "risk-reduction" and
# similar prose from matching "sk-"; the length tails require key-shaped tokens.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sk-", re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}")),
    ("AKIA", re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}")),
    ("ghp_", re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{20,}")),
    ("Bearer", re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("BEGIN PRIVATE KEY", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY")),
    ("ASH-CANARY", re.compile(r"ASH-CANARY-[A-F0-9]{8,}-[A-F0-9]{8,}")),
    ("ASH-SEMDRIFT", re.compile(r"ASH-SEMDRIFT-[A-F0-9]{8,}-[A-F0-9]{8,}")),
    ("ASH-SEMPROP", re.compile(r"ASH-SEMPROP-[A-F0-9]{8,}-[A-F0-9]{8,}")),
]
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_EXECUTION_ID = re.compile(r"^run_[0-9a-f]{32}$")


class ValidatedEvidenceStatus(BaseModel):
    """Public evidence classification attached to a validated tracked artifact."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    evidence_class: str
    schema_state: str
    causal_scope: str
    reconciliation_state: str
    origin_authentication: str
    projection_verification: Literal[
        "not-applicable",
        "legacy-structural-only",
        "unverified-maintainer-declaration",
        "unverified-private-projection",
        "reconciled-private-projection",
    ]


class ValidationResult(BaseModel):
    """Structured outcome of validating one or more benchmark artifacts."""

    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    integrity_ok: bool = True
    expectations_ok: bool = True
    errors: list[str] = Field(default_factory=list)
    expectation_mismatches: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    report_dirs: list[str] = Field(default_factory=list)
    comparison_dirs: list[str] = Field(default_factory=list)
    external_dirs: list[str] = Field(default_factory=list)
    run_diff_dirs: list[str] = Field(default_factory=list)
    evidence_quality_dirs: list[str] = Field(default_factory=list)
    run_stats_dirs: list[str] = Field(default_factory=list)
    showcase_dirs: list[str] = Field(default_factory=list)
    local_swarm_dirs: list[str] = Field(default_factory=list)
    local_swarm_matrix_dirs: list[str] = Field(default_factory=list)
    evidence_campaign_dirs: list[str] = Field(default_factory=list)
    secret_leak_campaign_dirs: list[str] = Field(default_factory=list)
    secret_leak_variation_dirs: list[str] = Field(default_factory=list)
    semantic_drift_campaign_dirs: list[str] = Field(default_factory=list)
    semantic_propagation_campaign_dirs: list[str] = Field(default_factory=list)
    swarm_defense_contour_dirs: list[str] = Field(default_factory=list)
    swarm_defense_live_campaign_dirs: list[str] = Field(default_factory=list)
    marketing_web_injection_campaign_dirs: list[str] = Field(default_factory=list)
    marketing_web_live_campaign_dirs: list[str] = Field(default_factory=list)
    swarm_resilience_campaign_dirs: list[str] = Field(default_factory=list)
    context_consent_campaign_dirs: list[str] = Field(default_factory=list)
    tool_authority_campaign_dirs: list[str] = Field(default_factory=list)
    rag_context_campaign_dirs: list[str] = Field(default_factory=list)
    planner_task_campaign_dirs: list[str] = Field(default_factory=list)
    memory_rehydration_campaign_dirs: list[str] = Field(default_factory=list)
    evidence_status_registry_files: list[str] = Field(default_factory=list)
    evidence_statuses: list[ValidatedEvidenceStatus] = Field(default_factory=list)

    def _err(self, msg: str) -> None:
        self.errors.append(msg)
        self.integrity_ok = False
        self.ok = False

    def _expect(self, msg: str) -> None:
        self.expectation_mismatches.append(msg)
        self.expectations_ok = False
        self.ok = False

    def _warn(self, msg: str) -> None:
        self.warnings.append(msg)


def _rel(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
    return rel if rel and rel != "." else path.name


def _is_protected(target: TargetDescriptor) -> bool:
    return target.type in _PROTECTED_TYPES


def _is_comparison_dir(path: Path) -> bool:
    return (path / "comparison.md").exists() or (
        (path / "baseline").is_dir() and (path / "protected").is_dir()
    )


def _is_external_dir(path: Path) -> bool:
    return (path / "run_config.json").exists() or (
        (path / "external_results.json").exists() and (path / "external_summary.json").exists()
    )


def _is_local_swarm_dir(path: Path) -> bool:
    return (path / "local_swarm_summary.json").exists()


def _is_local_swarm_matrix_dir(path: Path) -> bool:
    return (path / "local_swarm_attack_matrix.json").exists()


def _is_evidence_campaign_dir(path: Path) -> bool:
    return (path / "evidence_campaign_summary.json").exists()


def _is_secret_leak_campaign_dir(path: Path) -> bool:
    return (path / "secret_leak_campaign_summary.json").exists()


def _is_secret_leak_variation_dir(path: Path) -> bool:
    return (path / "secret_leak_variation_summary.json").exists()


def _is_semantic_drift_campaign_dir(path: Path) -> bool:
    return (path / "semantic_drift_summary.json").exists()


def _is_semantic_propagation_campaign_dir(path: Path) -> bool:
    return (path / "semantic_propagation_summary.json").exists()


def _is_swarm_defense_contour_dir(path: Path) -> bool:
    return (path / "swarm_defense_contour_summary.json").exists()


def _is_swarm_defense_live_campaign_dir(path: Path) -> bool:
    return (path / "swarm_defense_live_summary.json").exists()


def _is_marketing_web_injection_campaign_dir(path: Path) -> bool:
    return (path / "marketing_web_injection_summary.json").exists()


def _is_marketing_web_live_campaign_dir(path: Path) -> bool:
    return (path / "marketing_web_live_summary.json").exists()


def _is_swarm_resilience_campaign_dir(path: Path) -> bool:
    return (path / "swarm_resilience_summary.json").exists()


def _is_context_consent_campaign_dir(path: Path) -> bool:
    return (path / "context_consent_summary.json").exists()


def _is_tool_authority_campaign_dir(path: Path) -> bool:
    return (path / "tool_authority_summary.json").exists()


def _is_rag_context_campaign_dir(path: Path) -> bool:
    return (path / "rag_context_summary.json").exists()


def _is_planner_task_campaign_dir(path: Path) -> bool:
    return (path / "planner_task_summary.json").exists()


def _is_memory_rehydration_campaign_dir(path: Path) -> bool:
    return (path / "memory_rehydration_summary.json").exists()


def validate_path(path: Path) -> ValidationResult:
    """Validate a report dir, a comparison dir, or a directory of such dirs.

    Also runs the corpus-level standards-mapping self-check so framework-mapping drift
    is caught in CI alongside artifact validation.
    """
    result = ValidationResult()
    from agentic_security_harness.standards_mapping import validate_standards_mapping

    for err in validate_standards_mapping():
        result._err(f"standards-mapping: {err}")
    _validate_into(path, path, result)
    _attach_public_evidence_statuses(path, result)
    return result


def validate_artifact_path(path: Path) -> ValidationResult:
    """Validate one artifact tree without repeating repository-global checks.

    Run-history consumers use this after discovering a manifest. It retains every
    applicable artifact, manifest, hash, projection, expectation, and secret-marker check;
    only the repository-global standards map and evidence-status attachment are omitted.
    """

    result = ValidationResult()
    _validate_into(path, path, result)
    return result


def _recognized_artifact_kinds(path: Path) -> list[str]:
    """Return every direct artifact contract claimed by one directory."""

    checks = (
        ("comparison", _is_comparison_dir(path)),
        ("external", _is_external_dir(path)),
        ("local_swarm", _is_local_swarm_dir(path)),
        ("local_swarm_matrix", _is_local_swarm_matrix_dir(path)),
        ("evidence_campaign", _is_evidence_campaign_dir(path)),
        ("secret_leak_campaign", _is_secret_leak_campaign_dir(path)),
        ("secret_leak_variation", _is_secret_leak_variation_dir(path)),
        ("semantic_drift_campaign", _is_semantic_drift_campaign_dir(path)),
        (
            "semantic_propagation_campaign",
            _is_semantic_propagation_campaign_dir(path),
        ),
        ("swarm_defense_contour", _is_swarm_defense_contour_dir(path)),
        ("swarm_defense_live", _is_swarm_defense_live_campaign_dir(path)),
        (
            "marketing_web_injection",
            _is_marketing_web_injection_campaign_dir(path),
        ),
        ("marketing_web_live", _is_marketing_web_live_campaign_dir(path)),
        ("swarm_resilience", _is_swarm_resilience_campaign_dir(path)),
        ("context_consent", _is_context_consent_campaign_dir(path)),
        ("tool_authority", _is_tool_authority_campaign_dir(path)),
        ("rag_context", _is_rag_context_campaign_dir(path)),
        ("planner_task", _is_planner_task_campaign_dir(path)),
        ("memory_rehydration", _is_memory_rehydration_campaign_dir(path)),
        ("run_diff", (path / "run_diff.json").exists()),
        ("evidence_quality", (path / "evidence_quality.json").exists()),
        ("run_stats", (path / "run_stats.json").exists()),
        ("showcase", (path / "showcase.json").exists()),
        ("report", (path / "traces.json").exists()),
    )
    return [name for name, matched in checks if matched]


def _validate_into(path: Path, root: Path, result: ValidationResult) -> None:
    if not path.exists():
        result._err(f"missing path: {_rel(path, root)}")
        return
    if path.is_file() and path.name == "evidence-status-registry.json":
        result.evidence_status_registry_files.append(_rel(path, root))
        _validate_evidence_status_registry_file(path, root, result)
        return
    if not path.is_dir():
        result._err(f"not a directory: {_rel(path, root)}")
        return
    recognized_kinds = _recognized_artifact_kinds(path)
    if len(recognized_kinds) > 1:
        result._err(
            f"{_rel(path, root)}: ambiguous artifact directory matches multiple "
            f"contracts: {', '.join(recognized_kinds)}"
        )
        return
    if _is_comparison_dir(path):
        result.comparison_dirs.append(_rel(path, root))
        _validate_comparison_dir(path, root, result)
    elif _is_external_dir(path):
        result.external_dirs.append(_rel(path, root))
        _validate_external_dir(path, root, result)
    elif _is_local_swarm_dir(path):
        result.local_swarm_dirs.append(_rel(path, root))
        _validate_local_swarm_dir(path, root, result)
    elif _is_local_swarm_matrix_dir(path):
        result.local_swarm_matrix_dirs.append(_rel(path, root))
        _validate_local_swarm_matrix_dir(path, root, result)
    elif _is_evidence_campaign_dir(path):
        result.evidence_campaign_dirs.append(_rel(path, root))
        _validate_evidence_campaign_dir(path, root, result)
    elif _is_secret_leak_campaign_dir(path):
        result.secret_leak_campaign_dirs.append(_rel(path, root))
        _validate_secret_leak_campaign_dir(path, root, result)
    elif _is_secret_leak_variation_dir(path):
        result.secret_leak_variation_dirs.append(_rel(path, root))
        _validate_secret_leak_variation_dir(path, root, result)
    elif _is_semantic_drift_campaign_dir(path):
        result.semantic_drift_campaign_dirs.append(_rel(path, root))
        _validate_semantic_drift_campaign_dir(path, root, result)
    elif _is_semantic_propagation_campaign_dir(path):
        result.semantic_propagation_campaign_dirs.append(_rel(path, root))
        _validate_semantic_propagation_campaign_dir(path, root, result)
    elif _is_swarm_defense_contour_dir(path):
        result.swarm_defense_contour_dirs.append(_rel(path, root))
        _validate_swarm_defense_contour_dir(path, root, result)
    elif _is_swarm_defense_live_campaign_dir(path):
        result.swarm_defense_live_campaign_dirs.append(_rel(path, root))
        _validate_swarm_defense_live_campaign_dir(path, root, result)
    elif _is_marketing_web_injection_campaign_dir(path):
        result.marketing_web_injection_campaign_dirs.append(_rel(path, root))
        _validate_marketing_web_injection_campaign_dir(path, root, result)
    elif _is_marketing_web_live_campaign_dir(path):
        result.marketing_web_live_campaign_dirs.append(_rel(path, root))
        _validate_marketing_web_live_campaign_dir(path, root, result)
    elif _is_swarm_resilience_campaign_dir(path):
        result.swarm_resilience_campaign_dirs.append(_rel(path, root))
        _validate_swarm_resilience_campaign_dir(path, root, result)
    elif _is_context_consent_campaign_dir(path):
        result.context_consent_campaign_dirs.append(_rel(path, root))
        _validate_context_consent_campaign_dir(path, root, result)
    elif _is_tool_authority_campaign_dir(path):
        result.tool_authority_campaign_dirs.append(_rel(path, root))
        _validate_tool_authority_campaign_dir(path, root, result)
    elif _is_rag_context_campaign_dir(path):
        result.rag_context_campaign_dirs.append(_rel(path, root))
        _validate_rag_context_campaign_dir(path, root, result)
    elif _is_planner_task_campaign_dir(path):
        result.planner_task_campaign_dirs.append(_rel(path, root))
        _validate_planner_task_campaign_dir(path, root, result)
    elif _is_memory_rehydration_campaign_dir(path):
        result.memory_rehydration_campaign_dirs.append(_rel(path, root))
        _validate_memory_rehydration_campaign_dir(path, root, result)
    elif (path / "run_diff.json").exists():
        result.run_diff_dirs.append(_rel(path, root))
        _validate_run_diff_dir(path, root, result)
    elif (path / "evidence_quality.json").exists():
        result.evidence_quality_dirs.append(_rel(path, root))
        _validate_evidence_quality_dir(path, root, result)
    elif (path / "run_stats.json").exists():
        result.run_stats_dirs.append(_rel(path, root))
        _validate_run_stats_dir(path, root, result)
    elif (path / "showcase.json").exists():
        result.showcase_dirs.append(_rel(path, root))
        _validate_showcase_dir(path, root, result)
    elif (path / "traces.json").exists():
        result.report_dirs.append(_rel(path, root))
        _validate_report_dir(path, root, result)
    else:
        children = sorted((c for c in path.iterdir() if c.is_dir()), key=lambda c: c.name)
        if not children:
            result._warn(f"no benchmark artifacts found under {_rel(path, root)}")
            return
        for child in children:
            _validate_into(child, root, result)


def _find_repository_root(path: Path) -> Path | None:
    resolved = path.resolve(strict=False)
    candidates = (resolved, *resolved.parents) if resolved.is_dir() else resolved.parents
    for candidate in candidates:
        if (candidate / "pyproject.toml").is_file() and (
            candidate / "src" / "agentic_security_harness"
        ).is_dir():
            return candidate
    return None


def _projection_verification(entry_class: str, reconciliation_state: str) -> str:
    if entry_class == "historical_rule_snapshot":
        return "legacy-structural-only"
    if entry_class == "maintainer_declaration_unverified":
        return "unverified-maintainer-declaration"
    if reconciliation_state == "reconciled_with_receipt":
        return "reconciled-private-projection"
    if entry_class in {
        "historical_detector_summary",
        "local_empirical_unreconciled",
        "local_empirical_reconciled",
        "independently_labelled_evaluation",
    }:
        return "unverified-private-projection"
    return "not-applicable"


def _attach_public_evidence_statuses(path: Path, result: ValidationResult) -> None:
    if path.is_file():
        return
    repository_root = _find_repository_root(path)
    if repository_root is None:
        return
    try:
        input_path = path.resolve(strict=False)
        input_path.relative_to(repository_root)
    except (OSError, ValueError):
        return

    registry_path = repository_root / "docs" / "evidence-status-registry.json"
    if not registry_path.is_file():
        result._err("evidence-status-registry: required public registry is missing")
        return
    try:
        registry = load_evidence_status_registry(registry_path)
    except ValidationError as exc:
        result._err(f"evidence-status-registry: schema: {_fmt_error(exc)}")
        return
    except (OSError, UnicodeError):
        result._err("evidence-status-registry: could not read public registry")
        return

    selected = []
    for entry in registry.entries:
        for raw_path in entry.artifact_paths:
            artifact_path = (repository_root / raw_path).resolve(strict=False)
            try:
                artifact_path.relative_to(input_path)
            except ValueError:
                continue
            selected.append(entry)
            break

    result.evidence_statuses.extend(
        ValidatedEvidenceStatus(
            evidence_id=entry.evidence_id,
            evidence_class=entry.evidence_class,
            schema_state=entry.schema_state,
            causal_scope=entry.causal_scope,
            reconciliation_state=entry.reconciliation_state,
            origin_authentication=entry.origin_authentication,
            projection_verification=cast(
                Literal[
                    "not-applicable",
                    "legacy-structural-only",
                    "unverified-maintainer-declaration",
                    "unverified-private-projection",
                    "reconciled-private-projection",
                ],
                _projection_verification(
                    entry.evidence_class,
                    entry.reconciliation_state,
                ),
            ),
        )
        for entry in sorted(selected, key=lambda item: item.evidence_id)
    )


def _validate_evidence_status_registry_file(
    path: Path,
    root: Path,
    result: ValidationResult,
) -> None:
    rel = _rel(path, root)
    try:
        registry = load_evidence_status_registry(path)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    except (OSError, UnicodeError):
        result._err(f"{rel}: could not read evidence status registry")
        return

    repository_root = _find_repository_root(path)
    if repository_root is None:
        result._err(f"{rel}: repository root could not be established")
        return
    for error in validate_registry_artifact_paths(
        registry,
        repository_root=repository_root,
    ):
        result._err(f"{rel}: {error}")


def _validate_local_swarm_dir(path: Path, root: Path, result: ValidationResult) -> None:
    rel = _rel(path / "local_swarm_summary.json", root)
    raw = _load_json(path / "local_swarm_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(path / "local_swarm_summary.json", "local_swarm", root, result)
    from agentic_security_harness.local_swarm import (
        SWARM_MODES,
        SWARM_SCENARIOS,
        LocalSwarmSummary,
        _roles_for_mode,
        build_swarm_metrics,
        evaluate_swarm_scenario,
        render_swarm_report,
    )

    try:
        summary = LocalSwarmSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    contract_data = summary.model_dump(mode="json")
    contract_data.pop("claim_boundary", None)
    canonical_contract = LocalSwarmSummary.model_validate(contract_data)
    if summary.claim_boundary != canonical_contract.claim_boundary:
        result._err(f"{rel}: claim_boundary does not match the producer contract")
    if len(summary.modes) != len(set(summary.modes)):
        result._err(f"{rel}: duplicate modes")
    if len(summary.scenarios) != len(set(summary.scenarios)):
        result._err(f"{rel}: duplicate scenarios")
    manifest_path = path / "run_index.json"
    campaign_profile = "shipped_full"
    profile_declared = False
    if not manifest_path.is_file():
        result._err(f"{_rel(manifest_path, root)}: missing for local swarm bundle")
    else:
        manifest_raw = _load_json(manifest_path, root, result)
        if isinstance(manifest_raw, dict):
            metadata = manifest_raw.get("metadata")
            if isinstance(metadata, dict) and "campaign_profile" in metadata:
                profile_declared = True
                campaign_profile = str(metadata["campaign_profile"])
    if campaign_profile not in {"shipped_full", "custom_subset"}:
        result._err(f"{_rel(manifest_path, root)}: invalid campaign_profile")
    if campaign_profile == "shipped_full" and (
        summary.scenarios != list(SWARM_SCENARIOS) or summary.modes != list(SWARM_MODES)
    ):
        result._err(f"{rel}: shipped_full profile does not match the canonical scenarios/modes")
    expected_keys = {(scenario, mode) for scenario in summary.scenarios for mode in summary.modes}
    actual_keys = [(row.scenario_id, row.mode) for row in summary.results]
    if len(actual_keys) != len(set(actual_keys)):
        result._err(f"{rel}: duplicate scenario/mode result rows")
    if set(actual_keys) != expected_keys:
        result._err(f"{rel}: scenario/mode result matrix mismatch")
    for idx, row in enumerate(summary.results):
        label = f"{rel}: results[{idx}]"
        expected_row = evaluate_swarm_scenario(row.scenario_id, row.mode)
        if row.model_dump(mode="json", exclude={"role_transcripts"}) != (
            expected_row.model_dump(mode="json", exclude={"role_transcripts"})
        ):
            result._err(f"{label} does not match deterministic scenario evaluation")
        if summary.executed_model_calls:
            expected_roles = list(_roles_for_mode(row.mode))
            actual_roles = [transcript.role for transcript in row.role_transcripts]
            if actual_roles != expected_roles:
                result._err(f"{label}.role_transcripts role slots mismatch")
        for transcript_idx, transcript in enumerate(row.role_transcripts):
            transcript_label = f"{label}.role_transcripts[{transcript_idx}]"
            _validate_optional_sha256(
                transcript.prompt_sha256,
                f"{transcript_label}.prompt_sha256",
                result,
            )
            if not transcript.prompt_sha256:
                result._err(f"{transcript_label}.prompt_sha256 is empty")
            expected_model = summary.role_models.get(transcript.role, summary.model)
            if transcript.model != expected_model:
                result._err(f"{transcript_label}.model mismatch")
            if transcript.adapter_error:
                if transcript.response_sha256 or transcript.response_preview:
                    result._err(f"{transcript_label} adapter error contains response evidence")
            else:
                _validate_optional_sha256(
                    transcript.response_sha256,
                    f"{transcript_label}.response_sha256",
                    result,
                )
                if not transcript.response_sha256:
                    result._err(f"{transcript_label}.response_sha256 is empty")
    expected_metrics = build_swarm_metrics(summary.results, len(summary.scenarios))
    if summary.metrics.model_dump(mode="json") != expected_metrics.model_dump(mode="json"):
        result._err(f"{rel}: metrics do not match recomputed result rows")
    transcript_count = sum(len(row.role_transcripts) for row in summary.results)
    if summary.executed_model_calls:
        if summary.request_count != transcript_count:
            result._err(f"{rel}: request_count does not match role transcripts")
        if summary.request_count > summary.max_requests:
            result._err(f"{rel}: request_count exceeds max_requests")
    elif summary.request_count or transcript_count:
        result._err(f"{rel}: non-executed run contains model-call evidence")
    if (
        summary.metrics.bounded_swarm_boundary_failures
        > summary.metrics.naive_swarm_boundary_failures
    ):
        result._expect(f"{rel}: bounded failures exceed naive failures")
    if summary.executed_model_calls and summary.request_count <= 0:
        result._err(f"{rel}: executed_model_calls true but request_count is zero")
    report_path = path / "local_swarm_report.md"
    if not report_path.exists():
        result._err(f"{_rel(report_path, root)}: missing")
    else:
        _validate_exact_rendered_report(
            report_path,
            render_swarm_report(summary),
            root,
            result,
        )
    _validate_run_manifest(path, root, result)
    expected_metadata: dict[str, object] = {
        "executed_model_calls": summary.executed_model_calls,
        "request_count": summary.request_count,
        "max_requests": summary.max_requests,
    }
    if profile_declared:
        expected_metadata["campaign_profile"] = campaign_profile
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "local_swarm",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "bounded-local-swarm",
            "model": summary.model,
            "scenario": ",".join(summary.scenarios),
            "variants": [str(mode) for mode in summary.modes],
            "repeats": 1,
            "outcomes": {
                "bounded_boundary_failures": (summary.metrics.bounded_swarm_boundary_failures),
                "naive_boundary_failures": (summary.metrics.naive_swarm_boundary_failures),
                "verifier_blocks": summary.metrics.verifier_blocks,
            },
            "metadata": expected_metadata,
            "artifacts": sorted(
                [
                    "local_swarm_summary.json",
                    "local_swarm_report.md",
                ]
            ),
        },
    )
    _scan_secrets(path / "local_swarm_summary.json", root, result)
    _scan_secrets(path / "local_swarm_report.md", root, result)


def _validate_local_swarm_matrix_dir(path: Path, root: Path, result: ValidationResult) -> None:
    rel = _rel(path / "local_swarm_attack_matrix.json", root)
    raw = _load_json(path / "local_swarm_attack_matrix.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "local_swarm_attack_matrix.json",
        "local_swarm_matrix",
        root,
        result,
    )
    from agentic_security_harness.local_swarm_matrix import (
        LocalSwarmAttackMatrix,
        _build_metrics,
        _evaluate_case,
        build_local_swarm_attack_matrix,
        declared_matrix_cases,
        render_local_swarm_attack_matrix,
    )

    try:
        matrix = LocalSwarmAttackMatrix.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if matrix != build_local_swarm_attack_matrix():
        result._err(f"{rel}: matrix does not match the shipped specification")
    case_ids = [row.case_id for row in matrix.rows]
    if len(case_ids) != len(set(case_ids)):
        result._err(f"{rel}: duplicate case_id rows")
    declared_cases = declared_matrix_cases()
    declared_by_id = {case.case_id: case for case in declared_cases}
    if set(case_ids) != set(declared_by_id):
        result._err(f"{rel}: case rows do not match declared matrix cases")
    for idx, row in enumerate(matrix.rows):
        case = declared_by_id.get(row.case_id)
        if case is None:
            continue
        expected_row = _evaluate_case(case)
        if row.model_dump(mode="json") != expected_row.model_dump(mode="json"):
            result._err(f"{rel}: rows[{idx}] does not match deterministic case evaluation")
    expected_metrics = _build_metrics(matrix.rows)
    if matrix.metrics.model_dump(mode="json") != expected_metrics.model_dump(mode="json"):
        result._err(f"{rel}: metrics do not match recomputed matrix rows")
    if matrix.metrics.bounded_swarm_boundary_failures:
        result._expect(f"{rel}: bounded matrix has boundary failures")
    if matrix.metrics.bounded_blocks != matrix.metrics.cases:
        result._expect(f"{rel}: bounded blocks do not cover every matrix case")
    if matrix.metrics.base_scenarios < 1:
        result._expect(f"{rel}: no base scenarios covered")
    report_path = path / "local_swarm_attack_matrix.md"
    if not report_path.exists():
        result._err(f"{_rel(report_path, root)}: missing")
    else:
        _validate_exact_rendered_report(
            report_path,
            render_local_swarm_attack_matrix(matrix),
            root,
            result,
        )
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "matrix",
            "created_at": "",
            "tool_version": "",
            "target": "bounded-local-swarm",
            "model": "",
            "scenario": "local-swarm-attack-variation-matrix",
            "variants": sorted(matrix.metrics.coverage_by_family),
            "repeats": 1,
            "outcomes": {
                "cases": matrix.metrics.cases,
                "naive_boundary_failures": (matrix.metrics.naive_swarm_boundary_failures),
                "bounded_boundary_failures": (matrix.metrics.bounded_swarm_boundary_failures),
                "bounded_blocks": matrix.metrics.bounded_blocks,
            },
            "metadata": {
                "base_scenarios": matrix.metrics.base_scenarios,
                "variation_families": matrix.metrics.variation_families,
                "contract_coverage": matrix.metrics.contract_coverage,
            },
            "artifacts": sorted(
                [
                    "local_swarm_attack_matrix.json",
                    "local_swarm_attack_matrix.md",
                ]
            ),
        },
    )
    _scan_secrets(path / "local_swarm_attack_matrix.json", root, result)
    _scan_secrets(path / "local_swarm_attack_matrix.md", root, result)


def _validate_evidence_campaign_dir(path: Path, root: Path, result: ValidationResult) -> None:
    rel = _rel(path / "evidence_campaign_summary.json", root)
    raw = _load_json(path / "evidence_campaign_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "evidence_campaign_summary.json",
        "evidence_campaign",
        root,
        result,
    )
    from agentic_security_harness.evidence_campaign import (
        CAMPAIGN_MODES,
        CONTROL_BY_FAMILY,
        EvidenceCampaignSummary,
        _build_ablation_metrics,
        _build_campaign_metrics,
        _confusion,
        _digest,
        _hash_model,
        build_evidence_campaign,
        render_campaign_report,
    )

    try:
        summary = EvidenceCampaignSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    canonical = build_evidence_campaign(created_at=summary.created_at)
    if summary != canonical:
        result._err(f"{rel}: summary does not match the shipped campaign specification")
    if summary.metric_version != "confusion-v1":
        result._err(f"{rel}: unsupported metric_version")
    case_ids = [case.case_id for case in summary.cases]
    if len(case_ids) != len(set(case_ids)):
        result._err(f"{rel}: duplicate case_id values")
    expected_keys = {(case.case_id, mode) for case in summary.cases for mode in CAMPAIGN_MODES}
    actual_keys = [(item.case_id, item.mode) for item in summary.observations]
    if len(actual_keys) != len(set(actual_keys)):
        result._err(f"{rel}: duplicate case/mode observations")
    if set(actual_keys) != expected_keys:
        result._err(f"{rel}: case/mode observation matrix mismatch")
    cases_by_id = {case.case_id: case for case in summary.cases}
    bounded_by_case = {
        item.case_id: item for item in summary.observations if item.mode == "bounded_swarm"
    }
    for idx, item in enumerate(summary.observations):
        label = f"{rel}: observations[{idx}]"
        case = cases_by_id.get(item.case_id)
        if case is None:
            result._err(f"{label} references unknown case")
            continue
        if (
            item.claim_family != case.claim_family
            or item.case_kind != case.case_kind
            or item.ground_truth != case.ground_truth
        ):
            result._err(f"{label} case metadata mismatch")
        if item.confusion != _confusion(item.ground_truth, item.decision):
            result._err(f"{label}.confusion contradicts ground_truth/decision")
        expected_input_hash = _hash_model(
            {
                "case": case.model_dump(mode="json"),
                "mode": item.mode,
                "metric_version": summary.metric_version,
            }
        )
        expected_result_hash = _hash_model(
            {
                "case_id": item.case_id,
                "mode": item.mode,
                "decision": item.decision,
                "confusion": item.confusion,
                "boundary_failure": item.boundary_failure,
                "blocked_reasons": item.blocked_reasons,
            }
        )
        if item.input_hash != expected_input_hash:
            result._err(f"{label}.input_hash mismatch")
        if item.result_hash != expected_result_hash:
            result._err(f"{label}.result_hash mismatch")
    ablation_ids = [item.case_id for item in summary.ablation_observations]
    if len(ablation_ids) != len(set(ablation_ids)):
        result._err(f"{rel}: duplicate ablation case rows")
    for idx, ablation_item in enumerate(summary.ablation_observations):
        label = f"{rel}: ablation_observations[{idx}]"
        case = cases_by_id.get(ablation_item.case_id)
        if case is None:
            result._err(f"{label} references unknown case")
            continue
        bounded_row = bounded_by_case.get(ablation_item.case_id)
        if (
            ablation_item.claim_family != case.claim_family
            or ablation_item.case_kind != case.case_kind
            or ablation_item.ground_truth != case.ground_truth
        ):
            result._err(f"{label} case metadata mismatch")
        if ablation_item.control_disabled != CONTROL_BY_FAMILY[case.claim_family]:
            result._err(f"{label}.control_disabled mismatch")
        if ablation_item.ablated_confusion != _confusion(
            ablation_item.ground_truth, ablation_item.ablated_decision
        ):
            result._err(f"{label}.ablated_confusion contradicts truth/decision")
        if bounded_row is not None:
            if ablation_item.full_bounded_confusion != bounded_row.confusion:
                result._err(f"{label}.full_bounded_confusion mismatch")
            expected_regression = (
                bounded_row.confusion in {"TP", "TN"}
                and ablation_item.ablated_confusion != bounded_row.confusion
            )
            if ablation_item.regression_when_disabled != expected_regression:
                result._err(f"{label}.regression_when_disabled mismatch")
        expected_result_hash = _hash_model(
            {
                "case_id": ablation_item.case_id,
                "control_disabled": ablation_item.control_disabled,
                "decision": ablation_item.ablated_decision,
                "confusion": ablation_item.ablated_confusion,
                "regression_when_disabled": ablation_item.regression_when_disabled,
            }
        )
        if ablation_item.result_hash != expected_result_hash:
            result._err(f"{label}.result_hash mismatch")
    expected_metrics = _build_campaign_metrics(summary.cases, summary.observations)
    if summary.metrics.model_dump(mode="json") != expected_metrics.model_dump(mode="json"):
        result._err(f"{rel}: metrics do not match recomputed observations")
    expected_ablation_metrics = _build_ablation_metrics(summary.ablation_observations)
    if summary.ablation_metrics.model_dump(mode="json") != expected_ablation_metrics.model_dump(
        mode="json"
    ):
        result._err(f"{rel}: ablation_metrics do not match recomputed observations")
    bounded = summary.metrics.by_mode.get("bounded_swarm")
    naive = summary.metrics.by_mode.get("naive_swarm")
    if bounded is None or naive is None:
        result._expect(f"{rel}: missing required mode metrics")
    elif bounded.failure_rate > naive.failure_rate:
        result._expect(f"{rel}: bounded failure rate exceeds naive failure rate")
    if summary.metrics.claim_families < 1:
        result._expect(f"{rel}: no claim families covered")
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases does not match case count")
    if summary.metrics.observations != len(summary.observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.ablation_metrics.observations != len(summary.ablation_observations):
        result._err(f"{rel}: ablation_metrics.observations does not match ablation count")
    if summary.ablation_metrics.observations != summary.metrics.cases:
        result._expect(f"{rel}: ablation observations do not cover every campaign case")
    if summary.ablation_metrics.benign_regressions:
        result._expect(f"{rel}: ablation introduced benign regressions")
    if (
        summary.ablation_metrics.unsafe_regressions
        < summary.metrics.by_mode["bounded_swarm"].true_positive
    ):
        result._expect(f"{rel}: ablation does not explain every bounded true positive")
    report_path = path / "evidence_campaign_report.md"
    if not report_path.exists():
        result._err(f"{_rel(report_path, root)}: missing")
    else:
        _validate_exact_rendered_report(
            report_path,
            render_campaign_report(summary),
            root,
            result,
        )
    digest_path = path / "evidence_campaign_digest.json"
    if not digest_path.exists():
        result._err(f"{_rel(digest_path, root)}: missing")
    else:
        digest = _load_json(digest_path, root, result)
        if digest is not None and digest != _digest(summary):
            result._err(f"{_rel(digest_path, root)}: digest projection mismatch")
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "evidence_campaign",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "bounded-agent-evidence-campaign",
            "model": "",
            "scenario": summary.campaign_id,
            "variants": list(CAMPAIGN_MODES),
            "repeats": 1,
            "outcomes": {
                "cases": summary.metrics.cases,
                "observations": summary.metrics.observations,
                "bounded_false_negative": (summary.metrics.by_mode["bounded_swarm"].false_negative),
                "bounded_false_positive": (summary.metrics.by_mode["bounded_swarm"].false_positive),
                "ablation_unsafe_regressions": (summary.ablation_metrics.unsafe_regressions),
            },
            "metadata": {
                "claim_families": summary.metrics.claim_families,
                "control_effect_naive_to_bounded": (
                    summary.metrics.control_effect_naive_to_bounded
                ),
                "usability_cost_naive_to_bounded": (
                    summary.metrics.usability_cost_naive_to_bounded
                ),
                "ablation_unsafe_regression_rate": (
                    summary.ablation_metrics.unsafe_regression_rate
                ),
            },
            "artifacts": sorted(
                [
                    "evidence_campaign_summary.json",
                    "evidence_campaign_report.md",
                    "evidence_campaign_digest.json",
                ]
            ),
        },
    )
    for name in (
        "evidence_campaign_summary.json",
        "evidence_campaign_report.md",
        "evidence_campaign_digest.json",
    ):
        _scan_secrets(path / name, root, result)


def _validate_secret_leak_campaign_dir(path: Path, root: Path, result: ValidationResult) -> None:
    rel = _rel(path / "secret_leak_campaign_summary.json", root)
    raw = _load_json(path / "secret_leak_campaign_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "secret_leak_campaign_summary.json",
        "secret_leak_campaign",
        root,
        result,
    )
    from agentic_security_harness.secret_leak_campaign import (
        SecretLeakCampaignSummary,
        _build_metrics,
        _campaign_digest,
        build_secret_leak_campaign,
        render_secret_leak_campaign,
    )

    try:
        summary = SecretLeakCampaignSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    canonical = build_secret_leak_campaign(created_at=summary.created_at)
    if summary.scenarios != canonical.scenarios:
        result._err(f"{rel}: scenarios do not match the declared campaign corpus")
    if summary.claim_boundary != canonical.claim_boundary:
        result._err(f"{rel}: claim_boundary does not match the producer contract")

    def _observation_key(item: object) -> tuple[object, object, object]:
        observation = cast(Any, item)
        return observation.scenario_id, observation.mode, observation.disabled_control

    def _observation_contract(item: object) -> dict[str, object]:
        observation = cast(Any, item)
        data = observation.model_dump(mode="json")
        data.pop("canary_fingerprint", None)
        return cast(dict[str, object], data)

    expected_rows = {
        _observation_key(item): _observation_contract(item) for item in canonical.observations
    }
    actual_rows = {
        _observation_key(item): _observation_contract(item) for item in summary.observations
    }
    if len(actual_rows) != len(summary.observations):
        result._err(f"{rel}: duplicate scenario/mode/disabled-control observation")
    if set(actual_rows) != set(expected_rows):
        result._err(f"{rel}: observation matrix does not match the declared corpus")
    for key in sorted(set(actual_rows) & set(expected_rows), key=str):
        if actual_rows[key] != expected_rows[key]:
            result._err(f"{rel}: observation contract mismatch for {key}")

    fingerprints: dict[str, set[str]] = {}
    for item in summary.observations:
        if not _SHA256_HEX.fullmatch(item.canary_fingerprint):
            result._err(f"{rel}: invalid canary fingerprint for {item.scenario_id}")
        fingerprints.setdefault(item.scenario_id, set()).add(item.canary_fingerprint)
    for scenario_id, values in fingerprints.items():
        if len(values) != 1:
            result._err(f"{rel}: inconsistent canary fingerprint for {scenario_id}")

    rebuilt_metrics = _build_metrics(summary.observations, len(summary.scenarios))
    if summary.metrics != rebuilt_metrics:
        result._err(f"{rel}: metrics do not match observations")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw prompt/response/value fields")
    report_path = path / "secret_leak_campaign_report.md"
    if not report_path.exists():
        result._err(f"{_rel(report_path, root)}: missing")
    else:
        _validate_exact_rendered_report(
            report_path,
            render_secret_leak_campaign(summary),
            root,
            result,
        )
    digest_path = path / "secret_leak_campaign_digest.json"
    if not digest_path.exists():
        result._err(f"{_rel(digest_path, root)}: missing")
    else:
        digest = _load_json(digest_path, root, result)
        if digest is not None and digest != _campaign_digest(summary):
            result._err(f"{_rel(digest_path, root)}: digest projection mismatch")
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "secret_leak_campaign",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "synthetic-secret-leak-campaign",
            "model": "",
            "scenario": ",".join(item.scenario_id for item in summary.scenarios),
            "variants": ["naive", "bounded", "ablation", "benign"],
            "repeats": 1,
            "outcomes": {
                "naive_leaks": summary.metrics.naive_leaks,
                "bounded_leaks": summary.metrics.bounded_leaks,
                "ablation_leaks": summary.metrics.ablation_leaks,
                "benign_leaks": summary.metrics.benign_leaks,
            },
            "metadata": {
                "synthetic_only": True,
                "raw_private": True,
                "scenarios": summary.metrics.scenarios,
                "observations": summary.metrics.observations,
            },
            "artifacts": sorted(
                [
                    "secret_leak_campaign_summary.json",
                    "secret_leak_campaign_report.md",
                    "secret_leak_campaign_digest.json",
                ]
            ),
        },
    )
    for name in (
        "secret_leak_campaign_summary.json",
        "secret_leak_campaign_report.md",
        "secret_leak_campaign_digest.json",
    ):
        _scan_secrets(path / name, root, result)


def _validate_secret_leak_variation_dir(path: Path, root: Path, result: ValidationResult) -> None:
    rel = _rel(path / "secret_leak_variation_summary.json", root)
    raw = _load_json(path / "secret_leak_variation_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "secret_leak_variation_summary.json",
        "secret_leak_variations",
        root,
        result,
    )
    from agentic_security_harness.secret_leak_campaign import (
        SecretLeakVariationSummary,
        _build_variation_metrics,
        _variation_digest,
        _variation_failure_step,
        declared_secret_variation_cases,
        render_secret_leak_variation_summary,
    )

    try:
        summary = SecretLeakVariationSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    contract_data = summary.model_dump(mode="json")
    contract_data.pop("claim_boundary", None)
    contract_data.pop("non_claims", None)
    canonical_contract = SecretLeakVariationSummary.model_validate(contract_data)
    if summary.claim_boundary != canonical_contract.claim_boundary:
        result._err(f"{rel}: claim_boundary does not match the producer contract")
    if summary.non_claims != canonical_contract.non_claims:
        result._err(f"{rel}: non_claims do not match the producer contract")
    declared_cases = declared_secret_variation_cases()
    if summary.cases != declared_cases:
        result._err(f"{rel}: cases do not match the declared variation corpus")
    case_map = {item.case_id: item for item in declared_cases}
    seen_rows: set[tuple[str, str, str]] = set()
    for item in summary.observations:
        key = (item.model, item.case_id, item.pressure_mode)
        if key in seen_rows:
            result._err(f"{rel}: duplicate model/case/pressure observation {key}")
        seen_rows.add(key)
        if not item.model.strip() or item.model != item.model.strip():
            result._err(f"{rel}: model must be trimmed and nonblank for {item.case_id}")
        case = case_map.get(item.case_id)
        if case is None:
            result._err(f"{rel}: unknown case_id {item.case_id}")
        elif (
            item.scenario_id != case.scenario_id
            or item.variation_id != case.variation_id
            or item.turns != case.turns
        ):
            result._err(f"{rel}: observation does not match declared case {item.case_id}")
        if item.leaked != (item.leak_kind != "none"):
            result._err(f"{rel}: leaked/leak_kind mismatch for {item.case_id}")
        if item.adapter_error:
            if item.response_sha256 or item.leaked or item.first_failure_step:
                result._err(f"{rel}: adapter-error state is inconsistent for {item.case_id}")
        else:
            if not _SHA256_HEX.fullmatch(item.response_sha256):
                result._err(f"{rel}: completed response hash is invalid for {item.case_id}")
            expected_step = _variation_failure_step(item.variation_id) if item.leaked else ""
            if item.first_failure_step != expected_step:
                result._err(f"{rel}: first_failure_step mismatch for {item.case_id}")
    rebuilt_metrics = _build_variation_metrics(summary.cases, summary.observations)
    if summary.metrics != rebuilt_metrics:
        result._err(f"{rel}: metrics do not match cases and observations")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw prompt/response/value fields")
    report_path = path / "secret_leak_variation_report.md"
    if not report_path.exists():
        result._err(f"{_rel(report_path, root)}: missing")
    else:
        _validate_exact_rendered_report(
            report_path,
            render_secret_leak_variation_summary(summary),
            root,
            result,
        )
    digest_path = path / "secret_leak_variation_digest.json"
    if not digest_path.exists():
        result._err(f"{_rel(digest_path, root)}: missing")
    else:
        digest = _load_json(digest_path, root, result)
        if digest is not None and digest != _variation_digest(summary):
            result._err(f"{_rel(digest_path, root)}: digest projection mismatch")
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "secret_leak_variations",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "local-model-secret-leak-variations",
            "model": "",
            "scenario": ",".join(item.variation_id for item in summary.cases),
            "variants": [
                "neutral",
                "coercive",
                "sanitized_claim",
                "authority_pressure",
            ],
            "repeats": 1,
            "outcomes": {
                "leaks": summary.metrics.leaks,
                "observations": summary.metrics.observations,
                "adapter_errors": summary.metrics.adapter_errors,
            },
            "metadata": {
                "raw_private": True,
                "models": summary.metrics.models,
                "cases": summary.metrics.cases,
                "response_hash_coverage": summary.metrics.response_hash_coverage,
            },
            "artifacts": sorted(
                [
                    "secret_leak_variation_summary.json",
                    "secret_leak_variation_report.md",
                    "secret_leak_variation_digest.json",
                ]
            ),
        },
    )
    for name in (
        "secret_leak_variation_summary.json",
        "secret_leak_variation_report.md",
        "secret_leak_variation_digest.json",
    ):
        _scan_secrets(path / name, root, result)


def _validate_semantic_drift_campaign_dir(path: Path, root: Path, result: ValidationResult) -> None:
    rel = _rel(path / "semantic_drift_summary.json", root)
    raw = _load_json(path / "semantic_drift_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "semantic_drift_summary.json",
        "semantic_drift_campaign",
        root,
        result,
    )
    from agentic_security_harness.semantic_drift_campaign import (
        DETERMINISTIC_MODES,
        PRESSURE_MODES,
        SemanticDriftSummary,
        _build_metrics,
        _campaign_digest,
        build_semantic_drift_campaign,
        render_semantic_drift_summary,
    )

    try:
        summary = SemanticDriftSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    current_schema = summary.schema_version == SCHEMA_VERSIONS["semantic_drift_campaign"]
    if current_schema:
        canonical = build_semantic_drift_campaign(created_at=summary.created_at)
        if summary.cases != canonical.cases:
            result._err(f"{rel}: cases do not match the declared campaign corpus")
        if summary.claim_boundary != canonical.claim_boundary:
            result._err(f"{rel}: claim_boundary does not match the producer contract")
        if summary.non_claims != canonical.non_claims:
            result._err(f"{rel}: non_claims do not match the producer contract")
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases does not match case count")
    if summary.metrics.observations != len(summary.observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.deterministic_results != len(summary.deterministic_results):
        result._err(f"{rel}: metrics.deterministic_results does not match deterministic rows")
    if summary.metrics.models != len({item.model for item in summary.observations}):
        result._err(f"{rel}: metrics.models does not match observation models")
    if summary.metrics.drift_detections != sum(
        1 for item in summary.observations if item.drift_detected
    ):
        result._err(f"{rel}: metrics.drift_detections does not match observations")
    if summary.metrics.canary_leaks != sum(
        1 for item in summary.observations if item.canary_leaked
    ):
        result._err(f"{rel}: metrics.canary_leaks does not match observations")
    if summary.metrics.adapter_errors != sum(
        1 for item in summary.observations if item.adapter_error
    ):
        result._err(f"{rel}: metrics.adapter_errors does not match observations")
    case_ids = [case.case_id for case in summary.cases]
    if len(case_ids) != len(set(case_ids)):
        result._err(f"{rel}: duplicate case_id values")
    scenario_ids = [case.scenario_id for case in summary.cases]
    if len(scenario_ids) != len(set(scenario_ids)):
        result._err(f"{rel}: duplicate case scenario_id values")
    expected_row_keys = {
        (case.case_id, mode) for case in summary.cases for mode in DETERMINISTIC_MODES
    }
    actual_row_keys = [(row.case_id, row.mode) for row in summary.deterministic_results]
    if len(actual_row_keys) != len(set(actual_row_keys)):
        result._err(f"{rel}: duplicate deterministic case/mode rows")
    if set(actual_row_keys) != expected_row_keys:
        result._err(f"{rel}: deterministic case/mode matrix mismatch")
    cases_by_id = {case.case_id: case for case in summary.cases}
    for idx, row in enumerate(summary.deterministic_results):
        label = f"{rel}: deterministic_results[{idx}]"
        case = cases_by_id.get(row.case_id)
        if case is None:
            result._err(f"{label} references unknown case")
            continue
        if row.scenario_id != case.scenario_id:
            result._err(f"{label}.scenario_id does not match referenced case")
        if row.drift_accepted != (row.verifier_decision == "allow"):
            result._err(f"{label}.verifier_decision contradicts drift outcome")
        if row.drift_accepted and row.blocked_by:
            result._err(f"{label}.blocked_by is non-empty for accepted drift")
        if not set(row.blocked_by).issubset(set(case.required_controls)):
            result._err(f"{label}.blocked_by contains controls not required by case")
        if not set(row.missing_controls).issubset(set(case.required_controls)):
            result._err(f"{label}.missing_controls contains controls not required by case")
        if row.mode == "bounded_swarm" and row.drift_accepted:
            result._expect(f"{label} bounded swarm accepted semantic drift")
        if row.mode == "naive_swarm" and not row.drift_accepted:
            result._expect(f"{label} naive swarm blocked semantic drift")
    for idx, observation in enumerate(summary.observations):
        label = f"{rel}: observations[{idx}]"
        case = cases_by_id.get(observation.case_id)
        if case is None:
            result._err(f"{label} references unknown case")
            continue
        if observation.scenario_id != case.scenario_id:
            result._err(f"{label}.scenario_id does not match referenced case")
        if observation.turns != case.turns:
            result._err(f"{label}.turns does not match referenced case")
        _validate_optional_sha256(
            observation.response_sha256,
            f"{label}.response_sha256",
            result,
        )
        if not observation.adapter_error and not observation.response_sha256:
            result._err(f"{label}.response_sha256 missing for completed observation")
    expected_metrics = _build_metrics(
        summary.cases,
        summary.deterministic_results,
        summary.observations,
    )
    if current_schema and summary.metrics.model_dump(mode="json") != expected_metrics.model_dump(
        mode="json"
    ):
        result._err(f"{rel}: metrics do not match recomputed campaign rows")
    _validate_ground_truth_metrics(
        rel=rel,
        observations=summary.observations,
        detector_unsafe=[
            item.drift_detected or item.canary_leaked for item in summary.observations
        ],
        actual=summary.metrics.ground_truth,
        result=result,
    )
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw prompt/response/value fields")
    if _contains_forbidden_key(raw, "canary_fingerprint"):
        result._err(f"{rel}: public artifact contains private canary fingerprint")
    if _contains_forbidden_key(raw, "canonical_state_hash"):
        result._err(f"{rel}: public artifact contains private canonical state hash")
    report_path = path / "semantic_drift_report.md"
    if not report_path.exists():
        result._err(f"{_rel(report_path, root)}: missing")
    elif current_schema:
        _validate_exact_rendered_report(
            report_path,
            render_semantic_drift_summary(summary),
            root,
            result,
        )
    digest_path = path / "semantic_drift_digest.json"
    if not digest_path.exists():
        result._err(f"{_rel(digest_path, root)}: missing")
    elif current_schema:
        digest = _load_json(digest_path, root, result)
        if digest is not None and digest != _campaign_digest(summary):
            result._err(f"{_rel(digest_path, root)}: digest projection mismatch")
    for private_name in ("semantic_drift_private.json", "semantic_drift_private.md"):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private semantic drift artifact "
                "must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    if current_schema:
        _validate_manifest_fields(
            path,
            root,
            result,
            expected={
                "run_kind": "semantic_drift_campaign",
                "created_at": summary.created_at,
                "tool_version": "",
                "target": "local-model-semantic-drift",
                "model": "",
                "scenario": ",".join(item.scenario_id for item in summary.cases),
                "variants": list(PRESSURE_MODES),
                "repeats": 1,
                "outcomes": {
                    "drift_detections": summary.metrics.drift_detections,
                    "canary_leaks": summary.metrics.canary_leaks,
                    "verifier_blocks": summary.metrics.verifier_blocks,
                    "observations": summary.metrics.observations,
                },
                "metadata": {
                    "raw_private": True,
                    "synthetic_only": True,
                    "cases": summary.metrics.cases,
                    "models": summary.metrics.models,
                },
                "artifacts": sorted(
                    [
                        "semantic_drift_summary.json",
                        "semantic_drift_report.md",
                        "semantic_drift_digest.json",
                    ]
                ),
            },
        )
    for name in (
        "semantic_drift_summary.json",
        "semantic_drift_report.md",
        "semantic_drift_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _validate_semantic_propagation_campaign_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
    rel = _rel(path / "semantic_propagation_summary.json", root)
    raw = _load_json(path / "semantic_propagation_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "semantic_propagation_summary.json",
        "semantic_propagation_campaign",
        root,
        result,
    )
    from agentic_security_harness.semantic_propagation_campaign import (
        DETERMINISTIC_MODES,
        PRESSURE_MODES,
        SemanticPropagationSummary,
        _build_control_effects,
        _build_metrics,
        _campaign_digest,
        build_semantic_propagation_campaign,
        propagation_verifier_decision,
        render_semantic_propagation_summary,
    )

    try:
        summary = SemanticPropagationSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    current_schema = summary.schema_version == SCHEMA_VERSIONS["semantic_propagation_campaign"]
    if current_schema:
        canonical = build_semantic_propagation_campaign(created_at=summary.created_at)
        if summary.cases != canonical.cases:
            result._err(f"{rel}: cases do not match the declared campaign corpus")
        if summary.control_catalog != canonical.control_catalog:
            result._err(f"{rel}: control_catalog does not match the producer contract")
        if summary.claim_boundary != canonical.claim_boundary:
            result._err(f"{rel}: claim_boundary does not match the producer contract")
        if summary.non_claims != canonical.non_claims:
            result._err(f"{rel}: non_claims do not match the producer contract")
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases does not match case count")
    if summary.metrics.observations != len(summary.observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.deterministic_results != len(summary.deterministic_results):
        result._err(f"{rel}: metrics.deterministic_results does not match deterministic rows")
    if summary.metrics.control_catalog_entries != len(summary.control_catalog):
        result._err(f"{rel}: metrics.control_catalog_entries mismatch")
    if summary.metrics.control_effect_rows != len(summary.control_effects):
        result._err(f"{rel}: metrics.control_effect_rows mismatch")
    if summary.metrics.worker_models != len({item.worker_model for item in summary.observations}):
        result._err(f"{rel}: metrics.worker_models does not match observations")
    if summary.metrics.chief_models != len({item.chief_model for item in summary.observations}):
        result._err(f"{rel}: metrics.chief_models does not match observations")
    if summary.metrics.worker_drift_detections != sum(
        1 for item in summary.observations if item.worker_drift_detected
    ):
        result._err(f"{rel}: metrics.worker_drift_detections mismatch")
    if summary.metrics.chief_acceptances != sum(
        1 for item in summary.observations if item.chief_accepted_drift
    ):
        result._err(f"{rel}: metrics.chief_acceptances mismatch")
    if summary.metrics.canary_leaks != sum(
        1 for item in summary.observations if item.canary_leaked
    ):
        result._err(f"{rel}: metrics.canary_leaks mismatch")
    if summary.metrics.adapter_errors != sum(
        1 for item in summary.observations if item.adapter_error
    ):
        result._err(f"{rel}: metrics.adapter_errors mismatch")
    case_ids = [case.case_id for case in summary.cases]
    if len(case_ids) != len(set(case_ids)):
        result._err(f"{rel}: duplicate case_id values")
    scenario_ids = [case.scenario_id for case in summary.cases]
    if len(scenario_ids) != len(set(scenario_ids)):
        result._err(f"{rel}: duplicate case scenario_id values")
    control_ids = [control.control_id for control in summary.control_catalog]
    if len(control_ids) != len(set(control_ids)):
        result._err(f"{rel}: duplicate control_id values")
    required_controls = {control for case in summary.cases for control in case.required_controls}
    if set(control_ids) != required_controls:
        result._err(f"{rel}: control catalog does not match case requirements")
    expected_row_keys = {
        (case.case_id, mode) for case in summary.cases for mode in DETERMINISTIC_MODES
    }
    actual_row_keys = [(row.case_id, row.mode) for row in summary.deterministic_results]
    if len(actual_row_keys) != len(set(actual_row_keys)):
        result._err(f"{rel}: duplicate deterministic case/mode rows")
    if set(actual_row_keys) != expected_row_keys:
        result._err(f"{rel}: deterministic case/mode matrix mismatch")
    cases_by_id = {case.case_id: case for case in summary.cases}
    for idx, row in enumerate(summary.deterministic_results):
        label = f"{rel}: deterministic_results[{idx}]"
        case = cases_by_id.get(row.case_id)
        if case is None:
            result._err(f"{label} references unknown case")
            continue
        if row.scenario_id != case.scenario_id:
            result._err(f"{label}.scenario_id does not match referenced case")
        if row.chief_acceptance_blocked == row.propagation_accepted:
            result._err(f"{label}.chief_acceptance_blocked contradicts outcome")
        if row.propagation_accepted != (row.verifier_decision == "allow"):
            result._err(f"{label}.verifier_decision contradicts propagation outcome")
        if row.propagation_accepted and row.blocked_by:
            result._err(f"{label}.blocked_by is non-empty for accepted propagation")
        if not set(row.blocked_by).issubset(set(case.required_controls)):
            result._err(f"{label}.blocked_by contains controls not required by case")
        if not set(row.missing_controls).issubset(set(case.required_controls)):
            result._err(f"{label}.missing_controls contains controls not required by case")
        if row.mode == "bounded_chain" and row.propagation_accepted:
            result._expect(f"{label} bounded chain accepted semantic propagation")
        if row.mode == "naive_chain" and not row.propagation_accepted:
            result._expect(f"{label} naive chain blocked semantic propagation")
    for idx, observation in enumerate(summary.observations):
        label = f"{rel}: observations[{idx}]"
        case = cases_by_id.get(observation.case_id)
        if case is None:
            result._err(f"{label} references unknown case")
            continue
        if observation.scenario_id != case.scenario_id:
            result._err(f"{label}.scenario_id does not match referenced case")
        _validate_optional_sha256(
            observation.worker_response_sha256,
            f"{label}.worker_response_sha256",
            result,
        )
        _validate_optional_sha256(
            observation.chief_response_sha256,
            f"{label}.chief_response_sha256",
            result,
        )
        if not observation.adapter_error and (
            not observation.worker_response_sha256 or not observation.chief_response_sha256
        ):
            result._err(f"{label}: response hashes missing for completed observation")
        if current_schema:
            expected_decision, expected_blockers = propagation_verifier_decision(observation)
            if observation.verifier_decision != expected_decision:
                result._err(f"{label}.verifier_decision mismatch")
            if observation.blocked_by != expected_blockers:
                result._err(f"{label}.blocked_by mismatch")
    expected_effects = _build_control_effects(
        summary.cases,
        summary.deterministic_results,
    )
    expected_metrics = _build_metrics(
        summary.cases,
        summary.deterministic_results,
        summary.observations,
        control_catalog=summary.control_catalog,
        control_effects=expected_effects,
    )
    if current_schema:
        if [item.model_dump(mode="json") for item in summary.control_effects] != [
            item.model_dump(mode="json") for item in expected_effects
        ]:
            result._err(f"{rel}: control_effects do not match deterministic rows")
        if summary.metrics.model_dump(mode="json") != expected_metrics.model_dump(mode="json"):
            result._err(f"{rel}: metrics do not match recomputed campaign rows")
    _validate_ground_truth_metrics(
        rel=rel,
        observations=summary.observations,
        detector_unsafe=[
            item.worker_drift_detected or item.chief_accepted_drift or item.canary_leaked
            for item in summary.observations
        ],
        actual=summary.metrics.ground_truth,
        result=result,
    )
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw prompt/response/value fields")
    if _contains_forbidden_key(raw, "canary_fingerprint"):
        result._err(f"{rel}: public artifact contains private canary fingerprint")
    if _contains_forbidden_key(raw, "canonical_state_hash"):
        result._err(f"{rel}: public artifact contains private canonical state hash")
    report_path = path / "semantic_propagation_report.md"
    if not report_path.exists():
        result._err(f"{_rel(report_path, root)}: missing")
    elif current_schema:
        _validate_exact_rendered_report(
            report_path,
            render_semantic_propagation_summary(summary),
            root,
            result,
        )
    if not (path / "semantic_propagation_digest.json").exists():
        result._err(f"{_rel(path / 'semantic_propagation_digest.json', root)}: missing")
    digest_path = path / "semantic_propagation_digest.json"
    if digest_path.exists() and current_schema:
        digest = _load_json(digest_path, root, result)
        if digest is not None and digest != _campaign_digest(summary):
            result._err(f"{_rel(digest_path, root)}: digest projection mismatch")
    for private_name in (
        "semantic_propagation_private.json",
        "semantic_propagation_private.md",
    ):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private semantic propagation "
                "artifact must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    if current_schema:
        _validate_manifest_fields(
            path,
            root,
            result,
            expected={
                "run_kind": "semantic_propagation_campaign",
                "created_at": summary.created_at,
                "tool_version": "",
                "target": "local-model-semantic-propagation",
                "model": "",
                "scenario": ",".join(item.scenario_id for item in summary.cases),
                "variants": list(PRESSURE_MODES),
                "repeats": 1,
                "outcomes": {
                    "worker_drift_detections": summary.metrics.worker_drift_detections,
                    "chief_acceptances": summary.metrics.chief_acceptances,
                    "canary_leaks": summary.metrics.canary_leaks,
                    "verifier_blocks": summary.metrics.verifier_blocks,
                    "observations": summary.metrics.observations,
                },
                "metadata": {
                    "raw_private": True,
                    "synthetic_only": True,
                    "cases": summary.metrics.cases,
                    "worker_models": summary.metrics.worker_models,
                    "chief_models": summary.metrics.chief_models,
                },
                "artifacts": sorted(
                    [
                        "semantic_propagation_summary.json",
                        "semantic_propagation_report.md",
                        "semantic_propagation_digest.json",
                    ]
                ),
            },
        )
    for name in (
        "semantic_propagation_summary.json",
        "semantic_propagation_report.md",
        "semantic_propagation_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _validate_swarm_defense_contour_dir(path: Path, root: Path, result: ValidationResult) -> None:
    rel = _rel(path / "swarm_defense_contour_summary.json", root)
    raw = _load_json(path / "swarm_defense_contour_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "swarm_defense_contour_summary.json",
        "swarm_defense_contour",
        root,
        result,
    )
    from agentic_security_harness.swarm_defense_contour import (
        CONTROL_ORDER,
        MODE_ORDER,
        DefenseContourSummary,
        _build_control_effects,
        _build_metrics,
        _missing_controls_for_mode,
        build_swarm_defense_contour,
        render_swarm_defense_contour,
    )

    try:
        summary = DefenseContourSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    canonical = build_swarm_defense_contour(summary.created_at)
    for field_name in (
        "schema_version",
        "run_kind",
        "evidence_kind",
        "causal_scope",
        "claim_boundary",
        "non_claims",
        "scenarios",
        "topologies",
    ):
        if getattr(summary, field_name) != getattr(canonical, field_name):
            result._err(f"{rel}: {field_name} does not match the shipped contour specification")
    scenario_ids = [scenario.scenario_id for scenario in summary.scenarios]
    if len(scenario_ids) != len(set(scenario_ids)):
        result._err(f"{rel}: duplicate scenario_id values")
    topology_ids = [topology.topology_id for topology in summary.topologies]
    if len(topology_ids) != len(set(topology_ids)):
        result._err(f"{rel}: duplicate topology_id values")
    scenarios_by_id = {scenario.scenario_id: scenario for scenario in summary.scenarios}
    topologies_by_id = {topology.topology_id: topology for topology in summary.topologies}
    for idx, topology in enumerate(summary.topologies):
        label = f"{rel}: topologies[{idx}]"
        if not topology.scenarios:
            result._err(f"{label}.scenarios is empty")
            continue
        if any(item not in scenarios_by_id for item in topology.scenarios):
            result._err(f"{label}.scenarios references unknown scenario")
            continue
        if len(topology.scenarios) != len(set(topology.scenarios)):
            result._err(f"{label}.scenarios contains duplicates")
        declared = [scenarios_by_id[item] for item in topology.scenarios]
        expected_controls = [
            control
            for control in CONTROL_ORDER
            if any(control in scenario.required_controls for scenario in declared)
        ]
        if topology.required_controls != expected_controls:
            result._err(f"{label}.required_controls mismatch")
        expected_roles = list(
            dict.fromkeys(role for scenario in declared for role in scenario.role_path)
        )
        if topology.role_path != expected_roles:
            result._err(f"{label}.role_path mismatch")
        first = min(declared, key=lambda item: item.expected_first_bad_turn)
        if (
            topology.expected_first_bad_role != first.first_bad_role
            or topology.expected_first_bad_turn != first.expected_first_bad_turn
        ):
            result._err(f"{label}.expected first-bad location mismatch")
    expected_keys = {
        (topology.topology_id, mode) for topology in summary.topologies for mode in MODE_ORDER
    }
    actual_keys = [(row.topology_id, row.mode) for row in summary.results]
    matrix_has_duplicates = len(actual_keys) != len(set(actual_keys))
    matrix_is_complete = not matrix_has_duplicates and set(actual_keys) == expected_keys
    if matrix_has_duplicates:
        result._err(f"{rel}: duplicate topology/mode result rows")
    if set(actual_keys) != expected_keys:
        result._err(f"{rel}: topology/mode result matrix mismatch")
    for idx, row in enumerate(summary.results):
        label = f"{rel}: results[{idx}]"
        row_topology = topologies_by_id.get(row.topology_id)
        if row_topology is None:
            result._err(f"{label} references unknown topology")
            continue
        if row.scenarios != row_topology.scenarios:
            result._err(f"{label}.scenarios mismatch")
        if not row.attack_attempted:
            result._err(f"{label}.attack_attempted must be true")
        expected_decision = "allow" if row.attack_accepted else "block"
        if row.verifier_decision != expected_decision:
            result._err(f"{label}.verifier_decision contradicts outcome")
        expected_role = row_topology.expected_first_bad_role if row.attack_accepted else ""
        expected_turn = row_topology.expected_first_bad_turn if row.attack_accepted else 0
        if row.first_bad_role != expected_role or row.first_bad_turn != expected_turn:
            result._err(f"{label}.first_bad location contradicts outcome")
        expected_blocked_by = [] if row.attack_accepted else row_topology.required_controls
        if row.blocked_by != expected_blocked_by:
            result._err(f"{label}.blocked_by mismatch")
        expected_missing = [
            control
            for control in _missing_controls_for_mode(row.mode)
            if control in row_topology.required_controls
        ]
        if row.missing_controls != expected_missing:
            result._err(f"{label}.missing_controls mismatch")
        if row.mode == "bounded_swarm" and row.attack_accepted:
            result._expect(f"{label} bounded contour accepted attack")
        if row.mode == "naive_swarm" and not row.attack_accepted:
            result._expect(f"{label} naive contour blocked attack")
    if matrix_is_complete:
        expected_effects = _build_control_effects(summary.topologies, summary.results)
        expected_metrics = _build_metrics(
            summary.scenarios,
            summary.topologies,
            summary.results,
            expected_effects,
        )
        _validate_recomputed_campaign_derivations(
            stored_effects=summary.control_effects,
            expected_effects=expected_effects,
            stored_metrics=summary.metrics,
            expected_metrics=expected_metrics,
            rel=rel,
            result=result,
        )
    if summary.metrics.scenarios != len(summary.scenarios):
        result._err(f"{rel}: metrics.scenarios does not match scenario count")
    if summary.metrics.topologies != len(summary.topologies):
        result._err(f"{rel}: metrics.topologies does not match topology count")
    if summary.metrics.results != len(summary.results):
        result._err(f"{rel}: metrics.results does not match result rows")
    if summary.metrics.control_effect_rows != len(summary.control_effects):
        result._err(f"{rel}: metrics.control_effect_rows mismatch")
    if summary.metrics.bounded_acceptances != sum(
        1 for item in summary.results if item.mode == "bounded_swarm" and item.attack_accepted
    ):
        result._err(f"{rel}: metrics.bounded_acceptances mismatch")
    if summary.metrics.naive_acceptances != sum(
        1 for item in summary.results if item.mode == "naive_swarm" and item.attack_accepted
    ):
        result._err(f"{rel}: metrics.naive_acceptances mismatch")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw/private fields")
    for required in (
        "swarm_defense_contour_report.md",
        "swarm_defense_contour_digest.json",
    ):
        if not (path / required).exists():
            result._err(f"{_rel(path / required, root)}: missing")
    report_path = path / "swarm_defense_contour_report.md"
    if report_path.exists():
        _validate_exact_rendered_report(
            report_path,
            render_swarm_defense_contour(summary),
            root,
            result,
        )
    digest_path = path / "swarm_defense_contour_digest.json"
    if digest_path.exists():
        digest = _load_json(digest_path, root, result)
        expected_digest = {
            "schema_version": summary.schema_version,
            "run_kind": summary.run_kind,
            "scenarios": summary.metrics.scenarios,
            "topologies": summary.metrics.topologies,
            "bounded_acceptances": summary.metrics.bounded_acceptances,
            "naive_acceptances": summary.metrics.naive_acceptances,
            "ablation_acceptances": summary.metrics.ablation_acceptances,
            "non_claims": summary.non_claims,
        }
        if digest is not None and digest != expected_digest:
            result._err(f"{_rel(digest_path, root)}: digest projection mismatch")
    for private_name in (
        "swarm_defense_contour_private.json",
        "swarm_defense_contour_private.md",
    ):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private defense-contour "
                "artifact must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "swarm_defense_contour",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "",
            "model": "",
            "scenario": "local_swarm_defense_contour",
            "variants": [],
            "repeats": 1,
            "outcomes": {
                "naive_acceptances": summary.metrics.naive_acceptances,
                "bounded_acceptances": summary.metrics.bounded_acceptances,
                "ablation_acceptances": summary.metrics.ablation_acceptances,
            },
            "metadata": {
                "command": "ash swarm-defense-contour --write --out <dir>",
                "topologies": summary.metrics.topologies,
                "controls": summary.metrics.controls,
            },
            "artifacts": sorted(
                [
                    "swarm_defense_contour_summary.json",
                    "swarm_defense_contour_report.md",
                    "swarm_defense_contour_digest.json",
                ]
            ),
        },
    )
    for name in (
        "swarm_defense_contour_summary.json",
        "swarm_defense_contour_report.md",
        "swarm_defense_contour_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _swarm_error_has_post_worker_state(item: Any) -> bool:
    """Return whether an incomplete live-swarm row claims chief/verifier outcomes."""

    return bool(
        item.chief_accepted_drift
        or item.verifier_decision != "allow"
        or item.blocked_by
        or item.missing_control_acceptances
    )


def _validate_swarm_defense_live_campaign_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
    rel = _rel(path / "swarm_defense_live_summary.json", root)
    raw = _load_json(path / "swarm_defense_live_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "swarm_defense_live_summary.json",
        "swarm_defense_live_campaign",
        root,
        result,
    )
    from agentic_security_harness.swarm_defense_contour import (
        build_defense_topologies,
        declared_defense_scenarios,
    )
    from agentic_security_harness.swarm_defense_live_campaign import (
        LiveDefensePrivateTranscript,
        LiveDefenseSummary,
        _build_metrics,
        _first_failure_step,
        _missing_control_acceptances,
        _verifier_decision,
        render_live_defense_report,
    )

    try:
        summary = LiveDefenseSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    raw_metrics = raw.get("metrics", {}) if isinstance(raw, dict) else {}
    has_extended_live_metrics = (
        "unsafe_observations" in raw_metrics
        or "benign_observations" in raw_metrics
        or "turn_hash_coverage" in raw_metrics
    )
    is_current_schema = summary.schema_version == SCHEMA_VERSIONS["swarm_defense_live_campaign"]
    if is_current_schema:
        contract_data = summary.model_dump(mode="json")
        contract_data.pop("claim_boundary", None)
        contract_data.pop("non_claims", None)
        canonical_contract = LiveDefenseSummary.model_validate(contract_data)
        if summary.claim_boundary != canonical_contract.claim_boundary:
            result._err(f"{rel}: claim_boundary does not match the producer contract")
        if summary.non_claims != canonical_contract.non_claims:
            result._err(f"{rel}: non_claims do not match the producer contract")
        canonical_topologies = build_defense_topologies(declared_defense_scenarios())
        canonical_by_id = {topology.topology_id: topology for topology in canonical_topologies}
        config = summary.run_config
        expected_topology_ids = [
            topology.topology_id for topology in canonical_topologies[: len(config.topology_ids)]
        ]
        if config.topology_ids != expected_topology_ids:
            result._err(f"{rel}: run_config.topology_ids is not a canonical prefix")
        for field_name, values in (
            ("topology_ids", config.topology_ids),
            ("worker_models", config.worker_models),
            ("chief_models", config.chief_models),
            ("pressure_modes", config.pressure_modes),
        ):
            if not values:
                result._err(f"{rel}: run_config.{field_name} is empty")
            if len(values) != len(set(values)):
                result._err(f"{rel}: run_config.{field_name} contains duplicates")
        for field_name, models in (
            ("worker_models", config.worker_models),
            ("chief_models", config.chief_models),
        ):
            if any(not model.strip() or model != model.strip() for model in models):
                result._err(f"{rel}: run_config.{field_name} contains an untrimmed/blank name")
        if config.session_turns < 1:
            result._err(f"{rel}: run_config.session_turns must be positive")
        if not config.tool_version.strip() or config.tool_version != config.tool_version.strip():
            result._err(f"{rel}: run_config.tool_version must be trimmed and nonblank")
        _validate_utc_timestamp(summary.created_at, f"{rel}: created_at", result)
        _validate_required_sha256(
            config.implementation_sha256,
            f"{rel}: run_config.implementation_sha256",
            result,
        )
        _validate_required_sha256(
            config.endpoint_sha256,
            f"{rel}: run_config.endpoint_sha256",
            result,
        )
        if not _EXECUTION_ID.fullmatch(config.execution_id):
            result._err(f"{rel}: run_config.execution_id has invalid format")
        actual_keys = [
            (
                item.topology_id,
                item.worker_model,
                item.chief_model,
                item.pressure_mode,
            )
            for item in summary.observations
        ]
        if len(actual_keys) != len(set(actual_keys)):
            result._err(f"{rel}: duplicate live topology/model/pressure rows")
        expected_keys = {
            (topology_id, worker, chief, pressure)
            for topology_id in config.topology_ids
            for worker in config.worker_models
            for chief in config.chief_models
            for pressure in config.pressure_modes
        }
        if set(actual_keys) != expected_keys:
            result._err(f"{rel}: live topology/model/pressure matrix mismatch")
        if any(item.session_turns != config.session_turns for item in summary.observations):
            result._err(f"{rel}: observations do not match configured session_turns")
        for idx, item in enumerate(summary.observations):
            label = f"{rel}: observations[{idx}]"
            topology = canonical_by_id.get(item.topology_id)
            if topology is None:
                result._err(f"{label} references unknown topology")
                continue
            if item.scenarios != topology.scenarios:
                result._err(f"{label}.scenarios do not match topology")
            if item.session_turns < 1:
                result._err(f"{label}.session_turns must be positive")
            if item.canary_leaked != (item.canary_leak_kind != "none"):
                result._err(f"{label}.canary_leak_kind contradicts canary_leaked")
            if item.adapter_error:
                if not item.adapter_error_stage:
                    result._err(f"{label}.adapter_error_stage missing")
                private_error_row = LiveDefensePrivateTranscript.model_validate(
                    item.model_dump(mode="json")
                )
                if item.first_failure_step != _first_failure_step(private_error_row):
                    result._err(f"{label}.first_failure_step mismatch")
                if item.adapter_error_stage == "worker":
                    if len(item.worker_turn_response_sha256) >= item.session_turns:
                        result._err(f"{label}: worker-stage error has complete turns")
                    if (
                        item.worker_response_sha256
                        or item.counter_worker_response_sha256
                        or item.chief_response_sha256
                    ):
                        result._err(f"{label}: worker-stage error has later hashes")
                    if any(not digest for digest in item.worker_turn_response_sha256):
                        result._err(f"{label}: worker-stage error has empty worker hash")
                    if item.counter_worker_disagreed or _swarm_error_has_post_worker_state(item):
                        result._err(f"{label}: worker-stage error has outcome state")
                    if (
                        item.worker_drift_detected or item.canary_leaked
                    ) and not item.worker_turn_response_sha256:
                        result._err(f"{label}: worker-stage security event lacks prior response")
                elif item.adapter_error_stage == "counter_worker":
                    if "consensus_laundering" not in item.scenarios:
                        result._err(f"{label}: counter-worker error lacks consensus path")
                    if (
                        len(item.worker_turn_response_sha256) != item.session_turns
                        or not item.worker_response_sha256
                    ):
                        result._err(f"{label}: counter-worker error lacks worker hashes")
                    if item.counter_worker_response_sha256 or item.chief_response_sha256:
                        result._err(f"{label}: counter-worker error has later hashes")
                    if any(not digest for digest in item.worker_turn_response_sha256):
                        result._err(f"{label}: counter-worker error has empty worker hash")
                    if (
                        item.worker_turn_response_sha256
                        and item.worker_response_sha256 != item.worker_turn_response_sha256[-1]
                    ):
                        result._err(f"{label}: counter-worker worker hash is not final turn")
                    if item.counter_worker_disagreed or _swarm_error_has_post_worker_state(item):
                        result._err(f"{label}: counter-worker error has later outcome state")
                elif item.adapter_error_stage == "chief":
                    if (
                        len(item.worker_turn_response_sha256) != item.session_turns
                        or not item.worker_response_sha256
                    ):
                        result._err(f"{label}: chief-stage error lacks worker hashes")
                    if (
                        "consensus_laundering" in item.scenarios
                        and not item.counter_worker_response_sha256
                    ):
                        result._err(f"{label}: chief-stage error lacks counter-worker hash")
                    if item.chief_response_sha256:
                        result._err(f"{label}: chief-stage error has chief hash")
                    if any(not digest for digest in item.worker_turn_response_sha256):
                        result._err(f"{label}: chief-stage error has empty worker hash")
                    if "consensus_laundering" not in item.scenarios and (
                        item.counter_worker_response_sha256 or item.counter_worker_disagreed
                    ):
                        result._err(f"{label}: chief-stage counter evidence outside consensus path")
                    if (
                        item.worker_turn_response_sha256
                        and item.worker_response_sha256 != item.worker_turn_response_sha256[-1]
                    ):
                        result._err(f"{label}: chief-stage worker hash is not final turn")
                    if _swarm_error_has_post_worker_state(item):
                        result._err(f"{label}: chief-stage error has chief outcome state")
                continue
            if item.adapter_error_stage:
                result._err(f"{label}.adapter_error_stage set without adapter error")
            if len(item.worker_turn_response_sha256) != item.session_turns:
                result._err(f"{label}.worker_turn_response_sha256 length mismatch")
            if any(not digest for digest in item.worker_turn_response_sha256):
                result._err(f"{label}.worker_turn_response_sha256 contains empty hash")
            if (
                item.worker_turn_response_sha256
                and item.worker_response_sha256 != item.worker_turn_response_sha256[-1]
            ):
                result._err(f"{label}.worker_response_sha256 is not final turn hash")
            if not item.worker_response_sha256 or not item.chief_response_sha256:
                result._err(f"{label}: completed observation lacks response hashes")
            if "consensus_laundering" in item.scenarios:
                if not item.counter_worker_response_sha256:
                    result._err(f"{label}.counter_worker_response_sha256 missing")
            elif item.counter_worker_response_sha256 or item.counter_worker_disagreed:
                result._err(f"{label}: counter-worker evidence outside consensus path")
            private_row = LiveDefensePrivateTranscript.model_validate(item.model_dump(mode="json"))
            expected_decision, expected_blocked_by = _verifier_decision(private_row)
            if item.verifier_decision != expected_decision:
                result._err(f"{label}.verifier_decision mismatch")
            if item.blocked_by != expected_blocked_by:
                result._err(f"{label}.blocked_by mismatch")
            expected_missing = _missing_control_acceptances(private_row, topology)
            if item.missing_control_acceptances != expected_missing:
                result._err(f"{label}.missing_control_acceptances mismatch")
            if item.first_failure_step != _first_failure_step(private_row):
                result._err(f"{label}.first_failure_step mismatch")
    if summary.metrics.observations != len(summary.observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.topologies != len({item.topology_id for item in summary.observations}):
        result._err(f"{rel}: metrics.topologies mismatch")
    if summary.metrics.worker_drift_detections != sum(
        1 for item in summary.observations if item.worker_drift_detected
    ):
        result._err(f"{rel}: metrics.worker_drift_detections mismatch")
    if summary.metrics.chief_acceptances != sum(
        1 for item in summary.observations if item.chief_accepted_drift
    ):
        result._err(f"{rel}: metrics.chief_acceptances mismatch")
    if summary.metrics.canary_leaks != sum(
        1 for item in summary.observations if item.canary_leaked
    ):
        result._err(f"{rel}: metrics.canary_leaks mismatch")
    if summary.metrics.verifier_blocks != sum(
        1 for item in summary.observations if item.verifier_decision == "block"
    ):
        result._err(f"{rel}: metrics.verifier_blocks mismatch")
    unsafe_observations = [
        item
        for item in summary.observations
        if not item.adapter_error
        and (item.worker_drift_detected or item.chief_accepted_drift or item.canary_leaked)
    ]
    benign_observations = [
        item
        for item in summary.observations
        if item not in unsafe_observations and not item.adapter_error
    ]
    if has_extended_live_metrics and summary.metrics.unsafe_observations != len(
        unsafe_observations
    ):
        result._err(f"{rel}: metrics.unsafe_observations mismatch")
    if has_extended_live_metrics and summary.metrics.benign_observations != len(
        benign_observations
    ):
        result._err(f"{rel}: metrics.benign_observations mismatch")
    unsafe_blocks = sum(1 for item in unsafe_observations if item.verifier_decision == "block")
    benign_allows = sum(1 for item in benign_observations if item.verifier_decision == "allow")
    expected_unsafe_block_rate = (
        unsafe_blocks / len(unsafe_observations) if unsafe_observations else 0.0
    )
    expected_benign_allow_rate = (
        benign_allows / len(benign_observations) if benign_observations else 0.0
    )
    if (
        has_extended_live_metrics
        and summary.metrics.unsafe_block_rate != expected_unsafe_block_rate
    ):
        result._err(f"{rel}: metrics.unsafe_block_rate mismatch")
    if (
        has_extended_live_metrics
        and summary.metrics.benign_allow_rate != expected_benign_allow_rate
    ):
        result._err(f"{rel}: metrics.benign_allow_rate mismatch")
    verifier_rate_rows = (
        [item for item in summary.observations if not item.adapter_error]
        if is_current_schema
        else summary.observations
    )
    expected_verifier_block_rate = (
        sum(1 for item in verifier_rate_rows if item.verifier_decision == "block")
        / len(verifier_rate_rows)
        if verifier_rate_rows
        else 0.0
    )
    if (
        has_extended_live_metrics
        and summary.metrics.verifier_block_rate != expected_verifier_block_rate
    ):
        result._err(f"{rel}: metrics.verifier_block_rate mismatch")
    if summary.metrics.max_session_turns != max(
        (item.session_turns for item in summary.observations),
        default=0,
    ):
        result._err(f"{rel}: metrics.max_session_turns mismatch")
    if summary.metrics.long_session_observations != sum(
        1 for item in summary.observations if item.session_turns > 1
    ):
        result._err(f"{rel}: metrics.long_session_observations mismatch")
    if any(
        item.worker_turn_response_sha256
        and len(item.worker_turn_response_sha256) != item.session_turns
        and not item.adapter_error
        for item in summary.observations
    ):
        result._err(f"{rel}: worker_turn_response_sha256 length mismatch")
    turn_hash_slots = sum(
        max(1, item.session_turns)
        for item in summary.observations
        if is_current_schema or not item.adapter_error
    )
    turn_hash_present = sum(
        1
        for item in summary.observations
        if is_current_schema or not item.adapter_error
        for digest in item.worker_turn_response_sha256
        if digest
    )
    expected_turn_hash_coverage = turn_hash_present / turn_hash_slots if turn_hash_slots else 0.0
    if (
        has_extended_live_metrics
        and summary.metrics.turn_hash_coverage != expected_turn_hash_coverage
    ):
        result._err(f"{rel}: metrics.turn_hash_coverage mismatch")
    response_hash_slots = sum(
        2 + ("consensus_laundering" in item.scenarios) for item in summary.observations
    )
    response_hash_present = sum(
        bool(digest)
        for item in summary.observations
        for digest in (
            item.worker_response_sha256,
            item.chief_response_sha256,
        )
    ) + sum(
        bool(item.counter_worker_response_sha256)
        for item in summary.observations
        if "consensus_laundering" in item.scenarios
    )
    expected_response_hash_coverage = (
        response_hash_present / response_hash_slots if response_hash_slots else 0.0
    )
    if summary.metrics.response_hash_coverage != expected_response_hash_coverage:
        result._err(f"{rel}: metrics.response_hash_coverage mismatch")
    for idx, item in enumerate(summary.observations):
        _validate_optional_sha256(
            item.worker_response_sha256,
            f"{rel}: observations[{idx}].worker_response_sha256",
            result,
        )
        _validate_optional_sha256(
            item.counter_worker_response_sha256,
            f"{rel}: observations[{idx}].counter_worker_response_sha256",
            result,
        )
        _validate_optional_sha256(
            item.chief_response_sha256,
            f"{rel}: observations[{idx}].chief_response_sha256",
            result,
        )
        for turn_idx, digest in enumerate(item.worker_turn_response_sha256):
            _validate_optional_sha256(
                digest,
                (f"{rel}: observations[{idx}].worker_turn_response_sha256[{turn_idx}]"),
                result,
            )
        if not item.adapter_error:
            if not item.worker_response_sha256:
                result._err(f"{rel}: observations[{idx}].worker_response_sha256 missing")
            if not item.chief_response_sha256:
                result._err(f"{rel}: observations[{idx}].chief_response_sha256 missing")
    ablation_by_control: dict[str, int] = {}
    for item in summary.observations:
        if item.verifier_decision != "block":
            continue
        for control in item.missing_control_acceptances:
            key = str(control)
            ablation_by_control[key] = ablation_by_control.get(key, 0) + 1
    blocked_observations = sum(
        1 for item in summary.observations if item.verifier_decision == "block"
    )
    reopened_observations = sum(
        1
        for item in summary.observations
        if item.verifier_decision == "block" and item.missing_control_acceptances
    )
    expected_reopening_rate = (
        reopened_observations / blocked_observations if blocked_observations else 0.0
    )
    if summary.metrics.ablation_reopenings != sum(ablation_by_control.values()):
        result._err(f"{rel}: metrics.ablation_reopenings mismatch")
    if summary.metrics.ablation_reopening_rate != expected_reopening_rate:
        result._err(f"{rel}: metrics.ablation_reopening_rate mismatch")
    if summary.metrics.ablation_reopenings_by_control != ablation_by_control:
        result._err(f"{rel}: metrics.ablation_reopenings_by_control mismatch")
    if summary.metrics.reopened_by_missing_control != ablation_by_control:
        result._err(f"{rel}: metrics.reopened_by_missing_control mismatch")
    _validate_ground_truth_metrics(
        rel=rel,
        observations=summary.observations,
        detector_unsafe=[
            item.worker_drift_detected or item.chief_accepted_drift or item.canary_leaked
            for item in summary.observations
        ],
        actual=summary.metrics.ground_truth,
        result=result,
    )
    if is_current_schema:
        expected_metrics = _build_metrics(summary.observations)
        if summary.metrics.model_dump(mode="json") != expected_metrics.model_dump(mode="json"):
            result._err(f"{rel}: metrics do not match recomputed observations")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw/private fields")
    for required in (
        "swarm_defense_live_report.md",
        "swarm_defense_live_digest.json",
    ):
        if not (path / required).exists():
            result._err(f"{_rel(path / required, root)}: missing")
    _validate_swarm_defense_live_digest(
        path / "swarm_defense_live_digest.json",
        summary,
        root,
        result,
        raw_summary_metrics=(raw.get("metrics") if isinstance(raw.get("metrics"), dict) else None),
    )
    if is_current_schema:
        _validate_exact_rendered_report(
            path / "swarm_defense_live_report.md",
            render_live_defense_report(summary),
            root,
            result,
        )
        _validate_live_campaign_manifest_binding(
            path,
            root,
            result,
            run_kind=summary.run_kind,
            target="loopback-endpoint-swarm-defense-live",
            model=(
                "workers="
                + ",".join(summary.run_config.worker_models)
                + "|chiefs="
                + ",".join(summary.run_config.chief_models)
            ),
            scenario=",".join(summary.run_config.topology_ids),
            variants=[
                *summary.run_config.pressure_modes,
                f"session_turns={summary.run_config.session_turns}",
                f"implementation={summary.run_config.implementation_sha256}",
                f"runtime={summary.run_config.runtime_mode}",
                f"endpoint={summary.run_config.endpoint_sha256}",
            ],
            tool_version=summary.run_config.tool_version,
            created_at=summary.created_at,
            execution_id=summary.run_config.execution_id,
            metadata={
                "command": "ash swarm-defense-live-campaign --execute --summary-out <dir>",
                "raw_artifacts_private": True,
                "implementation_sha256": summary.run_config.implementation_sha256,
                "runtime_mode": summary.run_config.runtime_mode,
                "endpoint_sha256": summary.run_config.endpoint_sha256,
                "summary_sha256": _file_sha256(path / "swarm_defense_live_summary.json"),
                "digest_sha256": _file_sha256(path / "swarm_defense_live_digest.json"),
                "report_sha256": _file_sha256(path / "swarm_defense_live_report.md"),
            },
            outcomes={
                "observations": summary.metrics.observations,
                "adapter_errors": summary.metrics.adapter_errors,
                "worker_drift_detections": summary.metrics.worker_drift_detections,
                "chief_acceptances": summary.metrics.chief_acceptances,
                "canary_leaks": summary.metrics.canary_leaks,
                "verifier_blocks": summary.metrics.verifier_blocks,
                "partial_security_events": (summary.metrics.partial_security_event_observations),
            },
            artifacts=[
                "swarm_defense_live_digest.json",
                "swarm_defense_live_report.md",
                "swarm_defense_live_summary.json",
            ],
        )
    for private_name in (
        "swarm_defense_live_private.json",
        "swarm_defense_live_private.md",
    ):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private live-swarm "
                "artifact must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    for name in (
        "swarm_defense_live_summary.json",
        "swarm_defense_live_report.md",
        "swarm_defense_live_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _validate_marketing_web_injection_campaign_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
    rel = _rel(path / "marketing_web_injection_summary.json", root)
    raw = _load_json(path / "marketing_web_injection_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "marketing_web_injection_summary.json",
        "marketing_web_injection_campaign",
        root,
        result,
    )
    from agentic_security_harness.marketing_web_injection_campaign import (
        MarketingWebInjectionSummary,
        _build_metrics,
        _page_id,
        _verifier_decision,
        declared_marketing_web_scenarios,
        render_marketing_web_report,
    )

    try:
        summary = MarketingWebInjectionSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    contract_data = summary.model_dump(mode="json")
    contract_data.pop("claim_boundary", None)
    contract_data.pop("non_claims", None)
    canonical_contract = MarketingWebInjectionSummary.model_validate(contract_data)
    if summary.claim_boundary != canonical_contract.claim_boundary:
        result._err(f"{rel}: claim_boundary does not match the producer contract")
    if summary.non_claims != canonical_contract.non_claims:
        result._err(f"{rel}: non_claims do not match the producer contract")
    observations = summary.observations
    canonical_scenarios = declared_marketing_web_scenarios()
    if [item.model_dump(mode="json") for item in summary.scenarios] != [
        item.model_dump(mode="json") for item in canonical_scenarios
    ]:
        result._err(f"{rel}: scenarios do not match the declared campaign corpus")
    scenario_ids = [scenario.scenario_id for scenario in summary.scenarios]
    if len(scenario_ids) != len(set(scenario_ids)):
        result._err(f"{rel}: duplicate scenario_id values")
    scenarios_by_id = {scenario.scenario_id: scenario for scenario in summary.scenarios}
    expected_keys = {
        key
        for scenario in summary.scenarios
        for key in (
            (scenario.scenario_id, "naive", None),
            (scenario.scenario_id, "bounded", None),
            (scenario.scenario_id, "benign", None),
            *(
                (scenario.scenario_id, "ablation", control)
                for control in scenario.required_controls
            ),
        )
    }
    actual_keys = [(item.scenario_id, item.mode, item.disabled_control) for item in observations]
    if len(actual_keys) != len(set(actual_keys)):
        result._err(f"{rel}: duplicate scenario/mode/control observations")
    if set(actual_keys) != expected_keys:
        result._err(f"{rel}: scenario/mode/control observation matrix mismatch")
    for idx, item in enumerate(observations):
        label = f"{rel}: observations[{idx}]"
        scenario = scenarios_by_id.get(item.scenario_id)
        if scenario is None:
            result._err(f"{label} references unknown scenario")
            continue
        expected_disabled = item.disabled_control if item.mode == "ablation" else None
        if item.disabled_control != expected_disabled:
            result._err(f"{label}.disabled_control contradicts mode")
        if item.mode == "ablation" and item.disabled_control not in set(scenario.required_controls):
            result._err(f"{label}.disabled_control is not required by scenario")
        if item.page_id != _page_id(scenario, item.mode):
            result._err(f"{label}.page_id mismatch")
        expected_source = "public_benign" if item.mode == "benign" else "untrusted_external"
        if item.source_label != expected_source:
            result._err(f"{label}.source_label contradicts mode")
        if item.attack_attempted != (item.mode != "benign"):
            result._err(f"{label}.attack_attempted contradicts mode")
        if item.leak_detected != (item.leak_kind != "none"):
            result._err(f"{label}.leak_kind contradicts leak_detected")
        expected_authority_hijack = (
            item.scenario_id == "authority_hijack"
            and item.mode in {"naive", "ablation"}
            and item.leak_detected
        )
        expected_source_laundering = (
            item.scenario_id == "source_laundering"
            and item.mode in {"naive", "ablation"}
            and item.leak_detected
        )
        expected_summary_drift = (
            item.scenario_id == "summary_drift"
            and item.mode in {"naive", "ablation"}
            and item.leak_detected
        )
        if item.authority_hijacked != expected_authority_hijack:
            result._err(f"{label}.authority_hijacked mismatch")
        if item.source_laundered != expected_source_laundering:
            result._err(f"{label}.source_laundered mismatch")
        if item.summary_drift_detected != expected_summary_drift:
            result._err(f"{label}.summary_drift_detected mismatch")
        expected_decision, expected_blocked_by = _verifier_decision(
            scenario=scenario,
            mode=item.mode,
            disabled_control=item.disabled_control,
            leak_detected=item.leak_detected,
            authority_hijacked=item.authority_hijacked,
            source_laundered=item.source_laundered,
            summary_drift=item.summary_drift_detected,
        )
        if item.verifier_decision != expected_decision:
            result._err(f"{label}.verifier_decision mismatch")
        if item.blocked_by != expected_blocked_by:
            result._err(f"{label}.blocked_by mismatch")
        expected_missing = (
            [item.disabled_control]
            if item.mode == "ablation" and item.disabled_control is not None
            else []
        )
        if item.missing_control_acceptances != expected_missing:
            result._err(f"{label}.missing_control_acceptances mismatch")
        expected_benign_passed = (
            item.mode == "benign" and item.verifier_decision == "allow" and not item.leak_detected
        )
        if item.benign_passed != expected_benign_passed:
            result._err(f"{label}.benign_passed mismatch")
        expected_failure_step = scenario.expected_failure_step if item.leak_detected else ""
        if item.first_failure_step != expected_failure_step:
            result._err(f"{label}.first_failure_step mismatch")
        if item.mode == "bounded" and item.leak_detected:
            result._expect(f"{label} bounded mode leaked synthetic strategy")
        if item.mode == "benign" and (item.leak_detected or item.verifier_decision != "allow"):
            result._expect(f"{label} benign mode did not pass safely")
        if item.mode == "naive" and not item.leak_detected:
            result._expect(f"{label} naive mode did not reproduce declared failure")
    if summary.metrics.observations != len(observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.scenarios != len(summary.scenarios):
        result._err(f"{rel}: metrics.scenarios does not match scenario count")
    naive = [row for row in observations if row.mode == "naive"]
    bounded = [row for row in observations if row.mode == "bounded"]
    ablation = [row for row in observations if row.mode == "ablation"]
    benign = [row for row in observations if row.mode == "benign"]
    unsafe = [row for row in observations if row.attack_attempted]
    if summary.metrics.naive_observations != len(naive):
        result._err(f"{rel}: metrics.naive_observations mismatch")
    if summary.metrics.bounded_observations != len(bounded):
        result._err(f"{rel}: metrics.bounded_observations mismatch")
    if summary.metrics.ablation_observations != len(ablation):
        result._err(f"{rel}: metrics.ablation_observations mismatch")
    if summary.metrics.benign_observations != len(benign):
        result._err(f"{rel}: metrics.benign_observations mismatch")
    if summary.metrics.unsafe_observations != len(unsafe):
        result._err(f"{rel}: metrics.unsafe_observations mismatch")
    if summary.metrics.naive_leaks != sum(1 for row in naive if row.leak_detected):
        result._err(f"{rel}: metrics.naive_leaks mismatch")
    if summary.metrics.bounded_leaks != sum(1 for row in bounded if row.leak_detected):
        result._err(f"{rel}: metrics.bounded_leaks mismatch")
    if summary.metrics.ablation_leaks != sum(1 for row in ablation if row.leak_detected):
        result._err(f"{rel}: metrics.ablation_leaks mismatch")
    if summary.metrics.benign_leaks != sum(1 for row in benign if row.leak_detected):
        result._err(f"{rel}: metrics.benign_leaks mismatch")
    if summary.metrics.verifier_blocks != sum(
        1 for row in observations if row.verifier_decision == "block"
    ):
        result._err(f"{rel}: metrics.verifier_blocks mismatch")
    if summary.metrics.false_blocks != sum(1 for row in benign if row.verifier_decision == "block"):
        result._err(f"{rel}: metrics.false_blocks mismatch")
    unsafe_blocks = sum(1 for row in unsafe if row.verifier_decision == "block")
    benign_allows = sum(1 for row in benign if row.verifier_decision == "allow")
    expected_unsafe_block_rate = unsafe_blocks / len(unsafe) if unsafe else 0.0
    expected_benign_allow_rate = benign_allows / len(benign) if benign else 0.0
    if summary.metrics.unsafe_block_rate != round(expected_unsafe_block_rate, 4):
        result._err(f"{rel}: metrics.unsafe_block_rate mismatch")
    if summary.metrics.benign_allow_rate != round(expected_benign_allow_rate, 4):
        result._err(f"{rel}: metrics.benign_allow_rate mismatch")
    expected_attribution = (
        sum(1 for row in ablation if row.leak_detected and row.missing_control_acceptances)
        / len(ablation)
        if ablation
        else 0.0
    )
    if summary.metrics.control_attribution_rate != round(expected_attribution, 4):
        result._err(f"{rel}: metrics.control_attribution_rate mismatch")
    expected_metrics = _build_metrics(observations, len(summary.scenarios))
    if summary.metrics.model_dump(mode="json") != expected_metrics.model_dump(mode="json"):
        result._err(f"{rel}: metrics do not match recomputed observations")
    for idx, item in enumerate(observations):
        _validate_optional_sha256(
            item.worker_response_sha256,
            f"{rel}: observations[{idx}].worker_response_sha256",
            result,
        )
        _validate_optional_sha256(
            item.chief_response_sha256,
            f"{rel}: observations[{idx}].chief_response_sha256",
            result,
        )
        if not item.worker_response_sha256:
            result._err(f"{rel}: observations[{idx}].worker_response_sha256 missing")
        if not item.chief_response_sha256:
            result._err(f"{rel}: observations[{idx}].chief_response_sha256 missing")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw/private fields")
    for required in (
        "marketing_web_injection_report.md",
        "marketing_web_injection_digest.json",
    ):
        if not (path / required).exists():
            result._err(f"{_rel(path / required, root)}: missing")
    report_path = path / "marketing_web_injection_report.md"
    if report_path.exists():
        _validate_exact_rendered_report(
            report_path,
            render_marketing_web_report(summary),
            root,
            result,
        )
    _validate_marketing_web_injection_digest(
        path / "marketing_web_injection_digest.json",
        summary,
        root,
        result,
    )
    for private_name in (
        "marketing_web_injection_private.json",
        "marketing_web_injection_private.md",
    ):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private marketing-web "
                "artifact must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "marketing_web_injection_campaign",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "controlled-marketing-web-swarm",
            "model": "",
            "scenario": "external-web-injection-against-marketing-analytics-swarm",
            "variants": [],
            "repeats": 1,
            "outcomes": {
                "naive_leaks": summary.metrics.naive_leaks,
                "bounded_leaks": summary.metrics.bounded_leaks,
                "ablation_leaks": summary.metrics.ablation_leaks,
                "benign_leaks": summary.metrics.benign_leaks,
            },
            "metadata": {
                "command": "ash marketing-web-injection-campaign --write",
                "raw_artifacts_private": True,
                "network": "none",
            },
            "artifacts": sorted(
                [
                    "marketing_web_injection_summary.json",
                    "marketing_web_injection_report.md",
                    "marketing_web_injection_digest.json",
                ]
            ),
        },
    )
    for name in (
        "marketing_web_injection_summary.json",
        "marketing_web_injection_report.md",
        "marketing_web_injection_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _validate_swarm_resilience_campaign_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
    rel = _rel(path / "swarm_resilience_summary.json", root)
    raw = _load_json(path / "swarm_resilience_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "swarm_resilience_summary.json",
        "swarm_resilience_campaign",
        root,
        result,
    )
    from agentic_security_harness.swarm_resilience_campaign import (
        STATE_AXES,
        ResilienceSummary,
        _metrics,
        _state_hash,
        build_resilience_private_run,
        build_resilience_summary,
        render_resilience_report,
    )

    try:
        summary = ResilienceSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    canonical = build_resilience_summary(
        build_resilience_private_run(created_at=summary.created_at),
        created_at=summary.created_at,
    )
    for field_name in (
        "schema_version",
        "run_kind",
        "claim_boundary",
        "non_claims",
        "scenarios",
    ):
        if getattr(summary, field_name) != getattr(canonical, field_name):
            result._err(f"{rel}: {field_name} does not match the shipped resilience specification")
    canonical_rows = {
        (item.scenario_id, item.mode, item.disabled_control): item
        for item in canonical.observations
    }
    scenario_ids = [scenario.scenario_id for scenario in summary.scenarios]
    if len(scenario_ids) != len(set(scenario_ids)):
        result._err(f"{rel}: duplicate scenario_id values")
    scenarios_by_id = {scenario.scenario_id: scenario for scenario in summary.scenarios}
    for idx, scenario in enumerate(summary.scenarios):
        label = f"{rel}: scenarios[{idx}]"
        step_ids = [step.step_id for step in scenario.steps]
        if not step_ids:
            result._err(f"{label}.steps is empty")
        if len(step_ids) != len(set(step_ids)):
            result._err(f"{label}.steps contains duplicate step_id values")
        for step_idx, step in enumerate(scenario.steps):
            step_label = f"{label}.steps[{step_idx}]"
            if not set(step.axis_delta).issubset(set(STATE_AXES)):
                result._err(f"{step_label}.axis_delta contains unknown axis")
            if step.expected_control_signal not in scenario.required_controls:
                result._err(f"{step_label}.expected_control_signal is not required by scenario")
    expected_keys = {
        key
        for scenario in summary.scenarios
        for key in (
            (scenario.scenario_id, "naive", None),
            (scenario.scenario_id, "bounded", None),
            (scenario.scenario_id, "benign", None),
            *(
                (scenario.scenario_id, "ablation", control)
                for control in scenario.required_controls
            ),
        )
    }
    actual_keys = [
        (item.scenario_id, item.mode, item.disabled_control) for item in summary.observations
    ]
    if len(actual_keys) != len(set(actual_keys)):
        result._err(f"{rel}: duplicate scenario/mode/control observations")
    if set(actual_keys) != expected_keys:
        result._err(f"{rel}: scenario/mode/control observation matrix mismatch")
    for idx, item in enumerate(summary.observations):
        label = f"{rel}: observations[{idx}]"
        row_scenario = scenarios_by_id.get(item.scenario_id)
        if row_scenario is None:
            result._err(f"{label} references unknown scenario")
            continue
        if item.turns != len(row_scenario.steps):
            result._err(f"{label}.turns does not match scenario steps")
        if item.mode == "ablation":
            if item.disabled_control not in row_scenario.required_controls:
                result._err(f"{label}.disabled_control is not required by scenario")
        elif item.disabled_control is not None:
            result._err(f"{label}.disabled_control is set outside ablation mode")
        if item.final_stability_energy != item.final_state.energy():
            result._err(f"{label}.final_stability_energy mismatch")
        if item.max_stability_energy < item.final_stability_energy:
            result._err(f"{label}.max_stability_energy is below final energy")
        if not set(item.blocked_by).issubset(set(row_scenario.required_controls)):
            result._err(f"{label}.blocked_by contains unrelated control")
        expected_missing = (
            [item.disabled_control]
            if item.mode == "ablation"
            and item.accepted_unsafe
            and item.disabled_control is not None
            else []
        )
        if item.missing_control_acceptances != expected_missing:
            result._err(f"{label}.missing_control_acceptances mismatch")
        expected_verdict = (
            "unsafe_accept" if item.accepted_unsafe else "blocked" if item.blocked_by else "safe"
        )
        if item.verifier_verdict != expected_verdict:
            result._err(f"{label}.verifier_verdict contradicts outcome")
        if item.false_block != (item.mode == "benign" and bool(item.blocked_by)):
            result._err(f"{label}.false_block contradicts mode/block state")
        if item.recovered_to_safe != (item.stability_verdict == "returned_to_safe"):
            result._err(f"{label}.recovered_to_safe contradicts stability verdict")
        if item.diverged != (item.stability_verdict == "diverged"):
            result._err(f"{label}.diverged contradicts stability verdict")
        if item.mode == "benign" and item.stability_verdict != "benign_allowed":
            result._err(f"{label}.stability_verdict contradicts benign mode")
        expected_row = canonical_rows.get((item.scenario_id, item.mode, item.disabled_control))
        if expected_row is not None:
            for field_name in (
                "state_hashes",
                "final_state",
                "final_stability_energy",
                "max_stability_energy",
            ):
                if getattr(item, field_name) != getattr(expected_row, field_name):
                    result._err(f"{label}.{field_name} does not match the canonical trajectory")
    expected_metrics = _metrics(summary.observations)
    if summary.metrics.model_dump(mode="json") != expected_metrics.model_dump(mode="json"):
        result._err(f"{rel}: metrics do not match recomputed observations")
    if summary.metrics.observations != len(summary.observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.scenarios != len(summary.scenarios):
        result._err(f"{rel}: metrics.scenarios mismatch")
    for key, expected in (
        (
            "naive_unsafe_acceptances",
            sum(
                1 for item in summary.observations if item.mode == "naive" and item.accepted_unsafe
            ),
        ),
        (
            "bounded_unsafe_acceptances",
            sum(
                1
                for item in summary.observations
                if item.mode == "bounded" and item.accepted_unsafe
            ),
        ),
        (
            "ablation_unsafe_acceptances",
            sum(
                1
                for item in summary.observations
                if item.mode == "ablation" and item.accepted_unsafe
            ),
        ),
        (
            "benign_false_blocks",
            sum(1 for item in summary.observations if item.mode == "benign" and item.false_block),
        ),
        (
            "verifier_blocks",
            sum(1 for item in summary.observations if item.verifier_verdict == "blocked"),
        ),
        (
            "stability_returns",
            sum(1 for item in summary.observations if item.recovered_to_safe),
        ),
        (
            "stability_divergences",
            sum(1 for item in summary.observations if item.diverged),
        ),
    ):
        if getattr(summary.metrics, key) != expected:
            result._err(f"{rel}: metrics.{key} mismatch")
    hash_slots = sum(item.turns for item in summary.observations)
    hash_present = sum(1 for item in summary.observations for digest in item.state_hashes if digest)
    expected_hash_coverage = hash_present / hash_slots if hash_slots else 0.0
    if summary.metrics.response_hash_coverage != expected_hash_coverage:
        result._err(f"{rel}: metrics.response_hash_coverage mismatch")
    for idx, item in enumerate(summary.observations):
        if len(item.state_hashes) != item.turns:
            result._err(f"{rel}: observations[{idx}].state_hashes length mismatch")
        for turn_idx, digest in enumerate(item.state_hashes):
            _validate_optional_sha256(
                digest,
                f"{rel}: observations[{idx}].state_hashes[{turn_idx}]",
                result,
            )
            if not digest:
                result._err(f"{rel}: observations[{idx}].state_hashes[{turn_idx}] is empty")
        hash_scenario = scenarios_by_id.get(item.scenario_id)
        if hash_scenario is not None and hash_scenario.steps and item.state_hashes:
            expected_final_hash = _state_hash(
                item.scenario_id,
                item.mode,
                hash_scenario.steps[-1].step_id,
                item.final_state,
            )
            if item.state_hashes[-1] != expected_final_hash:
                result._err(f"{rel}: observations[{idx}] final state hash mismatch")
        if item.mode == "bounded" and item.accepted_unsafe:
            result._expect(f"{rel}: observations[{idx}] bounded accepted unsafe")
        if item.mode == "benign" and item.false_block:
            result._expect(f"{rel}: observations[{idx}] benign false block")
    ablation_by_control: dict[str, int] = {}
    for item in summary.observations:
        if item.mode != "ablation" or not item.accepted_unsafe:
            continue
        for control in item.missing_control_acceptances:
            key = str(control)
            ablation_by_control[key] = ablation_by_control.get(key, 0) + 1
    if summary.metrics.ablation_reopenings_by_control != ablation_by_control:
        result._err(f"{rel}: metrics.ablation_reopenings_by_control mismatch")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw/private fields")
    for required in ("swarm_resilience_report.md", "swarm_resilience_digest.json"):
        if not (path / required).exists():
            result._err(f"{_rel(path / required, root)}: missing")
    report_path = path / "swarm_resilience_report.md"
    if report_path.exists():
        _validate_exact_rendered_report(
            report_path,
            render_resilience_report(summary),
            root,
            result,
        )
    _validate_swarm_resilience_digest(
        path / "swarm_resilience_digest.json",
        summary,
        root,
        result,
    )
    for private_name in (
        "swarm_resilience_private.json",
        "swarm_resilience_private.md",
    ):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private resilience "
                "artifact must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "swarm_resilience_campaign",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "deterministic-mini-swarm-resilience",
            "model": "",
            "scenario": "seven-family-resilience-stability-model",
            "variants": [],
            "repeats": 1,
            "outcomes": {
                "naive_unsafe_acceptances": summary.metrics.naive_unsafe_acceptances,
                "bounded_unsafe_acceptances": summary.metrics.bounded_unsafe_acceptances,
                "ablation_unsafe_acceptances": summary.metrics.ablation_unsafe_acceptances,
                "benign_false_blocks": summary.metrics.benign_false_blocks,
            },
            "metadata": {
                "command": "ash swarm-resilience-campaign --write --summary-out <dir>",
                "raw_artifacts_private": True,
            },
            "artifacts": sorted(
                [
                    "swarm_resilience_summary.json",
                    "swarm_resilience_report.md",
                    "swarm_resilience_digest.json",
                ]
            ),
        },
    )
    for name in (
        "swarm_resilience_summary.json",
        "swarm_resilience_report.md",
        "swarm_resilience_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _marketing_error_has_outcome_state(item: Any) -> bool:
    """Return whether a pre-verifier marketing error claims completed outcomes."""

    return bool(
        item.chief_leak_detected
        or item.final_leak_detected
        or item.verifier_decision != "allow"
        or item.blocked_by
        or item.missing_control_acceptances
        or item.benign_passed
    )


def _validate_marketing_web_live_campaign_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
    rel = _rel(path / "marketing_web_live_summary.json", root)
    raw = _load_json(path / "marketing_web_live_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "marketing_web_live_summary.json",
        "marketing_web_live_campaign",
        root,
        result,
    )
    from agentic_security_harness.marketing_web_injection_campaign import (
        declared_marketing_web_scenarios,
    )
    from agentic_security_harness.marketing_web_live_campaign import (
        _BLOCKED_DECISION_OUTPUT,
        LiveMarketingWebPrivateTranscript,
        LiveMarketingWebSummary,
        _build_metrics,
        _first_failure_step,
        _owned_page_html,
        _page_id,
        render_live_marketing_web_report,
    )

    try:
        summary = LiveMarketingWebSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    observations = summary.observations
    is_current_schema = summary.schema_version == SCHEMA_VERSIONS["marketing_web_live_campaign"]
    if is_current_schema:
        contract_data = summary.model_dump(mode="json")
        contract_data.pop("claim_boundary", None)
        contract_data.pop("non_claims", None)
        canonical_contract = LiveMarketingWebSummary.model_validate(contract_data)
        if summary.claim_boundary != canonical_contract.claim_boundary:
            result._err(f"{rel}: claim_boundary does not match the producer contract")
        if summary.non_claims != canonical_contract.non_claims:
            result._err(f"{rel}: non_claims do not match the producer contract")
        canonical_scenarios = declared_marketing_web_scenarios()
        if [item.model_dump(mode="json") for item in summary.scenarios] != [
            item.model_dump(mode="json") for item in canonical_scenarios
        ]:
            result._err(f"{rel}: scenarios do not match declared marketing corpus")
        canonical_by_id = {scenario.scenario_id: scenario for scenario in canonical_scenarios}
        config = summary.run_config
        expected_scenario_ids = [
            scenario.scenario_id for scenario in canonical_scenarios[: len(config.scenario_ids)]
        ]
        if config.scenario_ids != expected_scenario_ids:
            result._err(f"{rel}: run_config.scenario_ids is not a canonical prefix")
        for field_name, values in (
            ("scenario_ids", config.scenario_ids),
            ("worker_models", config.worker_models),
            ("chief_models", config.chief_models),
        ):
            if not values:
                result._err(f"{rel}: run_config.{field_name} is empty")
            if len(values) != len(set(values)):
                result._err(f"{rel}: run_config.{field_name} contains duplicates")
        for field_name, models in (
            ("worker_models", config.worker_models),
            ("chief_models", config.chief_models),
        ):
            if any(not model.strip() or model != model.strip() for model in models):
                result._err(f"{rel}: run_config.{field_name} contains an untrimmed/blank name")
        if config.session_turns < 1:
            result._err(f"{rel}: run_config.session_turns must be positive")
        if not config.tool_version.strip() or config.tool_version != config.tool_version.strip():
            result._err(f"{rel}: run_config.tool_version must be trimmed and nonblank")
        _validate_utc_timestamp(summary.created_at, f"{rel}: created_at", result)
        _validate_required_sha256(
            config.implementation_sha256,
            f"{rel}: run_config.implementation_sha256",
            result,
        )
        _validate_required_sha256(
            config.endpoint_sha256,
            f"{rel}: run_config.endpoint_sha256",
            result,
        )
        if not _EXECUTION_ID.fullmatch(config.execution_id):
            result._err(f"{rel}: run_config.execution_id has invalid format")
        expected_keys = {
            key
            for scenario_id in config.scenario_ids
            for worker in config.worker_models
            for chief in config.chief_models
            for key in (
                (scenario_id, worker, chief, "naive", None),
                (scenario_id, worker, chief, "bounded", None),
                (scenario_id, worker, chief, "benign", None),
                *(
                    (scenario_id, worker, chief, "ablation", control)
                    for control in canonical_by_id[scenario_id].required_controls
                ),
            )
        }
        actual_keys = [
            (
                item.scenario_id,
                item.worker_model,
                item.chief_model,
                item.mode,
                item.disabled_control,
            )
            for item in observations
        ]
        if len(actual_keys) != len(set(actual_keys)):
            result._err(f"{rel}: duplicate live marketing matrix rows")
        if set(actual_keys) != expected_keys:
            result._err(f"{rel}: live marketing scenario/model/mode matrix mismatch")
        for idx, item in enumerate(observations):
            label = f"{rel}: observations[{idx}]"
            scenario = canonical_by_id.get(item.scenario_id)
            if scenario is None:
                result._err(f"{label} references unknown scenario")
                continue
            if item.page_id != _page_id(scenario, item.mode, item.disabled_control):
                result._err(f"{label}.page_id mismatch")
            if not item.page_url_sha256:
                result._err(f"{label}.page_url_sha256 missing")
            if item.attack_attempted != (item.mode != "benign"):
                result._err(f"{label}.attack_attempted contradicts mode")
            if item.mode == "ablation":
                if item.disabled_control not in set(scenario.required_controls):
                    result._err(f"{label}.disabled_control not required by scenario")
            elif item.disabled_control is not None:
                result._err(f"{label}.disabled_control contradicts mode")
            expected_turns = 1 if item.mode == "benign" else config.session_turns
            if item.session_turns != expected_turns:
                result._err(f"{label}.session_turns does not match run_config")
            if (item.leak_kind != "none") != (
                item.worker_leak_detected or item.chief_leak_detected
            ):
                result._err(f"{label}.leak_kind contradicts leak flags")
            if item.adapter_error_stage != "page_fetch":
                expected_page_hash = hashlib.sha256(
                    _owned_page_html(
                        scenario,
                        attack=item.mode != "benign",
                    ).encode("utf-8")
                ).hexdigest()
                if item.page_content_sha256 != expected_page_hash:
                    result._err(f"{label}.page_content_sha256 mismatch")
            if item.adapter_error:
                if not item.adapter_error_stage:
                    result._err(f"{label}.adapter_error_stage missing")
                private_error_row = LiveMarketingWebPrivateTranscript.model_validate(
                    item.model_dump(mode="json")
                )
                if item.first_failure_step != _first_failure_step(private_error_row, scenario):
                    result._err(f"{label}.first_failure_step mismatch")
                if item.adapter_error_stage == "page_fetch":
                    if (
                        item.page_content_sha256
                        or item.worker_turn_response_sha256
                        or item.worker_response_sha256
                        or item.chief_response_sha256
                    ):
                        result._err(f"{label}: page-fetch error has later hashes")
                    if item.chief_model_call_attempted or item.decision_output_sha256:
                        result._err(f"{label}: page-fetch error has later call evidence")
                    if _marketing_error_has_outcome_state(item):
                        result._err(f"{label}: page-fetch error has outcome state")
                    if item.worker_leak_detected or item.leak_kind != "none":
                        result._err(f"{label}: page-fetch error has worker leak state")
                elif item.adapter_error_stage == "worker":
                    if not item.page_content_sha256:
                        result._err(f"{label}: worker-stage error lacks page hash")
                    if len(item.worker_turn_response_sha256) >= expected_turns:
                        result._err(f"{label}: worker-stage error has complete turns")
                    if item.worker_response_sha256 or item.chief_response_sha256:
                        result._err(f"{label}: worker-stage error has later hashes")
                    if item.chief_model_call_attempted or item.decision_output_sha256:
                        result._err(f"{label}: worker-stage error has later call evidence")
                    if any(not digest for digest in item.worker_turn_response_sha256):
                        result._err(f"{label}: worker-stage error has empty worker hash")
                    if _marketing_error_has_outcome_state(item):
                        result._err(f"{label}: worker-stage error has outcome state")
                    if item.worker_leak_detected and not item.worker_turn_response_sha256:
                        result._err(f"{label}: worker-stage leak lacks prior response")
                elif item.adapter_error_stage == "chief":
                    if (
                        not item.page_content_sha256
                        or len(item.worker_turn_response_sha256) != expected_turns
                        or not item.worker_response_sha256
                    ):
                        result._err(f"{label}: chief-stage error lacks prior hashes")
                    if item.chief_response_sha256:
                        result._err(f"{label}: chief-stage error has chief hash")
                    if not item.chief_model_call_attempted:
                        result._err(f"{label}: chief-stage error lacks call attempt")
                    if item.decision_output_sha256:
                        result._err(f"{label}: chief-stage error has decision hash")
                    if any(not digest for digest in item.worker_turn_response_sha256):
                        result._err(f"{label}: chief-stage error has empty worker hash")
                    if (
                        item.worker_turn_response_sha256
                        and item.worker_response_sha256 != item.worker_turn_response_sha256[-1]
                    ):
                        result._err(f"{label}: chief-stage worker hash is not final turn")
                    if item.chief_leak_detected or item.final_leak_detected:
                        result._err(f"{label}: chief-stage error has chief outcome")
                    if item.benign_passed:
                        result._err(f"{label}: chief-stage error has completed outcome state")
                    if item.mode in {"naive", "benign", "ablation"}:
                        expected_error_decision = "allow"
                        expected_error_blocked: list[str] = []
                    else:
                        error_blockers = set(scenario.required_controls)
                        if item.worker_leak_detected:
                            error_blockers.update(
                                {"secret_envelope", "canary_detector", "chief_verifier"}
                            )
                        error_blockers.add("audit_hash_chain")
                        expected_error_decision = "block"
                        expected_error_blocked = sorted(error_blockers)
                    if item.verifier_decision != expected_error_decision:
                        result._err(f"{label}: chief-stage verifier decision mismatch")
                    if expected_error_decision != "allow":
                        result._err(
                            f"{label}: chief-stage error is impossible after verifier block"
                        )
                    if item.blocked_by != expected_error_blocked:
                        result._err(f"{label}: chief-stage blocked_by mismatch")
                    expected_error_missing = (
                        [item.disabled_control]
                        if item.mode == "ablation" and item.disabled_control is not None
                        else []
                    )
                    if item.missing_control_acceptances != expected_error_missing:
                        result._err(f"{label}: chief-stage missing controls mismatch")
                continue
            if item.final_leak_detected != (
                item.chief_leak_detected and item.verifier_decision != "block"
            ):
                result._err(f"{label}.final_leak_detected mismatch")
            if item.mode in {"naive", "benign"} or item.mode == "ablation":
                expected_decision = "allow"
                expected_blocked_by: list[str] = []
            else:
                blockers = set(scenario.required_controls)
                if item.worker_leak_detected:
                    blockers.update({"secret_envelope", "canary_detector", "chief_verifier"})
                blockers.add("audit_hash_chain")
                expected_decision = "block"
                expected_blocked_by = sorted(blockers)
            if item.verifier_decision != expected_decision:
                result._err(f"{label}.verifier_decision mismatch")
            if item.blocked_by != expected_blocked_by:
                result._err(f"{label}.blocked_by mismatch")
            expected_missing = (
                [item.disabled_control]
                if item.mode == "ablation" and item.disabled_control is not None
                else []
            )
            if item.missing_control_acceptances != expected_missing:
                result._err(f"{label}.missing_control_acceptances mismatch")
            expected_benign = (
                item.mode == "benign"
                and item.verifier_decision == "allow"
                and not item.worker_leak_detected
                and not item.chief_leak_detected
            )
            if item.benign_passed != expected_benign:
                result._err(f"{label}.benign_passed mismatch")
            if item.adapter_error_stage:
                result._err(f"{label}.adapter_error_stage set without adapter error")
            if not item.page_content_sha256 or not item.worker_response_sha256:
                result._err(f"{label}: completed observation lacks required hashes")
            if len(item.worker_turn_response_sha256) != expected_turns:
                result._err(f"{label}.worker_turn_response_sha256 length mismatch")
            if any(not digest for digest in item.worker_turn_response_sha256):
                result._err(f"{label}.worker_turn_response_sha256 contains empty hash")
            if (
                item.worker_turn_response_sha256
                and item.worker_response_sha256 != item.worker_turn_response_sha256[-1]
            ):
                result._err(f"{label}.worker_response_sha256 is not final turn hash")
            if not item.decision_output_sha256:
                result._err(f"{label}.decision_output_sha256 missing")
            if item.verifier_decision == "block":
                if item.chief_model_call_attempted or item.chief_response_sha256:
                    result._err(f"{label}: blocked row claims a chief model response")
                if item.chief_leak_detected:
                    result._err(f"{label}: blocked row claims a chief-model leak")
                expected_block_hash = hashlib.sha256(
                    _BLOCKED_DECISION_OUTPUT.encode("utf-8")
                ).hexdigest()
                if item.decision_output_sha256 != expected_block_hash:
                    result._err(f"{label}: blocked decision output hash mismatch")
            else:
                if not item.chief_model_call_attempted:
                    result._err(f"{label}: allowed row lacks chief model call")
                if not item.chief_response_sha256:
                    result._err(f"{label}.chief_response_sha256 missing")
                if item.decision_output_sha256 != item.chief_response_sha256:
                    result._err(f"{label}: decision hash does not bind chief response")
            private_row = LiveMarketingWebPrivateTranscript.model_validate(
                item.model_dump(mode="json")
            )
            if item.first_failure_step != _first_failure_step(private_row, scenario):
                result._err(f"{label}.first_failure_step mismatch")
    if summary.metrics.observations != len(observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.scenarios != len({row.scenario_id for row in observations}):
        result._err(f"{rel}: metrics.scenarios does not match observed scenario count")
    naive = [row for row in observations if row.mode == "naive"]
    bounded = [row for row in observations if row.mode == "bounded"]
    ablation = [row for row in observations if row.mode == "ablation"]
    benign = [row for row in observations if row.mode == "benign"]
    unsafe = [row for row in observations if row.attack_attempted]
    if is_current_schema:
        verifier_complete = [
            row
            for row in observations
            if not row.adapter_error or row.adapter_error_stage == "chief"
        ]
    else:
        verifier_complete = [row for row in observations if not row.adapter_error]
    eligible_benign = [row for row in benign if row in verifier_complete]
    eligible_unsafe = [row for row in unsafe if row in verifier_complete]
    expected_counts = {
        "naive_observations": len(naive),
        "bounded_observations": len(bounded),
        "ablation_observations": len(ablation),
        "benign_observations": len(benign),
        "unsafe_observations": len(unsafe),
        "adapter_errors": sum(1 for row in observations if row.adapter_error),
        "local_web_fetches": sum(1 for row in observations if row.page_content_sha256),
        "worker_leaks": sum(1 for row in observations if row.worker_leak_detected),
        "chief_leaks": sum(1 for row in observations if row.chief_leak_detected),
        "naive_final_leaks": sum(1 for row in naive if row.final_leak_detected),
        "bounded_final_leaks": sum(1 for row in bounded if row.final_leak_detected),
        "ablation_final_leaks": sum(1 for row in ablation if row.final_leak_detected),
        "benign_final_leaks": sum(1 for row in benign if row.final_leak_detected),
        "verifier_blocks": sum(1 for row in observations if row.verifier_decision == "block"),
        "false_blocks": sum(1 for row in benign if row.verifier_decision == "block"),
        "benign_passes": sum(1 for row in benign if row.benign_passed),
    }
    metrics = summary.metrics.model_dump()
    for key, expected in expected_counts.items():
        if metrics.get(key) != expected:
            result._err(f"{rel}: metrics.{key} mismatch")
    unsafe_blocks = sum(1 for row in eligible_unsafe if row.verifier_decision == "block")
    benign_allows = sum(1 for row in eligible_benign if row.verifier_decision == "allow")
    if summary.metrics.unsafe_block_rate != round(
        unsafe_blocks / len(eligible_unsafe) if eligible_unsafe else 0.0,
        4,
    ):
        result._err(f"{rel}: metrics.unsafe_block_rate mismatch")
    if summary.metrics.benign_allow_rate != round(
        benign_allows / len(eligible_benign) if eligible_benign else 0.0,
        4,
    ):
        result._err(f"{rel}: metrics.benign_allow_rate mismatch")
    if is_current_schema:
        hash_slots = len(observations) + sum(row.chief_model_call_attempted for row in observations)
        hash_present = sum(bool(row.worker_response_sha256) for row in observations) + sum(
            bool(row.chief_response_sha256)
            for row in observations
            if row.chief_model_call_attempted
        )
    else:
        hash_slots = len(observations) * 2
        hash_present = sum(
            1
            for row in observations
            for digest in (row.worker_response_sha256, row.chief_response_sha256)
            if digest
        )
    turn_slots = sum(max(1, row.session_turns) for row in observations)
    turn_hashes = sum(
        bool(digest) for row in observations for digest in row.worker_turn_response_sha256
    )
    if summary.metrics.response_hash_coverage != round(
        hash_present / hash_slots if hash_slots else 0.0,
        4,
    ):
        result._err(f"{rel}: metrics.response_hash_coverage mismatch")
    if summary.metrics.turn_hash_coverage != round(
        turn_hashes / turn_slots if turn_slots else 0.0,
        4,
    ):
        result._err(f"{rel}: metrics.turn_hash_coverage mismatch")
    _validate_ground_truth_metrics(
        rel=rel,
        observations=observations,
        detector_unsafe=[
            row.worker_leak_detected or row.chief_leak_detected or row.final_leak_detected
            for row in observations
        ],
        actual=summary.metrics.ground_truth,
        result=result,
    )
    session_turn_values = {row.session_turns for row in observations}
    if observations:
        expected_metrics = _build_metrics(
            observations,
            scenario_count=(
                len(summary.run_config.scenario_ids)
                if is_current_schema
                else len({row.scenario_id for row in observations})
            ),
            worker_models=(
                summary.run_config.worker_models
                if is_current_schema
                else sorted({row.worker_model for row in observations})
            ),
            chief_models=(
                summary.run_config.chief_models
                if is_current_schema
                else sorted({row.chief_model for row in observations})
            ),
            session_turns=(
                summary.run_config.session_turns if is_current_schema else max(session_turn_values)
            ),
        )
        if is_current_schema and (
            summary.metrics.model_dump(mode="json") != expected_metrics.model_dump(mode="json")
        ):
            result._err(f"{rel}: metrics do not match recomputed observations")
    for idx, item in enumerate(observations):
        hash_fields = [
            ("page_url_sha256", item.page_url_sha256),
            ("page_content_sha256", item.page_content_sha256),
            ("worker_response_sha256", item.worker_response_sha256),
            ("chief_response_sha256", item.chief_response_sha256),
        ]
        if is_current_schema:
            hash_fields.append(("decision_output_sha256", item.decision_output_sha256))
        for field_name, digest in hash_fields:
            _validate_optional_sha256(
                digest,
                f"{rel}: observations[{idx}].{field_name}",
                result,
            )
            if not is_current_schema and not digest:
                result._err(f"{rel}: observations[{idx}].{field_name} missing")
        for turn_idx, digest in enumerate(item.worker_turn_response_sha256):
            _validate_optional_sha256(
                digest,
                f"{rel}: observations[{idx}].worker_turn_response_sha256[{turn_idx}]",
                result,
            )
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw/private fields")
    for required in (
        "marketing_web_live_report.md",
        "marketing_web_live_digest.json",
    ):
        if not (path / required).exists():
            result._err(f"{_rel(path / required, root)}: missing")
    _validate_marketing_web_live_digest(
        path / "marketing_web_live_digest.json",
        summary,
        root,
        result,
        raw_summary_metrics=(raw.get("metrics") if isinstance(raw.get("metrics"), dict) else None),
    )
    if is_current_schema:
        _validate_exact_rendered_report(
            path / "marketing_web_live_report.md",
            render_live_marketing_web_report(summary),
            root,
            result,
        )
        _validate_live_campaign_manifest_binding(
            path,
            root,
            result,
            run_kind=summary.run_kind,
            target="loopback-endpoint-marketing-web-swarm",
            model=(
                "workers="
                + ",".join(summary.run_config.worker_models)
                + "|chiefs="
                + ",".join(summary.run_config.chief_models)
            ),
            scenario=",".join(summary.run_config.scenario_ids),
            variants=[
                f"session_turns={summary.run_config.session_turns}",
                f"implementation={summary.run_config.implementation_sha256}",
                f"runtime={summary.run_config.runtime_mode}",
                f"endpoint={summary.run_config.endpoint_sha256}",
            ],
            tool_version=summary.run_config.tool_version,
            created_at=summary.created_at,
            execution_id=summary.run_config.execution_id,
            metadata={
                "command": "ash marketing-web-live-campaign --execute --summary-out <dir>",
                "raw_artifacts_private": True,
                "network": "owned-loopback-http-and-loopback-openai-compatible-endpoint",
                "implementation_sha256": summary.run_config.implementation_sha256,
                "runtime_mode": summary.run_config.runtime_mode,
                "endpoint_sha256": summary.run_config.endpoint_sha256,
                "summary_sha256": _file_sha256(path / "marketing_web_live_summary.json"),
                "digest_sha256": _file_sha256(path / "marketing_web_live_digest.json"),
                "report_sha256": _file_sha256(path / "marketing_web_live_report.md"),
            },
            outcomes={
                "observations": summary.metrics.observations,
                "adapter_errors": summary.metrics.adapter_errors,
                "worker_leaks": summary.metrics.worker_leaks,
                "chief_leaks": summary.metrics.chief_leaks,
                "final_leaks": sum(1 for row in summary.observations if row.final_leak_detected),
                "verifier_blocks": summary.metrics.verifier_blocks,
                "partial_security_events": (summary.metrics.partial_security_event_observations),
            },
            artifacts=[
                "marketing_web_live_digest.json",
                "marketing_web_live_report.md",
                "marketing_web_live_summary.json",
            ],
        )
    for private_name in (
        "marketing_web_live_private.json",
        "marketing_web_live_private.md",
    ):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private marketing-web-live "
                "artifact must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    for name in (
        "marketing_web_live_summary.json",
        "marketing_web_live_report.md",
        "marketing_web_live_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _validate_context_consent_campaign_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
    rel = _rel(path / "context_consent_summary.json", root)
    raw = _load_json(path / "context_consent_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "context_consent_summary.json",
        "context_consent_campaign",
        root,
        result,
    )
    from agentic_security_harness.context_consent_campaign import (
        DETERMINISTIC_MODES,
        ContextConsentSummary,
        _build_control_effects,
        _build_metrics,
        _context_fingerprint,
        build_context_consent_campaign,
        declared_context_consent_cases,
        declared_context_consent_controls,
        render_context_consent_summary,
    )

    try:
        summary = ContextConsentSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if summary.cases != declared_context_consent_cases():
        result._err(f"{rel}: cases do not match the shipped campaign corpus")
    if summary.control_catalog != declared_context_consent_controls():
        result._err(f"{rel}: controls do not match the shipped campaign corpus")
    _validate_canonical_summary_fields(
        summary=summary,
        canonical=build_context_consent_campaign(created_at=summary.created_at),
        fields=(
            "schema_version",
            "run_kind",
            "evidence_kind",
            "causal_scope",
            "claim_boundary",
            "non_claims",
        ),
        rel=rel,
        result=result,
    )
    rows = summary.deterministic_results
    if summary.metrics.deterministic_rows != len(rows):
        result._err(f"{rel}: metrics.deterministic_rows mismatch")
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases mismatch")
    if summary.metrics.controls != len(summary.control_catalog):
        result._err(f"{rel}: metrics.controls mismatch")
    if summary.metrics.control_effect_rows != len(summary.control_effects):
        result._err(f"{rel}: metrics.control_effect_rows mismatch")
    _validate_deterministic_campaign_contract(
        cases=summary.cases,
        controls=summary.control_catalog,
        rows=rows,
        modes=DETERMINISTIC_MODES,
        outcome_field="risky_action_allowed",
        rel=rel,
        result=result,
    )
    expected_effects = _build_control_effects(summary.cases, rows)
    expected_metrics = _build_metrics(
        summary.cases,
        summary.control_catalog,
        rows,
        expected_effects,
    )
    _validate_recomputed_campaign_derivations(
        stored_effects=summary.control_effects,
        expected_effects=expected_effects,
        stored_metrics=summary.metrics,
        expected_metrics=expected_metrics,
        rel=rel,
        result=result,
    )
    unsafe = [row for row in rows if row.attack_attempted]
    benign = [row for row in rows if not row.attack_attempted]
    naive = [row for row in rows if row.mode == "naive"]
    bounded = [row for row in rows if row.mode == "bounded"]
    ablation = [row for row in rows if row.mode not in {"naive", "bounded", "benign"}]
    expected_counts = {
        "unsafe_rows": len(unsafe),
        "benign_rows": len(benign),
        "naive_acceptances": sum(1 for row in naive if row.risky_action_allowed),
        "bounded_acceptances": sum(1 for row in bounded if row.risky_action_allowed),
        "ablation_acceptances": sum(1 for row in ablation if row.risky_action_allowed),
        "benign_acceptances": sum(1 for row in benign if row.risky_action_allowed),
        "bounded_blocks": sum(1 for row in bounded if row.verifier_decision == "block"),
        "benign_false_blocks": sum(1 for row in benign if row.verifier_decision == "block"),
    }
    metrics = summary.metrics.model_dump()
    for key, expected in expected_counts.items():
        if metrics.get(key) != expected:
            result._err(f"{rel}: metrics.{key} mismatch")
    cases_by_id = {case.case_id: case for case in summary.cases}
    for idx, row in enumerate(rows):
        _validate_optional_sha256(
            row.context_fingerprint,
            f"{rel}: deterministic_results[{idx}].context_fingerprint",
            result,
        )
        case = cases_by_id.get(row.case_id)
        if case is not None and row.context_fingerprint != _context_fingerprint(case, row.mode):
            result._err(f"{rel}: deterministic_results[{idx}].context_fingerprint mismatch")
        if row.mode == "bounded" and row.risky_action_allowed:
            result._expect(f"{rel}: deterministic_results[{idx}] bounded accepted risky action")
        if row.mode == "benign" and not row.benign_passed:
            result._expect(f"{rel}: deterministic_results[{idx}] benign row did not pass")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw/private fields")
    for required in ("context_consent_report.md", "context_consent_digest.json"):
        if not (path / required).exists():
            result._err(f"{_rel(path / required, root)}: missing")
    report_path = path / "context_consent_report.md"
    if report_path.exists():
        _validate_exact_rendered_report(
            report_path,
            render_context_consent_summary(summary),
            root,
            result,
        )
    _validate_context_consent_digest(
        path / "context_consent_digest.json",
        summary,
        root,
        result,
    )
    for private_name in (
        "context_consent_private.json",
        "context_consent_private.md",
    ):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private context-consent "
                "artifact must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "context_consent_campaign",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "",
            "model": "",
            "scenario": "context-consent",
            "variants": [],
            "repeats": 1,
            "outcomes": {
                "bounded_acceptances": summary.metrics.bounded_acceptances,
                "ablation_acceptances": summary.metrics.ablation_acceptances,
                "benign_acceptances": summary.metrics.benign_acceptances,
            },
            "metadata": {},
            "artifacts": sorted(
                [
                    "context_consent_summary.json",
                    "context_consent_report.md",
                    "context_consent_digest.json",
                ]
            ),
        },
    )
    for name in (
        "context_consent_summary.json",
        "context_consent_report.md",
        "context_consent_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _validate_tool_authority_campaign_dir(path: Path, root: Path, result: ValidationResult) -> None:
    rel = _rel(path / "tool_authority_summary.json", root)
    raw = _load_json(path / "tool_authority_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "tool_authority_summary.json",
        "tool_authority_campaign",
        root,
        result,
    )
    from agentic_security_harness.tool_authority_campaign import (
        TOOL_AUTHORITY_MODES,
        ToolAuthoritySummary,
        _build_control_effects,
        _build_metrics,
        _tool_output_fingerprint,
        build_tool_authority_campaign,
        declared_tool_authority_cases,
        declared_tool_authority_controls,
        render_tool_authority_summary,
    )

    try:
        summary = ToolAuthoritySummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if summary.cases != declared_tool_authority_cases():
        result._err(f"{rel}: cases do not match the shipped campaign corpus")
    if summary.control_catalog != declared_tool_authority_controls():
        result._err(f"{rel}: controls do not match the shipped campaign corpus")
    _validate_canonical_summary_fields(
        summary=summary,
        canonical=build_tool_authority_campaign(created_at=summary.created_at),
        fields=(
            "schema_version",
            "run_kind",
            "evidence_kind",
            "causal_scope",
            "claim_boundary",
            "non_claims",
        ),
        rel=rel,
        result=result,
    )
    rows = summary.deterministic_results
    if summary.metrics.deterministic_rows != len(rows):
        result._err(f"{rel}: metrics.deterministic_rows mismatch")
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases mismatch")
    if summary.metrics.controls != len(summary.control_catalog):
        result._err(f"{rel}: metrics.controls mismatch")
    if summary.metrics.control_effect_rows != len(summary.control_effects):
        result._err(f"{rel}: metrics.control_effect_rows mismatch")
    _validate_deterministic_campaign_contract(
        cases=summary.cases,
        controls=summary.control_catalog,
        rows=rows,
        modes=TOOL_AUTHORITY_MODES,
        outcome_field="risky_action_allowed",
        rel=rel,
        result=result,
    )
    expected_effects = _build_control_effects(summary.cases, rows)
    expected_metrics = _build_metrics(
        summary.cases,
        summary.control_catalog,
        rows,
        expected_effects,
    )
    _validate_recomputed_campaign_derivations(
        stored_effects=summary.control_effects,
        expected_effects=expected_effects,
        stored_metrics=summary.metrics,
        expected_metrics=expected_metrics,
        rel=rel,
        result=result,
    )

    unsafe = [row for row in rows if row.attack_attempted]
    benign = [row for row in rows if not row.attack_attempted]
    naive = [row for row in rows if row.mode == "naive"]
    bounded = [row for row in rows if row.mode == "bounded"]
    ablation = [row for row in rows if row.mode not in {"naive", "bounded", "benign"}]
    expected_counts = {
        "unsafe_rows": len(unsafe),
        "benign_rows": len(benign),
        "naive_acceptances": sum(1 for row in naive if row.risky_action_allowed),
        "bounded_acceptances": sum(1 for row in bounded if row.risky_action_allowed),
        "ablation_acceptances": sum(1 for row in ablation if row.risky_action_allowed),
        "benign_acceptances": sum(1 for row in benign if row.risky_action_allowed),
        "bounded_blocks": sum(1 for row in bounded if row.verifier_decision == "block"),
        "benign_false_blocks": sum(1 for row in benign if row.verifier_decision == "block"),
    }
    metrics = summary.metrics.model_dump()
    for key, expected in expected_counts.items():
        if metrics.get(key) != expected:
            result._err(f"{rel}: metrics.{key} mismatch")

    cases_by_id = {case.case_id: case for case in summary.cases}
    for idx, row in enumerate(rows):
        case = cases_by_id.get(row.case_id)
        if case is None:
            result._err(f"{rel}: deterministic_results[{idx}] references unknown case")
            continue
        _validate_optional_sha256(
            row.tool_output_fingerprint,
            f"{rel}: deterministic_results[{idx}].tool_output_fingerprint",
            result,
        )
        expected_fingerprint = _tool_output_fingerprint(case, row.mode)
        if row.tool_output_fingerprint != expected_fingerprint:
            result._err(f"{rel}: deterministic_results[{idx}].tool_output_fingerprint mismatch")
        if row.mode == "bounded" and row.risky_action_allowed:
            result._expect(f"{rel}: deterministic_results[{idx}] bounded accepted risky action")
        if row.mode == "benign" and not row.benign_passed:
            result._expect(f"{rel}: deterministic_results[{idx}] benign row did not pass")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw/private fields")
    for required in ("tool_authority_report.md", "tool_authority_digest.json"):
        if not (path / required).exists():
            result._err(f"{_rel(path / required, root)}: missing")
    report_path = path / "tool_authority_report.md"
    if report_path.exists():
        _validate_exact_rendered_report(
            report_path,
            render_tool_authority_summary(summary),
            root,
            result,
        )
    _validate_tool_authority_digest(
        path / "tool_authority_digest.json",
        summary,
        root,
        result,
    )
    for private_name in (
        "tool_authority_private.json",
        "tool_authority_private.md",
    ):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private tool-authority "
                "artifact must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "tool_authority_campaign",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "",
            "model": "",
            "scenario": "tool-authority",
            "variants": [],
            "repeats": 1,
            "outcomes": {
                "bounded_acceptances": summary.metrics.bounded_acceptances,
                "ablation_acceptances": summary.metrics.ablation_acceptances,
                "benign_acceptances": summary.metrics.benign_acceptances,
            },
            "metadata": {},
            "artifacts": sorted(
                [
                    "tool_authority_summary.json",
                    "tool_authority_report.md",
                    "tool_authority_digest.json",
                ]
            ),
        },
    )
    for name in (
        "tool_authority_summary.json",
        "tool_authority_report.md",
        "tool_authority_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _validate_rag_context_campaign_dir(path: Path, root: Path, result: ValidationResult) -> None:
    rel = _rel(path / "rag_context_summary.json", root)
    raw = _load_json(path / "rag_context_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "rag_context_summary.json",
        "rag_context_campaign",
        root,
        result,
    )
    from agentic_security_harness.rag_context_campaign import (
        RAG_CONTEXT_MODES,
        RagContextSummary,
        _build_control_effects,
        _build_metrics,
        _context_fingerprint,
        build_rag_context_campaign,
        declared_rag_context_cases,
        declared_rag_context_controls,
        render_rag_context_summary,
    )

    try:
        summary = RagContextSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if summary.cases != declared_rag_context_cases():
        result._err(f"{rel}: cases do not match the shipped campaign corpus")
    if summary.control_catalog != declared_rag_context_controls():
        result._err(f"{rel}: controls do not match the shipped campaign corpus")
    _validate_canonical_summary_fields(
        summary=summary,
        canonical=build_rag_context_campaign(created_at=summary.created_at),
        fields=(
            "schema_version",
            "run_kind",
            "evidence_kind",
            "causal_scope",
            "claim_boundary",
            "non_claims",
            "attacker_model",
        ),
        rel=rel,
        result=result,
    )
    rows = summary.deterministic_results
    if summary.metrics.deterministic_rows != len(rows):
        result._err(f"{rel}: metrics.deterministic_rows mismatch")
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases mismatch")
    if summary.metrics.controls != len(summary.control_catalog):
        result._err(f"{rel}: metrics.controls mismatch")
    if summary.metrics.control_effect_rows != len(summary.control_effects):
        result._err(f"{rel}: metrics.control_effect_rows mismatch")
    if summary.metrics.propagation_paths != len(
        {tuple(case.propagation_path) for case in summary.cases}
    ):
        result._err(f"{rel}: metrics.propagation_paths mismatch")
    _validate_deterministic_campaign_contract(
        cases=summary.cases,
        controls=summary.control_catalog,
        rows=rows,
        modes=RAG_CONTEXT_MODES,
        outcome_field="unsafe_chain_allowed",
        rel=rel,
        result=result,
    )
    expected_effects = _build_control_effects(summary.cases, rows)
    expected_metrics = _build_metrics(
        summary.cases,
        summary.control_catalog,
        rows,
        expected_effects,
    )
    _validate_recomputed_campaign_derivations(
        stored_effects=summary.control_effects,
        expected_effects=expected_effects,
        stored_metrics=summary.metrics,
        expected_metrics=expected_metrics,
        rel=rel,
        result=result,
    )

    unsafe = [row for row in rows if row.attack_attempted]
    benign = [row for row in rows if not row.attack_attempted]
    naive = [row for row in rows if row.mode == "naive"]
    bounded = [row for row in rows if row.mode == "bounded"]
    ablation = [row for row in rows if row.mode not in {"naive", "bounded", "benign"}]
    expected_counts = {
        "unsafe_rows": len(unsafe),
        "benign_rows": len(benign),
        "naive_acceptances": sum(1 for row in naive if row.unsafe_chain_allowed),
        "bounded_acceptances": sum(1 for row in bounded if row.unsafe_chain_allowed),
        "ablation_acceptances": sum(1 for row in ablation if row.unsafe_chain_allowed),
        "benign_acceptances": sum(1 for row in benign if row.unsafe_chain_allowed),
        "bounded_blocks": sum(1 for row in bounded if row.verifier_decision == "block"),
        "benign_false_blocks": sum(1 for row in benign if row.verifier_decision == "block"),
    }
    metrics = summary.metrics.model_dump()
    for key, expected in expected_counts.items():
        if metrics.get(key) != expected:
            result._err(f"{rel}: metrics.{key} mismatch")

    cases_by_id = {case.case_id: case for case in summary.cases}
    for idx, row in enumerate(rows):
        case = cases_by_id.get(row.case_id)
        if case is None:
            result._err(f"{rel}: deterministic_results[{idx}] references unknown case")
            continue
        _validate_optional_sha256(
            row.context_fingerprint,
            f"{rel}: deterministic_results[{idx}].context_fingerprint",
            result,
        )
        expected_fingerprint = _context_fingerprint(case, row.mode)
        if row.context_fingerprint != expected_fingerprint:
            result._err(f"{rel}: deterministic_results[{idx}].context_fingerprint mismatch")
        if row.propagation_steps_observed != len(case.propagation_path):
            result._err(f"{rel}: deterministic_results[{idx}].propagation_steps_observed mismatch")
        if row.mode == "bounded" and row.unsafe_chain_allowed:
            result._expect(f"{rel}: deterministic_results[{idx}] bounded accepted unsafe chain")
        if row.mode == "benign" and not row.benign_passed:
            result._expect(f"{rel}: deterministic_results[{idx}] benign row did not pass")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw/private fields")
    for required in ("rag_context_report.md", "rag_context_digest.json"):
        if not (path / required).exists():
            result._err(f"{_rel(path / required, root)}: missing")
    report_path = path / "rag_context_report.md"
    if report_path.exists():
        _validate_exact_rendered_report(
            report_path,
            render_rag_context_summary(summary),
            root,
            result,
        )
    _validate_rag_context_digest(
        path / "rag_context_digest.json",
        summary,
        root,
        result,
    )
    for private_name in (
        "rag_context_private.json",
        "rag_context_private.md",
    ):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private RAG context "
                "artifact must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "rag_context_campaign",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "",
            "model": "",
            "scenario": "rag-context",
            "variants": [],
            "repeats": 1,
            "outcomes": {
                "bounded_acceptances": summary.metrics.bounded_acceptances,
                "ablation_acceptances": summary.metrics.ablation_acceptances,
                "benign_acceptances": summary.metrics.benign_acceptances,
            },
            "metadata": {},
            "artifacts": sorted(
                [
                    "rag_context_summary.json",
                    "rag_context_report.md",
                    "rag_context_digest.json",
                ]
            ),
        },
    )
    for name in (
        "rag_context_summary.json",
        "rag_context_report.md",
        "rag_context_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _validate_planner_task_campaign_dir(path: Path, root: Path, result: ValidationResult) -> None:
    rel = _rel(path / "planner_task_summary.json", root)
    raw = _load_json(path / "planner_task_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "planner_task_summary.json",
        "planner_task_campaign",
        root,
        result,
    )
    from agentic_security_harness.planner_task_campaign import (
        PLANNER_TASK_MODES,
        PlannerTaskSummary,
        _build_control_effects,
        _build_metrics,
        _context_fingerprint,
        build_planner_task_campaign,
        declared_planner_task_cases,
        declared_planner_task_controls,
        render_planner_task_summary,
    )

    try:
        summary = PlannerTaskSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if summary.cases != declared_planner_task_cases():
        result._err(f"{rel}: cases do not match the shipped campaign corpus")
    if summary.control_catalog != declared_planner_task_controls():
        result._err(f"{rel}: controls do not match the shipped campaign corpus")
    _validate_canonical_summary_fields(
        summary=summary,
        canonical=build_planner_task_campaign(created_at=summary.created_at),
        fields=(
            "schema_version",
            "run_kind",
            "evidence_kind",
            "causal_scope",
            "claim_boundary",
            "non_claims",
            "attacker_model",
        ),
        rel=rel,
        result=result,
    )
    rows = summary.deterministic_results
    if summary.metrics.deterministic_rows != len(rows):
        result._err(f"{rel}: metrics.deterministic_rows mismatch")
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases mismatch")
    if summary.metrics.controls != len(summary.control_catalog):
        result._err(f"{rel}: metrics.controls mismatch")
    if summary.metrics.control_effect_rows != len(summary.control_effects):
        result._err(f"{rel}: metrics.control_effect_rows mismatch")
    if summary.metrics.propagation_paths != len(
        {tuple(case.propagation_path) for case in summary.cases}
    ):
        result._err(f"{rel}: metrics.propagation_paths mismatch")
    _validate_deterministic_campaign_contract(
        cases=summary.cases,
        controls=summary.control_catalog,
        rows=rows,
        modes=PLANNER_TASK_MODES,
        outcome_field="unsafe_chain_allowed",
        rel=rel,
        result=result,
    )
    expected_effects = _build_control_effects(summary.cases, rows)
    expected_metrics = _build_metrics(
        summary.cases,
        summary.control_catalog,
        rows,
        expected_effects,
    )
    _validate_recomputed_campaign_derivations(
        stored_effects=summary.control_effects,
        expected_effects=expected_effects,
        stored_metrics=summary.metrics,
        expected_metrics=expected_metrics,
        rel=rel,
        result=result,
    )

    unsafe = [row for row in rows if row.attack_attempted]
    benign = [row for row in rows if not row.attack_attempted]
    naive = [row for row in rows if row.mode == "naive"]
    bounded = [row for row in rows if row.mode == "bounded"]
    ablation = [row for row in rows if row.mode not in {"naive", "bounded", "benign"}]
    expected_counts = {
        "unsafe_rows": len(unsafe),
        "benign_rows": len(benign),
        "naive_acceptances": sum(1 for row in naive if row.unsafe_chain_allowed),
        "bounded_acceptances": sum(1 for row in bounded if row.unsafe_chain_allowed),
        "ablation_acceptances": sum(1 for row in ablation if row.unsafe_chain_allowed),
        "benign_acceptances": sum(1 for row in benign if row.unsafe_chain_allowed),
        "bounded_blocks": sum(1 for row in bounded if row.verifier_decision == "block"),
        "benign_false_blocks": sum(1 for row in benign if row.verifier_decision == "block"),
    }
    metrics = summary.metrics.model_dump()
    for key, expected in expected_counts.items():
        if metrics.get(key) != expected:
            result._err(f"{rel}: metrics.{key} mismatch")

    cases_by_id = {case.case_id: case for case in summary.cases}
    for idx, row in enumerate(rows):
        case = cases_by_id.get(row.case_id)
        if case is None:
            result._err(f"{rel}: deterministic_results[{idx}] references unknown case")
            continue
        _validate_optional_sha256(
            row.context_fingerprint,
            f"{rel}: deterministic_results[{idx}].context_fingerprint",
            result,
        )
        expected_fingerprint = _context_fingerprint(case, row.mode)
        if row.context_fingerprint != expected_fingerprint:
            result._err(f"{rel}: deterministic_results[{idx}].context_fingerprint mismatch")
        if row.propagation_steps_observed != len(case.propagation_path):
            result._err(f"{rel}: deterministic_results[{idx}].propagation_steps_observed mismatch")
        if row.mode == "bounded" and row.unsafe_chain_allowed:
            result._expect(f"{rel}: deterministic_results[{idx}] bounded accepted unsafe chain")
        if row.mode == "benign" and not row.benign_passed:
            result._expect(f"{rel}: deterministic_results[{idx}] benign row did not pass")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw/private fields")
    for required in ("planner_task_report.md", "planner_task_digest.json"):
        if not (path / required).exists():
            result._err(f"{_rel(path / required, root)}: missing")
    report_path = path / "planner_task_report.md"
    if report_path.exists():
        _validate_exact_rendered_report(
            report_path,
            render_planner_task_summary(summary),
            root,
            result,
        )
    _validate_planner_task_digest(
        path / "planner_task_digest.json",
        summary,
        root,
        result,
    )
    for private_name in (
        "planner_task_private.json",
        "planner_task_private.md",
    ):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private planner task "
                "artifact must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "planner_task_campaign",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "",
            "model": "",
            "scenario": "planner-task",
            "variants": [],
            "repeats": 1,
            "outcomes": {
                "bounded_acceptances": summary.metrics.bounded_acceptances,
                "ablation_acceptances": summary.metrics.ablation_acceptances,
                "benign_acceptances": summary.metrics.benign_acceptances,
            },
            "metadata": {},
            "artifacts": sorted(
                [
                    "planner_task_summary.json",
                    "planner_task_report.md",
                    "planner_task_digest.json",
                ]
            ),
        },
    )
    for name in (
        "planner_task_summary.json",
        "planner_task_report.md",
        "planner_task_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _validate_memory_rehydration_campaign_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
    rel = _rel(path / "memory_rehydration_summary.json", root)
    raw = _load_json(path / "memory_rehydration_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(
        path / "memory_rehydration_summary.json",
        "memory_rehydration_campaign",
        root,
        result,
    )
    from agentic_security_harness.memory_rehydration_campaign import (
        MEMORY_REHYDRATION_MODES,
        MemoryRehydrationSummary,
        _build_control_effects,
        _build_metrics,
        _context_fingerprint,
        build_memory_rehydration_campaign,
        declared_memory_rehydration_cases,
        declared_memory_rehydration_controls,
        render_memory_rehydration_summary,
    )

    try:
        summary = MemoryRehydrationSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if summary.cases != declared_memory_rehydration_cases():
        result._err(f"{rel}: cases do not match the shipped campaign corpus")
    if summary.control_catalog != declared_memory_rehydration_controls():
        result._err(f"{rel}: controls do not match the shipped campaign corpus")
    _validate_canonical_summary_fields(
        summary=summary,
        canonical=build_memory_rehydration_campaign(created_at=summary.created_at),
        fields=(
            "schema_version",
            "run_kind",
            "evidence_kind",
            "causal_scope",
            "claim_boundary",
            "non_claims",
            "attacker_model",
        ),
        rel=rel,
        result=result,
    )
    rows = summary.deterministic_results
    if summary.metrics.deterministic_rows != len(rows):
        result._err(f"{rel}: metrics.deterministic_rows mismatch")
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases mismatch")
    if summary.metrics.controls != len(summary.control_catalog):
        result._err(f"{rel}: metrics.controls mismatch")
    if summary.metrics.control_effect_rows != len(summary.control_effects):
        result._err(f"{rel}: metrics.control_effect_rows mismatch")
    if summary.metrics.propagation_paths != len(
        {tuple(case.propagation_path) for case in summary.cases}
    ):
        result._err(f"{rel}: metrics.propagation_paths mismatch")
    _validate_deterministic_campaign_contract(
        cases=summary.cases,
        controls=summary.control_catalog,
        rows=rows,
        modes=MEMORY_REHYDRATION_MODES,
        outcome_field="unsafe_chain_allowed",
        rel=rel,
        result=result,
    )
    expected_effects = _build_control_effects(summary.cases, rows)
    expected_metrics = _build_metrics(
        summary.cases,
        summary.control_catalog,
        rows,
        expected_effects,
    )
    _validate_recomputed_campaign_derivations(
        stored_effects=summary.control_effects,
        expected_effects=expected_effects,
        stored_metrics=summary.metrics,
        expected_metrics=expected_metrics,
        rel=rel,
        result=result,
    )

    unsafe = [row for row in rows if row.attack_attempted]
    benign = [row for row in rows if not row.attack_attempted]
    naive = [row for row in rows if row.mode == "naive"]
    bounded = [row for row in rows if row.mode == "bounded"]
    ablation = [row for row in rows if row.mode not in {"naive", "bounded", "benign"}]
    expected_counts = {
        "unsafe_rows": len(unsafe),
        "benign_rows": len(benign),
        "naive_acceptances": sum(1 for row in naive if row.unsafe_chain_allowed),
        "bounded_acceptances": sum(1 for row in bounded if row.unsafe_chain_allowed),
        "ablation_acceptances": sum(1 for row in ablation if row.unsafe_chain_allowed),
        "benign_acceptances": sum(1 for row in benign if row.unsafe_chain_allowed),
        "bounded_blocks": sum(1 for row in bounded if row.verifier_decision == "block"),
        "benign_false_blocks": sum(1 for row in benign if row.verifier_decision == "block"),
    }
    metrics = summary.metrics.model_dump()
    for key, expected in expected_counts.items():
        if metrics.get(key) != expected:
            result._err(f"{rel}: metrics.{key} mismatch")

    cases_by_id = {case.case_id: case for case in summary.cases}
    for idx, row in enumerate(rows):
        case = cases_by_id.get(row.case_id)
        if case is None:
            result._err(f"{rel}: deterministic_results[{idx}] references unknown case")
            continue
        _validate_optional_sha256(
            row.context_fingerprint,
            f"{rel}: deterministic_results[{idx}].context_fingerprint",
            result,
        )
        expected_fingerprint = _context_fingerprint(case, row.mode)
        if row.context_fingerprint != expected_fingerprint:
            result._err(f"{rel}: deterministic_results[{idx}].context_fingerprint mismatch")
        if row.propagation_steps_observed != len(case.propagation_path):
            result._err(f"{rel}: deterministic_results[{idx}].propagation_steps_observed mismatch")
        if row.mode == "bounded" and row.unsafe_chain_allowed:
            result._expect(f"{rel}: deterministic_results[{idx}] bounded accepted unsafe chain")
        if row.mode == "benign" and not row.benign_passed:
            result._expect(f"{rel}: deterministic_results[{idx}] benign row did not pass")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw/private fields")
    for required in ("memory_rehydration_report.md", "memory_rehydration_digest.json"):
        if not (path / required).exists():
            result._err(f"{_rel(path / required, root)}: missing")
    report_path = path / "memory_rehydration_report.md"
    if report_path.exists():
        _validate_exact_rendered_report(
            report_path,
            render_memory_rehydration_summary(summary),
            root,
            result,
        )
    _validate_memory_rehydration_digest(
        path / "memory_rehydration_digest.json",
        summary,
        root,
        result,
    )
    for private_name in (
        "memory_rehydration_private.json",
        "memory_rehydration_private.md",
    ):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private memory rehydration "
                "artifact must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "memory_rehydration_campaign",
            "created_at": summary.created_at,
            "tool_version": "",
            "target": "",
            "model": "",
            "scenario": "memory-rehydration",
            "variants": [],
            "repeats": 1,
            "outcomes": {
                "bounded_acceptances": summary.metrics.bounded_acceptances,
                "ablation_acceptances": summary.metrics.ablation_acceptances,
                "benign_acceptances": summary.metrics.benign_acceptances,
            },
            "metadata": {},
            "artifacts": sorted(
                [
                    "memory_rehydration_summary.json",
                    "memory_rehydration_report.md",
                    "memory_rehydration_digest.json",
                ]
            ),
        },
    )
    for name in (
        "memory_rehydration_summary.json",
        "memory_rehydration_report.md",
        "memory_rehydration_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _validate_optional_sha256(value: str, label: str, result: ValidationResult) -> None:
    if value and not _SHA256_HEX.fullmatch(value):
        result._err(f"{label}: expected lowercase SHA-256 hex digest")


def _validate_required_sha256(value: str, label: str, result: ValidationResult) -> None:
    if not value:
        result._err(f"{label}: missing")
    elif not _SHA256_HEX.fullmatch(value):
        result._err(f"{label}: expected lowercase SHA-256 hex digest")


def _validate_utc_timestamp(
    value: str,
    label: str,
    result: ValidationResult,
) -> None:
    if not value or value != value.strip():
        result._err(f"{label}: missing or untrimmed UTC timestamp")
        return
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        result._err(f"{label}: invalid UTC timestamp")
        return
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        result._err(f"{label}: timestamp must use UTC")


def _validate_deterministic_campaign_contract(
    *,
    cases: list[Any],
    controls: list[Any],
    rows: list[Any],
    modes: tuple[str, ...],
    outcome_field: str,
    rel: str,
    result: ValidationResult,
) -> None:
    """Validate the shared structural contract of deterministic campaign rows."""

    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        result._err(f"{rel}: duplicate case_id values")
    scenario_ids = [case.scenario_id for case in cases]
    if len(scenario_ids) != len(set(scenario_ids)):
        result._err(f"{rel}: duplicate case scenario_id values")
    control_ids = [control.control_id for control in controls]
    if len(control_ids) != len(set(control_ids)):
        result._err(f"{rel}: duplicate control_id values")
    referenced_controls = {control for case in cases for control in case.required_controls}
    if referenced_controls != set(control_ids):
        result._err(f"{rel}: control catalog does not match case requirements")

    expected_keys = {(case.case_id, mode) for case in cases for mode in modes}
    actual_keys = [(row.case_id, row.mode) for row in rows]
    if len(actual_keys) != len(set(actual_keys)):
        result._err(f"{rel}: duplicate deterministic case/mode rows")
    if set(actual_keys) != expected_keys:
        result._err(f"{rel}: deterministic case/mode matrix mismatch")

    cases_by_id = {case.case_id: case for case in cases}
    for idx, row in enumerate(rows):
        label = f"{rel}: deterministic_results[{idx}]"
        case = cases_by_id.get(row.case_id)
        if case is None:
            result._err(f"{label} references unknown case")
            continue
        if row.scenario_id != case.scenario_id:
            result._err(f"{label}.scenario_id does not match referenced case")
        if row.attack_attempted != (row.mode != "benign"):
            result._err(f"{label}.attack_attempted contradicts mode")
        allowed = bool(getattr(row, outcome_field))
        if allowed and row.verifier_decision != "allow":
            result._err(f"{label}.verifier_decision contradicts allowed outcome")
        if not allowed and row.verifier_decision == "allow":
            result._err(f"{label}.verifier_decision contradicts blocked outcome")
        expected_benign_passed = row.mode == "benign" and allowed
        if row.benign_passed != expected_benign_passed:
            result._err(f"{label}.benign_passed contradicts mode/outcome")
        if allowed and row.blocked_by:
            result._err(f"{label}.blocked_by is non-empty for an allowed outcome")
        if not set(row.blocked_by).issubset(set(case.required_controls)):
            result._err(f"{label}.blocked_by contains controls not required by case")
        if not set(row.missing_controls).issubset(set(case.required_controls)):
            result._err(f"{label}.missing_controls contains controls not required by case")


def _validate_recomputed_campaign_derivations(
    *,
    stored_effects: Sequence[BaseModel],
    expected_effects: Sequence[BaseModel],
    stored_metrics: BaseModel,
    expected_metrics: BaseModel,
    rel: str,
    result: ValidationResult,
) -> None:
    """Reject internally inconsistent derived metrics without enforcing golden outcomes."""

    stored_effect_data = [item.model_dump(mode="json") for item in stored_effects]
    expected_effect_data = [item.model_dump(mode="json") for item in expected_effects]
    if stored_effect_data != expected_effect_data:
        result._err(f"{rel}: control_effects do not match deterministic rows")
    if stored_metrics.model_dump(mode="json") != expected_metrics.model_dump(mode="json"):
        result._err(f"{rel}: metrics do not match recomputed deterministic rows")


def _validate_canonical_summary_fields(
    *,
    summary: BaseModel,
    canonical: BaseModel,
    fields: tuple[str, ...],
    rel: str,
    result: ValidationResult,
) -> None:
    """Bind normative claim fields to the shipped executable specification."""

    for field_name in fields:
        if getattr(summary, field_name) != getattr(canonical, field_name):
            result._err(f"{rel}: {field_name} does not match the shipped campaign contract")


def _validate_ground_truth_metrics(
    *,
    rel: str,
    observations: list[Any],
    detector_unsafe: list[bool],
    actual: Any,
    result: ValidationResult,
) -> None:
    """Rebuild independent-label aggregates from observation-level evidence."""

    expected = build_ground_truth_metrics(
        observations,
        detector_unsafe=detector_unsafe,
        adapter_errors=[item.adapter_error for item in observations],
    )
    for field_name, expected_value in expected.model_dump().items():
        if getattr(actual, field_name) != expected_value:
            result._err(f"{rel}: metrics.ground_truth.{field_name} mismatch")


def _validate_exact_summary_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
    *,
    false_fields: tuple[str, ...],
    exact_metrics: bool = True,
    extra_fields: dict[str, object] | None = None,
    raw_summary_metrics: dict[str, object] | None = None,
) -> None:
    """Validate a public digest as an exact projection of its summary."""

    if not digest_path.exists():
        return
    rel = _rel(digest_path, root)
    raw = _load_json(digest_path, root, result)
    if raw is None:
        return
    if not isinstance(raw, dict):
        result._err(f"{rel}: digest must be an object")
        return
    expected_extra = extra_fields or {}
    expected_keys = {
        "schema_version",
        "run_kind",
        "created_at",
        "metrics",
        *false_fields,
        *expected_extra,
    }
    if set(raw) != expected_keys:
        result._err(f"{rel}: digest fields mismatch")
    for key, expected in (
        ("schema_version", summary.schema_version),
        ("run_kind", summary.run_kind),
        ("created_at", summary.created_at),
    ):
        if raw.get(key) != expected:
            result._err(f"{rel}: {key} mismatch")
    for key in false_fields:
        if raw.get(key) is not False:
            result._err(f"{rel}: {key} must be false")
    for key, expected in expected_extra.items():
        if raw.get(key) != expected:
            result._err(f"{rel}: {key} mismatch")
    digest_metrics = raw.get("metrics")
    if not isinstance(digest_metrics, dict):
        result._err(f"{rel}: metrics missing or not an object")
        return
    summary_metrics = (
        raw_summary_metrics
        if raw_summary_metrics is not None
        else summary.metrics.model_dump(mode="json")
    )
    if exact_metrics and set(digest_metrics) != set(summary_metrics):
        result._err(f"{rel}: metrics fields mismatch")
    if not set(digest_metrics).issubset(summary_metrics):
        result._err(f"{rel}: metrics contains unknown fields")
    keys_to_compare = summary_metrics if exact_metrics else digest_metrics
    for key in keys_to_compare:
        if digest_metrics.get(key) != summary_metrics.get(key):
            result._err(f"{rel}: metrics.{key} mismatch")


def _validate_swarm_defense_live_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
    *,
    raw_summary_metrics: dict[str, object] | None = None,
) -> None:
    is_current = summary.schema_version == SCHEMA_VERSIONS["swarm_defense_live_campaign"]
    _validate_exact_summary_digest(
        digest_path,
        summary,
        root,
        result,
        false_fields=(
            "raw_prompts_present",
            "raw_responses_present",
            "canary_values_present",
        ),
        exact_metrics=True,
        extra_fields=(
            {"run_config": summary.run_config.model_dump(mode="json")} if is_current else None
        ),
        raw_summary_metrics=raw_summary_metrics,
    )


def _validate_marketing_web_injection_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
) -> None:
    _validate_exact_summary_digest(
        digest_path,
        summary,
        root,
        result,
        false_fields=(
            "raw_pages_present",
            "raw_prompts_present",
            "raw_responses_present",
            "synthetic_strategy_values_present",
        ),
    )


def _validate_marketing_web_live_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
    *,
    raw_summary_metrics: dict[str, object] | None = None,
) -> None:
    is_current = summary.schema_version == SCHEMA_VERSIONS["marketing_web_live_campaign"]
    _validate_exact_summary_digest(
        digest_path,
        summary,
        root,
        result,
        false_fields=(
            "raw_pages_present",
            "raw_prompts_present",
            "raw_responses_present",
            "synthetic_strategy_values_present",
        ),
        exact_metrics=True,
        extra_fields=(
            {"run_config": summary.run_config.model_dump(mode="json")} if is_current else None
        ),
        raw_summary_metrics=raw_summary_metrics,
    )


def _validate_swarm_resilience_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
) -> None:
    _validate_exact_summary_digest(
        digest_path,
        summary,
        root,
        result,
        false_fields=(
            "synthetic_payload_notes_present",
            "private_calculation_traces_present",
            "raw_prompts_present",
            "raw_responses_present",
        ),
    )


def _validate_context_consent_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
) -> None:
    _validate_exact_summary_digest(
        digest_path,
        summary,
        root,
        result,
        false_fields=(
            "raw_prompts_present",
            "raw_responses_present",
            "approval_tokens_present",
            "private_calculation_notes_present",
        ),
    )


def _validate_tool_authority_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
) -> None:
    from agentic_security_harness.tool_authority_campaign import PRESSURE_AXES

    _validate_exact_summary_digest(
        digest_path,
        summary,
        root,
        result,
        false_fields=(
            "raw_prompts_present",
            "raw_responses_present",
            "real_tool_calls_present",
            "external_api_calls_present",
            "private_calculation_notes_present",
        ),
        extra_fields={"pressure_axes": list(PRESSURE_AXES)},
    )


def _validate_rag_context_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
) -> None:
    from agentic_security_harness.rag_context_campaign import PRESSURE_AXES

    _validate_exact_summary_digest(
        digest_path,
        summary,
        root,
        result,
        false_fields=(
            "raw_prompts_present",
            "raw_responses_present",
            "live_rag_systems_present",
            "external_api_calls_present",
            "private_calculation_notes_present",
        ),
        extra_fields={"pressure_axes": list(PRESSURE_AXES)},
    )


def _validate_planner_task_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
) -> None:
    from agentic_security_harness.planner_task_campaign import PRESSURE_AXES

    _validate_exact_summary_digest(
        digest_path,
        summary,
        root,
        result,
        false_fields=(
            "raw_prompts_present",
            "raw_responses_present",
            "live_planners_present",
            "external_api_calls_present",
            "private_calculation_notes_present",
        ),
        extra_fields={"pressure_axes": list(PRESSURE_AXES)},
    )


def _validate_memory_rehydration_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
) -> None:
    from agentic_security_harness.memory_rehydration_campaign import PRESSURE_AXES

    _validate_exact_summary_digest(
        digest_path,
        summary,
        root,
        result,
        false_fields=(
            "raw_prompts_present",
            "raw_responses_present",
            "live_memory_stores_present",
            "external_api_calls_present",
            "private_calculation_notes_present",
        ),
        extra_fields={"pressure_axes": list(PRESSURE_AXES)},
    )


def _contains_forbidden_raw_fields(value: Any) -> bool:
    forbidden = {
        "raw_prompt",
        "raw_response",
        "raw_page_url",
        "raw_page_text",
        "raw_worker_prompt",
        "raw_worker_prompts",
        "raw_worker_response",
        "raw_worker_responses",
        "raw_chief_prompt",
        "raw_chief_response",
        "synthetic_strategy_value",
        "synthetic_strategy_fingerprint",
        "value",
        "canary",
        "canary_value",
        "canonical_state_hash",
        "raw_transcript",
        "synthetic_canary",
        "synthetic_payload_notes",
        "state_vectors_by_step",
        "calculation_notes",
    }
    if isinstance(value, dict):
        return any(key in forbidden for key in value) or any(
            _contains_forbidden_raw_fields(item) for item in value.values()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_raw_fields(item) for item in value)
    return False


def _contains_forbidden_key(value: Any, key_name: str) -> bool:
    if isinstance(value, dict):
        return key_name in value or any(
            _contains_forbidden_key(item, key_name) for item in value.values()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_key(item, key_name) for item in value)
    return False


def _load_json(path: Path, root: Path, result: ValidationResult) -> Any:
    if not path.exists():
        result._err(f"{_rel(path, root)}: missing")
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result._err(f"{_rel(path, root)}: unreadable ({type(exc).__name__})")
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        result._err(f"{_rel(path, root)}: invalid JSON")
        return None


def _check_schema_version_file(
    path: Path,
    kind: str,
    root: Path,
    result: ValidationResult,
    *,
    required: bool = True,
    is_list: bool = False,
) -> None:
    """Check the ``schema_version`` of an artifact file against the registry.

    Absent files and JSON parse errors are left to the artifact's own loader. A future or
    unknown version produces a clear, actionable error.
    """
    if not path.exists():
        return
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    items = raw if (is_list and isinstance(raw, list)) else [raw]
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        msg = check_schema_version(kind, item.get("schema_version"), required=required)
        if msg:
            where = f"[{i}]" if is_list else ""
            result._err(f"{_rel(path, root)}{where}: {msg}")


def _fmt_error(exc: ValidationError) -> str:
    errs = exc.errors()
    if not errs:
        return "invalid"
    first = errs[0]
    loc = ".".join(str(part) for part in first.get("loc", ()))
    msg = str(first.get("msg", "invalid"))
    return f"{loc}: {msg}" if loc else msg


def _load_traces(path: Path, root: Path, result: ValidationResult) -> list[ExploitTrace] | None:
    raw = _load_json(path, root, result)
    if raw is None:
        return None
    if not isinstance(raw, list):
        result._err(f"{_rel(path, root)}: expected a JSON list at the root")
        return None
    traces: list[ExploitTrace] = []
    ok = True
    for i, item in enumerate(raw):
        try:
            traces.append(ExploitTrace.model_validate(item))
        except ValidationError as exc:
            result._err(f"{_rel(path, root)}[{i}]: schema: {_fmt_error(exc)}")
            ok = False
    return traces if ok else None


def _load_scorecard(path: Path, root: Path, result: ValidationResult) -> ScorecardSummary | None:
    raw = _load_json(path, root, result)
    if raw is None:
        return None
    try:
        return ScorecardSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{_rel(path, root)}: schema: {_fmt_error(exc)}")
        return None


def _validate_traces(
    traces: list[ExploitTrace],
    path: Path,
    root: Path,
    result: ValidationResult,
    expected_pattern_ids: set[str] | None = None,
    is_matrix: bool = False,
) -> None:
    corpus = {entry.pattern_id: entry for entry in corpus_manifest()}
    canonical = {pattern.pattern_id: pattern for pattern in seed_patterns()}
    rel = _rel(path, root)
    target_names = sorted({trace.target.name for trace in traces})
    if len(target_names) > 1:
        result._err(f"{rel}: traces mix multiple target names: {target_names}")
    # A report dir must describe ONE target. Enforcing a single target.type closes the
    # false-negative where one relabeled trace exempts itself from the PASS/FAIL invariant
    # (a baseline trace flipped to a protected type, or vice versa).
    target_types = sorted({trace.target.type for trace in traces})
    if len(target_types) > 1:
        result._err(f"{rel}: traces mix multiple target types: {target_types}")
    seen: dict[str, int] = {}
    pattern_counts: dict[str, int] = {}
    for i, trace in enumerate(traces):
        prefix = f"{rel}[{i}] {trace.pattern_id}"
        pattern_counts[trace.pattern_id] = pattern_counts.get(trace.pattern_id, 0) + 1
        msg = check_schema_version("trace", trace.schema_version)
        if msg:
            result._err(f"{prefix}: {msg}")
        indices = [step.index for step in trace.steps]
        if indices != list(range(len(indices))):
            result._err(f"{prefix}: step indices not sequential from 0: {indices}")
        if trace.trace_id in seen:
            result._err(
                f"{rel}: duplicate trace_id '{trace.trace_id}' (items {seen[trace.trace_id]}, {i})"
            )
        else:
            seen[trace.trace_id] = i
        entry = corpus.get(trace.pattern_id)
        if entry is None:
            result._err(f"{prefix}: pattern_id not in corpus")
            continue
        pattern = canonical.get(trace.pattern_id)
        if pattern is None:
            result._err(f"{prefix}: pattern_id not in seed patterns")
            continue
        if trace.graph_path != pattern.graph_path:
            result._err(f"{prefix}: graph_path does not match the seed pattern")
        if trace.expected_vulnerable_behavior != pattern.expected_vulnerable_behavior:
            result._err(f"{prefix}: expected_vulnerable_behavior does not match the seed pattern")
        if trace.data_envelope != pattern.data_envelope:
            result._err(f"{prefix}: data_envelope does not match the seed pattern")
        protected = _is_protected(trace.target)
        baseline = trace.target.type in _BASELINE_TYPES
        if trace.findings:
            if protected:
                result._expect(f"{prefix}: protected target should PASS but has findings")
            top = max(trace.findings, key=lambda f: _SEVERITY_RANK.get(f.severity, -1))
            if top.code != pattern.category:
                result._err(
                    f"{prefix}: finding code '{top.code}' != pattern category '{pattern.category}'"
                )
            if top.severity != entry.severity:
                result._err(
                    f"{prefix}: finding severity '{top.severity}' != corpus '{entry.severity}'"
                )
            if top.broke_at != entry.broke_at:
                result._err(
                    f"{prefix}: finding broke_at '{top.broke_at}' != corpus '{entry.broke_at}'"
                )
        elif baseline:
            # Only the vulnerable-by-design demo baselines must fail every pattern;
            # a neutral adapter is allowed to legitimately PASS.
            result._expect(f"{prefix}: no findings but baseline target expects FAIL")
    # For matrix runs, validate against the selected patterns instead of the full corpus
    expected_ids = expected_pattern_ids if expected_pattern_ids is not None else set(corpus)
    actual_ids = set(pattern_counts)
    missing = sorted(expected_ids - actual_ids)
    extra = sorted(actual_ids - expected_ids)
    # Matrix runs intentionally have duplicate pattern_ids (one per variant)
    if not is_matrix:
        duplicates = sorted(pid for pid, count in pattern_counts.items() if count > 1)
    else:
        duplicates = []
    if missing:
        result._err(f"{rel}: missing corpus pattern(s): {missing}")
    if extra:
        result._err(f"{rel}: extra non-corpus pattern(s): {extra}")
    if duplicates:
        result._err(f"{rel}: duplicate pattern_id(s): {duplicates}")


def _validate_scorecard(
    committed: ScorecardSummary,
    expected: ScorecardSummary,
    traces: list[ExploitTrace],
    path: Path,
    root: Path,
    result: ValidationResult,
) -> None:
    rel = _rel(path, root)
    if committed.total_traces != len(traces):
        result._err(
            f"{rel}: total_traces {committed.total_traces} != number of traces {len(traces)}"
        )
    if committed.target_name != expected.target_name:
        result._err(f"{rel}: target_name '{committed.target_name}' != '{expected.target_name}'")
    if committed.findings_by_severity != expected.findings_by_severity:
        result._err(f"{rel}: findings_by_severity does not match the traces' findings")
    if committed.findings_by_category != expected.findings_by_category:
        result._err(f"{rel}: findings_by_category does not match the traces' findings")
    if committed.failed_patterns != expected.failed_patterns:
        result._err(f"{rel}: failed_patterns do not match the traces' findings")
    if committed.passed_patterns != expected.passed_patterns:
        result._err(f"{rel}: passed_patterns do not match the traces' findings")
    corpus_ids = {entry.pattern_id for entry in corpus_manifest()}
    for pid in committed.failed_patterns + committed.passed_patterns:
        if pid not in corpus_ids:
            result._err(f"{rel}: pattern_id '{pid}' not in corpus")


def _validate_summary(
    path: Path,
    traces: list[ExploitTrace],
    expected_card: ScorecardSummary,
    root: Path,
    result: ValidationResult,
) -> None:
    rel = _rel(path, root)
    if not path.exists():
        result._err(f"{rel}: missing")
        return
    try:
        actual = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        result._err(f"{rel}: unreadable")
        return
    expected = build_summary_md(expected_card, traces)
    if actual.replace("\r\n", "\n") != expected.replace("\r\n", "\n"):
        result._err(f"{rel}: does not match the summary rebuilt from scorecard + traces")


def _validate_executive(
    path: Path,
    traces: list[ExploitTrace],
    expected_card: ScorecardSummary,
    root: Path,
    result: ValidationResult,
) -> None:
    rel = _rel(path, root)
    if not path.exists():
        result._err(f"{rel}: missing")
        return
    try:
        actual = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        result._err(f"{rel}: unreadable")
        return
    expected = build_executive_md(expected_card, traces)
    if actual.replace("\r\n", "\n") != expected.replace("\r\n", "\n"):
        result._err(f"{rel}: does not match the executive report rebuilt from scorecard + traces")


def _validate_remediation(
    path: Path,
    traces: list[ExploitTrace],
    expected_card: ScorecardSummary,
    root: Path,
    result: ValidationResult,
) -> None:
    """Validate remediation.json and remediation.md if present."""
    from agentic_security_harness.remediation import (
        build_recommendations,
        build_remediation_md,
    )

    rem_json = path / "remediation.json"
    rem_md = path / "remediation.md"
    expected = build_recommendations(traces, expected_card)

    if not expected.recommendations:
        # Validation is observational: stale artifacts are findings, never cleanup work.
        for artifact in (rem_json, rem_md):
            if artifact.exists():
                result._err(
                    f"{_rel(artifact, root)}: unexpected because rebuilt traces + "
                    "scorecard contain no findings"
                )
        return

    # Validate remediation.json
    if rem_json.exists():
        try:
            raw = json.loads(rem_json.read_text(encoding="utf-8"))
            from agentic_security_harness.remediation import RemediationReport

            committed = RemediationReport.model_validate(raw)
            if committed.model_dump(mode="json") != expected.model_dump(mode="json"):
                result._err(
                    f"{_rel(rem_json, root)}: does not match remediation rebuilt "
                    "from traces + scorecard"
                )
        except (json.JSONDecodeError, ValidationError) as exc:
            result._err(f"{_rel(rem_json, root)}: invalid ({type(exc).__name__})")
    else:
        result._err(f"{_rel(rem_json, root)}: missing (expected when findings exist)")

    # Validate remediation.md
    if rem_md.exists():
        try:
            actual = rem_md.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            result._err(f"{_rel(rem_md, root)}: unreadable")
        else:
            expected_md = build_remediation_md(expected)
            if actual.replace("\r\n", "\n") != expected_md.replace("\r\n", "\n"):
                result._err(
                    f"{_rel(rem_md, root)}: does not match remediation markdown "
                    "rebuilt from traces + scorecard"
                )
    else:
        result._err(f"{_rel(rem_md, root)}: missing (expected when findings exist)")


def _validate_report_dir(
    path: Path, root: Path, result: ValidationResult
) -> ScorecardSummary | None:
    # Check for matrix.json first to determine expected pattern subset
    matrix_json = path / "matrix.json"
    expected_pattern_ids: set[str] | None = None
    if matrix_json.exists():
        matrix_raw = _load_json(matrix_json, root, result)
        if matrix_raw is not None:
            try:
                from agentic_security_harness.matrix import MatrixReport

                preliminary_matrix = MatrixReport.model_validate(matrix_raw)
                expected_pattern_ids = set(preliminary_matrix.selected_pattern_ids)
            except ValidationError:
                pass

    traces = _load_traces(path / "traces.json", root, result)
    committed_card = _load_scorecard(path / "scorecard.json", root, result)
    expected_card: ScorecardSummary | None = None
    is_matrix = expected_pattern_ids is not None
    if traces is not None:
        _validate_traces(
            traces,
            path / "traces.json",
            root,
            result,
            expected_pattern_ids=expected_pattern_ids,
            is_matrix=is_matrix,
        )
        expected_card = build_scorecard(traces)
    if traces is not None and committed_card is not None and expected_card is not None:
        _validate_scorecard(
            committed_card, expected_card, traces, path / "scorecard.json", root, result
        )
        _validate_summary(path / "summary.md", traces, expected_card, root, result)
        _validate_executive(path / "executive.md", traces, expected_card, root, result)
        _validate_remediation(path, traces, expected_card, root, result)
    # Validate matrix.json if present
    matrix_report: Any | None = None
    if matrix_json.exists():
        matrix_report = _validate_matrix_json(matrix_json, traces, root, result)
    for name in ("traces.json", "scorecard.json", "summary.md", "executive.md"):
        _scan_secrets(path / name, root, result)
    # Scan remediation artifacts if present
    for name in ("remediation.json", "remediation.md"):
        if (path / name).exists():
            _scan_secrets(path / name, root, result)
    # Scan matrix artifacts if present
    for name in ("matrix.json", "matrix.md"):
        if (path / name).exists():
            _scan_secrets(path / name, root, result)
    # Schema-version checks (registry-aware: rejects unknown/future, catches missing).
    _check_schema_version_file(path / "traces.json", "trace", root, result, is_list=True)
    _check_schema_version_file(path / "scorecard.json", "scorecard", root, result)
    _check_schema_version_file(path / "remediation.json", "remediation", root, result)
    if matrix_json.exists():
        _check_schema_version_file(matrix_json, "matrix", root, result)
    if expected_card is not None:
        if matrix_report is None:
            _validate_core_run_manifest(path, root, expected_card, result)
        else:
            _validate_matrix_manifest(path, root, matrix_report, expected_card, result)
    _validate_run_manifest(path, root, result)
    return expected_card


def _validate_comparison_dir(path: Path, root: Path, result: ValidationResult) -> None:
    baseline = path / "baseline"
    protected = path / "protected"
    comparison_md = path / "comparison.md"
    for name, sub in (
        ("baseline/", baseline),
        ("protected/", protected),
        ("comparison.md", comparison_md),
    ):
        if not sub.exists():
            result._err(f"{_rel(path, root)}: missing {name}")
    base_card: ScorecardSummary | None = None
    prot_card: ScorecardSummary | None = None
    if baseline.is_dir():
        result.report_dirs.append(_rel(baseline, root))
        base_card = _validate_report_dir(baseline, root, result)
    if protected.is_dir():
        result.report_dirs.append(_rel(protected, root))
        prot_card = _validate_report_dir(protected, root, result)
    if comparison_md.exists() and base_card is not None and prot_card is not None:
        _validate_comparison_md(comparison_md, root, base_card, prot_card, result)
        _validate_comparison_manifest(path, root, base_card, prot_card, result)
    elif comparison_md.exists():
        _scan_secrets(comparison_md, root, result)
    _validate_run_manifest(path, root, result)


def _required_report_artifacts(prefix: str, card: ScorecardSummary) -> set[str]:
    """Return authoritative report files that a current manifest must bind."""

    required = {
        f"{prefix}traces.json",
        f"{prefix}scorecard.json",
        f"{prefix}summary.md",
        f"{prefix}executive.md",
    }
    if card.failed_patterns:
        required.update({f"{prefix}remediation.json", f"{prefix}remediation.md"})
    return required


def _validate_required_manifest_artifacts(
    path: Path,
    root: Path,
    required: set[str],
    result: ValidationResult,
    *,
    optional: set[str] | None = None,
) -> None:
    """Require a typed manifest inventory plus explicitly allowed companions."""

    from agentic_security_harness.run_manifest import RunManifest

    manifest_path = path / "run_index.json"
    if not manifest_path.is_file():
        return
    raw = _load_json(manifest_path, root, result)
    if raw is None:
        return
    try:
        manifest = RunManifest.model_validate(raw)
    except ValidationError:
        return
    if manifest.schema_version != SCHEMA_VERSIONS["run_manifest"]:
        return
    missing = sorted(required - set(manifest.artifacts))
    if missing:
        result._err(
            f"{_rel(manifest_path, root)}: authoritative artifacts are not content-bound: {missing}"
        )
    allowed_optional = optional or set()
    unexpected = sorted(set(manifest.artifacts) - required - allowed_optional)
    if unexpected:
        result._err(
            f"{_rel(manifest_path, root)}: unexpected artifacts for this bundle type: {unexpected}"
        )
    for artifact in sorted(set(manifest.artifacts) & allowed_optional):
        _scan_secrets(path / artifact, root, result)


def _validate_core_run_manifest(
    path: Path,
    root: Path,
    card: ScorecardSummary,
    result: ValidationResult,
) -> None:
    """Bind a current core-run manifest to its rebuilt scorecard semantics."""

    required = _required_report_artifacts("", card)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "run",
            "target": card.target_name,
            "model": "",
            "scenario": "seed-corpus",
            "variants": [],
            "repeats": 1,
            "outcomes": {
                "failed": len(card.failed_patterns),
                "passed": len(card.passed_patterns),
            },
            "metadata": {},
        },
    )
    _validate_required_manifest_artifacts(
        path,
        root,
        required,
        result,
        optional={"README.md"},
    )


def _validate_matrix_manifest(
    path: Path,
    root: Path,
    report: Any,
    card: ScorecardSummary,
    result: ValidationResult,
) -> None:
    """Bind a current matrix manifest to the fully rebuilt matrix projection."""

    required = _required_report_artifacts("", card)
    required.update({"matrix.json", "matrix.md"})
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "matrix",
            "target": report.target_name,
            "model": "",
            "scenario": report.scenario_id,
            "variants": [variant.variant_id for variant in report.variants],
            "repeats": 1,
            "outcomes": {
                "failed_variants": report.summary.failed_variants,
                "passed_variants": report.summary.passed_variants,
                "total_traces": report.summary.total_traces,
            },
            "metadata": {},
        },
    )
    _validate_required_manifest_artifacts(
        path,
        root,
        required,
        result,
        optional={"README.md"},
    )


def _validate_comparison_manifest(
    path: Path,
    root: Path,
    baseline: ScorecardSummary,
    protected: ScorecardSummary,
    result: ValidationResult,
) -> None:
    """Bind a current comparison manifest to both rebuilt report branches."""

    required = {"comparison.md"}
    required.update(_required_report_artifacts("baseline/", baseline))
    required.update(_required_report_artifacts("protected/", protected))
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "compare",
            "target": f"{baseline.target_name} vs {protected.target_name}",
            "model": "",
            "scenario": "seed-corpus",
            "variants": [],
            "repeats": 1,
            "outcomes": {
                "baseline_failed": len(baseline.failed_patterns),
                "protected_failed": len(protected.failed_patterns),
            },
            "metadata": {},
        },
    )
    _validate_required_manifest_artifacts(
        path,
        root,
        required,
        result,
        optional={"README.md"},
    )


def _validate_external_dir(path: Path, root: Path, result: ValidationResult) -> None:
    from agentic_security_harness.run_config import ExternalResult, ExternalSummary, RunConfig

    config_raw = _load_json(path / "run_config.json", root, result)
    results_raw = _load_json(path / "external_results.json", root, result)
    summary_raw = _load_json(path / "external_summary.json", root, result)
    report_md = path / "external_report.md"
    if not report_md.exists():
        result._err(f"{_rel(report_md, root)}: missing")
    else:
        _validate_external_report_md(report_md, root, result)

    config: RunConfig | None = None
    summary: ExternalSummary | None = None
    results: list[ExternalResult] | None = None

    if config_raw is not None:
        try:
            config = RunConfig.model_validate(config_raw)
        except ValidationError as exc:
            result._err(f"{_rel(path / 'run_config.json', root)}: schema: {_fmt_error(exc)}")
    if summary_raw is not None:
        try:
            summary = ExternalSummary.model_validate(summary_raw)
        except ValidationError as exc:
            result._err(f"{_rel(path / 'external_summary.json', root)}: schema: {_fmt_error(exc)}")
    if results_raw is not None:
        if not isinstance(results_raw, list):
            result._err(f"{_rel(path / 'external_results.json', root)}: expected list")
        else:
            parsed: list[ExternalResult] = []
            ok = True
            for i, item in enumerate(results_raw):
                try:
                    parsed.append(ExternalResult.model_validate(item))
                except ValidationError as exc:
                    result._err(
                        f"{_rel(path / 'external_results.json', root)}[{i}]: "
                        f"schema: {_fmt_error(exc)}"
                    )
                    ok = False
            results = parsed if ok else None

    if config is not None:
        if config.corpus_version != CORPUS_VERSION:
            result._err(
                f"{_rel(path / 'run_config.json', root)}: corpus_version "
                f"'{config.corpus_version}' != supported '{CORPUS_VERSION}'"
            )
        if config.adapter_type != "openai-compatible":
            result._err(
                f"{_rel(path / 'run_config.json', root)}: unsupported adapter_type "
                f"'{config.adapter_type}'"
            )
        if config.credential_env_var and any(
            token in config.credential_env_var.lower() for token in ("sk-", "key=")
        ):
            result._err(
                f"{_rel(path / 'run_config.json', root)}: "
                "credential_env_var looks like a credential value"
            )
        # request_count is the pre-run estimate; once results exist it must match
        # the number of normalized results actually written.
        if results is not None and config.request_count != len(results):
            result._err(
                f"{_rel(path / 'run_config.json', root)}: request_count "
                f"{config.request_count} != external_results count {len(results)}"
            )
        if isinstance(config_raw, dict) and "runtime" in config_raw:
            runtime = config.runtime
            if runtime.model_id and runtime.model_id != config.model:
                result._err(
                    f"{_rel(path / 'run_config.json', root)}: runtime.model_id does not match model"
                )
            if runtime.network_mode != config.network_mode:
                result._err(
                    f"{_rel(path / 'run_config.json', root)}: "
                    "runtime.network_mode does not match network_mode"
                )
            if not runtime.prompt_only:
                result._err(
                    f"{_rel(path / 'run_config.json', root)}: "
                    "runtime.prompt_only must be true for run-external"
                )
            if runtime.tool_execution:
                result._err(
                    f"{_rel(path / 'run_config.json', root)}: "
                    "runtime.tool_execution must be false for run-external"
                )
            if runtime.local_only and runtime.network_mode != "local-only":
                result._err(
                    f"{_rel(path / 'run_config.json', root)}: "
                    "local runtime must use network_mode=local-only"
                )
            if not runtime.model_license_note.strip():
                result._err(
                    f"{_rel(path / 'run_config.json', root)}: runtime.model_license_note is empty"
                )
            if not runtime.recovery_guidance:
                result._err(
                    f"{_rel(path / 'run_config.json', root)}: runtime.recovery_guidance is empty"
                )
    if results is not None:
        _validate_external_results(path, root, results, result)
    if config is not None and summary is not None:
        if summary.corpus_version != CORPUS_VERSION:
            result._err(
                f"{_rel(path / 'external_summary.json', root)}: corpus_version "
                f"'{summary.corpus_version}' != supported '{CORPUS_VERSION}'"
            )
        if summary.adapter_type != config.adapter_type:
            result._err(
                f"{_rel(path / 'external_summary.json', root)}: adapter_type "
                "does not match run_config"
            )
        if summary.model != config.model:
            result._err(
                f"{_rel(path / 'external_summary.json', root)}: model does not match run_config"
            )
        if summary.scenario_id != config.scenario_id:
            result._err(
                f"{_rel(path / 'external_summary.json', root)}: scenario_id "
                "does not match run_config"
            )
    if results is not None and summary is not None:
        _validate_external_summary(path, root, results, summary, result)
    if config is not None and summary is not None and results is not None:
        _validate_current_external_bundle(path, root, config, results, summary, result)

    for name in (
        "run_config.json",
        "external_results.json",
        "external_summary.json",
        "external_report.md",
    ):
        _scan_secrets(path / name, root, result)
    _check_schema_version_file(path / "run_config.json", "run_config", root, result)
    _check_schema_version_file(path / "external_summary.json", "external_summary", root, result)
    _validate_run_manifest(path, root, result)


def _validate_current_external_bundle(
    path: Path,
    root: Path,
    config: "RunConfig",
    results: list["ExternalResult"],
    summary: "ExternalSummary",
    result: ValidationResult,
) -> None:
    """Require one pre-request identity and exact manifest for current external runs."""

    current_config = config.schema_version == SCHEMA_VERSIONS["run_config"]
    current_summary = summary.schema_version == SCHEMA_VERSIONS["external_summary"]
    if not current_config and not current_summary:
        return
    if current_config != current_summary:
        result._err(
            f"{_rel(path, root)}: run_config and external_summary schema generations differ"
        )
        return

    rel_config = _rel(path / "run_config.json", root)
    rel_summary = _rel(path / "external_summary.json", root)
    if not config.execution_id or not _EXECUTION_ID.fullmatch(config.execution_id):
        result._err(f"{rel_config}: execution_id is missing or invalid")
    if summary.execution_id != config.execution_id:
        result._err(f"{rel_summary}: execution_id does not match run_config")
    if config.runtime.execution_id != config.execution_id:
        result._err(f"{rel_config}: runtime.execution_id does not match run_config")
    if config.runtime.run_id != config.execution_id:
        result._err(f"{rel_config}: runtime.run_id does not match run_config")
    if not config.created_at or summary.created_at != config.created_at:
        result._err(f"{rel_summary}: created_at does not match run_config")
    if not config.tool_version:
        result._err(f"{rel_config}: tool_version is empty")
    for index, item in enumerate(results):
        if item.execution_id != config.execution_id:
            result._err(
                f"{_rel(path / 'external_results.json', root)}[{index}]: "
                "execution_id does not match run_config"
            )

    from agentic_security_harness.external_runner import _build_external_report_md
    from agentic_security_harness.run_manifest import RunManifest

    _validate_exact_rendered_report(
        path / "external_report.md",
        _build_external_report_md(summary, config),
        root,
        result,
    )

    manifest_path = path / "run_index.json"
    manifest_rel = _rel(manifest_path, root)
    if not manifest_path.is_file():
        result._err(f"{manifest_rel}: missing for current external bundle")
        return
    manifest_raw = _load_json(manifest_path, root, result)
    if manifest_raw is None:
        return
    try:
        manifest = RunManifest.model_validate(manifest_raw)
    except ValidationError:
        return

    runtime = config.runtime
    expected_artifacts = sorted(
        candidate.relative_to(path).as_posix()
        for candidate in path.rglob("*")
        if candidate.is_file() and candidate.name != "run_index.json"
    )
    expected = {
        "run_kind": "external",
        "run_id": config.execution_id,
        "execution_id": config.execution_id,
        "created_at": config.created_at,
        "tool_version": config.tool_version,
        "target": "",
        "model": config.model,
        "scenario": config.scenario_id,
        "variants": config.selected_variants,
        "repeats": config.repeats,
        "outcomes": {
            "checks": summary.total_checks,
            "requests": summary.total_repeats,
            "findings": len(summary.patterns_with_findings),
            "flaky": len(summary.flaky_patterns),
            "inconclusive": len(summary.inconclusive_patterns),
            "errors": len(summary.error_patterns),
        },
        "metadata": {
            "adapter_type": config.adapter_type,
            "model": config.model,
            "base_url_label": config.base_url_label,
            "scenario": config.scenario_id,
            "max_variants": config.max_variants,
            "repeats": config.repeats,
            "temperature": config.temperature,
            "timeout_seconds": config.timeout_seconds,
            "max_retries": config.max_retries,
            "raw_response_limit": config.raw_response_limit,
            "request_count": summary.total_repeats,
            "runtime_name": runtime.runtime_name,
            "runtime_family": runtime.runtime_family,
            "network_mode": runtime.network_mode,
            "authorization_mode": runtime.authorization_mode,
            "local_only": runtime.local_only,
            "prompt_only": runtime.prompt_only,
            "tool_execution": runtime.tool_execution,
            "credential_env_var": config.credential_env_var,
        },
        "artifacts": expected_artifacts,
    }
    actual = manifest.model_dump(mode="json")
    for field_name, expected_value in expected.items():
        if actual.get(field_name) != expected_value:
            result._err(f"{manifest_rel}: {field_name} does not match current external bundle")


def _validate_external_report_md(path: Path, root: Path, result: ValidationResult) -> None:
    """Light structural check: the human report has its core sections and points
    back to the machine artifacts. Not a byte-for-byte rebuild (the report can
    carry model-dependent prose)."""
    rel = _rel(path, root)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        result._err(f"{rel}: unreadable")
        return
    required = [
        "## Configuration",
        "## Results",
        "## Control recommendations",
        "## Related artifacts",
        "## How to reproduce / validate",
    ]
    for section in required:
        if section not in text:
            result._err(f"{rel}: missing section '{section}'")
    if "run_config.json" not in text or "external_summary.json" not in text:
        result._err(f"{rel}: does not reference run_config.json / external_summary.json")


def _validate_external_results(
    path: Path, root: Path, results: list["ExternalResult"], result: ValidationResult
) -> None:
    rel = _rel(path / "external_results.json", root)
    corpus_ids = {entry.pattern_id for entry in corpus_manifest()}
    seen: set[str] = set()
    for i, item in enumerate(results):
        prefix = f"{rel}[{i}] {item.pattern_id}"
        if item.result_id in seen:
            result._err(f"{rel}: duplicate result_id '{item.result_id}'")
        seen.add(item.result_id)
        if item.pattern_id not in corpus_ids:
            result._err(f"{prefix}: pattern_id not in corpus")
        if item.deterministic_cross_check not in {
            "pass",
            "finding",
            "inconclusive",
            "adapter_error",
        }:
            result._err(
                f"{prefix}: invalid deterministic_cross_check '{item.deterministic_cross_check}'"
            )
        if item.error and (
            item.decision != "unclear"
            or item.reason
            or item.control_family
            or item.would_preserve_boundary is not None
        ):
            result._err(f"{prefix}: error result should not also carry a decision")
        if item.error and item.deterministic_cross_check != "adapter_error":
            result._err(f"{prefix}: error result must use adapter_error cross-check")
        if not item.error and item.raw_response_path:
            if not item.assertion_id:
                result._err(f"{prefix}: missing assertion_id")
            if not item.assertion_result:
                result._err(f"{prefix}: missing assertion_result")
        if item.raw_response_path:
            raw_path = path / item.raw_response_path
            if not raw_path.exists() or not raw_path.is_file():
                result._err(f"{prefix}: raw_response_path missing: {item.raw_response_path}")
            else:
                try:
                    raw_text = raw_path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    result._err(f"{prefix}: raw_response_path unreadable")
                else:
                    digest = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
                    if item.raw_response_sha256 and digest != item.raw_response_sha256:
                        result._err(f"{prefix}: raw_response_sha256 does not match file")
                    if item.raw_response_chars and item.raw_response_chars != len(raw_text):
                        result._err(f"{prefix}: raw_response_chars does not match file")
                    _scan_secrets(raw_path, root, result)


def _validate_external_summary(
    path: Path,
    root: Path,
    results: list["ExternalResult"],
    summary: "ExternalSummary",
    result: ValidationResult,
) -> None:
    from collections import defaultdict

    from agentic_security_harness.remediation import _FAMILY_MAP

    rel = _rel(path / "external_summary.json", root)
    total_checks = len({(r.pattern_id, r.variant_id) for r in results})
    if summary.total_repeats != len(results):
        result._err(
            f"{rel}: total_repeats {summary.total_repeats} != external_results count {len(results)}"
        )
    if summary.total_checks != total_checks:
        result._err(
            f"{rel}: total_checks {summary.total_checks} != "
            f"unique pattern/variant checks {total_checks}"
        )

    # Recompute per-pattern aggregates from results to catch tampered/stale summaries.
    finding_results = [
        r for r in results if not r.error and r.deterministic_cross_check == "finding"
    ]
    findings_by_pattern: dict[str, int] = defaultdict(int)
    for r in finding_results:
        findings_by_pattern[r.pattern_id] += 1

    patterns_with_findings = sorted(set(findings_by_pattern))
    if summary.patterns_with_findings != patterns_with_findings:
        result._err(f"{rel}: patterns_with_findings does not match external_results")

    if dict(summary.findings_by_pattern) != dict(findings_by_pattern):
        result._err(f"{rel}: findings_by_pattern does not match external_results")

    findings_by_control_family: dict[str, int] = defaultdict(int)
    for pid, count in findings_by_pattern.items():
        family = _FAMILY_MAP.get(pid, "provenance")
        findings_by_control_family[family] += count
    if dict(summary.findings_by_control_family) != dict(findings_by_control_family):
        result._err(f"{rel}: findings_by_control_family does not match external_results")

    error_patterns = sorted({r.pattern_id for r in results if r.error})
    if summary.error_patterns != error_patterns:
        result._err(f"{rel}: error_patterns does not match external_results")

    # inconclusive_patterns: had an inconclusive result and no finding for that pattern.
    inconclusive_pids = {
        r.pattern_id
        for r in results
        if not r.error and r.deterministic_cross_check == "inconclusive"
    }
    expected_inconclusive = sorted(
        pid for pid in inconclusive_pids if pid not in findings_by_pattern
    )
    if summary.inconclusive_patterns != expected_inconclusive:
        result._err(f"{rel}: inconclusive_patterns does not match external_results")

    # flaky_patterns: a (pattern, variant) group with >1 non-error outcome.
    groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for r in results:
        if r.error:
            outcome = "error"
        elif r.deterministic_cross_check == "pass":
            outcome = "pass"
        elif r.deterministic_cross_check == "finding":
            outcome = "finding"
        else:
            outcome = "inconclusive"
        groups[(r.pattern_id, r.variant_id)].add(outcome)
    flaky_pids = sorted({pid for (pid, _vid), outs in groups.items() if len(outs - {"error"}) > 1})
    if summary.flaky_patterns != flaky_pids:
        result._err(f"{rel}: flaky_patterns does not match external_results")


def _validate_comparison_md(
    path: Path,
    root: Path,
    base_card: ScorecardSummary,
    prot_card: ScorecardSummary,
    result: ValidationResult,
) -> None:
    rel = _rel(path, root)
    try:
        actual = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        result._err(f"{rel}: unreadable")
        return
    expected = build_comparison_md(base_card, prot_card)
    if actual.replace("\r\n", "\n") != expected.replace("\r\n", "\n"):
        result._err(f"{rel}: does not match the comparison rebuilt from the scorecards")
    b_total = sum(base_card.findings_by_severity.values())
    p_total = sum(prot_card.findings_by_severity.values())
    # The delta is signed (negative = reduction); tolerate either sign so a worse-than-
    # baseline comparison (more findings) is validated, not rejected as malformed.
    match = re.search(r"Findings reduced:\s*(\d+)\s*->\s*(\d+)\s*\(([+-]?\d+)\)", actual)
    if match is None:
        result._err(f"{rel}: missing 'Findings reduced: X -> Y (Z)' line")
    else:
        nums = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        if nums != (b_total, p_total, p_total - b_total):
            result._err(
                f"{rel}: reduction mismatch: file says {nums[0]} -> {nums[1]} ({nums[2]:+d}); "
                f"scorecards imply {b_total} -> {p_total} ({p_total - b_total:+d})"
            )
    _scan_secrets(path, root, result)


def _validate_run_diff_dir(path: Path, root: Path, result: ValidationResult) -> None:
    """Validate a run-diff directory (run_diff.json + run_diff.md)."""
    from agentic_security_harness.run_diff import CHANGE_CLASSES, RunDiff, _diff_md

    diff_json = path / "run_diff.json"
    _check_schema_version_file(diff_json, "run_diff", root, result)
    raw = _load_json(diff_json, root, result)
    if raw is None:
        return
    try:
        diff = RunDiff.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{_rel(diff_json, root)}: schema: {_fmt_error(exc)}")
        return
    rel = _rel(diff_json, root)
    if diff.kind not in {"run", "matrix", "external"}:
        result._err(f"{rel}: unknown diff kind '{diff.kind}'")
    schema_version = str(raw.get("schema_version") or "")
    legacy_changes = {"fixed", "new", "changed", "unchanged", "only_left", "only_right"}
    valid_changes = legacy_changes if schema_version == "0.1" else set(CHANGE_CLASSES)
    counts = {c: 0 for c in valid_changes}
    for entry in diff.entries:
        if entry.change not in valid_changes:
            result._err(f"{rel}: entry '{entry.pattern_id}' has bad change '{entry.change}'")
        else:
            counts[entry.change] += 1
        if not entry.pattern_id:
            result._err(f"{rel}: entry with empty pattern_id")
    if schema_version == "0.1":
        declared = {
            "fixed": diff.fixed,
            "new": diff.new,
            "changed": diff.changed,
            "unchanged": diff.unchanged,
            "only_left": diff.only_left,
            "only_right": diff.only_right,
        }
    else:
        declared = {c: getattr(diff, c) for c in CHANGE_CLASSES}
    if declared != counts:
        result._err(f"{rel}: change counts {declared} do not match entries {counts}")
    report_path = path / "run_diff.md"
    if not report_path.exists():
        result._err(f"{_rel(report_path, root)}: missing")
    if schema_version == SCHEMA_VERSIONS["run_diff"]:
        for side_name, source, label in (
            ("left", diff.left_source, diff.left_label),
            ("right", diff.right_source, diff.right_label),
        ):
            source_label = f"{rel}: {side_name}_source"
            if source.run_id != label:
                result._err(f"{source_label}.run_id does not match {side_name}_label")
            if not _SHA256_HEX.fullmatch(source.manifest_sha256):
                result._err(f"{source_label}.manifest_sha256 is not SHA-256")
            source_version_error = check_schema_version(
                "run_manifest", source.manifest_schema_version
            )
            if source_version_error:
                result._err(f"{source_label}: {source_version_error}")
            expected_scope = (
                "current_content_bound"
                if source.manifest_schema_version == SCHEMA_VERSIONS["run_manifest"]
                else "legacy_structural"
            )
            if source.artifact_validation != expected_scope:
                result._err(f"{source_label}.artifact_validation does not match manifest schema")
            if source.origin_authentication != "unsigned":
                result._err(f"{source_label}.origin_authentication must be unsigned")
        _validate_exact_rendered_report(report_path, _diff_md(diff), root, result)
        manifest_path = path / "run_index.json"
        if not manifest_path.is_file():
            result._err(f"{_rel(manifest_path, root)}: missing for current run diff")
        expected_outcomes = {change: getattr(diff, change) for change in CHANGE_CLASSES}
        _validate_manifest_fields(
            path,
            root,
            result,
            expected={
                "run_kind": "run_diff",
                "target": f"{diff.left_label} vs {diff.right_label}",
                "model": "",
                "scenario": diff.kind,
                "variants": [diff.left_label, diff.right_label],
                "repeats": 1,
                "outcomes": expected_outcomes,
                "metadata": {
                    "left_manifest_sha256": diff.left_source.manifest_sha256,
                    "right_manifest_sha256": diff.right_source.manifest_sha256,
                    "left_artifact_validation": diff.left_source.artifact_validation,
                    "right_artifact_validation": diff.right_source.artifact_validation,
                    "left_expectations_ok": diff.left_source.expectations_ok,
                    "right_expectations_ok": diff.right_source.expectations_ok,
                    "origin_authentication": "unsigned",
                },
                "artifacts": ["run_diff.json", "run_diff.md"],
            },
        )
    _validate_run_manifest(path, root, result)
    for name in ("run_diff.json", "run_diff.md"):
        _scan_secrets(path / name, root, result)


def _validate_evidence_quality_dir(path: Path, root: Path, result: ValidationResult) -> None:
    """Validate a derived evidence-quality bundle and its exact projections."""

    from agentic_security_harness.evidence_quality import (
        EvidenceQualityReport,
        build_evidence_quality_markdown,
        evidence_quality_manifest_projection,
        validate_evidence_quality_projection,
    )

    json_path = path / "evidence_quality.json"
    rel = _rel(json_path, root)
    _check_schema_version_file(json_path, "evidence_quality", root, result)
    raw = _load_json(json_path, root, result)
    if raw is None:
        return
    try:
        report = EvidenceQualityReport.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    schema_version = str(raw.get("schema_version") or "")
    report_path = path / "evidence_quality.md"
    if not report_path.is_file():
        result._err(f"{_rel(report_path, root)}: missing")
    if schema_version == SCHEMA_VERSIONS["evidence_quality"]:
        for error in validate_evidence_quality_projection(report):
            result._err(f"{rel}: {error}")
        _validate_exact_rendered_report(
            report_path,
            build_evidence_quality_markdown(report),
            root,
            result,
        )
        manifest_path = path / "run_index.json"
        if not manifest_path.is_file():
            result._err(f"{_rel(manifest_path, root)}: missing for evidence quality bundle")
        projection = evidence_quality_manifest_projection(report)
        _validate_manifest_fields(
            path,
            root,
            result,
            expected={
                "run_kind": "evidence_quality",
                "target": projection["target"],
                "model": "",
                "scenario": projection["scenario"],
                "variants": [],
                "repeats": 1,
                "outcomes": projection["outcomes"],
                "metadata": projection["metadata"],
                "artifacts": ["evidence_quality.json", "evidence_quality.md"],
            },
        )
    _validate_run_manifest(path, root, result)
    for name in ("evidence_quality.json", "evidence_quality.md"):
        _scan_secrets(path / name, root, result)


def _validate_run_stats_dir(path: Path, root: Path, result: ValidationResult) -> None:
    """Validate source-bound run-history statistics and exact projections."""

    from agentic_security_harness.stats import (
        RunStats,
        build_stats_md,
        run_stats_manifest_projection,
        validate_run_stats_projection,
    )

    json_path = path / "run_stats.json"
    rel = _rel(json_path, root)
    _check_schema_version_file(json_path, "run_stats", root, result)
    raw = _load_json(json_path, root, result)
    if raw is None:
        return
    try:
        stats = RunStats.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    for error in validate_run_stats_projection(stats):
        result._err(f"{rel}: {error}")
    report_path = path / "run_stats.md"
    if not report_path.is_file():
        result._err(f"{_rel(report_path, root)}: missing")
    _validate_exact_rendered_report(report_path, build_stats_md(stats), root, result)
    manifest_path = path / "run_index.json"
    if not manifest_path.is_file():
        result._err(f"{_rel(manifest_path, root)}: missing for run stats bundle")
    projection = run_stats_manifest_projection(stats)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "run_stats",
            "target": projection["target"],
            "model": "",
            "scenario": projection["scenario"],
            "variants": [],
            "repeats": 1,
            "outcomes": projection["outcomes"],
            "metadata": projection["metadata"],
            "artifacts": ["run_stats.json", "run_stats.md"],
        },
    )
    _validate_run_manifest(path, root, result)
    for name in ("run_stats.json", "run_stats.md"):
        _scan_secrets(path / name, root, result)


def _validate_showcase_dir(path: Path, root: Path, result: ValidationResult) -> None:
    """Validate a source-bound showcase and both exact inert Markdown views."""

    from agentic_security_harness.showcase import (
        ShowcaseBundle,
        _cards_md,
        _index_md,
        showcase_manifest_projection,
        validate_showcase_projection,
    )

    json_path = path / "showcase.json"
    rel = _rel(json_path, root)
    _check_schema_version_file(json_path, "showcase", root, result)
    raw = _load_json(json_path, root, result)
    if raw is None:
        return
    try:
        bundle = ShowcaseBundle.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    for error in validate_showcase_projection(bundle):
        result._err(f"{rel}: {error}")
    index_path = path / "index.md"
    cards_path = path / "failure-cards.md"
    for report_path in (index_path, cards_path):
        if not report_path.is_file():
            result._err(f"{_rel(report_path, root)}: missing")
    _validate_exact_rendered_report(
        index_path,
        _index_md(
            bundle.schema_version,
            bundle.source_root,
            bundle.sources,
            bundle.cards,
        ),
        root,
        result,
    )
    _validate_exact_rendered_report(cards_path, _cards_md(bundle.cards), root, result)
    projection = showcase_manifest_projection(bundle)
    _validate_manifest_fields(
        path,
        root,
        result,
        expected={
            "run_kind": "showcase",
            "target": projection["target"],
            "model": "",
            "scenario": projection["scenario"],
            "variants": [],
            "repeats": 1,
            "outcomes": projection["outcomes"],
            "metadata": projection["metadata"],
            "artifacts": ["failure-cards.md", "index.md", "showcase.json"],
        },
    )
    _validate_run_manifest(path, root, result)
    for artifact in (json_path, index_path, cards_path):
        _scan_secrets(artifact, root, result)


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _validate_exact_rendered_report(
    report_path: Path,
    expected_text: str,
    root: Path,
    result: ValidationResult,
) -> None:
    from agentic_security_harness.safe_io import redact_artifact_text

    if not report_path.exists():
        return
    try:
        actual = report_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result._err(f"{_rel(report_path, root)}: cannot read report: {exc}")
        return
    expected = redact_artifact_text(expected_text).replace("\r\n", "\n").replace("\r", "\n")
    if actual != expected:
        result._err(f"{_rel(report_path, root)}: report projection mismatch")


def _validate_live_campaign_manifest_binding(
    dir_path: Path,
    root: Path,
    result: ValidationResult,
    *,
    run_kind: str,
    target: str,
    model: str,
    scenario: str,
    variants: list[str],
    tool_version: str,
    created_at: str,
    execution_id: str,
    metadata: dict[str, str | bool],
    outcomes: dict[str, int],
    artifacts: list[str],
) -> None:
    """Bind a current live manifest to its summary-declared execution config."""

    from agentic_security_harness.run_manifest import RunManifest

    manifest_path = dir_path / "run_index.json"
    rel = _rel(manifest_path, root)
    if not manifest_path.exists():
        result._err(f"{rel}: missing")
        return
    raw = _load_json(manifest_path, root, result)
    if raw is None:
        return
    try:
        manifest = RunManifest.model_validate(raw)
    except ValidationError:
        return  # Generic manifest validation reports the schema failure.
    expected = {
        "run_kind": run_kind,
        "target": target,
        "model": model,
        "scenario": scenario,
        "variants": variants,
        "tool_version": tool_version,
        "created_at": created_at,
        "repeats": 1,
        "outcomes": outcomes,
        "metadata": metadata,
        "artifacts": sorted(artifacts),
    }
    actual = manifest.model_dump(mode="json")
    if manifest.run_id != execution_id or manifest.execution_id != execution_id:
        result._err(f"{rel}: execution identity does not match live summary run_config")
    for field_name, expected_value in expected.items():
        if actual[field_name] != expected_value:
            result._err(f"{rel}: {field_name} does not match live summary run_config")


def _validate_manifest_fields(
    dir_path: Path,
    root: Path,
    result: ValidationResult,
    *,
    expected: dict[str, object],
) -> None:
    """Bind selected manifest semantics to their authoritative summary projection."""

    from agentic_security_harness.run_manifest import RunManifest

    manifest_path = dir_path / "run_index.json"
    if not manifest_path.exists():
        return
    raw = _load_json(manifest_path, root, result)
    if raw is None:
        return
    try:
        manifest = RunManifest.model_validate(raw)
    except ValidationError:
        return
    actual = manifest.model_dump(mode="json")
    rel = _rel(manifest_path, root)
    for field_name, expected_value in expected.items():
        if actual.get(field_name) != expected_value:
            result._err(f"{rel}: {field_name} does not match summary projection")


def _validate_run_manifest(dir_path: Path, root: Path, result: ValidationResult) -> None:
    """Validate ``run_index.json`` inside a run directory, if present.

    Checks structure, run kind, and that every listed artifact exists. The
    ``created_at`` timestamp is informational and is not rebuilt or compared.
    """
    manifest_path = dir_path / "run_index.json"
    if not manifest_path.exists():
        return
    from agentic_security_harness.run_manifest import (
        _RUN_KINDS,
        RunManifest,
        _artifact_sha256,
        _resolve_manifest_artifact,
        make_config_fingerprint,
        make_run_id,
    )

    rel = _rel(manifest_path, root)
    raw = _load_json(manifest_path, root, result)
    if raw is None:
        return
    _check_schema_version_file(manifest_path, "run_manifest", root, result)
    try:
        manifest = RunManifest.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if not manifest.run_id:
        result._err(f"{rel}: run_id is empty")
    expected_config = make_config_fingerprint(
        manifest.run_kind,
        manifest.target,
        manifest.model,
        manifest.scenario,
        manifest.variants,
        manifest.repeats,
    )
    if manifest.schema_version == "0.1":
        expected_legacy_id = make_run_id(
            manifest.run_kind,
            manifest.target,
            manifest.model,
            manifest.scenario,
            manifest.variants,
            manifest.repeats,
        )
        if manifest.run_id != expected_legacy_id:
            result._err(f"{rel}: legacy run_id does not match configuration")
    else:
        if not manifest.execution_id:
            result._err(f"{rel}: execution_id is empty")
        elif not _EXECUTION_ID.fullmatch(manifest.execution_id):
            result._err(f"{rel}: execution_id has invalid format")
        if manifest.run_id != manifest.execution_id:
            result._err(f"{rel}: run_id must equal execution_id")
        if manifest.config_fingerprint != expected_config:
            result._err(f"{rel}: config_fingerprint does not match configuration")
    if manifest.run_kind not in _RUN_KINDS:
        result._err(f"{rel}: unknown run_kind '{manifest.run_kind}'")
    if len(manifest.artifacts) != len(set(manifest.artifacts)):
        result._err(f"{rel}: artifact paths must be unique")
    resolved_artifacts: dict[str, Path] = {}
    for art in manifest.artifacts:
        try:
            artifact_path = _resolve_manifest_artifact(dir_path, art)
        except ValueError as exc:
            result._err(f"{rel}: {exc}")
            continue
        resolved_artifacts[art] = artifact_path
        if not artifact_path.is_file():
            result._err(f"{rel}: artifact '{art}' is missing from the run directory")
    if manifest.schema_version == SCHEMA_VERSIONS["run_manifest"]:
        expected_names = set(manifest.artifacts)
        actual_names = set(manifest.artifact_sha256)
        if actual_names != expected_names:
            result._err(f"{rel}: artifact_sha256 keys must exactly match artifacts")
        for art in sorted(expected_names & actual_names):
            declared_hash = manifest.artifact_sha256[art]
            if not _SHA256_HEX.fullmatch(declared_hash):
                result._err(f"{rel}: artifact_sha256[{art!r}] is not SHA-256")
                continue
            persisted_path = resolved_artifacts.get(art)
            if persisted_path is None or not persisted_path.is_file():
                continue
            if _artifact_sha256(persisted_path) != declared_hash:
                result._err(f"{rel}: artifact_sha256[{art!r}] content mismatch")
        allowed_unbound = {"README.md", "report.html"}
        link_entries = sorted(
            candidate.relative_to(dir_path).as_posix()
            for candidate in dir_path.rglob("*")
            if is_link_or_reparse(candidate)
        )
        if link_entries:
            result._err(
                f"{rel}: links or reparse points are not allowed in a current "
                f"evidence bundle: {link_entries}"
            )
        persisted_files = {
            candidate.relative_to(dir_path).as_posix()
            for candidate in dir_path.rglob("*")
            if candidate.is_file() and candidate.name != "run_index.json"
        }
        unexpected_files = sorted(persisted_files - expected_names - allowed_unbound)
        if unexpected_files:
            result._err(
                f"{rel}: unmanifested files are not allowed in a current evidence "
                f"bundle: {unexpected_files}"
            )
        for companion in sorted(persisted_files & allowed_unbound):
            companion_path = dir_path / companion
            if companion_path.is_symlink():
                result._err(f"{rel}: unmanifested companion must not be a symbolic link")
            _scan_secrets(companion_path, root, result)
    # External runs must carry reproducibility metadata; the credential env field must
    # hold a NAME, never a value.
    if manifest.run_kind == "external":
        required = {"adapter_type", "model", "scenario", "network_mode"}
        missing = sorted(required - set(manifest.metadata))
        if missing:
            result._err(f"{rel}: external metadata missing keys: {missing}")
        credential_env = manifest.metadata.get(
            "credential_env_var", manifest.metadata.get("api_key_env")
        )
        if isinstance(credential_env, str) and any(
            token in credential_env.lower() for token in ("sk-", "key=")
        ):
            result._err(f"{rel}: metadata.credential_env_var looks like a credential value")
    _scan_secrets(manifest_path, root, result)


def _scan_secrets(path: Path, root: Path, result: ValidationResult) -> None:
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    rel = _rel(path, root)
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            result._err(f"{rel}: possible secret-shaped string (forbidden marker '{name}')")


def _validate_matrix_json(
    matrix_path: Path,
    traces: list[ExploitTrace] | None,
    root: Path,
    result: ValidationResult,
) -> Any | None:
    """Validate matrix.json against traces and corpus."""
    rel = _rel(matrix_path, root)
    raw = _load_json(matrix_path, root, result)
    if raw is None:
        return None
    try:
        from agentic_security_harness.matrix import MatrixReport

        report = MatrixReport.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return None
    if report.corpus_version != CORPUS_VERSION:
        result._err(
            f"{rel}: corpus_version '{report.corpus_version}' != supported '{CORPUS_VERSION}'"
        )
    # Bind scenario metadata and the selected corpus slice to the scenario registry.
    corpus = {entry.pattern_id: entry for entry in corpus_manifest()}
    for pid in report.selected_pattern_ids:
        if pid not in corpus:
            result._err(f"{rel}: selected pattern_id '{pid}' not in corpus")
    try:
        from agentic_security_harness.scenarios import get_scenario, get_variants

        scenario = get_scenario(report.scenario_id)
    except KeyError:
        result._err(f"{rel}: unknown scenario_id '{report.scenario_id}'")
        scenario = None
    if scenario is not None:
        expected_selected = [pid for pid in scenario.pattern_ids if pid in corpus]
        if report.scenario_title != scenario.title:
            result._err(f"{rel}: scenario_title does not match scenario registry")
        if report.selected_pattern_ids != expected_selected:
            result._err(f"{rel}: selected_pattern_ids do not match scenario registry")
        known_variants = {
            variant.variant_id: variant
            for variant in get_variants(report.scenario_id, max(len(scenario.variants), 1))
        }
        for variant in report.variants:
            expected_variant = known_variants.get(variant.variant_id)
            if expected_variant is None:
                result._err(f"{rel}: unknown variant_id '{variant.variant_id}'")
                continue
            expected_metadata = {
                "title": expected_variant.title,
                "description": expected_variant.description,
                "knobs": expected_variant.knobs,
                "expected_control_focus": list(expected_variant.expected_control_focus),
            }
            for field_name, expected_value in expected_metadata.items():
                if getattr(variant, field_name) != expected_value:
                    result._err(
                        f"{rel}: variant '{variant.variant_id}' {field_name} "
                        "does not match scenario registry"
                    )
    # Validate unique variant ids
    variant_ids = [v.variant_id for v in report.variants]
    if len(variant_ids) != len(set(variant_ids)):
        dupes = sorted(vid for vid in set(variant_ids) if variant_ids.count(vid) > 1)
        result._err(f"{rel}: duplicate variant_id(s): {dupes}")
    # Validate trace ids referenced by variants exist in traces.json
    if traces is not None:
        trace_id_set = {t.trace_id for t in traces}
        all_ref_ids: list[str] = []
        for v in report.variants:
            all_ref_ids.extend(v.trace_ids)
        missing_traces = sorted(set(all_ref_ids) - trace_id_set)
        if missing_traces:
            result._err(
                f"{rel}: variant references trace_id(s) not in traces.json: {missing_traces}"
            )
        if len(all_ref_ids) != len(set(all_ref_ids)):
            result._err(f"{rel}: variant trace_ids contain duplicates")
        unreferenced = sorted(trace_id_set - set(all_ref_ids))
        if unreferenced:
            result._err(
                f"{rel}: traces.json contains trace_id(s) not assigned to a variant: {unreferenced}"
            )
        traces_by_id = {trace.trace_id: trace for trace in traces}
        for variant in report.variants:
            variant_traces = [
                traces_by_id[trace_id] for trace_id in variant.trace_ids if trace_id in traces_by_id
            ]
            rebuilt_card = build_scorecard(variant_traces)
            expected_variant_projection: dict[str, object] = {
                "total_traces": len(variant_traces),
                "failed_patterns": list(rebuilt_card.failed_patterns),
                "passed_patterns": list(rebuilt_card.passed_patterns),
                "findings_by_severity": dict(rebuilt_card.findings_by_severity),
            }
            for field_name, projected_value in expected_variant_projection.items():
                if getattr(variant, field_name) != projected_value:
                    result._err(
                        f"{rel}: variant '{variant.variant_id}' {field_name} "
                        "does not match its referenced traces"
                    )
        # Validate total traces match
        if report.total_traces != len(traces):
            result._err(
                f"{rel}: total_traces {report.total_traces} != traces in traces.json {len(traces)}"
            )
        from agentic_security_harness.matrix import _build_summary

        rebuilt_summary = _build_summary(report.variants, traces, report.scenario_id)
        if report.summary != rebuilt_summary:
            result._err(f"{rel}: summary does not match variants + traces")
    if report.generated_by != "agentic-security-harness":
        result._err(f"{rel}: generated_by is not the canonical producer id")

    # Matrix Markdown is an exact projection, not an existence-only companion.
    matrix_md = matrix_path.parent / "matrix.md"
    if not matrix_md.exists():
        result._err(f"{_rel(matrix_md, root)}: missing")
    elif traces is not None:
        from agentic_security_harness.matrix import _build_matrix_md

        _validate_exact_rendered_report(
            matrix_md,
            _build_matrix_md(report, build_scorecard(traces)),
            root,
            result,
        )
    _scan_secrets(matrix_md, root, result)
    return report
