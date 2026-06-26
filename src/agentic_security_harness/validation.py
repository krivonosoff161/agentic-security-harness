"""Validation layer for committed benchmark artifacts and corpus consistency.

Deterministic, stdlib + Pydantic only - no network, no new dependencies. Validates report
directories (traces.json / scorecard.json / summary.md / executive.md) and comparison
directories (baseline/ + protected/ + comparison.md) against the corpus manifest, and scans for
forbidden secret-shaped markers.

Passing validation means the artifacts conform to the corpus manifest (schema v0.1) and
contain no forbidden marker patterns - NOT that any system is secure.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.models import ExploitTrace, TargetDescriptor
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.reporting import (
    _SEVERITY_RANK,
    build_comparison_md,
    build_executive_md,
    build_summary_md,
)
from agentic_security_harness.schema_versions import CORPUS_VERSION, check_schema_version
from agentic_security_harness.scorecard import ScorecardSummary, build_scorecard

if TYPE_CHECKING:
    from agentic_security_harness.run_config import ExternalResult, ExternalSummary

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


class ValidationResult(BaseModel):
    """Structured outcome of validating one or more benchmark artifacts."""

    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    report_dirs: list[str] = Field(default_factory=list)
    comparison_dirs: list[str] = Field(default_factory=list)
    external_dirs: list[str] = Field(default_factory=list)
    run_diff_dirs: list[str] = Field(default_factory=list)
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

    def _err(self, msg: str) -> None:
        self.errors.append(msg)
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
        (path / "external_results.json").exists()
        and (path / "external_summary.json").exists()
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
    return result


def _validate_into(path: Path, root: Path, result: ValidationResult) -> None:
    if not path.exists():
        result._err(f"missing path: {_rel(path, root)}")
        return
    if not path.is_dir():
        result._err(f"not a directory: {_rel(path, root)}")
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
    elif (path / "run_diff.json").exists():
        result.run_diff_dirs.append(_rel(path, root))
        _validate_run_diff_dir(path, root, result)
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


def _validate_local_swarm_dir(path: Path, root: Path, result: ValidationResult) -> None:
    rel = _rel(path / "local_swarm_summary.json", root)
    raw = _load_json(path / "local_swarm_summary.json", root, result)
    if raw is None:
        return
    _check_schema_version_file(path / "local_swarm_summary.json", "local_swarm", root, result)
    from agentic_security_harness.local_swarm import LocalSwarmSummary

    try:
        summary = LocalSwarmSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if (
        summary.metrics.bounded_swarm_boundary_failures
        > summary.metrics.naive_swarm_boundary_failures
    ):
        result._err(f"{rel}: bounded failures exceed naive failures")
    if summary.executed_model_calls and summary.request_count <= 0:
        result._err(f"{rel}: executed_model_calls true but request_count is zero")
    if not (path / "local_swarm_report.md").exists():
        result._err(f"{_rel(path / 'local_swarm_report.md', root)}: missing")
    _validate_run_manifest(path, root, result)
    _scan_secrets(path / "local_swarm_summary.json", root, result)
    _scan_secrets(path / "local_swarm_report.md", root, result)


def _validate_local_swarm_matrix_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
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
    from agentic_security_harness.local_swarm_matrix import LocalSwarmAttackMatrix

    try:
        matrix = LocalSwarmAttackMatrix.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if matrix.metrics.bounded_swarm_boundary_failures:
        result._err(f"{rel}: bounded matrix has boundary failures")
    if matrix.metrics.bounded_blocks != matrix.metrics.cases:
        result._err(f"{rel}: bounded blocks do not cover every matrix case")
    if matrix.metrics.base_scenarios < 1:
        result._err(f"{rel}: no base scenarios covered")
    if not (path / "local_swarm_attack_matrix.md").exists():
        result._err(f"{_rel(path / 'local_swarm_attack_matrix.md', root)}: missing")
    _validate_run_manifest(path, root, result)
    _scan_secrets(path / "local_swarm_attack_matrix.json", root, result)
    _scan_secrets(path / "local_swarm_attack_matrix.md", root, result)


def _validate_evidence_campaign_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
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
    from agentic_security_harness.evidence_campaign import EvidenceCampaignSummary

    try:
        summary = EvidenceCampaignSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    bounded = summary.metrics.by_mode.get("bounded_swarm")
    naive = summary.metrics.by_mode.get("naive_swarm")
    if bounded is None or naive is None:
        result._err(f"{rel}: missing required mode metrics")
    elif bounded.failure_rate > naive.failure_rate:
        result._err(f"{rel}: bounded failure rate exceeds naive failure rate")
    if summary.metrics.claim_families < 1:
        result._err(f"{rel}: no claim families covered")
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases does not match case count")
    if summary.metrics.observations != len(summary.observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.ablation_metrics.observations != len(summary.ablation_observations):
        result._err(
            f"{rel}: ablation_metrics.observations does not match ablation count"
        )
    if summary.ablation_metrics.observations != summary.metrics.cases:
        result._err(f"{rel}: ablation observations do not cover every campaign case")
    if summary.ablation_metrics.benign_regressions:
        result._err(f"{rel}: ablation introduced benign regressions")
    if summary.ablation_metrics.unsafe_regressions < summary.metrics.by_mode[
        "bounded_swarm"
    ].true_positive:
        result._err(f"{rel}: ablation does not explain every bounded true positive")
    if not (path / "evidence_campaign_report.md").exists():
        result._err(f"{_rel(path / 'evidence_campaign_report.md', root)}: missing")
    if not (path / "evidence_campaign_digest.json").exists():
        result._err(f"{_rel(path / 'evidence_campaign_digest.json', root)}: missing")
    _validate_run_manifest(path, root, result)
    for name in (
        "evidence_campaign_summary.json",
        "evidence_campaign_report.md",
        "evidence_campaign_digest.json",
    ):
        _scan_secrets(path / name, root, result)


def _validate_secret_leak_campaign_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
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
    from agentic_security_harness.secret_leak_campaign import SecretLeakCampaignSummary

    try:
        summary = SecretLeakCampaignSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if summary.metrics.scenarios != len(summary.scenarios):
        result._err(f"{rel}: metrics.scenarios does not match scenario count")
    if summary.metrics.observations != len(summary.observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.naive_leaks <= 0:
        result._err(f"{rel}: naive mode did not disclose any synthetic canary")
    if summary.metrics.ablation_leaks <= 0:
        result._err(f"{rel}: ablation mode did not attribute any control regression")
    if summary.metrics.bounded_leaks:
        result._err(f"{rel}: bounded mode leaked synthetic canaries")
    if summary.metrics.benign_leaks:
        result._err(f"{rel}: benign mode leaked synthetic canaries")
    if summary.metrics.benign_pass_rate != 1.0:
        result._err(f"{rel}: benign pass rate is not 1.0")
    if summary.metrics.control_attribution_rate <= 0:
        result._err(f"{rel}: control attribution rate is zero")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw prompt/response/value fields")
    if not (path / "secret_leak_campaign_report.md").exists():
        result._err(f"{_rel(path / 'secret_leak_campaign_report.md', root)}: missing")
    if not (path / "secret_leak_campaign_digest.json").exists():
        result._err(f"{_rel(path / 'secret_leak_campaign_digest.json', root)}: missing")
    _validate_run_manifest(path, root, result)
    for name in (
        "secret_leak_campaign_summary.json",
        "secret_leak_campaign_report.md",
        "secret_leak_campaign_digest.json",
    ):
        _scan_secrets(path / name, root, result)


def _validate_secret_leak_variation_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
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
    )

    try:
        summary = SecretLeakVariationSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases does not match case count")
    if summary.metrics.observations != len(summary.observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.models != len({item.model for item in summary.observations}):
        result._err(f"{rel}: metrics.models does not match observation models")
    if summary.metrics.leaks != sum(1 for item in summary.observations if item.leaked):
        result._err(f"{rel}: metrics.leaks does not match observations")
    if summary.metrics.adapter_errors != sum(
        1 for item in summary.observations if item.adapter_error
    ):
        result._err(f"{rel}: metrics.adapter_errors does not match observations")
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw prompt/response/value fields")
    if not (path / "secret_leak_variation_report.md").exists():
        result._err(f"{_rel(path / 'secret_leak_variation_report.md', root)}: missing")
    if not (path / "secret_leak_variation_digest.json").exists():
        result._err(f"{_rel(path / 'secret_leak_variation_digest.json', root)}: missing")
    _validate_run_manifest(path, root, result)
    for name in (
        "secret_leak_variation_summary.json",
        "secret_leak_variation_report.md",
        "secret_leak_variation_digest.json",
    ):
        _scan_secrets(path / name, root, result)


def _validate_semantic_drift_campaign_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
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
    from agentic_security_harness.semantic_drift_campaign import SemanticDriftSummary

    try:
        summary = SemanticDriftSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases does not match case count")
    if summary.metrics.observations != len(summary.observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.deterministic_results != len(summary.deterministic_results):
        result._err(
            f"{rel}: metrics.deterministic_results does not match deterministic rows"
        )
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
    if summary.metrics.bounded_drift_acceptances != sum(
        1
        for item in summary.deterministic_results
        if item.mode == "bounded_swarm" and item.drift_accepted
    ):
        result._err(
            f"{rel}: metrics.bounded_drift_acceptances does not match deterministic rows"
        )
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw prompt/response/value fields")
    if _contains_forbidden_key(raw, "canary_fingerprint"):
        result._err(f"{rel}: public artifact contains private canary fingerprint")
    if _contains_forbidden_key(raw, "canonical_state_hash"):
        result._err(f"{rel}: public artifact contains private canonical state hash")
    if not (path / "semantic_drift_report.md").exists():
        result._err(f"{_rel(path / 'semantic_drift_report.md', root)}: missing")
    if not (path / "semantic_drift_digest.json").exists():
        result._err(f"{_rel(path / 'semantic_drift_digest.json', root)}: missing")
    for private_name in ("semantic_drift_private.json", "semantic_drift_private.md"):
        if (path / private_name).exists():
            result._err(
                f"{_rel(path / private_name, root)}: private semantic drift artifact "
                "must stay under .internal/"
            )
    _validate_run_manifest(path, root, result)
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
        SemanticPropagationSummary,
    )

    try:
        summary = SemanticPropagationSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if summary.metrics.cases != len(summary.cases):
        result._err(f"{rel}: metrics.cases does not match case count")
    if summary.metrics.observations != len(summary.observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.deterministic_results != len(summary.deterministic_results):
        result._err(
            f"{rel}: metrics.deterministic_results does not match deterministic rows"
        )
    if summary.metrics.control_catalog_entries != len(summary.control_catalog):
        result._err(f"{rel}: metrics.control_catalog_entries mismatch")
    if summary.metrics.control_effect_rows != len(summary.control_effects):
        result._err(f"{rel}: metrics.control_effect_rows mismatch")
    if summary.metrics.worker_models != len(
        {item.worker_model for item in summary.observations}
    ):
        result._err(f"{rel}: metrics.worker_models does not match observations")
    if summary.metrics.chief_models != len(
        {item.chief_model for item in summary.observations}
    ):
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
    if summary.metrics.bounded_propagation_acceptances != sum(
        1
        for item in summary.deterministic_results
        if item.mode == "bounded_chain" and item.propagation_accepted
    ):
        result._err(
            f"{rel}: metrics.bounded_propagation_acceptances does not match rows"
        )
    if _contains_forbidden_raw_fields(raw):
        result._err(f"{rel}: public artifact contains raw prompt/response/value fields")
    if _contains_forbidden_key(raw, "canary_fingerprint"):
        result._err(f"{rel}: public artifact contains private canary fingerprint")
    if _contains_forbidden_key(raw, "canonical_state_hash"):
        result._err(f"{rel}: public artifact contains private canonical state hash")
    for required in (
        "semantic_propagation_report.md",
        "semantic_propagation_digest.json",
    ):
        if not (path / required).exists():
            result._err(f"{_rel(path / required, root)}: missing")
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
    for name in (
        "semantic_propagation_summary.json",
        "semantic_propagation_report.md",
        "semantic_propagation_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


def _validate_swarm_defense_contour_dir(
    path: Path, root: Path, result: ValidationResult
) -> None:
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
    from agentic_security_harness.swarm_defense_contour import DefenseContourSummary

    try:
        summary = DefenseContourSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if summary.metrics.scenarios != len(summary.scenarios):
        result._err(f"{rel}: metrics.scenarios does not match scenario count")
    if summary.metrics.topologies != len(summary.topologies):
        result._err(f"{rel}: metrics.topologies does not match topology count")
    if summary.metrics.results != len(summary.results):
        result._err(f"{rel}: metrics.results does not match result rows")
    if summary.metrics.control_effect_rows != len(summary.control_effects):
        result._err(f"{rel}: metrics.control_effect_rows mismatch")
    if summary.metrics.bounded_acceptances != sum(
        1
        for item in summary.results
        if item.mode == "bounded_swarm" and item.attack_accepted
    ):
        result._err(f"{rel}: metrics.bounded_acceptances mismatch")
    if summary.metrics.naive_acceptances != sum(
        1
        for item in summary.results
        if item.mode == "naive_swarm" and item.attack_accepted
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
    for name in (
        "swarm_defense_contour_summary.json",
        "swarm_defense_contour_report.md",
        "swarm_defense_contour_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


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
    from agentic_security_harness.swarm_defense_live_campaign import LiveDefenseSummary

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
    if summary.metrics.observations != len(summary.observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.topologies != len(
        {item.topology_id for item in summary.observations}
    ):
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
        if item.worker_drift_detected or item.chief_accepted_drift or item.canary_leaked
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
    unsafe_blocks = sum(
        1 for item in unsafe_observations if item.verifier_decision == "block"
    )
    benign_allows = sum(
        1 for item in benign_observations if item.verifier_decision == "allow"
    )
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
    expected_verifier_block_rate = (
        summary.metrics.verifier_blocks / len(summary.observations)
        if summary.observations
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
        if not item.adapter_error
    )
    turn_hash_present = sum(
        1
        for item in summary.observations
        if not item.adapter_error
        for digest in item.worker_turn_response_sha256
        if digest
    )
    expected_turn_hash_coverage = (
        turn_hash_present / turn_hash_slots if turn_hash_slots else 0.0
    )
    if (
        has_extended_live_metrics
        and summary.metrics.turn_hash_coverage != expected_turn_hash_coverage
    ):
        result._err(f"{rel}: metrics.turn_hash_coverage mismatch")
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
                (
                    f"{rel}: observations[{idx}].worker_turn_response_sha256"
                    f"[{turn_idx}]"
                ),
                result,
            )
        if not item.adapter_error:
            if not item.worker_response_sha256:
                result._err(
                    f"{rel}: observations[{idx}].worker_response_sha256 missing"
                )
            if not item.chief_response_sha256:
                result._err(
                    f"{rel}: observations[{idx}].chief_response_sha256 missing"
                )
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
        reopened_observations / blocked_observations
        if blocked_observations
        else 0.0
    )
    if summary.metrics.ablation_reopenings != sum(ablation_by_control.values()):
        result._err(f"{rel}: metrics.ablation_reopenings mismatch")
    if summary.metrics.ablation_reopening_rate != expected_reopening_rate:
        result._err(f"{rel}: metrics.ablation_reopening_rate mismatch")
    if summary.metrics.ablation_reopenings_by_control != ablation_by_control:
        result._err(f"{rel}: metrics.ablation_reopenings_by_control mismatch")
    if summary.metrics.reopened_by_missing_control != ablation_by_control:
        result._err(f"{rel}: metrics.reopened_by_missing_control mismatch")
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
    )

    try:
        summary = MarketingWebInjectionSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    observations = summary.observations
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
    if summary.metrics.ablation_leaks != sum(
        1 for row in ablation if row.leak_detected
    ):
        result._err(f"{rel}: metrics.ablation_leaks mismatch")
    if summary.metrics.benign_leaks != sum(1 for row in benign if row.leak_detected):
        result._err(f"{rel}: metrics.benign_leaks mismatch")
    if summary.metrics.verifier_blocks != sum(
        1 for row in observations if row.verifier_decision == "block"
    ):
        result._err(f"{rel}: metrics.verifier_blocks mismatch")
    if summary.metrics.false_blocks != sum(
        1 for row in benign if row.verifier_decision == "block"
    ):
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
    for name in (
        "marketing_web_injection_summary.json",
        "marketing_web_injection_report.md",
        "marketing_web_injection_digest.json",
        "README.md",
    ):
        candidate = path / name
        if candidate.exists():
            _scan_secrets(candidate, root, result)


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
    from agentic_security_harness.marketing_web_live_campaign import (
        LiveMarketingWebSummary,
    )

    try:
        summary = LiveMarketingWebSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    observations = summary.observations
    if summary.metrics.observations != len(observations):
        result._err(f"{rel}: metrics.observations does not match observation count")
    if summary.metrics.scenarios != len({row.scenario_id for row in observations}):
        result._err(f"{rel}: metrics.scenarios does not match observed scenario count")
    naive = [row for row in observations if row.mode == "naive"]
    bounded = [row for row in observations if row.mode == "bounded"]
    ablation = [row for row in observations if row.mode == "ablation"]
    benign = [row for row in observations if row.mode == "benign"]
    unsafe = [row for row in observations if row.attack_attempted]
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
        "verifier_blocks": sum(
            1 for row in observations if row.verifier_decision == "block"
        ),
        "false_blocks": sum(1 for row in benign if row.verifier_decision == "block"),
        "benign_passes": sum(1 for row in benign if row.benign_passed),
    }
    metrics = summary.metrics.model_dump()
    for key, expected in expected_counts.items():
        if metrics.get(key) != expected:
            result._err(f"{rel}: metrics.{key} mismatch")
    unsafe_blocks = sum(1 for row in unsafe if row.verifier_decision == "block")
    benign_allows = sum(1 for row in benign if row.verifier_decision == "allow")
    if summary.metrics.unsafe_block_rate != round(
        unsafe_blocks / len(unsafe) if unsafe else 0.0,
        4,
    ):
        result._err(f"{rel}: metrics.unsafe_block_rate mismatch")
    if summary.metrics.benign_allow_rate != round(
        benign_allows / len(benign) if benign else 0.0,
        4,
    ):
        result._err(f"{rel}: metrics.benign_allow_rate mismatch")
    hash_slots = len(observations) * 2
    hash_present = sum(
        1
        for row in observations
        for digest in (row.worker_response_sha256, row.chief_response_sha256)
        if digest
    )
    turn_slots = sum(max(1, row.session_turns) for row in observations)
    turn_hashes = sum(len(row.worker_turn_response_sha256) for row in observations)
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
    for idx, item in enumerate(observations):
        for field_name, digest in (
            ("page_url_sha256", item.page_url_sha256),
            ("page_content_sha256", item.page_content_sha256),
            ("worker_response_sha256", item.worker_response_sha256),
            ("chief_response_sha256", item.chief_response_sha256),
        ):
            _validate_optional_sha256(
                digest,
                f"{rel}: observations[{idx}].{field_name}",
                result,
            )
            if not digest:
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


def _validate_optional_sha256(
    value: str, label: str, result: ValidationResult
) -> None:
    if value and not _SHA256_HEX.fullmatch(value):
        result._err(f"{label}: expected lowercase SHA-256 hex digest")


def _validate_swarm_defense_live_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
) -> None:
    if not digest_path.exists():
        return
    rel = _rel(digest_path, root)
    raw = _load_json(digest_path, root, result)
    if raw is None:
        return
    for key, expected in (
        ("schema_version", summary.schema_version),
        ("run_kind", summary.run_kind),
        ("created_at", summary.created_at),
    ):
        if raw.get(key) != expected:
            result._err(f"{rel}: {key} mismatch")
    for key in (
        "raw_prompts_present",
        "raw_responses_present",
        "canary_values_present",
    ):
        if raw.get(key) is not False:
            result._err(f"{rel}: {key} must be false")
    digest_metrics = raw.get("metrics")
    if not isinstance(digest_metrics, dict):
        result._err(f"{rel}: metrics missing or not an object")
        return
    summary_metrics = summary.metrics.model_dump()
    for key, value in digest_metrics.items():
        if summary_metrics.get(key) != value:
            result._err(f"{rel}: metrics.{key} mismatch")


def _validate_marketing_web_injection_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
) -> None:
    if not digest_path.exists():
        return
    rel = _rel(digest_path, root)
    raw = _load_json(digest_path, root, result)
    if raw is None:
        return
    for key, expected in (
        ("schema_version", summary.schema_version),
        ("run_kind", summary.run_kind),
        ("created_at", summary.created_at),
    ):
        if raw.get(key) != expected:
            result._err(f"{rel}: {key} mismatch")
    for key in (
        "raw_pages_present",
        "raw_prompts_present",
        "raw_responses_present",
        "synthetic_strategy_values_present",
    ):
        if raw.get(key) is not False:
            result._err(f"{rel}: {key} must be false")
    digest_metrics = raw.get("metrics")
    if not isinstance(digest_metrics, dict):
        result._err(f"{rel}: metrics missing or not an object")
        return
    summary_metrics = summary.metrics.model_dump()
    for key, value in digest_metrics.items():
        if summary_metrics.get(key) != value:
            result._err(f"{rel}: metrics.{key} mismatch")


def _validate_marketing_web_live_digest(
    digest_path: Path,
    summary: Any,
    root: Path,
    result: ValidationResult,
) -> None:
    if not digest_path.exists():
        return
    rel = _rel(digest_path, root)
    raw = _load_json(digest_path, root, result)
    if raw is None:
        return
    for key, expected in (
        ("schema_version", summary.schema_version),
        ("run_kind", summary.run_kind),
        ("created_at", summary.created_at),
    ):
        if raw.get(key) != expected:
            result._err(f"{rel}: {key} mismatch")
    for key in (
        "raw_pages_present",
        "raw_prompts_present",
        "raw_responses_present",
        "synthetic_strategy_values_present",
    ):
        if raw.get(key) is not False:
            result._err(f"{rel}: {key} must be false")
    digest_metrics = raw.get("metrics")
    if not isinstance(digest_metrics, dict):
        result._err(f"{rel}: metrics missing or not an object")
        return
    summary_metrics = summary.metrics.model_dump()
    for key, value in digest_metrics.items():
        if summary_metrics.get(key) != value:
            result._err(f"{rel}: metrics.{key} mismatch")


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


def _load_traces(
    path: Path, root: Path, result: ValidationResult
) -> list[ExploitTrace] | None:
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


def _load_scorecard(
    path: Path, root: Path, result: ValidationResult
) -> ScorecardSummary | None:
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
                f"{rel}: duplicate trace_id '{trace.trace_id}' "
                f"(items {seen[trace.trace_id]}, {i})"
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
            result._err(
                f"{prefix}: expected_vulnerable_behavior does not match the seed pattern"
            )
        if trace.data_envelope != pattern.data_envelope:
            result._err(f"{prefix}: data_envelope does not match the seed pattern")
        protected = _is_protected(trace.target)
        baseline = trace.target.type in _BASELINE_TYPES
        if trace.findings:
            if protected:
                result._err(f"{prefix}: protected target should PASS but has findings")
            top = max(trace.findings, key=lambda f: _SEVERITY_RANK.get(f.severity, -1))
            if top.code != pattern.category:
                result._err(
                    f"{prefix}: finding code '{top.code}' != pattern category "
                    f"'{pattern.category}'"
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
            result._err(f"{prefix}: no findings but baseline target expects FAIL")
    # For matrix runs, validate against the selected patterns instead of the full corpus
    expected_ids = expected_pattern_ids if expected_pattern_ids is not None else set(corpus)
    actual_ids = set(pattern_counts)
    missing = sorted(expected_ids - actual_ids)
    extra = sorted(actual_ids - expected_ids)
    # Matrix runs intentionally have duplicate pattern_ids (one per variant)
    if not is_matrix:
        duplicates = sorted(
            pid for pid, count in pattern_counts.items() if count > 1
        )
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
        # No findings -> no remediation artifacts expected; clean up stale ones
        for p in (rem_json, rem_md):
            if p.exists():
                p.unlink()
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

                matrix_report = MatrixReport.model_validate(matrix_raw)
                expected_pattern_ids = set(matrix_report.selected_pattern_ids)
            except ValidationError:
                pass

    traces = _load_traces(path / "traces.json", root, result)
    committed_card = _load_scorecard(path / "scorecard.json", root, result)
    expected_card: ScorecardSummary | None = None
    is_matrix = expected_pattern_ids is not None
    if traces is not None:
        _validate_traces(
            traces, path / "traces.json", root, result,
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
    if matrix_json.exists():
        _validate_matrix_json(matrix_json, traces, root, result)
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
    _check_schema_version_file(
        path / "remediation.json", "remediation", root, result
    )
    if matrix_json.exists():
        _check_schema_version_file(matrix_json, "matrix", root, result)
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
    elif comparison_md.exists():
            _scan_secrets(comparison_md, root, result)
    _validate_run_manifest(path, root, result)


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
            result._err(
                f"{_rel(path / 'external_summary.json', root)}: schema: {_fmt_error(exc)}"
            )
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
                    f"{_rel(path / 'run_config.json', root)}: "
                    "runtime.model_id does not match model"
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
                    f"{_rel(path / 'run_config.json', root)}: "
                    "runtime.model_license_note is empty"
                )
            if not runtime.recovery_guidance:
                result._err(
                    f"{_rel(path / 'run_config.json', root)}: "
                    "runtime.recovery_guidance is empty"
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
                f"{_rel(path / 'external_summary.json', root)}: model "
                "does not match run_config"
            )
        if summary.scenario_id != config.scenario_id:
            result._err(
                f"{_rel(path / 'external_summary.json', root)}: scenario_id "
                "does not match run_config"
            )
    if results is not None and summary is not None:
        _validate_external_summary(path, root, results, summary, result)

    for name in (
        "run_config.json",
        "external_results.json",
        "external_summary.json",
        "external_report.md",
    ):
        _scan_secrets(path / name, root, result)
    _check_schema_version_file(path / "run_config.json", "run_config", root, result)
    _check_schema_version_file(
        path / "external_summary.json", "external_summary", root, result
    )
    _validate_run_manifest(path, root, result)


def _validate_external_report_md(
    path: Path, root: Path, result: ValidationResult
) -> None:
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
        result._err(
            f"{rel}: does not reference run_config.json / external_summary.json"
        )


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
            "pass", "finding", "inconclusive", "adapter_error"
        }:
            result._err(
                f"{prefix}: invalid deterministic_cross_check "
                f"'{item.deterministic_cross_check}'"
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
            f"{rel}: total_repeats {summary.total_repeats} != "
            f"external_results count {len(results)}"
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
        result._err(
            f"{rel}: findings_by_control_family does not match external_results"
        )

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
    flaky_pids = sorted({
        pid for (pid, _vid), outs in groups.items() if len(outs - {"error"}) > 1
    })
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
    from agentic_security_harness.run_diff import CHANGE_CLASSES, RunDiff

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
            "fixed": diff.fixed, "new": diff.new, "changed": diff.changed,
            "unchanged": diff.unchanged, "only_left": diff.only_left,
            "only_right": diff.only_right,
        }
    else:
        declared = {c: getattr(diff, c) for c in CHANGE_CLASSES}
    if declared != counts:
        result._err(f"{rel}: change counts {declared} do not match entries {counts}")
    if not (path / "run_diff.md").exists():
        result._err(f"{_rel(path / 'run_diff.md', root)}: missing")
    for name in ("run_diff.json", "run_diff.md"):
        _scan_secrets(path / name, root, result)


def _validate_run_manifest(dir_path: Path, root: Path, result: ValidationResult) -> None:
    """Validate ``run_index.json`` inside a run directory, if present.

    Checks structure, run kind, and that every listed artifact exists. The
    ``created_at`` timestamp is informational and is not rebuilt or compared.
    """
    manifest_path = dir_path / "run_index.json"
    if not manifest_path.exists():
        return
    from agentic_security_harness.run_manifest import _RUN_KINDS, RunManifest

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
    if manifest.run_kind not in _RUN_KINDS:
        result._err(f"{rel}: unknown run_kind '{manifest.run_kind}'")
    for art in manifest.artifacts:
        if not (dir_path / art).exists():
            result._err(f"{rel}: artifact '{art}' is missing from the run directory")
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
            result._err(
                f"{rel}: metadata.credential_env_var looks like a credential value"
            )
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
            result._err(
                f"{rel}: possible secret-shaped string (forbidden marker '{name}')"
            )


def _validate_matrix_json(
    matrix_path: Path,
    traces: list[ExploitTrace] | None,
    root: Path,
    result: ValidationResult,
) -> None:
    """Validate matrix.json against traces and corpus."""
    rel = _rel(matrix_path, root)
    raw = _load_json(matrix_path, root, result)
    if raw is None:
        return
    try:
        from agentic_security_harness.matrix import MatrixReport

        report = MatrixReport.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if report.corpus_version != CORPUS_VERSION:
        result._err(
            f"{rel}: corpus_version '{report.corpus_version}' != supported "
            f"'{CORPUS_VERSION}'"
        )
    # Validate selected pattern ids exist in corpus
    corpus = {entry.pattern_id: entry for entry in corpus_manifest()}
    for pid in report.selected_pattern_ids:
        if pid not in corpus:
            result._err(f"{rel}: selected pattern_id '{pid}' not in corpus")
    # Validate unique variant ids
    variant_ids = [v.variant_id for v in report.variants]
    if len(variant_ids) != len(set(variant_ids)):
        dupes = sorted(
            vid for vid in set(variant_ids) if variant_ids.count(vid) > 1
        )
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
                f"{rel}: variant references trace_id(s) not in traces.json: "
                f"{missing_traces}"
            )
        # Validate total traces match
        if report.total_traces != len(traces):
            result._err(
                f"{rel}: total_traces {report.total_traces} "
                f"!= traces in traces.json {len(traces)}"
            )
        # Validate summary counts
        if report.summary:
            if report.summary.total_variants != len(report.variants):
                result._err(
                    f"{rel}: summary.total_variants "
                    f"{report.summary.total_variants} "
                    f"!= variants count {len(report.variants)}"
                )
            if report.summary.total_traces != report.total_traces:
                result._err(
                    f"{rel}: summary.total_traces "
                    f"{report.summary.total_traces} "
                    f"!= total_traces {report.total_traces}"
                )
    # Validate matrix.md if present
    matrix_md = matrix_path.parent / "matrix.md"
    if matrix_md.exists():
        _scan_secrets(matrix_md, root, result)
