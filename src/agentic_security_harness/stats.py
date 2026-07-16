"""Run-history statistics and retention helpers."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.run_manifest import (
    RunManifest,
    build_manifest,
    expectation_validator_fingerprint,
    load_validated_run_manifests,
    load_validated_run_records,
    write_run_manifest,
)
from agentic_security_harness.safe_io import (
    atomic_evidence_bundle,
    require_fresh_output_dir,
    write_text_artifact,
)
from agentic_security_harness.safe_markdown import markdown_code_span
from agentic_security_harness.schema_versions import CORPUS_VERSION, SCHEMA_VERSIONS
from agentic_security_harness.version import __version__


class RunStatsSource(BaseModel):
    """Minimal content-bound manifest projection used to rebuild run statistics."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    manifest_sha256: str
    run_kind: str
    scenario: str = ""
    target_or_model: str = ""
    outcomes: dict[str, int] = Field(default_factory=dict)
    expectation_status: Literal["ok", "mismatch", "not_recorded"] = "not_recorded"
    expectation_mismatch_count: int = 0
    artifact_validation: str = "current_content_bound"
    origin_authentication: str = "unsigned"


class RunStats(BaseModel):
    """Aggregate metadata-only statistics over run manifests."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSIONS["run_stats"]
    root: str
    expectation_validation_scope: Literal[
        "independently_recomputed_at_generation", "not_recorded"
    ] = "not_recorded"
    validator_tool_version: str = ""
    corpus_version: str = ""
    validator_source_fingerprint: str = ""
    total_runs: int = 0
    by_kind: dict[str, int] = Field(default_factory=dict)
    by_scenario: dict[str, int] = Field(default_factory=dict)
    by_target_or_model: dict[str, int] = Field(default_factory=dict)
    by_expectation_status: dict[str, int] = Field(default_factory=dict)
    outcome_totals: dict[str, int] = Field(default_factory=dict)
    sources: list[RunStatsSource] = Field(default_factory=list)


class RetentionCandidate(BaseModel):
    """One run directory selected by a retention plan."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    run_kind: str
    run_dir: str
    reason: str
    manifest_sha256: str


class RetentionPlan(BaseModel):
    """Dry-run/applyable retention decision for run directories."""

    model_config = ConfigDict(extra="forbid")

    root: str
    keep_last: int
    kind_filter: list[str] = Field(default_factory=list)
    candidates: list[RetentionCandidate] = Field(default_factory=list)
    chronology_authority: str = "unsigned_manifest_created_at"
    requires_explicit_chronology_acceptance: bool = True
    applied: bool = False
    removed: int = 0


def retention_plan_public_projection(plan: RetentionPlan) -> dict[str, object]:
    """Return a portable CLI projection without workstation-absolute paths."""

    root = Path(plan.root).resolve()
    candidates: list[dict[str, object]] = []
    for candidate in plan.candidates:
        candidate_path = Path(candidate.run_dir).resolve(strict=False)
        try:
            relative = candidate_path.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError("retention candidate cannot be projected under root") from exc
        candidates.append({
            "run_id": candidate.run_id,
            "run_kind": candidate.run_kind,
            "run_dir": relative,
            "reason": candidate.reason,
            "manifest_sha256": candidate.manifest_sha256,
        })
    return {
        "root": "<run-root>",
        "keep_last": plan.keep_last,
        "kind_filter": plan.kind_filter,
        "candidates": candidates,
        "chronology_authority": plan.chronology_authority,
        "requires_explicit_chronology_acceptance": (
            plan.requires_explicit_chronology_acceptance
        ),
        "applied": plan.applied,
        "removed": plan.removed,
    }


def build_run_stats(root: Path) -> RunStats:
    records = [
        record
        for record in load_validated_run_records(root)
        if record.manifest.run_kind != "run_stats"
    ]
    validator_fingerprints = {
        record.validator_source_fingerprint for record in records
    }
    if len(validator_fingerprints) > 1:
        raise ValueError("validated run records came from mixed validator source snapshots")
    validator_fingerprint = (
        next(iter(validator_fingerprints))
        if validator_fingerprints
        else expectation_validator_fingerprint()
    )
    by_kind: Counter[str] = Counter()
    by_scenario: Counter[str] = Counter()
    by_target_or_model: Counter[str] = Counter()
    by_expectation_status: Counter[str] = Counter()
    outcome_totals: Counter[str] = Counter()
    sources: list[RunStatsSource] = []
    for record in records:
        manifest = record.manifest
        by_kind[manifest.run_kind] += 1
        if manifest.scenario:
            by_scenario[manifest.scenario] += 1
        label = manifest.target or manifest.model
        if label:
            by_target_or_model[label] += 1
        expectation_status: Literal["ok", "mismatch"] = (
            "ok" if record.expectations_ok else "mismatch"
        )
        by_expectation_status[expectation_status] += 1
        for key, value in manifest.outcomes.items():
            outcome_totals[key] += int(value)
        sources.append(RunStatsSource(
            run_id=manifest.run_id,
            manifest_sha256=record.manifest_sha256,
            run_kind=manifest.run_kind,
            scenario=manifest.scenario,
            target_or_model=label,
            outcomes=dict(sorted(manifest.outcomes.items())),
            expectation_status=expectation_status,
            expectation_mismatch_count=record.expectation_mismatch_count,
        ))
    return RunStats(
        root=root.resolve().name or ".",
        expectation_validation_scope="independently_recomputed_at_generation",
        validator_tool_version=__version__,
        corpus_version=CORPUS_VERSION,
        validator_source_fingerprint=validator_fingerprint,
        total_runs=len(records),
        by_kind=dict(sorted(by_kind.items())),
        by_scenario=dict(sorted(by_scenario.items())),
        by_target_or_model=dict(sorted(by_target_or_model.items())),
        by_expectation_status=dict(sorted(by_expectation_status.items())),
        outcome_totals=dict(sorted(outcome_totals.items())),
        sources=sources,
    )


def build_stats_md(stats: RunStats) -> str:
    lines = [
        "# Agentic Security Harness - run stats",
        "",
        f"Root: {markdown_code_span(stats.root)}",
        "",
        f"- Total runs: {stats.total_runs}",
    ]
    if stats.schema_version != "0.1":
        lines += [
            "- Expectation observation: "
            f"{markdown_code_span(stats.expectation_validation_scope)}",
            f"- Validator tool version: {markdown_code_span(stats.validator_tool_version)}",
            f"- Corpus version: {markdown_code_span(stats.corpus_version)}",
            "- Validator source fingerprint: "
            f"{markdown_code_span(stats.validator_source_fingerprint)}",
        ]
    lines += ["", "## By kind", ""]
    lines.extend(_table(stats.by_kind))
    lines += ["", "## By scenario", ""]
    lines.extend(_table(stats.by_scenario))
    lines += ["", "## By target/model", ""]
    lines.extend(_table(stats.by_target_or_model))
    lines += ["", "## Outcome totals", ""]
    lines.extend(_table(stats.outcome_totals))
    if stats.schema_version != "0.1":
        lines += ["", "## Behavioral expectation status", ""]
        lines.extend(_table(stats.by_expectation_status))
    lines.append("")
    return "\n".join(lines)


@atomic_evidence_bundle("out_dir")
def write_run_stats(stats: RunStats, out_dir: Path) -> dict[str, Path]:
    projection_errors = validate_run_stats_projection(stats)
    if projection_errors:
        raise ValueError(
            "refusing to persist invalid run-stats projection: "
            + "; ".join(projection_errors)
        )
    require_fresh_output_dir(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "run_stats.json"
    md_path = out_dir / "run_stats.md"
    write_text_artifact(
        json_path, json.dumps(stats.model_dump(mode="json"), indent=2) + "\n"
    )
    write_text_artifact(md_path, build_stats_md(stats))
    projection = run_stats_manifest_projection(stats)
    manifest = build_manifest(
        "run_stats",
        out_dir,
        target=str(projection["target"]),
        scenario=str(projection["scenario"]),
        outcomes=projection["outcomes"],  # type: ignore[arg-type]
        metadata=projection["metadata"],  # type: ignore[arg-type]
        artifacts=["run_stats.json", "run_stats.md"],
        created_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    manifest_path = write_run_manifest(out_dir, manifest)
    return {
        "run_stats_json": json_path,
        "run_stats_md": md_path,
        "run_index": manifest_path,
    }


def run_stats_manifest_projection(stats: RunStats) -> dict[str, object]:
    outcomes = {
        "total_runs": stats.total_runs,
        "source_manifests": len(stats.sources),
    }
    if stats.schema_version != "0.1":
        outcomes.update({
            "expectations_ok_runs": stats.by_expectation_status.get("ok", 0),
            "expectation_mismatch_runs": stats.by_expectation_status.get("mismatch", 0),
            "expectation_mismatches": sum(
                source.expectation_mismatch_count for source in stats.sources
            ),
        })
    metadata = {
        "artifact_validation": "current_content_bound",
        "origin_authentication": "unsigned",
    }
    if stats.schema_version != "0.1":
        metadata.update({
            "expectation_validation_scope": stats.expectation_validation_scope,
            "validator_tool_version": stats.validator_tool_version,
            "corpus_version": stats.corpus_version,
            "validator_source_fingerprint": stats.validator_source_fingerprint,
        })
    return {
        "target": "validated-run-history-statistics",
        "scenario": stats.root,
        "outcomes": outcomes,
        "metadata": metadata,
    }


def validate_run_stats_projection(stats: RunStats) -> list[str]:
    errors: list[str] = []
    if stats.schema_version == SCHEMA_VERSIONS["run_stats"]:
        if stats.expectation_validation_scope != "independently_recomputed_at_generation":
            errors.append("current stats require independently recomputed expectation status")
        if not stats.validator_tool_version or not stats.corpus_version:
            errors.append("current stats require validator and corpus version provenance")
        if (
            len(stats.validator_source_fingerprint) != 64
            or any(char not in "0123456789abcdef" for char in stats.validator_source_fingerprint)
        ):
            errors.append("current stats require a SHA-256 validator source fingerprint")
    elif stats.schema_version == "0.1":
        if (
            stats.expectation_validation_scope != "not_recorded"
            or stats.validator_tool_version
            or stats.corpus_version
            or stats.validator_source_fingerprint
        ):
            errors.append("legacy stats cannot claim expectation-validation provenance")
    if (
        not stats.root
        or stats.root.startswith("/")
        or "\\" in stats.root
        or (len(stats.root) >= 2 and stats.root[1] == ":")
        or ".." in Path(stats.root).parts
    ):
        errors.append("root must be a portable relative label")
    run_ids = [source.run_id for source in stats.sources]
    if len(run_ids) != len(set(run_ids)):
        errors.append("source run ids must be unique")
    by_kind: Counter[str] = Counter()
    by_scenario: Counter[str] = Counter()
    by_target_or_model: Counter[str] = Counter()
    by_expectation_status: Counter[str] = Counter()
    outcome_totals: Counter[str] = Counter()
    for source in stats.sources:
        if (
            len(source.manifest_sha256) != 64
            or any(char not in "0123456789abcdef" for char in source.manifest_sha256)
        ):
            errors.append(f"{source.run_id}: manifest_sha256 is not SHA-256")
        if source.artifact_validation != "current_content_bound":
            errors.append(f"{source.run_id}: artifact_validation must be current_content_bound")
        if source.origin_authentication != "unsigned":
            errors.append(f"{source.run_id}: origin_authentication must be unsigned")
        if source.expectation_status == "ok" and source.expectation_mismatch_count != 0:
            errors.append(f"{source.run_id}: ok expectation status cannot have mismatches")
        if source.expectation_status == "mismatch" and source.expectation_mismatch_count < 1:
            errors.append(f"{source.run_id}: mismatch status requires a positive count")
        if source.expectation_status == "not_recorded" and source.expectation_mismatch_count != 0:
            errors.append(f"{source.run_id}: unrecorded expectation status cannot have a count")
        if stats.schema_version == SCHEMA_VERSIONS["run_stats"]:
            if source.expectation_status == "not_recorded":
                errors.append(f"{source.run_id}: current stats require expectation status")
        elif stats.schema_version == "0.1" and source.expectation_status != "not_recorded":
            errors.append(f"{source.run_id}: legacy stats cannot claim expectation status")
        if any(value < 0 for value in source.outcomes.values()):
            errors.append(f"{source.run_id}: outcomes contain a negative count")
        by_kind[source.run_kind] += 1
        if source.scenario:
            by_scenario[source.scenario] += 1
        if source.target_or_model:
            by_target_or_model[source.target_or_model] += 1
        if source.expectation_status != "not_recorded":
            by_expectation_status[source.expectation_status] += 1
        outcome_totals.update(source.outcomes)
    expected = {
        "by_kind": dict(sorted(by_kind.items())),
        "by_scenario": dict(sorted(by_scenario.items())),
        "by_target_or_model": dict(sorted(by_target_or_model.items())),
        "by_expectation_status": dict(sorted(by_expectation_status.items())),
        "outcome_totals": dict(sorted(outcome_totals.items())),
    }
    if stats.total_runs != len(stats.sources):
        errors.append("total_runs does not match sources")
    for field, value in expected.items():
        if getattr(stats, field) != value:
            errors.append(f"{field} does not match sources")
    return errors


def build_retention_plan(
    root: Path, *, keep_last: int, kinds: list[str] | None = None
) -> RetentionPlan:
    if keep_last < 1:
        raise ValueError("keep_last must be >= 1")
    kind_filter = sorted(set(kinds or []))
    manifests = load_validated_run_manifests(root)
    if kind_filter:
        manifests = [(p, m) for p, m in manifests if m.run_kind in kind_filter]
    by_kind: dict[str, list[tuple[Path, RunManifest]]] = {}
    for path, manifest in manifests:
        by_kind.setdefault(manifest.run_kind, []).append((path, manifest))
    candidates: list[RetentionCandidate] = []
    for run_kind, items in sorted(by_kind.items()):
        ordered = sorted(
            items,
            key=lambda item: (
                item[1].created_at or "",
                item[1].run_id,
                item[0].parent.as_posix(),
            ),
        )
        stale = ordered[:-keep_last]
        for manifest_path, manifest in stale:
            candidates.append(
                RetentionCandidate(
                    run_id=manifest.run_id,
                    run_kind=run_kind,
                    run_dir=manifest_path.parent.resolve().as_posix(),
                    reason=(
                        f"outside last {keep_last} {run_kind} run(s) when ordered "
                        "by unsigned manifest created_at"
                    ),
                    manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                )
            )
    return RetentionPlan(
        root=root.resolve().as_posix(),
        keep_last=keep_last,
        kind_filter=kind_filter,
        candidates=candidates,
    )


def apply_retention_plan(
    plan: RetentionPlan,
    *,
    accept_unsigned_chronology: bool = False,
) -> RetentionPlan:
    if (
        plan.candidates
        and plan.requires_explicit_chronology_acceptance
        and not accept_unsigned_chronology
    ):
        raise ValueError(
            "retention chronology is unsigned; explicitly accept unsigned chronology "
            "before applying deletions"
        )
    if plan.applied or plan.removed:
        raise ValueError("retention plan has already been applied")
    if not Path(plan.root).is_absolute():
        raise ValueError("retention plan root must be an absolute path")
    root = Path(plan.root).resolve()
    candidate_dirs = [candidate.run_dir for candidate in plan.candidates]
    if len(candidate_dirs) != len(set(candidate_dirs)):
        raise ValueError("retention plan contains duplicate candidate directories")
    validated_dirs: list[Path] = []
    for candidate in plan.candidates:
        validated_dirs.append(_validate_retention_candidate(root, candidate))

    fresh_plan = build_retention_plan(
        root,
        keep_last=plan.keep_last,
        kinds=plan.kind_filter,
    )
    plan_projection = plan.model_dump(exclude={"applied", "removed"})
    fresh_projection = fresh_plan.model_dump(exclude={"applied", "removed"})
    if plan_projection != fresh_projection:
        raise ValueError("retention plan is stale or was not produced by the current scan")

    removed = 0
    for candidate, run_dir in zip(plan.candidates, validated_dirs, strict=True):
        # Narrow the validation/delete race for later candidates. Filesystem deletion is not
        # transactional, so callers must still exclude concurrent writers while applying.
        if _validate_retention_candidate(root, candidate) != run_dir:
            raise ValueError(f"retention candidate path changed: {candidate.run_dir}")
        shutil.rmtree(run_dir)
        removed += 1
    return plan.model_copy(update={"applied": True, "removed": removed})


def _validate_retention_candidate(
    root: Path,
    candidate: RetentionCandidate,
) -> Path:
    run_dir = Path(candidate.run_dir).resolve()
    if run_dir == root or root not in run_dir.parents:
        raise ValueError(f"refusing to remove path outside root: {candidate.run_dir}")
    manifest_path = run_dir / "run_index.json"
    if not manifest_path.is_file():
        raise ValueError(f"retention candidate manifest is missing: {candidate.run_dir}")
    current_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if current_hash != candidate.manifest_sha256:
        raise ValueError(f"retention candidate changed after planning: {candidate.run_dir}")
    validated = load_validated_run_manifests(run_dir)
    if len(validated) != 1 or validated[0][0].resolve() != manifest_path.resolve():
        raise ValueError(f"retention candidate no longer validates: {candidate.run_dir}")
    manifest = validated[0][1]
    if manifest.run_id != candidate.run_id or manifest.run_kind != candidate.run_kind:
        raise ValueError(f"retention candidate identity does not match: {candidate.run_dir}")
    return run_dir


def _table(values: dict[str, int]) -> list[str]:
    if not values:
        return ["| Name | Count |", "|---|---|", "| (none) | 0 |"]
    lines = ["| Name | Count |", "|---|---|"]
    for key, value in values.items():
        lines.append(f"| {markdown_code_span(key)} | {value} |")
    return lines
