"""Run-history statistics and retention helpers."""

from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.run_manifest import RunManifest, load_run_manifests
from agentic_security_harness.safe_io import write_text_artifact


class RunStats(BaseModel):
    """Aggregate metadata-only statistics over run manifests."""

    model_config = ConfigDict(extra="forbid")

    root: str
    total_runs: int = 0
    by_kind: dict[str, int] = Field(default_factory=dict)
    by_scenario: dict[str, int] = Field(default_factory=dict)
    by_target_or_model: dict[str, int] = Field(default_factory=dict)
    outcome_totals: dict[str, int] = Field(default_factory=dict)


class RetentionCandidate(BaseModel):
    """One run directory selected by a retention plan."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    run_kind: str
    run_dir: str
    reason: str


class RetentionPlan(BaseModel):
    """Dry-run/applyable retention decision for run directories."""

    model_config = ConfigDict(extra="forbid")

    root: str
    keep_last: int
    kind_filter: list[str] = Field(default_factory=list)
    candidates: list[RetentionCandidate] = Field(default_factory=list)
    applied: bool = False
    removed: int = 0


def build_run_stats(root: Path) -> RunStats:
    manifests = load_run_manifests(root)
    by_kind: Counter[str] = Counter()
    by_scenario: Counter[str] = Counter()
    by_target_or_model: Counter[str] = Counter()
    outcome_totals: Counter[str] = Counter()
    for _, manifest in manifests:
        by_kind[manifest.run_kind] += 1
        if manifest.scenario:
            by_scenario[manifest.scenario] += 1
        label = manifest.target or manifest.model
        if label:
            by_target_or_model[label] += 1
        for key, value in manifest.outcomes.items():
            outcome_totals[key] += int(value)
    return RunStats(
        root=root.as_posix(),
        total_runs=len(manifests),
        by_kind=dict(sorted(by_kind.items())),
        by_scenario=dict(sorted(by_scenario.items())),
        by_target_or_model=dict(sorted(by_target_or_model.items())),
        outcome_totals=dict(sorted(outcome_totals.items())),
    )


def build_stats_md(stats: RunStats) -> str:
    lines = [
        "# Agentic Security Harness - run stats",
        "",
        f"Root: `{stats.root}`",
        "",
        f"- Total runs: {stats.total_runs}",
        "",
        "## By kind",
        "",
    ]
    lines.extend(_table(stats.by_kind))
    lines += ["", "## By scenario", ""]
    lines.extend(_table(stats.by_scenario))
    lines += ["", "## By target/model", ""]
    lines.extend(_table(stats.by_target_or_model))
    lines += ["", "## Outcome totals", ""]
    lines.extend(_table(stats.outcome_totals))
    lines.append("")
    return "\n".join(lines)


def write_run_stats(stats: RunStats, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "run_stats.json"
    md_path = out_dir / "run_stats.md"
    write_text_artifact(
        json_path, json.dumps(stats.model_dump(mode="json"), indent=2) + "\n"
    )
    write_text_artifact(md_path, build_stats_md(stats))
    return {"run_stats_json": json_path, "run_stats_md": md_path}


def build_retention_plan(
    root: Path, *, keep_last: int, kinds: list[str] | None = None
) -> RetentionPlan:
    if keep_last < 1:
        raise ValueError("keep_last must be >= 1")
    kind_filter = sorted(set(kinds or []))
    manifests = load_run_manifests(root)
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
                    run_dir=manifest_path.parent.as_posix(),
                    reason=f"older than last {keep_last} {run_kind} run(s)",
                )
            )
    return RetentionPlan(
        root=root.as_posix(),
        keep_last=keep_last,
        kind_filter=kind_filter,
        candidates=candidates,
    )


def apply_retention_plan(plan: RetentionPlan) -> RetentionPlan:
    root = Path(plan.root).resolve()
    removed = 0
    for candidate in plan.candidates:
        run_dir = Path(candidate.run_dir).resolve()
        if run_dir == root or root not in run_dir.parents:
            raise ValueError(f"refusing to remove path outside root: {candidate.run_dir}")
        if (run_dir / "run_index.json").exists():
            shutil.rmtree(run_dir)
            removed += 1
    return plan.model_copy(update={"applied": True, "removed": removed})


def _table(values: dict[str, int]) -> list[str]:
    if not values:
        return ["| Name | Count |", "|---|---|", "| (none) | 0 |"]
    lines = ["| Name | Count |", "|---|---|"]
    for key, value in values.items():
        lines.append(f"| `{key}` | {value} |")
    return lines
