"""Ablation matrix for bounded local-swarm controls.

The local-swarm matrix proves that the full bounded contract blocks declared synthetic
attacks. This module answers the next reviewer question: which control is doing the
work, and what would become vulnerable if that control were removed?
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.local_swarm import (
    SWARM_SCENARIOS,
    SwarmScenarioId,
    evaluate_swarm_scenario,
)
from agentic_security_harness.run_manifest import build_manifest, write_run_manifest
from agentic_security_harness.safe_io import write_text_artifact
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS

ControlName = Literal[
    "payload_integrity",
    "label_provenance",
    "authority_non_expansion",
    "recipient_policy",
    "fail_closed_verifier",
    "memory_scope",
    "memory_ttl",
    "memory_trust",
    "memory_envelope_drift",
]

CONTROL_ORDER: tuple[ControlName, ...] = (
    "payload_integrity",
    "label_provenance",
    "authority_non_expansion",
    "recipient_policy",
    "fail_closed_verifier",
    "memory_scope",
    "memory_ttl",
    "memory_trust",
    "memory_envelope_drift",
)

_REASON_TO_CONTROL: dict[str, ControlName] = {
    "integrity_mismatch": "payload_integrity",
    "missing_provenance": "label_provenance",
    "label_loss": "label_provenance",
    "authority_expansion": "authority_non_expansion",
    "recipient_violation": "recipient_policy",
    "missing_envelope": "fail_closed_verifier",
    "verifier_error": "fail_closed_verifier",
    "scope_mismatch": "memory_scope",
    "read:ttl_expired_from_write_time": "memory_ttl",
    "trust_too_low": "memory_trust",
    "trust_precedence_violation": "memory_trust",
    "stored:allowed_recipients_expanded": "memory_envelope_drift",
    "stored:can_forward_weakened": "memory_envelope_drift",
    "read:allowed_recipients_expanded": "memory_envelope_drift",
    "read:data_class_downgraded": "memory_envelope_drift",
}


class SwarmAblationRow(BaseModel):
    """One scenario/control contribution row."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: SwarmScenarioId
    primary_control: ControlName
    blocked_reasons: list[str] = Field(default_factory=list)
    bounded_blocks_with_all_controls: bool
    vulnerable_if_control_removed: bool
    explanation: str


class SwarmAblationMetrics(BaseModel):
    """Aggregate ablation counters."""

    model_config = ConfigDict(extra="forbid")

    scenarios: int
    rows: int
    controls: int
    bounded_blocks: int
    vulnerable_when_primary_removed: int
    coverage_by_control: dict[str, int] = Field(default_factory=dict)


class SwarmAblationMatrix(BaseModel):
    """Machine-readable bounded-swarm ablation artifact."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSIONS["local_swarm_ablation"]
    run_kind: Literal["local_swarm_ablation"] = "local_swarm_ablation"
    created_at: str = ""
    metrics: SwarmAblationMetrics
    rows: list[SwarmAblationRow]
    claim_boundary: str = (
        "This deterministic ablation matrix maps each synthetic local-swarm block to "
        "the primary contract family that caught it. It is a control-attribution model, "
        "not a proof that removing the control is the only possible implementation bug."
    )


def build_local_swarm_ablation_matrix(*, created_at: str = "") -> SwarmAblationMatrix:
    """Build the deterministic control-attribution matrix."""

    rows = [_row_for_scenario(scenario_id) for scenario_id in SWARM_SCENARIOS]
    return SwarmAblationMatrix(
        created_at=created_at,
        metrics=_build_metrics(rows),
        rows=rows,
    )


def write_local_swarm_ablation_artifacts(
    out_dir: Path,
    matrix: SwarmAblationMatrix,
) -> list[Path]:
    """Write JSON, Markdown, and run manifest artifacts for the ablation matrix."""

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = write_text_artifact(
        out_dir / "local_swarm_ablation_matrix.json",
        json.dumps(matrix.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
    )
    md_path = write_text_artifact(
        out_dir / "local_swarm_ablation_matrix.md",
        render_local_swarm_ablation_matrix(matrix),
    )
    manifest = build_manifest(
        "local_swarm_ablation",
        out_dir,
        target="bounded-local-swarm",
        scenario="control-ablation-matrix",
        variants=sorted(matrix.metrics.coverage_by_control),
        repeats=1,
        outcomes={
            "scenarios": matrix.metrics.scenarios,
            "rows": matrix.metrics.rows,
            "bounded_blocks": matrix.metrics.bounded_blocks,
            "vulnerable_when_primary_removed": (matrix.metrics.vulnerable_when_primary_removed),
        },
        metadata={"controls": matrix.metrics.controls},
        artifacts=[
            "local_swarm_ablation_matrix.json",
            "local_swarm_ablation_matrix.md",
        ],
        created_at=matrix.created_at,
    )
    manifest_path = write_run_manifest(out_dir, manifest)
    return [json_path, md_path, manifest_path]


def render_local_swarm_ablation_matrix(matrix: SwarmAblationMatrix) -> str:
    """Render a concise Markdown report for reviewers."""

    lines = [
        "# Local Swarm Control Ablation Matrix",
        "",
        matrix.claim_boundary,
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Scenarios | {matrix.metrics.scenarios} |",
        f"| Rows | {matrix.metrics.rows} |",
        f"| Controls represented | {matrix.metrics.controls} |",
        f"| Bounded blocks with all controls | {matrix.metrics.bounded_blocks} |",
        (
            "| Vulnerable when primary control removed | "
            f"{matrix.metrics.vulnerable_when_primary_removed} |"
        ),
        "",
        "## Coverage By Control",
        "",
        "| Control | Rows |",
        "| --- | ---: |",
    ]
    for control in CONTROL_ORDER:
        if control in matrix.metrics.coverage_by_control:
            lines.append(f"| `{control}` | {matrix.metrics.coverage_by_control[control]} |")
    lines.extend(
        [
            "",
            "## Scenario Matrix",
            "",
            "| Scenario | Primary control | Reasons | Vulnerable if removed | Explanation |",
            "| --- | --- | --- | ---: | --- |",
        ]
    )
    for row in matrix.rows:
        reasons = ", ".join(row.blocked_reasons)
        lines.append(
            f"| `{row.scenario_id}` | `{row.primary_control}` | `{reasons}` | "
            f"{row.vulnerable_if_control_removed} | {row.explanation} |"
        )
    lines.extend(
        [
            "",
            "## Non-Claims",
            "",
            "- This matrix does not prove exhaustive attack coverage.",
            "- It does not model cryptographic signatures or production deployment.",
            "- A real implementation can have bugs outside these synthetic controls.",
            "",
        ]
    )
    return "\n".join(lines)


def _row_for_scenario(scenario_id: SwarmScenarioId) -> SwarmAblationRow:
    bounded = evaluate_swarm_scenario(scenario_id, "bounded_swarm")
    reasons = list(bounded.blocked_reasons)
    control = _primary_control(reasons)
    return SwarmAblationRow(
        scenario_id=scenario_id,
        primary_control=control,
        blocked_reasons=reasons,
        bounded_blocks_with_all_controls=bounded.verifier_blocked,
        vulnerable_if_control_removed=bounded.verifier_blocked,
        explanation=_explain(scenario_id, control),
    )


def _primary_control(reasons: list[str]) -> ControlName:
    for reason in reasons:
        if reason in _REASON_TO_CONTROL:
            return _REASON_TO_CONTROL[reason]
    return "fail_closed_verifier"


def _explain(scenario_id: SwarmScenarioId, control: ControlName) -> str:
    return (
        f"`{scenario_id}` is blocked by `{control}` in the bounded synthetic path; "
        "without that primary check the naive-swarm acceptance path is the modeled risk."
    )


def _build_metrics(rows: list[SwarmAblationRow]) -> SwarmAblationMetrics:
    controls = Counter(row.primary_control for row in rows)
    return SwarmAblationMetrics(
        scenarios=len({row.scenario_id for row in rows}),
        rows=len(rows),
        controls=len(controls),
        bounded_blocks=sum(1 for row in rows if row.bounded_blocks_with_all_controls),
        vulnerable_when_primary_removed=sum(1 for row in rows if row.vulnerable_if_control_removed),
        coverage_by_control={
            control: controls[control] for control in CONTROL_ORDER if control in controls
        },
    )
