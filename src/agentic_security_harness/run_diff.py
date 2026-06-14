"""Compare two run directories of the same kind and emit a diff artifact.

Supports run-vs-run, matrix-vs-matrix, and external-vs-external. The diff is an
*artifact comparison* (what changed between two committed results), not a re-run and not a
certification. Per-pattern outcomes are read from the authoritative JSON artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.html_report import detect_kind
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS

# Any non-"pass" status is "finding-like" for diff purposes.
_PASS = "pass"


class RunDiffEntry(BaseModel):
    """One pattern's status on each side and how it changed."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    control_family: str = ""
    left_status: str = ""
    right_status: str = ""
    left_severity: str = ""
    right_severity: str = ""
    change: str  # fixed | new | changed | unchanged | only_left | only_right


class RunDiff(BaseModel):
    """Aggregated diff between two run directories of the same kind."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSIONS["run_diff"]
    kind: str
    left_label: str
    right_label: str
    left_summary: dict[str, str | int] = Field(default_factory=dict)
    right_summary: dict[str, str | int] = Field(default_factory=dict)
    fixed: int = 0
    new: int = 0
    changed: int = 0
    unchanged: int = 0
    only_left: int = 0
    only_right: int = 0
    entries: list[RunDiffEntry] = Field(default_factory=list)
    note: str = (
        "Artifact comparison only: what changed between two recorded runs. "
        "Not a re-run and not a certification."
    )


def _load(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _family(pattern_id: str) -> str:
    from agentic_security_harness.remediation import _FAMILY_MAP

    return _FAMILY_MAP.get(pattern_id, "provenance")


def _run_outcomes(run_dir: Path) -> tuple[dict[str, tuple[str, str]], dict[str, str | int]]:
    """For a plain run: pattern -> (status, severity). status is pass|finding."""
    traces = _load(run_dir / "traces.json") or []
    scorecard = _load(run_dir / "scorecard.json") or {}
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    out: dict[str, tuple[str, str]] = {}
    for trace in traces:
        pid = trace.get("pattern_id", "")
        findings = trace.get("findings") or []
        if findings:
            top = max(findings, key=lambda f: sev_rank.get(f.get("severity", ""), -1))
            out[pid] = ("finding", top.get("severity", ""))
        else:
            out[pid] = (_PASS, "")
    summary: dict[str, str | int] = {
        "target": scorecard.get("target_name", ""),
        "patterns": len(out),
    }
    return out, summary


def _matrix_outcomes(
    run_dir: Path,
) -> tuple[dict[str, tuple[str, str]], dict[str, str | int]]:
    """For a matrix run: pattern -> (status, ""). status is pass|finding|variant_sensitive."""
    matrix = _load(run_dir / "matrix.json") or {}
    s = matrix.get("summary", {})
    stable = set(s.get("stable_failures", []))
    sensitive = set(s.get("variant_sensitive_failures", []))
    out: dict[str, tuple[str, str]] = {}
    for pid in matrix.get("selected_pattern_ids", []):
        if pid in stable:
            out[pid] = ("finding", "")
        elif pid in sensitive:
            out[pid] = ("variant_sensitive", "")
        else:
            out[pid] = (_PASS, "")
    summary: dict[str, str | int] = {
        "target": matrix.get("target_name", ""),
        "scenario": matrix.get("scenario_id", ""),
        "variants": len(matrix.get("variants", [])),
    }
    return out, summary


def _external_outcomes(
    run_dir: Path,
) -> tuple[dict[str, tuple[str, str]], dict[str, str | int]]:
    """External run: pattern -> (status, ""). status: pass|finding|flaky|inconclusive|error."""
    summary_j = _load(run_dir / "external_summary.json") or {}
    config = _load(run_dir / "run_config.json") or {}
    findings = set(summary_j.get("patterns_with_findings", []))
    flaky = set(summary_j.get("flaky_patterns", []))
    inconclusive = set(summary_j.get("inconclusive_patterns", []))
    errors = set(summary_j.get("error_patterns", []))
    seen = {rs.get("pattern_id", "") for rs in summary_j.get("repeat_summaries", [])}
    out: dict[str, tuple[str, str]] = {}
    for pid in sorted(seen):
        if pid in findings:
            status = "finding"
        elif pid in flaky:
            status = "flaky"
        elif pid in errors:
            status = "error"
        elif pid in inconclusive:
            status = "inconclusive"
        else:
            status = _PASS
        out[pid] = (status, "")
    cfg_summary: dict[str, str | int] = {
        "model": config.get("model", ""),
        "endpoint": config.get("base_url_label", ""),
        "scenario": config.get("scenario_id", ""),
        "repeats": config.get("repeats", 0),
        "request_count": config.get("request_count", 0),
    }
    return out, cfg_summary


def _outcomes(
    kind: str, run_dir: Path
) -> tuple[dict[str, tuple[str, str]], dict[str, str | int]]:
    if kind == "matrix":
        return _matrix_outcomes(run_dir)
    if kind == "external":
        return _external_outcomes(run_dir)
    return _run_outcomes(run_dir)


def _label(run_dir: Path) -> str:
    manifest = _load(run_dir / "run_index.json")
    if isinstance(manifest, dict) and manifest.get("run_id"):
        return str(manifest["run_id"])
    return run_dir.name


def diff_runs(left_dir: Path, right_dir: Path) -> RunDiff:
    """Diff two run directories of the same kind. Raises ValueError if incompatible."""
    left_kind = detect_kind(left_dir)
    right_kind = detect_kind(right_dir)
    if left_kind != right_kind:
        raise ValueError(
            f"cannot diff a '{left_kind}' run against a '{right_kind}' run; "
            "diff-runs compares runs of the same kind (run/matrix/external)"
        )

    left_out, left_summary = _outcomes(left_kind, left_dir)
    right_out, right_summary = _outcomes(right_kind, right_dir)

    entries: list[RunDiffEntry] = []
    counts = {"fixed": 0, "new": 0, "changed": 0, "unchanged": 0,
              "only_left": 0, "only_right": 0}
    for pid in sorted(set(left_out) | set(right_out)):
        in_left, in_right = pid in left_out, pid in right_out
        ls, lsev = left_out.get(pid, ("", ""))
        rs, rsev = right_out.get(pid, ("", ""))
        if in_left and not in_right:
            change = "only_left"
        elif in_right and not in_left:
            change = "only_right"
        elif ls == _PASS and rs != _PASS:
            change = "new"
        elif ls != _PASS and rs == _PASS:
            change = "fixed"
        elif ls != rs or lsev != rsev:
            change = "changed"
        else:
            change = "unchanged"
        counts[change] += 1
        entries.append(RunDiffEntry(
            pattern_id=pid,
            control_family=_family(pid),
            left_status=ls,
            right_status=rs,
            left_severity=lsev,
            right_severity=rsev,
            change=change,
        ))

    return RunDiff(
        kind=left_kind,
        left_label=_label(left_dir),
        right_label=_label(right_dir),
        left_summary=left_summary,
        right_summary=right_summary,
        fixed=counts["fixed"],
        new=counts["new"],
        changed=counts["changed"],
        unchanged=counts["unchanged"],
        only_left=counts["only_left"],
        only_right=counts["only_right"],
        entries=entries,
    )


def _diff_md(diff: RunDiff) -> str:
    lines = [
        "# Agentic Security Harness - run diff",
        "",
        f"Kind: `{diff.kind}`",
        "",
        f"- Left: `{diff.left_label}`",
        f"- Right: `{diff.right_label}`",
        "",
        "## Summary",
        "",
        "| Change | Count |",
        "|---|---|",
        f"| Fixed (finding -> pass) | {diff.fixed} |",
        f"| New (pass -> finding) | {diff.new} |",
        f"| Changed (status/severity) | {diff.changed} |",
        f"| Unchanged | {diff.unchanged} |",
        f"| Only on left | {diff.only_left} |",
        f"| Only on right | {diff.only_right} |",
        "",
        "## Configuration",
        "",
        "| | Left | Right |",
        "|---|---|---|",
    ]
    keys = sorted(set(diff.left_summary) | set(diff.right_summary))
    for k in keys:
        lines.append(
            f"| {k} | {diff.left_summary.get(k, '')} | {diff.right_summary.get(k, '')} |"
        )
    changed = [e for e in diff.entries if e.change in ("fixed", "new", "changed")]
    if changed:
        lines += ["", "## Changed patterns", "",
                  "| Pattern | Family | Left | Right | Change |",
                  "|---|---|---|---|---|"]
        for e in changed:
            ls = f"{e.left_status}/{e.left_severity}" if e.left_severity else e.left_status
            rs = (
                f"{e.right_status}/{e.right_severity}"
                if e.right_severity else e.right_status
            )
            lines.append(
                f"| `{e.pattern_id}` | {e.control_family} | {ls} | {rs} | {e.change} |"
            )
    lines += ["", f"> {diff.note}", ""]
    return "\n".join(lines)


def write_run_diff(diff: RunDiff, out_dir: Path) -> dict[str, Path]:
    """Write run_diff.json and run_diff.md into ``out_dir`` (LF newlines)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "run_diff.json"
    md_path = out_dir / "run_diff.md"
    json_path.write_text(
        json.dumps(diff.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    md_path.write_text(_diff_md(diff), encoding="utf-8", newline="\n")
    return {"run_diff_json": json_path, "run_diff_md": md_path}
