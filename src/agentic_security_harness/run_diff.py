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
from agentic_security_harness.safe_io import write_text_artifact
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS

_PASS = "pass"

# Statuses that are neither a clean pass nor a confirmed finding. A weak/local model that
# errors, times out, or contradicts itself produces these. They are *not* evidence that the
# boundary held or broke, so a transition that touches one of them must never be reported as
# a security fix or a new finding. (External runs surface these; run/matrix kinds do not.)
_NON_DECISIVE = {"flaky", "inconclusive", "error", "adapter_error"}

# Ordered change vocabulary. Two groups:
#   decisive   - both sides are a clean pass or a confirmed finding;
#   non-decisive - at least one side is inconclusive/error (no security conclusion);
#   coverage   - the pattern is present on only one side.
# Each label is unambiguous on its own so an external-run reviewer never has to guess
# whether "fixed" meant "finding -> pass" or "error -> pass" (see issue #29).
CHANGE_CLASSES: tuple[str, ...] = (
    "finding_fixed",            # finding -> pass
    "new_finding",              # pass -> finding
    "changed_status",           # finding <-> finding, status or severity moved
    "unchanged_finding",        # finding -> same finding
    "stable_pass",              # pass -> pass
    "inconclusive_error_drift",  # non-decisive on a side; not a fix or new finding
    "stable_inconclusive",      # inconclusive/flaky -> same (still no conclusion)
    "stable_error",             # error -> error
    "only_left",                # pattern only in the left run
    "only_right",               # pattern only in the right run
)

CHANGE_MEANINGS: dict[str, str] = {
    "finding_fixed": "finding -> pass",
    "new_finding": "pass -> finding",
    "changed_status": "finding <-> finding, status/severity moved",
    "unchanged_finding": "finding -> same finding",
    "stable_pass": "pass -> pass",
    "inconclusive_error_drift": (
        "inconclusive/adapter_error/error on a side; not a fix or new finding"
    ),
    "stable_inconclusive": "inconclusive/flaky -> same (no conclusion either side)",
    "stable_error": "adapter_error/error -> adapter_error/error",
    "only_left": "pattern only in the left run",
    "only_right": "pattern only in the right run",
}


def _classify(
    in_left: bool, in_right: bool, ls: str, rs: str, lsev: str, rsev: str
) -> str:
    """Map a per-pattern (left, right) status pair to one change label.

    The decisive labels (finding_fixed/new_finding) are reserved for pass<->finding
    transitions between two *decisive* statuses. Anything touching a non-decisive status
    falls into the inconclusive/error group so it cannot be read as a security change.
    """
    if in_left and not in_right:
        return "only_left"
    if in_right and not in_left:
        return "only_right"
    if ls in _NON_DECISIVE or rs in _NON_DECISIVE:
        if ls == rs:
            return "stable_error" if ls in {"error", "adapter_error"} else "stable_inconclusive"
        return "inconclusive_error_drift"
    l_pass, r_pass = ls == _PASS, rs == _PASS
    if l_pass and r_pass:
        return "stable_pass"
    if l_pass and not r_pass:
        return "new_finding"
    if not l_pass and r_pass:
        return "finding_fixed"
    if ls != rs or lsev != rsev:
        return "changed_status"
    return "unchanged_finding"


class RunDiffEntry(BaseModel):
    """One pattern's status on each side and how it changed (see ``CHANGE_CLASSES``)."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    control_family: str = ""
    left_status: str = ""
    right_status: str = ""
    left_severity: str = ""
    right_severity: str = ""
    change: str  # one of CHANGE_CLASSES


class RunDiff(BaseModel):
    """Aggregated diff between two run directories of the same kind."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSIONS["run_diff"]
    kind: str
    left_label: str
    right_label: str
    left_summary: dict[str, str | int] = Field(default_factory=dict)
    right_summary: dict[str, str | int] = Field(default_factory=dict)
    finding_fixed: int = 0
    new_finding: int = 0
    changed_status: int = 0
    unchanged_finding: int = 0
    stable_pass: int = 0
    inconclusive_error_drift: int = 0
    stable_inconclusive: int = 0
    stable_error: int = 0
    only_left: int = 0
    only_right: int = 0
    # Deprecated v0.1-compatible aliases. Kept in v0.2 so older consumers that read only
    # the four coarse counters do not break while reviewers migrate to the explicit labels.
    fixed: int = 0
    new: int = 0
    changed: int = 0
    unchanged: int = 0
    entries: list[RunDiffEntry] = Field(default_factory=list)
    note: str = (
        "Artifact comparison only: what changed between two recorded runs. "
        "inconclusive/error are not a pass and not a finding, so they never count as a "
        "fix or a new finding. Not a re-run and not a certification."
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
    """External run: pattern -> (status, "").

    Status is one of pass|finding|flaky|inconclusive|adapter_error|error. Older
    artifacts only expose ``error_patterns``; newer summaries may also carry the
    aggregate ``stability_status`` per pattern.
    """
    summary_j = _load(run_dir / "external_summary.json") or {}
    config = _load(run_dir / "run_config.json") or {}
    findings = set(summary_j.get("patterns_with_findings", []))
    flaky = set(summary_j.get("flaky_patterns", []))
    inconclusive = set(summary_j.get("inconclusive_patterns", []))
    errors = set(summary_j.get("error_patterns", []))
    repeat_summaries = summary_j.get("repeat_summaries", [])
    seen = {rs.get("pattern_id", "") for rs in repeat_summaries}
    stability_by_pattern = {
        rs.get("pattern_id", ""): rs.get("stability_status", "")
        for rs in repeat_summaries
        if rs.get("pattern_id")
    }
    out: dict[str, tuple[str, str]] = {}
    for pid in sorted(seen):
        if pid in findings:
            status = "finding"
        elif pid in flaky:
            status = "flaky"
        elif pid in errors:
            status = "adapter_error"
        elif pid in inconclusive:
            status = "inconclusive"
        elif stability_by_pattern.get(pid) == "adapter_error":
            status = "adapter_error"
        elif stability_by_pattern.get(pid) == "stable_finding":
            status = "finding"
        elif stability_by_pattern.get(pid) == "flaky":
            status = "flaky"
        elif stability_by_pattern.get(pid) == "inconclusive":
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
    counts = {c: 0 for c in CHANGE_CLASSES}
    for pid in sorted(set(left_out) | set(right_out)):
        in_left, in_right = pid in left_out, pid in right_out
        ls, lsev = left_out.get(pid, ("", ""))
        rs, rsev = right_out.get(pid, ("", ""))
        change = _classify(in_left, in_right, ls, rs, lsev, rsev)
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
        finding_fixed=counts["finding_fixed"],
        new_finding=counts["new_finding"],
        changed_status=counts["changed_status"],
        unchanged_finding=counts["unchanged_finding"],
        stable_pass=counts["stable_pass"],
        inconclusive_error_drift=counts["inconclusive_error_drift"],
        stable_inconclusive=counts["stable_inconclusive"],
        stable_error=counts["stable_error"],
        only_left=counts["only_left"],
        only_right=counts["only_right"],
        fixed=counts["finding_fixed"],
        new=counts["new_finding"],
        changed=counts["changed_status"] + counts["inconclusive_error_drift"],
        unchanged=(
            counts["unchanged_finding"] + counts["stable_pass"]
            + counts["stable_inconclusive"] + counts["stable_error"]
        ),
        entries=entries,
    )


# Changes worth listing per-pattern: real security movement plus inconclusive/error drift
# (the case issue #29 cares about). The "stable_*" and "only_*" classes are summary-only.
_NOTEWORTHY = ("finding_fixed", "new_finding", "changed_status", "inconclusive_error_drift")


def _diff_md(diff: RunDiff) -> str:
    counts = {c: getattr(diff, c) for c in CHANGE_CLASSES}
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
        "Decisive labels (`finding_fixed` / `new_finding`) describe `pass` <-> `finding` "
        "moves only. `inconclusive`, `adapter_error`, and `error` are not a pass and not "
        "a finding, so a side that is non-decisive is reported as drift, never as a fix "
        "or a new finding.",
        "",
        "| Change | Meaning | Count |",
        "|---|---|---|",
    ]
    lines += [f"| `{c}` | {CHANGE_MEANINGS[c]} | {counts[c]} |" for c in CHANGE_CLASSES]
    lines += [
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
    changed = [e for e in diff.entries if e.change in _NOTEWORTHY]
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
    write_text_artifact(
        json_path,
        json.dumps(diff.model_dump(mode="json"), indent=2) + "\n",
    )
    write_text_artifact(md_path, _diff_md(diff))
    return {"run_diff_json": json_path, "run_diff_md": md_path}
