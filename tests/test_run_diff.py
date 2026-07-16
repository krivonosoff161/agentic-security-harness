"""Tests for `ash diff-runs` and the run_diff artifacts."""

import json
import shutil
from pathlib import Path

import pytest

from agentic_security_harness import cli
from agentic_security_harness.run_diff import (
    RunDiff,
    _classify,
    _diff_md,
    _external_outcomes,
    diff_runs,
    write_run_diff,
)
from agentic_security_harness.validation import validate_path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _run(target: str, out: Path) -> Path:
    cli.main(["run", "--target", target, "--out", str(out)])
    return out


def test_diff_run_fixed(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    b = _run("protected-demo-agent", tmp_path / "b")
    diff = diff_runs(a, b)
    assert diff.kind == "run"
    assert diff.finding_fixed == 24
    assert diff.new_finding == 0 and diff.changed_status == 0
    assert all(e.change == "finding_fixed" for e in diff.entries)


def test_run_diff_markdown_neutralizes_untrusted_summary_and_note() -> None:
    payload = "value\n## forged\n![probe](https://example.invalid/p.gif)<img src=x>"
    diff = RunDiff(
        kind="external",
        left_label="left`label",
        right_label="right",
        left_summary={"model|name": payload},
        right_summary={"model|name": "safe"},
        note=payload,
    )

    rendered = _diff_md(diff)

    assert "\n## forged" not in rendered
    assert "![probe](" not in rendered
    assert r"\!\[probe\]" in rendered
    assert r"model\|name" in rendered
    assert "- Left: `` left`label ``" in rendered


def test_diff_run_unchanged(tmp_path: Path) -> None:
    # mock -> mock: every pattern is a finding on both sides -> unchanged_finding (not
    # stable_pass), and no fix/new finding is reported.
    a = _run("mock", tmp_path / "a")
    b = _run("mock", tmp_path / "b")
    diff = diff_runs(a, b)
    assert diff.unchanged_finding == 24
    assert diff.stable_pass == 0
    assert diff.finding_fixed == 0 and diff.new_finding == 0


def test_diff_run_stable_pass(tmp_path: Path) -> None:
    # protected -> protected: every pattern passes on both sides -> stable_pass.
    a = _run("protected-demo-agent", tmp_path / "a")
    b = _run("protected-demo-agent", tmp_path / "b")
    diff = diff_runs(a, b)
    assert diff.stable_pass == 24
    assert diff.unchanged_finding == 0
    assert all(e.change == "stable_pass" for e in diff.entries)


def test_diff_run_new_findings(tmp_path: Path) -> None:
    # protected (all pass) -> demo-agent (all finding): every pattern is "new_finding".
    a = _run("protected-demo-agent", tmp_path / "a")
    b = _run("demo-agent", tmp_path / "b")
    diff = diff_runs(a, b)
    assert diff.new_finding == 24
    assert all(e.change == "new_finding" for e in diff.entries)


def test_diff_incompatible_kinds(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    with pytest.raises(ValueError, match="same kind"):
        diff_runs(a, EXAMPLES / "external-demo-report")


def test_diff_external_unchanged(tmp_path: Path) -> None:
    # external-demo-report is all pass -> compared with itself every pattern is stable_pass.
    left = tmp_path / "left"
    right = tmp_path / "right"
    shutil.copytree(EXAMPLES / "external-demo-report", left)
    shutil.copytree(EXAMPLES / "external-demo-report", right)
    diff = diff_runs(left, right)
    assert diff.kind == "external"
    assert diff.new_finding == 0 and diff.finding_fixed == 0
    assert diff.stable_pass == len(diff.entries) > 0


# --- external label clarity (issue #29) ------------------------------------------------
#
# External runs surface pass/finding/flaky/inconclusive/error. A transition that touches a
# non-decisive status (inconclusive/error) must never be reported as a security fix or new
# finding. These tests build minimal external run dirs and assert the exact label.

_PID = "data_boundary_recipient_confusion"


def _ext_dir(path: Path, *, status: str) -> Path:
    """Write a minimal one-pattern external run directory in the given ``status``."""
    path.mkdir(parents=True, exist_ok=True)
    buckets = {
        "finding": "patterns_with_findings",
        "flaky": "flaky_patterns",
        "inconclusive": "inconclusive_patterns",
        "error": "error_patterns",
        "adapter_error": "error_patterns",
    }
    summary: dict = {
        "schema_version": "0.1",
        "patterns_with_findings": [],
        "flaky_patterns": [],
        "inconclusive_patterns": [],
        "error_patterns": [],
        "repeat_summaries": [{"pattern_id": _PID, "stability_status": status}],
    }
    if status in buckets:
        summary[buckets[status]] = [_PID]
    (path / "external_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    return path


def _ext_change(tmp_path: Path, left_status: str, right_status: str) -> str:
    del tmp_path  # classification unit tests do not manufacture trusted run bundles
    return _classify(True, True, left_status, right_status, "", "")


def test_external_finding_disappeared_is_fixed(tmp_path: Path) -> None:
    assert _ext_change(tmp_path, "finding", "pass") == "finding_fixed"


def test_external_finding_appeared_is_new(tmp_path: Path) -> None:
    assert _ext_change(tmp_path, "pass", "finding") == "new_finding"


def test_external_same_finding_is_unchanged(tmp_path: Path) -> None:
    assert _ext_change(tmp_path, "finding", "finding") == "unchanged_finding"


def test_external_pass_to_pass_is_stable_pass(tmp_path: Path) -> None:
    assert _ext_change(tmp_path, "pass", "pass") == "stable_pass"


def test_external_transition_matrix_is_explicit(tmp_path: Path) -> None:
    expected = {
        ("pass", "pass"): "stable_pass",
        ("pass", "finding"): "new_finding",
        ("finding", "pass"): "finding_fixed",
        ("finding", "finding"): "unchanged_finding",
    }
    non_decisive = ("flaky", "inconclusive", "error", "adapter_error")
    for status in non_decisive:
        expected[(status, status)] = (
            "stable_error" if status in {"error", "adapter_error"} else "stable_inconclusive"
        )
    expected[("error", "adapter_error")] = "stable_error"
    expected[("adapter_error", "error")] = "stable_error"

    statuses = ("pass", "finding", *non_decisive)
    for i, left_status in enumerate(statuses):
        for j, right_status in enumerate(statuses):
            expected_change = expected.get((left_status, right_status), "inconclusive_error_drift")
            actual = _ext_change(
                tmp_path / f"case_{i}_{j}",
                left_status,
                right_status,
            )
            assert actual == expected_change, (left_status, right_status)


def test_external_error_to_pass_is_drift_not_fixed(tmp_path: Path) -> None:
    # The issue #29 bug: error -> pass was mislabeled "fixed (finding -> pass)".
    assert _ext_change(tmp_path, "error", "pass") == "inconclusive_error_drift"


def test_external_adapter_error_to_pass_is_drift_not_fixed(tmp_path: Path) -> None:
    assert _ext_change(tmp_path, "adapter_error", "pass") == "inconclusive_error_drift"


def test_external_pass_to_error_is_drift_not_new(tmp_path: Path) -> None:
    assert _ext_change(tmp_path, "pass", "error") == "inconclusive_error_drift"


def test_external_pass_to_adapter_error_is_drift_not_new(tmp_path: Path) -> None:
    assert _ext_change(tmp_path, "pass", "adapter_error") == "inconclusive_error_drift"


def test_external_error_to_finding_is_drift_not_new(tmp_path: Path) -> None:
    assert _ext_change(tmp_path, "error", "finding") == "inconclusive_error_drift"


def test_external_inconclusive_to_pass_is_drift(tmp_path: Path) -> None:
    assert _ext_change(tmp_path, "inconclusive", "pass") == "inconclusive_error_drift"


def test_external_stable_error_and_inconclusive(tmp_path: Path) -> None:
    assert _ext_change(tmp_path, "error", "error") == "stable_error"
    assert _ext_change(tmp_path, "adapter_error", "adapter_error") == "stable_error"
    assert _ext_change(tmp_path, "inconclusive", "inconclusive") == "stable_inconclusive"
    # flaky on both sides is still "no conclusion", not a stable finding.
    assert _ext_change(tmp_path, "flaky", "flaky") == "stable_inconclusive"


def test_external_stability_status_adapter_error_without_error_bucket(tmp_path: Path) -> None:
    right = _ext_dir(tmp_path / "right", status="pass")
    summary = json.loads((right / "external_summary.json").read_text(encoding="utf-8"))
    summary["repeat_summaries"][0]["stability_status"] = "adapter_error"
    (right / "external_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    outcomes, _summary = _external_outcomes(right)
    right_status = outcomes[_PID][0]
    assert right_status == "adapter_error"
    assert _classify(True, True, "pass", right_status, "", "") == (
        "inconclusive_error_drift"
    )


def test_external_drift_counts_not_fix_or_new(tmp_path: Path) -> None:
    del tmp_path
    change = _classify(True, True, "error", "pass", "", "")
    assert change == "inconclusive_error_drift"
    assert change not in {"finding_fixed", "new_finding"}


def test_diff_matrix(tmp_path: Path) -> None:
    a = tmp_path / "ma"
    b = tmp_path / "mb"
    cli.main(["run-matrix", "--target", "demo-agent", "--scenario", "data-boundary",
              "--max-variants", "3", "--out", str(a)])
    cli.main(["run-matrix", "--target", "protected-demo-agent", "--scenario",
              "data-boundary", "--max-variants", "3", "--out", str(b)])
    diff = diff_runs(a, b)
    assert diff.kind == "matrix"
    # demo-agent fails data-boundary in every variant; protected passes -> finding_fixed.
    assert diff.finding_fixed > 0


def test_write_and_validate_diff(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    b = _run("protected-demo-agent", tmp_path / "b")
    diff = diff_runs(a, b)
    out = tmp_path / "diff"
    paths = write_run_diff(diff, out)
    assert paths["run_diff_json"].exists() and paths["run_diff_md"].exists()
    assert paths["run_index"].exists()
    data = json.loads(paths["run_diff_json"].read_text(encoding="utf-8"))
    # v0.3 writes source commitments plus explicit labels and deprecated aliases so old
    # consumers do not break while migrating away from ambiguous wording.
    assert data["finding_fixed"] == 24
    assert data["fixed"] == 24
    assert data["left_source"]["artifact_validation"] == "current_content_bound"
    assert data["left_source"]["origin_authentication"] == "unsigned"
    result = validate_path(out)
    assert result.ok, result.errors
    assert result.run_diff_dirs == ["diff"]


def test_validate_diff_bad_counts(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    b = _run("protected-demo-agent", tmp_path / "b")
    write_run_diff(diff_runs(a, b), tmp_path / "diff")
    data = json.loads((tmp_path / "diff" / "run_diff.json").read_text(encoding="utf-8"))
    data["finding_fixed"] = 999  # tamper
    (tmp_path / "diff" / "run_diff.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    result = validate_path(tmp_path / "diff")
    assert not result.ok
    assert any("change counts" in e for e in result.errors)


def test_diff_rejects_post_manifest_source_tampering(tmp_path: Path) -> None:
    left = _run("mock", tmp_path / "left")
    right = _run("protected-demo-agent", tmp_path / "right")
    traces = left / "traces.json"
    traces.write_text(traces.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(ValueError, match="cannot diff unvalidated artifacts"):
        diff_runs(left, right)


def test_validate_current_diff_rejects_markdown_projection_tamper(tmp_path: Path) -> None:
    left = _run("mock", tmp_path / "left")
    right = _run("protected-demo-agent", tmp_path / "right")
    out = tmp_path / "diff"
    write_run_diff(diff_runs(left, right), out)
    (out / "run_diff.md").write_text("# forged reviewer claim\n", encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert any("report projection mismatch" in error for error in result.errors)


def test_validate_legacy_run_diff_v01(tmp_path: Path) -> None:
    out = tmp_path / "legacy"
    out.mkdir()
    payload = {
        "schema_version": "0.1",
        "kind": "external",
        "left_label": "left",
        "right_label": "right",
        "fixed": 0,
        "new": 0,
        "changed": 1,
        "unchanged": 0,
        "only_left": 0,
        "only_right": 0,
        "entries": [
            {
                "pattern_id": "data_boundary_recipient_confusion",
                "control_family": "data_boundary",
                "left_status": "error",
                "right_status": "pass",
                "left_severity": "",
                "right_severity": "",
                "change": "changed",
            }
        ],
    }
    (out / "run_diff.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    (out / "run_diff.md").write_text("# legacy diff\n", encoding="utf-8")
    result = validate_path(out)
    assert result.ok, result.errors
    assert result.run_diff_dirs == ["legacy"]


def test_cli_diff_runs_success(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    b = _run("protected-demo-agent", tmp_path / "b")
    rc = cli.main(["diff-runs", "--left", str(a), "--right", str(b),
                   "--out", str(tmp_path / "diff")])
    assert rc == 0
    assert (tmp_path / "diff" / "run_diff.json").exists()


def test_cli_diff_runs_missing_dir(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    rc = cli.main(["diff-runs", "--left", str(a), "--right",
                   str(tmp_path / "nope"), "--out", str(tmp_path / "diff")])
    assert rc == 1


def test_cli_diff_runs_rejects_output_overlapping_source(tmp_path: Path) -> None:
    left = _run("mock", tmp_path / "left")
    right = _run("protected-demo-agent", tmp_path / "right")
    original_manifest = (left / "run_index.json").read_bytes()

    rc = cli.main([
        "diff-runs", "--left", str(left), "--right", str(right), "--out", str(left)
    ])

    assert rc == 1
    assert (left / "run_index.json").read_bytes() == original_manifest
    assert not (left / "run_diff.json").exists()


def test_cli_compare_models_rejects_invalid_source(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    shutil.copytree(EXAMPLES / "external-demo-report", left)
    shutil.copytree(EXAMPLES / "external-demo-report", right)
    summary_path = left / "external_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["total_checks"] = 999
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    out = tmp_path / "diff"

    rc = cli.main([
        "compare-models", "--left", str(left), "--right", str(right), "--out", str(out)
    ])

    assert rc == 1
    assert not out.exists()
