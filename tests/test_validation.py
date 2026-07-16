import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import cli
from agentic_security_harness.models import ExploitTrace
from agentic_security_harness.validation import (
    ValidationResult,
    _validate_traces,
    validate_path,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

DETERMINISTIC_CAMPAIGN_EXAMPLES = (
    (
        "context-consent-sanitized",
        "context_consent_summary.json",
        "context_consent_report.md",
    ),
    (
        "tool-authority-sanitized",
        "tool_authority_summary.json",
        "tool_authority_report.md",
    ),
    (
        "rag-context-sanitized",
        "rag_context_summary.json",
        "rag_context_report.md",
    ),
    (
        "planner-task-sanitized",
        "planner_task_summary.json",
        "planner_task_report.md",
    ),
    (
        "memory-rehydration-sanitized",
        "memory_rehydration_summary.json",
        "memory_rehydration_report.md",
    ),
)


def _copy(name: str, tmp_path: Path) -> Path:
    dst = tmp_path / name
    shutil.copytree(EXAMPLES / name, dst)
    return dst


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _dump(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _has(result: ValidationResult, needle: str) -> bool:
    return any(needle in message for message in result.errors + result.expectation_mismatches)


def _rebind_manifest_artifact(run_dir: Path, artifact: str) -> None:
    manifest_path = run_dir / "run_index.json"
    manifest = _load(manifest_path)
    manifest["artifact_sha256"][artifact] = hashlib.sha256(
        (run_dir / artifact).read_bytes()
    ).hexdigest()
    _dump(manifest_path, manifest)


# ---- valid committed examples ----------------------------------------------------------


def test_valid_examples_pass() -> None:
    for name in (
        "demo-report",
        "demo-agent-report",
        "protected-demo-agent-report",
        "comparison-report",
        "handoff-toy-comparison",
        "context-consent-sanitized",
        "tool-authority-sanitized",
        "rag-context-sanitized",
        "planner-task-sanitized",
        "memory-rehydration-sanitized",
    ):
        result = validate_path(EXAMPLES / name)
        assert result.ok, result.errors


def test_validate_examples_root_ok() -> None:
    result = validate_path(EXAMPLES)
    assert result.ok
    assert len(result.report_dirs) == 7
    assert len(result.comparison_dirs) == 2
    assert len(result.external_dirs) == 1
    assert len(result.context_consent_campaign_dirs) == 1
    assert len(result.tool_authority_campaign_dirs) == 1
    assert len(result.rag_context_campaign_dirs) == 1
    assert len(result.planner_task_campaign_dirs) == 1
    assert len(result.memory_rehydration_campaign_dirs) == 1


def test_cli_validate_examples_returns_zero() -> None:
    assert cli.main(["validate", str(EXAMPLES)]) == 0


@pytest.mark.parametrize(
    ("example_name", "summary_name", "report_name"),
    DETERMINISTIC_CAMPAIGN_EXAMPLES,
)
def test_deterministic_campaign_rejects_embedded_corpus_redefinition(
    tmp_path: Path,
    example_name: str,
    summary_name: str,
    report_name: str,
) -> None:
    del report_name
    out = _copy(example_name, tmp_path)
    summary_path = out / summary_name
    summary = _load(summary_path)
    summary["cases"][0]["title"] += " redefined"
    _dump(summary_path, summary)

    result = validate_path(out)

    assert not result.ok
    assert _has(result, "cases do not match the shipped campaign corpus")


@pytest.mark.parametrize(
    ("example_name", "summary_name", "report_name"),
    DETERMINISTIC_CAMPAIGN_EXAMPLES,
)
def test_deterministic_campaign_rejects_report_projection_tamper(
    tmp_path: Path,
    example_name: str,
    summary_name: str,
    report_name: str,
) -> None:
    del summary_name
    out = _copy(example_name, tmp_path)
    report_path = out / report_name
    report_path.write_text(
        report_path.read_text(encoding="utf-8") + "\nTampered claim.\n",
        encoding="utf-8",
    )

    result = validate_path(out)

    assert not result.ok
    assert _has(result, "report projection mismatch")


@pytest.mark.parametrize(
    ("example_name", "summary_name", "report_name"),
    DETERMINISTIC_CAMPAIGN_EXAMPLES,
)
def test_deterministic_campaign_rejects_manifest_outcome_tamper(
    tmp_path: Path,
    example_name: str,
    summary_name: str,
    report_name: str,
) -> None:
    del summary_name, report_name
    out = _copy(example_name, tmp_path)
    manifest_path = out / "run_index.json"
    manifest = _load(manifest_path)
    manifest["outcomes"]["bounded_acceptances"] = 999
    _dump(manifest_path, manifest)

    result = validate_path(out)

    assert not result.ok
    assert _has(result, "outcomes does not match summary projection")


def test_no_false_positive_on_risk_reduction() -> None:
    # comparison.md literally contains "risk-reduction" / "Risk reduction".
    result = validate_path(EXAMPLES / "comparison-report")
    assert result.ok
    assert not any("forbidden" in err for err in result.errors)


def test_current_run_manifest_requires_every_authoritative_artifact(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert cli.main(["run", "--target", "demo-agent", "--out", str(out)]) == 0
    manifest_path = out / "run_index.json"
    manifest = _load(manifest_path)
    manifest["artifacts"].remove("traces.json")
    manifest["artifact_sha256"].pop("traces.json")
    _dump(manifest_path, manifest)

    result = validate_path(out)

    assert not result.ok
    assert _has(result, "authoritative artifacts are not content-bound")
    assert _has(result, "traces.json")


def test_current_run_manifest_rejects_unexpected_listed_artifact(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert cli.main(["run", "--target", "mock", "--out", str(out)]) == 0
    extra = out / "unrelated-generation.txt"
    extra.write_text("unrelated\n", encoding="utf-8")
    manifest_path = out / "run_index.json"
    manifest = _load(manifest_path)
    manifest["artifacts"].append(extra.name)
    manifest["artifact_sha256"][extra.name] = hashlib.sha256(extra.read_bytes()).hexdigest()
    _dump(manifest_path, manifest)

    result = validate_path(out)

    assert not result.ok
    assert _has(result, "unexpected artifacts for this bundle type")


def test_current_run_manifest_rejects_unmanifested_private_subtree(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert cli.main(["run", "--target", "mock", "--out", str(out)]) == 0
    private = out / "private" / "raw.json"
    private.parent.mkdir()
    private.write_text('{"raw": true}\n', encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert _has(result, "unmanifested files are not allowed")
    assert _has(result, "private/raw.json")


def test_current_run_manifest_outcomes_are_rebuilt_from_scorecard(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert cli.main(["run", "--target", "demo-agent", "--out", str(out)]) == 0
    manifest_path = out / "run_index.json"
    manifest = _load(manifest_path)
    manifest["outcomes"]["failed"] = 0
    _dump(manifest_path, manifest)

    result = validate_path(out)

    assert not result.ok
    assert _has(result, "outcomes does not match summary projection")


def test_current_comparison_manifest_binds_both_branches(tmp_path: Path) -> None:
    out = tmp_path / "comparison"
    assert (
        cli.main(
            [
                "compare",
                "--baseline",
                "demo-agent",
                "--protected",
                "protected-demo-agent",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    manifest_path = out / "run_index.json"
    manifest = _load(manifest_path)
    omitted = "protected/scorecard.json"
    manifest["artifacts"].remove(omitted)
    manifest["artifact_sha256"].pop(omitted)
    _dump(manifest_path, manifest)

    result = validate_path(out)

    assert not result.ok
    assert _has(result, "authoritative artifacts are not content-bound")
    assert _has(result, omitted)


def test_current_matrix_rebuilds_semantic_aggregates_after_rehash(tmp_path: Path) -> None:
    out = tmp_path / "matrix"
    assert (
        cli.main(
            [
                "run-matrix",
                "--target",
                "mock",
                "--scenario",
                "data-boundary",
                "--max-variants",
                "1",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    matrix_path = out / "matrix.json"
    matrix = _load(matrix_path)
    matrix["summary"]["failed_variants"] = 0
    _dump(matrix_path, matrix)
    _rebind_manifest_artifact(out, "matrix.json")

    result = validate_path(out)

    assert not result.ok
    assert _has(result, "summary does not match variants + traces")


def test_current_matrix_markdown_is_exact_after_rehash(tmp_path: Path) -> None:
    out = tmp_path / "matrix"
    assert (
        cli.main(
            [
                "run-matrix",
                "--target",
                "mock",
                "--scenario",
                "data-boundary",
                "--max-variants",
                "1",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    matrix_md = out / "matrix.md"
    matrix_md.write_text(
        matrix_md.read_text(encoding="utf-8") + "\nForged reviewer claim.\n",
        encoding="utf-8",
    )
    _rebind_manifest_artifact(out, "matrix.md")

    result = validate_path(out)

    assert not result.ok
    assert _has(result, "report projection mismatch")


# ---- invalid traces --------------------------------------------------------------------


def test_invalid_json_traces_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    (report / "traces.json").write_text("[ {", encoding="utf-8")
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "traces.json") and _has(result, "invalid JSON")


def test_traces_root_not_a_list_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    (report / "traces.json").write_text("{}", encoding="utf-8")
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "expected a JSON list")


def test_unknown_pattern_id_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["pattern_id"] = "totally_made_up_pattern"
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "not in corpus")


def test_missing_corpus_pattern_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data = [trace for trace in data if trace["pattern_id"] != "memory_poisoning_sanitized"]
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "missing corpus pattern")


def test_duplicate_pattern_id_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[1]["pattern_id"] = data[0]["pattern_id"]
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "duplicate pattern_id")


def test_duplicate_trace_id_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[1]["trace_id"] = data[0]["trace_id"]
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "duplicate trace_id")


def test_non_sequential_step_indices_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["steps"][1]["index"] = 5
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "not sequential")


def test_severity_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    # memory_poisoning_sanitized has corpus severity "medium".
    by_id = {t["pattern_id"]: t for t in data}
    by_id["memory_poisoning_sanitized"]["findings"][0]["severity"] = "low"
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "severity")


def test_missing_required_field_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    del data[0]["expected_vulnerable_behavior"]
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "expected_vulnerable_behavior")


def test_no_findings_on_baseline_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["findings"] = []
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "baseline target expects FAIL")


def test_valid_baseline_regression_is_evidence_not_integrity_failure() -> None:
    raw = _load(EXAMPLES / "demo-agent-report" / "traces.json")
    for item in raw:
        item["findings"] = []
    traces = [ExploitTrace.model_validate(item) for item in raw]
    result = ValidationResult()

    _validate_traces(
        traces,
        EXAMPLES / "demo-agent-report" / "traces.json",
        EXAMPLES,
        result,
    )

    assert result.integrity_ok
    assert not result.expectations_ok
    assert not result.ok
    assert len(result.expectation_mismatches) == len(traces)
    assert result.errors == []


# ---- invalid scorecard -----------------------------------------------------------------


def test_scorecard_total_traces_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "scorecard.json")
    data["total_traces"] = 999
    _dump(report / "scorecard.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "total_traces")


def test_scorecard_failed_passed_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "scorecard.json")
    data["failed_patterns"].remove("memory_poisoning_sanitized")
    data["passed_patterns"].append("memory_poisoning_sanitized")
    _dump(report / "scorecard.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "failed_patterns") or _has(result, "passed_patterns")


# ---- comparison ------------------------------------------------------------------------


def test_comparison_reduction_numbers_wrong_fails(tmp_path: Path) -> None:
    comp = _copy("comparison-report", tmp_path)
    text = (comp / "comparison.md").read_text(encoding="utf-8")
    (comp / "comparison.md").write_text(text.replace("(-24)", "(-23)"), encoding="utf-8")
    result = validate_path(comp)
    assert not result.ok
    # Pin the dedicated reduction-mismatch branch specifically (not just the rebuild check).
    assert _has(result, "reduction mismatch")


def test_comparison_missing_reduction_line_fails(tmp_path: Path) -> None:
    comp = _copy("comparison-report", tmp_path)
    text = (comp / "comparison.md").read_text(encoding="utf-8")
    kept = [ln for ln in text.splitlines() if "Findings reduced:" not in ln]
    (comp / "comparison.md").write_text("\n".join(kept) + "\n", encoding="utf-8")
    result = validate_path(comp)
    assert not result.ok
    assert _has(result, "Findings reduced")


def test_comparison_missing_protected_fails(tmp_path: Path) -> None:
    comp = _copy("comparison-report", tmp_path)
    shutil.rmtree(comp / "protected")
    result = validate_path(comp)
    assert not result.ok
    assert _has(result, "missing protected")


# ---- safety scan -----------------------------------------------------------------------


def test_forbidden_secret_marker_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["observed_behavior"] = "leaked key sk-ABCDEFGHIJ0123456789"
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "forbidden marker 'sk-'")


# ---- determinism -----------------------------------------------------------------------


def test_validation_is_deterministic(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "scorecard.json")
    data["total_traces"] = 3
    _dump(report / "scorecard.json", data)
    first = validate_path(report)
    second = validate_path(report)
    assert first.errors == second.errors
    assert first.warnings == second.warnings
    assert first.errors  # non-empty


def test_root_validation_is_deterministic() -> None:
    first = validate_path(EXAMPLES)
    second = validate_path(EXAMPLES)
    assert first.ok and second.ok
    assert first.report_dirs == second.report_dirs
    assert first.comparison_dirs == second.comparison_dirs
    assert first.errors == second.errors


def test_validation_reports_stale_remediation_without_mutating_files(tmp_path: Path) -> None:
    report = _copy("protected-demo-agent-report", tmp_path)
    (report / "remediation.json").write_text('{"stale": true}\n', encoding="utf-8")
    (report / "remediation.md").write_text("# stale remediation\n", encoding="utf-8")
    before = {
        path.relative_to(report).as_posix(): path.read_bytes()
        for path in report.rglob("*")
        if path.is_file()
    }

    result = validate_path(report)

    after = {
        path.relative_to(report).as_posix(): path.read_bytes()
        for path in report.rglob("*")
        if path.is_file()
    }
    assert not result.ok
    assert _has(result, "remediation.json: unexpected")
    assert _has(result, "remediation.md: unexpected")
    assert after == before


# ---- protected-target outcome rule -----------------------------------------------------


def test_protected_target_with_findings_fails(tmp_path: Path) -> None:
    report = _copy("protected-demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["findings"] = [
        {
            "code": "data_boundary",
            "severity": "high",
            "message": "injected",
            "broke_at": "agent_decision",
            "mitigation": "n/a",
        }
    ]
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "protected target should PASS")


def test_valid_protected_regression_is_evidence_not_integrity_failure() -> None:
    raw = _load(EXAMPLES / "demo-agent-report" / "traces.json")
    for item in raw:
        item["target"]["type"] = "protected_demo_agent"
    traces = [ExploitTrace.model_validate(item) for item in raw]
    result = ValidationResult()

    _validate_traces(
        traces,
        EXAMPLES / "demo-agent-report" / "traces.json",
        EXAMPLES,
        result,
    )

    assert result.integrity_ok
    assert not result.expectations_ok
    assert not result.ok
    assert len(result.expectation_mismatches) == len(traces)
    assert result.errors == []


# ---- target consistency (security: no single-trace relabel bypass) ---------------------


def test_mixed_target_names_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[1]["target"]["name"] = "OtherName"
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "mix multiple target names")


def test_mixed_target_types_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[1]["target"]["type"] = "protected_demo_agent"
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "mix multiple target types")


def test_relabeled_trace_cannot_hide_dropped_finding(tmp_path: Path) -> None:
    # Security regression guard: a baseline trace must not exempt itself from the
    # baseline-FAIL invariant by relabeling only its own target.type to a protected type.
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["findings"] = []  # drop the finding ...
    data[0]["target"]["type"] = "protected_demo_agent"  # ... and pose as protected
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "mix multiple target types")


# ---- trace-level corpus cross-checks ---------------------------------------------------


def test_broke_at_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    by_id = {t["pattern_id"]: t for t in data}
    by_id["memory_poisoning_sanitized"]["findings"][0]["broke_at"] = "wrong_place"
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "broke_at")


def test_graph_path_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["graph_path"] = ["wrong_node"]
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "graph_path")


def test_expected_behavior_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["expected_vulnerable_behavior"] = "tampered expectation"
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "expected_vulnerable_behavior")


def test_data_envelope_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    by_id = {t["pattern_id"]: t for t in data}
    by_id["data_boundary_recipient_confusion"]["data_envelope"]["can_forward"] = True
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "data_envelope")


def test_finding_code_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["findings"][0]["code"] = "wrong_category"
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "finding code")


# ---- scorecard recompute-and-compare ---------------------------------------------------


def test_scorecard_category_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "scorecard.json")
    cat = next(iter(data["findings_by_category"]))
    data["findings_by_category"][cat] += 1
    _dump(report / "scorecard.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "findings_by_category")


def test_scorecard_severity_dict_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "scorecard.json")
    sev = next(iter(data["findings_by_severity"]))
    data["findings_by_severity"][sev] += 1
    _dump(report / "scorecard.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "findings_by_severity")


def test_scorecard_pattern_not_in_corpus_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "scorecard.json")
    data["failed_patterns"].append("ghost_pattern")
    _dump(report / "scorecard.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "not in corpus")


# ---- summary recompute-and-compare -----------------------------------------------------


def test_summary_md_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    summ = report / "summary.md"
    text = summ.read_text(encoding="utf-8")
    assert "Total traces: 24" in text
    summ.write_text(text.replace("Total traces: 24", "Total traces: 23"), encoding="utf-8")
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "summary rebuilt")


# ---- missing-file / structural paths ---------------------------------------------------


def test_missing_scorecard_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    (report / "scorecard.json").unlink()
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "scorecard.json") and _has(result, "missing")


def test_missing_summary_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    (report / "summary.md").unlink()
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "summary.md") and _has(result, "missing")


def test_ambiguous_artifact_directory_cannot_hide_second_contract(
    tmp_path: Path,
) -> None:
    report = _copy("local-swarm-report", tmp_path)
    shutil.copy2(EXAMPLES / "demo-agent-report" / "traces.json", report / "traces.json")

    result = validate_path(report)

    assert not result.ok
    assert not result.integrity_ok
    assert _has(result, "ambiguous artifact directory")
    assert _has(result, "local_swarm") and _has(result, "report")


def test_empty_dir_warns_but_ok(tmp_path: Path) -> None:
    result = validate_path(tmp_path)
    assert result.ok
    assert result.warnings
    assert not result.errors


def test_missing_path_errors(tmp_path: Path) -> None:
    result = validate_path(tmp_path / "nope")
    assert not result.ok
    assert _has(result, "missing path")


def test_path_is_a_file_errors(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    result = validate_path(report / "traces.json")
    assert not result.ok
    assert _has(result, "not a directory")


# ---- additional forbidden markers ------------------------------------------------------


def test_forbidden_akia_marker_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["observed_behavior"] = "cred AKIAIOSFODNN7EXAMPLE"
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "forbidden marker 'AKIA'")


def test_forbidden_private_key_marker_fails(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["observed_behavior"] = "-----BEGIN RSA PRIVATE KEY-----"
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not result.ok
    assert _has(result, "PRIVATE KEY")


def test_secret_scan_no_false_positive_on_near_misses(tmp_path: Path) -> None:
    # Short tail, alnum-prefixed, and dashed-but-short tokens must all stay clean.
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["observed_behavior"] = (
        "task-sk-abc sk-ABCDEFGHIJ risksk-ABCDEFGHIJ0123456789 begin a private key"
    )
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert not any("forbidden" in err for err in result.errors)


# ---- honest-wording pins (no overclaiming) ---------------------------------------------


def test_secret_scan_wording_is_not_overclaiming(tmp_path: Path) -> None:
    report = _copy("demo-agent-report", tmp_path)
    data = _load(report / "traces.json")
    data[0]["observed_behavior"] = "leaked key sk-ABCDEFGHIJ0123456789"
    _dump(report / "traces.json", data)
    result = validate_path(report)
    assert any(
        "possible secret-shaped string" in err and "forbidden marker" in err
        for err in result.errors
    )
    blob = " ".join(result.errors + result.warnings)
    for bad in ("secure", "guaranteed", "SECRET DETECTED", "protected against"):
        assert bad not in blob


def test_cli_success_line_is_not_overclaiming(capsys: Any) -> None:
    rc = cli.main(["validate", str(EXAMPLES)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK: artifacts satisfy their applicable validation contracts" in out
    for bad in ("secure", "guaranteed", "SECRET DETECTED"):
        assert bad not in out


# ---- external run artifacts ------------------------------------------------------------


def test_validate_external_report_dir_ok() -> None:
    result = validate_path(EXAMPLES / "external-demo-report")
    assert result.ok, result.errors
    assert result.external_dirs == ["external-demo-report"]


def test_external_summary_count_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("external-demo-report", tmp_path)
    data = _load(report / "external_summary.json")
    data["total_repeats"] += 1
    _dump(report / "external_summary.json", data)

    result = validate_path(report)
    assert not result.ok
    assert _has(result, "total_repeats")


def test_external_result_unknown_pattern_fails(tmp_path: Path) -> None:
    report = _copy("external-demo-report", tmp_path)
    data = _load(report / "external_results.json")
    data[0]["pattern_id"] = "not_in_corpus"
    _dump(report / "external_results.json", data)

    result = validate_path(report)
    assert not result.ok
    assert _has(result, "pattern_id not in corpus")


def test_external_request_count_mismatch_fails(tmp_path: Path) -> None:
    report = _copy("external-demo-report", tmp_path)
    data = _load(report / "run_config.json")
    data["request_count"] = 999
    _dump(report / "run_config.json", data)

    result = validate_path(report)
    assert not result.ok
    assert _has(result, "request_count")


def test_external_findings_by_control_family_tamper_fails(tmp_path: Path) -> None:
    # Flip one result to a finding without updating the family aggregation.
    report = _copy("external-demo-report", tmp_path)
    results = _load(report / "external_results.json")
    results[0]["would_preserve_boundary"] = False
    results[0]["decision"] = "allow"
    results[0]["deterministic_cross_check"] = "finding"
    results[0]["cross_check_reason"] = "tampered finding"
    _dump(report / "external_results.json", results)
    summary = _load(report / "external_summary.json")
    # Update some fields but deliberately leave findings_by_control_family wrong.
    summary["patterns_with_findings"] = [results[0]["pattern_id"]]
    summary["findings_by_pattern"] = {results[0]["pattern_id"]: 1}
    summary["findings_by_control_family"] = {}  # tampered: should be data_boundary:1
    _dump(report / "external_summary.json", summary)

    result = validate_path(report)
    assert not result.ok
    assert _has(result, "findings_by_control_family")


def test_external_missing_run_config_fails(tmp_path: Path) -> None:
    report = _copy("external-demo-report", tmp_path)
    (report / "run_config.json").unlink()

    result = validate_path(report)
    assert not result.ok
    assert _has(result, "run_config.json")


def test_external_missing_report_md_fails(tmp_path: Path) -> None:
    report = _copy("external-demo-report", tmp_path)
    (report / "external_report.md").unlink()

    result = validate_path(report)
    assert not result.ok
    assert _has(result, "external_report.md")


def test_external_report_md_has_reproduce_section() -> None:
    md = (EXAMPLES / "external-demo-report" / "external_report.md").read_text(encoding="utf-8")
    assert "## How to reproduce / validate" in md
    assert "ash validate" in md


def test_external_report_md_missing_section_fails(tmp_path: Path) -> None:
    report = _copy("external-demo-report", tmp_path)
    md = report / "external_report.md"
    text = md.read_text(encoding="utf-8").replace("## Control recommendations", "## Something else")
    md.write_text(text, encoding="utf-8")

    result = validate_path(report)
    assert not result.ok
    assert _has(result, "Control recommendations")
