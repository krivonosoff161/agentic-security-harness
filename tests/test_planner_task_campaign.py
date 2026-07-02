import json
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.planner_task_campaign import (
    build_planner_task_campaign,
    declared_planner_task_cases,
    declared_planner_task_controls,
    render_planner_task_summary,
    write_planner_task_artifacts,
)
from agentic_security_harness.validation import validate_path


def test_planner_task_cases_define_agentic_decomposition_family() -> None:
    cases = declared_planner_task_cases()
    controls = declared_planner_task_controls()

    assert len(cases) == 7
    assert len({case.case_id for case in cases}) == len(cases)
    assert len({case.scenario_id for case in cases}) == len(cases)
    assert all(len(case.propagation_path) >= 4 for case in cases)
    assert all(case.no_red_flag_path for case in cases)
    assert all(case.required_controls for case in cases)
    assert {control.control_id for control in controls} == {
        control for case in cases for control in case.required_controls
    }


def test_planner_task_metrics_are_deterministic() -> None:
    summary = build_planner_task_campaign(created_at="")
    metrics = summary.metrics

    assert metrics.cases == 7
    assert metrics.controls == 10
    assert metrics.pressure_axes == 9
    assert metrics.deterministic_rows == 91
    assert metrics.control_effect_rows == 10
    assert metrics.propagation_paths == 7
    assert metrics.naive_acceptances == 7
    assert metrics.bounded_acceptances == 0
    assert metrics.ablation_acceptances == 32
    assert metrics.benign_acceptances == 7
    assert metrics.benign_false_blocks == 0
    assert metrics.control_attribution_rate == 1.0


def test_planner_task_ablation_attributes_controls() -> None:
    summary = build_planner_task_campaign(created_at="")
    effects = {effect.control_id: effect for effect in summary.control_effects}

    expected = {
        "input_source_provenance": 5,
        "current_user_intent_anchor": 5,
        "consent_receipt_binding": 3,
        "task_authority_gate": 7,
        "subtask_source_inheritance": 6,
        "tool_output_data_boundary": 1,
        "retrieval_evidence_label": 1,
        "handoff_revalidation": 1,
        "batch_task_isolation": 1,
        "dependency_order_gate": 2,
    }
    assert {
        control: effect.required_by_cases for control, effect in effects.items()
    } == expected
    assert {
        control: effect.ablation_acceptances for control, effect in effects.items()
    } == expected
    assert all(effect.bounded_acceptances == 0 for effect in effects.values())
    assert all(
        effect.blocked_by_full_contract == effect.required_by_cases
        for effect in effects.values()
    )


def test_planner_task_rows_preserve_benign_path() -> None:
    summary = build_planner_task_campaign(created_at="")
    rows = summary.deterministic_results

    assert all(
        not row.unsafe_chain_allowed for row in rows if row.mode == "bounded"
    )
    assert all(row.benign_passed for row in rows if row.mode == "benign")
    assert all(
        row.verifier_decision == "allow" for row in rows if row.mode == "benign"
    )
    assert all(row.context_fingerprint for row in rows)
    assert all(row.propagation_steps_observed >= 4 for row in rows)


def test_planner_task_artifacts_validate_and_stay_sanitized(tmp_path: Path) -> None:
    out = tmp_path / "planner-task"
    summary = build_planner_task_campaign(created_at="")

    paths = write_planner_task_artifacts(out, summary)
    result = validate_path(out)

    assert result.ok, result.errors
    assert result.planner_task_campaign_dirs == ["planner-task"]
    assert {path.name for path in paths} == {
        "planner_task_summary.json",
        "planner_task_report.md",
        "planner_task_digest.json",
        "run_index.json",
    }
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert '"raw_prompt"' not in text
        assert '"raw_response"' not in text
        assert ".internal" not in text
    digest = json.loads((out / "planner_task_digest.json").read_text())
    assert digest["live_planners_present"] is False


def test_planner_task_public_validation_rejects_private_artifact(
    tmp_path: Path,
) -> None:
    out = tmp_path / "planner-task"
    write_planner_task_artifacts(out, build_planner_task_campaign(created_at=""))
    (out / "planner_task_private.json").write_text(
        json.dumps({"private_payload_chain": "private calculation notes"}),
        encoding="utf-8",
    )

    result = validate_path(out)

    assert not result.ok
    assert any("private planner task artifact" in error for error in result.errors)


def test_planner_task_report_contains_agentic_non_claims() -> None:
    report = render_planner_task_summary(build_planner_task_campaign(created_at=""))

    assert "Planner Task Authority Campaign" in report
    assert "Attacker Model" in report
    assert "Control Ablation Matrix" in report
    assert "No local or external models are called." in report
    assert "not proof that a deployed planning agent is safe" in report


def test_planner_task_cli_write(tmp_path: Path) -> None:
    out = tmp_path / "planner-task"

    rc = cli.main(["planner-task-campaign", "--write", "--out", str(out)])

    assert rc == 0
    data = json.loads((out / "planner_task_summary.json").read_text())
    assert data["metrics"]["bounded_acceptances"] == 0
    assert validate_path(out).ok
