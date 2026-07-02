import json
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.tool_authority_campaign import (
    build_tool_authority_campaign,
    declared_tool_authority_cases,
    declared_tool_authority_controls,
    render_tool_authority_summary,
    write_tool_authority_artifacts,
)
from agentic_security_harness.validation import validate_path


def test_tool_authority_cases_define_sixth_boundary_family() -> None:
    cases = declared_tool_authority_cases()
    controls = declared_tool_authority_controls()

    assert len(cases) == 6
    assert len({case.case_id for case in cases}) == len(cases)
    assert len({case.scenario_id for case in cases}) == len(cases)
    assert all(case.required_controls for case in cases)
    assert {control.control_id for control in controls} == {
        control for case in cases for control in case.required_controls
    }


def test_tool_authority_metrics_are_deterministic() -> None:
    summary = build_tool_authority_campaign(created_at="")
    metrics = summary.metrics

    assert metrics.cases == 6
    assert metrics.controls == 8
    assert metrics.pressure_axes == 7
    assert metrics.deterministic_rows == 66
    assert metrics.control_effect_rows == 8
    assert metrics.naive_acceptances == 6
    assert metrics.bounded_acceptances == 0
    assert metrics.ablation_acceptances == 23
    assert metrics.benign_acceptances == 6
    assert metrics.benign_false_blocks == 0
    assert metrics.control_attribution_rate == 1.0


def test_tool_authority_ablation_attributes_controls() -> None:
    summary = build_tool_authority_campaign(created_at="")
    effects = {effect.control_id: effect for effect in summary.control_effects}

    expected = {
        "source_provenance": 6,
        "authority_origin_gate": 5,
        "instruction_data_split": 3,
        "schema_pin": 1,
        "capability_binding": 3,
        "downstream_revalidation": 3,
        "recovery_policy_gate": 1,
        "metric_replay": 1,
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


def test_tool_authority_rows_preserve_benign_path() -> None:
    summary = build_tool_authority_campaign(created_at="")
    rows = summary.deterministic_results

    assert all(
        not row.risky_action_allowed for row in rows if row.mode == "bounded"
    )
    assert all(row.benign_passed for row in rows if row.mode == "benign")
    assert all(
        row.verifier_decision == "allow" for row in rows if row.mode == "benign"
    )
    assert all(row.tool_output_fingerprint for row in rows)


def test_tool_authority_artifacts_validate_and_stay_sanitized(tmp_path: Path) -> None:
    out = tmp_path / "tool-authority"
    summary = build_tool_authority_campaign(created_at="")

    paths = write_tool_authority_artifacts(out, summary)
    result = validate_path(out)

    assert result.ok, result.errors
    assert result.tool_authority_campaign_dirs == ["tool-authority"]
    assert {path.name for path in paths} == {
        "tool_authority_summary.json",
        "tool_authority_report.md",
        "tool_authority_digest.json",
        "run_index.json",
    }
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert '"raw_prompt"' not in text
        assert '"raw_response"' not in text
        assert '"real_tool_call"' not in text
        assert ".internal" not in text


def test_tool_authority_public_validation_rejects_private_artifact(
    tmp_path: Path,
) -> None:
    out = tmp_path / "tool-authority"
    write_tool_authority_artifacts(out, build_tool_authority_campaign(created_at=""))
    (out / "tool_authority_private.json").write_text(
        json.dumps({"raw_tool_output": "private calculation notes"}),
        encoding="utf-8",
    )

    result = validate_path(out)

    assert not result.ok
    assert any("private tool-authority artifact" in error for error in result.errors)


def test_tool_authority_report_contains_non_claims() -> None:
    report = render_tool_authority_summary(build_tool_authority_campaign(created_at=""))

    assert "Tool Authority Campaign" in report
    assert "Control Ablation Matrix" in report
    assert "No local or external models are called." in report
    assert "not proof that a deployed tool-using agent is safe" in report


def test_tool_authority_cli_write(tmp_path: Path) -> None:
    out = tmp_path / "tool-authority"

    rc = cli.main(["tool-authority-campaign", "--write", "--out", str(out)])

    assert rc == 0
    data = json.loads((out / "tool_authority_summary.json").read_text())
    assert data["metrics"]["bounded_acceptances"] == 0
    assert validate_path(out).ok
