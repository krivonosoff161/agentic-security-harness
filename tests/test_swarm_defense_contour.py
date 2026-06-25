import json
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.swarm_defense_contour import (
    CONTROL_ORDER,
    build_defense_topologies,
    build_swarm_defense_contour,
    declared_defense_scenarios,
    write_swarm_defense_contour_artifacts,
)
from agentic_security_harness.validation import validate_path


def test_defense_contour_declares_four_core_scenarios() -> None:
    scenarios = declared_defense_scenarios()

    assert len(scenarios) == 4
    assert {item.scenario_id for item in scenarios} == {
        "semantic_parameter_drift",
        "propagation_to_chief",
        "consensus_laundering",
        "benign_boundary_leak",
    }
    assert all("chief_verifier" in item.required_controls for item in scenarios)
    assert all(item.first_bad_role for item in scenarios)


def test_defense_contour_covers_all_single_and_combined_topologies() -> None:
    topologies = build_defense_topologies()

    assert len(topologies) == 15
    assert sum(1 for item in topologies if len(item.scenarios) == 1) == 4
    assert sum(1 for item in topologies if len(item.scenarios) > 1) == 11
    assert any(
        item.scenarios
        == [
            "semantic_parameter_drift",
            "propagation_to_chief",
            "consensus_laundering",
            "benign_boundary_leak",
        ]
        for item in topologies
    )


def test_defense_contour_metrics_show_naive_fails_and_bounded_blocks() -> None:
    summary = build_swarm_defense_contour(created_at="")

    assert summary.metrics.scenarios == 4
    assert summary.metrics.topologies == 15
    assert summary.metrics.results == 15 * 12
    assert summary.metrics.naive_acceptances == 15
    assert summary.metrics.bounded_acceptances == 0
    assert summary.metrics.baseline_failure_rate == 1.0
    assert summary.metrics.bounded_failure_rate == 0.0
    assert summary.metrics.ablation_acceptances > 0
    assert summary.metrics.control_effect_rows == len(CONTROL_ORDER)
    assert summary.metrics.first_bad_role_counts


def test_defense_contour_ablation_reopens_required_controls() -> None:
    summary = build_swarm_defense_contour(created_at="")

    effects = {item.control_id: item for item in summary.control_effects}

    assert effects["chief_verifier"].required_by_topologies == 15
    assert effects["chief_verifier"].ablation_acceptances == 15
    assert effects["cross_worker_check"].required_by_topologies > 0
    assert effects["cross_worker_check"].ablation_acceptances == (
        effects["cross_worker_check"].required_by_topologies
    )
    assert all(item.bounded_acceptances == 0 for item in summary.control_effects)


def test_defense_contour_artifacts_validate_and_stay_sanitized(tmp_path: Path) -> None:
    out = tmp_path / "swarm-defense-contour"
    summary = build_swarm_defense_contour(created_at="")

    paths = write_swarm_defense_contour_artifacts(out, summary)
    result = validate_path(out)

    assert result.ok, result.errors
    assert result.swarm_defense_contour_dirs == ["swarm-defense-contour"]
    assert {path.name for path in paths} == {
        "swarm_defense_contour_summary.json",
        "swarm_defense_contour_report.md",
        "swarm_defense_contour_digest.json",
        "run_index.json",
    }
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "raw_prompt" not in text
        assert "raw_response" not in text
        assert "synthetic_canary" not in text


def test_defense_contour_public_validation_rejects_private_fields(
    tmp_path: Path,
) -> None:
    out = tmp_path / "swarm-defense-contour"
    write_swarm_defense_contour_artifacts(
        out,
        build_swarm_defense_contour(created_at=""),
    )
    raw = json.loads((out / "swarm_defense_contour_summary.json").read_text())
    raw["raw_transcript"] = "private"
    (out / "swarm_defense_contour_summary.json").write_text(
        json.dumps(raw),
        encoding="utf-8",
    )

    result = validate_path(out)

    assert not result.ok
    assert any(
        "raw/private fields" in item or "raw_transcript" in item
        for item in result.errors
    )


def test_cli_swarm_defense_contour_write_validates(tmp_path: Path) -> None:
    out = tmp_path / "contour"

    rc = cli.main(["swarm-defense-contour", "--write", "--out", str(out)])

    assert rc == 0
    assert (out / "swarm_defense_contour_summary.json").exists()
    assert validate_path(out).ok
