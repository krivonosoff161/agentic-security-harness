import hashlib
import json
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.swarm_defense_contour import (
    CONTROL_ORDER,
    _build_control_effects,
    _build_metrics,
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


def test_defense_contour_routes_every_public_artifact_through_redaction(
    tmp_path: Path,
) -> None:
    out = tmp_path / "swarm-defense-contour-redaction"
    marker = "sk-" + ("A" * 20)
    summary = build_swarm_defense_contour(created_at=marker)

    paths = write_swarm_defense_contour_artifacts(out, summary)

    assert marker not in "\n".join(path.read_text(encoding="utf-8") for path in paths)
    assert "sk-[REDACTED]" in (out / "swarm_defense_contour_summary.json").read_text(
        encoding="utf-8"
    )


def test_valid_bounded_contour_regression_is_expectation_failure_only(
    tmp_path: Path,
) -> None:
    out = tmp_path / "swarm-defense-contour-regression"
    summary = build_swarm_defense_contour(created_at="")
    row = next(item for item in summary.results if item.mode == "bounded_swarm")
    topology = next(
        item for item in summary.topologies if item.topology_id == row.topology_id
    )
    row.attack_accepted = True
    row.verifier_decision = "allow"
    row.first_bad_role = topology.expected_first_bad_role
    row.first_bad_turn = topology.expected_first_bad_turn
    row.blocked_by = []
    summary.control_effects = _build_control_effects(
        summary.topologies,
        summary.results,
    )
    summary.metrics = _build_metrics(
        summary.scenarios,
        summary.topologies,
        summary.results,
        summary.control_effects,
    )

    write_swarm_defense_contour_artifacts(out, summary)
    result = validate_path(out)

    assert not result.ok
    assert result.integrity_ok
    assert not result.expectations_ok
    assert result.errors == []
    assert any(
        "bounded contour accepted attack" in mismatch
        for mismatch in result.expectation_mismatches
    )


def test_defense_contour_validator_recomputes_control_effects(tmp_path: Path) -> None:
    out = tmp_path / "swarm-defense-contour-effect-tamper"
    summary = build_swarm_defense_contour(created_at="")
    summary.control_effects[0].required_by_topologies += 1

    write_swarm_defense_contour_artifacts.__wrapped__(  # type: ignore[attr-defined]
        out, summary
    )
    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert result.expectations_ok
    assert any("control_effects do not match" in error for error in result.errors)


def test_defense_contour_digest_cannot_omit_field(tmp_path: Path) -> None:
    out = tmp_path / "swarm-defense-contour-digest-omission"
    write_swarm_defense_contour_artifacts(
        out,
        build_swarm_defense_contour(created_at=""),
    )
    digest_path = out / "swarm_defense_contour_digest.json"
    digest = json.loads(digest_path.read_text(encoding="utf-8"))
    digest.pop("ablation_acceptances")
    digest_path.write_text(json.dumps(digest), encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("digest projection mismatch" in error for error in result.errors)


def test_defense_contour_rejects_shipped_scenario_redefinition(tmp_path: Path) -> None:
    out = tmp_path / "swarm-defense-contour-corpus-rewrite"
    summary = build_swarm_defense_contour(created_at="")
    summary.scenarios[0].safe_behavior += " rewritten"
    write_swarm_defense_contour_artifacts.__wrapped__(  # type: ignore[attr-defined]
        out, summary
    )

    result = validate_path(out)

    assert not result.ok
    assert any(
        "scenarios does not match the shipped contour specification" in error
        for error in result.errors
    )


def test_defense_contour_rejects_report_tamper_after_hash_rewrite(
    tmp_path: Path,
) -> None:
    out = tmp_path / "swarm-defense-contour-report-rewrite"
    write_swarm_defense_contour_artifacts(
        out,
        build_swarm_defense_contour(created_at=""),
    )
    report_path = out / "swarm_defense_contour_report.md"
    report_path.write_text(
        report_path.read_text(encoding="utf-8") + "\nOverstated claim.\n",
        encoding="utf-8",
    )
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_sha256"][report_path.name] = hashlib.sha256(
        report_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert any("report projection mismatch" in error for error in result.errors)


def test_defense_contour_rejects_manifest_semantic_rewrite(tmp_path: Path) -> None:
    out = tmp_path / "swarm-defense-contour-manifest-rewrite"
    write_swarm_defense_contour_artifacts(
        out,
        build_swarm_defense_contour(created_at=""),
    )
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["metadata"]["topologies"] = 999
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert any(
        "metadata does not match summary projection" in error
        for error in result.errors
    )


def test_defense_contour_missing_matrix_row_reports_error_without_crash(
    tmp_path: Path,
) -> None:
    out = tmp_path / "swarm-defense-contour-missing-row"
    summary = build_swarm_defense_contour(created_at="")
    summary.results.pop()
    write_swarm_defense_contour_artifacts.__wrapped__(  # type: ignore[attr-defined]
        out, summary
    )

    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("topology/mode result matrix mismatch" in error for error in result.errors)


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
