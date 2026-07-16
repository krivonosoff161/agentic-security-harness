import hashlib
import json
from pathlib import Path

import pytest

from agentic_security_harness import cli
from agentic_security_harness.swarm_resilience_campaign import (
    _metrics,
    build_resilience_private_run,
    build_resilience_summary,
    write_resilience_artifacts,
    write_resilience_private_artifacts,
)
from agentic_security_harness.validation import validate_path


def test_resilience_campaign_covers_seven_families() -> None:
    summary = build_resilience_summary(build_resilience_private_run())

    assert summary.metrics.scenarios == 7
    assert summary.metrics.naive_unsafe_acceptances == 7
    assert summary.metrics.bounded_unsafe_acceptances == 0
    assert summary.metrics.ablation_unsafe_acceptances >= 7
    assert summary.metrics.benign_false_blocks == 0
    assert summary.metrics.response_hash_coverage == 1.0
    assert set(summary.metrics.observations_by_scenario) == {
        "memory_long_session",
        "semantic_term_drift",
        "source_trust_poisoning",
        "consensus_laundering",
        "metric_verdict_attack",
        "benign_fact_accumulation",
        "stability_cascade",
    }


def test_resilience_bounded_returns_to_safe_region() -> None:
    summary = build_resilience_summary(build_resilience_private_run())
    bounded = [item for item in summary.observations if item.mode == "bounded"]
    naive = [item for item in summary.observations if item.mode == "naive"]

    assert all(not item.accepted_unsafe for item in bounded)
    assert all(item.recovered_to_safe for item in bounded)
    assert all(item.final_stability_energy <= 0.55 for item in bounded)
    assert all(item.accepted_unsafe for item in naive)
    assert all(item.diverged for item in naive)


def test_resilience_ablation_reopens_responsible_controls() -> None:
    summary = build_resilience_summary(build_resilience_private_run())

    for control in (
        "memory_provenance",
        "canonical_terms",
        "source_trust_floor",
        "cross_worker_check",
        "metric_replay",
        "cumulative_risk_guard",
        "stability_monitor",
    ):
        assert summary.metrics.ablation_reopenings_by_control.get(control, 0) > 0


def test_resilience_summary_strips_private_fields() -> None:
    summary = build_resilience_summary(build_resilience_private_run())
    dumped = summary.model_dump_json()

    assert "synthetic_payload_notes" not in dumped
    assert "state_vectors_by_step" not in dumped
    assert "calculation_notes" not in dumped


def test_resilience_artifacts_validate_and_keep_private_raw_out(tmp_path: Path) -> None:
    private_out = tmp_path / ".internal" / "swarm-resilience"
    public_out = tmp_path / "swarm-resilience"
    private_run = build_resilience_private_run()
    summary = build_resilience_summary(private_run)

    private_paths = write_resilience_private_artifacts(private_out, private_run)
    public_paths = write_resilience_artifacts(public_out, summary)
    result = validate_path(public_out)

    assert result.ok, result.errors
    assert result.swarm_resilience_campaign_dirs == ["swarm-resilience"]
    assert {path.name for path in private_paths} == {
        "swarm_resilience_private.json",
        "swarm_resilience_private.md",
    }
    assert {path.name for path in public_paths} == {
        "swarm_resilience_summary.json",
        "swarm_resilience_report.md",
        "swarm_resilience_digest.json",
        "run_index.json",
    }
    for path in public_paths:
        text = path.read_text(encoding="utf-8")
        if path.name != "swarm_resilience_digest.json":
            assert "synthetic_payload_notes" not in text
        assert "calculation_notes" not in text


def test_valid_bounded_resilience_regression_is_expectation_failure_only(
    tmp_path: Path,
) -> None:
    public_out = tmp_path / "swarm-resilience-regression"
    summary = build_resilience_summary(build_resilience_private_run())
    row = next(item for item in summary.observations if item.mode == "bounded")
    row.accepted_unsafe = True
    row.verifier_verdict = "unsafe_accept"
    row.stability_verdict = "diverged"
    row.recovered_to_safe = False
    row.diverged = True
    row.blocked_by = []
    summary.metrics = _metrics(summary.observations)

    write_resilience_artifacts(public_out, summary)
    result = validate_path(public_out)

    assert not result.ok
    assert result.integrity_ok
    assert not result.expectations_ok
    assert result.errors == []
    assert any(
        "bounded accepted unsafe" in mismatch
        for mismatch in result.expectation_mismatches
    )


def test_resilience_validator_recomputes_all_summary_metrics(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-resilience-metric-tamper"
    summary = build_resilience_summary(build_resilience_private_run())
    summary.metrics.average_bounded_final_energy += 0.1

    write_resilience_artifacts.__wrapped__(  # type: ignore[attr-defined]
        public_out, summary
    )
    result = validate_path(public_out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("metrics do not match recomputed" in error for error in result.errors)


def test_resilience_validation_rejects_private_fields(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-resilience"
    write_resilience_artifacts(
        public_out,
        build_resilience_summary(build_resilience_private_run()),
    )
    raw = json.loads((public_out / "swarm_resilience_summary.json").read_text())
    raw["observations"][0]["calculation_notes"] = ["private"]
    (public_out / "swarm_resilience_summary.json").write_text(
        json.dumps(raw),
        encoding="utf-8",
    )

    result = validate_path(public_out)

    assert not result.ok
    assert any(
        "raw/private fields" in item or "calculation_notes" in item for item in result.errors
    )


def test_resilience_validation_rejects_digest_metric_drift(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-resilience"
    write_resilience_artifacts(
        public_out,
        build_resilience_summary(build_resilience_private_run()),
    )
    raw = json.loads((public_out / "swarm_resilience_digest.json").read_text())
    raw["metrics"]["observations"] = 999
    (public_out / "swarm_resilience_digest.json").write_text(
        json.dumps(raw),
        encoding="utf-8",
    )

    result = validate_path(public_out)

    assert not result.ok
    assert any(
        "swarm_resilience_digest.json: metrics.observations mismatch" in item
        for item in result.errors
    )


def test_resilience_validation_rejects_hash_length_drift(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-resilience"
    write_resilience_artifacts(
        public_out,
        build_resilience_summary(build_resilience_private_run()),
    )
    raw = json.loads((public_out / "swarm_resilience_summary.json").read_text())
    raw["observations"][0]["state_hashes"][0] = "not-a-sha256"
    (public_out / "swarm_resilience_summary.json").write_text(
        json.dumps(raw),
        encoding="utf-8",
    )

    result = validate_path(public_out)

    assert not result.ok
    assert any("expected lowercase SHA-256 hex digest" in item for item in result.errors)


def test_resilience_validation_rejects_empty_hash_slot(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-resilience"
    summary = build_resilience_summary(build_resilience_private_run())
    summary.observations[0].state_hashes[0] = ""
    summary.metrics = _metrics(summary.observations)
    write_resilience_artifacts.__wrapped__(  # type: ignore[attr-defined]
        public_out, summary
    )

    result = validate_path(public_out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("state_hashes[0] is empty" in error for error in result.errors)


def test_resilience_validation_binds_final_hash_to_final_state(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-resilience-final-hash"
    summary = build_resilience_summary(build_resilience_private_run())
    summary.observations[0].state_hashes[-1] = "0" * 64
    write_resilience_artifacts.__wrapped__(  # type: ignore[attr-defined]
        public_out, summary
    )

    result = validate_path(public_out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("final state hash mismatch" in error for error in result.errors)


def test_resilience_validation_binds_every_intermediate_state_hash(
    tmp_path: Path,
) -> None:
    public_out = tmp_path / "swarm-resilience-intermediate-hash"
    summary = build_resilience_summary(build_resilience_private_run())
    summary.observations[0].state_hashes[0] = "0" * 64
    write_resilience_artifacts.__wrapped__(  # type: ignore[attr-defined]
        public_out, summary
    )

    result = validate_path(public_out)

    assert not result.ok
    assert any(
        "state_hashes does not match the canonical trajectory" in error
        for error in result.errors
    )


def test_resilience_validation_rejects_report_tamper_after_hash_rewrite(
    tmp_path: Path,
) -> None:
    public_out = tmp_path / "swarm-resilience-report-rewrite"
    write_resilience_artifacts(
        public_out,
        build_resilience_summary(build_resilience_private_run()),
    )
    report_path = public_out / "swarm_resilience_report.md"
    report_path.write_text(
        report_path.read_text(encoding="utf-8") + "\nOverstated claim.\n",
        encoding="utf-8",
    )
    manifest_path = public_out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_sha256"][report_path.name] = hashlib.sha256(
        report_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = validate_path(public_out)

    assert not result.ok
    assert any("report projection mismatch" in error for error in result.errors)


def test_resilience_validation_rejects_manifest_semantic_rewrite(
    tmp_path: Path,
) -> None:
    public_out = tmp_path / "swarm-resilience-manifest-rewrite"
    write_resilience_artifacts(
        public_out,
        build_resilience_summary(build_resilience_private_run()),
    )
    manifest_path = public_out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["outcomes"]["bounded_unsafe_acceptances"] = 1
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = validate_path(public_out)

    assert not result.ok
    assert any(
        "outcomes does not match summary projection" in error
        for error in result.errors
    )


def test_cli_swarm_resilience_dry_run(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli.main(["swarm-resilience-campaign"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "scenarios=7" in out
    assert "naive_unsafe=7" in out
    assert "bounded_unsafe=0" in out
    assert "Dry-run only" in out
