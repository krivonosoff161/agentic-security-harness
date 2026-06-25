import json
from pathlib import Path

import pytest

from agentic_security_harness import cli
from agentic_security_harness.swarm_defense_contour import (
    build_defense_topologies,
    declared_defense_scenarios,
)
from agentic_security_harness.swarm_defense_live_campaign import (
    LiveDefensePrivateRun,
    LiveDefensePrivateTranscript,
    build_live_defense_summary,
    estimate_live_request_count,
    run_live_defense_campaign,
    write_live_defense_artifacts,
    write_live_defense_private_artifacts,
)
from agentic_security_harness.validation import validate_path


def _private_run() -> LiveDefensePrivateRun:
    topology = build_defense_topologies(declared_defense_scenarios())[0]
    return LiveDefensePrivateRun(
        created_at="",
        worker_models=["qwen2.5:0.5b"],
        chief_models=["llama3.2:1b"],
        pressure_modes=["pseudo_code"],
        transcripts=[
            LiveDefensePrivateTranscript(
                topology_id=topology.topology_id,
                scenarios=topology.scenarios,
                pressure_mode="pseudo_code",
                worker_model="qwen2.5:0.5b",
                chief_model="llama3.2:1b",
                raw_worker_prompt="private prompt with ASH-CANARY-AAAABBBB-CCCCDDDD",
                raw_worker_response="A_EQUALS_C: true",
                raw_chief_prompt="private chief prompt",
                raw_chief_response="APPROVE_PUBLIC_CLAIM: true",
                canary_fingerprint="f" * 64,
                worker_response_sha256="a" * 64,
                chief_response_sha256="b" * 64,
                worker_drift_detected=True,
                chief_accepted_drift=True,
                verifier_decision="block",
                blocked_by=["audit_hash_chain", "canonical_state", "chief_verifier"],
                missing_control_acceptances=["canonical_state", "chief_verifier"],
                first_failure_step="worker_drift",
            )
        ],
    )


def test_live_request_count_is_conservative() -> None:
    assert (
        estimate_live_request_count(
            topology_count=15,
            worker_models=["w1", "w2"],
            chief_models=["c"],
            pressure_modes=["pseudo_code", "memory_rewrite"],
        )
        == 180
    )


def test_live_campaign_refuses_calculator_model() -> None:
    with pytest.raises(ValueError, match="calculator"):
        run_live_defense_campaign(
            base_url="http://127.0.0.1:11434/v1",
            worker_models=["calculator:latest"],
            chief_models=["llama3.2:1b"],
            pressure_modes=["pseudo_code"],
            max_topologies=1,
            max_requests=10,
        )


def test_live_summary_strips_private_fields() -> None:
    summary = build_live_defense_summary(_private_run(), created_at="")
    dumped = summary.model_dump_json()

    assert summary.metrics.observations == 1
    assert summary.metrics.worker_drift_detections == 1
    assert summary.metrics.chief_acceptances == 1
    assert summary.metrics.verifier_blocks == 1
    assert "raw_worker_prompt" not in dumped
    assert "raw_worker_response" not in dumped
    assert "raw_chief_response" not in dumped
    assert "ASH-CANARY-" not in dumped
    assert "canary_fingerprint" not in dumped


def test_live_artifacts_validate_and_stay_sanitized(tmp_path: Path) -> None:
    private_out = tmp_path / ".internal" / "live"
    public_out = tmp_path / "swarm-defense-live"
    run = _private_run()

    private_paths = write_live_defense_private_artifacts(private_out, run)
    paths = write_live_defense_artifacts(public_out, build_live_defense_summary(run))
    result = validate_path(public_out)

    assert result.ok, result.errors
    assert result.swarm_defense_live_campaign_dirs == ["swarm-defense-live"]
    assert {path.name for path in paths} == {
        "swarm_defense_live_summary.json",
        "swarm_defense_live_report.md",
        "swarm_defense_live_digest.json",
        "run_index.json",
    }
    assert {path.name for path in private_paths} == {
        "swarm_defense_live_private.json",
        "swarm_defense_live_private.md",
    }
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "raw_worker_prompt" not in text
        assert "ASH-CANARY-" not in text
        assert "canary_fingerprint" not in text


def test_live_validation_rejects_private_fields(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    raw = json.loads((public_out / "swarm_defense_live_summary.json").read_text())
    raw["raw_worker_prompt"] = "private"
    (public_out / "swarm_defense_live_summary.json").write_text(
        json.dumps(raw),
        encoding="utf-8",
    )

    result = validate_path(public_out)

    assert not result.ok
    assert any(
        "raw/private fields" in item or "raw_worker_prompt" in item
        for item in result.errors
    )


def test_cli_swarm_defense_live_dry_run(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(
        [
            "swarm-defense-live-campaign",
            "--max-topologies",
            "2",
            "--worker-model",
            "qwen2.5:0.5b",
            "--chief-model",
            "llama3.2:1b",
            "--pressure-mode",
            "pseudo_code",
        ]
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert "estimated_requests<=6" in out
    assert "Dry-run only" in out
