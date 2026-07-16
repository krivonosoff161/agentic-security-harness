import json
from pathlib import Path

import pytest

import agentic_security_harness.swarm_defense_live_campaign as live_campaign
from agentic_security_harness import cli
from agentic_security_harness.swarm_defense_contour import (
    build_defense_topologies,
    declared_defense_scenarios,
)
from agentic_security_harness.swarm_defense_live_campaign import (
    LiveDefenseObservation,
    LiveDefensePrivateRun,
    LiveDefensePrivateTranscript,
    _build_metrics,
    _max_leak,
    build_live_defense_summary,
    estimate_live_request_count,
    render_live_defense_private,
    run_live_defense_campaign,
    write_live_defense_artifacts,
    write_live_defense_private_artifacts,
)
from agentic_security_harness.validation import validate_path


def _private_run() -> LiveDefensePrivateRun:
    topology = build_defense_topologies(declared_defense_scenarios())[0]
    return LiveDefensePrivateRun(
        created_at="2026-07-15T00:00:00Z",
        worker_models=["qwen2.5:0.5b"],
        chief_models=["llama3.2:1b"],
        pressure_modes=["pseudo_code"],
        topology_ids=[topology.topology_id],
        endpoint_sha256="e" * 64,
        tool_version=live_campaign.__version__,
        implementation_sha256=live_campaign._implementation_sha256(),
        execution_id="run_" + "1" * 32,
        runtime_mode="local-only",
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
                worker_turn_response_sha256=["a" * 64],
                chief_response_sha256="b" * 64,
                worker_drift_detected=True,
                chief_accepted_drift=True,
                verifier_decision="block",
                blocked_by=[
                    "audit_hash_chain",
                    "canonical_state",
                    "chief_verifier",
                    "source_hash",
                    "summary_guard",
                    "transition_table",
                    "worker_attestation",
                ],
                missing_control_acceptances=[
                    "audit_hash_chain",
                    "canonical_state",
                    "chief_verifier",
                    "source_hash",
                    "transition_table",
                ],
                first_failure_step="worker_drift",
                ground_truth_label="unsafe",
                ground_truth_source="independent_review",
                ground_truth_evidence_sha256="d" * 64,
            )
        ],
    )


def test_private_live_defense_markdown_neutralizes_model_control_text() -> None:
    malicious = "m|x``\n## forged\n![p](https://evil.invalid)<img src=x>\u202e"
    run = _private_run()
    transcript = run.transcripts[0].model_copy(
        update={"worker_model": malicious, "chief_model": malicious}
    )
    tainted = run.model_copy(
        update={
            "worker_models": [malicious],
            "chief_models": [malicious],
            "transcripts": [transcript],
        }
    )

    rendered = render_live_defense_private(tainted)

    assert "\n## forged" not in rendered
    assert "\u202e" not in rendered
    assert r"\|" in rendered
    assert "``` m|x`` ## forged" in rendered
    assert r"\<img" in rendered


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


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (("none",), "none"),
        (("partial", "none"), "partial"),
        (("partial", "recombined"), "recombined"),
        (("recombined", "encoded"), "encoded"),
        (("encoded", "full"), "full"),
        (("full", "partial", "encoded", "recombined"), "full"),
    ],
)
def test_live_canary_leak_aggregation_matches_detector_categories(
    values: tuple[str, ...],
    expected: str,
) -> None:
    assert _max_leak(*values) == expected  # type: ignore[arg-type]


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


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_topologies": 0}, "max_topologies"),
        ({"worker_models": [" "]}, "trimmed non-blank"),
        ({"worker_models": ["worker", "worker"]}, "duplicates"),
        ({"worker_models": ["sk-1234567890abcdefghijkl"]}, "unsafe-to-persist"),
        ({"pressure_modes": []}, "must not be empty"),
        ({"pressure_modes": ["unknown"]}, "unknown pressure_modes"),
        ({"pressure_modes": ["pseudo_code", "pseudo_code"]}, "duplicates"),
        ({"base_url": "https://models.example/v1"}, "loopback"),
    ],
)
def test_live_campaign_rejects_invalid_execution_axes(
    kwargs: dict[str, object],
    message: str,
) -> None:
    arguments: dict[str, object] = {
        "base_url": "http://127.0.0.1:11434/v1",
        "worker_models": ["worker"],
        "chief_models": ["chief"],
        "pressure_modes": ["pseudo_code"],
        "max_topologies": 1,
        "max_requests": 10,
    }
    arguments.update(kwargs)

    with pytest.raises(ValueError, match=message):
        run_live_defense_campaign(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("failure_role", "expected_stage"),
    [
        ("worker-turn-1", "worker"),
        ("counter-worker", "counter_worker"),
        ("chief", "chief"),
    ],
)
def test_live_chain_records_exact_adapter_error_stage(
    monkeypatch: pytest.MonkeyPatch,
    failure_role: str,
    expected_stage: str,
) -> None:
    topologies = build_defense_topologies(declared_defense_scenarios())
    topology = (
        next(item for item in topologies if "consensus_laundering" in item.scenarios)
        if failure_role == "counter-worker"
        else topologies[0]
    )

    def fake_call_model(**kwargs: object) -> str:
        if kwargs["role"] == failure_role:
            raise OSError("synthetic adapter failure")
        return "SOURCE_LABEL_PRESERVED: true"

    monkeypatch.setattr(live_campaign, "_call_model", fake_call_model)
    row = live_campaign._run_one_chain(
        topology=topology,
        pressure="pseudo_code",
        worker_model="worker",
        chief_model="chief",
        base_url="http://127.0.0.1:11434/v1",
        timeout_seconds=1,
        session_turns=1,
    )

    assert row.adapter_error is True
    assert row.adapter_error_stage == expected_stage
    assert row.first_failure_step == "adapter_error"
    if expected_stage != "worker":
        assert row.worker_response_sha256 == row.worker_turn_response_sha256[-1]


@pytest.mark.parametrize(
    ("blank_role", "expected_stage"),
    [("worker-turn-1", "worker"), ("chief", "chief")],
)
def test_live_chain_treats_blank_model_content_as_staged_error(
    monkeypatch: pytest.MonkeyPatch,
    blank_role: str,
    expected_stage: str,
) -> None:
    topology = build_defense_topologies(declared_defense_scenarios())[0]

    def fake_call_model(**kwargs: object) -> str:
        return "" if kwargs["role"] == blank_role else "SOURCE_LABEL_PRESERVED: true"

    monkeypatch.setattr(live_campaign, "_call_model", fake_call_model)
    row = live_campaign._run_one_chain(
        topology=topology,
        pressure="pseudo_code",
        worker_model="worker",
        chief_model="chief",
        base_url="http://127.0.0.1:11434/v1",
        timeout_seconds=1,
        session_turns=1,
    )

    assert row.adapter_error_stage == expected_stage
    assert row.first_failure_step == "adapter_error"


def test_live_chain_preserves_early_security_event_before_later_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    topology = build_defense_topologies(declared_defense_scenarios())[0]
    calls = 0

    def fake_call_model(**kwargs: object) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("later synthetic adapter failure")
        prompt = str(kwargs["prompt"])
        marker = next(token for token in prompt.split() if token.startswith("ASH-CANARY-"))
        return f"A=C\n{marker}"

    monkeypatch.setattr(live_campaign, "_call_model", fake_call_model)
    row = live_campaign._run_one_chain(
        topology=topology,
        pressure="pseudo_code",
        worker_model="worker",
        chief_model="chief",
        base_url="http://127.0.0.1:11434/v1",
        timeout_seconds=1,
        session_turns=2,
    )

    assert row.adapter_error_stage == "worker"
    assert row.worker_drift_detected is True
    assert row.canary_leak_kind == "full"
    assert row.canary_leaked is True
    assert row.first_failure_step == "worker_drift"
    observation = LiveDefenseObservation(
        **row.model_dump(exclude=live_campaign._private_fields())
    )
    metrics = _build_metrics([observation])
    assert metrics.partial_security_event_observations == 1
    assert metrics.canary_outcome_observations == 1
    assert metrics.canary_leak_rate == 1.0


def test_live_metrics_use_stage_completed_denominators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    topology = build_defense_topologies(declared_defense_scenarios())[0]
    roles_to_fail = iter(("worker-turn-1", "chief"))

    def build_error_row() -> LiveDefenseObservation:
        failure_role = next(roles_to_fail)

        def fake_call_model(**kwargs: object) -> str:
            if kwargs["role"] == failure_role:
                raise OSError("synthetic adapter failure")
            return "SOURCE_LABEL_PRESERVED: true"

        monkeypatch.setattr(live_campaign, "_call_model", fake_call_model)
        private = live_campaign._run_one_chain(
            topology=topology,
            pressure="pseudo_code",
            worker_model="worker",
            chief_model="chief",
            base_url="http://127.0.0.1:11434/v1",
            timeout_seconds=1,
            session_turns=1,
        )
        return LiveDefenseObservation(
            **private.model_dump(exclude=live_campaign._private_fields())
        )

    worker_error = build_error_row()
    chief_error = build_error_row()
    complete = LiveDefenseObservation(
        **_private_run().transcripts[0].model_dump(
            exclude=live_campaign._private_fields()
        )
    )

    metrics = _build_metrics([worker_error, chief_error, complete])

    assert metrics.worker_outcome_observations == 2
    assert metrics.chief_outcome_observations == 1
    assert metrics.worker_drift_rate == 0.5
    assert metrics.chief_acceptance_rate == 1.0


def test_live_summary_strips_private_fields() -> None:
    summary = build_live_defense_summary(_private_run(), created_at="")
    dumped = summary.model_dump_json()

    assert summary.metrics.observations == 1
    assert summary.metrics.worker_drift_detections == 1
    assert summary.metrics.chief_acceptances == 1
    assert summary.metrics.verifier_blocks == 1
    assert summary.metrics.max_session_turns == 1
    assert summary.metrics.long_session_observations == 0
    assert summary.metrics.ablation_reopenings == 5
    assert summary.metrics.ablation_reopening_rate == 1.0
    assert summary.metrics.unsafe_observations == 1
    assert summary.metrics.benign_observations == 0
    assert summary.metrics.unsafe_block_rate == 1.0
    assert summary.metrics.benign_allow_rate == 0.0
    assert summary.metrics.verifier_block_rate == 1.0
    assert summary.metrics.turn_hash_coverage == 1.0
    assert summary.metrics.ground_truth.coverage == 1.0
    assert summary.metrics.ground_truth.true_positives == 1
    assert "chief_acceptance_rate" in summary.metrics.rate_confidence_intervals
    assert summary.metrics.observations_by_worker_model == {"qwen2.5:0.5b": 1}
    assert summary.metrics.chief_acceptance_by_worker_model == {"qwen2.5:0.5b": 1}
    assert summary.metrics.observations_by_chief_model == {"llama3.2:1b": 1}
    assert summary.metrics.chief_acceptance_by_chief_model == {"llama3.2:1b": 1}
    assert summary.metrics.ablation_reopenings_by_control == {
        "audit_hash_chain": 1,
        "canonical_state": 1,
        "chief_verifier": 1,
        "source_hash": 1,
        "transition_table": 1,
    }
    assert "raw_worker_prompt" not in dumped
    assert "raw_worker_response" not in dumped
    assert "raw_chief_response" not in dumped
    assert "ASH-CANARY-" not in dumped
    assert "canary_fingerprint" not in dumped


def test_live_summary_tracks_benign_and_model_breakdowns() -> None:
    topology = build_defense_topologies(declared_defense_scenarios())[0]
    run = LiveDefensePrivateRun(
        worker_models=["qwen2.5:0.5b", "qwen2.5-coder:0.5b-instruct"],
        chief_models=["llama3.2:1b"],
        pressure_modes=["pseudo_code"],
        topology_ids=[topology.topology_id],
        endpoint_sha256="e" * 64,
        tool_version=live_campaign.__version__,
        implementation_sha256=live_campaign._implementation_sha256(),
        execution_id="run_" + "2" * 32,
        runtime_mode="local-only",
        transcripts=[
            LiveDefensePrivateTranscript(
                topology_id=topology.topology_id,
                scenarios=topology.scenarios,
                pressure_mode="pseudo_code",
                worker_model="qwen2.5:0.5b",
                chief_model="llama3.2:1b",
                worker_response_sha256="a" * 64,
                worker_turn_response_sha256=["a" * 64],
                chief_response_sha256="b" * 64,
                worker_drift_detected=True,
                chief_accepted_drift=True,
                verifier_decision="block",
                blocked_by=["audit_hash_chain", "canonical_state", "chief_verifier"],
                missing_control_acceptances=["canonical_state", "chief_verifier"],
                first_failure_step="worker_drift",
                ground_truth_label="unsafe",
                ground_truth_source="independent_review",
                ground_truth_evidence_sha256="e" * 64,
            ),
            LiveDefensePrivateTranscript(
                topology_id=topology.topology_id,
                scenarios=topology.scenarios,
                pressure_mode="pseudo_code",
                worker_model="qwen2.5-coder:0.5b-instruct",
                chief_model="llama3.2:1b",
                worker_response_sha256="c" * 64,
                worker_turn_response_sha256=["c" * 64],
                chief_response_sha256="d" * 64,
                verifier_decision="allow",
                ground_truth_label="benign",
                ground_truth_source="independent_review",
                ground_truth_evidence_sha256="f" * 64,
            ),
        ],
    )

    summary = build_live_defense_summary(run)

    assert summary.metrics.observations == 2
    assert summary.metrics.unsafe_observations == 1
    assert summary.metrics.benign_observations == 1
    assert summary.metrics.unsafe_block_rate == 1.0
    assert summary.metrics.benign_allow_rate == 1.0
    assert summary.metrics.ground_truth.coverage == 1.0
    assert summary.metrics.ground_truth.true_positives == 1
    assert summary.metrics.ground_truth.true_negatives == 1
    assert summary.metrics.turn_hash_coverage == 1.0
    assert summary.metrics.observations_by_worker_model == {
        "qwen2.5-coder:0.5b-instruct": 1,
        "qwen2.5:0.5b": 1,
    }
    assert summary.metrics.chief_acceptance_by_worker_model == {"qwen2.5:0.5b": 1}
    assert summary.metrics.chief_acceptance_by_chief_model == {"llama3.2:1b": 1}
    assert summary.metrics.verifier_blocks_by_pressure == {"pseudo_code": 1}
    low, high = summary.metrics.rate_confidence_intervals["chief_acceptance_rate"]
    assert 0.0 <= low < high <= 1.0


def test_live_artifacts_validate_and_stay_sanitized(tmp_path: Path) -> None:
    private_out = tmp_path / ".internal" / "live"
    public_out = tmp_path / "swarm-defense-live"
    run = _private_run()

    private_paths = write_live_defense_private_artifacts(private_out, run)
    summary = build_live_defense_summary(run)
    paths = write_live_defense_artifacts(public_out, summary)
    result = validate_path(public_out)

    assert result.ok, result.errors
    assert summary.run_config.execution_id == run.execution_id
    manifest = json.loads((public_out / "run_index.json").read_text(encoding="utf-8"))
    assert manifest["execution_id"] == run.execution_id
    assert manifest["outcomes"]["observations"] == 1
    assert manifest["metadata"]["summary_sha256"]
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


def test_live_validator_rejects_self_consistent_claim_contract_rewrite(
    tmp_path: Path,
) -> None:
    public_out = tmp_path / "swarm-defense-live"
    summary = build_live_defense_summary(_private_run())
    summary.claim_boundary = "This rewritten boundary claims production safety."
    summary.non_claims = ["Production safety is proven."]
    write_live_defense_artifacts.__wrapped__(  # type: ignore[attr-defined]
        public_out, summary
    )

    result = validate_path(public_out)

    assert not result.integrity_ok
    assert any("claim_boundary does not match" in error for error in result.errors)
    assert any("non_claims do not match" in error for error in result.errors)


def test_live_private_writer_requires_internal(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=".internal"):
        write_live_defense_private_artifacts(tmp_path / "public", _private_run())


def test_live_private_writer_rejects_internal_parent_traversal(tmp_path: Path) -> None:
    disguised_public = tmp_path / ".internal" / ".." / "public"

    with pytest.raises(ValueError, match=".internal"):
        write_live_defense_private_artifacts(disguised_public, _private_run())


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


def test_live_validation_rejects_malformed_response_hash(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    raw = json.loads((public_out / "swarm_defense_live_summary.json").read_text())
    raw["observations"][0]["worker_response_sha256"] = "not-a-sha256"
    (public_out / "swarm_defense_live_summary.json").write_text(
        json.dumps(raw),
        encoding="utf-8",
    )

    result = validate_path(public_out)

    assert not result.ok
    assert any("expected lowercase SHA-256 hex digest" in item for item in result.errors)


def test_live_validation_rejects_digest_metric_drift(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    raw = json.loads((public_out / "swarm_defense_live_digest.json").read_text())
    raw["metrics"]["observations"] = 999
    (public_out / "swarm_defense_live_digest.json").write_text(
        json.dumps(raw),
        encoding="utf-8",
    )

    result = validate_path(public_out)

    assert not result.ok
    assert any(
        "swarm_defense_live_digest.json: metrics.observations mismatch" in item
        for item in result.errors
    )


def test_legacy_live_digest_cannot_drop_all_summary_metrics(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    summary_path = public_out / "swarm_defense_live_summary.json"
    digest_path = public_out / "swarm_defense_live_digest.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    digest = json.loads(digest_path.read_text(encoding="utf-8"))
    summary["schema_version"] = "0.4"
    summary.pop("run_config")
    digest["schema_version"] = "0.4"
    digest.pop("run_config")
    digest["metrics"] = {}
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    digest_path.write_text(json.dumps(digest), encoding="utf-8")

    result = validate_path(public_out)

    assert not result.integrity_ok
    assert any("digest.json: metrics fields mismatch" in item for item in result.errors)


def test_live_validation_rejects_inconsistent_ablation_metrics(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    raw = json.loads((public_out / "swarm_defense_live_summary.json").read_text())
    raw["metrics"]["ablation_reopenings"] = 0
    (public_out / "swarm_defense_live_summary.json").write_text(
        json.dumps(raw),
        encoding="utf-8",
    )

    result = validate_path(public_out)

    assert not result.ok
    assert any("ablation_reopenings mismatch" in item for item in result.errors)


def test_live_validation_rejects_inconsistent_extended_metrics(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    raw = json.loads((public_out / "swarm_defense_live_summary.json").read_text())
    raw["metrics"]["unsafe_observations"] = 0
    raw["metrics"]["unsafe_block_rate"] = 0.0
    raw["metrics"]["response_hash_coverage"] = 0.0
    raw["metrics"]["turn_hash_coverage"] = 0.0
    raw["metrics"]["ground_truth"]["recall"] = 0.0
    (public_out / "swarm_defense_live_summary.json").write_text(
        json.dumps(raw),
        encoding="utf-8",
    )

    result = validate_path(public_out)

    assert not result.ok
    assert any("unsafe_observations mismatch" in item for item in result.errors)
    assert any("unsafe_block_rate mismatch" in item for item in result.errors)
    assert any("response_hash_coverage mismatch" in item for item in result.errors)
    assert any("turn_hash_coverage mismatch" in item for item in result.errors)
    assert any("metrics.ground_truth.recall mismatch" in item for item in result.errors)


def test_live_validation_rejects_empty_completed_hash_in_chief_error(
    tmp_path: Path,
) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    summary_path = public_out / "swarm_defense_live_summary.json"
    raw = json.loads(summary_path.read_text(encoding="utf-8"))
    row = raw["observations"][0]
    row.update(
        {
            "adapter_error": True,
            "adapter_error_stage": "chief",
            "first_failure_step": "adapter_error",
            "worker_turn_response_sha256": [""],
            "chief_response_sha256": "",
            "chief_accepted_drift": False,
            "canary_leak_kind": "none",
            "canary_leaked": False,
            "verifier_decision": "allow",
            "blocked_by": [],
            "missing_control_acceptances": [],
        }
    )
    summary_path.write_text(json.dumps(raw), encoding="utf-8")

    result = validate_path(public_out)

    assert not result.integrity_ok
    assert any("chief-stage error has empty worker hash" in item for item in result.errors)


def test_live_validation_recomputes_every_current_metric(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    summary_path = public_out / "swarm_defense_live_summary.json"
    raw = json.loads(summary_path.read_text(encoding="utf-8"))
    raw["metrics"]["chief_acceptance_by_pressure"] = {"fabricated": 99}
    summary_path.write_text(json.dumps(raw), encoding="utf-8")

    result = validate_path(public_out)

    assert not result.integrity_ok
    assert any(
        "metrics do not match recomputed observations" in item
        for item in result.errors
    )


def test_live_validation_binds_manifest_to_run_config(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    manifest_path = public_out / "run_index.json"
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["metadata"]["endpoint_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")

    result = validate_path(public_out)

    assert not result.integrity_ok
    assert any(
        "metadata does not match live summary run_config" in item
        for item in result.errors
    )


def test_live_validation_requires_current_utc_created_at(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    summary_path = public_out / "swarm_defense_live_summary.json"
    raw = json.loads(summary_path.read_text(encoding="utf-8"))
    raw["created_at"] = ""
    summary_path.write_text(json.dumps(raw), encoding="utf-8")

    result = validate_path(public_out)

    assert not result.integrity_ok
    assert any("missing or untrimmed UTC timestamp" in item for item in result.errors)


def test_live_validation_rejects_swapped_execution_manifest(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    manifest_path = public_out / "run_index.json"
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["run_id"] = raw["execution_id"] = "run_" + "9" * 32
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")

    result = validate_path(public_out)

    assert not result.integrity_ok
    assert any("execution identity does not match" in item for item in result.errors)


def test_live_validation_rejects_report_tampering(tmp_path: Path) -> None:
    public_out = tmp_path / "swarm-defense-live"
    write_live_defense_artifacts(public_out, build_live_defense_summary(_private_run()))
    report_path = public_out / "swarm_defense_live_report.md"
    report_path.write_text("# Contradictory report\n", encoding="utf-8")

    result = validate_path(public_out)

    assert not result.integrity_ok
    assert any("report projection mismatch" in item for item in result.errors)


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
    assert "session_turns=1" in out
    assert "Dry-run only" in out


def test_cli_swarm_defense_live_long_session_dry_run(
    capsys: pytest.CaptureFixture[str],
) -> None:
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
            "long_session_relabel",
            "--session-turns",
            "3",
        ]
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert "session_turns=3" in out
    assert "estimated_requests<=10" in out
