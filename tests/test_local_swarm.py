"""Tests for the bounded local-swarm research runner (#61)."""

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentic_security_harness import cli
from agentic_security_harness.external_openai_compatible import ExternalAPIError
from agentic_security_harness.local_swarm import (
    SWARM_SCENARIOS,
    build_swarm_metrics,
    estimate_request_count,
    evaluate_swarm_scenario,
    model_is_forbidden,
    normalize_role_models,
    render_swarm_report,
    run_local_swarm,
    write_local_swarm_artifacts,
)
from agentic_security_harness.validation import validate_path


def _boom(*args: object, **kwargs: object) -> MagicMock:
    raise AssertionError("network call attempted in dry-run path")


def _mock_swarm_open() -> Callable[..., MagicMock]:
    def _open(req: object, *args: object, **kwargs: object) -> MagicMock:
        body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
        role = "unknown"
        for message in body.get("messages", []):
            text = str(message.get("content", ""))
            for line in text.splitlines():
                if line.startswith("Role: "):
                    role = line.split("Role: ", 1)[1].strip()
        resp = MagicMock()
        resp.read.return_value = json.dumps(
            {"choices": [{"message": {"content": f"{role} follows deterministic gate."}}]}
        ).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    return _open


@pytest.mark.parametrize("scenario", SWARM_SCENARIOS)
def test_bounded_swarm_blocks_each_boundary_scenario(scenario: str) -> None:
    naive = evaluate_swarm_scenario(scenario, "naive_swarm")  # type: ignore[arg-type]
    bounded = evaluate_swarm_scenario(scenario, "bounded_swarm")  # type: ignore[arg-type]

    assert naive.boundary_failure
    assert not bounded.boundary_failure
    assert bounded.verifier_blocked
    assert bounded.blocked_reasons


def test_metrics_show_bounded_reduction() -> None:
    summary = run_local_swarm(created_at="")

    assert summary.metrics.scenarios == len(SWARM_SCENARIOS)
    assert summary.metrics.monolith_boundary_failures == len(SWARM_SCENARIOS)
    assert summary.metrics.naive_swarm_boundary_failures == len(SWARM_SCENARIOS)
    assert summary.metrics.bounded_swarm_boundary_failures == 0
    assert summary.metrics.bounded_failure_reduction_vs_naive == 1.0
    assert summary.metrics.contract_coverage == 1.0
    assert summary.metrics.evidence_completeness == 1.0
    assert summary.metrics.unique_blocked_reasons >= 7
    assert summary.metrics.invalid_acceptances == len(SWARM_SCENARIOS) * 2


def test_local_swarm_report_neutralizes_untrusted_model_markdown() -> None:
    payload = "model`name\n## forged\n![probe](https://example.invalid/p.gif)"
    summary = run_local_swarm(model=payload, created_at="")

    rendered = render_swarm_report(summary)

    model_line = next(line for line in rendered.splitlines() if line.startswith("- Model:"))
    assert model_line.startswith("- Model: `` ")
    assert "\n## forged" not in rendered


def test_scenario_suite_covers_expected_boundary_classes() -> None:
    expected = {
        "handoff_label_stripping",
        "authority_expansion",
        "tool_result_injection",
        "approval_laundering",
        "missing_envelope_recovery",
        "malformed_envelope",
        "verifier_outage",
        "memory_stale_recall",
        "cross_user_memory",
        "memory_trust_precedence",
        "memory_poisoned_recall",
        "memory_envelope_widening",
        "tool_output_authority_confusion",
        "multi_hop_label_laundering",
        "multi_hop_authority_laundering",
    }
    assert set(SWARM_SCENARIOS) == expected


@pytest.mark.parametrize(
    ("scenario", "expected_reason"),
    [
        ("memory_poisoned_recall", "trust_too_low"),
        ("memory_envelope_widening", "stored:allowed_recipients_expanded"),
        ("tool_output_authority_confusion", "authority_expansion"),
        ("multi_hop_label_laundering", "label_loss"),
        ("multi_hop_authority_laundering", "authority_expansion"),
    ],
)
def test_deep_attack_variants_block_on_expected_contract_reason(
    scenario: str,
    expected_reason: str,
) -> None:
    result = evaluate_swarm_scenario(scenario, "bounded_swarm")  # type: ignore[arg-type]

    assert not result.boundary_failure
    assert result.verifier_blocked
    assert expected_reason in result.blocked_reasons


def test_estimated_request_count_is_mode_role_sum() -> None:
    assert estimate_request_count(["handoff_label_stripping"], ["monolith"]) == 1
    assert estimate_request_count(["handoff_label_stripping"], ["naive_swarm"]) == 3
    assert estimate_request_count(["handoff_label_stripping"], ["bounded_swarm"]) == 4


def test_calculator_model_is_refused() -> None:
    assert model_is_forbidden("calculator:latest")
    with pytest.raises(ValueError, match="calculator model"):
        run_local_swarm(
            scenarios=["handoff_label_stripping"],
            modes=["monolith"],
            execute_model_calls=True,
            base_url="http://127.0.0.1:11434/v1",
            model="calculator:latest",
        )


def test_calculator_model_is_refused_as_role_model() -> None:
    with pytest.raises(ValueError, match="calculator model"):
        normalize_role_models({"worker": "calculator:latest"})


def test_execute_routes_roles_to_declared_models() -> None:
    calls: list[str] = []

    def _fake_chat_completion(**kwargs: object) -> dict[str, object]:
        calls.append(str(kwargs["model"]))
        return {"choices": [{"message": {"content": f"model={kwargs['model']}"}}]}

    with patch(
        "agentic_security_harness.local_swarm.chat_completion",
        side_effect=_fake_chat_completion,
    ):
        summary = run_local_swarm(
            scenarios=["handoff_label_stripping"],
            modes=["bounded_swarm"],
            execute_model_calls=True,
            base_url="http://127.0.0.1:11434/v1",
            model="chief-local-model:latest",
            role_models={
                "worker": "small-worker-model:latest",
                "verifier": "small-verifier-model:latest",
                "auditor": "small-auditor-model:latest",
            },
            max_requests=4,
            created_at="",
        )

    assert calls == [
        "chief-local-model:latest",
        "small-worker-model:latest",
        "small-verifier-model:latest",
        "small-auditor-model:latest",
    ]
    assert summary.chief_model == "chief-local-model:latest"
    assert summary.role_models["coordinator"] == "chief-local-model:latest"
    assert summary.role_models["worker"] == "small-worker-model:latest"
    assert {item.model for item in summary.results[0].role_transcripts} == set(calls)


def test_request_cap_is_enforced() -> None:
    with pytest.raises(ValueError, match="exceeds max_requests"):
        run_local_swarm(
            execute_model_calls=True,
            base_url="http://127.0.0.1:11434/v1",
            model="prometheus-qwen15b-lowctx:latest",
            max_requests=1,
        )


def test_artifacts_validate(tmp_path: Path) -> None:
    out = tmp_path / "swarm"
    summary = run_local_swarm(created_at="")
    write_local_swarm_artifacts(out, summary)

    assert (out / "local_swarm_summary.json").exists()
    assert (out / "local_swarm_report.md").exists()
    assert (out / "run_index.json").exists()
    assert validate_path(out).ok


def test_custom_subset_artifact_declares_profile_and_validates(tmp_path: Path) -> None:
    out = tmp_path / "custom-swarm"
    summary = run_local_swarm(
        scenarios=["handoff_label_stripping"],
        modes=["bounded_swarm"],
        created_at="",
    )

    write_local_swarm_artifacts(out, summary)

    manifest = json.loads((out / "run_index.json").read_text(encoding="utf-8"))
    assert manifest["metadata"]["campaign_profile"] == "custom_subset"
    assert validate_path(out).ok


def test_shipped_profile_rejects_coherent_reduced_subset(tmp_path: Path) -> None:
    out = tmp_path / "reduced-shipped-swarm"
    summary = run_local_swarm(
        scenarios=["handoff_label_stripping"],
        modes=["bounded_swarm"],
        created_at="",
    )
    write_local_swarm_artifacts(out, summary)
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["metadata"]["campaign_profile"] = "shipped_full"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert any("shipped_full profile" in item for item in result.errors)


def test_local_swarm_validation_rejects_missing_manifest(tmp_path: Path) -> None:
    out = tmp_path / "missing-manifest"
    write_local_swarm_artifacts(out, run_local_swarm(created_at=""))
    (out / "run_index.json").unlink()

    result = validate_path(out)

    assert not result.ok
    assert any("missing for local swarm bundle" in item for item in result.errors)


def test_validator_recomputes_local_swarm_metrics(tmp_path: Path) -> None:
    out = tmp_path / "swarm-metric-tamper"
    summary = run_local_swarm(created_at="")
    summary.metrics.unique_blocked_reasons += 1
    write_local_swarm_artifacts.__wrapped__(out, summary)  # type: ignore[attr-defined]

    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("metrics do not match recomputed" in error for error in result.errors)


def test_validator_rejects_local_swarm_claim_contract_rewrite(tmp_path: Path) -> None:
    out = tmp_path / "swarm-claim-rewrite"
    summary = run_local_swarm(created_at="")
    summary.claim_boundary = "Rewritten empirical effectiveness claim."
    write_local_swarm_artifacts.__wrapped__(out, summary)  # type: ignore[attr-defined]

    result = validate_path(out)

    assert not result.ok
    assert any(
        "claim_boundary does not match the producer contract" in error for error in result.errors
    )


def test_validator_rejects_local_swarm_report_tamper_after_hash_rewrite(
    tmp_path: Path,
) -> None:
    out = tmp_path / "swarm-report-rewrite"
    write_local_swarm_artifacts(out, run_local_swarm(created_at=""))
    report_path = out / "local_swarm_report.md"
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


def test_validator_rejects_local_swarm_manifest_semantic_rewrite(
    tmp_path: Path,
) -> None:
    out = tmp_path / "swarm-manifest-rewrite"
    write_local_swarm_artifacts(out, run_local_swarm(created_at=""))
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["outcomes"]["bounded_boundary_failures"] = 1
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert any("outcomes does not match summary projection" in error for error in result.errors)


def test_execute_collects_hashed_role_transcripts(tmp_path: Path) -> None:
    out = tmp_path / "swarm"
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_swarm_open(),
    ):
        summary = run_local_swarm(
            scenarios=["handoff_label_stripping"],
            modes=["bounded_swarm"],
            execute_model_calls=True,
            base_url="http://127.0.0.1:11434/v1",
            model="prometheus-qwen15b-lowctx:latest",
            max_requests=4,
            created_at="",
        )
    write_local_swarm_artifacts(out, summary)

    transcripts = summary.results[0].role_transcripts
    assert len(transcripts) == 4
    assert all(item.response_sha256 for item in transcripts)
    assert all("deterministic" in item.response_preview for item in transcripts)
    assert summary.metrics.role_transcript_hash_coverage == 1.0
    assert summary.metrics.adapter_error_rate == 0.0
    assert validate_path(out).ok


def test_validator_rejects_non_sha_transcript_hash(tmp_path: Path) -> None:
    out = tmp_path / "swarm-invalid-transcript-hash"
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_swarm_open(),
    ):
        summary = run_local_swarm(
            scenarios=["handoff_label_stripping"],
            modes=["bounded_swarm"],
            execute_model_calls=True,
            base_url="http://127.0.0.1:11434/v1",
            model="prometheus-qwen15b-lowctx:latest",
            max_requests=4,
            created_at="",
        )
    summary.results[0].role_transcripts[0].prompt_sha256 = "x"
    write_local_swarm_artifacts.__wrapped__(out, summary)  # type: ignore[attr-defined]

    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("prompt_sha256" in error for error in result.errors)


def test_adapter_errors_are_counted_without_turning_into_contract_failures() -> None:
    with patch(
        "agentic_security_harness.local_swarm.chat_completion",
        side_effect=ExternalAPIError("network unavailable"),
    ):
        summary = run_local_swarm(
            scenarios=["handoff_label_stripping"],
            modes=["bounded_swarm"],
            execute_model_calls=True,
            base_url="http://127.0.0.1:11434/v1",
            model="prometheus-qwen15b-lowctx:latest",
            max_requests=4,
            created_at="",
        )

    assert summary.metrics.bounded_swarm_boundary_failures == 0
    assert summary.metrics.adapter_error_rate == 1.0
    assert summary.metrics.role_transcript_hash_coverage == 0.0


def test_cli_dry_run_makes_no_network_call_and_no_files(tmp_path: Path) -> None:
    out = tmp_path / "dry"
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect", side_effect=_boom
    ):
        rc = cli.main(["local-swarm", "--out", str(out)])

    assert rc == 0
    assert not out.exists()


def test_cli_write_dry_run_validates(tmp_path: Path) -> None:
    out = tmp_path / "dry-artifacts"
    rc = cli.main(["local-swarm", "--write-dry-run", "--out", str(out)])

    assert rc == 0
    assert validate_path(out).ok


def test_cli_refuses_calculator_before_network(tmp_path: Path) -> None:
    out = tmp_path / "blocked"
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect", side_effect=_boom
    ):
        rc = cli.main(
            ["local-swarm", "--execute", "--model", "calculator:latest", "--out", str(out)]
        )

    assert rc == 1
    assert not out.exists()


def test_cli_refuses_calculator_role_model_before_network(tmp_path: Path) -> None:
    out = tmp_path / "blocked"
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect", side_effect=_boom
    ):
        rc = cli.main(
            [
                "local-swarm",
                "--execute",
                "--role-model",
                "worker=calculator:latest",
                "--out",
                str(out),
            ]
        )

    assert rc == 1
    assert not out.exists()


def test_metric_helper_accepts_empty_results() -> None:
    metrics = build_swarm_metrics([], 0)
    assert metrics.results == 0
    assert metrics.bounded_failure_reduction_vs_naive == 0.0
