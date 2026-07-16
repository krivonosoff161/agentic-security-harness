import hashlib
import json
import shutil
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from agentic_security_harness.evidence_quality import (
    build_evidence_quality_report,
    discover_external_run_dirs,
    discover_local_swarm_run_dirs,
    write_evidence_quality,
)
from agentic_security_harness.external_openai_compatible import ExternalAPIError
from agentic_security_harness.external_runner import run_external
from agentic_security_harness.local_swarm import (
    RoleTranscript,
    SwarmMode,
    _roles_for_mode,
    run_local_swarm,
    write_local_swarm_artifacts,
)
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS
from agentic_security_harness.validation import validate_path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _write_external_run(
    root: Path,
    name: str,
    *,
    model: str,
    outcomes: list[str],
    stability_status: str,
) -> Path:
    run = root / name
    remaining = iter(outcomes)

    def _chat_completion(**kwargs: object) -> dict:
        outcome = next(remaining)
        if outcome == "adapter_error":
            raise ExternalAPIError("timeout")
        messages = kwargs["messages"]
        pattern_id = ""
        assert isinstance(messages, list)
        for message in messages:
            assert isinstance(message, dict)
            for line in str(message.get("content", "")).splitlines():
                if line.startswith("Pattern: "):
                    pattern_id = line.split("Pattern: ", 1)[1].strip()
        if outcome == "pass":
            decision, assertion, preserve = "block", "preserve_boundary", True
        elif outcome == "finding":
            decision, assertion, preserve = "allow", "vulnerable_behavior", False
        else:
            decision, assertion, preserve = "unclear", "unclear", None
        content = json.dumps({
            "pattern_id": pattern_id,
            "decision": decision,
            "boundary_assertion": assertion,
            "would_preserve_boundary": preserve,
            "reason": f"fixture {outcome}",
        })
        return {"choices": [{"message": {"content": content}}]}

    with patch(
        "agentic_security_harness.external_runner.chat_completion",
        side_effect=_chat_completion,
    ):
        summary = run_external(
            base_url="http://127.0.0.1:8765/v1",
            model=model,
            scenario_id="perception-boundary",
            out_dir=run,
            repeats=len(outcomes),
            max_retries=0,
        )
    assert summary.repeat_summaries[0].stability_status == stability_status
    return run


def _write_local_swarm_run(
    root: Path,
    name: str,
    *,
    executed: bool = False,
    adapter_error: bool = False,
    modes: list[SwarmMode] | None = None,
) -> Path:
    run = root / name
    summary = run_local_swarm(
        scenarios=["handoff_label_stripping"],
        modes=modes or ["bounded_swarm"],
        execute_model_calls=False,
        max_requests=20,
        model="prometheus-qwen15b-lowctx:latest" if executed else "",
    )
    if executed:
        def _collect_role_transcripts(**kwargs: object) -> list[RoleTranscript]:
            raw_mode = kwargs["mode"]
            model_name = str(kwargs["model"])
            assert raw_mode in {"monolith", "naive_swarm", "bounded_swarm"}
            mode = cast(SwarmMode, raw_mode)
            transcripts = []
            for idx, role in enumerate(_roles_for_mode(mode)):
                failed = adapter_error and role == "verifier"
                transcripts.append(RoleTranscript(
                    role=role,
                    model=model_name,
                    prompt_sha256=f"{idx:a>64}",
                    response_sha256="" if failed else f"{idx + 8:a>64}",
                    response_preview="" if failed else "bounded context summary",
                    adapter_error="timeout" if failed else "",
                ))
            return transcripts

        with patch(
            "agentic_security_harness.local_swarm._collect_role_transcripts",
            side_effect=_collect_role_transcripts,
        ):
            summary = run_local_swarm(
                scenarios=["handoff_label_stripping"],
                modes=modes or ["bounded_swarm"],
                execute_model_calls=True,
                base_url="http://127.0.0.1:8765/v1",
                model="prometheus-qwen15b-lowctx:latest",
                max_requests=20,
            )
    write_local_swarm_artifacts(run, summary)
    return run


def test_discover_external_run_dirs_finds_nested_runs(tmp_path: Path) -> None:
    run = _write_external_run(
        tmp_path / "reports",
        "a",
        model="m1",
        outcomes=["pass"],
        stability_status="stable_pass",
    )

    assert discover_external_run_dirs(tmp_path / "reports") == [run]


def test_discover_local_swarm_run_dirs_finds_nested_runs(tmp_path: Path) -> None:
    run = _write_local_swarm_run(tmp_path / "reports", "swarm")

    assert discover_local_swarm_run_dirs(tmp_path / "reports") == [run]


def test_evidence_quality_report_counts_decisive_weak_and_raw_hash(
    tmp_path: Path,
) -> None:
    _write_external_run(
        tmp_path,
        "mixed",
        model="m1",
        outcomes=["pass", "finding", "inconclusive", "adapter_error"],
        stability_status="flaky",
    )

    report = build_evidence_quality_report(tmp_path)

    assert report.total_runs == 1
    assert report.total_results == 4
    assert report.outcome_counts == {
        "adapter_error": 1,
        "finding": 1,
        "inconclusive": 1,
        "invalid": 0,
        "pass": 1,
    }
    assert report.decisive_rate == 0.5
    assert report.weak_evidence_rate == 0.5
    assert report.raw_response_coverage_rate == 0.75
    assert report.raw_hash_coverage_rate == 0.75
    assert report.assertion_binding_rate == 1.0
    assert report.runs[0].flaky_groups == 1
    assert report.runs[0].artifact_validation == "current_content_bound"
    assert report.runs[0].origin_authentication == "unsigned"
    assert report.safety_note.startswith("Derived evidence-quality analysis only")


def test_evidence_quality_report_counts_local_swarm_dry_run(tmp_path: Path) -> None:
    _write_local_swarm_run(tmp_path, "swarm")

    report = build_evidence_quality_report(tmp_path)

    assert report.total_runs == 0
    assert report.local_swarm_runs_count == 1
    assert report.local_swarm_results == 1
    assert report.local_swarm_executed_runs == 0
    assert report.local_swarm_contract_coverage_rate == 1.0
    assert report.local_swarm_evidence_completeness_rate == 1.0
    assert report.local_swarm_transcript_hash_coverage_rate == 0.0
    assert report.local_swarm_adapter_error_rate == 0.0
    assert report.local_swarm_runtime_mode_coverage_rate == 0.0
    run = report.local_swarm_runs[0]
    assert run.verifier_blocks == 1
    assert run.bounded_swarm_boundary_failures == 0
    assert run.evidence_maturity == "deterministic_example"
    assert run.artifact_validation == "current_content_bound"


def test_evidence_quality_report_counts_local_swarm_executed_hashes_and_errors(
    tmp_path: Path,
) -> None:
    _write_local_swarm_run(tmp_path, "swarm", executed=True, adapter_error=True)

    report = build_evidence_quality_report(tmp_path)

    assert report.local_swarm_runs_count == 1
    assert report.local_swarm_executed_runs == 1
    assert report.local_swarm_transcript_hash_coverage_rate == 0.75
    assert report.local_swarm_adapter_error_rate == 0.25
    run = report.local_swarm_runs[0]
    assert run.role_transcripts == 4
    assert run.role_transcript_hashes == 3
    assert run.adapter_errors == 1
    assert run.evidence_maturity == "bounded_runtime_smoke"
    assert report.warnings


def test_evidence_quality_marks_full_local_swarm_runtime_comparison(
    tmp_path: Path,
) -> None:
    _write_local_swarm_run(
        tmp_path,
        "swarm",
        executed=True,
        modes=["monolith", "naive_swarm", "bounded_swarm"],
    )

    report = build_evidence_quality_report(tmp_path)

    assert report.local_swarm_runtime_mode_coverage_rate == 1.0
    run = report.local_swarm_runs[0]
    assert run.evidence_maturity == "full_runtime_comparison"
    assert run.runtime_mode_coverage_rate == 1.0
    assert not report.warnings


def test_cross_run_disagreement_is_counted_per_pattern_variant(tmp_path: Path) -> None:
    _write_external_run(
        tmp_path,
        "left",
        model="m1",
        outcomes=["pass"],
        stability_status="stable_pass",
    )
    _write_external_run(
        tmp_path,
        "right",
        model="m2",
        outcomes=["finding"],
        stability_status="stable_finding",
    )

    report = build_evidence_quality_report(tmp_path)

    assert report.comparable_groups == 1
    assert report.disagreement_groups == 1
    assert report.cross_run_disagreement_rate == 1.0


def test_write_evidence_quality_outputs_json_and_markdown(tmp_path: Path) -> None:
    _write_external_run(
        tmp_path,
        "run",
        model="m1",
        outcomes=["pass"],
        stability_status="stable_pass",
    )
    _write_local_swarm_run(tmp_path, "swarm")
    report = build_evidence_quality_report(tmp_path)
    paths = write_evidence_quality(report, tmp_path / "out")

    assert paths["run_index"].is_file()
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["schema_version"] == SCHEMA_VERSIONS["evidence_quality"]
    assert "local_swarm_runs" in data
    md = paths["markdown"].read_text(encoding="utf-8")
    assert "Derived analysis only" in md
    assert "Raw hash coverage" in md
    assert "Local swarm runs" in md
    assert "Maturity" in md
    assert str(tmp_path).replace("\\", "/") not in json.dumps(data)
    assert str(tmp_path).replace("\\", "/") not in md
    validation = validate_path(tmp_path / "out")
    assert validation.ok, validation.errors
    assert validation.evidence_quality_dirs == ["out"]


def test_cli_evidence_quality_writes_artifacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from agentic_security_harness import cli

    _write_external_run(
        tmp_path / "reports",
        "run",
        model="m1",
        outcomes=["pass", "inconclusive"],
        stability_status="flaky",
    )

    rc = cli.main([
        "evidence-quality",
        "--root",
        str(tmp_path / "reports"),
        "--out",
        str(tmp_path / "quality"),
    ])

    assert rc == 0
    assert (tmp_path / "quality" / "evidence_quality.json").is_file()
    assert (tmp_path / "quality" / "evidence_quality.md").is_file()
    assert (tmp_path / "quality" / "run_index.json").is_file()
    out = capsys.readouterr().out
    assert "Derived analysis only" in out
    assert "weak_evidence_rate" in out
    assert "local_swarm_runs" in out
    assert "local_swarm_runtime_mode_coverage_rate" in out


def test_evidence_quality_excludes_post_manifest_tampering(tmp_path: Path) -> None:
    run = _write_local_swarm_run(tmp_path, "swarm")
    summary_path = run / "local_swarm_summary.json"
    summary_path.write_text(
        summary_path.read_text(encoding="utf-8") + " ",
        encoding="utf-8",
    )

    report = build_evidence_quality_report(tmp_path)

    assert report.local_swarm_runs_count == 0
    assert any("excluded: artifact integrity validation failed" in w for w in report.warnings)


def test_evidence_quality_excludes_bundle_without_manifest(tmp_path: Path) -> None:
    run = _write_external_run(
        tmp_path,
        "external",
        model="m1",
        outcomes=["pass"],
        stability_status="stable_pass",
    )
    (run / "run_index.json").unlink()

    report = build_evidence_quality_report(tmp_path)

    assert report.total_runs == 0
    assert any("missing run_index.json validation boundary" in w for w in report.warnings)


def test_evidence_quality_labels_valid_legacy_bundle(tmp_path: Path) -> None:
    run = tmp_path / "external-legacy"
    shutil.copytree(EXAMPLES / "external-demo-report", run)

    report = build_evidence_quality_report(run)

    assert report.total_runs == 1
    assert report.runs[0].manifest_schema_version == "0.1"
    assert report.runs[0].artifact_validation == "legacy_structural"
    assert any("without persisted-byte hash binding" in w for w in report.warnings)


def test_validate_evidence_quality_rejects_coherent_aggregate_tamper(
    tmp_path: Path,
) -> None:
    _write_external_run(
        tmp_path / "inputs",
        "external",
        model="m1",
        outcomes=["pass"],
        stability_status="stable_pass",
    )
    out = tmp_path / "quality"
    write_evidence_quality(build_evidence_quality_report(tmp_path / "inputs"), out)
    json_path = out / "evidence_quality.json"
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    payload["decisive_rate"] = 0.125
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_sha256"]["evidence_quality.json"] = hashlib.sha256(
        json_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    validation = validate_path(out)

    assert not validation.ok
    assert any("decisive_rate does not match included runs" in e for e in validation.errors)


def test_writer_rejects_invalid_projection_before_creating_output(tmp_path: Path) -> None:
    _write_external_run(
        tmp_path / "inputs",
        "external",
        model="m1",
        outcomes=["pass"],
        stability_status="stable_pass",
    )
    report = build_evidence_quality_report(tmp_path / "inputs").model_copy(
        update={"decisive_rate": 0.125}
    )
    out = tmp_path / "quality"

    with pytest.raises(ValueError, match="refusing to persist invalid"):
        write_evidence_quality(report, out)

    assert not out.exists()


def test_cli_evidence_quality_refuses_output_overlapping_source(tmp_path: Path) -> None:
    from agentic_security_harness import cli

    run = _write_external_run(
        tmp_path,
        "external",
        model="m1",
        outcomes=["pass"],
        stability_status="stable_pass",
    )
    original_manifest = (run / "run_index.json").read_bytes()

    rc = cli.main([
        "evidence-quality", "--root", str(run), "--out", str(run)
    ])

    assert rc == 1
    assert (run / "run_index.json").read_bytes() == original_manifest
    assert not (run / "evidence_quality.json").exists()
