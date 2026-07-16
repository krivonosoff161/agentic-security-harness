"""Tests for run stats, retention planning, and model comparisons."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from agentic_security_harness import cli
from agentic_security_harness import stats as stats_module
from agentic_security_harness.run_manifest import build_manifest, write_run_manifest
from agentic_security_harness.safe_io import write_text_artifact
from agentic_security_harness.stats import (
    RetentionCandidate,
    RunStats,
    RunStatsSource,
    apply_retention_plan,
    build_retention_plan,
    build_run_stats,
    build_stats_md,
    run_stats_manifest_projection,
    write_run_stats,
)
from agentic_security_harness.validation import validate_path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _manifested_run(root: Path, name: str, created_at: str, target: str = "mock") -> Path:
    run_dir = root / name
    assert cli.main(["run", "--target", target, "--out", str(run_dir)]) == 0
    manifest_path = run_dir / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["created_at"] = created_at
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return run_dir


def test_build_and_write_run_stats(tmp_path: Path) -> None:
    _manifested_run(tmp_path, "a", "2026-06-14T00:00:00Z")
    _manifested_run(tmp_path, "b", "2026-06-15T00:00:00Z", target="demo-agent")

    stats = build_run_stats(tmp_path)
    assert stats.total_runs == 2
    assert stats.by_kind == {"run": 2}
    assert stats.by_scenario == {"seed-corpus": 2}
    assert stats.by_expectation_status == {"ok": 2}
    assert stats.expectation_validation_scope == "independently_recomputed_at_generation"
    assert len(stats.validator_source_fingerprint) == 64
    assert stats.outcome_totals

    paths = write_run_stats(stats, tmp_path / "stats")
    assert paths["run_stats_json"].exists()
    assert paths["run_stats_md"].exists()
    assert paths["run_index"].exists()
    payload = json.loads(paths["run_stats_json"].read_text(encoding="utf-8"))
    assert payload["root"] == tmp_path.name
    assert payload["schema_version"] == "0.2"
    assert {source["expectation_status"] for source in payload["sources"]} == {"ok"}
    assert str(tmp_path).replace("\\", "/") not in json.dumps(payload)
    validation = validate_path(tmp_path / "stats")
    assert validation.ok, validation.errors
    assert validation.run_stats_dirs == ["stats"]


def test_nonempty_legacy_run_stats_bundle_retains_v01_projection(tmp_path: Path) -> None:
    out = tmp_path / "legacy-stats"
    out.mkdir()
    stats = RunStats(
        schema_version="0.1",
        root="legacy-root",
        total_runs=1,
        by_kind={"run": 1},
        by_scenario={"legacy": 1},
        by_target_or_model={"legacy-target": 1},
        outcome_totals={"passed": 1},
        sources=[
            RunStatsSource(
                run_id="run_legacy",
                manifest_sha256="a" * 64,
                run_kind="run",
                scenario="legacy",
                target_or_model="legacy-target",
                outcomes={"passed": 1},
            )
        ],
    )
    write_text_artifact(out / "run_stats.json", stats.model_dump_json(indent=2))
    write_text_artifact(out / "run_stats.md", build_stats_md(stats))
    projection = run_stats_manifest_projection(stats)
    write_run_manifest(
        out,
        build_manifest(
            "run_stats",
            out,
            target=str(projection["target"]),
            scenario=str(projection["scenario"]),
            outcomes=projection["outcomes"],  # type: ignore[arg-type]
            metadata=projection["metadata"],  # type: ignore[arg-type]
            artifacts=["run_stats.json", "run_stats.md"],
        ),
    )

    result = validate_path(out)

    assert result.ok, result.errors
    assert "Behavioral expectation status" not in (out / "run_stats.md").read_text(
        encoding="utf-8"
    )


def test_retention_plan_and_apply(tmp_path: Path) -> None:
    oldest = _manifested_run(tmp_path, "oldest", "2026-06-13T00:00:00Z")
    middle = _manifested_run(tmp_path, "middle", "2026-06-14T00:00:00Z")
    newest = _manifested_run(tmp_path, "newest", "2026-06-15T00:00:00Z")

    plan = build_retention_plan(tmp_path, keep_last=1, kinds=["run"])

    assert [Path(c.run_dir).name for c in plan.candidates] == ["oldest", "middle"]
    assert plan.chronology_authority == "unsigned_manifest_created_at"
    assert plan.requires_explicit_chronology_acceptance is True
    assert oldest.exists() and middle.exists() and newest.exists()

    with pytest.raises(ValueError, match="chronology is unsigned"):
        apply_retention_plan(plan)
    assert oldest.exists() and middle.exists() and newest.exists()

    applied = apply_retention_plan(plan, accept_unsigned_chronology=True)
    assert applied.applied is True
    assert applied.removed == 2
    assert not oldest.exists()
    assert not middle.exists()
    assert newest.exists()


def test_cli_stats_and_retention_dry_run(tmp_path: Path) -> None:
    run_dir = _manifested_run(tmp_path, "run1", "2026-06-15T00:00:00Z")
    assert cli.main(["stats", "--root", str(tmp_path), "--out", str(tmp_path / "stats")]) == 0
    assert (tmp_path / "stats" / "run_stats.json").exists()

    assert cli.main(["retention", "--root", str(tmp_path), "--keep-last", "1"]) == 0
    assert run_dir.exists()


def test_cli_stats_json(capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    _manifested_run(tmp_path, "run1", "2026-06-15T00:00:00Z")
    capsys.readouterr()

    assert cli.main(["stats", "--root", str(tmp_path), "--format", "json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["total_runs"] == 1
    assert payload["by_kind"] == {"run": 1}


def test_cli_stats_refuses_output_overlapping_source(tmp_path: Path) -> None:
    run_dir = _manifested_run(tmp_path, "run1", "2026-06-15T00:00:00Z")
    original_manifest = (run_dir / "run_index.json").read_bytes()

    rc = cli.main(["stats", "--root", str(tmp_path), "--out", str(run_dir)])

    assert rc == 1
    assert (run_dir / "run_index.json").read_bytes() == original_manifest
    assert not (run_dir / "run_stats.json").exists()


def test_validate_run_stats_rejects_rehashed_aggregate_tamper(tmp_path: Path) -> None:
    _manifested_run(tmp_path, "run1", "2026-06-15T00:00:00Z")
    out = tmp_path / "stats"
    write_run_stats(build_run_stats(tmp_path), out)
    json_path = out / "run_stats.json"
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    payload["total_runs"] = 99
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_sha256"]["run_stats.json"] = hashlib.sha256(
        json_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    validation = validate_path(out)

    assert not validation.ok
    assert any("total_runs does not match sources" in error for error in validation.errors)


def test_validate_run_stats_rejects_rehashed_expectation_status_tamper(
    tmp_path: Path,
) -> None:
    _manifested_run(tmp_path, "run1", "2026-06-15T00:00:00Z")
    out = tmp_path / "stats"
    write_run_stats(build_run_stats(tmp_path), out)
    json_path = out / "run_stats.json"
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    payload["sources"][0]["expectation_mismatch_count"] = 1
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_sha256"]["run_stats.json"] = hashlib.sha256(
        json_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    validation = validate_path(out)

    assert not validation.integrity_ok
    assert any(
        "ok expectation status cannot have mismatches" in error
        for error in validation.errors
    )


def test_cli_retention_json(capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    _manifested_run(tmp_path, "old", "2026-06-14T00:00:00Z")
    _manifested_run(tmp_path, "new", "2026-06-15T00:00:00Z")
    capsys.readouterr()

    assert cli.main([
        "retention",
        "--root",
        str(tmp_path),
        "--keep-last",
        "1",
        "--format",
        "json",
    ]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["applied"] is False
    assert len(payload["candidates"]) == 1
    assert payload["root"] == "<run-root>"
    assert payload["candidates"][0]["run_dir"] == "old"
    assert str(tmp_path).replace("\\", "/") not in json.dumps(payload)
    assert payload["chronology_authority"] == "unsigned_manifest_created_at"
    assert payload["requires_explicit_chronology_acceptance"] is True


def test_cli_retention_text_uses_portable_candidate_paths(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    _manifested_run(tmp_path, "old", "2026-06-14T00:00:00Z")
    _manifested_run(tmp_path, "new", "2026-06-15T00:00:00Z")
    capsys.readouterr()

    assert cli.main(["retention", "--root", str(tmp_path), "--keep-last", "1"]) == 0

    output = capsys.readouterr().out
    assert "Retention plan for <run-root>" in output
    assert str(tmp_path).replace("\\", "/") not in output.replace("\\", "/")
    assert " old " in output


def test_cli_retention_apply_requires_unsigned_chronology_acceptance(
    tmp_path: Path,
) -> None:
    old = _manifested_run(tmp_path, "old", "2026-06-14T00:00:00Z")
    new = _manifested_run(tmp_path, "new", "2026-06-15T00:00:00Z")

    blocked = cli.main(
        ["retention", "--root", str(tmp_path), "--keep-last", "1", "--apply"]
    )

    assert blocked == 1
    assert old.exists() and new.exists()

    applied = cli.main(
        [
            "retention",
            "--root",
            str(tmp_path),
            "--keep-last",
            "1",
            "--apply",
            "--accept-unsigned-chronology",
        ]
    )

    assert applied == 0
    assert not old.exists()
    assert new.exists()


def test_cli_retention_rejects_bad_kind(tmp_path: Path) -> None:
    assert cli.main(["retention", "--root", str(tmp_path), "--kind", "bogus"]) == 1


def test_run_history_ignores_parseable_but_unvalidated_manifest(tmp_path: Path) -> None:
    forged = tmp_path / "forged"
    forged.mkdir()
    payload = json.loads(
        (EXAMPLES / "demo-agent-report" / "run_index.json").read_text(encoding="utf-8")
    )
    payload["schema_version"] = "0.3"
    payload["execution_id"] = "run_" + ("f" * 32)
    payload["run_id"] = payload["execution_id"]
    payload["artifact_sha256"] = {}
    (forged / "run_index.json").write_text(json.dumps(payload), encoding="utf-8")

    assert build_run_stats(tmp_path).total_runs == 0
    assert build_retention_plan(tmp_path, keep_last=1).candidates == []


def test_retention_apply_rejects_post_plan_manifest_tampering(tmp_path: Path) -> None:
    oldest = _manifested_run(tmp_path, "oldest", "2026-06-12T00:00:00Z")
    middle = _manifested_run(tmp_path, "middle", "2026-06-13T00:00:00Z")
    _manifested_run(tmp_path, "newest", "2026-06-15T00:00:00Z")
    plan = build_retention_plan(tmp_path, keep_last=1)
    manifest_path = middle / "run_index.json"
    manifest_path.write_text(manifest_path.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(ValueError, match="changed after planning"):
        apply_retention_plan(plan, accept_unsigned_chronology=True)
    assert oldest.exists()
    assert middle.exists()


def test_retention_apply_rejects_forged_current_candidate(tmp_path: Path) -> None:
    old = _manifested_run(tmp_path, "old", "2026-06-14T00:00:00Z")
    new = _manifested_run(tmp_path, "new", "2026-06-15T00:00:00Z")
    plan = build_retention_plan(tmp_path, keep_last=1)
    new_manifest_path = new / "run_index.json"
    new_manifest = json.loads(new_manifest_path.read_text(encoding="utf-8"))
    forged_candidate = plan.candidates[0].model_copy(update={
        "run_id": new_manifest["run_id"],
        "run_dir": new.resolve().as_posix(),
        "manifest_sha256": hashlib.sha256(new_manifest_path.read_bytes()).hexdigest(),
    })
    forged = plan.model_copy(update={"candidates": [forged_candidate]})

    with pytest.raises(ValueError, match="not produced by the current scan"):
        apply_retention_plan(forged, accept_unsigned_chronology=True)

    assert old.exists() and new.exists()


def test_retention_apply_rechecks_immediately_before_first_delete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    old = _manifested_run(tmp_path, "old", "2026-06-14T00:00:00Z")
    new = _manifested_run(tmp_path, "new", "2026-06-15T00:00:00Z")
    plan = build_retention_plan(tmp_path, keep_last=1)
    original = stats_module._validate_retention_candidate
    calls = 0

    def mutate_before_delete(root: Path, candidate: RetentionCandidate) -> Path:
        nonlocal calls
        calls += 1
        if calls == 2:
            manifest_path = old / "run_index.json"
            manifest_path.write_text(
                manifest_path.read_text(encoding="utf-8") + " ",
                encoding="utf-8",
            )
        return original(root, candidate)

    monkeypatch.setattr(
        stats_module,
        "_validate_retention_candidate",
        mutate_before_delete,
    )

    with pytest.raises(ValueError, match="changed after planning"):
        apply_retention_plan(plan, accept_unsigned_chronology=True)

    assert old.exists() and new.exists()


def test_cli_compare_models_writes_external_diff(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    shutil.copytree(EXAMPLES / "external-demo-report", left)
    shutil.copytree(EXAMPLES / "external-demo-report", right)

    out = tmp_path / "model-diff"
    assert cli.main(["compare-models", "--left", str(left), "--right", str(right),
                     "--out", str(out)]) == 0
    assert (out / "run_diff.json").exists()
    result = validate_path(out)
    assert result.ok, result.errors


def test_cli_compare_models_json(capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    left = tmp_path / "left"
    right = tmp_path / "right"
    shutil.copytree(EXAMPLES / "external-demo-report", left)
    shutil.copytree(EXAMPLES / "external-demo-report", right)

    assert cli.main([
        "compare-models",
        "--left",
        str(left),
        "--right",
        str(right),
        "--out",
        str(tmp_path / "model-diff"),
        "--format",
        "json",
    ]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "external"
    # external-demo-report is all pass -> compared with itself everything is stable_pass.
    assert payload["stable_pass"] > 0


def test_cli_compare_models_rejects_non_external(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    assert cli.main(["compare-models", "--left", str(run_dir), "--right", str(run_dir),
                     "--out", str(tmp_path / "out")]) == 1
