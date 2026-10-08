"""Closed host recipe compilation uses local files, never a model or job writer."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness.document_coverage import load_plan
from agentic_security_harness.document_plan import compile_plan, job_arguments, prepare_plan
from agentic_security_harness.document_quality import DocumentRequirements
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.document_workflow import DocumentConfig, run_job
from agentic_security_harness.models import DataEnvelope


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _fixture(tmp_path: Path) -> tuple[DocumentConfig, Path, dict[str, Any]]:
    root = tmp_path / "work" / "jobs"
    root.mkdir(parents=True)
    config = DocumentConfig(root, "local-model:latest", data_class="private")
    spec_dir = tmp_path / "recipe"
    spec_dir.mkdir()
    (spec_dir / "source.txt").write_text("Public synthetic source.\n", encoding="utf-8")
    _write(spec_dir / "requirements.json", DocumentRequirements(
        "exact_json", expected_json={"ok": True},
    ).record())
    raw = (spec_dir / "source.txt").read_bytes()
    binding = DocumentSourceRestrictions.bind(raw, DataEnvelope(
        data_class="private", allowed_recipients=["local-model"],
        allowed_purpose=["document-generation"], can_store=True, can_forward=True,
        ttl_seconds=None, requires_confirmation=False,
        classification_source="host-config", classification_mutable=False,
    ), created_at=datetime.now(UTC))
    _write(spec_dir / "restrictions.json", binding.record())
    spec: dict[str, Any] = {
        "schema_version": "ash.document-plan-spec.v1",
        "jobs": [
            {
                "job_id": "first", "task": "Extract one fact",
                "input": "source.txt", "requirements": "requirements.json",
                "source_restrictions": "restrictions.json",
            },
            {"job_id": "second", "task": "Reframe the first draft", "from_job": "first"},
        ],
    }
    return config, spec_dir / "plan-spec.json", spec


def test_two_step_preview_then_create_once_without_model_or_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, spec_path, spec = _fixture(tmp_path)
    _write(spec_path, spec)
    monkeypatch.chdir(tmp_path / "work")
    plan = compile_plan(config, spec_path)
    assert len(plan.jobs) == 2
    assert plan.jobs[0].input_sha256 == _sha((spec_path.parent / "source.txt").read_bytes())
    assert plan.jobs[1].source_job == "first"
    assert all(job.execution_sha256 is not None for job in plan.jobs)
    args = job_arguments(config, spec_path, "first")
    assert set(args) == {
        "source_path", "task", "source_job", "requirements", "source_restrictions",
        "reviewed_source_sha256", "recover_source",
    }
    assert args["source_path"] == spec_path.parent / "source.txt"
    assert args["source_restrictions"].sha256 == plan.jobs[0].source_restrictions_sha256
    assert job_arguments(config, spec_path, "second")["source_path"] is None
    assert job_arguments(config, spec_path, "second")["reviewed_source_sha256"] is None
    out = tmp_path / "host-plan.json"
    preview = prepare_plan(config, spec_path, out)
    assert preview == {
        "state": "preview", "plan_sha256": plan.sha256,
        "planned_jobs": 2, "writes_performed": False, "authority": "none",
    }
    assert not out.exists() and list(config.jobs_dir.iterdir()) == []
    saved = prepare_plan(config, spec_path, out, execute=True)
    assert saved["state"] == "planned" and saved["plan_sha256"] == plan.sha256
    assert load_plan(out, expected_sha256=plan.sha256) == plan
    with pytest.raises(FileExistsError):
        prepare_plan(config, spec_path, out, execute=True)


def test_spec_relative_paths_are_independent_of_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, spec_path, spec = _fixture(tmp_path)
    _write(spec_path, spec)
    before = compile_plan(config, spec_path)
    monkeypatch.chdir(tmp_path / "work")
    assert compile_plan(config, spec_path) == before


def test_dependent_arguments_need_no_original_or_unrelated_files(tmp_path: Path) -> None:
    config, spec_path, spec = _fixture(tmp_path)
    _write(spec_path, spec)
    plan = compile_plan(config, spec_path)
    (spec_path.parent / "source.txt").unlink()
    (spec_path.parent / "requirements.json").unlink()
    (spec_path.parent / "restrictions.json").unlink()
    args = job_arguments(config, spec_path, "second")
    assert args["source_job"] == "first" and args["source_path"] is None
    assert args["task"] == "Reframe the first draft"
    with pytest.raises(FileNotFoundError):
        compile_plan(config, spec_path)
    assert plan.for_job("second").source_job == "first"
    spec["jobs"][0]["unexpected_authority"] = True
    _write(spec_path, spec)
    with pytest.raises(ValueError, match="closed document job spec"):
        job_arguments(config, spec_path, "second")


@pytest.mark.parametrize("drift", ["source", "requirements"])
def test_selected_drift_still_fails_existing_plan_gate(tmp_path: Path, drift: str) -> None:
    config, spec_path, spec = _fixture(tmp_path)
    if drift == "source":
        del spec["jobs"][0]["source_restrictions"]
    _write(spec_path, spec)
    plan_path = tmp_path / "host-plan.json"
    saved = prepare_plan(config, spec_path, plan_path, execute=True)
    if drift == "source":
        (spec_path.parent / "source.txt").write_text(
            "Changed synthetic source.\n", encoding="utf-8",
        )
    else:
        _write(spec_path.parent / "requirements.json", DocumentRequirements(
            "exact_json", expected_json={"ok": False},
        ).record())
    arguments = job_arguments(config, spec_path, "first")
    with pytest.raises(ValueError, match=(
        "captured input differs" if drift == "source" else "execution differs"
    )):
        run_job(
            config, job_id="first", execute=False,
            run_plan_path=plan_path, run_plan_sha256=saved["plan_sha256"], **arguments,
        )
    assert not list(config.jobs_dir.iterdir())


def test_input_and_quality_drift_change_plan_digest(tmp_path: Path) -> None:
    config, spec_path, spec = _fixture(tmp_path)
    _write(spec_path, spec)
    initial = compile_plan(config, spec_path)
    (spec_path.parent / "source.txt").write_text("Different source.\n", encoding="utf-8")
    with pytest.raises(ValueError, match="restriction digest mismatch"):
        compile_plan(config, spec_path)
    del spec["jobs"][0]["source_restrictions"]
    _write(spec_path, spec)
    changed_input = compile_plan(config, spec_path)
    assert changed_input.sha256 != initial.sha256
    _write(spec_path.parent / "requirements.json", DocumentRequirements(
        "exact_json", expected_json={"ok": False},
    ).record())
    assert compile_plan(config, spec_path).sha256 != changed_input.sha256


@pytest.mark.parametrize("change", [
    "unknown", "oracle", "duplicate", "forward", "both_sources", "no_source",
    "bad_recover", "bad_boolean", "review_without_source", "override_restrictions",
    "bad_task", "absolute_input", "windows_absolute", "null_requirements",
])
def test_malformed_specs_rejected_without_echoing_values(
    tmp_path: Path, change: str,
) -> None:
    config, spec_path, spec = _fixture(tmp_path)
    rows = spec["jobs"]
    if change == "unknown":
        rows[0]["permission_from_model_SECRET"] = True
    elif change == "oracle":
        rows[0]["expected_json_SECRET"] = {"answer": "SECRET"}
    elif change == "duplicate":
        rows[1]["job_id"] = "first"
    elif change == "forward":
        rows[0]["from_job"] = "second"
        del rows[0]["input"]
        del rows[0]["source_restrictions"]
    elif change == "both_sources":
        rows[0]["from_job"] = "second"
    elif change == "no_source":
        del rows[0]["input"]
    elif change == "bad_recover":
        rows[0]["recover_source"] = True
    elif change == "bad_boolean":
        rows[1]["recover_source"] = 1
    elif change == "review_without_source":
        rows[0]["reviewed_source_sha256"] = "a" * 64
    elif change == "override_restrictions":
        rows[1]["source_restrictions"] = "restrictions.json"
    elif change == "bad_task":
        rows[0]["task"] = "x" * 4097
    elif change == "absolute_input":
        rows[0]["input"] = str(spec_path.parent / "source.txt")
    elif change == "windows_absolute":
        rows[0]["input"] = "C:\\private\\source.txt"
    elif change == "null_requirements":
        rows[0]["requirements"] = None
    _write(spec_path, spec)
    with pytest.raises((ValueError, TypeError)) as caught:
        compile_plan(config, spec_path)
    assert "SECRET" not in str(caught.value)


def test_bounded_spec_and_input_and_recovery_mode_binding(tmp_path: Path) -> None:
    config, spec_path, spec = _fixture(tmp_path)
    spec["jobs"][1]["recover_source"] = True
    _write(spec_path, spec)
    original = compile_plan(config, spec_path)
    args = job_arguments(config, spec_path, "second")
    assert args["recover_source"] is True and args["reviewed_source_sha256"] is None
    changed = copy.deepcopy(spec)
    changed["jobs"][1]["recover_source"] = False
    _write(spec_path, changed)
    assert compile_plan(config, spec_path).sha256 != original.sha256
    (spec_path.parent / "source.txt").write_bytes(b"a" * 16385)
    with pytest.raises(ValueError, match="size rejected"):
        compile_plan(config, spec_path)
    spec_path.write_bytes(b" " * 65537)
    with pytest.raises(ValueError, match="size rejected"):
        compile_plan(config, spec_path)
