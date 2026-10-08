"""Public CLI planned work uses real writes and a scripted local transport."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import cli
from agentic_security_harness.document_workflow import DocumentConfig
from test_document_workflow import reply, setup


def spec_for(root: Path, source: Path) -> Path:
    requirements = root / "requirements.json"
    requirements.write_text(json.dumps({
        "schema_version": "ash.document-requirements.v1", "mode": "exact_json",
        "expected_json": {"ok": True},
    }), encoding="utf-8")
    spec = root / "spec.json"
    spec.write_text(json.dumps({
        "schema_version": "ash.document-plan-spec.v1", "jobs": [
            {"job_id": "first", "task": "Return JSON with ok true", "input": source.name,
             "requirements": requirements.name},
            {"job_id": "second", "task": "Keep the same JSON", "from_job": "first",
             "requirements": requirements.name},
        ],
    }), encoding="utf-8")
    return spec


def invoke(capsys: pytest.CaptureFixture[str], args: list[str]) -> tuple[int, dict[str, Any]]:
    code = cli.main([*args, "--json"])
    return code, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("engine", ["native", "pydantic-ai"])
def test_plan_to_two_job_completion_and_read_only_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    engine: str,
) -> None:
    if engine == "pydantic-ai":
        pytest.importorskip("pydantic_ai")
    config, source, config_path = setup(tmp_path, engine)
    spec = spec_for(tmp_path, source)
    plan = tmp_path / "plan.json"
    calls = reply(monkeypatch, '{"ok":true}')
    shared = ["--config", str(config_path)]
    prepare = ["document-plan", *shared, "--spec", str(spec), "--out", str(plan)]
    code, preview = invoke(capsys, prepare)
    assert code == 0 and preview["state"] == "preview"
    assert not calls and not plan.exists() and not list(config.jobs_dir.iterdir())
    code, saved = invoke(capsys, [*prepare, "--execute"])
    assert code == 0 and saved["state"] == "planned"
    assert saved["plan_sha256"] == preview["plan_sha256"]
    pinned = ["--plan", str(plan), "--plan-sha256", saved["plan_sha256"]]
    code, missing = invoke(capsys, ["document-coverage", *shared, *pinned])
    assert code == 1 and missing["unresolved_jobs"] == 2
    monkeypatch.chdir(tmp_path.parent)
    for job in ("first", "second"):
        command = ["document-run", *shared, *pinned, "--spec", str(spec), "--job", job]
        code, preview_job = invoke(capsys, command)
        assert code == 0 and preview_job["state"] == "preview"
        count = len(calls)
        code, outcome = invoke(capsys, [*command, "--execute"])
        assert code == 0 and outcome["quality"]["status"] == "checked"
        assert len(calls) == count + 1
    before = {p: p.read_bytes() for p in config.jobs_dir.rglob("*") if p.is_file()}
    code, complete = invoke(capsys, ["document-coverage", *shared, *pinned])
    assert code == 0 and complete["complete"] and complete["declared_quality_checked"] == 2
    assert before == {p: p.read_bytes() for p in before}
    code, _ = invoke(capsys, ["document-run", *shared, *pinned,
                             "--spec", str(spec), "--job", "first", "--execute"])
    assert code == 1 and len(calls) == 2
    assert "Public meeting" not in json.dumps(complete)
    assert DocumentConfig.load(config_path) == config


@pytest.mark.parametrize("drift", ["task", "input", "requirements", "plan", "digest"])
def test_changed_recipe_or_anchor_never_calls_or_reserves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    drift: str,
) -> None:
    config, source, config_path = setup(tmp_path)
    spec = spec_for(tmp_path, source)
    plan = tmp_path / "plan.json"
    calls = reply(monkeypatch)
    _, saved = invoke(capsys, ["document-plan", "--config", str(config_path),
                              "--spec", str(spec), "--out", str(plan), "--execute"])
    anchor = saved["plan_sha256"]
    if drift == "task":
        value = json.loads(spec.read_bytes())
        value["jobs"][0]["task"] = "PRIVATE_SENTINEL changed task"
        spec.write_text(json.dumps(value))
    elif drift == "input":
        source.write_text("PRIVATE_SENTINEL changed source")
    elif drift == "requirements":
        path = tmp_path / "requirements.json"
        value = json.loads(path.read_bytes())
        value["expected_json"] = {"ok": False}
        path.write_text(json.dumps(value))
    elif drift == "plan":
        value = json.loads(plan.read_bytes())
        value["jobs"][0]["task_sha256"] = "0" * 64
        plan.write_text(json.dumps(value))
    else:
        anchor = "0" * 64
    code, result = invoke(capsys, ["document-run", "--config", str(config_path),
                                  "--spec", str(spec), "--job", "first", "--plan", str(plan),
                                  "--plan-sha256", anchor, "--execute"])
    assert code == 1 and result["state"] == "error"
    assert not calls and not list(config.jobs_dir.iterdir())
    assert "PRIVATE_SENTINEL" not in json.dumps(result)


@pytest.mark.parametrize("extra", [
    ["--task", "override"], ["--requirements", "override.json"],
    ["--source-restrictions", "override.json"],
    ["--recover-source"],
])
def test_spec_disallows_hidden_execution_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    extra: list[str],
) -> None:
    config, source, config_path = setup(tmp_path)
    spec = spec_for(tmp_path, source)
    calls = reply(monkeypatch)
    code, result = invoke(capsys, ["document-run", "--config", str(config_path),
                                  "--spec", str(spec), "--job", "first", "--plan", "plan.json",
                                  "--plan-sha256", "a" * 64, "--execute", *extra])
    assert code == 1 and result["state"] == "error"
    assert not calls and not list(config.jobs_dir.iterdir())


@pytest.mark.parametrize("extra", [[], ["--plan", "plan.json"],
                                   ["--plan-sha256", "a" * 64]])
def test_spec_requires_both_plan_and_independent_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    extra: list[str],
) -> None:
    config, source, config_path = setup(tmp_path)
    spec = spec_for(tmp_path, source)
    calls = reply(monkeypatch)
    code, _ = invoke(capsys, ["document-run", "--config", str(config_path),
                             "--spec", str(spec), "--job", "first", "--execute", *extra])
    assert code == 1 and not calls and not list(config.jobs_dir.iterdir())


def test_plan_human_output_exposes_anchor_not_task_or_source(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    _, source, config_path = setup(tmp_path)
    spec = spec_for(tmp_path, source)
    assert cli.main(["document-plan", "--config", str(config_path), "--spec", str(spec),
                     "--out", str(tmp_path / "plan.json")]) == 0
    output = capsys.readouterr().out
    assert "Plan SHA-256:" in output and "Retain this digest separately" in output
    assert "Public meeting" not in output and "Return JSON" not in output


def test_failed_quality_handoff_has_specific_reason_and_review_cannot_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    config, source, config_path = setup(tmp_path)
    spec = spec_for(tmp_path, source)
    plan = tmp_path / "plan.json"
    calls = reply(monkeypatch, '{"ok":false}')
    common = ["--config", str(config_path)]
    _, saved = invoke(capsys, ["document-plan", *common, "--spec", str(spec),
                              "--out", str(plan), "--execute"])
    run = ["document-run", *common, "--spec", str(spec), "--plan", str(plan),
           "--plan-sha256", saved["plan_sha256"], "--execute"]
    code, first = invoke(capsys, [*run, "--job", "first"])
    assert code == 2 and first["quality"]["status"] == "failed"
    for extra in ([], ["--reviewed-source-sha256", first["quality"]["content_sha256"]]):
        code, denied = invoke(capsys, [*run, "--job", "second", *extra])
        assert code == 1 and denied["reason"] == "source_quality_failed"
        assert denied["next_step"] == "review_failed_document_requirements_do_not_chain"
        assert denied["model"]["transport_attempts"] == 0 and denied["effect"] == "none"
        assert len(calls) == 1 and not (config.jobs_dir / "second").exists()
