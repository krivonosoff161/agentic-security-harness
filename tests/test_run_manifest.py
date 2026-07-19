"""Tests for the run manifest layer (run_index.json), list-runs CLI, and validation."""

import ast
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agentic_security_harness import cli
from agentic_security_harness.remediation import _FAMILY_MAP
from agentic_security_harness.run_manifest import (
    RunManifest,
    build_manifest,
    load_run_manifests,
    load_validated_run_manifests,
    make_config_fingerprint,
    make_run_id,
    write_run_manifest,
)
from agentic_security_harness.validation import validate_path

# --- module-level model tests ---


def test_every_manifested_producer_uses_atomic_bundle_publication() -> None:
    package = Path(__file__).resolve().parents[1] / "src" / "agentic_security_harness"
    producers: list[str] = []
    for path in sorted(package.glob("*.py")):
        if path.name == "run_manifest.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = [
                (child.lineno, child.func.id)
                for child in ast.walk(node)
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
            ]
            manifest_lines = [
                line for line, name in calls if name == "write_run_manifest"
            ]
            if not manifest_lines:
                continue
            fresh_lines = [
                line for line, name in calls if name == "require_fresh_output_dir"
            ]
            staged_lines = [
                line for line, name in calls if name == "staged_evidence_bundle"
            ]
            atomic_decorators = [
                decorator
                for decorator in node.decorator_list
                if isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Name)
                and decorator.func.id
                in {"atomic_evidence_bundle", "atomic_private_bundle"}
            ]
            label = f"{path.name}:{node.name}"
            producers.append(label)
            assert atomic_decorators or staged_lines, label
            if atomic_decorators:
                assert fresh_lines, label
                assert min(fresh_lines) < min(manifest_lines), label
            else:
                assert min(staged_lines) < min(manifest_lines), label

    assert len(producers) >= 24


def test_manifest_discovery_ignores_unpublished_staging_generations(
    tmp_path: Path,
) -> None:
    staging = tmp_path / f".run.ash-staging-{'0' * 32}"
    staging.mkdir()
    write_run_manifest(staging, build_manifest("run", staging, target="mock"))

    assert load_run_manifests(tmp_path) == []


def test_validated_manifest_loader_rejects_nested_only_validation(
    tmp_path: Path,
) -> None:
    container = tmp_path / "container"
    child = container / "child"
    cli.main(["run", "--target", "mock", "--out", str(child)])
    write_run_manifest(container, build_manifest("run", container, target="mock"))

    loaded = load_validated_run_manifests(container)

    assert [path.parent for path, _manifest in loaded] == [child]


def test_validated_manifest_loader_rejects_manifest_changed_during_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])

    from agentic_security_harness import validation

    original_validate = validation.validate_artifact_path

    def mutate_after_validation(path: Path):  # type: ignore[no-untyped-def]
        result = original_validate(path)
        manifest_path = path / "run_index.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["target"] = "changed-after-validation"
        manifest_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return result

    monkeypatch.setattr(validation, "validate_artifact_path", mutate_after_validation)

    assert load_validated_run_manifests(tmp_path) == []


def _pattern_id_from_request(req: object) -> str:
    body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
    for message in body.get("messages", []):
        for line in str(message.get("content", "")).splitlines():
            if line.startswith("Pattern: "):
                return line.split("Pattern: ", 1)[1].strip()
    return "unknown"


def _mock_external_open(req: object, *args: object, **kwargs: object) -> MagicMock:
    pattern_id = _pattern_id_from_request(req)
    resp = MagicMock()
    content = json.dumps(
        {
            "pattern_id": pattern_id,
            "decision": "block",
            "boundary_assertion": "preserve_boundary",
            "reason": "boundary preserved",
            "control_family": _FAMILY_MAP.get(pattern_id, "data_boundary"),
            "would_preserve_boundary": True,
        }
    )
    requested_model = json.loads(req.data.decode("utf-8"))["model"]  # type: ignore[attr-defined]
    resp.read.return_value = json.dumps(
        {"model": requested_model, "choices": [{"message": {"content": content}}]}
    ).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def test_make_run_id_is_deterministic() -> None:
    a = make_run_id("run", "mock", "", "seed-corpus", [], 1)
    b = make_run_id("run", "mock", "", "seed-corpus", [], 1)
    assert a == b
    assert a.startswith("run_")


def test_make_run_id_varies_with_config() -> None:
    a = make_run_id("run", "mock", "", "seed-corpus", [], 1)
    b = make_run_id("run", "demo-agent", "", "seed-corpus", [], 1)
    assert a != b


def test_build_manifest_separates_execution_from_configuration(tmp_path: Path) -> None:
    first = build_manifest("run", tmp_path / "a", target="mock")
    second = build_manifest("run", tmp_path / "b", target="mock")

    assert first.execution_id != second.execution_id
    assert first.run_id == first.execution_id
    assert second.run_id == second.execution_id
    assert first.config_fingerprint == second.config_fingerprint
    assert first.config_fingerprint == make_config_fingerprint("run", "mock", "", "", [], 1)


def test_build_manifest_rejects_unknown_kind(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown run_kind"):
        build_manifest("not-a-kind", tmp_path)


def test_write_and_load_manifest(tmp_path: Path) -> None:
    run_dir = tmp_path / "r1"
    run_dir.mkdir()
    (run_dir / "executive.md").write_text("x", encoding="utf-8")
    manifest = build_manifest(
        "run",
        run_dir,
        target="mock",
        scenario="seed-corpus",
        outcomes={"failed": 0, "passed": 24},
        artifacts=["executive.md"],
        tool_version="0.11.0",
        created_at="2026-06-14T00:00:00Z",
    )
    path = write_run_manifest(run_dir, manifest)
    assert path.name == "run_index.json"
    loaded = RunManifest.model_validate(json.loads(path.read_text(encoding="utf-8")))
    assert loaded.run_id == manifest.run_id
    assert loaded.execution_id == manifest.execution_id
    assert loaded.config_fingerprint == manifest.config_fingerprint
    assert loaded.outcomes == {"failed": 0, "passed": 24}
    assert loaded.artifact_sha256 == {"executive.md": hashlib.sha256(b"x").hexdigest()}


def test_load_run_manifests_skips_malformed(tmp_path: Path) -> None:
    good = tmp_path / "good"
    good.mkdir()
    write_run_manifest(good, build_manifest("run", good, target="mock"))
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "run_index.json").write_text("{ not json", encoding="utf-8")

    found = load_run_manifests(tmp_path)
    assert len(found) == 1
    assert found[0][1].target == "mock"


def test_load_run_manifests_missing_root(tmp_path: Path) -> None:
    assert load_run_manifests(tmp_path / "nope") == []


# --- CLI integration ---


def test_cli_run_writes_manifest(tmp_path: Path) -> None:
    rc = cli.main(["run", "--target", "mock", "--out", str(tmp_path / "run")])
    assert rc == 0
    manifest_path = tmp_path / "run" / "run_index.json"
    assert manifest_path.exists()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["run_kind"] == "run"
    assert data["run_id"].startswith("run_")
    assert data["execution_id"] == data["run_id"]
    assert data["config_fingerprint"].startswith("cfg_")
    assert "passed" in data["outcomes"]
    assert "traces.json" in data["artifacts"]


def test_cli_list_runs_lists_runs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["run", "--target", "mock", "--out", str(tmp_path / "run")])
    capsys.readouterr()  # clear
    rc = cli.main(["list-runs", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Found 1 current validated run(s)" in out
    assert "run_" in out
    assert "seed-corpus" in out


def test_cli_list_runs_empty(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["list-runs", "--root", str(tmp_path / "empty")])
    assert rc == 0
    assert "No runs found" in capsys.readouterr().out


# --- validation ---


def test_validate_accepts_manifest(tmp_path: Path) -> None:
    cli.main(["run", "--target", "mock", "--out", str(tmp_path / "run")])
    result = validate_path(tmp_path / "run")
    assert result.ok, result.errors


def test_validate_accepts_legacy_v02_manifest_without_artifact_hashes(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    manifest_path = run_dir / "run_index.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["schema_version"] = "0.2"
    del data["artifact_sha256"]
    manifest_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    result = validate_path(run_dir)

    assert result.ok, result.errors


def test_validate_rejects_missing_artifact(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    data = json.loads((run_dir / "run_index.json").read_text(encoding="utf-8"))
    data["artifacts"].append("does_not_exist.md")
    (run_dir / "run_index.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    result = validate_path(run_dir)
    assert not result.ok
    assert any("does_not_exist.md" in e for e in result.errors)


def test_validate_rejects_manifested_artifact_content_tampering(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    (run_dir / "executive.md").write_text("tampered\n", encoding="utf-8")

    result = validate_path(run_dir)

    assert not result.ok
    assert any(
        "artifact_sha256['executive.md'] content mismatch" in error for error in result.errors
    )


def test_validate_rejects_manifest_artifact_path_escape(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    manifest_path = run_dir / "run_index.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["artifacts"].append("../outside.txt")
    data["artifact_sha256"]["../outside.txt"] = "0" * 64
    manifest_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    result = validate_path(run_dir)

    assert not result.ok
    assert any("artifact path escapes the run directory" in error for error in result.errors)


def test_validate_rejects_manifested_symbolic_link(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    summary = run_dir / "summary.md"
    summary.unlink()
    try:
        summary.symlink_to(run_dir / "executive.md")
    except OSError:
        pytest.skip("symbolic links are unavailable in this environment")

    result = validate_path(run_dir)

    assert not result.ok
    accepted_link_errors = (
        "must not traverse a link or reparse point",
        "links or reparse points are not allowed",
        "must not be a symbolic link",
    )
    assert any(
        marker in error
        for error in result.errors
        for marker in accepted_link_errors
    )


def test_validate_rejects_unmanifested_directory_link(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    outside = tmp_path / "outside"
    outside.mkdir()
    link = run_dir / "hidden-tree"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symbolic links are unavailable in this environment")

    result = validate_path(run_dir)

    assert not result.integrity_ok
    assert any("links or reparse points are not allowed" in error for error in result.errors)


def test_validate_rejects_identity_and_configuration_tampering(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    manifest_path = run_dir / "run_index.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["execution_id"] = "run_" + "0" * 32
    data["config_fingerprint"] = "cfg_0000000000"
    manifest_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    result = validate_path(run_dir)

    assert not result.ok
    assert any("run_id must equal execution_id" in error for error in result.errors)
    assert any(
        "config_fingerprint does not match configuration" in error for error in result.errors
    )


def test_validate_rejects_malformed_execution_id(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    manifest_path = run_dir / "run_index.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["run_id"] = data["execution_id"] = "run_not-opaque"
    manifest_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    result = validate_path(run_dir)

    assert not result.ok
    assert any("execution_id has invalid format" in error for error in result.errors)


def test_external_run_writes_metadata(tmp_path: Path) -> None:
    from unittest.mock import patch

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_external_open,
    ):
        rc = cli.main(
            [
                "run-external",
                "--base-url",
                "http://localhost:8000/v1",
                "--model",
                "demo-model",
                "--scenario",
                "data-boundary",
                "--credential-env",
                "ASH_EXTERNAL_API_KEY",
                "--execute",
                "--out",
                str(tmp_path / ".internal" / "ext"),
            ]
        )
    assert rc == 0
    out = tmp_path / ".internal" / "ext"
    data = json.loads((out / "run_index.json").read_text(encoding="utf-8"))
    meta = data["metadata"]
    assert meta["adapter_type"] == "openai-compatible"
    assert meta["model"] == "demo-model"
    assert meta["network_mode"] == "local-only"
    assert meta["runtime_name"] == "local-openai-compatible"
    assert meta["runtime_family"] == "local-runtime"
    assert meta["authorization_mode"] == "local_runtime"
    assert meta["prompt_only"] is True
    assert meta["tool_execution"] is False
    assert meta["credential_env_var"] == "[CREDENTIAL_ENV_VAR_CONFIGURED]"
    assert meta["base_url_label"] == "http://localhost:8000/v1"
    # And the whole external dir still validates with the metadata checks on.
    result = validate_path(out)
    assert result.ok, result.errors


def test_validate_rejects_missing_external_metadata(tmp_path: Path) -> None:
    from unittest.mock import patch

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_external_open,
    ):
        cli.main(
            [
                "run-external",
                "--base-url",
                "http://localhost:8000/v1",
                "--model",
                "m",
                "--scenario",
                "data-boundary",
                "--execute",
                "--out",
                str(tmp_path / ".internal" / "ext"),
            ]
        )
    out = tmp_path / ".internal" / "ext"
    data = json.loads((out / "run_index.json").read_text(encoding="utf-8"))
    del data["metadata"]["network_mode"]
    (out / "run_index.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    result = validate_path(out)
    assert not result.ok
    assert any("metadata missing keys" in e for e in result.errors)


def test_validate_rejects_bad_run_kind(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    data = json.loads((run_dir / "run_index.json").read_text(encoding="utf-8"))
    data["run_kind"] = "bogus"
    (run_dir / "run_index.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    result = validate_path(run_dir)
    assert not result.ok
    assert any("run_kind" in e for e in result.errors)
