"""Offline example/checker regressions; real garak source is exercised separately in CI."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import stat
import zipfile
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "garak-gateway"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location("garak_example_" + name, EXAMPLE / (name + ".py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _observation() -> dict[str, Any]:
    runner = _load("check")
    corpus_bytes = (EXAMPLE / "cases.json").read_bytes()
    result = {
        "schema": "GarakGatewayObservation.v1", "data_class": "public_synthetic",
        "manifest_sha256": runner.digest((EXAMPLE / "manifest.json").read_bytes()),
        "corpus_sha256": runner.digest(corpus_bytes), "status": "completed", "error_class": None,
        "garak_source_sha": None, "detector_executed": False, "detector_calls": 0,
        "model_calls": 0, "real_tool_dispatches": 0, "operational_authority": "none",
        "audit": {"network_attempts": 0, "process_attempts": 0, "file_denials": 0,
                  "scratch_write_events": 0},
    }
    result.update(runner.run(json.loads(corpus_bytes), None))
    return result


def test_harness_control_routes_and_independent_checker() -> None:
    result = _observation()
    _load("verify").verify(result)
    assert [row["synthetic_executions"] for row in result["cases"]] == [1, 0, 0, 0]
    assert [row["gateway"] for row in result["cases"]] == [
        "allow", "deny", "not_evaluated", "deny"]
    assert all(row["detector_status"] == "not_run" for row in result["cases"])
    with pytest.raises(ValueError):
        _load("verify").verify(result, require_detector=True)


def test_committed_actual_detector_observation_is_independently_consistent() -> None:
    result = json.loads((EXAMPLE / "observation.windows.json").read_bytes())
    _load("verify").verify(result, require_detector=True)


@pytest.mark.parametrize(("field", "bad"), [
    ("manifest_sha256", "0" * 64), ("corpus_sha256", "0" * 64),
    ("operational_authority", "admin"), ("real_tool_dispatches", 1),
    ("model_calls", 1), ("raw_response", "unwanted"), ("detector_calls", 4),
])
def test_checker_rejects_header_mutation(field: str, bad: Any) -> None:
    result = _observation()
    result[field] = bad
    with pytest.raises(ValueError):
        _load("verify").verify(result)


@pytest.mark.parametrize(("index", "field", "bad"), [
    (0, "synthetic_executions", 0), (1, "synthetic_executions", 1),
    (2, "gateway", "allow"), (0, "result_sha256", "0" * 64),
    (1, "audit_sha256", "0" * 64), (0, "decision_sha256", "0" * 64),
    (3, "gateway_reason", "synthetic_tool_allowed"), (0, "output_index", True),
    (0, "detector_score", 0.0), (0, "raw_response", "unwanted"),
])
def test_checker_rejects_row_mutation(index: int, field: str, bad: Any) -> None:
    result = copy.deepcopy(_observation())
    result["cases"][index][field] = bad
    with pytest.raises(ValueError):
        _load("verify").verify(result)


def test_manifest_pins_corpus_and_modules() -> None:
    runner = _load("check")
    manifest = json.loads((EXAMPLE / "manifest.json").read_bytes())
    assert manifest["corpus_sha256"] == runner.digest((EXAMPLE / "cases.json").read_bytes())
    for module, expected in manifest["harness_module_sha256"].items():
        assert runner.digest((ROOT / "src" / "agentic_security_harness" /
                              (module + ".py")).read_bytes()) == expected


def test_documented_source_only_and_non_affiliation_boundary() -> None:
    doc = (ROOT / "docs" / "garak-plan-connector.md").read_text(encoding="utf-8")
    assert "not included in published Harness 1.6.0" in doc
    assert "not an official NVIDIA component" in doc
    assert "unmerged at selection" in doc
    assert "not an OS sandbox" in doc
    assert "no garak dependency" in doc
    assert "garak-plan-connector.md" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_source_origins_accept_only_pinned_files_or_namespace_paths(tmp_path: Path) -> None:
    runner = _load("check")
    good = SimpleNamespace(__file__=str(tmp_path / "garak" / "attempt.py"))
    namespace = SimpleNamespace(__spec__=SimpleNamespace(
        submodule_search_locations=[str(tmp_path / "garak" / "namespace")]))
    runner.verify_garak_origins({"garak.attempt": good, "garak.ns": namespace,
                                "garak.missing": None}, tmp_path)
    for bad in (SimpleNamespace(), SimpleNamespace(__file__=str(tmp_path / "outside.py")),
                SimpleNamespace(__spec__=SimpleNamespace(submodule_search_locations=[
                    str(tmp_path / "garak"), str(tmp_path / "outside")]))):
        with pytest.raises(ValueError):
            runner.verify_garak_origins({"garak.untrusted": bad}, tmp_path)


@pytest.mark.parametrize(("event", "arguments", "counter"), [
    ("subprocess.Popen", (), "process_attempts"),
    ("socket.connect", (), "network_attempts"),
    ("os.system", (), "process_attempts"),
])
def test_guard_denies_effect_before_execution(
    tmp_path: Path, event: str, arguments: tuple[Any, ...], counter: str,
) -> None:
    guard = _load("check").EffectGuard(tmp_path / "out.json", tmp_path / "scratch", None)
    with pytest.raises(PermissionError):
        guard(event, arguments)
    assert guard.counts[counter] == 1


def test_guard_rejects_outside_write_and_rename(tmp_path: Path) -> None:
    guard = _load("check").EffectGuard(tmp_path / "out.json", tmp_path / "scratch", None)
    with pytest.raises(PermissionError):
        guard("open", (str(tmp_path / "unapproved.txt"), "w", 0))
    with pytest.raises(PermissionError):
        guard("os.rename", (str(tmp_path / "scratch" / "data"), str(tmp_path / "outside")))
    assert guard.counts["file_denials"] == 2


def test_tree_hash_has_platform_independent_case_sensitive_order(tmp_path: Path) -> None:
    runner = _load("check")
    for name in ("z.py", "A.py", "b.py"):
        (tmp_path / name).write_bytes(b"public fixture")
    rows = [name + "\0" + runner.digest(b"public fixture") for name in ("A.py", "b.py", "z.py")]
    assert runner.tree_digest(tmp_path) == runner.digest("\n".join(rows).encode("utf-8"))


@pytest.mark.parametrize("cached", ["module.pyc", "__pycache__/module.cpython-311.pyc"])
def test_source_tree_rejects_unbound_bytecode(tmp_path: Path, cached: str) -> None:
    path = tmp_path / cached
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(b"inert synthetic bytes, not executable bytecode")
    with pytest.raises(ValueError, match="bytecode"):
        _load("check").tree_digest(tmp_path)


def test_source_archive_link_is_inert_text_and_never_followed(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        link = zipfile.ZipInfo("pinned/calibration.json")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        bundle.writestr(link, b"public-target.json")
    with zipfile.ZipFile(buffer) as bundle:
        _load("prepare_source").extract_checked(bundle, tmp_path / "source",
                                                 {"pinned/calibration.json"})
    extracted = tmp_path / "source/pinned/calibration.json"
    assert not extracted.is_symlink()
    assert extracted.read_bytes() == b"public-target.json"
    with zipfile.ZipFile(buffer) as bundle, pytest.raises(ValueError):
        _load("prepare_source").extract_checked(bundle, tmp_path / "rejected", set())
    assert not (tmp_path / "rejected").exists()


def test_source_archive_rejects_traversal_before_extraction(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("../outside.txt", b"public fixture")
    with zipfile.ZipFile(buffer) as bundle, pytest.raises(ValueError):
        _load("prepare_source").extract_checked(bundle, tmp_path / "source", set())
    assert not (tmp_path / "source").exists()
