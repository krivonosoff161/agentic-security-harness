"""The public seed is checked against fixed source cases, not its own checksum."""

from __future__ import annotations

import copy
import importlib.util
import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import pytest
from tools import export_boundary_seed as seed


def _synthetic_dataset() -> dict[str, Any]:
    cases = seed.fixed_cases()
    rows = [{"actual": seed._expected(case)} for case in cases]
    return seed.build_dataset(cases, rows, "a" * 64)


def test_literal_corpus_and_path_free_seed_validate_without_optional_framework() -> None:
    cases = seed.fixed_cases()
    assert len(cases) == 8
    assert [case["split"] for case in cases] == ["development"] * 4 + ["heldout"] * 4
    dataset = _synthetic_dataset()
    seed.verify_dataset(dataset)
    assert dataset["model_calls"] == dataset["provider_calls"] == 0
    assert [row["split"] for row in dataset["rows"]] == (
        ["development"] * 4 + ["evaluation_reserved_known"] * 4
    )
    assert dataset["blind_independent_labels"] is False
    assert dataset["trained_model"] is False
    assert "C:/" not in json.dumps(dataset) and "E:/" not in json.dumps(dataset)


@pytest.mark.parametrize(
    "field,value",
    [
        ("input", "forged input"),
        ("input_sha256", "0" * 64),
        ("trusted_labels", {**seed.LABELS, "authority": "owner"}),
        ("expected", {"reason": "write_completed", "applied": True,
                      "report_sha256": "0" * 64, "protected_sha256": "0" * 64}),
        ("actual", {"reason": "write_completed", "applied": True,
                    "report_sha256": "0" * 64, "protected_sha256": "0" * 64}),
        ("effect_after", {"report": {"bytes": 0, "sha256": "0" * 64},
                          "protected": {"bytes": 0, "sha256": "0" * 64}}),
        ("split", "evaluation_reserved_known"),
    ],
)
def test_recomputed_digest_does_not_hide_row_tampering(field: str, value: object) -> None:
    dataset = _synthetic_dataset()
    dataset["rows"][0][field] = value
    dataset["dataset_sha256"] = seed._digest_dataset(dataset)
    with pytest.raises(ValueError, match="dataset_row_mismatch"):
        seed.verify_dataset(dataset)


def test_duplicate_and_cross_split_rows_fail_after_checksum_recalculation() -> None:
    for index in (0, 4):
        dataset = _synthetic_dataset()
        dataset["rows"][index] = copy.deepcopy(dataset["rows"][1])
        dataset["dataset_sha256"] = seed._digest_dataset(dataset)
        with pytest.raises(ValueError, match="dataset_row_mismatch"):
            seed.verify_dataset(dataset)


@pytest.mark.parametrize("field,value", [("actual", 1), ("effect_bytes", 8.0)])
def test_recomputed_digest_does_not_hide_bool_integer_or_float_substitution(
    field: str, value: object,
) -> None:
    dataset = _synthetic_dataset()
    if field == "actual":
        dataset["rows"][0]["actual"]["applied"] = value
    else:
        dataset["rows"][0]["effect_after"]["report"]["bytes"] = value
    dataset["dataset_sha256"] = seed._digest_dataset(dataset)
    with pytest.raises(ValueError, match="dataset_row_mismatch"):
        seed.verify_dataset(dataset)


def test_dataset_digest_and_duplicate_json_keys_fail(tmp_path: Path) -> None:
    dataset = _synthetic_dataset()
    dataset["dataset_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="dataset_digest"):
        seed.verify_dataset(dataset)
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_bytes(b'{"schema":"BoundaryEvaluationSeed.v1","schema":"forged"}')
    with pytest.raises(ValueError, match="duplicate_json_key"):
        seed.read_json(duplicate)


def test_capture_source_pin_mismatch_stops_before_readback(tmp_path: Path) -> None:
    cases = seed.fixed_cases()
    source_hashes = {name: seed.sha((seed.SOURCE / name).read_bytes())
                     for name in seed.SOURCE_NAMES}
    manifest = {
        "schema": "PydanticAIExperiment.v1", "repetitions": 1,
        "cases_per_repetition": 8, "model_calls": 0,
        "framework": "pydantic-ai-slim==1.107.1",
        "example_sha256": seed.sha(seed.EXAMPLE.read_bytes()),
        "checker_sha256": seed.sha(seed.CHECKER.read_bytes()),
        "corpus_sha256": seed.sha(seed.canonical(cases)), "corpus": cases,
        "source_hashes": source_hashes,
        "data_class": "public_synthetic", "independent_human_review": False,
    }
    source_hashes[seed.SOURCE_NAMES[0]] = "0" * 64
    (tmp_path / "manifest.json").write_bytes(seed.canonical(manifest) + b"\n")
    (tmp_path / "verification.json").write_bytes(b"{}\n")
    with pytest.raises(ValueError, match="capture_manifest_pin"):
        seed.verify_capture(tmp_path)


def test_export_refuses_symlink_output_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linked"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink is unavailable")
    cases = seed.fixed_cases()
    rows = [{"actual": seed._expected(case)} for case in cases]
    monkeypatch.setattr(seed, "verify_capture", lambda *args: (rows, "a" * 64))
    with pytest.raises(ValueError):
        seed.export(tmp_path / "unused-capture", link / "seed.json")
    assert not (real / "seed.json").exists()


@pytest.fixture(scope="module")
def pinned_capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    try:
        installed = version("pydantic-ai-slim")
    except PackageNotFoundError:
        pytest.skip("optional Pydantic AI integration is not installed")
    if installed != "1.107.1":
        pytest.skip("optional Pydantic AI integration pin is unavailable")
    pytest.importorskip("pydantic_ai")
    spec = importlib.util.spec_from_file_location("boundary_seed_example", seed.EXAMPLE)
    assert spec is not None and spec.loader is not None
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)

    capture = tmp_path_factory.mktemp("boundary-seed") / "capture"
    capture.mkdir()
    result = example.run_example(capture / "run-01")
    cases = seed.fixed_cases()
    assert result["case_count"] == 8 and result["mismatches"] == []
    manifest = {
        "schema": "PydanticAIExperiment.v1", "repetitions": 1,
        "cases_per_repetition": 8, "model_calls": 0,
        "framework": "pydantic-ai-slim==1.107.1",
        "example_sha256": seed.sha(seed.EXAMPLE.read_bytes()),
        "checker_sha256": seed.sha(seed.CHECKER.read_bytes()),
        "corpus_sha256": seed.sha(seed.canonical(cases)),
        "corpus": cases,
        "source_hashes": {name: seed.sha((seed.SOURCE / name).read_bytes())
                          for name in seed.SOURCE_NAMES},
        "data_class": "public_synthetic", "independent_human_review": False,
    }
    (capture / "manifest.json").write_bytes(seed.canonical(manifest) + b"\n")
    receipt = {
        "schema": "PydanticAIExperimentResult.v1", "verified_rows": 8,
        "protected_files_unchanged": 8, "model_calls": 0, "provider_calls": 0,
        "blocked_audit_events": [], "framework_tool_calls": 8,
        "scripted_function_requests": 16, "applied": 2,
        "manifest_sha256": seed.sha(seed.canonical(manifest)),
    }
    (capture / "verification.json").write_bytes(seed.canonical(receipt) + b"\n")
    return capture


def test_exclusive_export_and_capture_readback_with_optional_framework(
    pinned_capture: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = pinned_capture
    out = capture.parent / "seed.json"
    exported = seed.export(capture, out)
    assert seed.read_json(out) == exported
    seed.verify_dataset(exported)
    assert seed.main(["--check", str(out), "--capture", str(capture)]) == 0
    with pytest.raises((ValueError, FileExistsError)):
        seed.export(capture, out)

    # The release workflow passes relative paths; SQLite's read-only URI requires
    # an absolute database path, without resolving links before evidence checks.
    monkeypatch.chdir(capture.parent)
    relative_capture = Path("capture")
    relative_out = Path("seed-relative.json")
    assert seed.main(["--capture", str(relative_capture), "--out", str(relative_out)]) == 0
    assert seed.read_json(relative_out) == exported
    assert seed.main(["--check", str(relative_out), "--capture", str(relative_capture)]) == 0
    with pytest.raises((ValueError, FileExistsError)):
        seed.export(relative_capture, relative_out)


def test_linked_capture_is_rejected_with_optional_framework(
    pinned_capture: Path, tmp_path: Path,
) -> None:
    linked_capture = tmp_path / "capture-link"
    try:
        linked_capture.symlink_to(pinned_capture, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink is unavailable")
    with pytest.raises(ValueError, match="link/reparse evidence rejected"):
        seed.verify_capture(linked_capture)
