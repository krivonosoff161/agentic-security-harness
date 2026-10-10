"""Export and check one fixed, public synthetic boundary evaluation seed.

The corpus is read as an AST literal. This tool never imports the optional
Pydantic AI example or starts an agent, model, provider, or fixture run.
Standalone --check validates source conformance, not capture provenance;
provide --capture to recheck original bytes and ancestry.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/pydantic_ai_guarded_files.py"
CHECKER = ROOT / "tools/check_pydantic_ai_guarded_files.py"
SOURCE = ROOT / "src/agentic_security_harness"
SOURCE_NAMES = (
    "ancestry_store.py", "_file_policy.py", "_fixture_files.py",
    "controlled_file_workflow.py", "controlled_file_verifier.py",
    "runtime_guard_foundation.py", "quarantine_connector.py",
)
LABELS = {
    "source": "scripted_test_model", "representation": "untrusted_tool_proposal",
    "authority": "none", "data_class": "public_synthetic",
}
PENDING = b"pending\n"
PROTECTED = b"protected fixture; do not modify\n"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    return json.loads(path.read_bytes(), object_pairs_hook=_no_duplicates)


def _absolute_without_resolving(path: Path) -> Path:
    """Give SQLite an absolute URI path while retaining link components for checks."""
    return path if path.is_absolute() else Path.cwd() / path


def fixed_cases() -> tuple[dict[str, Any], ...]:
    tree = ast.parse(EXAMPLE.read_text(encoding="utf-8"), filename=EXAMPLE.name)
    assignments = [node for node in tree.body if isinstance(node, ast.AnnAssign)
                   and isinstance(node.target, ast.Name) and node.target.id == "CASES"]
    if len(assignments) != 1 or assignments[0].value is None:
        raise ValueError("fixed_corpus_literal_missing")
    cases = ast.literal_eval(assignments[0].value)
    if type(cases) is not tuple or len(cases) != 8:
        raise ValueError("fixed_corpus_shape")
    ids: set[str] = set()
    splits = {"development": 0, "heldout": 0}
    for case in cases:
        if (type(case) is not dict or set(case) != {"id", "split", "input", "reason", "report"}
                or any(type(case[key]) is not str for key in ("id", "split", "input", "reason"))
                or type(case["id"]) is not str or case["id"] in ids
                or case["split"] not in splits
                or case["reason"] not in {"write_completed", "guard_rejected", "proposal_rejected"}
                or (case["report"] is not None and type(case["report"]) is not str)
                or (case["reason"] == "write_completed") != (case["report"] is not None)):
            raise ValueError("fixed_corpus_case")
        ids.add(case["id"])
        splits[case["split"]] += 1
    if splits != {"development": 4, "heldout": 4}:
        raise ValueError("fixed_corpus_split")
    return cases


def _effect(data: bytes) -> dict[str, int | str]:
    return {"bytes": len(data), "sha256": sha(data)}


def _expected(case: dict[str, Any]) -> dict[str, Any]:
    report = case["report"].encode() if case["report"] is not None else PENDING
    return {
        "reason": case["reason"], "applied": case["reason"] == "write_completed",
        "report_sha256": sha(report), "protected_sha256": sha(PROTECTED),
    }


def _row(case: dict[str, Any], captured: dict[str, Any]) -> dict[str, Any]:
    report = case["report"].encode() if case["report"] is not None else PENDING
    return {
        "case_id": case["id"],
        "split": "development" if case["split"] == "development" else "evaluation_reserved_known",
        "input_schema": "ControlledFileProposal.v1",
        "label_schema": "ScriptedProposalLabels.v1",
        "input": case["input"], "input_sha256": sha(case["input"].encode()),
        "trusted_labels": dict(LABELS),
        "expected": _expected(case), "actual": captured["actual"],
        "effect_before": {"report": _effect(PENDING), "protected": _effect(PROTECTED)},
        "effect_after": {"report": _effect(report), "protected": _effect(PROTECTED)},
    }


def _digest_dataset(dataset: dict[str, Any]) -> str:
    return sha(canonical({key: value for key, value in dataset.items() if key != "dataset_sha256"}))


def build_dataset(cases: tuple[dict[str, Any], ...], rows: list[dict[str, Any]],
                  manifest_sha256: str) -> dict[str, Any]:
    if len(rows) != len(cases) or not HEX64.fullmatch(manifest_sha256):
        raise ValueError("capture_rows_or_manifest")
    dataset = {
        "schema": "BoundaryEvaluationSeed.v1",
        "source_manifest_sha256": manifest_sha256,
        "example_sha256": sha(EXAMPLE.read_bytes()),
        "corpus_sha256": sha(canonical(cases)),
        "data_class": "public_synthetic",
        "provenance": "fixed_author_authored_known_cases",
        "evaluation_reserved_known": True,
        "blind_independent_labels": False,
        "trained_model": False,
        "model_calls": 0,
        "provider_calls": 0,
        "rows": [_row(case, captured) for case, captured in zip(cases, rows, strict=True)],
    }
    dataset["dataset_sha256"] = _digest_dataset(dataset)
    verify_dataset(dataset, cases)
    return dataset


def verify_dataset(
    dataset: dict[str, Any], cases: tuple[dict[str, Any], ...] | None = None,
) -> None:
    cases = fixed_cases() if cases is None else cases
    expected_keys = {
        "schema", "source_manifest_sha256", "example_sha256", "corpus_sha256",
        "data_class", "provenance", "evaluation_reserved_known", "blind_independent_labels",
        "trained_model", "model_calls", "provider_calls", "rows", "dataset_sha256",
    }
    if type(dataset) is not dict or set(dataset) != expected_keys:
        raise ValueError("dataset_shape")
    manifest_hash = dataset["source_manifest_sha256"]
    if (type(manifest_hash) is not str or not HEX64.fullmatch(manifest_hash)
            or dataset["schema"] != "BoundaryEvaluationSeed.v1"
            or dataset["example_sha256"] != sha(EXAMPLE.read_bytes())
            or dataset["corpus_sha256"] != sha(canonical(cases))
            or dataset["data_class"] != "public_synthetic"
            or dataset["provenance"] != "fixed_author_authored_known_cases"
            or dataset["evaluation_reserved_known"] is not True
            or dataset["blind_independent_labels"] is not False
            or dataset["trained_model"] is not False
            or type(dataset["model_calls"]) is not int or dataset["model_calls"] != 0
            or type(dataset["provider_calls"]) is not int or dataset["provider_calls"] != 0
            or type(dataset["rows"]) is not list or len(dataset["rows"]) != 8):
        raise ValueError("dataset_contract")
    for case, row in zip(cases, dataset["rows"], strict=True):
        if type(row) is not dict:
            raise ValueError("dataset_row_shape")
        expected_row = _row(case, {"actual": _expected(case)})
        if canonical(row) != canonical(expected_row):
            raise ValueError("dataset_row_mismatch")
    if dataset["dataset_sha256"] != _digest_dataset(dataset):
        raise ValueError("dataset_digest")


def verify_capture(capture: Path, cases: tuple[dict[str, Any], ...] | None = None
                   ) -> tuple[list[dict[str, Any]], str]:
    capture = _absolute_without_resolving(capture)
    cases = fixed_cases() if cases is None else cases
    manifest = read_json(capture / "manifest.json")
    receipt = read_json(capture / "verification.json")
    manifest_sha = sha(canonical(manifest))
    source_hashes = {name: sha((SOURCE / name).read_bytes()) for name in SOURCE_NAMES}
    if (type(manifest) is not dict or manifest.get("schema") != "PydanticAIExperiment.v1"
            or type(manifest.get("repetitions")) is not int or manifest["repetitions"] != 1
            or type(manifest.get("cases_per_repetition")) is not int
            or manifest["cases_per_repetition"] != 8
            or type(manifest.get("model_calls")) is not int or manifest["model_calls"] != 0
            or manifest.get("framework") != "pydantic-ai-slim==1.107.7"
            or manifest.get("example_sha256") != sha(EXAMPLE.read_bytes())
            or manifest.get("checker_sha256") != sha(CHECKER.read_bytes())
            or manifest.get("corpus_sha256") != sha(canonical(cases))
            or manifest.get("corpus") != list(cases)
            or manifest.get("source_hashes") != source_hashes
            or manifest.get("data_class") != "public_synthetic"
            or manifest.get("independent_human_review") is not False):
        raise ValueError("capture_manifest_pin")
    if (type(receipt) is not dict or receipt.get("schema") != "PydanticAIExperimentResult.v1"
            or receipt.get("manifest_sha256") != manifest_sha
            or type(receipt.get("verified_rows")) is not int or receipt["verified_rows"] != 8
            or type(receipt.get("protected_files_unchanged")) is not int
            or receipt["protected_files_unchanged"] != 8
            or type(receipt.get("model_calls")) is not int or receipt["model_calls"] != 0
            or type(receipt.get("provider_calls")) is not int or receipt["provider_calls"] != 0
            or receipt.get("blocked_audit_events") != []
            or type(receipt.get("framework_tool_calls")) is not int
            or receipt["framework_tool_calls"] != 8
            or type(receipt.get("scripted_function_requests")) is not int
            or receipt["scripted_function_requests"] != 16
            or type(receipt.get("applied")) is not int or receipt["applied"] != 2):
        raise ValueError("capture_receipt")
    # The checker imports only the base Harness dependencies when verify_run is
    # called. Source hashes above bind that readback to the captured installation.
    original_path = sys.path.copy()
    try:
        sys.path.insert(0, str(SOURCE.parent))
        verifier = importlib.import_module("agentic_security_harness.controlled_file_verifier")
        verifier_path = Path(verifier.__file__ or "")
        if sha(verifier_path.read_bytes()) != source_hashes["controlled_file_verifier.py"]:
            raise ValueError("capture_verifier_pin")
        spec = importlib.util.spec_from_file_location("boundary_seed_checker", CHECKER)
        if spec is None or spec.loader is None:
            raise ValueError("capture_checker_unavailable")
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        rows = checker.verify_run(capture / "run-01", cases)
    finally:
        sys.path[:] = original_path
    if len(rows) != 8 or sum(row["actual"]["applied"] for row in rows) != receipt["applied"]:
        raise ValueError("capture_readback_counts")
    return rows, manifest_sha


def export(capture: Path, out: Path) -> dict[str, Any]:
    from agentic_security_harness.safe_io import require_atomic_output_destination

    out = _absolute_without_resolving(out)
    cases = fixed_cases()
    rows, manifest_sha = verify_capture(capture, cases)
    dataset = build_dataset(cases, rows, manifest_sha)
    if not out.parent.is_dir():
        raise ValueError("output_parent_missing")
    require_atomic_output_destination(out)
    with out.open("xb") as stream:
        stream.write(canonical(dataset) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return dataset


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args(argv)
    if args.check is not None:
        if args.out is not None:
            parser.error("--check cannot be combined with --out")
        dataset = read_json(args.check)
        verify_dataset(dataset)
        if args.capture is not None:
            rows, manifest_sha = verify_capture(args.capture)
            if dataset != build_dataset(fixed_cases(), rows, manifest_sha):
                raise ValueError("dataset_capture_mismatch")
    else:
        if args.capture is None or args.out is None:
            parser.error("export requires --capture and --out")
        dataset = export(args.capture, args.out)
    print(json.dumps({"schema": dataset["schema"], "rows": len(dataset["rows"]),
                      "dataset_sha256": dataset["dataset_sha256"],
                      "capture_provenance_verified": args.capture is not None}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
