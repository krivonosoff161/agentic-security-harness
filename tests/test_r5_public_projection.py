from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from agentic_security_harness.r5_public_projection import (
    one_sided_clopper_pearson_lower,
    validate_r5_public_projection,
)
from agentic_security_harness.validation import validate_path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "r5-sealed-synthetic-sanitized"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _dump(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _rebind_manifest(directory: Path) -> None:
    manifest_path = directory / "publication-manifest.json"
    manifest = _load(manifest_path)
    for entry in manifest["files"]:
        payload = (directory / entry["name"]).read_bytes()
        entry["size"] = len(payload)
        entry["sha256"] = hashlib.sha256(payload).hexdigest()
    _dump(manifest_path, manifest)


def test_committed_r5_terminal_projection_recomputes_cleanly() -> None:
    assert validate_r5_public_projection(EXAMPLE) == []
    result = validate_path(EXAMPLE)
    assert result.ok, result.errors
    assert result.r5_public_projection_dirs == ["r5-sealed-synthetic-sanitized"]
    assert [status.evidence_id for status in result.evidence_statuses] == [
        "runtime-guard.r5-terminal"
    ]


def test_r5_public_calculations_are_independently_reproducible() -> None:
    aggregate = _load(EXAMPLE / "aggregate-evidence.json")
    counts = aggregate["counts"]
    gate = aggregate["gate_result"]

    assert counts["harmful_challenge"] / 250 == gate["recall"] == 0.636
    assert counts["benign_observe"] / 250 == gate["specificity"] == 0.828
    assert (gate["recall"] + gate["specificity"]) / 2 == 0.732
    assert one_sided_clopper_pearson_lower(159, 250, 0.05 / 4) == (
        gate["recall_lower_acceptance_index"]
    )
    assert one_sided_clopper_pearson_lower(207, 250, 0.05 / 4) == (
        gate["specificity_lower_acceptance_index"]
    )
    assert one_sided_clopper_pearson_lower(420, 420, 0.05 / 4) == (
        gate["incomplete_abstention_lower_acceptance_index"]
    )
    assert one_sided_clopper_pearson_lower(81, 250, 0.05 / 4) == (
        gate["counterfactual_pre_effect_lower_acceptance_index"]
    )


def test_r5_projection_rejects_semantic_tamper_even_if_file_manifest_is_rebound(
    tmp_path: Path,
) -> None:
    out = tmp_path / "r5"
    shutil.copytree(EXAMPLE, out)
    aggregate_path = out / "aggregate-evidence.json"
    aggregate = _load(aggregate_path)
    aggregate["counts"]["harmful_challenge"] = 160
    aggregate["counts"]["harmful_observe"] = 90
    _dump(aggregate_path, aggregate)
    terminal = _load(out / "terminal-envelope.json")
    terminal["terminal_payload_sha256"] = hashlib.sha256(
        json.dumps(aggregate, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    _dump(out / "terminal-envelope.json", terminal)
    _rebind_manifest(out)

    errors = validate_r5_public_projection(out)

    assert any("calculation mismatch" in error for error in errors)
    assert any("aggregate counts digest mismatch" in error for error in errors)


def test_r5_projection_rejects_file_inventory_and_receipt_tamper(tmp_path: Path) -> None:
    out = tmp_path / "r5"
    shutil.copytree(EXAMPLE, out)
    (out / "raw-labels.json").write_text("{}\n", encoding="utf-8")
    assert validate_r5_public_projection(out) == [
        "R5 public projection must contain exactly the three sanitized files"
    ]

    (out / "raw-labels.json").unlink()
    terminal = _load(out / "terminal-envelope.json")
    terminal["state"] = "PASS"
    _dump(out / "terminal-envelope.json", terminal)
    _rebind_manifest(out)
    assert any(
        "state mismatch" in error for error in validate_r5_public_projection(out)
    )


def test_r5_projection_rejects_private_or_unknown_fields(tmp_path: Path) -> None:
    out = tmp_path / "r5"
    shutil.copytree(EXAMPLE, out)
    aggregate_path = out / "aggregate-evidence.json"
    aggregate = _load(aggregate_path)
    aggregate["raw_cases"] = []
    _dump(aggregate_path, aggregate)
    _rebind_manifest(out)

    assert any(
        "field set does not match" in error for error in validate_r5_public_projection(out)
    )
