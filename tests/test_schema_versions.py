"""Tests for the schema-version registry and schema-aware validation."""

import json
import shutil
from pathlib import Path

from agentic_security_harness.schema_versions import (
    SCHEMA_VERSIONS,
    check_schema_version,
    is_known,
    schema_version,
)
from agentic_security_harness.validation import validate_path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


# --- registry ---


def test_registry_has_core_artifacts() -> None:
    for kind in (
        "trace", "scorecard", "remediation", "matrix",
        "run_config", "external_summary", "run_manifest", "run_diff",
    ):
        assert kind in SCHEMA_VERSIONS
        assert schema_version(kind)


def test_check_known_version_ok() -> None:
    assert check_schema_version("trace", "0.1") is None
    assert is_known("trace", "0.1")


def test_check_unknown_future_version_errors() -> None:
    msg = check_schema_version("trace", "9.9")
    assert msg is not None
    assert "unknown/future" in msg
    assert "9.9" in msg


def test_check_missing_required_errors() -> None:
    msg = check_schema_version("scorecard", None, required=True)
    assert msg is not None and "missing schema_version" in msg


def test_check_missing_optional_ok() -> None:
    assert check_schema_version("remediation", None, required=False) is None


# --- validation integration ---


def _copy(name: str, tmp_path: Path) -> Path:
    dst = tmp_path / name
    shutil.copytree(EXAMPLES / name, dst)
    return dst


def test_committed_scorecard_has_schema_version() -> None:
    data = json.loads(
        (EXAMPLES / "demo-report" / "scorecard.json").read_text(encoding="utf-8")
    )
    assert data["schema_version"] == SCHEMA_VERSIONS["scorecard"]


def test_future_scorecard_version_fails_validation(tmp_path: Path) -> None:
    report = _copy("demo-report", tmp_path)
    data = json.loads((report / "scorecard.json").read_text(encoding="utf-8"))
    data["schema_version"] = "9.9"
    (report / "scorecard.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    result = validate_path(report)
    assert not result.ok
    assert any("unknown/future schema_version" in e for e in result.errors)


def test_missing_scorecard_version_fails_validation(tmp_path: Path) -> None:
    report = _copy("demo-report", tmp_path)
    data = json.loads((report / "scorecard.json").read_text(encoding="utf-8"))
    del data["schema_version"]
    (report / "scorecard.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    result = validate_path(report)
    assert not result.ok
    assert any("missing schema_version" in e for e in result.errors)


def test_future_trace_version_fails_validation(tmp_path: Path) -> None:
    report = _copy("demo-report", tmp_path)
    traces = json.loads((report / "traces.json").read_text(encoding="utf-8"))
    traces[0]["schema_version"] = "9.9"
    (report / "traces.json").write_text(
        json.dumps(traces, indent=2) + "\n", encoding="utf-8"
    )
    result = validate_path(report)
    assert not result.ok
    assert any("unknown/future schema_version" in e for e in result.errors)
