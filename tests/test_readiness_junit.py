"""The CI readiness gate cannot mistake omitted or skipped tests for passes."""

from __future__ import annotations

import importlib.util
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "tools" / "check_readiness_junit.py"
_SPEC = importlib.util.spec_from_file_location("readiness_gate", _PATH)
assert _SPEC and _SPEC.loader
gate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gate)


def report(tmp_path: Path, platform: str) -> tuple[ET.Element, ET.Element, Path]:
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    for node in gate.required_nodes(platform):
        file, name = node.split("::", 1)
        ET.SubElement(suite, "testcase", classname=file[:-3].replace("/", "."), name=name)
    path = tmp_path / "junit.xml"
    return root, suite, path


@pytest.mark.parametrize("platform,count", [("posix", 14), ("nt", 13)])
def test_platform_requires_every_applicable_node(
    tmp_path: Path, platform: str, count: int,
) -> None:
    root, _, path = report(tmp_path, platform)
    ET.ElementTree(root).write(path)
    result = gate.verify_report(path, platform)
    assert result["status"] == "PASS"
    assert result["passed_count"] == count
    assert len(result["required_passed"]) == count


@pytest.mark.parametrize("kind", ["skipped", "failure", "error", "missing", "duplicate"])
def test_report_cannot_hide_nonpass_or_missing_node(tmp_path: Path, kind: str) -> None:
    root, suite, path = report(tmp_path, "posix")
    if kind == "missing":
        suite.remove(suite[0])
    elif kind == "duplicate":
        ET.SubElement(suite, "testcase", attrib=suite[0].attrib)
    else:
        ET.SubElement(suite[0], kind)
    ET.ElementTree(root).write(path)
    with pytest.raises(ValueError):
        gate.verify_report(path, "posix")


def test_empty_and_wrong_platform_report_rejected(tmp_path: Path) -> None:
    root, _, path = report(tmp_path, "nt")
    ET.ElementTree(root).write(path)
    with pytest.raises(ValueError, match="required test missing"):
        gate.verify_report(path, "posix")
    with pytest.raises(ValueError, match="unsupported platform"):
        gate.verify_report(path, "unknown")
    path.write_text("<testsuites/>", encoding="utf-8")
    with pytest.raises(ValueError, match="required test missing"):
        gate.verify_report(path, "nt")
