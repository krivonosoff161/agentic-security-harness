"""Require complete, passing union coverage from four exact-candidate JUnit reports."""

from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path

REPORTS = (
    "full-ubuntu-latest.xml",
    "full-windows-latest.xml",
    "optional-ubuntu-latest.xml",
    "optional-windows-latest.xml",
)


def _identity(classname: str, name: str) -> tuple[str, bool]:
    if not classname:
        normalized = name.replace("\\", "/")
        if normalized.startswith("tests/test_") and normalized.endswith(".py"):
            return normalized, True
        parts = name.split(".")
        if len(parts) == 2 and parts[0] == "tests" and parts[1].startswith("test_"):
            return "tests/" + parts[1] + ".py", True
        raise ValueError(f"unrecognized module skip identity: {name!r}")
    prefix = classname.split(".")
    for index, part in enumerate(prefix):
        if part.startswith("test_"):
            return "/".join(prefix[:index + 1]) + ".py", False
    raise ValueError(f"unrecognized test identity: {classname!r} {name!r}")


def verify_coverage(report_dir: Path, tests_root: Path) -> dict[str, int]:
    expected_modules = {
        path.relative_to(tests_root.parent).as_posix()
        for path in tests_root.glob("test_*.py")
    }
    if not expected_modules:
        raise ValueError("no expected test modules")
    passed: set[tuple[str, str]] = set()
    skipped: set[tuple[str, str]] = set()
    module_skips: set[str] = set()
    for filename in REPORTS:
        path = report_dir / filename
        if not path.is_file():
            raise ValueError(f"missing report: {filename}")
        root = ET.fromstring(path.read_bytes())
        if root.tag not in {"testsuites", "testsuite"}:
            raise ValueError(f"invalid JUnit report: {filename}")
        for suite in (root, *root.iter("testsuite")):
            for field in ("failures", "errors"):
                count = suite.get(field)
                if count is not None and (not count.isdecimal() or int(count) != 0):
                    raise ValueError(f"failed JUnit report: {filename}")
        has_failure = next(root.iter("failure"), None) is not None
        has_error = next(root.iter("error"), None) is not None
        if has_failure or has_error:
            raise ValueError(f"failed JUnit report: {filename}")
        cases = list(root.iter("testcase"))
        if not cases:
            raise ValueError(f"empty JUnit report: {filename}")
        for case in cases:
            classname, name = case.get("classname", ""), case.get("name", "")
            if not name:
                raise ValueError(f"missing test identity: {filename}")
            module, is_module = _identity(classname, name)
            if module not in expected_modules:
                raise ValueError(f"unknown test module: {module}")
            if case.find("failure") is not None or case.find("error") is not None:
                raise ValueError(f"failed test: {filename}: {module}::{name}")
            node = (classname, name)
            if case.find("skipped") is not None:
                if is_module:
                    module_skips.add(module)
                else:
                    skipped.add(node)
            else:
                if is_module:
                    raise ValueError(f"module collection identity passed: {filename}: {name}")
                passed.add(node)
    missing_nodes = skipped - passed
    if missing_nodes:
        raise ValueError(f"skipped tests never passed: {sorted(missing_nodes)}")
    passed_modules = {_identity(classname, name)[0] for classname, name in passed}
    missing_module_skips = module_skips - passed_modules
    if missing_module_skips:
        raise ValueError(f"skipped modules never passed: {sorted(missing_module_skips)}")
    missing_modules = expected_modules - passed_modules
    if missing_modules:
        raise ValueError(f"test modules without passing cases: {sorted(missing_modules)}")
    return {"reports": len(REPORTS), "passed_nodes": len(passed), "modules": len(passed_modules)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_dir", type=Path)
    parser.add_argument("--tests-root", type=Path, default=Path("tests"))
    args = parser.parse_args()
    result = verify_coverage(args.report_dir, args.tests_root)
    print(f"PASS: {result['reports']} reports, {result['passed_nodes']} passing nodes, "
          f"{result['modules']} covered modules")


if __name__ == "__main__":
    main()
