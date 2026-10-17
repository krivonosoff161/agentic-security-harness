"""Installed-only, bounded synthetic unittest acceptance for the candidate wheel."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import platform
import sys
import time
import unittest
from pathlib import Path

EXPECTED_MODULES = frozenset(
    {
        "test_boundaries",
        "test_cli",
        "test_embedding",
        "test_engine",
        "test_host",
        "test_native_parity",
        "test_operator",
        "test_process",
        "test_protocol",
    }
)
EXPECTED_SOURCE_FILES = frozenset(
    {
        "__init__.py",
        "engine.py",
        "host.py",
        "operator.py",
        "protocol.py",
    }
)
EXPECTED_EXAMPLE_FILES = frozenset({"content_only_dispatch.py"})
EXPECTED_TESTS = 61
sys.dont_write_bytecode = True


def _installed_module(name: str) -> str:
    module = importlib.import_module(name)
    path = Path(module.__file__).resolve()
    prefix = Path(sys.prefix).resolve()
    if sys.prefix == sys.base_prefix or prefix not in path.parents:
        raise RuntimeError("isolated_venv_import_required")
    if not any(part in {"site-packages", "dist-packages"} for part in path.parts):
        raise RuntimeError("site_packages_import_required")
    return f"{name}/{path.name}"


def _cases(suite: unittest.TestSuite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _cases(item)
        else:
            yield item


def _bounded_trace(trace: str, source: Path) -> str:
    for root, label in ((source.parents[1], "<checkout>"), (Path(sys.prefix).resolve(), "<venv>")):
        raw = str(root)
        trace = trace.replace(raw, label).replace(raw.replace("\\", "/"), label)
    return "\n".join(trace.splitlines()[-40:])[-6000:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        required=True,
        help="packages/action-authority directory, used only for byte inventory and tests",
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    # Refuse an existing destination before running any fixture effects.
    args.out.mkdir(exist_ok=False)
    source = args.source.resolve(strict=True)
    if Path.cwd().resolve().is_relative_to(source.parents[1]):
        raise RuntimeError("run_from_outside_checkout")
    if str(source / "src") in sys.path:
        raise RuntimeError("source_path_shadowing")
    imported = {
        "candidate": _installed_module("ash_action_authority"),
        "harness": _installed_module("agentic_security_harness"),
    }
    harness_version = importlib.metadata.version("agentic-security-harness")
    if harness_version != "1.14.1":
        raise RuntimeError("wrong_installed_harness_version")
    candidate_version = importlib.metadata.version("ash-action-authority-candidate")
    files = sorted((source / "src" / "ash_action_authority").glob("*.py"))
    tests = sorted((source / "tests").glob("test_*.py"))
    examples = sorted((source / "examples").glob("*.py"))
    if (
        {path.stem for path in tests} != EXPECTED_MODULES
        or {path.name for path in files} != EXPECTED_SOURCE_FILES
        or {path.name for path in examples} != EXPECTED_EXAMPLE_FILES
    ):
        raise RuntimeError("candidate_test_or_source_inventory_changed")
    hashes = {
        path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (*files, *tests, *examples)
    }
    loader = unittest.TestLoader()
    suite = loader.discover(str(source / "tests"), pattern="test_*.py")
    discovered = list(_cases(suite))
    modules = {case.__class__.__module__ for case in discovered}
    if modules != EXPECTED_MODULES or len(discovered) != EXPECTED_TESTS:
        raise RuntimeError("candidate_test_discovery_incomplete")
    result = unittest.TestResult()
    started = time.monotonic()
    suite.run(result)
    elapsed = time.monotonic() - started
    success = (
        result.wasSuccessful()
        and result.testsRun == EXPECTED_TESTS
        and not result.skipped
        and not result.expectedFailures
        and not result.unexpectedSuccesses
    )
    record = {
        "schema": "action-authority-installed-check-v1",
        "installed_acceptance": True,
        "candidate_version": candidate_version,
        "harness_version": harness_version,
        "imports": imported,
        "tests_expected": EXPECTED_TESTS,
        "tests_run": result.testsRun,
        "failure_tests": [case.id() for case, _ in result.failures],
        "error_tests": [case.id() for case, _ in result.errors],
        "skipped_tests": [case.id() for case, _ in result.skipped],
        "expected_failure_tests": [case.id() for case, _ in result.expectedFailures],
        "unexpected_success_tests": [case.id() for case in result.unexpectedSuccesses],
        "elapsed_seconds": round(elapsed, 3),
        "python": platform.python_version(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "source_sha256": hashes,
        "synthetic_approvals_are_not_human_consent": True,
        "model_calls_by_fixed_tests": 0,
        "network_calls_audited": False,
        "success": success,
    }
    (args.out / "RESULT.json").write_text(
        json.dumps(record, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="ascii"
    )
    log = [
        "installed synthetic unittest acceptance",
        f"tests_run={result.testsRun} expected={EXPECTED_TESTS} success={success}",
    ]
    for label, pairs in (
        ("failure", result.failures),
        ("error", result.errors),
        ("expected_failure", result.expectedFailures),
    ):
        for case, trace in pairs:
            log.extend((f"{label}={case.id()}", _bounded_trace(trace, source)))
    log.extend(f"skipped={case.id()}" for case, _ in result.skipped)
    log.extend(f"unexpected_success={case.id()}" for case in result.unexpectedSuccesses)
    (args.out / "tests.log").write_text("\n".join(log) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "tests_run": result.testsRun,
                "success": success,
                "synthetic_approvals_are_not_human_consent": True,
            }
        )
    )
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
