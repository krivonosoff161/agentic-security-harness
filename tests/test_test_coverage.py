"""Deterministic checks for the cross-platform JUnit union gate."""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

import pytest
from tools.check_test_coverage import REPORTS, verify_coverage


def _case(module: str, name: str, outcome: str = "pass") -> str:
    marker = "" if outcome == "pass" else f"<{outcome} message='fixture'/>"
    return (f'<testcase classname="tests.{module}" name="{escape(name)}">'
            f"{marker}</testcase>")


def _reports(tmp_path: Path, cases: list[list[str]]) -> tuple[Path, Path]:
    tests = tmp_path / "tests"
    tests.mkdir()
    for module in ("test_alpha", "test_beta"):
        (tests / f"{module}.py").write_text("# fixture\n", encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()
    for filename, contents in zip(REPORTS, cases, strict=True):
        (reports / filename).write_text(
            "<testsuites><testsuite>" + "".join(contents) + "</testsuite></testsuites>",
            encoding="utf-8",
        )
    return reports, tests


def test_all_six_reports_cover_each_module(tmp_path: Path) -> None:
    reports, tests = _reports(tmp_path, [
        [_case("test_alpha", "test_one"), _case("test_beta", "test_two", "skipped")],
        [_case("test_alpha", "test_one"), _case("test_beta", "test_two")],
        [_case("test_alpha", "test_one")],
        [_case("test_beta", "test_two")],
        [_case("test_alpha", "test_one")],
        [_case("test_beta", "test_two")],
    ])
    assert verify_coverage(reports, tests) == {
        "reports": 6, "passed_nodes": 2, "modules": 2,
    }


def test_missing_report_rejected(tmp_path: Path) -> None:
    reports, tests = _reports(tmp_path, [[_case("test_alpha", "test_one")]] * 6)
    (reports / REPORTS[-1]).unlink()
    with pytest.raises(
        ValueError, match="missing report: installed-document-integration-windows-latest",
    ):
        verify_coverage(reports, tests)


def test_pydantic_skips_pass_only_in_installed_reports(tmp_path: Path) -> None:
    pydantic_nodes = (
        (
            "test_document_coverage",
            "test_real_planned_jobs_missing_then_complete[False-pydantic-ai]",
        ),
        (
            "test_document_coverage",
            "test_real_planned_jobs_missing_then_complete[True-pydantic-ai]",
        ),
        (
            "test_document_recovered_handoff",
            "test_recovered_data_reaches_new_job_without_repeating_original_action[False-pydantic-ai]",
        ),
        (
            "test_document_recovered_handoff",
            "test_recovered_data_reaches_new_job_without_repeating_original_action[True-pydantic-ai]",
        ),
        (
            "test_document_source_restrictions",
            "test_chain_keeps_exact_restrictions_and_origin[pydantic-ai]",
        ),
        (
            "test_document_source_restrictions",
            "test_expiry_during_generation_stops_effect_not_status[pydantic-ai]",
        ),
    )
    skipped = [_case(module, name, "skipped") for module, name in pydantic_nodes]
    installed_ubuntu = [_case(module, name) for module, name in pydantic_nodes[:3]]
    installed_windows = [_case(module, name) for module, name in pydantic_nodes[3:]]
    reports, tests = _reports(tmp_path, [
        [_case("test_alpha", "test_one"), _case("test_beta", "test_two"), *skipped],
        [_case("test_alpha", "test_one"), *skipped],
        [_case("test_alpha", "test_one")],
        [_case("test_beta", "test_two")],
        installed_ubuntu,
        installed_windows,
    ])
    for module in {module for module, _ in pydantic_nodes}:
        (tests / f"{module}.py").write_text("# fixture\n", encoding="utf-8")
    assert verify_coverage(reports, tests) == {
        "reports": 6, "passed_nodes": 8, "modules": 5,
    }


@pytest.mark.parametrize("outcome", ["failure", "error"])
def test_failure_or_error_rejected(tmp_path: Path, outcome: str) -> None:
    reports, tests = _reports(tmp_path, [
        [_case("test_alpha", "test_one"), _case("test_beta", "test_two")],
        [_case("test_alpha", "test_one", outcome)],
        [_case("test_alpha", "test_one")],
        [_case("test_beta", "test_two")],
        [_case("test_alpha", "test_one")],
        [_case("test_beta", "test_two")],
    ])
    with pytest.raises(ValueError, match="failed JUnit report"):
        verify_coverage(reports, tests)


def test_uncovered_individual_skip_rejected(tmp_path: Path) -> None:
    reports, tests = _reports(tmp_path, [
        [_case("test_alpha", "test_one"), _case("test_beta", "test_two")],
        [_case("test_beta", "test_three", "skipped")],
        [_case("test_alpha", "test_one")],
        [_case("test_beta", "test_two")],
        [_case("test_alpha", "test_one")],
        [_case("test_beta", "test_two")],
    ])
    with pytest.raises(ValueError, match="skipped tests never passed"):
        verify_coverage(reports, tests)


@pytest.mark.parametrize("module_name", ["tests/test_beta.py", "tests.test_beta"])
def test_module_import_skip_requires_real_pass_from_module(
    tmp_path: Path, module_name: str,
) -> None:
    module_skip = f'<testcase classname="" name="{module_name}"><skipped/></testcase>'
    reports, tests = _reports(tmp_path, [
        [_case("test_alpha", "test_one"), module_skip],
        [_case("test_alpha", "test_one")],
        [_case("test_alpha", "test_one")],
        [_case("test_alpha", "test_one")],
        [_case("test_alpha", "test_one")],
        [_case("test_alpha", "test_one")],
    ])
    with pytest.raises(ValueError, match="skipped modules never passed"):
        verify_coverage(reports, tests)
    (reports / REPORTS[-1]).write_text(
        "<testsuite>" + _case("test_beta", "test_two") + "</testsuite>",
        encoding="utf-8",
    )
    assert verify_coverage(reports, tests)["modules"] == 2


def test_missing_expected_module_rejected_even_with_six_reports(tmp_path: Path) -> None:
    reports, tests = _reports(tmp_path, [[_case("test_alpha", "test_one")]] * 6)
    with pytest.raises(ValueError, match="test modules without passing cases"):
        verify_coverage(reports, tests)


def test_same_named_methods_in_distinct_classes_do_not_cover_skip(tmp_path: Path) -> None:
    skipped = ('<testcase classname="tests.test_alpha.TestA" name="test_same">'
               '<skipped/></testcase>')
    passed = '<testcase classname="tests.test_alpha.TestB" name="test_same"/>'
    reports, tests = _reports(tmp_path, [
        [skipped, _case("test_beta", "test_two")],
        [passed],
        [passed],
        [passed],
        [passed],
        [passed],
    ])
    with pytest.raises(ValueError, match="skipped tests never passed"):
        verify_coverage(reports, tests)


@pytest.mark.parametrize("field", ["failures", "errors"])
def test_nonzero_suite_count_without_failed_child_rejected(tmp_path: Path, field: str) -> None:
    reports, tests = _reports(tmp_path, [
        [_case("test_alpha", "test_one"), _case("test_beta", "test_two")],
        [_case("test_alpha", "test_one")],
        [_case("test_alpha", "test_one")],
        [_case("test_beta", "test_two")],
        [_case("test_alpha", "test_one")],
        [_case("test_beta", "test_two")],
    ])
    (reports / REPORTS[0]).write_text(
        f'<testsuites><testsuite {field}="1">'
        + _case("test_alpha", "test_one") + _case("test_beta", "test_two")
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="failed JUnit report"):
        verify_coverage(reports, tests)
