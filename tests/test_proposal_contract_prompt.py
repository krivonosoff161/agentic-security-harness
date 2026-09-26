"""Exact public-synthetic prompt framing; no model or product import."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "installed-ecosystem"


def _helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("proposal_contract_example",
                                                EXAMPLE / "proposal_contract.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cases() -> dict[str, dict]:
    corpus = json.loads((EXAMPLE / "proposal-contract-cases.json").read_text(encoding="utf-8"))
    assert corpus["schema"] == "proposal-contract-corpus-v1"
    return {case["id"]: case for case in corpus["cases"]}


@pytest.mark.parametrize(
    ("key", "framing", "case_id"),
    [
        ("project-status", "literal", "literal-1"),
        ("gateway-mode", "literal", "literal-2"),
        ("project-status", "contract", "contract-1"),
        ("gateway-mode", "contract", "contract-2"),
    ],
)
def test_prompt_matches_declared_public_case(key: str, framing: str, case_id: str,
                                             cases: dict[str, dict]) -> None:
    actual = _helper().build_lookup_prompt(key, framing=framing)
    expected = ("Return one JSON proposal only. You have no tools or execution authority. "
                + cases[case_id]["prompt"])
    assert actual == expected
    assert cases[case_id]["offline"] == {
        "capability_id": "bounded.lookup", "arguments": {"key": key}}
    assert all(field not in actual for field in
               ('"request_id"', '"operational_authority"', '"gateway_policy"',
                '"execution_permitted"'))


def test_default_is_declared_contract_case(cases: dict[str, dict]) -> None:
    assert _helper().build_lookup_prompt("project-status") == (
        "Return one JSON proposal only. You have no tools or execution authority. "
        + cases["contract-1"]["prompt"])


@pytest.mark.parametrize("key", [None, 1, True, b"project-status", "other", "public.delete"])
def test_rejects_undeclared_or_wrong_type_keys(key: object) -> None:
    with pytest.raises(ValueError, match="unsupported public lookup key"):
        _helper().build_lookup_prompt(key)


@pytest.mark.parametrize("framing", [None, 1, True, b"contract", "free", "other"])
def test_rejects_undeclared_or_wrong_type_framing(framing: object) -> None:
    with pytest.raises(ValueError, match="unsupported prompt framing"):
        _helper().build_lookup_prompt("project-status", framing=framing)


def test_cli_defaults_print_one_fixed_prompt(monkeypatch: pytest.MonkeyPatch,
                                             capsys: pytest.CaptureFixture[str]) -> None:
    module = _helper()
    monkeypatch.setattr(sys, "argv", ["proposal_contract.py"])
    module.main()
    assert capsys.readouterr().out == module.build_lookup_prompt("project-status") + "\n"
