"""Focused source checks for the installed ancestry release smoke."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = (Path(__file__).resolve().parents[1] / "examples" / "installed-ecosystem" /
          "check_ancestry.py")
COMPANIONS = (
    "agent_guard", "agentic_transfer_verifier", "llm_router",
    "llm_cheap_filter", "llm_safety_playbooks",
)


@pytest.fixture(autouse=True)
def isolated_companion_imports() -> Iterator[None]:
    def selected(name: str) -> bool:
        return any(name == package or name.startswith(package + ".")
                   for package in COMPANIONS)

    before = {name: module for name, module in sys.modules.items() if selected(name)}
    for name in before:
        del sys.modules[name]
    try:
        yield
    finally:
        for name in tuple(sys.modules):
            if selected(name):
                del sys.modules[name]
        sys.modules.update(before)


def smoke_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("installed_ancestry_smoke_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_version_mismatch_fails_before_import(monkeypatch: pytest.MonkeyPatch) -> None:
    smoke = smoke_module()
    monkeypatch.setattr(smoke.metadata, "version", lambda _name: "1.7.1")
    monkeypatch.setattr(smoke.importlib, "import_module",
                        lambda _name: pytest.fail("import before version check"))
    with pytest.raises(ValueError, match="core_version_mismatch"):
        smoke.installed_core("1.8.0")


def test_source_cases_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in COMPANIONS:
        pytest.importorskip(name)
    smoke = smoke_module()
    monkeypatch.setattr(smoke, "installed_core", lambda _version: None)
    result = smoke.run("1.8.0")
    assert result["case_count"] == 8
    assert result["synthetic_executions"] == 1
    assert [case["outcome"] for case in result["cases"]] == [
        "completed", "denied", "rejected", "rejected", "rejected",
        "rejected", "rejected", "recovery_required",
    ]
    assert "pure_result" not in str(result)
    assert result["real_model_calls"] == result["real_provider_calls"] == 0
