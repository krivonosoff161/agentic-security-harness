from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "transfer": {
        "agentic-transfer-verifier==0.2.1",
        "agentic-transfer-verifier-harness-extension==1.0.1",
    },
    "handoff": {
        "ai-agent-handoff==0.3.0",
        "ai-agent-handoff-harness-extension==1.0.0",
    },
    "playbooks": {"llm-safety-playbooks==0.1.0"},
    "router": {"agentic-llm-router==0.2.0"},
    "filter": {"llm-cheap-filter==0.2.0"},
}


def test_optional_dependency_groups_are_exact_and_closed() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    optional = project["optional-dependencies"]
    assert set(optional) == {*EXPECTED, "all", "dev"}
    for name, requirements in EXPECTED.items():
        assert set(optional[name]) == requirements
        assert len(optional[name]) == len(requirements)
    union = set().union(*EXPECTED.values())
    assert set(optional["all"]) == union
    assert len(optional["all"]) == len(union)


def test_optional_groups_pin_only_owned_unique_coordinates() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    declared = set(project["optional-dependencies"]["all"])
    assert "llm-router==0.2.0" not in declared
    assert all(" @ " not in requirement for requirement in declared)
    assert all("git+" not in requirement for requirement in declared)
