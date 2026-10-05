from __future__ import annotations

import re
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
    "router": {"agentic-llm-router==0.2.1"},
    "filter": {"llm-cheap-filter==0.2.0"},
}


def test_optional_dependency_groups_are_exact_and_closed() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    optional = project["optional-dependencies"]
    assert set(optional) == {*EXPECTED, "all", "dev", "document-agent"}
    # Framework integration remains a separate opt-in, not an owned companion.
    assert optional["document-agent"] == ["pydantic-ai-slim==1.107.1"]
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


def test_windows_colorama_input_keeps_exact_hashed_lock() -> None:
    source = (ROOT / "requirements/dev.in").read_text(encoding="utf-8")
    lock = (ROOT / "requirements/dev.txt").read_text(encoding="utf-8")
    declared = re.search(r'^colorama==([^ ;]+) ; sys_platform == "win32"$', source, re.M)
    assert declared is not None
    locked = re.search(r"^colorama==([^\n]+)\n((?:[ \t]+[^\n]*\n)+)", lock, re.M)
    assert locked is not None, "Windows pytest dependency must not vanish on a Linux lock update"
    assert locked.group(1).rstrip(" \\") == declared.group(0).removeprefix("colorama==")
    assert re.search(r"--hash=sha256:[0-9a-f]{64}", locked.group(2))


def test_multidict_lock_respects_current_aiohttp_upper_bound() -> None:
    lock = (ROOT / "requirements/companions.txt").read_text(encoding="utf-8")
    # This is the reviewed aiohttp release's declared requirement, not a claim
    # that every future aiohttp release keeps the same compatibility bound.
    assert re.search(r"^aiohttp==3\.14\.3 \\\s*$", lock, re.M)
    version = re.search(r"^multidict==(\d+\.\d+\.\d+) \\\s*$", lock, re.M)
    assert version is not None
    parts = tuple(int(part) for part in version.group(1).split("."))
    assert (4, 5, 0) <= parts < (7, 0, 0)
