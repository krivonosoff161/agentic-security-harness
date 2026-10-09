"""Keep published route status distinct from synthetic and future authority."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_current_model_guide_names_published_document_route() -> None:
    project = tomllib.loads(_read("pyproject.toml"))["project"]
    guide = _read("docs/connect-models.md")
    assert project["version"] == "1.13.0"
    assert "current 1.13.0 package" in guide
    assert "releases/v1.13.0.md" in guide
    assert "current 1.12.0 package" not in guide
    assert "prompt-based evaluation only" in guide.lower()


def test_synthetic_agent_host_is_shipped_but_live_collector_is_not() -> None:
    guide = _read("docs/connect-models.md")
    matrix = _read("docs/capability-matrix.md")
    assert "Agent Host owned-workflow quickstart" in guide
    assert "shipped, not arbitrary host execution" in guide
    assert "Agent Host owned-workflow V1" in matrix
    assert "agent-host-quickstart --out <new-dir>" in matrix
    assert "Live agent-host collector / arbitrary tool-use adapter" in matrix
    assert "**future**" in matrix.split(
        "| Live agent-host collector / arbitrary tool-use adapter |", 1
    )[1].splitlines()[0]
    assert "does not load or execute an arbitrary host" in matrix


def test_extension_extras_are_published_pins_without_automatic_activation() -> None:
    project = tomllib.loads(_read("pyproject.toml"))["project"]
    extras = project["optional-dependencies"]
    guide = _read("docs/extension-sdk.md")
    assert {"transfer", "handoff", "playbooks", "router", "filter", "all"} <= set(extras)
    assert "current `v1.13.0` package" in guide
    assert "passive optional companion extras" in guide
    assert "does not discover, approve, bind, load, or activate" in guide
    assert "remain separately unreleased" not in guide


def test_gateway_status_remains_shipped_synthetic_not_production() -> None:
    guide = _read("docs/runtime-gateway.md")
    assert "shipped in `v1.2.0`" in guide
    assert "current `v1.13.0` package" in guide
    assert "**not** a production firewall" in guide
    assert "arbitrary executors" in guide
    assert "denial delivery guaranteed" in guide
    assert "published in `v1.5.0`" in guide
    assert "source-only additions" not in guide
