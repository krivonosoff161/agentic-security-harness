"""Tests for the adapter registry."""

import pytest

from agentic_security_harness.adapters import list_targets, make_target, target_ids


def test_list_targets_returns_builtin_targets() -> None:
    targets = list_targets()
    ids = [t.target_id for t in targets]
    assert "mock" in ids
    assert "demo-agent" in ids
    assert "protected-demo-agent" in ids
    assert "toy-local-function" in ids


def test_target_ids_matches_list() -> None:
    assert target_ids() == [t.target_id for t in list_targets()]


def test_make_target_mock() -> None:
    target = make_target("mock")
    assert target.name == "demo-mock-agent"
    assert target.descriptor_fields() == ("mock_agent", "demo-mock-agent", "mock")


def test_make_target_demo_agent() -> None:
    target = make_target("demo-agent")
    assert target.name == "demo-local-agent"
    type_, name, adapter = target.descriptor_fields()
    assert type_ == "demo_agent"
    assert adapter == "local"


def test_make_target_protected_demo_agent() -> None:
    target = make_target("protected-demo-agent")
    assert target.name == "protected-demo-agent"
    type_, name, adapter = target.descriptor_fields()
    assert type_ == "protected_demo_agent"


def test_make_target_toy_local_function() -> None:
    target = make_target("toy-local-function")
    assert target.name == "toy-local-function"
    type_, name, adapter = target.descriptor_fields()
    assert type_ == "toy_local"
    assert adapter == "toy"


def test_make_target_unknown_raises_key_error() -> None:
    with pytest.raises(KeyError, match="unknown target id"):
        make_target("nonexistent-target")


def test_all_targets_are_deterministic() -> None:
    for info in list_targets():
        assert info.deterministic is True


def test_all_targets_have_descriptions() -> None:
    for info in list_targets():
        assert info.description
        assert len(info.description) > 5


def test_targets_are_distinct() -> None:
    ids = target_ids()
    assert len(ids) == len(set(ids))
