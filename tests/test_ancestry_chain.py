"""Synthetic retained-chain interface and exact installed integration when available."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from agentic_security_harness.ancestry_store import (
    AncestryRecord,
    AncestryStore,
    Checkpoint,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "installed-ecosystem"
COMPANION_PACKAGES = (
    "agent_guard", "agentic_transfer_verifier", "llm_router",
    "llm_cheap_filter", "llm_safety_playbooks",
)


@pytest.fixture(autouse=True)
def isolated_companion_imports() -> Iterator[None]:
    """Do not leak installed imports into the exact-source compatibility gates."""
    def selected(name: str) -> bool:
        return any(name == package or name.startswith(package + ".")
                   for package in COMPANION_PACKAGES)

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


def chain_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "retained_chain_test", EXAMPLE / "ancestry_chain.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wire(capability: str = "bounded.lookup", key: str = "project-status") -> bytes:
    helper_spec = importlib.util.spec_from_file_location("chain_test_helper", EXAMPLE / "chain.py")
    assert helper_spec and helper_spec.loader
    helper = importlib.util.module_from_spec(helper_spec)
    helper_spec.loader.exec_module(helper)
    return helper.canonical({
        "schema_version": "AgenticSecurityHarnessModelEnvelope.v1",
        "profile_id": "example.chain", "profile_version": "v1",
        "representation": {"kind": "capability_request", "request_id": "request:test",
                           "capability_id": capability, "arguments": {"key": key}},
    })


def retained(tmp_path: Path, *, payload: bytes | None = None,
             scope: tuple[str, ...] = ("bounded.lookup",)
             ) -> tuple[AncestryStore, Checkpoint, AncestryRecord, AncestryRecord]:
    root = AncestryRecord("root", "case-one", b"public-root", (), scope)
    store = AncestryStore.create(tmp_path / "store.db", tmp_path / "witness.json",
                                 context="case-one", root=root)
    first = store.checkpoint()
    child = AncestryRecord("target", "case-one", payload or wire(), ("root",), scope)
    checkpoint = store.append(child, expected=first)
    return store, checkpoint, root, child


@pytest.mark.parametrize("kind", ["missing_ancestor", "rebound", "cycle", "unknown_target"])
def test_invalid_ancestry_stops_before_components(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    chain = chain_module()
    store, checkpoint, root, child = retained(tmp_path)
    monkeypatch.setattr(chain, "_chain_helpers",
                        lambda: pytest.fail("component loaded before ancestry admission"))
    candidate: tuple[AncestryRecord, ...]
    target: str
    if kind == "missing_ancestor":
        candidate, target = (child,), "target"
    elif kind == "rebound":
        candidate = (root, AncestryRecord("target", "case-one", b"different",
                                          ("root",), ("bounded.lookup",)))
        target = "target"
    elif kind == "cycle":
        candidate = (AncestryRecord("root", "case-one", b"public-root",
                                    ("target",), ("bounded.lookup",)), child)
        target = "target"
    else:
        candidate, target = (root, child), "absent"
    row = chain.run_retained_case(store, target, checkpoint, candidate)
    assert row["outcome"] == "rejected"
    assert row["stages"] == [{"stage": "ancestry", "disposition": "reject",
                              "reason": "candidate_mismatch"}]
    assert row["synthetic_executions"] == 0


def test_stale_checkpoint_and_missing_witness_stop_before_components(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain = chain_module()
    store, checkpoint, _, _ = retained(tmp_path)
    monkeypatch.setattr(chain, "_chain_helpers",
                        lambda: pytest.fail("component loaded before ancestry admission"))
    stale = chain.run_retained_case(
        store, "target", store.snapshot(expected=checkpoint).checkpoint.__class__(
            checkpoint.context, checkpoint.root_digest, checkpoint.version,
            1, "0" * 64,
        )
    )
    assert stale["stages"][0]["reason"] == "checkpoint_conflict"
    store.witness_path.unlink()
    damaged = chain.run_retained_case(store, "target", checkpoint)
    assert damaged["outcome"] == "recovery_required"
    assert damaged["synthetic_executions"] == 0


def _installed_available() -> None:
    for name in COMPANION_PACKAGES:
        pytest.importorskip(name)


@pytest.mark.parametrize("key,expected_outcome,executions", [
    ("project-status", "completed", 1),
    ("unknown-public-key", "denied", 0),
])
def test_exact_installed_chain_preserves_gateway_decision(
    tmp_path: Path, key: str, expected_outcome: str, executions: int
) -> None:
    _installed_available()
    chain = chain_module()
    store, checkpoint, root, child = retained(tmp_path, payload=wire(key=key))
    row = chain.run_retained_case(store, "target", checkpoint, (root, child),
                                  return_pure_result=True)
    assert row["outcome"] == expected_outcome
    assert row["synthetic_executions"] == executions
    stages = {stage["stage"]: stage for stage in row["stages"]}
    assert (
        stages["ancestry"]["target_payload_sha256"]
        == stages["quarantine"]["input_payload_sha256"]
        == stages["transfer"]["target_payload_sha256"]
        == stages["handoff"]["target_payload_sha256"]
    )
    assert row["result_sha256"] is not None
    assert ("pure_result" in row) is (expected_outcome == "completed")


@pytest.mark.parametrize("payload,scope,outcome", [
    (b"{", ("bounded.lookup",), "rejected"),
    (None, (), "rejected"),
])
def test_malformed_or_scope_denied_zero_execution(
    tmp_path: Path, payload: bytes | None, scope: tuple[str, ...], outcome: str
) -> None:
    _installed_available()
    chain = chain_module()
    store, checkpoint, _, _ = retained(tmp_path, payload=payload, scope=scope)
    row = chain.run_retained_case(store, "target", checkpoint)
    assert row["outcome"] == outcome
    assert row["synthetic_executions"] == 0


def test_no_request_is_typed_zero_execution(tmp_path: Path) -> None:
    _installed_available()
    chain = chain_module()
    helper = chain._chain_helpers()
    payload = helper.canonical({
        "schema_version": "AgenticSecurityHarnessModelEnvelope.v1",
        "profile_id": "example.chain", "profile_version": "v1",
        "representation": {"kind": "no_request"},
    })
    store, checkpoint, _, _ = retained(tmp_path, payload=payload)
    row = chain.run_retained_case(store, "target", checkpoint)
    assert row["outcome"] == "no_request"
    assert row["synthetic_executions"] == 0
