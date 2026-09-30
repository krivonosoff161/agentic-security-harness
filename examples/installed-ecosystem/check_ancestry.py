"""Offline, installed-distribution smoke for the retained ancestry chain."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata as metadata
import json
import sys
import tempfile
import types
from pathlib import Path
from typing import Any

CORE = "agentic-security-harness"
CORE_MODULE = "agentic_security_harness"
COMPANIONS = {
    "agentic-transfer-verifier": "0.2.1",
    "ai-agent-handoff": "0.3.0",
    "agentic-llm-router": "0.2.1",
    "llm-cheap-filter": "0.2.0",
    "llm-safety-playbooks": "0.1.0",
}


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def deny_effects(event: str, _args: tuple[Any, ...]) -> None:
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn")) or event in {
        "os.system", "os.posix_spawn", "os.fork", "os.forkpty", "os.startfile",
    }:
        raise PermissionError("offline ancestry smoke denies process/network activity")


def installed_core(expected_version: str) -> None:
    require(metadata.version(CORE) == expected_version, "core_version_mismatch")
    for name, expected in COMPANIONS.items():
        require(metadata.version(name) == expected, "companion_version_mismatch")
    distribution = metadata.distribution(CORE)
    package_file = Path(distribution.locate_file(CORE_MODULE + "/__init__.py")).resolve()
    imported = importlib.import_module(CORE_MODULE)
    source = Path(imported.__file__).resolve()
    checkout = Path(__file__).resolve().parents[2]
    require(source == package_file and not source.is_relative_to(checkout),
            "core_not_installed_distribution")


def load_chain() -> Any:
    path = Path(__file__).with_name("ancestry_chain.py")
    module = types.ModuleType("installed_ancestry_chain")
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)  # noqa: S102
    return module


def payload(key: str) -> bytes:
    return json.dumps({
        "schema_version": "AgenticSecurityHarnessModelEnvelope.v1",
        "profile_id": "example.chain", "profile_version": "v1",
        "representation": {
            "kind": "capability_request", "request_id": "request:ancestry-smoke",
            "capability_id": "bounded.lookup", "arguments": {"key": key},
        },
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def one_case(chain: Any, case_id: str, directory: Path) -> dict[str, Any]:
    from agentic_security_harness.ancestry_store import AncestryRecord, AncestryStore, Checkpoint

    scope = ("bounded.lookup",)
    root = AncestryRecord("root", "public-smoke", b"public-root", (), scope)
    store = AncestryStore.create(directory / "store.db", directory / "witness.json",
                                 context="public-smoke", root=root)
    first = store.checkpoint()
    wire = b"{" if case_id == "malformed" else payload(
        "unknown-public-key" if case_id == "denied_key" else "project-status"
    )
    child = AncestryRecord("target", "public-smoke", wire, ("root",), scope)
    checkpoint = store.append(child, expected=first)
    candidate: tuple[AncestryRecord, ...] | None = (root, child)
    if case_id == "missing_ancestor":
        candidate = (child,)
    elif case_id == "rebound":
        candidate = (root, AncestryRecord("target", "public-smoke", b"different",
                                          ("root",), scope))
    elif case_id == "cycle":
        candidate = (AncestryRecord("root", "public-smoke", b"public-root",
                                    ("target",), scope), child)
    elif case_id == "stale_checkpoint":
        checkpoint = Checkpoint(checkpoint.context, checkpoint.root_digest,
                                checkpoint.version, checkpoint.sequence, "0" * 64)
    elif case_id == "missing_witness":
        store.witness_path.unlink()
    row = chain.run_retained_case(store, "target", checkpoint, candidate)
    expected = {
        "valid": ("completed", 1, "gateway", "allow"),
        "denied_key": ("denied", 0, "gateway", "deny"),
        "malformed": ("rejected", 0, "quarantine", "reject"),
        "missing_ancestor": ("rejected", 0, "ancestry", "reject"),
        "rebound": ("rejected", 0, "ancestry", "reject"),
        "cycle": ("rejected", 0, "ancestry", "reject"),
        "stale_checkpoint": ("rejected", 0, "ancestry", "reject"),
        "missing_witness": ("recovery_required", 0, "ancestry", "recovery_required"),
    }[case_id]
    outcome, executions, last_stage, disposition = expected
    require(row["outcome"] == outcome, case_id + ":outcome")
    require(row["synthetic_executions"] == executions, case_id + ":executions")
    require(row["stages"][-1]["stage"] == last_stage and
            row["stages"][-1]["disposition"] == disposition, case_id + ":stage")
    require(row["operational_authority"] == "none" and
            row["may_authorize_effects"] is False, case_id + ":authority")
    require(row["fake_transport_calls"] == int(case_id in {"valid", "denied_key"}),
            case_id + ":transport")
    require((row["result_sha256"] is not None) == (last_stage == "gateway"),
            case_id + ":result_digest")
    return {
        "id": case_id,
        "outcome": row["outcome"],
        "synthetic_executions": row["synthetic_executions"],
        "fake_transport_calls": row["fake_transport_calls"],
        "result_sha256": row["result_sha256"],
        "stages": [{"stage": item["stage"], "disposition": item["disposition"]}
                   for item in row["stages"]],
    }


def run(core_version: str) -> dict[str, Any]:
    installed_core(core_version)
    chain = load_chain()
    cases = []
    with tempfile.TemporaryDirectory(prefix="ash-installed-ancestry-") as scratch:
        for case_id in (
            "valid", "denied_key", "malformed", "missing_ancestor", "rebound",
            "cycle", "stale_checkpoint", "missing_witness",
        ):
            directory = Path(scratch) / case_id
            directory.mkdir()
            cases.append(one_case(chain, case_id, directory))
    return {
        "schema": "installed-retained-ancestry-smoke.v1",
        "data_class": "public_synthetic",
        "core_version": core_version,
        "cases": cases,
        "case_count": len(cases),
        "synthetic_executions": sum(case["synthetic_executions"] for case in cases),
        "real_model_calls": 0,
        "real_provider_calls": 0,
        "operational_authority": "none",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-version", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("output already exists")
    sys.dont_write_bytecode = True
    sys.addaudithook(deny_effects)
    try:
        result = run(args.core_version)
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
    except Exception as exc:
        print(json.dumps({"ok": False, "error_type": type(exc).__name__,
                          "reason": str(exc) if isinstance(exc, ValueError) else "smoke_failed"}))
        return 1
    print(json.dumps({"ok": True, "cases": result["case_count"],
                      "synthetic_executions": result["synthetic_executions"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
