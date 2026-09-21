"""Independent report mutation checks; installed runtime is exercised separately in CI."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/installed-ecosystem"


def module(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, EXAMPLE / f"{name}.py")
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def signed(value: dict[str, Any]) -> dict[str, Any]:
    value["result_sha256"] = hashlib.sha256(
        canonical({key: item for key, item in value.items() if key != "result_sha256"})
    ).hexdigest()
    return value


def reference_report() -> dict[str, Any]:
    """Independent artificial report for testing the validator, not runtime evidence."""
    checker = module("verify_chain")
    fixtures = (EXAMPLE / "chain-cases.json").read_bytes()
    rows = []
    for case in json.loads(fixtures)["cases"]:
        seed = {key: case[key] for key in ("id", "mutation", "score")}
        first = hashlib.sha256(canonical(seed)).hexdigest()
        previous = first
        stages = []
        count = checker.ORDER.index(case["terminal_stage"]) + 1
        for name in checker.ORDER[:count]:
            disposition = "accepted"
            if name == "filter":
                disposition = (
                    "drop" if case["score"] < 0.2 else "chief" if case["score"] >= 0.65 else "cheap"
                )
            if name == "playbooks":
                disposition = "observe"
            if name == "gateway":
                disposition = "allow" if case["outcome"] == "completed" else "deny"
            if name == case["terminal_stage"]:
                disposition = checker.TERMINAL_DISPOSITIONS[case["id"]]
            stages.append(
                {
                    "stage": name,
                    "input_sha256": previous,
                    "output_sha256": "a" * 64,
                    "disposition": disposition,
                }
            )
            previous = "a" * 64
        rows.append(
            {
                "id": case["id"],
                "stages": stages,
                "fixture_sha256": first,
                "operational_authority": "none",
                "outcome": case["outcome"],
                "terminal_stage": case["terminal_stage"],
                "synthetic_executions": case["synthetic_executions"],
                "fake_transport_calls": int(count >= 3),
            }
        )
    return signed(
        {
            "schema": "ecosystem-functional-chain-v1",
            "fixture_sha256": checker.sha(fixtures),
            "runner_sha256": checker.sha((EXAMPLE / "chain.py").read_bytes()),
            "versions": checker.PINS,
            "cases": rows,
            "operational_authority": "none",
            "real_model_calls": 0,
            "real_provider_calls": 0,
            "real_effects": 0,
            "non_claims": checker.NON_CLAIMS,
            "effect_guard": {"process_attempts": 0, "network_attempts": 0, "file_denials": 0},
        }
    )


def test_independent_verifier_accepts_its_structural_reference() -> None:
    verdict = module("verify_chain").verify(
        reference_report(), (EXAMPLE / "chain-cases.json").read_bytes()
    )
    assert verdict["verdict"] == "PASS" and verdict["full_paths"] == 2


@pytest.mark.parametrize(
    "mutation",
    [
        "authority",
        "model",
        "pin",
        "omitted",
        "link",
        "outcome",
        "execution",
        "raw",
        "unknown_stage",
        "transport",
    ],
)
def test_independent_verifier_rejects_resigned_mutations(mutation: str) -> None:
    report = copy.deepcopy(reference_report())
    if mutation == "authority":
        report["operational_authority"] = "admin"
    elif mutation == "model":
        report["real_model_calls"] = 1
    elif mutation == "pin":
        report["versions"]["agentic-security-harness"] = "0.0.0"
    elif mutation == "omitted":
        report["cases"].pop()
    elif mutation == "link":
        report["cases"][0]["stages"][1]["input_sha256"] = "f" * 64
    elif mutation == "outcome":
        report["cases"][0]["outcome"] = "rejected"
    elif mutation == "execution":
        report["cases"][-1]["synthetic_executions"] = 1
    elif mutation == "raw":
        report["raw_response"] = "public synthetic but forbidden field"
    elif mutation == "unknown_stage":
        report["cases"][0]["stages"][2]["stage"] = "skip-router"
    else:
        report["cases"][0]["fake_transport_calls"] = 0
    with pytest.raises(ValueError):
        module("verify_chain").verify(signed(report), (EXAMPLE / "chain-cases.json").read_bytes())


@pytest.mark.parametrize(
    "event",
    [
        "socket.__new__",
        "socket.connect",
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.rename",
        "os.putenv",
    ],
)
def test_chain_guard_denies_effects(event: str, tmp_path: Path) -> None:
    guard = module("chain").EffectGuard(tmp_path / "out.json")
    with pytest.raises(PermissionError):
        guard(event, ())
    assert sum(guard.counts.values()) == 1


def test_chain_guard_allows_only_declared_output_and_runtime_reads(tmp_path: Path) -> None:
    guard = module("chain").EffectGuard(tmp_path / "out.json")
    guard("open", (str(tmp_path / "out.json"), "x", os.O_WRONLY | os.O_CREAT))
    guard("open", (str(EXAMPLE / "chain.py"), "r", 0))
    with pytest.raises(PermissionError):
        guard("open", (str(tmp_path / "not-declared.json"), "w", os.O_WRONLY))
    with pytest.raises(PermissionError):
        guard("open", (str(tmp_path / "private.txt"), "r", 0))


def test_ci_runs_functional_chain_and_separate_verifier_for_published_wheels() -> None:
    workflow = (ROOT / ".github/workflows/ecosystem-integration.yml").read_text(encoding="utf-8")
    assert "published-functional-chain:" in workflow
    assert "examples/installed-ecosystem/chain.py" in workflow
    assert "examples/installed-ecosystem/verify_chain.py" in workflow
    assert "-r examples/installed-ecosystem/core-release.txt" in workflow
    assert "os: [ubuntu-latest, windows-latest]" in workflow


@pytest.mark.parametrize("payload", [b'{"x":1,"x":1}', b'{"x":NaN}', b'{"x":Infinity}'])
def test_verifier_rejects_ambiguous_json(payload: bytes) -> None:
    with pytest.raises(ValueError):
        module("verify_chain").decode(payload)


def test_verifier_rejects_boolean_execution_count_and_missing_limits() -> None:
    fixtures = (EXAMPLE / "chain-cases.json").read_bytes()
    report = reference_report()
    report["cases"][0]["synthetic_executions"] = True
    with pytest.raises(ValueError):
        module("verify_chain").verify(signed(report), fixtures)
    report = reference_report()
    report["non_claims"] = []
    with pytest.raises(ValueError):
        module("verify_chain").verify(signed(report), fixtures)
