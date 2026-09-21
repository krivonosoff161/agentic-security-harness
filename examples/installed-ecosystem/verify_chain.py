"""Stdlib-only independent validation of the fixed functional-chain evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ORDER = ["quarantine", "filter", "router", "transfer", "handoff", "playbooks", "gateway"]
PINS = {
    "agentic-security-harness": "1.6.0",
    "agentic-transfer-verifier": "0.2.1",
    "ai-agent-handoff": "0.3.0",
    "agentic-llm-router": "0.2.1",
    "llm-cheap-filter": "0.2.0",
    "llm-safety-playbooks": "0.1.0",
}
NON_CLAIMS = [
    "classifier accuracy",
    "real provider compatibility",
    "authenticated custody",
    "OS sandbox",
    "independent human review",
    "production safety",
]
TERMINAL_DISPOSITIONS = {
    "valid-cheap": "allow",
    "valid-chief": "allow",
    "filter-drop": "drop",
    "malformed-input": "reject",
    "authority-field": "reject",
    "no-request": "admit",
    "router-rebind": "reject",
    "router-accounting": "reject",
    "transfer-authority": "FAIL",
    "transfer-cycle": "WARN",
    "handoff-tamper": "reject",
    "handoff-replay": "reject",
    "handoff-rebind": "reject",
    "playbooks-tamper": "reject",
    "playbooks-unknown": "challenge",
    "gateway-deny": "deny",
}


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def check(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def decode(payload: bytes) -> Any:
    check(len(payload) <= 1_000_000, "report byte bound")

    def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            check(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        raise ValueError("nonfinite JSON number")

    return json.loads(payload, object_pairs_hook=closed_pairs, parse_constant=reject_constant)


def verify(result: dict[str, Any], fixtures: bytes) -> dict[str, Any]:
    """No producer import, package import, model, provider or callable execution."""
    check(
        set(result)
        == {
            "schema",
            "fixture_sha256",
            "versions",
            "cases",
            "operational_authority",
            "real_model_calls",
            "real_provider_calls",
            "real_effects",
            "non_claims",
            "effect_guard",
            "result_sha256",
            "runner_sha256",
        },
        "closed report shape",
    )
    body = {key: value for key, value in result.items() if key != "result_sha256"}
    expected_digest = sha(
        json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    )
    check(result["result_sha256"] == expected_digest, "report digest")
    check(result["schema"] == "ecosystem-functional-chain-v1", "schema")
    check(result["fixture_sha256"] == sha(fixtures), "fixture binding")
    check(
        result["runner_sha256"] == sha(Path(__file__).with_name("chain.py").read_bytes()),
        "runner binding",
    )
    check(result["versions"] == PINS, "package pins")
    check(result["operational_authority"] == "none", "authority")
    check(result["non_claims"] == NON_CLAIMS, "evidence limits")
    for field in ("real_model_calls", "real_provider_calls", "real_effects"):
        check(type(result[field]) is int and result[field] == 0, field)
    check(
        result["effect_guard"] == {"process_attempts": 0, "network_attempts": 0, "file_denials": 0},
        "effects",
    )
    check(all(type(value) is int for value in result["effect_guard"].values()), "counter types")
    expected = json.loads(fixtures)["cases"]
    check(len(expected) == 16 and len(result["cases"]) == 16, "case count")
    completed = 0
    for specification, observed in zip(expected, result["cases"], strict=True):
        check(
            set(observed)
            == {
                "id",
                "stages",
                "synthetic_executions",
                "fake_transport_calls",
                "operational_authority",
                "fixture_sha256",
                "outcome",
                "terminal_stage",
            },
            "closed row",
        )
        for key in ("id", "outcome", "terminal_stage", "synthetic_executions"):
            check(observed[key] == specification[key], "declared outcome: " + specification["id"])
        check(observed["operational_authority"] == "none", "row authority")
        check(type(observed["synthetic_executions"]) is int, "execution counter type")
        seed = {key: specification[key] for key in ("id", "mutation", "score")}
        previous = sha(
            json.dumps(seed, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        )
        check(observed["fixture_sha256"] == previous, "row fixture")
        stage_count = ORDER.index(specification["terminal_stage"]) + 1
        check(
            [entry["stage"] for entry in observed["stages"]] == ORDER[:stage_count],
            "actual stage prefix",
        )
        check(type(observed["fake_transport_calls"]) is int, "transport counter type")
        check(
            observed["fake_transport_calls"] == int(stage_count >= 3), "fake transport accounting"
        )
        check(
            observed["stages"][-1]["disposition"] == TERMINAL_DISPOSITIONS[specification["id"]],
            "terminal component disposition",
        )
        for entry in observed["stages"]:
            check(
                set(entry) == {"stage", "input_sha256", "output_sha256", "disposition"},
                "closed stage",
            )
            check(entry["input_sha256"] == previous, "causal digest link")
            check(
                isinstance(entry["output_sha256"], str)
                and re.fullmatch("[0-9a-f]{64}", entry["output_sha256"]) is not None,
                "output digest",
            )
            previous = entry["output_sha256"]
        if stage_count >= 2:
            score = specification["score"]
            role = "drop" if score < 0.2 else "chief" if score >= 0.65 else "cheap"
            check(observed["stages"][1]["disposition"] == role, "filter role")
        if specification["outcome"] == "completed":
            check(
                stage_count == 7 and observed["stages"][-1]["disposition"] == "allow", "full path"
            )
            check(observed["stages"][-2]["disposition"] == "observe", "advice not authorization")
            completed += 1
        if specification["outcome"] == "denied":
            check(observed["stages"][-1]["disposition"] == "deny", "Gateway denial")
    check(completed == 2, "positive controls")
    return {
        "schema": "ecosystem-chain-verification-v1",
        "verdict": "PASS",
        "cases": 16,
        "full_paths": completed,
        "synthetic_executions": 2,
        "real_effects": 0,
        "verified_result_sha256": result["result_sha256"],
        "independent_human_review": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    try:
        result = decode(args.result.read_bytes())
        print(
            json.dumps(
                verify(result, Path(__file__).with_name("chain-cases.json").read_bytes()),
                sort_keys=True,
            )
        )
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(json.dumps({"verdict": "FAIL", "error_type": type(exc).__name__}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
