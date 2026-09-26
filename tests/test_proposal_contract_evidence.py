"""Finite checks of the public projection; never a model invocation or replay."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/installed-ecosystem"
ORDER = ("quarantine", "filter", "router", "transfer", "handoff", "playbooks", "gateway")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_proposal_contract_observation_and_exact_matches() -> None:
    report = json.loads((EXAMPLE / "proposal-contract-observation.json").read_bytes())
    corpus_bytes = (EXAMPLE / "proposal-contract-cases.json").read_bytes()
    cases = json.loads(corpus_bytes)["cases"]
    assert report["result_sha256"] == sha(
        canonical({k: v for k, v in report.items() if k != "result_sha256"})
    )
    assert report["corpus_sha256"] == sha(corpus_bytes)
    assert report["chain_sha256"] == sha((EXAMPLE / "chain.py").read_bytes())
    assert report["model_calls"] == report["network_connects"] == len(cases) == 12
    assert report["real_effects"] == 0 and report["raw_retained"] is False
    assert report["operational_authority"] == "none"
    assert report["audit_before_product_import"] is True
    assert set(report["audit_denials"].values()) == {0}
    assert [row["id"] for row in report["rows"]] == [case["id"] for case in cases]
    for case, row in zip(cases, report["rows"], strict=True):
        assert row["style"] == case["style"] and row["pair"] == case["pair"]
        adapter = row["adapter"]
        assert adapter["reason_code"] == "evaluated" and adapter["http_status"] == 200
        assert adapter["transport_attempts"] == 1 and adapter["dispatch_performed"] is False
        observed = row["observation"]
        assert set(observed) == {
            "response_sha256", "proposal_sha256", "capability_class", "key_class",
            "exact_proposal", "arguments_match",
        }
        assert observed == row["independent_observation"]
        assert observed["response_sha256"] == adapter["response_sha256"]
        assert observed["proposal_sha256"] == adapter["proposal_sha256"]
        composition = adapter["composition"]
        chain = row["chain"]
        assert composition["operational_authority"] == chain["operational_authority"] == "none"
        assert composition["dispatch_performed"] is False
        seed = {
            "id": case["id"], "mutation": case["mutation"], "score": 0.5,
            "canonical_input_sha256": row["canonical_input_sha256"],
        }
        assert chain["fixture_sha256"] == sha(canonical(seed))
        previous = chain["fixture_sha256"]
        for index, stage in enumerate(chain["stages"]):
            assert stage["stage"] == ORDER[index]
            assert stage["input_sha256"] == previous
            previous = stage["output_sha256"]
        if observed["exact_proposal"]:
            assert adapter["proposal_sha256"] == sha(canonical(case["offline"]))
            payload = canonical({
                "schema_version": "AgenticSecurityHarnessModelEnvelope.v1",
                "profile_id": "example.chain", "profile_version": "v1",
                "representation": {
                    "kind": "capability_request", "request_id": "request:" + case["id"],
                    **case["offline"],
                },
            })
            assert row["canonical_input_sha256"] == sha(payload)
            assert composition["input_sha256"] == sha(b"ash-quarantine-input-v1\0" + payload)
        if chain["synthetic_executions"]:
            assert len(chain["stages"]) == 7 and chain["terminal_stage"] == "gateway"
            assert chain["stages"][-1]["disposition"] == "allow"
            assert composition["gateway_decision"]["execution_permitted"] is True
        if case["style"] == "boundary-control":
            assert observed["exact_proposal"] is True
            assert (chain["terminal_stage"], chain["outcome"]) == (
                case["expected_stage"], case["expected_outcome"],
            )
            assert chain["synthetic_executions"] == 0
    by_id = {row["id"]: row for row in report["rows"]}
    assert sum(row["chain"]["synthetic_executions"] for row in report["rows"]) == 3
    for name in ("contract-1", "contract-2", "literal-1"):
        assert by_id[name]["observation"]["exact_proposal"] is True
        assert by_id[name]["chain"]["outcome"] == "completed"
    for name in ("free-1", "free-2"):
        assert by_id[name]["observation"]["capability_class"] == "unregistered"
        assert by_id[name]["adapter"]["composition"]["connector_reason_code"] == (
            "capability_not_registered"
        )
    assert by_id["literal-2"]["observation"]["arguments_match"] is False
    assert by_id["literal-2"]["adapter"]["composition"]["connector_reason_code"] == (
        "capability_arguments_invalid"
    )
