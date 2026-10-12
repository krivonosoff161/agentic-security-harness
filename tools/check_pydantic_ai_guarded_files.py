"""Bounded offline experiment: real Agent dispatch, audited effects, disk readback.

The stdlib event loop is created before the audit hook because Windows may use
local IPC sockets to wake it. All third-party imports and case execution are
after the hook. This is a diagnostic control, not an OS security sandbox.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import math
import sys
from pathlib import Path
from typing import Any


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def verify_run(out: Path, cases: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
    """Read-only verification of actual bytes and the captured ancestry chain.

    Cases are the caller's pinned expected corpus, not expectations read from the
    result. Never run this function with a corpus supplied by the tested agent.
    """
    from agentic_security_harness.controlled_file_verifier import _ancestry, _json, _read

    result = _json(out / "result.json")
    rows = result["rows"]
    if len(rows) != len(cases) or result["mismatches"]:
        raise ValueError("integration cases missing or mismatched")
    for case, row in zip(cases, rows, strict=True):
        area = out / case["id"]
        labels = {
            "source": "scripted_test_model",
            "representation": "untrusted_tool_proposal",
            "authority": "none",
            "data_class": "public_synthetic",
        }
        document = canonical(
            {
                "context": case["id"],
                "label_schema": "ScriptedProposalLabels.v1",
                "labels": labels,
            }
        )
        report = case["report"].encode() if case["report"] is not None else b"pending\n"
        protected = b"protected fixture; do not modify\n"
        expected = {
            "reason": case["reason"],
            "applied": case["reason"] == "write_completed",
            "report_sha256": sha(report),
            "protected_sha256": sha(protected),
        }
        session = {
            "schema": "ControlledFileSession.v1",
            "context": case["id"],
            "document_sha256": sha(document),
            "max_proposals": 1,
            "data_class": "public_synthetic",
            "authority": "fresh_fixture_report_only",
            "guarded": True,
            "recovery": "no_resume_no_overwrite",
        }
        intent = {
            "attempt": 1,
            "call_id": "proposal-1",
            "proposal_sha256": sha(case["input"].encode()),
            "status": "started",
        }
        if (
            _json(area / "session.json") != session
            or _json(area / "proposal-1-intent.json") != intent
            or _json(area / "proposal-1-result.json") != row["decision"]
            or row["decision"]["call_id"] != "proposal-1"
        ):
            raise ValueError("session manifest, intent or result receipt mismatch")
        checks = (
            row["case_id"] == case["id"],
            row["split"] == case["split"],
            row["input"] == case["input"],
            row["input_sha256"] == sha(case["input"].encode()),
            row["trusted_labels"] == labels,
            row["trusted_context"] == case["id"],
            row["input_schema"] == "ControlledFileProposal.v1",
            row["label_schema"] == "ScriptedProposalLabels.v1",
            row["agent_usage"] == {"requests": 2, "tool_calls": 1},
            row["trusted_root_document_sha256"] == sha(document),
            row["actual"] == expected,
            row["expected"] == expected,
            row["decision"]["guarded"] is True,
            row["decision"]["proposal_sha256"] == row["input_sha256"],
            _read(area / "files/report.txt", 4096) == report,
            _read(area / "files/protected.txt", 4096) == protected,
            _json(area / "row.json") == row,
            row["effect_before"] == row["decision"]["before"],
            row["effect_after"] == row["decision"]["after"],
            row["effect_before"]["report"]["sha256"] == sha(b"pending\n"),
            row["effect_before"]["protected"]["sha256"] == sha(protected),
            row["effect_after"]["report"]["sha256"] == sha(report),
            row["effect_after"]["protected"]["sha256"] == sha(protected),
            type(row["hook_ns"]) is int and 0 <= row["hook_ns"] <= row["loop_ns"],
        )
        if not all(checks):
            raise ValueError("row, capture labels or effect bytes mismatch")
        _ancestry(area, case["id"], document.decode(), [row["decision"]])
    return rows


def summarize(values: list[int]) -> dict[str, int]:
    ordered = sorted(values)
    return {
        "n": len(values),
        "min_ns": ordered[0],
        "p50_ns": ordered[math.ceil(len(values) * 0.5) - 1],
        "p95_ns": ordered[math.ceil(len(values) * 0.95) - 1],
        "max_ns": ordered[-1],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=10, choices=range(1, 26))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    # Installed package should be selected by the caller's environment. Tests may
    # explicitly set PYTHONPATH=src, which the receipt makes visible by a hash.
    loop = asyncio.new_event_loop()
    forbidden = {
        "socket.connect",
        "socket.bind",
        "socket.getaddrinfo",
        "socket.sendto",
        "subprocess.Popen",
        "os.system",
        "os.posix_spawn",
        "os.startfile",
    }
    blocked: list[str] = []

    def audit(event: str, details: tuple[Any, ...]) -> None:
        if event in forbidden:
            blocked.append(event)
            raise RuntimeError("audit denied: " + event)

    sys.addaudithook(audit)
    from agentic_security_harness.controlled_file_workflow import _new_json
    from agentic_security_harness.safe_io import require_atomic_output_destination

    example_path = root / "examples/pydantic_ai_guarded_files.py"
    spec = importlib.util.spec_from_file_location("guarded_files_example", example_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("example unavailable")
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)
    example._require_pin()
    out = args.out.absolute()
    require_atomic_output_destination(out)
    if not out.parent.is_dir():
        raise ValueError("output parent must exist")
    out.mkdir(mode=0o700)
    source_names = (
        "ancestry_store.py",
        "_file_policy.py",
        "_fixture_files.py",
        "controlled_file_workflow.py",
        "controlled_file_verifier.py",
        "runtime_guard_foundation.py",
        "quarantine_connector.py",
    )
    import agentic_security_harness

    package_root = Path(agentic_security_harness.__file__).parent
    manifest = {
        "schema": "PydanticAIExperiment.v1",
        "repetitions": args.repetitions,
        "cases_per_repetition": len(example.CASES),
        "model_calls": 0,
        "framework": "pydantic-ai-slim==1.107.7",
        "example_sha256": sha(example_path.read_bytes()),
        "checker_sha256": sha(Path(__file__).read_bytes()),
        "corpus_sha256": sha(canonical(example.CASES)),
        "corpus": example.CASES,
        "source_hashes": {name: sha((package_root / name).read_bytes()) for name in source_names},
        "audit": (
            "deny process/network after stdlib event-loop IPC bootstrap, before third-party import"
        ),
        "latency": "perf_counter_ns; all samples retained; nearest-rank quantiles; no SLA",
        "data_class": "public_synthetic",
        "independent_human_review": False,
        "holdout": "reserved deterministic cases, not blind external labels; no model trained",
    }
    _new_json(out / "manifest.json", manifest)
    rows = []
    try:
        for index in range(args.repetitions):
            run = out / f"run-{index + 1:02d}"
            loop.run_until_complete(example.run_example_async(run))
            rows.extend(verify_run(run, example.CASES))
    finally:
        loop.close()
    by_reason = {
        reason: summarize([row["hook_ns"] for row in rows if row["actual"]["reason"] == reason])
        for reason in sorted({row["actual"]["reason"] for row in rows})
    }
    result = {
        "schema": "PydanticAIExperimentResult.v1",
        "verified_rows": len(rows),
        "applied": sum(row["actual"]["applied"] for row in rows),
        "protected_files_unchanged": len(rows),
        "blocked_audit_events": blocked,
        "model_calls": 0,
        "provider_calls": 0,
        "scripted_function_requests": sum(row["agent_usage"]["requests"] for row in rows),
        "framework_tool_calls": sum(row["agent_usage"]["tool_calls"] for row in rows),
        "hook_latency_by_reason": by_reason,
        "loop_latency": summarize([row["loop_ns"] for row in rows]),
        "manifest_sha256": sha(canonical(manifest)),
    }
    _new_json(out / "verification.json", result)
    print(json.dumps(result, sort_keys=True))
    return int(bool(blocked))


if __name__ == "__main__":
    raise SystemExit(main())
