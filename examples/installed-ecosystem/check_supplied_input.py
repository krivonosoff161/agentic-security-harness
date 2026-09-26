"""Offline installed regression: caller bytes, never a model or network connection."""

from __future__ import annotations

import argparse
import importlib.metadata as metadata
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("output already exists")
    sys.dont_write_bytecode = True
    path = Path(__file__).with_name("chain.py")
    chain: Any = ModuleType("supplied_chain")
    chain.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), chain.__dict__)  # noqa: S102
    guard = chain.EffectGuard(args.out)
    sys.addaudithook(guard)
    rows = []
    try:
        chain.require({name: metadata.version(name) for name in chain.VERSIONS} == chain.VERSIONS)
        for case_id, key, outcome in (
            ("valid", "gateway-mode", "completed"),
            ("unknown", "unknown-public-key", "denied"),
            ("authority", {"authority": "admin"}, "rejected"),
            ("malformed", None, "rejected"),
        ):
            wire = {
                "schema_version": "AgenticSecurityHarnessModelEnvelope.v1",
                "profile_id": "example.chain",
                "profile_version": "v1",
                "representation": {"kind": "capability_request", "request_id": case_id,
                                   "capability_id": "bounded.lookup", "arguments": {"key": key}},
            }
            payload = b"{" if case_id == "malformed" else chain.canonical(wire)
            row = chain.run_case({"id": case_id, "mutation": "none", "score": 0.5},
                                 canonical_input=payload)
            chain.require(row["outcome"] == outcome)
            chain.require(row["synthetic_executions"] == int(outcome == "completed"))
            chain.require(row["operational_authority"] == "none")
            rows.append(row)
        chain.require(all(value == 0 for value in guard.counts.values()))
        result = {"schema": "supplied-chain-input-conformance-v1", "cases": rows,
                  "real_model_calls": 0, "real_effects": 0, "effect_guard": guard.counts,
                  "synthetic_executions": 1, "ok": True}
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
        print(json.dumps({"ok": True, "cases": len(rows), "synthetic_executions": 1}))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error_type": type(exc).__name__,
                          "effect_guard": guard.counts}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
