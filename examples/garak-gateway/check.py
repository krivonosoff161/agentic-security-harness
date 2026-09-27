"""Fixed public-synthetic garak plan / Gateway experiment; no model or real tools.

Run in a fresh interpreter with an installed candidate Harness wheel. Optional garak
source is identity-checked before import. The audit hook is not an OS sandbox.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import json
import os
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
STATE: dict[str, Any] = {"stage": "preflight", "detector_calls": 0}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def tree_digest(root: Path) -> str:
    rows = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError("source symlink rejected")
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            raise ValueError("unbound bytecode cache rejected")
        if path.is_file():
            rows.append(path.relative_to(root).as_posix() + "\0" + digest(path.read_bytes()))
    return digest("\n".join(rows).encode("utf-8"))


class EffectGuard:
    """Deny audited network/process events and writes outside declared scratch/output."""

    def __init__(self, output: Path, scratch: Path, source: Path | None) -> None:
        self.output, self.scratch = output, scratch
        self.roots = [Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve(), HERE,
                      scratch]
        if source is not None:
            self.roots.append(source)
        self.counts = dict(network_attempts=0, process_attempts=0, file_denials=0,
                           scratch_write_events=0)

    def __call__(self, event: str, args: tuple[Any, ...]) -> None:
        if event.startswith("socket."):
            self.counts["network_attempts"] += 1
            raise PermissionError("network denied")
        if event.startswith(("subprocess.", "os.exec", "os.spawn")) or event in {
            "os.system", "os.posix_spawn", "os.fork", "os.forkpty", "os.startfile",
        }:
            self.counts["process_attempts"] += 1
            raise PermissionError("process denied")
        if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(args[0])).resolve()
            mode, flags = args[1:3]
            writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
            allowed = (path == self.output or path.is_relative_to(self.scratch)) if writing else (
                path == self.output or any(path.is_relative_to(root) for root in self.roots))
            if not allowed:
                self.counts["file_denials"] += 1
                raise PermissionError("file boundary denied")
            if writing and path.is_relative_to(self.scratch):
                self.counts["scratch_write_events"] += 1
        if event in {"os.mkdir", "os.remove", "os.rmdir", "os.rename", "os.link",
                     "os.symlink", "os.truncate", "os.chmod", "os.chown"}:
            paths = args[:2] if event in {"os.rename", "os.link", "os.symlink"} else args[:1]
            if not all(isinstance(p, (str, bytes, os.PathLike)) and
                       Path(os.fsdecode(p)).resolve().is_relative_to(self.scratch) for p in paths):
                self.counts["file_denials"] += 1
                raise PermissionError("mutation denied")
            self.counts["scratch_write_events"] += 1


class MemoryAudit:
    """In-memory test double only, not durable or authenticated custody."""

    def __init__(self) -> None:
        self.rows: list[dict[str, str]] = []

    def append(self, **values: Any) -> None:
        self.rows.append({"disposition": values["disposition"],
                          "payload_sha256": digest(canonical(values["payload"]))})


def verify_garak_origins(modules: dict[str, Any], source: Path) -> None:
    root = (source / "garak").resolve()
    for name, module in tuple(modules.items()):
        if name != "garak" and not name.startswith("garak."):
            continue
        # None is an import-system negative cache entry, not imported code.
        if module is None:
            continue
        origin = getattr(module, "__file__", None)
        locations = getattr(getattr(module, "__spec__", None),
                            "submodule_search_locations", None)
        paths = [origin] if origin is not None else list(locations or ())
        if not paths or not all(Path(path).resolve().is_relative_to(root) for path in paths):
            STATE["stage"] = "garak_origin_rejected:" + name
            raise ValueError("garak import origin mismatch")


def run(corpus: dict[str, Any], source: Path | None) -> dict[str, Any]:
    STATE["stage"] = "harness_import"
    from agentic_security_harness.garak_plan_adapter import (
        GarakPlanAdapterConfigV1,
        GarakToolBindingV1,
        normalize_garak_plan_v1,
    )
    from agentic_security_harness.quarantine_connector import (
        ProviderAdapterProfileRegistryV1,
        ProviderAdapterProfileV1,
        QuarantineCapabilityBindingV1,
        bridge_quarantine_admission_v1,
        evaluate_quarantine_input_v1,
    )
    from agentic_security_harness.runtime_gateway import GatewayEngine, default_gateway_policy_v1

    config = GarakPlanAdapterConfigV1(
        profile_id="example.garak", profile_version="1",
        bindings=(GarakToolBindingV1(tool_name="custom.unregistered",
                                     capability_id="fixture.unsupported"),
                  GarakToolBindingV1(tool_name="synthetic.lookup", capability_id="bounded.lookup")))
    registry = ProviderAdapterProfileRegistryV1(profiles=(ProviderAdapterProfileV1(
        profile_id=config.profile_id, profile_version=config.profile_version,
        capabilities=tuple(QuarantineCapabilityBindingV1(
            capability_id=cap, gateway_protocol="mcp", gateway_tool_name=tool,
            allowed_argument_keys=("key",), required_argument_keys=("key",)) for cap, tool in (
                ("bounded.lookup", "synthetic.lookup"),
                ("fixture.unsupported", "custom.unregistered"))),
    ),))
    detector: Any = None
    if source is not None:
        selected = json.loads((HERE / "manifest.json").read_bytes())
        if any(metadata.version(name) != version
               for name, version in selected["garak_dependencies"].items()):
            raise ValueError("detector dependency pin mismatch")
        STATE["stage"] = "garak_import"
        from garak.attempt import Attempt, Message
        from garak.detectors.tooluse import ForbiddenToolPlan
        STATE["stage"] = "detector_construct"
        detector = ForbiddenToolPlan()
        verify_garak_origins(sys.modules, source)

    rows = []
    for index, case in enumerate(corpus["cases"]):
        raw = case["plan"].encode("utf-8")
        score = None
        if detector is not None:
            STATE["stage"] = "detector_call"
            attempt = Attempt(prompt=Message(text=corpus["prompt"], lang="en"))
            attempt.outputs = [case["plan"]]
            STATE["detector_calls"] += 1
            scores = detector.detect(attempt)
            if len(scores) != 1 or scores[0] not in (0.0, 1.0):
                raise ValueError("unexpected detector result")
            score = float(scores[0])
        STATE["stage"] = "normalization"
        normalized = normalize_garak_plan_v1(raw, config=config, request_id="garak:" + case["id"])
        row: dict[str, Any] = {
            "id": case["id"], "output_index": index, "plan_sha256": digest(raw),
            "detector_status": "observed" if detector is not None else "not_run",
            "detector_score": score, "normalization": normalized.outcome.model_dump(mode="json"),
            "connector": "not_evaluated", "connector_reason": None,
            "gateway": "not_evaluated", "gateway_reason": None, "decision_sha256": None,
            "synthetic_executions": 0, "audit_rows": 0, "result_sha256": None,
            "audit_sha256": None,
        }
        if normalized.envelope is not None:
            STATE["stage"] = "quarantine"
            verdict = evaluate_quarantine_input_v1(
                registry, selected_profile_id=config.profile_id,
                selected_profile_version=config.profile_version, payload=normalized.envelope)
            row["connector"], row["connector_reason"] = verdict.disposition, verdict.reason_code
            if verdict.disposition == "admit" and verdict.capability_request is not None:
                bridge = bridge_quarantine_admission_v1(verdict, registry)
                if bridge is None:
                    raise ValueError("admission bridge absent")
                audit = MemoryAudit()
                STATE["stage"] = "gateway"
                engine = GatewayEngine(audit=audit)  # declared no-filesystem test double
                decision, result = engine.call_tool(bridge.gateway_call,
                                                    request_id="garak:" + case["id"])
                expected_audit = [{"disposition": decision.disposition,
                                   "payload_sha256": digest(canonical(
                                       bridge.gateway_call.arguments))}]
                if audit.rows != expected_audit:
                    raise ValueError("audit decision/input mismatch")
                row.update(gateway=decision.disposition, gateway_reason=decision.reason_code,
                           decision_sha256=digest(canonical(decision.model_dump(mode="json"))),
                           synthetic_executions=engine.execution_count, audit_rows=len(audit.rows),
                           result_sha256=None if result is None else digest(canonical(result)),
                           audit_sha256=digest(canonical(audit.rows)))
        rows.append(row)
    module_hashes = {}
    for short_name in ("garak_plan_adapter", "quarantine_connector", "runtime_gateway"):
        origin = sys.modules["agentic_security_harness." + short_name].__file__
        if origin is None:
            raise ValueError("Harness module origin absent")
        module_hashes[short_name] = digest(Path(origin).read_bytes())
    selected = json.loads((HERE / "manifest.json").read_bytes())
    if module_hashes != selected["harness_module_sha256"]:
        raise ValueError("Harness module pin mismatch")
    return {"harness_module_sha256": module_hashes, "registry_sha256": registry.sha256(),
            "policy_sha256": default_gateway_policy_v1().sha256(), "cases": rows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--garak-source", type=Path)
    args = parser.parse_args()
    output = args.out.resolve()
    if output.exists() or not output.parent.is_dir():
        raise SystemExit("output must be new in an existing directory")
    scratch = output.with_suffix(".scratch")
    if scratch.exists():
        raise SystemExit("scratch must be new")
    scratch.mkdir()
    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    corpus_bytes = (HERE / "cases.json").read_bytes()
    if digest(corpus_bytes) != manifest["corpus_sha256"]:
        raise SystemExit("corpus pin mismatch")
    source = args.garak_source.resolve() if args.garak_source else None
    if source is not None:
        if tree_digest(source / "garak") != manifest["garak_package_tree_sha256"]:
            raise SystemExit("garak source pin mismatch")
        sys.path.insert(0, str(source))
    # Preserve only the Windows OS root required by native Python dependencies.
    # No credential/provider/profile environment values are read or recorded.
    windows_root = os.environ.get("SystemRoot", "C:\\Windows") if os.name == "nt" else None
    os.environ.clear()
    if windows_root is not None:
        os.environ["SystemRoot"] = windows_root
    for key, leaf in (("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache"),
                      ("XDG_DATA_HOME", "data"), ("HOME", "home"), ("USERPROFILE", "home"),
                      ("TEMP", "tmp"), ("TMP", "tmp")):
        os.environ[key] = str(scratch / leaf)
    os.environ["GARAK_LOG_FILE"] = str(scratch / "garak.log")
    sys.dont_write_bytecode = True
    guard = EffectGuard(output, scratch, source)
    sys.addaudithook(guard)
    result: dict[str, Any] = {
        "schema": "GarakGatewayObservation.v1", "data_class": "public_synthetic",
        "manifest_sha256": digest((HERE / "manifest.json").read_bytes()),
        "corpus_sha256": digest(corpus_bytes), "status": "error", "error_class": None,
        "garak_source_sha": manifest["garak_source_sha"] if source is not None else None,
        "detector_executed": False, "detector_calls": 0,
        "model_calls": 0, "real_tool_dispatches": 0,
        "operational_authority": "none", "cases": [],
    }
    try:
        result.update(run(json.loads(corpus_bytes), source))
        result["status"] = "completed"
    except Exception as error:
        result["error_class"] = type(error).__name__  # no raw messages or traceback
        result["error_stage"] = STATE["stage"]
        result["error_errno"] = getattr(error, "errno", None)
        result["error_winerror"] = getattr(error, "winerror", None)
    result["detector_calls"] = STATE["detector_calls"]
    result["detector_executed"] = STATE["detector_calls"] > 0
    result["audit"] = dict(guard.counts)
    output.write_bytes(canonical(result) + b"\n")
    print("garak-gateway:", result["status"], "cases=" + str(len(result["cases"])))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
