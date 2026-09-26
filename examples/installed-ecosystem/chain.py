"""Explicit installed-package six-component synthetic chain; never a real provider."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

VERSIONS = {
    "agentic-security-harness": "1.6.0",
    "agentic-transfer-verifier": "0.2.1",
    "ai-agent-handoff": "0.3.0",
    "agentic-llm-router": "0.2.1",
    "llm-cheap-filter": "0.2.0",
    "llm-safety-playbooks": "0.1.0",
}
STAGES = ("quarantine", "filter", "router", "transfer", "handoff", "playbooks", "gateway")
PACK_SHA256 = "1c8ca14e6ab83d92742f6fba0b0d1b1bc422ebe30163c6619e9c80f5413b8915"
CORE_RELEASE_SHA = "0796fc60020ced318ad67fecb29de60234e707df"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("ecosystem chain invariant failed")


class EffectGuard:
    """Early denial, not an OS sandbox; reads restricted to code/runtime roots."""

    def __init__(self, output: Path) -> None:
        self.output = output.resolve()
        self.roots = (
            Path(sys.prefix).resolve(),
            Path(sys.base_prefix).resolve(),
            Path(__file__).resolve().parent,
        )
        self.counts = {"process_attempts": 0, "network_attempts": 0, "file_denials": 0}

    def __call__(self, event: str, args: tuple[Any, ...]) -> None:
        if event.startswith("socket."):
            self.counts["network_attempts"] += 1
            raise PermissionError("network denied")
        if event.startswith(("subprocess.", "os.exec", "os.spawn")) or event in {
            "os.system",
            "os.posix_spawn",
            "os.fork",
            "os.forkpty",
            "os.startfile",
        }:
            self.counts["process_attempts"] += 1
            raise PermissionError("process denied")
        if event in {
            "os.remove",
            "os.rename",
            "os.rmdir",
            "os.mkdir",
            "os.link",
            "os.symlink",
            "os.truncate",
            "os.chmod",
            "os.chown",
            "os.putenv",
        }:
            self.counts["file_denials"] += 1
            raise PermissionError("state mutation denied")
        if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
            target = Path(os.fsdecode(args[0])).resolve()
            mode, flags = args[1:3]
            writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)
            )
            permitted = (
                target == self.output
                if writing
                else any(target.is_relative_to(root) for root in self.roots)
            )
            if not permitted:
                self.counts["file_denials"] += 1
                raise PermissionError("file boundary denied")


class MemoryAudit:
    """Declared in-memory test double; not durable or authenticated custody."""

    def __init__(self) -> None:
        self.rows: list[dict[str, str]] = []

    def append(self, **values: Any) -> None:
        self.rows.append(
            {
                "disposition": values["disposition"],
                "payload_sha256": digest(canonical(values["payload"])),
            }
        )


def router_with_in_memory_transport(role: str, payload: bytes) -> tuple[str, dict[str, Any], int]:
    """Execute Router.call with an explicit fake transport and synthetic configuration.

    No process environment is read or copied; no aiohttp client is constructed.
    The coroutine must complete synchronously through its in-memory awaits.
    """
    import llm_router.client as client

    calls = 0
    toy_configuration = {
        "OPENAI_API_KEY": "public-toy-not-a-credential",
        "OPENAI_BASE_URL": "https://public-synthetic.invalid/v1",
        "LLM_MAX_RETRIES": "0",
        "LLM_CHEAP_MODEL": "public-toy",
        "LLM_CHIEF_MODEL": "public-toy",
    }

    class Response:
        status = 200

        async def __aenter__(self) -> Any:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def json(self) -> dict[str, Any]:
            return {
                "choices": [{"message": {"content": payload.decode()}}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
            }

    class Session(Response):
        def post(self, url: str, **kwargs: Any) -> Response:
            nonlocal calls
            require(url == "https://public-synthetic.invalid/v1/chat/completions")
            require(kwargs["json"]["model"] == "public-toy")
            calls += 1
            return Response()

    fake = SimpleNamespace(ClientSession=Session, ClientTimeout=lambda **kwargs: None)
    config = SimpleNamespace(getenv=lambda key, default=None: toy_configuration.get(key, default))
    with (
        patch.object(client, "os", config),
        patch.object(client, "_load_http_client", lambda: fake),
    ):
        coroutine = client.call(
            role,
            "Fixed public synthetic JSON compatibility fixture.",
            "Return the declared fixture.",
            provider="openai",
            timeout=1,
            json_mode=True,
            max_tokens=128,
        )
        try:
            coroutine.send(None)
        except StopIteration as stop:
            text, usage = stop.value
        else:
            raise ValueError("fake Router transport unexpectedly suspended")
        finally:
            coroutine.close()
    require(isinstance(text, str) and calls == 1)
    return text, usage, calls


def run_case(case: dict[str, Any], *, canonical_input: bytes | None = None) -> dict[str, Any]:
    """Evaluate one closed chain; supplied bytes still pass normal Quarantine admission.

    The optional input is an in-memory seam for separately manifested research.
    It never adds transport, selects a provider, or changes the CLI fixture suite.
    """
    from agent_guard.handoff_metadata import (
        HandoffAdapterContext,
        HandoffMetadataError,
        build_handoff_metadata,
        project_handoff_metadata,
    )
    from agentic_transfer_verifier.models import ProvenanceStep, TransferEnvelope
    from agentic_transfer_verifier.verifier import verify_envelope
    from llm_cheap_filter.policy import EscalationPolicy
    from llm_cheap_filter.prefilter import PreFilter
    from llm_router.receipt import (
        InvocationAttemptV1,
        InvocationReceiptError,
        build_invocation_receipt_v1,
        decode_invocation_receipt_v1,
        encode_invocation_receipt_v1,
    )
    from llm_safety_playbooks import policy_pack_bytes

    from agentic_security_harness.policy_pack_extension import (
        PolicyPackExtensionError,
        PolicyPackSignalsV1,
        build_policy_pack_signal_binding_v1,
        decode_policy_pack_v1,
        evaluate_policy_pack_binding_v1,
    )
    from agentic_security_harness.portfolio_contract import CanonicalObservationEventV1
    from agentic_security_harness.quarantine_connector import (
        ProviderAdapterProfileRegistryV1,
        ProviderAdapterProfileV1,
        QuarantineCapabilityBindingV1,
        bridge_quarantine_admission_v1,
        evaluate_quarantine_input_v1,
    )
    from agentic_security_harness.runtime_gateway import GatewayEngine

    mutation = case["mutation"]
    row: dict[str, Any] = {
        "id": case["id"],
        "stages": [],
        "synthetic_executions": 0,
        "fake_transport_calls": 0,
        "operational_authority": "none",
    }
    seed = {key: case[key] for key in ("id", "mutation", "score")}
    if canonical_input is not None:
        require(type(canonical_input) is bytes)
        seed["canonical_input_sha256"] = digest(canonical_input)
    commitment = digest(canonical(seed))
    row["fixture_sha256"] = commitment

    def stage(name: str, disposition: str, evidence: Any) -> None:
        nonlocal commitment
        output = digest(canonical(evidence))
        row["stages"].append(
            {
                "stage": name,
                "input_sha256": commitment,
                "output_sha256": output,
                "disposition": disposition,
            }
        )
        commitment = output

    def finish(outcome: str) -> dict[str, Any]:
        row["outcome"] = outcome
        row["terminal_stage"] = row["stages"][-1]["stage"]
        return row

    registry = ProviderAdapterProfileRegistryV1(
        profiles=(
            ProviderAdapterProfileV1(
                profile_id="example.chain",
                profile_version="v1",
                capabilities=(
                    QuarantineCapabilityBindingV1(
                        capability_id="bounded.lookup",
                        gateway_protocol="mcp",
                        gateway_tool_name="synthetic.lookup",
                        allowed_argument_keys=("key",),
                        required_argument_keys=("key",),
                    ),
                ),
            ),
        )
    )
    representation: dict[str, Any] = {
        "kind": "capability_request",
        "request_id": "request:" + case["id"],
        "capability_id": "bounded.lookup",
        "arguments": {
            "key": "unknown-public-key" if mutation == "gateway-deny" else "project-status"
        },
    }
    if mutation == "no-request":
        representation = {"kind": "no_request"}
    if mutation == "authority-field":
        representation["authority"] = "admin"
    wire = {
        "schema_version": "AgenticSecurityHarnessModelEnvelope.v1",
        "profile_id": "example.chain",
        "profile_version": "v1",
        "representation": representation,
    }
    payload = b"{" if mutation == "malformed-input" else canonical(wire)
    if canonical_input is not None:
        payload = canonical_input
    verdict = evaluate_quarantine_input_v1(
        registry,
        selected_profile_id="example.chain",
        selected_profile_version="v1",
        payload=payload,
    )
    stage("quarantine", verdict.disposition, verdict.model_dump(mode="json"))
    if verdict.disposition != "admit":
        return finish("rejected")
    if verdict.capability_request is None:
        return finish("no_request")
    require(verdict.operational_authority == "none")
    filtered = PreFilter(min_chars=1).score(payload.decode(), [])
    role = EscalationPolicy().decide(case["score"])
    stage(
        "filter",
        role,
        {
            "keep": filtered.keep,
            "role": role,
            "request_sha256": verdict.capability_request.sha256(),
        },
    )
    if not filtered.keep or role == "drop":
        return finish("filtered")

    response_payload = payload
    if mutation == "router-rebind":
        wire["representation"]["arguments"]["key"] = "gateway-mode"
        response_payload = canonical(wire)
    text, usage, row["fake_transport_calls"] = router_with_in_memory_transport(
        role, response_payload
    )
    try:
        require(text.encode() == payload)
        receipt = build_invocation_receipt_v1(
            occurred_at="2026-09-21T00:00:00.000000Z",
            producer_id_hash=digest(b"public-toy-router"),
            request_payload_sha256=digest(payload),
            provider_id="openai",
            model_id_sha256=digest(b"public-toy"),
            role=role,
            attempts=(
                InvocationAttemptV1(
                    attempt_index=1,
                    outcome="success",
                    http_status=200,
                    reason_code="provider.success",
                    response_payload_sha256=digest(text.encode()),
                ),
            ),
            terminal_status="success",
            response_payload_sha256=digest(text.encode()),
            output_text_sha256=digest(text.encode()),
            usage_provenance="provider_reported",
            input_tokens=usage["input_tokens"],
            output_tokens=usage["output_tokens"],
            total_tokens=99 if mutation == "router-accounting" else usage["total_tokens"],
            pricing_source="unpriced",
            pricing_source_ref_sha256=None,
            input_rate_usd_nanos_per_million=0,
            output_rate_usd_nanos_per_million=0,
        )
        receipt_bytes = encode_invocation_receipt_v1(receipt)
        require(decode_invocation_receipt_v1(receipt_bytes) == receipt)
    except (InvocationReceiptError, ValueError):
        stage("router", "reject", {"reason": "route_or_receipt_integrity"})
        return finish("rejected")
    stage(
        "router",
        role,
        {
            "receipt_sha256": digest(receipt_bytes),
            "role": receipt.role,
            "total_tokens": receipt.total_tokens,
            "cost_usd_nanos": receipt.cost_usd_nanos,
        },
    )

    envelope = TransferEnvelope(
        envelope_id=commitment,
        producer="public-router",
        consumer="public-handoff",
        payload_kind="invocation-receipt",
        trust_level="untrusted",
        authority_scope="admin" if mutation == "transfer-authority" else "none",
        payload={
            "receipt_sha256": digest(receipt_bytes),
            "request_sha256": verdict.capability_request.sha256(),
        },
        provenance=[
            ProvenanceStep(actor="public-router", action="fixture", source="public_synthetic")
        ],
        parent_envelope_id=commitment if mutation == "transfer-cycle" else "",
    )
    transfer = verify_envelope(envelope)
    stage("transfer", transfer.status, transfer.to_dict())
    if transfer.status != "PASS":
        return finish("rejected")
    artifact = canonical(envelope.to_dict())
    context = HandoffAdapterContext(
        project_id="ai-agent-handoff",
        repository_id="example/public-synthetic",
        repository_sha=CORE_RELEASE_SHA,
        source_surface="agent",
        data_envelope_ref=digest(artifact),
    )
    created = datetime(2026, 9, 21, tzinfo=UTC)
    previous = build_handoff_metadata(
        artifact_kind="task",
        artifact_bytes=receipt_bytes,
        sequence=0,
        created_at=created,
        producer_id_hash=digest(b"public-toy-handoff"),
    )
    previous_projection = project_handoff_metadata(previous, receipt_bytes, context)
    current = build_handoff_metadata(
        artifact_kind="task",
        artifact_bytes=artifact,
        sequence=1,
        created_at=created + timedelta(seconds=1),
        producer_id_hash=previous.producer_id_hash,
        parent_artifact_sha256="0" * 64
        if mutation == "handoff-rebind"
        else previous.artifact_sha256,
    )
    try:
        projection = project_handoff_metadata(
            current,
            artifact + b" " if mutation == "handoff-tamper" else artifact,
            context,
            previous=previous,
            previous_observation=previous_projection.observation,
        )
        if mutation == "handoff-replay":
            projection = project_handoff_metadata(
                current,
                artifact,
                context,
                previous=current,
                previous_observation=projection.observation,
            )
    except HandoffMetadataError:
        stage("handoff", "reject", {"reason": "artifact_or_sequence_binding"})
        return finish("rejected")
    event = CanonicalObservationEventV1.model_validate(projection.observation.to_dict())
    require(event.operational_authority == "none" and event.authority_envelope_ref is None)
    stage("handoff", "accepted", event.model_dump(mode="json"))
    try:
        pack_bytes = policy_pack_bytes()
        if mutation == "playbooks-tamper":
            pack_bytes += b" "
        pack = decode_policy_pack_v1(pack_bytes, expected_file_sha256=PACK_SHA256)
        signal_values = dict.fromkeys(PolicyPackSignalsV1.model_fields, "absent")
        if mutation == "playbooks-unknown":
            signal_values["handoff_verification_incomplete"] = "unknown"
        binding = build_policy_pack_signal_binding_v1(
            event, signals=PolicyPackSignalsV1(**signal_values), source_class="synthetic_fixture"
        )
        advice = evaluate_policy_pack_binding_v1(pack, binding, event)
    except PolicyPackExtensionError:
        stage("playbooks", "reject", {"reason": "pack_integrity"})
        return finish("rejected")
    require(advice.operational_authority == "none" and not advice.may_authorize_effects)
    stage("playbooks", advice.overall_advisory_disposition, advice.model_dump(mode="json"))
    if advice.overall_advisory_disposition != "observe":
        return finish("inconclusive")
    # Caller-owned stop rules can withhold work; only the Gateway permits its
    # built-in constant/digest computation. Advice never becomes an allow decision.
    bridge = bridge_quarantine_admission_v1(verdict, registry)
    require(bridge is not None)
    audit = MemoryAudit()
    engine = GatewayEngine(audit=audit)  # declared test double; no key or filesystem
    decision, result = engine.call_tool(bridge.gateway_call, request_id="chain:" + case["id"])
    row["synthetic_executions"] = engine.execution_count
    require(len(audit.rows) == 1)
    stage(
        "gateway",
        decision.disposition,
        {"decision": decision.model_dump(mode="json"), "result_sha256": digest(canonical(result))},
    )
    return finish("completed" if decision.execution_permitted else "denied")


def run(cases_bytes: bytes) -> dict[str, Any]:
    versions = {name: metadata.version(name) for name in VERSIONS}
    require(versions == VERSIONS)
    cases = json.loads(cases_bytes)["cases"]
    require(len(cases) == 16)
    rows = [run_case(case) for case in cases]
    return {
        "schema": "ecosystem-functional-chain-v1",
        "fixture_sha256": digest(cases_bytes),
        "runner_sha256": digest(Path(__file__).read_bytes()),
        "versions": versions,
        "cases": rows,
        "operational_authority": "none",
        "real_model_calls": 0,
        "real_provider_calls": 0,
        "real_effects": 0,
        "non_claims": [
            "classifier accuracy",
            "real provider compatibility",
            "authenticated custody",
            "OS sandbox",
            "independent human review",
            "production safety",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("output already exists")
    sys.dont_write_bytecode = True
    guard = EffectGuard(args.out)
    sys.addaudithook(guard)
    try:
        result = run(Path(__file__).with_name("chain-cases.json").read_bytes())
        result["effect_guard"] = guard.counts
        require(all(count == 0 for count in guard.counts.values()))
        result["result_sha256"] = digest(canonical(result))
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except Exception as exc:
        print(
            json.dumps(
                {"ok": False, "error_type": type(exc).__name__, "effect_guard": guard.counts}
            )
        )
        return 1
    print("Functional chain produced; run verify_chain.py for the independent verdict.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
