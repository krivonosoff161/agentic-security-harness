# Agent Host Adapter SDK

Status: implemented development slice; offline record/replay only; not part of the
published `v1.0.0` package.

The Agent Host Adapter V1 contract is the first provider-neutral integration surface for
recording what an owned or explicitly authorized agent host did. It reuses the stable
authority-free portfolio observation envelope and deliberately stops before live host
execution, provider transport, policy enforcement, or security scoring.

## What this slice does

- defines a closed `agent-host-recording-v1.0` model and JSON Schema;
- binds one stable corpus pattern and its exact corpus-manifest digest;
- records an ordered, self-contained event graph;
- requires one exact commitment for every canonical observation event;
- rejects unknown fields, duplicate JSON fields, non-canonical bytes, identity drift,
  forward/missing parents, telemetry drift, links, reparse points, and hardlinks;
- exposes an offline `StaticAgentHostAdapterV1` reference collector;
- provides `ash agent-host-inspect` for safe validation and replay summary;
- emits only `observation_only_no_security_verdict` with operational authority `none`.

The SDK does **not** load plugins dynamically, start a host process, open a network
connection, read provider credentials, execute a tool, or turn the producer's statement
into PASS/FAIL.

## Contract files

| Role | File |
|---|---|
| Python contract and validator | `src/agentic_security_harness/agent_host_adapter.py` |
| Closed JSON Schema | `schemas/agent-host-recording.v1.schema.json` |
| Content-bound manifest | `schemas/agent-host-recording.v1.manifest.json` |
| Synthetic accept/reject fixtures | `tests/fixtures/agent-host-recording-v1/` |
| Generator/checker | `tools/agent_host_contract.py` |

The manifest binds the schema, validator, CLI, fixture runner, fixture bytes, byte/event
limits, commitment domain, non-verdict semantics, and forbidden capabilities.

## Producer integration

A future authorized collector implements this structural protocol:

```python
class AgentHostAdapterV1(Protocol):
    descriptor: AgentHostDescriptorV1

    def collect(self, pattern: DefensivePattern) -> AgentHostRecordingV1: ...
```

Collectors must convert host activity into `CanonicalObservationEventV1` objects. Raw
prompts, tool arguments, tool output, credentials, endpoints, customer data, and local
paths do not belong in this public contract. Use digest-shaped `SafeEvidencePointer`
references for retained private evidence.

Build a record with derived event commitments, aggregate telemetry, corpus binding, and
recording identity:

```python
from agentic_security_harness import (
    AgentHostDescriptorV1,
    build_agent_host_recording_v1,
    encode_agent_host_recording_v1,
)

host = AgentHostDescriptorV1(
    schema_version="agent-host-descriptor-v1.0",
    adapter_id="example.record-replay",
    adapter_version="1.0.0",
    host_type="owned.local.agent",
    runtime_id="python",
    runtime_version="3.11",
    capture_mode="recorded_offline",
    network_mode="off",
    raw_payload_policy="digests_only",
    producer_attestation="unattested",
    operational_authority="none",
)

recording = build_agent_host_recording_v1(
    pattern_id=pattern.pattern_id,
    host=host,
    events=tuple(canonical_events),
    terminal_status="completed",
)
payload = encode_agent_host_recording_v1(recording)
```

`completed` means only that the record has complete telemetry. It does not mean the agent
was safe or that the pattern passed.

## Offline inspection

```bash
ash agent-host-inspect recording.json
ash agent-host-inspect recording.json --format json
```

The command prints pattern id, event count, declared capture/network mode, telemetry,
tool-activity presence, and the exact recording commitment. Failure output intentionally
does not echo the untrusted path, bytes, or parser details.

Validate the committed schema/fixtures during development:

```bash
PYTHONPATH=src python tools/agent_host_contract.py --root . --check
python -m pytest tests/test_agent_host_adapter.py
```

On PowerShell, use `$env:PYTHONPATH = "src"` for the generator command.

## Trust boundary

| Claim | Status |
|---|---|
| Canonical bytes and event commitments verify | Deterministically checked |
| Events form one ordered, self-contained graph | Deterministically checked |
| Corpus pattern and manifest identity match | Deterministically checked |
| Producer identity/provider/runtime is authentic | Not claimed |
| Recorded action really happened | Not claimed by this contract |
| Tool execution was safe | Not evaluated |
| Agent passes the benchmark pattern | No verdict produced |
| Runtime enforcement authority | None |

The next separately reviewed slice is a deterministic evaluator that maps a declared
subset of event activities to benchmark observations. Native OpenAI, Anthropic, Google,
MCP, and live agent-host collectors come after that evaluator and retain explicit
network/credential/authorization gates.
