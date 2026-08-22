# Agent Host Adapter SDK

Status: shipped in `v1.1.0`; offline record/evaluate plus a built-in synthetic
owned-workflow quickstart.

The Agent Host Adapter V1 contract is the first provider-neutral integration surface for
recording what an owned or explicitly authorized agent host declared it did. It reuses the
stable authority-free portfolio observation envelope. A separate deterministic evaluator
now classifies closed terminal events. An explicit Python collector API and a no-network
reference workflow exercise the whole record/evaluate/publish path, while the development
slice still stops before provider transport, arbitrary host execution, policy enforcement,
or security certification. Packaging this contour does not expand its authority.

## What this slice does

- defines a closed `agent-host-recording-v1.0` model and JSON Schema;
- binds one stable corpus pattern and its exact corpus-manifest digest;
- records an ordered, self-contained event graph;
- requires one exact commitment for every canonical observation event;
- rejects unknown fields, duplicate JSON fields, non-canonical bytes, identity drift,
  forward/missing parents, telemetry drift, links, reparse points, and hardlinks;
- exposes an offline `StaticAgentHostAdapterV1` reference collector;
- provides `ash agent-host-inspect` for safe validation and replay summary;
- keeps the recording itself at `observation_only_no_security_verdict`;
- provides a separate content-bound evaluator and `ash agent-host-evaluate` over all 24
  frozen corpus patterns, always with operational authority `none`;
- provides `AgentHostSessionV1` as an append-only digest-only instrumentation API;
- provides `ash agent-host-quickstart` as a working 48-case protected/vulnerable workflow,
  atomically published only after full bundle validation.

The SDK does **not** load plugins dynamically, start a host process, open a network
connection, read provider credentials, execute a tool, or trust a producer-supplied
PASS/FAIL statement. Evaluator outcomes are rule-derived classifications of an unattested
recording, not proof that the recorded action occurred.

## Contract files

| Role | File |
|---|---|
| Python contract and validator | `src/agentic_security_harness/agent_host_adapter.py` |
| Closed JSON Schema | `schemas/agent-host-recording.v1.schema.json` |
| Content-bound manifest | `schemas/agent-host-recording.v1.manifest.json` |
| Synthetic accept/reject fixtures | `tests/fixtures/agent-host-recording-v1/` |
| Generator/checker | `tools/agent_host_contract.py` |
| Deterministic evaluator | `src/agentic_security_harness/agent_host_evaluator.py` |
| Evaluator schemas and ruleset | `schemas/agent-host-evaluation*.json` |
| Evaluator fixtures | `tests/fixtures/agent-host-evaluation-v1/` |
| Evaluator generator/checker | `tools/agent_host_evaluation_contract.py` |
| Owned-workflow collector and bundle | `src/agentic_security_harness/agent_host_workflow.py` |
| Run-summary schema and manifest | `schemas/agent-host-run-summary.v1.*` |
| Owned-workflow fixtures | `tests/fixtures/agent-host-run-summary-v1/` |
| Owned-workflow generator/checker | `tools/agent_host_workflow_contract.py` |

The manifest binds the schema, validator, CLI, fixture runner, fixture bytes, byte/event
limits, commitment domain, non-verdict semantics, and forbidden capabilities.

## Working no-network quickstart

```bash
ash agent-host-quickstart --out reports/agent-host-quickstart
ash validate reports/agent-host-quickstart
```

This executes only the built-in pure synthetic workflow. It runs all 24 frozen patterns in
protected and vulnerable modes, producing 48 canonical recordings, 48 independently
rebuildable evaluations, a content-bound summary, and `run_index.json`. The expected
reference result is 24 `pass`, 24 `finding`, zero `inconclusive`, and zero `adapter_error`.
Those counts verify the fixture and evaluator path; they are not measurements of a real
agent or a security certification.

The public bundle contains pattern identifiers, event metadata, timestamps, and SHA-256
commitments. It does not contain raw prompts, tool arguments/results, credentials,
endpoints, customer data, exception text, or local filesystem paths. The command has no
network or dynamic-plugin surface and refuses to merge with an existing output directory.

## Producer integration

An existing host integration may either emit the recording protocol directly or call the
instrumented workflow API explicitly. The Harness never imports a caller-supplied module
or executes a command string:

```python
from datetime import UTC, datetime

from agentic_security_harness import run_owned_agent_workflow_v1

result = run_owned_agent_workflow_v1(
    pattern=pattern,
    workflow=my_owned_workflow,
    repository_sha=exact_source_sha,
    occurred_at=datetime.now(UTC),
)
```

`my_owned_workflow.run(pattern, session)` records only canonical activities and precomputed
digest references through `session.observe(...)`, then chooses one terminal method:
`boundary_preserved()`, `boundary_violated()`, `inconclusive()`, or `adapter_error()`.
The application remains responsible for executing its own authorized work. The Harness
session does not accept raw payload fields. Exceptions before terminalization become a
sanitized `adapter_error`; an exception after a terminal event fails closed rather than
returning a misleading pass.

The lower-level retained-recording adapter remains available:

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

## Deterministic evaluation

```bash
ash agent-host-evaluate recording.json
ash agent-host-evaluate recording.json --format json
```

The evaluator accepts only these terminal activities:

| Terminal activity | Outcome |
|---|---|
| `benchmark.boundary_preserved` | `pass` |
| `benchmark.boundary_violated` | `finding` |
| `benchmark.inconclusive` | `inconclusive` |
| `benchmark.adapter_error` | `adapter_error` |

One terminal event must be unique, final, and causally cover the entire ordered event
graph. Missing, multiple, disconnected, non-final, or incomplete evidence fails closed to
`inconclusive`; adapter failure stays visible. The ruleset binds exact corpus-1.0.0
metadata for all 24 patterns. It never interprets arbitrary log text, prompts, tool
arguments, or model output.

Validate its committed artifacts with:

```bash
PYTHONPATH=src python tools/agent_host_evaluation_contract.py --root . --check
python -m pytest tests/test_agent_host_evaluator.py
```

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
| Closed evaluator outcome for a canonical recording | Deterministically rule-derived |
| Outcome authenticates the producer or real-world action | Not claimed |
| Outcome certifies external-system security | Not claimed |
| Runtime enforcement authority | None |

The next separately reviewed slice is a native provider/agent-host collector over this
explicit API. OpenAI, Anthropic, Google, MCP, and other live collectors remain future work
with separate network, credential, privacy, retention, and authorization gates.
