# Evaluation topologies

Agentic Security Harness evaluates **agentic systems under a target adapter**, not just
standalone model answers. A target adapter may wrap a single deterministic mock, a local
agent, a model chain, a tool loop, a memory loop, a multi-agent handoff, or a future
authorized runtime.

The benchmark unit is:

```text
boundary invariant -> evaluation topology -> defensive pattern -> target adapter
-> trace -> scorecard -> validation
```

The topology describes where the boundary can fail. It is not a license to enumerate every
combination of providers, prompts, agents, tools, memory modes, and time windows. Corpus
growth remains invariant-based and bounded; see [corpus-expansion-plan.md](corpus-expansion-plan.md).

## Current and planned topologies

| Topology | What is tested | Boundary failures to look for | Status | Evidence artifacts |
|---|---|---|---|---|
| Single model prompt-only | A model judges a synthetic scenario from a prompt. | Incoherent self-report, missing pattern id, invalid boundary assertion. | Experimental via `run-external`. | `run_config.json`, `external_results.json`, raw responses, cross-check status. |
| Local deterministic target | A mock or synthetic local target is driven by one pattern at a time. | Declared boundary fails under deterministic conditions. | Shipped. | `traces.json`, `scorecard.json`, `summary.md`, validation result. |
| Vulnerable vs protected agent | The same corpus is replayed against vulnerable and protected local agents. | Protection does not reduce the modeled finding. | Shipped via `ash compare`. | Baseline/protected traces and comparison report. |
| Agent plus memory | Target records, recalls, expires, or scopes memory entries. | Provenance loss, TTL loss, trust-level overwrite, cross-user leakage. | Shipped locally for memory-governance patterns; richer adapters planned. | Trace steps showing write/read scope, trust level, TTL, and finding. |
| Agent plus tools | Target selects or calls a mock tool. | Tool chosen from untrusted bias, permission misuse, schema drift. | Shipped locally with `toy-tools` and tool patterns; live tool execution future. | Trace steps for selection, schema/provenance checks, permission decision. |
| Model chain / router | One model or filter gates context before another model acts. | Weak model suppresses risk, trust escalates from cheap to chief, context is stripped. | Planned. | Trace records each model role, context passed, labels preserved/dropped, final action. |
| Router / filter / validator | A deterministic or model-assisted gate routes, blocks, or escalates. | Gate returns final failure without recovery path; validator trusts weak evidence. | Partial via external cross-checks; richer runtime planned. | Gate decision, reason, retry/recovery path, raw evidence. |
| Multi-agent handoff | Agent A sends data, authority, or memory to Agent B. | Envelope loss, source-label loss, capability drift, receiver over-trust. | Partial: label stripping and delegation drift are shipped; toy multi-agent adapter planned. | Trace shows before/after envelope, issuer/subject, recipient, and receiver decision. |
| Cross-provider / cross-ecosystem handoff | Work moves across providers or runtimes, such as local -> external or Claude/Qwen/DeepSeek/OpenAI-compatible chains. | Source labels, policy envelope, or provider constraints are lost at the boundary. | Planned. | Provider/runtime labels, redacted endpoint metadata, envelope before/after route. |
| Human approval loop | Agent asks a human to approve a privileged or risky action. | Approval request lacks provenance, data class, recipient, purpose, or risk context. | Shipped for underjustified approval; broader pressure/escalation planned. | Approval request fields, presented context, approved action, audit entry. |
| Provider boundary | Target decides whether data may leave local/runtime boundary for a provider. | `can_forward=false` ignored, redaction skipped, fallback loses envelope. | Shipped for a local provider-boundary pattern; richer fallback chains planned. | Trace steps for egress gate, provider label, redaction/block decision. |
| Recovery path / escalation | System handles inconclusive, adapter error, failed trust gate, or mismatch. | User sees a dead end, silent failure, no retry, or no alternate route. | Planned as a first-class pattern family. | Error class, user-facing next step, retry command, alternate route, saved artifacts. |

## Reading topology status

- **Shipped** means the repo has deterministic local code and validated artifacts for that
  topology or a representative slice.
- **Partial** means the boundary is represented by current patterns, but the full topology
  adapter is not yet shipped.
- **Experimental** means the path exists but evidence is weaker than local traces.
- **Planned** means the topology is documented for future work and must not be described
  as current behavior.

## Adapter metadata expectations

Future adapters should record the topology they implement, the observation layer they
control, network mode, memory mode, tool mode, permission model, model/provider family,
and whether protection is built into the target or wrapped around it. The formal adapter
contract is [adapter-contract.md](adapter-contract.md); the current mode matrix is
[capability-matrix.md](capability-matrix.md).
