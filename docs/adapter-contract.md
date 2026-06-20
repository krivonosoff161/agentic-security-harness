# Target adapter contract

> **Agentic Security Harness.** This page defines how the benchmark can run against
> different agent runtimes without becoming tied to one model, provider, framework, or
> operating system. Current shipped adapters are local and synthetic; real adapters are
> future, opt-in, and must be explicitly authorized.

If you want to implement a small local target first, start with
[custom-adapter-tutorial.md](custom-adapter-tutorial.md), then come back here for the
formal contract and review gates.

## Why this matters

The benchmark is not "a test for one demo agent." The stable unit is:

```text
defensive pattern -> target adapter -> portable trace -> scorecard -> validation
```

Any target can participate if an adapter can drive it with a sanitized pattern and return
the observed behavior in the common trace model.

## Current shipped contract

The current Python protocol is intentionally small:

```python
class Target(Protocol):
    name: str

    def descriptor_fields(self) -> tuple[str, str, str]: ...
    def observe(self, pattern: DefensivePattern) -> Observation: ...
```

`observe()` returns:

- ordered `TraceStep` records;
- an `observed_behavior` summary;
- zero or more `Finding` objects.

The runner wraps that into an `ExploitTrace` with the target descriptor, graph path,
expected vulnerable behavior, data envelope, and reproducibility metadata.

The repository also ships typed metadata models and lifecycle hooks:

- `TargetMetadata` - adapter/runtime/model/network/memory reproducibility metadata;
- `HealthStatus` - readiness checks before a run;
- `CapabilityCheckResult` - per-pattern adapter compatibility and safety-gate result.
- `TargetAdapterBase` - optional base class with default `health()`, `metadata(run_id)`,
  and `capability_check(pattern)` hooks.

The runner now calls these hooks when an adapter exposes them. Existing local demo targets
remain compatible through default structural behavior. Future non-synthetic or stochastic
adapters must use the lifecycle hooks before their results are treated as comparable to
the deterministic examples.

## Required adapter behavior

A target adapter must:

1. Accept one `DefensivePattern` at a time.
2. Preserve the pattern id exactly.
3. Return deterministic trace steps when operating in local/synthetic mode.
4. Record enough context for a reviewer to understand where a boundary failed.
5. Never hide a finding by weakening the pattern.
6. Distinguish target failure from adapter failure.
7. Keep secrets, raw credentials, and private runtime details out of committed artifacts.

## Adapter classes

| Adapter class | Status | What it means |
|---|---|---|
| `mock` | current | Deterministic minimal target used for fast benchmark checks. |
| `demo-agent` | current | Local vulnerable-by-design synthetic agent. |
| `protected-demo-agent` | current | Local controlled synthetic agent; demonstrates risk reduction. |
| `toy-local-function` | current | Toy adapter wrapping a plain Python function; passes every pattern. |
| `toy-rag` | current | Toy retrieval agent exercising the data/memory/injection surface (no network). |
| `toy-tools` | current | Toy tool-using agent exercising the tool/authority surface (no network). |
| `toy-multi-agent` | current | Toy coordinator/worker handoff exercising data-label handoff and capability delegation surfaces (no network). |
| `openai-compatible` (external) | experimental | Evaluates an authorized OpenAI-compatible endpoint with synthetic prompts. Opt-in network; no tool execution. |
| Native provider adapter | future | Provider SDK adapter (Anthropic/OpenAI Responses/Google/etc.); never a default path. |
| Agent-host / tool-use adapter | future | Drives a live agent that actually calls tools; explicitly authorized only. |

## Runtime metadata to record

Real or semi-real adapters need more reproducibility metadata than the current synthetic
targets. `TargetMetadata` captures the stable fields:

- adapter name and version;
- target runtime name and version;
- model/provider family, if a model is used;
- model settings relevant to reproducibility (`temperature`, tool mode, system policy
  identifier, routing tier);
- tool registry snapshot or schema hash, if tools are involved;
- memory mode (`off`, `session`, `persistent`, `external`);
- permission model (`none`, `prompt-only`, `capability-token`, `RBAC`, custom);
- network mode (`off`, `local-only`, `authorized-external`);
- whether the run is deterministic or stochastic;
- anonymized run id for cross-report correlation.

Do not put provider keys, account ids, raw prompts containing secrets, private URLs, or
private customer data into the public artifact.

Adapters should also state whether protection is built into the target, wrapped by an
external control, absent by design, or unknown. This avoids confusing a model-only check
with an agentic-system boundary measurement.

## Adapter safety gates

Before a non-synthetic adapter can be merged, it needs:

- a written authorization model;
- a default offline mode or local fixture mode;
- explicit network/provider gating;
- tests that prove no real API call happens by default;
- redaction/sanitization of target metadata;
- `ash validate` compatibility;
- documentation that names residual risk and limitations.

## PASS and FAIL semantics

The harness does not ask whether a model is "smart." It asks whether a boundary survived.

- **FAIL** (a **FINDING**) means the target showed the expected vulnerable behavior.
- **PASS** means the target did not show that vulnerable behavior under the test.
- **Adapter error** means the adapter failed to run or observe the target; it is not a PASS.
- **Inconclusive** means no usable verdict was produced (e.g. an external model returned
  non-JSON). For external runs this is shipped today, alongside per-`(pattern, variant)`
  stochastic statuses (`stable_pass`, `stable_finding`, `flaky`, `inconclusive`,
  `adapter_error`). See [benchmark-semantics.md](benchmark-semantics.md).

Local scorecards are deterministic because local targets are deterministic. The external
path records repeats and stochastic status; native model adapters would additionally need
run count, stochastic settings, and confidence limits before their results are compared
with local examples.

## Compatibility target

A future adapter should be able to run the same corpus against:

- a local toy agent;
- a local LLM;
- a hosted LLM;
- a RAG agent;
- an MCP/tool-using agent;
- a multi-agent workflow;
- a custom internal company workflow.

The adapter may translate the pattern into that runtime's inputs, but it must return the
same portable trace structure. The trace is the stable benchmark artifact.

## What remains future work

- A plugin/entry-point system for third-party adapters.
- Native provider SDK adapters and agent-host / tool-use adapters.
- A policy for publishing sanitized adapter examples without leaking private runtime data.

Shipped since this contract was first written: the toy RAG, tool, and multi-agent handoff
adapters; the experimental OpenAI-compatible external path; adapter metadata in
`run_index.json`; and a stochastic-run report format for external runs.
