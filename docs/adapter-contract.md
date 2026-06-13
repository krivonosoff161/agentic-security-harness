# Target adapter contract

> **Agentic Security Harness.** This page defines how the benchmark can run against
> different agent runtimes without becoming tied to one model, provider, framework, or
> operating system. Current shipped adapters are local and synthetic; real adapters are
> future, opt-in, and must be explicitly authorized.

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
| Toy RAG adapter | planned | Local fixture-based RAG app with no network and no provider calls. |
| Toy MCP adapter | planned | Local mock MCP-like server/client pair; no live third-party server. |
| Toy multi-agent adapter | planned | Local handoff runtime for cross-agent and capability-boundary tests. |
| Real authorized adapter | future | Explicitly authorized company/runtime adapter; never a default path. |

## Runtime metadata to record

Real or semi-real adapters need more reproducibility metadata than the current synthetic
targets. The trace should include or reference:

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

- **FAIL** means the target showed the expected vulnerable behavior for that pattern.
- **PASS** means the target did not show that vulnerable behavior under the test.
- **Adapter error** means the adapter failed to run or observe the target; it is not a PASS.
- **Inconclusive** is a future report status for stochastic or external targets where a
  deterministic verdict would be misleading.

The current scorecard is deterministic because current targets are deterministic. Real
model adapters must record run count, stochastic settings, and confidence limits before
their results are compared with local examples.

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
- A stochastic-run report format.
- A local toy RAG adapter.
- A local toy MCP adapter.
- A local multi-agent adapter.
- A policy for publishing sanitized adapter examples without leaking private runtime data.
