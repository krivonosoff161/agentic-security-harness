# Bring your own target

> **Agentic Security Harness.** This guide explains how a future authorized target adapter
> can run the same benchmark corpus. The current release ships only local synthetic targets.
> Real adapters are future work and require explicit authorization.

## What the benchmark checks

The benchmark measures whether **agentic operating-environment boundaries survive** across
22 deterministic synthetic patterns. It checks:

- data envelope propagation (labels, recipients, forwarding rules)
- memory governance (provenance, trust levels, TTL, scope isolation)
- tool selection integrity and schema provenance
- capability delegation and ambient authority
- approval context completeness
- audit trail integrity and completeness
- budget and recursion depth enforcement
- perception-channel trust boundaries

The benchmark does **not** ask whether a model is "smart." It asks whether a boundary
survived.

## The adapter contract

Any target can participate if an adapter can drive it with a sanitized pattern and return
observed behavior in the common trace model.

```python
class Target(Protocol):
    name: str

    def descriptor_fields(self) -> tuple[str, str, str]: ...
    def observe(self, pattern: DefensivePattern) -> Observation: ...
```

`observe()` receives one `DefensivePattern` and must return:

- ordered `TraceStep` records (the steps the agent took);
- an `observed_behavior` summary;
- zero or more `Finding` objects (if a boundary failed).

The runner wraps that into an `ExploitTrace` with the target descriptor, graph path,
expected vulnerable behavior, data envelope, and reproducibility metadata.

## What an adapter must provide

| Requirement | Why |
|---|---|
| Accept one `DefensivePattern` at a time | The runner drives one pattern per trace. |
| Preserve the pattern id exactly | Traces must be machine-matchable to the corpus. |
| Return deterministic trace steps (local/synthetic mode) | Reproducibility and committed-example validation. |
| Record enough context for reviewer understanding | A finding must be explainable from the trace. |
| Never hide a finding by weakening the pattern | Integrity of the benchmark measurement. |
| Distinguish target failure from adapter failure | Adapter errors are not PASS/FAIL outcomes. |
| Keep secrets and private runtime details out of committed artifacts | Safety and public-release readiness. |

## What metadata to declare

For non-synthetic or stochastic adapters, the `TargetMetadata` model captures
reproducibility fields:

- **adapter name and version** - e.g. `my-company-rag-adapter v0.1.0`
- **target runtime name and version** - e.g. `langgraph 0.2.0`
- **model family / model name** - e.g. `openai gpt-4o` or `llama-3.1-8b`
- **model settings** - temperature, tool mode, system policy identifier
- **tool registry hash** - snapshot of tool definitions at run start
- **memory mode** - `off`, `session`, `persistent`, `external`
- **permission model** - `none`, `prompt-only`, `capability-token`, `rbac`
- **network mode** - `off`, `local-only`, `authorized-external`
- **deterministic flag** - `True` for synthetic, `False` for stochastic
- **run count** - how many runs for stochastic targets
- **confidence level** - statistical confidence for stochastic results
- **anonymized run id** - for cross-report correlation

Do not put provider keys, account ids, raw prompts with secrets, private URLs, or
private customer data into public artifacts.

## Safety gates for non-synthetic adapters

Before a non-synthetic adapter can be merged or used publicly, it must pass:

1. **Written authorization model** - who approved this adapter and why.
2. **Default offline mode** - the adapter must have a mode that makes no network calls.
3. **Explicit network/provider gating** - network mode must be declared.
4. **Tests proving no real API call by default** - the default path is local/synthetic.
5. **Redaction/sanitization** - target metadata must be safe for public artifacts.
6. **`ash validate` compatibility** - the adapter's output must conform to the trace model.
7. **Documentation of residual risk and limitations** - what the adapter does not cover.

## How to run

### Current built-in targets

```bash
# List registered targets and scenario families
ash targets
ash scenarios --verbose

# Fastest: deterministic mock target
ash run --target mock --out reports/demo

# Synthetic agent: closer to real agent mechanics
ash run --target demo-agent --out reports/demo-agent

# Protected variant: demonstrates risk reduction
ash run --target protected-demo-agent --out reports/protected-demo-agent

# Compare baseline vs protected
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison

# Run a scenario matrix (multiple variants, aggregated results)
ash run-matrix --target demo-agent --scenario data-boundary --out reports/matrix-demo

# Limit variants or run a specific one
ash run-matrix --target mock --scenario all --max-variants 2 --out reports/matrix-small
ash run-matrix --target mock --scenario all --variant baseline-all --out reports/matrix-one
```

### External model evaluation (experimental)

The `ash run-external` command evaluates an authorized OpenAI-compatible endpoint
with safe synthetic prompts. This is useful for testing a local vLLM server, a
local gateway, or an authorized test endpoint.

```bash
# Dry run first (no network calls)
ash run-external --adapter openai-compatible \
  --base-url http://localhost:8000/v1 \
  --model deepseek-chat \
  --scenario data-boundary \
  --dry-run

# Actual run (makes network calls)
export ASH_EXTERNAL_API_KEY=your_key_here
ash run-external --adapter openai-compatible \
  --base-url http://localhost:8000/v1 \
  --model deepseek-chat \
  --scenario data-boundary \
  --repeats 3 \
  --api-key-env ASH_EXTERNAL_API_KEY \
  --out reports/external-demo
```

**Important:** External runs evaluate model decision boundaries with synthetic
prompts. No tools are executed. This is not a benchmark-grade comparison yet.
See the [adapter contract](adapter-contract.md) for details.

### Future custom target path

The current release does **not** support loading arbitrary external adapters via CLI.
The adapter contract is documented as the implementation contract and next integration
point. To run a custom target today:

1. Implement the `Target` protocol in your adapter module.
2. Import and use `HarnessRunner` directly in Python:

```python
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.scorecard import build_scorecard
from agentic_security_harness.reporting import write_reports

# Your adapter implements the Target protocol
runner = HarnessRunner(your_adapter)
traces = runner.run_many(seed_patterns())
scorecard = build_scorecard(traces)
write_reports(traces, scorecard, Path("reports/your-target"))
```

3. Run `ash validate reports/your-target` to check artifact conformance.

## What artifacts you get

Each `ash run` produces:

| Artifact | Purpose |
|---|---|
| `traces.json` | Portable machine-readable failure traces (one per pattern). |
| `scorecard.json` | Deterministic aggregate: findings by severity, failed/passed patterns. |
| `summary.md` | Human-readable pattern table with results. |
| `executive.md` | Executive view: scope, headline result, top control families, residual risk. |
| `remediation.json` | Structured control recommendations (when findings exist). |
| `remediation.md` | Human-readable remediation report (when findings exist). |

`ash run-matrix` additionally produces:

| Artifact | Purpose |
|---|---|
| `matrix.json` | Variant metadata: target, scenario, selected patterns, variant knobs. |
| `matrix.md` | Scenario-specific summary with variant details and pattern results. |

In the current release, matrix variants are deterministic replay metadata. They group
scenario conditions and aggregate results; they do not mutate the underlying pattern
content yet.

`ash compare` produces:

| Artifact | Purpose |
|---|---|
| `baseline/` | All report artifacts for the vulnerable target. |
| `protected/` | All report artifacts for the protected target. |
| `comparison.md` | Side-by-side risk-reduction summary with control priorities. |

## How to read the results

1. **Start with `executive.md`** - it tells you the target, total patterns, failed/passed
   count, and which control families need attention.
2. **Check `summary.md`** - see which patterns failed and at which break point.
3. **Read `remediation.md`** - for each finding, it recommends quick fix, engineering fix,
   architecture fix, verification step, and residual risk.
4. **Compare with `comparison.md`** - if you have a protected target, see the risk reduction.

## How to use remediation recommendations

The remediation report maps each finding to a **control family** and provides:

- **Quick fix** - immediate action (e.g. "tag content with provenance label").
- **Engineering fix** - implementation-level change (e.g. "propagate DataEnvelope
  across all handoffs").
- **Architecture fix** - stronger design (e.g. "adopt IFC model with label separation").
- **Verification step** - how to confirm the fix works (e.g. "re-run pattern X and
  compare traces").
- **Residual risk** - what remains after the fix.

The goal is not "complete protection" - it is **measurable risk reduction** that you
can verify by re-running the benchmark.

## How to verify your fix

1. Implement the recommended control in your target.
2. Re-run the benchmark: `ash run --target your-target --out reports/after-fix`
3. Compare with the baseline: `ash compare --baseline before --protected after-fix --out reports/comparison`
4. Check that the previously failing patterns now produce PASS traces.
5. Verify with `ash validate reports/comparison`.

## Pass and FAIL semantics

- **FAIL** - the target showed the expected vulnerable behavior for that pattern.
- **PASS** - the target did not show that vulnerable behavior under the test.
- **Adapter error** - the adapter failed to run; this is not a PASS.
- **Inconclusive** (future) - for stochastic targets where a deterministic verdict
  would be misleading.

The harness measures **boundary survival**, not model intelligence.

## What the benchmark is NOT

- Not a prompt-injection scanner (garak, PyRIT, promptfoo do that).
- Not a defense implementation (CaMeL, FIDES do that).
- Not a production monitoring tool (ADR/Uber does that).
- Not tied to OpenAI, Anthropic, Alibaba, or any one provider.
- Not a complete security assessment - it measures specific boundary failure classes.
- Not a guarantee of real-world protection - it is deterministic and synthetic.
