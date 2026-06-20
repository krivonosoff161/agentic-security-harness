# Public evidence showcase

This showcase is the reviewer-facing entry point for benchmark evidence. It avoids code
details and points to the artifacts, scenarios, and follow-up work needed to understand
what the project currently proves.

## Read first

| Page | Purpose |
|---|---|
| [Scenario matrix](scenario-matrix.md) | What scenario families exist and what topology each one tests. |
| [Weak spots and findings](weak-spots-and-findings.md) | Separates findings from inconclusive/error/runtime weak spots. |
| [Deepening backlog](deepening-backlog.md) | Bounded follow-up variations selected from evidence, not a full cross-product. |
| [Metrics contract](../metric-contract.md) | How to read traffic, benchmark, runtime, and process metrics. |
| [Scenario investigation workflow](../scenario-investigation-workflow.md) | How scenarios become evidence and then deeper checks. |
| [Generated failure cards](generated/failure-cards.md) | Artifact-driven failure/replay cards generated from a committed run (`ash showcase --root examples/demo-agent-report --out docs/showcase/generated`); every card links a trace reference. |

## Current public evidence

| Evidence | Status | Start here | What it proves | What it does not prove |
|---|---|---|---|---|
| Deterministic baseline/protected comparison | Validated example | [`examples/comparison-report/README.md`](../../examples/comparison-report/README.md) | The shipped synthetic corpus can produce a visible 24 -> 0 modeled-risk reduction between demo targets. | A real deployed agent is secure. |
| Deterministic multi-agent handoff toy comparison | Local validated artifact | [`handoff-toy-topology.md`](../handoff-toy-topology.md) | The shipped local `toy-multi-agent` slice produces 2 modeled handoff findings, while `protected-toy-multi-agent` blocks the malformed handoffs under the same corpus. | Evidence about a live multi-agent framework, provider, or production handoff protocol. |
| External fake-server run | Validated example | [`examples/external-demo-report/README.md`](../../examples/external-demo-report/README.md) | The experimental external artifact path can validate against a deterministic local fake OpenAI-compatible endpoint. | A real model/provider is safe. |
| Local Prometheus/Ollama smoke | Local scratch only | [`local-prometheus-workflow.md`](../local-prometheus-workflow.md) | A weak local model can be exercised through the prompt-only external path; first smoke exposed evidence-quality/runtime limits. | Public benchmark finding; model leaderboard result. |

## Current local Prometheus observation

A maintainer local smoke run on a low-memory Ollama profile (`qwen2.5:1.5b`, one
`data-boundary` variant, one repeat) produced:

```text
checks: 4
findings: 0
inconclusive: 2
adapter_error: 2
validation: OK
```

Interpretation: this is a weak-spot result, not a pass. The useful evidence is that the
weak local model/runtime struggled with strict JSON verdict reliability and timeouts.
The local report remains under `reports/` and is not committed as public evidence until
the showcase generator and curation rules are implemented.

## Reproduce the safe deterministic showcase

```bash
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
ash report --root reports/comparison
```

Generate reviewer-facing Markdown from recorded artifacts:

```bash
ash showcase --root reports --out docs/showcase/generated
```

The generated files are a reviewer aid. JSON artifacts remain the source of truth.

## Reproduce the local handoff toy comparison

```bash
ash compare --baseline toy-multi-agent --protected protected-toy-multi-agent --out reports/handoff-toy-comparison
ash validate reports/handoff-toy-comparison
```

Expected current result: `toy-multi-agent` records 2 deterministic modeled findings
(`data_boundary_handoff_label_stripping` and `capability.delegation_chain_drift`);
`protected-toy-multi-agent` records 0 findings by blocking consumption of the malformed
handoffs. This remains a local synthetic topology, not a live multi-agent runtime claim.

## Reproduce the low-memory local smoke

```powershell
python -m agentic_security_harness.cli run-external `
  --preset ollama `
  --model qwen2.5:1.5b `
  --scenario data-boundary `
  --max-variants 1 `
  --repeats 1 `
  --max-requests 10 `
  --timeout 60 `
  --raw-response-limit 0 `
  --out reports/local-prometheus-lowmem-smoke-qwen2.5-1.5b

python -m agentic_security_harness.cli validate reports/local-prometheus-lowmem-smoke-qwen2.5-1.5b
```

## Claim boundary

Allowed:

> The project has a trace-first deterministic showcase and a documented path for local
> real-model probes. Local weak-model runs are interpreted through explicit
> finding/inconclusive/error states.

Not allowed:

- "The local model passed."
- "The project has a model leaderboard."
- "GitHub traffic proves benchmark credibility."
- "A local weak model result generalizes to all LLMs."
