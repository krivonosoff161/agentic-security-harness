# Local Swarm Real-Model Evaluation

Status: local-empirical evidence for issue #66. Last refreshed: 2026-06-23.

This page records a bounded local Ollama evaluation of the `local-swarm` runner. It is
evidence about runtime execution and artifact quality, not a model-safety result.

## Claim Boundary

Allowed:

- The 15-scenario `local-swarm` suite was executed against two local Ollama models.
- Deterministic ASH contracts made all pass/block decisions.
- Model role text was recorded as hashes and short previews for evidence-quality review.
- Both local runs produced complete artifacts with no adapter errors.

Not allowed:

- The models passed a safety benchmark.
- The models are safe or unsafe.
- A production swarm is secure.
- Model text is the verifier decision.

## Runs

| Model | Scenarios | Modes | Role calls | Monolith failures | Naive-swarm failures | Bounded-swarm failures | Verifier blocks | Contract coverage | Transcript hash coverage | Adapter error rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `prometheus-qwen15b-lowctx:latest` | 15 | 3 | 120 | 15 | 15 | 0 | 15 | 100% | 100% | 0% |
| `qwen2.5:1.5b` | 15 | 3 | 120 | 15 | 15 | 0 | 15 | 100% | 100% | 0% |

The bounded-swarm result is the expected deterministic outcome: all 15 modeled boundary
failures that monolith and naive-swarm accept are blocked by ASH handoff or
memory-governance contracts.

## Commands

```bash
ash local-swarm --execute \
  --model prometheus-qwen15b-lowctx:latest \
  --max-requests 140 \
  --timeout 60 \
  --out .internal/local-swarm-prometheus/2026-06-23-full-clean

ash validate .internal/local-swarm-prometheus/2026-06-23-full-clean

ash evidence-quality \
  --root .internal/local-swarm-prometheus/2026-06-23-full-clean \
  --out .internal/evidence-quality/2026-06-23-full-clean
```

```bash
ash local-swarm --execute \
  --model qwen2.5:1.5b \
  --max-requests 140 \
  --timeout 60 \
  --out .internal/local-swarm-qwen25/2026-06-23-full-clean

ash validate .internal/local-swarm-qwen25/2026-06-23-full-clean

ash evidence-quality \
  --root .internal/local-swarm-qwen25/2026-06-23-full-clean \
  --out .internal/evidence-quality/2026-06-23-full-clean
```

Raw model-response artifacts stay in local ignored `.internal/` or `reports/`
directories. The public repository records only aggregate evidence-quality metrics,
artifact schemas, sanitized examples, and claim boundaries.

The 2026-06-23 evidence-quality refresh over local scratch artifacts reported:

```text
local_swarm_runs: 5
local_swarm_results: 138
local_swarm_contract_coverage_rate: 1.000
local_swarm_transcript_hash_coverage_rate: 1.000
local_swarm_adapter_error_rate: 0.000
local_swarm_runtime_mode_coverage_rate: 1.000
```

## Interpretation

The useful result is not "the model behaved safely." The useful result is that weak local
models can participate in the role topology while deterministic contracts still decide
whether data, memory, authority, approval, and tool-output boundaries are preserved.

This supports the research direction for small local swarms:

1. generation roles may be weak;
2. delegation and memory roles must carry structured metadata;
3. verifier roles must be deterministic and fail closed;
4. audit roles should record hashes, coverage, adapter errors, and runtime-mode coverage.

The next research step is multi-turn live orchestration. That would test whether separate
runtime agents can preserve the same envelope and memory contracts across real role
handoffs, not just role-call prompts inside one runner.
