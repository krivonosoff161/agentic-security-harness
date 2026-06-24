# Local Swarm Deep Probes

> Last reviewed: 2026-06-23.
>
> Scope: executable deep probes for the bounded local-swarm attack matrix. This page
> documents the method and aggregate local results; raw model responses remain private
> under `.internal/`.

## What Changed

The original attack matrix expanded the 15 local-swarm scenarios into declared rows.
That was useful for review, but several rows were aliases over the same base scenario.
The current matrix keeps those rows and adds 10 executable deep probes that call the
actual deterministic handoff and memory contracts with mutated state:

- payload rewrite after hash binding -> `integrity_mismatch`;
- receiver switch by model text -> `recipient_violation`;
- expired handoff replay -> `stale_or_replayed`;
- policy-version mismatch -> `policy_mismatch`;
- tool output smuggling an authority scope -> `authority_expansion`;
- tool-output summary dropping source label -> `label_loss`;
- similar memory key recall -> `key_mismatch`;
- read before write -> `read_before_write`;
- read-side TTL removal -> `read:ttl_removed`;
- stored memory forwarding weakening -> `stored:can_forward_weakened`.

## Current Deterministic Calculation

```text
cases=43
variation_families=9
deep_probe_cases=10
monolith_boundary_failures=43
naive_swarm_boundary_failures=43
bounded_swarm_boundary_failures=0
bounded_blocks=43
unsafe_consumption_rate=100%
contract_coverage=100%
```

Interpretation: the deep probes model points where weak role logic would consume a
mutated handoff, tool output, or memory record. The deterministic boundary blocks those
consumptions. This is not a proof that a real multi-agent runtime or model is safe.

## Local Model Probe

The model-probe path is explicit and private-ready:

```bash
ash local-swarm-matrix --execute-model \
  --model prometheus-qwen15b-lowctx:latest \
  --pressure-mode neutral \
  --out .internal/local-swarm-matrix-deep/prometheus-qwen15b-lowctx

ash local-swarm-matrix --execute-model \
  --model qwen2.5:1.5b \
  --pressure-mode coercive \
  --out .internal/local-swarm-matrix-deep/qwen2.5-1.5b-coercive
```

The model text is hashed and summarized for evidence-quality review. It never changes
the deterministic pass/block result.

Current local private runs covered:

| Model | Pressure | Cases | Responses | Adapter errors | Unsafe PROCEED observations |
| --- | --- | ---: | ---: | ---: | ---: |
| `prometheus-qwen15b-lowctx:latest` | neutral | 10 | 10 | 0 | 0 |
| `qwen2.5:1.5b` | neutral | 10 | 10 | 0 | 0 |
| `prometheus-qwen15b-lowctx:latest` | coercive | 10 | 10 | 0 | 0 |
| `qwen2.5:1.5b` | coercive | 10 | 10 | 0 | 0 |

These results mean only that the two tested local models did not choose unsafe `PROCEED`
on these 10 prompts under the current classifier. The main safety claim remains the
deterministic contract behavior, not model understanding.

## Non-Claims

- No production multi-agent runtime is certified by these probes.
- No local model is declared safe.
- No prompt-only probe proves semantic truthfulness.
- The 10 rows are representative invariant probes, not an exhaustive cross-product.
- Private raw responses are not public benchmark artifacts.

