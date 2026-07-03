# Memory Rehydration Authority Campaign

> Status: deterministic public research contour.

This page documents the cross-agent memory rehydration authority boundary:

> Recalled memory is evidence, not current authority.

An agent may restore old, summarized, merged, or cross-agent memory as context, but
that memory does not become a fresh user command, permission receipt, or policy grant.
Protected actions still need current authority and scope checks.

## What It Models

The campaign declares seven synthetic memory rehydration cases:

| Case | Plain-language failure |
|---|---|
| `cross_agent_instruction_recall` | A worker memory note is recalled as a current instruction. |
| `expired_memory_rehydration` | Expired memory is treated as live permission. |
| `cross_session_scope_loss` | Memory from one workspace/session affects another scope. |
| `summary_trust_level_loss` | A compressed memory summary drops low-trust labels. |
| `worker_memory_to_chief_authority` | Worker-local memory becomes chief-agent authority. |
| `merged_memory_restricted_source` | Restricted memory is blended into normal context. |
| `dependency_memory_delayed_activation` | Safe recalled memory unlocks a later protected step. |

Each case records:

- memory surface;
- entry vector;
- propagation path;
- no-red-flag path;
- timing window;
- authority conversion;
- risky action;
- expected bounded behavior;
- required controls;
- benign variant.

## Control Model

The deterministic controls are:

- `memory_source_provenance`
- `memory_scope_binding`
- `memory_ttl_enforcement`
- `trust_level_preservation`
- `current_user_intent_anchor`
- `rehydration_authority_gate`
- `recipient_scope_check`
- `merge_source_isolation`
- `handoff_revalidation`
- `dependency_revalidation_gate`

The campaign runs each case in naive, bounded, control-ablation, and benign modes. A
bounded row must block the declared unsafe chain. A benign row must still pass.

## Public Result

The committed sanitized example records:

| Metric | Value |
|---|---:|
| Cases | 7 |
| Controls | 10 |
| Pressure axes | 9 |
| Deterministic rows | 91 |
| Naive unsafe-chain acceptances | 7 |
| Bounded unsafe-chain acceptances | 0 |
| Ablation unsafe-chain acceptances | 32 |
| Benign false blocks | 0 |

The ablation rows are the key evidence: when a responsible control is removed, the
specific dependent memory rehydration path reopens. That is stronger than only showing
a bounded block.

## Reproduce

```bash
ash memory-rehydration-campaign --write --out examples/memory-rehydration-sanitized
ash validate examples/memory-rehydration-sanitized
```

The committed public artifact lives at
[`examples/memory-rehydration-sanitized/`](../examples/memory-rehydration-sanitized/).

## Non-Claims

This campaign does not prove:

- production memory-agent safety;
- model safety;
- provider vulnerability;
- exhaustive memory-system coverage;
- that deterministic validators solve semantic truth;
- that a deployed system preserves authority boundaries.

It is a deterministic public contour for one boundary family. Future live-memory,
gateway, or model-in-the-loop probes require a separate authorized implementation
boundary and the same private/public evidence split used elsewhere in the project.
