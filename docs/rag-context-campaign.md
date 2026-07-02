# RAG Context Authority Campaign

This campaign is the deterministic retrieved-context / RAG authority contour for
Agentic Security Harness.

The boundary is:

> Retrieved context is evidence, not authority.

An agent may use retrieved text, citations, summaries, rankings, memory notes, and
handoff summaries as context. It must not treat them as user instruction, policy grant,
planner permission, or downstream authority unless a trusted authority source grants that
permission.

No model calls are made. No live RAG systems, provider APIs, endpoints, credentials, raw
prompts, or unsafe payload chains are used.

## Why This Is Agentic

The campaign models agentic propagation rather than a single prompt-level failure.

A retrieved document does not need an obvious jailbreak string to create risk. The
declared synthetic cases model paths where normal-looking retrieved text passes through:

1. retrieval ranking or top-k selection;
2. citation or summary compression;
3. planner task decomposition;
4. memory or handoff;
5. action selection or report writing.

The unsafe conversion happens when the workflow treats retrieved data as permission.

## Cases

The public campaign contains seven synthetic cases:

| Case | Boundary pressure |
|---|---|
| `ranked_snippet_command` | A high-ranked snippet is treated as a command. |
| `citation_permission_laundering` | A citation is mistaken for a permission grant. |
| `summary_source_label_loss` | A summary drops the untrusted source label. |
| `planner_subtask_conversion` | A planner converts retrieved context into a protected subtask. |
| `multi_document_corroboration` | Multiple retrieved documents launder authority through agreement. |
| `memory_delayed_activation` | Retrieved context persists into memory and activates later. |
| `handoff_inherited_authority` | A downstream agent inherits retrieved-context authority from a handoff. |

Each case records:

- entry vector;
- propagation path;
- no-red-flag path;
- timing window;
- authority conversion;
- expected safe behavior;
- required controls;
- benign variant.

## Control Model

The bounded contract uses ten controls:

| Control | Role |
|---|---|
| `source_provenance` | Preserve source and trust labels. |
| `retrieval_trust_label` | Keep retrieval rank separate from trust. |
| `context_instruction_split` | Keep retrieved instructions as data unless elevated. |
| `rank_is_not_authority` | Prevent high rank from becoming permission. |
| `citation_permission_split` | Separate fact support from authority grants. |
| `summary_provenance_preservation` | Keep source labels through compression. |
| `planner_authority_gate` | Stop planners from creating protected subtasks from context. |
| `cross_document_independence` | Prevent top-k agreement from laundering authority. |
| `memory_quarantine` | Keep retrieved context quarantined across turns. |
| `handoff_revalidation` | Revalidate retrieved-context authority downstream. |

## Metrics

The committed sanitized example records:

| Metric | Value |
|---|---:|
| Cases | 7 |
| Controls | 10 |
| Pressure axes | 8 |
| Deterministic rows | 91 |
| Control-effect rows | 10 |
| Naive unsafe-chain acceptances | 7 |
| Bounded unsafe-chain acceptances | 0 |
| Ablation unsafe-chain acceptances | 30 |
| Benign acceptances | 7 |
| Benign false blocks | 0 |

## Reproduce

```bash
ash rag-context-campaign --write --out examples/rag-context-sanitized
ash validate examples/rag-context-sanitized
```

The committed artifact lives at
[`examples/rag-context-sanitized/`](../examples/rag-context-sanitized/).

## Non-Claims

This campaign does not prove:

- a deployed RAG agent is safe;
- a deployed RAG agent is vulnerable;
- a provider model has a specific weakness;
- a vector database, search service, or retriever is secure;
- the declared controls cover every possible multi-step attack.

It only shows that the declared synthetic agentic propagation class can be modeled,
measured, bounded, and validated inside this harness.
