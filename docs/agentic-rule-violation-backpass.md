# Agentic Rule-Violation Back-Pass

> Status: public documentation pass over shipped contours.
>
> Scope: synthetic/mock/authorized artifacts only. This page does not include raw
> prompts, private calculation notes, canaries, provider details, or exploit recipes.

This back-pass re-reads the shipped evidence through one question:

> How does a normal-looking agentic workflow turn data into authority?

The goal is not to add more scenarios by volume. The goal is to make each shipped
contour explicit about the agentic path:

1. entry vector;
2. propagation path;
3. no-red-flag path;
4. timing window;
5. boundary violated;
6. controls that stop the chain;
7. ablations that reopen it;
8. benign preservation;
9. residual risk;
10. next action.

## Back-Pass Matrix

| Contour | Entry vector | Propagation path | No-red-flag path | Timing | Violated boundary | Stopping controls | Current evidence | Residual risk | Next action |
|---|---|---|---|---|---|---|---|---|---|
| Baseline 24-pattern corpus | Synthetic repo data, tool output, memory, approvals, provider routing, and audit state. | Single target consumes the corpus pattern and records pass/finding state. | Patterns look like ordinary project or tool artifacts. | Same-turn and short delayed paths. | Data, authority, memory, approval, provider, and audit boundaries. | Protected demo target contracts, envelope policy, memory checks, audit checks. | `examples/comparison-report/` shows `24 -> 0` modeled-risk reduction. | Broad corpus proves breadth, not deep coverage for every boundary. | Keep as front-door demo and route deepening to dedicated contours. |
| Secret egress / synthetic leak | Synthetic restricted values inside labels, memory, summaries, or web-like content. | Value enters an agentic chain, summary, memory, split recombination, or web-ingestion path. | The content resembles ordinary internal notes or analytics work. | Same-turn, multi-step, and summary-mediated. | Restricted value leaves allowed recipient/provider/surface. | Secret-envelope checks, source labels, egress gates, verifier blocks. | Secret-leak and marketing-web examples show naive leaks blocked by bounded contracts. | Does not prove real-secret detection in arbitrary traffic. | Keep raw canaries private; add only authorized sanitized summaries. |
| Semantic drift | Canonical meaning is slowly relabeled under low-amplitude pressure. | Worker state drifts before a downstream decision consumes it. | Each single turn can look like harmless clarification. | Multi-turn / gradual. | Canonical parameter meaning and label stability. | Canonical state checks, worker attestation, summary guards, chief verification. | Semantic drift and propagation examples show bounded acceptances `0` with ablation reopenings. | Deterministic checks do not solve semantic truth in all natural language. | Back-pass long-session variants only when labels and private transcripts remain controlled. |
| Semantic propagation / consensus laundering | Drifted or conflicting worker output reaches a chief or aggregator. | Worker output -> summary -> chief decision or consensus step. | Looks like normal handoff or multi-worker agreement. | Worker-to-chief / multi-agent. | Worker evidence becomes chief authority. | Worker attestation, cross-worker checks, canonical state, chief verification. | Propagation and consensus rows show bounded blocks and ablation reopenings. | Does not cover colluding workers or every aggregation policy. | Add colluding-worker variants only as a separate issue. |
| Swarm boundary defense | Combined semantic, propagation, consensus, and benign-framed leakage pressures. | Multiple family combinations pass through worker/chief topology. | Combination can look like normal distributed task work. | Multi-agent and multi-step. | Source, trust, consent, memory, and verifier boundaries across a chain. | Four-family bounded contour and replay-ablation attribution. | `examples/swarm-defense-contour-sanitized/` and live sanitized summaries. | Local-model summaries are evidence-quality snapshots, not model safety claims. | Keep public/private split; do not expand into provider leaderboard. |
| Context consent boundary | Repo issues, stale approvals, task batches, handoff claims, or ambient chat history claim approval. | Context is summarized or decomposed into a protected action. | Approval text looks relevant and user-like. | Same-turn, stale, batch, handoff. | Context is treated as current consent. | Current consent receipt, scope binding, source labels, handoff checks. | `examples/context-consent-sanitized/` records `5` naive risky acceptances and `0` bounded. | Does not prove legal consent handling. | Use as consent layer for future approval provenance work. |
| Tool-output authority boundary | CLI output, scanner text, schema annotations, error text, worker summaries, or metric rows claim authority. | Tool text becomes command, policy, schema, handoff, or metric authority. | Tool output looks structured and operational. | Same-turn and worker-to-chief. | Tool output is treated as authority. | Tool-output data boundary, schema authority split, metric/verdict split, handoff revalidation. | `examples/tool-authority-sanitized/` records `6` naive acceptances and `0` bounded. | Does not prove real MCP/schema verification. | Add live-tool work only under a separate authorized boundary. |
| RAG context authority boundary | Ranked snippets, citations, summaries, top-k corroboration, memory notes, or handoff summaries. | Retrieved evidence passes through summary, planner, memory, or handoff. | Retrieved text looks relevant and cited. | Same-turn, delayed, multi-agent. | Retrieved context is treated as authority. | Source provenance, trust labels, instruction/data split, planner gate, memory quarantine, handoff revalidation. | `examples/rag-context-sanitized/` records `7` naive unsafe-chain acceptances and `0` bounded. | Does not prove production RAG-agent safety. | Use as evidence layer for future live-RAG or gateway work only after authorization. |
| Planner task authority boundary | Untrusted context, stale approvals, tool output, retrieved snippets, handoffs, batches, or dependency graphs. | Planner decomposes inputs into subtasks and protected action candidates. | Work items look like normal planning output. | Same-turn, milliseconds, delayed, multi-agent. | Planning is treated as authorization. | Current intent anchor, consent receipt binding, task authority gate, subtask source inheritance, batch isolation, dependency gate. | `examples/planner-task-sanitized/` records `7` naive unsafe-chain acceptances and `0` bounded. | Does not prove production planning-agent safety. | Treat as closed deterministic contour; future live-planner probes require separate authorization. |
| Swarm resilience / stability | Memory, semantic, source-trust, consensus, metric/verdict, benign accumulation, or cascade state pressure. | State vector moves toward unsafe region across steps. | Each step can look operationally acceptable in isolation. | Long-session / cumulative. | State stability and return-to-safe-region assumptions fail. | State-vector thresholds, verifier attribution, benign preservation, replay-ablation checks. | `examples/swarm-resilience-sanitized/` records `7` naive unsafe and `0` bounded unsafe. | State-vector abstraction does not capture all model behavior. | Use as stability spine for later private local-model stress tests. |

## What This Changes

The shipped evidence now has a common review lens:

- **Data is not authority:** repo text, tool output, retrieved context, and summaries need
  trusted authority before protected actions.
- **Planning is not authorization:** decomposition can transform work, but each generated
  subtask keeps source, consent, authority, and trust labels.
- **Agreement is not authority:** consensus, top-k corroboration, and repeated context can
  raise evidence confidence, not permission.
- **Delay does not grant authority:** memory, old approvals, and dependency ordering must
  be revalidated at the point of action.
- **Benign work must still pass:** every deterministic contour keeps a benign path to
  avoid measuring only refusal.

## Follow-Up Candidates

The next useful gaps are not more prompt variants. They are distinct invariants:

| Candidate | Why it is next |
|---|---|
| `memory_governance.cross_agent_rehydration` | Memory resurrection across agents is not the same as first-turn context or planner decomposition. |
| `recovery.trust_gate_no_path` | A safe block that gives no recovery path is operationally weak. |
| `model_trust.weak_to_strong_escalation` | Weak-model output becoming chief authority is a different trust boundary. |
| `data_boundary.summary_boundary_loss` | Summaries can drop envelope limits even without planner conversion. |
| `handoff.signature_scope_ignored` | Signature/scope verification bridges this project toward transfer verification. |

## Non-Claims

This back-pass does not prove:

- production agent safety;
- model safety;
- provider vulnerability;
- exhaustive attack coverage;
- compliance with OWASP, NIST, or MITRE;
- that deterministic validators solve semantic truth.

It is a maintenance document that keeps shipped evidence coherent and points future work
to distinct boundary invariants.
