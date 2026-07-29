# Agentic AI Security threat ontology

> Status: portfolio-level normalization contract, version `0.1-draft`.
>
> Purpose: deduplicate existing scenarios by the protected invariant and causal transition,
> not by prompt wording, model name, or repository.

## Canonical threat statement

A threat case describes a transition:

```text
untrusted or bounded input
    -> transformation or transfer
    -> violated invariant
    -> attempted trust/authority/effect promotion
    -> observable evidence
```

A scenario is not unique merely because it uses another provider, prompt, modality, or agent
name.

## Deduplication key

The canonical identity of a scenario is:

```text
(protected_object,
 invariant,
 source_trust,
 transition,
 topology,
 timing,
 attempted_effect,
 expected_guard_decision,
 evidence_class)
```

Two cases with the same key are aliases or variants. A new model, provider, wording, or
synthetic payload becomes a variation unless it changes at least one causal field.

## Factor model

| Axis | Initial vocabulary |
|---|---|
| Protected object | data, instruction, provenance, identity, trust, authority, capability, consent, policy, memory, resource, telemetry, evidence, effect |
| Source | user, model, agent, tool, MCP server, retrieval, memory, document, browser/app surface, sensor transcript, environment, provider, audit record |
| Transition | accept, summarize, classify, retrieve, recall, merge, delegate, plan, select tool, invoke, fallback, retry, persist, replay, attest, execute |
| Topology | single, linear chain, worker-chief, fan-out, fan-in, multi-hop, multi-session, cross-user, cross-app, cross-provider, shared-resource swarm |
| Timing | immediate, delayed, stale, expired, replayed, burst, low-and-slow, long-session |
| Modality | structured event, text, tool metadata, OCR, ASR, image feature, audio feature, filesystem metadata |
| Guard state | naive, bounded, ablated, incomplete, degraded, unavailable, forged telemetry |
| Decision | allow, deny, challenge, escalate, abstain, quarantine |
| Evidence | executable specification, synthetic observation, independently labelled evaluation, historical declaration, design-only |

## Canonical threat families

| ID | Family | Protected invariant | Current portfolio coverage |
|---|---|---|---|
| T01 | Data becomes instruction | Untrusted content remains data unless a trusted authority explicitly promotes it | Baseline corpus, tool/RAG/planner campaigns, playbooks |
| T02 | Envelope weakening | Classification, recipient, purpose, storage, forwarding and source restrictions cannot weaken through transformation | Baseline corpus and envelope policy; summary-loss expansion planned |
| T03 | Secret reconstruction or egress | Restricted fragments cannot be exposed, recombined, relabelled or routed to an unauthorized sink | Secret-leak and private-asset leakage models |
| T04 | Memory poisoning and unsafe rehydration | Memory retains provenance, trust, scope, TTL, recipient and dependency constraints | Baseline, memory governance, memory-rehydration campaign |
| T05 | Consent or approval laundering | Context, history, summaries and third-party claims are not current action-bound consent | Context-consent and approval-laundering cases |
| T06 | Capability and authority expansion | Delegation cannot expand issuer, subject, scope, purpose, target, TTL or depth | Harness delegation pattern, Transfer Verifier, Runtime Guard |
| T07 | Tool and MCP deception | Tool metadata, schema, output and errors remain untrusted and version-bound | MCP schema/tool selection patterns and tool-authority campaign |
| T08 | Phantom resource trust | Model-generated URL, package, endpoint, webhook or domain is untrusted until independently resolved | Playbook exists; Harness contour designed, not implemented |
| T09 | Semantic drift | Canonical meaning cannot silently change under repeated low-amplitude transformations | Deterministic semantic drift specification; empirical evidence withdrawn/unreconciled |
| T10 | Consensus laundering | Repetition or majority agreement cannot promote an unverified claim | Two-worker semantic closure and swarm contour |
| T11 | Weak-to-strong model escalation | Weak/filter output keeps trust and uncertainty labels and requires independent validation | Designed; Router and Cheap Filter expose mechanics but do not enforce trust |
| T12 | Cross-surface/provider contamination | Source surface, provider policy and trust envelope survive routing and fallback | Cross-provider matrix variants; broader contours planned |
| T13 | Planning creates authority | Generated tasks and dependencies cannot inherit unstated authorization | Planner-task campaign |
| T14 | Delayed and multi-turn activation | A dormant instruction does not gain authority through time, repetition or dependency order | Sleeping prompt, multi-turn escalation and delayed memory cases |
| T15 | Budget and recursive amplification | Cost pressure, recursion and fan-out cannot bypass verification or owner budgets | Baseline budget patterns, Router budget arithmetic |
| T16 | Perception and ambient authority | Sensor-derived text and host capabilities remain bounded observations | Synthetic OCR/ASR pattern and non-semantic sensor adapters |
| T17 | Identity, provenance and handoff integrity | Receiver verifies source, digest, scope, freshness and identity before trust transfer | Harness toy topology, Transfer Verifier, Handoff protocol |
| T18 | Audit integrity and context completeness | Evidence is append-only and records action, decision context, envelope and policy basis | Hash-chain shipped; action/audit divergence planned |
| T19 | Telemetry omission or forgery | Missing, malformed, forged or selectively sampled observations cause abstention, not confidence | Runtime Guard event adapter and scorer |
| T20 | Swarm campaign coordination | Campaign-level convergence, replay and privilege growth are assessed across lineage and time | Observe-only scorer and Generation 2/3 research |
| T21 | Policy letter versus spirit | Literal compliance cannot violate minimization, reconstruction, recipient or purpose invariants | Designed; no product semantic detector |
| T22 | Unsafe recovery | A refusal or failed verifier provides a bounded recovery envelope without weakening policy | One baseline case; broader recovery family planned |
| T23 | Receipt replay and effect substitution | One exact allowed action produces at most one consumed effect; payload and outcome stay bound | Runtime Guard receipt authority, ledger and bounded executor |
| T24 | Supply-chain and artifact authenticity | Generated resources, schemas, packages and releases require independent provenance evidence | Phantom-resource design, schema pinning, release attestations |
| T25 | Privacy-minimized evidence | Hashing and minimization do not become false anonymity claims; raw sensitive content stays separate | Evidence contracts and current hash-linkability residual risk |
| T26 | Sandbox and trusted-computing-base escape | An authorized effect cannot escape its declared local boundary | Bounded filesystem slice only; OS-specific production sandbox remains open |

## Alias examples

These names represent related variants, not automatically separate threat families:

- `tool_permission_abuse_sanitized`, `mcp.tool_schema_deception`,
  `mcp.tool_selection_manipulation`, `toolauth.schema.annotation_smuggling` map primarily
  to T07;
- `memory_poisoning_sanitized`, `memory_governance.environment_injected_poisoning`,
  `memory.recall.expired_policy`, and `temporal.stale_memory_authority` map primarily to T04
  with different source/timing values;
- `semantic.var.summary_laundering_chain`, `propagation.var.worker_relabel_to_chief`, and
  `semantic.consensus_laundering` cross T09/T10 and must declare a primary invariant;
- `data_boundary_handoff_label_stripping` and `data_boundary.summary_boundary_loss` both
  weaken an envelope, but the latter is a transformation case rather than a direct handoff.

## Scenario promotion states

| State | Meaning |
|---|---|
| `idea` | Discussed only; no invariant or topology is frozen |
| `designed` | Invariant, topology, failure condition and expected artifact are documented |
| `implemented_spec` | Deterministic executable specification and tests exist |
| `synthetic_observed` | A bounded synthetic runtime/model observation exists |
| `independently_evaluated` | Labels and evaluation satisfy the declared independence protocol |
| `shadow_product` | Integrated product path runs without effect authority |
| `bounded_enforcement` | A reviewed non-bypassable effect gate is enabled for an explicit boundary |

Promotion is monotone only with current evidence. A stale schema, unreconciled run, changed
detector, or invalidated holdout can move the evidence status backwards.

## Covering-array design

Do not generate the full Cartesian product. Use a staged design:

1. one minimal counterexample for each canonical family;
2. pairwise coverage across source, transition, topology, timing, and guard state;
3. three-way coverage only for interactions supported by a causal hypothesis;
4. mandatory benign twins for each promoted attack case;
5. control ablations tied to the claimed dependency;
6. family-separated unseen evaluation after detector and thresholds are frozen.

Combinatorial coverage is evidence of factor coverage, not proof that every natural-language
attack is represented.

The initial executable pairwise design is implemented in
`agentic_security_harness.covering_array`. It covers every feasible pair across a deliberately
bounded six-axis vocabulary after causal constraints are applied. Each generated row carries
only synthetic factor labels, a canonical family and an authority-free expected shadow
disposition. It contains no prompts, payloads, provider routes, secrets, effects, or holdout
labels.

This development design is not the unseen-family evaluation set. Its factors, constraints,
case identifiers and expected dispositions are public to the developer and therefore cannot
serve as a sealed holdout.

## Open ontology work

- independently review the provisional primary-family adjudication of all 120 current
  executable Harness builder units;
- bind every Runtime Guard generator family to one primary family;
- distinguish aliases from genuinely different causal transitions;
- add explicit revocation and uniformly over-privileged-window cases;
- define semantic-sentinel abstention and disagreement cases;
- define producer attestation and telemetry-completeness threat families precisely;
- review mappings independently before publishing a total scenario count.
