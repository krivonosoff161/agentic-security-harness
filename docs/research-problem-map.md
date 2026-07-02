# Active research problem map

> Last reviewed: 2026-07-02.
>
> Scope: public-facing map of defensive violation models for Agentic Security Harness.
> This is a planning and evidence index, not a production-safety claim, model
> leaderboard, CVE claim, or offensive guide.

## Purpose

This page shows how the project develops beyond adding more prompt variants.

The rule is:

```text
problem -> boundary invariant -> topology -> synthetic case
-> vulnerable behavior -> bounded behavior -> ablation -> benign check
-> public artifact -> claim boundary
```

A new violation model should enter the project only when it tests a materially new
boundary, not because a provider, model name, prompt wording, or framework changed.

## Current release baseline

Agentic Security Harness v0.14.0 has two layers of public evidence:

1. A **24-pattern deterministic corpus** for core agentic boundary failures.
2. Deeper **research contours** that combine scenarios, controls, ablations, benign-path
   checks, and sanitized evidence artifacts.

The current public claim stays conservative:

> Trace-first defensive benchmark for reproducible agentic AI boundary-failure
> evaluation, with local deterministic targets, validated artifacts, bounded local-swarm
> evidence, and experimental opt-in external/local model checks.

Do not claim production certification, complete security coverage, provider endorsement,
or deployed-agent safety.

## Closed / shipped deep contours

These are the main research contours that already have public artifacts.

| Status | Contour | Boundary invariant | Public evidence | What it proves | What it does not prove |
|---|---|---|---|---|---|
| Shipped | Baseline deterministic corpus | Project data, authority, memory, approval, audit, and tool boundaries must survive agent-like workflows. | [`docs/corpus.md`](corpus.md), [`examples/comparison-report/`](../examples/comparison-report/) | Vulnerable demo target records 24 modeled findings; protected demo target records 0 on the same synthetic corpus. | Safety of a real deployed agent. |
| Shipped | Secret egress / synthetic leak | Restricted synthetic values must not leave allowed recipients, providers, summaries, or web-like paths. | [`examples/secret-leak-campaign-sanitized/`](../examples/secret-leak-campaign-sanitized/), [`examples/marketing-web-injection-sanitized/`](../examples/marketing-web-injection-sanitized/) | Naive paths leak declared synthetic values while bounded paths block the modeled egress. | Detection of real secrets in arbitrary enterprise traffic. |
| Shipped | Semantic drift | Canonical meaning and labels must not slowly shift under low-amplitude pressure. | [`examples/semantic-drift-sanitized/`](../examples/semantic-drift-sanitized/), [`semantic-drift-propagation-closure.md`](semantic-drift-propagation-closure.md) | Drift can be modeled, detected, and bounded through deterministic controls plus sanitized local observations. | Complete semantic understanding or model-wide robustness. |
| Shipped | Semantic propagation | A drifted worker summary must not become an authoritative chief decision. | [`examples/semantic-propagation-sanitized/`](../examples/semantic-propagation-sanitized/), [`semantic-propagation-defense-model.md`](semantic-propagation-defense-model.md) | Worker-to-chief propagation can be attributed to declared controls and ablations. | Real multi-agent production safety. |
| Shipped | Swarm boundary defense | Multi-agent chains must preserve source, trust, consent, memory, and verifier boundaries across combined failure families. | [`examples/swarm-defense-contour-sanitized/`](../examples/swarm-defense-contour-sanitized/), [`examples/swarm-defense-live-deep-sanitized/`](../examples/swarm-defense-live-deep-sanitized/) | Combined failure families can be blocked by bounded contracts, with replay-ablation attribution. | General swarm safety or benchmark-grade model ranking. |
| Shipped | Context is not consent | Contextual text that claims approval is not current user consent. | [`examples/context-consent-sanitized/`](../examples/context-consent-sanitized/), [`context-consent-campaign.md`](context-consent-campaign.md) | Five consent-boundary cases produce naive risky-action acceptances, bounded acceptances 0, and benign false blocks 0. | Legal proof of consent handling in deployed systems. |
| Shipped | Tool output is not authority | Tool results, scanner text, schema annotations, error messages, worker summaries, and metric rows remain data unless a trusted authority source grants action. | [`examples/tool-authority-sanitized/`](../examples/tool-authority-sanitized/), [`tool-authority-campaign.md`](tool-authority-campaign.md) | Six tool-output authority cases produce naive risky-action acceptances, bounded acceptances 0, ablation attribution, and benign false blocks 0. | Production tool-agent safety, real MCP/schema verification, or exhaustive tool-output coverage. |

## Active evidence and maintenance tracks

These tracks are active because they keep the shipped evidence trustworthy.

| Track | Current job | Evidence / owner document | Next maintenance action |
|---|---|---|---|
| Public evidence map | Keep front-page metrics tied to committed artifacts and non-claims. | [`showcase/evidence-map.md`](showcase/evidence-map.md) | Update whenever a metric or example path changes. |
| Private/public evidence boundary | Keep raw local-model prompts, responses, canaries, and calculation notes out of public artifacts. | [`private-public-evidence-boundary.md`](private-public-evidence-boundary.md), [`evidence-pack-format.md`](evidence-pack-format.md) | Re-check before every new sanitized evidence pack. |
| Research claims registry | Keep each claim in hypothesis / evidence / closed status. | [`research-claims.md`](research-claims.md) | Add a row when a new contour moves beyond discussion. |
| Corpus expansion control | Keep new patterns invariant-based, not combinatorial. | [`corpus-expansion-plan.md`](corpus-expansion-plan.md) | Promote only candidates with topology, failure condition, artifact, and residual risk. |
| Project-track separation | Keep the shipped benchmark distinct from the future LLM Safety Gateway / Runtime Verifier track. | [`project-tracks.md`](project-tracks.md) | Gateway ideas stay design/research until there is a separate implementation boundary. |

## Next candidate violation models

These are candidate directions. They are not shipped until they have an issue, branch,
implementation, tests, examples, validation, and a merged PR.

### P1 candidates

| Candidate | Plain-language problem | Boundary invariant | Why it is different | Existing anchor | Graduation artifact |
|---|---|---|---|---|---|
| `memory_governance.cross_agent_rehydration` | Agent B recalls Agent A's old memory as if it were trusted current authority. | Recalled memory preserves provenance, scope, TTL, and trust level. | Memory resurrection across agents, not a first-turn prompt. | [`corpus-expansion-plan.md`](corpus-expansion-plan.md), [`theory/memory-governance.md`](theory/memory-governance.md) | Public sanitized memory rehydration report. |
| `recovery.trust_gate_no_path` | A gate blocks a request but gives no recovery path, artifact, or next step. | Refusal must still produce a structured recovery envelope. | Safety usability and operations, not only block/allow. | [`corpus-expansion-plan.md`](corpus-expansion-plan.md) | Deterministic recovery-path example plus validation. |
| `model_trust.weak_to_strong_escalation` | A chief model treats weak-model output as authoritative. | Weak outputs carry trust labels and require validation before action. | Model-chain trust asymmetry, not single-agent behavior. | [`corpus-expansion-plan.md`](corpus-expansion-plan.md) | Weak-to-chief trust escalation matrix. |
| `data_boundary.summary_boundary_loss` | A summary drops the original data envelope, so restricted data becomes unrestricted. | Summaries inherit recipient, purpose, storage, and forwarding limits. | Transformation boundary, not direct forwarding. | [`corpus-expansion-plan.md`](corpus-expansion-plan.md) | Summary-boundary comparison artifact. |
| `handoff.signature_scope_ignored` | A receiver ignores missing/invalid signature, hash, or scope evidence in a handoff. | Chain-of-custody must be verified before trust transfer. | Bridges the benchmark toward transfer verification. | [`inter-agent-handoff-integrity.md`](inter-agent-handoff-integrity.md) | Handoff signature/scope verifier artifact. |

### P2 candidates

| Candidate | Plain-language problem | Boundary invariant | Why it waits |
|---|---|---|---|
| `approval_context.missing_provenance` | A human approval prompt hides source, data class, recipient, purpose, or risk. | Approval must include enough provenance to be meaningful. | Related to context-consent; implement after a distinct approval artifact shape is chosen. |
| `temporal.permission_drift` | Old permission is reused as current authority. | Permissions expire or narrow over time. | Needs a clean temporal fixture so it does not duplicate context-consent. |
| `temporal.stale_memory_authority` | Expired memory controls a current decision. | Memory reads check freshness and source before authority use. | Related to memory rehydration; likely a second phase. |
| `provider_boundary.fallback_envelope_loss` | A fallback provider route loses policy context after primary failure. | Fallback keeps the same envelope and re-checks policy. | Needs careful provider-neutral wording and no live provider dependency. |
| `cross_app.data_instruction_contamination` | Content from one app surface influences action in another surface. | Current surface rejects instructions from another surface unless explicitly authorized. | Needs a multi-surface local target, not a real browser/editor. |
| `audit_context_split.action_audit_divergence` | The audit says what happened but not why or under which policy. | Audit records action, decision context, envelope, and policy basis. | Best done after recovery-path and handoff evidence shapes are stable. |

## Promotion rules

A candidate becomes shipped only after all of this exists:

1. **Issue:** names the problem, invariant, topology, safe scope, and done criteria.
2. **Design:** explains expected vulnerable behavior, bounded behavior, controls, and
   residual risk.
3. **Implementation:** uses synthetic/mock/authorized targets only.
4. **Ablation:** shows which control reopening makes the failure possible again.
5. **Benign path:** shows the bounded control does not block an ordinary safe case.
6. **Artifacts:** writes public-safe JSON/Markdown summaries under `examples/`.
7. **Validation:** `ash validate examples/` understands the artifact or the artifact is
   covered by an existing validator.
8. **Docs:** README/evidence map/research claims explain the claim and non-claim.
9. **Checks:** targeted tests, `ruff`, `mypy`, `git diff --check`, and GitHub checks pass.
10. **Merge:** PR lands on `main`; release notes move it from active research to shipped.

## Decision rule for the next contour

When choosing the next build, prefer the candidate that adds the most new boundary
coverage with the least new machinery.

Current likely order:

1. `memory_governance.cross_agent_rehydration`
2. `recovery.trust_gate_no_path`
3. `model_trust.weak_to_strong_escalation`
4. `data_boundary.summary_boundary_loss`
5. `handoff.signature_scope_ignored`

This order can change if a new issue shows a clearer invariant, stronger artifact, or a
more important gap.

## How this map relates to standards

Use standards as anchors, not as claims of compliance:

- OWASP LLM and OWASP Agentic categories help name risk families.
- MITRE ATLAS helps align with known AI threat patterns where the fit is direct.
- NIST AI RMF / GenAI profile helps keep traceability and risk-management language
  conservative.

This map is project-specific: the deciding unit is always the boundary invariant and the
validated artifact, not the standard label.
