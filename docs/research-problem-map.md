# Active research problem map

> Last reviewed: 2026-07-14.
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

Agentic Security Harness v0.14.0 has three explicitly separated layers of public evidence:

1. A **24-pattern deterministic corpus** for core agentic boundary failures.
2. **Executable specifications** whose controls and ablation outcomes are rule-derived.
3. **Local empirical observations**, with detector-accuracy claims allowed only when
   independently reviewed ground-truth coverage is non-zero.

The current public claim stays conservative:

> Trace-first defensive benchmark for reproducible agentic AI boundary-failure
> evaluation, with local deterministic targets, validated artifacts, bounded local-swarm
> evidence, and experimental opt-in external/local model checks.

Do not claim production certification, complete security coverage, provider endorsement,
or deployed-agent safety.

## Closed / shipped deep contours

These are the main research contours that already have public artifacts.

| Status | Contour | Boundary invariant | Public evidence | What the current evidence supports | What it does not prove |
|---|---|---|---|---|---|
| Shipped | Baseline deterministic corpus | Project data, authority, memory, approval, audit, and tool boundaries must survive agent-like workflows. | [`docs/corpus.md`](corpus.md), [`examples/comparison-report/`](../examples/comparison-report/) | Vulnerable demo target records 24 modeled findings; protected demo target records 0 on the same synthetic corpus. | Safety of a real deployed agent. |
| Shipped | Secret egress / synthetic leak | Restricted synthetic values must not leave allowed recipients, providers, summaries, or web-like paths. | [`examples/secret-leak-campaign-sanitized/`](../examples/secret-leak-campaign-sanitized/), [`examples/marketing-web-injection-sanitized/`](../examples/marketing-web-injection-sanitized/) | The executable specifications mark declared naive branches as leaking and bounded branches as blocked under their encoded rules. | An observed causal effect or detection of real secrets in arbitrary enterprise traffic. |
| Shipped | Semantic drift | Canonical meaning and labels must not slowly shift under low-amplitude pressure. | [`examples/semantic-drift-sanitized/`](../examples/semantic-drift-sanitized/), [`semantic-drift-propagation-closure.md`](semantic-drift-propagation-closure.md) | The current executable specification reproduces declared drift branches and rule-encoded dependencies. Linked legacy detector observations remain historical and unreconciled. | Current model behavior, detector accuracy, complete semantic understanding, or model-wide robustness. |
| Shipped | Semantic propagation | A drifted worker summary must not become an authoritative chief decision. | [`examples/semantic-propagation-sanitized/`](../examples/semantic-propagation-sanitized/), [`semantic-propagation-defense-model.md`](semantic-propagation-defense-model.md) | The executable specification records declared worker-to-chief branches and rule-derived control dependencies. Linked detector observations remain historical. | An independent causal control effect or real multi-agent production safety. |
| Shipped | Swarm boundary defense | Multi-agent chains must preserve source, trust, consent, memory, and verifier boundaries across combined failure families. | [`examples/swarm-defense-contour-sanitized/`](../examples/swarm-defense-contour-sanitized/), [`examples/swarm-defense-live-deep-sanitized/`](../examples/swarm-defense-live-deep-sanitized/) | The current contour records rule-derived bounded/naive branches and encoded dependencies. The linked deep live artifact is a separate legacy detector summary. | Current empirical effectiveness, general swarm safety, or benchmark-grade model ranking. |
| Shipped | Context is not consent | Contextual text that claims approval is not current user consent. | [`examples/context-consent-sanitized/`](../examples/context-consent-sanitized/), [`context-consent-campaign.md`](context-consent-campaign.md) | The evaluator records declared branches for five consent cases: naive acceptances 5, bounded acceptances 0, and benign false blocks 0. | Independent causal effect or legal proof of consent handling in deployed systems. |
| Shipped | Tool output is not authority | Tool results, scanner text, schema annotations, error messages, worker summaries, and metric rows remain data unless a trusted authority source grants action. | [`examples/tool-authority-sanitized/`](../examples/tool-authority-sanitized/), [`tool-authority-campaign.md`](tool-authority-campaign.md) | The evaluator records declared branches for six cases, including bounded acceptances 0 and rule-derived dependency counts. | Independent causal effect, production tool-agent safety, real MCP/schema verification, or exhaustive tool-output coverage. |
| Shipped | Retrieved context is not authority | RAG/search results, citations, summaries, rankings, memory notes, and handoff summaries remain evidence unless a trusted authority source grants action. | [`examples/rag-context-sanitized/`](../examples/rag-context-sanitized/), [`rag-context-campaign.md`](rag-context-campaign.md) | The evaluator records declared branches for seven cases, including bounded acceptances 0 and rule-derived dependency counts. | Independent causal effect, production RAG-agent safety, provider/model vulnerability claims, or exhaustive retrieval coverage. |
| Shipped | Planning is not authorization | Planner/task decomposition must preserve source, consent, authority, and trust labels; generated subtasks do not inherit authority from context, stale approval, tool output, retrieval, handoff, batching, or dependency ordering. | [`examples/planner-task-sanitized/`](../examples/planner-task-sanitized/), [`planner-task-campaign.md`](planner-task-campaign.md) | The evaluator records declared branches for seven cases, including bounded acceptances 0 and rule-derived dependency counts. | Independent causal effect, production planning-agent safety, provider/model vulnerability claims, or exhaustive planner coverage. |
| Shipped | Recalled memory is not current authority | Rehydrated memory must preserve source, scope, TTL, trust level, recipient, merge, handoff, and dependency labels before it can affect protected work. | [`examples/memory-rehydration-sanitized/`](../examples/memory-rehydration-sanitized/), [`memory-rehydration-campaign.md`](memory-rehydration-campaign.md) | The evaluator records declared branches for seven cases, including bounded acceptances 0 and rule-derived dependency counts. | Independent causal effect, production memory-agent safety, provider/model vulnerability claims, or exhaustive memory-system coverage. |

## Active evidence and maintenance tracks

These tracks are active because they keep the shipped evidence trustworthy.

| Track | Current job | Evidence / owner document | Next maintenance action |
|---|---|---|---|
| Public evidence map | Keep front-page metrics tied to committed artifacts and non-claims. | [`showcase/evidence-map.md`](showcase/evidence-map.md) | Update whenever a metric or example path changes. |
| Evidence classification | Keep lifecycle, evidence class, schema state, causal scope, reconciliation state, and origin-authentication state separate. | [`evidence-classes.md`](evidence-classes.md), [`research-claims.md`](research-claims.md), [`private-public-evidence-boundary.md`](private-public-evidence-boundary.md) | Require every promoted contour to declare each axis before its metric or claim. |
| Private/public evidence boundary | Keep raw local-model prompts, responses, canaries, and calculation notes out of public artifacts. | [`private-public-evidence-boundary.md`](private-public-evidence-boundary.md), [`evidence-pack-format.md`](evidence-pack-format.md) | Re-check before every new sanitized evidence pack. |
| Research claims registry | Keep each claim in hypothesis / evidence / closed status. | [`research-claims.md`](research-claims.md) | Add a row when a new contour moves beyond discussion. |
| Agentic rule-violation back-pass | Keep shipped contours aligned to entry vector, propagation path, timing window, controls, ablations, benign preservation, and residual risk. | [`agentic-rule-violation-backpass.md`](agentic-rule-violation-backpass.md) | Re-run when a new deterministic contour is promoted. |
| Corpus expansion control | Keep new patterns invariant-based, not combinatorial. | [`corpus-expansion-plan.md`](corpus-expansion-plan.md) | Promote only candidates with topology, failure condition, artifact, and residual risk. |
| Project-track separation | Keep the shipped benchmark distinct from the future LLM Safety Gateway / Runtime Verifier track. | [`project-tracks.md`](project-tracks.md) | Gateway ideas stay design/research until there is a separate implementation boundary. |

## Next planned contour

The next designed contour is **#8: Phantom Resource Trust**. Issue #140 is closed because
the design was documented; there is currently no open implementation issue.

It is not part of the current seven-scenario trading-stand gate. The current
trading-stand evidence remains a seven-scenario baseline. Contour #8 is the
next research model to design after that baseline: an agent must not treat a
model-generated URL, package name, API endpoint, webhook, or service domain as
verified infrastructure merely because an LLM produced it.

The safe project version uses synthetic brands and mock DNS, registry, package,
and API surfaces. It does not register real domains, probe real brands, publish
working phishing payloads, or test live third-party infrastructure.

## Next candidate violation models

These are candidate directions. They are not shipped until they have an issue, branch,
implementation, tests, examples, validation, and a merged PR.

### P1 candidates

| Candidate | Plain-language problem | Boundary invariant | Why it is different | Existing anchor | Graduation artifact |
|---|---|---|---|---|---|
| `phantom_resource.model_generated_resource_trust` | An agent treats a model-generated URL, package name, API endpoint, webhook, or service domain as verified infrastructure. | Model-generated resources remain untrusted until independently resolved through provenance, allowlist, registry, DNS, or signed-source checks. | The risky artifact is generated by the model and then becomes supply-chain input; this is not ordinary retrieved-context authority. | Unit 42 phantom squatting research; adjacent to slopsquatting and agentic URL-fetch risk. | Synthetic phantom-resource report with mock DNS/registry/API resolution, bounded-vs-naive rows, ablation, benign allowlisted resource, and no real domains. |
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
4. **Ablation:** for an executable specification, shows the rule-derived outcome when a
   declared control is removed; an independent causal claim requires separate evaluation.
5. **Benign path:** shows the bounded control does not block an ordinary safe case.
6. **Artifacts:** writes public-safe JSON/Markdown summaries under `examples/`.
7. **Validation:** `ash validate examples/` understands the artifact or the artifact is
   covered by an existing validator.
8. **Docs:** README/evidence map/research claims explain the claim and non-claim.
9. **Evidence classification:** lifecycle, evidence class, schema state, causal scope,
   label source/coverage, reconciliation state, and origin-authentication state are explicit.
10. **Checks:** targeted tests, `ruff`, `mypy`, `git diff --check`, and GitHub checks pass.
11. **Merge:** PR lands on `main`; release notes move it from active research to shipped.

## Decision rule for the next contour

When choosing the next build, prefer the candidate that adds the most new boundary
coverage with the least new machinery.

Current likely order:

1. `phantom_resource.model_generated_resource_trust`
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

This map is project-specific: the deciding unit is the boundary invariant, declared
evidence class/schema/causal scope, and the validation strength of the referenced artifact,
not the standard label or validation status alone.
