# Evidence appendix

This appendix is a compact public entry point for the strongest committed evidence
artifacts. It summarizes existing sanitized reports under `examples/` and the commands
used to validate them.

It is not a production safety proof, a model leaderboard, a CVE claim, or evidence that
any deployed agent is secure. The goal is narrower: show replayable, inspectable
boundary-failure measurements over synthetic or authorized artifacts.

## What this shows

| Evidence artifact | What it measures | Key public result | Validate |
|---|---|---|---|
| [`examples/comparison-report/`](../../examples/comparison-report/) | Deterministic vulnerable-vs-protected demo targets on the same 24-pattern corpus. | `demo-agent` records `24` modeled findings; `protected-demo-agent` records `0`. | `ash validate examples/comparison-report` |
| [`examples/evidence-campaign-sanitized/`](../../examples/evidence-campaign-sanitized/) | Bounded-vs-naive behavior across 24 declared boundary cases and 4 claim families. | `monolith` and `naive_swarm` show `69.57%` failure rate; `bounded_swarm` shows `0.00%`. Bounded mode records `16` TP, `0` FP, `7` TN, `0` FN, and `1` inconclusive row. | `ash validate examples/evidence-campaign-sanitized` |
| [`examples/semantic-propagation-sanitized/`](../../examples/semantic-propagation-sanitized/) | Whether worker-side semantic drift can propagate into a downstream chief decision. | `32` deterministic rows, `6` controls, bounded propagation acceptances `0`, ablation propagation acceptances `20`, and `8` local-model observations. | `ash validate examples/semantic-propagation-sanitized` |
| [`examples/secret-leak-campaign-sanitized/`](../../examples/secret-leak-campaign-sanitized/) | Synthetic secret-egress classes using synthetic canaries only. | Naive leaks `4/4`, bounded leaks `0/4`, ablation leaks `11/11`, benign leaks `0/4`. | `ash validate examples/secret-leak-campaign-sanitized` |
| [`examples/context-consent-sanitized/`](../../examples/context-consent-sanitized/) | Whether contextual approval claims are mistaken for current user consent. | `5` cases, `6` controls, `45` deterministic rows, naive risky-action acceptances `5`, bounded acceptances `0`, ablation acceptances `18`, benign false blocks `0`. | `ash validate examples/context-consent-sanitized` |
| [`examples/tool-authority-sanitized/`](../../examples/tool-authority-sanitized/) | Whether tool output is mistaken for command, policy, schema, handoff, or metric authority. | `6` cases, `8` controls, `66` deterministic rows, naive risky-action acceptances `6`, bounded acceptances `0`, ablation acceptances `23`, benign false blocks `0`. | `ash validate examples/tool-authority-sanitized` |
| [`examples/rag-context-sanitized/`](../../examples/rag-context-sanitized/) | Whether retrieved context is mistaken for command, policy, planner, memory, handoff, or permission authority. | `7` cases, `10` controls, `91` deterministic rows, naive unsafe-chain acceptances `7`, bounded acceptances `0`, ablation acceptances `30`, benign false blocks `0`. | `ash validate examples/rag-context-sanitized` |
| [`examples/planner-task-sanitized/`](../../examples/planner-task-sanitized/) | Whether task decomposition turns context, stale approval, tool output, retrieval, handoff, batch, or dependency state into subtask authority. | `7` cases, `10` controls, `91` deterministic rows, naive unsafe-chain acceptances `7`, bounded acceptances `0`, ablation acceptances `32`, benign false blocks `0`. | `ash validate examples/planner-task-sanitized` |
| [`examples/memory-rehydration-sanitized/`](../../examples/memory-rehydration-sanitized/) | Whether recalled, expired, cross-scope, summarized, merged, handoff, or dependency memory is mistaken for current authority. | `7` cases, `10` controls, `91` deterministic rows, naive unsafe-chain acceptances `7`, bounded acceptances `0`, ablation acceptances `32`, benign false blocks `0`. | `ash validate examples/memory-rehydration-sanitized` |
| [`examples/swarm-defense-live-sanitized/`](../../examples/swarm-defense-live-sanitized/) | Sanitized local-model mini-swarm observations with private raw transcripts retained locally. | `180` observations, verifier blocks `22`, canary leaks `0`, adapter errors `0`, response hash coverage `1.00`, replay-ablation reopenings `96`. | `ash validate examples/swarm-defense-live-sanitized` |
| [`examples/swarm-defense-live-long-session-sanitized/`](../../examples/swarm-defense-live-long-session-sanitized/) | Long-session supplement for the sanitized mini-swarm campaign. | `15` long-session observations, max session turns `3`, verifier blocks `1`, canary leaks `0`, response hash coverage `1.00`. | `ash validate examples/swarm-defense-live-long-session-sanitized` |

## Why these artifacts matter

The useful evidence pattern is not a single screenshot. It is the combination of:

- before/after comparison on the same scenario corpus;
- pass/finding/inconclusive separation;
- benign rows that still pass under bounded controls;
- ablation rows that reopen unsafe paths when a responsible control is disabled;
- sanitized local-model observations anchored by response hashes;
- validation commands that check artifact integrity and forbidden-marker hygiene.

That combination supports the claim that the harness can turn declared agentic boundary
failure situations into inspectable evidence. It does not support a claim that a model,
provider, framework, or production deployment is safe.

## Private/public boundary

Public artifacts may include:

- aggregate counters and rates;
- scenario ids, topology ids, roles, pressure labels, and model/runtime labels;
- response hashes and hash-coverage rates;
- deterministic pass/finding/inconclusive/error classifications;
- control-attribution and replay-ablation metrics;
- conservative non-claims and validation commands.

Private artifacts stay out of Git:

- raw prompts and prompt chains;
- raw model responses and raw transcripts;
- synthetic canary values and secret-shaped strings;
- private calculation notes;
- local absolute paths and machine-specific logs;
- operational text that would read like a bypass recipe.

The field-level rule is documented in
[`docs/private-public-evidence-boundary.md`](../private-public-evidence-boundary.md).

## Validation commands

```bash
ash validate examples/comparison-report
ash validate examples/evidence-campaign-sanitized
ash validate examples/semantic-propagation-sanitized
ash validate examples/secret-leak-campaign-sanitized
ash validate examples/context-consent-sanitized
ash validate examples/tool-authority-sanitized
ash validate examples/rag-context-sanitized
ash validate examples/planner-task-sanitized
ash validate examples/memory-rehydration-sanitized
ash validate examples/swarm-defense-live-sanitized
ash validate examples/swarm-defense-live-long-session-sanitized
```

`ash validate` is an artifact-integrity and hygiene check. It does not re-run models and
does not certify safety.
