# Evidence map

This page is the short reviewer map from public claims to artifacts. It keeps three
things separate:

- deterministic benchmark evidence;
- sanitized local-model evidence-quality snapshots;
- private calculations that must stay under `.internal/`.

## Public Evidence Tracks

| Track | Source artifact | Reproduce / validate | Current metrics | Public claim | Non-claim |
|---|---|---|---|---|---|
| Deterministic corpus comparison | `examples/comparison-report/` | `ash validate examples/comparison-report` | `24` modeled findings on `demo-agent`, `0` on `protected-demo-agent` | The shipped synthetic corpus can show a reproducible before/after reduction between local demo targets. | A deployed agent is secure. |
| Bounded local swarm | `examples/local-swarm-report/` | `ash validate examples/local-swarm-report` | `15` modeled naive-swarm failures, `0` bounded-swarm failures | Deterministic contracts block the declared swarm handoff/memory/tool failures. | A production swarm or model is safe. |
| Local swarm variation matrix | `examples/local-swarm-attack-matrix/` | `ash validate examples/local-swarm-attack-matrix` | `43` rows, `9` families, `10` executable deep probes, bounded failures `0` | The current variations are encoded as replayable deterministic checks. | Exhaustive attack coverage. |
| Evidence campaign | `examples/evidence-campaign-sanitized/` | `ash validate examples/evidence-campaign-sanitized` | `24` cases, `72` observations, false-block rate `0%` | The campaign calculates bounded-vs-ablation control effect and usability cost. | Production-safety proof. |
| Synthetic secret-egress | `examples/secret-leak-campaign-sanitized/` | `ash validate examples/secret-leak-campaign-sanitized` | naive leaks `4/4`, bounded leaks `0/4`, ablation leaks `11/11` | Declared controls block declared synthetic secret-egress paths. | Real-secret extraction or CVE. |
| Secret-egress local variations | `examples/secret-leak-variations-sanitized/` | `ash validate examples/secret-leak-variations-sanitized` | `64` local-model observations, leaks `0`, adapter errors `0` | Private local-model pressure runs can be summarized without exposing raw prompts/responses. | Absence of model vulnerabilities. |
| Semantic drift mini-swarm | `examples/semantic-drift-sanitized/` | `ash validate examples/semantic-drift-sanitized` | `80` observations, drift detections `13`, canary leaks `4`, verifier blocks `15` | Slow relabeling pressure can be observed and bounded by deterministic verifier decisions. | A real model or production swarm is safe. |
| Semantic propagation defense | `examples/semantic-propagation-sanitized/` + `docs/semantic-propagation-defense-model.md` + `docs/semantic-drift-propagation-closure.md` | `ash validate examples/semantic-propagation-sanitized` | `6` controls, bounded acceptances `0`, ablation acceptances `20`, `8` observations, adapter errors `1` | Declared worker-to-chief drift propagation paths are blocked by the full bounded contract and reopen when responsible controls are ablated; the closure note ties the drift and propagation layers into one reviewer-readable research unit. | Adapter errors are passes; this is a CVE, leaderboard, or production-swarm proof. |
| Consensus laundering sub-unit | `examples/semantic-propagation-sanitized/` + `docs/semantic-consensus-laundering-closure.md` | `ash validate examples/semantic-propagation-sanitized` | consensus case rows `8`, bounded acceptance `0`, naive acceptance `1`, `cross_worker_check` ablation acceptance `1` | The declared two-worker path cannot turn disagreement into acceptance under the full bounded contract, and reopens when the cross-worker check is disabled. | Exhaustive consensus coverage or production swarm safety. |
| Local swarm defense contour | `examples/swarm-defense-contour-sanitized/` + `docs/local-swarm-defense-contour.md` | `ash validate examples/swarm-defense-contour-sanitized` | `4` scenario families, `15` non-empty combination topologies, bounded acceptances `0`, naive acceptances `15`, ablation acceptances `68` | The four declared semantic/local-swarm defense families are evaluated together, and each bounded block is tied to deterministic controls plus ablation reopenings. | A live local model is safe, a production swarm is safe, or the four families are exhaustively covered. |

## Private Calculation Boundary

The public artifacts deliberately omit raw local-model prompts, raw responses,
canonical-state hashes, and synthetic canary values. Those are private calculation
artifacts and must remain under `.internal/`.

Public summaries may include:

- aggregate counters;
- response hashes or hash-coverage rates;
- adapter-error counts;
- deterministic control-ablation metrics;
- conservative non-claims.

Public summaries must not include:

- raw secret-shaped canaries;
- raw model responses;
- private prompts;
- local absolute paths or machine-specific logs;
- claims that a model, provider, or deployed agent is secure.

## Reviewer Commands

```bash
ash validate examples/
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
ash showcase --root reports --out docs/showcase/generated
```

`ash validate` is an artifact-integrity check. It does not re-run models and does not
certify safety.
