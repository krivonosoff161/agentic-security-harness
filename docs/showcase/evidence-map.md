# Evidence map

This page is the short reviewer map from public claims to artifacts. It keeps three
things separate:

- deterministic benchmark evidence;
- sanitized local-model evidence-quality snapshots;
- private calculations that must stay under `.internal/`.

See [Evidence classes and causal claims](../evidence-classes.md): deterministic ablation
metrics are executable-specification results, and detector accuracy requires independent
labels rather than detector-derived unsafe/benign buckets.

The same distinctions are encoded per component in the
[machine-readable evidence status registry](../evidence-status-registry.json). The
registry is validated with `ash validate docs/evidence-status-registry.json`; validation
checks classification semantics and referenced paths, not the truth of an empirical
observation.

The lifecycle and promotion view is maintained in the
[research problem map](../research-problem-map.md). A committed public example is a
publication state, not evidence that its schema is current or its observation origin is
authenticated.

The field-level publication rule is defined in
[Private/Public Evidence Boundary](../private-public-evidence-boundary.md).

## Public Evidence Tracks

| Track | Source artifact | Reproduce / validate | Current metrics | Public claim | Non-claim |
|---|---|---|---|---|---|
| Deterministic corpus comparison | `examples/comparison-report/` | `ash validate examples/comparison-report` | `24` modeled findings on `demo-agent`, `0` on `protected-demo-agent` | The shipped synthetic corpus can show a reproducible before/after reduction between local demo targets. | A deployed agent is secure. |
| Bounded local swarm | `examples/local-swarm-report/` | `ash validate examples/local-swarm-report` | `15` modeled naive-swarm failures, `0` bounded-swarm failures | The deterministic fixture reproduces its declared swarm contract. | Independent causal effect, or that a production swarm/model is safe. |
| Local swarm variation matrix | `examples/local-swarm-attack-matrix/` | `ash validate examples/local-swarm-attack-matrix` | `43` rows, `9` families, `10` executable deep probes, bounded failures `0` | The current variations are encoded as replayable deterministic checks. | Exhaustive attack coverage. |
| Evidence campaign | `examples/evidence-campaign-sanitized/` | `ash validate examples/evidence-campaign-sanitized` | `24` cases, `72` rule-derived observations, false-block rate `0%` | The executable specification calculates its declared bounded-vs-ablation and usability metrics. | Independent detector accuracy, independent causal effect, or production-safety proof. |
| Synthetic secret-egress | `examples/secret-leak-campaign-sanitized/` | `ash validate examples/secret-leak-campaign-sanitized` | naive leaks `4/4`, bounded leaks `0/4`, ablation leaks `11/11` | Declared controls block declared synthetic secret-egress paths. | Real-secret extraction or CVE. |
| Secret-egress local variations | `examples/secret-leak-variations-sanitized/` | `ash validate examples/secret-leak-variations-sanitized` | `64` declared observations, leaks `0`, adapter errors `0`; private-byte and execution-origin reconciliation is absent | The public summary retains declared model identifiers, detector labels, hash fields, and aggregates without exposing raw text. | Current empirical status, retained-byte equality, execution/model authenticity, detector accuracy, or absence of model vulnerabilities. |
| Semantic drift mini-swarm | `examples/semantic-drift-sanitized/` | `ash validate examples/semantic-drift-sanitized` | `80` historical observations, drift detector matches `13`, canary leaks `4`, verifier blocks `15`, independent-label coverage `0%`; current schema is unexecuted | The legacy artifact retains declared detector labels, aggregates, and internally consistent deterministic rows under structural validation. | Current-corpus executable conformance, current empirical evidence, detector precision/recall, execution authenticity, or that a real model or production swarm is safe. |
| Semantic propagation defense | `examples/semantic-propagation-sanitized/` + `docs/semantic-propagation-defense-model.md` + `docs/semantic-drift-propagation-closure.md` | `ash validate examples/semantic-propagation-sanitized` | `6` controls, bounded acceptances `0`, rule-derived ablation acceptances `20`, `8` observations, adapter errors `1`, independent-label coverage `0%` | Legacy deterministic rows are internally consistent with their embedded cases; local-model rows expose detector observations separately. | Current-corpus executable conformance. Adapter errors are passes. Detector accuracy, a CVE, leaderboard, or production-swarm proof. |
| Consensus laundering historical snapshot | `examples/semantic-propagation-sanitized/` + `docs/semantic-consensus-laundering-closure.md` | `ash validate examples/semantic-propagation-sanitized` | consensus case rows `8`, bounded acceptance `0`, naive acceptance `1`, `cross_worker_check` ablation acceptance `1` | The legacy artifact retains internally consistent full-contract and control-disabled branches. | Current-corpus executable conformance, independent causal effect, exhaustive consensus coverage, or production swarm safety. |
| Local swarm defense contour | `examples/swarm-defense-contour-sanitized/` + `docs/local-swarm-defense-contour.md` | `ash validate examples/swarm-defense-contour-sanitized` | `4` scenario families, `15` non-empty combination topologies, bounded acceptances `0`, naive acceptances `15`, ablation acceptances `112` | The executable specification evaluates the four declared families and records rule-derived control-dependency counts. | Independent causal proof, a live local model is safe, a production swarm is safe, or the four families are exhaustively covered. |
| Historical loopback-endpoint mini-swarm campaign | `examples/swarm-defense-live-sanitized/`, `examples/swarm-defense-live-long-session-sanitized/`, `examples/swarm-defense-live-deep-sanitized/` + `docs/live-mini-swarm-defense-campaign.md` | Legacy structural validation only | The committed schemas `0.2/0.3` contain historical drift/chief/adapter observations; schema `0.5` is unexecuted. Legacy canary-zero rates are withdrawn and “reopenings” are only named-control attribution counts. | The examples preserve a historical loopback first-hop slice. They do not exercise current staged-error, execution-identity, partial-event, or transitive-source contracts. | Current verified evidence, absence of canary leakage, causal control effects, local model-execution attestation, tamper authenticity, independent ground truth, or production safety. |
| Marketing web-injection swarm | `examples/marketing-web-injection-sanitized/` + `docs/marketing-web-injection-campaign.md` | `ash validate examples/marketing-web-injection-sanitized` | `5` scenarios, `36` observations, naive leaks `5/5`, bounded leaks `0/5`, ablation leaks `21/21`, benign runs `5/5` allowed, response-hash coverage `100%` | The executable specification selects declared mode-specific branches and reproduces rule-encoded control dependencies. Ablation counts are not empirical causal effects. | Real internet safety, real-secret extraction, CVE status, production swarm safety, or exhaustive web-injection coverage. |
| Historical loopback-endpoint marketing web-injection | `examples/marketing-web-live-sanitized/` + `docs/marketing-web-live-campaign.md` | `ash validate examples/marketing-web-live-sanitized` | Historical schema `0.2`: `2` scenarios and `60` observations; current schema `0.3` is unexecuted. | The example records detector outputs over an owned local page stand. Verifier and ablation outcomes are rule-derived contract behavior; validation is structural-only for this legacy schema. | A current-contract execution, causal control effect, independent verifier effectiveness, local model-execution attestation, tamper authenticity, or production safety. |
| Swarm resilience/stability model | `examples/swarm-resilience-sanitized/` + `docs/swarm-resilience-campaign.md` | `ash validate examples/swarm-resilience-sanitized` | `7` degradation families, `46` observations, naive unsafe `7`, bounded unsafe `0`, ablation unsafe `18`, benign false blocks `0`, state-hash coverage `100%` | The executable state-vector specification recomputes declared mode branches and rule-encoded control dependencies across seven families. It is not empirical or causal-effect evidence. | Production swarm safety, exhaustive attack coverage, real-secret extraction, or proof that the state-vector abstraction covers all model behavior. |
| Context consent boundary | `examples/context-consent-sanitized/` + `docs/context-consent-campaign.md` | `ash validate examples/context-consent-sanitized` | `5` cases / `45` rows; 5 naive, 0 bounded, 18 ablation acceptances | The executable specification reproduces the declared consent rules and rule-derived ablations. | Independent causal effect, production consent enforcement, or deployed-agent safety. |
| Tool-output authority boundary | `examples/tool-authority-sanitized/` + `docs/tool-authority-campaign.md` | `ash validate examples/tool-authority-sanitized` | `6` cases / `66` rows; 6 naive, 0 bounded, 23 ablation acceptances | The executable specification reproduces the declared tool-authority rules and rule-derived ablations. | Independent causal effect, production tool-agent safety, or exhaustive coverage. |
| RAG context authority boundary | `examples/rag-context-sanitized/` + `docs/rag-context-campaign.md` | `ash validate examples/rag-context-sanitized` | `7` cases / `91` rows; 7 naive, 0 bounded, 30 ablation acceptances | The executable specification reproduces the declared retrieval-authority rules and rule-derived ablations. | Independent causal effect, production RAG-agent safety, or provider/model claims. |
| Planner task authority boundary | `examples/planner-task-sanitized/` + `docs/planner-task-campaign.md` | `ash validate examples/planner-task-sanitized` | `7` cases / `91` rows; 7 naive, 0 bounded, 32 ablation acceptances | The executable specification reproduces the declared planner-authority rules and rule-derived ablations. | Independent causal effect, production planner safety, or exhaustive coverage. |
| Memory rehydration authority boundary | `examples/memory-rehydration-sanitized/` + `docs/memory-rehydration-campaign.md` | `ash validate examples/memory-rehydration-sanitized` | `7` cases / `91` rows; 7 naive, 0 bounded, 32 ablation acceptances | The executable specification reproduces the declared memory-authority rules and rule-derived ablations. | Independent causal effect, production memory-agent safety, or exhaustive coverage. |

## Private Calculation Boundary

The public artifacts deliberately omit raw local-model prompts, raw responses,
canonical-state hashes, and synthetic canary values. Those are private calculation
artifacts and must remain under `.internal/`.

Public summaries may include:

- safe model ids, runtime roles, topology ids, scenario ids, and pressure labels;
- aggregate counters and per-observation classifications;
- response hashes, per-turn response hashes, and hash-coverage rates;
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

`ash validate` applies the contract supported by each schema. Current deterministic
artifacts receive internal-consistency checks; legacy local-model summaries receive
limited structural validation. For tracked public examples, `--format json` also emits
the registry classification and `unverified-private-projection` where private bytes are
not reconciled. It does not re-run models, authenticate execution origin, or certify
safety.
