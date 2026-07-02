# Evidence map

This page is the short reviewer map from public claims to artifacts. It keeps three
things separate:

- deterministic benchmark evidence;
- sanitized local-model evidence-quality snapshots;
- private calculations that must stay under `.internal/`.

The field-level publication rule is defined in
[Private/Public Evidence Boundary](../private-public-evidence-boundary.md).

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
| Sanitized local-model mini-swarm campaign | `examples/swarm-defense-live-sanitized/`, `examples/swarm-defense-live-long-session-sanitized/`, `examples/swarm-defense-live-deep-sanitized/` + `docs/live-mini-swarm-defense-campaign.md` | `ash validate examples/swarm-defense-live-sanitized`, `ash validate examples/swarm-defense-live-long-session-sanitized`, and `ash validate examples/swarm-defense-live-deep-sanitized` | Base: `180` observations, chief acceptances `22`, worker drift detections `1`, canary leaks `0`, verifier blocks `22`, replay-ablation reopenings `96`, adapter errors `0`, response-hash coverage `100%`. Long-session supplement: `15` observations, each with `3` worker turns, chief acceptances `1`, canary leaks `0`, verifier blocks `1`, replay-ablation reopenings `4`, adapter errors `1`. Deep: `168` observations, chief acceptances `67`, worker drift detections `3`, canary leaks `0`, verifier blocks `70`, unsafe block rate `70/70`, benign allow rate `91/91`, replay-ablation reopenings `242`. | The private local worker/chief probes exercise the four-family contour with real local model text, while public artifacts expose safe model ids, roles, topology ids, pressure labels, response/per-turn hashes, aggregate labels, verifier block attribution, adapter flags, replay-ablation control attribution, Wilson intervals, and model breakdowns. Public artifacts do not include raw transcripts, but every private response is anchored by a public SHA-256 hash for owner-side audit replay. | A CVE, a real-secret leak, a model leaderboard, production swarm safety, or exhaustive attack coverage. |
| Marketing web-injection swarm | `examples/marketing-web-injection-sanitized/` + `docs/marketing-web-injection-campaign.md` | `ash validate examples/marketing-web-injection-sanitized` | `5` scenarios, `36` observations, naive leaks `5/5`, bounded leaks `0/5`, ablation leaks `21/21`, benign runs `5/5` allowed, response-hash coverage `100%` | The declared offline marketing/ads web-ingestion cases show how source-label loss, authority hijack, summary drift, and synthetic strategy leakage are blocked by the bounded contract and reopen under targeted control ablations. | Real internet safety, real-secret extraction, CVE status, production swarm safety, or exhaustive web-injection coverage. |
| Live local-model marketing web-injection | `examples/marketing-web-live-sanitized/` + `docs/marketing-web-live-campaign.md` | `ash validate examples/marketing-web-live-sanitized` | `2` scenarios, `60` observations, worker leaks `3`, chief leaks `1`, ablation final leaks `1`, bounded final leaks `0`, benign final leaks `0`, false blocks `0`, response/turn hash coverage `100%` | An owned local-web worker/chief run shows a synthetic strategy component can reach final chief output when the responsible control is removed, while the full bounded verifier path blocks final leakage and allows benign rows in the committed run. | A CVE, real-secret extraction, real internet safety, production swarm safety, a model leaderboard, or exhaustive web-injection coverage. |
| Swarm resilience/stability model | `examples/swarm-resilience-sanitized/` + `docs/swarm-resilience-campaign.md` | `ash validate examples/swarm-resilience-sanitized` | `7` degradation families, `46` observations, naive unsafe `7`, bounded unsafe `0`, ablation unsafe `18`, benign false blocks `0`, state-hash coverage `100%` | The declared state-vector model shows when a bounded swarm returns to a safe region and which controls reopen failure when ablated across memory, semantics, source trust, consensus, metric/verdict, cumulative benign-fact, and cascade attacks. | Production swarm safety, exhaustive attack coverage, real-secret extraction, or proof that the state-vector abstraction covers all model behavior. |
| Context consent boundary | `examples/context-consent-sanitized/` + `docs/context-consent-campaign.md` | `ash validate examples/context-consent-sanitized` | `5` cases, `6` controls, `45` deterministic rows, naive risky-action acceptances `5`, bounded acceptances `0`, ablation acceptances `18`, benign false blocks `0` | The declared context-consent matrix shows that repo issues, stale approvals, task batches, handoff claims, and ambient chat history cannot authorize protected actions under the full bounded contract, and reopen when responsible consent controls are removed. | Production consent enforcement, user-understanding proof, model safety, exhaustive workflow coverage, or proof that deployed agents preserve intent. |
| Tool-output authority boundary | `examples/tool-authority-sanitized/` + `docs/tool-authority-campaign.md` | `ash validate examples/tool-authority-sanitized` | `6` cases, `8` controls, `66` deterministic rows, naive risky-action acceptances `6`, bounded acceptances `0`, ablation acceptances `23`, benign false blocks `0` | The declared tool-output authority matrix shows that CLI output, scanner reports, schema annotations, error text, worker summaries, and metric rows cannot authorize protected actions under the full bounded contract, and reopen when responsible controls are removed. | Production tool-agent safety, real MCP/schema verification, model safety, exhaustive tool-output coverage, or proof that deployed agents preserve authority boundaries. |
| RAG context authority boundary | `examples/rag-context-sanitized/` + `docs/rag-context-campaign.md` | `ash validate examples/rag-context-sanitized` | `7` cases, `10` controls, `91` deterministic rows, naive unsafe-chain acceptances `7`, bounded acceptances `0`, ablation acceptances `30`, benign false blocks `0` | The declared retrieved-context propagation matrix shows that ranked snippets, citations, summaries, planner subtasks, top-k corroboration, memory notes, and handoff summaries cannot authorize protected actions under the full bounded contract, and reopen when responsible controls are removed. | Production RAG-agent safety, provider/model vulnerability claims, model safety, exhaustive retrieval coverage, or proof that deployed agents preserve authority boundaries. |

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

`ash validate` is an artifact-integrity check. It does not re-run models and does not
certify safety.
