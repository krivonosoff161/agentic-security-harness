# Current state

> Last reviewed: 2026-07-14.
>
> Scope: public status of `agentic-security-harness` on `main`, version `0.14.0`. This
> page is a reviewer-facing status snapshot, not a roadmap promise.

## One-line status

Agentic Security Harness is a **public research release**: a working trace-first,
defensive benchmark for agentic AI boundary failures with committed
deterministic examples, bounded local-swarm evidence, evidence-campaign metrics, and
sanitized local-model semantic-drift / propagation probes.

It is strong enough to show as a public research benchmark/toolkit. It is not a
production certification benchmark, a general pentest tool, or a claim that a target is
secure.

Evidence classes are explicit in [evidence-classes.md](evidence-classes.md): deterministic
control-ablation contours are executable specifications with rule-derived attribution;
local-model classifications are empirical detector observations only when a versioned
public projection exists; docs-only maintainer counts are unverified declarations.
Detector-accuracy claims require independently reviewed labels and non-zero label coverage.

## Shipped, historical, and documented status

| Area | Status | Evidence |
|---|---|---|
| Local deterministic corpus | Shipped | 24 sanitized seed patterns in `corpus.py` and `patterns.py`. |
| Local targets | Shipped | `mock`, `demo-agent`, `protected-demo-agent`, `toy-local-function`, `toy-rag`, `toy-tools`, `toy-multi-agent`, `protected-toy-multi-agent`. |
| Baseline vs protected replay | Shipped | `ash compare --baseline demo-agent --protected protected-demo-agent`. |
| Inter-agent handoff verifier toy topology | Shipped local slice | `handoff_integrity.py`, `toy-multi-agent`, and `protected-toy-multi-agent` model deterministic label-loss and authority-expansion handoffs. |
| Boundary-layer variation matrices | Shipped local slice | `boundary-layer-evidence-matrix.md` and `tests/test_boundary_variation_matrices.py` tie declared handoff, authority, and memory-governance variation rows to executable deterministic checks. |
| Scenario timeline contract | Shipped local slice | `ScenarioTimeline`, `validate_timeline()`, three committed fixtures, and `replay_timeline()` model multi-turn/delayed/context-overload/handoff scenarios with explicit invariant and decision step. |
| Portable artifacts | Shipped | `traces.json`, `scorecard.json`, `summary.md`, `executive.md`, remediation, run manifests. |
| Artifact authenticity | Workflow implementation awaiting a real tag run | The tag workflow now creates GitHub/Sigstore attestations for the exact wheel, sdist, and checksum subjects after its gates, then verifies repository/workflow/tag/source/builder/predicate policy in a separate job. Historical releases and examples remain unsigned, no current evidence-registry row is `signed_attested`, and private/reviewer authenticity remains a separate unimplemented trust domain. |
| Static reports | Shipped | `ash report --root <run-dir>` first validates the supplied artifact tree, then writes a self-contained HTML report; integrity failures stop publication and behavioral expectation mismatches are shown as non-clean results. |
| Run history and maintenance | Shipped | `list-runs`, `index-runs`, `stats`, and `retention` consume only current content-bound validated runs. Stats v0.1 retains portable source-manifest commitments and rebuildable aggregates in a content-bound output; retention rebuilds the exact current plan, rechecks candidate identity and validation immediately before removal, and requires explicit acceptance of unsigned `created_at` chronology. Absolute paths remain internal to apply while normal text/JSON uses a portable root marker and relative candidates. Recursive deletion remains non-transactional under a concurrent local writer. |
| Run/model diff | Shipped | Schema 0.3 compares only validator-accepted manifested sources, records source-manifest commitments and unsigned validation scope, and writes an exact content-bound diff bundle; source/output overlap is refused. |
| External OpenAI-compatible prompt check | Experimental | `run-external` is dry-run by default; `--execute` is required for prompt-only network calls, live bundles are restricted to `.internal`, and no tool execution is available. Current schema 0.2 creates one pre-request execution identity and a content-bound manifest; the committed schema-0.1 fake-endpoint example remains legacy structural evidence. |
| Public run-your-model path | Shipped docs slice | `docs/run-your-model.md` gives one operator path for deterministic demo, one local/remote OpenAI-compatible model, and local mini-swarm campaigns on Windows and Linux/macOS. |
| External evidence cross-check | Shipped for experimental path | Pattern id, boundary assertion, control family, decision coherence, raw response files. |
| Derived evidence quality | Shipped | Schema 0.3 aggregates only validator-accepted bundles with `run_index.json`; rows distinguish current/legacy validation and unsigned origin, paths are portable, aggregates are independently rebuildable, and exact JSON/Markdown output is content-bound. |
| Local-runtime metadata | Shipped for experimental path | `run_config.runtime`, report/runtime metadata, `local-only` mode for localhost/Ollama/LM Studio/vLLM, recovery guidance. |
| Bounded local-model suite | Shipped local slice | `ash local-suite`, named Prometheus/Ollama profiles, dry-run by default, request caps, validated artifacts after explicit `--execute`, and weak-evidence classification. |
| Trading paper-stand safety map | Shipped non-executing profile; empirical work blocked | Artifact identity joins and the canonical 2-batch/187-module static import topology are machine-readable. Filled rows remain self-declared without receipts; public hashes cover sanitized projections only; provider/messaging/configuration/execution isolation remains fail-closed. No target module is imported or executed. |
| Bounded local swarm | Shipped research slice | `ash local-swarm` compares monolith, naive swarm, and bounded swarm across 15 deterministic handoff, memory, approval/tool, multi-hop laundering, and verifier-outage scenarios. |
| Attack variation matrix | Shipped research slice | `ash local-swarm-matrix` expands the 15 swarm scenarios into 43 rows across 9 families, including 10 executable deep probes over handoff and memory verifier mutations. |
| Evidence campaign | Shipped executable specification | `ash evidence-campaign` calculates consistency counters, modeled attack/benign behavior, rule-derived control attribution, and usability deltas across 24 scenario-author-labelled cases / 72 observations / 4 claim families. These are not independent detector-accuracy or causal-effect measurements. |
| Synthetic secret-leak campaign | Shipped research slice | `ash secret-leak-campaign` models four synthetic secret-egress topologies: naive leaks 4/4, bounded leaks 0/4, ablation leaks 11/11, benign leaks 0/4. |
| Secret-leak variation probes | Unreconciled detector summary | The public artifact records 8 cases, declared model identifiers, detector labels, aggregates, and hash fields. Public validation does not replay retained private bytes or attest execution origin/model locality. |
| Semantic parameter drift probes | Historical detector summary plus rule snapshot | The committed artifact predates current schema 0.2. Its 80 observation rows and aggregates are historical declarations; deterministic rows are internally checked legacy data, not a current-corpus executable specification. |
| Semantic propagation probes | Historical detector summary plus rule snapshot | The committed artifact predates current schema 0.3. Its 8 observation rows and aggregates are historical declarations; deterministic ablations are internally checked legacy rule rows, not current-corpus execution. |
| Semantic drift propagation closure | Deterministic invariant retained; empirical closure withdrawn | The closure documents declared cases and deterministic bounded-vs-ablation rows. Legacy local observations are unreconciled and do not establish current model/runtime behavior. |
| Semantic consensus laundering snapshot | Historical sub-unit | `semantic-consensus-laundering-closure.md` isolates legacy two-worker consensus rows: bounded acceptance 0, naive acceptance 1, and `cross_worker_check` ablation acceptance 1. Structural validation does not bind them to the current corpus. |
| Local swarm defense contour | Shipped executable specification | `ash swarm-defense-contour` combines four failure families across 15 combinations. Its 0 bounded, 15 naive, and 112 ablation acceptances are deterministic, rule-derived specification results—not independent causal estimates. |
| Sanitized loopback-endpoint mini-swarm campaign | Historical local empirical slice; current contract unexecuted | The committed examples predate schema 0.5. Their adapter/drift counts remain historical observations, but old canary-zero claims are withdrawn because the legacy aggregator mismatched detector categories. “Replay reopenings” are rule-attribution counts, not paired causal effects; independent-label coverage is 0%. |
| Marketing web-injection swarm campaign | Shipped synthetic defense slice | `ash marketing-web-injection-campaign` models an offline marketing/ads web-ingestion swarm with hostile page text, synthetic internal strategy/contract values, naive/bounded/ablation/benign modes, sanitized public summaries, and validation support. The committed example records naive leaks 5/5, bounded leaks 0/5, ablation leaks 21/21, benign runs 5/5 allowed, and response-hash coverage 100%. |
| Live loopback-endpoint marketing web-injection campaign | Historical local empirical slice; current contract unexecuted | The committed schema-0.2 owned-localhost example has 60 observations and detector-derived leak counts. Verifier/ablation outcomes are rule-derived policy simulation, not independent effectiveness or causal estimates; schema 0.3 has no committed live rerun. |
| Context consent boundary | Shipped executable specification | 5 cases / 45 rows; 5 naive, 0 bounded, and 18 rule-derived ablation acceptances; benign false blocks 0. |
| Tool-output authority boundary | Shipped executable specification | 6 cases / 66 rows; 6 naive, 0 bounded, and 23 rule-derived ablation acceptances; benign false blocks 0. |
| RAG context authority boundary | Shipped executable specification | 7 cases / 91 rows; 7 naive, 0 bounded, and 30 rule-derived ablation acceptances; benign false blocks 0. |
| Planner task authority boundary | Shipped executable specification | 7 cases / 91 rows; 7 naive, 0 bounded, and 32 rule-derived ablation acceptances; benign false blocks 0. |
| Memory rehydration authority boundary | Shipped executable specification | 7 cases / 91 rows; 7 naive, 0 bounded, and 32 rule-derived ablation acceptances; benign false blocks 0. |
| Public evidence map | Shipped docs slice | `docs/showcase/evidence-map.md` links each front-page metric to the artifact, reproduce command, claim, and non-claim. Generated showcase output now has a source-bound JSON authority, inert exact Markdown, and its own content-bound manifest. |
| Agentic rule-violation back-pass | Shipped docs slice | `docs/agentic-rule-violation-backpass.md` reviews shipped contours through entry vector, propagation path, no-red-flag path, timing window, violated boundary, stopping controls, residual risk, and next action. |
| Evidence pack format | Shipped docs slice | `docs/evidence-pack-format.md` defines how future local research becomes sanitized public evidence with private/public boundaries, hashes, claim rows, tests, and validation commands. |
| Local real-model swarm probes | Unverified maintainer declaration | Historical documentation declares two full 15-scenario runs and complete hash-field coverage. No versioned public result projection or reconciliation receipt is present, so the repository cannot verify that the runs occurred or bind the aggregates to retained bytes. |
| Standards-aware mapping | Partial | OWASP Agentic per pattern; OWASP LLM and NIST at category level; MITRE ATLAS verified for direct-fit categories and deferred where speculative. |
| Public project process | Shipped locally; provenance change unexercised | Governance, security policy, issue templates, PR template, CI, CodeQL, Scorecard, and a tag-only release artifact workflow that binds tag/package/CHANGELOG version and reruns the repository gates. Package/release CI now requires two exact-byte-equal wheel/sdist builds after commit-epoch sdist normalization. The workflow contains least-privilege attestation and independent policy-verification jobs, but no post-change tag has executed them; existing release artifacts remain unsigned and no release SBOM is shipped. |
| Local CLI container | Shipped source definition; image unpublished | The root Dockerfile packages the source-layout CLI and runs the offline doctor as a non-root user. This is not the planned gateway image and does not attest network isolation. Docker build-context private-path exclusion is an open audit finding. |

## Experimental

These features exist, but their results must be read conservatively:

- `ash run-external`: prompt-only evaluation of an authorized OpenAI-compatible endpoint;
  local runtimes are labeled `local-only` and still require model-license /
  authorization review.
- `ash local-suite`: a bounded wrapper around the external path for local Prometheus/Ollama
  smoke profiles. A newly retained current-schema projection can be local empirical
  evidence; the older counts present only in maintainer documentation remain unverified
  declarations.
- `ash local-swarm --execute`: real local model role text can be collected through
  bounded swarm scenarios. Deterministic contracts, not the model text, make pass/block
  decisions.
- External model comparisons: useful for exploratory checks, not benchmark-grade
  leaderboards.
- `ash secret-leak-campaign --execute-variations`: private local-model pressure probes
  over synthetic secret-egress cases. Public summaries are sanitized; raw prompts,
  responses, and canaries stay under `.internal/`.
- `ash semantic-drift-campaign --execute`: private local-model semantic relabeling probes
  over synthetic mini-swarm handoff cases. Public summaries are sanitized; raw prompts,
  responses, canonical-state hashes, and canaries stay under `.internal/`.
- `ash semantic-propagation-campaign --execute`: private local-model worker-to-chief
  propagation probes over synthetic drifted summaries. Public summaries are sanitized;
  raw worker/chief prompts, responses, canonical-state hashes, and canaries stay under
  `.internal/`.
- `ash swarm-defense-live-campaign --execute`: private local worker/chief probes over
  the four-family defense contour. Public summaries expose safe model ids, topology ids,
  pressure labels, response hashes, per-turn response hashes, aggregate labels, adapter
  flags, verifier block attribution, replay-ablation metrics, and non-claims; raw
  prompts, responses, canaries, and calculation notes stay under `.internal/`.
  `--session-turns` enables bounded long-session pressure while still keeping raw turns
  private.
- `ash marketing-web-injection-campaign`: controlled offline marketing/ads
  web-ingestion campaign. It is synthetic and no-network; live web tests are not part of
  the current shipped claim.
- `ash marketing-web-live-campaign --execute`: owned-localhost web-ingestion probes
  against local worker/chief models. Raw pages, prompts, responses, and synthetic
  strategy values remain private under `.internal/`; public examples expose only hashes,
  aggregate classifications, verifier attribution, and non-claims.
- `ash tool-authority-campaign`: deterministic, no-model tool-output authority campaign
  over synthetic tool outputs. It has no private local-model run and does not call real
  tools or endpoints.
- `ash rag-context-campaign`: deterministic, no-model retrieved-context authority
  campaign over synthetic RAG-like context propagation. It has no private local-model run
  and does not call live RAG systems, provider APIs, or endpoints.
- `ash planner-task-campaign`: deterministic, no-model planner/task-decomposition
  authority campaign over synthetic subtask propagation. It has no private local-model
  run and does not call live planners, provider APIs, or endpoints.
- `ash memory-rehydration-campaign`: deterministic, no-model cross-agent memory
  rehydration authority campaign over synthetic recall, summary, merge, handoff, and
  dependency paths. It has no private local-model run and does not call live memory
  stores, provider APIs, or endpoints.
- Scenario matrix and timeline variants: deterministic local replay metadata and pattern
  subsets, not live multi-tool execution.

External results are weak evidence until a stronger observation layer exists. The harness
records contradictory or incomplete model self-reports as `inconclusive`.

## Planned, not shipped

These are roadmap items and must not be described as current capability:

- native provider SDK adapters;
- live agent-host or tool-executing adapters;
- live MCP server adapter;
- cross-provider and cross-ecosystem handoff tests beyond the local toy adapter;
- broader recovery-path pattern family implementation beyond the shipped
  `data_boundary_missing_envelope_recovery` case;
- second-reviewer MITRE ATLAS mapping review and release-to-release upkeep;
- interactive multi-run viewer;
- persistent trace store beyond local manifests / SQLite metadata index;
- reference gateway / internal LLM Safety Gateway runtime.

## Current active work

The next public-development focus is:

1. Keep current-vs-planned documentation synchronized with code and committed artifacts.
   The public-facing model backlog is [research-problem-map.md](research-problem-map.md).
2. Keep the public evidence layer close to the artifacts: comparison, local swarm,
   attack matrix, evidence campaign, secret-egress, semantic drift, and semantic
   propagation pages must agree on counts and claim boundaries.
3. Maintain bounded local Prometheus/Ollama profiles as evidence-quality smokes, not as
   a broad model leaderboard.
4. Expand the corpus by invariant and topology, not by prompt/model cross-products.
5. Expand multi-agent-handoff coverage beyond the shipped local verifier toy topology
   only when each new track has explicit safety gates.
6. Verify standards mappings without implying certification.
7. Improve public demo/showcase reports with replayable, validated artifacts and clear
   private/public evidence boundaries.
8. Keep the benchmark track separate from the future internal LLM Safety Gateway /
   Runtime Verifier track; see [project-tracks.md](project-tracks.md).

## Validation commands

Use these before trusting a local checkout or public example:

```bash
python -m pytest
python -m ruff check .
python -m mypy src tests
ash validate examples/
git diff --check
```

For a quick public demo:

```bash
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
ash report --root reports/comparison
```

Expected current demonstration: the vulnerable baseline shows findings on the shipped
24-pattern corpus; the protected demo target removes those modeled findings under the
same configuration.

Expected research-swarm demonstration: `monolith` and `naive_swarm` accept the 15
declared modeled boundary failures, while `bounded_swarm` blocks them through
deterministic handoff, authority, memory, and verifier/auditor contracts. The 43-row
attack matrix and 24-case evidence campaign extend that same claim boundary; they do not
prove production swarm safety. Ten matrix rows are executable deep probes that model
harmful weak-model consumption attempts while deterministic contracts still make the
pass/block decision.

Expected secret-egress demonstration: the deterministic secret-leak campaign records
naive leaks 4/4, bounded leaks 0/4, ablation leaks 11/11, and benign leaks 0/4. The
Phase 2 public summary declares 64 detector-labelled observations across two model ids,
0 leaks, and 0 adapter errors. It is unreconciled evidence-quality context: public
validation does not establish private-byte retention or model/runtime identity.

Expected semantic-drift demonstration: the deterministic semantic drift campaign records
bounded drift acceptances 0 and ablation drift acceptances 19 across four synthetic
semantic relabeling cases. The committed schema-`0.1` summary retains 80 historical
detector-labelled observations and declared aggregates; current schema is `0.2` and no
public reconciliation receipt exists. This is not current empirical evidence.

Expected semantic-propagation demonstration: the deterministic semantic propagation
campaign records 6 declared controls, 6 control-effect rows, bounded propagation
acceptances 0, and ablation propagation acceptances 20 across four worker-to-chief chain
cases. The committed schema-`0.2` summary retains 8 historical detector-labelled rows
and declared aggregates; current schema is `0.3` and no public reconciliation receipt
exists. This is not current empirical or causal-effect evidence.

Expected semantic-closure reading: `docs/semantic-drift-propagation-closure.md` is the
reviewer-facing record for the first semantic unit. Deterministic invariants remain
implemented, while the previous empirical closure is withdrawn until a current-schema,
reconciled run exists. `docs/semantic-consensus-laundering-closure.md` describes a
rule-derived two-worker executable-specification sub-unit.

Expected defense-contour demonstration: the deterministic local swarm defense contour
records 4 scenario families, 15 non-empty combination topologies, bounded acceptances 0,
naive acceptances 15, and control-ablation reopenings for the declared dependent paths.
It is a synthetic control-attribution layer, not a live model or production-swarm proof.

## Claim boundary

Allowed public claim:

> Trace-first defensive benchmark for reproducible agentic AI boundary-failure
> evaluation, with local deterministic targets, validated artifacts, bounded local-swarm
> evidence, and experimental opt-in external/local model checks.

Do not claim:

- production certification;
- complete security coverage;
- real target coverage without an adapter and authorization model;
- provider endorsement;
- benchmark-grade model leaderboard;
- live tool-executing agent evaluation.
