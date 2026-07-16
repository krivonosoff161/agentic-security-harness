# Artifact schemas and versioning

Every top-level machine-readable JSON artifact this benchmark writes carries a
`schema_version`, so a consumer (a CI job, another tool, or a future version of `ash`) can
tell whether it can read the file. The single source of truth is
[`src/agentic_security_harness/schema_versions.py`](../src/agentic_security_harness/schema_versions.py);
the models and the validator both read it, so they cannot drift.

Public JSON Schema files live under [`../schemas/`](../schemas/) for stable core
artifacts. Campaign artifacts that are not listed in `schemas/` are still
schema-versioned and are validated by `ash validate` through the corresponding Pydantic
models and consistency checks. `ash validate` remains the authoritative validator
because it also checks corpus consistency, schema registry compatibility, standards
mapping, and forbidden marker scans.

## Artifacts

| Artifact | Schema kind | Current `schema_version` | Written by | Validated by |
|---|---|---|---|---|
| `traces.json` (each item) | `trace` | 0.1 | `ash run`, `compare`, `run-matrix` | `ash validate` (per item) |
| `scorecard.json` | `scorecard` | 0.1 | `ash run`, `compare`, `run-matrix` | `ash validate` |
| `remediation.json` | `remediation` | 0.1 | the above, when findings exist | `ash validate` |
| `matrix.json` | `matrix` | 0.2 | `ash run-matrix` | `ash validate` |
| `run_config.json` | `run_config` | 0.2 | `ash run-external` | `ash validate` |
| `external_summary.json` | `external_summary` | 0.2 | `ash run-external` | `ash validate` |
| `run_index.json` | `run_manifest` | 0.3 | every run (manifest) | `ash validate` |
| `run_diff.json` | `run_diff` | 0.3 | `ash diff-runs` / `compare-models` | validated source-manifest commitments, exact Markdown projection, and content-bound output manifest |
| `evidence_quality.json` | `evidence_quality` | 0.3 | `ash evidence-quality` | validator-accepted inputs, portable labels, rebuildable aggregates/comparison groups, exact Markdown, and content-bound output manifest |
| `run_stats.json` | `run_stats` | 0.2 | `ash stats` | portable, source-manifest-bound run-history aggregates with independently recomputed expectation status, exact Markdown, and a content-bound output manifest |
| `showcase.json` | `showcase` | 0.2 | `ash showcase` | current validated source-manifest commitments, independently recomputed expectation status, portable card projection, inert exact Markdown, and a content-bound output manifest |
| `local_swarm_summary.json` | `local_swarm` | 0.1 | `ash local-swarm` | `ash validate` |
| `local_swarm_attack_matrix.json` | `local_swarm_matrix` | 0.2 | `ash local-swarm-matrix` | `ash validate` |
| `evidence_campaign_summary.json` | `evidence_campaign` | 0.2 | `ash evidence-campaign` | `ash validate` |
| `secret_leak_campaign_summary.json` | `secret_leak_campaign` | 0.1 | `ash secret-leak-campaign` | `ash validate` |
| `secret_leak_variation_summary.json` | `secret_leak_variations` | 0.1 | `ash secret-leak-campaign --execute-variations` | `ash validate` |
| `semantic_drift_summary.json` | `semantic_drift_campaign` | 0.2 | `ash semantic-drift-campaign` | `ash validate` |
| `semantic_propagation_summary.json` | `semantic_propagation_campaign` | 0.3 | `ash semantic-propagation-campaign` | `ash validate` |
| `swarm_defense_contour_summary.json` | `swarm_defense_contour` | 0.2 | `ash swarm-defense-contour` | `ash validate` |
| `swarm_defense_live_summary.json` | `swarm_defense_live_campaign` | 0.5 | `ash swarm-defense-live-campaign` | `ash validate` |
| `marketing_web_live_summary.json` | `marketing_web_live_campaign` | 0.3 | `ash marketing-web-live-campaign` | `ash validate` |
| `swarm_resilience_summary.json` | `swarm_resilience_campaign` | 0.1 | `ash swarm-resilience-campaign` | `ash validate` |
| `context_consent_summary.json` | `context_consent_campaign` | 0.2 | `ash context-consent-campaign` | `ash validate` |
| `tool_authority_summary.json` | `tool_authority_campaign` | 0.2 | `ash tool-authority-campaign` | `ash validate` |
| `rag_context_summary.json` | `rag_context_campaign` | 0.2 | `ash rag-context-campaign` | `ash validate` |
| `planner_task_summary.json` | `planner_task_campaign` | 0.2 | `ash planner-task-campaign` | `ash validate` |
| `memory_rehydration_summary.json` | `memory_rehydration_campaign` | 0.2 | `ash memory-rehydration-campaign` | `ash validate` |
| `docs/evidence-status-registry.json` | `evidence_status_registry` | 0.1 | maintained public inventory | `ash validate` |
| `reconciliation_receipt.json` | `private_public_reconciliation` | 0.1 | owner-side reconciliation library | public-byte binding via `validate_public_receipt`; private replay via `verify_owner_reconciliation` |

The evidence-status vocabulary includes stronger future assurance states, but schema
`0.1` still rejects promotion to those states. The reconciliation receipt contract is now
implemented, but its public form is deliberately unsigned and a public-only validator cannot
replay the private HMAC commitment. Promotion remains blocked until an authorized signer,
signature policy, revocation/freshness policy, and signed-receipt validator exist. Path
existence and a manually declared status are not evidence of reconciliation, independent
review, content binding, or signature verification.

`private_public_reconciliation` v0.1 is created only after owner-side code reads exact
persisted private/public JSON bytes, rebuilds the campaign sanitizer projection, and obtains
an exact projection match. It rejects incomplete declared matrices, unsupported private schema
versions, impossible adapter-error stage combinations, and mismatches between retained raw text
and the response/page/decision hashes that the producer actually derives. It binds the exact
public artifact bytes with SHA-256 and the exact
private artifact bytes with HMAC-SHA-256 under a separately supplied owner-only key of at
least 32 bytes. The key and private bytes are never serialized into the receipt. Public-only
validation can establish only the public digest binding; it reports private replay and origin
authentication as false. The algorithm/source fingerprint covers the five supported campaign
sanitizers, bundle validator, path checks, and shared projection code. Endpoint locality,
implementation execution, model identity, detector correctness, and canary semantics remain
self-declared or non-replayable because the necessary independent raw inputs/attestations are not
retained. No trusted time, signer, execution locality, semantic truth, or exhaustive-coverage
claim is inferred.

`run_diff` v0.2 replaced the ambiguous v0.1 coarse labels (`fixed`, `new`,
`changed`, `unchanged`) with explicit decisive/non-decisive counters such as
`finding_fixed`, `new_finding`, and `inconclusive_error_drift`. The writer still emits
the v0.1 alias counters as deprecated optional fields. v0.3 first validates both inputs,
records each source manifest hash and current/legacy validation scope, writes an exact
Markdown projection, and adds a run-manifest v0.3 over the diff bundle. `ash validate`
keeps v0.1 and v0.2 readable as legacy artifacts; their absent source commitments and
output hashes cannot be inferred retroactively.

`run_manifest` v0.2 separates unique `execution_id` from deterministic
`config_fingerprint`. The legacy `run_id` remains an alias of `execution_id` for
existing consumers. Validators recompute the configuration fingerprint; v0.1 manifests
remain readable but cannot retroactively prove distinct executions that shared one
configuration id.
`run_manifest` v0.3 binds every listed artifact path to the SHA-256 of its exact
persisted bytes and rejects absolute, parent-escaping, duplicate, missing, and
self-referential artifact paths. This detects accidental or uncoordinated content
changes after manifest creation. It is an internal content-integrity commitment, not
proof of authorship or non-rewrite: a writer able to replace both artifact and manifest
can recompute the hashes. Versions 0.1 and 0.2 remain readable as legacy manifests.
The same rule applies to `adapter_error -> pass` and other non-decisive external
transitions.

`run_stats` and `showcase` v0.2 preserve each source bundle's independently recomputed
behavioral expectation status and mismatch count instead of treating only integrity-valid
inputs as implicit passes. The observation binds the source manifest bytes, validator tool
and corpus versions, and a content fingerprint of the local expectation-validation source.
It is an unsigned observation made when the derived bundle was generated. Standalone
validation of the derived bundle verifies that recorded projection and provenance fields are
internally consistent; it does not reacquire the source tree or claim the observation is
current. Schemas v0.1 remain readable with `not_recorded` expectation authority and their
original Markdown/manifest projections; missing status is never backfilled as `ok`.

External config/summary schema v0.2 creates one execution id before the first request,
persists it in runtime metadata, every normalized result, and the summary, and binds the
same id plus the complete bundle inventory into run-manifest v0.3. Direct library and CLI
producers now write the same manifest contract. A current external bundle without its
manifest, with mixed execution ids, or with a non-empty reused output directory fails
closed. Schema v0.1 external artifacts remain structurally readable legacy evidence and
cannot claim this execution binding.

Current manifested producers treat an output directory as one immutable generation.
The final destination must be missing; rerunning into a completed, partial, or merely
pre-created directory is refused instead of updating files in place.
Manifest inventory is family-typed, and validation rejects unmanifested files anywhere
under the bundle root. A root-level `README.md` and canonical `report.html` are the only
unbound presentation companions; they are secret-scanned and cannot be symlinks.
Private and sanitized output roots must be distinct and must not contain one another.
Local model-probe output is restricted to a normalized `.internal` path and cannot share
the same command/output root with a manifested deterministic bundle.

Individual text artifacts are written through a same-directory temporary file and
`os.replace`, so a failed single-file replacement preserves the previous complete file.
Every current manifest-producing public writer now builds into a unique sibling
`.ash-staging-<id>` directory, writes the manifest last, runs the applicable artifact,
semantic, hash, projection, inventory, and secret-marker validation, and publishes the
complete generation with one same-filesystem directory rename. Behavioral expectation
mismatches remain publishable evidence when integrity is valid. Failed cooperative writes
remove only their owned staging directory; manifest discovery ignores staging names, so an
abruptly interrupted orphan is not treated as run history. Private raw-artifact writers use
the same missing-final/staging/rename transaction without applying public secret-marker
validation; their staging directories are created owner-only where the platform honors
POSIX modes. Both public and private transactions reject symlinks and Windows reparse points
in path components and recheck their trees before publication.

The remaining filesystem residuals are an owner-only orphan potentially retaining private
bytes after a hard process kill, platform-specific directory-durability guarantees
(directory `fsync` is used where exposed), a private/public pair being two atomic bundles
rather than one cross-root commit, and an uncooperative local actor racing filesystem names.
Replaceable `latest` views still need
immutable `generations/<execution-id>/` plus an atomic `CURRENT` pointer rather than
replacement of a published bundle.

Run-history discovery uses the same root-bound integrity rule and does not erase a
published behavioral expectation mismatch. `list-runs` reports the recomputed expectation
status beside each run. Commands that can call a model preflight every private and public
destination before the first request, so an existing generation fails before consuming the
request budget; the publisher repeats the check at commit time to catch ordinary races.

Non-versioned by design:

- `external_results.json` - a bare list whose item schema is governed by the
  `external_summary` version; it is not separately versioned today.
- `run_config.json` includes a `runtime` metadata block for new external runs
  (`runtime_name`, `runtime_family`, `network_mode`, authorization mode, model id,
  prompt-only/tool-execution flags, model license/policy note, recovery guidance, and
  the pre-request execution id).
- Markdown artifacts (`summary.md`, `executive.md`, `comparison.md`, `matrix.md`,
  `remediation.md`, `external_report.md`, `run_diff.md`) - human views; the JSON next to
  them is authoritative.
- `showcase.json` is the authoritative structured projection for generated reviewer cards.
  Only current validator-recognized `run` and `external` bundles are eligible. Source
  manifest hashes, exact escaped Markdown, and the output manifest make later changes
  detectable; unsigned source origin and modeled evidence limitations remain explicit.
  The committed `docs/showcase/generated/*.md` files are reproducible documentation views,
  not a committed structured showcase bundle; a generated `showcase.json` plus its manifest
  is authoritative only when retained together.
- External raw response text files under `raw_responses/` are evidence artifacts linked
  from `external_results.json` by relative path and sha256.
- `evidence_quality.json` is a derived analysis over recorded external/local artifacts.
  Schema 0.3 excludes bundles that fail the applicable artifact validator or lack a run
  manifest, and carries manifest schema, validation scope, and unsigned-origin status into
  every row. Aggregate and cross-run metrics are rebuildable from retained rows/groups;
  absolute workstation paths are not persisted; exact JSON/Markdown bytes are bound by a
  current output manifest. Legacy inputs may remain readable as structural history; they are
  not promoted to current persisted-byte binding.
  It does not call a model and does not certify model safety.
- `local_swarm_attack_matrix.json` is a deterministic attack-variation analysis over
  existing local-swarm contracts. It does not call a model and does not claim exhaustive
  attack coverage.
- `evidence_campaign_summary.json` is a deterministic private-ready campaign artifact
  that calculates TP/FP/FN/TN, control effect, usability cost, and control-ablation
  regressions across declared agentic-boundary situations. It is not a
  production-safety proof.
- `secret_leak_campaign_summary.json` is a sanitized deterministic campaign artifact for
  synthetic secret-egress topologies. Raw canary values, prompts, and local-model
  responses are private calculation artifacts and must remain under `.internal/`.
- `secret_leak_variation_summary.json` is a sanitized aggregate over private
  local-model secret-egress variation probes. Raw prompts, raw responses, and synthetic
  canary values remain under `.internal/`; the public artifact keeps only hashes,
  classifications, and aggregate metrics.
- `semantic_drift_summary.json` is a sanitized aggregate over deterministic and private
  local-model semantic-parameter drift probes. Raw prompts, raw responses, canonical
  state hashes, and synthetic canary values remain under `.internal/`; the public
  artifact keeps only response hashes, classifications, model names, pressure labels,
  and aggregate verifier metrics. Version 0.2 adds independent-review labels, private
  review-evidence hashes, label coverage, and confusion-matrix metrics. Version 0.1
  remains readable and is treated as unadjudicated.
- `semantic_propagation_summary.json` is a sanitized aggregate over deterministic and
  private local-model worker-to-chief propagation probes. Raw worker/chief prompts,
  raw responses, canonical-state hashes, and synthetic canary values remain under
  `.internal/`; the public artifact keeps only response hashes, classifications, model
  names, pressure labels, adapter-error counts, response-hash coverage, control catalog
  rows, control-effect rows, and aggregate verifier metrics. Version 0.2 adds the
  public-safe defense control model and deterministic ablation attribution; 0.1 remains
  readable for older local artifacts. Version 0.3 adds the independent-review label
  contract; older rows remain readable as unadjudicated.
- `swarm_defense_live_summary.json` is a sanitized aggregate over private local-model
  worker/chief probes across the four-family local swarm defense contour. Raw prompts,
  raw responses, synthetic canary values, and calculation notes remain under
  `.internal/`; the public artifact keeps safe model ids, runtime roles, topology ids,
  scenario ids, pressure labels, response hashes, per-turn response hashes, aggregate
  labels, adapter-error flags, verifier block attribution, replay-ablation metrics, and
  response-hash coverage. Version 0.2 adds public-safe replay-ablation reopenings.
  Version 0.3 adds long-session metrics and per-turn public response hashes. Version 0.4
  adds independent-review labels, review-evidence hashes, coverage, and confusion-matrix
  metrics. Version 0.5 declares the planned topology/model/pressure matrix, local
  endpoint commitment, execution id, tool/component identity, and exact adapter-error
  stage. Outcome-rate denominators now name the causal stages that completed. Versions
  0.1 through 0.4 remain readable; their digest metrics must still exactly mirror the
  metrics physically present in their summary. Legacy validation is structural-only:
  it does not independently replay every historical rate/map formula and must not be
  presented as current verified evidence. Historical canary-zero claims are withdrawn
  because the pre-0.5 aggregator used category names that did not match its detector.
- `marketing_web_live_summary.json` is a sanitized aggregate over private local-model
  worker/chief probes against an owned local web stand. Raw local HTML pages, prompts,
  model responses, synthetic strategy values, and calculation notes remain under
  `.internal/`; the public artifact keeps scenario ids, modes, safe model ids,
  page URL/content hashes, worker/chief response hashes, per-turn response hashes, leak
  kind labels, verifier decisions, control attribution, aggregate metrics, and
  non-claims. Version 0.2 adds the independent-review label contract. Version 0.3
  declares the planned scenario/model matrix, local endpoint and execution identity,
  records exact adapter-error stages, and separates a deterministic decision-output
  hash from a chief-model response hash when the verifier blocks before any chief call.
  Versions 0.1 and 0.2 remain readable as unadjudicated historical data, with exact
  raw-summary-to-digest metric projection. Their semantic validation remains
  structural-only; no committed schema-0.3 live rerun exists yet.
- `swarm_resilience_summary.json` is a sanitized deterministic stability artifact over
  seven multi-step mini-swarm degradation families: memory, semantics, source trust,
  consensus, metrics/verdicts, benign-looking fact accumulation, and coupled cascades.
  Private synthetic payload notes and per-step calculation traces remain under
  `.internal/`; the public artifact keeps state hashes, numeric state-vector metrics,
  stability verdicts, block attribution, ablation reopenings, and non-claims.
- `context_consent_summary.json` is a sanitized deterministic artifact over contextual
  approval claims that are not current user consent. It keeps consent-boundary cases,
  control-ablation rows, benign-path checks, context fingerprints, metrics, and
  non-claims. Version 0.2 classifies it as an executable specification with rule-derived,
  not independently estimated, control attribution.
- `tool_authority_summary.json` is a sanitized deterministic artifact over tool-output
  authority claims. It keeps tool-surface labels, authority-claim descriptions,
  control-ablation rows, benign-path checks, tool-output fingerprints, metrics, and
  non-claims. It does not call real tools or models. Version 0.2 adds the executable-
  specification evidence and causal-scope contract.
- `rag_context_summary.json` is a sanitized deterministic artifact over
  retrieved-context authority claims. It keeps retrieval-surface labels, entry vectors,
  public-safe propagation paths, no-red-flag labels, control-ablation rows, benign-path
  checks, context fingerprints, metrics, and non-claims. It does not call live RAG
  systems, real retrievers, provider APIs, or models. Version 0.2 adds the executable-
  specification evidence and causal-scope contract. Planner-task and memory-rehydration
  v0.2 use the same contract.
- Campaign digest files such as `evidence_campaign_digest.json`,
  `secret_leak_campaign_digest.json`, `semantic_drift_digest.json`,
  `semantic_propagation_digest.json`, `swarm_defense_live_digest.json`,
  `swarm_resilience_digest.json`, `context_consent_digest.json`, and
  `tool_authority_digest.json`, and `rag_context_digest.json` are derived public summary
  indexes next to the versioned summaries. They are validated as part of their campaign
  directory, but the summary JSON remains the canonical schema-versioned artifact.
- A `comparison` is represented as two report directories (`baseline/`, `protected/`) plus
  `comparison.md`; there is no separate `comparison.json`. Use `ash diff-runs` for an
  arbitrary run-vs-run diff (which does emit a versioned `run_diff.json`).

## What `ash validate` checks

For each versioned artifact present, validation:

- rejects an **unknown / future** `schema_version` with a clear, actionable error
  ("this build supports: ...; upgrade the tool to read it");
- catches a **missing** `schema_version` where one is required;
- otherwise proceeds with the normal structural/consistency checks.

Validation is artifact-integrity only - see
[benchmark-semantics.md](benchmark-semantics.md).

## Compatibility policy

- `schema_version` is `MAJOR.MINOR`, independent per artifact kind.
- **Backwards-compatible change** (a new optional field, a widened enum that old readers
  can ignore): bump the **minor** version and widen `KNOWN_SCHEMA_VERSIONS` so the tool
  reads both old and new.
- **Breaking change** (removing/renaming a field, changing a field's type or meaning,
  tightening a constraint): bump the **major** version. Old artifacts of the previous
  major are then read only if explicitly kept in `KNOWN_SCHEMA_VERSIONS`.
- Until v1.0 the schemas may still move; from v1.0 the corpus manifest and trace schema
  are frozen and this policy is enforced (see [release-checklist.md](release-checklist.md)).

## What counts as a breaking change

- Removing or renaming a field consumers rely on.
- Changing a field's type (e.g. string -> object) or its semantics.
- Making a previously-optional field required, or changing default behavior in a way that
  changes the meaning of an existing field.

Adding a new optional field, a new artifact kind, or a new enum value that older readers
can safely ignore is **not** breaking - bump the minor version instead.
