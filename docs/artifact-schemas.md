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
| `run_config.json` | `run_config` | 0.1 | `ash run-external` | `ash validate` |
| `external_summary.json` | `external_summary` | 0.1 | `ash run-external` | `ash validate` |
| `run_index.json` | `run_manifest` | 0.1 | every run (manifest) | `ash validate` |
| `run_diff.json` | `run_diff` | 0.2 | `ash diff-runs` | `ash validate` |
| `evidence_quality.json` | `evidence_quality` | 0.2 | `ash evidence-quality` | derived artifact; schema-versioned, not a replacement for `ash validate` |
| `local_swarm_summary.json` | `local_swarm` | 0.1 | `ash local-swarm` | `ash validate` |
| `local_swarm_attack_matrix.json` | `local_swarm_matrix` | 0.2 | `ash local-swarm-matrix` | `ash validate` |
| `evidence_campaign_summary.json` | `evidence_campaign` | 0.2 | `ash evidence-campaign` | `ash validate` |
| `secret_leak_campaign_summary.json` | `secret_leak_campaign` | 0.1 | `ash secret-leak-campaign` | `ash validate` |
| `secret_leak_variation_summary.json` | `secret_leak_variations` | 0.1 | `ash secret-leak-campaign --execute-variations` | `ash validate` |
| `semantic_drift_summary.json` | `semantic_drift_campaign` | 0.1 | `ash semantic-drift-campaign` | `ash validate` |
| `semantic_propagation_summary.json` | `semantic_propagation_campaign` | 0.2 | `ash semantic-propagation-campaign` | `ash validate` |
| `swarm_defense_live_summary.json` | `swarm_defense_live_campaign` | 0.3 | `ash swarm-defense-live-campaign` | `ash validate` |
| `marketing_web_live_summary.json` | `marketing_web_live_campaign` | 0.1 | `ash marketing-web-live-campaign` | `ash validate` |

`run_diff` v0.2 replaces the ambiguous v0.1 coarse labels (`fixed`, `new`,
`changed`, `unchanged`) with explicit decisive/non-decisive counters such as
`finding_fixed`, `new_finding`, and `inconclusive_error_drift`. The writer still emits
the v0.1 alias counters as deprecated optional fields, and `ash validate` accepts both
v0.1 and v0.2 `run_diff.json` artifacts. This keeps old local reports readable while new
reports stop treating `error -> pass` as a security fix.
The same rule applies to `adapter_error -> pass` and other non-decisive external
transitions.

Non-versioned by design:

- `external_results.json` - a bare list whose item schema is governed by the
  `external_summary` version; it is not separately versioned today.
- `run_config.json` includes a `runtime` metadata block for new external runs
  (`runtime_name`, `runtime_family`, `network_mode`, authorization mode, model id,
  prompt-only/tool-execution flags, model license/policy note, and recovery guidance).
- Markdown artifacts (`summary.md`, `executive.md`, `comparison.md`, `matrix.md`,
  `remediation.md`, `external_report.md`, `run_diff.md`) - human views; the JSON next to
  them is authoritative.
- External raw response text files under `raw_responses/` are evidence artifacts linked
  from `external_results.json` by relative path and sha256.
- `evidence_quality.json` is a derived analysis over recorded external/local artifacts.
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
  and aggregate verifier metrics.
- `semantic_propagation_summary.json` is a sanitized aggregate over deterministic and
  private local-model worker-to-chief propagation probes. Raw worker/chief prompts,
  raw responses, canonical-state hashes, and synthetic canary values remain under
  `.internal/`; the public artifact keeps only response hashes, classifications, model
  names, pressure labels, adapter-error counts, response-hash coverage, control catalog
  rows, control-effect rows, and aggregate verifier metrics. Version 0.2 adds the
  public-safe defense control model and deterministic ablation attribution; 0.1 remains
  readable for older local artifacts.
- `swarm_defense_live_summary.json` is a sanitized aggregate over private local-model
  worker/chief probes across the four-family local swarm defense contour. Raw prompts,
  raw responses, synthetic canary values, and calculation notes remain under
  `.internal/`; the public artifact keeps safe model ids, runtime roles, topology ids,
  scenario ids, pressure labels, response hashes, per-turn response hashes, aggregate
  labels, adapter-error flags, verifier block attribution, replay-ablation metrics, and
  response-hash coverage. Version 0.2 adds public-safe replay-ablation reopenings.
  Version 0.3 adds long-session metrics and per-turn public response hashes. The
  committed base example is legacy-readable schema 0.2; the long-session supplement is
  schema 0.3. Versions 0.1 and 0.2 remain readable for older local artifacts.
- `marketing_web_live_summary.json` is a sanitized aggregate over private local-model
  worker/chief probes against an owned local web stand. Raw local HTML pages, prompts,
  model responses, synthetic strategy values, and calculation notes remain under
  `.internal/`; the public artifact keeps scenario ids, modes, safe model ids,
  page URL/content hashes, worker/chief response hashes, per-turn response hashes, leak
  kind labels, verifier decisions, control attribution, aggregate metrics, and
  non-claims.
- Campaign digest files such as `evidence_campaign_digest.json`,
  `secret_leak_campaign_digest.json`, `semantic_drift_digest.json`,
  `semantic_propagation_digest.json`, and `swarm_defense_live_digest.json` are derived
  public summary indexes next to the versioned summaries. They are validated as part of
  their campaign directory, but the summary JSON remains the canonical schema-versioned
  artifact.
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
