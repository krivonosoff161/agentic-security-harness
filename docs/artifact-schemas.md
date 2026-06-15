# Artifact schemas and versioning

Every machine-readable JSON artifact this benchmark writes carries a `schema_version`, so
a consumer (a CI job, another tool, or a future version of `ash`) can tell whether it can
read the file. The single source of truth is
[`src/agentic_security_harness/schema_versions.py`](../src/agentic_security_harness/schema_versions.py);
the models and the validator both read it, so they cannot drift.

Public JSON Schema files live under [`../schemas/`](../schemas/). They are integration
aids for external tools and document the top-level artifact contract. `ash validate`
remains the authoritative validator because it also checks corpus consistency, schema
registry compatibility, standards mapping, and forbidden marker scans.

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
| `run_diff.json` | `run_diff` | 0.1 | `ash diff-runs` | `ash validate` |

Non-versioned by design:

- `external_results.json` - a bare list whose item schema is governed by the
  `external_summary` version; it is not separately versioned today.
- Markdown artifacts (`summary.md`, `executive.md`, `comparison.md`, `matrix.md`,
  `remediation.md`, `external_report.md`, `run_diff.md`) - human views; the JSON next to
  them is authoritative.
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
