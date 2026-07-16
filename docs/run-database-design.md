# Local run database (design + current minimal index)

The benchmark records each run as a `run_index.json` manifest. For users who accumulate
many runs, `ash index-runs` builds a **lightweight local SQLite index** of that metadata so
runs can be listed and (later) queried without re-scanning the filesystem.

This is deliberately minimal and safe: stdlib `sqlite3` only (no dependency), **metadata
only** (no trace bodies, no secrets), local file, no network, no server.

## Current implementation (shipped)

```bash
ash index-runs --root reports --db reports/runs.db   # build/refresh the index
ash list-runs  --db reports/runs.db                  # read from the index
ash stats      --root reports --out reports/stats    # aggregate manifest statistics
ash retention  --root reports --keep-last 20         # dry-run cleanup plan
```

- `index-runs` scans `--root` for current content-bound `run_index.json` manifests that
  pass their applicable artifact validator and indexes schema-v0.3
  executions by unique `execution_id` (idempotent for the same manifest). Repeated
  executions of one configuration remain separate rows with the same
  `config_fingerprint`.
- Re-indexing byte-equivalent metadata for an existing execution is a no-op. Reusing an
  existing `execution_id` with different metadata is rejected as an identity collision;
  indexed execution rows are not updated in place.
- `list-runs --db` reads from the index in deterministic execution-identity order rather
  than pretending unsigned `created_at` is trusted chronology. Filesystem listing labels any
  displayed timestamp as unsigned. DB output labels cached observations as
  `indexed_expectations`, including validation scope/tool/corpus; it does not present them as
  a fresh filesystem validation.
- `stats` scans current validator-accepted manifests (excluding prior `run_stats` outputs) and
  can write schema-v0.2 `run_stats.json` / `run_stats.md` plus `run_index.json`. Persisted
  output uses a portable root label and retains the minimal source rows/manifest hashes needed
  to rebuild every aggregate, including independently recomputed expectation status/count;
  exact Markdown and output bytes are validated. Source/output path overlap is refused.
- `retention` scans only current validated manifests and prints removable old run directories.
  Apply rechecks both the planned manifest hash and applicable validator immediately before
  deletion. Because ordering uses unsigned manifest `created_at`, deletion requires both
  `--apply` and `--accept-unsigned-chronology`; without that explicit acceptance it fails
  before removing any directory.
  Apply also rebuilds the complete plan from the current validated scan and requires exact
  candidate identity, labels, reasons, and hashes. A caller-constructed or stale plan therefore
  cannot nominate an arbitrary valid run. Each candidate is revalidated again immediately before
  its deletion. Deletion is not a filesystem transaction: the operator must exclude concurrent
  local writers, and a failure after an earlier candidate was removed can still leave a partial
  apply.
- Core run/compare/matrix manifests are semantically checked against rebuilt artifacts and
  must hash every authoritative report file. Their outcome labels can no longer be changed
  independently or made selectively mutable by omitting an authoritative file from the
  manifest inventory. `created_at` remains unsigned informational metadata; retention's
  chronological ordering therefore remains operator-declared rather than authenticated and
  is surfaced as `chronology_authority=unsigned_manifest_created_at` in every plan.
- `stats`, `retention`, `validate`, and `compare-models` support `--format json` for
  automation. Retention keeps canonical absolute paths only in its internal apply model; text and
  JSON CLI projections use `<run-root>` plus relative candidate paths so automation logs do not
  publish workstation roots.
- The JSON manifests remain the source of truth; the DB is a derived convenience index that
  can be deleted and rebuilt at any time. Discovery uses artifact-scoped validation.
  Repository-global standards and evidence-status checks remain owned by `ash validate` and
  are not redundantly repeated per manifest.
- Stats source-manifest commitments and its output manifest are unsigned internal-consistency
  evidence. They do not authenticate who produced a source run or which runtime/model acted.

Schema-v0.1 manifests remain readable. Because their old `run_id` represented only a
configuration, the index derives a stable legacy execution identity from that id plus
the manifest path. New v0.2 manifests do not use this compatibility path.

### Schema (DB v2)

`PRAGMA user_version=2` identifies the current internal DB layout. Opening a pre-v2 DB
for listing is read-only: its legacy `runs` rows are projected with stable derived execution
ids and `expectation_status=not_recorded`. The next explicit `index-runs` copies those rows
into `run_executions` without inventing validation authority, creates the observation table,
and records current validator observations for current source manifests. The legacy table is
preserved. Re-indexing refreshes validation observations but never rewrites immutable execution
metadata.

#### `run_executions` — immutable execution metadata

| Column | Meaning |
|---|---|
| `execution_id` (PK) | unique identity for one execution attempt |
| `config_fingerprint` | deterministic identity for comparable configuration |
| `legacy_run_id` | original id retained for schema-v0.1 imports |
| `run_kind` | typed producer family (`run`, `compare`, `matrix`, `external`, derived analysis/showcase kinds, or a campaign kind) |
| `created_at` | manifest timestamp (informational) |
| `tool_version` | tool version that produced the run |
| `target` | target label (or "vs" labels for compare) |
| `model` | external model label, if any |
| `scenario` | scenario id |
| `outcomes` | JSON of outcome counts (e.g. `{"failed": 24, "passed": 0}`) |
| `manifest_path` | path to the run dir, relative to the scanned root |

#### `run_validation_status` — replaceable validator observation

| Column | Meaning |
|---|---|
| `execution_id` (PK) | execution row observed by the validator |
| `manifest_sha256` | exact manifest snapshot validated during indexing |
| `expectation_status` | `ok` or `mismatch`; legacy/unindexed rows are exposed as `not_recorded` by the reader |
| `expectation_mismatch_count` | independently recomputed mismatch count; mismatch text is not stored |
| `validation_scope` | fixed `independently_recomputed_at_index` label |
| `validator_tool_version` | package version used for the observation |
| `corpus_version` | corpus revision used for the observation |
| `validator_source_fingerprint` | SHA-256 commitment to the local expectation-validation source bytes |

No trace contents, prompts, responses, or secrets are stored. `reports/` and `*.db` are
git-ignored, so an index is never committed by accident.

## Deliberately out of scope (future)

These are **not** implemented and should wait until the trace schema is frozen at v1.0:

- Storing trace bodies or findings in the DB (the file artifacts already hold these).
- A query CLI (filter by kind/target/outcome, time ranges).
- Automatic deletion of the preserved pre-v2 `runs` table after migration.
- Any networked or multi-user database (Postgres, a server) - see
  [roadmap.md](roadmap.md) and
  [independent-benchmark-gap-list.md](independent-benchmark-gap-list.md).

## Why a derived index (not a primary store)

Keeping the JSON manifests authoritative means the benchmark stays diffable in git,
inspectable without tooling, and reproducible. The SQLite index is a convenience that can
always be rebuilt with `ash index-runs`, so it never becomes a source of truth that could
drift from the artifacts.
