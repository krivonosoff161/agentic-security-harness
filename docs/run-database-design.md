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

- `index-runs` scans `--root` for `run_index.json` manifests and upserts them by `run_id`
  (idempotent). It stores only the manifest metadata.
- `list-runs --db` reads from the index instead of scanning.
- `stats` scans manifests and can write `run_stats.json` / `run_stats.md`.
- `retention` scans manifests and prints removable old run directories. It does not
  delete anything unless `--apply` is passed.
- `stats`, `retention`, `validate`, and `compare-models` support `--format json` for
  automation.
- The JSON manifests remain the source of truth; the DB is a derived convenience index and
  can be deleted and rebuilt at any time.

### Schema (v0, `runs` table)

| Column | Meaning |
|---|---|
| `run_id` (PK) | deterministic run id from the manifest |
| `run_kind` | run / compare / matrix / external |
| `created_at` | manifest timestamp (informational) |
| `tool_version` | tool version that produced the run |
| `target` | target label (or "vs" labels for compare) |
| `model` | external model label, if any |
| `scenario` | scenario id |
| `outcomes` | JSON of outcome counts (e.g. `{"failed": 22, "passed": 0}`) |
| `manifest_path` | path to the run dir, relative to the scanned root |

No trace contents, prompts, responses, or secrets are stored. `reports/` and `*.db` are
git-ignored, so an index is never committed by accident.

## Deliberately out of scope (future)

These are **not** implemented and should wait until the trace schema is frozen at v1.0:

- Storing trace bodies or findings in the DB (the file artifacts already hold these).
- A query CLI (filter by kind/target/outcome, time ranges).
- A migration/versioning story for the DB schema itself.
- Any networked or multi-user database (Postgres, a server) - see
  [roadmap.md](roadmap.md) and
  [independent-benchmark-gap-list.md](independent-benchmark-gap-list.md).

## Why a derived index (not a primary store)

Keeping the JSON manifests authoritative means the benchmark stays diffable in git,
inspectable without tooling, and reproducible. The SQLite index is a convenience that can
always be rebuilt with `ash index-runs`, so it never becomes a source of truth that could
drift from the artifacts.
