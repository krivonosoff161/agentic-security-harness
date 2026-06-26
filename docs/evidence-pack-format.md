# Evidence pack format

> **Agentic Security Harness.** This document defines how new research results
> should enter the public repository without leaking private model transcripts,
> synthetic canaries, or local calculation material.

An evidence pack is a bounded, reviewable update that connects:

```text
research question -> run command -> sanitized artifacts -> validation -> claim row
```

It is not a loose folder of logs.

## Required public structure

Use this shape for every public evidence update:

```text
examples/<pack-name>/              # committed sanitized artifact pack, if stable
  run_index.json
  <summary>.json
  <report>.md
  <digest>.json                    # when private raw material exists

docs/<topic>.md                    # methodology / result / non-claims
docs/showcase/evidence-map.md      # reviewer-facing index row
docs/research-claims.md            # claim registry row
tests/test_<topic>.py              # schema, invariant, or doc-contract tests
```

For exploratory work that is not ready as a committed example, use `reports/` during
local development and promote only the sanitized result.

## Required private structure

Keep raw calculations and raw local model material outside public git:

```text
.internal/<campaign>/latest/
  raw_prompts/
  raw_responses/
  raw_transcripts/
  private_calculations/
  canary_values/
```

The public pack may reference private material only by digest, for example:

```json
{
  "private_transcript_sha256": "64 lowercase hex chars",
  "private_response_hashes": ["64 lowercase hex chars"],
  "raw_private_material_committed": false
}
```

Public artifacts do not include raw transcripts. They may include hashes that let
the owner replay and audit the private material locally.

## Required claim boundary

Every pack must say what the evidence proves and what it does not prove.

Allowed wording:

- "This pack validates the declared synthetic scenario under the stated topology."
- "The local-model run is a sanitized empirical slice, not a model-safety verdict."
- "The protected path blocked this modeled flow in this configuration."
- "The result is hash-anchored to private owner-side raw responses."

Forbidden wording:

- "This model is safe."
- "This protects any agent."
- "This is CVE-grade evidence."
- "This is a production certification."
- "This proves complete swarm security."

## Required metadata

Each public evidence pack must include:

| Field | Requirement |
|---|---|
| `schema_version` | Uses the current artifact schema registry. |
| `created_at` | UTC timestamp or stable generated value for committed examples. |
| `scenario_ids` | Scenario families or pattern ids under test. |
| `topology` | Single model, deterministic target, local swarm, model chain, etc. |
| `model_ids` | Public model/runtime labels if local/real models were used. |
| `network_mode` | `offline`, `local-only`, or `authorized-external`. |
| `request_count` | Actual or bounded maximum request count for model calls. |
| `private_boundary` | Whether raw prompts/responses/canaries remain private. |
| `hash_coverage` | Count or ratio of private responses represented by public hashes. |
| `validation_command` | Exact command used to validate the public pack. |
| `non_claims` | Explicit limits. |

## Required tests

At least one test must prevent silent drift. Choose the smallest useful test:

- schema validation for the new artifact shape;
- doc-contract test that required links and non-claims exist;
- invariant test for calculated metrics;
- privacy test proving raw prompts/responses/canaries are not committed;
- CLI smoke test for the command that generates or validates the pack.

## Required commands before PR

Run these before opening or updating a public PR:

```bash
ash validate examples/
python -m pytest
python -m ruff check .
python -m mypy src tests
git diff --check
```

If only docs changed, still run the documentation contract tests and
`ash validate examples/`.

## Promotion checklist

Before a local research result becomes a public evidence pack:

1. Raw model material is under `.internal/` and ignored by git.
2. Public files contain no raw prompts, raw responses, synthetic canary values, API
   keys, private URLs, or local absolute paths.
3. Public summaries include enough metadata for a reviewer to understand the
   configuration.
4. Private raw responses are represented by SHA-256 hashes when the claim depends on
   local model behavior.
5. `docs/research-claims.md` states the correct status:
   - `synthetic_validation` for deterministic synthetic proof;
   - `local_empirical` for local model evidence;
   - `public_example` only when committed examples are sufficient to reproduce the
     claim without private material.
6. The evidence map links the pack.
7. The PR description includes commands run and non-claims.

