# Trading Bot Private Experiment Row Contract

> Status: public-safe contract for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> This document defines how future real paper-only experiment rows must be
> recorded privately before any public summary is accepted. It intentionally
> contains no raw vectors, target rows, traces, provider transcripts, card text,
> private calculations, secrets, prompt bodies, or bypass recipes.

## Purpose

The current stand has three proven non-executing row paths:

- observed baseline rows from existing paper artifacts;
- synthetic finding-path control rows;
- synthetic inconclusive-path control rows.

The next step is real private filled rows from authorized paper-only
experiments. Those rows are allowed to contain sensitive vectors and target-side
observations only under the ignored private evidence root. Public docs may only
contain sanitized aggregate derivatives.

## Row Types

| Row type | `target_observation` | Marker | Public meaning |
|---|---:|---|---|
| Template | false | `template_only=true` | Empty private skeleton. |
| Baseline | true | `baseline_only=true` | Existing artifact-schema observation, not adversarial. |
| Finding control | false | `control_only=true` | Synthetic sanitizer/validator finding path. |
| Inconclusive control | false | `control_only=true` | Synthetic sanitizer/validator weak-evidence path. |
| Real private row | true | no control/baseline/template marker | Future authorized paper-only observation. |

## Required Real Row Fields

A real private row is any row with:

- `target_observation=true`;
- `control_only` not true;
- `baseline_only` not true;
- `template_only` not true.

Such a row must include:

| Field | Requirement |
|---|---|
| `scenario_id` | One of the seven `tbps.*` scenario ids. |
| `batch_id` | Expected scenario batch (`A`, `B`, or `C`). |
| `result_class` | `pass`, `finding`, `inconclusive`, or `error`. |
| `artifact_hash` | `sha256:` anchor over private evidence. |
| `public_evidence` | Object with bounded public fields only. |
| `adversarial_condition_id` | Opaque condition id, not a payload body. |
| `observed_boundary_preserved` | `true` for pass, `false` for finding, boolean/null for weak rows. |
| `private_slots.raw_vector` | Present and filled privately. |
| `private_slots.raw_agent_script` | Present and filled privately. |
| `private_slots.raw_target_rows` | Present and filled privately. |
| `private_slots.private_calculation_note` | Present and filled privately. |
| `private_slots.raw_trace` | Present and filled privately. |

## Validator Behavior

`ash trading-stand --mode validate-experiment` now checks:

- all seven scenarios are present exactly once;
- every row uses the expected batch id;
- result classes are valid;
- `pass` rows preserve the boundary;
- `finding` rows break the boundary;
- weak rows use boolean/null boundary status;
- every row has a `sha256:` artifact anchor;
- private slots exist for every scenario;
- claimed real target-observation rows have filled private slots;
- claimed real target-observation rows have a public evidence object;
- claimed real target-observation rows have an opaque
  `adversarial_condition_id`;
- fixtures live under `.internal/trading-bot-paper-stand/issue-136/`.

The validator reports counts for:

- all target observations;
- real target observations;
- synthetic control rows.

## Intake Gate

`ash trading-stand --mode experiment-intake` is stricter than structural
validation. It accepts private rows for public-safe sanitization only when:

- `validate-experiment` passes;
- a valid private batch manifest is supplied;
- all seven rows are real target observations;
- no synthetic control rows are present;
- baseline/template/control markers are absent from the accepted row set.

This means observed baseline rows, synthetic finding controls, and
all-inconclusive controls can remain useful checks, but they are blocked from
becoming real filled-row research evidence.

## Public Sanitization

`ash trading-stand --mode sanitize-experiment` may publish only:

- aggregate result counts;
- batch counts;
- scenario ids;
- `sha256:` artifact anchors;
- private slot names;
- sanitized public fields.

It must not publish:

- raw vectors;
- agent scripts;
- target rows;
- traces;
- card text;
- provider transcripts;
- prompt bodies;
- private calculations;
- secrets or secret-shaped canaries;
- step-by-step bypass recipes.

## Current Status

The contract has been verified with synthetic private filled rows in tests. The
intake gate has also been checked against the current observed baseline fixture:
it blocks the baseline from being promoted into filled-row evidence because the
real target-observation count is 0. The public repository does not contain real
raw filled rows. Future real rows must be written under `.internal/`, validated,
pass intake, and then be sanitized before any public claim is made.
