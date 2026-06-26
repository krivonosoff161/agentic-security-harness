# Private/Public Evidence Boundary

This project has two evidence surfaces:

- deterministic public examples that can be fully regenerated and committed; and
- local empirical campaigns that use real local model outputs while keeping raw
  transcripts private.

The second surface is useful, but it needs a stricter publication contract. Public
artifacts should let a reviewer inspect the run shape, counts, classifications, response
hashes, and validation status without exposing prompts, raw model text, synthetic
canaries, local paths, or private calculation notes.

## Public Fields

Sanitized local empirical artifacts may publish:

- model names and runtime family labels;
- worker/chief/runtime roles;
- topology ids, scenario ids, pressure labels, and session-turn counts;
- observation counts, adapter-error counts, and response-hash coverage;
- response SHA-256 hashes and per-turn response SHA-256 hashes;
- aggregate classifications such as drift detections, chief acceptances, verifier
  blocks, and canary-leak counts;
- unsafe/benign aggregate counts and rates, with confidence intervals;
- model-level aggregate breakdowns, without publishing raw model text;
- verifier/control attribution, replay-ablation metrics, and non-claims;
- schema version, run kind, command shape, and validation commands.

These fields are enough to support public artifact review. They are not enough to prove
semantic truthfulness or general model safety.

## Private Fields

The following stay private under `.internal/` or another ignored local workspace:

- raw prompts and prompt chains;
- raw model responses and raw transcripts;
- synthetic canary values and secret-shaped strings;
- canonical state raw material and private calculation notes;
- local absolute paths, machine-specific logs, and credentials;
- operational notes that teach how to pressure a model into an unsafe response.

Do not commit ad hoc `reports/` output as public evidence unless it has been curated,
sanitized, validated, and explicitly promoted into `examples/`.

## Hash Anchoring

Public artifacts do not include raw transcripts, but every private response is anchored
by a public SHA-256 hash for owner-side audit replay.

That hash anchor proves public/private artifact hygiene: the public row can be matched
to a private response retained by the owner. It does not prove that the response is
semantically correct, that the model is safe, or that another runtime will reproduce the
same text.

## Claim Levels

Use this language consistently:

| Evidence class | Publication state | What it supports | What it does not support |
|---|---|---|---|
| Deterministic public example | Committed under `examples/` | Reproducible synthetic control behavior and artifact validation. | Production safety or model safety. |
| Local empirical summary | Sanitized public example plus private raw run | Real local model outputs were exercised under the declared caps and summarized safely. | Leaderboard, CVE, universal model vulnerability, or exhaustive attack coverage. |
| Local scratch | Ignored `.internal/` or `reports/` only | Owner-side calculation and debugging. | Public evidence claim. |

The live mini-swarm campaign uses real local model outputs, but ASH publishes only
sanitized hash-anchored summaries. The evidence supports the declared control-path
claim, not a general model-safety conclusion.

## Reviewer Workflow

For public review:

```bash
ash validate examples/
ash validate examples/swarm-defense-live-sanitized
ash validate examples/swarm-defense-live-long-session-sanitized
ash validate examples/swarm-defense-live-deep-sanitized
ash validate examples/marketing-web-live-sanitized
```

For owner-side replay, compare the public response hashes with the private raw run kept
outside git. If the private run is unavailable, the public artifact remains an aggregate
validated summary, not a transcript-level proof.

## Non-Claims

Do not claim:

- production swarm safety;
- provider or model safety;
- CVE status;
- real-secret extraction;
- exhaustive pressure coverage;
- deterministic validators solve semantic truth.
