# Private/Public Evidence Boundary

Portfolio-level documentation and storage authority is defined in the
[Documentation Contract](https://github.com/krivonosoff161/krivonosoff161/blob/main/docs/documentation-contract.md).
This page is the Agentic Security Harness evidence-specific rule: it explains
which benchmark artifacts can be public and which raw/local evidence must stay
private.

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

Public artifacts do not include raw transcripts. Some rows carry a SHA-256-shaped
owner-side commitment intended for later reconciliation with retained private bytes.

The public hash alone does not prove that matching private bytes exist, that they were
produced by the declared model/runtime, or that the unverified detector label is correct.
Only a separate owner-side reconciliation over the exact persisted representation can
show byte equality; authorship still requires an external trust root or signature. The
implemented v0.1 owner-side contract rebuilds each supported public campaign projection,
binds the exact public JSON bytes with SHA-256, and commits to the exact private JSON bytes
with HMAC-SHA-256 under a non-published owner key. A public-only receipt check intentionally
reports private replay and origin authentication as unverified.
The current owner-side replay additionally requires the producer-declared matrix to be complete,
checks supported private schema versions and adapter-error ordering, and recomputes every retained
raw-text hash used by the supported public projection. It cannot replay the raw endpoint behind
`endpoint_sha256`, prove which implementation or model executed, or independently recalculate
detector/canary classifications whose full inputs are not retained. Those remain explicit
limitations even when byte reconciliation succeeds.
The release-signing and private-reconciliation trust domains must remain separate; see
[Artifact Authenticity Trust-Root Design](artifact-authenticity-design.md).

## Claim Levels

Use this language consistently:

| Evidence class | Publication state | What it supports | What it does not support |
|---|---|---|---|
| Deterministic public example | Committed under `examples/` | Reproducible synthetic control behavior and artifact validation. | Production safety or model safety. |
| Reconciled local empirical summary | Sanitized public example plus validated private bundle and reconciliation receipt | The supplied persisted bytes reproduce the public projection and its retained raw-text hash bindings for the complete declared matrix. | Detector correctness, endpoint/model/implementation identity without independent evidence, model-execution locality without attestation, authorship without a trust root, leaderboard, CVE, or exhaustive coverage. |
| Historical detector-observation summary | Legacy sanitized public example without current private-bundle reconciliation | Declared rows, hashes, and aggregates remain readable under limited structural checks. | Current empirical evidence, private-byte retention, detector correctness, model locality, or authenticity. |
| Local scratch | Ignored `.internal/` or `reports/` only | Owner-side calculation and debugging. | Public evidence claim. |

The committed mini-swarm examples are historical detector-observation summaries under
legacy schemas. Current public validation does not replay their private bytes, and the
current live schema has no committed execution.

## Reviewer Workflow

For public review:

```bash
ash validate examples/
ash validate examples/swarm-defense-live-sanitized
ash validate examples/swarm-defense-live-long-session-sanitized
ash validate examples/swarm-defense-live-deep-sanitized
ash validate examples/marketing-web-live-sanitized
```

For owner-side reconciliation, use `create_reconciliation_receipt` on the exact persisted
private JSON under `.internal/` and the corresponding public summary, then independently
replay it with `verify_owner_reconciliation`. Keep the HMAC key outside the receipt and do
not reuse it as a signing or trading-authorization key. The v0.1 receipt records
`trusted_time=not_recorded`; it must not be described as dated or authenticated until the
separate signer/trusted-time policy is implemented. If the private bundle, HMAC key, or
receipt is unavailable, the public artifact remains a structural aggregate, not empirical or
transcript-level proof.

## Non-Claims

Do not claim:

- production swarm safety;
- provider or model safety;
- CVE status;
- real-secret extraction;
- exhaustive pressure coverage;
- deterministic validators solve semantic truth.
