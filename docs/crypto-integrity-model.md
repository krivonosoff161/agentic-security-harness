# Crypto / Artifact Integrity Model

This document defines what ASH currently means by artifact integrity. It is intentionally
conservative: the project validates local benchmark artifacts and hash links, but it does
not yet claim signed provenance or tamper-proof distribution.

## Scope

The model covers committed and locally generated ASH artifacts:

- traces, scorecards, remediation, comparisons, matrices, run manifests, and static HTML;
- external/local evidence metadata and raw-response hashes where present;
- local-swarm summaries, allowed-flow checks, ablation matrices, and attack matrices;
- reproducibility reports that regenerate deterministic examples and compare stable
  metrics.

It does not cover production model providers, live agent hosts, private deployment logs,
or third-party storage systems.

## Trusted Computing Base

The current trusted computing base (TCB) is:

| Component | Why it is trusted today | Residual risk |
|---|---|---|
| Local Python interpreter and package environment | Executes the deterministic benchmark code. | A compromised interpreter or dependency can alter results. |
| ASH source tree at a Git commit | Defines patterns, targets, validators, and artifact writers. | Git history proves authorship order, not runtime honesty. |
| `ash validate` | Checks structure, schema versions, corpus consistency, standards mapping, and forbidden markers. | Validation is not a security proof. |
| `run_index.json` manifests | Bind a run kind, target, scenario, variants, outcomes, and artifact filenames. | They are local metadata, not signed attestations. |
| Hash fields in artifacts | Bind raw responses or payloads to recorded metadata. | Hashes prove byte identity only when the referenced bytes are present. |

## Artifact Hashes

Current hash uses:

- `payload_sha256(...)` in handoff envelopes over canonical JSON payload bytes.
- `raw_response_sha256` in external artifacts when raw model text is retained locally.
- `prompt_sha256` / `response_sha256` in local-swarm role transcripts.
- Run manifests list artifact filenames but do not yet hash every artifact.

The project treats hashes as integrity metadata, not confidentiality controls. A hash does
not hide content and does not prove that content is true.

## Canonical JSON

For handoff payloads, canonical bytes are generated with:

- UTF-8 JSON;
- sorted keys;
- compact separators;
- no semantic normalization beyond JSON structure.

This is sufficient for deterministic synthetic fixtures. It is not yet a cross-language
canonicalization standard for arbitrary provider payloads.

Future artifact-level canonicalization should define:

1. which JSON fields are signed or hashed;
2. which fields are intentionally excluded (`created_at`, local paths, transient runtime
   diagnostics);
3. domain separation strings such as `ash.trace.v1` or `ash.local_swarm.v1`;
4. stable line endings and UTF-8 requirements for Markdown or raw text references.

## Replay And Timestamp Model

Current replay evidence is deterministic for built-in local targets. Timestamps are
metadata unless a scenario explicitly checks freshness, TTL, or replay.

Timestamp-sensitive checks currently exist in:

- handoff TTL / `expires_at`;
- memory TTL measured from write time;
- run manifests as informational `created_at`.

Non-claim: current run manifests do not prove wall-clock execution time, trusted time, or
non-replay across machines.

## Future Signatures

The next integrity layer can add signatures without changing the benchmark thesis:

1. produce a canonical artifact manifest with per-file SHA-256;
2. sign the manifest with Sigstore or another transparent signing flow;
3. optionally attach SLSA/in-toto provenance for release artifacts;
4. validate signatures separately from benchmark verdicts.

Signatures would prove that a named identity signed a specific artifact set. They would
not prove that the benchmark claim is correct or complete.

## Current Verification Algorithm

For a public deterministic example:

1. run `ash validate examples/`;
2. verify every discovered artifact schema version is supported;
3. verify corpus consistency and report shape;
4. verify forbidden marker scans pass;
5. optionally run `ash reproduce-examples` and compare stable metrics against committed
   examples;
6. inspect static HTML/Markdown views only as human-readable projections of JSON.

## Non-Claims

ASH currently does not claim:

- cryptographic non-repudiation for every public artifact;
- signed release provenance;
- tamper-proof local reports;
- secure storage of private model responses;
- production audit-log completeness;
- that a hash proves semantic truthfulness;
- that the `24 -> 0` demo is a production security guarantee.

## Roadmap

| Step | Status |
|---|---|
| Schema-versioned JSON artifacts | Shipped |
| Run manifests per run directory | Shipped |
| Raw response / local role-output hash fields | Shipped where applicable |
| Reproducibility pack over deterministic examples | Shipped |
| Whole-artifact manifest hash | Planned |
| Sigstore / signing workflow | Future |
| in-toto / SLSA provenance for releases | Future |
