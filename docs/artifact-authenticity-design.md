# Artifact Authenticity Trust-Root Design

Date: 2026-07-16
Status: public release workflow implementation is present on the audit branch; no post-change tag
has exercised it, historical subjects remain unsigned, and private/reviewer signing is not
implemented.

## Problem

Current schema-v0.3 run manifests bind the exact persisted bytes of their declared artifacts.
Applicable validators then rebuild semantic projections from those bytes. This detects an
uncoordinated edit, but a party that can rewrite both artifacts and manifest can create a new
self-consistent bundle. SHA-256, a Merkle tree, or a Git commit alone does not identify the
producer of a run.

The project needs separate answers to four questions:

1. Which bytes are the subject?
2. Which identity or service signed those bytes?
3. Which policy authorizes that signer for this artifact class?
4. What does the signed statement prove, and what remains outside it?

## Recommended Trust Split

Use two trust domains rather than one universal project signature.

### Public release and deterministic evidence bundles

Recommended root: GitHub Actions workload identity plus GitHub artifact attestations/Sigstore.
The release workflow builds exact wheel, source-distribution, and checksum subjects, emits
in-toto/SLSA provenance attestations only after repository gates and smoke installs, and verifies
both each subject digest and the expected repository/workflow/tag/source/builder policy in a
separate job. For a public repository, the Sigstore public-good trust root and transparency log supply
an independently auditable signing-time anchor. GitHub's private-repository Sigstore instance does
not provide that public transparency log, so a private-repository policy must not claim the same
public inclusion property.

This is a good fit for wheels, source distributions, and a canonical archive of curated public
examples. It is not evidence that a private local model run happened.

### Private/local empirical reconciliation

Recommended root: a separately authorized owner or reviewer identity signing a sanitized,
action-bound reconciliation receipt. The receipt should bind the public projection digest, the
private bundle commitment, the exact reconciliation algorithm/schema, reviewer role, decision,
and expiry/review policy. It must not publish raw private-file hashes when that creates a dictionary
or equality oracle.

Keyless public signing may expose signer identity and the receipt digest in a transparency log.
If that disclosure is unacceptable, an offline owner-managed signing key is the alternative, but
then secure key generation, storage, rotation, revocation, backup, and verifier distribution become
project responsibilities. The harness must never generate an "owner" signature for itself.

The local v0.1 reconciliation implementation intentionally stops below this trust root.
It can prove to the key-holding owner that exact private JSON bytes rebuild the supplied
public projection, satisfy the supported producer-stage/hash contract, and can emit an unsigned
HMAC/SHA-256 receipt. The retained private formats do not let it replay endpoint identity,
implementation execution, model identity, or all detector/canary semantics. Public-only validation
cannot replay the private commitment and the evidence registry therefore does not promote
such a receipt to `local_empirical_reconciled`, `content_bound`, or `signed_attested`.

## Verification Contract

No artifact may be promoted to `signed_attested` merely because it contains a signature-shaped
field or a Sigstore bundle. A verifier must fail closed unless all of these hold:

- the signed subject digest matches the exact canonical persisted subject bytes;
- signature, certificate chain, and transparency inclusion verify under the configured trust root;
- issuer and signer identity match an explicit artifact-class policy;
- repository, workflow path, ref/event policy, and source commit match the expected release policy;
- predicate type is exactly `https://slsa.dev/provenance/v1`, its supported major-version schema is
  enforced, unexpected `externalParameters` fail, and ignored extension fields never widen trust;
- the verified signing/workload identity and provenance `builder.id` pair is allowed by policy and
  maps to an explicit maximum SLSA Build level; they are not required to be distinct identities;
- the attestation is not revoked and satisfies the configured freshness/review policy;
- every promoted evidence-registry row points to the validated receipt/attestation;
- unsupported model/runtime, semantic-truth, locality, and completeness claims remain forbidden.

Verification must be independent of self-declared manifest fields. A workflow that signs arbitrary
tenant-supplied provenance without verifying it does not create trustworthy provenance.

## Trusted-Time Boundary

A transparency-log inclusion time can show that a signed statement existed no later than a logged
time. It does not authenticate the run's self-declared `created_at`, observation time, exchange time,
or model response time. Retention must continue to call its chronology unsigned unless its ordering
field is supplied by the chosen trusted service and bound into the verified statement.

## Options Rejected As Sole Trust Roots

| Option | Why it is insufficient alone |
|---|---|
| SHA-256 or Merkle root in the same bundle | Detects uncoordinated edits, but the bundle owner can rewrite content and root together. |
| Signed Git commit/tag only | Authenticates a repository object under a key policy, but does not prove which CI process built a released wheel or produced a local empirical run. |
| Self-generated receipt signature | The producer would be attesting its own owner/reviewer authority. |
| Unsigned in-toto/SLSA JSON | Gives a useful interoperable statement shape, but remains forgeable. |
| One shared long-lived key in CI and local workstations | Expands compromise scope and makes attribution, rotation, and revocation ambiguous. |

## Implementation State And Remaining Sequence

1. The user authorized the public GitHub Actions workload identity and exact tag-push workflow for
   this audit branch; private/reviewer trust remains separate.
2. Wheel, source distribution, and checksum file are the exact release-workflow subjects. A
   canonical deterministic-example archive remains future work.
3. The branch adds a versioned in-toto/SLSA v1.2 attestation policy and negative verification
   fixtures.
4. The branch pins `actions/attest` by immutable commit and grants
   `contents: read`, `id-token: write`, and `attestations: write` only to the release job that
   needs them. `artifact-metadata: write` is separate and is needed only if the owner chooses
   GitHub linked-artifact storage records.
5. The branch generates attestations only after tests, validation, package smoke, and subject
   digest creation.
6. The branch adds a separate verification job with expected subject, repository, workflow, issuer,
   tag ref, source digest, builder, event, hosted-runner, predicate, and verified-time constraints.
7. Run a future authorized tag and independently retain/verify its exact subjects. Until that
   succeeds, operational status remains unverified and historical artifacts remain unsigned.
8. Only a future supported evidence-registry contract may reference a validated
   `signed_attested` receipt; this workflow does not promote any current row.
9. Design the separate private reconciliation signer and revocation process; do not reuse release
   provenance as owner observation or trading approval.

## Decisions Still Required

The public workflow implementation is authorized for the task branch, but merge and future tag
creation remain owner decisions. The owner must still choose:

- whether deterministic examples are attested individually or as one canonical archive;
- the signer and disclosure policy for private reconciliation receipts;
- rotation, revocation, monitoring, and incident-response ownership.

## Primary References

- [Sigstore keyless signing overview](https://docs.sigstore.dev/cosign/signing/overview/)
- [Sigstore security model](https://docs.sigstore.dev/about/security/)
- [GitHub artifact attestation security model](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [GitHub artifact attestation workflow](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [SLSA v1.2 specification](https://slsa.dev/spec/v1.2/)
- [SLSA v1.2 build provenance](https://slsa.dev/spec/v1.2/build-provenance)
- [SLSA v1.2 artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts)
