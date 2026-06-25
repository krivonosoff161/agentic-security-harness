# Live Swarm Defense Campaign

Status: sanitized public summary over private local-model probes.

## Metrics

- observations: 180
- worker drift detections: 1
- chief acceptances: 22
- canary leaks: 0
- verifier blocks: 22
- adapter errors: 0
- response hash coverage: 1.00

## Control attribution

| Control | Blocks | Reopened when missing |
|---|---:|---:|
| `audit_hash_chain` | 22 | 22 |
| `canonical_state` | 1 | 1 |
| `chief_verifier` | 22 | 22 |
| `cross_worker_check` | 17 | 17 |
| `source_hash` | 22 | 16 |
| `summary_guard` | 22 | 17 |
| `transition_table` | 1 | 0 |
| `worker_attestation` | 1 | 1 |

## Non-claims

- No real secrets were used.
- A live local-model failure is not a CVE.
- A block in this campaign is not proof that a production swarm is secure.
- Response hashes prove artifact hygiene, not semantic truth.

Raw prompts, raw responses, synthetic canary values, and calculation notes are
private artifacts and are not part of this public summary.
