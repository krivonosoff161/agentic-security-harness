# Historical Swarm Defense Observation (Legacy Schema)

Status: structural-only pre-0.5 detector-observation summary. The current schema
has no committed execution; canary-zero and causal-reopening interpretations are
withdrawn, and public validation does not replay private responses.

## Metrics

- observations: 180
- max session turns: 1
- long-session observations: 0
- worker drift detections: 1
- chief acceptances: 22
- canary leaks: 0
- verifier blocks: 22
- adapter errors: 0
- detector-positive observations: 22
- detector-negative observations: 158
- expected response hash coverage: 1.00
- turn hash coverage: 0.00
- detector-positive block consistency: 1.00
- benign allow rate: 1.00
- independent-label coverage: 0.00

Unsafe/benign observation counts above are detector-derived. Precision, recall, and specificity are claimed only for independently reviewed rows; historical rows without a private review remain `not_adjudicated`.
The legacy `unsafe_block_rate` field is a policy-consistency check: the same detector signals define detector-positive rows and trigger the deterministic block. It is not an independent effectiveness estimate.

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

## Replay ablation

Replay ablation does not make new model calls. It replays the sanitized
verifier decisions from the private live run and asks which blocked
unsafe decisions would reopen if a named required control were absent.

- replay ablation reopenings: 96
- replay ablation reopening rate: 1.00

| Removed control | Reopened decisions |
|---|---:|
| `audit_hash_chain` | 22 |
| `canonical_state` | 1 |
| `chief_verifier` | 22 |
| `cross_worker_check` | 17 |
| `source_hash` | 16 |
| `summary_guard` | 17 |
| `worker_attestation` | 1 |

## Rate confidence intervals

Wilson 95% intervals over this bounded campaign:
- `benign_allow_rate`: [0.976, 1.000]
- `canary_leak_rate`: [0.000, 0.021]
- `chief_acceptance_rate`: [0.082, 0.178]
- `verifier_block_rate`: [0.082, 0.178]
- `worker_drift_rate`: [0.001, 0.031]

## Model breakdown

Worker model observations:
- `qwen2.5-coder:0.5b-instruct`: observations=90, chief_acceptances=6
- `qwen2.5:0.5b`: observations=90, chief_acceptances=16

Chief model observations:
- `llama3.2:1b`: observations=180, chief_acceptances=22

## Non-claims

- No real secrets were used.
- A live local-model failure is not a CVE.
- A block in this campaign is not proof that a production swarm is secure.
- Response hash fields are commitments; without owner-side reconciliation they do not prove private-byte retention, origin, or semantic truth.

Raw prompts, raw responses, synthetic canary values, and calculation notes are
private artifacts and are not part of this public summary.

## Historical Reliability Notice

This pre-0.5 artifact is retained for structural historical review only. Its `canary leaks: 0` result is withdrawn because the legacy aggregator did not recognize several detector categories. Control “reopening” counts are rule attributions, not paired causal effects. It does not exercise the current staged-error, partial-event, execution-identity, or source-fingerprint contract.
