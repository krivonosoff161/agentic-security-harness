# Historical Swarm Defense Observation (Legacy Schema)

Status: structural-only pre-0.5 detector-observation summary. The current schema
has no committed execution; canary-zero and causal-reopening interpretations are
withdrawn, and public validation does not replay private responses.

## Metrics

- observations: 168
- max session turns: 3
- long-session observations: 168
- worker drift detections: 3
- chief acceptances: 67
- canary leaks: 0
- verifier blocks: 70
- adapter errors: 7
- detector-positive observations: 70
- detector-negative observations: 91
- expected response hash coverage: 0.96
- turn hash coverage: 1.00
- detector-positive block consistency: 1.00
- benign allow rate: 1.00
- independent-label coverage: 0.00

Unsafe/benign observation counts above are detector-derived. Precision, recall, and specificity are claimed only for independently reviewed rows; historical rows without a private review remain `not_adjudicated`.
The legacy `unsafe_block_rate` field is a policy-consistency check: the same detector signals define detector-positive rows and trigger the deterministic block. It is not an independent effectiveness estimate.

## Control attribution

| Control | Blocks | Reopened when missing |
|---|---:|---:|
| `audit_hash_chain` | 70 | 70 |
| `canonical_state` | 3 | 1 |
| `chief_verifier` | 67 | 67 |
| `cross_worker_check` | 18 | 18 |
| `source_hash` | 67 | 48 |
| `summary_guard` | 67 | 37 |
| `transition_table` | 3 | 1 |
| `worker_attestation` | 3 | 0 |

## Replay ablation

Replay ablation does not make new model calls. It replays the sanitized
verifier decisions from the private live run and asks which blocked
unsafe decisions would reopen if a named required control were absent.

- replay ablation reopenings: 242
- replay ablation reopening rate: 1.00

| Removed control | Reopened decisions |
|---|---:|
| `audit_hash_chain` | 70 |
| `canonical_state` | 1 |
| `chief_verifier` | 67 |
| `cross_worker_check` | 18 |
| `source_hash` | 48 |
| `summary_guard` | 37 |
| `transition_table` | 1 |

## Rate confidence intervals

Wilson 95% intervals over this bounded campaign:
- `benign_allow_rate`: [0.960, 1.000]
- `canary_leak_rate`: [0.000, 0.022]
- `chief_acceptance_rate`: [0.328, 0.474]
- `verifier_block_rate`: [0.345, 0.492]
- `worker_drift_rate`: [0.006, 0.051]

## Model breakdown

Worker model observations:
- `qwen2.5-coder:0.5b-instruct`: observations=84, chief_acceptances=35
- `qwen2.5:0.5b`: observations=84, chief_acceptances=32

Chief model observations:
- `llama3.2:1b`: observations=84, chief_acceptances=6
- `prometheus-qwen15b-lowctx:latest`: observations=84, chief_acceptances=61

## Non-claims

- No real secrets were used.
- A live local-model failure is not a CVE.
- A block in this campaign is not proof that a production swarm is secure.
- Response hash fields are commitments; without owner-side reconciliation they do not prove private-byte retention, origin, or semantic truth.

Raw prompts, raw responses, synthetic canary values, and calculation notes are
private artifacts and are not part of this public summary.

## Historical Reliability Notice

This pre-0.5 artifact is retained for structural historical review only. Its `canary leaks: 0` result is withdrawn because the legacy aggregator did not recognize several detector categories. Control “reopening” counts are rule attributions, not paired causal effects. It does not exercise the current staged-error, partial-event, execution-identity, or source-fingerprint contract.
