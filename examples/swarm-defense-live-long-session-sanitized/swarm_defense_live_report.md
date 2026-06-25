# Live Swarm Defense Campaign

Status: sanitized public summary over private local-model probes.

## Metrics

- observations: 15
- max session turns: 3
- long-session observations: 15
- worker drift detections: 0
- chief acceptances: 1
- canary leaks: 0
- verifier blocks: 1
- adapter errors: 1
- response hash coverage: 1.00

## Control attribution

| Control | Blocks | Reopened when missing |
|---|---:|---:|
| `audit_hash_chain` | 1 | 1 |
| `chief_verifier` | 1 | 1 |
| `cross_worker_check` | 1 | 1 |
| `source_hash` | 1 | 1 |
| `summary_guard` | 1 | 0 |

## Replay ablation

Replay ablation does not make new model calls. It replays the sanitized
verifier decisions from the private live run and asks which blocked
unsafe decisions would reopen if a named required control were absent.

- replay ablation reopenings: 4
- replay ablation reopening rate: 1.00

| Removed control | Reopened decisions |
|---|---:|
| `audit_hash_chain` | 1 |
| `chief_verifier` | 1 |
| `cross_worker_check` | 1 |
| `source_hash` | 1 |

## Non-claims

- No real secrets were used.
- A live local-model failure is not a CVE.
- A block in this campaign is not proof that a production swarm is secure.
- Response hashes prove artifact hygiene, not semantic truth.

Raw prompts, raw responses, synthetic canary values, and calculation notes are
private artifacts and are not part of this public summary.
