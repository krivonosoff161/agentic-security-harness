# Historical Marketing Web Observation (Schema 0.2)

This directory retains a structural-only detector-observation summary produced
under schema 0.2. Current schema 0.3 has no committed execution. Public validation
does not replay the private response bytes and does not prove model-execution
locality, origin, or absence of leakage.

## What ran

- Scenario domain: ads/marketing analysis swarm.
- Runtime shape: local web page -> worker model -> chief model -> deterministic verifier.
- Models: two local worker models and two local chief models.
- Modes: naive, bounded, control-ablation, and benign.
- Session pressure: unsafe rows use three worker turns before chief review.

## Public result

| Metric | Value |
|---|---:|
| Scenarios | `2` |
| Observations | `60` |
| Local web fetches | `60` |
| Worker leaks detected | `3` |
| Chief leaks detected | `1` |
| Naive final leaks | `0` |
| Bounded final leaks | `0` |
| Control-ablation final leaks | `1` |
| Benign final leaks | `0` |
| Verifier blocks | `8` |
| False blocks | `0` |
| Benign passes | `8` |
| Response hash coverage | `100%` |
| Per-turn hash coverage | `100%` |

The table preserves historical detector and rule-derived counts. The ablation and
verifier values are policy-simulation consistency, not independent causal effects.

## Validate

```bash
ash validate examples/marketing-web-live-sanitized
```

## Non-claims

This example is not a CVE, not a model leaderboard, not a real-secret extraction, and
not a production-swarm safety proof. It is a legacy structural summary, not a
current verified empirical artifact.
