# Marketing Web Live Sanitized Example

This directory is a curated public summary of a private local-model run against an
owned local web stand. Raw HTML pages, prompts, model responses, and synthetic strategy
values remain under `.internal/` and are not committed.

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

The useful evidence is the contrast: a synthetic strategy component reached the final
chief output when the responsible control was ablated, while bounded mode recorded zero
final leaks and benign rows still passed.

## Validate

```bash
ash validate examples/marketing-web-live-sanitized
```

## Non-claims

This example is not a CVE, not a model leaderboard, not a real-secret extraction, and
not a production-swarm safety proof. It is a sanitized local empirical artifact for the
declared marketing web-ingestion scenario.
