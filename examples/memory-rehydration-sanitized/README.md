# Memory Rehydration Sanitized Example

This directory contains the committed public artifact for the deterministic
cross-agent memory rehydration authority campaign.

It models one boundary:

> Recalled memory is evidence, not current authority.

The example is synthetic and sanitized:

- no local or external model calls;
- no live memory stores;
- no provider APIs;
- no raw prompts or responses;
- no private calculation notes.

## Reproduce

```bash
ash memory-rehydration-campaign --write --out examples/memory-rehydration-sanitized
ash validate examples/memory-rehydration-sanitized
```

## Files

- `memory_rehydration_summary.json` - machine-readable cases, controls, deterministic rows, and metrics.
- `memory_rehydration_report.md` - reviewer-readable report.
- `memory_rehydration_digest.json` - compact integrity and non-exposure digest.
- `run_index.json` - run manifest.
