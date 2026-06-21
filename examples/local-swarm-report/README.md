# Local Swarm Report

Committed deterministic example for the bounded local-swarm research lane.

It compares three synthetic execution shapes over the same boundary scenarios:

- `monolith`: one role consumes unsafe context without a contract gate;
- `naive_swarm`: roles exist, but checks are advisory or absent;
- `bounded_swarm`: deterministic ASH handoff and memory contracts block unsafe transfers
  before later roles can consume them.

## Reproduce

```bash
ash local-swarm --write-dry-run --out reports/local-swarm
ash validate reports/local-swarm
```

Validate this committed snapshot:

```bash
ash validate examples/local-swarm-report
```

## Read First

1. `local_swarm_report.md` - human-readable metrics and per-scenario results.
2. `local_swarm_summary.json` - machine-readable source of truth.
3. `run_index.json` - run manifest for indexing.

## Claim Boundary

This example shows deterministic modeled boundary-failure reduction in a synthetic local
topology. It does not prove that a live multi-agent framework, provider, local model, or
production deployment is safe.
