# Demo report: mock target

This directory is a committed, validated snapshot of:

```bash
ash run --target mock --out reports/demo
```

The `mock` target is deterministic, local, synthetic, and vulnerable by design. It exists
to make the corpus and report format easy to inspect without running a model, network
endpoint, or real agent.

Read in this order:

1. `executive.md` - high-level result and residual risk.
2. `summary.md` - per-pattern table.
3. `remediation.md` - control recommendations for findings.
4. `traces.json` and `scorecard.json` - authoritative machine-readable artifacts.

Validate with:

```bash
ash validate examples/demo-report
```

Validation checks artifact integrity and corpus consistency. It does not prove any real
system is secure.
