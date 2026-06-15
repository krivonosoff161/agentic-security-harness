# Protected demo agent report

This directory is a committed, validated snapshot of:

```bash
ash run --target protected-demo-agent --out reports/protected-demo-agent
```

`protected-demo-agent` is the same local synthetic agent shape as `demo-agent`, but with
simple deterministic controls. It demonstrates how the same corpus can be replayed
against a protected target.

Expected reading:

- `scorecard.json` should show no findings for the shipped corpus.
- `summary.md` and `executive.md` explain the clean result and residual risk.
- There is no remediation report because this target is clean under the modeled patterns.

Validate with:

```bash
ash validate examples/protected-demo-agent-report
```

A clean report is not a production safety claim. It only means this target handled the
modeled synthetic patterns in this deterministic run.
