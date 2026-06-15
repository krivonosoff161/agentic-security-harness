# Demo agent report

This directory is a committed, validated snapshot of:

```bash
ash run --target demo-agent --out reports/demo-agent
```

`demo-agent` is a local vulnerable-by-design synthetic agent. It models agent mechanics
such as memory, tool calls, data-envelope propagation, and recipient checks, but it makes
no network or provider calls.

This report demonstrates what a vulnerable target looks like in the harness:

- portable traces in `traces.json`;
- deterministic aggregate results in `scorecard.json`;
- human-readable summaries in `executive.md` and `summary.md`;
- remediation guidance in `remediation.md` / `remediation.json`.

Validate with:

```bash
ash validate examples/demo-agent-report
```
