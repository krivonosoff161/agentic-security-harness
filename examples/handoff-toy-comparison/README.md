# Handoff toy comparison

Curated public example for the local deterministic coordinator/worker handoff
topology.

Reproduce:

```bash
ash compare --baseline toy-multi-agent --protected protected-toy-multi-agent --out examples/handoff-toy-comparison
ash validate examples/handoff-toy-comparison
```

What this shows:

- `toy-multi-agent` records two modeled handoff findings: label/provenance loss and
  capability authority expansion.
- `protected-toy-multi-agent` blocks the same malformed handoffs.
- The artifact is local, synthetic, deterministic, and validates against the committed
  corpus manifest.

What this does not show:

- It is not evidence that a live multi-agent framework preserves handoff integrity.
- It is not evidence about real provider calls, real tools, or production handoff
  protocols.
- It does not solve semantic truthfulness; it only checks typed envelope, payload hash,
  provenance labels, recipient, policy, freshness, and authority non-expansion
  invariants under this toy topology.
