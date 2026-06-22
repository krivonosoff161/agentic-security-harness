# Local Swarm Allowed-Flow Example

This committed example is the utility side of the bounded-swarm evidence suite. It checks
that benign synthetic handoffs and memory reads pass deterministic contracts instead of
being blocked by a "deny everything" system.

Regenerate:

```bash
ash local-swarm-allowed --write --out reports/local-swarm-allowed-flows
ash validate reports/local-swarm-allowed-flows
```

Expected stable metrics:

- flows: 6
- allowed passes: 6
- unexpected blocks: 0
- false-positive rate: 0%

Non-claim: this is not a production false-positive rate and does not execute real tools.
