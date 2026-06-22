# Local Swarm Control Ablation Example

This committed example attributes each bounded local-swarm block to the primary
deterministic control that catches it.

Regenerate:

```bash
ash local-swarm-ablation --write --out reports/local-swarm-ablation-matrix
ash validate reports/local-swarm-ablation-matrix
```

Expected stable metrics:

- scenarios: 15
- bounded blocks with all controls: 15
- vulnerable when primary control removed: 15
- represented controls: 7

Non-claim: this is a deterministic control-attribution model, not exhaustive attack
coverage or a cryptographic audit-log proof.
