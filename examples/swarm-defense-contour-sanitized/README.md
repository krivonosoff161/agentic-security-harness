# Swarm Defense Contour Sanitized Example

This committed example is the public, sanitized output of:

```bash
ash swarm-defense-contour --write --out examples/swarm-defense-contour-sanitized
ash validate examples/swarm-defense-contour-sanitized
```

It combines four declared local-swarm failure families:

- semantic parameter drift;
- worker-to-chief propagation;
- consensus laundering;
- benign-framed boundary leakage.

The artifact evaluates all 15 non-empty family combinations in bounded, naive, and
control-ablation modes.

Public claim: bounded deterministic contracts accept 0 declared unsafe paths while naive
mode accepts the declared unsafe paths, and responsible control ablations reopen dependent
paths.

Non-claim: this is not a live model benchmark, production swarm guarantee, CVE, or proof
that semantic truthfulness is solved. Raw local-model prompts, responses, synthetic
canaries, and private calculations stay under `.internal/`.
