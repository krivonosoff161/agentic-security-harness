# Swarm Resilience Campaign

This campaign is the deterministic stability layer for the local mini-swarm work.
It asks a narrower question than "is a model safe?":

> When a small-agent system is slowly pushed through memory, semantics, source trust,
> consensus, metrics, and cumulative benign-looking facts, does the bounded contract
> return the swarm to a safe state, or does the state diverge?

## Scope

The campaign covers seven declared degradation families:

1. long-session memory contamination;
2. semantic term drift;
3. source trust-score poisoning;
4. consensus laundering between small workers;
5. metric and verdict manipulation;
6. benign-looking fact accumulation;
7. coupled stability cascades across several weak axes.

The public artifact is committed at
[`examples/swarm-resilience-sanitized/`](../examples/swarm-resilience-sanitized/).
Private calculation traces are written under `.internal/swarm-resilience/` and are
not committed.

## State Model

Each step updates an explicit state vector:

```text
x_t = [
  memory_contamination,
  semantic_drift,
  trust_poison,
  consensus_pressure,
  verdict_bias,
  cumulative_pressure
]
```

The update rule is deliberately simple and auditable:

```text
x_{t+1} = decay(mode) * x_t + attenuation(mode, active_controls) * delta_t
```

The stability energy is:

```text
E_t = sqrt(sum_i x_{t,i}^2)
```

Bounded mode is expected to either keep `E_t` below the unsafe region or block and
recover the responsible axis. Ablation mode removes one named control and must reopen
the dependent failure when that control is actually responsible.

## Current Public Result

The committed sanitized example records:

- scenarios: `7`
- observations: `46`
- naive unsafe acceptances: `7`
- bounded unsafe acceptances: `0`
- ablation unsafe acceptances: `18`
- benign false blocks: `0`
- state-hash coverage: `100%`

This reproduces rule-encoded control dependencies for the declared stability model. It does not prove
production swarm safety, exhaustive attack coverage, or real-secret extraction.

## Controls

| Control | Role |
|---|---|
| `memory_provenance` | Rejects stale/untrusted memory as current authority. |
| `canonical_terms` | Pins meanings and rejects unapproved relabeling. |
| `source_trust_floor` | Separates source reputation from evidence volume. |
| `cross_worker_check` | Preserves disagreement and rejects fake consensus. |
| `metric_replay` | Recomputes verdict metrics from immutable observations. |
| `cumulative_risk_guard` | Tracks aggregate sensitivity across benign-looking facts. |
| `stability_monitor` | Watches coupled low-amplitude drift across axes. |

## Reproduce

```bash
ash swarm-resilience-campaign --write \
  --out .internal/swarm-resilience/latest \
  --summary-out examples/swarm-resilience-sanitized
ash validate examples/swarm-resilience-sanitized
```

Use a different `--summary-out` for scratch runs; committed examples are curated.
