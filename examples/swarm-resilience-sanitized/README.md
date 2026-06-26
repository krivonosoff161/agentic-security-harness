# Swarm Resilience Sanitized Example

This directory contains the public artifact for the deterministic swarm-resilience
campaign.

It covers seven multi-step degradation families:

- long-session memory contamination
- semantic term drift
- source trust-score poisoning
- consensus laundering
- metric/verdict manipulation
- benign-looking fact accumulation
- coupled stability cascades

The committed files are sanitized. Private synthetic payload notes and per-step
calculation traces are written under `.internal/swarm-resilience/` and are not part
of the public repository.

Validate this example with:

```bash
ash validate examples/swarm-resilience-sanitized
```
