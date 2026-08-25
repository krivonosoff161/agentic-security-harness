# Security Portfolio roadmap contract

> Historical R4 research projection, preserved without rewriting its evidence semantics.
> Current public product sequencing lives in [`ecosystem/roadmap.yaml`](../ecosystem/roadmap.yaml)
> and the generated [ecosystem roadmap](ecosystem-roadmap.md). This page grants no
> authority and must not be used as current cross-repository product status.

Agentic Security Harness owns six public portfolio modules:

- `M02-canonical-envelope`: provider-neutral development contract and scenario identity;
- `M12-harness-regression`: public synthetic falsification and regression laboratory.
- `M17-typed-outcome-contract`: bounded outcome taxonomy without inferred success;
- `M18-mcp-redaction-receipt`: privacy-minimized MCP telemetry and redaction receipt;
- `M19-trajectory-accounting`: retry, route-change, timing, and lineage accounting;
- `M20-telemetry-completeness`: explicit missing-field and incomplete-telemetry semantics.

All six modules are `implemented_development`: verified only within their declared
development/synthetic contours, not independently or in production.

The vendored [`security-portfolio-roadmap-public.yaml`](security-portfolio-roadmap-public.yaml)
is the digest-bound portfolio-wide sanitized projection. The profile copy is a publication
location, not digest authority. The private Runtime Guard repository remains the source
for its private research evidence, not the owner of the public ecosystem product roadmap.
This repository owns the six historical projection modules above and a separate open
synthetic gateway reference contour; that contour does not
change portfolio digests or promote phase, evidence class, independence, authority,
production enforcement, release, or effectiveness claims.

The machine pin is [`security-portfolio-roadmap-contract.json`](security-portfolio-roadmap-contract.json). Local CI checks its schema, digest format, module ownership, bounded statuses, and non-claims. A new public projection version requires an explicit contract update; it is never fetched from a private repository in public CI.

Current pin: `2026.08.02-r4-trajectory-containment`. Authority: `none`.
