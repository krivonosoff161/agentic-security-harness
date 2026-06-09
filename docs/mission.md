# Mission

> **Agentic Security Harness** — a **defensive education + measurement** project, not offensive
> tooling. See [Responsible use](../SECURITY.md#responsible-use) and
> [Safe research rules](research-rules.md).

## Problem

Agentic AI adoption is moving **faster than security literacy**. Teams ship agents, tool
chains, and multi-agent workflows before they can see, reproduce, or measure how those
systems fail. Failure modes — injection via tool output, lost data boundaries, memory
poisoning, recipient confusion — are discussed abstractly and rarely reproduced.

## Goal

Make agentic failure modes **visible, reproducible, measurable, and teachable**:

- **visible** — name and map the failure as a path through an attack graph;
- **reproducible** — capture it as a portable, deterministic trace;
- **measurable** — derive a scorecard, and replay against a defense to measure the delta;
- **teachable** — explain it with sanitized, mock-only learning material.

## Audience

Developers, security engineers, AI builders, and reviewers who need to understand and test
agentic systems **they own or are authorized to test**.

## Scope

Defensive testing and education only, against **mock / demo / authorized** systems, with
**synthetic** data and **sanitized** fixtures. The reference gateway is an optional defense
to measure against — not the product.

## Non-goals

- No offensive exploitation of real systems.
- No live-target testing.
- No weaponized payloads or abuse instructions.
- No claim of being the first or only tool in the category, or of providing complete protection.
