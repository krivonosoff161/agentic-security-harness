# Use cases

> **Agentic Security Harness** is for defensive evaluation of agentic AI systems. It is
> model-provider agnostic: the benchmark logic is about agents, tools, memory, handoffs,
> providers, and data boundaries, not one specific LLM vendor.

## Who this is for

- AI platform teams preparing agent workflows for production.
- Security teams reviewing tool-using LLM systems.
- Engineering teams adding memory, RAG, MCP/tools, provider routing, or multi-agent flows.
- Researchers who need reproducible, sanitized examples of agentic failure modes.
- Educators teaching practical AI safety and security controls.

## What it helps answer

- Can an agent keep sensitive data within the allowed recipient set?
- Does `can_store=false` survive memory writes and later use?
- Can untrusted tool output influence an agent decision?
- Are labels preserved across handoffs?
- Can an agent call a tool outside the allowed purpose?
- Can restricted data cross a provider boundary?
- Does a proposed defense reduce findings on the same reproducible corpus?

## Practical company workflows

### 1. Pre-production agent review

Before an agent workflow goes live, run a local benchmark against a toy or adapter target
that mirrors the workflow's data boundaries. The output is not a compliance certificate;
it is a structured list of behaviors to fix or accept as residual risk.

### 2. Data-boundary regression testing

When a team changes memory, tool routing, provider routing, or handoff logic, replay the
same patterns and compare scorecards. This catches regressions such as label stripping,
recipient confusion, or unwanted storage.

### 3. Defense comparison

Compare a baseline target with a protected target. The current demo shows:

```text
baseline demo-agent:       24 findings
protected demo-agent:      0 findings
measured reduction:        24 -> 0
```

This is synthetic and local, but the workflow is the important part: same corpus, same
trace format, side-by-side scorecard.

### 4. Security review evidence

Use traces and scorecards as review artifacts. A trace shows what input was tested, what
the target did, where the failure occurred, and which mitigation is expected.

### 5. Training and internal education

Use the learning docs, problem catalog, and committed examples to teach teams why
agentic data boundaries are not just a prompt-writing problem. The benchmark makes the
failure visible without using real secrets or live systems.

## What this project is not

- Not an offensive toolkit.
- Not a guarantee of real-world protection.
- Not a replacement for threat modeling, secure architecture, or human review.
- Not a live scanner for third-party systems.
- Not a shipped gateway or production proxy in the current release.

## Evaluation checklist for companies

When reviewing this project, check:

- Does the trace format capture enough context for your review process?
- Do the seed patterns match failure modes your agents can face?
- Can your team map the data envelope fields to internal data-handling rules?
- Can protected controls be represented as deterministic pass/fail behavior?
- Can benchmark reports become part of CI or release review?
- Are planned real adapters authorized, isolated, and documented before use?

## How to start

Run the local benchmark first:

```bash
pip install -e ".[dev]"
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
```

Then read:

- [Project map](project-map.md) for how the repository fits together.
- [Corpus coverage matrix](corpus.md) for the implemented patterns.
- [Problem-solution catalog](problem-solution-catalog.md) for future pattern ideas.
- [Threat model](threat-model.md) for boundaries and residual risk.
