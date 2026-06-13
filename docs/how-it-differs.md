# How it differs

> Honest comparison with adjacent tools. This project does not claim to be the first or
> only tool in the category.

## vs garak / PyRIT / promptfoo

These are established red-team / eval tools. They scan for prompt injection, jailbreaks,
and LLM vulnerabilities using real or simulated LLM calls.

**We are different because:**
- We test **boundary failures**, not injection success. "Did the data envelope survive?"
  not "Can injection bypass the filter?"
- We are **deterministic**. No network, no LLM, no provider calls. Same input = same
  output, always.
- We produce **portable traces**. Machine-readable, replayable, auditable artifacts.
- We measure **baseline-vs-protected delta**. Not just "is there a vulnerability?" but
  "does this control reduce findings?"

**We are complementary:** garak probes could feed into our corpus as additional patterns.

## vs CaMeL / FIDES

These are **defense implementations**. CaMeL separates control and data flows; FIDES
implements information-flow control middleware.

**We are different because:**
- We are a **benchmark**, not a defense. We measure whether boundaries hold, we don't
  enforce them.
- We are **framework-agnostic**. Our traces can be replayed against any target.
- We test **22 deterministic seed patterns** across data, authority, perception, approval,
  memory, audit, budget, and schema-boundary classes.

**We are complementary:** a team using CaMeL could use this harness to verify that their
defense actually works across our corpus.

## vs ADR (Uber)

ADR is published work on **production monitoring for MCP agents**.

**We are different because:**
- We are a **pre-production benchmark**, not a runtime monitor.
- We are **deterministic and synthetic**, not production telemetry.
- We focus on **boundary failure measurement**, not anomaly detection.

## vs AgentDojo

AgentDojo is a **benchmark environment** for attacks and defenses on LLM agents.

**We are different because:**
- AgentDojo focuses on **tool-output prompt injection**. We test the broader
  operating-environment boundary.
- We are **trace-first**. Our primary artifact is a portable failure trace, not a
  benchmark score.
- We are **deterministic**. No LLM calls, no network.

## vs BotGuard

BotGuard is an agent security platform (scan + shield + fix).

**We are different because:**
- We are a **focused benchmark**, not a platform.
- We test specific boundary failure classes, not general agent security.

## Summary

| Dimension | garak/PyRIT/promptfoo | CaMeL/FIDES | ADR | AgentDojo | **This harness** |
|---|---|---|---|---|---|
| Type | Scanner / eval | Defense | Monitor | Benchmark | **Benchmark** |
| Target | LLM injection | Agent flows | Production MCP | Agent attacks | **Environment boundary** |
| Deterministic | No | N/A | No | Partially | **Yes** |
| Trace-first | No | N/A | No | No | **Yes** |
| Baseline-vs-protected | No | N/A | N/A | Partially | **Yes** |
| Local/no-provider default | No | N/A | No | Varies | **Yes** |
