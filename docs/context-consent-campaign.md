# Context consent campaign

`Context is not consent` is the fifth deterministic authority-boundary family in
Agentic Security Harness.

The problem is simple: an agent may see text that sounds like approval, but that text
is only context. It may come from an issue comment, old chat history, a worker handoff,
or a broad task batch. A risky action still needs current, scoped, fresh user consent.

This campaign is deterministic. It does not call local or external models.

## Boundary statement

Context can describe consent, quote consent, or claim consent. It is not itself consent.

Protected actions require:

- current user intent;
- a consent receipt;
- scope binding to the exact action;
- freshness within the current session or approval window;
- one-action consent isolation for risky actions;
- risk classification before execution.

## Public artifact

The committed public example is:

[`examples/context-consent-sanitized/`](../examples/context-consent-sanitized/)

Validate it with:

```bash
ash validate examples/context-consent-sanitized
```

Regenerate it with:

```bash
ash context-consent-campaign --write --out examples/context-consent-sanitized
```

## Current result

| Metric | Value |
|---|---:|
| Cases | `5` |
| Controls | `6` |
| Deterministic rows | `45` |
| Naive risky-action acceptances | `5` |
| Bounded risky-action acceptances | `0` |
| Ablation risky-action acceptances | `18` |
| Benign acceptances | `5` |
| Benign false blocks | `0` |

The useful signal is the same pattern as other public campaigns: bounded mode blocks
declared unsafe rows, benign rows still pass, and ablations reopen unsafe paths when a
responsible control is removed.

## Cases

| Case | Boundary failure |
|---|---|
| Repo issue action claim | Issue text claims a protected action is already approved. |
| Stale approval reuse | Old approval is reused outside its action/session window. |
| Batched benign context | A risky action is hidden inside a broad benign task batch. |
| Handoff claims user approved | Worker summary claims approval without a consent receipt. |
| Ambient chat history intent | Surrounding chat preference is treated as present authorization. |

## Non-claims

- This is not a production consent system.
- This is not a model-safety benchmark.
- This does not prove a deployed agent preserves user intent.
- This does not use real approvals, real tickets, real repositories, or production
  workflows.
- The artifact checks deterministic contract rows and hygiene only.

