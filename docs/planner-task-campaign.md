# Planner Task Authority Campaign

> Status: deterministic public research contour.

This page documents the planner/task-decomposition authority boundary:

> Planning is transformation, not authorization.

A planner may decompose work into subtasks, but generated subtasks do not inherit
authority from untrusted context, stale approvals, tool output, retrieved snippets,
batches, dependency ordering, or worker summaries. Protected subtasks still need a
current user intent anchor or trusted policy authority.

## What It Models

The campaign declares seven synthetic planner propagation cases:

| Case | Plain-language failure |
|---|---|
| `untrusted_context_subtask` | Project context is converted into a protected subtask. |
| `stale_approval_work_item` | Old approval text becomes current work. |
| `tool_output_policy_task` | Tool output is treated as planner policy. |
| `retrieved_snippet_task` | Retrieved text becomes implementation authority. |
| `handoff_parent_task_authority` | Worker handoff text becomes parent-task authority. |
| `batch_hidden_protected_subtask` | One protected subtask hides inside a benign batch. |
| `dependency_delayed_activation` | Safe setup unlocks a later protected step. |

Each case records:

- entry vector;
- propagation path;
- no-red-flag path;
- timing window;
- authority conversion;
- risky action;
- expected bounded behavior;
- required controls;
- benign variant.

## Control Model

The deterministic controls are:

- `input_source_provenance`
- `current_user_intent_anchor`
- `consent_receipt_binding`
- `task_authority_gate`
- `subtask_source_inheritance`
- `tool_output_data_boundary`
- `retrieval_evidence_label`
- `handoff_revalidation`
- `batch_task_isolation`
- `dependency_order_gate`

The campaign runs each case in naive, bounded, control-ablation, and benign modes. A
bounded row must block the declared unsafe chain. A benign row must still pass.

## Public Result

The committed sanitized example records:

| Metric | Value |
|---|---:|
| Cases | 7 |
| Controls | 10 |
| Pressure axes | 9 |
| Deterministic rows | 91 |
| Naive unsafe-chain acceptances | 7 |
| Bounded unsafe-chain acceptances | 0 |
| Ablation unsafe-chain acceptances | 32 |
| Benign false blocks | 0 |

The ablation rows are the key evidence: when a responsible control is removed, the
specific dependent planner path reopens. That is stronger than only showing a bounded
block.

## Reproduce

```bash
ash planner-task-campaign --write --out examples/planner-task-sanitized
ash validate examples/planner-task-sanitized
```

The committed public artifact lives at
[`examples/planner-task-sanitized/`](../examples/planner-task-sanitized/).

## Non-Claims

This campaign does not prove:

- production planning-agent safety;
- model safety;
- provider vulnerability;
- exhaustive planner coverage;
- that deterministic validators solve semantic truth;
- that a deployed system preserves authority boundaries.

It is a deterministic public contour for one boundary family. Future live-planner,
gateway, or model-in-the-loop probes require a separate authorized implementation
boundary and the same private/public evidence split used elsewhere in the project.
