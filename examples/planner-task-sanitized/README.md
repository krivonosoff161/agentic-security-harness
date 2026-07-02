# Planner Task Authority Campaign

Sanitized deterministic example for the planner/task-decomposition authority boundary.

It models the rule: planning is transformation, not authorization. Generated subtasks
must not inherit authority from untrusted context, stale approvals, tool output,
retrieved snippets, batches, dependency ordering, or worker summaries.

No local models, external APIs, live planners, credentials, or raw prompt chains are
used.

## Reproduce

```bash
ash planner-task-campaign --write --out examples/planner-task-sanitized
```

## Validate

```bash
ash validate examples/planner-task-sanitized
```

Passing validation means artifact integrity and forbidden-marker checks passed. It is not
a production safety guarantee.
