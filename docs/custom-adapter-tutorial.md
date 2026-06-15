# Custom adapter tutorial

This tutorial shows the smallest useful adapter shape for Agentic Security Harness.
It is for local, synthetic, authorized targets. Do not connect real systems, provider
accounts, private data, or live tools from this tutorial.

For the formal contract, read [adapter-contract.md](adapter-contract.md).

## What an adapter must do

An adapter translates one `DefensivePattern` into an observation from a target:

```text
DefensivePattern -> target behavior -> Observation -> ExploitTrace
```

The runner owns trace construction. Your adapter owns only `observe(pattern)`.

## Minimal target

```python
from agentic_security_harness.models import (
    DefensivePattern,
    Finding,
    Observation,
    TraceStep,
)
from agentic_security_harness.runner import HarnessRunner


class MyLocalTarget:
    name = "my-local-target"

    def descriptor_fields(self) -> tuple[str, str, str]:
        return ("local", self.name, "synthetic local adapter")

    def observe(self, pattern: DefensivePattern) -> Observation:
        steps = [
            TraceStep(
                index=0,
                actor="harness",
                action="present_pattern",
                input_ref=pattern.pattern_id,
                observed="Pattern delivered to local synthetic target.",
            )
        ]

        findings: list[Finding] = []
        if pattern.category == "data-boundary":
            findings.append(
                Finding(
                    code=pattern.category,
                    severity="medium",
                    message="Synthetic target did not preserve the modeled boundary.",
                    broke_at="synthetic-test",
                    mitigation=pattern.mitigation,
                )
            )

        return Observation(
            observed_behavior="local synthetic observation",
            steps=steps,
            findings=findings,
        )


traces = HarnessRunner(MyLocalTarget()).run_many([])
```

In real use, pass a list from `seed_patterns()` or a selected scenario. The example uses
an empty list only to keep the snippet minimal.

## Safer local example

```python
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.runner import HarnessRunner

target = MyLocalTarget()
traces = HarnessRunner(target).run_many(seed_patterns())
```

Then convert traces into reports with the existing reporting functions or use the CLI
targets as the reference implementation.

## Adapter checklist

Before an adapter is considered reviewable:

- It must be local/offline by default.
- It must use synthetic inputs and synthetic findings.
- It must never log provider keys, account ids, private URLs, or private customer data.
- It must separate adapter failure from target failure.
- It must not weaken the pattern to make a target pass.
- It must record enough trace steps for a reviewer to understand the boundary decision.
- It must document whether results are deterministic or stochastic.

## When an adapter is not benchmark-grade

An adapter is exploratory, not benchmark-grade, if it:

- asks a model to self-report whether it would behave safely;
- does not observe actual target behavior;
- makes network calls without explicit opt-in;
- omits run configuration or target metadata;
- cannot be replayed or validated.

The current `run-external` path is intentionally labeled experimental because it is
prompt-only and does not execute tools or observe a real agent host.

## Where to look next

- Built-in target registry: `src/agentic_security_harness/adapters.py`
- Target protocol and metadata: `src/agentic_security_harness/models.py`
- Local synthetic agents: `src/agentic_security_harness/demo_agent.py`,
  `src/agentic_security_harness/protected_demo_agent.py`
- Toy adapters: `src/agentic_security_harness/toy_adapters.py`
- Benchmark protocol: [benchmark-protocol.md](benchmark-protocol.md)
