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

## Complete local example

Run this from an empty directory with Agentic Security Harness installed. It uses only
the shipped sanitized seed corpus and writes a new `custom-adapter-report/` directory.
Choose a fresh output directory for each run; the evidence bundle is create-only.

```python
from datetime import UTC, datetime
from pathlib import Path

from agentic_security_harness import __version__
from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.html_report import write_html_report
from agentic_security_harness.models import (
    DefensivePattern,
    Finding,
    Observation,
    TraceStep,
)
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.reporting import write_reports
from agentic_security_harness.run_manifest import build_manifest, write_run_manifest
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.safe_io import staged_evidence_bundle
from agentic_security_harness.scorecard import build_scorecard
from agentic_security_harness.validation import validate_path


CORPUS_BY_ID = {entry.pattern_id: entry for entry in corpus_manifest()}


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
        if pattern.category == "data_boundary":
            entry = CORPUS_BY_ID[pattern.pattern_id]
            findings.append(
                Finding(
                    code=pattern.category,
                    severity=entry.severity,
                    message="Synthetic target did not preserve the modeled boundary.",
                    broke_at=entry.broke_at,
                    mitigation=pattern.mitigation,
                )
            )

        return Observation(
            observed_behavior="local synthetic observation",
            steps=steps,
            findings=findings,
        )


traces = HarnessRunner(MyLocalTarget()).run_many(seed_patterns())
card = build_scorecard(traces)
out = Path("custom-adapter-report")

with staged_evidence_bundle(out) as staging:
    paths = write_reports(traces, card, staging)
    artifacts = sorted(path.name for path in paths.values())
    manifest = build_manifest(
        "run",
        staging,
        target=card.target_name,
        scenario="seed-corpus",
        outcomes={
            "failed": len(card.failed_patterns),
            "passed": len(card.passed_patterns),
        },
        artifacts=artifacts,
        tool_version=__version__,
        created_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    write_run_manifest(staging, manifest)

result = validate_path(out)
assert result.ok, result.errors + result.expectation_mismatches
write_html_report(out, out / "report.html")
print(f"{card.total_traces} traces, {len(card.failed_patterns)} synthetic findings")
print(f"rendered report: {out / 'report.html'}")
```

The example intentionally reports synthetic data-boundary findings. Their severity and
boundary location come from the committed corpus metadata so the normal validator can
check the traces; those fields are not an independent security judgment. The manifest
binds the JSON/Markdown evidence artifacts. HTML is rendered from the validated
bundle but is not itself manifest-hashed; rendering refuses an invalid input bundle.
This is a local adapter demonstration, not evidence about a real agent or provider.

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
