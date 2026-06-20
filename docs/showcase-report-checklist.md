# Public showcase report checklist

Use this checklist before promoting a report in the README, release notes, GitHub
description, or another public-facing demo. A showcase report must prove reproducibility,
not just look readable.

## Required command record

A public showcase must state the exact commands used to create and validate it:

```bash
pip install -e ".[dev]"
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
ash report --root reports/comparison
```

If the showcase uses `run-external`, it must also include the dry-run / preflight command,
the selected scenario, repeats, temperature, redacted base URL, credential env-var name
only, and a note that the path is experimental and prompt-only.

## Required artifacts

For the main baseline/protected showcase, require:

- `baseline/traces.json`;
- `baseline/scorecard.json`;
- `baseline/summary.md`;
- `baseline/executive.md`;
- `baseline/remediation.json` and `baseline/remediation.md` when findings exist;
- `protected/traces.json`;
- `protected/scorecard.json`;
- `protected/summary.md`;
- `protected/executive.md`;
- `comparison.md`;
- `report.html` if a rendered HTML view is promoted;
- a successful `ash validate <showcase-dir>` result.

Do not promote screenshots or prose summaries that cannot be traced back to these files.

## Required summary

The showcase must include a small comparison table:

| Metric | Required value |
|---|---|
| Corpus size | Current implemented pattern count. |
| Baseline target | Target id and descriptor. |
| Protected target | Target id and descriptor. |
| Baseline findings | Count and severity distribution. |
| Protected findings | Count and severity distribution. |
| Findings delta | Example: `23 -> 0`; do not call this a security guarantee. |
| Validation | Command and pass/fail result. |

## Claim boundary text

Every public showcase must say:

> This is a deterministic synthetic benchmark run. It demonstrates behavior on the
> shipped corpus under the recorded run configuration. It is not production
> certification, not a complete security guarantee, and not evidence about a real target
> unless a separate authorized adapter and scope are documented.

Do not use showcase material for:

- first/only claims;
- production-safe claims;
- provider endorsement claims;
- benchmark leaderboard claims;
- real-target claims without authorization evidence.

## Standards mapping caveat

If the showcase mentions OWASP, NIST, MITRE ATLAS, CISA, NCSC, or other public standards,
it must include this caveat:

> Standards mappings are for analyst orientation only. They are not certification,
> endorsement, compliance proof, or a claim that the benchmark fully covers the standard.

For MITRE ATLAS, only use technique IDs already verified in
[standards-mapping.md](standards-mapping.md). Leave deferred categories unmapped rather
than guessing.

## Safety and publication checks

Before publishing, confirm:

- `ash validate` passes on the exact directory being referenced;
- no secrets, private URLs, customer data, local absolute paths, or provider keys appear;
- README/current-state/capability-matrix agree with the target and mode being shown;
- future items are not described as shipped;
- the report states residual risk and what it does not prove;
- external or local-runtime runs include recovery guidance and raw-response artifact
  references where applicable.
