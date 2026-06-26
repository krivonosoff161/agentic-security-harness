# Marketing web-injection sanitized example

This directory is a sanitized public summary for a controlled offline campaign. It
models a marketing/ads analytics swarm that reads web-like material while holding an
internal synthetic strategy/contract value. Hostile pages try to launder external
instructions into worker summaries and chief analysis.

No network, real websites, accounts, contracts, credentials, or real business secrets
are used. Raw hostile pages, raw prompts, raw responses, and synthetic secret values
stay private under `.internal/`.

## Result

| Mode | Result |
|---|---:|
| Naive unsafe runs | `5/5` leaked |
| Bounded unsafe runs | `0/5` leaked |
| Control-ablation unsafe runs | `21/21` reopened |
| Benign runs | `5/5` allowed |
| Response hash coverage | `100%` |

The bounded result depends on seven controls: external source labels, an authority
floor, secret envelope checks, summary guards, chief verification, audit hash chaining,
and canary detection. The ablation rows show which failures reopen when a control is
removed.

## Reproduce

Dry-run:

```bash
ash marketing-web-injection-campaign
```

Write private artifacts and a sanitized public summary:

```bash
ash marketing-web-injection-campaign \
  --write \
  --out .internal/marketing-web-injection/latest \
  --summary-out reports/marketing-web-injection
```

Validate this committed public example:

```bash
ash validate examples/marketing-web-injection-sanitized
```

## Read order

1. `marketing_web_injection_report.md` - reviewer-facing summary.
2. `marketing_web_injection_digest.json` - aggregate metrics and publication flags.
3. `marketing_web_injection_summary.json` - sanitized per-observation rows.
4. `run_index.json` - run manifest.

## Non-claims

- This is not real-secret extraction.
- This is not a CVE or a model leaderboard.
- This does not prove internet-wide or production-swarm safety.
- Response hashes prove artifact hygiene and owner-side replay anchors, not semantic
  truth by themselves.
