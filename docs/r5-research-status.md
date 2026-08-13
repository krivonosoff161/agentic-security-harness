# R5 sealed synthetic result

> Last reviewed: 2026-08-13.
>
> Scope: sanitized public projection of the separate Runtime Guard R5 research track.
> This is a common-control synthetic evaluation, not independent validation, population
> inference, promotion approval, production protection, or operational authority.

## Terminal status

Exactly one owner-authorized R5 lifecycle reached `PRECOMMITTED`, `CONSUMED`, and
`COMPLETED`. Its scientific terminal state is **`FAIL`**, not `VOID`. The run used the
frozen Runtime Guard source commit
`d90168b16c415775e2b897aed3b004dfe52e5746` and tree
`db94d4f8230cfa53609d715b56611955fb2e13ec`.

The public artifact is
[`examples/r5-sealed-synthetic-sanitized/`](../examples/r5-sealed-synthetic-sanitized/).
It contains only aggregate evidence, a terminal envelope, and their publication manifest.
Run cases, labels, seeds, role payloads, private keys, the witness ledger, and machine-local
custody remain outside public Git.

## Reproducible calculations

The frozen study has `250` harmful, `250` opportunity-benign, and `420` incomplete
synthetic roots across `10` families (`920` unique roots). The public validator recomputes:

| Metric | Public calculation | Result | Gate | Status |
|---|---:|---:|---:|---|
| Recall | `159 / (159 + 91)` | `0.636` | lower index `>= 0.75` | **fail** (`0.564147936923141`) |
| Specificity | `207 / (207 + 43)` | `0.828` | lower index `>= 0.75` | pass (`0.7676957315720971`) |
| Incomplete abstention | `420 / 420` | `1.0` | lower index `>= 0.95` and exact `1.0` | pass (`0.9896208423381082`) |
| Counterfactual pre-effect detection | `81 / 250` | `0.324` | lower index `>= 0.50` | **fail** (`0.25873190104949617`) |
| Balanced accuracy | `(0.636 + 0.828) / 2` | `0.732` | `>= 0.80` | **fail** |
| Matthews correlation coefficient | `(159*207 - 43*91) / sqrt(202*250*250*298)` | `0.47279641242768755` | `> 0` | pass |
| Harmful / benign decision coverage | `(159+91)/250`; `(43+207)/250` | `1.0`; `1.0` | each `>= 0.80` | pass |

The four lower acceptance indices use one-sided exact Clopper-Pearson bounds with
familywise alpha `0.05` divided across four inferential gates (`alpha = 0.0125` per
interval). They are an internal synthetic acceptance index only; the method does not
establish exchangeability, generalization, field performance, or independence.

Timing counts are `0` detections before 20 seconds, `13` at exactly 20 seconds, `106`
between 21 and 40 seconds, `40` after 40 seconds, and `91` right-censored. The five bins
sum to the harmful denominator (`250`), and detected bins sum to harmful challenges
(`159`). The run recorded zero system errors, zero effects, and zero authority violations.

## Integrity and validation

- Canonical aggregate payload SHA-256:
  `c63d3daae5f8ad0a2d42b605d1ef784fdf05e78dfa5306aa37ede46c9c35031e`.
- Terminal receipt-chain SHA-256:
  `133b34bed0d91cc36be3356499af6e6d4d4d536682bf713a87e06cd24a7c0d28`.
- Claim-burn key:
  `3e4b91297ebb042df599efc95f9f1c1a131b9248868a4c262fb4ce42386f34c7`.
- Plan digest:
  `cf3d0a756d496ce6a8767304abbf0e2f7d9990c0001ec8a7263835374ec39ce0`.

The Git copies use the repository's final-LF convention. Their publication manifest binds
the exact tracked bytes, while the terminal envelope continues to bind the canonical JSON
aggregate payload above. Validate both the byte transport and the independent calculations:

```bash
ash validate examples/r5-sealed-synthetic-sanitized
python -m pytest -q tests/test_r5_public_projection.py
```

## Why the raw calculations are not public

They are not hidden to obscure the result. The custody protocol intentionally separates
safe aggregate evidence from sensitive or scientifically reusable run material. Publishing
raw cases, labels, seeds, private witness keys, or role payloads would weaken the one-burn
and blindness boundary. The aggregate counts, formulas, thresholds, exact lower indices,
terminal verdict, provenance commitments, signatures, and deterministic validator are
public so reviewers can reproduce the disclosed result without those private inputs.

## Claim boundary

The evidence remains under `common_control=true`, `independence=not_claimed`,
`blindness=procedural_not_independent`, `promotion_eligible=false`, and
`operational_authority=none`. A scientific `FAIL` is useful falsification evidence for this
frozen candidate; it is not evidence that all Runtime Guard designs fail, and it does not
authorize deployment, release, enforcement, or a rerun.
