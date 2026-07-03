# Trading Bot Paper Stand Inventory

> Date: 2026-07-03.
>
> Scope: public-safe, read-only inventory for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> Source: filenames plus public project docs from the local owned
> `trading-bot-v2` checkout. `.env`, private logs, raw state, `.internal/`,
> provider transcripts, credentials, and trading calculations were not read.

## Inventory Result

The target is suitable as a future authorized paper-only stand, but not as a
default executable ASH target.

Observed target shape:

- paper/research backbone is the active runtime boundary;
- `execution_allowed=false` and paper-only semantics are documented as current
  state;
- `main_paper_*` modules form the current paper product bridge;
- paper Telegram artifacts are preview/audit surfaces, not required sends;
- LLM/provider components exist, but adversarial provider testing is out of
  scope;
- old live `main.py`, exchange clients, `.env`, Telegram send paths, and live
  automation remain forbidden surfaces.

This inventory is a target-shape anchor, not a security result.

## Candidate Observation Surfaces

| ASH surface | Candidate target files | Why it matters |
|---|---|---|
| Input routing | `src/scout/watch_queue.py`, `src/scout/scanner_records.py`, `src/research_lab/intake_adapter.py` | Repo/event text can enter later paper workflows as data. |
| LLM role boundary | `src/scout/agents/layer_agent.py`, `src/scout/agents/chief.py`, `src/research_lab/llm_provider.py`, `src/research_lab/local_llm_advisor.py` | Model output must remain advisory and structured. |
| Deterministic gate | `src/scout/agents/orchestrator.py`, `src/research_lab/validator.py`, `src/research_lab/paper_signals/pfr_bridge.py` | Code-owned gates decide readiness and authority. |
| Paper bridge | `src/research_lab/main_paper_bridge.py`, `src/research_lab/main_paper_consumer.py`, `src/research_lab/main_adaptive_policy.py` | Validated paper rows become main-compatible watch intent. |
| Runtime queue | `src/research_lab/main_paper_runtime_adapter.py`, `src/research_lab/main_paper_runtime.py`, `src/research_lab/paper_runtime.py` | Paper runtime actions must stay `watch_paper` and non-live. |
| Ledger/training | `src/research_lab/main_paper_trade_ledger.py`, `src/research_lab/paper_signals/training_export.py`, `src/research_lab/product_signal_training.py` | Evidence and outcomes must remain replayable and auditable. |
| Telegram preview/audit | `src/research_lab/paper_telegram_preview.py`, `src/research_lab/paper_telegram_sender.py`, `src/utils/telegram_audit.py` | Preview/audit can be observed; real sends remain disabled for ASH work. |

## Seven-Contour Mapping

| Contour | Inventory anchor | First safe evidence type |
|---|---|---|
| Data vs instruction boundary | scanner/watch queue and intake adapter | sanitized row showing source text did or did not alter operational fields |
| Authority escalation | validator/PFR/main paper bridge | sanitized row showing authority stayed code-owned or crossed boundary |
| Memory contamination | scanner records, setup memory, paper/training export | sanitized row showing provenance retention or stale trust propagation |
| Audit tampering | runtime observation, ledger, training export | sanitized row showing invalid/reordered/mislabeled evidence handling |
| Planner/task authority confusion | farm tasks, validator, main paper consumer | sanitized row showing advisory/task status could not become action |
| Agentic rule-violation backpass | LLM role boundary plus deterministic gates | sanitized multi-step row showing final boundary held or crossed |
| Delayed/stale-context rehydration | watch queues, runtime queue, outcome/training rows | sanitized row showing expired context was rejected or wrongly reused |

## Forbidden Surfaces Confirmed

The inventory keeps these out of scope for ASH target work:

- `.env`, credentials, or secret loaders;
- old live `main.py`;
- exchange order/account clients under `src/exchange/`;
- `scripts/auto_execute.py`;
- real Telegram send paths;
- external provider abuse or adversarial calls to cloud LLM services;
- private logs, raw state, and trading calculations.

## Next Safe Step

The next implementation step is still not live execution. It is a private,
owner-retained fixture pack under `.internal/trading-bot-paper-stand/issue-136/`
that mirrors the candidate surfaces with sanitized rows and hashes. A read-only
static probe may inspect only the candidate files listed above and publish only
hashes, marker booleans, scenario ids, component names, aggregate counts, and
sanitized summaries.
