# Roadmap

Harness-first. Versioning is feature-gated, not date-gated; each version is shippable.
Detector precision/recall — **including the false-negative rate** — is measured against the
attack corpus and published per release. The gateway is the **reference defense** and
arrives later as a replay target.

---

## v0.1 — Harness core (mock target)

- **Goal:** prove the loop *pattern → trace → scorecard* end to end on a mock agent.
- **Features:** an **attack corpus** (seed [defensive test patterns](harness.md#attack-pattern-taxonomy)),
  a **trace schema** (incl. the data-envelope fields), a **simple runner**, and a
  **scorecard** — all run against a **mock agent** target. The deterministic scanner core
  is reused as the detectors/oracles.
- **Out of scope:** real targets, MCP, multi-agent, multimodal, the reference gateway.
- **Done when:** running the corpus against the mock agent emits one trace per chain,
  scorecard is derived deterministically, ruff/mypy clean, CI green on 3.11/3.12.
- **Tests:** benign chain → no finding; each seed pattern → expected trace + finding;
  scorecard regenerates deterministically from the same traces.

## v0.2 — Real agent adapter + cross-target replay

- **Goal:** drive a real (authorized) LLM agent and compare targets.
- **Features:** an **LLM-agent target adapter** (OpenAI-compatible); expanded sanitized
  patterns; **cross-target replay** — run the same trace set against two targets and diff
  the scorecards.
- **Done when:** the same traces run against two targets produce comparable scorecards;
  provider calls are mocked in CI.
- **Tests:** adapter contract; replay determinism; scorecard diff correctness.

## v0.3 — Tools & MCP

- **Goal:** cover the tools/permissions layer of the graph.
- **Features:** **MCP / tool-chain target adapter**; **MCP / tool-permission scanner**
  (static analysis of tools, permissions, and tool schemas); tool-permission-abuse and
  MCP/tool-schema-deception patterns.
- **Done when:** the scanner emits the tools/permissions graph layer; the two patterns
  produce findings against a mock MCP target.
- **Tests:** permission-graph extraction; schema-deception pattern; dangerous-argument detection.

## v0.4 — Multi-agent, memory & data boundary

- **Goal:** the agentic-specific failure modes, including **data-boundary survival**.
- **Features:** **multi-agent workflow adapter**; **cross-agent contamination** and
  **memory poisoning** patterns; **data-boundary / recipient-control** patterns —
  data-envelope checks, **sleeping prompt / delayed injection**, **classification
  mutation**, **memory no-store / TTL violation**, and **handoff label stripping**.
- **Done when:** a contamination chain across two mock agents is captured with a clear
  break point; a data item's envelope is shown to be violated (e.g. label stripped at a
  handoff) in a trace.
- **Tests:** contamination propagation; memory persistence across turns; envelope-survival
  checks (recipient, store/forward, TTL, classification immutability).

## v0.5 — Multimodal & reference defense

- **Goal:** the full signal path, and measured risk reduction.
- **Features:**
  - **Voice / multimodal target adapter** — **sanitized, pre-recorded ASR/OCR fixtures**
    only; sensor-to-agent path; trace captures the `modality` fields. **No ultrasonic /
    adversarial-audio generation** (out of scope by design).
  - **Reference gateway as a defense target** + **policy engine** + **measured
    risk-reduction replay** (baseline vs gateway-protected scorecards).
- **Done when:** a multimodal chain runs from a sanitized fixture to an observed agent
  action; replay through the reference gateway yields a measured delta.
- **Tests:** ASR-fixture pattern; modality fields populated; risk-reduction delta computed.

## v1.0 — Production-ready

- **Goal:** something a platform / security team can run.
- **Features:** hardened harness + reference gateway; **PostgreSQL** trace store;
  **trace integrity (hash chaining)** — earlier versions use normal append-only storage;
  **streaming** support in the reference gateway (deferred to here on purpose — streaming
  and full egress scanning are in tension); CI + SBOM/dependency scanning; published
  performance budget; finalized threat model.
- **Done when:** deploy via Compose/Helm; load-tested at a documented overhead; trace log
  tamper-evident; security disclosure live.
- **Tests:** full integration + attack corpus, load/soak, migration, audit-integrity.

---

## Education track (parallel)

Alongside the version milestones, an education + measurement track grows in step — all
sanitized and mock-only:

- **Mission docs** — [mission](mission.md), [safe research rules](research-rules.md). *(done)*
- **Learning modules** — [agentic security basics](learning/01-agentic-security-basics.md),
  [data-boundary failures](learning/02-data-boundary-failures.md); more modules later.
- **Safe scenario catalog** — sanitized scenarios mapped to harness test patterns, seeded by
  the [problem–solution catalog](problem-solution-catalog.md).
- **Demo notebooks / examples** *(later)* — runnable walkthroughs against **mock targets only**.

---

## A note on self-learning

**The harness does not self-learn.** It never mutates its own patterns, thresholds, or
detectors at runtime. Findings and reviewed results produce **labels** that are stored
only; any adaptive rules built from them are a **future, explicitly human-reviewed** step.
A security tool that silently rewrites itself is hard to audit — predictability is a feature.
