# Agentic Security Harness

> **Agentic Security Harness** (repository `agentic-security-harness`). The gateway is
> the [reference defense](#reference-defense-replay) component).
>
> **One line:** *An open-source harness for reproducing and measuring agentic failure
> chains through portable traces, attack graphs, and security scorecards.*

This is the flagship document. It defines the **failure trace format**, the **attack
graph**, the **defensive test patterns**, the **scorecard**, and **reference-defense
replay**.

---

## Defensive framing (read first)

**This is an authorized defensive testing harness, not a hacking manual.**

Attack chains here are documented as **defensive test patterns**. Every pattern is:

- **sanitized** — payloads are placeholders / minimal proof-of-concept, never weaponized;
- **reproducible** — the same inputs produce the same trace;
- **run against mock / demo / authorized targets only** — never against third-party
  systems you do not own or have written permission to test;
- documented with its **expected vulnerable behavior**;
- documented with a **mitigation**;
- prepared for standards references where applicable. The implemented corpus currently
  includes coarse **OWASP Agentic Security Initiative** mappings; OWASP LLM and MITRE ATLAS
  fields remain verification-gated.

The harness contains **no real credential theft, no live exploitation, and no
instructions for abusing third-party systems.** See [SECURITY.md](../SECURITY.md#responsible-use)
for the responsible-use policy.

The mental model is closer to a **test suite for failure modes** than to an offensive
toolkit: it shows *how agentic systems break*, records it as a trace, and lets you verify
a defense **repeatably**.

---

## What the harness produces

Given a **target** and a set of **defensive test patterns**, the runner produces:

1. **Traces** — one machine-readable, portable failure trace per attack chain (the core artifact).
2. **A scorecard** — an aggregate derived from a set of traces.

Both are data, not prose, so they can be diffed, version-controlled, and replayed.

---

## Failure trace format

A **trace** is the central artifact (the model class is `ExploitTrace` in
`src/agentic_security_harness/models.py`). It is:

- **machine-readable** — structured data (JSON/YAML), not a log line;
- **portable** — describes the target abstractly, so the same trace can be **replayed
  against a different target or defense**;
- **explanatory** — it records *where the chain broke* along the attack graph, not just
  pass/fail.

### Illustrative example

> ⚠️ **Illustrative, not the final spec.** Field names and shape will change. Payloads are
> sanitized placeholders. The implemented schema is the `ExploitTrace` model in
> `src/agentic_security_harness/models.py`; the current committed artifacts use
> `pattern_id`, indexed `steps`, and a `findings` list. The `mapping` block below is
> contextual documentation only; implemented standards metadata lives in the corpus manifest.

```json
{
  "trace_id": "trc_0001",
  "schema_version": "0.0-illustrative",
  "pattern": "indirect_prompt_injection_via_tool_output",
  "target": { "type": "mock_agent", "name": "demo-rag-agent", "adapter": "mock" },
  "mapping": { "owasp_agentic": ["ASI01", "ASI02"], "owasp_llm": [], "mitre_atlas": [] },
  "graph_path": [
    "exposed_input:rag_document",
    "external_data:retrieved_chunk",
    "agent_decision",
    "tool_call:send_message",
    "observed_behavior"
  ],
  "steps": [
    { "step": 1, "actor": "harness", "action": "seed_document",
      "input": "<sanitized: benign doc with a hidden instruction placeholder>" },
    { "step": 2, "actor": "target", "action": "retrieve_and_reason",
      "observed": "agent treats retrieved instruction as trusted" },
    { "step": 3, "actor": "target", "action": "tool_call",
      "observed": "agent invokes send_message with attacker-chosen arguments" }
  ],
  "expected_vulnerable_behavior": "agent follows the hidden instruction and calls a tool",
  "observed_behavior": "tool call issued from untrusted retrieved content",
  "finding": { "severity": "high", "broke_at": "agent_decision",
               "description": "no provenance separation between user intent and tool output" },
  "mitigation": "tool-output sanitization + tool-permission gate (reference defense)",
  "reproducibility": { "deterministic": true, "seed": 0, "inputs_ref": "fixtures/trc_0001" }
}
```

The format is deliberately small: a target descriptor, a path through the attack graph,
the steps, the expected vs observed behavior, the finding (with **where it broke**), the
mitigation, and a reproducibility anchor.

Future sensor / multimodal targets would add a `modality` block to the trace — see
[Multimodal and sensor-to-agent injection](#multimodal-and-sensor-to-agent-injection).

---

## Attack graph

The graph is **practical, not abstract** — it models the real surface of an agentic
system as a chain:

```
target → exposed inputs → agents → tools → permissions → memory → external data
       → attack chain → observed behavior → finding → mitigation
```

Each trace is a **path** through this graph. The value is locating the **break point**:
e.g. a chain that flows `exposed_input → external_data(retrieval) → agent_decision →
tool_call` and breaks at `agent_decision` tells you the agent failed to separate
untrusted content from instructions — which points directly at the mitigation.

**Planned sensor / multimodal targets extend the front of the graph** — an `external signal →
input channel → ASR / OCR transcript` prefix sits before `exposed inputs` (see
[Multimodal and sensor-to-agent injection](#multimodal-and-sensor-to-agent-injection)).

**A data envelope travels alongside the data** (`data_class`, `allowed_recipients`,
`can_store`, `can_forward`, `ttl`, `classification_mutable=false`); the harness checks it
**survives** each hop — see
[Agentic data boundary and recipient control](#agentic-data-boundary-and-recipient-control).

---

## Target adapters

A **target adapter** lets the harness drive a system under test. Planned adapter kinds:

- **LLM agent** — a single agent with tools.
- **MCP / tool chain** — an agent wired to MCP servers / tool schemas.
- **Multi-agent workflow** — several agents passing messages / shared memory.
- **AI gateway** — a gateway in front of any of the above (including the
  [reference gateway](#reference-defense-replay)).
- **Voice / multimodal target** — an agent that accepts audio / image input, tested via
  **sanitized ASR / OCR fixtures**, exercising the pre-LLM sensor channel.

**Mock / demo adapters come first.** Real adapters are opt-in and only ever pointed at
targets you own or are authorized to test.

---

## Attack pattern taxonomy

Each pattern is a **defensive test pattern** (sanitized, with expected vulnerable
behavior + mitigation; coarse OWASP Agentic mapping is available in
[corpus.md](corpus.md)). The **local demo corpus
implements 7 of these as deterministic, sanitized seed patterns** (run with `ash run` /
`ash compare`); **v0.5
additionally validates the committed artifacts** against the corpus manifest (`ash
validate`). The corpus is defined in `src/agentic_security_harness/corpus.py` and its
coverage matrix is documented in [corpus.md](corpus.md). Taxonomy:

| Pattern | What it probes |
|---|---|
| **Context flooding / instruction overload** | Agent degrades or drops guardrails under oversized / noisy context. |
| **Indirect prompt injection via RAG / tool output** | Hidden instruction in retrieved content or tool output is treated as trusted. |
| **Cross-agent contamination** | One agent poisons another via shared memory / messages / tool outputs. |
| **Memory poisoning** | Planted state changes the agent's *future* decisions. |
| **Tool-permission abuse** | Over-broad tool permissions enable an unintended action. |
| **MCP / tool-schema deception** | A misleading tool schema/description steers the agent into a wrong call. |
| **Data exfiltration attempt (simulated)** | Agent is induced to route sanitized "sensitive" markers outward — simulation only, never real secrets. |
| **Budget exhaustion / loop abuse** | A chain burns tokens / loops without bound. |
| **Policy bypass via multi-turn escalation** | A guardrail holds for one turn but is escalated across turns. |
| **Multimodal and sensor-to-agent injection** | A signal on a non-text channel (esp. **audio → ASR**, also image / OCR) carries an instruction the agent acts on — testing the path *before* the LLM sees text ([details](#multimodal-and-sensor-to-agent-injection)). |
| **Agentic data boundary and recipient control** | Whether a data item's **envelope** (class, allowed recipients, store / forward rules, TTL) **survives** agent handoffs, memory writes, tool calls, and provider routing — incl. classification mutation, recipient confusion, label stripping ([details](#agentic-data-boundary-and-recipient-control)). |

All payloads are sanitized; "sensitive" data in exfiltration tests are **synthetic
markers**, not real credentials.

### Multimodal and sensor-to-agent injection

Most LLM gateways only see **text / API traffic** and typically do not see the **pre-LLM
sensor / input channels**. A future harness track should test the **full path from
external signal to agent action**:

```
external signal (audio / image) → input channel (e.g. microphone) → ASR / OCR transcript
  → agent context → tool call / memory / output
```

Audio-to-agent is the primary case:
`audio input → microphone / input channel → ASR transcript → agent context → tool call / memory / output`.

**Safety framing (strict):**

- **No instructions for generating ultrasonic / adversarial audio** — out of scope by design.
- **Sanitized, pre-recorded fixtures only** (benign, checked-in test assets).
- This is **defensive testing of systems that accept voice / image / audio inputs** — not
  signal weaponization.

For these targets the trace captures additional `modality` fields: `modality`,
`source_channel`, `human_perceptibility`, `asr_transcript`, `asr_confidence` (if
available), `anomaly_or_spectral_flag` (if available),
`tool_execution_required_confirmation`, `observed_side_effect`, `mitigation`.

### Agentic data boundary and recipient control

A primary wedge. Most tools test *whether an injection succeeded*; this class tests whether
a **data item's rules survive the agent's internal handling** — across handoffs, memory
writes, tool calls, and provider routing.

Model each data item as a **policy-enforced data envelope**:

| Field | Meaning |
|---|---|
| `data_class` | sensitivity / category label |
| `allowed_recipients` | who may receive it |
| `allowed_purpose` | what it may be used for |
| `can_store` | may it be persisted |
| `can_forward` | may it be forwarded onward |
| `ttl` | how long it may live |
| `requires_confirmation` | does an action on it need human confirmation |
| `classification_source` | who set the class (must be trusted) |
| `classification_mutable` | **`false`** — content / agents cannot relabel it |

The harness checks whether these properties **hold** as data crosses each boundary:
classification mutation, recipient confusion, `can_store` / `ttl` violation, handoff label
stripping, and provider-boundary leakage. Full set in the
[problem–solution catalog](problem-solution-catalog.md).

> **Not encryption.** A data envelope is a **policy label that must be enforced and survive
> transformation** — it is *not* magic encryption. Encryption protects transport and
> storage; it does **not** solve prompt injection, because an authorized agent can still be
> tricked into misusing data it is allowed to read. The envelope is what the harness
> **verifies**; the reference gateway is one place to **enforce** it.

---

## Scorecard

A **scorecard** is derived **from a set of traces** for a target. It reports, per target:

- which patterns produced a finding, and at what severity;
- **where** chains broke (which graph node);
- corpus coverage by implemented pattern;
- reproducibility (deterministic vs flaky).

It is a derived artifact — regenerating it from the same traces is deterministic.

**Benchmark-artifact integrity.** The committed examples under `examples/` are validated
artifacts. `ash validate` checks them against the corpus manifest
(`src/agentic_security_harness/corpus.py`, coverage matrix in [corpus.md](corpus.md)) so
the committed traces and scorecards stay consistent with the declared pattern set.

---

## Reference-defense replay

The reference gateway (this repo's original component, now **optional**) is one **defense
target design** for a later release; it is not implemented in the current benchmark
release. The replay loop is where traces pay off:

1. Run a trace set against a **baseline** target → record findings.
2. Put the target **behind a defense** (the reference gateway, or any other gateway you
   want to evaluate) → replay the **same** trace set.
3. Compare the two scorecards → **measured risk reduction**, not a marketing claim.

This is the honest core: the harness does not assert protection — it **measures the
delta** a defense produces against reproducible traces.

---

## Relation to prior art

This space is **not empty**, and this project does **not** claim to be first or only. The closest
combined prior art and the established tools are named honestly in
[competitors.md](competitors.md). The intended angle is narrow and specific — **portable
traces + a practical attack graph + reproducible cross-target replay + cross-agent
contamination**, not "more attacks."
