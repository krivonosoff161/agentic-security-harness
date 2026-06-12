# Roadmap

Harness-first and trace-first. Versioning is feature-gated, not date-gated; each version
is shippable. Everything is local, deterministic, and synthetic: no network, no LLM or
provider calls, no real targets, no real secrets.

---

## Done

- **v0.1 - harness core:** models, runner, scorecard, mock target.
- **v0.2 - demo CLI + local demo-agent:** `ash run`, deterministic reports, committed examples.
- **v0.3 - protected replay:** protected-demo-agent, `ash compare`, measured risk reduction 7 -> 0.
- **v0.4 - expanded local corpus:** 7 deterministic seed patterns, corpus manifest
  (`corpus.py`), coverage matrix ([docs/corpus.md](corpus.md)).
- **v0.5 - validation layer:** `ash validate`, benchmark-artifact validation, corpus
  consistency checks.
- **v0.6 - corpus expansion (first slice):** sleeping-prompt delayed activation,
  audit / spam-label abuse, budget / loop abuse - 10 deterministic patterns total.

---

## Next

- **v0.6.x - corpus expansion (continued):** cross-agent contamination, MCP / tool-schema
  deception, approval pressure.
- **v0.7 - local adapter examples:** toy RAG app, toy MCP server, toy multi-agent handoff.
  Still local / synthetic only.
- **v0.8 - report quality:** better Markdown / HTML audit report, executive summary,
  mitigation checklist, before/after score.
- **v0.9 - mapping and standardization:** OWASP LLM mapping, MITRE ATLAS mapping, severity
  rationale, pattern versioning policy.
- **v1.0 - stable benchmark release:** stable trace schema, stable corpus manifest, stable
  CLI, validated examples, coherent docs, public tag.

---

## Future tracks / not part of the current benchmark release

These come after v1.0 and are not implemented today. They stay out of the benchmark
release scope until the core above is stable:

- **Reference gateway** - a planned optional defense target for risk-reduction replay.
- **Real LLM adapters** - drive authorized live agents instead of local synthetic targets.
- **Multimodal / audio-ASR** - sanitized, pre-recorded ASR / OCR fixtures for the
  sensor-to-agent path.
- **Postgres / hash-chain trace integrity** - durable trace store with tamper-evident
  append-only logging.

---

## A note on self-learning

The harness does not self-learn. It never mutates its own patterns, thresholds, or
detectors at runtime. Findings and reviewed results produce labels that are stored only;
any adaptive rules built from them are a future, explicitly human-reviewed step. A security
tool that silently rewrites itself is hard to audit - predictability is a feature.
