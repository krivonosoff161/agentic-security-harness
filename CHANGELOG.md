# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Marketing web-injection campaign: `ash marketing-web-injection-campaign` models a
  controlled offline marketing/ads analytics swarm reading hostile web-like material,
  writes private raw artifacts under `.internal/`, publishes a sanitized example under
  `examples/marketing-web-injection-sanitized/`, and validates naive/bounded/ablation/
  benign outcomes without exposing synthetic strategy values.
- Deep sanitized local-model mini-swarm evidence pack:
  `examples/swarm-defense-live-deep-sanitized/` records 168 private local-model
  observations as public-safe hashes and aggregate metrics, including unsafe/benign
  rates, Wilson intervals, model breakdowns, and replay-ablation attribution.
- `docs/run-your-model.md`: a single cross-platform operator path for deterministic
  demo, one OpenAI-compatible model, and local mini-swarm campaigns.
- `docs/evidence-pack-format.md`: public rules for promoting private/local research
  into sanitized, hash-anchored evidence updates with claim rows, tests, and validation.
- `instruction-integrity` scenario family so named scenario groups cover the full
  24-pattern corpus instead of leaving prompt/instruction patterns only under `all`.
- Semantic propagation defense model v0.2: sanitized public artifacts now include a
  defensive control catalog, control-effect ablation rows, validator checks, and a
  reviewer note documenting the public/private evidence boundary.
- Semantic propagation campaign: `ash semantic-propagation-campaign` writes sanitized
  public artifacts for worker-to-chief semantic drift propagation probes, including
  deterministic bounded-vs-ablation contract results, local-model observation
  aggregates, response-hash coverage, and validator support. Raw worker/chief prompts,
  responses, canonical-state hashes, and synthetic canaries stay private under
  `.internal/`.
- Semantic parameter drift campaign: `ash semantic-drift-campaign` writes sanitized
  public artifacts for 4 synthetic local mini-swarm handoff cases, including
  deterministic bounded-vs-ablation contract results, local-model observation
  aggregates, response-hash coverage, and validator support. Raw prompts, raw
  responses, canonical-state hashes, and synthetic canaries stay private under
  `.internal/`.
- Git evidence workflow documenting the issue -> branch -> artifact -> PR -> GitHub
  checks -> review gate -> merge/close process as a public project norm.
- Scenario timeline fixtures and validator contract for delayed activation, context
  overload, and handoff provenance scenarios. These are synthetic design fixtures, not a
  live multi-agent executor.
- Generated showcase failure cards from the committed demo-agent report, with trace
  references and non-claim language for reviewer-facing evidence.
- `ash local-suite` for bounded local Prometheus/Ollama smoke profiles. The command is
  dry-run by default, enforces request caps, and validates real local-run artifacts after
  explicit `--execute`.
- First-class low-context Prometheus profiles (`prometheus-lowctx-smoke` and
  `prometheus-lowctx-reliability`) for the maintainer Ollama alias
  `prometheus-qwen15b-lowctx:latest`, keeping the recovered local smoke reproducible by
  name instead of as an ad hoc command.
- `docs/current-state.md`: reviewer-facing status snapshot that separates shipped,
  experimental, planned, active, and claim-boundary items.
- `docs/authorized-testing-paths.md`: official/authorized use paths for synthetic local
  labs, local runtimes, owned-system assessments, customer-authorized assessments,
  provider-program testing, and standards-aligned benchmarking.
- GitHub project-governance surface: PR template, issue templates for bugs/features/
  defensive pattern proposals, CODEOWNERS, Dependabot config, CodeQL, Scorecard, release
  artifact workflow, governance, maintainers, support, code-of-conduct, and citation files.
- Evaluation topology documentation for single models, local targets, protected-vs-
  vulnerable agents, memory/tool loops, model chains, multi-agent handoffs, provider
  boundaries, human approval, and recovery paths.
- Corpus expansion plan that requires invariant-based, topology-aware pattern selection
  and rejects full combinatorial sweeps of model/provider/agent/time variants.
- Documentation contract tests for methodology links, topology coverage, expansion-plan
  structure, governance files, and stale pattern-count claims.
- External raw-response evidence: new `run-external --raw-response-limit` flag, full
  per-request response files under `raw_responses/`, and `raw_response_path`,
  `raw_response_sha256`, `raw_response_chars`, and `raw_response_truncated` fields in
  `external_results.json`.
- Pattern-level external verdict validation: external prompts now require `pattern_id`
  and `boundary_assertion`; the harness validates them against the concrete
  `DefensivePattern` and canonical control family before recording PASS/FINDING.
- JSON CLI output for automation: `ash validate --format json`, `ash stats --format json`,
  `ash retention --format json`, and `ash compare-models --format json`.
- Golden snapshot coverage for external artifacts, including the normalized
  `external_results.json`, `external_summary.json`, `external_report.md`, `run_config.json`,
  and the linked raw response file.
- Run-history maintenance commands: `ash stats`, `ash retention`, and `ash compare-models`
  expose the previously internal stats, retention, and external-run comparison logic.
- External retry controls are part of the recorded run configuration and reproduction
  command (`--retries`, retry backoff in artifacts).
- Local-runtime metadata for external runs: `run_config.runtime` records runtime name,
  runtime family, `network_mode`, authorization mode, model id, model license/policy note,
  prompt-only/tool-execution flags, and recovery guidance for local Ollama, LM Studio,
  vLLM, localhost, and generic OpenAI-compatible endpoints.
- Local toy multi-agent handoff target: `toy-multi-agent` models a deterministic
  coordinator/worker handoff for data-label stripping and capability-delegation drift,
  records before/after handoff evidence in trace steps, and remains offline with no
  provider calls or live tools.
- Recovery-path pattern design: `recovery.trust_gate_no_path` now has a documented
  pre-implementation proposal covering invariant, topology, expected vulnerable behavior,
  trace evidence, protected control, residual risk, and anti-combinatorial guardrails.
- Public showcase report checklist: required commands, artifacts, validation result,
  baseline/protected summary, claim-boundary language, and standards-mapping caveat before
  any report is promoted in README or release material.
- `docs/v1-readiness.md`: stable-vs-experimental readiness matrix covering clean install,
  fake-server path, schema/corpus freeze expectations, showcase report gate, claim
  boundaries, and open v1.0 blockers.
- Data-boundary theory module with an explicit envelope restriction relation
  (`E_out <= E_in`), field-level non-expansion rules, and conservative policy-context
  caveats for classification ordering, trusted sources, and TTL checks.
- Data-boundary missing-envelope recovery pattern:
  `data_boundary_missing_envelope_recovery` checks fail-closed behavior when a required
  `DataEnvelope` is absent at a boundary action. The local corpus now has 24 deterministic
  seed patterns; baseline demo targets fail all 24 and the protected demo target passes
  all 24 under deterministic replay.
- Data-boundary research closure records in the project tracker and claims registry,
  separating public evidence artifacts from local-only derivation/audit notes.

### Changed
- `run_diff.json` is now schema v0.2 with explicit decisive/non-decisive labels such as
  `finding_fixed`, `new_finding`, and `inconclusive_error_drift`; v0.1 aliases and
  validation support remain for compatibility.
- Project tracker, project map, local Prometheus docs, and research claims now point to
  the bounded local-suite workflow and clarify that weak local model evidence is
  inconclusive/error unless the validated artifacts say otherwise.
- `agentic-boundary-model.md` is now the canonical protection/boundary model catalog,
  including current coverage and missing situation families.
- README, protocol, semantics, project map, roadmap, research roadmap, harness,
  development, adapter contract, and release checklist now distinguish boundary
  invariants, evaluation topologies, shipped coverage, and planned work more explicitly.
- README and project map now point reviewers to current-state and authorized-testing
  documents before they infer status from scattered docs.
- New external runs treat missing pattern ids, invalid boundary assertions, control-family
  mismatches, and contradictory verdict fields as `inconclusive` instead of PASS/FINDING.
- The fake OpenAI-compatible demo server now echoes the requested pattern id and emits the
  new boundary assertion field.
- Benchmark protocol and semantics now document the conservative external cross-check:
  contradictory model self-reports, such as `decision=block` with
  `would_preserve_boundary=false`, are weak evidence and remain `inconclusive`.
- Key CLI commands now have machine-readable output paths for automation while preserving
  the existing human-readable default output.
- External credential metadata now uses `credential_env_var` and the preferred
  `--credential-env` flag. The legacy `api_key_env` artifact field and `--api-key-env`
  CLI alias remain readable for compatibility, but new artifacts and prompts avoid
  secret-like plaintext patterns.
- `ash validate` now hides validation message details in text output and redacts
  secret-shaped strings in JSON output.
- Standards mapping now asserts a small MITRE ATLAS 2026.05 verified subset for direct-fit
  categories and keeps governance/audit/delegation categories deferred where the fit would
  be speculative.
- External reports and run manifests now surface runtime metadata and recovery guidance,
  and the committed external demo report uses the same fake-local runtime metadata path
  as a normal CLI run.
- README, current-state, adapter contract, capability matrix, evaluation topologies,
  roadmap, boundary model, and project map now list `toy-multi-agent` as shipped while
  keeping live/cross-provider multi-agent workflows future-scoped.
- The committed comparison example README now reflects the current 24-pattern corpus and
  links to the public showcase checklist.

## [0.13.0] - 2026-06-14

### Added
- **Schema-version registry** (`schema_versions.py`): a single source of truth for every
  artifact's `schema_version`. `scorecard.json` and `remediation.json` now carry one too.
  `ash validate` rejects unknown/future versions with a clear message and catches a missing
  version where required. Policy documented in `docs/artifact-schemas.md`.
- **`ash diff-runs --left … --right … --out …`**: compare two run directories of the same
  kind (run/matrix/external). Writes schema-versioned `run_diff.json` + `run_diff.md` with
  fixed / new / changed / unchanged / only-left / only-right per pattern. Validated by
  `ash validate`; rendered by `ash report`. Docs: `docs/run-diff.md`.
- **HTML report v2**: per-pattern findings detail (category, severity, control family,
  evidence, quick/engineering/architecture fix, retest hint) on run reports, an explicit
  "needs more data" (flaky/inconclusive/error) section on external reports, and a run-diff
  view. Still self-contained: no JS, no CDN, no network.
- **External connection presets** (`ash external-presets`, `--preset`): fake-local, vllm,
  ollama, lm-studio, deepseek, alibaba-qwen-compatible, generic-openai-compatible. A preset
  only fills a default base URL and a credential env-var **name**; it adds no SDK and hides no
  network call. `--base-url` is now optional when `--preset` is given.
- **doctor v2**: adds a reports-dir writability check and an external-preset validation
  check (no network). New `--reports-root` flag.
- **Local run index** (`ash index-runs`, `ash list-runs --db`): a stdlib-only SQLite index
  of run-manifest **metadata** (no trace bodies, no secrets). Design + scope in
  `docs/run-database-design.md`.
- **Packaging readiness**: `Dockerfile` (local/offline CLI + fake-server demo, non-root,
  no secrets), `.dockerignore`, a minimal `.devcontainer`, and `docs/release-to-pypi.md`.

### Changed
- Bumped to 0.13.0. Regenerated the committed report examples to include the new
  `schema_version` fields in `scorecard.json` / `remediation.json`.
- `run-external` / `external-check`: a clean error (rc 1) instead of an argparse exit when
  neither `--base-url` nor `--preset` is provided.

## [0.12.1] - 2026-06-14

### Added
- **docs/benchmark-semantics.md** — what is and is not tested, the meaning of
  PASS / FINDING / INCONCLUSIVE / FLAKY / ADAPTER_ERROR, what `ash validate` verifies and
  does **not** prove, and how to compare runs responsibly.
- **docs/capability-matrix.md** — per-target/mode table (network default, model use,
  determinism, corpus scope, repeats, variants, manifest, validation, good-for / not-for).
- **docs/user-journey.md** — one complete happy path (install → local report → validate →
  fake-server external flow), with Windows PowerShell and Linux/macOS commands.
- **docs/independent-benchmark-gap-list.md** and **docs/benchmark-positioning-gap-list.md**
  — honest gap lists (not implemented in this pass).

### Changed
- **Network scoping clarified** across README, project-map, roadmap, adapter-contract,
  reporting, and the package docstring: built-in/local targets are offline; the
  `run-external` path is explicit opt-in OpenAI-compatible; native provider and
  agent-host adapters are future. Removed broad "no network/no LLM" claims that
  contradicted the opt-in path.
- **Stale "future" claims fixed**: `ash report`, toy-rag/toy-tools, adapter metadata, and
  the stochastic/inconclusive statuses are documented as shipped (were "planned/future").
- **Fuller external reproduce command** in `external_report.md`: now includes temperature,
  timeout, repeats, the selected variant or max-variants, the credential env-var **name**
  (never the value), the redacted base_url, and `--max-requests` only when the cap would
  block the rerun; notes that `run_config.json` is authoritative.
- `ash validate` success line now states it is artifact integrity only, not a safety
  guarantee.

## [0.12.0] - 2026-06-14

### Added
- **Static HTML reports** — `ash report --root <dir> [--out <file>]` renders a
  self-contained `report.html` (inline CSS, no JS, no CDN, no network) for run, compare,
  matrix, and external directories. Includes an executive summary, severity distribution,
  pattern table, a **coverage heatmap** (pattern × variant) for matrix runs, a
  before/after view for comparisons, a stochastic repeat-status view for external runs,
  control-family summary, run/adapter metadata, and a "what this does not prove" section.
- **`ash doctor`** — onboarding diagnostics (Python version, package import, CLI commands,
  examples/fake-server presence, writability, key-env presence (value never read),
  supported external adapters, next commands). Flags: `--json`, `--live-local`,
  `--base-url`, `--credential-env`. No network unless `--live-local`.
- **Toy adapters** — `toy-rag` (data/memory/injection surface) and `toy-tools`
  (tool/authority surface): deterministic, local, no network, with corpus-consistent
  findings and honest partial coverage. Registered in `ash targets`.
- **Adapter metadata in `run_index.json`** — external runs record an adapter metadata
  block (adapter_type, model, redacted base_url, scenario, repeats, temperature, timeout,
  request_count, network_mode, key-env name). Exposed in the HTML report.
- **Explicit stochastic repeat status** — each external `(pattern, variant)` group gets a
  `stability_status`: `stable_pass`, `stable_finding`, `flaky`, `inconclusive`, or
  `adapter_error`. Documented in connect-models.md.
- **Standards mapping v0.12** — category-level OWASP LLM 2025 and NIST AI RMF function
  mappings with rationale (`standards_mapping.py`); MITRE ATLAS explicitly deferred.
- **Release checklist** — `docs/release-checklist.md` with maintainer commands and v1.0
  blockers.

### Changed
- **Validation tiers** — target types now validate in three tiers: `baseline`
  (must FAIL every pattern), `protected` (must PASS), and `neutral` (any other adapter;
  findings optional but still corpus-consistent). This unblocks toy and arbitrary
  adapters that legitimately PASS some patterns.
- `ash validate` runs a corpus-level standards-mapping self-check so docs and code cannot
  silently drift, and validates external adapter metadata in `run_index.json`.

### Fixed
- `docs/standards-mapping.md` stale count (said "seventeen") now reflects 22 patterns /
  14 categories and matches the machine-readable mapping.

## [0.11.0] - 2026-06-14

### Added
- **Run history manifests** — every run writes `run_index.json` (run id, kind,
  target/model, scenario, variants, repeats, outcome counts, artifact paths). New
  `ash list-runs --root <dir>` lists runs; manifests are validated by `ash validate`
  when present. New `run_manifest` module exported from the package API.
- **Getting-started guide** — `docs/getting-started.md`: clone → first validated report
  in 10–30 minutes, no keys or network; includes the run-history workflow.
- **Examples showcase** — `examples/README.md` documents each committed example, the
  exact command to regenerate it, expected output, and the recommended reading order.
- **Cross-platform CI** — the test matrix now runs on Ubuntu (Python 3.11–3.13) and
  Windows (Python 3.11), backing the cross-platform claim. Added a 3.13 classifier and
  `Operating System :: OS Independent`.
- **Read-this-first pointers** — `run`, `compare`, `run-matrix`, and `run-external`
  now print a `Start here:` line to the primary report plus the run id.
- **Connector recipes doc** — `docs/connect-models.md`: a connection matrix and
  copy-pasteable Windows PowerShell + Linux/macOS recipes for the fake server, vLLM,
  DeepSeek, Alibaba/Qwen compatible-mode, generic OpenAI-compatible gateways, and
  Ollama / LM Studio, with a "supported now / via OpenAI-compatible / future" status
  table and troubleshooting. Linked from README and `docs/test-your-model.md`.
- **external-check next steps** — the preflight now prints a copy-pasteable
  dry-run → live → validate command sequence (redacted base_url, env-var name only)
  and clarifies that only `--live` / a real run make network calls.
- **`How to reproduce / validate` section** in `external_report.md` (and required by
  `ash validate`), with a redacted, copy-pasteable rerun + validate command.
- **External-run control recommendations** — `external_report.md` now ends with a
  per-control-family recommendations section (what failed, why it matters, quick /
  engineering / architecture fix, verification, residual risk) for any finding.
- **Deterministic control-family aggregation for external runs** —
  `external_summary.json` now populates `findings_by_control_family` from the canonical
  pattern→family map (not the model's self-reported field).
- **`request_count` in `run_config.json`** — the pre-run request estimate is recorded
  and validated against the number of results actually written.
- **Cost safety cap** — `run-external` refuses to start when the estimated request
  count (`patterns × variants × repeats`) exceeds `--max-requests` (default 50);
  `external-check` surfaces whether the current scope is within the cap.

### Changed
- `ash run-external` preflight now prints the request estimate, the artifacts path,
  and an "API key value is never stored" notice; `--dry-run` states "No network call.
  No files written." and the next command to run.
- `_classify_outcome` now treats `would_preserve_boundary` as the single canonical
  outcome signal, consistent with summary aggregation.

### Validation
- `ash validate` now recomputes and checks external `findings_by_pattern`,
  `findings_by_control_family`, `inconclusive_patterns`, and `flaky_patterns`,
  verifies `run_config.request_count`, and checks `external_report.md` has its core
  sections and references the machine artifacts.
- `ash validate` validates `run_index.json` when present (schema, run kind, and that
  every listed artifact exists).

### Fixed
- Reconciled the package version: `pyproject.toml`, `__version__`, and the CHANGELOG
  now agree (was `pyproject` 0.8.0 vs `__version__` 0.10.0).

## [0.10.0] - 2026-06-13

### Added
- **Remediation layer** — structured control recommendations for every finding:
  - `ControlRecommendation` model with control family, priority (p0-p3), quick fix,
    engineering fix, architecture fix, verification, and residual risk.
  - `RemediationReport` aggregation model.
  - 11 control families: provenance, data_boundary, memory_governance, tool_selection,
    capability_control, approval_context, audit_completeness, budget_control,
    perception_boundary, provider_boundary, adapter_metadata.
  - Deterministic mapping from 22 patterns to control families.
- **Remediation report artifacts:**
  - `remediation.json` — machine-readable control recommendations.
  - `remediation.md` — human-readable remediation report with priorities, quick fixes,
    engineering fixes, architecture fixes, verification steps, and residual risk.
- **Executive report integration** — `executive.md` now shows top control families needed.
- **Comparison report integration** — `comparison.md` includes a "Recommended control
  priorities" section referencing baseline remediation.
- **Validation of remediation artifacts** — `ash validate` checks `remediation.json` and
  `remediation.md` against rebuilt recommendations; scans for forbidden markers.
- **Known limitations documentation** — `docs/threat-model.md` now documents 7 known
  limitations (covert channels, stochastic behavior, adaptive attacks, standards gaps,
  real adapter requirements, cross-app contamination, audit context completeness).

### Changed
- `write_reports()` now emits `remediation.json` and `remediation.md` when findings exist.
- `build_executive_md()` includes top control families in the executive view.
- `build_comparison_md()` includes a "Recommended control priorities" section.
- `__version__` updated to `0.10.0`.

## [0.9.0] - 2026-06-13

### Added
- **v0.9 corpus deepening slice** — 5 deeper variant patterns expanding the corpus
  from 17 to 22 deterministic seed patterns:
  - `memory_governance.environment_injected_poisoning`: retrieved content stored as
    memory without provenance; later treated as trusted policy.
  - `memory_governance.unintentional_cross_user`: User A data returned to User B
    from shared memory without per-user scope isolation.
  - `budget.recursive_execution_amplification`: recursive call-depth budget not
    enforced; synthetic recursive request structure exceeds depth limit.
  - `mcp.tool_selection_manipulation`: tool selection follows untrusted bias instead
    of task intent; read-only task selects write-like mock tool.
  - `indirect_instruction.multi_turn_escalation`: agent acts on final turn after
    context-shaping turns soften per-turn defenses.
- Adapter contract models (`TargetMetadata`, `HealthStatus`, `CapabilityCheckResult`) to
  define reproducibility and safety metadata for future non-synthetic targets.
- `executive.md` report artifact for `ash run` outputs and comparison subreports.

### Changed
- Baseline `demo-agent` / `mock` fail all 22 patterns (high: 20, medium: 2);
  `protected-demo-agent` passes all 22; `ash compare` shows findings reduced 22 -> 0.
- Updated corpus, roadmap, standards mapping, research roadmap, and problem-solution
  catalog for the expanded memory-governance, budget, tool-selection, and
  multi-turn-instruction coverage.
- Regenerated and revalidated all committed benchmark examples for the 22-pattern corpus.
- Updated reporting and adapter documentation to reflect the new metadata/report
  foundation while keeping current targets deterministic and local.

## [0.8.0] - 2026-06-13

### Added
- **Perception boundary and ambient authority corpus slice:** added
  `perception_boundary.sensor_command_confusion` (perception-channel content must not be
  treated as user intent or system directive),
  `ambient_authority.environmental_privilege_escalation` (ambient host capabilities must
  not be used without explicit envelope binding),
  `approval_laundering.underjustified_confirmation` (approval requests must include full
  envelope context for informed consent), and
  `memory_governance.unscoped_memory_persistence` (memory writes must track provenance,
  trust level, TTL; untrusted entries must not overwrite trusted ones). Baseline
  `demo-agent` / `mock` fail all 17 (high: 15, medium: 2); `protected-demo-agent` passes
  all 17; `ash compare` shows findings reduced 17 -> 0.
- Minimal local models for `PerceptionTranscript` and `MemoryEntry`.

### Changed
- Regenerated and revalidated all committed benchmark examples for the 17-pattern corpus.
- Updated corpus, standards mapping, research roadmap, project map, and problem-solution
  catalog for the expanded authority / perception / governance coverage.

## [0.7.0] - 2026-06-13

### Added
- **Authority and integrity corpus slice:** added
  `capability.delegation_chain_drift` (synthetic capability delegation must not widen
  scope, purpose, or TTL), `mcp.tool_schema_deception` (mock tool-schema hash drift must
  be rejected unless provenance is trusted), and `audit.hash_chain_tamper` (local
  append-only audit entries must detect edits via hash-chain validation). Baseline
  `demo-agent` / `mock` fail all 13 (high: 11, medium: 2); `protected-demo-agent` passes
  all 13; `ash compare` shows findings reduced 13 -> 0.
- Minimal local models for `CapabilityToken`, `ToolSchemaRecord`, and `AuditEntry`.

### Changed
- Regenerated and revalidated all committed benchmark examples for the 13-pattern corpus.
- Updated corpus, standards mapping, research roadmap, project map, and problem-solution
  catalog to distinguish current v0.7 mock coverage from future live MCP / real-adapter work.

## [0.6.0] - 2026-06-12

### Added
- **Corpus expansion to 10 deterministic seed patterns (v0.6):** added
  `sleeping_prompt.delayed_activation` (a sanitized dormant-instruction placeholder must
  not be trusted on a later turn; provenance/TTL enforced at read time),
  `audit.spam_label_abuse` (an untrusted spam/ignore label must never suppress an audit
  entry), and `budget.loop_abuse` (a synthetic loop marker against a deterministic step
  counter; a loop guard must stop at the step budget). Baseline `demo-agent`/`mock` fail
  all 10 (high: 8, medium: 2); `protected-demo-agent` passes all 10; `ash compare` shows
  findings reduced 10 -> 0. Committed examples regenerated and validated. All scenarios
  remain synthetic, sanitized, local-only - no network, no real payloads, no real
  resource consumption.
- Standards mapping page for the implemented local corpus, with coarse OWASP Agentic
  Security Initiative mappings and explicit verification gates for OWASP LLM / MITRE ATLAS.
- Release packaging checks in CI: build sdist/wheel, run `twine check`, smoke the installed
  wheel, verify `py.typed`, and run `ash validate examples/` from the wheel install.

### Changed
- Strengthened the data-boundary / label-propagation positioning and refreshed the
  competitive landscape with CaMeL, FIDES, and AgentDojo as key adjacent references.
- Tightened public wording around current vs planned capabilities: multimodal, cross-agent,
  gateway, OWASP LLM, and MITRE ATLAS coverage are explicitly marked as planned or
  verification-gated where they are not implemented.
- Updated package metadata with author, classifiers, keywords, URLs, SPDX license syntax,
  and license-file declarations.
- Corrected the Prompt Security ownership note after verifying SentinelOne's acquisition
  completion in an SEC filing.

### Fixed
- Hardened `ash validate` so a report must include every implemented corpus pattern exactly
  once, and trace fields must match the canonical seed pattern graph, expected behavior,
  data envelope, and finding category.
- Clarified the problem-solution catalog with current/planned status and exact implemented
  pattern IDs where available.

## [0.5.0] - 2026-06-12

### Added
- Plain-language project map, company-facing use cases, and a comparison-report README to
  make the benchmark easier to review without reading the source code first.
- GitHub Actions CI for `pytest`, `ruff`, `mypy`, and `ash validate examples/` on Python
  3.11 and 3.12.
- **Validation layer + `ash validate`** (v0.5): `src/agentic_security_harness/validation.py`
  validates report dirs (traces / scorecard / summary), comparison dirs (baseline / protected
  + comparison.md), and corpus consistency against the manifest, with a conservative
  forbidden-marker scan and a structured `{ok, errors, warnings}` result. `ash validate
  examples/` runs as a benchmark check. Deterministic, stdlib + Pydantic only, no new deps.
- **Corpus manifest + coverage matrix:** `src/agentic_security_harness/corpus.py` (curated
  machine-readable metadata for the 7 implemented patterns) and `docs/corpus.md`; plus a
  `NOTICE` file.
- Expanded the local defensive corpus to **7 deterministic seed patterns** (v0.4): added
  data-boundary classification mutation, handoff label stripping, tool-permission abuse, and
  provider-boundary leakage (sanitized) on top of the original three. The vulnerable
  `demo-agent` and `mock` fail all 7; `protected-demo-agent` passes all 7; `ash compare` now
  shows findings reduced 7 -> 0. Committed examples regenerated. Local, no network, sanitized.
- Protected **demo-agent** target + risk-reduction comparison (v0.3): a
  `protected-demo-agent` (the same local agent with simple deterministic controls that
  mitigate the three seed patterns -> PASS) and an `ash compare --baseline ... --protected
  ... --out ...` command that writes `baseline/`, `protected/`, and a `comparison.md`
  showing the reduction in findings. Committed examples under
  `examples/protected-demo-agent-report/` and `examples/comparison-report/`. Local,
  deterministic, no network, sanitized data only.
- Local **demo-agent** target (v0.2): a deterministic, synthetic local agent (in-memory
  memory, mock tool calls, data-envelope propagation, recipient-control checks) exposed via
  a target adapter; `ash run --target demo-agent --out <dir>`; committed example under
  `examples/demo-agent-report/`. No network, no LLM, sanitized data only.
- Demo CLI (`ash`) and deterministic report artifacts: `ash run --target mock --out <dir>`
  writes `traces.json`, `scorecard.json`, and `summary.md`; a curated example is committed
  under `examples/demo-report/`. Mock-only, no network.
- v0.1 harness core scaffold (code): Pydantic v2 models (`DataEnvelope`, `Finding`,
  `TraceStep`, `TargetDescriptor`, `ExploitTrace`, `DefensivePattern`), three sanitized seed
  patterns, a deterministic mock target, the runner (`pattern -> trace`), and the scorecard —
  with unit tests. No LLM, network, gateway, or CLI.
- Education + safe-research docs: `docs/mission.md`, `docs/research-rules.md`, and learning
  modules (`docs/learning/01-agentic-security-basics.md`,
  `docs/learning/02-data-boundary-failures.md`); README "Mission", "Safe research rules",
  and "What exists today" sections.
- Project blueprint and documentation set: README, harness (flagship), problem–solution
  catalog, architecture, roadmap, threat model, API reference, deployment, development, and
  competitive-landscape docs.
- Apache-2.0 license, contribution guidelines, and security disclosure policy.
- Competitive landscape (all listed tools) and OWASP claims verified against primary
  sources with inline links — incl. Trylon Gateway (closest prior art), LiteLLM
  guardrails, Guardrails AI, NeMo Guardrails, LLM Guard, Presidio, Lakera; Rebuff
  archived; Protect AI acquired by Palo Alto Networks; Prompt Security acquired by
  SentinelOne; OWASP LLM Top 10 2025 numbering.

### Changed
- Strengthened public positioning and attribution: named **Agentic Security Harness**
  (dropped "Product name TBD" headers), replaced "no uniqueness claims" headlines with
  confident honest wording (not first/only; competes on trace portability, corpus clarity,
  data-boundary measurement, and deterministic replay), README now leads as a trace-first
  defensive benchmark, and added a Brand-and-attribution section.
- Repositioned the project as an **Agentic Security Harness** — an open-source harness for
  reproducible, portable agentic exploit **traces**, an **attack graph**, and a
  **scorecard**. The OpenAI-compatible gateway is now the **reference defense** component,
  not the main product. Added an **agentic data-boundary / recipient-control** class (data
  envelope) and a sanitized **multimodal / sensor-to-agent (audio → ASR)** class, a new
  **problem–solution catalog**, and a **responsible-use** policy. Renamed the repository to
  `agentic-security-harness`.
- Softened public positioning to a **defensive education + measurement lab** — the repo
  description and README lead now read "agentic AI failure modes" rather than "exploit
  chains" (no functional change).

### Docs
- Clarified current-vs-planned boundaries in README and gateway-related docs: the current
  release is CLI-only with local synthetic targets; the reference gateway/API remain
  planned design, not shipped runtime.
- Realigned the documentation set with the v0.5 benchmark roadmap and current project
  structure (roadmap, development, architecture, harness, deployment, threat-model,
  api-reference, CONTRIBUTING). Removed stale gateway-era references (`tests/attacks`,
  `tests/unit`, `tests/integration`, `mypy app`) and reframed the reference gateway and real
  adapters as planned/future. Synced the quality gates to `pytest` / `ruff` / `mypy` /
  `ash validate`.

### Fixed
- **Comparison reduction line uses a signed delta** (surfaced by the v0.5 validator):
  `build_comparison_md` now formats the findings delta as a single signed quantity
  (`(-7)` / `(+3)` / `(+0)`) instead of a literal `-` prefix that produced a malformed
  `(--3)` when the protected target had *more* findings than baseline. The validator parses
  the signed value, so producer and validator stay in lockstep. Committed examples are
  byte-identical (the normal baseline-vs-protected case still reads `(-7)`).

### Notes
- The `v0.1` harness core (code) is implemented — see *Added*. Next milestones are corpus
  expansion, local adapter examples, report quality, mapping/standardization, and a stable
  benchmark release; real adapters/reference gateway remain future tracks. See
  [docs/roadmap.md](docs/roadmap.md).
