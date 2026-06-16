# External demo report

This directory is a committed snapshot of the experimental external path.

The external path is OpenAI-compatible, prompt-only, and opt-in. It does not execute
tools, drive a real agent host, or provide benchmark-grade model comparison. It is useful
for early, authorized checks of model responses to synthetic boundary scenarios.

The committed example can be reproduced with the bundled fake local server:

```bash
# terminal 1
python examples/fake_openai_server.py

# terminal 2
ash run-external --preset fake-local --model fake-model --scenario data-boundary --out reports/external-demo
ash validate reports/external-demo
```

Read in this order:

1. `external_report.md` - human-readable external-run summary.
2. `external_summary.json` - aggregate status counts.
3. `external_results.json` - per-response records.
4. `run_config.json` - exact run configuration, including runtime metadata.
5. `run_index.json` - run-history metadata.
6. `raw_responses/` - full mocked model responses referenced by `external_results.json`.

Treat external results as exploratory unless they have sufficient repeats, stable
configuration, and an independent observation layer.
