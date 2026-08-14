"""Generate or verify the frozen public corpus manifest v1 contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agentic_security_harness.corpus import (
    CorpusEntry,
    CorpusManifestV1,
    CorpusPatternReplacement,
    corpus_contract,
)

MANIFEST_PATH = "schemas/corpus-manifest.v1.json"
SCHEMA_PATH = "schemas/corpus-manifest.v1.schema.json"


def _encoded_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def corpus_manifest_json_schema() -> dict[str, Any]:
    """Return the closed public shape schema; semantic checks remain in Python."""

    schema = CorpusManifestV1.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = (
        "https://github.com/krivonosoff161/agentic-security-harness/"
        "schemas/corpus-manifest.v1.schema.json"
    )
    schema["title"] = "Agentic Security Harness corpus manifest v1"
    schema["description"] = (
        "Closed shape contract for the stable deterministic corpus manifest. "
        "Pattern identity, ordering, deprecation and replacement semantics are "
        "enforced by the Python validator."
    )
    schema["required"] = list(CorpusManifestV1.model_fields)
    schema["additionalProperties"] = False
    definitions = schema["$defs"]
    definitions["CorpusEntry"]["required"] = list(CorpusEntry.model_fields)
    definitions["CorpusEntry"]["additionalProperties"] = False
    definitions["CorpusPatternReplacement"]["required"] = list(
        CorpusPatternReplacement.model_fields
    )
    definitions["CorpusPatternReplacement"]["additionalProperties"] = False
    return schema


def build_outputs() -> dict[str, bytes]:
    return {
        MANIFEST_PATH: _encoded_json(corpus_contract().model_dump(mode="json")),
        SCHEMA_PATH: _encoded_json(corpus_manifest_json_schema()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    for relative, content in build_outputs().items():
        path = (root / relative).resolve()
        if root not in path.parents:
            raise RuntimeError("corpus contract output escaped repository root")
        if args.check:
            if not path.is_file() or path.read_bytes() != content:
                raise RuntimeError(f"generated corpus contract is stale: {relative}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
