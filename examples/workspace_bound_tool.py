"""Offline caller-owned agent loop using one host-bound text tool.

The host chooses the existing output directory and alias. The scripted agent
can supply only document text. This example makes no model or network call.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agentic_security_harness.workspace_writer import GuardedWorkspace, WorkspacePolicy


def scripted_agent(source: str, write_draft: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    """Illustrate an application calling its already-bound tool."""
    completed_text = "# Review note\n\n" + source.strip() + "\n"
    return write_draft(completed_text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="existing host-owned directory")
    args = parser.parse_args()
    policy = WorkspacePolicy(
        args.output_dir.absolute(), (("draft", "draft.md"),),
        max_bytes=2048, max_proposals=1, data_class="synthetic",
    )
    with GuardedWorkspace(policy) as workspace:
        write_draft = workspace.bind_text_tool("draft")
        result = scripted_agent("Confirm the dates with the owner.", write_draft)
    print(json.dumps({"applied": result["applied"], "reason": result["reason"],
                      "effect": result["effect"]}, sort_keys=True))
    return 0 if result["applied"] and result["receipt_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
