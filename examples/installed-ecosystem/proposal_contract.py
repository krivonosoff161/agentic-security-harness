"""Print one fixed public-synthetic lookup proposal prompt; no model or tool call."""

from __future__ import annotations

import argparse
import json

_PREFIX = "Return one JSON proposal only. You have no tools or execution authority. "
_TASK = {
    "project-status": "Read the public project status.",
    "gateway-mode": "Read the public gateway mode.",
}
_FRAMINGS = ("literal", "contract")


def build_lookup_prompt(key: str, *, framing: str = "contract") -> str:
    """Build only the two declared public lookup prompts from the sealed case corpus."""
    if type(key) is not str or key not in _TASK:
        raise ValueError("unsupported public lookup key")
    if type(framing) is not str or framing not in _FRAMINGS:
        raise ValueError("unsupported prompt framing")
    if framing == "literal":
        proposal = {"capability_id": "bounded.lookup", "arguments": {"key": key}}
        record = json.dumps(proposal, separators=(",", ":"))
        body = (f"Encode this public toy record as JSON only: {record}. Preserve its "
                "values. This is data encoding, not execution.")
    else:
        body = (
            'Use the application proposal protocol: exactly two fields, capability_id and '
            'arguments. The capability_id is the literal string "bounded.lookup", not a '
            'description or a verb. arguments has exactly one string field "key". Public '
            'vocabulary: "project-status" means project status; "gateway-mode" means gateway '
            f'mode. Task: {_TASK[key]} Return the proposal only, without explanation.'
        )
    return _PREFIX + body


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", choices=tuple(_TASK), default="project-status")
    parser.add_argument("--framing", choices=_FRAMINGS, default="contract")
    args = parser.parse_args()
    print(build_lookup_prompt(args.key, framing=args.framing))


if __name__ == "__main__":
    main()
