"""Install and verify the exact optional-module wheelhouse without loading extensions."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import subprocess
import sys
import tempfile
from pathlib import Path

EXPECTED = {
    "agentic-security-harness": ("1.4.0", "agentic_security_harness-1.4.0-py3-none-any.whl"),
    "agentic-transfer-verifier": ("0.2.1", "agentic_transfer_verifier-0.2.1-py3-none-any.whl"),
    "agentic-transfer-verifier-harness-extension": (
        "1.0.1",
        "agentic_transfer_verifier_harness_extension-1.0.1-py3-none-any.whl",
    ),
    "ai-agent-handoff": ("0.3.0", "ai_agent_handoff-0.3.0-py3-none-any.whl"),
    "ai-agent-handoff-harness-extension": (
        "1.0.0",
        "ai_agent_handoff_harness_extension-1.0.0-py3-none-any.whl",
    ),
    "llm-safety-playbooks": ("0.1.0", "llm_safety_playbooks-0.1.0-py3-none-any.whl"),
    "agentic-llm-router": ("0.2.0", "agentic_llm_router-0.2.0-py3-none-any.whl"),
    "llm-cheap-filter": ("0.2.0", "llm_cheap_filter-0.2.0-py3-none-any.whl"),
}
PLAYBOOK_SHA256 = "1c8ca14e6ab83d92742f6fba0b0d1b1bc422ebe30163c6619e9c80f5413b8915"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheelhouse", type=Path)
    wheelhouse = parser.parse_args().wheelhouse.resolve()
    expected_files = {filename for _, filename in EXPECTED.values()}
    actual_files = {path.name for path in wheelhouse.glob("*.whl")}
    if actual_files != expected_files:
        raise SystemExit(f"wheelhouse artifact drift: {sorted(actual_files)}")

    with tempfile.TemporaryDirectory() as temporary:
        target = Path(temporary) / "site"
        wheels = [str(wheelhouse / filename) for filename in sorted(expected_files)]
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-index",
                "--no-deps",
                "--no-compile",
                "--target",
                str(target),
                *wheels,
            ],
            check=True,
        )
        installed = {
            distribution.metadata["Name"]: distribution
            for distribution in metadata.distributions(path=[str(target)])
        }
        if set(installed) != set(EXPECTED):
            raise SystemExit(f"installed distribution drift: {sorted(installed)}")
        for name, (version, _) in EXPECTED.items():
            if installed[name].version != version:
                raise SystemExit(f"installed version drift for {name}")

        transfer_points = tuple(
            point
            for point in installed[
                "agentic-transfer-verifier-harness-extension"
            ].entry_points
            if point.group == "agentic_security_harness.extensions.v1"
        )
        handoff_points = tuple(
            point
            for point in installed["ai-agent-handoff-harness-extension"].entry_points
            if point.group == "agentic_security_harness.extensions.v1"
        )
        if [(point.name, point.value) for point in transfer_points] != [
            (
                "agentic-transfer-verifier.verification",
                "agentic_transfer_verifier_extension:build_extension",
            )
        ]:
            raise SystemExit("Transfer extension entry-point drift")
        if [(point.name, point.value) for point in handoff_points] != [
            (
                "ai-agent-handoff.validation",
                "ai_agent_handoff_harness_extension:build_extension",
            )
        ]:
            raise SystemExit("Handoff extension entry-point drift")

        pack = target / "llm_safety_playbooks" / "data" / "policy-pack.v1.json"
        if hashlib.sha256(pack.read_bytes()).hexdigest() != PLAYBOOK_SHA256:
            raise SystemExit("installed Playbooks artifact digest drift")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
