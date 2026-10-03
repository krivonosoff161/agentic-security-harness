"""Offline acceptance of the installed configured writer, with real file effects.

Run with python -I -B: no source-path injection, providers or private input. Only
the new --out directory is written. Existing output directories are never reused.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def check(out: Path) -> dict[str, Any]:
    from agentic_security_harness import __version__
    from agentic_security_harness import workspace_writer as writer

    module = Path(writer.__file__).resolve()
    if not module.is_relative_to(Path(sys.prefix).resolve()):
        raise ValueError("acceptance requires an installed package, not checkout imports")
    out = out.absolute()
    out.mkdir(parents=True, exist_ok=False)
    output = out / "output"
    output.mkdir()
    config = out / "policy.json"
    config.write_text(json.dumps({
        "schema_version": "ash.workspace-write.v1", "output_dir": "output",
        "outputs": {"draft": "summary.md"}, "data_class": "public",
        "max_bytes": 8192, "max_proposals": 4,
    }), encoding="utf-8")
    content = "# Application document\n\nUnicode: проверка.\n"
    protected = output / "protected.txt"
    protected.write_bytes(b"host file; preserve exactly\n")
    protected_before = protected.read_bytes()
    rows: list[dict[str, Any]] = []

    def call(name: str, *args: str, proposal: dict[str, Any] | None = None,
             expected: int = 0) -> dict[str, Any]:
        proc = subprocess.run(
            [sys.executable, "-I", "-B", "-m", "agentic_security_harness.cli", *args],
            cwd=out, input=json.dumps(proposal).encode() if proposal is not None else None,
            capture_output=True, timeout=60, check=False,
        )
        if proc.returncode != expected:
            raise ValueError(f"{name}: unexpected exit code {proc.returncode}")
        result: dict[str, Any] = json.loads(proc.stdout)
        rows.append({"case": name, "exit_code": proc.returncode, "result": result})
        return result

    call("configuration", "workspace-check", "--config", "policy.json")
    proposal = {"operation": "write_text", "artifact": "draft", "content": content}
    written = call("allowed_write", "workspace-write", "--config", "policy.json",
                   proposal=proposal)
    assert written["applied"] and written["receipt_complete"]
    assert (output / "summary.md").read_bytes() == content.encode()
    receipt = str(Path("output") / written["receipt"])
    verified = call("readback", "workspace-verify", "--config", "policy.json",
                    "--receipt", receipt)
    assert verified["integrity_ok"]
    call("existing_file_preserved", "workspace-write", "--config", "policy.json",
         proposal=proposal, expected=1)
    denied = call("unknown_destination", "workspace-write", "--config", "policy.json",
                  proposal={**proposal, "artifact": "protected"}, expected=1)
    assert not denied["applied"] and denied["reason"] == "guard_rejected"
    forged = call("forged_authority", "workspace-write", "--config", "policy.json",
                  proposal={**proposal, "authority": "allow"}, expected=1)
    assert not forged["applied"] and forged["reason"] == "proposal_rejected"
    assert protected.read_bytes() == protected_before
    assert (output / "summary.md").read_bytes() == content.encode()

    api_output = out / "application-output"
    api_output.mkdir()
    policy = writer.WorkspacePolicy(api_output, (("note", "note.txt"),), data_class="public")
    with writer.GuardedWorkspace(policy) as workspace:
        result = workspace.submit(json.dumps({**proposal, "artifact": "note"}).encode())
    assert result["applied"] and result["receipt_complete"]
    assert (api_output / "note.txt").read_bytes() == content.encode()
    assert writer.verify_workspace_output(policy, api_output / result["receipt"])["integrity_ok"]
    rows.append({"case": "python_hook", "result": result})

    # A verifier must catch changed output bytes, not merely parse its own receipt.
    (api_output / "note.txt").write_bytes(b"changed by acceptance control\n")
    changed = writer.verify_workspace_output(policy, api_output / result["receipt"])
    assert not changed["integrity_ok"]
    rows.append({"case": "readback_detects_changed_bytes", "detected": True})
    summary = {"evidence_class": "installed_workspace_writer_offline_acceptance",
               "version": __version__, "checks": len(rows), "passed": True,
               "model_calls": 0, "protected_unchanged": True, "rows": rows}
    (out / "result.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    result = check(args.out)
    print(json.dumps({key: result[key] for key in ("version", "checks", "passed", "model_calls")}))


if __name__ == "__main__":
    main()
