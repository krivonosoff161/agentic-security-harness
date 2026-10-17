"""Synthetic tool-call facade checks; signatures are not human consent."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ash_action_authority import ActionGate, canonical, decision_message
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentic_security_harness.workspace_operation import WorkspaceOperation
from agentic_security_harness.workspace_writer import WorkspacePolicy

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "content_only_dispatch.py"
SPEC = importlib.util.spec_from_file_location("content_only_dispatch_example", EXAMPLE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("dispatch_example_unavailable")
example = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(example)


class ContentOnlyDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="ash-dispatch-")
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name).resolve()
        output = base / "output"
        output.mkdir()
        state = base / "state"
        state.mkdir()
        self.target = output / "report.md"
        self.content = "Exact synthetic document.\n"
        self.signer = Ed25519PrivateKey.generate()
        policy = WorkspacePolicy(
            output_dir=output,
            outputs=(("report", "report.md"),),
            max_bytes=65536,
            max_proposals=1,
            data_class="public",
        )
        self.now = 1_800_000_000
        self.gate = ActionGate.create(
            state / "operation-1",
            policy,
            content=self.content,
            operation_id="a" * 64,
            artifact="report",
            public_key=self.signer.public_key().public_bytes_raw(),
            key_id="fixture-operator",
            app_id="fixture-app",
            task_id="fixture-task",
            initiator="fixture-agent",
            expires_at=self.now + 3600,
            dependencies={"input": hashlib.sha256(b"fixture source").hexdigest()},
            clock=lambda: self.now,
        )
        self.dispatch = example.make_dispatch(self.gate)

    def approve(self) -> None:
        message = decision_message(self.gate.request(), decision="approve", issued_at=self.now)
        self.assertTrue(
            self.gate.apply_decision(message, self.signer.sign(canonical(message)))["accepted"]
        )

    def call(self, content: str | None = None) -> dict[str, str]:
        return self.dispatch(
            example.TOOL_NAME, {"content": self.content if content is None else content}
        )

    def test_descriptor_exposes_only_content_not_host_authority(self) -> None:
        descriptor = example.tool_descriptor()
        self.assertEqual(descriptor["name"], "submit_approved_document")
        self.assertEqual(descriptor["parameters"]["properties"], {"content": {"type": "string"}})
        self.assertEqual(descriptor["parameters"]["required"], ["content"])
        self.assertFalse(descriptor["parameters"]["additionalProperties"])
        encoded = json.dumps(descriptor, sort_keys=True)
        for forbidden in (
            str(self.target.parent),
            self.gate.operation_id,
            "public_key",
            "private_key",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_without_approval_no_file(self) -> None:
        self.assertEqual(self.call(), {"outcome": "refused", "reason": "not_approved"})
        self.assertFalse(self.target.exists())

    def test_exact_signed_action_creates_one_real_file(self) -> None:
        self.approve()
        self.assertEqual(self.call(), {"outcome": "applied", "reason": "writer_receipt_recorded"})
        self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))

    def test_changed_content_refused_without_spending_approval(self) -> None:
        self.approve()
        self.assertEqual(
            self.call("Changed document."), {"outcome": "refused", "reason": "object_changed"}
        )
        self.assertFalse(self.target.exists())
        self.assertEqual(self.call()["outcome"], "applied")

    def test_repeat_refused_without_second_effect(self) -> None:
        self.approve()
        self.assertEqual(self.call()["outcome"], "applied")
        original = self.target.stat()
        self.assertEqual(self.call(), {"outcome": "refused", "reason": "already_consumed"})
        after = self.target.stat()
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_mtime_ns),
            (original.st_dev, original.st_ino, original.st_mtime_ns),
        )
        self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))

    def test_post_effect_storage_failure_is_uncertain_and_recovers_without_replay(self) -> None:
        self.approve()
        original_save = self.gate._save
        marker = "synthetic_private_path_or_key_must_not_reach_tool_result"

        def fail_outcome(state, *, kind=None, **kwargs):
            if kind == "outcome":
                raise sqlite3.OperationalError(marker)
            return original_save(state, kind=kind, **kwargs)

        with patch.object(self.gate, "_save", side_effect=fail_outcome):
            result = self.call()
        self.assertEqual(result, {"outcome": "uncertain", "reason": "host_recovery_required"})
        self.assertNotIn(marker, json.dumps(result))
        self.assertNotIn(str(self.target), json.dumps(result))
        self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))
        identity = self.target.stat()
        self.assertEqual(self.gate.status()["status"], "EXECUTING")
        with patch.object(
            WorkspaceOperation, "deliver", side_effect=AssertionError("recovery_must_not_deliver")
        ):
            recovered = self.gate.recover()
        self.assertEqual(recovered["state"], "DELIVERED_RECEIPT")
        self.assertEqual(recovered["recorded_outcome"], "EXECUTING")
        self.assertTrue(recovered["current_verified"])
        after = self.target.stat()
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_mtime_ns),
            (identity.st_dev, identity.st_ino, identity.st_mtime_ns),
        )
        self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))

    def test_extra_authority_fields_refused_before_gate(self) -> None:
        for extra in ({"path": str(self.target)}, {"approve": True}, {"key": "forged"}):
            with self.subTest(extra=tuple(extra)):
                before = self.gate.status()["control_events"]
                result = self.dispatch(example.TOOL_NAME, {"content": self.content, **extra})
                self.assertEqual(result, {"outcome": "refused", "reason": "invalid_arguments"})
                self.assertEqual(self.gate.status()["control_events"], before)
                self.assertFalse(self.target.exists())

    def test_unknown_tool_and_malformed_args_refused_before_gate(self) -> None:
        before = self.gate.status()["control_events"]
        self.assertEqual(
            self.dispatch("apply_decision", {"content": self.content}),
            {"outcome": "refused", "reason": "unknown_tool"},
        )
        for bad in (None, {}, {"content": 123}, {"content": self.content, "output": "elsewhere"}):
            with self.subTest(bad=type(bad).__name__):
                self.assertEqual(
                    self.dispatch(example.TOOL_NAME, bad),
                    {"outcome": "refused", "reason": "invalid_arguments"},
                )
        self.assertEqual(self.gate.status()["control_events"], before)
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
