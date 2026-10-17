"""Offline native-writer parity; fixture signatures are not human consent.

The native baseline is a properly configured WorkspaceOperation, not a raw or
weakened file writer. These checks compare preserved create-only guarantees;
they do not establish novelty, competitive superiority, or native HITL parity.
"""

from __future__ import annotations

import hashlib
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ash_action_authority.engine import ActionGate
from ash_action_authority.protocol import canonical, decision_message
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentic_security_harness.workspace_operation import WorkspaceOperation, WorkspaceOperationError
from agentic_security_harness.workspace_writer import WorkspacePolicy


class NativeParityTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory(prefix="ash-native-parity-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.content = "Exact public parity document.\n"
        self.now = int(time.time())
        self.signer = Ed25519PrivateKey.generate()
        self.public_key = self.signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def pair(self, name: str):
        operation_id = hashlib.sha256(f"{name}:one-action".encode()).hexdigest()
        sides = {}
        for side in ("native", "candidate"):
            home = self.base / name / side
            output = home / "output"
            state = home / "state"
            output.mkdir(parents=True)
            state.mkdir()
            policy = WorkspacePolicy(
                output_dir=output,
                outputs=(("report", "report.md"),),
                max_bytes=65536,
                max_proposals=8,
                data_class="public",
            )
            policy.check()
            sides[side] = (output, state, policy)
        native_output, native_state, native_policy = sides["native"]
        candidate_output, candidate_state, candidate_policy = sides["candidate"]
        native = WorkspaceOperation.create(
            native_state / "operation.sqlite",
            native_policy,
            operation_id=operation_id,
            artifact="report",
            content=self.content,
            max_attempts=1,
        )
        candidate = ActionGate.create(
            candidate_state / "authority",
            candidate_policy,
            content=self.content,
            operation_id=operation_id,
            artifact="report",
            public_key=self.public_key,
            key_id="fixture-operator-key",
            app_id="fixture-app",
            task_id=name,
            initiator="fixture-agent",
            expires_at=self.now + 3600,
            clock=lambda: self.now,
        )
        request = candidate.request()
        message = decision_message(request, decision="approve", issued_at=self.now)
        signed = self.signer.sign(canonical(message))
        self.assertTrue(candidate.apply_decision(message, signed)["accepted"])
        return native, candidate, native_output, candidate_output

    @staticmethod
    def receipts(output: Path) -> tuple[Path, ...]:
        return tuple(sorted(output.glob(".ash-*-result.json")))

    def assert_exact_outputs(self, native_output: Path, candidate_output: Path) -> None:
        for output in (native_output, candidate_output):
            self.assertEqual((output / "report.md").read_bytes(), self.content.encode())
            self.assertEqual(len(self.receipts(output)), 1)

    def test_legal_exact_document_write_succeeds_on_both(self) -> None:
        native, candidate, native_output, candidate_output = self.pair("legal")
        permission = native.authorize()
        native_result = native.deliver(permission)
        candidate_result = candidate.submit(self.content)
        self.assertEqual(native_result["state"], "DELIVERED_RECEIPT")
        self.assertEqual(native_result["attempts_spent"], 1)
        self.assertTrue(candidate_result["applied"])
        self.assertEqual(candidate_result["status"], "DELIVERED_RECEIPT")
        self.assert_exact_outputs(native_output, candidate_output)
        self.assertEqual(native.fence()["reason"], "verified_retained_outcome")
        self.assertTrue(candidate.recover()["current_verified"])

    def test_foreign_target_before_delivery_is_not_overwritten_on_either(self) -> None:
        native, candidate, native_output, candidate_output = self.pair("foreign")
        permission = native.authorize()
        foreign = b"foreign pre-existing bytes"
        for output in (native_output, candidate_output):
            (output / "report.md").write_bytes(foreign)
        native_result = native.deliver(permission)
        candidate_result = candidate.submit(self.content)
        self.assertEqual(native_result["state"], "UNKNOWN")
        self.assertEqual(candidate_result["status"], "UNKNOWN")
        self.assertFalse(candidate_result["applied"])
        for output in (native_output, candidate_output):
            self.assertEqual((output / "report.md").read_bytes(), foreign)
            self.assertEqual(self.receipts(output), ())

    def test_duplicate_native_permission_and_candidate_submit_cause_one_effect(self) -> None:
        native, candidate, native_output, candidate_output = self.pair("duplicate")
        permission = native.authorize()
        self.assertEqual(native.deliver(permission)["state"], "DELIVERED_RECEIPT")
        self.assertTrue(candidate.submit(self.content)["applied"])
        before = {
            output: (
                (output / "report.md").stat().st_ino,
                (output / "report.md").stat().st_mtime_ns,
                tuple(
                    (path.name, path.stat().st_ino, path.stat().st_mtime_ns)
                    for path in self.receipts(output)
                ),
            )
            for output in (native_output, candidate_output)
        }
        repeated = native.deliver(permission)
        denied = candidate.submit(self.content)
        self.assertEqual(repeated["state"], "DELIVERED_RECEIPT")
        self.assertEqual(repeated["reason"], "verified_retained_outcome")
        self.assertEqual(repeated["attempts_spent"], 1)
        self.assertFalse(denied["applied"])
        self.assertEqual(denied["reason"], "already_consumed")
        self.assert_exact_outputs(native_output, candidate_output)
        after = {
            output: (
                (output / "report.md").stat().st_ino,
                (output / "report.md").stat().st_mtime_ns,
                tuple(
                    (path.name, path.stat().st_ino, path.stat().st_mtime_ns)
                    for path in self.receipts(output)
                ),
            )
            for output in (native_output, candidate_output)
        }
        self.assertEqual(after, before)

    def test_tamper_after_delivery_is_detected_without_rewriting_history(self) -> None:
        native, candidate, native_output, candidate_output = self.pair("tamper")
        self.assertEqual(native.deliver(native.authorize())["state"], "DELIVERED_RECEIPT")
        self.assertTrue(candidate.submit(self.content)["applied"])
        for output in (native_output, candidate_output):
            (output / "report.md").write_bytes(b"changed after delivery")
        with self.assertRaisesRegex(WorkspaceOperationError, "stored_outcome_file_mismatch"):
            native.fence()
        recovered = candidate.recover()
        self.assertEqual(recovered["state"], "UNKNOWN")
        self.assertEqual(recovered["recorded_outcome"], "DELIVERED_RECEIPT")
        self.assertFalse(recovered["current_verified"])
        self.assertEqual(candidate.status()["status"], "DELIVERED_RECEIPT")
        for output in (native_output, candidate_output):
            self.assertEqual((output / "report.md").read_bytes(), b"changed after delivery")
            self.assertEqual(len(self.receipts(output)), 1)


if __name__ == "__main__":
    unittest.main()
