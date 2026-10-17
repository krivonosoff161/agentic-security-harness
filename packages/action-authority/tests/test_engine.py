"""Local ActionGate checks. Fixture signatures are not operator consent."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ash_action_authority.engine import ActionGate, AuthorityError
from ash_action_authority.protocol import ProtocolError, canonical, decision_message
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentic_security_harness.workspace_operation import WorkspaceOperationError
from agentic_security_harness.workspace_writer import WorkspacePolicy


class ActionGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.output = self.base / "output"
        self.output.mkdir()
        self.state_parent = self.base / "state"
        self.state_parent.mkdir()
        self.root = self.state_parent / "operation-1"
        self.content = "Exact fixture document.\n"
        self.policy = WorkspacePolicy(
            output_dir=self.output,
            outputs=(("report", "report.md"),),
            max_bytes=65536,
            max_proposals=8,
            data_class="public",
        )
        self.signer = Ed25519PrivateKey.generate()
        self.public_key = self.signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.now = 1_800_000_000
        self.expiry = self.now + 3600
        self.configuration = {
            "content": self.content,
            "operation_id": "a" * 64,
            "artifact": "report",
            "public_key": self.public_key,
            "key_id": "fixture-operator-key",
            "app_id": "fixture-app",
            "task_id": "fixture-task",
            "initiator": "fixture-agent",
            "expires_at": self.expiry,
            "dependencies": {"input": hashlib.sha256(b"fixture source").hexdigest()},
            "clock": lambda: self.now,
        }

    def gate(self, root: Path | None = None) -> ActionGate:
        return ActionGate.create(root or self.root, self.policy, **self.configuration)

    def signed(self, gate: ActionGate, decision: str = "approve") -> tuple[dict, bytes]:
        message = decision_message(gate.request(), decision=decision, issued_at=self.now)
        return message, self.signer.sign(canonical(message))

    def approve(self, gate: ActionGate) -> tuple[dict, bytes]:
        message, signature = self.signed(gate)
        result = gate.apply_decision(message, signature)
        self.assertTrue(result["accepted"])
        return message, signature

    def test_exact_write_has_verified_recovery_without_replay(self) -> None:
        gate = self.gate()
        self.approve(gate)
        result = gate.submit(self.content)
        self.assertTrue(result["applied"])
        self.assertEqual(result["status"], "DELIVERED_RECEIPT")
        self.assertEqual((self.output / "report.md").read_bytes(), self.content.encode())
        before = gate.status()["control_events"]
        recovered = gate.recover()
        self.assertEqual(recovered["recorded_outcome"], "DELIVERED_RECEIPT")
        self.assertTrue(recovered["current_verified"])
        self.assertEqual(gate.recover()["recorded_outcome"], "DELIVERED_RECEIPT")
        self.assertEqual(gate.status()["control_events"], before)

    def test_no_approval_cannot_create_output(self) -> None:
        gate = self.gate()
        result = gate.submit(self.content)
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "not_approved")
        self.assertFalse((self.output / "report.md").exists())

    def test_changed_content_cannot_spend_approved_action(self) -> None:
        gate = self.gate()
        self.approve(gate)
        changed = gate.submit("different fixture text")
        self.assertEqual(changed["reason"], "object_changed")
        self.assertFalse((self.output / "report.md").exists())
        self.assertEqual(gate.submit(self.content)["status"], "DELIVERED_RECEIPT")

    def test_wrong_signature_cannot_approve(self) -> None:
        gate = self.gate()
        message, _ = self.signed(gate)
        impostor = Ed25519PrivateKey.generate()
        with self.assertRaises(ProtocolError):
            gate.apply_decision(message, impostor.sign(canonical(message)))
        self.assertEqual(gate.status()["status"], "PENDING_APPROVAL")
        self.assertFalse((self.output / "report.md").exists())

    def test_revoke_before_begin_consumes_epoch_and_requires_fresh_approval(self) -> None:
        gate = self.gate()
        old_message, old_signature = self.approve(gate)
        revoke_message, revoke_signature = self.signed(gate, "revoke")
        revoked = gate.apply_decision(revoke_message, revoke_signature)
        self.assertEqual(revoked["reason"], "revoked_before_begin")
        self.assertEqual(gate.submit(self.content)["reason"], "not_approved")
        with self.assertRaises(ProtocolError):
            gate.apply_decision(old_message, old_signature)
        fresh_request = gate.request()
        self.assertEqual(fresh_request["epoch"], 1)
        self.assertNotEqual(fresh_request["challenge"], old_message["challenge"])
        self.approve(gate)
        self.assertEqual(gate.submit(self.content)["status"], "DELIVERED_RECEIPT")

    def test_trusted_invalidation_blocks_old_approval(self) -> None:
        gate = self.gate()
        old_message, old_signature = self.approve(gate)
        self.assertTrue(gate.invalidate()["accepted"])
        self.assertEqual(gate.submit(self.content)["reason"], "not_approved")
        with self.assertRaises(ProtocolError):
            gate.apply_decision(old_message, old_signature)
        self.assertFalse((self.output / "report.md").exists())

    def test_expiry_and_clock_rollback_refuse_effect(self) -> None:
        gate = self.gate()
        self.approve(gate)
        self.now = self.expiry
        self.assertEqual(gate.submit(self.content)["reason"], "expired")
        self.assertFalse((self.output / "report.md").exists())
        self.now = 1_799_999_999
        with self.assertRaisesRegex(AuthorityError, "clock_regression"):
            gate.submit(self.content)

    def test_duplicate_approval_and_submit_do_not_repeat_effect(self) -> None:
        gate = self.gate()
        message, signature = self.approve(gate)
        before = gate.status()["control_events"]
        self.assertEqual(gate.apply_decision(message, signature)["reason"], "already_approved")
        self.assertEqual(gate.status()["control_events"], before)
        self.assertTrue(gate.submit(self.content)["applied"])
        self.assertEqual(gate.submit(self.content)["reason"], "already_consumed")
        self.assertEqual((self.output / "report.md").read_bytes(), self.content.encode())
        self.assertEqual(len(list(self.output.glob("report.md"))), 1)

    def test_changed_or_deleted_target_is_unknown_while_outcome_is_retained(self) -> None:
        for change in ("tamper", "delete"):
            with self.subTest(change=change):
                root = self.state_parent / f"operation-{change}"
                gate = self.gate(root)
                self.approve(gate)
                self.assertEqual(gate.submit(self.content)["status"], "DELIVERED_RECEIPT")
                target = self.output / "report.md"
                if change == "tamper":
                    target.write_bytes(b"changed after delivery")
                else:
                    target.unlink()
                observed = gate.recover()
                self.assertEqual(observed["recorded_outcome"], "DELIVERED_RECEIPT")
                self.assertFalse(observed["current_verified"])
                self.assertEqual(observed["state"], "UNKNOWN")
                self.assertEqual(gate.status()["status"], "DELIVERED_RECEIPT")
                if target.exists():
                    target.unlink()

    def test_incomplete_setup_refuses_reuse_and_guides_new_directory(self) -> None:
        with patch(
            "ash_action_authority.engine.WorkspaceOperation.create",
            side_effect=WorkspaceOperationError("synthetic_setup_failure"),
        ):
            with self.assertRaises(WorkspaceOperationError):
                self.gate()
        self.assertTrue(self.root.exists())
        with self.assertRaisesRegex(AuthorityError, "state_already_exists_use_new_directory"):
            self.gate()
        fresh = self.gate(self.state_parent / "new-operation")
        self.assertEqual(fresh.status()["status"], "PENDING_APPROVAL")

    def test_many_bad_proposals_do_not_consume_control_events(self) -> None:
        gate = self.gate()
        for _ in range(150):
            self.assertEqual(gate.submit("wrong proposed bytes")["reason"], "object_changed")
        self.assertEqual(gate.status()["control_events"], 0)
        self.approve(gate)
        self.assertTrue(gate.submit(self.content)["applied"])

    def test_open_rejects_changed_policy_content_or_key(self) -> None:
        gate = self.gate()
        self.assertEqual(gate.status()["status"], "PENDING_APPROVAL")
        changed_policy = WorkspacePolicy(
            output_dir=self.output,
            outputs=(("report", "report.md"),),
            max_bytes=65536,
            max_proposals=7,
            data_class="public",
        )
        with self.assertRaises(AuthorityError):
            ActionGate.open(self.root, changed_policy, **self.configuration)
        with self.assertRaises(AuthorityError):
            ActionGate.open(
                self.root, self.policy, **{**self.configuration, "content": "different"}
            )
        other = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        with self.assertRaises(AuthorityError):
            ActionGate.open(self.root, self.policy, **{**self.configuration, "public_key": other})

    def test_synthetic_unknown_result_does_not_retry_delivery(self) -> None:
        class SyntheticUnknownOperation:
            def __init__(self) -> None:
                self.deliveries = 0

            def authorize(self) -> object:
                return object()

            def deliver(self, permission: object) -> dict[str, str]:
                self.deliveries += 1
                return {"state": "UNKNOWN", "reason": "synthetic_ambiguous_effect"}

            def fence(self) -> dict[str, str]:
                return {"state": "UNKNOWN", "reason": "synthetic_readback_unavailable"}

        gate = self.gate()
        self.approve(gate)
        fake = SyntheticUnknownOperation()
        with patch.object(gate, "_operation", return_value=fake):
            first = gate.submit(self.content)
            self.assertEqual(first["status"], "UNKNOWN")
            self.assertEqual(gate.submit(self.content)["reason"], "already_consumed")
            self.assertEqual(gate.recover()["state"], "UNKNOWN")
        self.assertEqual(fake.deliveries, 1)
        self.assertFalse((self.output / "report.md").exists())


if __name__ == "__main__":
    unittest.main()
