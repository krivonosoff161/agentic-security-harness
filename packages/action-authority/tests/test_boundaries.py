"""Fresh offline boundary fixtures; fixture signatures are not owner consent."""

from __future__ import annotations

import hashlib
import sqlite3
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ash_action_authority.engine import ActionGate, AuthorityError
from ash_action_authority.protocol import canonical, decision_message
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentic_security_harness.companion_contracts import build_coverage_expectation_profile_v1
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.models import DataEnvelope
from agentic_security_harness.workspace_admission import WorkspaceSource, WorkspaceSources
from agentic_security_harness.workspace_capture import capture_workspace_sources
from agentic_security_harness.workspace_operation import WorkspaceOperation
from agentic_security_harness.workspace_writer import WorkspacePolicy


class BoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory(prefix="ash-boundaries-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.now = int(time.time())
        self.content = "Exact public fixture document.\n"
        self.signer = Ed25519PrivateKey.generate()
        self.public_key = self.signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def fixture(self, name: str, *, with_admission: bool = False):
        case = self.base / name
        case.mkdir()
        output = case / "output"
        output.mkdir()
        state_parent = case / "state"
        state_parent.mkdir()
        operation_id = hashlib.sha256(name.encode("ascii")).hexdigest()
        policy = WorkspacePolicy(
            output_dir=output,
            outputs=(("report", "report.md"),),
            max_bytes=65536,
            max_proposals=8,
            data_class="public",
        )
        admission = None
        if with_admission:
            source = b"public input for one fixture document"
            envelope = DataEnvelope(
                data_class="public",
                allowed_recipients=["local-model"],
                allowed_purpose=["document-generation"],
                can_store=True,
                can_forward=True,
                ttl_seconds=None,
                requires_confirmation=False,
                classification_source="host",
                classification_mutable=False,
            )
            restrictions = DocumentSourceRestrictions.bind(
                source,
                envelope,
                created_at=datetime.now(UTC) - timedelta(seconds=2),
            )
            sources = WorkspaceSources.bind(
                (
                    WorkspaceSource(
                        "input",
                        "public-input",
                        source,
                        restrictions,
                    ),
                )
            )
            policy = sources.bind_policy(policy)
            profile = build_coverage_expectation_profile_v1(
                project_id="agentic-security-harness",
                repository_id="krivonosoff161/agentic-security-harness",
                repository_sha="a" * 40,
                expected_channels=("input",),
                expected_event_count=1,
                expectation_source_sha256=hashlib.sha256(b"one public fixture input").hexdigest(),
            )
            admission = capture_workspace_sources(
                case / "history.db",
                case / "history.witness",
                sources=sources,
                policy=policy,
                expected_profile=profile,
                logical_operation_id=operation_id,
            ).admission
        configuration = {
            "content": self.content,
            "operation_id": operation_id,
            "artifact": "report",
            "public_key": self.public_key,
            "key_id": "fixture-operator-key",
            "app_id": "fixture-app",
            "task_id": name,
            "initiator": "fixture-agent",
            "expires_at": self.now + 3600,
            "admission": admission,
            "clock": lambda: self.now,
        }
        gate = ActionGate.create(state_parent / "operation", policy, **configuration)
        return gate, policy, configuration, case

    def decide(self, gate: ActionGate, choice: str) -> dict:
        message = decision_message(gate.request(), decision=choice, issued_at=self.now)
        return gate.apply_decision(message, self.signer.sign(canonical(message)))

    def test_captured_public_source_admission_allows_actual_exact_write(self) -> None:
        gate, policy, configuration, case = self.fixture("admitted", with_admission=True)
        self.assertIsNotNone(configuration["admission"])
        self.assertEqual(
            configuration["admission"]
            .verify(
                operation_id=configuration["operation_id"],
                policy=policy,
            )
            .completion,
            "complete",
        )
        self.assertTrue(self.decide(gate, "approve")["accepted"])
        result = gate.submit(self.content)
        self.assertTrue(result["applied"])
        self.assertEqual(result["status"], "DELIVERED_RECEIPT")
        self.assertEqual((case / "output" / "report.md").read_bytes(), self.content.encode())

    def test_corrupted_owned_history_after_approval_prevents_effect_and_replay(self) -> None:
        gate, _, _, case = self.fixture("corrupt-history", with_admission=True)
        self.assertTrue(self.decide(gate, "approve")["accepted"])
        # Only this newly created temporary fixture's history is modified.
        (case / "history.db").write_bytes(b"corrupted owned fixture history")
        result = gate.submit(self.content)
        self.assertFalse(result["applied"])
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse((case / "output" / "report.md").exists())
        self.assertEqual(gate.submit(self.content)["reason"], "already_consumed")
        with patch.object(
            WorkspaceOperation, "deliver", side_effect=AssertionError("recovery must not deliver")
        ):
            recovered = gate.recover()
        self.assertEqual(recovered["state"], "FENCED_ABSENT")
        self.assertTrue(recovered["current_verified"])
        self.assertFalse((case / "output" / "report.md").exists())

    def test_post_effect_outer_sql_failure_recovers_without_second_delivery(self) -> None:
        gate, policy, configuration, case = self.fixture("post-effect-sql")
        self.assertTrue(self.decide(gate, "approve")["accepted"])
        original_save = gate._save

        def fail_outcome(state, *, kind=None, **kwargs):
            if kind == "outcome":
                raise sqlite3.OperationalError("synthetic_outer_outcome_commit_failure")
            return original_save(state, kind=kind, **kwargs)

        with patch.object(gate, "_save", side_effect=fail_outcome):
            with self.assertRaisesRegex(
                sqlite3.OperationalError, "synthetic_outer_outcome_commit_failure"
            ):
                gate.submit(self.content)
        target = case / "output" / "report.md"
        self.assertEqual(target.read_bytes(), self.content.encode())
        reopened = ActionGate.open(gate.root, policy, **configuration)
        self.assertEqual(reopened.status()["status"], "EXECUTING")
        with patch.object(
            WorkspaceOperation, "deliver", side_effect=AssertionError("recovery must not deliver")
        ):
            recovered = reopened.recover()
        self.assertEqual(recovered["state"], "DELIVERED_RECEIPT")
        self.assertEqual(recovered["recorded_outcome"], "EXECUTING")
        self.assertTrue(recovered["current_verified"])
        self.assertEqual(reopened.status()["status"], "DELIVERED_RECEIPT")
        self.assertEqual(target.read_bytes(), self.content.encode())

    def test_authenticated_controls_revoke_near_full_and_refuse_before_effect(self) -> None:
        gate, _, _, case = self.fixture("control-capacity")
        # 62 signed approve/revoke pairs produce exactly 124 control events.
        for _ in range(62):
            self.assertTrue(self.decide(gate, "approve")["accepted"])
            self.assertTrue(self.decide(gate, "revoke")["accepted"])
        self.assertEqual(gate.status()["control_events"], 124)
        self.assertTrue(self.decide(gate, "approve")["accepted"])
        self.assertEqual(gate.status()["control_events"], 125)
        self.assertTrue(self.decide(gate, "revoke")["accepted"])
        self.assertEqual(gate.status()["control_events"], 126)
        with self.assertRaisesRegex(AuthorityError, "control_capacity_before_effect"):
            self.decide(gate, "approve")
        self.assertEqual(gate.status()["control_events"], 126)
        self.assertEqual(gate.submit(self.content)["reason"], "not_approved")
        self.assertFalse((case / "output" / "report.md").exists())


if __name__ == "__main__":
    unittest.main()
