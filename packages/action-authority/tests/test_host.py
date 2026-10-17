"""Persisted public-document host checks using only synthetic operator keys."""

from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ash_action_authority.engine import AuthorityError
from ash_action_authority.host import _restore, apply, setup
from ash_action_authority.operator import generate_keypair, sign_request
from ash_action_authority.protocol import request_digest


class PublicDocumentHostTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "new-host-home"
        self.private = self.root / "synthetic-operator.pem"
        self.public = self.root / "synthetic-operator.hex"
        self.passphrase = "synthetic-test-passphrase"
        with patch(
            "ash_action_authority.operator.getpass.getpass",
            side_effect=[self.passphrase, self.passphrase],
        ):
            generate_keypair(self.private, self.public)
        self.source = self.root / "owned-public-source.txt"
        self.proposal = self.root / "proposed-document.txt"
        self.source.write_bytes(b"Host-declared public source.\n")
        self.document = b"Proposed public document from declared source.\n"
        self.proposal.write_bytes(self.document)

    def _setup(self) -> None:
        result = setup(
            self.home,
            self.public,
            self.source,
            self.proposal,
            host_revision="a" * 40,
            valid_seconds=3600,
            allow_local_source_use=True,
        )
        self.assertEqual(result["state"], "PENDING_APPROVAL")
        self.assertFalse(result["effect_created"])
        self.assertFalse((self.home / "output" / "document.md").exists())

    def _approve(self) -> Path:
        request = _restore(self.home).request()
        self.assertEqual(request, json.loads((self.home / "request.json").read_text("ascii")))
        phrase = f"APPROVE {request_digest(request)[:12]}"
        detached = self.root / "synthetic-approval.json"
        with (
            patch("builtins.input", return_value=phrase),
            patch("ash_action_authority.operator.getpass.getpass", return_value=self.passphrase),
            redirect_stdout(StringIO()),
        ):
            sign_request(
                self.private,
                self.home / "request.json",
                self.home / "document.txt",
                "approve",
                detached,
            )
        return detached

    def test_persisted_approval_actual_write_and_verified_recovery(self) -> None:
        self._setup()
        detached = self._approve()
        approved = apply(self.home, detached)
        self.assertTrue(approved["accepted"])
        self.assertEqual(approved["reason"], "approved_exact_action")
        before = _restore(self.home).status()["control_events"]
        duplicate = apply(self.home, detached)
        self.assertTrue(duplicate["accepted"])
        self.assertEqual(duplicate["reason"], "already_approved")
        self.assertEqual(_restore(self.home).status()["control_events"], before)
        self.assertFalse((self.home / "output" / "document.md").exists())
        reopened = _restore(self.home)
        self.assertEqual(reopened.status()["status"], "APPROVED")
        delivered = reopened.submit(self.document.decode("utf-8"))
        self.assertTrue(delivered["applied"])
        self.assertEqual(delivered["status"], "DELIVERED_RECEIPT")
        target = self.home / "output" / "document.md"
        self.assertEqual(target.read_bytes(), self.document)
        recovered = _restore(self.home).recover()
        self.assertEqual(recovered["recorded_outcome"], "DELIVERED_RECEIPT")
        self.assertTrue(recovered["current_verified"])
        repeated = _restore(self.home).submit(self.document.decode("utf-8"))
        self.assertFalse(repeated["applied"])
        self.assertEqual(repeated["reason"], "already_consumed")
        self.assertEqual(target.read_bytes(), self.document)

    def test_source_use_requires_explicit_host_decision_before_setup(self) -> None:
        with self.assertRaisesRegex(AuthorityError, "host_must_authorize_local_public_source_use"):
            setup(self.home, self.public, self.source, self.proposal, host_revision="a" * 40)
        self.assertFalse(self.home.exists())

    def test_changed_retained_document_refuses_approval(self) -> None:
        self._setup()
        detached = self._approve()
        (self.home / "document.txt").write_bytes(b"Changed retained document.\n")
        with self.assertRaisesRegex(AuthorityError, "retained_input_changed"):
            apply(self.home, detached)
        self.assertFalse((self.home / "output" / "document.md").exists())

    def test_changed_retained_source_refuses_run(self) -> None:
        self._setup()
        detached = self._approve()
        self.assertTrue(apply(self.home, detached)["accepted"])
        (self.home / "source.txt").write_bytes(b"Changed retained source.\n")
        with self.assertRaisesRegex(AuthorityError, "retained_input_changed"):
            _restore(self.home).submit(self.document.decode("utf-8"))
        self.assertFalse((self.home / "output" / "document.md").exists())

    def test_corrupt_owned_history_blocks_authorize_but_allows_fencing(self) -> None:
        self._setup()
        detached = self._approve()
        self.assertTrue(apply(self.home, detached)["accepted"])
        (self.home / "history.witness").write_bytes(b"corrupted test witness\n")
        gate = _restore(self.home)
        refused = gate.submit(self.document.decode("utf-8"))
        self.assertFalse(refused["applied"])
        self.assertEqual(refused["status"], "UNKNOWN")
        self.assertFalse((self.home / "output" / "document.md").exists())
        fenced = _restore(self.home).recover()
        self.assertEqual(fenced["recorded_outcome"], "UNKNOWN")
        self.assertEqual(fenced["state"], "FENCED_ABSENT")
        self.assertTrue(fenced["current_verified"])
        self.assertFalse((self.home / "output" / "document.md").exists())

    def test_recovery_of_existing_receipt_does_not_require_fresh_source_admission(self) -> None:
        self._setup()
        detached = self._approve()
        self.assertTrue(apply(self.home, detached)["accepted"])
        self.assertTrue(_restore(self.home).submit(self.document.decode("utf-8"))["applied"])
        expires_at = json.loads((self.home / "host.json").read_text("ascii"))["expires_at"]

        class ExpiredAdmissionClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return cls.fromtimestamp(expires_at + 1, tz or UTC)

        with patch("agentic_security_harness.workspace_admission.datetime", ExpiredAdmissionClock):
            recovered = _restore(self.home).recover()
        self.assertEqual(recovered["recorded_outcome"], "DELIVERED_RECEIPT")
        self.assertTrue(recovered["current_verified"])
        self.assertEqual((self.home / "output" / "document.md").read_bytes(), self.document)


if __name__ == "__main__":
    unittest.main()
