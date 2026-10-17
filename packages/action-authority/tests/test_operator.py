"""Synthetic signer utility checks; fixture signatures are not owner consent."""

from __future__ import annotations

import base64
import hashlib
import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ash_action_authority.operator import OperatorError, generate_keypair, sign_request
from ash_action_authority.protocol import build_request, canonical, request_digest, verify_decision


class OperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.private = self.root / "fixture-private.pem"
        self.public = self.root / "fixture-public.hex"
        self.password = "fixture-passphrase-only"
        with patch(
            "ash_action_authority.operator.getpass.getpass",
            side_effect=[self.password, self.password],
        ):
            self.key_info = generate_keypair(self.private, self.public)
        self.public_bytes = bytes.fromhex(self.public.read_text(encoding="ascii").strip())
        self.now = 1_800_000_000
        self.expiry = self.now + 3600
        self.content = "Exact fixture text \x1b[31m\n"
        self.content_path = self.root / "document.txt"
        self.content_path.write_bytes(self.content.encode("utf-8"))
        binding = {
            "app_id": "fixture-app",
            "task_id": "fixture-task",
            "operation_id": "fixture-operation",
            "initiator": "fixture-agent",
            "action": "write_text",
            "artifact": "report",
            "policy_sha256": "1" * 64,
            "source_admission_sha256": None,
            "root_path": str(self.root / "output"),
            "root_device": "1",
            "root_inode": "2",
            "filename": "report.md",
            "payload_sha256": hashlib.sha256(self.content.encode("utf-8")).hexdigest(),
            "payload_length": len(self.content.encode("utf-8")),
            "dependencies": {"fixture-source": "2" * 64},
            "operator_key_fingerprint": self.key_info["public_key_fingerprint"],
        }
        self.request = build_request(
            binding, epoch=0, challenge="3" * 64, expires_at=self.expiry, key_id="fixture-key"
        )
        self.request_path = self.root / "request.json"
        self.request_path.write_bytes(canonical(self.request) + b"\n")
        self.out = self.root / "decision.json"

    def _sign(self, decision: str = "approve") -> tuple[dict, str]:
        digest = request_digest(self.request)
        phrase = f"{decision.upper()} {digest[:12]}"
        displayed = StringIO()
        with (
            patch("ash_action_authority.operator.time.time", return_value=self.now),
            patch("builtins.input", return_value=phrase),
            patch("ash_action_authority.operator.getpass.getpass", return_value=self.password),
            redirect_stdout(displayed),
        ):
            result = sign_request(
                self.private, self.request_path, self.content_path, decision, self.out
            )
        return result, displayed.getvalue()

    def test_keygen_encrypts_private_key_and_creates_only_new_paths(self) -> None:
        self.assertIn(b"ENCRYPTED PRIVATE KEY", self.private.read_bytes())
        self.assertEqual(len(self.public_bytes), 32)
        self.assertEqual(
            hashlib.sha256(self.public_bytes).hexdigest(), self.key_info["public_key_fingerprint"]
        )
        old_private = self.private.read_bytes()
        with patch("ash_action_authority.operator.getpass.getpass") as prompt:
            with self.assertRaisesRegex(OperatorError, "key_output_exists"):
                generate_keypair(self.private, self.public)
            prompt.assert_not_called()
        self.assertEqual(self.private.read_bytes(), old_private)

    def test_approval_reviews_escaped_exact_bytes_and_exports_verified_detached_decision(
        self,
    ) -> None:
        result, shown = self._sign()
        self.assertTrue(result["signature_written"])
        self.assertIn("REVIEW_REQUEST_JSON ", shown)
        self.assertIn("REVIEW_DOCUMENT_UTF8_JSON ", shown)
        self.assertIn("\\u001b", shown)
        self.assertNotIn("\x1b", shown)
        detached = json.loads(self.out.read_text(encoding="ascii"))
        self.assertEqual(set(detached), {"message", "signature_base64"})
        signature = base64.b64decode(detached["signature_base64"], validate=True)
        self.assertEqual(
            verify_decision(
                self.request, detached["message"], signature, self.public_bytes, now=self.now
            )["decision"],
            "approve",
        )

    def test_revoke_uses_explicit_human_word_and_signed_request(self) -> None:
        self._sign("revoke")
        detached = json.loads(self.out.read_text(encoding="ascii"))
        signature = base64.b64decode(detached["signature_base64"], validate=True)
        self.assertEqual(
            verify_decision(
                self.request, detached["message"], signature, self.public_bytes, now=self.now
            )["decision"],
            "revoke",
        )

    def test_wrong_document_bytes_refuse_before_confirmation_or_key_read(self) -> None:
        self.content_path.write_bytes(b"different document")
        with patch("builtins.input") as confirmation:
            with patch("ash_action_authority.operator.getpass.getpass") as password:
                with self.assertRaisesRegex(OperatorError, "content_not_exact_request"):
                    sign_request(
                        self.private, self.request_path, self.content_path, "approve", self.out
                    )
                confirmation.assert_not_called()
                password.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_cancel_refuses_before_private_key_read(self) -> None:
        with (
            patch("ash_action_authority.operator.time.time", return_value=self.now),
            patch("builtins.input", return_value="NO"),
            patch("ash_action_authority.operator.getpass.getpass") as password,
            redirect_stdout(StringIO()),
        ):
            with self.assertRaisesRegex(OperatorError, "human_confirmation_not_given"):
                sign_request(
                    self.private, self.request_path, self.content_path, "approve", self.out
                )
            password.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_different_key_cannot_sign_host_bound_request(self) -> None:
        other_private = self.root / "other-private.pem"
        other_public = self.root / "other-public.hex"
        with patch(
            "ash_action_authority.operator.getpass.getpass",
            side_effect=[self.password, self.password],
        ):
            generate_keypair(other_private, other_public)
        phrase = "APPROVE " + request_digest(self.request)[:12]
        with (
            patch("ash_action_authority.operator.time.time", return_value=self.now),
            patch("builtins.input", return_value=phrase),
            patch("ash_action_authority.operator.getpass.getpass", return_value=self.password),
            redirect_stdout(StringIO()),
        ):
            with self.assertRaisesRegex(OperatorError, "operator_key_not_enrolled_for_request"):
                sign_request(
                    other_private, self.request_path, self.content_path, "approve", self.out
                )
        self.assertFalse(self.out.exists())

    def test_expired_request_refuses_before_confirmation(self) -> None:
        with (
            patch("ash_action_authority.operator.time.time", return_value=self.expiry),
            patch("builtins.input") as confirmation,
        ):
            with self.assertRaisesRegex(OperatorError, "request_expired"):
                sign_request(
                    self.private, self.request_path, self.content_path, "approve", self.out
                )
            confirmation.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_existing_output_is_not_overwritten(self) -> None:
        self.out.write_bytes(b"preexisting detached decision")
        with (
            patch("ash_action_authority.operator.time.time", return_value=self.now),
            patch("builtins.input") as confirmation,
        ):
            with self.assertRaisesRegex(OperatorError, "decision_output_exists"):
                sign_request(
                    self.private, self.request_path, self.content_path, "approve", self.out
                )
            confirmation.assert_not_called()
        self.assertEqual(self.out.read_bytes(), b"preexisting detached decision")


if __name__ == "__main__":
    unittest.main()
