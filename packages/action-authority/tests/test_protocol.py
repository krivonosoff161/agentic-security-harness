"""Synthetic protocol fixtures; signatures here are not human operator consent."""

from __future__ import annotations

import hashlib
import unittest

from ash_action_authority.protocol import (
    DECISION_DOMAIN,
    ProtocolError,
    build_request,
    canonical,
    decision_message,
    request_digest,
    verify_decision,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _fixture() -> tuple[Ed25519PrivateKey, bytes, dict[str, object]]:
    signer = Ed25519PrivateKey.generate()
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    binding = {
        "app_id": "test-app",
        "task_id": "test-task",
        "operation_id": "test-operation",
        "initiator": "fixture-agent",
        "action": "write_text",
        "artifact": "report",
        "policy_sha256": "1" * 64,
        "source_admission_sha256": "2" * 64,
        "root_path": "C:/fixture/output",
        "root_device": "11",
        "root_inode": "12",
        "filename": "report.md",
        "payload_sha256": "3" * 64,
        "payload_length": 42,
        "dependencies": {"source": "4" * 64},
        "operator_key_fingerprint": hashlib.sha256(public_key).hexdigest(),
    }
    request = build_request(
        binding, epoch=7, challenge="5" * 64, expires_at=200, key_id="fixture-key"
    )
    return signer, public_key, request


def _signed(
    signer: Ed25519PrivateKey,
    request: dict[str, object],
    *,
    decision: str = "approve",
    issued_at: int = 100,
) -> tuple[dict[str, object], bytes]:
    message = decision_message(request, decision=decision, issued_at=issued_at)
    return message, signer.sign(canonical(message))


class ProtocolTests(unittest.TestCase):
    def test_fixture_signature_verifies_exact_decision(self) -> None:
        for decision in ("approve", "revoke"):
            with self.subTest(decision=decision):
                signer, public_key, request = _fixture()
                message, signature = _signed(signer, request, decision=decision)
                self.assertEqual(
                    verify_decision(request, message, signature, public_key, now=100), message
                )
                self.assertEqual(message["request_digest"], request_digest(request))
                self.assertEqual(message["domain"], DECISION_DOMAIN)

    def test_wrong_key_and_signature_fail(self) -> None:
        signer, public_key, request = _fixture()
        message, signature = _signed(signer, request)
        other = Ed25519PrivateKey.generate()
        other_public = other.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        with self.assertRaisesRegex(ProtocolError, "operator_key_mismatch"):
            verify_decision(request, message, signature, other_public, now=100)
        with self.assertRaisesRegex(ProtocolError, "signature_verification_failed"):
            verify_decision(request, message, other.sign(canonical(message)), public_key, now=100)

    def test_signed_message_cannot_be_tampered(self) -> None:
        signer, public_key, request = _fixture()
        message, signature = _signed(signer, request)
        for field, value in (
            ("domain", "other-decision-domain"),
            ("epoch", 8),
            ("challenge", "6" * 64),
            ("expires_at", 201),
            ("key_id", "other-key"),
            ("request_digest", "7" * 64),
            ("decision", "revoke"),
        ):
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                verify_decision(request, {**message, field: value}, signature, public_key, now=100)

    def test_request_change_invalidates_prior_signature(self) -> None:
        signer, public_key, request = _fixture()
        message, signature = _signed(signer, request)
        for changed in (
            {**request, "epoch": 8},
            {**request, "challenge": "6" * 64},
            {**request, "binding": {**request["binding"], "payload_sha256": "8" * 64}},
        ):
            with (
                self.subTest(changed=changed),
                self.assertRaisesRegex(ProtocolError, "decision_request_digest_mismatch"),
            ):
                verify_decision(changed, message, signature, public_key, now=100)

    def test_future_or_expired_decision_fails(self) -> None:
        signer, public_key, request = _fixture()
        message, signature = _signed(signer, request)
        for now in (99, 200, 201):
            with (
                self.subTest(now=now),
                self.assertRaisesRegex(ProtocolError, "decision_time_invalid"),
            ):
                verify_decision(request, message, signature, public_key, now=now)

    def test_closed_schemas_and_types(self) -> None:
        signer, public_key, request = _fixture()
        message, signature = _signed(signer, request)
        with self.assertRaisesRegex(ProtocolError, "request_fields_invalid"):
            request_digest({**request, "consent": True})
        with self.assertRaisesRegex(ProtocolError, "decision_fields_invalid"):
            verify_decision(
                request, {**message, "role": "operator"}, signature, public_key, now=100
            )
        with self.assertRaisesRegex(ProtocolError, "epoch_invalid"):
            build_request(
                request["binding"],
                epoch=True,
                challenge="5" * 64,
                expires_at=200,
                key_id="fixture-key",
            )
        with self.assertRaisesRegex(ProtocolError, "issued_at_invalid"):
            decision_message(request, decision="approve", issued_at=100.0)
        with self.assertRaisesRegex(ProtocolError, "now_invalid"):
            verify_decision(request, message, signature, public_key, now=True)
        with self.assertRaisesRegex(ProtocolError, "signature_invalid"):
            verify_decision(request, message, b"short", public_key, now=100)
        with self.assertRaisesRegex(ProtocolError, "public_key_invalid"):
            verify_decision(request, message, signature, b"short", now=100)

    def test_binding_closed_and_bounded(self) -> None:
        _, _, request = _fixture()
        binding = request["binding"]
        for changed in (
            {**binding, "unexpected": "value"},
            {**binding, "action": "delete_file"},
            {**binding, "payload_length": 42.0},
            {**binding, "payload_length": 65537},
            {**binding, "app_id": "bad\nname"},
            {**binding, "app_id": "bad\u202ename"},
            {**binding, "filename": "bad\ud800name"},
            {**binding, "dependencies": {"source": "not-a-digest"}},
        ):
            with self.subTest(changed=changed), self.assertRaises(ProtocolError):
                build_request(
                    changed, epoch=7, challenge="5" * 64, expires_at=200, key_id="fixture-key"
                )

    def test_file_id_is_canonical_unsigned_decimal_up_to_128_bits(self) -> None:
        _, _, request = _fixture()
        binding = request["binding"]
        huge = str(2**128 - 1)
        accepted = build_request(
            {**binding, "root_device": "0", "root_inode": huge},
            epoch=7,
            challenge="5" * 64,
            expires_at=200,
            key_id="fixture-key",
        )
        self.assertEqual(accepted["binding"]["root_inode"], huge)
        for bad in (12, 12.0, "", "00", "012", "+12", "-1", str(2**128)):
            with self.subTest(bad=bad), self.assertRaisesRegex(ProtocolError, "root_inode_invalid"):
                build_request(
                    {**binding, "root_inode": bad},
                    epoch=7,
                    challenge="5" * 64,
                    expires_at=200,
                    key_id="fixture-key",
                )

    def test_canonical_rejects_unbounded_or_ambiguous_types(self) -> None:
        for value in (True, 1.0, 2**53 + 1, {"nested": ["list"]}, {"x": "\x00"}):
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                canonical(value)


if __name__ == "__main__":
    unittest.main()
