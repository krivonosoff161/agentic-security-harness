"""Human-operated, local Ed25519 signer for exact ActionGate requests.

The generated public file is not trusted until the host separately enrolls it.
This utility signs decisions; it never invokes an action or grants itself access.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .protocol import ProtocolError, canonical, decision_message, request_digest, verify_decision


class OperatorError(ValueError):
    """A local signing request was refused without changing the action state."""


def _read_bounded(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        original = path.lstat()
        if (
            not stat.S_ISREG(original.st_mode)
            or original.st_nlink != 1
            or path.is_symlink()
            or getattr(original, "st_file_attributes", 0) & 0x400
        ):
            raise OperatorError("input_file_invalid")
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size > limit
                or (info.st_dev, info.st_ino) != (original.st_dev, original.st_ino)
            ):
                raise OperatorError("input_file_invalid")
            raw = os.read(fd, limit + 1)
            if len(raw) > limit or len(raw) != info.st_size:
                raise OperatorError("input_file_changed_or_oversize")
            return raw
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        if isinstance(exc, OperatorError):
            raise
        raise OperatorError("input_file_unavailable") from exc


def _create_once(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        # A partial exclusive file, if created, is retained for explicit review.
        raise OperatorError("output_create_unavailable_or_exists") from exc


def _unique_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OperatorError("request_duplicate_field")
        value[key] = item
    return value


def _reject_constant(_: str) -> None:
    raise OperatorError("request_nonfinite_number")


def _request_file(path: Path) -> dict[str, Any]:
    raw = _read_bounded(path, 32768)
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_json, parse_constant=_reject_constant
        )
        request_digest(value)  # Closed protocol schema and canonical-size validation.
    except (UnicodeError, json.JSONDecodeError, ProtocolError, TypeError) as exc:
        raise OperatorError("request_invalid") from exc
    return value


def _passphrase(prompt: str) -> bytes:
    value = getpass.getpass(prompt)
    if type(value) is not str or not 0 < len(value) <= 1024:
        raise OperatorError("passphrase_required")
    try:
        return value.encode("utf-8")
    except UnicodeError as exc:
        raise OperatorError("passphrase_invalid") from exc


def generate_keypair(private_path: Path, public_path: Path) -> dict[str, str]:
    """Create an encrypted PKCS#8 key and raw-hex public key at new paths."""
    if not isinstance(private_path, Path) or not isinstance(public_path, Path):
        raise OperatorError("key_paths_invalid")
    if os.path.normcase(os.path.abspath(private_path)) == os.path.normcase(
        os.path.abspath(public_path)
    ):
        raise OperatorError("key_paths_must_differ")
    if (
        private_path.exists()
        or private_path.is_symlink()
        or public_path.exists()
        or public_path.is_symlink()
    ):
        raise OperatorError("key_output_exists")
    first = _passphrase("New private-key passphrase: ")
    second = _passphrase("Repeat private-key passphrase: ")
    if first != second:
        raise OperatorError("passphrases_differ")
    signer = Ed25519PrivateKey.generate()
    private_pem = signer.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(first),
    )
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    _create_once(private_path, private_pem)
    _create_once(public_path, public_key.hex().encode("ascii") + b"\n")
    return {
        "public_key_fingerprint": hashlib.sha256(public_key).hexdigest(),
        "public_key_hex": public_key.hex(),
    }


def _load_signer(path: Path) -> Ed25519PrivateKey:
    raw = _read_bounded(path, 16384)
    passphrase_bytes = _passphrase("Private-key passphrase: ")
    try:
        signer = serialization.load_pem_private_key(raw, password=passphrase_bytes)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise OperatorError("private_key_invalid_or_passphrase_wrong") from exc
    if not isinstance(signer, Ed25519PrivateKey):
        raise OperatorError("private_key_not_ed25519")
    return signer


def sign_request(
    private_path: Path,
    request_path: Path,
    content_path: Path,
    decision: str,
    out_path: Path,
) -> dict[str, Any]:
    """Review exact bytes, require typed human intent, then export a detached decision."""
    if decision not in ("approve", "revoke") or type(decision) is not str:
        raise OperatorError("decision_invalid")
    request = _request_file(request_path)
    digest = request_digest(request)
    content = _read_bounded(content_path, 65536)
    binding = request["binding"]
    if (
        not content
        or len(content) != binding["payload_length"]
        or hashlib.sha256(content).hexdigest() != binding["payload_sha256"]
    ):
        raise OperatorError("content_not_exact_request")
    try:
        document = content.decode("utf-8")
    except UnicodeError as exc:
        raise OperatorError("content_not_utf8") from exc
    now = int(time.time())
    if now < 0 or now >= request["expires_at"]:
        raise OperatorError("request_expired")
    if out_path.exists() or out_path.is_symlink():
        raise OperatorError("decision_output_exists")
    # JSON escaping keeps document controls, bidi formatting, and surrogates inert.
    print("REQUEST_SHA256 " + digest)
    print("REVIEW_REQUEST_JSON " + canonical(request).decode("ascii"))
    print("REVIEW_DOCUMENT_UTF8_JSON " + json.dumps(document, ensure_ascii=True))
    phrase = f"{decision.upper()} {digest[:12]}"
    if input(f"Type {phrase} to sign this exact request: ") != phrase:
        raise OperatorError("human_confirmation_not_given")
    # The private key is not opened or decrypted until after the review prompt.
    signer = _load_signer(private_path)
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if hashlib.sha256(public_key).hexdigest() != binding["operator_key_fingerprint"]:
        raise OperatorError("operator_key_not_enrolled_for_request")
    issued_at = int(time.time())
    if issued_at < 0 or issued_at >= request["expires_at"]:
        raise OperatorError("request_expired")
    message = decision_message(request, decision=decision, issued_at=issued_at)
    signature = signer.sign(canonical(message))
    verify_decision(request, message, signature, public_key, now=issued_at)
    detached = {"message": message, "signature_base64": base64.b64encode(signature).decode("ascii")}
    _create_once(out_path, canonical(detached) + b"\n")
    return {
        "request_sha256": digest,
        "decision": decision,
        "signature_written": True,
        "output": str(out_path),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ash_action_authority.operator")
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="create encrypted Ed25519 keypair files")
    keygen.add_argument("--private", type=Path, required=True)
    keygen.add_argument("--public", type=Path, required=True)
    sign = commands.add_parser("sign", help="review and sign an exact request")
    sign.add_argument("--private", type=Path, required=True)
    sign.add_argument("--request", type=Path, required=True)
    sign.add_argument("--content", type=Path, required=True)
    sign.add_argument("--decision", choices=("approve", "revoke"), required=True)
    sign.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            result = generate_keypair(args.private, args.public)
            print("PUBLIC_KEY_HEX " + result["public_key_hex"])
            print("PUBLIC_KEY_FINGERPRINT " + result["public_key_fingerprint"])
            print("Host enrollment is a separate trusted action.")
        else:
            result = sign_request(args.private, args.request, args.content, args.decision, args.out)
            print("DETACHED_DECISION_WRITTEN " + result["request_sha256"])
        return 0
    except (OperatorError, ProtocolError) as exc:
        print("operator_refused: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
