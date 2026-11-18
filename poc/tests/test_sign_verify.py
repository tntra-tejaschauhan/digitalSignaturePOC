"""Tests for the demo crypto module.

Each test mirrors one live-demo moment, so a green suite means the manager
demo has no surprises.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.crypto import (
    ALGORITHM,
    generate_keypair,
    hash_file,
    sign_file,
    verify_file,
)

PASSWORD = "demo-password-for-tests-only"


@pytest.fixture()
def signed_bundle(tmp_path: Path) -> dict[str, Path]:
    """A complete valid bundle: keys, document, signature, metadata."""
    private_key = tmp_path / "alice_private.pem"
    public_key = tmp_path / "alice_public.pem"
    generate_keypair(private_key, public_key, PASSWORD)
    document = tmp_path / "contract.txt"
    document.write_text("Alice pays Bob Rs. 10,000.")
    sig = tmp_path / "contract.txt.sig"
    meta = tmp_path / "contract.txt.meta.json"
    sign_file(document, private_key, PASSWORD, "Alice", sig, meta)
    return {
        "private": private_key,
        "public": public_key,
        "doc": document,
        "sig": sig,
        "meta": meta,
    }


def test_sign_then_verify_is_valid(signed_bundle: dict[str, Path]) -> None:
    ok, reason = verify_file(
        signed_bundle["doc"],
        signed_bundle["sig"],
        signed_bundle["public"],
        signed_bundle["meta"],
    )
    assert ok, reason
    assert reason.startswith("VALID")
    metadata = json.loads(signed_bundle["meta"].read_text())
    assert metadata["algorithm"] == ALGORITHM
    assert metadata["file_hash"] == hash_file(signed_bundle["doc"])


def test_modified_file_is_invalid(signed_bundle: dict[str, Path]) -> None:
    # Flip one byte: amount 10,000 -> 90,000. Smallest possible tamper.
    text = signed_bundle["doc"].read_text().replace("10,000", "90,000")
    signed_bundle["doc"].write_text(text)
    ok, reason = verify_file(
        signed_bundle["doc"],
        signed_bundle["sig"],
        signed_bundle["public"],
        signed_bundle["meta"],
    )
    assert not ok
    assert "changed after signing" in reason


def test_wrong_public_key_is_invalid(signed_bundle: dict[str, Path], tmp_path: Path) -> None:
    other_private = tmp_path / "mallory_private.pem"
    other_public = tmp_path / "mallory_public.pem"
    generate_keypair(other_private, other_public, PASSWORD)
    # Verify without metadata so the check reaches the cryptographic step:
    # the signature is real, but this key did not make it.
    ok, reason = verify_file(signed_bundle["doc"], signed_bundle["sig"], other_public)
    assert not ok
    assert "signature check failed" in reason


def test_corrupted_signature_is_invalid(signed_bundle: dict[str, Path]) -> None:
    raw = bytearray(signed_bundle["sig"].read_bytes())
    raw[10] ^= 0xFF  # corrupt one byte, keep the length valid
    signed_bundle["sig"].write_bytes(bytes(raw))
    ok, reason = verify_file(
        signed_bundle["doc"], signed_bundle["sig"], signed_bundle["public"]
    )
    assert not ok
    assert "INVALID" in reason


def test_truncated_signature_reports_corruption(signed_bundle: dict[str, Path]) -> None:
    signed_bundle["sig"].write_bytes(b"too-short")
    ok, reason = verify_file(
        signed_bundle["doc"], signed_bundle["sig"], signed_bundle["public"]
    )
    assert not ok
    assert "corrupted" in reason


def test_wrong_algorithm_handled_gracefully(signed_bundle: dict[str, Path]) -> None:
    metadata = json.loads(signed_bundle["meta"].read_text())
    metadata["algorithm"] = "MD5-RSA-v1.5"  # ancient, broken, unsupported here
    signed_bundle["meta"].write_text(json.dumps(metadata))
    ok, reason = verify_file(
        signed_bundle["doc"],
        signed_bundle["sig"],
        signed_bundle["public"],
        signed_bundle["meta"],
    )
    assert not ok
    assert "unsupported algorithm" in reason


def test_missing_files_handled_gracefully(signed_bundle: dict[str, Path]) -> None:
    ok, reason = verify_file(
        signed_bundle["doc"], tmp_path_missing(signed_bundle), signed_bundle["public"]
    )
    assert not ok
    assert "missing or unreadable" in reason


def tmp_path_missing(bundle: dict[str, Path]) -> Path:
    return bundle["doc"].parent / "does-not-exist.sig"


def test_empty_password_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="password is required"):
        generate_keypair(tmp_path / "a.pem", tmp_path / "b.pem", "")
