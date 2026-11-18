"""Tests for the demo CA and certificate-based verification."""

from __future__ import annotations

from pathlib import Path

from app.certs import (
    describe_chain,
    ensure_demo_ca,
    issue_signer_cert,
    verify_with_cert,
)
from app.crypto import generate_keypair, sign_file

PASSWORD = "demo-password-for-tests-only"


def _signed_doc(tmp_path: Path):
    private_key = tmp_path / "alice_private.pem"
    public_key = tmp_path / "alice_public.pem"
    generate_keypair(private_key, public_key, PASSWORD)
    document = tmp_path / "contract.txt"
    document.write_text("Alice pays Bob Rs. 10,000.")
    sig = tmp_path / "contract.txt.sig"
    meta = tmp_path / "contract.txt.meta.json"
    sign_file(document, private_key, PASSWORD, "Alice", sig, meta)
    return private_key, public_key, document, sig, meta


def test_cert_chain_verify_is_valid(tmp_path: Path) -> None:
    _, public_key, document, sig, meta = _signed_doc(tmp_path)
    ca_key, ca_cert = tmp_path / "ca_key.pem", tmp_path / "ca_cert.pem"
    ensure_demo_ca(ca_key, ca_cert)
    cert = tmp_path / "alice_cert.pem"
    issue_signer_cert(ca_key, ca_cert, public_key, cert, "Alice")
    assert "Alice" in describe_chain(cert, ca_cert)
    ok, reason = verify_with_cert(document, sig, cert, ca_cert, meta)
    assert ok, reason
    assert "chain OK" in reason


def test_cert_from_another_ca_is_rejected(tmp_path: Path) -> None:
    _, public_key, document, sig, meta = _signed_doc(tmp_path)
    ensure_demo_ca(tmp_path / "ca1_key.pem", tmp_path / "ca1_cert.pem", "Demo CA 1")
    ensure_demo_ca(tmp_path / "ca2_key.pem", tmp_path / "ca2_cert.pem", "Demo CA 2")
    cert = tmp_path / "alice_cert.pem"
    issue_signer_cert(tmp_path / "ca1_key.pem", tmp_path / "ca1_cert.pem", public_key, cert, "Alice")
    # Present the cert against the WRONG CA: must fail, not crash.
    ok, reason = verify_with_cert(document, sig, cert, tmp_path / "ca2_cert.pem", meta)
    assert not ok
    assert "not issued by" in reason


def test_tampered_doc_fails_even_with_good_chain(tmp_path: Path) -> None:
    _, public_key, document, sig, meta = _signed_doc(tmp_path)
    ensure_demo_ca(tmp_path / "ca_key.pem", tmp_path / "ca_cert.pem")
    cert = tmp_path / "alice_cert.pem"
    issue_signer_cert(
        tmp_path / "ca_key.pem", tmp_path / "ca_cert.pem", public_key, cert, "Alice"
    )
    document.write_text("Alice pays Bob Rs. 90,000.")  # tamper after signing
    ok, reason = verify_with_cert(document, sig, cert, tmp_path / "ca_cert.pem", meta)
    assert not ok
    assert "Chain OK, but document check failed" in reason
