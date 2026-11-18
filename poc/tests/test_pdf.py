"""Tests for the PDF signing stretch goal."""

from __future__ import annotations

from pathlib import Path

import pytest

pyhanko = pytest.importorskip("pyhanko", reason="PDF stretch goal needs pyHanko")

from app.certs import ensure_demo_ca, issue_signer_cert  # noqa: E402
from app.crypto import generate_keypair  # noqa: E402
from app.pdf_sign import ensure_sample_pdf, sign_pdf_file, validate_pdf_file  # noqa: E402

PASSWORD = "demo-password-for-tests-only"


@pytest.fixture()
def pdf_bundle(tmp_path: Path) -> dict[str, Path]:
    private_key = tmp_path / "alice_private.pem"
    public_key = tmp_path / "alice_public.pem"
    generate_keypair(private_key, public_key, PASSWORD)
    ca_key, ca_cert = tmp_path / "ca_key.pem", tmp_path / "ca_cert.pem"
    ensure_demo_ca(ca_key, ca_cert)
    cert = tmp_path / "alice_cert.pem"
    issue_signer_cert(ca_key, ca_cert, public_key, cert, "Alice")
    original = ensure_sample_pdf(tmp_path / "contract.pdf")
    return {
        "private": private_key,
        "cert": cert,
        "ca": ca_cert,
        "original": original,
        "signed": tmp_path / "contract-signed.pdf",
    }


def test_sign_then_validate_pdf_is_valid(pdf_bundle: dict[str, Path]) -> None:
    summary = sign_pdf_file(
        pdf_bundle["original"],
        pdf_bundle["signed"],
        pdf_bundle["private"],
        pdf_bundle["cert"],
        pdf_bundle["ca"],
        PASSWORD,
    )
    assert "Signed" in summary
    ok, reason = validate_pdf_file(pdf_bundle["signed"], pdf_bundle["ca"])
    assert ok, reason
    assert reason.startswith("VALID")


def _fake_handwriting(path: Path) -> Path:
    """Draw a scribble PNG like the browser pad would send."""
    pil_image = pytest.importorskip("PIL.Image", reason="visible ink needs Pillow")
    pil_draw = pytest.importorskip("PIL.ImageDraw", reason="visible ink needs Pillow")
    img = pil_image.new("RGB", (320, 100), "white")
    draw = pil_draw.Draw(img)
    draw.arc([20, 10, 150, 90], start=200, end=340, fill="darkblue", width=3)
    draw.line([140, 70, 300, 30], fill="darkblue", width=3)
    draw.arc([210, 20, 300, 90], start=100, end=260, fill="darkblue", width=2)
    img.save(path)
    return path


def test_visible_ink_pdf_is_valid(pdf_bundle: dict[str, Path], tmp_path: Path) -> None:
    ink = _fake_handwriting(tmp_path / "ink.png")
    summary = sign_pdf_file(
        pdf_bundle["original"],
        pdf_bundle["signed"],
        pdf_bundle["private"],
        pdf_bundle["cert"],
        pdf_bundle["ca"],
        PASSWORD,
        ink,
        "Alice",
    )
    assert "visible hand-drawn" in summary
    ok, reason = validate_pdf_file(pdf_bundle["signed"], pdf_bundle["ca"])
    assert ok, reason
    assert reason.startswith("VALID")


def test_tampered_pdf_is_invalid(pdf_bundle: dict[str, Path]) -> None:
    sign_pdf_file(
        pdf_bundle["original"],
        pdf_bundle["signed"],
        pdf_bundle["private"],
        pdf_bundle["cert"],
        pdf_bundle["ca"],
        PASSWORD,
    )
    raw = bytearray(pdf_bundle["signed"].read_bytes())
    # Tamper inside the original page text, which the signature covers.
    # (The middle of the file is the signature blob itself, which is unsigned.)
    at = raw.find(b"Demo contract")
    assert at != -1
    raw[at] ^= 0x01
    pdf_bundle["signed"].write_bytes(bytes(raw))
    ok, reason = validate_pdf_file(pdf_bundle["signed"], pdf_bundle["ca"])
    assert not ok
    assert "INVALID" in reason
