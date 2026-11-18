"""Web tests pinning the sign/verify split for the PDF flow.

Why these exist: signing must never validate by itself, in UI or CLI style.
The signer downloads the file; the receiver verifies it in a separate step.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pyhanko", reason="PDF flow needs pyHanko")
pytest.importorskip("PIL.Image", reason="visible ink needs Pillow")

from app import web  # noqa: E402
from app.crypto import generate_keypair  # noqa: E402
from app.pdf_sign import ensure_sample_pdf  # noqa: E402

PASSWORD = "demo-password-for-tests-only"


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with keys/uploads redirected to a temp dir."""
    keys = tmp_path / "keys"
    keys.mkdir()
    monkeypatch.setattr(web, "KEYS_DIR", keys)
    monkeypatch.setattr(web, "UPLOAD_DIR", tmp_path / "uploads")
    generate_keypair(keys / "demo_private.pem", keys / "demo_public.pem", PASSWORD)
    web.app.config["TESTING"] = True
    return web.app.test_client()


def _ink_png(tmp_path: Path) -> Path:
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (320, 100), "white")
    ImageDraw.Draw(img).line([20, 70, 300, 30], fill="darkblue", width=3)
    path = tmp_path / "ink.png"
    img.save(path)
    return path


def test_sign_pdf_does_not_validate(client, tmp_path: Path) -> None:
    pdf = ensure_sample_pdf(tmp_path / "contract.pdf")
    ink = _ink_png(tmp_path)
    response = client.post(
        "/api/sign-pdf",
        data={
            "signer": "Alice",
            "password": PASSWORD,
            "pdffile": (open(pdf, "rb"), "contract.pdf"),
            "ink": (open(ink, "rb"), "signature.png"),
        },
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["ok"] is True
    # The split: no verdict at signing time, only a download for the receiver.
    assert "valid" not in body
    assert body["pdf_download"].endswith("_signed.pdf")


def test_verify_pdf_accepts_signed_file(client, tmp_path: Path) -> None:
    pdf = ensure_sample_pdf(tmp_path / "contract.pdf")
    ink = _ink_png(tmp_path)
    signed_name = client.post(
        "/api/sign-pdf",
        data={
            "signer": "Alice",
            "password": PASSWORD,
            "pdffile": (open(pdf, "rb"), "contract.pdf"),
            "ink": (open(ink, "rb"), "signature.png"),
        },
    ).get_json()["pdf_download"]
    download = client.get(f"/download/{signed_name}")
    assert download.status_code == 200
    signed_copy = tmp_path / "got.pdf"
    signed_copy.write_bytes(download.data)
    verdict = client.post(
        "/api/verify-pdf", data={"signedpdf": (open(signed_copy, "rb"), "got.pdf")}
    )
    assert verdict.status_code == 200
    body = verdict.get_json()
    assert body["valid"] is True
    assert body["reason"].startswith("VALID")


def test_verify_pdf_missing_file_handled(client) -> None:
    verdict = client.post("/api/verify-pdf", data={})
    body = verdict.get_json()
    assert body["ok"] is False
    assert "Choose the signed PDF" in body["error"]
