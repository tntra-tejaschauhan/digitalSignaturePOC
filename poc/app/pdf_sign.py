"""PDF signing stretch goal, via pyHanko.

Why a hand-built sample PDF: the demo needs a valid one-page PDF but must not
gain a second PDF dependency just to create it. The generator below computes
byte offsets programmatically, so the cross-reference table is always correct.
"""

from __future__ import annotations

from pathlib import Path


def ensure_sample_pdf(path: str | Path) -> Path:
    """Create a minimal valid one-page PDF unless it already exists."""
    path = Path(path)
    if path.exists():
        return path
    body_text = "Demo contract for PDF signing. Alice agrees to pay Bob Rs. 10,000."
    content_stream = f"BT /F1 20 Tf 72 720 Td ({body_text}) Tj ET".encode("latin-1")
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(content_stream) + content_stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii")
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_at}\n%%EOF\n"
    ).encode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(out))
    return path


def sign_pdf_file(
    input_pdf: str | Path,
    output_pdf: str | Path,
    key_path: str | Path,
    cert_path: str | Path,
    ca_cert_path: str | Path,
    password: str,
    ink_image_path: str | Path | None = None,
    signer_name: str = "Alice",
) -> str:
    """Sign a PDF with the demo key + CA-issued certificate. Returns a summary.

    When ink_image_path is given (a hand-drawn signature PNG), the drawing is
    shown visibly on the last page, like ink on paper. The visible picture is
    for humans only: verification ignores it and checks the cryptographic
    signature, which covers the whole file including the picture.
    """
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields, signers

    # Local imports keep `import app.pdf_sign` working even before `pip install pyhanko`.
    signer = signers.SimpleSigner.load(
        str(key_path),
        str(cert_path),
        ca_chain_files=(str(ca_cert_path),),
        key_passphrase=password.encode(),
    )
    if signer is None:
        # pyHanko returns None (instead of raising) when the key password is
        # wrong. Fail with a plain message the demo can show.
        raise ValueError("Could not unlock the private key. Wrong password?")
    stamp_style = None
    field_spec: fields.SigFieldSpec = fields.SigFieldSpec("Signature1")
    if ink_image_path is not None:
        from pyhanko.pdf_utils.images import PdfImage
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.stamp import TextStampStyle

        with open(input_pdf, "rb") as probe:
            page_count = len(PdfFileReader(probe).root["/Pages"]["/Kids"])
        # Bottom area of the last page, like a paper signature block.
        field_spec = fields.SigFieldSpec(
            "Signature1", on_page=max(0, page_count - 1), box=(72, 96, 340, 190)
        )
        stamp_style = TextStampStyle(
            background=PdfImage(str(ink_image_path)),
            background_opacity=1.0,  # keep the handwriting crisp, not faded
            stamp_text=f"Signed by {signer_name}\n%(ts)s",
        )
    with open(input_pdf, "rb") as handle:
        writer = IncrementalPdfFileWriter(handle)
        fields.append_signature_field(writer, field_spec)
        meta = signers.PdfSignatureMetadata(field_name="Signature1")
        pdf_signer = signers.PdfSigner(meta, signer=signer, stamp_style=stamp_style)
        with open(output_pdf, "wb") as out:
            pdf_signer.sign_pdf(writer, output=out)
    visible = "with visible hand-drawn signature" if ink_image_path else "invisible signature"
    return f"Signed {Path(output_pdf).name} ({visible}, demo CA chain embedded)."


def validate_pdf_file(
    signed_pdf: str | Path, ca_cert_path: str | Path
) -> tuple[bool, str]:
    """Validate embedded PDF signatures against the demo CA as trust root."""
    from asn1crypto import pem as asn1_pem
    from asn1crypto import x509 as asn1_x509

    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    try:
        # asn1crypto parses DER, so unarmor the PEM wrapper first.
        _, _, ca_der = asn1_pem.unarmor(Path(ca_cert_path).read_bytes())
        ca_asn1 = asn1_x509.Certificate.load(ca_der)
        context = ValidationContext(trust_roots=[ca_asn1])
        # The reader must stay open: validation pulls bytes lazily from it.
        with open(signed_pdf, "rb") as handle:
            reader = PdfFileReader(handle)
            embedded = list(reader.embedded_signatures)
            if not embedded:
                return False, "INVALID: no embedded signatures found in this PDF."
            count = 0
            for sig in embedded:
                status = validate_pdf_signature(sig, context)
                count += 1
                if not status.valid:
                    return False, f"INVALID: PDF signature failed ({status.summary()})."
                if not status.trusted:
                    return False, "INVALID: PDF signature is intact but NOT trusted by the demo CA."
        return True, (
            f"VALID: {count} PDF signature(s) intact and trusted by the demo CA."
        )
    except FileNotFoundError:
        return False, "INVALID: signed PDF or CA file not found."
    except Exception as exc:  # noqa: BLE001 - any parse failure is an INVALID verdict
        return False, f"INVALID: could not validate this PDF ({exc})."
