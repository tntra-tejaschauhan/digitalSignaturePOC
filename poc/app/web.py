"""Flask web UI for the live manager demo.

Why Flask with server-rendered page + JSON API: one process, no build step, and
the exact same crypto functions as the CLI, so the browser demo can never
disagree with the terminal demo.
"""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

from .certs import ensure_demo_ca, issue_signer_cert
from .crypto import (
    ALGORITHM,
    generate_keypair,
    hash_file,
    sign_file,
    signature_preview,
    verify_file,
)
from .pdf_sign import ensure_sample_pdf, sign_pdf_file, validate_pdf_file

HERE = Path(__file__).resolve().parent
POC_ROOT = HERE.parent
KEYS_DIR = POC_ROOT / "keys"
UPLOAD_DIR = POC_ROOT / "web_uploads"  # demo scratch space, gitignored

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB cap for demo uploads


def _demo_private_key() -> Path:
    return KEYS_DIR / "demo_private.pem"


def _demo_public_key() -> Path:
    return KEYS_DIR / "demo_public.pem"


def _save_upload(storage, suffix: str = "") -> Path:
    """Save an uploaded file under a random name.

    Why random names: two managers signing "contract.pdf" at the same demo must
    not overwrite each other.
    """
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    name = f"{uuid.uuid4().hex[:8]}_{secure_filename(storage.filename or 'file')}{suffix}"
    path = UPLOAD_DIR / name
    storage.save(path)
    return path


@app.get("/")
def index():
    return render_template("index.html", algorithm=ALGORITHM)


@app.post("/api/keygen")
def api_keygen():
    password = (request.form.get("password") or "").strip()
    steps = ["1. Creating RSA-3072 key pair..."]
    if not password:
        return jsonify(ok=False, steps=steps, error="A password is required."), 400
    try:
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        generate_keypair(_demo_private_key(), _demo_public_key(), password)
    except ValueError as exc:
        return jsonify(ok=False, steps=steps, error=str(exc)), 400
    steps.append("2. Private key saved (password-protected PEM).")
    steps.append("3. Public key saved. Ready to sign.")
    return jsonify(ok=True, steps=steps)


@app.post("/api/sign")
def api_sign():
    upload = request.files.get("file")
    signer = (request.form.get("signer") or "Alice").strip()
    password = request.form.get("password") or ""
    steps = ["1. Receiving document..."]
    if upload is None or not upload.filename:
        return jsonify(ok=False, steps=steps, error="Choose a file first."), 400
    if not _demo_private_key().exists():
        return jsonify(ok=False, steps=steps, error="Generate demo keys first (tab 1)."), 400
    try:
        doc_path = _save_upload(upload)
        steps.append(f"2. Hashing with SHA-256 (fingerprint {hash_file(doc_path)[:24]}...).")
        steps.append("3. Signing hash with the private key...")
        sig_path = doc_path.with_suffix(doc_path.suffix + ".sig")
        meta_path = doc_path.with_suffix(doc_path.suffix + ".meta.json")
        metadata = sign_file(doc_path, _demo_private_key(), password, signer, sig_path, meta_path)
    except ValueError as exc:
        # Wrong password or bad key: a plain message, not a stack trace.
        return jsonify(ok=False, steps=steps, error=str(exc)), 400
    steps.append("4. Done. Download the signature and metadata below.")
    return jsonify(
        ok=True,
        steps=steps,
        metadata=metadata,
        signature_preview=signature_preview(sig_path),
        sig_download=sig_path.name,
        meta_download=meta_path.name,
    )


def _verify_inputs():
    """Shared input handling for verify and tamper-demo (same form fields)."""
    upload = request.files.get("file")
    sig_upload = request.files.get("sig")
    if upload is None or not upload.filename:
        return None, jsonify(ok=False, steps=[], error="Choose the document file."), None
    if sig_upload is None or not sig_upload.filename:
        return None, jsonify(ok=False, steps=[], error="Choose the .sig signature file."), None
    pub_upload = request.files.get("pubkey")
    if pub_upload is not None and pub_upload.filename:
        pubkey_path: Path | None = _save_upload(pub_upload)
    elif _demo_public_key().exists():
        pubkey_path = _demo_public_key()  # default: the demo key from tab 1
    else:
        return None, jsonify(ok=False, steps=[], error="Upload a public key or generate demo keys."), None
    meta_upload = request.files.get("meta")
    meta_path: Path | None = _save_upload(meta_upload) if meta_upload and meta_upload.filename else None
    doc_path = _save_upload(upload)
    sig_path = _save_upload(sig_upload)
    return (doc_path, sig_path, pubkey_path, meta_path), None, None


@app.post("/api/verify")
def api_verify():
    inputs, error_response, _ = _verify_inputs()
    if error_response is not None:
        return error_response, 400
    assert inputs is not None
    doc_path, sig_path, pubkey_path, meta_path = inputs
    steps = [
        "1. Hashing the received document...",
        "2. Unlocking the signature with the public key...",
        "3. Comparing fingerprints...",
    ]
    ok, reason = verify_file(doc_path, sig_path, pubkey_path, meta_path)
    return jsonify(ok=ok, steps=steps, valid=ok, reason=reason)


@app.post("/api/tamper")
def api_tamper():
    """One-click tamper demo: flip bytes in a temp copy, then verify it."""
    inputs, error_response, _ = _verify_inputs()
    if error_response is not None:
        return error_response, 400
    assert inputs is not None
    doc_path, sig_path, pubkey_path, meta_path = inputs
    tampered = Path(tempfile.mkstemp(suffix=".tampered", dir=UPLOAD_DIR)[1])
    raw = bytearray(doc_path.read_bytes())
    # Flip a middle byte when possible (more realistic than appending), else append.
    if raw:
        raw[len(raw) // 2] ^= 0x01
    else:
        raw[:] = b"!"
    tampered.write_bytes(bytes(raw))
    steps = [
        "1. Copied the document and changed 1 byte...",
        "2. Verifying the changed copy against the ORIGINAL signature...",
    ]
    ok, reason = verify_file(tampered, sig_path, pubkey_path, meta_path)
    return jsonify(ok=True, steps=steps, valid=ok, reason=reason)


@app.post("/api/sign-pdf")
def api_sign_pdf():
    """Sign a PDF with a visible hand-drawn signature. No validation here.

    Why sign-only: tabs 2 and 3 keep the sender and receiver apart, and the
    PDF flow must match. The signer downloads the file; the receiver verifies
    it on tab 3, like in real life.
    """
    ink = request.files.get("ink")
    signer = (request.form.get("signer") or "Alice").strip()
    password = request.form.get("password") or ""
    steps = ["1. Receiving your drawing and the PDF..."]
    if ink is None or not ink.filename:
        return jsonify(ok=False, steps=steps, error="Draw your signature first."), 400
    if not _demo_private_key().exists():
        return jsonify(ok=False, steps=steps, error="Generate demo keys first (tab 1)."), 400
    pdf_upload = request.files.get("pdffile")
    try:
        if pdf_upload is not None and pdf_upload.filename:
            input_pdf = _save_upload(pdf_upload)
        else:
            input_pdf = ensure_sample_pdf(POC_ROOT / "samples" / "sample.pdf")
        ink_path = _save_upload(ink, suffix=".png")
        steps.append("2. Preparing demo certificate...")
        ca_key = KEYS_DIR / "demo_ca_key.pem"
        ca_cert = KEYS_DIR / "demo_ca_cert.pem"
        cert = KEYS_DIR / "demo_signer_cert.pem"
        ensure_demo_ca(ca_key, ca_cert)
        issue_signer_cert(ca_key, ca_cert, _demo_public_key(), cert, signer)
        steps.append("3. Placing your drawing on the page and signing...")
        output_pdf = UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_signed.pdf"
        summary = sign_pdf_file(input_pdf, output_pdf, _demo_private_key(), cert, ca_cert, password, ink_path, signer)
        steps.append(f"4. {summary}")
    except ValueError as exc:
        return jsonify(ok=False, steps=steps, error=str(exc)), 400
    except Exception as exc:  # noqa: BLE001 - demo must show a message, not a traceback
        return jsonify(ok=False, steps=steps, error=f"Could not sign this PDF ({exc})."), 400
    steps.append("5. Done. Download the signed PDF, then verify it on tab 3.")
    return jsonify(
        ok=True,
        steps=steps,
        reason="Signed. Now switch to tab 3 and verify it as the receiver.",
        pdf_download=output_pdf.name,
    )


@app.post("/api/verify-pdf")
def api_verify_pdf():
    """Verify a signed PDF (the receiver step for tab 4)."""
    upload = request.files.get("signedpdf")
    steps = ["1. Reading the signed PDF..."]
    if upload is None or not upload.filename:
        return jsonify(ok=False, steps=steps, error="Choose the signed PDF first."), 400
    ca_cert = KEYS_DIR / "demo_ca_cert.pem"
    if not ca_cert.exists():
        return jsonify(ok=False, steps=steps, error="No demo CA yet. Sign a PDF first (tab 4)."), 400
    pdf_path = _save_upload(upload)
    steps.append("2. Checking the certificate chain...")
    steps.append("3. Comparing fingerprints...")
    ok, reason = validate_pdf_file(pdf_path, ca_cert)
    return jsonify(ok=ok, steps=steps, valid=ok, reason=reason)


@app.get("/download/<name>")
def download(name: str):
    return send_from_directory(UPLOAD_DIR, secure_filename(name), as_attachment=True)


@app.get("/api/demo-keys")
def demo_keys_status():
    return jsonify(
        private_exists=_demo_private_key().exists(),
        public_exists=_demo_public_key().exists(),
    )


if __name__ == "__main__":
    # Local demo only: loopback interface, debug off so tracebacks never leak keys.
    app.run(host="127.0.0.1", port=5000, debug=False)
