"""Tiny demo Certificate Authority (CA) plus X.509 signer certificates.

Why this exists: verification with a bare public key begs the question "whose
key is this?". A certificate answers it by wrapping the signer's public key in
a document the demo CA has signed. The receiver trusts the CA's public key once
(up front, in person for a demo) and can then check any certificate it issued.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .crypto import RSA_KEY_SIZE, load_private_key, load_public_key, verify_file


def ensure_demo_ca(
    ca_key_path: str | Path, ca_cert_path: str | Path, common_name: str = "Demo CA"
) -> None:
    """Create a self-signed demo CA (key + certificate), unless it exists.

    Why path_length=0: this demo CA may only issue end-user certificates, never
    another CA. That matches the single-level chain the docs draw.
    """
    ca_key_path, ca_cert_path = Path(ca_key_path), Path(ca_cert_path)
    if ca_key_path.exists() and ca_cert_path.exists():
        return  # keep existing CA so previously issued certs stay valid
    from cryptography.hazmat.primitives.asymmetric import rsa

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed: issuer == subject
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())  # X.509 certs use PKCS#1 v1.5: ecosystem standard
    )
    ca_key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),  # demo CA key is throwaway; real CAs use HSMs
        )
    )
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))


def issue_signer_cert(
    ca_key_path: str | Path,
    ca_cert_path: str | Path,
    signer_pubkey_path: str | Path,
    cert_path: str | Path,
    common_name: str,
) -> None:
    """Issue an end-user certificate binding a name to the signer's public key."""
    ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
    ca_key = serialization.load_pem_private_key(Path(ca_key_path).read_bytes(), None)
    signer_pubkey = load_public_key(signer_pubkey_path)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(signer_pubkey)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def describe_chain(cert_path: str | Path, ca_cert_path: str | Path) -> str:
    """One-line summary of the chain for demo output."""
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    ca = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
    leaf = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    root = ca.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    return f"{leaf} <- issued by {issuer} (root: {root}, self-signed)"


def verify_with_cert(
    file_path: str | Path,
    sig_path: str | Path,
    cert_path: str | Path,
    ca_cert_path: str | Path,
    meta_path: str | Path | None = None,
) -> tuple[bool, str]:
    """Verify a signature using the public key inside a CA-issued certificate.

    Checks the chain first (issuer, CA signature, expiry), then the document
    signature. Returns (valid, plain-language reason) like verify_file.
    """
    try:
        cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
    except (OSError, ValueError):
        return False, "INVALID: certificate or CA file is missing or not valid PEM."
    if cert.issuer != ca_cert.subject:
        return False, "INVALID: this certificate was not issued by the demo CA."
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception:  # noqa: BLE001 - any failure means "don't trust this cert"
        return False, "INVALID: the CA signature on the certificate is bad."
    now = datetime.now(timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        return False, "INVALID: the signer certificate is expired or not yet valid."
    # Chain is good: verify the document with the key the CA vouches for.
    import tempfile

    pubkey_pem = cert.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=True) as tmp:
        Path(tmp.name).write_bytes(pubkey_pem)
        ok, reason = verify_file(file_path, sig_path, tmp.name, meta_path)
    if ok:
        leaf = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        return True, f"VALID: chain OK ({describe_chain(cert_path, ca_cert_path)}); {reason}"
    return False, f"Chain OK, but document check failed: {reason}"
