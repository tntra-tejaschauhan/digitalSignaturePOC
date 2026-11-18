"""Core signing and verification logic for the demo.

Why this module exists: the CLI and the web UI are both thin shells over these
functions, so every demo path (valid, tampered, wrong key, corrupt signature)
behaves identically no matter which interface the manager clicks.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

# Single algorithm for the whole demo, so "wrong algorithm" inputs are easy to
# spot and reject instead of silently accepted.
ALGORITHM = "RSA-3072-PSS-SHA256"
HASH_ALGORITHM = "SHA-256"
RSA_KEY_SIZE = 3072
_CHUNK_SIZE = 65536  # stream files so big uploads never fill memory


def _pss_padding() -> padding.PSS:
    """PSS padding with maximum salt length.

    Why PSS and not the older PKCS#1 v1.5: PSS is randomized and has a security
    proof, while v1.5 has a long history of padding bugs. Max salt gives the
    strongest default for this key size.
    """
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


def hash_file(path: str | Path) -> str:
    """Return the hex SHA-256 digest of a file, read in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate_keypair(
    private_path: str | Path, public_path: str | Path, password: str
) -> None:
    """Create an RSA-3072 key pair and save it as PEM files.

    The private key is encrypted with the password. We refuse an empty password
    because shipping unprotected demo keys teaches the exact habit this demo
    warns managers against.
    """
    if not password:
        raise ValueError("A password is required to protect the private key.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(private_path).write_bytes(private_bytes)
    Path(public_path).write_bytes(public_bytes)


def load_private_key(path: str | Path, password: str) -> rsa.RSAPrivateKey:
    """Load a password-protected private key, rejecting non-RSA keys."""
    key = serialization.load_pem_private_key(
        Path(path).read_bytes(), password=password.encode()
    )
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Only RSA private keys are supported by this demo.")
    return key


def load_public_key(path: str | Path) -> rsa.RSAPublicKey:
    """Load a PEM public key, rejecting non-RSA keys."""
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Only RSA public keys are supported by this demo.")
    return key


def sign_file(
    file_path: str | Path,
    private_key_path: str | Path,
    password: str,
    signer_name: str,
    sig_path: str | Path,
    meta_path: str | Path,
) -> dict[str, str]:
    """Hash a file with SHA-256, sign the hash, write .sig + metadata JSON.

    The signature is "detached": the original file is left untouched and the
    signature travels beside it, which makes the tamper demo easy to show.
    Returns the metadata dict so callers can display it.
    """
    file_path = Path(file_path)
    file_hash = hash_file(file_path)
    private_key = load_private_key(private_key_path, password)
    # Prehashed keeps the two demo steps visible (hash, then sign) instead of
    # hiding the hash inside the sign call.
    signature = private_key.sign(
        bytes.fromhex(file_hash), _pss_padding(), Prehashed(hashes.SHA256())
    )
    Path(sig_path).write_bytes(signature)
    metadata = {
        "signer": signer_name,
        "algorithm": ALGORITHM,
        "hash_algorithm": HASH_ALGORITHM,
        "file_hash": file_hash,
        "file_name": file_path.name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    Path(meta_path).write_text(json.dumps(metadata, indent=2) + "\n")
    return metadata


def verify_file(
    file_path: str | Path,
    sig_path: str | Path,
    public_key_path: str | Path,
    meta_path: str | Path | None = None,
) -> tuple[bool, str]:
    """Verify a file against its detached signature.

    Returns (True, reason) when VALID and (False, reason) when INVALID. Reasons
    are plain sentences because they are shown directly to managers in the UI.
    Never raises on bad input: corrupt files, keys, or metadata all become a
    clear INVALID result instead of a stack trace during a live demo.
    """
    try:
        public_key = load_public_key(public_key_path)
    except (ValueError, OSError) as exc:
        return False, f"INVALID: public key could not be read ({exc})."
    except Exception:  # noqa: BLE001 - any parse failure is an INVALID verdict
        return False, "INVALID: public key file is not a valid PEM key."

    if meta_path is not None:
        try:
            metadata = json.loads(Path(meta_path).read_text())
        except (OSError, json.JSONDecodeError):
            return False, "INVALID: metadata file is missing or not valid JSON."
        if metadata.get("algorithm") != ALGORITHM:
            return (
                False,
                f"INVALID: unsupported algorithm "
                f"'{metadata.get('algorithm')}'. This demo only verifies "
                f"{ALGORITHM}.",
            )

    try:
        signature = Path(sig_path).read_bytes()
    except OSError:
        return False, "INVALID: signature file is missing or unreadable."
    if not signature:
        return False, "INVALID: signature file is empty."
    # Guard against truncated or garbage signatures before the crypto call so
    # the manager sees "corrupted" instead of a generic failure.
    if len(signature) != RSA_KEY_SIZE // 8:
        return False, (
            "INVALID: signature is corrupted "
            f"(expected {RSA_KEY_SIZE // 8} bytes, got {len(signature)})."
        )

    try:
        file_hash = hash_file(file_path)
    except OSError:
        return False, "INVALID: document file is missing or unreadable."

    if meta_path is not None and metadata.get("file_hash") != file_hash:
        return False, (
            "INVALID: the file was changed after signing. "
            "Its fingerprint no longer matches the signed fingerprint."
        )

    try:
        public_key.verify(
            signature, bytes.fromhex(file_hash), _pss_padding(), Prehashed(hashes.SHA256())
        )
    except InvalidSignature:
        return False, (
            "INVALID: signature check failed. The file was changed, "
            "the wrong public key was used, or the signature is corrupted."
        )
    return True, "VALID: the file is unchanged and the signature matches this key."


def signature_preview(sig_path: str | Path, length: int = 48) -> str:
    """Short base64 preview of a signature for display in the UI."""
    raw = Path(sig_path).read_bytes()
    text = base64.b64encode(raw).decode("ascii")
    return text[:length] + "..." if len(text) > length else text
