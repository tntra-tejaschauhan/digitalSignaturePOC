"""Command-line interface for the digital signature demo.

Why a CLI as well as a web UI: the CLI output is what gets pasted into the
explainer document as proof, and it works over screen-share when a browser
cannot reach the demo server.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

# Allow `python cli.py ...` from inside poc/ without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.certs import describe_chain, ensure_demo_ca, issue_signer_cert, verify_with_cert  # noqa: E402
from app.pdf_sign import ensure_sample_pdf, sign_pdf_file, validate_pdf_file  # noqa: E402
from app.crypto import (  # noqa: E402
    hash_file,
    generate_keypair,
    sign_file,
    signature_preview,
    verify_file,
)

PASSWORD_ENV_VAR = "DIGITAL_SIG_PASSWORD"


def resolve_password(args_password: str | None) -> str:
    """Password from flag, env var, or hidden prompt — never hardcoded.

    Why this order: a flag suits scripts, the env var suits CI, and the prompt
    suits a live demo where the password must not appear on screen.
    """
    if args_password:
        return args_password
    from_env = os.environ.get(PASSWORD_ENV_VAR)
    if from_env:
        return from_env
    return getpass.getpass("Key password: ")


def cmd_keygen(args: argparse.Namespace) -> int:
    password = resolve_password(args.password)
    generate_keypair(args.private, args.public, password)
    print(f"Private key: {args.private} (password-protected)")
    print(f"Public key:  {args.public}")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    password = resolve_password(args.password)
    sig = args.sig or (args.file + ".sig")
    meta = args.meta or (args.file + ".meta.json")
    print("1. Hashing document with SHA-256...")
    digest = hash_file(args.file)
    print(f"   fingerprint: {digest[:32]}...")
    print("2. Signing hash with private key...")
    metadata = sign_file(args.file, args.private, password, args.signer, sig, meta)
    print(f"3. Wrote signature: {sig} ({signature_preview(sig)})")
    print(f"4. Wrote metadata:  {meta}")
    print(f"   signer={metadata['signer']} time={metadata['timestamp']}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    print("1. Hashing received document...")
    print("2. Checking signature with public key...")
    ok, reason = verify_file(args.file, args.sig, args.public, args.meta)
    print(reason)
    return 0 if ok else 1


def cmd_tamper(args: argparse.Namespace) -> int:
    """Append one byte to a COPY of the file, then show verification failing.

    Why a copy: the original signed file stays intact so the demo can show
    VALID again right after, on the untouched original.
    """
    data = Path(args.file).read_bytes()
    tampered = Path(args.output)
    tampered.write_bytes(data + b"!")
    print(f"Tampered copy: {tampered} (added 1 byte)")
    print("Verifying tampered copy against the ORIGINAL signature...")
    ok, reason = verify_file(str(tampered), args.sig, args.public, args.meta)
    print(reason)
    return 0 if not ok else 1  # success = tamper correctly detected


def cmd_cert_demo(args: argparse.Namespace) -> int:
    print("1. Creating demo CA (self-signed root)...")
    ensure_demo_ca(args.ca_key, args.ca_cert)
    print("2. Issuing signer certificate for the demo public key...")
    issue_signer_cert(args.ca_key, args.ca_cert, args.public, args.cert, args.signer)
    print(f"   chain: {describe_chain(args.cert, args.ca_cert)}")
    print("3. Verifying signature using the key inside the certificate...")
    ok, reason = verify_with_cert(args.file, args.sig, args.cert, args.ca_cert, args.meta)
    print(reason)
    return 0 if ok else 1


def cmd_pdf_demo(args: argparse.Namespace) -> int:
    password = resolve_password(args.password)
    print("1. Preparing demo CA + signer certificate...")
    ensure_demo_ca(args.ca_key, args.ca_cert)
    issue_signer_cert(args.ca_key, args.ca_cert, args.public, args.cert, args.signer)
    print("2. Preparing sample PDF...")
    ensure_sample_pdf(args.input)
    print("3. Signing PDF with pyHanko...")
    print(
        f"   {sign_pdf_file(args.input, args.output, args.private, args.cert, args.ca_cert, password, args.ink, args.signer)}"
    )
    print("4. Done. Verify it as the receiver would:")
    print(f"   python cli.py verify-pdf {args.output} --ca-cert {args.ca_cert}")
    return 0


def cmd_verify_pdf(args: argparse.Namespace) -> int:
    print("1. Reading the signed PDF...")
    print("2. Checking the certificate chain against the demo CA...")
    ok, reason = validate_pdf_file(args.file, args.ca_cert)
    print(reason)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Digital signature demo (demo keys only).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_key = sub.add_parser("keygen", help="Create a password-protected key pair.")
    p_key.add_argument("--private", default="keys/demo_private.pem")
    p_key.add_argument("--public", default="keys/demo_public.pem")
    p_key.add_argument("--password", default=None, help="Or set DIGITAL_SIG_PASSWORD.")
    p_key.set_defaults(func=cmd_keygen)

    p_sign = sub.add_parser("sign", help="Sign a file (detached .sig + metadata).")
    p_sign.add_argument("file")
    p_sign.add_argument("--private", default="keys/demo_private.pem")
    p_sign.add_argument("--signer", default="Alice")
    p_sign.add_argument("--sig", default=None)
    p_sign.add_argument("--meta", default=None)
    p_sign.add_argument("--password", default=None)
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify a file (prints VALID/INVALID).")
    p_verify.add_argument("file")
    p_verify.add_argument("sig")
    p_verify.add_argument("--public", default="keys/demo_public.pem")
    p_verify.add_argument("--meta", default=None)
    p_verify.set_defaults(func=cmd_verify)

    p_tamper = sub.add_parser("tamper-demo", help="Tamper a copy and show INVALID.")
    p_tamper.add_argument("file")
    p_tamper.add_argument("sig")
    p_tamper.add_argument("--public", default="keys/demo_public.pem")
    p_tamper.add_argument("--meta", default=None)
    p_tamper.add_argument("--output", default=None)
    p_tamper.set_defaults(func=cmd_tamper)

    p_cert = sub.add_parser("cert-demo", help="Demo CA + certificate verification.")
    p_cert.add_argument("file")
    p_cert.add_argument("sig")
    p_cert.add_argument("--public", default="keys/demo_public.pem")
    p_cert.add_argument("--meta", default=None)
    p_cert.add_argument("--signer", default="Alice")
    p_cert.add_argument("--ca-key", default="keys/demo_ca_key.pem")
    p_cert.add_argument("--ca-cert", default="keys/demo_ca_cert.pem")
    p_cert.add_argument("--cert", default="keys/demo_signer_cert.pem")
    p_cert.set_defaults(func=cmd_cert_demo)

    p_pdf = sub.add_parser("pdf-demo", help="Sign a PDF with pyHanko (verify it with verify-pdf).")
    p_pdf.add_argument("--input", default="samples/sample.pdf")
    p_pdf.add_argument("--output", default="samples/sample-signed.pdf")
    p_pdf.add_argument("--private", default="keys/demo_private.pem")
    p_pdf.add_argument("--public", default="keys/demo_public.pem")
    p_pdf.add_argument("--signer", default="Alice")
    p_pdf.add_argument("--ca-key", default="keys/demo_ca_key.pem")
    p_pdf.add_argument("--ca-cert", default="keys/demo_ca_cert.pem")
    p_pdf.add_argument("--cert", default="keys/demo_signer_cert.pem")
    p_pdf.add_argument("--ink", default=None, help="PNG of a hand-drawn signature for a visible mark.")
    p_pdf.add_argument("--password", default=None)
    p_pdf.set_defaults(func=cmd_pdf_demo)

    p_vpdf = sub.add_parser("verify-pdf", help="Verify a signed PDF (prints VALID/INVALID).")
    p_vpdf.add_argument("file")
    p_vpdf.add_argument("--ca-cert", default="keys/demo_ca_cert.pem")
    p_vpdf.set_defaults(func=cmd_verify_pdf)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) == "tamper-demo" and not args.output:
        args.output = args.file + ".tampered"
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        print(f"Error: file not found: {exc.filename}")
        return 2
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
