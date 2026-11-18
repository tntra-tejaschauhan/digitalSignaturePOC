# Digital Signature POC

A small demo that signs files and verifies them. Built for a live demo to
non-technical managers. For the full explanation, see
`docs/digital-signature-explained.md`.

> **Demo only.** Keys generated here are for demonstration. Never use them for
> real documents or production systems.

## Setup

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r poc/requirements.txt
cd poc
export DIGITAL_SIG_PASSWORD=demo-pass   # demo password only
```

## Run the CLI

```bash
cd poc
python cli.py keygen                                   # 1. create key pair
python cli.py sign samples/sample.txt --signer Alice   # 2. sign a file
python cli.py verify samples/sample.txt samples/sample.txt.sig --meta samples/sample.txt.meta.json
python cli.py tamper-demo samples/sample.txt samples/sample.txt.sig --meta samples/sample.txt.meta.json
python cli.py cert-demo samples/sample.txt samples/sample.txt.sig --meta samples/sample.txt.meta.json
python cli.py pdf-demo                                 # stretch: sign a PDF (verify it next)
python cli.py pdf-demo --ink signature.png           # ...with your hand drawing visible on the page
python cli.py verify-pdf samples/sample-signed.pdf   # stretch: verify the signed PDF
```

Without `DIGITAL_SIG_PASSWORD`, each command prompts for the password (hidden input).

## Run the web UI

```bash
cd poc
source ../.venv/bin/activate
python -m app.web
```

Then open **http://127.0.0.1:5000/** in a browser. Four tabs: Generate Keys,
Sign, Verify (with a one-click tamper demo button), and Sign PDF, where you
draw your signature with the mouse like ink on paper.

## Run the tests

```bash
cd poc
../.venv/bin/python -m pytest tests -v
```

17 tests: valid round-trip, 1-byte tamper, wrong key, corrupt signature,
wrong algorithm, missing files, certificate chain (valid + wrong CA + tampered
doc), PDF sign/validate (valid + tampered + visible ink), and the web
sign/verify split (sign returns no verdict, separate PDF verify step).

## Demo script (5 minutes, for a manager)

Say this, click that:

1. **Tab 1, Generate Keys.** Say: "This creates two linked keys. The private
   key signs and stays secret. The public key verifies and can be shared."
   Enter a password, click Generate.
2. **Tab 2, Sign.** Say: "I pick our contract. The demo fingerprints it, then
   locks that fingerprint with the private key. That locked fingerprint is the
   signature." Upload `samples/sample.txt`, click Sign, download both files.
3. **Tab 3, Verify.** Say: "Now I am the receiver. I re-fingerprint the file
   and unlock the signature with the public key. If both fingerprints match,
   the file is genuine." Upload the three files, click Verify. Show VALID.
4. **Tamper button.** Say: "Now an attacker changes one byte." Click the tamper
   button. Show INVALID. Say: "One byte changed, and verification fails. That
   is tamper detection."
5. **Tab 4, Sign PDF.** Say: "And you can sign like on paper." Draw on the
   pad, click Sign PDF, download it. Say: "Your drawing is visible on the page
   for humans, while invisible cryptography protects the whole file." Then go
   back to tab 3, upload the signed PDF under "Or verify a signed PDF", and
   show VALID. Say: "Signing and checking are separate steps, like sender and
   receiver in real life."
6. **Close.** Say: "In production we would store keys in an HSM, buy
   certificates from a real CA, and add timestamps and audit logs. This demo
   proves the concept."

## Project structure

```text
poc/
  app/
    crypto.py      # keygen, SHA-256 hash, sign, verify
    certs.py       # stretch: demo CA + X.509 certificates
    pdf_sign.py    # stretch: pyHanko PDF signing + validation
    web.py         # Flask UI (JSON API + pages)
    templates/     # single-page UI (3 tabs)
  cli.py           # keygen, sign, verify, tamper-demo, cert-demo, pdf-demo
  tests/           # pytest suite (13 tests)
  samples/         # sample contract + generated outputs
  keys/            # demo keys (gitignored, password-protected)
```

## Sample CLI output

Real output from this repo (timestamps and fingerprints vary per run):

```text
$ python cli.py sign samples/sample.txt --signer Alice
1. Hashing document with SHA-256...
   fingerprint: 3180dc750b5a842e7a6d0b0037000d82...
2. Signing hash with private key...
3. Wrote signature: samples/sample.txt.sig (bmz4cnuwbiLfmAE/YXmhuJlcn/mD9Jv7...)
4. Wrote metadata:  samples/sample.txt.meta.json
   signer=Alice time=2026-11-18T10:53:38+00:00

$ python cli.py verify samples/sample.txt samples/sample.txt.sig --meta samples/sample.txt.meta.json
1. Hashing received document...
2. Checking signature with public key...
VALID: the file is unchanged and the signature matches this key.

$ python cli.py tamper-demo samples/sample.txt samples/sample.txt.sig --meta samples/sample.txt.meta.json
Tampered copy: samples/sample.txt.tampered (added 1 byte)
Verifying tampered copy against the ORIGINAL signature...
INVALID: the file was changed after signing. Its fingerprint no longer matches the signed fingerprint.
```

## Screenshots

UI screenshots are taken during the live demo (the UI runs locally at
http://127.0.0.1:5000/). The three tabs and the VALID/INVALID result panels are
the shots to capture.

## Known limitations

- Demo CA and keys live on disk. Production needs an HSM or KMS.
- No trusted timestamping, revocation checking, or audit logs.
- Single RSA-3072-PSS-SHA256 algorithm. No algorithm negotiation.
- Web uploads are stored in `poc/web_uploads/` with no auth or rate limits.
