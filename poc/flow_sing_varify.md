
The core flow (signer(sign) <---> reciver (varify)), step by step:

One-time setup
    The signer creates a key pair: one private key, one matching public key.
    The private key is locked with a password and never leaves the signer's machine.
    The public key is shared freely with the world.
Signing (sender side)
    The software reads the document and creates its fingerprint (hash).
    The fingerprint is locked with the private key. That locked fingerprint is the signature.
    The sender ships three things: the document, the .sig signature, and the .meta.json details (signer name, algorithm, time).
Verification (receiver side)
    The receiver fingerprints the received document. This is the fresh fingerprint.
    The receiver unlocks the .sig with the sender's public key. This reveals the original fingerprint from signing time.
    The receiver compares the two fingerprints. Equal means VALID. Different means INVALID.



-----------------------------------------------------------------------
drawing case :

One-time setup (unchanged)
    The signer creates a key pair and locks the private key with a password.
    The demo CA issues a certificate binding the signer's name to the public key.
Drawing and signing
    You draw your signature on the pad with mouse or finger.
    You pick a PDF, or use the sample contract.
    Your drawing is placed visibly on the last page, with your name and time.
    The whole PDF, including your drawing, is fingerprinted.
    That fingerprint is locked with the private key. The locked fingerprint and the certificate are embedded inside the PDF.
    One single file travels: the signed PDF. No separate .sig or .meta.json.
Verification (receiver side)
    The receiver checks the certificate chain back to the trusted demo CA.
    The receiver unlocks the embedded signature with the public key. This reveals the original fingerprint.
    The receiver fingerprints the PDF bytes. This is the fresh fingerprint.
    The two fingerprints are compared. Equal means VALID. Different means INVALID.


---------------------------------------------------------

Flow with CA.

One-time setup
    The CA creates its own key pair. Its public key is shared with the world as pre-trusted (built into browsers, or handed over in person for our demo).
    The signer creates a key pair and locks the private key with a password.
    The signer proves identity to the CA and hands over the public key.
    The CA issues a certificate: signer name + signer public key + expiry date, all signed with the CA's private key.
Signing (sender side)
    The software fingerprints the document.
    The fingerprint is locked with the signer's private key. That is the signature.
    The sender ships the document, the signature, and the certificate.
Verification (receiver side)
    Level 1, trust the key: unlock the CA's signature on the certificate with the CA's public key. If it holds, and the certificate is not expired, the receiver trusts the signer public key inside it.
    Level 2, trust the document: fingerprint the received document (fresh fingerprint).
    Unlock the document signature with the trusted signer public key (original fingerprint).
    Compare the two fingerprints. Equal means VALID. Different means INVALID.
