# app/tools.py
# Global shared tools and Human-In-The-Loop approval gates.

import os
import logging
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def approve_vibe_diff_with_mfa(vibe_diff: str, challenge: str, signature_hex: str, public_key_pem: str) -> dict:
    """Verifies the human reviewer's hardware MFA signature on the Vibe Diff payload before merging code.
    
    Args:
        vibe_diff: The plain-English summary of execution changes.
        challenge: The generated cryptographic challenge string.
        signature_hex: The signature hex string returned by the WebAuthn/FIDO2 token.
        public_key_pem: The PEM-encoded public key registered for the human reviewer.
    """
    try:
        # Load the developer's public key
        pub_key = load_pem_public_key(public_key_pem.encode('utf-8'))
        
        # Challenge bytes and signature hex decoding
        challenge_bytes = challenge.encode('utf-8')
        signature_bytes = bytes.fromhex(signature_hex)
        
        # Verify the signature
        if hasattr(pub_key, "verify"):
            # Check if Elliptic Curve (common in WebAuthn ES256 tokens)
            if isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(signature_bytes, challenge_bytes, ec.ECDSA(hashes.SHA256()))
            else:
                # Fallback to RSA
                pub_key.verify(
                    signature_bytes,
                    challenge_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            logging.info("Hardware MFA Signature verification succeeded.")
            return {
                "status": "approved",
                "message": "Vibe Diff cryptographically approved via physical security key (WebAuthn MFA)."
            }
        else:
            return {"status": "failed", "error": "Invalid public key type."}
    except Exception as e:
        logging.error(f"Hardware MFA Signature verification failed: {e}")
        return {
            "status": "rejected",
            "error": f"Cryptographic Hardware MFA verification failed: {e}"
        }
