"""OAuth 2.0 PKCE (Proof Key for Code Exchange - RFC 7636)."""
import base64
import hashlib
import re
import secrets
from typing import Tuple


def generate_code_verifier() -> str:
    """Generate a random 43-128 character URL-safe code verifier."""
    token = secrets.token_urlsafe(64)
    # RFC 7636 allows characters: [A-Z], [a-z], [0-9], "-", ".", "_", "~"
    return token[:64]


def compute_code_challenge(verifier: str, method: str = "S256") -> str:
    """Compute code_challenge from code_verifier."""
    if method != "S256":
        raise ValueError(f"Unsupported PKCE code_challenge_method: {method}. Only S256 is permitted.")
    
    sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(sha256_hash).decode("ascii").rstrip("=")
    return challenge


def generate_pkce_pair() -> Tuple[str, str]:
    """Generates a valid (code_verifier, code_challenge) pair."""
    verifier = generate_code_verifier()
    challenge = compute_code_challenge(verifier, method="S256")
    return verifier, challenge


def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    """
    Validates code_verifier against stored code_challenge.
    Prevents authorization code interception attacks.
    """
    if not code_verifier or not code_challenge:
        return False
    
    if len(code_verifier) < 43 or len(code_verifier) > 128:
        return False

    # Check allowed character set
    if not re.match(r"^[A-Za-z0-9\-._~]+$", code_verifier):
        return False

    if method != "S256":
        return False

    computed = compute_code_challenge(code_verifier, method="S256")
    return secrets.compare_digest(computed, code_challenge)
