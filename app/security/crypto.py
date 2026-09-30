"""Cryptographic Primitives: RSA Keypair Management, JWKS, and Argon2 Hashing."""
import base64
from pathlib import Path
from typing import Dict, Any, Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from app.config import get_settings

settings = get_settings()

# Initialize Argon2 Password Hasher with standard secure parameters
pwd_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16
)


def hash_secret(secret: str) -> str:
    """Hashes passwords or API keys using Argon2id."""
    return pwd_hasher.hash(secret)


def verify_secret(secret: str, hashed: str) -> bool:
    """Verifies a plain secret against an Argon2id hash in constant time."""
    try:
        return pwd_hasher.verify(hashed, secret)
    except (VerifyMismatchError, InvalidHashError):
        return False


def int_to_base64url(val: int) -> str:
    """Convert an integer (e.g. RSA modulus or exponent) to URL-safe base64 without padding."""
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).decode("ascii").rstrip("=")


def ensure_rsa_keys() -> Tuple[str, str]:
    """
    Ensure 2048-bit RSA keypair exists on disk.
    If not found, generates and saves them to .keys/ (private key is protected).
    Returns (private_pem_str, public_pem_str).
    """
    private_path = settings.private_key_file
    public_path = settings.public_key_file

    if private_path.exists() and public_path.exists():
        private_pem = private_path.read_text(encoding="utf-8")
        public_pem = public_path.read_text(encoding="utf-8")
        return private_pem, public_pem

    # Ensure parent directory exists
    private_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate 2048-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_pem = private_pem_bytes.decode("utf-8")
    public_pem = public_pem_bytes.decode("utf-8")

    private_path.write_text(private_pem, encoding="utf-8")
    public_path.write_text(public_pem, encoding="utf-8")

    return private_pem, public_pem


def get_private_key_pem() -> str:
    """Loads RSA private key PEM string."""
    priv, _ = ensure_rsa_keys()
    return priv


def get_public_key_pem() -> str:
    """Loads RSA public key PEM string."""
    _, pub = ensure_rsa_keys()
    return pub


def get_jwks() -> Dict[str, Any]:
    """
    Exports the public key in standard RFC 7517 JWKS format.
    Exposes only the public key modulus (n) and exponent (e).
    """
    _, public_pem = ensure_rsa_keys()
    public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Configured public key is not an RSA key")

    pub_numbers = public_key.public_numbers()
    n_b64 = int_to_base64url(pub_numbers.n)
    e_b64 = int_to_base64url(pub_numbers.e)

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": settings.RSA_KEY_ID,
                "n": n_b64,
                "e": e_b64
            }
        ]
    }
