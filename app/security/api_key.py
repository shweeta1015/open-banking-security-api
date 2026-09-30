"""Partner API Key Generation, Storage Hashing, and Validation."""
import secrets
from typing import Tuple, Optional
from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Partner, AuditLog
from app.security.crypto import hash_secret, verify_secret


def generate_partner_api_key() -> Tuple[str, str, str]:
    """
    Generates a cryptographically strong API key.
    Format: ob_live_<prefix_8chars>_<random_secret_32chars>
    Returns: (raw_full_key, prefix_str, hashed_key)
    """
    prefix_rnd = secrets.token_hex(4)  # 8 chars
    secret_rnd = secrets.token_urlsafe(32)  # 43 chars
    prefix = f"ob_live_{prefix_rnd}"
    full_key = f"{prefix}_{secret_rnd}"
    key_hash = hash_secret(full_key)
    return full_key, prefix, key_hash


def get_api_key_partner(
    request: Request,
    db: Session = Depends(get_db)
) -> Partner:
    """
    FastAPI dependency: Validates the X-API-Key header.
    - Requires header presence.
    - Extracts prefix to locate candidate partner without exposing secrets.
    - Verifies full key against stored one-way Argon2 hash.
    - Rejects REVOKED partners.
    """
    api_key = request.headers.get("X-API-Key")
    client_ip = request.client.host if request.client else "127.0.0.1"

    if not api_key:
        # Audit missing API key
        audit = AuditLog(
            event_type="AUTH_FAILURE",
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=401,
            details="Rejected request: Missing X-API-Key header"
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_client", "error_description": "API Key is required in X-API-Key header"}
        )

    # Validate structure: must start with ob_live_ and contain prefix delimiter
    parts = api_key.split("_")
    if len(parts) < 4 or not api_key.startswith("ob_live_"):
        audit = AuditLog(
            event_type="AUTH_FAILURE",
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=401,
            details="Rejected request: Malformed API key format"
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_client", "error_description": "Invalid API key format"}
        )

    # Prefix is ob_live_<hex8>
    prefix = f"{parts[0]}_{parts[1]}_{parts[2]}"

    partner = db.query(Partner).filter(Partner.api_key_prefix == prefix).first()
    if not partner:
        audit = AuditLog(
            event_type="AUTH_FAILURE",
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=401,
            details=f"Rejected request: Unrecognized API key prefix '{prefix}'"
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_client", "error_description": "Invalid API key"}
        )

    if partner.status != "ACTIVE":
        audit = AuditLog(
            event_type="AUTH_FAILURE",
            client_id=partner.client_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=403,
            details=f"Rejected request: Partner '{partner.client_id}' is revoked"
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "unauthorized_client", "error_description": "Partner API key has been revoked"}
        )

    # Verify full key against Argon2 hash in constant time
    if not verify_secret(api_key, partner.api_key_hash):
        audit = AuditLog(
            event_type="AUTH_FAILURE",
            client_id=partner.client_id,
            endpoint=request.url.path,
            method=request.method,
            ip_address=client_ip,
            status_code=401,
            details=f"Rejected request: Invalid secret for partner '{partner.client_id}'"
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_client", "error_description": "Invalid API key credentials"}
        )

    # Attach partner to request state
    request.state.partner = partner
    return partner
