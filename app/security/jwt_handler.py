"""RS256 Signed JWT Access Token Issuance and Stateless Verification."""
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
import uuid
import jwt
from fastapi import Request, HTTPException, status, Depends
from app.config import get_settings
from app.security.crypto import get_private_key_pem, get_public_key_pem

settings = get_settings()

# Cache public key in memory for zero-database local verification
_CACHED_PUBLIC_KEY: Optional[str] = None


def get_cached_public_key() -> str:
    """Returns in-memory cached public key PEM for high-performance verification."""
    global _CACHED_PUBLIC_KEY
    if _CACHED_PUBLIC_KEY is None:
        _CACHED_PUBLIC_KEY = get_public_key_pem()
    return _CACHED_PUBLIC_KEY


def issue_access_token(
    customer_id: str,
    client_id: str,
    consent_id: str,
    scopes: List[str]
) -> TupleToken:
    """
    Issue an RS256-signed JWT access token adhering to RFC 7519 and Open Banking standards.
    Contains: iss, sub, aud, client_id, scope, consent_id, iat, nbf, exp, jti.
    """
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())
    scope_str = " ".join(scopes)

    payload = {
        "iss": settings.JWT_ISSUER,
        "sub": customer_id,
        "aud": settings.JWT_AUDIENCE,
        "client_id": client_id,
        "scope": scope_str,
        "consent_id": consent_id,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": jti
    }

    headers = {
        "kid": settings.RSA_KEY_ID,
        "alg": "RS256",
        "typ": "JWT"
    }

    private_pem = get_private_key_pem()
    token = jwt.encode(
        payload=payload,
        key=private_pem,
        algorithm="RS256",
        headers=headers
    )

    return token, int(settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)


TupleToken = tuple[str, int]


def verify_access_token(token: str) -> Dict[str, Any]:
    """
    Verifies the RS256 JWT access token locally using ONLY the cached public key.
    Validates:
    - Signature using asymmetric RS256
    - Algorithm explicitly restricted to RS256 (preventing 'alg: none' or HMAC confusion)
    - Issuer (iss)
    - Audience (aud)
    - Expiration time (exp)
    - Not Before (nbf)
    NOTE: Zero database queries are performed for cryptographic verification.
    """
    public_pem = get_cached_public_key()
    try:
        decoded = jwt.decode(
            token,
            public_pem,
            algorithms=["RS256"],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["iss", "sub", "aud", "client_id", "scope", "consent_id", "iat", "exp", "jti"]
            }
        )
        return decoded
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": "The access token has expired"}
        )
    except jwt.ImmatureSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": "The token is not yet valid (nbf check)"}
        )
    except jwt.InvalidAlgorithmError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": "Invalid cryptographic algorithm"}
        )
    except jwt.InvalidSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": "Cryptographic signature validation failed"}
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": f"Malformed or invalid token: {str(e)}"}
        )


def get_current_token_claims(request: Request) -> Dict[str, Any]:
    """FastAPI Dependency: extracts and verifies Bearer token claims."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": "Missing Authorization header"}
        )

    parts = auth_header.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": "Authorization header must be 'Bearer <token>'"}
        )

    claims = verify_access_token(parts[1])
    request.state.claims = claims
    return claims


def require_scope(required_scope: str):
    """Factory dependency to enforce specific OAuth 2.0 scopes (e.g. 'accounts:read')."""
    def scope_checker(claims: Dict[str, Any] = Depends(get_current_token_claims)) -> Dict[str, Any]:
        token_scopes = claims.get("scope", "").split(" ")
        if required_scope not in token_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_scope",
                    "error_description": f"The access token does not have required scope '{required_scope}'",
                    "scope": required_scope
                }
            )
        return claims
    return scope_checker
