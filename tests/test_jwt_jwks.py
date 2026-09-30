"""Unit and Integration Tests for RS256 JWT and RFC 7517 JWKS."""
import time
import pytest
import jwt
from app.config import get_settings
from app.security.crypto import get_private_key_pem
from app.security.jwt_handler import issue_access_token, verify_access_token
from fastapi import HTTPException

settings = get_settings()


def test_jwks_endpoint_rfc7517(client):
    """Test that JWKS endpoint complies with RFC 7517 format."""
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "keys" in data
    assert len(data["keys"]) > 0

    key = data["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert key["kid"] == settings.RSA_KEY_ID
    assert "n" in key
    assert "e" in key
    assert "d" not in key  # Private exponent must NEVER be exposed!


def test_jwt_issuance_and_stateless_verification():
    """Verify that token is signed with RS256 and verified locally using cached public key."""
    token, expires_in = issue_access_token(
        customer_id="cust_alice_101",
        client_id="fintech_partner_demo",
        consent_id="consent_test_123",
        scopes=["accounts:read", "balances:read"]
    )
    assert isinstance(token, str)
    assert expires_in > 0

    # Local stateless verification (no database call)
    claims = verify_access_token(token)
    assert claims["sub"] == "cust_alice_101"
    assert claims["client_id"] == "fintech_partner_demo"
    assert claims["consent_id"] == "consent_test_123"
    assert claims["scope"] == "accounts:read balances:read"
    assert claims["iss"] == settings.JWT_ISSUER
    assert claims["aud"] == settings.JWT_AUDIENCE
    assert "jti" in claims
    assert "iat" in claims
    assert "exp" in claims


def test_tampered_jwt_signature_rejected():
    """Modifying token bytes must fail cryptographic verification."""
    token, _ = issue_access_token(
        customer_id="cust_alice_101",
        client_id="fintech_partner_demo",
        consent_id="consent_test_123",
        scopes=["accounts:read"]
    )

    parts = token.split(".")
    # Modify signature
    tampered_sig = parts[2][:-4] + "AAAA"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(tampered_token)
    assert exc_info.value.status_code == 401
    assert "signature" in exc_info.value.detail["error_description"].lower()


def test_expired_jwt_rejected():
    """Expired tokens must fail validation."""
    now = int(time.time())
    payload = {
        "iss": settings.JWT_ISSUER,
        "sub": "cust_alice_101",
        "aud": settings.JWT_AUDIENCE,
        "client_id": "fintech_partner_demo",
        "scope": "accounts:read",
        "consent_id": "consent_123",
        "iat": now - 3600,
        "nbf": now - 3600,
        "exp": now - 10,  # Already expired
        "jti": "test_expired_jti"
    }
    headers = {"kid": settings.RSA_KEY_ID, "alg": "RS256"}
    expired_token = jwt.encode(payload, get_private_key_pem(), algorithm="RS256", headers=headers)

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(expired_token)
    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail["error_description"].lower()
