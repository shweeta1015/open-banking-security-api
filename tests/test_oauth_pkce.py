"""Unit and Integration Tests for OAuth 2.0 PKCE and Delegated Consent."""
import pytest
from app.security.pkce import generate_pkce_pair
from app.seed import DEMO_CLIENT_ID


def test_authorize_endpoint_validation(client):
    """Test authorize endpoint parameter validation."""
    verifier, challenge = generate_pkce_pair()
    redirect_uri = "http://localhost:8000/oauth/callback"

    # Valid call
    resp = client.get(
        f"/oauth/authorize?client_id={DEMO_CLIENT_ID}&response_type=code"
        f"&redirect_uri={redirect_uri}&scope=accounts:read&state=test_state"
        f"&code_challenge={challenge}&code_challenge_method=S256"
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "pending_consent"
    assert data["client_id"] == DEMO_CLIENT_ID

    # Invalid code_challenge_method (plain not allowed)
    resp_plain = client.get(
        f"/oauth/authorize?client_id={DEMO_CLIENT_ID}&response_type=code"
        f"&redirect_uri={redirect_uri}&scope=accounts:read&state=test_state"
        f"&code_challenge={challenge}&code_challenge_method=plain"
    )
    assert resp_plain.status_code == 400


def test_consent_and_token_exchange_full_flow(client):
    """Test end-to-end OAuth 2.0 PKCE flow."""
    verifier, challenge = generate_pkce_pair()
    redirect_uri = "http://localhost:8000/oauth/callback"

    # 1. Customer Alice submits consent
    consent_payload = {
        "client_id": DEMO_CLIENT_ID,
        "username": "alice",
        "password": "AliceSecurePass2026!",
        "redirect_uri": redirect_uri,
        "state": "csrf_token_123",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scopes": ["accounts:read", "balances:read"],
        "allowed_account_ids": ["acc_alice_chk_01"]
    }
    consent_resp = client.post("/oauth/consent", json=consent_payload)
    assert consent_resp.status_code == 200
    code = consent_resp.json()["code"]
    assert code.startswith("authcode_")

    # 2. Exchange Code + PKCE Verifier for Access Token
    token_payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": DEMO_CLIENT_ID,
        "code_verifier": verifier
    }
    token_resp = client.post("/oauth/token", json=token_payload)
    assert token_resp.status_code == 200
    token_data = token_resp.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "Bearer"
    assert token_data["scope"] == "accounts:read balances:read"
    assert "consent_id" in token_data


def test_pkce_verifier_mismatch_rejected(client):
    """Providing an incorrect code_verifier must fail PKCE validation."""
    verifier, challenge = generate_pkce_pair()
    redirect_uri = "http://localhost:8000/oauth/callback"

    consent_payload = {
        "client_id": DEMO_CLIENT_ID,
        "username": "alice",
        "password": "AliceSecurePass2026!",
        "redirect_uri": redirect_uri,
        "state": "state123",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scopes": ["accounts:read"],
        "allowed_account_ids": ["acc_alice_chk_01"]
    }
    consent_resp = client.post("/oauth/consent", json=consent_payload)
    code = consent_resp.json()["code"]

    # Exchange with WRONG verifier
    wrong_verifier = "wrong_code_verifier_1234567890123456789012345678901234567890"
    token_resp = client.post("/oauth/token", json={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": DEMO_CLIENT_ID,
        "code_verifier": wrong_verifier
    })
    assert token_resp.status_code == 400
    assert "PKCE" in token_resp.json()["detail"]["error_description"]


def test_authorization_code_cannot_be_reused(client):
    """Single-use authorization code: reusing an auth code must be rejected."""
    verifier, challenge = generate_pkce_pair()
    redirect_uri = "http://localhost:8000/oauth/callback"

    consent_payload = {
        "client_id": DEMO_CLIENT_ID,
        "username": "alice",
        "password": "AliceSecurePass2026!",
        "redirect_uri": redirect_uri,
        "state": "state123",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scopes": ["accounts:read"],
        "allowed_account_ids": ["acc_alice_chk_01"]
    }
    code = client.post("/oauth/consent", json=consent_payload).json()["code"]

    # First exchange succeeds
    resp1 = client.post("/oauth/token", json={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": DEMO_CLIENT_ID,
        "code_verifier": verifier
    })
    assert resp1.status_code == 200

    # Second exchange fails (code already consumed)
    resp2 = client.post("/oauth/token", json={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": DEMO_CLIENT_ID,
        "code_verifier": verifier
    })
    assert resp2.status_code == 400
    assert "already been used" in resp2.json()["detail"]["error_description"]


def test_consent_rejects_unowned_accounts(client):
    """Alice cannot grant consent for Bob's account (BOLA prevention in consent phase)."""
    verifier, challenge = generate_pkce_pair()
    redirect_uri = "http://localhost:8000/oauth/callback"

    consent_payload = {
        "client_id": DEMO_CLIENT_ID,
        "username": "alice",
        "password": "AliceSecurePass2026!",
        "redirect_uri": redirect_uri,
        "state": "state123",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scopes": ["accounts:read"],
        "allowed_account_ids": ["acc_bob_chk_01"]  # Bob's account!
    }
    resp = client.post("/oauth/consent", json=consent_payload)
    assert resp.status_code == 403
    assert "not owned by customer" in resp.json()["detail"]["error_description"]
