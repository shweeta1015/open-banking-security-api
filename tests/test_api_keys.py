"""Unit and Integration Tests for Partner API Keys."""
import pytest
from app.models import Partner
from app.seed import DEMO_CLIENT_ID, DEMO_PARTNER_API_KEY


def test_valid_api_key_authenticates(client, valid_api_key):
    """Test that a registered active partner can authenticate using X-API-Key."""
    resp = client.get("/api/v1/partners/me", headers={"X-API-Key": valid_api_key})
    assert resp.status_code == 200
    data = resp.json()
    assert data["client_id"] == DEMO_CLIENT_ID
    assert data["status"] == "ACTIVE"
    assert "api_key_prefix" in data
    assert "api_key_hash" not in data  # Never leak hash


def test_missing_api_key_returns_401(client):
    """Requests without X-API-Key header must be rejected with 401."""
    resp = client.get("/api/v1/partners/me")
    assert resp.status_code == 401
    assert "invalid_client" in resp.json()["detail"]["error"]


def test_malformed_api_key_returns_401(client):
    """Requests with malformed API keys must be rejected."""
    resp = client.get("/api/v1/partners/me", headers={"X-API-Key": "invalid_key_format"})
    assert resp.status_code == 401


def test_unknown_api_key_returns_401(client):
    """Requests with a valid format but unknown prefix must be rejected."""
    fake_key = "ob_live_ffff9999_fakeunregisteredrandomsecretkey12345"
    resp = client.get("/api/v1/partners/me", headers={"X-API-Key": fake_key})
    assert resp.status_code == 401


def test_revoked_partner_returns_403(client, db_session, valid_api_key):
    """Revoking a partner must immediately deny access with 403 Forbidden."""
    partner = db_session.query(Partner).filter(Partner.client_id == DEMO_CLIENT_ID).first()
    partner.status = "REVOKED"
    db_session.commit()

    resp = client.get("/api/v1/partners/me", headers={"X-API-Key": valid_api_key})
    assert resp.status_code == 403
    assert "unauthorized_client" in resp.json()["detail"]["error"]


def test_api_key_rotation(client, valid_api_key):
    """Rotating an API key invalidates the old key and activates the new key."""
    # 1. Rotate Key
    rotate_resp = client.post(f"/api/v1/partners/{DEMO_CLIENT_ID}/rotate-key")
    assert rotate_resp.status_code == 200
    new_key = rotate_resp.json()["raw_api_key"]
    assert new_key != valid_api_key

    # 2. Old key is rejected
    old_resp = client.get("/api/v1/partners/me", headers={"X-API-Key": valid_api_key})
    assert old_resp.status_code == 401

    # 3. New key is accepted
    new_resp = client.get("/api/v1/partners/me", headers={"X-API-Key": new_key})
    assert new_resp.status_code == 200
    assert new_resp.json()["client_id"] == DEMO_CLIENT_ID


def test_api_key_never_stored_plaintext_in_db(db_session):
    """Verify that only the Argon2 secure hash is stored in the database."""
    partner = db_session.query(Partner).filter(Partner.client_id == DEMO_CLIENT_ID).first()
    assert partner.api_key_hash != DEMO_PARTNER_API_KEY
    assert partner.api_key_hash.startswith("$argon2")
