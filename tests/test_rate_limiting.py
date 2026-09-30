"""OWASP API4: Unrestricted Resource Consumption / Rate Limiting Tests."""
import pytest
from app.models import Partner
from app.seed import DEMO_CLIENT_ID, DEMO_PARTNER_API_KEY


def test_rate_limit_headers_emitted(client, valid_api_key):
    """Requests must emit standard rate-limiting headers."""
    resp = client.get("/api/v1/partners/me", headers={"X-API-Key": valid_api_key})
    assert resp.status_code == 200
    assert "X-RateLimit-Limit" in resp.headers
    assert "X-RateLimit-Remaining" in resp.headers
    assert "X-RateLimit-Reset" in resp.headers


def test_rate_limit_threshold_triggers_429(client, db_session, valid_api_key):
    """OWASP API4 Test: Exceeding partner rate limit returns HTTP 429 with Retry-After header."""
    partner = db_session.query(Partner).filter(Partner.client_id == DEMO_CLIENT_ID).first()
    # Set a low limit of 3 requests per minute for fast testing
    partner.rate_limit_rpm = 3
    db_session.commit()

    # 3 allowed requests
    for _ in range(3):
        res = client.get("/api/v1/partners/me", headers={"X-API-Key": valid_api_key})
        assert res.status_code == 200

    # 4th request must be rejected with 429
    res_blocked = client.get("/api/v1/partners/me", headers={"X-API-Key": valid_api_key})
    assert res_blocked.status_code == 429
    assert "Retry-After" in res_blocked.headers
    assert "rate_limit_exceeded" in res_blocked.json()["detail"]["error"]
