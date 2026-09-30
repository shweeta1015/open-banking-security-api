"""OWASP API1: Broken Object Level Authorization (BOLA / IDOR) Tests."""
from datetime import datetime, timezone, timedelta
import json
import pytest
from app.models import Consent, AuditLog
from app.security.jwt_handler import issue_access_token
from app.seed import DEMO_CLIENT_ID


@pytest.fixture
def alice_token_and_consent(db_session):
    """Creates an active consent and token for Alice granting access only to acc_alice_chk_01."""
    now = datetime.now(timezone.utc)
    consent = Consent(
        consent_id="consent_alice_chk_only",
        client_id=DEMO_CLIENT_ID,
        customer_id="cust_alice_101",
        allowed_account_ids=json.dumps(["acc_alice_chk_01"]),
        scopes="accounts:read balances:read transactions:read payments:write",
        status="ACTIVE",
        created_at=now,
        expires_at=now + timedelta(days=30)
    )
    db_session.add(consent)
    db_session.commit()

    token, _ = issue_access_token(
        customer_id="cust_alice_101",
        client_id=DEMO_CLIENT_ID,
        consent_id=consent.consent_id,
        scopes=["accounts:read", "balances:read", "transactions:read", "payments:write"]
    )
    return token, consent.consent_id


def test_authorized_account_access_succeeds(client, alice_token_and_consent):
    """Alice can successfully access her consented checking account."""
    token, _ = alice_token_and_consent
    resp = client.get("/api/v1/accounts/acc_alice_chk_01", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["account_id"] == "acc_alice_chk_01"


def test_cross_customer_account_bola_blocked(client, alice_token_and_consent, db_session):
    """OWASP API1 Test: Alice attempts to query Bob's account (acc_bob_chk_01). Must be blocked."""
    token, _ = alice_token_and_consent
    resp = client.get("/api/v1/accounts/acc_bob_chk_01", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code in [403, 404]

    # Verify BOLA event recorded in audit logs
    audit = db_session.query(AuditLog).filter(
        AuditLog.event_type == "BOLA_VIOLATION_BLOCKED",
        AuditLog.account_id == "acc_bob_chk_01"
    ).first()
    assert audit is not None


def test_cross_customer_balance_bola_blocked(client, alice_token_and_consent):
    """OWASP API1 Test: Alice attempts to query Bob's balance. Must be blocked."""
    token, _ = alice_token_and_consent
    resp = client.get("/api/v1/accounts/acc_bob_chk_01/balances", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code in [403, 404]


def test_cross_customer_transactions_bola_blocked(client, alice_token_and_consent):
    """OWASP API1 Test: Alice attempts to query Bob's transactions. Must be blocked."""
    token, _ = alice_token_and_consent
    resp = client.get("/api/v1/accounts/acc_bob_chk_01/transactions", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code in [403, 404]


def test_unconsented_own_account_bola_blocked(client, alice_token_and_consent):
    """
    Alice owns acc_alice_sav_02, but did NOT grant consent for it in this session.
    Attempting to query it must be blocked with 403 Forbidden.
    """
    token, _ = alice_token_and_consent
    resp = client.get("/api/v1/accounts/acc_alice_sav_02", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    assert "not authorize" in resp.json()["detail"]["error_description"]
