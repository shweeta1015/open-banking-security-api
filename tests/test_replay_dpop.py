"""Replay Attack Protection and Idempotency Tests (DPoP RFC 9449 Simulation)."""
from datetime import datetime, timezone, timedelta
import json
import time
import uuid
import pytest
from app.models import Consent, Account
from app.security.jwt_handler import issue_access_token
from app.security.dpop import create_demo_dpop_proof
from app.seed import DEMO_CLIENT_ID


@pytest.fixture
def payment_token_and_consent(db_session):
    """Creates a token with 'payments:write' scope for Alice."""
    now = datetime.now(timezone.utc)
    consent = Consent(
        consent_id="consent_pay_001",
        client_id=DEMO_CLIENT_ID,
        customer_id="cust_alice_101",
        allowed_account_ids=json.dumps(["acc_alice_chk_01", "acc_alice_sav_02"]),
        scopes="accounts:read balances:read payments:write",
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
        scopes=["accounts:read", "balances:read", "payments:write"]
    )
    return token


def test_payment_with_valid_dpop_proof_succeeds(client, payment_token_and_consent):
    """Payment succeeds when valid DPoP proof is supplied."""
    proof = create_demo_dpop_proof(method="POST", path="/api/v1/payments")
    body = {
        "source_account_id": "acc_alice_chk_01",
        "destination_account_id": "acc_alice_sav_02",
        "amount": 50.00,
        "currency": "USD",
        "description": "Legitimate payment"
    }
    resp = client.post(
        "/api/v1/payments",
        headers={
            "Authorization": f"Bearer {payment_token_and_consent}",
            "X-DPoP-Proof": proof
        },
        json=body
    )
    assert resp.status_code == 201
    assert resp.json()["status"] == "SETTLED"


def test_dpop_replay_attack_rejected(client, payment_token_and_consent):
    """Replaying an identical DPoP proof (same JTI) must be rejected with 401 Replay Detected."""
    replayed_jti = "unique_proof_uuid_" + str(uuid.uuid4())
    proof = create_demo_dpop_proof(method="POST", path="/api/v1/payments", jti=replayed_jti)

    body = {
        "source_account_id": "acc_alice_chk_01",
        "destination_account_id": "acc_alice_sav_02",
        "amount": 25.00,
        "currency": "USD",
        "description": "Payment test"
    }

    # 1. First legitimate call succeeds
    resp1 = client.post(
        "/api/v1/payments",
        headers={
            "Authorization": f"Bearer {payment_token_and_consent}",
            "X-DPoP-Proof": proof
        },
        json=body
    )
    assert resp1.status_code == 201

    # 2. Intercepted request replayed with identical proof header
    resp2 = client.post(
        "/api/v1/payments",
        headers={
            "Authorization": f"Bearer {payment_token_and_consent}",
            "X-DPoP-Proof": proof
        },
        json=body
    )
    assert resp2.status_code == 401
    assert "replay_detected" in resp2.json()["detail"]["error"]


def test_dpop_expired_timestamp_rejected(client, payment_token_and_consent):
    """A proof older than maximum allowed drift (> 60s) must be rejected."""
    import base64
    old_time = int(time.time()) - 120  # 2 minutes ago
    expired_proof = base64.urlsafe_b64encode(json.dumps({
        "htm": "POST",
        "htu": "/api/v1/payments",
        "iat": old_time,
        "jti": str(uuid.uuid4())
    }).encode()).decode()

    body = {
        "source_account_id": "acc_alice_chk_01",
        "destination_account_id": "acc_alice_sav_02",
        "amount": 10.00,
        "currency": "USD"
    }
    resp = client.post(
        "/api/v1/payments",
        headers={
            "Authorization": f"Bearer {payment_token_and_consent}",
            "X-DPoP-Proof": expired_proof
        },
        json=body
    )
    assert resp.status_code == 401
    assert "expired_dpop_proof" in resp.json()["detail"]["error"]


def test_idempotency_key_prevents_duplicate_charge(client, payment_token_and_consent, db_session):
    """Submitting with the same Idempotency-Key returns cached response without duplicate transfer."""
    idempotency_key = "idemp_test_" + str(uuid.uuid4())

    account = db_session.query(Account).filter(Account.account_id == "acc_alice_chk_01").first()
    initial_balance = account.balance

    body = {
        "source_account_id": "acc_alice_chk_01",
        "destination_account_id": "acc_alice_sav_02",
        "amount": 100.00,
        "currency": "USD",
        "description": "Idempotent payment"
    }

    # Request 1 (Proof 1)
    proof1 = create_demo_dpop_proof(method="POST", path="/api/v1/payments")
    resp1 = client.post(
        "/api/v1/payments",
        headers={
            "Authorization": f"Bearer {payment_token_and_consent}",
            "X-DPoP-Proof": proof1,
            "Idempotency-Key": idempotency_key
        },
        json=body
    )
    assert resp1.status_code == 201
    payment_id1 = resp1.json()["payment_id"]

    # Request 2 (Proof 2 with fresh JTI, but same Idempotency-Key)
    proof2 = create_demo_dpop_proof(method="POST", path="/api/v1/payments")
    resp2 = client.post(
        "/api/v1/payments",
        headers={
            "Authorization": f"Bearer {payment_token_and_consent}",
            "X-DPoP-Proof": proof2,
            "Idempotency-Key": idempotency_key
        },
        json=body
    )
    assert resp2.status_code == 201
    payment_id2 = resp2.json()["payment_id"]

    # Must return identical payment ID
    assert payment_id1 == payment_id2

    # Balance should only have been deducted once (-100.00, not -200.00)
    db_session.refresh(account)
    assert account.balance == initial_balance - 100.00
