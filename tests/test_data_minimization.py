"""OWASP API3: Excessive Data Exposure / BOPLA and API5: Broken Function Level Authorization Tests."""
from datetime import datetime, timezone, timedelta
import json
import pytest
from app.models import Consent
from app.security.jwt_handler import issue_access_token
from app.seed import DEMO_CLIENT_ID


@pytest.fixture
def read_only_token(db_session):
    """Creates a token with ONLY 'accounts:read' scope."""
    now = datetime.now(timezone.utc)
    consent = Consent(
        consent_id="consent_readonly_001",
        client_id=DEMO_CLIENT_ID,
        customer_id="cust_alice_101",
        allowed_account_ids=json.dumps(["acc_alice_chk_01"]),
        scopes="accounts:read",
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
        scopes=["accounts:read"]
    )
    return token


def test_data_minimization_internal_properties_omitted(client, read_only_token):
    """OWASP API3 Test: Verify internal routing codes and ledger references are never exposed."""
    resp = client.get("/api/v1/accounts", headers={"Authorization": f"Bearer {read_only_token}"})
    assert resp.status_code == 200
    accounts = resp.json()
    assert len(accounts) > 0

    first_acc = accounts[0]
    # Required safe fields
    assert "account_id" in first_acc
    assert "account_number_masked" in first_acc
    # Prohibited internal fields (data minimization)
    assert "internal_routing_code" not in first_acc
    assert "balance" not in first_acc


def test_bfla_read_only_token_cannot_access_balances(client, read_only_token):
    """Token with only 'accounts:read' must be denied access to /balances (API5)."""
    resp = client.get(
        "/api/v1/accounts/acc_alice_chk_01/balances",
        headers={"Authorization": f"Bearer {read_only_token}"}
    )
    assert resp.status_code == 403
    assert "insufficient_scope" in resp.json()["detail"]["error"]


def test_bfla_read_only_token_cannot_access_transactions(client, read_only_token):
    """Token with only 'accounts:read' must be denied access to /transactions (API5)."""
    resp = client.get(
        "/api/v1/accounts/acc_alice_chk_01/transactions",
        headers={"Authorization": f"Bearer {read_only_token}"}
    )
    assert resp.status_code == 403
    assert "insufficient_scope" in resp.json()["detail"]["error"]


def test_bfla_read_only_token_cannot_initiate_payments(client, read_only_token):
    """OWASP API5 Test: A read-only token cannot perform state-changing payments."""
    payment_body = {
        "source_account_id": "acc_alice_chk_01",
        "destination_account_id": "acc_bob_chk_01",
        "amount": 25.00,
        "currency": "USD",
        "description": "Unauthorized transfer"
    }
    resp = client.post(
        "/api/v1/payments",
        headers={"Authorization": f"Bearer {read_only_token}"},
        json=payment_body
    )
    assert resp.status_code == 403
    assert "insufficient_scope" in resp.json()["detail"]["error"]
