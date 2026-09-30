"""Database Seeding Script for Dummy Banking Data and Demo Partner."""
from datetime import datetime, timezone, timedelta
import json
from sqlalchemy.orm import Session
from app.database import engine, SessionLocal, init_db
from app.models import Partner, Customer, Account, Transaction
from app.security.crypto import hash_secret

DEMO_PARTNER_API_KEY = "ob_live_demo1234_supersecretpartnerkey987654321"
DEMO_PARTNER_PREFIX = "ob_live_demo1234"
DEMO_CLIENT_ID = "fintech_partner_demo"


def seed_database(db: Session = None) -> None:
    """Populates the database with initial educational dummy banking data."""
    close_db = False
    if db is None:
        init_db()
        db = SessionLocal()
        close_db = True

    try:
        # Check if already seeded
        existing_partner = db.query(Partner).filter(Partner.client_id == DEMO_CLIENT_ID).first()
        if existing_partner:
            print("[INFO] Database already contains seed data.")
            return

        print("[INFO] Seeding initial database with dummy banking data...")

        # 1. Demo Fintech Partner
        partner = Partner(
            client_id=DEMO_CLIENT_ID,
            name="Demo Fintech Analytics Ltd",
            api_key_hash=hash_secret(DEMO_PARTNER_API_KEY),
            api_key_prefix=DEMO_PARTNER_PREFIX,
            redirect_uris=json.dumps([
                "http://localhost:8000/oauth/callback",
                "http://127.0.0.1:8000/oauth/callback",
                "http://localhost:8000/dashboard",
                "http://127.0.0.1:8000/dashboard"
            ]),
            rate_limit_rpm=60,
            status="ACTIVE"
        )
        db.add(partner)

        # 2. Customer: Alice Johnson
        alice = Customer(
            customer_id="cust_alice_101",
            username="alice",
            password_hash=hash_secret("AliceSecurePass2026!"),
            full_name="Alice Johnson",
            email="alice.johnson@example.com"
        )
        db.add(alice)

        # Alice Accounts
        alice_chk = Account(
            account_id="acc_alice_chk_01",
            customer_id="cust_alice_101",
            account_number_masked="****-****-1001",
            account_type="CHECKING",
            currency="USD",
            balance=12450.00,
            status="ACTIVE",
            internal_routing_code="ROUT-INTERNAL-ALICE-CHK-991"
        )
        alice_sav = Account(
            account_id="acc_alice_sav_02",
            customer_id="cust_alice_101",
            account_number_masked="****-****-1002",
            account_type="SAVINGS",
            currency="USD",
            balance=45200.00,
            status="ACTIVE",
            internal_routing_code="ROUT-INTERNAL-ALICE-SAV-992"
        )
        db.add(alice_chk)
        db.add(alice_sav)

        # Alice Transactions
        now = datetime.now(timezone.utc)
        alice_txs = [
            Transaction(
                transaction_id="tx_alice_1001",
                account_id="acc_alice_chk_01",
                amount=-85.50,
                currency="USD",
                transaction_type="DEBIT",
                counterparty="WholeFoods Market",
                description="Organic groceries",
                timestamp=now - timedelta(days=1),
                internal_ledger_ref="LEDGER-CORE-TX-8801"
            ),
            Transaction(
                transaction_id="tx_alice_1002",
                account_id="acc_alice_chk_01",
                amount=4200.00,
                currency="USD",
                transaction_type="CREDIT",
                counterparty="Acme Tech Corp",
                description="Bi-weekly payroll direct deposit",
                timestamp=now - timedelta(days=3),
                internal_ledger_ref="LEDGER-CORE-TX-8802"
            ),
            Transaction(
                transaction_id="tx_alice_1003",
                account_id="acc_alice_chk_01",
                amount=-142.10,
                currency="USD",
                transaction_type="DEBIT",
                counterparty="Clean Energy Utility",
                description="Monthly power electric bill",
                timestamp=now - timedelta(days=5),
                internal_ledger_ref="LEDGER-CORE-TX-8803"
            ),
            Transaction(
                transaction_id="tx_alice_1004",
                account_id="acc_alice_chk_01",
                amount=-6.75,
                currency="USD",
                transaction_type="DEBIT",
                counterparty="Artisan Espresso Lab",
                description="Morning cappuccino",
                timestamp=now - timedelta(hours=4),
                internal_ledger_ref="LEDGER-CORE-TX-8804"
            )
        ]
        for tx in alice_txs:
            db.add(tx)

        # 3. Customer: Bob Smith
        bob = Customer(
            customer_id="cust_bob_202",
            username="bob",
            password_hash=hash_secret("BobSecurePass2026!"),
            full_name="Bob Smith",
            email="bob.smith@example.com"
        )
        db.add(bob)

        # Bob Account
        bob_chk = Account(
            account_id="acc_bob_chk_01",
            customer_id="cust_bob_202",
            account_number_masked="****-****-2001",
            account_type="CHECKING",
            currency="USD",
            balance=3120.50,
            status="ACTIVE",
            internal_routing_code="ROUT-INTERNAL-BOB-CHK-771"
        )
        db.add(bob_chk)

        # Bob Transactions
        bob_txs = [
            Transaction(
                transaction_id="tx_bob_2001",
                account_id="acc_bob_chk_01",
                amount=-1200.00,
                currency="USD",
                transaction_type="DEBIT",
                counterparty="Skyline Property Mgmt",
                description="Monthly residential rent",
                timestamp=now - timedelta(days=2),
                internal_ledger_ref="LEDGER-CORE-TX-7701"
            ),
            Transaction(
                transaction_id="tx_bob_2002",
                account_id="acc_bob_chk_01",
                amount=-34.20,
                currency="USD",
                transaction_type="DEBIT",
                counterparty="Downtown Books & Coffee",
                description="Technical reading paperbacks",
                timestamp=now - timedelta(days=4),
                internal_ledger_ref="LEDGER-CORE-TX-7702"
            )
        ]
        for tx in bob_txs:
            db.add(tx)

        db.commit()
        print("[SUCCESS] Database successfully initialized and seeded with dummy data.")
        print(f"  Demo Partner: client_id='{DEMO_CLIENT_ID}'")
        print(f"  Demo API Key: '{DEMO_PARTNER_API_KEY}'")
        print("  Customer 1: username='alice', password='AliceSecurePass2026!'")
        print("  Customer 2: username='bob', password='BobSecurePass2026!'")

    finally:
        if close_db:
            db.close()


if __name__ == "__main__":
    seed_database()
