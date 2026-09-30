"""Banking Service with Object-Level Authorization (BOLA/IDOR) & Data Minimization."""
from datetime import datetime, timezone, timedelta
import hashlib
import json
import secrets
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.models import Account, Transaction, Consent, IdempotencyRecord
from app.schemas import (
    AccountSummary,
    BalanceResponse,
    TransactionResponse,
    PaymentInitiateRequest,
    PaymentInitiateResponse
)


class BankingService:
    @staticmethod
    def _verify_consent_and_account_access(
        db: Session,
        customer_id: str,
        consent_id: str,
        account_id: str
    ) -> Account:
        """
        OWASP API1 (BOLA / IDOR) Defense:
        Verifies that:
        1. The target account exists.
        2. The account belongs strictly to the authenticated customer (customer_id in token).
        3. The active consent record explicitly includes this account_id in allowed_account_ids.
        4. The consent has not expired or been revoked.
        Returns the Account object if authorized, otherwise raises safe 404 / 403 error.
        """
        # Retrieve consent
        consent = db.query(Consent).filter(Consent.consent_id == consent_id).first()
        if not consent or consent.status != "ACTIVE":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "consent_invalid", "error_description": "User consent is revoked, expired, or missing."}
            )

        now = datetime.now(timezone.utc)
        expires_at_utc = consent.expires_at.replace(tzinfo=timezone.utc) if consent.expires_at.tzinfo is None else consent.expires_at
        if now > expires_at_utc:
            consent.status = "EXPIRED"
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "consent_expired", "error_description": "User consent has expired."}
            )

        if consent.customer_id != customer_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "access_denied", "error_description": "Token customer does not match consent subject."}
            )

        allowed_accounts = consent.get_allowed_accounts()
        if account_id not in allowed_accounts:
            # Safe generic error to prevent cross-account probing/enumeration
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "unauthorized_account",
                    "error_description": f"Consent '{consent_id}' does not authorize access to account '{account_id}'."
                }
            )

        # Retrieve account and verify customer ownership
        account = db.query(Account).filter(Account.account_id == account_id).first()
        if not account or account.customer_id != customer_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "account_not_found", "error_description": f"Account '{account_id}' not found."}
            )

        return account

    @staticmethod
    def get_authorized_accounts(
        db: Session,
        customer_id: str,
        consent_id: str
    ) -> List[AccountSummary]:
        """
        Returns only the accounts consented to by the user.
        Data Minimization: Returns AccountSummary excluding balances and internal routing codes.
        """
        consent = db.query(Consent).filter(Consent.consent_id == consent_id).first()
        if not consent or consent.status != "ACTIVE":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "consent_invalid", "error_description": "Consent is revoked or expired."}
            )

        allowed_ids = consent.get_allowed_accounts()
        accounts = (
            db.query(Account)
            .filter(
                Account.customer_id == customer_id,
                Account.account_id.in_(allowed_ids)
            )
            .all()
        )

        return [
            AccountSummary(
                account_id=acc.account_id,
                account_number_masked=acc.account_number_masked,
                account_type=acc.account_type,
                currency=acc.currency,
                status=acc.status
            )
            for acc in accounts
        ]

    @staticmethod
    def get_account_detail(
        db: Session,
        customer_id: str,
        consent_id: str,
        account_id: str
    ) -> AccountSummary:
        """Retrieves a single authorized account summary with BOLA verification."""
        account = BankingService._verify_consent_and_account_access(db, customer_id, consent_id, account_id)
        return AccountSummary(
            account_id=account.account_id,
            account_number_masked=account.account_number_masked,
            account_type=account.account_type,
            currency=account.currency,
            status=account.status
        )

    @staticmethod
    def get_account_balance(
        db: Session,
        customer_id: str,
        consent_id: str,
        account_id: str
    ) -> BalanceResponse:
        """
        Retrieves real-time balance for an authorized account.
        Enforces BOLA protection; caller must also have verified 'balances:read' scope.
        """
        account = BankingService._verify_consent_and_account_access(db, customer_id, consent_id, account_id)
        return BalanceResponse(
            account_id=account.account_id,
            currency=account.currency,
            balance=account.balance,
            as_of=datetime.now(timezone.utc)
        )

    @staticmethod
    def get_account_transactions(
        db: Session,
        customer_id: str,
        consent_id: str,
        account_id: str
    ) -> List[TransactionResponse]:
        """
        Retrieves transactions for an authorized account with BOLA check.
        Data Minimization: Excludes internal ledger reference numbers.
        """
        account = BankingService._verify_consent_and_account_access(db, customer_id, consent_id, account_id)
        transactions = (
            db.query(Transaction)
            .filter(Transaction.account_id == account.account_id)
            .order_by(Transaction.timestamp.desc())
            .all()
        )
        return [
            TransactionResponse(
                transaction_id=tx.transaction_id,
                account_id=tx.account_id,
                amount=tx.amount,
                currency=tx.currency,
                transaction_type=tx.transaction_type,
                counterparty=tx.counterparty,
                description=tx.description,
                timestamp=tx.timestamp
            )
            for tx in transactions
        ]

    @staticmethod
    def process_payment(
        db: Session,
        customer_id: str,
        consent_id: str,
        client_id: str,
        req: PaymentInitiateRequest,
        idempotency_key: Optional[str] = None
    ) -> PaymentInitiateResponse:
        """
        Initiates a simulated payment with:
        - BOLA verification on source account
        - 'payments:write' scope requirement (checked by caller)
        - Idempotency-Key support to prevent duplicate payment execution
        """
        # 1. Idempotency Check
        if idempotency_key:
            req_hash = hashlib.sha256(
                f"{client_id}:{req.source_account_id}:{req.destination_account_id}:{req.amount}:{req.currency}".encode()
            ).hexdigest()

            cached = db.query(IdempotencyRecord).filter(
                IdempotencyRecord.idempotency_key == idempotency_key,
                IdempotencyRecord.client_id == client_id
            ).first()

            if cached:
                cached_data = json.loads(cached.response_body)
                return PaymentInitiateResponse(**cached_data)

        # 2. BOLA check: Customer must own source account & consent must allow it
        source_account = BankingService._verify_consent_and_account_access(
            db, customer_id, consent_id, req.source_account_id
        )

        # 3. Balance verification
        if source_account.balance < req.amount:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "insufficient_funds", "error_description": "Source account has insufficient balance."}
            )

        # 4. Perform simulated transfer
        source_account.balance -= req.amount
        now = datetime.now(timezone.utc)
        payment_id = f"pay_{secrets.token_hex(8)}"
        reference = f"REF-{secrets.token_hex(4).upper()}"

        tx = Transaction(
            transaction_id=f"tx_{secrets.token_hex(8)}",
            account_id=source_account.account_id,
            amount=-req.amount,
            currency=req.currency,
            transaction_type="DEBIT",
            counterparty=req.destination_account_id,
            description=req.description or "Simulated payment transfer",
            timestamp=now
        )
        db.add(tx)
        db.commit()

        response = PaymentInitiateResponse(
            payment_id=payment_id,
            source_account_id=req.source_account_id,
            destination_account_id=req.destination_account_id,
            amount=req.amount,
            currency=req.currency,
            status="SETTLED",
            reference=reference,
            timestamp=now
        )

        # 5. Store Idempotency Record if key provided
        if idempotency_key:
            rec = IdempotencyRecord(
                idempotency_key=idempotency_key,
                client_id=client_id,
                request_hash=req_hash,
                response_status=201,
                response_body=response.model_dump_json(),
                expires_at=now + timedelta(hours=24)
            )
            db.add(rec)
            db.commit()

        return response
