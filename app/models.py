"""SQLAlchemy ORM Models for OpenBankingSecurityAPI."""
from datetime import datetime, timezone
import json
from typing import List
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Partner(Base):
    """Registered fintech partner entity."""
    __tablename__ = "partners"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=False)
    api_key_hash = Column(String(256), nullable=False)  # Argon2 secure hash
    api_key_prefix = Column(String(16), nullable=False)  # e.g. ob_live_abc123...
    redirect_uris = Column(Text, default="[]", nullable=False)  # JSON list
    rate_limit_rpm = Column(Integer, default=60, nullable=False)
    status = Column(String(20), default="ACTIVE", nullable=False)  # ACTIVE, REVOKED
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    def get_redirect_uris(self) -> List[str]:
        try:
            return json.loads(self.redirect_uris)
        except Exception:
            return []

    def set_redirect_uris(self, uris: List[str]) -> None:
        self.redirect_uris = json.dumps(uris)


class Customer(Base):
    """Bank customer / user account."""
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(String(64), unique=True, index=True, nullable=False)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)  # Argon2 secure hash
    full_name = Column(String(128), nullable=False)
    email = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    accounts = relationship("Account", back_populates="customer", cascade="all, delete-orphan")


class Account(Base):
    """Customer bank account."""
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(String(64), unique=True, index=True, nullable=False)
    customer_id = Column(String(64), ForeignKey("customers.customer_id"), nullable=False, index=True)
    account_number_masked = Column(String(32), nullable=False)
    account_type = Column(String(32), default="CHECKING", nullable=False)  # CHECKING, SAVINGS, CREDIT
    currency = Column(String(3), default="USD", nullable=False)
    balance = Column(Float, default=0.0, nullable=False)
    status = Column(String(20), default="ACTIVE", nullable=False)
    
    # Internal proprietary field - NEVER exposed in sanitized API responses (Data Minimization / BOPLA test)
    internal_routing_code = Column(String(64), default="ROUT-INTERNAL-9981-CORE", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    customer = relationship("Customer", back_populates="accounts")
    transactions = relationship("Transaction", back_populates="account", cascade="all, delete-orphan")


class Transaction(Base):
    """Account financial transaction."""
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String(64), unique=True, index=True, nullable=False)
    account_id = Column(String(64), ForeignKey("accounts.account_id"), nullable=False, index=True)
    amount = Column(Float, nullable=False)
    currency = Column(String(3), default="USD", nullable=False)
    transaction_type = Column(String(20), nullable=False)  # DEBIT, CREDIT
    counterparty = Column(String(128), nullable=False)
    description = Column(String(256), nullable=False)
    timestamp = Column(DateTime, default=utc_now, nullable=False)

    # Internal core ledger reference - NEVER exposed in sanitized API response
    internal_ledger_ref = Column(String(64), default="CORE-LEDGER-V1-X719", nullable=False)

    account = relationship("Account", back_populates="transactions")


class Consent(Base):
    """OAuth 2.0 Customer Consent record."""
    __tablename__ = "consents"

    id = Column(Integer, primary_key=True, index=True)
    consent_id = Column(String(64), unique=True, index=True, nullable=False)
    client_id = Column(String(64), nullable=False, index=True)
    customer_id = Column(String(64), nullable=False, index=True)
    allowed_account_ids = Column(Text, default="[]", nullable=False)  # JSON list of account_ids
    scopes = Column(String(256), nullable=False)  # Space-separated scopes
    status = Column(String(20), default="ACTIVE", nullable=False)  # ACTIVE, REVOKED, EXPIRED
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False)

    def get_allowed_accounts(self) -> List[str]:
        try:
            return json.loads(self.allowed_account_ids)
        except Exception:
            return []

    def set_allowed_accounts(self, account_ids: List[str]) -> None:
        self.allowed_account_ids = json.dumps(account_ids)


class AuthorizationCode(Base):
    """OAuth 2.0 Authorization Code with PKCE parameters."""
    __tablename__ = "authorization_codes"

    id = Column(Integer, primary_key=True, index=True)
    code_hash = Column(String(128), unique=True, index=True, nullable=False)
    client_id = Column(String(64), nullable=False, index=True)
    customer_id = Column(String(64), nullable=False)
    consent_id = Column(String(64), nullable=False)
    redirect_uri = Column(String(512), nullable=False)
    code_challenge = Column(String(128), nullable=False)
    code_challenge_method = Column(String(10), default="S256", nullable=False)
    scopes = Column(String(256), nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)


class AuditLog(Base):
    """Sanitized structured security audit log."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    client_id = Column(String(64), nullable=True, index=True)
    customer_id = Column(String(64), nullable=True)
    account_id = Column(String(64), nullable=True)
    endpoint = Column(String(256), nullable=False)
    method = Column(String(10), nullable=False)
    ip_address = Column(String(64), default="127.0.0.1", nullable=False)
    status_code = Column(Integer, nullable=False)
    details = Column(String(512), nullable=False)


class IdempotencyRecord(Base):
    """Stores executed state-changing responses to prevent duplicate operations."""
    __tablename__ = "idempotency_records"

    id = Column(Integer, primary_key=True, index=True)
    idempotency_key = Column(String(128), unique=True, index=True, nullable=False)
    client_id = Column(String(64), nullable=False)
    request_hash = Column(String(64), nullable=False)
    response_status = Column(Integer, nullable=False)
    response_body = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
