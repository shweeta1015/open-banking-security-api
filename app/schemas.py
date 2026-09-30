"""Pydantic Schemas with Strict Data Minimization."""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


# --- Generic Errors ---
class ErrorDetail(BaseModel):
    error: str
    error_description: str
    error_code: Optional[str] = None


# --- Partner Schemas ---
class PartnerRegisterRequest(BaseModel):
    client_id: str = Field(..., min_length=3, max_length=64, description="Unique identifier for the partner")
    name: str = Field(..., min_length=2, max_length=128, description="Partner organization name")
    redirect_uris: List[str] = Field(..., min_length=1, description="Registered redirect URIs for OAuth")
    rate_limit_rpm: Optional[int] = Field(60, ge=5, le=1000, description="Requests per minute limit")


class PartnerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    client_id: str
    name: str
    api_key_prefix: str
    redirect_uris: List[str]
    rate_limit_rpm: int
    status: str
    created_at: datetime


class PartnerCreatedResponse(PartnerResponse):
    raw_api_key: str = Field(..., description="Copy this API key now; it will never be displayed again.")


class ApiKeyRotateResponse(BaseModel):
    client_id: str
    new_api_key_prefix: str
    raw_api_key: str = Field(..., description="Newly generated API key. Store securely.")
    message: str = "Key rotated successfully. Old key is revoked."


# --- OAuth 2.0 & PKCE Schemas ---
class AuthorizeParams(BaseModel):
    client_id: str
    response_type: str = "code"
    redirect_uri: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str = "S256"


class CustomerLoginRequest(BaseModel):
    username: str
    password: str


class ConsentSubmitRequest(BaseModel):
    client_id: str
    username: str
    password: str
    redirect_uri: str
    state: str
    code_challenge: str
    code_challenge_method: str = "S256"
    scopes: List[str]
    allowed_account_ids: List[str]


class ConsentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    consent_id: str
    client_id: str
    customer_id: str
    scopes: str
    allowed_account_ids: List[str]
    status: str
    expires_at: datetime


class TokenRequest(BaseModel):
    grant_type: str = Field(..., pattern="^authorization_code$")
    code: str
    redirect_uri: str
    client_id: str
    code_verifier: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str
    consent_id: str


# --- Banking APIs (Strict Data Minimization) ---
# NOTE: Accounts list intentionally excludes sensitive internal bank routing code
class AccountSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    account_id: str
    account_number_masked: str
    account_type: str
    currency: str
    status: str


# Balance is separated into its own endpoint requiring 'balances:read' scope
class BalanceResponse(BaseModel):
    account_id: str
    currency: str
    balance: float
    as_of: datetime


class TransactionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    transaction_id: str
    account_id: str
    amount: float
    currency: str
    transaction_type: str
    counterparty: str
    description: str
    timestamp: datetime


class PaymentInitiateRequest(BaseModel):
    source_account_id: str
    destination_account_id: str
    amount: float = Field(..., gt=0.0)
    currency: str = Field("USD", min_length=3, max_length=3)
    description: str = Field("Simulated transfer", max_length=128)


class PaymentInitiateResponse(BaseModel):
    payment_id: str
    source_account_id: str
    destination_account_id: str
    amount: float
    currency: str
    status: str
    reference: str
    timestamp: datetime


# --- Audit Log Schemas ---
class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    event_type: str
    client_id: Optional[str]
    customer_id: Optional[str]
    account_id: Optional[str]
    endpoint: str
    method: str
    ip_address: str
    status_code: int
    details: str

